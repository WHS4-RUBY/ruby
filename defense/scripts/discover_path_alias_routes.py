"""Inventory candidate API paths from saved app assets and browser HAR files.

This produces review material; it never edits the enforcing route configuration.
"""

import argparse
import hashlib
import json
import re
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from defense.app.path_alias import Route


PATH = re.compile(r"/(?:(?:rest|api)/)[A-Za-z0-9_.$/{}/%:-]*", re.I)
QUERY_PATH = re.compile(r"[?&]([A-Za-z][A-Za-z0-9_-]*)=([^&#\s\"'`]+)")
INPUT_SUFFIXES = {".js", ".mjs", ".html", ".har"}
JS_REF = re.compile(r"[\"']([^\"'\s]+\.(?:m?js))[\"']", re.I)


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "script":
            source = dict(attrs).get("src")
            if source:
                self.sources.append(source)


def fetch_assets(origin: str, directory: Path) -> list[Path]:
    """Save a bounded set of public, same-origin HTML/JS assets for review."""
    base = origin.rstrip("/") + "/"
    parsed_base = urlsplit(base)
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc or parsed_base.path != "/":
        raise ValueError("Asset URL must be an HTTP(S) origin")
    directory.mkdir(parents=True, exist_ok=True)
    queued = [base]
    seen: set[str] = set()
    files = []
    total = 0
    while queued:
        url = queued.pop(0)
        parsed = urlsplit(url)
        if (parsed.scheme, parsed.netloc) != (parsed_base.scheme, parsed_base.netloc) or url in seen:
            continue
        if len(seen) >= 64:
            raise ValueError("Asset discovery exceeds 64 same-origin URLs")
        seen.add(url)
        try:
            with urlopen(Request(url, headers={"Accept-Encoding": "identity"}), timeout=10) as response:
                final = urlsplit(response.geturl())
                if (final.scheme, final.netloc) != (parsed_base.scheme, parsed_base.netloc):
                    raise ValueError(f"Asset redirected outside app origin: {url}")
                data = response.read(8 * 1024 * 1024 + 1)
                media_type = response.headers.get_content_type()
        except HTTPError:
            if url == base:
                raise
            continue
        if len(data) > 8 * 1024 * 1024:
            raise ValueError(f"Asset exceeds 8 MiB: {url}")
        total += len(data)
        if total > 32 * 1024 * 1024:
            raise ValueError("Asset discovery exceeds 32 MiB")
        if media_type not in {"text/html", "application/javascript", "text/javascript"}:
            continue
        suffix = ".html" if media_type == "text/html" else ".js"
        file = directory / (hashlib.sha256(url.encode()).hexdigest()[:12] + suffix)
        file.write_bytes(data)
        files.append(file)
        text = data.decode("utf-8", errors="replace")
        if suffix == ".html":
            parser = Scripts()
            parser.feed(text)
            queued.extend(urljoin(url, source) for source in parser.sources)
        else:
            queued.extend(urljoin(url, match.group(1)) for match in JS_REF.finditer(text))
    return files


def protected_path(value: str) -> str | None:
    value = unquote(value)
    if value.startswith(("http://", "https://")):
        value = urlsplit(value).path
    match = PATH.match(value)
    return match.group(0) if match else None


def inventory(inputs: list[Path], routes_file: Path | None = None,
              origin: str | None = None) -> dict:
    configured = json.loads(routes_file.read_text(encoding="utf-8"))["routes"] if routes_file else []
    routes = [Route(item if isinstance(item, str) else item["path"],
                    ("*",) if isinstance(item, str) else tuple(item.get("methods", ["*"])))
              for item in configured]
    found: dict[str, set[str]] = defaultdict(set)
    observed_methods: dict[str, set[str]] = defaultdict(set)
    query_paths: dict[tuple[str, str], set[str]] = defaultdict(set)

    def add_text(source: str, value: str) -> None:
        value = value.replace("\\/", "/")
        for match in PATH.finditer(value):
            found[match.group(0)].add(source)
        for match in QUERY_PATH.finditer(value):
            path = protected_path(match.group(2))
            if path:
                query_paths[(match.group(1), path)].add(source)

    for file in inputs:
        if file.suffix.lower() == ".har":
            har = json.loads(file.read_text(encoding="utf-8"))
            for entry in har.get("log", {}).get("entries", []):
                url = entry.get("request", {}).get("url", "")
                parsed = urlsplit(url)
                if origin and (parsed.scheme, parsed.netloc) != (urlsplit(origin).scheme,
                                                                 urlsplit(origin).netloc):
                    continue
                path = protected_path(parsed.path)
                if path:
                    found[path].add(file.name)
                    method = entry.get("request", {}).get("method", "").upper()
                    if re.fullmatch(r"[A-Z]+", method):
                        observed_methods[path].add(method)
                for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                    path = protected_path(value)
                    if path:
                        query_paths[(key, path)].add(file.name)
        else:
            add_text(file.name, file.read_text(encoding="utf-8", errors="replace"))

    candidates = []
    for path, sources in sorted(found.items()):
        covered = [route.path for route in routes if route.real_pattern().fullmatch(path)]
        # A bundle may build the variable segment at runtime: "/image-captcha/" + id.
        dynamic_prefix = [route.path for route in routes
                          if route.path.startswith(path + "{") or
                          (path.endswith("/") and route.path.startswith(path + "{"))]
        candidates.append({"path": path,
                           "covered_by": covered,
                           "dynamic_prefix_of": dynamic_prefix if not covered else [],
                           "observed_methods": sorted(observed_methods[path]),
                           "sources": sorted(sources)})
    return {
        "note": "Candidates require human review before enabling enforcement.",
        "har_origin_filter": origin,
        "candidates": candidates,
        "query_path_candidates": [
            {"key": key, "path": path, "sources": sorted(sources)}
            for (key, path), sources in sorted(query_paths.items())
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path,
                        help="saved JS, HTML, browser HAR, or a directory containing them")
    parser.add_argument("--routes", type=Path, help="optional existing route file for coverage comparison")
    parser.add_argument("--origin", help="include only this origin's HAR requests")
    parser.add_argument("--fetch", help="fetch public HTML and JS from this app origin")
    parser.add_argument("--asset-dir", type=Path, help="directory for fetched assets")
    parser.add_argument("--output", type=Path, help="write the JSON report here")
    args = parser.parse_args()
    if args.fetch and not args.asset_dir:
        parser.error("--fetch requires --asset-dir")
    if args.asset_dir and not args.fetch:
        parser.error("--asset-dir requires --fetch")
    fetched = fetch_assets(args.fetch, args.asset_dir) if args.fetch else []
    files = sorted({child for path in [*args.inputs, *fetched]
                    for child in (path.rglob("*") if path.is_dir() else [path])
                    if child.is_file() and child.suffix.lower() in INPUT_SUFFIXES})
    if not files:
        parser.error("No JS, HTML, or HAR input files found")
    if args.origin:
        parsed = urlsplit(args.origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            parser.error("--origin must be an HTTP(S) origin without a path or query")
    report = json.dumps(inventory(files, args.routes, args.origin), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
