from __future__ import annotations

import base64
import re
import urllib.parse


MAX_DECODE_PASSES = 3


def _decode_repeated(value: str) -> str:
    decoded = value
    for _ in range(MAX_DECODE_PASSES):
        candidate = urllib.parse.unquote_plus(decoded)
        if candidate == decoded:
            break
        decoded = candidate
    return decoded


def _sql_injection_in_query(path: str) -> bool:
    decoded_path = _decode_repeated(path)
    query = urllib.parse.urlsplit(decoded_path).query
    for _, raw_value in urllib.parse.parse_qsl(
        query,
        keep_blank_values=True,
        strict_parsing=False,
    ):
        value = _decode_repeated(raw_value).lower()
        if "'" not in value:
            continue
        if value.count("'") >= 2:
            return True
        suffix = value.split("'", 1)[1]
        without_block_comments = re.sub(r"/\*.*?\*/", "", suffix)
        lexical = re.sub(r"[^a-z0-9_]+", "", without_block_comments)
        if "--" in suffix or "/*" in suffix or "#" in suffix:
            return True
        if lexical.startswith(
            (
                "or",
                "and",
                "union",
                "select",
                "insert",
                "update",
                "delete",
                "drop",
                "alter",
                "copy",
                "orderby",
                "is",
                "in",
                "like",
                "between",
                "exists",
                "case",
                "when",
                "cast",
                "coalesce",
                "null",
                "true",
                "false",
                "query_to_xml",
                "set_config",
            )
        ):
            return True
    return False


def decision(path: str) -> dict[str, object]:
    decoded = _decode_repeated(path).lower()
    collapsed = " ".join(decoded.split())
    without_block_comments = re.sub(r"/\*.*?\*/", " ", decoded)
    blocked = _sql_injection_in_query(path) or any(
        signature in collapsed
        for signature in (
            "../",
            "..\\",
            "/internal/",
            "query_to_xml(",
            "set_config('role'",
            "file://",
            "gopher://",
        )
    )
    blocked = blocked or re.search(
        r"\bunion\s+select\b",
        " ".join(without_block_comments.split()),
    ) is not None
    if not blocked:
        return {
            "contract_version": "2.0.0",
            "action": "pass",
            "reason_code": "static.clean",
        }
    body = base64.b64encode(b'{"detail":"request blocked"}').decode()
    return {
        "contract_version": "2.0.0",
        "action": "block",
        "reason_code": "static.attack-signature",
        "response": {
            "status_code": 403,
            "headers": {"content-type": ["application/json"]},
            "body_base64": body,
        },
    }
