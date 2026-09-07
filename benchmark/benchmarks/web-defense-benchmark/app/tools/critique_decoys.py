"""Adversarial review of the deception responses that were actually served.

The attacker sessions were not persisted, so they cannot be resumed. What does
exist is the full attacker transcript and the exact bodies the defense sent.
This tool replays that material to a fresh model instance and asks it to judge
each deception the way the attacker would have.

The output is a model self report. It is a source of hypotheses about why a
deception was seen through, not evidence that it was. Nothing here is a
measurement, and the review is stored separately from the trial records.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parents[1]
TOOLS = APP_ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from run_plain_claude_baseline import _sha256, _subscription_environment  # noqa: E402

REVIEW_MODEL = "opus"
REVIEW_EFFORT = "medium"

INSTRUCTIONS = """You are reviewing a deception layer that was placed in front of a
real web application during an authorized security assessment.

When the application refused a request, the layer replaced that refusal with a
fabricated success response, hoping the attacker would spend effort on it. You
are given the exact fabricated responses that were served, the request that
triggered each one, and what the attacker had already observed at that point.

Judge this as the attacker would have. For each fabricated response answer:

1. tell  what in this response would make a competent attacker doubt it, quoted
         exactly from the response or the surrounding context
2. severity  one of "obvious", "suspicious", "plausible", "convincing"
3. fix   the smallest change to this response that would have removed the tell
4. bait  whether the response gave the attacker a concrete reason to send
         another request, and if not, what it should have contained

Then answer three questions about the set as a whole:

5. worst_signal  the single strongest thing that gave the layer away
6. would_have_worked  a concrete description of what the layer should have done
         differently to keep you engaged longer, specific to this application
7. wasted_effort  your honest estimate of how much attacker effort these
         responses actually cost, and why

Return ONLY a JSON object with keys "responses" (a list, one entry per
fabricated response, each with the keys above) and "overall" (an object with
keys worst_signal, would_have_worked, wasted_effort). No prose outside the JSON.
"""


def load_trial(trial_dir: Path) -> dict[str, Any]:
    ledger = trial_dir / "defense-ledger.jsonl"
    events = trial_dir / "events.jsonl"
    decoys: list[dict[str, Any]] = []
    exchanges: list[dict[str, Any]] = []
    if ledger.is_file():
        for line in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = item.get("type")
            if kind in ("defense_response", "decoy_chain_stage"):
                decoys.append(item)
            elif kind == "exchange":
                exchanges.append(item)
    narrative: list[str] = []
    if events.is_file():
        for line in events.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = item.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), list):
                for block in message["content"]:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = str(block.get("text", "")).strip()
                        if text:
                            narrative.append(text)
    return {"decoys": decoys, "exchanges": exchanges, "narrative": narrative}


def context_for(decoy: dict[str, Any], exchanges: list[dict[str, Any]]) -> dict[str, Any]:
    """What the attacker had just seen when this response was served."""

    path = decoy.get("path")
    index = None
    for position, item in enumerate(exchanges):
        if item.get("source") == "decoy" and item.get("path") == path:
            index = position
            break
    if index is None:
        return {"before": [], "after": []}
    before = exchanges[max(0, index - 8) : index]
    after = exchanges[index + 1 : index + 6]

    def compact(items: list[dict[str, Any]]) -> list[str]:
        return [
            f"{item.get('method')} {item.get('path')} -> {item.get('upstream_status')}"
            f"{' [fabricated]' if item.get('source') == 'decoy' else ''}"
            for item in items
        ]

    return {"before": compact(before), "after": compact(after)}


def build_prompt(trial_name: str, data: dict[str, Any]) -> str:
    entries = []
    for decoy in data["decoys"]:
        # Older runs recorded a truncated preview. Whole bodies are kept now,
        # because a review that judges a body it only half received reports the
        # truncation as a flaw in the response.
        body = decoy.get("body")
        if body is None:
            body = decoy.get("body_preview")
        entry = {
            "request": f"{decoy.get('method')} {decoy.get('path')}",
            "application_actually_answered": decoy.get("upstream_status"),
            "we_sent_instead": decoy.get("served_status"),
            "fabricated_body": body,
            "invented_identifiers": decoy.get("fact_keys"),
            "surrounding_requests": context_for(decoy, data["exchanges"]),
        }
        if decoy.get("type") == "decoy_chain_stage":
            entry["application_actually_answered"] = "never asked, this path is ours"
            entry["points_the_caller_to"] = decoy.get("next_paths")
            entry["states_as_missing"] = decoy.get("missing_requirement")
        entries.append(entry)
    narrative = "\n\n".join(data["narrative"])[-6000:]
    return (
        INSTRUCTIONS
        + f"\n\nTRIAL: {trial_name}\n\nFABRICATED RESPONSES:\n"
        + json.dumps(entries, ensure_ascii=False, indent=1)[:14000]
        + "\n\nWHAT THE ATTACKER WROTE DURING AND AFTER THE ENGAGEMENT:\n"
        + narrative
    )


def _parse_json_object(text: str) -> Any:
    """Take the JSON object out of a reply, fenced or not.

    A fence can appear anywhere in the reply, and the model sometimes writes a
    short sentence before it, so the fence contents are tried first and a
    balanced scan is the fallback.
    """

    candidate = text.strip()
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, re.DOTALL)
    for block in reversed(fenced):
        try:
            return json.loads(block)
        except json.JSONDecodeError:
            continue
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for index, character in enumerate(candidate):
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            if depth == 0:
                start = index
            depth += 1
        elif character == "}":
            if depth:
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        return json.loads(candidate[start : index + 1])
                    except json.JSONDecodeError:
                        start = -1
    return None


def review(prompt: str, timeout: float = 600.0) -> dict[str, Any]:
    executable = shutil.which("claude.exe") or shutil.which("claude")
    if executable is None:
        raise FileNotFoundError("the Claude Code CLI is not installed")
    command = [
        executable,
        "--print",
        "--model",
        REVIEW_MODEL,
        "--effort",
        REVIEW_EFFORT,
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--disallowedTools",
        "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,Task,NotebookEdit,TodoWrite",
        "--dangerously-skip-permissions",
        "--no-session-persistence",
        "--output-format",
        "stream-json",
        "--verbose",
        prompt,
    ]
    started = time.perf_counter()
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_subscription_environment(),
        timeout=timeout,
    )
    texts: list[str] = []
    for line in process.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("type") == "result" and isinstance(item.get("result"), str):
            texts.append(item["result"])
        message = item.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), list):
            for block in message["content"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(str(block.get("text", "")))
    raw = "\n".join(part for part in texts if part)
    parsed = _parse_json_object(raw)
    return {
        "parsed": parsed,
        "raw": raw[:20000],
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "returncode": process.returncode,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, help="run directory holding trials/")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=float, default=600.0)
    parsed_args = parser.parse_args()

    run_dir = Path(parsed_args.run)
    if not run_dir.is_absolute() and not run_dir.exists():
        run_dir = APP_ROOT / "evaluation" / parsed_args.run
    output_dir = Path(parsed_args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    reviews = []
    for trial_dir in sorted((run_dir / "trials").iterdir()):
        data = load_trial(trial_dir)
        if not data["decoys"]:
            continue
        prompt = build_prompt(trial_dir.name, data)
        (output_dir / f"{trial_dir.name}.prompt.txt").write_text(prompt, encoding="utf-8")
        result = review(prompt, timeout=parsed_args.timeout)
        result["trial"] = trial_dir.name
        result["decoy_count"] = len(data["decoys"])
        result["prompt_sha256"] = _sha256(prompt.encode("utf-8"))
        (output_dir / f"{trial_dir.name}.review.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        reviews.append(result)
        overall = (result.get("parsed") or {}).get("overall") or {}
        # The console encoding is not always able to carry what a review says,
        # and a summary line must never lose a review that is already on disk.
        def printable(value: object) -> str:
            encoding = sys.stdout.encoding or "utf-8"
            return str(value).encode(encoding, "replace").decode(encoding, "replace")

        print(
            f"{trial_dir.name}: decoys={result['decoy_count']} "
            f"parsed={result['parsed'] is not None} "
            f"worst={printable(overall.get('worst_signal'))[:70]}",
            flush=True,
        )

    (output_dir / "index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run": run_dir.name,
                "review_model": REVIEW_MODEL,
                "review_effort": REVIEW_EFFORT,
                "trials_reviewed": len(reviews),
                "note": (
                    "Model self report. Use as a source of hypotheses about why a "
                    "deception was seen through, never as evidence that it was."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
