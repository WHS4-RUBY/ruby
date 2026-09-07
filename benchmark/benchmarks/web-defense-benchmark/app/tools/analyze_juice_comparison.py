"""Read a Juice Shop comparison run and say what it measured.

Three quantities decide whether the deception can move the outcome, and they
multiply: how often a caller walks into the chain, how much of its own working
time the chain then takes, and how much time a solved weakness costs it. The
first two are reported per arm here; the third comes from the undefended arm.

One caution is built in. Chain dwell was first measured as the span between the
first and last chain request, which counts every minute the caller spent
elsewhere in between and reported more seconds than the trial was allowed to
run. It is measured here by charging each of the attacker's turns to whatever
that turn was working on, so a turn that requests a chain path is charged to the
chain together with the thinking that preceded it.

The comparison that matters is against proxy-only rather than against
undefended. Standing a reverse proxy in the path is not the defense under
study; what it fabricates is.

    python tools/analyze_juice_comparison.py evaluation/<run-id> [more runs...]
"""

from __future__ import annotations

import argparse
import glob
import json
import random
import re
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

# A turn separated from the one before it by more than this was not work on
# anything; it was the run waiting. Charging it to whatever came next would
# credit the chain with a stall.
LONGEST_TURN_SECONDS = 300.0
PERMUTATIONS = 20000

ENDPOINTS = (
    ("해결", "newly_solved_count"),
    ("공격자 초", "attacker_seconds"),
    ("출력 토큰", "attacker_output_tokens"),
)


def read_lines(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def moment(text: Any) -> datetime | None:
    for form in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, form)
        except (TypeError, ValueError):
            continue
    return None


def chain_paths(events: list[dict[str, Any]]) -> set[str]:
    paths: set[str] = set()
    for event in events:
        if event.get("type") == "decoy_chain_advertised":
            try:
                chain = json.loads(event["chain"])
            except (KeyError, json.JSONDecodeError):
                continue
            paths.add(chain.get("entry_path", ""))
            paths.update(stage.get("path", "") for stage in chain.get("stages", []))
        elif event.get("type") == "decoy_chain_stage":
            paths.add(event.get("path", ""))
    return {path for path in paths if path}


def shell_turns(events: list[dict[str, Any]]) -> list[tuple[datetime, str]]:
    """Every shell call the attacker made, with the time its result arrived."""

    pending: dict[str, str] = {}
    turns: list[tuple[datetime, str]] = []
    for event in events:
        content = (event.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        when = moment(event.get("timestamp"))
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                command = (block.get("input") or {}).get("command")
                if isinstance(command, str):
                    pending[block.get("id")] = command
            elif block.get("type") == "tool_result":
                command = pending.pop(block.get("tool_use_id"), None)
                if command is not None and when is not None:
                    turns.append((when, command))
    return turns


def charged_to_chain(turns, paths) -> tuple[float, int, int, int]:
    """Seconds charged to the chain, chain turns, first contact, total turns."""

    if not turns or not paths:
        return 0.0, 0, 0, len(turns)
    hunting = [re.compile(re.escape(path) + r"(?![\w-])") for path in paths]
    charged = 0.0
    hits = 0
    first = 0
    previous = turns[0][0]
    for index, (when, command) in enumerate(turns, start=1):
        gap = (when - previous).total_seconds()
        previous = when
        if gap < 0 or gap > LONGEST_TURN_SECONDS:
            gap = 0.0
        if any(pattern.search(command) for pattern in hunting):
            charged += gap
            hits += 1
            first = first or index
    return charged, hits, first, len(turns)


def collect(run_dirs: list[str]) -> dict[str, list[dict[str, Any]]]:
    arms: dict[str, list[dict[str, Any]]] = {}
    excluded: dict[str, list[dict[str, Any]]] = {}
    for run_dir in run_dirs:
        pattern = str(Path(run_dir) / "trials" / "*" / "result.json")
        for result_path in sorted(glob.glob(pattern)):
            trial = Path(result_path).parent
            record = json.loads(Path(result_path).read_text(encoding="utf-8"))
            condition = record.get("condition") or "unknown"
            events = read_lines(trial / "events.jsonl")
            ledger = read_lines(trial / "defense-ledger.jsonl")
            charged, hits, first, total = charged_to_chain(
                shell_turns(events), chain_paths(ledger)
            )
            record["chain_seconds"] = charged
            record["chain_turns"] = hits
            record["first_contact"] = first
            record["attacker_turns"] = total
            # A trial killed at the cap writes no result event, so it carries no
            # duration. Dropping those measures only the trials that finished
            # early, which is the fast half. The attacker did work up to the cap,
            # so the cap is used and the censoring is reported.
            if record.get("attacker_seconds") is None and record.get("timed_out"):
                record["attacker_seconds"] = record.get("timeout_seconds")
                record["duration_censored"] = True
            # A trial killed at the cap writes no result event, so its output
            # token total is gone. The streamed turns carry only fragments of
            # it, and their sum came to a fifth of the truth with a spread from
            # 0.20 to 0.35 across trials, so there is nothing here to rebuild
            # it from. A zero would be read as a real measurement, so it is
            # marked missing and the count of missing trials is reported.
            if not record.get("attacker_output_tokens"):
                record["attacker_output_tokens"] = None
                record["tokens_missing"] = True
            # A trial where the attacker never made a call measured nothing:
            # the process exited before it started, and its solved count is
            # whatever the application does on its own. Counting it as a low
            # score would credit the defense with a crash.
            if not record.get("attacker_tool_uses"):
                record["attacker_never_ran"] = True
                excluded.setdefault(condition, []).append(record)
                continue
            arms.setdefault(condition, []).append(record)
    for condition, dropped in excluded.items():
        print(f"  제외: {condition} {len(dropped)}판, 공격자가 한 번도 안 돌았다")
    return arms


def median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def shown(values: list[float], places: int = 0) -> str:
    """A median, or a dash when nothing was measured.

    Printing zero for an empty set reads as a measurement of zero, and with
    the caller asked to spend its whole budget most trials end at the cap with
    no token total at all.
    """

    return f"{median(values):>10.{places}f}" if values else f"{'-':>10}"


def permutation_p(left: list[float], right: list[float]) -> float:
    """Two sided, on the difference of medians. Small samples, no assumptions."""

    if not left or not right:
        return 1.0
    observed = abs(median(left) - median(right))
    pooled = left + right
    rng = random.Random(20260906)
    extreme = 0
    for _ in range(PERMUTATIONS):
        rng.shuffle(pooled)
        gap = abs(median(pooled[: len(left)]) - median(pooled[len(left) :]))
        if gap >= observed - 1e-12:
            extreme += 1
    return (extreme + 1) / (PERMUTATIONS + 1)


def numbers(records, key) -> list[float]:
    return [float(r[key]) for r in records if isinstance(r.get(key), (int, float))]


def compare(title: str, base: list[dict], arms: dict, wanted) -> None:
    print(f"\n{title}")
    for condition in sorted(arms):
        if not wanted(condition):
            continue
        for label, key in ENDPOINTS:
            left, right = numbers(base, key), numbers(arms[condition], key)
            gap = median(right) - median(left)
            print(
                f"  {condition:<18}{label:<10}{gap:+9.1f}"
                f"  p={permutation_p(left, right):.3f}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--against", default="undefended", help="비교 기준 조건")
    parsed = parser.parse_args()

    arms = collect(parsed.runs)
    if not arms:
        print("시험 기록이 없다")
        return 1

    print(
        f"{'조건':<20}{'판':>4}{'해결 중앙':>10}{'공격자 초':>11}"
        f"{'출력 토큰':>10}{'시간초과':>9}{'시간없음':>9}{'토큰없음':>9}"
    )
    for condition in sorted(arms):
        records = arms[condition]
        censored = sum(1 for r in records if r.get("duration_censored"))
        missing = sum(1 for r in records if r.get("attacker_seconds") is None)
        no_tokens = sum(1 for r in records if r.get("tokens_missing"))
        print(
            f"{condition:<20}{len(records):>4}"
            f"{median(numbers(records, 'newly_solved_count')):>10.1f}"
            f"{median(numbers(records, 'attacker_seconds')):>11.1f}"
            f"{shown(numbers(records, 'attacker_output_tokens'))}"
            f"{censored:>9}{missing:>9}{no_tokens:>9}"
        )
    print("  시간초과는 상한값으로 넣었고, 시간없음과 토큰없음은 뺐다.")

    base = arms.get(parsed.against)
    if base:
        compare(
            f"{parsed.against} 대비 (순열검정, 중앙값 차이)",
            base,
            arms,
            lambda condition: condition != parsed.against,
        )

    # undefended against honeyval mixes two things: standing a reverse proxy in
    # the path, and what that proxy fabricates. Only the second is the defense.
    control = arms.get("proxy-only")
    if control:
        compare(
            "proxy-only 대비 — 기만만의 몫",
            control,
            arms,
            lambda condition: condition.startswith("honeyval"),
        )
        if base and parsed.against != "proxy-only":
            gap = median(numbers(control, "newly_solved_count")) - median(
                numbers(base, "newly_solved_count")
            )
            print(f"  프록시를 세운 것만으로 생긴 해결 수 차이: {gap:+.1f}")

    print(f"\n{'조건':<20}{'사슬 세움':>10}{'진입':>8}{'사슬 초 중앙':>13}{'첫 접촉':>10}")
    for condition in sorted(arms):
        records = arms[condition]
        if not any(r.get("decoy_chains_advertised") for r in records):
            continue
        built = sum(1 for r in records if r.get("decoy_chain_built"))
        entered = [r for r in records if r["chain_turns"]]
        spots = [
            r["first_contact"] / r["attacker_turns"] for r in entered if r["attacker_turns"]
        ]
        print(
            f"{condition:<20}{built:>6}/{len(records):<3}{len(entered):>5}/{len(records):<3}"
            f"{median([r['chain_seconds'] for r in entered]):>13.1f}"
            f"{median(spots) * 100 if spots else 0:>9.0f}%"
        )

    # The threshold this run has to clear, restated from the undefended arm so
    # it is never quoted from memory: five weaknesses is the smallest change
    # ten trials per arm can separate from noise.
    if base:
        solved = median(numbers(base, "newly_solved_count"))
        seconds = median(numbers(base, "attacker_seconds"))
        if solved:
            each = seconds / solved
            print(
                f"\n무방어에서 약점 하나에 {each:.1f}초. 검출 기준 5개를 넘기려면 "
                f"판당 {each * 5:.0f}초를 뺏어야 한다."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
