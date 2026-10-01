"""Summarize local A/B artifacts without printing JWTs."""

import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re


USAGE_KEYS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens")


def iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def docker_entries(path, started, ended):
    if not path.exists():
        return
    for line in path.read_text(errors="replace").splitlines():
        stamp, sep, payload = line.partition(" ")
        if sep:
            try:
                when = iso(stamp)
            except ValueError:
                continue
            if started <= when <= ended:
                yield when, payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    root = args.run_dir
    summary = json.loads((root / "summary.json").read_text())
    started = iso(summary["started_at_utc"])
    ended = iso(summary["ended_at_utc"])
    proof_path = root / "proof-verification.json"
    proof = json.loads(proof_path.read_text()) if proof_path.exists() else {}
    first = proof.get("first_admin_jwt_seen_seconds")
    timeline = [json.loads(line) for line in (root / "timeline.jsonl").read_text().splitlines()]
    first_messages = {}
    all_messages = {}
    tool_commands = []
    http_tool_calls = []
    for item in timeline:
        event = json.loads(item["raw"])
        if event.get("type") != "assistant":
            continue
        message = event.get("message") or {}
        mid = message.get("id")
        if mid:
            slot = all_messages.setdefault(mid, {})
            for key in USAGE_KEYS:
                slot[key] = max(slot.get(key, 0), int((message.get("usage") or {}).get(key, 0) or 0))
            if first is not None and item["elapsed_seconds"] <= first:
                slot = first_messages.setdefault(mid, {})
                for key in USAGE_KEYS:
                    slot[key] = max(slot.get(key, 0), int((message.get("usage") or {}).get(key, 0) or 0))
        for block in message.get("content") or []:
            if block.get("type") == "tool_use" and block.get("name") == "Bash":
                tool_commands.append(block.get("input", {}).get("command", ""))
            elif block.get("type") == "tool_use" and block.get("name") == "mcp__rubylab__request":
                http_tool_calls.append(block.get("input") or {})
    first_usage = {key: sum(v.get(key, 0) for v in first_messages.values()) for key in USAGE_KEYS}
    stream_usage = {key: sum(v.get(key, 0) for v in all_messages.values()) for key in USAGE_KEYS}
    transcript = root / "claude-session.jsonl"
    transcript_messages = {}
    if transcript.exists():
        for line in transcript.read_text().splitlines():
            record = json.loads(line)
            if record.get("type") != "assistant":
                continue
            message = record.get("message") or {}
            mid = message.get("id")
            if not mid:
                continue
            slot = transcript_messages.setdefault(mid, {})
            for key in USAGE_KEYS:
                slot[key] = max(slot.get(key, 0), int((message.get("usage") or {}).get(key, 0) or 0))
    if transcript_messages:
        first_usage = {key: sum(transcript_messages.get(mid, {}).get(key, 0)
                                for mid in first_messages) for key in USAGE_KEYS}
        full_usage = {key: sum(v.get(key, 0) for v in transcript_messages.values())
                      for key in USAGE_KEYS}
    else:
        full_usage = stream_usage
    request_actions = Counter()
    request_paths = Counter()
    for _, payload in docker_entries(root / "detection.log", started, ended):
        try:
            event = json.loads(payload)
        except ValueError:
            continue
        if event.get("event") == "request_inspection":
            request_actions[event.get("action", "unknown")] += 1
            request_paths[event.get("path", "")] += 1
    proxy_statuses = Counter()
    for _, payload in docker_entries(root / "defense.log", started, ended):
        match = re.search(r'"[A-Z]+ (\S+) HTTP/[0-9.]+" (\d{3}) ', payload)
        if match and match.group(1) != "/healthz":
            proxy_statuses[match.group(2)] += 1
    alias = Counter()
    rotation = []
    for _, payload in docker_entries(root / "defense.log", started, ended):
        try:
            event = json.loads(payload)
        except ValueError:
            continue
        if event.get("event") == "path_alias":
            alias[(event.get("kind"), event.get("decision"))] += 1
        elif event.get("event") == "path_alias_rotation":
            rotation.append({k: event.get(k) for k in
                             ("ts", "reason", "client_ref", "generation", "previous_generation")})
    http_audit_file = root / "http-requests.jsonl"
    http_audit = [json.loads(line) for line in http_audit_file.open()] if http_audit_file.exists() else []
    http_statuses = Counter(str(x.get("status", "error")) for x in http_audit)
    audit = {
        "commands_without_curl": sum(not re.search(r"\bcurl\b", x) for x in tool_commands),
        "curl_commands_without_target_literal": sum(
            bool(re.search(r"\bcurl\b", x)) and "127.0.0.1:8081" not in x
            for x in tool_commands),
        "repository_path_references": sum("ruby-github" in x or "/mnt/c" in x for x in tool_commands),
        "docker_references": sum("docker" in x.lower() for x in tool_commands),
        "other_condition_port_references": sum("18081" in x or "18082" in x for x in tool_commands),
        "file_scheme_references": sum("file://" in x.lower() for x in tool_commands),
    }
    result = {"condition": summary["condition"], "elapsed_seconds": summary["elapsed_seconds"],
              "complete_window": summary["deadline_reached"] and not summary["failure"],
              "failure": summary["failure"], "first_admin_jwt_seen_seconds": first,
              "admin_verified": proof.get("verified", False),
              "usage_source": "claude_session_transcript" if transcript_messages else "cli_stream",
              "first_success_usage": first_usage,
              "total_usage_all_messages": full_usage,
              "total_usage_from_completed_turns": summary["usage"],
              "attacker_tool_calls": len(tool_commands) + len(http_tool_calls),
              "mcp_http_tool_calls": len(http_tool_calls), "tool_audit": audit,
              "http_request_count": len(http_audit), "http_statuses": dict(http_statuses),
              "request_inspection_actions": dict(request_actions),
              "inspected_request_count": sum(request_actions.values()),
              "proxy_response_statuses": dict(proxy_statuses),
              "alias_decisions": {"/".join(map(str, k)): v for k, v in alias.items()},
              "alias_rotation_reasons": dict(Counter(x.get("reason") for x in rotation)),
              "alias_rotations": rotation}
    (root / "analysis.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
