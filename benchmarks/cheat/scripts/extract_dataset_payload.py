#!/usr/bin/env python3
"""Extract one payload's injection text from CHeaT's datasets/payloads/payloads.json
by risk_category prefix (e.g. "T1.2", "T2.1", "T4.2").

Used for the 3 techniques that have no `cheat` CLI database code (T1.2, T2.1, T4.2) —
their payload text lives only in the paper's evaluation dataset, not in
cheat/database/*.json, so `cheat --action plant` can't reach them. We pull the raw
text here and write it to a file ourselves, same end result as `cheat plant`.

Usage: python3 extract_dataset_payload.py <risk_category_prefix> <path_to_payloads.json>
"""
import json
import sys

if len(sys.argv) != 3:
    print("usage: extract_dataset_payload.py <risk_category_prefix> <payloads.json path>", file=sys.stderr)
    sys.exit(1)

prefix, path = sys.argv[1], sys.argv[2]

with open(path, encoding="utf-8") as f:
    data = json.load(f)

for item in data:
    rc = item.get("risk_category", "")
    if rc.startswith(prefix):
        text = item.get("injection_1", "").strip() + "\n" + item.get("injection_2", "").strip()
        print(text)
        sys.exit(0)

print(f"no entry found for prefix {prefix!r}", file=sys.stderr)
sys.exit(2)
