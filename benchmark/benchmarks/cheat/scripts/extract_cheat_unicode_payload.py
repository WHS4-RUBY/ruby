#!/usr/bin/env python3
"""Extract a technique's payload from cheat/database/*.json and properly decode
the \\Uxxxxxxxx escape-text sequences into real Unicode codepoints.

Why this exists: `cheat plant` writes the JSON's Injection_Task/Injection_Suffix
text to the target file byte-for-byte, without ever interpreting `\\U000e004e`-style
escape text as an actual codepoint. So techniques that rely on invisible Unicode
Tag characters (S3ii/T3.2, S7i/T3.1) are silently defanged when planted through
the normal `cheat plant` CLI path -- the "invisible" trick shows up as visible,
obviously-fake escape text instead. This script does the decoding CHeaT's own
tool skips, so the technique is tested as originally intended.

Usage: python3 extract_cheat_unicode_payload.py <CHeaT-code> <path to honeytokens_defenses.json>
"""
import json
import re
import sys

if len(sys.argv) != 3:
    print("usage: extract_cheat_unicode_payload.py <CHeaT-code> <honeytokens_defenses.json path>", file=sys.stderr)
    sys.exit(1)

code, path = sys.argv[1], sys.argv[2]

with open(path, encoding="utf-8") as f:
    data = json.load(f)

_escape_re = re.compile(r"\\U([0-9a-fA-F]{8})")


def decode_escapes(s: str) -> str:
    """Turn literal '\\U000e004e'-style escape TEXT into the real codepoint it names."""
    return _escape_re.sub(lambda m: chr(int(m.group(1), 16)), s)


for item in data:
    if item.get("technique") == code:
        task = decode_escapes(item.get("Injection_Task", "")).strip()
        suffix = decode_escapes(item.get("Injection_Suffix", "")).strip()
        print(task + "\n" + suffix)
        sys.exit(0)

print(f"no entry found for technique {code!r} in {path}", file=sys.stderr)
sys.exit(2)
