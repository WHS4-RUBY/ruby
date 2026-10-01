from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

from freeze_attacker_v11 import frozen_mismatches


def generate_variants(count: int = 5) -> dict[str, object]:
    variants = []
    prefixes: set[str] = set()
    for repetition in range(count):
        while True:
            prefix = "/" + secrets.token_hex(5)
            if prefix not in prefixes:
                prefixes.add(prefix)
                break
        variants.append(
            {
                "repetition": repetition,
                "variant_id": f"frozen-{secrets.token_hex(8)}",
                "normal_traffic_seed": secrets.randbelow(2_000_000_000) + 1,
                "public_api_prefix": prefix,
            }
        )
    canonical = json.dumps(variants, sort_keys=True, separators=(",", ":"))
    return {
        "schema_version": 1,
        "purpose": "post-freeze hidden route and state variants for attacker v11",
        "generated_at": datetime.now(UTC).isoformat(),
        "variants_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "variants": variants,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate v11 variants once, after the attacker source is frozen"
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--freeze-seal", required=True, type=Path)
    parser.add_argument("--count", type=int, default=5)
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite variant manifest: {args.output}")
    freeze_seal = json.loads(args.freeze_seal.read_text(encoding="utf-8"))
    mismatches = frozen_mismatches(freeze_seal)
    if mismatches:
        raise ValueError(f"attacker changed after freeze: {mismatches}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    value = generate_variants(args.count)
    value["freeze_id"] = freeze_seal["freeze_id"]
    args.output.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(value["variants_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
