from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path

import httpx

from ruby_runner.ledger import TrialLedger


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one non-attack Stage 2 lifecycle smoke trial")
    parser.add_argument("--output-root", type=Path, default=Path("evaluation/stage2-smoke"))
    parser.add_argument("--public-url", default="http://127.0.0.1:18080")
    parser.add_argument("--control-url", default="http://127.0.0.1:18081")
    parser.add_argument("--reset-token", default="development-reset-only")
    parser.add_argument("--inject-failure-after-reset", action="store_true")
    args = parser.parse_args()

    trial_id = secrets.token_hex(16)
    ledger = TrialLedger.create(args.output_root, trial_id)
    control_headers = {"X-Ruby-Reset-Token": args.reset_token}
    try:
        reset = httpx.post(
            f"{args.control_url}/internal/reset", headers=control_headers, timeout=20
        )
        reset.raise_for_status()
        initial = httpx.get(
            f"{args.control_url}/internal/state", headers=control_headers, timeout=20
        )
        initial.raise_for_status()
        initial_state = initial.json()
        ledger.artifact(
            "reset-attestation.json",
            {
                "residue_count": sum(initial_state["payload"]["transient_counts"].values()),
                "state_sha256": initial_state["sha256"],
            },
        )
        if args.inject_failure_after_reset:
            raise RuntimeError("injected local failure")
        ledger.transition("running")
        response = httpx.get(f"{args.public_url}/api/products", timeout=20)
        response.raise_for_status()
        ledger.artifact(
            "request-trace.json",
            {
                "body_sha256": __import__("hashlib").sha256(response.content).hexdigest(),
                "method": "GET",
                "path": "/api/products",
                "status_code": response.status_code,
            },
        )
        final_reset = httpx.post(
            f"{args.control_url}/internal/reset", headers=control_headers, timeout=20
        )
        final_reset.raise_for_status()
        restored = httpx.get(
            f"{args.control_url}/internal/state", headers=control_headers, timeout=20
        )
        restored.raise_for_status()
        restored_state = restored.json()
        ledger.artifact(
            "final-reset-attestation.json",
            {
                "residue_count": sum(restored_state["payload"]["transient_counts"].values()),
                "state_sha256": restored_state["sha256"],
                "state_matches_initial": restored_state["sha256"] == initial_state["sha256"],
            },
        )
        ledger.transition("completed")
    except Exception as error:
        ledger.transition("failed", reason=str(error)[:500])
    manifest = ledger.seal()
    result = {
        "artifact_manifest": str(manifest),
        "status": ledger.status,
        "trial_id": trial_id,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if ledger.status == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
