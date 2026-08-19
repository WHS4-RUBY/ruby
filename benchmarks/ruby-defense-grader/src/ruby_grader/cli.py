from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .demo import generate_demo
from .grader import grade_manifest_file, inspect_manifest_file
from .normal_web_demo import generate_normal_web_run
from .done_server import serve_done
from .models import ValidationError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ruby-grader", description="Grade resistance to fixed and adaptive LLM attacks")
    sub = parser.add_subparsers(dest="command", required=True)
    grade = sub.add_parser("grade", help="grade a run manifest")
    grade.add_argument("manifest", type=Path)
    grade.add_argument("--output", "-o", type=Path)
    inspect = sub.add_parser("inspect", help="inspect one or more runs without requiring A/B baseline success")
    inspect.add_argument("manifest", type=Path)
    inspect.add_argument("--output", "-o", type=Path)
    demo = sub.add_parser("demo", help="generate deterministic demo artifacts and grade them")
    demo.add_argument("--output-dir", type=Path, default=Path("demo-output"))
    normal = sub.add_parser("normal-web-demo", help="run benign traffic against a real local HTTP server and inspect it")
    normal.add_argument("--output-dir", type=Path, default=Path("normal-web-output"))
    serve = sub.add_parser("serve-done", help="serve a CVE-Bench-compatible GET /done endpoint for one run")
    serve.add_argument("manifest", type=Path)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=9091)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "serve-done":
            serve_done(args.manifest, args.host, args.port)
            return 0
        if args.command == "demo":
            manifest = generate_demo(args.output_dir)
            report = grade_manifest_file(manifest)
        elif args.command == "normal-web-demo":
            manifest = generate_normal_web_run(args.output_dir)
            report = inspect_manifest_file(manifest)
        elif args.command == "inspect":
            report = inspect_manifest_file(args.manifest)
        else:
            report = grade_manifest_file(args.manifest)
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
        if getattr(args, "output", None):
            args.output.write_text(rendered + "\n", encoding="utf-8")
        print(rendered)
        return 0
    except ValidationError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
