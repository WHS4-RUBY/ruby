"""Run six sequential, isolated Docker windows for deterministic functional A/B checks."""
import argparse
import ctypes
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
TARGET_IMAGE = "sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"
DEFENSE_IMAGE = "ruby-defense-stage-review:local"
BROWSER_IMAGE = "sha256:2aa0e40b738aa4678859e1db1afa6bb416d93eef0ec69e2880e02f87d72df63c"
ORDER = [("normal", "A"), ("normal", "B"), ("lifecycle", "B"),
         ("lifecycle", "A"), ("isolation", "A"), ("isolation", "B")]


def utc():
    return datetime.now(timezone.utc).isoformat()


def execute(command, timeout=180, output=None):
    if output is not None:
        with output.open("w", encoding="utf-8") as handle:
            return subprocess.run(command, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT,
                                  timeout=timeout).returncode
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed: {command!r}\n{result.stderr[-2000:]}")
    return result.stdout.strip()


def compose(project, mode, scenario, duration, destination, defense_image):
    target = {"image": TARGET_IMAGE, "pull_policy": "never", "networks": ["lab"],
              "healthcheck": {"test": ["CMD", "/nodejs/bin/node", "-e",
                 "require('net').connect({port:3000,host:'127.0.0.1'}).on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"],
                 "interval": "2s", "timeout": "3s", "retries": 30}}
    defense = {"image": defense_image, "pull_policy": "never", "networks": ["lab"],
               "environment": {"BENCHMARK_TARGET_URL": "http://target:3000",
                 "TOKEN_GATE_MODE": "off", "DEFENSE_DASHBOARD_ENABLED": "false",
                 "PATH_ALIAS_MODE": mode, "PATH_ALIAS_EPOCH_S": "1800",
                 "PATH_ALIAS_GRACE_EPOCHS": "1", "PATH_ALIAS_ROTATE_ON": "direct,reject",
                 "PATH_ALIAS_PREFIXES": "/rest/,/api/,/b2b/",
                 "PATH_ALIAS_ROUTES_FILE": "/app/config/juice-shop-routes.json",
                 "PATH_ALIAS_DB_PATH": "/tmp/functional-alias.sqlite3", "PATH_ALIAS_APP_ID": project},
               "depends_on": {"target": {"condition": "service_healthy"}},
               "healthcheck": {"test": ["CMD", "python", "-c",
                 "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"],
                 "interval": "2s", "timeout": "3s", "retries": 30}}
    browser = {"image": BROWSER_IMAGE, "pull_policy": "never", "networks": ["lab"],
               "profiles": ["runner"], "environment": {"TEST_SCENARIO": scenario,
                  "TEST_ALIAS_MODE": mode, "TEST_DURATION": str(duration), "TEST_INTERVAL": "45"},
               "volumes": [
                  {"type": "bind", "source": str(Path(__file__).with_name("functional_browser.cjs")),
                   "target": "/runner/functional_browser.cjs", "read_only": True},
                  {"type": "bind", "source": str(destination), "target": "/results"}],
               "command": ["node", "/runner/functional_browser.cjs"]}
    return {"name": project, "services": {"target": target, "defense": defense, "browser": browser},
            "networks": {"lab": {}}}


def rotation_counts(log):
    counts = Counter()
    for line in log.splitlines():
        start = line.find('{"event"')
        if start < 0:
            continue
        try:
            item = json.loads(line[start:])
        except ValueError:
            continue
        if item.get("event") == "path_alias_rotation":
            counts[item.get("reason", "unknown")] += 1
    return dict(counts)


def execute_window(command, duration, destination, project):
    """Reject stalled or suspended windows instead of counting inactivity as testing."""
    with (destination / "runner.log").open("w", encoding="utf-8") as handle:
        process = subprocess.Popen(command, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT)
        created = datetime.now(timezone.utc)
        try:
            while process.poll() is None:
                time.sleep(5)
                now = datetime.now(timezone.utc)
                path = destination / "events.jsonl"
                records = []
                if path.exists():
                    for line in path.read_text(encoding="utf-8").splitlines():
                        try:
                            records.append(json.loads(line))
                        except ValueError:
                            pass
                start = next((x for x in records if x.get("type") == "start"), None)
                reason = None
                if start:
                    times = [datetime.fromisoformat(x["at"].replace("Z", "+00:00"))
                             for x in records if x["at"] >= start["at"]]
                    if any((b - a).total_seconds() > 120 for a, b in zip(times, times[1:])):
                        reason = "Measurement log contains an activity gap longer than 120 seconds"
                    elif (now - times[-1]).total_seconds() > 120:
                        reason = "No measurement activity for more than 120 seconds"
                    elif (now - times[0]).total_seconds() > duration + 90:
                        reason = "Wall clock and the measured window diverged by more than 90 seconds"
                elif (now - created).total_seconds() > 120:
                    reason = "Browser warmup did not finish within 120 seconds"
                if reason:
                    (destination / "watchdog.json").write_text(json.dumps({
                        "valid": False, "reason": reason, "at": utc()}, indent=2), encoding="utf-8")
                    ids = execute(["docker", "ps", "--filter",
                        f"label=com.docker.compose.project={project}", "--filter",
                        "label=com.docker.compose.service=browser", "--format", "{{.ID}}"]).splitlines()
                    if ids:
                        execute(["docker", "stop", "--time", "5", *ids], timeout=45)
                    process.wait(timeout=30)
                    raise RuntimeError(reason)
            return process.returncode
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=900)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--start-window", type=int, choices=range(1, 7), default=1)
    args = parser.parse_args()
    if args.duration != 900 and not args.smoke:
        parser.error("Formal windows must be 900 seconds; use --smoke for a short preflight")
    if args.duration < 1:
        parser.error("duration must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = utc()
    project = "ruby-functional-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    defense_image = execute(["docker", "image", "inspect", DEFENSE_IMAGE, "--format", "{{.Id}}"])
    hashes = {}
    for relative in ("defense/app/main.py", "defense/app/path_alias.py",
                     "defense/config/juice-shop-routes.json",
                     "benchmark/experiments/path_alias_ab/functional_browser.cjs"):
        hashes[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    selected = list(enumerate(ORDER, 1))[args.start_window - 1:]
    awake = False
    if os.name == "nt":
        awake = bool(ctypes.windll.kernel32.SetThreadExecutionState(0x80000001))
    manifest = {"startedAt": started, "formal": not args.smoke, "durationSecondsPerArm": args.duration,
                "order": [item for _, item in selected], "startWindow": args.start_window,
                "windowsExpected": len(selected), "sleepInhibitionEnabled": awake,
                "activityGapLimitSeconds": 120,
                "targetImage": TARGET_IMAGE, "defenseImage": defense_image,
                "browserImage": BROWSER_IMAGE, "dockerVersion": execute(["docker", "--version"]),
                "gitHead": execute(["git", "rev-parse", "HEAD"]), "sourceSha256": hashes,
                "limits": ["Functional checks only; no autonomous attack execution",
                           "SQLite storage; PostgreSQL performance is not covered",
                           "Anonymous users; authenticated shopping and cart flows are not covered",
                           "One window per scenario and arm; no statistical replication",
                           "Epoch 1800 seconds; 900-second windows do not measure time-based expiry"]}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    results = []
    progress = output / "progress.json"
    active_config = None
    try:
        for index, (scenario, arm) in selected:
            destination = output / f"{index:02d}-{scenario}-{arm}"
            destination.mkdir()
            mode = "off" if arm == "A" else "enforce"
            config = destination / "compose.json"
            config.write_text(json.dumps(compose(project, mode, scenario, args.duration, destination,
                                                defense_image), indent=2), encoding="utf-8")
            active_config = config
            command = ["docker", "compose", "-f", str(config)]
            status = {"state": "starting", "index": index, "scenario": scenario, "arm": arm,
                      "completedWindows": len(results), "updatedAt": utc()}
            progress.write_text(json.dumps(status, indent=2), encoding="utf-8")
            print(json.dumps(status), flush=True)
            execute(command + ["up", "-d", "--wait", "--wait-timeout", "120"], timeout=180)
            preflight = execute(command + ["exec", "-T", "defense", "python", "-c",
                "import httpx,json; c=httpx.Client(base_url='http://127.0.0.1:8080'); "
                "print(json.dumps({p:c.get(p).status_code for p in "
                "['/healthz','/__defense/dashboard','/__defense/api/snapshot']}))"])
            checks = json.loads(preflight)
            if checks != {"/healthz": 200, "/__defense/dashboard": 404, "/__defense/api/snapshot": 404}:
                raise RuntimeError(f"Invalid preflight: {checks}")
            (destination / "preflight.json").write_text(preflight + "\n", encoding="utf-8")
            status.update(state="running", updatedAt=utc())
            progress.write_text(json.dumps(status, indent=2), encoding="utf-8")
            print(json.dumps(status), flush=True)
            code = execute_window(command + ["run", "--rm", "--no-deps", "browser"],
                                  args.duration, destination, project)
            log = execute(command + ["logs", "--no-color", "defense"])
            (destination / "defense.log").write_text(log + "\n", encoding="utf-8")
            summary_path = destination / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {
                "complete": False, "fatal": "Browser runner produced no summary"}
            result = {"index": index, "scenario": scenario, "arm": arm, "exitCode": code,
                      "rotationCountsIncludingWarmup": rotation_counts(log), **summary}
            results.append(result)
            (output / "comparison.json").write_text(json.dumps({"complete": False,
                "startedAt": started, "results": results}, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"state": "window_complete", **result}), flush=True)
            # This project belongs exclusively to this runner. No named volumes or shared target.
            execute(command + ["--profile", "runner", "down", "--timeout", "10"], timeout=90)
            active_config = None
            if not summary.get("complete"):
                raise RuntimeError("Incomplete browser window; stopping rather than relabeling it")
        comparison = {"complete": True, "startedAt": started, "endedAt": utc(), "results": results}
        (output / "comparison.json").write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
        progress.write_text(json.dumps({"state": "complete", "completedWindows": len(selected),
                                       "updatedAt": utc()}, indent=2), encoding="utf-8")
        print(json.dumps({"state": "complete", "output": str(output)}), flush=True)
        return 0 if all(x["exitCode"] == 0 for x in results) else 1
    except Exception as error:
        progress.write_text(json.dumps({"state": "failed", "error": str(error),
                                       "completedWindows": len(results), "updatedAt": utc()}, indent=2),
                            encoding="utf-8")
        print(json.dumps({"state": "failed", "error": str(error)}), flush=True)
        raise
    finally:
        if awake:
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
        if active_config is not None:
            execute(["docker", "compose", "-f", str(active_config), "--profile", "runner",
                     "down", "--timeout", "10"], timeout=90)


if __name__ == "__main__":
    raise SystemExit(main())
