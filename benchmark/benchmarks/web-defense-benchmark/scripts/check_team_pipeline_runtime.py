"""Bounded, non-exploit runtime check of the current Detection/Defense/RUBY chain.

Creates only uniquely named local Docker resources. No vulnerable mode, attack agent,
working exploit, team server access, image publication, or GitHub mutation is used.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import http.cookiejar as cookiejar
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


BENCHMARK = Path(__file__).resolve().parents[1]
REPOSITORY = BENCHMARK.parents[2]
APP = BENCHMARK / "app"
OBSERVER = APP / "tools" / "team_pipeline_observer.py"


def command(args, *, env=None, timeout=300):
    result = subprocess.run(args, cwd=REPOSITORY, env=env, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr[-1800:]}")
    return result.stdout.strip()


def docker(*args, env=None, timeout=300):
    return command(["docker", *args], env=env, timeout=timeout)


def check(name, condition, checks):
    checks[name] = bool(condition)
    print(json.dumps({"check": name, "passed": bool(condition)}), flush=True)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; refusing to replace an earlier result")
    run_id = "ruby-prcheck-" + secrets.token_hex(5)
    network = run_id + "-pipeline"
    prefix = run_id
    env = os.environ.copy()
    sha = command(["git", "rev-parse", "HEAD"])
    env.update({
        "RUBY_BENCHMARK_IMAGE_PREFIX": prefix,
        "RUBY_BENCHMARK_IMAGE_TAG": sha[:12],
        "RUBY_BENCHMARK_PIPELINE_NETWORK": network,
        "RUBY_WEB_PUBLIC_ORIGIN": "http://ruby-web-target:8080",
        "RUBY_WEB_VULNERABILITY_MODULES": "",
        "RUBY_WEB_TRIAL_ID": "",
        "RUBY_WEB_PREPARATION_SEED": "",
        "DETECTION_DASHBOARD_PASSWORD": secrets.token_hex(24),
        "ACCOUNT_ID_HASH_KEY": secrets.token_hex(32),
    })
    secret_names = ["POSTGRES_PASSWORD", "POSTGRES_APP_PASSWORD", "POSTGRES_UNTRUSTED_PASSWORD",
                    "POSTGRES_VERIFIER_PASSWORD", "RUBY_WEB_OBJECT_ACCESS_KEY", "RUBY_WEB_OBJECT_SECRET_KEY",
                    "RUBY_WEB_RESET_TOKEN", "RUBY_EVALUATOR_TOKEN", "RUBY_WEB_OPERATIONS_DIAGNOSTIC_KEY"]
    env.update({name: secrets.token_hex(20) for name in secret_names})
    compose = ["compose", "-p", run_id, "-f", str(APP / "compose.production.yaml")]
    checks = {}
    report = {"report_version": 1, "source_commit": sha, "run_id": run_id,
              "started_at": datetime.now(UTC).isoformat(),
              "policy_configuration": json.loads((REPOSITORY / "detection/config/policy.json").read_text(encoding="utf-8")),
              "test_configuration": {"target_mode": "normal", "vulnerable_modules": [],
                                     "automation_requests": 8, "detection_level": "medium",
                                     "crs_enabled": True, "block_mode": False,
                                     "listener": "random loopback-only port", "secret_values": "ephemeral, omitted"},
              "test_scope": "benign requests, inert marker, real policy and delay execution",
              "source_inputs": {}, "checks": checks, "images": {}, "requests": [],
              "limits": ["No exploit reproduction or attack-success/blocking-effect measurement.",
                         "No team server deployment or end-to-end server test.",
                         "Defense observer records real calls; it does not replace their implementation.",
                         "Direct 200/300/500ms plans test Defense contracts, not detector recall."]}
    for path in [REPOSITORY / "detection/config/policy.json", REPOSITORY / "docker-compose.yml",
                 APP / "compose.production.yaml", OBSERVER, Path(__file__).resolve()]:
        report["source_inputs"][str(path.relative_to(REPOSITORY)).replace("\\", "/")] = hashlib.sha256(path.read_bytes()).hexdigest()
    containers = []
    network_created = False
    compose_started = False
    defense = run_id + "-defense"
    detection = run_id + "-detection"
    try:
        contexts = {"benchmark-web-postgres": APP / "postgres", "benchmark-web-redis": APP / "redis",
                    "benchmark-web-object-store": APP / "object-store", "benchmark-web-mock-integration": APP / "mock-integration",
                    "benchmark-web-api": APP / "backend", "benchmark-web-evaluator": APP / "evaluator",
                    "benchmark-web-frontend": APP / "frontend", "detection": REPOSITORY / "detection",
                    "defense": REPOSITORY / "defense"}
        for name, context in contexts.items():
            print(f"Building current source: {name}", flush=True)
            tag = f"{prefix}/{name}:{sha[:12]}"
            docker("build", "--quiet", "--label", f"org.opencontainers.image.revision={sha}",
                   "--tag", tag, str(context), timeout=1200)
            report["images"][name] = json.loads(docker("image", "inspect", tag))[0]["Id"]
        docker("network", "create", "--label", f"ruby.integration-check={run_id}", network)
        network_created = True
        compose_started = True
        print("Starting isolated production RUBY services", flush=True)
        docker(*compose, "up", "-d", "--wait", "--wait-timeout", "120", env=env)
        docker("run", "-d", "--name", defense, "--label", f"ruby.integration-check={run_id}",
               "--network", network, "--network-alias", "defense",
               "-e", "BENCHMARK_TARGET_URL=http://ruby-web-target:8080",
               "-e", "PYTHONPATH=/app", "--mount", f"type=bind,src={OBSERVER},dst=/opt/observer.py,readonly",
               f"{prefix}/defense:{sha[:12]}", "python", "/opt/observer.py")
        containers.append(defense)
        env["DCID_HMAC_SECRET"] = secrets.token_hex(32)
        env["PAYLOAD_FINGERPRINT_KEY"] = secrets.token_hex(32)
        docker("run", "-d", "--name", detection, "--label", f"ruby.integration-check={run_id}",
               "--network", network, "--network-alias", "detection", "-p", "127.0.0.1::8080",
               "-e", "NODE_ENV=production", "-e", "TARGET_URL=http://defense:8080",
               "-e", "PORT=8080", "-e", "BLOCK_MODE=false",
               "-e", "DETECTION_LEVEL=medium", "-e", "CRS_ENABLED=true", "-e", "CRS_SCAN_TIMEOUT_MS=2000",
               "-e", "CRS_MAX_BODY_BYTES=1048576", "-e", "DECEPTION_ENABLED=true",
               "-e", "ENABLE_EXPERIMENT_RUN_ID=true", "-e", "TRUST_PROXY=false",
               "-e", "ALLOW_INSECURE_DASHBOARD_HTTP=true",
               "-e", "DETECTION_DASHBOARD_COOKIE_SECURE=false",
               "-e", "DETECTION_DASHBOARD_REQUIRE_HTTPS=false",
               "-e", "CSRF_ALLOWED_ORIGINS=http://ruby-web-target:8080",
               "-e", "DCID_HMAC_SECRET", "-e", "PAYLOAD_FINGERPRINT_KEY",
               "-e", "ACCOUNT_ID_HASH_KEY", "-e", "DETECTION_DASHBOARD_PASSWORD",
               f"{prefix}/detection:{sha[:12]}", env=env)
        containers.append(detection)
        inspection = json.loads(docker("inspect", detection))[0]
        port = inspection["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
        origin = "http://127.0.0.1:" + port

        def http(path, *, client=None, headers=None, data=None):
            req = urllib.request.Request(origin + path, headers=headers or {}, data=data)
            started = time.perf_counter()
            try:
                response = (client or urllib.request.build_opener(urllib.request.ProxyHandler({}))).open(req, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            body = response.read()
            return {"status": response.status, "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                    "body": body, "headers": dict(response.headers)}

        for attempt in range(30):
            try:
                if http("/healthz")["status"] == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError("isolated Detection did not become ready")
        browser = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookiejar.CookieJar()))
        check("operator_api_rejects_anonymous_requests", http("/__detection/api/sessions")["status"] == 401, checks)
        login = http(
            "/__detection/api/login",
            client=browser,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"password": env["DETECTION_DASHBOARD_PASSWORD"]}).encode(),
        )
        check("operator_login_accepts_isolated_secret", login["status"] == 204, checks)
        check("operator_api_accepts_authenticated_requests", http("/__detection/api/sessions", client=browser)["status"] == 200, checks)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36",
                   "Accept-Language": "ko-KR", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
                   "Sec-Fetch-Dest": "empty", "X-Experiment-Run-ID": run_id}
        public = http("/api/products?ruby_check=normal-products", client=browser, headers=headers)
        check("normal_products_through_full_chain", public["status"] == 200 and isinstance(json.loads(public["body"]), list), checks)
        home = http("/?ruby_check=normal-home", client=browser, headers=headers)
        check("frontend_through_full_chain", home["status"] == 200 and b'id="root"' in home["body"], checks)
        check("telemetry_in_real_html", b"/__detection/static/telemetry.js" in home["body"], checks)
        for key in ["body", "headers"]:
            public.pop(key)
        report["requests"].append({"case": "normal-products", **public})
        automation = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookiejar.CookieJar()))
        automated_headers = {"User-Agent": "python-urllib/3.13", "X-Experiment-Run-ID": run_id}
        for index in range(8):
            case = f"automation-{index}"
            response = http("/api/products?ruby_check=" + case, client=automation, headers=automated_headers)
            report["requests"].append({"case": case, "status": response["status"], "elapsed_ms": response["elapsed_ms"]})
        # Literal template-looking text, not a working expression or exploit.
        marker = urllib.parse.urlencode({"q": "{{RUBY_TEST_TEXT}}", "ruby_check": "inert-marker"})
        response = http("/api/products?" + marker, client=automation, headers=automated_headers)
        check("inert_marker_keeps_normal_web_response", response["status"] == 200, checks)
        observed = json.loads(http("/__detection/api/sessions", client=browser)["body"])
        summaries = []
        for session in observed:
            if not session.get("features", {}).get("totalRequests"):
                continue
            details = json.loads(http("/__detection/api/sessions/" + session["sessionId"], client=browser)["body"])
            summaries.append({key: details.get(key) for key in ["automationScore", "attackScore", "detection", "attackHistory", "features", "requests"]})
        report["detection_observations"] = summaries
        report["crs_status"] = json.loads(http("/__detection/api/crs-status", client=browser)["body"])
        check("automation_score_recorded", any((s.get("automationScore") or 0) > 0.2 for s in summaries), checks)
        marker_records = [row for session in summaries for row in session.get("requests", [])
                          if "ruby_check=inert-marker" in row.get("url", "")]
        # The inert text is not ground truth for an attack category. Verify that
        # the real scanner result survives the pipeline, without assuming its label.
        check("inert_marker_crs_result_recorded", bool(marker_records) and all(
            row.get("attackDetection", {}).get("available") for row in marker_records), checks)
        report["operator_api_public_at_detection_entry"] = http("/__detection/api/sessions")["status"] == 200

        # Exercise existing Defense strategies over real HTTP, from the trusted test controller only.
        direct_code = """import json,time,urllib.request
results=[]
for delay in [0,200,300,500]:
 plan=[] if delay==0 else [{'name':'delay','params':{'delay_ms':delay}}]
 req=urllib.request.Request('http://127.0.0.1:8080/api/products?ruby_check=direct-'+str(delay),headers={'X-Defense-Plan':json.dumps(plan),'X-Client-Id':'trusted-runtime-check'})
 start=time.perf_counter()
 with urllib.request.urlopen(req,timeout=10) as res:
  body=json.loads(res.read()); results.append({'delay_ms':delay,'status':res.status,'products':len(body),'elapsed_ms':round((time.perf_counter()-start)*1000,3)})
print(json.dumps(results))
"""
        report["direct_defense"] = json.loads(docker("exec", defense, "python", "-c", direct_code))
        check("all_default_delay_tiers_forward_normal_requests", all(row["status"] == 200 for row in report["direct_defense"]), checks)
        logs = docker("logs", defense)
        audit = [json.loads(line.split("RUBY_PIPELINE_AUDIT ", 1)[1]) for line in logs.splitlines() if "RUBY_PIPELINE_AUDIT " in line]
        report["defense_observations"] = audit
        full_chain = [row for row in audit if row["kind"] == "request" and row["case"].startswith("automation-")]
        check("detection_generated_real_defense_plan", any(row["plan"] for row in full_chain), checks)
        check("client_identity_reaches_defense", bool(full_chain) and all(row["client_id_present"] for row in full_chain), checks)
        live_delays = [row for row in audit if row["kind"] == "delay" and row["case"].startswith("automation-")]
        check("live_chain_executes_real_delay", bool(live_delays) and all(row["elapsed_ms"] >= row["configured_ms"] - 5 for row in live_delays), checks)
        direct_delays = [row for row in audit if row["kind"] == "delay" and row["case"].startswith("direct-")]
        check("200_300_500ms_real_delay_verified", len(direct_delays) == 3 and all(row["elapsed_ms"] >= row["configured_ms"] - 5 for row in direct_delays), checks)
        evaluator_env = {**env, "RUBY_COMPOSE_PROJECT": run_id, "RUBY_COMPOSE_FILE": str(APP / "compose.production.yaml")}
        report["synthetic_evaluator_contract"] = json.loads(command([sys.executable, str(APP / "tools/check_private_evaluator.py")], env=evaluator_env))
        check("private_evaluator_synthetic_event_contract", report["synthetic_evaluator_contract"]["passed"], checks)
        ids = docker(*compose, "ps", "-q", env=env).splitlines()
        info = json.loads(docker("inspect", *ids))
        exposed = [item["Config"]["Labels"]["com.docker.compose.service"] for item in info if network in item["NetworkSettings"]["Networks"]]
        check("only_web_joins_pipeline", exposed == ["web"], checks)
        report["runtime_contract_passed"] = all(checks.values())
        report["pr_ready"] = report["runtime_contract_passed"] and not report["operator_api_public_at_detection_entry"]
    except Exception as error:
        report["error"] = str(error)
        report["runtime_contract_passed"] = False
        report["pr_ready"] = False
    finally:
        cleanup_errors = []
        for name in reversed(containers):
            try:
                meta = json.loads(docker("inspect", name))[0]
                if meta["Config"]["Labels"].get("ruby.integration-check") != run_id:
                    raise RuntimeError("refusing cleanup of a container with a different ownership label")
                docker("rm", "-f", name)
            except Exception as error:
                cleanup_errors.append(str(error))
        if compose_started:
            try:
                docker(*compose, "down", "--volumes", "--remove-orphans", env=env)
            except Exception as error:
                cleanup_errors.append(str(error))
        if network_created:
            try:
                net = json.loads(docker("network", "inspect", network))[0]
                if net["Labels"].get("ruby.integration-check") != run_id or net["Containers"]:
                    raise RuntimeError("refusing cleanup of an unowned or occupied network")
                docker("network", "rm", network)
            except Exception as error:
                cleanup_errors.append(str(error))
        report["cleanup"] = {"passed": not cleanup_errors, "errors": cleanup_errors}
        report["finished_at"] = datetime.now(UTC).isoformat()
        if cleanup_errors:
            report["pr_ready"] = False
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(args.output), "runtime_contract_passed": report.get("runtime_contract_passed"),
                          "pr_ready": report.get("pr_ready"), "error": report.get("error"), "cleanup": report["cleanup"]}, ensure_ascii=False), flush=True)
    return 0 if report.get("pr_ready") else 1


if __name__ == "__main__":
    raise SystemExit(main())
