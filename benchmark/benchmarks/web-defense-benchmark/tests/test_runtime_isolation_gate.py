from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "app" / "tools"))

from check_runtime_isolation_gate import (  # noqa: E402
    POLICY_PATH,
    gate_checks,
    load_policy,
    public_bind_mounts,
    required_checks_passed,
    security_observation,
    static_compose_contracts,
)


def hardened_inspect() -> dict[str, object]:
    return {
        "Id": "a" * 64,
        "Image": "sha256:" + "b" * 64,
        "Config": {
            "Image": "vendor/product@sha256:" + "c" * 64,
            "Labels": {"com.docker.compose.service": "target"},
        },
        "HostConfig": {
            "Privileged": False,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 256,
            "Memory": 512 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "NetworkMode": "project_target",
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "Devices": [],
            "Binds": None,
            "PortBindings": {},
            "ReadonlyRootfs": False,
        },
        "Mounts": [],
        "NetworkSettings": {
            "Networks": {"project_target": {"Gateway": "172.30.0.1"}}
        },
    }


class RuntimeIsolationGateTests(unittest.TestCase):
    def test_skipped_defense_gate_is_not_recorded_as_a_defense_pass(self) -> None:
        checks = gate_checks(
            static_results=[{"passed": True}],
            target_results=[{"passed": True}],
            defense_results=[],
            expected_target_runs=1,
            skip_defenses=True,
            canary_cleanup=True,
        )

        self.assertFalse(checks["managed_defenses_executed"])
        self.assertIsNone(checks["all_managed_defenses_passed"])
        self.assertTrue(required_checks_passed(checks, skip_defenses=True))

    def test_required_defense_gate_rejects_an_empty_result(self) -> None:
        checks = gate_checks(
            static_results=[{"passed": True}],
            target_results=[{"passed": True}],
            defense_results=[],
            expected_target_runs=1,
            skip_defenses=False,
            canary_cleanup=True,
        )

        self.assertTrue(checks["managed_defenses_executed"])
        self.assertFalse(checks["all_managed_defenses_passed"])
        self.assertFalse(required_checks_passed(checks, skip_defenses=False))

    def test_public_bind_mounts_remove_host_paths(self) -> None:
        result = public_bind_mounts(
            [r"C:\private\workspace\relay.conf:/etc/nginx/conf.d/default.conf:ro"]
        )
        self.assertEqual(
            [{"target": "/etc/nginx/conf.d/default.conf", "mode": "ro"}],
            result,
        )
        self.assertNotIn("private", str(result))

    def test_policy_covers_every_registered_original_target_and_both_releases(self) -> None:
        policy = load_policy(POLICY_PATH)
        self.assertEqual(5, len(policy["original_cve_targets"]))
        self.assertTrue(
            all(item["releases"] == ["vulnerable", "fixed"] for item in policy["original_cve_targets"])
        )
        self.assertRegex(str(policy["probe_image"]), r"@sha256:[a-f0-9]{64}$")

    def test_all_original_cve_compose_files_pass_static_isolation_contract(self) -> None:
        results = static_compose_contracts(load_policy(POLICY_PATH))
        self.assertEqual(5, len(results))
        self.assertTrue(all(item["passed"] for item in results), results)

    @patch("check_runtime_isolation_gate.network_inspect")
    def test_hardened_target_inspect_passes_all_static_checks(self, inspect_network) -> None:
        inspect_network.return_value = {"Internal": True}
        result = security_observation(
            hardened_inspect(),
            allowed_cap_add=[],
            maximum_pids=512,
            require_read_only=False,
            require_pinned_image=True,
            require_no_ports=True,
            require_internal_networks=True,
        )
        self.assertTrue(result["passed"], result["checks"])

    @patch("check_runtime_isolation_gate.network_inspect")
    def test_unapproved_capability_bind_mount_port_and_external_network_fail(self, inspect_network) -> None:
        inspect_network.return_value = {"Internal": False}
        value = copy.deepcopy(hardened_inspect())
        value["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
        value["HostConfig"]["Binds"] = ["/var/run/docker.sock:/var/run/docker.sock"]
        value["HostConfig"]["PortBindings"] = {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
        value["Mounts"] = [
            {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}
        ]
        result = security_observation(
            value,
            allowed_cap_add=[],
            maximum_pids=512,
            require_read_only=False,
            require_pinned_image=True,
            require_no_ports=True,
            require_internal_networks=True,
        )
        for check in (
            "capability_additions_allowlisted",
            "no_host_bind_mount",
            "no_docker_socket",
            "no_published_ports",
            "networks_internal",
        ):
            self.assertFalse(result["checks"][check])
        self.assertFalse(result["passed"])

    @patch("check_runtime_isolation_gate.network_inspect")
    def test_docker_cap_prefix_matches_compose_allowlist(self, inspect_network) -> None:
        inspect_network.return_value = {"Internal": True}
        value = hardened_inspect()
        value["HostConfig"]["CapAdd"] = ["CAP_CHOWN", "CAP_SETUID"]
        result = security_observation(
            value,
            allowed_cap_add=["CHOWN", "SETUID"],
            maximum_pids=512,
            require_read_only=False,
            require_pinned_image=True,
            require_no_ports=True,
            require_internal_networks=True,
        )
        self.assertTrue(result["checks"]["capability_additions_allowlisted"])
        self.assertTrue(result["passed"], result["checks"])


if __name__ == "__main__":
    unittest.main()
