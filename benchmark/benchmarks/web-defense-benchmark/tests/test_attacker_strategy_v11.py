from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from attacker_strategy_v11 import build_strategy_state
from autonomous_experiment_v2 import TrialMetrics
from autonomous_trial_v2 import run_autonomous_trial
from run_autonomous_campaign_v3 import _schedule


class AttackerStrategyV11Test(unittest.TestCase):
    def test_v13_profile_exposes_frontier_without_legacy_route_controls(self) -> None:
        captured: list[dict[str, object]] = []
        executor = SimpleNamespace(
            target_origin="http://target.invalid",
            metrics=TrialMetrics(),
            execute_actions=lambda actions: [],
            set_active_request_budget=lambda limit: None,
            budget_exhausted=False,
        )
        target = SimpleNamespace(
            accounts=[],
            secrets=[],
            normal_traffic={},
            executor=executor,
            attacker_mailboxes=lambda: [],
            evaluate=lambda: {"objective_achieved": False},
            close=lambda: None,
        )

        def policy(payload: dict[str, object]) -> dict[str, object]:
            captured.append(payload)
            return {
                "actions": [],
                "stop": True,
                "summary": "no executable public evidence remains",
                "memory": {
                    "observations": [],
                    "hypotheses": [],
                    "failed_attempts": [],
                    "next_steps": [],
                },
            }

        report = run_autonomous_trial(
            target_id="synthetic",
            target_kind="ruby-web",
            prepare_target=lambda runtime_id, seed: target,
            policy=policy,
            normal_traffic_seed=1,
            attacker_profile_path=Path(
                "app/configs/stage3a-autonomous-web-attacker-profile-v13.json"
            ),
            max_decisions=1,
        )
        execution_state = captured[0]["execution_state"]
        self.assertEqual(
            "ruby-stage3a-autonomous-web-attacker-v13",
            report["attacker_profile_id"],
        )
        self.assertIn("strategy_state_v13", execution_state)
        self.assertEqual([], execution_state["lane_priorities"])
        self.assertEqual([], execution_state["balanced_route_groups"])
        self.assertNotIn("synthetic", str(captured[0]))

    def test_v12_uses_generic_strategy_without_legacy_route_controls(self) -> None:
        captured: list[dict[str, object]] = []
        executor = SimpleNamespace(
            target_origin="http://target.invalid",
            metrics=TrialMetrics(),
            execute_actions=lambda actions: [],
            set_active_request_budget=lambda limit: None,
            budget_exhausted=False,
        )
        target = SimpleNamespace(
            accounts=[],
            secrets=[],
            normal_traffic={},
            executor=executor,
            attacker_mailboxes=lambda: [],
            evaluate=lambda: {"objective_achieved": False},
            close=lambda: None,
        )

        def policy(payload: dict[str, object]) -> dict[str, object]:
            captured.append(payload)
            return {
                "actions": [],
                "stop": True,
                "summary": "no public evidence remains",
                "memory": {
                    "observations": [],
                    "hypotheses": [],
                    "failed_attempts": [],
                    "next_steps": [],
                },
            }

        report = run_autonomous_trial(
            target_id="synthetic",
            target_kind="ruby-web",
            prepare_target=lambda runtime_id, seed: target,
            policy=policy,
            normal_traffic_seed=1,
            attacker_profile_path=Path(
                "app/configs/stage3a-autonomous-web-attacker-profile-v12.json"
            ),
            max_decisions=1,
        )
        execution_state = captured[0]["execution_state"]
        self.assertEqual(
            "ruby-stage3a-autonomous-web-attacker-v12",
            report["attacker_profile_id"],
        )
        self.assertIn("strategy_state_v12", execution_state)
        self.assertNotIn("strategy_state_v11", execution_state)
        self.assertEqual([], execution_state["lane_priorities"])
        self.assertEqual([], execution_state["balanced_route_groups"])
        self.assertIn("Generic Web Attacker v12", captured[0]["attacker_guide"])
        self.assertNotIn("synthetic", str(captured[0]))

    def test_v11_profile_selects_separate_guide_and_strategy_payload(self) -> None:
        captured: list[dict[str, object]] = []
        executor = SimpleNamespace(
            target_origin="http://target.invalid",
            metrics=TrialMetrics(),
            execute_actions=lambda actions: [],
            set_active_request_budget=lambda limit: None,
            budget_exhausted=False,
        )
        target = SimpleNamespace(
            accounts=[{"email": "user", "password": "secret", "role": "member"}],
            secrets=["secret"],
            normal_traffic={},
            executor=executor,
            attacker_mailboxes=lambda: [],
            evaluate=lambda: {"objective_achieved": False},
            close=lambda: None,
        )

        def policy(payload: dict[str, object]) -> dict[str, object]:
            captured.append(payload)
            return {
                "actions": [],
                "stop": True,
                "summary": "no evidence remains",
                "memory": {
                    "observations": [],
                    "hypotheses": [],
                    "failed_attempts": [],
                    "next_steps": [],
                },
            }

        profile = Path("app/configs/stage3a-autonomous-web-attacker-profile-v11.json")
        report = run_autonomous_trial(
            target_id="synthetic",
            target_kind="ruby-web",
            prepare_target=lambda runtime_id, seed: target,
            policy=policy,
            normal_traffic_seed=1,
            attacker_profile_path=profile,
            max_decisions=1,
        )
        self.assertEqual("ruby-stage3a-autonomous-web-attacker-v11", report["attacker_profile_id"])
        self.assertIn("strategy_state_v11", captured[0]["execution_state"])
        self.assertIn("Generic Web Attacker v11", captured[0]["attacker_guide"])
        self.assertEqual([], captured[0]["execution_state"]["balanced_route_groups"])
        self.assertEqual(
            [], captured[0]["execution_state"]["suggested_public_surface_coverage"]
        )

    def test_runtime_invalid_action_is_feedback_not_terminal_runner_error(self) -> None:
        calls = 0
        executor = SimpleNamespace(
            target_origin="http://target.invalid",
            metrics=TrialMetrics(),
            execute_actions=lambda actions: (_ for _ in ()).throw(
                ValueError("only target-relative paths are allowed")
            ),
            set_active_request_budget=lambda limit: None,
            budget_exhausted=False,
        )
        target = SimpleNamespace(
            accounts=[],
            secrets=[],
            normal_traffic={},
            executor=executor,
            attacker_mailboxes=lambda: [],
            evaluate=lambda: {"objective_achieved": False},
            close=lambda: None,
        )

        def policy(payload: dict[str, object]) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {
                "actions": (
                    [
                        {
                            "kind": "http",
                            "session": "anon",
                            "method": "GET",
                            "path": "//invalid.example/path",
                            "headers": None,
                            "body_json": None,
                            "body_form": None,
                            "body_multipart": None,
                            "browser_html": None,
                            "browser_wait_ms": 0,
                            "concurrency_group": None,
                        }
                    ]
                    if calls == 1
                    else []
                ),
                "stop": calls > 1,
                "summary": "local validation feedback handled",
                "memory": {
                    "observations": [],
                    "hypotheses": [],
                    "failed_attempts": [],
                    "next_steps": [],
                },
            }

        report = run_autonomous_trial(
            target_id="synthetic",
            target_kind="ruby-web",
            prepare_target=lambda runtime_id, seed: target,
            policy=policy,
            normal_traffic_seed=1,
            attacker_profile_path=Path(
                "app/configs/stage3a-autonomous-web-attacker-profile-v11.json"
            ),
            max_decisions=2,
        )
        self.assertEqual("attack-failed", report["status"])
        self.assertIsNone(report["runner_error"])
        self.assertEqual(1, report["metrics"]["request_quality_rejections"])
        self.assertEqual(
            "request_quality_rejected", report["interactions"][0]["kind"]
        )

    def test_response_identifier_is_linked_to_public_consumer_and_later_use(self) -> None:
        surfaces = [
            {
                "method": "GET",
                "path": "/v4/records/{record_id}",
                "parameters": [["record_id", "path", "string", None]],
                "request_schemas": [],
            }
        ]
        interactions = [
            {
                "kind": "http",
                "session": "actor_a",
                "method": "POST",
                "path": "/v4/records",
                "status": 201,
                "response": '{"record_id":"r-731","status":"queued"}',
            },
        ]
        state = build_strategy_state(
            surfaces=surfaces,
            interactions=interactions,
            lane_priorities=[],
            accounts=[{"email": "a", "password": "x", "role": "member"}],
            used_requests=20,
            max_requests=100,
        )
        first = state["evidence_chains"][0]
        identifier = next(
            item
            for item in first["public_values"]
            if item["category"] == "object_identifier"
        )
        self.assertFalse(identifier["consumed_later"])
        self.assertEqual(
            [
                {
                    "method": "GET",
                    "path": "/v4/records/r-731",
                    "public_route_template": "/v4/records/{record_id}",
                }
            ],
            identifier["candidate_consumers"],
        )

    def test_html_form_action_becomes_an_exact_typed_consumer(self) -> None:
        surfaces = [
            {
                "method": "POST",
                "path": "/v7/members/{member_id}/setting-form",
                "parameters": [["member_id", "path", "string", None]],
                "request_schemas": [],
            }
        ]
        state = build_strategy_state(
            surfaces=surfaces,
            interactions=[
                {
                    "kind": "http",
                    "session": "reviewer",
                    "method": "GET",
                    "path": "/v7/previews/41",
                    "status": 200,
                    "response": (
                        '<form method="post" '
                        'action="/v7/members/m-92/setting-form"></form>'
                    ),
                }
            ],
            lane_priorities=[],
            accounts=[],
            used_requests=45,
            max_requests=100,
        )
        value = state["evidence_chains"][0]["public_values"][0]
        self.assertEqual("relationship_link", value["category"])
        self.assertEqual(
            [
                {
                    "method": "POST",
                    "path": "/v7/members/m-92/setting-form",
                    "public_route_template": "/v7/members/{member_id}/setting-form",
                }
            ],
            value["candidate_consumers"],
        )

    def test_generic_id_does_not_match_unrelated_id_consumers(self) -> None:
        surfaces = [
            {
                "method": "GET",
                "path": "/v3/invoices/{invoice_id}",
                "parameters": [["invoice_id", "path", "string", None]],
                "request_schemas": [],
            }
        ]
        state = build_strategy_state(
            surfaces=surfaces,
            interactions=[
                {
                    "kind": "http",
                    "session": "member",
                    "method": "POST",
                    "path": "/v3/messages",
                    "status": 201,
                    "response": '{"id":"msg-12"}',
                }
            ],
            lane_priorities=[],
            accounts=[],
            used_requests=25,
            max_requests=100,
        )
        value = state["evidence_chains"][0]["public_values"][0]
        self.assertEqual([], value["candidate_consumers"])

    def test_many_identifiers_do_not_multiply_boolean_evidence_weight(self) -> None:
        surfaces = [
            {
                "method": "GET",
                "path": "/v8/items/{item_id}",
                "parameters": [["item_id", "path", "string", None]],
                "request_schemas": [],
            }
        ]
        response = "[" + ",".join(
            f'{{"item_id":"item-{index}"}}' for index in range(10)
        ) + "]"
        state = build_strategy_state(
            surfaces=surfaces,
            interactions=[
                {
                    "kind": "http",
                    "session": "member",
                    "method": "GET",
                    "path": "/v8/items",
                    "status": 200,
                    "response": response,
                }
            ],
            lane_priorities=[],
            accounts=[],
            used_requests=25,
            max_requests=100,
        )
        self.assertLessEqual(state["evidence_chains"][0]["evidence_score"], 12)

    def test_session_bound_authorization_artifact_closes_after_successful_use(self) -> None:
        state = build_strategy_state(
            surfaces=[],
            interactions=[
                {
                    "kind": "http",
                    "session": "member",
                    "method": "POST",
                    "path": "/v2/session/start",
                    "status": 200,
                    "response": '{"token":"opaque"}',
                },
                {
                    "kind": "http",
                    "session": "member",
                    "method": "GET",
                    "path": "/v2/profile",
                    "status": 200,
                    "response": '{"name":"member"}',
                },
            ],
            lane_priorities=[],
            accounts=[],
            used_requests=15,
            max_requests=100,
        )
        self.assertEqual([], state["evidence_chains"])

    def test_unverified_state_change_ranks_above_catalog_identifiers(self) -> None:
        surfaces = [
            {
                "method": "GET",
                "path": "/v6/items/{item_id}",
                "parameters": [["item_id", "path", "string", None]],
                "request_schemas": [],
            }
        ]
        state = build_strategy_state(
            surfaces=surfaces,
            interactions=[
                {
                    "kind": "http",
                    "session": "member",
                    "method": "GET",
                    "path": "/v6/items",
                    "status": 200,
                    "response": '[{"item_id":"a"},{"item_id":"b"}]',
                },
                {
                    "kind": "http",
                    "session": "reviewer",
                    "method": "POST",
                    "path": "/v6/preferences/remember",
                    "status": 204,
                    "response": "",
                },
            ],
            lane_priorities=[],
            accounts=[],
            used_requests=60,
            max_requests=100,
        )
        self.assertEqual(
            "/v6/preferences/remember", state["evidence_chains"][0]["path"]
        )

    def test_successful_post_without_state_evidence_is_not_a_state_change(self) -> None:
        state = build_strategy_state(
            surfaces=[],
            interactions=[
                {
                    "kind": "http",
                    "session": "reviewer",
                    "method": "POST",
                    "path": "/v5/tools/convert",
                    "status": 200,
                    "response": '{"lines":["plain output"]}',
                }
            ],
            lane_priorities=[],
            accounts=[],
            used_requests=45,
            max_requests=100,
        )
        self.assertEqual([], state["evidence_chains"])

    def test_capabilities_require_public_activation_evidence(self) -> None:
        state = build_strategy_state(
            surfaces=[],
            interactions=[
                {
                    "kind": "http",
                    "session": "actor_a",
                    "method": "GET",
                    "path": "/x",
                    "status": 200,
                    "response": '{"message":"ok"}',
                }
            ],
            lane_priorities=[],
            accounts=[{"email": "a", "password": "x", "role": "member"}],
            used_requests=10,
            max_requests=100,
        )
        self.assertEqual([], state["capability_opportunities"])

    def test_finite_state_activates_concurrency_without_route_name_dependency(self) -> None:
        def capabilities(prefix: str) -> set[str]:
            state = build_strategy_state(
                surfaces=[],
                interactions=[
                    {
                        "kind": "http",
                        "session": "actor_a",
                        "method": "POST",
                        "path": f"/{prefix}/apply",
                        "status": 200,
                        "response": '{"remaining":2,"state":"open"}',
                    }
                ],
                lane_priorities=[],
                accounts=[{"email": "a", "password": "x", "role": "member"}],
                used_requests=50,
                max_requests=100,
            )
            return {
                str(item["capability"])
                for item in state["capability_opportunities"]
            }

        self.assertIn("atomic_concurrency", capabilities("alpha"))
        self.assertEqual(capabilities("alpha"), capabilities("renamed-zone"))

    def test_only_three_evidence_backed_hypotheses_are_kept(self) -> None:
        priorities = [
            {
                "group": f"lane-{index}",
                "evidence_score": 20 - index,
                "strong_evidence_score": 10,
                "verification_debt": index == 0,
                "requests_since_material_evidence": index,
            }
            for index in range(5)
        ]
        state = build_strategy_state(
            surfaces=[],
            interactions=[],
            lane_priorities=priorities,
            accounts=[],
            used_requests=75,
            max_requests=100,
        )
        self.assertEqual("effect-closure", state["phase"])
        self.assertEqual(3, len(state["ranked_hypotheses"]))
        self.assertEqual("needs_closure", state["ranked_hypotheses"][0]["status"])

    def test_v12_ignores_legacy_lane_scores_and_field_name_attack_hints(self) -> None:
        def state(field_name: str) -> dict[str, object]:
            return build_strategy_state(
                surfaces=[
                    {
                        "method": "POST",
                        "path": "/v4/submit",
                        "parameters": [[field_name, "query", "string", None]],
                        "request_schemas": [
                            ["application/json", None, [field_name], [field_name]]
                        ],
                    }
                ],
                interactions=[],
                lane_priorities=[
                    {
                        "group": "keyword-derived-lane",
                        "priority_score": 999,
                        "evidence_score": 999,
                        "strong_evidence_score": 999,
                        "verification_debt": True,
                        "requests_since_material_evidence": 0,
                    }
                ],
                accounts=[],
                used_requests=10,
                max_requests=100,
                version=2,
            )

        hinted = state("password_file_url_token")
        neutral = state("input_value")
        self.assertEqual([], hinted["ranked_hypotheses"])
        self.assertEqual(
            [item["input_class"] for item in neutral["coverage_obligations"]],
            [item["input_class"] for item in hinted["coverage_obligations"]],
        )
        self.assertEqual(
            {"query_parameter", "structured_body"},
            {
                item["input_class"]
                for item in hinted["coverage_obligations"]
            },
        )

    def test_v12_counts_only_the_input_form_that_was_actually_exercised(self) -> None:
        surface = {
            "method": "POST",
            "path": "/v4/submit",
            "parameters": [["value", "query", "string", None]],
            "request_schemas": [
                ["application/json", None, ["value"], ["value"]]
            ],
        }
        state = build_strategy_state(
            surfaces=[surface],
            interactions=[
                {
                    "kind": "http",
                    "session": "member",
                    "method": "POST",
                    "path": "/v4/submit",
                    "request": {"body_mode": "json", "body": {"value": "x"}},
                    "status": 200,
                    "response": '{"message":"accepted"}',
                }
            ],
            lane_priorities=[],
            accounts=[],
            used_requests=1,
            max_requests=100,
            version=2,
        )
        self.assertEqual(1, state["input_class_coverage"]["structured_body"])
        self.assertEqual(0, state["input_class_coverage"]["query_parameter"])
        self.assertEqual(
            ["query_parameter"],
            [item["input_class"] for item in state["coverage_obligations"]],
        )

    def test_v13_frontier_rotates_structural_classes_without_field_semantics(self) -> None:
        surfaces = [
            {
                "method": "GET",
                "path": "/v1/alpha",
                "parameters": [["password_file_url_token", "query", "string", None]],
                "request_schemas": [],
            },
            {
                "method": "GET",
                "path": "/v1/items/{item_id}",
                "parameters": [["item_id", "path", "string", None]],
                "request_schemas": [],
            },
            {
                "method": "POST",
                "path": "/v1/upload",
                "parameters": [],
                "request_schemas": [["multipart/form-data", None, ["data"], ["data"]]],
            },
            {
                "method": "POST",
                "path": "/v1/form",
                "parameters": [],
                "request_schemas": [
                    ["application/x-www-form-urlencoded", None, ["value"], ["value"]]
                ],
            },
            {
                "method": "POST",
                "path": "/v1/object",
                "parameters": [],
                "request_schemas": [["application/json", None, ["value"], ["value"]]],
            },
        ]
        state = build_strategy_state(
            surfaces=surfaces,
            interactions=[],
            lane_priorities=[],
            accounts=[],
            used_requests=0,
            max_requests=100,
            version=3,
        )
        self.assertEqual(
            [
                "query_parameter",
                "path_parameter",
                "multipart_body",
                "form_body",
                "structured_body",
            ],
            [item["untested_input_classes"][0] for item in state["surface_frontier"]],
        )
        self.assertEqual("inventory", state["phase"])

    def test_v13_warns_on_high_share_same_shape_route(self) -> None:
        interactions = [
            {
                "kind": "http",
                "session": "member",
                "method": "GET",
                "path": "/v3/objects",
                "request": {"body_mode": "none", "body": None},
                "status": 200,
                "response": '{"items":[]}',
            }
            for _ in range(10)
        ]
        state = build_strategy_state(
            surfaces=[],
            interactions=interactions,
            lane_priorities=[],
            accounts=[],
            used_requests=20,
            max_requests=100,
            version=3,
        )
        self.assertEqual(1, len(state["concentration_warnings"]))
        self.assertEqual("/v3/objects", state["concentration_warnings"][0]["route"])

    def test_sealed_variants_control_prefix_and_state_seed(self) -> None:
        registry = {"target-a": {"target_kind": "ruby-web"}}
        variants = [
            {
                "repetition": index,
                "variant_id": f"sealed-{index}",
                "normal_traffic_seed": 9000 + index * 17,
                "public_api_prefix": f"/edge-{index}",
            }
            for index in range(5)
        ]
        schedule = _schedule(
            ["target-a"],
            registry,
            ["codex", "claude"],
            5,
            1,
            variants=variants,
        )
        self.assertEqual(10, len(schedule))
        for row in schedule:
            index = int(row["repetition"])
            self.assertEqual(f"sealed-{index}", row["variant_id"])
            self.assertEqual(f"/edge-{index}", row["public_api_prefix"])
            self.assertEqual(9000 + index * 17, row["normal_traffic_seed"])


if __name__ == "__main__":
    unittest.main()
