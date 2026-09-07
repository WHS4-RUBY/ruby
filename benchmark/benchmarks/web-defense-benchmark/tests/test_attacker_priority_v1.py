from __future__ import annotations

import unittest

from autonomous_trial_v2 import (
    _lane_budget_policy,
    _lane_priorities,
    _priority_budget_decision_error,
    _response_shape_signature,
    _route_family,
    _stop_decision_error,
    _strategy_policy_deviations,
    _update_lane_evidence,
)


def _action(method: str, path: str, session: str = "owner") -> dict[str, object]:
    return {
        "kind": "http",
        "session": session,
        "method": method,
        "path": path,
        "headers": None,
        "body_json": None,
        "body_form": None,
        "body_multipart": None,
        "concurrency_group": None,
        "browser_html": None,
        "browser_wait_ms": 0,
    }


class AttackerPriorityV1Tests(unittest.TestCase):
    @staticmethod
    def _record(
        lane_state: dict[str, dict[str, object]],
        endpoint_state: dict[tuple[str, str], dict[str, object]],
        action: dict[str, object],
        *,
        status: int,
        response: str,
        request_index: int,
    ) -> None:
        result = {"status": status, "response": response}
        _update_lane_evidence(
            lane_state,
            endpoint_state,
            action,
            result,
            request_index=request_index,
        )
        key = (str(action["method"]), _route_family(action["path"]))
        state = endpoint_state.setdefault(
            key,
            {
                "attempts": 0,
                "statuses": {},
                "response_shapes": set(),
                "sessions": set(),
            },
        )
        state["attempts"] += 1
        state["statuses"][str(status)] = state["statuses"].get(str(status), 0) + 1
        state["response_shapes"].add(_response_shape_signature(response))
        state["sessions"].add(action["session"])

    def test_observed_differences_outrank_untested_route_name_salience(self) -> None:
        lanes: dict[str, dict[str, object]] = {}
        endpoints: dict[tuple[str, str], dict[str, object]] = {}
        surfaces = [
            {"method": "GET", "path": "/api/alpha/items"},
            {"method": "POST", "path": "/api/alpha/items/{item_id}"},
            {"method": "GET", "path": "/api/omega/private-diagnostics"},
        ]
        self._record(
            lanes,
            endpoints,
            _action("GET", "/api/alpha/items", "owner"),
            status=200,
            response='[{"id":"one","status":"ready"}]',
            request_index=1,
        )
        self._record(
            lanes,
            endpoints,
            _action("GET", "/api/alpha/items", "peer"),
            status=403,
            response='{"detail":"forbidden"}',
            request_index=2,
        )

        priorities = _lane_priorities(
            surfaces,
            endpoints,
            lanes,
            used_requests=2,
            max_requests=100,
        )

        self.assertEqual("alpha", priorities[0]["group"])
        self.assertGreater(priorities[0]["evidence_score"], 0)
        self.assertEqual("omega", priorities[-1]["group"])

    def test_resource_collection_precedes_opaque_object_identifier(self) -> None:
        priorities = _lane_priorities(
            [
                {
                    "method": "GET",
                    "path": "/api/customers/{customer_id}/profile",
                }
            ],
            {},
            {},
            used_requests=0,
            max_requests=100,
        )

        self.assertEqual("customers", priorities[0]["group"])

    def test_priority_scores_are_invariant_to_route_group_names(self) -> None:
        def score(prefix: str) -> tuple[int, int, int]:
            lanes: dict[str, dict[str, object]] = {}
            endpoints: dict[tuple[str, str], dict[str, object]] = {}
            path = f"/api/{prefix}/objects"
            self._record(
                lanes,
                endpoints,
                _action("POST", path),
                status=201,
                response='{"id":"new-object","state":"created"}',
                request_index=1,
            )
            priority = _lane_priorities(
                [{"method": "POST", "path": path}],
                endpoints,
                lanes,
                used_requests=1,
                max_requests=100,
            )[0]
            return (
                int(priority["priority_score"]),
                int(priority["evidence_score"]),
                int(priority["material_events"]),
            )

        self.assertEqual(score("alpha"), score("renamed"))

    def test_stalled_group_is_blocked_after_fair_share_without_evidence(self) -> None:
        priorities = _lane_priorities(
            [
                {"method": "GET", "path": "/api/alpha/items"},
                {"method": "GET", "path": "/api/beta/items"},
            ],
            {},
            {
                "alpha": {
                    "attempts": 25,
                    "signal_counts": {},
                    "material_events": 0,
                    "last_material_request": 0,
                },
                "beta": {
                    "attempts": 3,
                    "signal_counts": {"status_difference": 1},
                    "material_events": 1,
                    "last_material_request": 58,
                },
            },
            used_requests=60,
            max_requests=100,
        )
        policy = _lane_budget_policy(
            priorities, used_requests=60, max_requests=100
        )
        decision = {"actions": [_action("GET", "/api/alpha/items")]}

        self.assertEqual("evidence-focus", policy["phase"])
        self.assertIn("alpha", policy["stalled_groups"])
        self.assertIsNotNone(
            _priority_budget_decision_error(
                decision, policy, mandatory_routes=[]
            )
        )

    def test_recent_evidence_keeps_busy_group_available_for_validation(self) -> None:
        priorities = _lane_priorities(
            [{"method": "POST", "path": "/api/alpha/items/{item_id}"}],
            {},
            {
                "alpha": {
                    "attempts": 30,
                    "signal_counts": {"cross_session_difference": 1},
                    "material_events": 1,
                    "last_material_request": 79,
                    "last_signals": ["cross_session_difference"],
                }
            },
            used_requests=80,
            max_requests=100,
        )
        policy = _lane_budget_policy(
            priorities, used_requests=80, max_requests=100
        )
        decision = {
            "actions": [_action("POST", "/api/alpha/items/observed-id", "peer")]
        }

        self.assertEqual("validation-reserve", policy["phase"])
        self.assertEqual(["alpha"], policy["allowed_priority_groups"])
        self.assertNotIn("alpha", policy["stalled_groups"])
        self.assertIsNone(
            _priority_budget_decision_error(
                decision, policy, mandatory_routes=[]
            )
        )

    def test_exact_evidence_route_can_cross_priority_boundary(self) -> None:
        policy = {
            "phase": "validation-reserve",
            "maximum_actions_this_decision": 3,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": ["beta"],
        }
        decision = {"actions": [_action("GET", "/api/beta/observed-link")]}

        self.assertIsNone(
            _priority_budget_decision_error(
                decision,
                policy,
                mandatory_routes=[
                    {"method": "GET", "path": "/api/beta/observed-link"}
                ],
            )
        )

    def test_focus_keeps_one_low_cost_unexplored_group(self) -> None:
        priorities = [
            {
                "group": "alpha",
                "priority_score": 40,
                "evidence_score": 40,
                "strong_evidence_score": 30,
                "attempts": 12,
                "untested_public_surfaces": 0,
                "requests_since_material_evidence": 1,
                "stalled_at_share_cap": False,
            },
            {
                "group": "beta",
                "priority_score": 30,
                "evidence_score": 30,
                "strong_evidence_score": 20,
                "attempts": 10,
                "untested_public_surfaces": 0,
                "requests_since_material_evidence": 2,
                "stalled_at_share_cap": False,
            },
            {
                "group": "renamed",
                "priority_score": 2,
                "evidence_score": 0,
                "strong_evidence_score": 0,
                "attempts": 1,
                "untested_public_surfaces": 3,
                "requests_since_material_evidence": 60,
                "stalled_at_share_cap": False,
            },
        ]

        policy = _lane_budget_policy(
            priorities, used_requests=60, max_requests=100
        )

        self.assertEqual(
            ["alpha", "beta", "renamed"], policy["allowed_priority_groups"]
        )

    def test_stop_is_rejected_while_fresh_evidence_remains(self) -> None:
        policy = {
            "phase": "evidence-focus",
            "maximum_actions_this_decision": 4,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": [],
            "fresh_evidence_groups": ["alpha"],
        }

        error = _stop_decision_error({"actions": [], "stop": True}, policy)

        self.assertIsNotNone(error)
        self.assertIn("fresh evidence-bearing groups", error)

    def test_stop_is_allowed_when_request_budget_is_exhausted(self) -> None:
        policy = {
            "phase": "validation-reserve",
            "remaining_requests": 0,
            "maximum_actions_this_decision": 3,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": [],
            "fresh_evidence_groups": ["alpha"],
            "verification_debt_groups": ["alpha"],
        }

        error = _stop_decision_error({"actions": [], "stop": True}, policy)

        self.assertIsNone(error)

    def test_one_bounded_lower_priority_group_is_allowed(self) -> None:
        policy = {
            "phase": "evidence-focus",
            "maximum_actions_this_decision": 4,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": [],
            "maximum_out_of_priority_groups": 1,
            "maximum_out_of_priority_actions": 2,
        }
        decision = {
            "actions": [
                _action("GET", "/api/beta/items"),
                _action("GET", "/api/beta/items/observed-id"),
            ]
        }

        self.assertIsNone(
            _priority_budget_decision_error(
                decision, policy, mandatory_routes=[]
            )
        )

    def test_two_lower_priority_groups_are_rejected(self) -> None:
        policy = {
            "phase": "evidence-focus",
            "maximum_actions_this_decision": 4,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": [],
            "maximum_out_of_priority_groups": 1,
            "maximum_out_of_priority_actions": 2,
        }
        decision = {
            "actions": [
                _action("GET", "/api/beta/items"),
                _action("GET", "/api/gamma/items"),
            ]
        }

        error = _priority_budget_decision_error(
            decision, policy, mandatory_routes=[]
        )

        self.assertIsNotNone(error)
        self.assertIn("bounded closure exception", error)

    def test_three_actions_in_one_lower_priority_group_are_rejected(self) -> None:
        policy = {
            "phase": "validation-reserve",
            "maximum_actions_this_decision": 3,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": [],
            "maximum_out_of_priority_groups": 1,
            "maximum_out_of_priority_actions": 2,
        }
        decision = {
            "actions": [
                _action("GET", "/api/beta/items"),
                _action("GET", "/api/beta/items/one"),
                _action("GET", "/api/beta/items/two"),
            ]
        }

        self.assertIsNotNone(
            _priority_budget_decision_error(
                decision, policy, mandatory_routes=[]
            )
        )

    def test_stalled_group_cannot_use_bounded_closure_exception(self) -> None:
        policy = {
            "phase": "validation-reserve",
            "maximum_actions_this_decision": 3,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": ["beta"],
            "maximum_out_of_priority_groups": 1,
            "maximum_out_of_priority_actions": 2,
        }

        error = _priority_budget_decision_error(
            {"actions": [_action("GET", "/api/beta/items")]},
            policy,
            mandatory_routes=[],
        )

        self.assertIsNotNone(error)
        self.assertIn("stalled groups", error)

    def test_state_change_creates_and_later_read_clears_verification_debt(self) -> None:
        lanes: dict[str, dict[str, object]] = {}
        endpoints: dict[tuple[str, str], dict[str, object]] = {}
        surfaces = [
            {"method": "POST", "path": "/api/alpha/items"},
            {"method": "GET", "path": "/api/alpha/items"},
        ]
        self._record(
            lanes,
            endpoints,
            _action("POST", "/api/alpha/items"),
            status=201,
            response='{"id":"new-object","state":"created"}',
            request_index=1,
        )

        before = _lane_priorities(
            surfaces,
            endpoints,
            lanes,
            used_requests=1,
            max_requests=100,
        )[0]
        self.assertTrue(before["verification_debt"])

        self._record(
            lanes,
            endpoints,
            _action("GET", "/api/alpha/items"),
            status=200,
            response='[{"id":"new-object","state":"created"}]',
            request_index=2,
        )
        after = _lane_priorities(
            surfaces,
            endpoints,
            lanes,
            used_requests=2,
            max_requests=100,
        )[0]

        self.assertFalse(after["verification_debt"])
        self.assertGreater(int(before["priority_score"]), int(after["priority_score"]))

    def test_successful_login_does_not_create_verification_debt(self) -> None:
        lanes: dict[str, dict[str, object]] = {}
        endpoints: dict[tuple[str, str], dict[str, object]] = {}
        path = "/api/auth/login"
        self._record(
            lanes,
            endpoints,
            _action("POST", path),
            status=200,
            response='{"token":"opaque-session-value"}',
            request_index=1,
        )

        item = _lane_priorities(
            [{"method": "POST", "path": path}],
            endpoints,
            lanes,
            used_requests=1,
            max_requests=100,
        )[0]

        self.assertFalse(item["verification_debt"])

    def test_nonpersistent_preview_response_does_not_create_verification_debt(self) -> None:
        lanes: dict[str, dict[str, object]] = {}
        endpoints: dict[tuple[str, str], dict[str, object]] = {}
        path = "/api/alpha/preview"
        self._record(
            lanes,
            endpoints,
            _action("POST", path),
            status=200,
            response='{"rendered":"sample output"}',
            request_index=1,
        )

        item = _lane_priorities(
            [{"method": "POST", "path": path}],
            endpoints,
            lanes,
            used_requests=1,
            max_requests=100,
        )[0]

        self.assertFalse(item["verification_debt"])

    def test_successful_patch_with_state_creates_verification_debt(self) -> None:
        lanes: dict[str, dict[str, object]] = {}
        endpoints: dict[tuple[str, str], dict[str, object]] = {}
        path = "/api/alpha/objects/observed-id"
        self._record(
            lanes,
            endpoints,
            _action("PATCH", path),
            status=200,
            response='{"state":"updated"}',
            request_index=1,
        )

        item = _lane_priorities(
            [{"method": "PATCH", "path": path}],
            endpoints,
            lanes,
            used_requests=1,
            max_requests=100,
        )[0]

        self.assertTrue(item["verification_debt"])

    def test_verification_debt_is_invariant_to_route_group_name(self) -> None:
        def debt(prefix: str) -> tuple[bool, int]:
            lanes: dict[str, dict[str, object]] = {}
            endpoints: dict[tuple[str, str], dict[str, object]] = {}
            path = f"/api/{prefix}/objects"
            self._record(
                lanes,
                endpoints,
                _action("POST", path),
                status=201,
                response='{"id":"new-object","state":"created"}',
                request_index=1,
            )
            item = _lane_priorities(
                [{"method": "POST", "path": path}],
                endpoints,
                lanes,
                used_requests=1,
                max_requests=100,
            )[0]
            return bool(item["verification_debt"]), int(item["priority_score"])

        self.assertEqual(debt("alpha"), debt("renamed"))

    def test_stop_cannot_assume_same_batch_state_change_succeeded(self) -> None:
        policy = {
            "phase": "exploration",
            "maximum_actions_this_decision": 6,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": [],
            "fresh_evidence_groups": [],
        }

        error = _stop_decision_error(
            {
                "actions": [_action("POST", "/api/alpha/items")],
                "stop": True,
            },
            policy,
        )

        self.assertIsNotNone(error)
        self.assertIn("state-changing action", error)

    def test_strategy_priority_violation_is_reported_as_a_deviation(self) -> None:
        policy = {
            "phase": "validation-reserve",
            "remaining_requests": 10,
            "maximum_actions_this_decision": 3,
            "allowed_priority_groups": ["alpha"],
            "stalled_groups": ["beta"],
            "maximum_out_of_priority_groups": 1,
            "maximum_out_of_priority_actions": 2,
        }
        decision = {
            "actions": [_action("GET", "/api/beta/items")],
            "stop": False,
        }

        deviations = _strategy_policy_deviations(
            decision,
            policy,
            disclosed_routes=[],
            evidence_followups=[],
            balance_groups=[],
        )

        self.assertTrue(deviations)
        self.assertIn("stalled groups", deviations[-1])
        self.assertIsNone(_stop_decision_error(decision, policy))


if __name__ == "__main__":
    unittest.main()
