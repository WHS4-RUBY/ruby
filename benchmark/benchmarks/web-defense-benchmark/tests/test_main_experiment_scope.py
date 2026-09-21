from __future__ import annotations

from types import SimpleNamespace

import pytest

import run_autonomous_campaign_v3 as campaign
from main_experiment_scope_v1 import (
    assert_main_experiment_targets,
    load_main_experiment_policy,
    main_experiment_target_gate,
    registered_target_ids,
    target_policy_metadata,
)


EXCLUDED_TARGETS = {
    "ruby-web:unsafe-file-upload.seller-document-preview",
    "ruby-web:roundcube-derived.support-ticket-html-postprocess",
    "ruby-web:cross-site-request-forgery.support-role-change",
    "cve-original:CVE-2024-42009",
    "cve-original:CVE-2026-54433",
}


def test_policy_partitions_all_implemented_targets() -> None:
    policy = load_main_experiment_policy()
    eligible = {str(item) for item in policy["eligible_target_ids"]}
    excluded = {str(item["target_id"]) for item in policy["excluded_targets"]}

    assert len(registered_target_ids()) == 34
    assert len(eligible) == 29
    assert excluded == EXCLUDED_TARGETS
    assert eligible | excluded == set(registered_target_ids())
    assert {
        item for item in eligible if item.startswith("cve-original:")
    } == {
        "cve-original:CVE-2024-23897",
        "cve-original:CVE-2024-36401",
        "cve-original:CVE-2025-3248",
    }


def test_policy_gate_allows_main_scope_and_rejects_exclusions() -> None:
    assert_main_experiment_targets(["ruby-web:sql-injection.product-search"])
    gate = main_experiment_target_gate(
        ["ruby-web:cross-site-request-forgery.support-role-change"]
    )
    assert gate["passed"] is False
    assert {item["target_id"] for item in gate["blocked_targets"]} == {
        "ruby-web:cross-site-request-forgery.support-role-change"
    }
    with pytest.raises(ValueError, match="excluded from the main experiment"):
        assert_main_experiment_targets(list(EXCLUDED_TARGETS))


def test_policy_metadata_keeps_excluded_targets_visible() -> None:
    metadata = target_policy_metadata()
    assert len(metadata) == 34
    assert metadata["ruby-web:sql-injection.product-search"][
        "main_experiment_eligible"
    ] is True
    excluded = metadata["cve-original:CVE-2026-54433"]
    assert excluded["main_experiment_eligible"] is False
    assert excluded["success_judgment"] == "verified"
    assert excluded["request_identification"] == "not-adopted"


def test_runner_rejects_excluded_target_before_docker_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reconciled = False

    def reconcile() -> tuple[str, ...]:
        nonlocal reconciled
        reconciled = True
        return ()

    monkeypatch.setattr(campaign, "_reconcile_managed_docker_projects", reconcile)

    with pytest.raises(ValueError, match="excluded from the main experiment"):
        campaign.run_campaign(
            SimpleNamespace(
                targets=["cve-original:CVE-2024-42009"],
            )
        )

    assert reconciled is False


def test_runner_default_target_list_is_the_29_target_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    def reject_after_gate(
        public_brief: object, target_ids: list[str]
    ) -> tuple[None, None]:
        captured.extend(target_ids)
        raise RuntimeError("stop after target preflight")

    monkeypatch.setattr(campaign, "_public_brief_input", reject_after_gate)

    with pytest.raises(RuntimeError, match="stop after target preflight"):
        campaign.run_campaign(SimpleNamespace(targets=None))

    assert captured == load_main_experiment_policy()["eligible_target_ids"]
    assert len(captured) == 29
    assert not set(captured) & EXCLUDED_TARGETS


def test_runner_seals_the_policy_and_uses_the_main_scope_by_default() -> None:
    sealed_names = {path.name for path in campaign.BASE_SEALED_INPUTS}
    assert campaign.SCOPE_PATH.name == "stage3a-main-experiment-scope-v1.json"
    assert "main-experiment-target-policy-v1.json" in sealed_names
    assert "main-experiment-target-policy.schema.json" in sealed_names
    assert "main_experiment_scope_v1.py" in sealed_names
