from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from decimal import Decimal, localcontext

import pytest
from ravage.agent_core.autonomous_graph.work_planner import ONLINE_PLANNER_POLICY_VERSION
from ravage.xben_parts.comparison_budgets import (
    ArmResourceBudgets,
    CostBudgetPartition,
)
from ravage.xben_parts.comparison_model_gateway import ModelGatewayPolicy, ModelPricing
from ravage.xben_parts.comparison_profile import (
    COMPARISON_PROFILE_SCHEMA,
    PAIRED_CASE_COUNT,
    PROFILE_EXECUTION_STATUS,
    SCHEDULE_ALGORITHM,
    SELECTION_ALGORITHM,
    PairedComparisonProfile,
)


def test_profile_commits_sampling_execution_planner_and_gateway_policy() -> None:
    profile = _profile()
    payload = profile.to_json()

    assert payload["schema_version"] == COMPARISON_PROFILE_SCHEMA
    assert payload["execution_readiness"] == {
        "status": PROFILE_EXECUTION_STATUS,
        "eligible_as_scored_evidence": False,
        "required_bindings": [
            "published_case_population_drand_selection_and_schedule_specifications",
            "prepublished_profile_and_gateway_digest_binding_to_every_receipt",
            "single_shared_campaign_model_gateway",
            "forty_unique_arm_credentials_with_profile_bound_total_limits",
            "ravage_base_and_graph_lane_enforcement",
            "ravage_online_planner_mode_and_policy_version_binding",
            "semantic_projection_digest_and_forbidden_literal_scan_binding",
            "target_gateway_request_limit_enforcement",
            "wall_clock_single_attempt_and_serial_lifecycle_enforcement",
            "independent_artifact_verifier",
        ],
    }
    assert payload["paired_cases"] == PAIRED_CASE_COUNT
    assert payload["systems"] == ["ravage", "reference"]
    assert payload["sampling"] == {
        "without_replacement": True,
        "same_cases_for_both_systems": True,
        "randomness": "future_public_drand_round_committed_before_draw",
        "selection_algorithm": SELECTION_ALGORITHM,
        "schedule_algorithm": SCHEDULE_ALGORITHM,
    }
    execution = payload["execution"]
    assert execution["max_concurrent_scored_arms"] == 1
    assert execution["budget_scope"] == "per_scored_arm"
    assert execution["attempt_policy"] == {
        "scored_attempts_per_arm": 1,
        "resume": False,
        "retry_failed_arms": False,
    }
    assert execution["native_client_retries"] == {
        "normalized_between_systems": False,
        "each_physical_model_attempt_metered": True,
        "admitted_gateway_failure_invalidates_arm": True,
    }
    assert payload["planner"] == {
        "ravage_mode": "online",
        "ravage_policy_version": ONLINE_PLANNER_POLICY_VERSION,
    }
    gateway = payload["model_gateway"]
    assert gateway["policy"]["schema_version"] == "ravage.xben.model-gateway-policy.v3"
    assert gateway["policy_sha256"] == profile.model_gateway_policy.digest
    assert payload["prompt_policy"]["claim"] == (
        "both_arms_receive_projections_of_one_evaluator_authored_semantic_document"
    )

    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert profile.canonical_bytes() == canonical
    assert profile.digest == "sha256:" + hashlib.sha256(canonical).hexdigest()
    serialized = canonical.decode()
    for forbidden_key in ("api_key", "credential", "case_id", "target_url", "source_root"):
        assert f'"{forbidden_key}":' not in serialized


def test_profile_projects_ravage_lanes_and_reference_total() -> None:
    profile = _profile()
    ravage = profile.for_system("ravage")
    reference = profile.for_system("reference")

    assert ravage["system"] == "ravage"
    assert reference["system"] == "reference"
    assert ravage["execution_readiness"] == reference["execution_readiness"]
    assert ravage["execution_readiness"]["eligible_as_scored_evidence"] is False
    assert set(ravage["budgets"]) == {"base", "graph"}
    assert set(reference["budgets"]) == {"total"}
    assert ravage["planner"] == {
        "mode": "online",
        "policy_version": ONLINE_PLANNER_POLICY_VERSION,
    }
    assert "planner" not in reference
    assert ravage["model_gateway"] == reference["model_gateway"]
    assert ravage["prompt_policy"] == reference["prompt_policy"]


@pytest.mark.parametrize("campaign_cost", ["9.999", "10.001"])
def test_profile_requires_exact_forty_arm_campaign_cap(campaign_cost: str) -> None:
    with pytest.raises(ValueError, match="forty times"):
        _profile(model_gateway_policy=_gateway_policy(campaign_cost=campaign_cost))


def test_gateway_policy_changes_alter_the_profile_digest() -> None:
    first = _profile(model_gateway_policy=_gateway_policy(max_completion_tokens=100))
    second = _profile(model_gateway_policy=_gateway_policy(max_completion_tokens=99))

    assert first.model_gateway_policy.digest != second.model_gateway_policy.digest
    assert first.digest != second.digest


def test_profile_digest_is_independent_of_ambient_decimal_precision() -> None:
    precise_cost = CostBudgetPartition.build(
        total="0.1234567890123456789",
        base="0.02",
        graph="0.1034567890123456789",
    )
    precise_budgets = replace(_budgets(), model_gateway_charged_cost_usd=precise_cost)
    precise_policy = _gateway_policy(campaign_cost="4.938271560493827156")

    with localcontext() as context:
        context.prec = 2
        low_precision = _profile(
            budgets=precise_budgets,
            model_gateway_policy=precise_policy,
        )
    with localcontext() as context:
        context.prec = 80
        high_precision = _profile(
            budgets=precise_budgets,
            model_gateway_policy=precise_policy,
        )

    assert low_precision.to_json() == high_precision.to_json()
    assert low_precision.digest == high_precision.digest


def test_profile_rejects_wrong_components_and_unknown_system() -> None:
    with pytest.raises(TypeError, match="ArmResourceBudgets"):
        PairedComparisonProfile(  # type: ignore[arg-type]
            budgets=object(),
            model_gateway_policy=_gateway_policy(),
        )
    with pytest.raises(TypeError, match="ModelGatewayPolicy"):
        PairedComparisonProfile(  # type: ignore[arg-type]
            budgets=_budgets(),
            model_gateway_policy=object(),
        )
    with pytest.raises(ValueError, match="ravage or reference"):
        _profile().for_system("other")  # type: ignore[arg-type]


def _profile(
    *,
    budgets: ArmResourceBudgets | None = None,
    model_gateway_policy: ModelGatewayPolicy | None = None,
) -> PairedComparisonProfile:
    return PairedComparisonProfile(
        budgets=budgets or _budgets(),
        model_gateway_policy=model_gateway_policy or _gateway_policy(),
    )


def _budgets() -> ArmResourceBudgets:
    return ArmResourceBudgets.build(
        total_model_gateway_requests_started=40,
        base_model_gateway_requests_started=16,
        graph_model_gateway_requests_started=24,
        total_model_gateway_charged_cost_usd="0.25",
        base_model_gateway_charged_cost_usd="0.10",
        graph_model_gateway_charged_cost_usd="0.15",
        total_target_gateway_observed_requests=1000,
        base_target_gateway_observed_requests=400,
        graph_target_gateway_observed_requests=600,
        total_wall_clock_seconds=600,
        base_wall_clock_seconds=240,
        graph_wall_clock_seconds=360,
    )


def _gateway_policy(
    *,
    campaign_cost: str = "10",
    max_completion_tokens: int = 100,
) -> ModelGatewayPolicy:
    return ModelGatewayPolicy.build(
        model="gpt-5.4-mini-2026-03-17",
        reasoning_effort="high",
        pricing=ModelPricing.from_numbers(
            input_per_million=Decimal("0.75"),
            cached_input_per_million=Decimal("0.075"),
            output_per_million=Decimal("4.50"),
        ),
        campaign_max_cost_usd=campaign_cost,
        max_completion_tokens_per_request=max_completion_tokens,
    )
