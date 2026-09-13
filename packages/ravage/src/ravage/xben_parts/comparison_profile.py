"""Pre-run declarations for paired XBEN comparisons."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Context, Decimal, localcontext

from ravage.agent_core.autonomous_graph.work_planner import (
    ONLINE_PLANNER_POLICY_VERSION,
    InvestigationPlannerMode,
)
from ravage.xben_parts.comparison_budgets import (
    ArmResourceBudgets,
)
from ravage.xben_parts.comparison_model_gateway import ModelGatewayPolicy
from ravage.xben_parts.comparison_semantics import (
    COMPARISON_SYSTEMS,
    ComparisonSystem,
    semantic_prompt_policy,
)

COMPARISON_PROFILE_SCHEMA = "ravage.xben.comparison-profile.v1"
PAIRED_CASE_COUNT = 20
MAX_CONCURRENT_SCORED_ARMS = 1
PROFILE_EXECUTION_STATUS = "declaration_only_runtime_binding_required"
SELECTION_ALGORITHM = "sha256-rank-v2-nonmalleable"
SCHEDULE_ALGORITHM = "sha256-counterbalanced-paired-interleave-v1"
_REQUIRED_MODEL_GATEWAY_POLICY_SCHEMA = "ravage.xben.model-gateway-policy.v3"
_COST_CONTEXT = Context(prec=128)
_REQUIRED_RUNTIME_BINDINGS = (
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
)


@dataclass(frozen=True, slots=True)
class PairedComparisonProfile:
    """Secret-free declaration that is not evidence until runtime-bound."""

    budgets: ArmResourceBudgets
    model_gateway_policy: ModelGatewayPolicy

    def __post_init__(self) -> None:
        if not isinstance(self.budgets, ArmResourceBudgets):
            message = "budgets must be an ArmResourceBudgets"
            raise TypeError(message)
        if not isinstance(self.model_gateway_policy, ModelGatewayPolicy):
            message = "model gateway policy must be a ModelGatewayPolicy"
            raise TypeError(message)
        self.model_gateway_policy.validate()
        policy_json = self.model_gateway_policy.to_json()
        if policy_json.get("schema_version") != _REQUIRED_MODEL_GATEWAY_POLICY_SCHEMA:
            message = "comparison profile requires model gateway policy v3"
            raise ValueError(message)
        with localcontext(_COST_CONTEXT):
            exact_campaign_cost = (
                Decimal(PAIRED_CASE_COUNT)
                * Decimal(len(COMPARISON_SYSTEMS))
                * self.budgets.model_gateway_charged_cost_usd.total
            )
        if self.model_gateway_policy.campaign_max_cost_usd != exact_campaign_cost:
            message = "gateway campaign cost must equal forty times the per-arm total cost"
            raise ValueError(message)

    def to_json(self) -> dict[str, object]:
        policy = self.model_gateway_policy.to_json()
        return {
            "schema_version": COMPARISON_PROFILE_SCHEMA,
            "execution_readiness": _execution_readiness(),
            "paired_cases": PAIRED_CASE_COUNT,
            "systems": list(COMPARISON_SYSTEMS),
            "sampling": {
                "without_replacement": True,
                "same_cases_for_both_systems": True,
                "randomness": "future_public_drand_round_committed_before_draw",
                "selection_algorithm": SELECTION_ALGORITHM,
                "schedule_algorithm": SCHEDULE_ALGORITHM,
            },
            "execution": {
                "max_concurrent_scored_arms": MAX_CONCURRENT_SCORED_ARMS,
                "budget_scope": "per_scored_arm",
                "attempt_policy": {
                    "scored_attempts_per_arm": 1,
                    "resume": False,
                    "retry_failed_arms": False,
                },
                "native_client_retries": {
                    "normalized_between_systems": False,
                    "each_physical_model_attempt_metered": True,
                    "admitted_gateway_failure_invalidates_arm": True,
                },
            },
            "planner": {
                "ravage_mode": InvestigationPlannerMode.ONLINE.value,
                "ravage_policy_version": ONLINE_PLANNER_POLICY_VERSION,
            },
            "model_gateway": {
                "policy": policy,
                "policy_sha256": self.model_gateway_policy.digest,
            },
            "budgets": self.budgets.to_json(),
            "prompt_policy": semantic_prompt_policy(),
        }

    def for_system(self, system: ComparisonSystem) -> dict[str, object]:
        if system not in COMPARISON_SYSTEMS:
            message = "comparison system must be ravage or reference"
            raise ValueError(message)
        payload: dict[str, object] = {
            "system": system,
            "execution_readiness": _execution_readiness(),
            "model_gateway": {
                "policy": self.model_gateway_policy.to_json(),
                "policy_sha256": self.model_gateway_policy.digest,
            },
            "budgets": self.budgets.for_system(system),
            "prompt_policy": semantic_prompt_policy(),
        }
        if system == "ravage":
            payload["planner"] = {
                "mode": InvestigationPlannerMode.ONLINE.value,
                "policy_version": ONLINE_PLANNER_POLICY_VERSION,
            }
        return payload

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_json())

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes())


def _execution_readiness() -> dict[str, object]:
    return {
        "status": PROFILE_EXECUTION_STATUS,
        "eligible_as_scored_evidence": False,
        "required_bindings": list(_REQUIRED_RUNTIME_BINDINGS),
    }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


__all__ = [
    "COMPARISON_PROFILE_SCHEMA",
    "MAX_CONCURRENT_SCORED_ARMS",
    "PAIRED_CASE_COUNT",
    "PROFILE_EXECUTION_STATUS",
    "SCHEDULE_ALGORITHM",
    "SELECTION_ALGORITHM",
    "PairedComparisonProfile",
]
