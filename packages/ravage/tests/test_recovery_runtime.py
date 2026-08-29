from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.recovery_policy import RecoveryRole, RecoveryStatus
from ravage.agent_core.recovery_runtime import (
    RecoveryCampaign,
    RecoveryRequestAccountingError,
    recovery_config_for_budget,
)

if TYPE_CHECKING:
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
XBEN_MODEL_REQUESTS = 40
INITIAL_CORE_LEASE = 4
CLOSURE_LEASE = 6
COUNTERFACTUAL_LEASE = 8
PROGRESS_LEASE = 8
PROOF_RESERVE = 6
NEXT_TURN_AFTER_INTERRUPTION = 2
ATTEMPTS_AFTER_CORE_LEASE = 4
REQUESTS_AFTER_EARLY_HANDOFF = 5
RECOMMENDED = [
    {"probe": "direct_exposure", "task_id": "flag-and-secret-sweep", "score": 4},
    {"probe": "xxe_boundary", "task_id": "file-fetch-parser", "score": 3},
]


def _no_progress_result(text: str = "same target response") -> ActionResult:
    return ActionResult(
        ok=True,
        observation=text,
        evidence_source_kind="tool_run_command",
        evidence_observation=text,
    )


def _record_no_progress(campaign: RecoveryCampaign, *, suffix: str) -> None:
    campaign.begin_model_request()
    campaign.record_action_result(
        action={"action": "run_command", "command": f"target check {suffix}"},
        outcome=_no_progress_result(f"observation {suffix}"),
        recommended_specialists=RECOMMENDED,
    )


def test_default_campaign_budget_matches_the_xben_contract() -> None:
    config = recovery_config_for_budget(XBEN_MODEL_REQUESTS)

    assert config.max_model_requests == XBEN_MODEL_REQUESTS
    assert config.initial_core_lease == INITIAL_CORE_LEASE
    assert config.closure_lease == CLOSURE_LEASE
    assert config.counterfactual_lease == COUNTERFACTUAL_LEASE
    assert config.progress_lease == PROGRESS_LEASE
    assert config.proof_reserve == PROOF_RESERVE


def test_action_result_keeps_full_evidence_out_of_persisted_outcome_json() -> None:
    outcome = ActionResult(
        ok=True,
        observation="clipped tail",
        evidence_source_kind="tool_run_probe",
        evidence_observation="full structured target observation with secret material",
    )

    encoded = json.dumps(outcome.to_json())

    assert "evidence_source_kind" not in encoded
    assert "full structured" not in encoded
    assert outcome.evidence_source_kind == "tool_run_probe"


def test_full_structured_evidence_is_classified_even_if_model_observation_is_clipped() -> None:
    campaign = RecoveryCampaign.create(target_url=TARGET_URL, max_model_requests=40)
    full = json.dumps(
        {
            "ok": True,
            "probe": "sqli_differential",
            "findings": [
                {
                    "type": "blind_sql_injection_boolean_signal",
                    "input": {"name": "lookup"},
                    "replay": {
                        "method": "POST",
                        "url": f"{TARGET_URL}/search",
                        "payload_field": "lookup",
                        "form": {"lookup": "redacted"},
                    },
                }
            ],
        }
    )
    campaign.begin_model_request()
    result = campaign.record_action_result(
        action={"action": "run_probe", "probe": "sqli_differential"},
        outcome=ActionResult(
            ok=True,
            observation=full[-20:],
            evidence_source_kind="tool_run_probe",
            evidence_observation=full,
        ),
        recommended_specialists=RECOMMENDED,
    )

    assert result.assessment.material_progress
    assert result.decision.reason == "material_progress_lease_granted"
    assert result.decision.next_role is RecoveryRole.CLOSURE
    assert result.active_objective is not None
    assert result.active_objective.probe == "sqli_exploit"


def test_pending_model_request_is_durably_charged_instead_of_replayed(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "recovery-state.json"
    campaign = RecoveryCampaign.create(target_url=TARGET_URL, max_model_requests=40)
    campaign.begin_model_request()
    campaign.save(state_path)

    restored = RecoveryCampaign.load_or_create(
        state_path,
        target_url=TARGET_URL,
        max_model_requests=40,
    )
    decision = restored.account_interrupted_request(recommended_specialists=RECOMMENDED)

    assert decision.total_model_requests == 1
    assert restored.started_model_requests == 1
    assert restored.interrupted_model_requests == 1
    assert restored.has_pending_model_request is False
    assert restored.next_turn == NEXT_TURN_AFTER_INTERRUPTION


def test_campaign_round_trips_mid_closure_with_objective_and_ledgers(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "recovery-state.json"
    campaign = RecoveryCampaign.create(target_url=TARGET_URL, max_model_requests=40)
    for suffix in ("one", "two", "three", "four"):
        _record_no_progress(campaign, suffix=suffix)
    assert campaign.scheduler.role is RecoveryRole.CLOSURE
    assert campaign.active_objective is not None
    campaign.save(state_path)

    restored = RecoveryCampaign.load_or_create(
        state_path,
        target_url=TARGET_URL,
        max_model_requests=40,
    )

    assert restored.to_json() == campaign.to_json()
    assert restored.scheduler.role is RecoveryRole.CLOSURE
    assert restored.active_objective == campaign.active_objective
    assert len(restored.attempts) == ATTEMPTS_AFTER_CORE_LEASE


def test_specialist_final_hands_off_without_consuming_the_remaining_lease() -> None:
    campaign = RecoveryCampaign.create(target_url=TARGET_URL, max_model_requests=40)
    for suffix in ("one", "two", "three", "four"):
        _record_no_progress(campaign, suffix=suffix)
    assert campaign.scheduler.role is RecoveryRole.CLOSURE
    assert campaign.active_objective is not None

    final_action = {"action": "final", "summary": "lead exhausted"}
    handoff = campaign.create_handoff(final_action)
    campaign.begin_model_request()
    result = campaign.record_action_result(
        action=final_action,
        outcome=ActionResult(ok=True, observation=handoff.summary, outcome="handoff"),
        recommended_specialists=RECOMMENDED,
        branch_handoff=True,
    )

    assert result.decision.executed_role is RecoveryRole.CLOSURE
    assert result.decision.executed_lease_used == 1
    assert result.decision.next_role is RecoveryRole.COUNTERFACTUAL
    assert result.decision.next_lease_used == 0
    assert result.decision.branch_handoff_triggered is True
    assert result.decision.total_model_requests == REQUESTS_AFTER_EARLY_HANDOFF
    assert handoff.campaign_terminal is False


def test_recording_without_a_started_request_fails_closed() -> None:
    campaign = RecoveryCampaign.create(target_url=TARGET_URL, max_model_requests=40)

    with pytest.raises(RecoveryRequestAccountingError, match="must be started"):
        campaign.record_action_result(
            action={"action": "run_command", "command": "target check"},
            outcome=_no_progress_result(),
        )


def test_small_campaign_still_terminates_at_its_one_global_cap() -> None:
    max_requests = 4
    campaign = RecoveryCampaign.create(
        target_url=TARGET_URL,
        max_model_requests=max_requests,
    )

    while campaign.scheduler.status is RecoveryStatus.RUNNING:
        _record_no_progress(campaign, suffix=str(campaign.next_turn))

    assert campaign.scheduler.total_model_requests <= max_requests
    assert campaign.started_model_requests == campaign.scheduler.total_model_requests
