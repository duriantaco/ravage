from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.coordinator import (
    GraphBudgetExceededError,
    GraphCoordinator,
    GraphLeaseExhaustedError,
    RepeatedGraphActionError,
)
from ravage.agent_core.autonomous_graph.models import (
    GraphLimits,
    GraphObjective,
    GraphStatus,
)
from ravage.agent_core.autonomous_graph.protocol import (
    GraphActionKind,
    GraphProtocolError,
    GraphWorkerAction,
    parse_worker_action,
    semantic_action_fingerprint,
)
from ravage.agent_core.autonomous_graph.scheduler import (
    GraphProgressBinding,
    ProgressiveGraphScheduler,
    ProgressKind,
    ProgressReceipt,
    ProgressReceiptValidationError,
    ProgressSource,
    ValidatedProgressBatch,
    validate_progress_receipt_batch,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

INITIAL_LEASE = 2
PROGRESS_EXTENSION = 2
EXTENDED_LEASE = 4
EXPLORATION_REQUESTS = 3
TOTAL_REQUESTS = 4
TARGET_IDENTITY = "target:scheduler-test"

_EVIDENCE_KIND_FOR_PROGRESS = {
    ProgressKind.PROOF_CONFIRMED: "proof_confirmed",
    ProgressKind.PRIMITIVE_CONFIRMED: "primitive_confirmed",
    ProgressKind.AUTH_STATE_CHANGED: "auth_state_changed",
    ProgressKind.REQUEST_TEMPLATE_VALIDATED: "request_contract",
    ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED: "response_differential",
    ProgressKind.SQL_ORACLE_CALIBRATED: "sql_oracle_calibrated",
    ProgressKind.EXTRACTION_CHECKPOINT: "extraction_checkpoint",
    ProgressKind.HYPOTHESIS_CONFIRMED: "hypothesis_confirmed",
    ProgressKind.HYPOTHESIS_DISPROVED: "hypothesis_disproved",
}


@dataclass(frozen=True)
class _EvidenceRecord:
    evidence_id: str
    kind: str
    source: str
    producer_node_id: str = "node-001"
    target_identity: str = TARGET_IDENTITY
    material: bool = True


class _EvidenceValidator:
    target_identity = TARGET_IDENTITY

    def __init__(self, records: tuple[_EvidenceRecord, ...]) -> None:
        self.records = {record.evidence_id: record for record in records}

    def validate_references(
        self,
        evidence_refs: Sequence[str],
        *,
        require_trusted: bool = False,
    ) -> tuple[object, ...]:
        assert require_trusted is True
        return tuple(self.records[evidence_ref] for evidence_ref in evidence_refs)


def _objective(instruction: str = "coordinate route") -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction=instruction,
        endpoint="/search",
        inputs=("query",),
        strategy="differential",
        expected_signal=f"target-observed result for {instruction}",
        evidence_refs=("evidence:base",),
    )


def _coordinator(
    *,
    limits: GraphLimits | None = None,
    root_lease_limit: int = INITIAL_LEASE,
) -> GraphCoordinator:
    return GraphCoordinator.start(
        graph_id="scheduler-test",
        root_objective=_objective(),
        limits=limits,
        root_lease_limit=root_lease_limit,
    )


def _execute_action(
    arguments: Mapping[str, object] | None = None,
) -> GraphWorkerAction:
    return GraphWorkerAction.from_json(
        {
            "kind": "execute",
            "payload": {
                "tool": "http_request",
                "arguments": dict(arguments or {"path": "/search?q=1"}),
                "expected_signal": "target response differential",
            },
        }
    )


def _receipt(
    kind: ProgressKind,
    *,
    value: str = "new target fact",
    evidence_ref: str = "evidence:response-1",
    source: ProgressSource = ProgressSource.TARGET_OBSERVATION,
) -> ProgressReceipt:
    return ProgressReceipt(
        kind=kind,
        value=value,
        evidence_ref=evidence_ref,
        source=source,
    )


def _binding(
    coordinator: GraphCoordinator,
    *,
    node_id: str = "node-001",
    tool_call_id: str = "tool-call:scheduler-test",
) -> GraphProgressBinding:
    node = coordinator.state.nodes[node_id]
    return GraphProgressBinding(
        graph_id=coordinator.state.graph_id,
        target_identity=TARGET_IDENTITY,
        tool_call_id=tool_call_id,
        runtime_binding_id="runtime-binding:scheduler-test",
        node_id=node_id,
        objective_fingerprint=node.objective.fingerprint,
        hypothesis_fingerprint=(node.hypothesis.fingerprint if node.hypothesis is not None else ""),
        agent_spec_fingerprint=node.agent_spec.fingerprint,
    )


def _validated_batch(  # noqa: PLR0913 - validation subjects are explicit.
    coordinator: GraphCoordinator,
    receipts: tuple[ProgressReceipt, ...],
    *,
    records: tuple[_EvidenceRecord, ...] | None = None,
    result_evidence_refs: tuple[str, ...] | None = None,
    tool_call_id: str = "tool-call:scheduler-test",
    counterfactual_objective_fingerprint: str = "",
) -> ValidatedProgressBatch:
    trusted = tuple(receipt for receipt in receipts if receipt.trusted)
    resolved_records = records or tuple(
        _EvidenceRecord(
            evidence_id=receipt.evidence_ref,
            kind=_EVIDENCE_KIND_FOR_PROGRESS[receipt.kind],
            source=(
                "coordinator_validator"
                if receipt.source is ProgressSource.INDEPENDENT_VALIDATOR
                else "tool_run_probe"
            ),
        )
        for receipt in trusted
    )
    return validate_progress_receipt_batch(
        receipts,
        result_evidence_refs=(
            result_evidence_refs
            if result_evidence_refs is not None
            else tuple(receipt.evidence_ref for receipt in receipts)
        ),
        evidence_validator=_EvidenceValidator(resolved_records),
        binding=_binding(
            coordinator,
            tool_call_id=tool_call_id,
        ),
        counterfactual_objective_fingerprint=(counterfactual_objective_fingerprint),
    )


async def _spend_request(coordinator: GraphCoordinator) -> None:
    request_id = await coordinator.begin_model_request("node-001")
    await coordinator.complete_model_request(
        "node-001",
        request_id=request_id,
        cost_usd=0.01,
    )


def test_protocol_accepts_one_json_action_or_one_json_fence() -> None:
    direct = parse_worker_action('{"kind":"wait","payload":{"timeout_seconds":0.5}}')
    fenced = parse_worker_action('```json\n{"kind":"finish","payload":{"summary":"done"}}\n```')

    assert direct.kind is GraphActionKind.WAIT
    assert fenced.kind is GraphActionKind.FINISH


def test_protocol_rejects_prose_around_an_action() -> None:
    with pytest.raises(GraphProtocolError):
        parse_worker_action('I will do this: {"kind":"wait","payload":{}}')


def test_spawn_protocol_accepts_falsifiable_hypothesis_proposal() -> None:
    action = GraphWorkerAction.from_json(
        {
            "kind": "spawn",
            "payload": {
                "name": "fresh-context-critic",
                "lease_limit": 1,
                "objective": {
                    "family": "sql_injection",
                    "instruction": "Falsify the filtered-query mechanism",
                    "endpoint": "/search",
                    "inputs": ["query"],
                    "strategy": "critic_counterfactual",
                    "expected_signal": "controlled response divergence or disproof",
                    "evidence_refs": ["evidence:baseline"],
                },
                "hypothesis": {
                    "claim": "The query filter changes parser semantics",
                    "support_signal": "repeatable divergence under one changed input",
                    "falsification_signal": "all controlled variants are equivalent",
                    "next_discriminating_test": "run a paired encoding control",
                    "required_capabilities": ["http_differential"],
                    "basis_evidence_refs": ["evidence:baseline"],
                },
            },
        }
    )

    hypothesis = action.spawn_hypothesis(parent_hypothesis_fingerprint="hypothesis:" + "a" * 64)

    assert hypothesis.claim == "The query filter changes parser semantics"
    assert hypothesis.objective_fingerprint == action.spawn_objective().fingerprint
    assert hypothesis.parent_hypothesis_fingerprint == "hypothesis:" + "a" * 64
    assert hypothesis.basis_evidence_refs == ("evidence:baseline",)


@pytest.mark.parametrize(
    "forbidden_payload",
    [
        {"agent_spec": {"role": "validator"}},
        {
            "hypothesis": {
                "claim": "claim",
                "support_signal": "support",
                "falsification_signal": "falsify",
                "next_discriminating_test": "test",
                "belief_basis_points": 10_000,
            }
        },
    ],
)
def test_spawn_protocol_rejects_model_control_plane_authority(
    forbidden_payload: dict[str, object],
) -> None:
    payload: dict[str, object] = {
        "name": "unauthorized",
        "objective": {
            "family": "sql_injection",
            "instruction": "Try to claim authority",
            "strategy": "differential",
            "expected_signal": "typed observation",
        },
        **forbidden_payload,
    }

    with pytest.raises(GraphProtocolError, match="control-plane"):
        GraphWorkerAction.from_json({"kind": "spawn", "payload": payload})


def test_semantic_action_fingerprint_ignores_nonces_not_effects() -> None:
    first = _execute_action(
        {
            "path": " /search?q=1 ",
            "headers": {"Accept": "text/html"},
            "request_id": "one",
        }
    )
    same_effect = _execute_action(
        {
            "headers": {"Accept": "text/html"},
            "request_id": "two",
            "path": "/search?q=1",
        }
    )
    different_effect = _execute_action({"path": "/search?q=2"})

    assert semantic_action_fingerprint(first) == semantic_action_fingerprint(same_effect)
    assert semantic_action_fingerprint(first) != semantic_action_fingerprint(different_effect)


def test_contradictory_progress_batch_is_rejected_before_graph_mutation() -> None:
    coordinator = _coordinator()
    before = coordinator.state.to_json()
    receipts = (
        _receipt(
            ProgressKind.PRIMITIVE_CONFIRMED,
            evidence_ref="evidence:support",
        ),
        _receipt(
            ProgressKind.HYPOTHESIS_DISPROVED,
            evidence_ref="evidence:disproof",
        ),
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="both support and disprove",
    ):
        _validated_batch(coordinator, receipts)

    assert coordinator.state.to_json() == before


def test_raw_evidence_cannot_back_typed_progress_or_mutate_graph() -> None:
    coordinator = _coordinator()
    before = coordinator.state.to_json()
    receipt = _receipt(ProgressKind.HYPOTHESIS_CONFIRMED)
    raw_record = _EvidenceRecord(
        evidence_id=receipt.evidence_ref,
        kind="raw_observation",
        source="tool_run_probe",
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="incompatible with its evidence kind",
    ):
        _validated_batch(
            coordinator,
            (receipt,),
            records=(raw_record,),
        )

    assert coordinator.state.to_json() == before


def test_foreign_evidence_producer_is_rejected_before_graph_mutation() -> None:
    coordinator = _coordinator()
    before = coordinator.state.to_json()
    receipt = _receipt(ProgressKind.PRIMITIVE_CONFIRMED)
    foreign_record = _EvidenceRecord(
        evidence_id=receipt.evidence_ref,
        kind="primitive_confirmed",
        source="tool_run_probe",
        producer_node_id="node-999",
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="another producer node",
    ):
        _validated_batch(
            coordinator,
            (receipt,),
            records=(foreign_record,),
        )

    assert coordinator.state.to_json() == before


def test_omitted_result_evidence_ref_is_rejected_before_graph_mutation() -> None:
    coordinator = _coordinator()
    before = coordinator.state.to_json()
    receipt = _receipt(ProgressKind.PRIMITIVE_CONFIRMED)

    with pytest.raises(
        ProgressReceiptValidationError,
        match="omitted from the executor result",
    ):
        _validated_batch(
            coordinator,
            (receipt,),
            result_evidence_refs=(),
        )

    assert coordinator.state.to_json() == before


@pytest.mark.asyncio
async def test_no_progress_does_not_expand_initial_lease() -> None:
    coordinator = _coordinator(root_lease_limit=2)
    await _spend_request(coordinator)
    await _spend_request(coordinator)

    with pytest.raises(GraphLeaseExhaustedError):
        await coordinator.begin_model_request("node-001")

    root = coordinator.state.nodes["node-001"]
    assert root.lease_limit == INITIAL_LEASE
    assert root.lease_extensions == 0


@pytest.mark.asyncio
async def test_model_prose_cannot_renew_a_lease() -> None:
    coordinator = _coordinator()
    scheduler = ProgressiveGraphScheduler(coordinator)
    batch = _validated_batch(
        coordinator,
        (
            _receipt(
                ProgressKind.PRIMITIVE_CONFIRMED,
                source=ProgressSource.MODEL_STATEMENT,
            ),
        ),
    )

    decision = await scheduler.apply_progress(
        "node-001",
        batch,
    )

    assert decision.granted is False
    assert decision.reason == "untrusted_or_missing_material_progress"
    assert coordinator.state.nodes["node-001"].lease_limit == INITIAL_LEASE
    assert coordinator.state.evidence_epoch == 0


@pytest.mark.asyncio
async def test_scheduler_rejects_raw_or_tampered_progress_before_mutation() -> None:
    coordinator = _coordinator()
    scheduler = ProgressiveGraphScheduler(coordinator)
    receipt = _receipt(ProgressKind.PRIMITIVE_CONFIRMED)
    batch = _validated_batch(coordinator, (receipt,))
    before = coordinator.state.to_json()

    with pytest.raises(
        ProgressReceiptValidationError,
        match="ValidatedProgressBatch",
    ):
        await scheduler.apply_progress(
            "node-001",
            (receipt,),  # type: ignore[arg-type]
        )
    with pytest.raises(
        ProgressReceiptValidationError,
        match="digest mismatch",
    ):
        await scheduler.apply_progress(
            "node-001",
            replace(batch, validation_digest="progress-batch:tampered"),
        )

    assert coordinator.state.to_json() == before


@pytest.mark.asyncio
async def test_novel_trusted_progress_grants_only_bounded_continuation() -> None:
    coordinator = _coordinator()
    scheduler = ProgressiveGraphScheduler(coordinator)
    await _spend_request(coordinator)
    await _spend_request(coordinator)

    receipt = _receipt(ProgressKind.PRIMITIVE_CONFIRMED)
    batch = _validated_batch(coordinator, (receipt,))
    decision = await scheduler.apply_progress("node-001", batch)

    assert decision.granted is True
    assert decision.additional_requests == PROGRESS_EXTENSION
    assert decision.lease_limit == EXTENDED_LEASE
    assert decision.proof_eligible is True
    await _spend_request(coordinator)

    repeated = await scheduler.apply_progress("node-001", batch)
    assert repeated.granted is False
    assert "novel trusted progress" in repeated.reason
    assert coordinator.state.nodes["node-001"].lease_limit == EXTENDED_LEASE


@pytest.mark.asyncio
async def test_disproved_hypothesis_requires_one_novel_counterfactual() -> None:
    coordinator = _coordinator()
    scheduler = ProgressiveGraphScheduler(coordinator)
    receipt = _receipt(ProgressKind.HYPOTHESIS_DISPROVED)
    missing_batch = _validated_batch(coordinator, (receipt,))
    same_batch = _validated_batch(
        coordinator,
        (receipt,),
        tool_call_id="tool-call:scheduler-test-same",
        counterfactual_objective_fingerprint=(
            coordinator.state.nodes["node-001"].objective.fingerprint
        ),
    )
    novel_fingerprint = _objective("test encoding boundary").fingerprint
    novel_batch = _validated_batch(
        coordinator,
        (receipt,),
        tool_call_id="tool-call:scheduler-test-novel",
        counterfactual_objective_fingerprint=novel_fingerprint,
    )

    missing = await scheduler.apply_progress("node-001", missing_batch)
    same = await scheduler.apply_progress("node-001", same_batch)
    granted = await scheduler.apply_progress("node-001", novel_batch)
    second_receipt = _receipt(
        ProgressKind.HYPOTHESIS_DISPROVED,
        value="another disproved assumption",
        evidence_ref="evidence:response-2",
    )
    second_batch = _validated_batch(
        coordinator,
        (second_receipt,),
        tool_call_id="tool-call:scheduler-test-2",
        counterfactual_objective_fingerprint=novel_fingerprint,
    )
    reused_route = await scheduler.apply_progress("node-001", second_batch)

    assert missing.granted is False
    assert same.granted is False
    assert granted.granted is True
    assert granted.additional_requests == 1
    assert granted.proof_eligible is False
    assert reused_route.granted is False
    assert "already granted" in reused_route.reason


@pytest.mark.asyncio
async def test_semantic_repeat_is_rejected_before_tool_budget_spend() -> None:
    coordinator = _coordinator()
    scheduler = ProgressiveGraphScheduler(coordinator)
    action = _execute_action()

    first = await scheduler.register_action("node-001", action)
    with pytest.raises(RepeatedGraphActionError):
        await scheduler.register_action("node-001", action)

    assert first in coordinator.state.semantic_action_counts
    assert coordinator.state.semantic_action_counts[first] == 1
    assert coordinator.state.tool_calls_started == 0


@pytest.mark.asyncio
async def test_reconnaissance_cannot_consume_proof_reserve() -> None:
    coordinator = _coordinator(
        limits=GraphLimits(
            max_model_requests=4,
            proof_reserve_model_requests=1,
        ),
        root_lease_limit=TOTAL_REQUESTS,
    )
    await _spend_request(coordinator)
    await _spend_request(coordinator)
    await _spend_request(coordinator)

    with pytest.raises(GraphBudgetExceededError, match="proof reserve"):
        await coordinator.begin_model_request("node-001")

    assert coordinator.state.model_requests_started == EXPLORATION_REQUESTS
    assert coordinator.state.status is GraphStatus.EXPLORATION_EXHAUSTED


@pytest.mark.asyncio
async def test_proof_eligible_worker_can_use_reserved_request() -> None:
    coordinator = _coordinator(
        limits=GraphLimits(
            max_model_requests=4,
            proof_reserve_model_requests=1,
        ),
        root_lease_limit=EXPLORATION_REQUESTS,
    )
    scheduler = ProgressiveGraphScheduler(coordinator)
    batch = _validated_batch(
        coordinator,
        (_receipt(ProgressKind.REQUEST_TEMPLATE_VALIDATED),),
    )
    progress = await scheduler.apply_progress(
        "node-001",
        batch,
    )
    assert progress.proof_eligible is True

    for _ in range(TOTAL_REQUESTS):
        await _spend_request(coordinator)

    assert coordinator.state.model_requests_started == TOTAL_REQUESTS
    with pytest.raises(GraphBudgetExceededError, match="global model"):
        await coordinator.begin_model_request("node-001")


@pytest.mark.asyncio
async def test_observation_watchdog_requests_a_pivot() -> None:
    coordinator = _coordinator()
    scheduler = ProgressiveGraphScheduler(coordinator)

    first = await scheduler.record_observation(
        "node-001",
        digest="same-response",
    )
    second = await scheduler.record_observation(
        "node-001",
        digest="same-response",
    )

    assert first.watchdog_triggered is False
    assert second.watchdog_triggered is True
    assert second.reason == "repeated_observation_requires_pivot"


@pytest.mark.asyncio
async def test_trusted_proof_is_routed_to_gate_not_used_as_more_budget() -> None:
    coordinator = _coordinator()
    scheduler = ProgressiveGraphScheduler(coordinator)
    batch = _validated_batch(
        coordinator,
        (
            _receipt(
                ProgressKind.PROOF_CONFIRMED,
                value="flag{verified}",
                evidence_ref="evidence:proof-response",
            ),
        ),
    )

    decision = await scheduler.apply_progress(
        "node-001",
        batch,
    )

    assert decision.granted is False
    assert decision.reason == "trusted_proof_ready_for_gate"
    assert decision.proof_evidence_refs == ("evidence:proof-response",)
    assert coordinator.state.nodes["node-001"].lease_limit == INITIAL_LEASE
