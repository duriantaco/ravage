from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.evidence import (
    BlackboardProofGate,
    EvidenceBlackboard,
    EvidenceBlackboardError,
    EvidenceKind,
    EvidencePromotion,
    EvidenceReferenceError,
    EvidenceWorkError,
    EvidenceWorkKind,
    EvidenceWorkStatus,
    graph_tool_result_from_promotion,
)
from ravage.agent_core.autonomous_graph.models import (
    GraphObjective,
    GraphStatus,
)
from ravage.agent_core.autonomous_graph.scheduler import (
    GraphProgressBinding,
    ProgressiveGraphScheduler,
    ProgressKind,
    validate_progress_receipt_batch,
)
from ravage.agent_core.autonomous_graph.sessions import GraphSessionStore
from ravage.agent_core.autonomous_graph.worker import (
    GraphModelReply,
    GraphToolResult,
    GraphWorker,
    ProofGateResult,
    WorkerStepKind,
)

if TYPE_CHECKING:
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
PROMOTED_SQL_RECORDS = 2


def _blackboard(tmp_path: Path) -> EvidenceBlackboard:
    return EvidenceBlackboard(
        target_url=TARGET_URL,
        state_path=tmp_path / "evidence-blackboard.json",
    )


def _objective() -> GraphObjective:
    return GraphObjective.create(
        family="sql_injection",
        instruction="coordinate evidence closure",
        endpoint="/search",
        inputs=("lookup",),
        strategy="differential",
        expected_signal="target-observed proof closure",
    )


def _sql_probe_payload() -> dict[str, object]:
    return {
        "ok": True,
        "probe": "sqli_differential",
        "findings": [
            {
                "type": "sql_literal_comment_exposed_secret",
                "input": {"name": "lookup"},
                "replay": {
                    "method": "POST",
                    "url": "http://target/search",
                    "payload_field": "lookup",
                    "form": {"lookup": "redacted"},
                },
                "response": {
                    "status": 200,
                    "body_snippet": "redacted",
                },
            }
        ],
    }


def _probe_result(
    payload: dict[str, object] | None = None,
    *,
    source_kind: str = "tool_run_probe",
) -> ActionResult:
    body = json.dumps(payload or _sql_probe_payload())
    return ActionResult(
        ok=True,
        observation=body,
        outcome="confirmed_signal",
        evidence_source_kind=source_kind,
        evidence_observation=body,
    )


def _record_sql_evidence(
    blackboard: EvidenceBlackboard,
    *,
    producer_node_id: str = "node-001",
    observation_id: str = "observation-1",
) -> EvidencePromotion:
    return blackboard.record_action_result(
        producer_node_id=producer_node_id,
        action={"action": "run_probe", "probe": "sqli_differential"},
        result=_probe_result(),
        observation_id=observation_id,
    )


def test_model_and_source_claims_never_become_material(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)

    model = blackboard.record_model_claim(
        producer_node_id="node-001",
        claim="I found the flag",
    )
    source = blackboard.record_source_claim(
        producer_node_id="node-001",
        claim="README says this endpoint is vulnerable",
    )

    assert model.trusted is False
    assert model.material is False
    assert source.trusted is False
    assert source.material is False
    with pytest.raises(EvidenceReferenceError, match="untrusted"):
        blackboard.validate_references(
            (model.evidence_id,),
            require_trusted=True,
        )
    assert blackboard.state.progress_snapshot.confirmed_proofs == frozenset()


def test_custom_python_output_is_context_not_material_evidence(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)
    fake_payload = {
        "ok": True,
        "probe": "custom",
        "findings": [{"type": "xxe_file_read_signal", "target": "/proof"}],
    }

    promotion = blackboard.record_action_result(
        producer_node_id="node-001",
        action={
            "action": "run_python",
            "code": "print(fake_finding)",
        },
        result=_probe_result(
            fake_payload,
            source_kind="tool_run_python",
        ),
        observation_id="python-observation",
    )

    raw = blackboard.state.records[promotion.raw_evidence_ref]
    assert raw.trusted is True
    assert raw.material is False
    assert promotion.promoted_evidence_refs == ()
    assert promotion.progress_receipts == ()
    assert "untyped_tool_output" in promotion.reason_codes


def test_structured_target_probe_promotes_typed_progress(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)

    promotion = _record_sql_evidence(blackboard)

    assert promotion.source_trusted is True
    assert len(promotion.promoted_evidence_refs) == PROMOTED_SQL_RECORDS
    kinds = {
        blackboard.state.records[evidence_ref].kind
        for evidence_ref in promotion.promoted_evidence_refs
    }
    assert kinds == {
        EvidenceKind.REQUEST_CONTRACT,
        EvidenceKind.RESPONSE_DIFFERENTIAL,
    }
    assert {receipt.kind for receipt in promotion.progress_receipts} == {
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
        ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
    }
    for evidence_ref in promotion.promoted_evidence_refs:
        record = blackboard.state.records[evidence_ref]
        assert record.trusted is True
        assert record.material is True
        assert record.parent_refs == (promotion.raw_evidence_ref,)


def test_missing_executor_observation_id_fails_closed(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)

    promotion = blackboard.record_action_result(
        producer_node_id="node-001",
        action={"action": "run_probe", "probe": "sqli_differential"},
        result=_probe_result(),
        observation_id="",
    )

    assert promotion.source_trusted is False
    assert promotion.promoted_evidence_refs == ()
    assert promotion.progress_receipts == ()


def test_duplicate_observation_is_canonical_route_wide(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)
    first = _record_sql_evidence(blackboard)
    record_count = len(blackboard.state.records)

    repeated = _record_sql_evidence(
        blackboard,
        producer_node_id="node-002",
    )

    assert repeated.raw_evidence_ref == first.raw_evidence_ref
    assert repeated.promoted_evidence_refs == ()
    assert len(blackboard.state.records) == record_count


def test_confirmed_proof_traces_to_executor_observation(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)
    result = ActionResult(
        ok=True,
        observation="target returned flag{verified}",
        stop=True,
        outcome="flag_candidate",
        flag="flag{verified}",
        evidence_source_kind="tool_run_command",
        evidence_observation="target returned flag{verified}",
    )

    promotion = blackboard.record_action_result(
        producer_node_id="node-001",
        action={"action": "run_command", "command": "curl target"},
        result=result,
        observation_id="tool-observation-proof",
    )
    accepted = blackboard.verify_proof_references(promotion.proof_evidence_refs)

    assert accepted == promotion.proof_evidence_refs
    assert len(accepted) == 1
    proof = blackboard.state.records[accepted[0]]
    assert proof.kind is EvidenceKind.PROOF_CONFIRMED
    assert proof.material is True
    parent = blackboard.state.records[proof.parent_refs[0]]
    assert parent.observation_id == "tool-observation-proof"
    assert "flag{verified}" not in json.dumps(blackboard.state.to_json())


@pytest.mark.asyncio
async def test_blackboard_proof_gate_rejects_model_claim_and_accepts_proof(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)
    model_claim = blackboard.record_model_claim(
        producer_node_id="node-001",
        claim="flag{invented}",
    )
    proof_result = ActionResult(
        ok=True,
        observation="proof",
        flag="flag{verified}",
        evidence_source_kind="tool_validate_poc",
        evidence_observation="proof",
    )
    promotion = blackboard.record_action_result(
        producer_node_id="node-001",
        action={"action": "validate_poc", "steps": []},
        result=proof_result,
        observation_id="validated-proof",
    )
    gate = BlackboardProofGate(blackboard)

    rejected = await gate("node-001", (model_claim.evidence_id,))
    accepted = await gate(
        "node-001",
        promotion.proof_evidence_refs,
    )

    assert rejected.accepted is False
    assert accepted.accepted is True
    assert accepted.evidence_refs == promotion.proof_evidence_refs


def test_work_is_deduplicated_and_proof_closure_preempts_exploration(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)
    promotion = _record_sql_evidence(blackboard)
    basis = (promotion.raw_evidence_ref,)
    sql = blackboard.register_work(
        kind=EvidenceWorkKind.SQL_ORACLE,
        canonical_key="/search:lookup",
        evidence_refs=basis,
    )
    duplicate = blackboard.register_work(
        kind=EvidenceWorkKind.SQL_ORACLE,
        canonical_key=" /search:lookup ",
        evidence_refs=basis,
    )
    proof = blackboard.register_work(
        kind=EvidenceWorkKind.PROOF_CLOSURE,
        canonical_key="close:/search:lookup",
        evidence_refs=basis,
    )

    claimed = blackboard.claim_next_work(owner_node_id="node-002")

    assert sql.created is True
    assert duplicate.created is False
    assert duplicate.item.work_id == sql.item.work_id
    assert proof.created is True
    assert claimed is not None
    assert claimed.kind is EvidenceWorkKind.PROOF_CLOSURE
    assert claimed.status is EvidenceWorkStatus.CLAIMED


def test_work_completion_requires_owner_and_trusted_result(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)
    promotion = _record_sql_evidence(blackboard)
    registration = blackboard.register_work(
        kind=EvidenceWorkKind.CLOSURE_OBLIGATION,
        canonical_key="closure:/search",
        evidence_refs=(promotion.raw_evidence_ref,),
    )
    claimed = blackboard.claim_next_work(owner_node_id="node-002")
    assert claimed is not None
    model_claim = blackboard.record_model_claim(
        producer_node_id="node-002",
        claim="done",
    )

    with pytest.raises(EvidenceWorkError, match="belongs"):
        blackboard.complete_work(
            work_id=registration.item.work_id,
            owner_node_id="node-003",
            result_evidence_refs=(promotion.raw_evidence_ref,),
        )
    with pytest.raises(EvidenceReferenceError, match="untrusted"):
        blackboard.complete_work(
            work_id=registration.item.work_id,
            owner_node_id="node-002",
            result_evidence_refs=(model_claim.evidence_id,),
        )

    completed = blackboard.complete_work(
        work_id=registration.item.work_id,
        owner_node_id="node-002",
        result_evidence_refs=(promotion.raw_evidence_ref,),
    )
    assert completed.status is EvidenceWorkStatus.COMPLETED


def test_claimed_work_is_released_after_worker_loss(tmp_path: Path) -> None:
    blackboard = _blackboard(tmp_path)
    promotion = _record_sql_evidence(blackboard)
    registration = blackboard.register_work(
        kind=EvidenceWorkKind.EXTRACTION_CHECKPOINT,
        canonical_key="extract:/search",
        evidence_refs=(promotion.raw_evidence_ref,),
    )
    blackboard.claim_next_work(owner_node_id="node-002")

    released = blackboard.release_owner("node-002")

    assert released == (registration.item.work_id,)
    assert (
        blackboard.state.work_items[registration.item.work_id].status is EvidenceWorkStatus.PENDING
    )


def test_blackboard_reload_rejects_target_mismatch(tmp_path: Path) -> None:
    blackboard = _blackboard(tmp_path)
    _record_sql_evidence(blackboard)

    with pytest.raises(EvidenceBlackboardError, match="target identity"):
        EvidenceBlackboard(
            target_url="http://127.0.0.1:9999",
            state_path=blackboard.state_path,
        )


class OneReplyModel:
    def __init__(self, content: str) -> None:
        self.content = content

    async def __call__(
        self,
        node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        del node_id, messages
        return GraphModelReply(content=self.content)


class NoopExecute:
    async def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        del node_id, tool, arguments
        return GraphToolResult(output="unused")


class RejectProof:
    async def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        del node_id, evidence_refs
        return ProofGateResult(accepted=False)


@pytest.mark.asyncio
async def test_worker_rejects_fabricated_evidence_reference(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)
    coordinator = GraphCoordinator.start(
        graph_id="evidence-worker-test",
        root_objective=_objective(),
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=OneReplyModel(
            json.dumps(
                {
                    "kind": "finish",
                    "payload": {
                        "summary": "done",
                        "evidence_refs": ["evidence:invented"],
                    },
                }
            )
        ),
        execute=NoopExecute(),
        proof_gate=RejectProof(),
        evidence_validator=blackboard,
    )

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.ACTION_REJECTED
    assert "unknown evidence reference" in result.reason
    assert coordinator.state.status is GraphStatus.RUNNING


@pytest.mark.asyncio
async def test_promoted_receipts_unlock_scheduler_without_model_trust(
    tmp_path: Path,
) -> None:
    blackboard = _blackboard(tmp_path)
    promotion = _record_sql_evidence(blackboard)
    coordinator = GraphCoordinator.start(
        graph_id="evidence-scheduler-test",
        root_objective=_objective(),
    )
    scheduler = ProgressiveGraphScheduler(coordinator)
    tool_result = graph_tool_result_from_promotion(
        result=_probe_result(),
        promotion=promotion,
    )
    visible = json.loads(tool_result.output)
    node = coordinator.state.nodes["node-001"]
    batch = validate_progress_receipt_batch(
        tool_result.progress_receipts,
        result_evidence_refs=tool_result.evidence_refs,
        evidence_validator=blackboard,
        binding=GraphProgressBinding(
            graph_id=coordinator.state.graph_id,
            target_identity=blackboard.target_identity,
            tool_call_id="tool-call:evidence-scheduler-test",
            runtime_binding_id="runtime-binding:evidence-scheduler-test",
            node_id=node.node_id,
            objective_fingerprint=node.objective.fingerprint,
            hypothesis_fingerprint="",
            agent_spec_fingerprint=node.agent_spec.fingerprint,
        ),
    )

    decision = await scheduler.apply_progress(
        "node-001",
        batch,
    )

    assert visible["evidence"]["material_refs"] == list(promotion.promoted_evidence_refs)
    assert visible["evidence"]["raw_ref"] == promotion.raw_evidence_ref
    assert decision.granted is True
    assert decision.proof_eligible is True
    assert coordinator.state.evidence_epoch == 1
