from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.failure_memory import (
    FailureCertificate,
    InvestigationFailureMemory,
)
from ravage.agent_core.autonomous_graph.investigation import (
    InvestigationActionRejectedError,
    InvestigationEngine,
)
from ravage.agent_core.autonomous_graph.learning import (
    GraphLearningError,
    extract_route_lessons,
)
from ravage.agent_core.autonomous_graph.loop_policy import LoopDisposition
from ravage.agent_core.autonomous_graph.models import (
    AgentSpec,
    GraphObjective,
    Hypothesis,
)
from ravage.agent_core.autonomous_graph.scheduler import (
    GraphProgressBinding,
    ProgressBatchClass,
    ProgressiveGraphScheduler,
    ProgressKind,
    ProgressReceipt,
    ProgressReceiptValidationError,
    ProgressSource,
    ValidatedProgressBatch,
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
    from collections.abc import Sequence
    from pathlib import Path

PROGRESS_EXTENSION = 2
COUNTERFACTUAL_EXTENSION = 1
FIRST_CAMPAIGN_REQUESTS = 2
CLIPPED_CAMPAIGN_REQUESTS = 7
SUPPORTED_BELIEF_BASIS_POINTS = 6500
TARGET_IDENTITY = "target:investigation-fixture"
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


def _objective(
    *,
    family: str = "sql_injection",
    strategy: str = "sqli_differential",
    endpoint: str = "/search",
    inputs: tuple[str, ...] = ("query",),
    instruction: str = "Investigate the assigned bounded route",
) -> GraphObjective:
    return GraphObjective.create(
        family=family,
        instruction=instruction,
        endpoint=endpoint,
        inputs=inputs,
        strategy=strategy,
        expected_signal="target-observed typed progress or bounded disproof",
    )


def _probe_output(*, request_count: int = 0) -> str:
    observation = {
        "ok": True,
        "probe": "fixture",
        "summary": "bounded fixture campaign",
        "findings": [],
        "requests": [{"url": f"/request/{index}"} for index in range(request_count)],
        "errors": [],
    }
    return json.dumps(
        {
            "observation": json.dumps(observation),
            "result": {
                "ok": True,
                "outcome": "observed",
                "timed_out": False,
                "exit_code": None,
            },
            "evidence": {
                "raw_ref": "evidence:raw",
                "material_refs": [],
                "lead_refs": [],
                "proof_refs": [],
                "source_trusted": True,
                "reason_codes": [],
            },
        }
    )


def _receipt(
    kind: ProgressKind,
    *,
    evidence_ref: str = "evidence:material",
) -> ProgressReceipt:
    return ProgressReceipt(
        kind=kind,
        value=f"fixture {kind.value}",
        evidence_ref=evidence_ref,
        source=ProgressSource.TARGET_OBSERVATION,
    )


@dataclass(frozen=True)
class _EvidenceRecord:
    evidence_id: str
    kind: str
    producer_node_id: str
    source: str = "tool_run_probe"
    target_identity: str = TARGET_IDENTITY
    material: bool = True


class _TrustedEvidenceValidator:
    target_identity = TARGET_IDENTITY

    def __init__(self, records: Sequence[_EvidenceRecord]) -> None:
        self.records = {record.evidence_id: record for record in records}

    def validate_references(
        self,
        evidence_refs: Sequence[str],
        *,
        require_trusted: bool = False,
    ) -> tuple[object, ...]:
        assert require_trusted is True
        assert set(evidence_refs) <= set(self.records)
        return tuple(self.records[evidence_ref] for evidence_ref in evidence_refs)


def _evidence_validator(
    *receipts: ProgressReceipt,
    node_id: str,
) -> _TrustedEvidenceValidator:
    return _TrustedEvidenceValidator(
        tuple(
            _EvidenceRecord(
                evidence_id=receipt.evidence_ref,
                kind=_EVIDENCE_KIND_FOR_PROGRESS[receipt.kind],
                producer_node_id=node_id,
                source=(
                    "coordinator_validator"
                    if receipt.source is ProgressSource.INDEPENDENT_VALIDATOR
                    else "tool_run_probe"
                ),
            )
            for receipt in receipts
            if receipt.trusted
        )
    )


def _validated_batch(  # noqa: PLR0913 - test subject identity is explicit.
    receipts: tuple[ProgressReceipt, ...],
    *,
    validator: _TrustedEvidenceValidator,
    objective: GraphObjective,
    hypothesis: Hypothesis | None,
    agent_spec: AgentSpec,
    node_id: str,
    counterfactual_objective_fingerprint: str = "",
    allow_routed_pivot: bool = False,
) -> ValidatedProgressBatch:
    return validate_progress_receipt_batch(
        receipts,
        result_evidence_refs=tuple(receipt.evidence_ref for receipt in receipts),
        evidence_validator=validator,
        counterfactual_objective_fingerprint=counterfactual_objective_fingerprint,
        allow_routed_pivot=allow_routed_pivot,
        binding=GraphProgressBinding(
            graph_id="investigation-test-graph",
            target_identity=TARGET_IDENTITY,
            tool_call_id="tool-call:investigation-test",
            runtime_binding_id="runtime-binding:investigation-test",
            node_id=node_id,
            objective_fingerprint=objective.fingerprint,
            hypothesis_fingerprint=(hypothesis.fingerprint if hypothesis is not None else ""),
            agent_spec_fingerprint=agent_spec.fingerprint,
        ),
    )


def test_executor_progress_binds_belief_revision_to_learning_receipt(
    tmp_path: Path,
) -> None:
    objective = _objective()
    hypothesis = Hypothesis.from_objective(objective)
    agent_spec = AgentSpec.for_objective(objective)
    receipt = _receipt(
        ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
        evidence_ref="evidence:material",
    )
    validator = _evidence_validator(receipt, node_id="node-002")
    progress_batch = _validated_batch(
        (receipt,),
        validator=validator,
        objective=objective,
        hypothesis=hypothesis,
        agent_spec=agent_spec,
        node_id="node-002",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
    )
    ticket = engine.authorize_action(
        node_id="node-002",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    engine.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="supported",
            progress_receipts=(receipt,),
            evidence_refs=("evidence:material",),
        ),
        hypothesis=hypothesis,
        agent_spec=agent_spec,
        evidence_epoch=7,
        progress_batch=progress_batch,
    )

    attempt = engine.coverage.snapshot().attempts[0]
    lesson = extract_route_lessons(tmp_path)[0]
    projection = engine.context_projection(
        node_id="node-002",
        objective=objective,
        hypothesis=hypothesis,
    )

    assert attempt["hypothesis_fingerprint"] == hypothesis.fingerprint
    assert attempt["agent_spec_fingerprint"] == agent_spec.fingerprint
    assert str(attempt["belief_revision_id"]).startswith("belief:")
    assert attempt["belief_disposition"] == "supported"
    assert str(attempt["executor_receipt_digest"]).startswith("executor-receipt:")
    assert lesson.executor_verified is True
    assert lesson.verified_material_progress is True
    assert projection["belief"]["belief_basis_points"] == SUPPORTED_BELIEF_BASIS_POINTS
    assert "executor_belief_bp=6500" in (projection["recommended_campaigns"][0]["reason"])

    coverage_path = tmp_path / "investigation-coverage.json"
    tampered = json.loads(coverage_path.read_text(encoding="utf-8"))
    tampered["attempts"][0]["belief_revision_id"] = "belief:" + "0" * 64
    coverage_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(GraphLearningError, match="unknown belief revision"):
        extract_route_lessons(tmp_path)


@pytest.mark.parametrize(
    "mismatch",
    [
        "node_id",
        "objective_fingerprint",
        "hypothesis_fingerprint",
        "agent_spec_fingerprint",
    ],
)
def test_validated_progress_batch_rejects_another_investigation_subject_before_mutation(
    tmp_path: Path,
    mismatch: str,
) -> None:
    objective = _objective()
    hypothesis = Hypothesis.from_objective(objective)
    agent_spec = AgentSpec.for_objective(objective)
    ticket_node_id = "node-002"
    batch_node_id = ticket_node_id
    batch_objective = objective
    batch_hypothesis = hypothesis
    batch_agent_spec = agent_spec
    if mismatch == "node_id":
        batch_node_id = "node-foreign"
    elif mismatch == "objective_fingerprint":
        batch_objective = _objective(
            strategy="filtered_query_bypass",
            instruction="Investigate another bounded objective",
        )
        batch_hypothesis = Hypothesis.from_objective(batch_objective)
    elif mismatch == "hypothesis_fingerprint":
        batch_hypothesis = Hypothesis.create(
            objective_fingerprint=objective.fingerprint,
            claim="A different falsifiable claim",
            support_signal="a distinct target response",
            falsification_signal="paired controls remain equivalent",
            next_discriminating_test="change the query control",
        )
    else:
        batch_agent_spec = AgentSpec.create(role="critic")

    receipt = _receipt(ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED)
    validator = _evidence_validator(receipt, node_id=batch_node_id)
    batch = _validated_batch(
        (receipt,),
        validator=validator,
        objective=batch_objective,
        hypothesis=batch_hypothesis,
        agent_spec=batch_agent_spec,
        node_id=batch_node_id,
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
    )
    ticket = engine.authorize_action(
        node_id=ticket_node_id,
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    with pytest.raises(ProgressReceiptValidationError, match=mismatch):
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(request_count=1),
                observation_digest="wrong-subject",
                progress_receipts=(receipt,),
                evidence_refs=(receipt.evidence_ref,),
            ),
            hypothesis=hypothesis,
            agent_spec=agent_spec,
            progress_batch=batch,
        )

    snapshot = engine.coverage.snapshot()
    assert snapshot.attempts == []
    assert snapshot.reservations == {}
    assert engine.beliefs is not None
    assert engine.beliefs.snapshot().revisions == {}


def test_direct_progress_requires_evidence_validation_before_coverage_mutation(
    tmp_path: Path,
) -> None:
    objective = _objective()
    receipt = _receipt(ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED)
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )
    ticket = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="requires an evidence validator",
    ):
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(request_count=1),
                observation_digest="unvalidated",
                progress_receipts=(receipt,),
                evidence_refs=(receipt.evidence_ref,),
            ),
        )

    snapshot = engine.coverage.snapshot()
    assert snapshot.attempts == []
    assert snapshot.reservations == {}


def test_root_routed_pivot_updates_coverage_without_contradictory_belief(
    tmp_path: Path,
) -> None:
    objective = _objective(
        family="credential_recovery",
        strategy="credential_representation_boundary",
    )
    counterfactual = _objective(
        family="authentication",
        strategy="default_credentials",
        endpoint="/login",
        inputs=("username", "password"),
        instruction="Replay the recovered credential through a bounded login probe",
    )
    agent_spec = AgentSpec.for_objective(objective)
    extraction = _receipt(
        ProgressKind.EXTRACTION_CHECKPOINT,
        evidence_ref="evidence:extraction",
    )
    disproof = _receipt(
        ProgressKind.HYPOTHESIS_DISPROVED,
        evidence_ref="evidence:replay-rejected",
    )
    validator = _TrustedEvidenceValidator(
        (
            _EvidenceRecord(
                evidence_id=extraction.evidence_ref,
                kind="extraction_checkpoint",
                producer_node_id="node-001",
            ),
            _EvidenceRecord(
                evidence_id=disproof.evidence_ref,
                kind="credential_replay_rejected",
                producer_node_id="node-001",
            ),
        )
    )
    batch = _validated_batch(
        (extraction, disproof),
        validator=validator,
        objective=objective,
        hypothesis=None,
        agent_spec=agent_spec,
        node_id="node-001",
        counterfactual_objective_fingerprint=counterfactual.fingerprint,
        allow_routed_pivot=True,
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
    )
    ticket = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "credential_representation_boundary"},
    )

    decision = engine.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=2),
            observation_digest="routed-pivot",
            progress_receipts=(extraction, disproof),
            evidence_refs=(extraction.evidence_ref, disproof.evidence_ref),
            counterfactual_objective_fingerprint=counterfactual.fingerprint,
        ),
        agent_spec=agent_spec,
        progress_batch=batch,
    )

    assert batch.classification is ProgressBatchClass.PIVOT
    assert decision.disposition is LoopDisposition.PIVOT
    attempt = engine.coverage.snapshot().attempts[0]
    assert attempt["belief_revision_id"] == ""
    assert attempt["belief_disposition"] == ""
    assert engine.beliefs is not None
    assert engine.beliefs.snapshot().revisions == {}


def test_sql_campaigns_pivot_then_exhaust_without_blind_loop(
    tmp_path: Path,
) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )
    projection = engine.context_projection(
        node_id="node-001",
        objective=objective,
    )

    assert projection["recommended_campaigns"][0]["probe"] == "sqli_differential"

    first = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    first_decision = engine.record_result(
        first,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=2),
            observation_digest="first",
            evidence_refs=("evidence:raw-1",),
        ),
    )

    assert first_decision.disposition is LoopDisposition.PIVOT
    assert first_decision.recommended_probe == "filtered_query_bypass"
    assert first_decision.recommended_additional_model_requests == 0
    coverage = engine.coverage.projection(first.cell.cell_id)
    assert coverage["target_requests"] == FIRST_CAMPAIGN_REQUESTS
    assert coverage["no_progress_streak"] == 1

    with pytest.raises(
        InvestigationActionRejectedError,
        match="failure_certificate_blocks_equivalent_campaign",
    ):
        engine.authorize_action(
            node_id="node-002",
            objective=objective,
            tool="run_probe",
            arguments={"probe": "sqli_differential"},
        )

    second = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "filtered_query_bypass"},
    )
    second_decision = engine.record_result(
        second,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="second",
            evidence_refs=("evidence:raw-2",),
        ),
    )

    assert second_decision.disposition is LoopDisposition.EXHAUST
    assert engine.coverage.projection(first.cell.cell_id)["exhausted"] is True


def test_executor_request_count_survives_clipped_visible_observation(
    tmp_path: Path,
) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )
    ticket = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    engine.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output="{\n...[truncated from middle]...\n}",
            observation_digest="clipped",
            evidence_refs=("evidence:raw",),
            target_requests=CLIPPED_CAMPAIGN_REQUESTS,
        ),
    )

    assert (
        engine.coverage.projection(ticket.cell.cell_id)["target_requests"]
        == CLIPPED_CAMPAIGN_REQUESTS
    )


def test_typed_progress_moves_from_calibration_to_closure(
    tmp_path: Path,
) -> None:
    objective = _objective()
    calibration_receipt = _receipt(
        ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
    )
    primitive_receipt = _receipt(
        ProgressKind.PRIMITIVE_CONFIRMED,
        evidence_ref="evidence:primitive",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=_evidence_validator(
            calibration_receipt,
            primitive_receipt,
            node_id="node-001",
        ),
    )
    calibration = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    calibrated = engine.record_result(
        calibration,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=4),
            observation_digest="calibrated",
            progress_receipts=(calibration_receipt,),
            evidence_refs=("evidence:material",),
        ),
    )

    assert calibrated.disposition is LoopDisposition.CONTINUE
    assert calibrated.stage == "calibrated"
    assert calibrated.recommended_probe == "sqli_exploit"
    assert calibrated.recommended_additional_model_requests == PROGRESS_EXTENSION

    closure = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_exploit"},
    )
    close_decision = engine.record_result(
        closure,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=3),
            observation_digest="primitive",
            progress_receipts=(primitive_receipt,),
            evidence_refs=("evidence:primitive",),
        ),
    )

    assert close_decision.disposition is LoopDisposition.CLOSE
    assert close_decision.stage == "primitive"
    assert close_decision.recommended_additional_model_requests == PROGRESS_EXTENSION


def test_first_ad_hoc_loop_is_rejected_in_favor_of_bounded_campaign(
    tmp_path: Path,
) -> None:
    objective = _objective(
        family="authentication",
        strategy="default_credentials",
        endpoint="/login",
        inputs=("username", "password"),
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )

    with pytest.raises(
        InvestigationActionRejectedError,
        match="bounded_campaign_required_before_ad_hoc_loop",
    ):
        engine.authorize_action(
            node_id="node-001",
            objective=objective,
            tool="run_python",
            arguments={"code": "for candidate in candidates: try_login(candidate)"},
        )

    assert engine.coverage.snapshot().attempts == []


def test_existing_xss_specialists_are_available_as_graph_campaigns(
    tmp_path: Path,
) -> None:
    objective = _objective(
        family="cross_site_scripting",
        strategy="xss_context",
        endpoint="/reflect",
        inputs=("value",),
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )

    projection = engine.context_projection(
        node_id="node-001",
        objective=objective,
    )

    probes = [campaign["probe"] for campaign in projection["recommended_campaigns"]]
    assert probes[0] == "xss_context"
    assert {"dom_execution", "reflection_value_boundary"}.intersection(probes)

    with pytest.raises(
        InvestigationActionRejectedError,
        match="bounded_campaign_required_before_ad_hoc_loop",
    ):
        engine.authorize_action(
            node_id="node-001",
            objective=objective,
            tool="run_python",
            arguments={"code": "for payload in xss_payloads: send(payload)"},
        )


@pytest.mark.parametrize(
    ("family", "probe"),
    [
        ("template_injection", "ssti_fingerprint"),
        ("object_authorization", "idor_boundary"),
        ("command_injection", "command_boundary"),
        ("deserialization", "cookie_deserialization"),
        ("path_traversal", "file_read_extract"),
        ("exposure", "cms_exposure"),
        ("server_side_request_forgery", "ssrf_boundary"),
        ("graphql", "graphql_exploit"),
        ("authentication", "default_credentials"),
        ("xml_external_entity", "xxe_boundary"),
        ("api_behavior", "browser_boundary"),
    ],
)
def test_assigned_existing_specialist_is_first_campaign(
    tmp_path: Path,
    family: str,
    probe: str,
) -> None:
    objective = _objective(
        family=family,
        strategy=probe,
        instruction=f"Use the observed {probe} surface",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )

    projection = engine.context_projection(
        node_id="node-001",
        objective=objective,
    )

    assert projection["recommended_campaigns"][0]["probe"] == probe


def test_unknown_family_gets_two_distinct_creative_attempts_not_infinite_turns(
    tmp_path: Path,
) -> None:
    objective = _objective(
        family="nosql_injection",
        strategy="operator_confusion",
        endpoint="/lookup",
        inputs=("filter",),
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )
    first = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_python",
        arguments={
            "strategy": "operator_confusion",
            "code": "send_controlled_operator_probe()",
        },
    )
    first_decision = engine.record_result(
        first,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="nosql-first",
            evidence_refs=("evidence:nosql-1",),
        ),
    )

    assert first_decision.disposition is LoopDisposition.PIVOT
    assert first_decision.required_dimension == "model_declared_material_counterfactual"

    second = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_python",
        arguments={
            "strategy": "type_confusion",
            "code": "send_controlled_type_probe()",
        },
    )
    second_decision = engine.record_result(
        second,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="nosql-second",
            evidence_refs=("evidence:nosql-2",),
        ),
    )

    assert second_decision.disposition is LoopDisposition.EXHAUST


def test_semantic_failure_blocks_cosmetic_payload_variants(
    tmp_path: Path,
) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )
    bounded = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    engine.record_result(
        bounded,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="bounded",
            evidence_refs=("evidence:bounded",),
        ),
    )
    custom = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_python",
        arguments={"code": "candidate = ' UNION SELECT 1'"},
    )
    engine.record_result(
        custom,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="custom",
            evidence_refs=("evidence:custom",),
        ),
    )

    with pytest.raises(
        InvestigationActionRejectedError,
        match="failure_certificate_blocks_equivalent_campaign",
    ):
        engine.authorize_action(
            node_id="node-002",
            objective=objective,
            tool="run_python",
            arguments={"code": "candidate = ' UNION   SELECT 999'"},
        )


def test_route_wide_campaign_reservation_prevents_duplicate_workers(
    tmp_path: Path,
) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )
    ticket = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    with pytest.raises(
        InvestigationActionRejectedError,
        match="already reserved by node-001",
    ):
        engine.authorize_action(
            node_id="node-002",
            objective=objective,
            tool="run_probe",
            arguments={"probe": "sqli_differential"},
        )

    engine.cancel_action(ticket)
    replacement = engine.authorize_action(
        node_id="node-002",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    assert replacement.reservation.node_id == "node-002"


def test_failure_certificate_is_versioned_by_new_evidence(
    tmp_path: Path,
) -> None:
    memory = InvestigationFailureMemory.open(tmp_path / "failures.json")
    certificate = FailureCertificate.create(
        cell_id="cell:one",
        family="sql_injection",
        strategy="sql-calibration",
        dimension="query-oracle",
        evidence_version=2,
        reason="paired controls disproved the route",
    )
    memory.remember(certificate)

    assert (
        memory.blocking_certificate(
            cell_id="cell:one",
            strategy="sql-calibration",
            dimension="query-oracle",
            evidence_version=2,
        )
        == certificate
    )
    assert (
        memory.blocking_certificate(
            cell_id="cell:one",
            strategy="sql-calibration",
            dimension="query-oracle",
            evidence_version=3,
        )
        is None
    )


def test_investigation_artifacts_are_deterministic_for_the_same_sequence(
    tmp_path: Path,
) -> None:
    objective = _objective()

    def run(workspace: Path) -> tuple[dict[str, object], dict[str, object], str]:
        engine = InvestigationEngine.open(
            workspace_dir=workspace,
            objectives=(objective,),
        )
        ticket = engine.authorize_action(
            node_id="node-001",
            objective=objective,
            tool="run_probe",
            arguments={"probe": "sqli_differential"},
        )
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(request_count=2),
                observation_digest="same-observation",
                evidence_refs=("evidence:same",),
            ),
        )
        return (
            engine.coverage.snapshot().to_json(),
            engine.failures.snapshot().to_json(),
            engine.decision_path.read_text(encoding="utf-8"),
        )

    assert run(tmp_path / "first") == run(tmp_path / "second")


def test_resume_releases_only_stale_in_flight_campaign_reservations(
    tmp_path: Path,
) -> None:
    objective = _objective()
    first = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )
    abandoned = first.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    assert first.coverage.snapshot().reservations

    resumed = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
    )
    assert resumed.coverage.snapshot().reservations == {}
    replacement = resumed.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    assert replacement.reservation.reservation_id == abandoned.reservation.reservation_id


@pytest.mark.asyncio
async def test_worker_rejects_manual_loop_before_tool_accounting(
    tmp_path: Path,
) -> None:
    objective = _objective()
    coordinator = GraphCoordinator.start(
        graph_id="investigation-worker",
        root_objective=objective,
        root_lease_limit=2,
        state_path=tmp_path / "graph.json",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path / "investigation",
        objectives=(objective,),
    )
    calls: list[tuple[str, str, dict[str, object]]] = []
    captured_contexts: list[dict[str, object]] = []

    async def complete(
        _node_id: str,
        messages: list[dict[str, str]],
    ) -> GraphModelReply:
        captured_contexts.append(json.loads(messages[-1]["content"]))
        return GraphModelReply(
            content=json.dumps(
                {
                    "kind": "execute",
                    "payload": {
                        "tool": "run_python",
                        "arguments": {
                            "code": "for payload in payloads: test(payload)",
                        },
                        "expected_signal": "SQL response differential",
                    },
                }
            )
        )

    async def execute(
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        calls.append((node_id, tool, arguments))
        return GraphToolResult(output="must not execute")

    async def proof_gate(
        _node_id: str,
        _evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        return ProofGateResult(accepted=False)

    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=complete,
        execute=execute,
        proof_gate=proof_gate,
        investigation_engine=engine,
    )

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.ACTION_REJECTED
    assert calls == []
    assert coordinator.state.tool_calls_started == 0
    campaigns = captured_contexts[0]["investigation"]["recommended_campaigns"]
    assert campaigns[0]["probe"] == "sqli_differential"


@pytest.mark.asyncio
async def test_worker_disproof_grants_only_one_changed_strategy_request(
    tmp_path: Path,
) -> None:
    objective = _objective()
    disproof_receipt = _receipt(
        ProgressKind.HYPOTHESIS_DISPROVED,
        evidence_ref="evidence:disproof",
    )
    evidence_validator = _evidence_validator(
        disproof_receipt,
        node_id="node-001",
    )
    counterfactual = _objective(
        strategy="filtered_query_bypass",
        instruction="Change the filter and encoding dimension",
    )
    coordinator = GraphCoordinator.start(
        graph_id="investigation-disproof-worker",
        root_objective=objective,
        root_lease_limit=1,
        state_path=tmp_path / "graph.json",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path / "investigation",
        objectives=(objective,),
        evidence_validator=evidence_validator,
    )

    async def complete(
        _node_id: str,
        _messages: list[dict[str, str]],
    ) -> GraphModelReply:
        return GraphModelReply(
            content=json.dumps(
                {
                    "kind": "execute",
                    "payload": {
                        "tool": "run_probe",
                        "arguments": {"probe": "sqli_differential"},
                        "expected_signal": "paired SQL controls",
                    },
                }
            )
        )

    async def execute(
        _node_id: str,
        _tool: str,
        _arguments: dict[str, object],
    ) -> GraphToolResult:
        return GraphToolResult(
            output=_probe_output(request_count=2),
            observation_digest="typed-disproof",
            progress_receipts=(disproof_receipt,),
            evidence_refs=("evidence:disproof",),
            counterfactual_objective_fingerprint=counterfactual.fingerprint,
        )

    async def proof_gate(
        _node_id: str,
        _evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        return ProofGateResult(accepted=False)

    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=complete,
        execute=execute,
        proof_gate=proof_gate,
        evidence_validator=evidence_validator,
        investigation_engine=engine,
    )

    result = await worker.step("node-001")

    assert result.kind is WorkerStepKind.EXECUTED
    assert result.lease_decision is not None
    assert result.lease_decision.additional_requests == COUNTERFACTUAL_EXTENSION
    assert result.loop_decision is not None
    assert result.loop_decision.disposition is LoopDisposition.PIVOT
    assert result.loop_decision.recommended_additional_model_requests == COUNTERFACTUAL_EXTENSION
    assert result.loop_decision.recommended_probe == "filtered_query_bypass"
