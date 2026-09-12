from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.branch_search import (
    BranchOutcomeIndex,
    BranchSearchError,
    seal_planner_feedback_attempt,
)
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.coverage_ledger import (
    InvestigationCoverageError,
    SurfaceCell,
)
from ravage.agent_core.autonomous_graph.effort_policy import (
    GRAPH_ROUTE_TARGET_REQUEST_LIMIT,
)
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
    GraphLimits,
    GraphObjective,
    GraphRaceLane,
    Hypothesis,
)
from ravage.agent_core.autonomous_graph.runtime_binding import GraphRuntimeResolver
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
from ravage.agent_core.autonomous_graph.work_planner import InvestigationPlannerMode
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
COMPLETION_FAILURE = "fixture completion failure"
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


def _race_lanes(objective: GraphObjective) -> tuple[GraphRaceLane, GraphRaceLane]:
    return (
        GraphRaceLane(
            lane_id="lane-a",
            name="race lane a",
            agent_spec=AgentSpec.create(
                role="specialist",
                model_policy_key="lane_a",
                skill_ids=(objective.family,),
            ),
        ),
        GraphRaceLane(
            lane_id="lane-b",
            name="race lane b",
            agent_spec=AgentSpec.create(
                role="critic",
                model_policy_key="lane_b",
                skill_ids=(objective.strategy,),
            ),
        ),
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
        planner_mode=InvestigationPlannerMode.SHADOW,
    )
    ticket = engine.authorize_action(
        node_id="node-002",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
        hypothesis=hypothesis,
    )

    engine.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="supported",
            progress_receipts=(
                *progress_batch.trusted_receipts,
                *progress_batch.ignored_untrusted_receipts,
            ),
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
    assert attempt["planner_feedback_schema_version"] == 1
    assert str(attempt["planner_feedback_digest"]).startswith("planner-feedback:")
    assert attempt["stage_before"] == "observed"
    assert attempt["progress_class"] == "support"
    assert attempt["progress_kinds"] == ["response_differential_validated"]
    assert attempt["planner_attributed"] is True
    assert attempt["validated_batch_digest"] == progress_batch.validation_digest
    assert attempt["hypothesis_path"] == [hypothesis.fingerprint]
    assert lesson.executor_verified is True
    assert lesson.verified_material_progress is True
    assert projection["belief"]["belief_basis_points"] == SUPPORTED_BELIEF_BASIS_POINTS
    assert "executor_belief_bp=6500" in (projection["recommended_campaigns"][0]["reason"])

    coverage_path = tmp_path / "investigation-coverage.json"
    tampered = json.loads(coverage_path.read_text(encoding="utf-8"))
    tampered["attempts"][0]["belief_revision_id"] = "belief:" + "0" * 64
    tampered["attempts"][0].pop("planner_feedback_digest")
    tampered["attempts"][0] = seal_planner_feedback_attempt(tampered["attempts"][0])
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
        hypothesis=hypothesis,
    )

    with pytest.raises(ProgressReceiptValidationError, match=mismatch):
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(request_count=1),
                observation_digest="wrong-subject",
                progress_receipts=(
                    *batch.trusted_receipts,
                    *batch.ignored_untrusted_receipts,
                ),
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


def test_validated_progress_batch_must_match_the_exact_executor_result(
    tmp_path: Path,
) -> None:
    objective = _objective()
    hypothesis = Hypothesis.from_objective(objective)
    agent_spec = AgentSpec.for_objective(objective)
    first = _receipt(
        ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
        evidence_ref="evidence:first-result",
    )
    second = _receipt(
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
        evidence_ref="evidence:second-result",
    )
    validator = _evidence_validator(first, second, node_id="node-002")
    authorized_batch = _validated_batch(
        (first,),
        validator=validator,
        objective=objective,
        hypothesis=hypothesis,
        agent_spec=agent_spec,
        node_id="node-002",
    )
    result_batch = _validated_batch(
        (second,),
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
        hypothesis=hypothesis,
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="does not match this executor result",
    ):
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(request_count=1),
                observation_digest="different-valid-result",
                progress_receipts=result_batch.trusted_receipts,
                evidence_refs=(second.evidence_ref,),
            ),
            hypothesis=hypothesis,
            agent_spec=agent_spec,
            progress_batch=authorized_batch,
        )

    snapshot = engine.coverage.snapshot()
    assert snapshot.attempts == []
    assert snapshot.reservations == {}
    assert engine.beliefs is not None
    assert engine.beliefs.snapshot().revisions == {}


def test_result_hypothesis_must_match_the_authorized_ticket(tmp_path: Path) -> None:
    objective = _objective()
    authorized = Hypothesis.from_objective(objective)
    substituted = Hypothesis.create(
        objective_fingerprint=objective.fingerprint,
        claim="A substituted claim",
        support_signal="a distinct response",
        falsification_signal="paired responses remain equivalent",
        next_discriminating_test="change the controlled input",
    )
    engine = InvestigationEngine.open(workspace_dir=tmp_path, objectives=(objective,))
    ticket = engine.authorize_action(
        node_id="node-002",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
        hypothesis=authorized,
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="hypothesis does not match the authorized ticket",
    ):
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(request_count=1),
                observation_digest="substituted-hypothesis",
            ),
            hypothesis=substituted,
        )

    snapshot = engine.coverage.snapshot()
    assert snapshot.attempts == []
    assert snapshot.reservations == {}


@pytest.mark.parametrize("failure_point", ["prepare", "commit"])
def test_completion_failure_cleans_up_coverage_and_belief_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    objective = _objective()
    hypothesis = Hypothesis.from_objective(objective)
    agent_spec = AgentSpec.for_objective(objective)
    receipt = _receipt(ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED)
    validator = _evidence_validator(receipt, node_id="node-002")
    batch = _validated_batch(
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
        hypothesis=hypothesis,
    )
    before = engine.coverage.snapshot()

    def fail_completion(*_args: object, **_kwargs: object) -> None:
        raise InvestigationCoverageError(COMPLETION_FAILURE)

    monkeypatch.setattr(
        engine.coverage,
        "prepare_completion" if failure_point == "prepare" else "commit_prepared",
        fail_completion,
    )

    with pytest.raises(InvestigationCoverageError, match=COMPLETION_FAILURE):
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(request_count=1),
                observation_digest="atomic-completion",
                progress_receipts=batch.trusted_receipts,
                evidence_refs=(receipt.evidence_ref,),
            ),
            hypothesis=hypothesis,
            agent_spec=agent_spec,
            progress_batch=batch,
        )

    after = engine.coverage.snapshot()
    assert after.cells == before.cells
    assert after.attempts == before.attempts
    assert after.total_target_requests == before.total_target_requests
    assert after.reservations == {}
    assert engine.beliefs is not None
    assert engine.beliefs.snapshot().revisions == {}
    assert engine.failures.snapshot().certificates == {}
    replacement = engine.authorize_action(
        node_id="node-002",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
        hypothesis=hypothesis,
    )
    assert replacement.effort == ticket.effort
    engine.cancel_action(replacement)


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
            progress_receipts=(
                *batch.trusted_receipts,
                *batch.ignored_untrusted_receipts,
            ),
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


@pytest.mark.parametrize(
    ("planner_mode", "expected_probe"),
    [
        (InvestigationPlannerMode.SHADOW, "default_credentials"),
        (InvestigationPlannerMode.ONLINE, "stateful_session"),
    ],
)
def test_feedback_planner_shadows_before_it_controls_campaign_order(
    tmp_path: Path,
    planner_mode: InvestigationPlannerMode,
    expected_probe: str,
) -> None:
    objective = _objective(
        family="authentication",
        strategy="unspecified",
        endpoint="/login",
        inputs=("username", "password"),
    )
    contract = _receipt(
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
        evidence_ref="evidence:contract",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=_evidence_validator(contract, node_id="node-001"),
        planner_mode=planner_mode,
    )

    failed_default = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "default_credentials"},
    )
    engine.record_result(
        failed_default,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=4),
            observation_digest="default-credentials-missed",
            evidence_refs=("evidence:default-miss",),
        ),
    )
    session_contract = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "stateful_session"},
    )
    decision = engine.record_result(
        session_contract,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=2),
            observation_digest="session-contract",
            progress_receipts=(contract,),
            evidence_refs=(contract.evidence_ref,),
        ),
    )

    assert decision.recommended_probe == expected_probe
    records = [
        json.loads(line)
        for line in engine.planner_decision_path.read_text(encoding="utf-8").splitlines()
    ]
    latest = records[-1]
    assert latest["legacy"][0]["probe"] == "default_credentials"
    assert latest["candidate"][0]["probe"] == "stateful_session"
    assert latest["candidate_changed_top"] is True
    assert latest["top_ranked_campaign"] == (
        "auth-session-contract"
        if planner_mode is InvestigationPlannerMode.ONLINE
        else "auth-bounded-credential-baseline"
    )
    authorized = [
        record["authorized_action"]
        for record in records
        if record["decision_point"] == "action_authorized"
    ]
    assert all(receipt is not None for receipt in authorized)
    assert authorized[-1]["reservation_id"] == session_contract.reservation.reservation_id


@pytest.mark.parametrize(
    ("family", "probe", "instruction"),
    [
        ("authentication", "stateful_session", "Map the login and session boundary"),
        (
            "file_handling",
            "ssti_fingerprint",
            "Test the observed upload, include, and template render path",
        ),
    ],
)
def test_catalog_feedback_closes_on_the_cell_that_received_the_recommendation(
    tmp_path: Path,
    family: str,
    probe: str,
    instruction: str,
) -> None:
    objective = _objective(
        family=family,
        strategy="unspecified",
        endpoint="/workflow",
        inputs=("value",),
        instruction=instruction,
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.SHADOW,
    )
    objective_cell_id = SurfaceCell.from_objective(objective).cell_id
    projection = engine.context_projection(node_id="node-001", objective=objective)
    assert projection["coverage_cell"]["cell_id"] == objective_cell_id

    ticket = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": probe},
    )
    engine.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest=f"{probe}-no-progress",
        ),
    )

    attempt = engine.coverage.snapshot().attempts[-1]
    resumed_projection = engine.context_projection(node_id="node-002", objective=objective)
    context_records = [
        json.loads(line)
        for line in engine.planner_decision_path.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["decision_point"] == "context_projection"
    ]
    candidate_probes = {row["probe"] for row in context_records[-1]["candidate"]}
    index = BranchOutcomeIndex.from_attempts(engine.coverage.snapshot().attempts)
    assert ticket.campaign is not None
    assert ticket.cell.cell_id != objective_cell_id
    assert attempt["cell_id"] == ticket.cell.cell_id
    assert attempt["planner_cell_id"] == objective_cell_id
    assert resumed_projection["coverage_cell"]["attempt_count"] == 0
    assert probe not in candidate_probes
    assert index.cell_stats(objective_cell_id).attempt_count == 1
    assert index.campaign_stats(
        cell_id=objective_cell_id,
        strategy=ticket.strategy,
        dimension=ticket.dimension,
    ).visits == 1


def test_legacy_resume_keeps_route_cell_failure_blocking_for_catalog_campaigns(
    tmp_path: Path,
) -> None:
    objective = _objective(
        family="authentication",
        strategy="unspecified",
        endpoint="/login",
        inputs=("username", "password"),
    )
    engine = InvestigationEngine.open(workspace_dir=tmp_path, objectives=(objective,))
    ticket = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "stateful_session"},
    )
    engine.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="legacy-route-failure",
        ),
    )

    resumed = InvestigationEngine.open(workspace_dir=tmp_path, objectives=(objective,))

    assert ticket.cell.cell_id != SurfaceCell.from_objective(objective).cell_id
    assert "planner_feedback_schema_version" not in engine.coverage.snapshot().attempts[0]
    with pytest.raises(
        InvestigationActionRejectedError,
        match="failure_certificate_blocks_equivalent_campaign",
    ):
        resumed.authorize_action(
            node_id="node-002",
            objective=objective,
            tool="run_probe",
            arguments={"probe": "stateful_session"},
        )


def test_shadow_planner_trace_is_idempotent_across_resume(tmp_path: Path) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.SHADOW,
    )

    first = engine.context_projection(node_id="node-001", objective=objective)
    second = engine.context_projection(node_id="node-001", objective=objective)

    assert first == second
    assert len(engine.planner_decision_path.read_text(encoding="utf-8").splitlines()) == 1
    resumed = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.SHADOW,
    )
    assert resumed.context_projection(node_id="node-001", objective=objective) == first
    assert len(resumed.planner_decision_path.read_text(encoding="utf-8").splitlines()) == 1
    assert resumed.summary()["planner"]["decision_records"] == 1


def test_shadow_candidate_failure_returns_exact_legacy_projection(tmp_path: Path) -> None:
    objective = _objective()
    legacy = InvestigationEngine.open(
        workspace_dir=tmp_path / "legacy",
        objectives=(objective,),
    )
    shadow = InvestigationEngine.open(
        workspace_dir=tmp_path / "shadow",
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.SHADOW,
    )
    shadow.coverage.state.attempts.append({"planner_feedback_schema_version": 999})

    expected = legacy.context_projection(node_id="node-001", objective=objective)
    actual = shadow.context_projection(node_id="node-001", objective=objective)

    assert actual == expected
    assert shadow.summary()["planner"]["degraded"] is True
    assert shadow.summary()["planner"]["degradation_reasons"] == ["candidate_evaluation_failed"]


def test_corrupt_diagnostic_trace_never_controls_candidate_policy(tmp_path: Path) -> None:
    objective = _objective()
    decision_path = tmp_path / "investigation-planner-decisions.jsonl"
    decision_path.write_text('{"torn":', encoding="utf-8")

    shadow = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.SHADOW,
    )

    assert shadow.context_projection(node_id="node-001", objective=objective)[
        "recommended_campaigns"
    ]
    assert shadow.summary()["planner"]["degradation_reasons"] == ["decision_log_invalid"]
    online = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    assert online.summary()["planner"]["candidate_controls_recommendations"] is True
    assert online.summary()["planner"]["degradation_reasons"] == ["decision_log_invalid"]


def test_online_trace_failure_after_result_keeps_the_settled_action_atomic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    ticket = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    def fail_trace_write(_records: object) -> None:
        message = "fixture planner trace failure"
        raise OSError(message)

    monkeypatch.setattr(engine, "_persist_planner_decision_records", fail_trace_write)
    decision = engine.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="settled-before-trace-failure",
        ),
    )

    snapshot = engine.coverage.snapshot()
    assert decision.cell_id == ticket.cell.cell_id
    assert len(snapshot.attempts) == 1
    assert snapshot.reservations == {}
    assert engine.summary()["planner"] == {
        "mode": "online",
        "policy_version": "branch-search-v1",
        "candidate_controls_recommendations": True,
        "action_authorization_remains_policy_gated": True,
        "decision_records": 1,
        "degraded": True,
        "degradation_reasons": ["decision_record_failed"],
    }
    resumed = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    assert resumed.summary()["planner"]["candidate_controls_recommendations"] is True
    assert BranchOutcomeIndex.from_attempts(
        resumed.coverage.snapshot().attempts
    ).cell_stats(ticket.planner_cell_id).attempt_count == 1


def test_online_resume_requires_and_accepts_the_settled_result_receipt(tmp_path: Path) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
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
            output=_probe_output(request_count=1),
            observation_digest="settled-online-result",
        ),
    )

    resumed = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )

    assert resumed.summary()["planner"]["degraded"] is False
    assert resumed.context_projection(node_id="node-002", objective=objective)[
        "recommended_campaigns"
    ]


def test_tampered_feedback_fails_open_in_shadow_and_closed_online(tmp_path: Path) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.SHADOW,
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
            output=_probe_output(request_count=1),
            observation_digest="no-progress",
        ),
    )
    coverage_path = tmp_path / "investigation-coverage.json"
    payload = json.loads(coverage_path.read_text(encoding="utf-8"))
    payload["attempts"][0]["progress_class"] = "proof"
    coverage_path.write_text(json.dumps(payload), encoding="utf-8")

    legacy = InvestigationEngine.open(workspace_dir=tmp_path, objectives=(objective,))
    expected = legacy.context_projection(node_id="node-001", objective=objective)
    shadow = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.SHADOW,
    )

    assert shadow.context_projection(node_id="node-001", objective=objective) == expected
    assert shadow.summary()["planner"]["degradation_reasons"] == ["candidate_evaluation_failed"]
    with pytest.raises(InvestigationCoverageError, match="planner feedback"):
        InvestigationEngine.open(
            workspace_dir=tmp_path,
            objectives=(objective,),
            planner_mode=InvestigationPlannerMode.ONLINE,
        )


def test_online_rejects_feedback_root_stage_not_bound_to_the_objective(
    tmp_path: Path,
) -> None:
    objective = _objective()
    shadow = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.SHADOW,
    )
    ticket = shadow.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    shadow.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="valid-observed-root",
        ),
    )
    coverage_path = tmp_path / "investigation-coverage.json"
    payload = json.loads(coverage_path.read_text(encoding="utf-8"))
    attempt = payload["attempts"][0]
    attempt.pop("planner_feedback_digest")
    attempt["planner_stage_before"] = "closure"
    attempt["planner_stage_after"] = "closure"
    payload["attempts"][0] = seal_planner_feedback_attempt(attempt)
    coverage_path.write_text(json.dumps(payload), encoding="utf-8")
    online = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )

    with pytest.raises(BranchSearchError, match="root stage does not match the objective"):
        online.context_projection(node_id="node-002", objective=objective)


def test_unrelated_feedback_cannot_change_online_model_context(tmp_path: Path) -> None:
    objective = _objective()
    unrelated = _objective(endpoint="/other")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective, unrelated),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    before = engine.context_projection(
        node_id="node-main",
        objective=objective,
    )["recommended_campaigns"]
    ticket = engine.authorize_action(
        node_id="node-other",
        objective=unrelated,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    engine.record_result(
        ticket,
        objective=unrelated,
        result=GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="unrelated-no-progress",
        ),
    )
    after = engine.context_projection(
        node_id="node-main",
        objective=objective,
    )["recommended_campaigns"]

    assert after == before
    assert all("search_adjustment" not in campaign for campaign in after)
    assert "branch-outcomes:" not in json.dumps(after)


def test_invalid_feedback_path_cannot_partially_mutate_coverage(tmp_path: Path) -> None:
    objective = _objective()
    hypothesis = Hypothesis.from_objective(objective)
    engine = InvestigationEngine.open(workspace_dir=tmp_path, objectives=(objective,))
    ticket = engine.authorize_action(
        node_id="node-001",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
        hypothesis=hypothesis,
    )
    before = engine.coverage.snapshot().to_json()

    with pytest.raises(InvestigationCoverageError, match="duplicate identity"):
        engine.record_result(
            ticket,
            objective=objective,
            hypothesis=hypothesis,
            hypothesis_path=(hypothesis.fingerprint, hypothesis.fingerprint),
            result=GraphToolResult(
                output=_probe_output(request_count=1),
                observation_digest="invalid-feedback-path",
            ),
        )

    after = engine.coverage.snapshot().to_json()
    assert after["cells"] == before["cells"]
    assert after["attempts"] == before["attempts"]
    assert after["total_target_requests"] == before["total_target_requests"]
    assert after["reservations"] == {}


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


@pytest.mark.asyncio
async def test_worker_online_race_loss_after_execution_charges_the_full_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _objective(endpoint="/race-root")
    objective = _objective(endpoint="/race-charge")
    coordinator = GraphCoordinator.start(
        graph_id="investigation-race-charge",
        root_objective=root,
        limits=GraphLimits(max_concurrent_nodes=3),
        root_lease_limit=2,
        state_path=tmp_path / "graph.json",
    )
    group = await coordinator.spawn_race_group(
        parent_id=coordinator.state.root_node_id,
        objective=objective,
        lanes=_race_lanes(objective),
    )
    winner, loser = group.member_node_ids
    receipt = _receipt(
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
        evidence_ref="evidence:race-loser-executed",
    )
    validator = _evidence_validator(receipt, node_id=loser)
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path / "investigation",
        objectives=(objective,),
        evidence_validator=validator,
        planner_mode=InvestigationPlannerMode.ONLINE,
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
                        "expected_signal": "bounded SQL differential",
                    },
                }
            )
        )

    execute_calls = 0

    async def execute(
        _node_id: str,
        _tool: str,
        _arguments: dict[str, object],
    ) -> GraphToolResult:
        nonlocal execute_calls
        execute_calls += 1
        return GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="race-loser-executed",
            progress_receipts=(receipt,),
            evidence_refs=(receipt.evidence_ref,),
        )

    async def proof_gate(
        _node_id: str,
        _evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        return ProofGateResult(accepted=False)

    original_claim = coordinator.claim_race_progress

    async def force_lost_claim(
        *,
        node_id: str,
        validation_digest: str,
        evidence_refs: Sequence[str],
    ) -> object:
        await original_claim(
            node_id=winner,
            validation_digest="winner-validated-first",
            evidence_refs=("evidence:race-winner",),
        )
        return await original_claim(
            node_id=node_id,
            validation_digest=validation_digest,
            evidence_refs=evidence_refs,
        )

    monkeypatch.setattr(coordinator, "claim_race_progress", force_lost_claim)
    resolver = GraphRuntimeResolver(
        default_complete=complete,
        default_execute=execute,
        model_policies={"lane_a": complete, "lane_b": complete},
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=complete,
        execute=execute,
        proof_gate=proof_gate,
        runtime_resolver=resolver,
        evidence_validator=validator,
        investigation_engine=engine,
    )

    result = await worker.step(loser)

    snapshot = engine.coverage.snapshot()
    initial_grant = 12
    assert result.kind is WorkerStepKind.RACE_LOST
    assert execute_calls == 1
    assert snapshot.total_target_requests == 0
    assert snapshot.pessimistic_target_request_charges == initial_grant
    assert snapshot.attempts == []
    assert snapshot.reservations == {}


@pytest.mark.asyncio
async def test_worker_online_terminal_after_execution_charges_the_full_grant(
    tmp_path: Path,
) -> None:
    objective = _objective(endpoint="/terminal-charge")
    coordinator = GraphCoordinator.start(
        graph_id="investigation-terminal-charge",
        root_objective=objective,
        root_lease_limit=2,
        state_path=tmp_path / "graph.json",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path / "investigation",
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
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
                        "expected_signal": "bounded SQL differential",
                    },
                }
            )
        )

    async def execute(
        _node_id: str,
        _tool: str,
        _arguments: dict[str, object],
    ) -> GraphToolResult:
        await coordinator.solve(proof_evidence_refs=("evidence:terminal-peer",))
        return GraphToolResult(
            output=_probe_output(request_count=1),
            observation_digest="terminal-after-execution",
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
        investigation_engine=engine,
    )

    result = await worker.step(coordinator.state.root_node_id)

    snapshot = engine.coverage.snapshot()
    initial_grant = 12
    assert result.kind is WorkerStepKind.TERMINAL
    assert snapshot.total_target_requests == 0
    assert snapshot.pessimistic_target_request_charges == initial_grant
    assert snapshot.attempts == []
    assert snapshot.reservations == {}


@pytest.mark.asyncio
async def test_worker_online_race_loss_before_execution_refunds_the_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _objective(endpoint="/race-refund-root")
    objective = _objective(endpoint="/race-refund")
    coordinator = GraphCoordinator.start(
        graph_id="investigation-race-refund",
        root_objective=root,
        limits=GraphLimits(max_concurrent_nodes=3),
        root_lease_limit=2,
        state_path=tmp_path / "graph.json",
    )
    group = await coordinator.spawn_race_group(
        parent_id=coordinator.state.root_node_id,
        objective=objective,
        lanes=_race_lanes(objective),
    )
    winner, loser = group.member_node_ids
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path / "investigation",
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
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
                        "expected_signal": "bounded SQL differential",
                    },
                }
            )
        )

    execute_calls = 0

    async def execute(
        _node_id: str,
        _tool: str,
        _arguments: dict[str, object],
    ) -> GraphToolResult:
        nonlocal execute_calls
        execute_calls += 1
        return GraphToolResult(output="must not execute")

    async def proof_gate(
        _node_id: str,
        _evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        return ProofGateResult(accepted=False)

    original_begin_tool_call = coordinator.begin_tool_call

    async def begin_after_winner_claim(
        node_id: str,
        *,
        call_id: str | None = None,
    ) -> str:
        identifier = await original_begin_tool_call(node_id, call_id=call_id)
        await coordinator.claim_race_progress(
            node_id=winner,
            validation_digest="winner-before-execution",
            evidence_refs=("evidence:race-winner",),
        )
        return identifier

    monkeypatch.setattr(coordinator, "begin_tool_call", begin_after_winner_claim)
    resolver = GraphRuntimeResolver(
        default_complete=complete,
        default_execute=execute,
        model_policies={"lane_a": complete, "lane_b": complete},
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=complete,
        execute=execute,
        proof_gate=proof_gate,
        runtime_resolver=resolver,
        investigation_engine=engine,
    )

    result = await worker.step(loser)

    snapshot = engine.coverage.snapshot()
    assert result.kind is WorkerStepKind.RACE_LOST
    assert execute_calls == 0
    assert snapshot.total_target_requests == 0
    assert snapshot.pessimistic_target_request_charges == 0
    assert snapshot.attempts == []
    assert snapshot.reservations == {}


def test_global_target_budget_preserves_zero_target_control_actions(tmp_path: Path) -> None:
    objective = _objective()
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    engine.coverage.state.total_target_requests = GRAPH_ROUTE_TARGET_REQUEST_LIMIT
    engine.coverage._persist()  # noqa: SLF001 - persist a bounded ledger fixture.

    controls = (
        ("capture_flag", {"flag": "FLAG{fixture}"}),
        ("process_stop", {"session_id": "session:fixture"}),
    )
    for index, (tool, arguments) in enumerate(controls):
        ticket = engine.authorize_action(
            node_id=f"node-control-{index}",
            objective=objective,
            tool=tool,
            arguments=arguments,
        )
        assert ticket.effort.target_request_limit == 0
        engine.cancel_action(ticket)

    for tool, arguments in (
        ("http_request", {"url": "https://target.invalid/search"}),
        ("run_command", {"command": "true", "strategy": "bounded-command"}),
    ):
        with pytest.raises(
            InvestigationActionRejectedError,
            match="graph_route_target_request_budget_exhausted",
        ):
            engine.authorize_action(
                node_id=f"node-target-{tool}",
                objective=objective,
                tool=tool,
                arguments=arguments,
            )
    assert engine.coverage.snapshot().reservations == {}


def test_global_target_budget_counts_concurrent_reservations(tmp_path: Path) -> None:
    objective = _objective(endpoint="/concurrent-budget")
    engine = InvestigationEngine.open(workspace_dir=tmp_path, objectives=(objective,))
    initial_grant = 12
    tickets = []
    for index in range(GRAPH_ROUTE_TARGET_REQUEST_LIMIT // initial_grant):
        ticket = engine.authorize_action(
            node_id=f"node-budget-{index}",
            objective=objective,
            tool="run_probe",
            arguments={
                "probe": "sqli_differential",
                "path": f"/concurrent-budget/route-{index}",
            },
        )
        assert ticket.effort.target_request_limit == initial_grant
        tickets.append(ticket)

    with pytest.raises(
        InvestigationActionRejectedError,
        match="graph_route_target_request_budget_exhausted",
    ):
        engine.authorize_action(
            node_id="node-budget-overflow",
            objective=objective,
            tool="run_probe",
            arguments={
                "probe": "sqli_differential",
                "path": "/concurrent-budget/overflow",
            },
        )

    assert (
        sum(ticket.effort.target_request_limit for ticket in tickets)
        == GRAPH_ROUTE_TARGET_REQUEST_LIMIT
    )
    assert len(engine.coverage.snapshot().reservations) == len(tickets)
    for ticket in tickets:
        engine.cancel_action(ticket)


def _record_online_probe_failure(
    engine: InvestigationEngine,
    objective: GraphObjective,
    *,
    suffix: str,
) -> int:
    ticket = engine.authorize_action(
        node_id=f"node-failure-{suffix}",
        objective=objective,
        tool="run_probe",
        arguments={
            "probe": "sqli_differential",
            "path": f"/pessimistic-charge/{suffix}",
        },
    )
    engine.record_tool_failure(ticket, reason=f"fixture failure {suffix}")
    return ticket.effort.target_request_limit


def test_online_tool_failures_pessimistically_exhaust_global_budget(
    tmp_path: Path,
) -> None:
    objective = _objective(endpoint="/pessimistic-charge")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    initial_grant = 12

    grants = [
        _record_online_probe_failure(engine, objective, suffix=f"route-{index}")
        for index in range(GRAPH_ROUTE_TARGET_REQUEST_LIMIT // initial_grant)
    ]

    snapshot = engine.coverage.snapshot()
    assert grants == [initial_grant] * len(grants)
    assert snapshot.total_target_requests == 0
    assert snapshot.pessimistic_target_request_charges == GRAPH_ROUTE_TARGET_REQUEST_LIMIT
    assert snapshot.reservations == {}
    with pytest.raises(
        InvestigationActionRejectedError,
        match="graph_route_target_request_budget_exhausted",
    ):
        engine.authorize_action(
            node_id="node-after-failures",
            objective=objective,
            tool="run_probe",
            arguments={
                "probe": "sqli_differential",
                "path": "/pessimistic-charge/overflow",
            },
        )


def test_online_invalid_executed_result_charges_the_full_authorized_grant(
    tmp_path: Path,
) -> None:
    objective = _objective(endpoint="/invalid-result-charge")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    ticket = engine.authorize_action(
        node_id="node-invalid-result",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="exceeds the authorized target-request grant",
    ):
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(
                    request_count=ticket.effort.target_request_limit + 1,
                ),
                observation_digest="invalid-result-over-grant",
            ),
        )

    snapshot = engine.coverage.snapshot()
    assert snapshot.total_target_requests == 0
    assert (
        snapshot.pessimistic_target_request_charges
        == ticket.effort.target_request_limit
    )
    assert snapshot.reservations == {}
    replacement = engine.authorize_action(
        node_id="node-after-invalid-result",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/invalid-result/replacement"},
    )
    assert replacement.effort.route_committed == ticket.effort.target_request_limit
    engine.cancel_action(replacement)


def test_online_explicit_cancel_refunds_the_reserved_grant(tmp_path: Path) -> None:
    objective = _objective(endpoint="/cancel-refund")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    ticket = engine.authorize_action(
        node_id="node-cancel",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )

    engine.cancel_action(ticket)

    snapshot = engine.coverage.snapshot()
    assert snapshot.total_target_requests == 0
    assert snapshot.pessimistic_target_request_charges == 0
    assert snapshot.reservations == {}
    replacement = engine.authorize_action(
        node_id="node-after-cancel",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/cancel-refund/replacement"},
    )
    assert replacement.effort.target_request_limit == ticket.effort.target_request_limit
    assert replacement.effort.route_committed == 0
    engine.cancel_action(replacement)


def test_online_restart_preserves_pessimistic_charges_and_remaining_budget(
    tmp_path: Path,
) -> None:
    objective = _objective(endpoint="/restart-charge")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    initial_grant = 12
    charge_before_restart = GRAPH_ROUTE_TARGET_REQUEST_LIMIT - initial_grant
    for index in range(charge_before_restart // initial_grant):
        _record_online_probe_failure(engine, objective, suffix=f"restart-{index}")

    resumed = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    assert resumed.summary()["target_requests_pessimistic_charges"] == charge_before_restart
    final = resumed.authorize_action(
        node_id="node-restart-final",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/restart-charge/final"},
    )
    assert final.effort.target_request_limit == initial_grant
    assert final.effort.route_committed == charge_before_restart
    resumed.record_tool_failure(final, reason="final persisted failure")

    exhausted = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    assert (
        exhausted.summary()["target_requests_pessimistic_charges"]
        == GRAPH_ROUTE_TARGET_REQUEST_LIMIT
    )
    with pytest.raises(
        InvestigationActionRejectedError,
        match="graph_route_target_request_budget_exhausted",
    ):
        exhausted.authorize_action(
            node_id="node-restart-overflow",
            objective=objective,
            tool="run_probe",
            arguments={"probe": "sqli_differential", "path": "/restart-charge/overflow"},
        )


def test_failed_charge_persistence_keeps_reservation_and_in_memory_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    objective = _objective(endpoint="/failed-charge-persistence")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    initial_grant = 12
    charge_before_failure = GRAPH_ROUTE_TARGET_REQUEST_LIMIT - initial_grant
    for index in range(charge_before_failure // initial_grant):
        _record_online_probe_failure(engine, objective, suffix=f"persist-{index}")
    ticket = engine.authorize_action(
        node_id="node-persist-failure",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/persist-charge/final"},
    )

    def fail_persist(_state: object) -> None:
        message = "fixture charge persistence failure"
        raise OSError(message)

    monkeypatch.setattr(engine.coverage, "_persist_state", fail_persist)
    with pytest.raises(OSError, match="fixture charge persistence failure"):
        engine.record_tool_failure(ticket, reason="tool failed after execution")

    snapshot = engine.coverage.snapshot()
    assert snapshot.pessimistic_target_request_charges == charge_before_failure
    assert snapshot.reservations[ticket.reservation.route_key] == ticket.reservation
    monkeypatch.undo()
    with pytest.raises(
        InvestigationActionRejectedError,
        match="graph_route_target_request_budget_exhausted",
    ):
        engine.authorize_action(
            node_id="node-persist-overflow",
            objective=objective,
            tool="run_probe",
            arguments={"probe": "sqli_differential", "path": "/persist-charge/overflow"},
        )
    engine.cancel_action(ticket)


def test_coverage_open_rejects_observed_plus_pessimistic_charge_overflow(
    tmp_path: Path,
) -> None:
    objective = _objective(endpoint="/persisted-charge-overflow")
    engine = InvestigationEngine.open(workspace_dir=tmp_path, objectives=(objective,))
    payload = json.loads(engine.coverage.state_path.read_text(encoding="utf-8"))
    payload["total_target_requests"] = GRAPH_ROUTE_TARGET_REQUEST_LIMIT - 1
    payload["pessimistic_target_request_charges"] = 2
    engine.coverage.state_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        InvestigationCoverageError,
        match="coverage target-request charges exceed the route bound",
    ):
        InvestigationEngine.open(
            workspace_dir=tmp_path,
            objectives=(objective,),
            planner_mode=InvestigationPlannerMode.ONLINE,
        )


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("run_command", {"command": "true"}),
        ("run_python", {"code": "pass"}),
        ("process_start", {"command": "true"}),
        ("process_write", {"session_id": "session:fixture", "data": "x"}),
        ("validate_poc", {"steps": [{"method": "GET", "path": "/opaque"}]}),
    ],
)
def test_online_planner_rejects_unmetered_target_tools_before_reservation(
    tmp_path: Path,
    tool: str,
    arguments: dict[str, object],
) -> None:
    objective = _objective(
        family="nosql_injection",
        strategy="operator_confusion",
        endpoint="/opaque",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )

    with pytest.raises(
        InvestigationActionRejectedError,
        match="online_planner_requires_metered_target_request_tool",
    ):
        engine.authorize_action(
            node_id=f"node-{tool}",
            objective=objective,
            tool=tool,
            arguments=arguments,
        )

    assert engine.coverage.snapshot().reservations == {}


@pytest.mark.parametrize(
    "planner_mode",
    [InvestigationPlannerMode.LEGACY, InvestigationPlannerMode.SHADOW],
)
@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("run_command", {"command": "true"}),
        ("run_python", {"code": "pass"}),
        ("process_start", {"command": "true"}),
        ("process_write", {"session_id": "session:fixture", "data": "x"}),
        ("validate_poc", {"steps": [{"method": "GET", "path": "/opaque"}]}),
    ],
)
def test_non_online_planners_preserve_unmetered_target_tool_authorization(
    tmp_path: Path,
    planner_mode: InvestigationPlannerMode,
    tool: str,
    arguments: dict[str, object],
) -> None:
    objective = _objective(
        family="nosql_injection",
        strategy="operator_confusion",
        endpoint="/opaque",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=planner_mode,
    )

    ticket = engine.authorize_action(
        node_id=f"node-{tool}",
        objective=objective,
        tool=tool,
        arguments=arguments,
    )

    assert ticket.effort.target_request_limit > 0
    assert ticket.planner_state_attributed is False
    engine.cancel_action(ticket)


@pytest.mark.parametrize(
    ("probe", "family"),
    [
        ("dom_execution", "cross_site_scripting"),
        ("captcha_form_state", "authentication"),
    ],
)
def test_online_planner_rejects_external_process_probe_before_reservation(
    tmp_path: Path,
    probe: str,
    family: str,
) -> None:
    objective = _objective(
        family=family,
        strategy=probe,
        endpoint="/external-process",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )

    with pytest.raises(
        InvestigationActionRejectedError,
        match="online_planner_requires_metered_run_probe",
    ):
        engine.authorize_action(
            node_id=f"node-{probe}",
            objective=objective,
            tool="run_probe",
            arguments={"probe": probe},
        )

    snapshot = engine.coverage.snapshot()
    assert snapshot.reservations == {}
    assert snapshot.total_target_requests == 0
    assert snapshot.pessimistic_target_request_charges == 0


@pytest.mark.parametrize(
    "planner_mode",
    [InvestigationPlannerMode.LEGACY, InvestigationPlannerMode.SHADOW],
)
@pytest.mark.parametrize(
    ("probe", "family"),
    [
        ("dom_execution", "cross_site_scripting"),
        ("captcha_form_state", "authentication"),
    ],
)
def test_non_online_planners_preserve_external_process_probe_authorization(
    tmp_path: Path,
    planner_mode: InvestigationPlannerMode,
    probe: str,
    family: str,
) -> None:
    objective = _objective(
        family=family,
        strategy=probe,
        endpoint="/external-process",
    )
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=planner_mode,
    )

    ticket = engine.authorize_action(
        node_id=f"node-{probe}",
        objective=objective,
        tool="run_probe",
        arguments={"probe": probe},
    )

    assert ticket.campaign is not None
    assert ticket.campaign.probe == probe
    assert ticket.effort.target_request_limit > 0
    assert ticket.reservation.route_key in engine.coverage.snapshot().reservations
    engine.cancel_action(ticket)
    assert engine.coverage.snapshot().reservations == {}


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("http_request", {"method": "GET", "path": "/metered-http"}),
        ("run_probe", {"probe": "sqli_differential", "path": "/metered-probe"}),
    ],
)
def test_online_planner_authorizes_metered_target_tools(
    tmp_path: Path,
    tool: str,
    arguments: dict[str, object],
) -> None:
    objective = _objective(endpoint="/metered")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )

    ticket = engine.authorize_action(
        node_id=f"node-{tool}",
        objective=objective,
        tool=tool,
        arguments=arguments,
    )

    assert ticket.effort.target_request_limit > 0
    assert ticket.reservation.route_key in engine.coverage.snapshot().reservations
    engine.cancel_action(ticket)


@pytest.mark.parametrize(
    ("tool", "arguments", "target_requests"),
    [
        ("http_request", {"method": "GET", "path": "/generic-proof"}, 1),
        ("capture_flag", {"flag": "FLAG{fixture}"}, 0),
    ],
)
def test_online_generic_terminal_result_updates_state_without_campaign_reward(
    tmp_path: Path,
    tool: str,
    arguments: dict[str, object],
    target_requests: int,
) -> None:
    objective = _objective(endpoint="/generic-proof")
    proof = _receipt(
        ProgressKind.PROOF_CONFIRMED,
        evidence_ref=f"evidence:generic-proof-{tool}",
    )
    validator = _evidence_validator(proof, node_id="node-generic-proof")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    ticket = engine.authorize_action(
        node_id="node-generic-proof",
        objective=objective,
        tool=tool,
        arguments=arguments,
    )

    assert ticket.planner_state_attributed is True
    decision = engine.record_result(
        ticket,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(request_count=target_requests),
            observation_digest=f"generic-proof-{tool}",
            progress_receipts=(proof,),
            evidence_refs=(proof.evidence_ref,),
        ),
    )

    assert decision.disposition is LoopDisposition.PROVE
    attempts = engine.coverage.snapshot().attempts
    attempt = attempts[-1]
    assert attempt["planner_state_attributed"] is True
    assert attempt["planner_attributed"] is False
    index = BranchOutcomeIndex.from_attempts(attempts)
    assert index.outcome_ids
    assert index.campaigns == ()
    assert index.cell_stats(ticket.planner_cell_id).stage == "proof"
    assert engine.context_projection(
        node_id="node-after-generic-proof",
        objective=objective,
    )["coverage_cell"]["stage"] == "proof"
    with pytest.raises(
        InvestigationActionRejectedError,
        match="coverage_cell_proof_complete",
    ):
        engine.authorize_action(
            node_id="node-after-generic-proof",
            objective=objective,
            tool="run_probe",
            arguments={"probe": "sqli_differential"},
        )


def test_online_empty_generic_results_do_not_consume_virtual_planner_attempts(
    tmp_path: Path,
) -> None:
    objective = _objective(endpoint="/generic-empty")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    for index, method in enumerate(("GET", "POST")):
        ticket = engine.authorize_action(
            node_id=f"node-generic-empty-{index}",
            objective=objective,
            tool="http_request",
            arguments={
                "method": method,
                "path": f"/generic-empty/route-{index}",
            },
        )
        assert ticket.planner_state_attributed is True
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(request_count=1),
                observation_digest=f"generic-empty-{index}",
            ),
        )

    attempts = engine.coverage.snapshot().attempts
    assert all(attempt["planner_state_attributed"] is False for attempt in attempts)
    assert all(attempt["planner_attributed"] is False for attempt in attempts)
    index = BranchOutcomeIndex.from_attempts(attempts)
    planner_cell_id = SurfaceCell.from_objective(objective).cell_id
    stats = index.cell_stats(planner_cell_id)
    assert index.outcome_ids == ()
    assert stats.attempt_count == 0
    assert stats.no_progress_streak == 0
    projection = engine.context_projection(node_id="node-after-generic-empty", objective=objective)
    assert projection["coverage_cell"]["attempt_count"] == 0
    assert projection["recommended_campaigns"][0]["probe"] == "sqli_differential"
    catalog = engine.authorize_action(
        node_id="node-catalog-after-generic-empty",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    assert catalog.campaign is not None
    engine.cancel_action(catalog)


def test_online_planner_reserves_the_last_per_cell_attempt_once(tmp_path: Path) -> None:
    objective = _objective(endpoint="/planner-cap")
    receipts = tuple(
        _receipt(
            ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
            evidence_ref=f"evidence:planner-cap-{index}",
        )
        for index in range(7)
    )
    validator = _evidence_validator(*receipts, node_id="node-planner-cap")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    for index, receipt in enumerate(receipts):
        ticket = engine.authorize_action(
            node_id="node-planner-cap",
            objective=objective,
            tool="run_probe",
            arguments={
                "probe": "sqli_differential" if index == 0 else "sqli_exploit",
                "path": f"/planner-cap/{index}",
            },
        )
        engine.record_result(
            ticket,
            objective=objective,
            result=GraphToolResult(
                output=_probe_output(),
                observation_digest=f"planner-cap-{index}",
                progress_receipts=(receipt,),
                evidence_refs=(receipt.evidence_ref,),
            ),
        )

    planner_cell_id = SurfaceCell.from_objective(objective).cell_id
    index = BranchOutcomeIndex.from_attempts(engine.coverage.snapshot().attempts)
    assert index.cell_stats(planner_cell_id).attempt_count == len(receipts)
    last_ticket = engine.authorize_action(
        node_id="node-planner-cap-a",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_exploit", "path": "/planner-cap/a"},
    )
    try:
        with pytest.raises(
            InvestigationActionRejectedError,
            match="planner_cell_attempt_capacity_reached",
        ):
            engine.authorize_action(
                node_id="node-planner-cap-b",
                objective=objective,
                tool="run_probe",
                arguments={"probe": "sqli_exploit", "path": "/planner-cap/b"},
            )
    finally:
        engine.cancel_action(last_ticket)


def test_online_stale_catalog_result_preserves_concurrent_proof(tmp_path: Path) -> None:
    objective = _objective(endpoint="/proof-race")
    proof = _receipt(ProgressKind.PROOF_CONFIRMED, evidence_ref="evidence:proof-race")
    validator = _evidence_validator(proof, node_id="node-proof")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    stale = engine.authorize_action(
        node_id="node-stale",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/proof-race/stale"},
    )
    winner = engine.authorize_action(
        node_id="node-proof",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/proof-race/winner"},
    )
    engine.record_result(
        winner,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="proof-race-winner",
            progress_receipts=(proof,),
            evidence_refs=(proof.evidence_ref,),
        ),
    )

    decision = engine.record_result(
        stale,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="proof-race-stale",
        ),
    )

    attempts = engine.coverage.snapshot().attempts
    assert decision.disposition is LoopDisposition.PROVE
    assert decision.reason == "planner_cell_already_proof_complete"
    assert len(BranchOutcomeIndex.from_attempts(attempts).outcome_ids) == 1
    stale_attempt = next(
        item for item in attempts if item["reservation_id"] == stale.reservation.reservation_id
    )
    assert "planner_feedback_schema_version" not in stale_attempt


def test_shadow_stale_result_does_not_adopt_concurrent_candidate_proof(
    tmp_path: Path,
) -> None:
    objective = _objective(endpoint="/shadow-proof-race")
    proof = _receipt(
        ProgressKind.PROOF_CONFIRMED,
        evidence_ref="evidence:shadow-proof-race",
    )
    validator = _evidence_validator(proof, node_id="node-proof")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
        planner_mode=InvestigationPlannerMode.SHADOW,
    )
    winner = engine.authorize_action(
        node_id="node-proof",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/shadow-proof/winner"},
    )
    stale = engine.authorize_action(
        node_id="node-stale",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/shadow-proof/stale"},
    )
    engine.record_result(
        winner,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="shadow-proof-winner",
            progress_receipts=(proof,),
            evidence_refs=(proof.evidence_ref,),
        ),
    )

    decision = engine.record_result(
        stale,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="shadow-proof-stale",
        ),
    )

    assert decision.disposition is LoopDisposition.PIVOT
    assert decision.reason == "no_typed_delta_requires_a_new_material_dimension"
    assert engine.coverage.projection(stale.cell.cell_id)["exhausted"] is False


def test_shadow_reused_planner_evidence_preserves_legacy_completion(tmp_path: Path) -> None:
    objective = _objective(endpoint="/shadow-evidence")
    receipt = _receipt(
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
        evidence_ref="evidence:shadow-reused",
    )
    validator = _evidence_validator(receipt, node_id="node-shadow-evidence")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
        planner_mode=InvestigationPlannerMode.SHADOW,
    )
    first = engine.authorize_action(
        node_id="node-shadow-evidence",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential", "path": "/shadow-evidence/a"},
    )
    engine.record_result(
        first,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="shadow-evidence-first",
            progress_receipts=(receipt,),
            evidence_refs=(receipt.evidence_ref,),
        ),
    )
    second = engine.authorize_action(
        node_id="node-shadow-evidence",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "filtered_query_bypass", "path": "/shadow-evidence/b"},
    )

    decision = engine.record_result(
        second,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="shadow-evidence-second",
            progress_receipts=(receipt,),
            evidence_refs=(receipt.evidence_ref,),
        ),
    )

    attempts = engine.coverage.snapshot().attempts
    assert decision.disposition is LoopDisposition.CONTINUE
    assert len(attempts) == len((first, second))
    assert attempts[-1]["reservation_id"] == second.reservation.reservation_id
    assert "planner_feedback_schema_version" not in attempts[-1]


def test_online_cross_cell_progress_unlocks_one_retry_then_suppresses_it(
    tmp_path: Path,
) -> None:
    objective = _objective(endpoint="/cross-cell/a")
    receipt = _receipt(
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
        evidence_ref="evidence:cross-cell-progress",
    )
    validator = _evidence_validator(receipt, node_id="node-cross-cell")
    engine = InvestigationEngine.open(
        workspace_dir=tmp_path,
        objectives=(objective,),
        evidence_validator=validator,
        planner_mode=InvestigationPlannerMode.ONLINE,
    )
    blocked = engine.authorize_action(
        node_id="node-blocked",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    engine.record_result(
        blocked,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="cross-cell-empty",
        ),
    )
    progress = engine.authorize_action(
        node_id="node-cross-cell",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "filtered_query_bypass", "path": "/cross-cell/b"},
    )
    engine.record_result(
        progress,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="cross-cell-progress",
            progress_receipts=(receipt,),
            evidence_refs=(receipt.evidence_ref,),
        ),
    )

    campaigns = engine.context_projection(
        node_id="node-context",
        objective=objective,
    )["recommended_campaigns"]

    assert campaigns
    assert campaigns[0]["probe"] == "sqli_differential"
    retry = engine.authorize_action(
        node_id="node-blocked-retry",
        objective=objective,
        tool="run_probe",
        arguments={"probe": "sqli_differential"},
    )
    engine.record_result(
        retry,
        objective=objective,
        result=GraphToolResult(
            output=_probe_output(),
            observation_digest="cross-cell-retry-empty",
        ),
    )

    campaigns = engine.context_projection(
        node_id="node-after-retry",
        objective=objective,
    )["recommended_campaigns"]
    assert all(campaign["probe"] != "sqli_differential" for campaign in campaigns)
    with pytest.raises(
        InvestigationActionRejectedError,
        match=r"(failure_certificate|planner_feedback)_blocks_equivalent_campaign",
    ):
        engine.authorize_action(
            node_id="node-blocked-repeat",
            objective=objective,
            tool="run_probe",
            arguments={"probe": "sqli_differential"},
        )
