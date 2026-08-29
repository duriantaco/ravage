from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.beliefs import (
    BeliefDisposition,
    BeliefLedger,
    BeliefLedgerError,
)
from ravage.agent_core.autonomous_graph.models import (
    AgentSpec,
    GraphAgentRole,
    GraphObjective,
    Hypothesis,
)
from ravage.agent_core.autonomous_graph.scheduler import (
    GraphProgressBinding,
    ProgressBatchClass,
    ProgressKind,
    ProgressReceipt,
    ProgressReceiptValidationError,
    ProgressSource,
    validate_progress_receipt_batch,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

SUPPORTED_BELIEF_BASIS_POINTS = 6500
SECOND_REVISION_SEQUENCE = 2
TARGET_IDENTITY = "target:belief-fixture"


@dataclass(frozen=True)
class _EvidenceRecord:
    evidence_id: str
    kind: str
    target_identity: str = TARGET_IDENTITY
    producer_node_id: str = "node-002"
    material: bool = True
    source: str = "tool_http_request"


class _EvidenceValidator:
    def __init__(
        self,
        records: Sequence[_EvidenceRecord],
        *,
        target_identity: str = TARGET_IDENTITY,
    ) -> None:
        self.target_identity = target_identity
        self.records = {record.evidence_id: record for record in records}
        self.calls: list[tuple[tuple[str, ...], bool]] = []

    def validate_references(
        self,
        evidence_refs: Sequence[str],
        *,
        require_trusted: bool = False,
    ) -> tuple[object, ...]:
        refs = tuple(evidence_refs)
        self.calls.append((refs, require_trusted))
        if any(ref not in self.records for ref in refs):
            message = "unknown or untrusted evidence"
            raise ValueError(message)
        return tuple(self.records[ref] for ref in refs)


def _hypothesis() -> Hypothesis:
    objective = GraphObjective.create(
        family="sql_injection",
        instruction="A filtered search parameter changes query semantics",
        endpoint="/search",
        inputs=("query",),
        strategy="boolean_differential",
        expected_signal="a repeatable target-observed response differential",
    )
    return Hypothesis.from_objective(objective)


def _agent_spec() -> AgentSpec:
    return AgentSpec.create(role=GraphAgentRole.SPECIALIST)


def _binding(
    hypothesis: Hypothesis,
    agent_spec: AgentSpec,
    *,
    node_id: str = "node-002",
) -> GraphProgressBinding:
    return GraphProgressBinding(
        graph_id="graph-belief-fixture",
        target_identity=TARGET_IDENTITY,
        tool_call_id="tool-call-001",
        runtime_binding_id="runtime-binding:fixture",
        node_id=node_id,
        objective_fingerprint=hypothesis.objective_fingerprint,
        hypothesis_fingerprint=hypothesis.fingerprint,
        agent_spec_fingerprint=agent_spec.fingerprint,
    )


def _receipt(
    kind: ProgressKind,
    *,
    evidence_ref: str,
    source: ProgressSource = ProgressSource.TARGET_OBSERVATION,
) -> ProgressReceipt:
    return ProgressReceipt(
        kind=kind,
        value=f"fixture {kind.value}",
        evidence_ref=evidence_ref,
        source=source,
    )


def test_trusted_executor_receipt_creates_persistent_belief_revision(
    tmp_path: Path,
) -> None:
    validator = _EvidenceValidator(
        (
            _EvidenceRecord(
                evidence_id="evidence:response-diff",
                kind="response_differential",
            ),
        )
    )
    path = tmp_path / "beliefs.json"
    hypothesis = _hypothesis()
    agent_spec = _agent_spec()
    ledger = BeliefLedger.open(path, evidence_validator=validator)
    receipt = _receipt(
        ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
        evidence_ref="evidence:response-diff",
    )
    batch = validate_progress_receipt_batch(
        (receipt,),
        result_evidence_refs=(receipt.evidence_ref,),
        evidence_validator=validator,
        binding=_binding(hypothesis, agent_spec),
    )

    revision = ledger.record_from_validated_batch(
        hypothesis=hypothesis,
        agent_spec=agent_spec,
        producer_node_id="node-002",
        batch=batch,
        evidence_epoch=3,
    )

    assert revision is not None
    assert revision.disposition is BeliefDisposition.SUPPORTED
    assert revision.sequence == 1
    assert revision.executor_receipt_digest.startswith("executor-receipt:")
    assert validator.calls == [(("evidence:response-diff",), True)]

    reopened = BeliefLedger.open(path, evidence_validator=validator)
    assert reopened.head(hypothesis.fingerprint) == revision
    assert (
        reopened.projection(hypothesis.fingerprint)["belief_basis_points"]
        == SUPPORTED_BELIEF_BASIS_POINTS
    )


def test_model_statement_cannot_create_a_belief_revision(tmp_path: Path) -> None:
    validator = _EvidenceValidator(
        (
            _EvidenceRecord(
                evidence_id="evidence:model-claim",
                kind="hypothesis_confirmed",
            ),
        )
    )
    hypothesis = _hypothesis()
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=validator,
    )

    revision = ledger.record_from_receipts(
        hypothesis=hypothesis,
        agent_spec=_agent_spec(),
        producer_node_id="node-002",
        receipts=(
            _receipt(
                ProgressKind.HYPOTHESIS_CONFIRMED,
                evidence_ref="evidence:model-claim",
                source=ProgressSource.MODEL_STATEMENT,
            ),
        ),
        evidence_epoch=0,
    )

    assert revision is None
    assert ledger.head(hypothesis.fingerprint) is None
    assert validator.calls == [((), True)]


def test_unknown_evidence_fails_before_belief_commit(tmp_path: Path) -> None:
    hypothesis = _hypothesis()
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=_EvidenceValidator(()),
    )

    with pytest.raises(ValueError, match="unknown or untrusted"):
        ledger.record_from_receipts(
            hypothesis=hypothesis,
            agent_spec=_agent_spec(),
            producer_node_id="node-002",
            receipts=(
                _receipt(
                    ProgressKind.HYPOTHESIS_CONFIRMED,
                    evidence_ref="evidence:missing",
                ),
            ),
            evidence_epoch=1,
        )

    assert ledger.head(hypothesis.fingerprint) is None


def test_contradictory_receipts_cannot_create_one_revision(tmp_path: Path) -> None:
    hypothesis = _hypothesis()
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=_EvidenceValidator(
            (
                _EvidenceRecord(
                    evidence_id="evidence:support",
                    kind="hypothesis_confirmed",
                ),
                _EvidenceRecord(
                    evidence_id="evidence:disproof",
                    kind="hypothesis_disproved",
                ),
            )
        ),
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="both support and disprove",
    ):
        ledger.record_from_receipts(
            hypothesis=hypothesis,
            agent_spec=_agent_spec(),
            producer_node_id="node-002",
            receipts=(
                _receipt(
                    ProgressKind.HYPOTHESIS_CONFIRMED,
                    evidence_ref="evidence:support",
                ),
                _receipt(
                    ProgressKind.HYPOTHESIS_DISPROVED,
                    evidence_ref="evidence:disproof",
                ),
            ),
            evidence_epoch=2,
        )


def test_confirmed_receipt_cannot_use_raw_or_incompatible_evidence(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=_EvidenceValidator(
            (
                _EvidenceRecord(
                    evidence_id="evidence:raw-observation",
                    kind="raw_observation",
                ),
            )
        ),
    )

    with pytest.raises(
        ProgressReceiptValidationError,
        match="incompatible with its evidence kind",
    ):
        ledger.record_from_receipts(
            hypothesis=hypothesis,
            agent_spec=_agent_spec(),
            producer_node_id="node-002",
            receipts=(
                _receipt(
                    ProgressKind.HYPOTHESIS_CONFIRMED,
                    evidence_ref="evidence:raw-observation",
                ),
            ),
            evidence_epoch=1,
        )

    assert ledger.head(hypothesis.fingerprint) is None
    assert ledger.snapshot().order == []


def test_validated_batch_subject_mismatch_cannot_mutate_the_ledger(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    agent_spec = _agent_spec()
    validator = _EvidenceValidator(
        (
            _EvidenceRecord(
                evidence_id="evidence:confirmation",
                kind="hypothesis_confirmed",
            ),
        )
    )
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=validator,
    )
    receipt = _receipt(
        ProgressKind.HYPOTHESIS_CONFIRMED,
        evidence_ref="evidence:confirmation",
    )
    batch = validate_progress_receipt_batch(
        (receipt,),
        result_evidence_refs=(receipt.evidence_ref,),
        evidence_validator=validator,
        binding=_binding(hypothesis, agent_spec),
    )

    with pytest.raises(BeliefLedgerError, match=r"node_id.*belief subject"):
        ledger.record_from_validated_batch(
            hypothesis=hypothesis,
            agent_spec=agent_spec,
            producer_node_id="node-999",
            batch=batch,
            evidence_epoch=1,
        )

    assert ledger.head(hypothesis.fingerprint) is None
    assert ledger.snapshot().order == []


def test_routed_pivot_batch_never_mutates_a_hypothesis_belief(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    agent_spec = _agent_spec()
    records = (
        _EvidenceRecord(
            evidence_id="evidence:checkpoint",
            kind="extraction_checkpoint",
        ),
        _EvidenceRecord(
            evidence_id="evidence:credential-rejected",
            kind="hypothesis_disproved",
        ),
    )
    validator = _EvidenceValidator(records)
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=validator,
    )
    binding = GraphProgressBinding(
        graph_id="graph-belief-fixture",
        target_identity=TARGET_IDENTITY,
        tool_call_id="tool-call-pivot",
        runtime_binding_id="runtime-binding:fixture",
        node_id="node-002",
        objective_fingerprint=hypothesis.objective_fingerprint,
        hypothesis_fingerprint="",
        agent_spec_fingerprint=agent_spec.fingerprint,
    )
    receipts = (
        _receipt(
            ProgressKind.EXTRACTION_CHECKPOINT,
            evidence_ref="evidence:checkpoint",
        ),
        _receipt(
            ProgressKind.HYPOTHESIS_DISPROVED,
            evidence_ref="evidence:credential-rejected",
        ),
    )
    batch = validate_progress_receipt_batch(
        receipts,
        result_evidence_refs=tuple(record.evidence_id for record in records),
        evidence_validator=validator,
        binding=binding,
        counterfactual_objective_fingerprint="objective:credential-replay",
        allow_routed_pivot=True,
    )

    revision = ledger.record_from_validated_batch(
        hypothesis=hypothesis,
        agent_spec=agent_spec,
        producer_node_id="node-002",
        batch=batch,
        evidence_epoch=1,
    )

    assert batch.classification is ProgressBatchClass.PIVOT
    assert revision is None
    assert ledger.head(hypothesis.fingerprint) is None
    assert ledger.snapshot().order == []


def test_belief_revisions_form_a_tamper_evident_append_only_chain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "beliefs.json"
    hypothesis = _hypothesis()
    validator = _EvidenceValidator(
        (
            _EvidenceRecord(
                evidence_id="evidence:support",
                kind="response_differential",
            ),
            _EvidenceRecord(
                evidence_id="evidence:confirmation",
                kind="hypothesis_confirmed",
                producer_node_id="node-003",
            ),
        )
    )
    ledger = BeliefLedger.open(path, evidence_validator=validator)
    first = ledger.record_from_receipts(
        hypothesis=hypothesis,
        agent_spec=_agent_spec(),
        producer_node_id="node-002",
        receipts=(
            _receipt(
                ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
                evidence_ref="evidence:support",
            ),
        ),
        evidence_epoch=1,
    )
    second = ledger.record_from_receipts(
        hypothesis=hypothesis,
        agent_spec=_agent_spec(),
        producer_node_id="node-003",
        receipts=(
            _receipt(
                ProgressKind.HYPOTHESIS_CONFIRMED,
                evidence_ref="evidence:confirmation",
            ),
        ),
        evidence_epoch=2,
    )

    assert first is not None
    assert second is not None
    assert second.sequence == SECOND_REVISION_SEQUENCE
    assert second.previous_revision_id == first.revision_id
    assert second.disposition is BeliefDisposition.CONFIRMED

    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["revisions"][second.revision_id]["disposition"] = "disproved"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(BeliefLedgerError, match="ID mismatch"):
        BeliefLedger.open(path, evidence_validator=validator)


def test_weak_support_cannot_downgrade_a_conclusive_belief(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    agent_spec = _agent_spec()
    validator = _EvidenceValidator(
        (
            _EvidenceRecord(
                evidence_id="evidence:confirmation",
                kind="hypothesis_confirmed",
            ),
            _EvidenceRecord(
                evidence_id="evidence:later-support",
                kind="response_differential",
                producer_node_id="node-003",
            ),
        )
    )
    ledger = BeliefLedger.open(
        tmp_path / "beliefs.json",
        evidence_validator=validator,
    )
    confirmed = ledger.record_from_receipts(
        hypothesis=hypothesis,
        agent_spec=agent_spec,
        producer_node_id="node-002",
        receipts=(
            _receipt(
                ProgressKind.HYPOTHESIS_CONFIRMED,
                evidence_ref="evidence:confirmation",
            ),
        ),
        evidence_epoch=1,
    )
    after_weak_support = ledger.record_from_receipts(
        hypothesis=hypothesis,
        agent_spec=agent_spec,
        producer_node_id="node-003",
        receipts=(
            _receipt(
                ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
                evidence_ref="evidence:later-support",
            ),
        ),
        evidence_epoch=2,
    )

    assert confirmed is not None
    assert after_weak_support == confirmed
    assert ledger.head(hypothesis.fingerprint) == confirmed
    assert len(ledger.snapshot().order) == 1
