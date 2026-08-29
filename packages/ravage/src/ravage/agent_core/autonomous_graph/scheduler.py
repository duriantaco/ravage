from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from ravage.agent_core.autonomous_graph.coordinator import (
    GraphCoordinator,
    GraphLeaseGrantError,
)
from ravage.agent_core.autonomous_graph.protocol import (
    GraphWorkerAction,
    semantic_action_fingerprint,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class ProgressReceiptValidationError(ValueError):
    """Raised before graph mutation when executor progress is not admissible."""


class ProgressKind(StrEnum):
    PROOF_CONFIRMED = "proof_confirmed"
    PRIMITIVE_CONFIRMED = "primitive_confirmed"
    AUTH_STATE_CHANGED = "auth_state_changed"
    REQUEST_TEMPLATE_VALIDATED = "request_template_validated"
    RESPONSE_DIFFERENTIAL_VALIDATED = "response_differential_validated"
    SQL_ORACLE_CALIBRATED = "sql_oracle_calibrated"
    EXTRACTION_CHECKPOINT = "extraction_checkpoint"
    HYPOTHESIS_CONFIRMED = "hypothesis_confirmed"
    HYPOTHESIS_DISPROVED = "hypothesis_disproved"


class ProgressSource(StrEnum):
    TARGET_OBSERVATION = "target_observation"
    INDEPENDENT_VALIDATOR = "independent_validator"
    MODEL_STATEMENT = "model_statement"


_TRUSTED_PROGRESS_SOURCES = frozenset(
    {
        ProgressSource.TARGET_OBSERVATION,
        ProgressSource.INDEPENDENT_VALIDATOR,
    }
)
_PROOF_CLOSEABLE_KINDS = frozenset(
    {
        ProgressKind.PRIMITIVE_CONFIRMED,
        ProgressKind.AUTH_STATE_CHANGED,
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
        ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
        ProgressKind.SQL_ORACLE_CALIBRATED,
        ProgressKind.EXTRACTION_CHECKPOINT,
        ProgressKind.HYPOTHESIS_CONFIRMED,
    }
)
_OBSERVATION_ONLY_TOOLS = frozenset({"process_read"})
_TRUSTED_TOOL_EVIDENCE_SOURCES = frozenset(
    {
        "tool_run_command",
        "tool_run_python",
        "tool_run_probe",
        "tool_validate_poc",
        "tool_http_request",
    }
)
_ALLOWED_EVIDENCE_KINDS = {
    ProgressKind.PROOF_CONFIRMED: frozenset({"proof_confirmed"}),
    ProgressKind.PRIMITIVE_CONFIRMED: frozenset({"primitive_confirmed"}),
    ProgressKind.AUTH_STATE_CHANGED: frozenset({"auth_state_changed"}),
    ProgressKind.REQUEST_TEMPLATE_VALIDATED: frozenset({"request_contract"}),
    ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED: frozenset({"response_differential"}),
    ProgressKind.SQL_ORACLE_CALIBRATED: frozenset({"sql_oracle_calibrated"}),
    ProgressKind.EXTRACTION_CHECKPOINT: frozenset({"extraction_checkpoint"}),
    ProgressKind.HYPOTHESIS_CONFIRMED: frozenset({"hypothesis_confirmed"}),
    ProgressKind.HYPOTHESIS_DISPROVED: frozenset(
        {
            "hypothesis_disproved",
            "credential_replay_rejected",
        }
    ),
}


class ProgressEvidenceValidator(Protocol):
    """Structural evidence resolver used without importing the evidence module."""

    target_identity: str

    def validate_references(
        self,
        evidence_refs: Sequence[str],
        *,
        require_trusted: bool = False,
    ) -> tuple[object, ...]: ...


@dataclass(frozen=True)
class GraphProgressBinding:
    """Control-plane identity attached after an executor returns evidence."""

    graph_id: str
    target_identity: str
    tool_call_id: str
    runtime_binding_id: str
    node_id: str
    objective_fingerprint: str
    hypothesis_fingerprint: str
    agent_spec_fingerprint: str

    def __post_init__(self) -> None:
        required = {
            "graph_id": self.graph_id,
            "target_identity": self.target_identity,
            "tool_call_id": self.tool_call_id,
            "runtime_binding_id": self.runtime_binding_id,
            "node_id": self.node_id,
            "objective_fingerprint": self.objective_fingerprint,
            "agent_spec_fingerprint": self.agent_spec_fingerprint,
        }
        missing = tuple(name for name, value in required.items() if not value.strip())
        if missing:
            message = "progress binding fields are required: " + ",".join(missing)
            raise ProgressReceiptValidationError(message)

    def to_json(self) -> dict[str, str]:
        return {
            "graph_id": self.graph_id,
            "target_identity": self.target_identity,
            "tool_call_id": self.tool_call_id,
            "runtime_binding_id": self.runtime_binding_id,
            "node_id": self.node_id,
            "objective_fingerprint": self.objective_fingerprint,
            "hypothesis_fingerprint": self.hypothesis_fingerprint,
            "agent_spec_fingerprint": self.agent_spec_fingerprint,
        }


class ProgressBatchClass(StrEnum):
    EMPTY = "empty"
    SUPPORT = "support"
    CONFIRM = "confirm"
    DISPROVE = "disprove"
    PIVOT = "pivot"
    PROOF = "proof"


@dataclass(frozen=True)
class ProgressReceipt:
    """A typed progress claim carrying its authoritative evidence provenance."""

    kind: ProgressKind
    value: str
    evidence_ref: str
    source: ProgressSource
    binding: GraphProgressBinding | None = None

    def __post_init__(self) -> None:
        if not self.value.strip():
            message = "progress receipt value is required"
            raise ValueError(message)
        if not self.evidence_ref.strip():
            message = "progress receipt evidence_ref is required"
            raise ValueError(message)

    @property
    def trusted(self) -> bool:
        return self.source in _TRUSTED_PROGRESS_SOURCES

    @property
    def token(self) -> str:
        fields = [
            "progress-receipt-v2",
            self.kind.value,
            " ".join(self.value.strip().split()),
            self.evidence_ref.strip(),
            self.source.value,
        ]
        if self.binding is not None:
            fields.append(
                json.dumps(
                    self.binding.to_json(),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        canonical = "|".join(fields)
        return f"{self.kind.value}:{hashlib.sha256(canonical.encode()).hexdigest()}"

    def bind(self, binding: GraphProgressBinding) -> ProgressReceipt:
        if self.binding is not None and self.binding != binding:
            message = "executor receipt attempted to override its control-plane binding"
            raise ProgressReceiptValidationError(message)
        return ProgressReceipt(
            kind=self.kind,
            value=self.value,
            evidence_ref=self.evidence_ref,
            source=self.source,
            binding=binding,
        )


@dataclass(frozen=True)
class ValidatedProgressBatch:
    """One semantically validated executor result, safe for scheduler consumption."""

    validation_digest: str
    binding: GraphProgressBinding
    classification: ProgressBatchClass
    trusted_receipts: tuple[ProgressReceipt, ...]
    ignored_untrusted_receipts: tuple[ProgressReceipt, ...]
    evidence_refs: tuple[str, ...]
    progress_tokens: tuple[str, ...]
    counterfactual_objective_fingerprint: str = ""


def validate_progress_receipt_batch(  # noqa: PLR0913
    receipts: Sequence[ProgressReceipt],
    *,
    result_evidence_refs: Sequence[str],
    evidence_validator: ProgressEvidenceValidator | None,
    binding: GraphProgressBinding,
    counterfactual_objective_fingerprint: str = "",
    allow_routed_pivot: bool = False,
) -> ValidatedProgressBatch:
    """Bind and validate every trusted receipt before graph state can change."""
    result_refs = _clean_strings(result_evidence_refs)
    trusted: list[ProgressReceipt] = []
    ignored: list[ProgressReceipt] = []
    semantic_sources: dict[tuple[str, str, str], ProgressSource] = {}
    for raw_receipt in receipts:
        receipt = raw_receipt.bind(binding)
        if not receipt.trusted:
            ignored.append(receipt)
            continue
        semantic_key = (
            receipt.kind.value,
            " ".join(receipt.value.strip().split()),
            receipt.evidence_ref.strip(),
        )
        previous_source = semantic_sources.get(semantic_key)
        if previous_source is not None and previous_source is not receipt.source:
            message = "equivalent progress receipts disagree on authoritative source"
            raise ProgressReceiptValidationError(message)
        semantic_sources[semantic_key] = receipt.source
        trusted.append(receipt)

    trusted_by_token = {receipt.token: receipt for receipt in trusted}
    trusted_receipts = tuple(trusted_by_token[token] for token in sorted(trusted_by_token))
    kinds = {receipt.kind for receipt in trusted_receipts}
    counterfactual = " ".join(counterfactual_objective_fingerprint.strip().split())
    receipt_refs = _clean_strings(receipt.evidence_ref for receipt in trusted_receipts)
    if not set(receipt_refs).issubset(result_refs):
        message = "trusted receipt references evidence omitted from the executor result"
        raise ProgressReceiptValidationError(message)

    if trusted_receipts and evidence_validator is None:
        message = "trusted progress requires an evidence validator"
        raise ProgressReceiptValidationError(message)
    records = (
        evidence_validator.validate_references(
            receipt_refs,
            require_trusted=True,
        )
        if evidence_validator is not None
        else ()
    )
    by_id = {_record_text(record, "evidence_id"): record for record in records}
    if set(by_id) != set(receipt_refs):
        message = "evidence validator did not return every trusted receipt record"
        raise ProgressReceiptValidationError(message)
    validator_target = str(getattr(evidence_validator, "target_identity", "")).strip()
    if trusted_receipts and validator_target != binding.target_identity:
        message = "progress binding target does not match the evidence validator"
        raise ProgressReceiptValidationError(message)
    for receipt in trusted_receipts:
        record = by_id[receipt.evidence_ref]
        _validate_receipt_record(
            receipt,
            record=record,
            binding=binding,
        )

    classification = _progress_batch_classification(
        kinds,
        binding=binding,
        counterfactual_objective_fingerprint=counterfactual,
        allow_routed_pivot=allow_routed_pivot,
    )
    progress_tokens = tuple(receipt.token for receipt in trusted_receipts)
    validation_digest = _progress_batch_validation_digest(
        binding=binding,
        classification=classification,
        counterfactual_objective_fingerprint=counterfactual,
        progress_tokens=progress_tokens,
        ignored_untrusted_receipts=tuple(ignored),
        evidence_refs=receipt_refs,
    )
    return ValidatedProgressBatch(
        validation_digest=validation_digest,
        binding=binding,
        classification=classification,
        trusted_receipts=trusted_receipts,
        ignored_untrusted_receipts=tuple(ignored),
        evidence_refs=receipt_refs,
        progress_tokens=progress_tokens,
        counterfactual_objective_fingerprint=counterfactual,
    )


def require_validated_progress_batch(
    candidate: object,
) -> ValidatedProgressBatch:
    """Reject hand-built or mutated batches at every state-mutation boundary."""
    if not isinstance(candidate, ValidatedProgressBatch):
        message = "scheduler progress requires a ValidatedProgressBatch"
        raise ProgressReceiptValidationError(message)
    batch = candidate
    trusted = batch.trusted_receipts
    ignored = batch.ignored_untrusted_receipts
    if any(not receipt.trusted for receipt in trusted):
        message = "validated progress batch contains an untrusted receipt"
        raise ProgressReceiptValidationError(message)
    if any(receipt.trusted for receipt in ignored):
        message = "validated progress batch ignored a trusted receipt"
        raise ProgressReceiptValidationError(message)
    if any(receipt.binding != batch.binding for receipt in (*trusted, *ignored)):
        message = "validated progress batch receipt binding mismatch"
        raise ProgressReceiptValidationError(message)
    expected_trusted = tuple(
        {receipt.token: receipt for receipt in trusted}[token]
        for token in sorted({receipt.token for receipt in trusted})
    )
    if trusted != expected_trusted:
        message = "validated progress batch trusted receipts are not canonical"
        raise ProgressReceiptValidationError(message)
    _validate_semantic_receipt_sources(trusted)
    expected_refs = _clean_strings(receipt.evidence_ref for receipt in trusted)
    expected_tokens = tuple(receipt.token for receipt in trusted)
    if batch.evidence_refs != expected_refs or batch.progress_tokens != expected_tokens:
        message = "validated progress batch receipt projection mismatch"
        raise ProgressReceiptValidationError(message)
    counterfactual = " ".join(batch.counterfactual_objective_fingerprint.strip().split())
    if counterfactual != batch.counterfactual_objective_fingerprint:
        message = "validated progress batch counterfactual is not canonical"
        raise ProgressReceiptValidationError(message)
    expected_classification = _progress_batch_classification(
        {receipt.kind for receipt in trusted},
        binding=batch.binding,
        counterfactual_objective_fingerprint=counterfactual,
        allow_routed_pivot=batch.classification is ProgressBatchClass.PIVOT,
    )
    if batch.classification is not expected_classification:
        message = "validated progress batch classification mismatch"
        raise ProgressReceiptValidationError(message)
    expected_digest = _progress_batch_validation_digest(
        binding=batch.binding,
        classification=batch.classification,
        counterfactual_objective_fingerprint=counterfactual,
        progress_tokens=batch.progress_tokens,
        ignored_untrusted_receipts=ignored,
        evidence_refs=batch.evidence_refs,
    )
    if batch.validation_digest != expected_digest:
        message = "validated progress batch digest mismatch"
        raise ProgressReceiptValidationError(message)
    return batch


def _validate_semantic_receipt_sources(
    receipts: Sequence[ProgressReceipt],
) -> None:
    sources: dict[tuple[str, str, str], ProgressSource] = {}
    for receipt in receipts:
        semantic_key = (
            receipt.kind.value,
            " ".join(receipt.value.strip().split()),
            receipt.evidence_ref.strip(),
        )
        previous = sources.get(semantic_key)
        if previous is not None and previous is not receipt.source:
            message = "equivalent progress receipts disagree on authoritative source"
            raise ProgressReceiptValidationError(message)
        sources[semantic_key] = receipt.source


def _progress_batch_classification(
    kinds: set[ProgressKind],
    *,
    binding: GraphProgressBinding,
    counterfactual_objective_fingerprint: str,
    allow_routed_pivot: bool,
) -> ProgressBatchClass:
    has_mixed_disproof = ProgressKind.HYPOTHESIS_DISPROVED in kinds and len(kinds) > 1
    if not has_mixed_disproof:
        return _classify_progress(kinds)
    pivot_support_kinds = kinds - {ProgressKind.HYPOTHESIS_DISPROVED}
    safe_routed_pivot = (
        allow_routed_pivot
        and bool(counterfactual_objective_fingerprint)
        and not binding.hypothesis_fingerprint
        and pivot_support_kinds <= (_PROOF_CLOSEABLE_KINDS - {ProgressKind.HYPOTHESIS_CONFIRMED})
        and ProgressKind.PROOF_CONFIRMED not in pivot_support_kinds
    )
    if not safe_routed_pivot:
        message = "one executor result cannot both support and disprove a hypothesis"
        raise ProgressReceiptValidationError(message)
    return ProgressBatchClass.PIVOT


def _progress_batch_validation_digest(  # noqa: PLR0913
    *,
    binding: GraphProgressBinding,
    classification: ProgressBatchClass,
    counterfactual_objective_fingerprint: str,
    progress_tokens: Sequence[str],
    ignored_untrusted_receipts: Sequence[ProgressReceipt],
    evidence_refs: Sequence[str],
) -> str:
    payload = {
        "binding": binding.to_json(),
        "classification": classification.value,
        "counterfactual_objective_fingerprint": (counterfactual_objective_fingerprint),
        "receipt_tokens": list(progress_tokens),
        "ignored_untrusted_tokens": [receipt.token for receipt in ignored_untrusted_receipts],
        "evidence_refs": list(evidence_refs),
    }
    return (
        "progress-batch:"
        + hashlib.sha256(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )


def _validate_receipt_record(
    receipt: ProgressReceipt,
    *,
    record: object,
    binding: GraphProgressBinding,
) -> None:
    if _record_text(record, "target_identity") != binding.target_identity:
        message = "trusted receipt evidence belongs to another target"
        raise ProgressReceiptValidationError(message)
    if _record_text(record, "producer_node_id") != binding.node_id:
        message = "trusted receipt evidence belongs to another producer node"
        raise ProgressReceiptValidationError(message)
    if getattr(record, "material", None) is not True:
        message = "trusted progress requires material evidence"
        raise ProgressReceiptValidationError(message)
    evidence_kind = _record_text(record, "kind")
    if evidence_kind not in _ALLOWED_EVIDENCE_KINDS[receipt.kind]:
        message = "progress receipt kind is incompatible with its evidence kind"
        raise ProgressReceiptValidationError(message)
    evidence_source = _record_text(record, "source")
    if (
        receipt.source is ProgressSource.INDEPENDENT_VALIDATOR
        and evidence_source != "coordinator_validator"
    ):
        message = "independent-validator receipt lacks validator evidence"
        raise ProgressReceiptValidationError(message)
    if (
        receipt.source is ProgressSource.TARGET_OBSERVATION
        and evidence_source not in _TRUSTED_TOOL_EVIDENCE_SOURCES
    ):
        message = "target-observation receipt lacks direct trusted tool evidence"
        raise ProgressReceiptValidationError(message)


def _record_text(record: object, field: str) -> str:
    value = getattr(record, field, "")
    return str(getattr(value, "value", value)).strip()


def _classify_progress(kinds: set[ProgressKind]) -> ProgressBatchClass:
    if not kinds:
        return ProgressBatchClass.EMPTY
    if ProgressKind.PROOF_CONFIRMED in kinds:
        return ProgressBatchClass.PROOF
    if ProgressKind.HYPOTHESIS_DISPROVED in kinds:
        return ProgressBatchClass.DISPROVE
    if ProgressKind.HYPOTHESIS_CONFIRMED in kinds:
        return ProgressBatchClass.CONFIRM
    return ProgressBatchClass.SUPPORT


def _clean_strings(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(
        sorted({" ".join(str(value).strip().split()) for value in values if str(value).strip()})
    )


@dataclass(frozen=True)
class LeaseDecision:
    granted: bool
    reason: str
    node_id: str
    additional_requests: int = 0
    lease_limit: int = 0
    evidence_epoch: int = 0
    proof_eligible: bool = False
    proof_evidence_refs: tuple[str, ...] = ()
    progress_tokens: tuple[str, ...] = ()


@dataclass(frozen=True)
class ObservationDecision:
    node_id: str
    repeated_count: int
    watchdog_triggered: bool
    reason: str


class ProgressiveGraphScheduler:
    """
    Grant small extensions only for novel trusted evidence or a true pivot.

    Global requests, proof reserve, and per-node limits remain owned by the
    coordinator so parallel workers cannot race past them.
    """

    def __init__(self, coordinator: GraphCoordinator) -> None:
        self.coordinator = coordinator

    def action_fingerprint(
        self,
        node_id: str,
        action: GraphWorkerAction,
    ) -> str:
        """Compute the semantic slot without consuming it."""
        fingerprint = semantic_action_fingerprint(action)
        tool = str(action.payload.get("tool") or "")
        if tool in _OBSERVATION_ONLY_TOOLS:
            node = self.coordinator.state.nodes[node_id]
            fingerprint = f"{fingerprint}:observation-{node.tool_calls_started + 1}"
        return fingerprint

    async def register_action(
        self,
        node_id: str,
        action: GraphWorkerAction,
    ) -> str:
        fingerprint = self.action_fingerprint(node_id, action)
        await self.coordinator.register_semantic_action(
            node_id,
            fingerprint=fingerprint,
        )
        return fingerprint

    async def record_observation(
        self,
        node_id: str,
        *,
        digest: str,
    ) -> ObservationDecision:
        triggered = await self.coordinator.record_observation(
            node_id,
            digest=digest,
        )
        node = self.coordinator.state.nodes[node_id]
        return ObservationDecision(
            node_id=node_id,
            repeated_count=node.repeated_observation_count,
            watchdog_triggered=triggered,
            reason=("repeated_observation_requires_pivot" if triggered else "observation_recorded"),
        )

    async def apply_progress(
        self,
        node_id: str,
        batch: ValidatedProgressBatch,
    ) -> LeaseDecision:
        batch = require_validated_progress_batch(batch)
        node = self.coordinator.state.nodes[node_id]
        expected_binding = {
            "graph_id": self.coordinator.state.graph_id,
            "node_id": node_id,
            "objective_fingerprint": node.objective.fingerprint,
            "hypothesis_fingerprint": (
                node.hypothesis.fingerprint if node.hypothesis is not None else ""
            ),
            "agent_spec_fingerprint": node.agent_spec.fingerprint,
        }
        actual_binding = batch.binding.to_json()
        mismatch = tuple(
            field
            for field, expected in expected_binding.items()
            if actual_binding[field] != expected
        )
        if mismatch:
            raise ProgressReceiptValidationError(
                "validated progress batch is bound to another graph subject: " + ",".join(mismatch)
            )
        if batch.classification is ProgressBatchClass.EMPTY:
            return self._denied(
                node_id,
                reason="untrusted_or_missing_material_progress",
            )

        if batch.classification is ProgressBatchClass.PROOF:
            proof_receipts = tuple(
                receipt
                for receipt in batch.trusted_receipts
                if receipt.kind is ProgressKind.PROOF_CONFIRMED
            )
            return LeaseDecision(
                granted=False,
                reason="trusted_proof_ready_for_gate",
                node_id=node_id,
                lease_limit=self.coordinator.state.nodes[node_id].lease_limit,
                evidence_epoch=self.coordinator.state.evidence_epoch,
                proof_eligible=True,
                proof_evidence_refs=tuple(
                    sorted({receipt.evidence_ref.strip() for receipt in proof_receipts})
                ),
                progress_tokens=batch.progress_tokens,
            )

        disproved = tuple(
            receipt
            for receipt in batch.trusted_receipts
            if receipt.kind is ProgressKind.HYPOTHESIS_DISPROVED
        )
        if batch.classification in {
            ProgressBatchClass.SUPPORT,
            ProgressBatchClass.CONFIRM,
            ProgressBatchClass.PIVOT,
        }:
            additional = self.coordinator.state.limits.progress_lease_extension
            proof_eligible = True
            reason = (
                "trusted_routed_pivot_lease_granted"
                if batch.classification is ProgressBatchClass.PIVOT
                else "trusted_progress_lease_granted"
            )
            counterfactual = (
                batch.counterfactual_objective_fingerprint
                if batch.classification is ProgressBatchClass.PIVOT
                else ""
            )
        elif batch.classification is ProgressBatchClass.DISPROVE:
            counterfactual = batch.counterfactual_objective_fingerprint
            if not counterfactual:
                return self._denied(
                    node_id,
                    reason="disproved_hypothesis_requires_novel_counterfactual",
                )
            additional = self.coordinator.state.limits.counterfactual_lease_extension
            proof_eligible = False
            reason = "novel_counterfactual_lease_granted"
        else:
            return self._denied(
                node_id,
                reason="receipt_kind_does_not_unlock_requests",
            )

        progress_tokens = batch.progress_tokens
        disproved_tokens = tuple(sorted(receipt.token for receipt in disproved))
        previous_limit = self.coordinator.state.nodes[node_id].lease_limit
        try:
            node = await self.coordinator.apply_progress_lease(
                node_id,
                progress_tokens=progress_tokens,
                disproved_hypothesis_tokens=disproved_tokens,
                additional_requests=additional,
                proof_eligible=proof_eligible,
                counterfactual_objective_fingerprint=counterfactual,
                reason=reason,
            )
        except GraphLeaseGrantError as exc:
            return self._denied(node_id, reason=str(exc))
        return LeaseDecision(
            granted=True,
            reason=reason,
            node_id=node_id,
            additional_requests=node.lease_limit - previous_limit,
            lease_limit=node.lease_limit,
            evidence_epoch=self.coordinator.state.evidence_epoch,
            proof_eligible=node.proof_eligible,
            progress_tokens=progress_tokens,
        )

    def _denied(self, node_id: str, *, reason: str) -> LeaseDecision:
        node = self.coordinator.state.nodes[node_id]
        return LeaseDecision(
            granted=False,
            reason=reason,
            node_id=node_id,
            lease_limit=node.lease_limit,
            evidence_epoch=self.coordinator.state.evidence_epoch,
            proof_eligible=node.proof_eligible,
        )


__all__ = [
    "GraphProgressBinding",
    "LeaseDecision",
    "ObservationDecision",
    "ProgressBatchClass",
    "ProgressEvidenceValidator",
    "ProgressKind",
    "ProgressReceipt",
    "ProgressReceiptValidationError",
    "ProgressSource",
    "ProgressiveGraphScheduler",
    "ValidatedProgressBatch",
    "require_validated_progress_batch",
    "validate_progress_receipt_batch",
]
