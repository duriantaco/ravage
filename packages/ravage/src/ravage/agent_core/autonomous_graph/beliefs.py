# Belief revisions are advisory state derived only from trusted executor receipts.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from ravage.agent_core.autonomous_graph.scheduler import (
    GraphProgressBinding,
    ProgressBatchClass,
    ProgressReceipt,
    ProgressReceiptValidationError,
    ValidatedProgressBatch,
    require_validated_progress_batch,
    validate_progress_receipt_batch,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.autonomous_graph.models import AgentSpec, Hypothesis

_STATE_VERSION = 1
_MAX_REVISIONS = 1000
_SHA256_HEX_LENGTH = 64


class BeliefLedgerError(RuntimeError):
    """Raised when an evidence-grounded belief revision is invalid."""


class BeliefDisposition(StrEnum):
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"
    DISPROVED = "disproved"

    @property
    def belief_basis_points(self) -> int:
        return {
            BeliefDisposition.SUPPORTED: 6500,
            BeliefDisposition.CONFIRMED: 10_000,
            BeliefDisposition.DISPROVED: 500,
        }[self]


class EvidenceReferenceValidator(Protocol):
    target_identity: str

    def validate_references(
        self,
        evidence_refs: Sequence[str],
        *,
        require_trusted: bool = False,
    ) -> tuple[object, ...]: ...


@dataclass(frozen=True)
class BeliefRevision:
    """One immutable, executor-grounded update to a hypothesis."""

    revision_id: str
    hypothesis_fingerprint: str
    agent_spec_fingerprint: str
    sequence: int
    previous_revision_id: str
    disposition: BeliefDisposition
    evidence_refs: tuple[str, ...]
    receipt_tokens: tuple[str, ...]
    producer_node_id: str
    evidence_epoch: int

    @classmethod
    def create(  # noqa: PLR0913 - immutable revision identity is explicit.
        cls,
        *,
        hypothesis_fingerprint: str,
        agent_spec_fingerprint: str,
        sequence: int,
        previous_revision_id: str,
        disposition: BeliefDisposition | str,
        evidence_refs: Sequence[str],
        receipt_tokens: Sequence[str],
        producer_node_id: str,
        evidence_epoch: int,
    ) -> BeliefRevision:
        if sequence <= 0:
            raise BeliefLedgerError("belief revision sequence must be positive")
        if evidence_epoch < 0:
            raise BeliefLedgerError("belief evidence epoch cannot be negative")
        try:
            parsed_disposition = (
                disposition
                if isinstance(disposition, BeliefDisposition)
                else BeliefDisposition(str(disposition))
            )
        except ValueError as exc:
            raise BeliefLedgerError(f"unknown belief disposition: {disposition}") from exc
        hypothesis_id = hypothesis_fingerprint.strip()
        agent_spec_id = agent_spec_fingerprint.strip()
        producer = producer_node_id.strip()
        refs = _strings(evidence_refs)
        tokens = _strings(receipt_tokens)
        _require_sha256_identity(
            hypothesis_id,
            prefix="hypothesis:",
            label="belief hypothesis fingerprint",
        )
        _require_sha256_identity(
            agent_spec_id,
            prefix="agent-spec:",
            label="belief agent spec fingerprint",
        )
        if not producer:
            raise BeliefLedgerError("belief producer node is required")
        if not refs or not tokens:
            raise BeliefLedgerError(
                "belief revision requires trusted evidence references and receipt tokens"
            )
        canonical = {
            "hypothesis_fingerprint": hypothesis_id,
            "agent_spec_fingerprint": agent_spec_id,
            "sequence": sequence,
            "previous_revision_id": previous_revision_id.strip(),
            "disposition": parsed_disposition.value,
            "evidence_refs": refs,
            "receipt_tokens": tokens,
            "producer_node_id": producer,
            "evidence_epoch": evidence_epoch,
        }
        return cls(
            revision_id=f"belief:{_digest_json(canonical)}",
            hypothesis_fingerprint=hypothesis_id,
            agent_spec_fingerprint=agent_spec_id,
            sequence=sequence,
            previous_revision_id=str(canonical["previous_revision_id"]),
            disposition=parsed_disposition,
            evidence_refs=refs,
            receipt_tokens=tokens,
            producer_node_id=producer,
            evidence_epoch=evidence_epoch,
        )

    @property
    def executor_receipt_digest(self) -> str:
        receipt = {
            "refs": self.evidence_refs,
            "tokens": self.receipt_tokens,
        }
        return f"executor-receipt:{_digest_json(receipt)}"

    def to_json(self) -> dict[str, object]:
        return {
            "revision_id": self.revision_id,
            "hypothesis_fingerprint": self.hypothesis_fingerprint,
            "agent_spec_fingerprint": self.agent_spec_fingerprint,
            "sequence": self.sequence,
            "previous_revision_id": self.previous_revision_id,
            "disposition": self.disposition.value,
            "evidence_refs": list(self.evidence_refs),
            "receipt_tokens": list(self.receipt_tokens),
            "producer_node_id": self.producer_node_id,
            "evidence_epoch": self.evidence_epoch,
            "executor_receipt_digest": self.executor_receipt_digest,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> BeliefRevision:
        revision = cls.create(
            hypothesis_fingerprint=str(payload.get("hypothesis_fingerprint") or ""),
            agent_spec_fingerprint=str(payload.get("agent_spec_fingerprint") or ""),
            sequence=_positive_int(payload.get("sequence"), "belief sequence"),
            previous_revision_id=str(payload.get("previous_revision_id") or ""),
            disposition=str(payload.get("disposition") or ""),
            evidence_refs=_string_tuple(payload.get("evidence_refs")),
            receipt_tokens=_string_tuple(payload.get("receipt_tokens")),
            producer_node_id=str(payload.get("producer_node_id") or ""),
            evidence_epoch=_non_negative_int(
                payload.get("evidence_epoch"),
                "belief evidence epoch",
            ),
        )
        if str(payload.get("revision_id") or "") != revision.revision_id:
            raise BeliefLedgerError("belief revision ID mismatch")
        stored_digest = str(payload.get("executor_receipt_digest") or "")
        if stored_digest and stored_digest != revision.executor_receipt_digest:
            raise BeliefLedgerError("belief executor receipt digest mismatch")
        return revision


@dataclass
class BeliefLedgerState:
    revisions: dict[str, BeliefRevision] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    heads: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "revisions": {
                revision_id: self.revisions[revision_id].to_json() for revision_id in self.order
            },
            "order": list(self.order),
            "heads": dict(sorted(self.heads.items())),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> BeliefLedgerState:
        if payload.get("version") != _STATE_VERSION:
            raise BeliefLedgerError("unsupported belief-ledger version")
        raw_revisions = payload.get("revisions")
        raw_order = payload.get("order")
        raw_heads = payload.get("heads")
        if (
            not isinstance(raw_revisions, Mapping)
            or not isinstance(raw_order, list)
            or not isinstance(raw_heads, Mapping)
        ):
            raise BeliefLedgerError("belief ledger fields are malformed")
        revisions: dict[str, BeliefRevision] = {}
        order: list[str] = []
        for raw_id in raw_order:
            revision_id = str(raw_id)
            raw_revision = raw_revisions.get(revision_id)
            if not isinstance(raw_revision, Mapping):
                raise BeliefLedgerError("belief order references an unknown revision")
            revision = BeliefRevision.from_json(raw_revision)
            if revision.revision_id != revision_id or revision_id in revisions:
                raise BeliefLedgerError("belief revision identity is inconsistent")
            revisions[revision_id] = revision
            order.append(revision_id)
        if set(raw_revisions) != set(order):
            raise BeliefLedgerError("belief revisions and order do not match")
        heads = {str(key): str(value) for key, value in raw_heads.items()}
        for hypothesis_fingerprint, revision_id in heads.items():
            head_revision = revisions.get(revision_id)
            if (
                head_revision is None
                or head_revision.hypothesis_fingerprint != hypothesis_fingerprint
            ):
                raise BeliefLedgerError("belief head is inconsistent")
        state = cls(revisions=revisions, order=order, heads=heads)
        state.validate_chains()
        return state

    def validate_chains(self) -> None:
        by_hypothesis: dict[str, list[BeliefRevision]] = {}
        for revision_id in self.order:
            revision = self.revisions[revision_id]
            by_hypothesis.setdefault(revision.hypothesis_fingerprint, []).append(revision)
        for hypothesis_fingerprint, revisions in by_hypothesis.items():
            previous = ""
            for sequence, revision in enumerate(revisions, start=1):
                if revision.sequence != sequence or revision.previous_revision_id != previous:
                    raise BeliefLedgerError("belief revision chain is not contiguous")
                previous = revision.revision_id
            if self.heads.get(hypothesis_fingerprint) != previous:
                raise BeliefLedgerError("belief chain head does not reference its latest revision")


class BeliefLedger:
    """Append-only belief history with evidence validation at the commit boundary."""

    def __init__(
        self,
        *,
        state_path: Path,
        evidence_validator: EvidenceReferenceValidator,
        state: BeliefLedgerState,
    ) -> None:
        self.state_path = state_path
        self.evidence_validator = evidence_validator
        self.state = state
        self._lock = threading.RLock()

    @classmethod
    def open(
        cls,
        state_path: Path,
        *,
        evidence_validator: EvidenceReferenceValidator,
    ) -> BeliefLedger:
        if state_path.exists():
            try:
                raw = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise BeliefLedgerError(f"cannot read belief ledger: {exc}") from exc
            if not isinstance(raw, Mapping):
                raise BeliefLedgerError("belief ledger must be an object")
            state = BeliefLedgerState.from_json(raw)
        else:
            state = BeliefLedgerState()
        ledger = cls(
            state_path=state_path,
            evidence_validator=evidence_validator,
            state=state,
        )
        ledger._persist()
        return ledger

    def record_from_receipts(
        self,
        *,
        hypothesis: Hypothesis,
        agent_spec: AgentSpec,
        producer_node_id: str,
        receipts: Sequence[ProgressReceipt],
        evidence_epoch: int,
    ) -> BeliefRevision | None:
        """Compatibility path that first performs canonical scheduler validation."""
        binding = self._compatibility_binding(
            hypothesis=hypothesis,
            agent_spec=agent_spec,
            producer_node_id=producer_node_id,
            receipts=receipts,
            evidence_epoch=evidence_epoch,
        )
        batch = validate_progress_receipt_batch(
            receipts,
            result_evidence_refs=tuple(receipt.evidence_ref for receipt in receipts),
            evidence_validator=self.evidence_validator,
            binding=binding,
        )
        return self.record_from_validated_batch(
            hypothesis=hypothesis,
            agent_spec=agent_spec,
            producer_node_id=producer_node_id,
            batch=batch,
            evidence_epoch=evidence_epoch,
        )

    def record_from_validated_batch(
        self,
        *,
        hypothesis: Hypothesis,
        agent_spec: AgentSpec,
        batch: ValidatedProgressBatch,
        evidence_epoch: int,
        producer_node_id: str | None = None,
    ) -> BeliefRevision | None:
        """Commit one canonical progress batch bound to the supplied belief subject."""
        _require_canonical_batch(batch)
        if batch.classification is ProgressBatchClass.PIVOT:
            return None
        subject_node_id = batch.binding.node_id if producer_node_id is None else producer_node_id
        _require_subject_binding(
            batch.binding,
            hypothesis=hypothesis,
            agent_spec=agent_spec,
            producer_node_id=subject_node_id,
        )
        disposition = _disposition_for_batch(batch)
        if disposition is None:
            return None
        with self._lock:
            previous = self.head(hypothesis.fingerprint)
            if (
                previous is not None
                and disposition is BeliefDisposition.SUPPORTED
                and previous.disposition
                in {
                    BeliefDisposition.CONFIRMED,
                    BeliefDisposition.DISPROVED,
                }
            ):
                return previous
            refs = _strings(batch.evidence_refs)
            tokens = _strings(batch.progress_tokens)
            if (
                previous is not None
                and previous.disposition is disposition
                and previous.evidence_refs == refs
                and previous.receipt_tokens == tokens
            ):
                return previous
            if len(self.state.order) >= _MAX_REVISIONS:
                raise BeliefLedgerError(
                    "belief ledger capacity reached; archive the immutable ledger "
                    "before accepting more revisions"
                )
            revision = BeliefRevision.create(
                hypothesis_fingerprint=hypothesis.fingerprint,
                agent_spec_fingerprint=agent_spec.fingerprint,
                sequence=(previous.sequence + 1 if previous is not None else 1),
                previous_revision_id=(previous.revision_id if previous is not None else ""),
                disposition=disposition,
                evidence_refs=refs,
                receipt_tokens=tokens,
                producer_node_id=batch.binding.node_id,
                evidence_epoch=evidence_epoch,
            )
            self.state.revisions[revision.revision_id] = revision
            self.state.order.append(revision.revision_id)
            self.state.heads[hypothesis.fingerprint] = revision.revision_id
            self._persist()
            return copy.deepcopy(revision)

    def _compatibility_binding(
        self,
        *,
        hypothesis: Hypothesis,
        agent_spec: AgentSpec,
        producer_node_id: str,
        receipts: Sequence[ProgressReceipt],
        evidence_epoch: int,
    ) -> GraphProgressBinding:
        existing = {receipt.binding for receipt in receipts if receipt.binding is not None}
        if len(existing) > 1:
            raise BeliefLedgerError("progress receipts do not share one control-plane binding")
        if existing:
            return next(iter(existing))
        target_identity = str(getattr(self.evidence_validator, "target_identity", "")).strip()
        if not target_identity:
            raise BeliefLedgerError("belief evidence validator target identity is required")
        epoch = _non_negative_int(evidence_epoch, "belief evidence epoch")
        producer = producer_node_id.strip()
        return GraphProgressBinding(
            graph_id="belief-ledger-direct",
            target_identity=target_identity,
            tool_call_id=f"belief-ledger-direct:{producer}:{epoch}",
            runtime_binding_id="belief-ledger-direct",
            node_id=producer,
            objective_fingerprint=hypothesis.objective_fingerprint,
            hypothesis_fingerprint=hypothesis.fingerprint,
            agent_spec_fingerprint=agent_spec.fingerprint,
        )

    def head(self, hypothesis_fingerprint: str) -> BeliefRevision | None:
        with self._lock:
            revision_id = self.state.heads.get(hypothesis_fingerprint)
            if revision_id is None:
                return None
            return copy.deepcopy(self.state.revisions[revision_id])

    def projection(self, hypothesis_fingerprint: str) -> dict[str, object]:
        revision = self.head(hypothesis_fingerprint)
        if revision is None:
            return {
                "status": "proposed",
                "belief_basis_points": 2500,
                "revision": None,
            }
        return {
            "status": revision.disposition.value,
            "belief_basis_points": revision.disposition.belief_basis_points,
            "revision": revision.to_json(),
        }

    def snapshot(self) -> BeliefLedgerState:
        with self._lock:
            return copy.deepcopy(self.state)

    def _persist(self) -> None:
        self.state.validate_chains()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.state.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.state_path)


def _disposition_for_batch(
    batch: ValidatedProgressBatch,
) -> BeliefDisposition | None:
    if batch.classification in {
        ProgressBatchClass.EMPTY,
        ProgressBatchClass.PIVOT,
    }:
        return None
    if batch.classification is ProgressBatchClass.DISPROVE:
        return BeliefDisposition.DISPROVED
    if batch.classification in {
        ProgressBatchClass.CONFIRM,
        ProgressBatchClass.PROOF,
    }:
        return BeliefDisposition.CONFIRMED
    if batch.classification is ProgressBatchClass.SUPPORT:
        return BeliefDisposition.SUPPORTED
    raise BeliefLedgerError("validated progress batch classification is unsupported")


def _require_subject_binding(
    binding: GraphProgressBinding,
    *,
    hypothesis: Hypothesis,
    agent_spec: AgentSpec,
    producer_node_id: str,
) -> None:
    expected = {
        "node_id": producer_node_id.strip(),
        "objective_fingerprint": hypothesis.objective_fingerprint,
        "hypothesis_fingerprint": hypothesis.fingerprint,
        "agent_spec_fingerprint": agent_spec.fingerprint,
    }
    for field_name, expected_value in expected.items():
        if getattr(binding, field_name) != expected_value:
            raise BeliefLedgerError(
                f"progress batch {field_name} does not match the belief subject"
            )


def _require_canonical_batch(batch: ValidatedProgressBatch) -> None:
    try:
        require_validated_progress_batch(batch)
    except ProgressReceiptValidationError as exc:
        raise BeliefLedgerError(str(exc)) from exc


def _strings(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        sorted({" ".join(str(value).strip().split()) for value in values if str(value).strip()})
    )


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return _strings(tuple(str(item) for item in value))


def _positive_int(value: object, label: str) -> int:
    parsed = _non_negative_int(value, label)
    if parsed <= 0:
        raise BeliefLedgerError(f"{label} must be positive")
    return parsed


def _non_negative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BeliefLedgerError(f"{label} must be a non-negative integer")
    return value


def _require_sha256_identity(value: str, *, prefix: str, label: str) -> None:
    suffix = value.removeprefix(prefix)
    if (
        not value.startswith(prefix)
        or len(suffix) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in suffix)
    ):
        raise BeliefLedgerError(f"{label} is invalid")


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "BeliefDisposition",
    "BeliefLedger",
    "BeliefLedgerError",
    "BeliefLedgerState",
    "BeliefRevision",
]
