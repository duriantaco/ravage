# Evidence errors carry record-specific provenance context.
# ruff: noqa: CPY001, EM101, EM102, FURB192, TRY003

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ravage.agent_core.autonomous_graph.scheduler import (
    ProgressKind,
    ProgressReceipt,
    ProgressSource,
)
from ravage.agent_core.recovery_evidence import (
    RecoveryEvidenceAssessment,
    assess_recovery_evidence,
)
from ravage.agent_core.recovery_policy import (
    MaterialProgressKind,
    ProgressSnapshot,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.action_executor import ActionResult
    from ravage.agent_core.autonomous_graph.worker import (
        GraphToolResult,
        ProofGateResult,
    )
    from ravage.agent_core.frontier_credential_replay import (
        RejectedCredentialReplay,
    )
    from ravage.agent_core.frontier_extraction_memory import (
        ExtractionCheckpoint,
    )
    from ravage.agent_core.frontier_sql_oracle import SqlOracleContract

_STATE_VERSION = 1
_TRUSTED_TOOL_SOURCE_KINDS = frozenset(
    {
        "tool_run_command",
        "tool_run_python",
        "tool_run_probe",
        "tool_validate_poc",
        "tool_http_request",
    }
)


class EvidenceBlackboardError(RuntimeError):
    """Base error for durable graph evidence operations."""


class EvidenceReferenceError(EvidenceBlackboardError):
    """Raised when a worker cites absent or inadmissible evidence."""


class EvidenceWorkError(EvidenceBlackboardError):
    """Raised when closure-work ownership or lifecycle is invalid."""


class EvidenceSource(StrEnum):
    TOOL_RUN_COMMAND = "tool_run_command"
    TOOL_RUN_PYTHON = "tool_run_python"
    TOOL_RUN_PROBE = "tool_run_probe"
    TOOL_VALIDATE_POC = "tool_validate_poc"
    TOOL_HTTP_REQUEST = "tool_http_request"
    COORDINATOR_VALIDATOR = "coordinator_validator"
    UNVERIFIED_TOOL = "unverified_tool"
    MODEL_STATEMENT = "model_statement"
    SOURCE_TEXT = "source_text"

    @property
    def trusted(self) -> bool:
        return self in {
            EvidenceSource.TOOL_RUN_COMMAND,
            EvidenceSource.TOOL_RUN_PYTHON,
            EvidenceSource.TOOL_RUN_PROBE,
            EvidenceSource.TOOL_VALIDATE_POC,
            EvidenceSource.TOOL_HTTP_REQUEST,
            EvidenceSource.COORDINATOR_VALIDATOR,
        }


class EvidenceKind(StrEnum):
    RAW_OBSERVATION = "raw_observation"
    WEAK_SIGNAL = "weak_signal"
    SPECIALIST_LEAD = "specialist_lead"
    PRIMITIVE_CONFIRMED = "primitive_confirmed"
    AUTH_STATE_CHANGED = "auth_state_changed"
    REQUEST_CONTRACT = "request_contract"
    RESPONSE_DIFFERENTIAL = "response_differential"
    SQL_ORACLE_CALIBRATED = "sql_oracle_calibrated"
    EXTRACTION_CHECKPOINT = "extraction_checkpoint"
    CREDENTIAL_REPLAY_REJECTED = "credential_replay_rejected"
    HYPOTHESIS_CONFIRMED = "hypothesis_confirmed"
    HYPOTHESIS_DISPROVED = "hypothesis_disproved"
    PROOF_CONFIRMED = "proof_confirmed"
    MODEL_CLAIM = "model_claim"
    SOURCE_CLAIM = "source_claim"


class EvidenceWorkKind(StrEnum):
    REQUEST_CONTRACT = "request_contract"
    SQL_ORACLE = "sql_oracle"
    EXTRACTION_CHECKPOINT = "extraction_checkpoint"
    CREDENTIAL_REPLAY = "credential_replay"
    CLOSURE_OBLIGATION = "closure_obligation"
    PROOF_CLOSURE = "proof_closure"

    @property
    def priority(self) -> int:
        return {
            EvidenceWorkKind.REQUEST_CONTRACT: 20,
            EvidenceWorkKind.SQL_ORACLE: 30,
            EvidenceWorkKind.EXTRACTION_CHECKPOINT: 40,
            EvidenceWorkKind.CREDENTIAL_REPLAY: 50,
            EvidenceWorkKind.CLOSURE_OBLIGATION: 80,
            EvidenceWorkKind.PROOF_CLOSURE: 100,
        }[self]


class EvidenceWorkStatus(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    sequence: int
    kind: EvidenceKind
    source: EvidenceSource
    producer_node_id: str
    target_identity: str
    observation_id: str
    route_fingerprint: str
    payload: dict[str, object]
    parent_refs: tuple[str, ...] = ()
    material: bool = False

    @property
    def trusted(self) -> bool:
        return self.source.trusted

    def to_json(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "sequence": self.sequence,
            "kind": self.kind.value,
            "source": self.source.value,
            "producer_node_id": self.producer_node_id,
            "target_identity": self.target_identity,
            "observation_id": self.observation_id,
            "route_fingerprint": self.route_fingerprint,
            "payload": _json_mapping(self.payload),
            "parent_refs": list(self.parent_refs),
            "material": self.material,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> EvidenceRecord:
        raw_payload = payload.get("payload")
        if not isinstance(raw_payload, Mapping):
            raise EvidenceBlackboardError("evidence record payload must be an object")
        record = cls(
            evidence_id=str(payload.get("evidence_id") or ""),
            sequence=_required_int(payload, "sequence"),
            kind=EvidenceKind(str(payload.get("kind") or "")),
            source=EvidenceSource(str(payload.get("source") or "")),
            producer_node_id=str(payload.get("producer_node_id") or ""),
            target_identity=str(payload.get("target_identity") or ""),
            observation_id=str(payload.get("observation_id") or ""),
            route_fingerprint=str(payload.get("route_fingerprint") or ""),
            payload=_json_mapping(raw_payload),
            parent_refs=_string_tuple(payload.get("parent_refs")),
            material=_required_bool(payload, "material"),
        )
        expected = _record_id(
            kind=record.kind,
            source=record.source,
            target_identity=record.target_identity,
            observation_id=record.observation_id,
            route_fingerprint=record.route_fingerprint,
            payload=record.payload,
            parent_refs=record.parent_refs,
        )
        if record.evidence_id != expected:
            raise EvidenceBlackboardError("evidence record id does not match canonical content")
        return record


@dataclass
class EvidenceWorkItem:
    work_id: str
    kind: EvidenceWorkKind
    canonical_key: str
    evidence_refs: tuple[str, ...]
    status: EvidenceWorkStatus = EvidenceWorkStatus.PENDING
    owner_node_id: str = ""
    result_evidence_refs: tuple[str, ...] = ()
    last_reason: str = "work_registered"

    def to_json(self) -> dict[str, object]:
        return {
            "work_id": self.work_id,
            "kind": self.kind.value,
            "canonical_key": self.canonical_key,
            "evidence_refs": list(self.evidence_refs),
            "status": self.status.value,
            "owner_node_id": self.owner_node_id,
            "result_evidence_refs": list(self.result_evidence_refs),
            "last_reason": self.last_reason,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> EvidenceWorkItem:
        item = cls(
            work_id=str(payload.get("work_id") or ""),
            kind=EvidenceWorkKind(str(payload.get("kind") or "")),
            canonical_key=str(payload.get("canonical_key") or ""),
            evidence_refs=_string_tuple(payload.get("evidence_refs")),
            status=EvidenceWorkStatus(str(payload.get("status") or "")),
            owner_node_id=str(payload.get("owner_node_id") or ""),
            result_evidence_refs=_string_tuple(payload.get("result_evidence_refs")),
            last_reason=str(payload.get("last_reason") or ""),
        )
        expected = _work_id(item.kind, item.canonical_key)
        if item.work_id != expected:
            raise EvidenceBlackboardError("evidence work id does not match canonical content")
        return item


@dataclass
class EvidenceBlackboardState:
    target_identity: str
    records: dict[str, EvidenceRecord] = field(default_factory=dict)
    work_items: dict[str, EvidenceWorkItem] = field(default_factory=dict)
    next_sequence: int = 1
    progress_snapshot: ProgressSnapshot = field(default_factory=ProgressSnapshot)

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "target_identity": self.target_identity,
            "records": [
                record.to_json()
                for record in sorted(
                    self.records.values(),
                    key=lambda item: item.sequence,
                )
            ],
            "work_items": [
                self.work_items[work_id].to_json() for work_id in sorted(self.work_items)
            ],
            "next_sequence": self.next_sequence,
            "progress_snapshot": self.progress_snapshot.to_json(),
        }

    @classmethod
    def from_json(  # noqa: C901 - explicit persisted ledger decoding.
        cls,
        payload: Mapping[str, object],
    ) -> EvidenceBlackboardState:
        if _required_int(payload, "version") != _STATE_VERSION:
            raise EvidenceBlackboardError("unsupported evidence blackboard version")
        raw_records = payload.get("records")
        raw_work = payload.get("work_items")
        raw_snapshot = payload.get("progress_snapshot")
        if not isinstance(raw_records, list):
            raise EvidenceBlackboardError("evidence blackboard records must be a list")
        if not isinstance(raw_work, list):
            raise EvidenceBlackboardError("evidence blackboard work_items must be a list")
        if not isinstance(raw_snapshot, Mapping):
            raise EvidenceBlackboardError("evidence progress_snapshot must be an object")
        records: dict[str, EvidenceRecord] = {}
        for raw in raw_records:
            if not isinstance(raw, Mapping):
                raise EvidenceBlackboardError("evidence record must be an object")
            record = EvidenceRecord.from_json(raw)
            if record.evidence_id in records:
                raise EvidenceBlackboardError(f"duplicate evidence id: {record.evidence_id}")
            records[record.evidence_id] = record
        work_items: dict[str, EvidenceWorkItem] = {}
        for raw in raw_work:
            if not isinstance(raw, Mapping):
                raise EvidenceBlackboardError("evidence work item must be an object")
            item = EvidenceWorkItem.from_json(raw)
            if item.work_id in work_items:
                raise EvidenceBlackboardError(f"duplicate evidence work id: {item.work_id}")
            work_items[item.work_id] = item
        state = cls(
            target_identity=str(payload.get("target_identity") or ""),
            records=records,
            work_items=work_items,
            next_sequence=_required_int(payload, "next_sequence"),
            progress_snapshot=ProgressSnapshot.from_json(raw_snapshot),
        )
        state.validate()
        return state

    def validate(self) -> None:  # noqa: C901, PLR0912 - explicit ledger audit.
        if not self.target_identity:
            raise EvidenceBlackboardError("evidence target_identity is required")
        if self.next_sequence <= 0:
            raise EvidenceBlackboardError("evidence next_sequence must be positive")
        sequences: set[int] = set()
        for evidence_id, record in self.records.items():
            if evidence_id != record.evidence_id:
                raise EvidenceBlackboardError("evidence dictionary key does not match record id")
            if record.sequence <= 0 or record.sequence in sequences:
                raise EvidenceBlackboardError("evidence record sequence is invalid")
            sequences.add(record.sequence)
            if record.target_identity != self.target_identity:
                raise EvidenceBlackboardError("evidence record target identity mismatch")
            if not record.producer_node_id:
                raise EvidenceBlackboardError(f"evidence {evidence_id} producer is required")
            if record.material and not record.trusted:
                raise EvidenceBlackboardError(
                    f"untrusted evidence cannot be material: {evidence_id}"
                )
            if record.source is EvidenceSource.COORDINATOR_VALIDATOR:
                if not record.parent_refs:
                    raise EvidenceBlackboardError(
                        f"validated evidence requires parents: {evidence_id}"
                    )
                for parent_ref in record.parent_refs:
                    parent = self.records.get(parent_ref)
                    if parent is None or not parent.trusted:
                        raise EvidenceBlackboardError(
                            "validated evidence parent is absent or untrusted"
                        )
        if sequences and self.next_sequence <= max(sequences):
            raise EvidenceBlackboardError("evidence next_sequence does not follow existing records")
        for work_id, item in self.work_items.items():
            if work_id != item.work_id:
                raise EvidenceBlackboardError("evidence work dictionary key mismatch")
            for evidence_ref in (
                *item.evidence_refs,
                *item.result_evidence_refs,
            ):
                record = self.records.get(evidence_ref)
                if record is None or not record.trusted:
                    raise EvidenceBlackboardError(f"work item {work_id} has inadmissible evidence")
            if item.status is EvidenceWorkStatus.CLAIMED and not item.owner_node_id:
                raise EvidenceBlackboardError(f"claimed work item {work_id} requires an owner")
            if item.status is EvidenceWorkStatus.COMPLETED and not item.result_evidence_refs:
                raise EvidenceBlackboardError(
                    f"completed work item {work_id} requires result evidence"
                )


@dataclass(frozen=True)
class EvidencePromotion:
    raw_evidence_ref: str
    promoted_evidence_refs: tuple[str, ...]
    lead_evidence_refs: tuple[str, ...]
    progress_receipts: tuple[ProgressReceipt, ...]
    proof_evidence_refs: tuple[str, ...]
    observation_digest: str
    source_trusted: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class WorkRegistration:
    item: EvidenceWorkItem
    created: bool


@dataclass(frozen=True)
class TypedEvidenceUpdate:
    record: EvidenceRecord
    created: bool
    progress_receipt: ProgressReceipt | None = None


class EvidenceBlackboard:
    """Durable, canonical, target-bound evidence and closure-work ledger."""

    def __init__(
        self,
        *,
        target_url: str,
        state_path: Path,
    ) -> None:
        self.target_identity = _target_identity(target_url)
        self.state_path = state_path
        self._lock = threading.RLock()
        self.state = self._load_or_start()
        self._persist()

    def record_action_result(
        self,
        *,
        producer_node_id: str,
        action: Mapping[str, object],
        result: ActionResult,
        observation_id: str,
    ) -> EvidencePromotion:
        with self._lock:
            source_kind = result.evidence_source_kind.strip()
            source = _source_from_kind(
                source_kind,
                observation_id=observation_id,
            )
            admissible_source_kind = source_kind if source.trusted else ""
            previous = self.state.progress_snapshot
            assessment = assess_recovery_evidence(
                previous,
                action=action,
                outcome=result.to_json(),
                source_kind=admissible_source_kind,
                raw_observation=(result.evidence_observation or result.observation),
            )
            raw_record, _ = self._record(
                kind=EvidenceKind.RAW_OBSERVATION,
                source=source,
                producer_node_id=producer_node_id,
                observation_id=observation_id.strip(),
                route_fingerprint=assessment.route_fingerprint,
                payload={
                    "observation_digest": assessment.observation_digest,
                    "ok": result.ok,
                    "outcome": result.outcome,
                    "timed_out": result.timed_out,
                    "exit_code": result.exit_code,
                    "source_kind": source_kind,
                },
                material=False,
            )
            promoted, receipts, proof_refs = self._promote_assessment(
                producer_node_id=producer_node_id,
                raw_record=raw_record,
                previous=previous,
                assessment=assessment,
            )
            lead_refs = self._record_leads(
                producer_node_id=producer_node_id,
                raw_record=raw_record,
                assessment=assessment,
            )
            self.state.progress_snapshot = assessment.snapshot
            self._persist()
            return EvidencePromotion(
                raw_evidence_ref=raw_record.evidence_id,
                promoted_evidence_refs=promoted,
                lead_evidence_refs=lead_refs,
                progress_receipts=receipts,
                proof_evidence_refs=proof_refs,
                observation_digest=assessment.observation_digest,
                source_trusted=assessment.source_trusted,
                reason_codes=assessment.reason_codes,
            )

    def record_model_claim(
        self,
        *,
        producer_node_id: str,
        claim: str,
        evidence_refs: Sequence[str] = (),
    ) -> EvidenceRecord:
        with self._lock:
            parents = self.validate_references(
                evidence_refs,
                require_trusted=False,
            )
            record, _ = self._record(
                kind=EvidenceKind.MODEL_CLAIM,
                source=EvidenceSource.MODEL_STATEMENT,
                producer_node_id=producer_node_id,
                observation_id="",
                route_fingerprint="",
                payload={"claim_digest": _digest(claim.strip())},
                parent_refs=tuple(item.evidence_id for item in parents),
                material=False,
            )
            self._persist()
            return record

    def record_source_claim(
        self,
        *,
        producer_node_id: str,
        claim: str,
    ) -> EvidenceRecord:
        with self._lock:
            record, _ = self._record(
                kind=EvidenceKind.SOURCE_CLAIM,
                source=EvidenceSource.SOURCE_TEXT,
                producer_node_id=producer_node_id,
                observation_id="",
                route_fingerprint="",
                payload={"claim_digest": _digest(claim.strip())},
                material=False,
            )
            self._persist()
            return record

    def record_sql_oracle_contract(
        self,
        *,
        producer_node_id: str,
        raw_evidence_ref: str,
        contract: SqlOracleContract,
    ) -> TypedEvidenceUpdate:
        """Promote only a parser-validated repeated true/false target oracle."""
        with self._lock:
            raw = self._trusted_raw_parent(raw_evidence_ref)
            if raw.source not in {
                EvidenceSource.TOOL_RUN_PROBE,
                EvidenceSource.TOOL_VALIDATE_POC,
            }:
                raise EvidenceReferenceError(
                    "SQL oracle promotion requires a coordinator-owned probe or validator"
                )
            payload = {
                "family": contract.family,
                "endpoint": contract.endpoint,
                "input_name": contract.input_name,
                "method": contract.method,
                "true_status": contract.true_status,
                "true_body_digest": _digest(contract.true_body),
                "false_status": contract.false_status,
                "false_body_digest": _digest(contract.false_body),
                "contract_fingerprint": contract.fingerprint,
                "authority": "repeated_target_controls",
            }
            existing = self._record_with_payload_value(
                kind=EvidenceKind.SQL_ORACLE_CALIBRATED,
                key="contract_fingerprint",
                value=contract.fingerprint,
            )
            if existing is not None:
                return TypedEvidenceUpdate(record=existing, created=False)
            record, created = self._record(
                kind=EvidenceKind.SQL_ORACLE_CALIBRATED,
                source=EvidenceSource.COORDINATOR_VALIDATOR,
                producer_node_id=producer_node_id,
                observation_id=raw.observation_id,
                route_fingerprint=contract.fingerprint,
                payload=payload,
                parent_refs=(raw.evidence_id,),
                material=True,
            )
            receipt = (
                ProgressReceipt(
                    kind=ProgressKind.SQL_ORACLE_CALIBRATED,
                    value=f"{contract.family}:{contract.fingerprint}",
                    evidence_ref=record.evidence_id,
                    source=ProgressSource.INDEPENDENT_VALIDATOR,
                )
                if created
                else None
            )
            self._persist()
            return TypedEvidenceUpdate(
                record=record,
                created=created,
                progress_receipt=receipt,
            )

    def record_extraction_checkpoint(
        self,
        *,
        producer_node_id: str,
        raw_evidence_ref: str,
        oracle_evidence_refs: Sequence[str],
        checkpoint: ExtractionCheckpoint,
    ) -> TypedEvidenceUpdate:
        """Record an advancing extraction checkpoint without persisting its value."""
        with self._lock:
            raw = self._trusted_raw_parent(raw_evidence_ref)
            oracle_records = self.validate_references(
                oracle_evidence_refs,
                require_trusted=True,
            )
            if not oracle_records or any(
                item.kind is not EvidenceKind.SQL_ORACLE_CALIBRATED for item in oracle_records
            ):
                raise EvidenceReferenceError(
                    "extraction checkpoint requires a calibrated SQL oracle"
                )
            existing = self._record_with_payload_value(
                kind=EvidenceKind.EXTRACTION_CHECKPOINT,
                key="checkpoint_fingerprint",
                value=checkpoint.fingerprint,
            )
            if existing is not None:
                return TypedEvidenceUpdate(record=existing, created=False)
            record, created = self._record(
                kind=EvidenceKind.EXTRACTION_CHECKPOINT,
                source=EvidenceSource.COORDINATOR_VALIDATOR,
                producer_node_id=producer_node_id,
                observation_id=raw.observation_id,
                route_fingerprint=checkpoint.objective_fingerprint,
                payload={
                    "objective_fingerprint": checkpoint.objective_fingerprint,
                    "family": checkpoint.family,
                    "endpoint": checkpoint.endpoint,
                    "candidate_kind": checkpoint.candidate_kind,
                    "position": checkpoint.position,
                    "expected_length": checkpoint.expected_length,
                    "candidate_length": len(checkpoint.prefix),
                    "candidate_digest": _digest(checkpoint.prefix),
                    "complete": checkpoint.complete,
                    "checkpoint_fingerprint": checkpoint.fingerprint,
                },
                parent_refs=(
                    raw.evidence_id,
                    *(item.evidence_id for item in oracle_records),
                ),
                material=True,
            )
            receipt = (
                ProgressReceipt(
                    kind=ProgressKind.EXTRACTION_CHECKPOINT,
                    value=checkpoint.material_progress_token,
                    evidence_ref=record.evidence_id,
                    source=ProgressSource.INDEPENDENT_VALIDATOR,
                )
                if created
                else None
            )
            self._persist()
            return TypedEvidenceUpdate(
                record=record,
                created=created,
                progress_receipt=receipt,
            )

    def record_rejected_credential_replay(
        self,
        *,
        producer_node_id: str,
        raw_evidence_ref: str,
        checkpoint_evidence_ref: str,
        replay: RejectedCredentialReplay,
    ) -> TypedEvidenceUpdate:
        """Turn an exact failed replay into durable route-changing counter-evidence."""
        with self._lock:
            raw = self._trusted_raw_parent(raw_evidence_ref)
            checkpoint_records = self.validate_references(
                (checkpoint_evidence_ref,),
                require_trusted=True,
            )
            checkpoint_record = checkpoint_records[0]
            if checkpoint_record.kind is not EvidenceKind.EXTRACTION_CHECKPOINT:
                raise EvidenceReferenceError(
                    "credential rejection requires extraction-checkpoint evidence"
                )
            existing = self._record_with_payload_value(
                kind=EvidenceKind.CREDENTIAL_REPLAY_REJECTED,
                key="fingerprint",
                value=replay.fingerprint,
            )
            if existing is not None:
                return TypedEvidenceUpdate(record=existing, created=False)
            record, created = self._record(
                kind=EvidenceKind.CREDENTIAL_REPLAY_REJECTED,
                source=EvidenceSource.COORDINATOR_VALIDATOR,
                producer_node_id=producer_node_id,
                observation_id=raw.observation_id,
                route_fingerprint=replay.objective_fingerprint,
                payload=replay.to_json(),
                parent_refs=(raw.evidence_id, checkpoint_record.evidence_id),
                material=True,
            )
            receipt = (
                ProgressReceipt(
                    kind=ProgressKind.HYPOTHESIS_DISPROVED,
                    value=f"credential_replay:{replay.fingerprint}",
                    evidence_ref=record.evidence_id,
                    source=ProgressSource.INDEPENDENT_VALIDATOR,
                )
                if created
                else None
            )
            self._persist()
            return TypedEvidenceUpdate(
                record=record,
                created=created,
                progress_receipt=receipt,
            )

    def trusted_sql_oracle_refs(
        self,
        *,
        family: str,
        endpoint: str,
    ) -> tuple[str, ...]:
        with self._lock:
            endpoint_path = _normalized_path(endpoint)
            return tuple(
                record.evidence_id
                for record in sorted(
                    self.state.records.values(),
                    key=lambda item: item.sequence,
                )
                if record.kind is EvidenceKind.SQL_ORACLE_CALIBRATED
                and record.trusted
                and str(record.payload.get("family") or "") == family
                and _normalized_path(str(record.payload.get("endpoint") or "")) == endpoint_path
            )

    def rejected_credential_records(
        self,
        *,
        family: str,
        endpoint: str,
    ) -> tuple[EvidenceRecord, ...]:
        with self._lock:
            endpoint_path = _normalized_path(endpoint)
            return tuple(
                record
                for record in sorted(
                    self.state.records.values(),
                    key=lambda item: item.sequence,
                )
                if record.kind is EvidenceKind.CREDENTIAL_REPLAY_REJECTED
                and record.trusted
                and str(record.payload.get("family") or "") == family
                and _normalized_path(str(record.payload.get("endpoint") or "")) == endpoint_path
            )

    def context_projection(
        self,
        *,
        max_records: int = 12,
        max_work_items: int = 8,
    ) -> dict[str, object]:
        """Return bounded typed evidence and work state for one worker turn."""
        if max_records <= 0 or max_work_items <= 0:
            raise EvidenceBlackboardError("evidence context limits must be positive")
        with self._lock:
            material = [
                record
                for record in sorted(
                    self.state.records.values(),
                    key=lambda item: item.sequence,
                )
                if record.material
            ][-max_records:]
            work = sorted(
                self.state.work_items.values(),
                key=lambda item: (-item.kind.priority, item.work_id),
            )[:max_work_items]
            return {
                "target_identity": self.target_identity,
                "material_evidence": [
                    {
                        "evidence_id": record.evidence_id,
                        "kind": record.kind.value,
                        "producer_node_id": record.producer_node_id,
                        "payload": _json_mapping(record.payload),
                        "parent_refs": list(record.parent_refs),
                    }
                    for record in material
                ],
                "closure_work": [
                    {
                        "work_id": item.work_id,
                        "kind": item.kind.value,
                        "status": item.status.value,
                        "owner_node_id": item.owner_node_id,
                        "evidence_refs": list(item.evidence_refs),
                        "last_reason": item.last_reason,
                    }
                    for item in work
                ],
            }

    def validate_references(
        self,
        evidence_refs: Sequence[str],
        *,
        require_trusted: bool = False,
    ) -> tuple[EvidenceRecord, ...]:
        records: list[EvidenceRecord] = []
        for evidence_ref in _string_tuple(evidence_refs):
            record = self.state.records.get(evidence_ref)
            if record is None:
                raise EvidenceReferenceError(f"unknown evidence reference: {evidence_ref}")
            if require_trusted and not record.trusted:
                raise EvidenceReferenceError(f"untrusted evidence reference: {evidence_ref}")
            records.append(record)
        return tuple(records)

    def verify_proof_references(
        self,
        evidence_refs: Sequence[str],
    ) -> tuple[str, ...]:
        records = self.validate_references(
            evidence_refs,
            require_trusted=True,
        )
        if not records:
            raise EvidenceReferenceError("proof gate requires at least one evidence reference")
        accepted: list[str] = []
        for record in records:
            if record.kind is not EvidenceKind.PROOF_CONFIRMED or not record.material:
                raise EvidenceReferenceError(
                    f"evidence is not confirmed proof: {record.evidence_id}"
                )
            parents = self.validate_references(
                record.parent_refs,
                require_trusted=True,
            )
            if not any(
                parent.kind is EvidenceKind.RAW_OBSERVATION
                and parent.source
                in {
                    EvidenceSource.TOOL_RUN_COMMAND,
                    EvidenceSource.TOOL_RUN_PYTHON,
                    EvidenceSource.TOOL_RUN_PROBE,
                    EvidenceSource.TOOL_VALIDATE_POC,
                    EvidenceSource.TOOL_HTTP_REQUEST,
                }
                and parent.observation_id
                for parent in parents
            ):
                raise EvidenceReferenceError(
                    "confirmed proof lacks executor observation provenance"
                )
            accepted.append(record.evidence_id)
        return tuple(sorted(accepted))

    def register_work(
        self,
        *,
        kind: EvidenceWorkKind,
        canonical_key: str,
        evidence_refs: Sequence[str],
    ) -> WorkRegistration:
        with self._lock:
            canonical = " ".join(canonical_key.strip().split())
            if not canonical:
                raise EvidenceWorkError("work canonical_key is required")
            records = self.validate_references(
                evidence_refs,
                require_trusted=True,
            )
            if not records:
                raise EvidenceWorkError("work registration requires trusted evidence")
            work_id = _work_id(kind, canonical)
            existing = self.state.work_items.get(work_id)
            if existing is not None:
                return WorkRegistration(
                    item=EvidenceWorkItem.from_json(existing.to_json()),
                    created=False,
                )
            item = EvidenceWorkItem(
                work_id=work_id,
                kind=kind,
                canonical_key=canonical,
                evidence_refs=tuple(record.evidence_id for record in records),
            )
            self.state.work_items[work_id] = item
            self._persist()
            return WorkRegistration(
                item=EvidenceWorkItem.from_json(item.to_json()),
                created=True,
            )

    def claim_next_work(
        self,
        *,
        owner_node_id: str,
    ) -> EvidenceWorkItem | None:
        with self._lock:
            pending = [
                item
                for item in self.state.work_items.values()
                if item.status is EvidenceWorkStatus.PENDING
            ]
            if not pending:
                return None
            item = sorted(
                pending,
                key=lambda candidate: (
                    -candidate.kind.priority,
                    candidate.work_id,
                ),
            )[0]
            item.status = EvidenceWorkStatus.CLAIMED
            item.owner_node_id = owner_node_id
            item.last_reason = "work_claimed"
            self._persist()
            return EvidenceWorkItem.from_json(item.to_json())

    def claim_work(
        self,
        *,
        work_id: str,
        owner_node_id: str,
    ) -> EvidenceWorkItem:
        """Atomically bind a specific routed work item to its spawned child."""
        with self._lock:
            item = self.state.work_items.get(work_id)
            if item is None:
                raise EvidenceWorkError(f"unknown evidence work item: {work_id}")
            if item.status is EvidenceWorkStatus.CLAIMED:
                if item.owner_node_id != owner_node_id:
                    raise EvidenceWorkError(f"evidence work item belongs to {item.owner_node_id}")
                return EvidenceWorkItem.from_json(item.to_json())
            if item.status is not EvidenceWorkStatus.PENDING:
                raise EvidenceWorkError(
                    f"evidence work item cannot be claimed from {item.status.value}"
                )
            if not owner_node_id.strip():
                raise EvidenceWorkError("evidence work owner is required")
            item.status = EvidenceWorkStatus.CLAIMED
            item.owner_node_id = owner_node_id
            item.last_reason = "specific_work_claimed"
            self._persist()
            return EvidenceWorkItem.from_json(item.to_json())

    def owned_work_items(
        self,
        *,
        owner_node_id: str,
    ) -> tuple[EvidenceWorkItem, ...]:
        with self._lock:
            return tuple(
                EvidenceWorkItem.from_json(item.to_json())
                for item in sorted(
                    self.state.work_items.values(),
                    key=lambda candidate: candidate.work_id,
                )
                if item.status is EvidenceWorkStatus.CLAIMED and item.owner_node_id == owner_node_id
            )

    def complete_owned_work(
        self,
        *,
        owner_node_id: str,
        result_evidence_refs: Sequence[str],
    ) -> tuple[EvidenceWorkItem, ...]:
        """
        Complete routed closure work only with a conclusive trusted result.

        A raw observation alone is insufficient: closure needs an auth/proof
        transition or typed target-observed counter-evidence.
        """
        with self._lock:
            owned = self.owned_work_items(owner_node_id=owner_node_id)
            if not owned:
                return ()
            records = self.validate_references(
                result_evidence_refs,
                require_trusted=True,
            )
            conclusive = tuple(
                record
                for record in records
                if record.producer_node_id == owner_node_id
                and record.material
                and record.kind
                in {
                    EvidenceKind.AUTH_STATE_CHANGED,
                    EvidenceKind.PROOF_CONFIRMED,
                    EvidenceKind.HYPOTHESIS_DISPROVED,
                }
            )
            if not conclusive:
                return self.fail_owned_work(
                    owner_node_id=owner_node_id,
                    reason="closure_finished_without_conclusive_target_evidence",
                )
            completed: list[EvidenceWorkItem] = []
            refs = tuple(record.evidence_id for record in conclusive)
            for owned_item in owned:
                item = self.state.work_items[owned_item.work_id]
                item.status = EvidenceWorkStatus.COMPLETED
                item.result_evidence_refs = refs
                item.last_reason = "routed_closure_completed"
                completed.append(EvidenceWorkItem.from_json(item.to_json()))
            self._persist()
            return tuple(completed)

    def fail_owned_work(
        self,
        *,
        owner_node_id: str,
        reason: str,
    ) -> tuple[EvidenceWorkItem, ...]:
        with self._lock:
            normalized = " ".join(reason.strip().split()) or "routed_closure_failed"
            failed: list[EvidenceWorkItem] = []
            for item in self.state.work_items.values():
                if (
                    item.status is EvidenceWorkStatus.CLAIMED
                    and item.owner_node_id == owner_node_id
                ):
                    item.status = EvidenceWorkStatus.FAILED
                    item.last_reason = normalized
                    failed.append(EvidenceWorkItem.from_json(item.to_json()))
            if failed:
                self._persist()
            return tuple(failed)

    def complete_work(
        self,
        *,
        work_id: str,
        owner_node_id: str,
        result_evidence_refs: Sequence[str],
    ) -> EvidenceWorkItem:
        with self._lock:
            item = self._owned_work(work_id, owner_node_id)
            records = self.validate_references(
                result_evidence_refs,
                require_trusted=True,
            )
            if not records:
                raise EvidenceWorkError("completed work requires trusted result evidence")
            item.status = EvidenceWorkStatus.COMPLETED
            item.result_evidence_refs = tuple(record.evidence_id for record in records)
            item.last_reason = "work_completed"
            self._persist()
            return EvidenceWorkItem.from_json(item.to_json())

    def fail_work(
        self,
        *,
        work_id: str,
        owner_node_id: str,
        reason: str,
    ) -> EvidenceWorkItem:
        with self._lock:
            item = self._owned_work(work_id, owner_node_id)
            item.status = EvidenceWorkStatus.FAILED
            item.last_reason = " ".join(reason.strip().split())
            self._persist()
            return EvidenceWorkItem.from_json(item.to_json())

    def release_owner(self, owner_node_id: str) -> tuple[str, ...]:
        with self._lock:
            released: list[str] = []
            for item in self.state.work_items.values():
                if (
                    item.status is EvidenceWorkStatus.CLAIMED
                    and item.owner_node_id == owner_node_id
                ):
                    item.status = EvidenceWorkStatus.PENDING
                    item.owner_node_id = ""
                    item.last_reason = "owner_released"
                    released.append(item.work_id)
            if released:
                self._persist()
            return tuple(sorted(released))

    def _load_or_start(self) -> EvidenceBlackboardState:
        if not self.state_path.exists():
            return EvidenceBlackboardState(target_identity=self.target_identity)
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceBlackboardError(f"cannot read evidence blackboard: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise EvidenceBlackboardError("evidence blackboard must be an object")
        state = EvidenceBlackboardState.from_json(payload)
        if state.target_identity != self.target_identity:
            raise EvidenceBlackboardError("evidence blackboard target identity mismatch")
        return state

    def _trusted_raw_parent(self, evidence_ref: str) -> EvidenceRecord:
        records = self.validate_references(
            (evidence_ref,),
            require_trusted=True,
        )
        raw = records[0]
        if raw.kind is not EvidenceKind.RAW_OBSERVATION or not raw.observation_id:
            raise EvidenceReferenceError(
                "validated evidence requires a trusted raw executor observation"
            )
        return raw

    def _record_with_payload_value(
        self,
        *,
        kind: EvidenceKind,
        key: str,
        value: str,
    ) -> EvidenceRecord | None:
        if not value:
            return None
        return next(
            (
                record
                for record in sorted(
                    self.state.records.values(),
                    key=lambda item: item.sequence,
                )
                if record.kind is kind and str(record.payload.get(key) or "") == value
            ),
            None,
        )

    def _record(  # noqa: PLR0913 - explicit evidence identity boundary.
        self,
        *,
        kind: EvidenceKind,
        source: EvidenceSource,
        producer_node_id: str,
        observation_id: str,
        route_fingerprint: str,
        payload: Mapping[str, object],
        parent_refs: Sequence[str] = (),
        material: bool,
    ) -> tuple[EvidenceRecord, bool]:
        body = _json_mapping(payload)
        parents = _string_tuple(parent_refs)
        evidence_id = _record_id(
            kind=kind,
            source=source,
            target_identity=self.target_identity,
            observation_id=observation_id,
            route_fingerprint=route_fingerprint,
            payload=body,
            parent_refs=parents,
        )
        existing = self.state.records.get(evidence_id)
        if existing is not None:
            return existing, False
        record = EvidenceRecord(
            evidence_id=evidence_id,
            sequence=self.state.next_sequence,
            kind=kind,
            source=source,
            producer_node_id=producer_node_id,
            target_identity=self.target_identity,
            observation_id=observation_id,
            route_fingerprint=route_fingerprint,
            payload=body,
            parent_refs=parents,
            material=material,
        )
        self.state.next_sequence += 1
        self.state.records[evidence_id] = record
        return record, True

    def _promote_assessment(
        self,
        *,
        producer_node_id: str,
        raw_record: EvidenceRecord,
        previous: ProgressSnapshot,
        assessment: RecoveryEvidenceAssessment,
    ) -> tuple[
        tuple[str, ...],
        tuple[ProgressReceipt, ...],
        tuple[str, ...],
    ]:
        promoted: list[str] = []
        receipts: list[ProgressReceipt] = []
        proof_refs: list[str] = []
        for material_kind in assessment.material_progress:
            values = _progress_values(
                material_kind,
                previous=previous,
                current=assessment.snapshot,
            )
            if not values:
                continue
            evidence_kind, progress_kind = _progress_kind(material_kind)
            record, _ = self._record(
                kind=evidence_kind,
                source=EvidenceSource.COORDINATOR_VALIDATOR,
                producer_node_id=producer_node_id,
                observation_id=raw_record.observation_id,
                route_fingerprint=assessment.route_fingerprint,
                payload={
                    "progress_kind": material_kind.value,
                    "tokens": list(values),
                    "observation_digest": assessment.observation_digest,
                },
                parent_refs=(raw_record.evidence_id,),
                material=True,
            )
            promoted.append(record.evidence_id)
            receipt = ProgressReceipt(
                kind=progress_kind,
                value=",".join(values),
                evidence_ref=record.evidence_id,
                source=ProgressSource.INDEPENDENT_VALIDATOR,
            )
            receipts.append(receipt)
            if progress_kind is ProgressKind.PROOF_CONFIRMED:
                proof_refs.append(record.evidence_id)
        return (
            tuple(sorted(set(promoted))),
            tuple(receipts),
            tuple(sorted(set(proof_refs))),
        )

    def _record_leads(
        self,
        *,
        producer_node_id: str,
        raw_record: EvidenceRecord,
        assessment: RecoveryEvidenceAssessment,
    ) -> tuple[str, ...]:
        references: list[str] = []
        for lead in assessment.leads:
            record, _ = self._record(
                kind=EvidenceKind.SPECIALIST_LEAD,
                source=EvidenceSource.COORDINATOR_VALIDATOR,
                producer_node_id=producer_node_id,
                observation_id=raw_record.observation_id,
                route_fingerprint=assessment.route_fingerprint,
                payload=lead.to_json(),
                parent_refs=(raw_record.evidence_id,),
                material=lead.material,
            )
            references.append(record.evidence_id)
        return tuple(sorted(set(references)))

    def _owned_work(
        self,
        work_id: str,
        owner_node_id: str,
    ) -> EvidenceWorkItem:
        item = self.state.work_items.get(work_id)
        if item is None:
            raise EvidenceWorkError(f"unknown evidence work item: {work_id}")
        if item.status is not EvidenceWorkStatus.CLAIMED:
            raise EvidenceWorkError(f"evidence work item is not claimed: {work_id}")
        if item.owner_node_id != owner_node_id:
            raise EvidenceWorkError(f"evidence work item belongs to {item.owner_node_id}")
        return item

    def _persist(self) -> None:
        self.state.validate()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.state.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.state_path)


class BlackboardProofGate:
    """Worker proof gate backed only by confirmed blackboard records."""

    def __init__(self, blackboard: EvidenceBlackboard) -> None:
        self.blackboard = blackboard

    async def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        del node_id
        from ravage.agent_core.autonomous_graph.worker import (  # noqa: PLC0415
            ProofGateResult,
        )

        try:
            accepted = self.blackboard.verify_proof_references(evidence_refs)
        except EvidenceReferenceError as exc:
            return ProofGateResult(
                accepted=False,
                reason=str(exc),
            )
        return ProofGateResult(
            accepted=True,
            evidence_refs=accepted,
            reason="blackboard_proof_provenance_verified",
        )


def graph_tool_result_from_promotion(
    *,
    result: ActionResult,
    promotion: EvidencePromotion,
    counterfactual_objective_fingerprint: str = "",
) -> GraphToolResult:
    from ravage.agent_core.autonomous_graph.worker import (  # noqa: PLC0415
        GraphToolResult,
    )

    evidence_refs = (
        promotion.raw_evidence_ref,
        *promotion.promoted_evidence_refs,
        *promotion.lead_evidence_refs,
    )
    output = json.dumps(
        {
            "observation": result.observation,
            "result": {
                "ok": result.ok,
                "outcome": result.outcome,
                "timed_out": result.timed_out,
                "exit_code": result.exit_code,
            },
            "evidence": {
                "raw_ref": promotion.raw_evidence_ref,
                "material_refs": list(promotion.promoted_evidence_refs),
                "lead_refs": list(promotion.lead_evidence_refs),
                "proof_refs": list(promotion.proof_evidence_refs),
                "source_trusted": promotion.source_trusted,
                "reason_codes": list(promotion.reason_codes),
            },
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return GraphToolResult(
        output=output,
        observation_digest=promotion.observation_digest,
        progress_receipts=promotion.progress_receipts,
        evidence_refs=evidence_refs,
        target_requests=_executor_observed_target_requests(result),
        counterfactual_objective_fingerprint=(counterfactual_objective_fingerprint.strip()),
    )


def _executor_observed_target_requests(result: ActionResult) -> int:
    if result.evidence_source_kind not in {
        "tool_run_probe",
        "tool_http_request",
    }:
        return 0
    try:
        observation = json.loads(result.evidence_observation)
    except (TypeError, json.JSONDecodeError):
        return 0
    if not isinstance(observation, Mapping):
        return 0
    graph_budget = observation.get("graph_target_request_budget")
    if isinstance(graph_budget, Mapping):
        used = graph_budget.get("used")
        if isinstance(used, int) and not isinstance(used, bool) and used >= 0:
            return used
    requests = observation.get("requests")
    return len(requests) if isinstance(requests, list) else 0


def _source_from_kind(
    source_kind: str,
    *,
    observation_id: str,
) -> EvidenceSource:
    if source_kind not in _TRUSTED_TOOL_SOURCE_KINDS:
        return EvidenceSource.UNVERIFIED_TOOL
    if not observation_id.strip():
        return EvidenceSource.UNVERIFIED_TOOL
    return EvidenceSource(source_kind)


_PROGRESS_FIELDS: dict[
    MaterialProgressKind,
    tuple[str, EvidenceKind, ProgressKind],
] = {
    MaterialProgressKind.PROOF_CONFIRMED: (
        "confirmed_proofs",
        EvidenceKind.PROOF_CONFIRMED,
        ProgressKind.PROOF_CONFIRMED,
    ),
    MaterialProgressKind.PRIMITIVE_CONFIRMED: (
        "confirmed_primitives",
        EvidenceKind.PRIMITIVE_CONFIRMED,
        ProgressKind.PRIMITIVE_CONFIRMED,
    ),
    MaterialProgressKind.AUTH_STATE_CHANGED: (
        "authenticated_states",
        EvidenceKind.AUTH_STATE_CHANGED,
        ProgressKind.AUTH_STATE_CHANGED,
    ),
    MaterialProgressKind.REQUEST_TEMPLATE_VALIDATED: (
        "validated_request_templates",
        EvidenceKind.REQUEST_CONTRACT,
        ProgressKind.REQUEST_TEMPLATE_VALIDATED,
    ),
    MaterialProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED: (
        "validated_response_differentials",
        EvidenceKind.RESPONSE_DIFFERENTIAL,
        ProgressKind.RESPONSE_DIFFERENTIAL_VALIDATED,
    ),
    MaterialProgressKind.HYPOTHESIS_CONFIRMED: (
        "confirmed_hypotheses",
        EvidenceKind.HYPOTHESIS_CONFIRMED,
        ProgressKind.HYPOTHESIS_CONFIRMED,
    ),
    MaterialProgressKind.HYPOTHESIS_DISPROVED: (
        "disproved_hypotheses",
        EvidenceKind.HYPOTHESIS_DISPROVED,
        ProgressKind.HYPOTHESIS_DISPROVED,
    ),
}


def _progress_values(
    kind: MaterialProgressKind,
    *,
    previous: ProgressSnapshot,
    current: ProgressSnapshot,
) -> tuple[str, ...]:
    field_name, _evidence_kind, _progress_kind = _PROGRESS_FIELDS[kind]
    old = getattr(previous, field_name)
    new = getattr(current, field_name)
    return tuple(sorted(new - old))


def _progress_kind(
    kind: MaterialProgressKind,
) -> tuple[EvidenceKind, ProgressKind]:
    _field_name, evidence_kind, progress_kind = _PROGRESS_FIELDS[kind]
    return evidence_kind, progress_kind


def _target_identity(target_url: str) -> str:
    return f"target:{_digest(target_url.strip())}"


def _normalized_path(value: str) -> str:
    path = urlsplit(value).path.strip()
    return f"/{path.strip('/')}" if path else "/"


def _record_id(  # noqa: PLR0913 - explicit canonical evidence identity.
    *,
    kind: EvidenceKind,
    source: EvidenceSource,
    target_identity: str,
    observation_id: str,
    route_fingerprint: str,
    payload: Mapping[str, object],
    parent_refs: Sequence[str],
) -> str:
    identity = {
        "kind": kind.value,
        "source": source.value,
        "target_identity": target_identity,
        "observation_id": observation_id,
        "route_fingerprint": route_fingerprint,
        "payload": _json_mapping(payload),
        "parent_refs": list(_string_tuple(parent_refs)),
    }
    return f"evidence:{kind.value}:{_digest_json(identity)[:24]}"


def _work_id(kind: EvidenceWorkKind, canonical_key: str) -> str:
    identity = {
        "kind": kind.value,
        "canonical_key": " ".join(canonical_key.strip().split()),
    }
    return f"work:{kind.value}:{_digest_json(identity)[:24]}"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _json_mapping(value: Mapping[str, object]) -> dict[str, object]:
    try:
        encoded = json.dumps(dict(value), ensure_ascii=False, sort_keys=True)
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise EvidenceBlackboardError(f"evidence payload must be JSON serializable: {exc}") from exc
    if not isinstance(decoded, dict):
        raise EvidenceBlackboardError("evidence payload must encode to an object")
    return dict(decoded)


def _string_tuple(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return ()
    return tuple(
        sorted({" ".join(str(value).strip().split()) for value in values if str(value).strip()})
    )


def _required_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceBlackboardError(f"{key} must be an integer")
    return value


def _required_bool(payload: Mapping[str, object], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise EvidenceBlackboardError(f"{key} must be a boolean")
    return value


__all__ = [
    "BlackboardProofGate",
    "EvidenceBlackboard",
    "EvidenceBlackboardError",
    "EvidenceBlackboardState",
    "EvidenceKind",
    "EvidencePromotion",
    "EvidenceRecord",
    "EvidenceReferenceError",
    "EvidenceSource",
    "EvidenceWorkError",
    "EvidenceWorkItem",
    "EvidenceWorkKind",
    "EvidenceWorkStatus",
    "TypedEvidenceUpdate",
    "WorkRegistration",
    "graph_tool_result_from_promotion",
]
