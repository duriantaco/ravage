# Persisted investigation state is validated at the boundary and fails closed.
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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.autonomous_graph.models import GraphObjective

_STATE_VERSION = 1
_MAX_ATTEMPTS = 500


class InvestigationCoverageError(RuntimeError):
    """Raised when durable investigation coverage cannot preserve its invariants."""


class CoverageStage(StrEnum):
    OBSERVED = "observed"
    CONTRACTED = "contracted"
    CALIBRATED = "calibrated"
    PRIMITIVE = "primitive"
    CLOSURE = "closure"
    PROOF = "proof"


_STAGE_RANK = {
    CoverageStage.OBSERVED: 0,
    CoverageStage.CONTRACTED: 1,
    CoverageStage.CALIBRATED: 2,
    CoverageStage.PRIMITIVE: 3,
    CoverageStage.CLOSURE: 4,
    CoverageStage.PROOF: 5,
}

_FAMILY_ALIASES = {
    "auth": "authentication",
    "credential_recovery": "authentication",
    "credential_representation": "authentication",
    "login": "authentication",
    "file_fetch_parser": "file_handling",
    "file_read": "file_handling",
    "file_upload": "file_handling",
    "path_traversal": "file_handling",
    "local_file_inclusion": "file_handling",
    "xml_external_entity": "file_handling",
    "sqli": "sql_injection",
}


def canonical_family(value: str) -> str:
    normalized = "_".join(value.strip().lower().replace("-", " ").split())
    return _FAMILY_ALIASES.get(normalized, normalized or "unknown")


@dataclass(frozen=True)
class SurfaceCell:
    """Canonical investigation unit independent of payload spelling."""

    cell_id: str
    family: str
    endpoint: str
    method: str
    inputs: tuple[str, ...]
    identity: str
    content_type: str

    @classmethod
    def create(  # noqa: PLR0913 - explicit canonical surface dimensions.
        cls,
        *,
        family: str,
        endpoint: str = "",
        method: str = "",
        inputs: Sequence[str] = (),
        identity: str = "",
        content_type: str = "",
    ) -> SurfaceCell:
        canonical = {
            "family": canonical_family(family),
            "endpoint": _normalized_endpoint(endpoint),
            "method": _normalized_token(method).upper() or "ANY",
            "inputs": list(_clean_strings(inputs)),
            "identity": _normalized_token(identity) or "anonymous",
            "content_type": _normalized_content_type(content_type),
        }
        return cls(
            cell_id=f"cell:{_digest_json(canonical)[:24]}",
            family=str(canonical["family"]),
            endpoint=str(canonical["endpoint"]),
            method=str(canonical["method"]),
            inputs=tuple(canonical["inputs"]),
            identity=str(canonical["identity"]),
            content_type=str(canonical["content_type"]),
        )

    @classmethod
    def from_objective(
        cls,
        objective: GraphObjective,
        *,
        route: Mapping[str, object] | None = None,
    ) -> SurfaceCell:
        current = route or {}
        endpoints = _string_tuple(current.get("endpoints"))
        route_inputs = _string_tuple(current.get("inputs"))
        return cls.create(
            family=str(current.get("family") or objective.family),
            endpoint=endpoints[0] if endpoints else objective.endpoint,
            method=str(current.get("method") or ""),
            inputs=route_inputs or objective.inputs,
            identity=str(current.get("identity") or ""),
            content_type=str(current.get("content_type") or ""),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "cell_id": self.cell_id,
            "family": self.family,
            "endpoint": self.endpoint,
            "method": self.method,
            "inputs": list(self.inputs),
            "identity": self.identity,
            "content_type": self.content_type,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> SurfaceCell:
        cell = cls.create(
            family=str(payload.get("family") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            method=str(payload.get("method") or ""),
            inputs=_string_tuple(payload.get("inputs")),
            identity=str(payload.get("identity") or ""),
            content_type=str(payload.get("content_type") or ""),
        )
        if str(payload.get("cell_id") or "") != cell.cell_id:
            raise InvestigationCoverageError("coverage cell ID does not match canonical fields")
        return cell


@dataclass
class CoverageCellState:
    cell: SurfaceCell
    stage: CoverageStage = CoverageStage.OBSERVED
    evidence_version: int = 0
    attempt_count: int = 0
    no_progress_streak: int = 0
    target_requests: int = 0
    attempted_dimensions: dict[str, int] = field(default_factory=dict)
    last_dimension: str = ""
    last_outcome: str = ""
    evidence_refs: tuple[str, ...] = ()
    exhausted: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "cell": self.cell.to_json(),
            "stage": self.stage.value,
            "evidence_version": self.evidence_version,
            "attempt_count": self.attempt_count,
            "no_progress_streak": self.no_progress_streak,
            "target_requests": self.target_requests,
            "attempted_dimensions": dict(sorted(self.attempted_dimensions.items())),
            "last_dimension": self.last_dimension,
            "last_outcome": self.last_outcome,
            "evidence_refs": list(self.evidence_refs),
            "exhausted": self.exhausted,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> CoverageCellState:
        raw_cell = payload.get("cell")
        if not isinstance(raw_cell, Mapping):
            raise InvestigationCoverageError("coverage cell state requires a cell object")
        return cls(
            cell=SurfaceCell.from_json(raw_cell),
            stage=CoverageStage(str(payload.get("stage") or "")),
            evidence_version=_non_negative_int(payload, "evidence_version"),
            attempt_count=_non_negative_int(payload, "attempt_count"),
            no_progress_streak=_non_negative_int(payload, "no_progress_streak"),
            target_requests=_non_negative_int(payload, "target_requests"),
            attempted_dimensions=_version_mapping(payload.get("attempted_dimensions")),
            last_dimension=str(payload.get("last_dimension") or ""),
            last_outcome=str(payload.get("last_outcome") or ""),
            evidence_refs=_string_tuple(payload.get("evidence_refs")),
            exhausted=bool(payload.get("exhausted", False)),
        )


@dataclass(frozen=True)
class CampaignReservation:
    reservation_id: str
    node_id: str
    cell_id: str
    strategy: str
    dimension: str
    evidence_version: int

    @property
    def route_key(self) -> str:
        return "|".join(
            (
                self.cell_id,
                self.strategy,
                self.dimension,
                str(self.evidence_version),
            )
        )

    def to_json(self) -> dict[str, object]:
        return {
            "reservation_id": self.reservation_id,
            "node_id": self.node_id,
            "cell_id": self.cell_id,
            "strategy": self.strategy,
            "dimension": self.dimension,
            "evidence_version": self.evidence_version,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> CampaignReservation:
        reservation = cls(
            reservation_id=str(payload.get("reservation_id") or ""),
            node_id=str(payload.get("node_id") or ""),
            cell_id=str(payload.get("cell_id") or ""),
            strategy=_normalized_token(str(payload.get("strategy") or "")),
            dimension=_normalized_token(str(payload.get("dimension") or "")),
            evidence_version=_non_negative_int(payload, "evidence_version"),
        )
        if not all(
            (
                reservation.reservation_id,
                reservation.node_id,
                reservation.cell_id,
                reservation.strategy,
                reservation.dimension,
            )
        ):
            raise InvestigationCoverageError("coverage reservation is incomplete")
        return reservation


@dataclass
class CoverageLedgerState:
    cells: dict[str, CoverageCellState] = field(default_factory=dict)
    reservations: dict[str, CampaignReservation] = field(default_factory=dict)
    attempts: list[dict[str, object]] = field(default_factory=list)
    total_target_requests: int = 0

    def to_json(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "cells": {cell_id: state.to_json() for cell_id, state in sorted(self.cells.items())},
            "reservations": {
                route_key: reservation.to_json()
                for route_key, reservation in sorted(self.reservations.items())
            },
            "attempts": copy.deepcopy(self.attempts),
            "total_target_requests": self.total_target_requests,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> CoverageLedgerState:
        if payload.get("version") != _STATE_VERSION:
            raise InvestigationCoverageError("unsupported investigation coverage version")
        raw_cells = payload.get("cells")
        raw_reservations = payload.get("reservations", {})
        if not isinstance(raw_cells, Mapping) or not isinstance(raw_reservations, Mapping):
            raise InvestigationCoverageError("coverage cells and reservations must be objects")
        cells: dict[str, CoverageCellState] = {}
        for cell_id, raw_state in raw_cells.items():
            if not isinstance(raw_state, Mapping):
                raise InvestigationCoverageError("coverage cell state must be an object")
            state = CoverageCellState.from_json(raw_state)
            if str(cell_id) != state.cell.cell_id:
                raise InvestigationCoverageError("coverage cell map key mismatch")
            cells[state.cell.cell_id] = state
        reservations: dict[str, CampaignReservation] = {}
        for route_key, raw_reservation in raw_reservations.items():
            if not isinstance(raw_reservation, Mapping):
                raise InvestigationCoverageError("coverage reservation must be an object")
            reservation = CampaignReservation.from_json(raw_reservation)
            if str(route_key) != reservation.route_key:
                raise InvestigationCoverageError("coverage reservation key mismatch")
            reservations[reservation.route_key] = reservation
        attempts = payload.get("attempts", [])
        if not isinstance(attempts, list) or not all(
            isinstance(attempt, Mapping) for attempt in attempts
        ):
            raise InvestigationCoverageError("coverage attempts must be a list of objects")
        return cls(
            cells=cells,
            reservations=reservations,
            attempts=[dict(attempt) for attempt in attempts[-_MAX_ATTEMPTS:]],
            total_target_requests=_non_negative_int(payload, "total_target_requests"),
        )


class InvestigationCoverageLedger:
    """Durable route-wide coverage and campaign reservation ledger."""

    def __init__(self, state_path: Path, state: CoverageLedgerState) -> None:
        self.state_path = state_path
        self.state = state
        self._lock = threading.RLock()

    @classmethod
    def open(cls, state_path: Path) -> InvestigationCoverageLedger:
        if state_path.exists():
            try:
                raw = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise InvestigationCoverageError(
                    f"cannot read investigation coverage: {exc}"
                ) from exc
            if not isinstance(raw, Mapping):
                raise InvestigationCoverageError("investigation coverage must be an object")
            state = CoverageLedgerState.from_json(raw)
            # No worker survives a process restart. Durable in-flight tool accounting
            # belongs to GraphCoordinator, so stale campaign reservations are released.
            state.reservations.clear()
        else:
            state = CoverageLedgerState()
        ledger = cls(state_path, state)
        ledger._persist()
        return ledger

    def ensure_cell(
        self,
        cell: SurfaceCell,
        *,
        initial_stage: CoverageStage = CoverageStage.OBSERVED,
    ) -> CoverageCellState:
        with self._lock:
            current = self.state.cells.get(cell.cell_id)
            if current is None:
                current = CoverageCellState(cell=cell, stage=initial_stage)
                self.state.cells[cell.cell_id] = current
                self._persist()
            elif _STAGE_RANK[initial_stage] > _STAGE_RANK[current.stage]:
                current.stage = initial_stage
                current.exhausted = False
                self._persist()
            return copy.deepcopy(current)

    def cell_state(self, cell_id: str) -> CoverageCellState:
        with self._lock:
            current = self.state.cells.get(cell_id)
            if current is None:
                raise InvestigationCoverageError(f"unknown coverage cell: {cell_id}")
            return copy.deepcopy(current)

    def reserve(
        self,
        *,
        node_id: str,
        cell: SurfaceCell,
        strategy: str,
        dimension: str,
    ) -> CampaignReservation:
        normalized_strategy = _normalized_token(strategy)
        normalized_dimension = _normalized_token(dimension)
        if not node_id.strip() or not normalized_strategy or not normalized_dimension:
            raise InvestigationCoverageError("campaign reservation fields are required")
        with self._lock:
            current = self.state.cells.get(cell.cell_id)
            if current is None:
                current = CoverageCellState(cell=cell)
                self.state.cells[cell.cell_id] = current
            identity = {
                "node_id": node_id,
                "cell_id": cell.cell_id,
                "strategy": normalized_strategy,
                "dimension": normalized_dimension,
                "evidence_version": current.evidence_version,
                "attempt_sequence": current.attempt_count + 1,
            }
            reservation = CampaignReservation(
                reservation_id=f"reservation:{_digest_json(identity)[:24]}",
                node_id=node_id,
                cell_id=cell.cell_id,
                strategy=normalized_strategy,
                dimension=normalized_dimension,
                evidence_version=current.evidence_version,
            )
            existing = self.state.reservations.get(reservation.route_key)
            if existing is not None:
                raise InvestigationCoverageError(
                    "campaign route is already reserved by "
                    f"{existing.node_id}: {normalized_strategy}/{normalized_dimension}"
                )
            self.state.reservations[reservation.route_key] = reservation
            self._persist()
            return reservation

    def cancel(self, reservation: CampaignReservation) -> None:
        with self._lock:
            stored = self.state.reservations.get(reservation.route_key)
            if stored is not None and stored.reservation_id == reservation.reservation_id:
                del self.state.reservations[reservation.route_key]
                self._persist()

    def complete(  # noqa: PLR0913 - explicit durable attempt result.
        self,
        reservation: CampaignReservation,
        *,
        stage: CoverageStage,
        material_progress: bool,
        evidence_changed: bool,
        outcome: str,
        evidence_refs: Sequence[str] = (),
        target_requests: int = 0,
        hypothesis_fingerprint: str = "",
        agent_spec_fingerprint: str = "",
        belief_revision_id: str = "",
        belief_disposition: str = "",
        executor_receipt_digest: str = "",
    ) -> CoverageCellState:
        if target_requests < 0:
            raise InvestigationCoverageError("target request count cannot be negative")
        with self._lock:
            stored = self.state.reservations.get(reservation.route_key)
            if stored is None or stored.reservation_id != reservation.reservation_id:
                raise InvestigationCoverageError("campaign reservation is not active")
            current = self.state.cells.get(reservation.cell_id)
            if current is None:
                raise InvestigationCoverageError("campaign coverage cell disappeared")
            current.attempt_count += 1
            current.target_requests += target_requests
            current.last_dimension = reservation.dimension
            current.last_outcome = _normalized_text(outcome)
            current.attempted_dimensions[f"{reservation.strategy}:{reservation.dimension}"] = (
                reservation.evidence_version
            )
            if _STAGE_RANK[stage] > _STAGE_RANK[current.stage]:
                current.stage = stage
            if evidence_changed:
                current.evidence_version += 1
            if material_progress:
                current.no_progress_streak = 0
                current.exhausted = False
            else:
                current.no_progress_streak += 1
            current.evidence_refs = _clean_strings((*current.evidence_refs, *evidence_refs))
            self.state.total_target_requests += target_requests
            self.state.attempts.append(
                {
                    "reservation_id": reservation.reservation_id,
                    "node_id": reservation.node_id,
                    "cell_id": reservation.cell_id,
                    "strategy": reservation.strategy,
                    "dimension": reservation.dimension,
                    "evidence_version_before": reservation.evidence_version,
                    "evidence_version_after": current.evidence_version,
                    "stage": current.stage.value,
                    "material_progress": material_progress,
                    "evidence_changed": evidence_changed,
                    "outcome": current.last_outcome,
                    "evidence_refs": list(_clean_strings(evidence_refs)),
                    "target_requests": target_requests,
                    "hypothesis_fingerprint": hypothesis_fingerprint.strip(),
                    "agent_spec_fingerprint": agent_spec_fingerprint.strip(),
                    "belief_revision_id": belief_revision_id.strip(),
                    "belief_disposition": belief_disposition.strip(),
                    "executor_receipt_digest": executor_receipt_digest.strip(),
                }
            )
            del self.state.attempts[:-_MAX_ATTEMPTS]
            del self.state.reservations[reservation.route_key]
            self._persist()
            return copy.deepcopy(current)

    def mark_exhausted(self, cell_id: str) -> CoverageCellState:
        with self._lock:
            current = self.state.cells.get(cell_id)
            if current is None:
                raise InvestigationCoverageError(f"unknown coverage cell: {cell_id}")
            current.exhausted = True
            self._persist()
            return copy.deepcopy(current)

    def projection(self, cell_id: str) -> dict[str, object]:
        current = self.cell_state(cell_id)
        return {
            **current.cell.to_json(),
            "stage": current.stage.value,
            "evidence_version": current.evidence_version,
            "attempt_count": current.attempt_count,
            "no_progress_streak": current.no_progress_streak,
            "target_requests": current.target_requests,
            "attempted_dimensions": dict(sorted(current.attempted_dimensions.items())),
            "last_dimension": current.last_dimension,
            "last_outcome": current.last_outcome,
            "evidence_refs": list(current.evidence_refs),
            "exhausted": current.exhausted,
        }

    def snapshot(self) -> CoverageLedgerState:
        with self._lock:
            return copy.deepcopy(self.state)

    def _persist(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.state.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.state_path)


def _normalized_endpoint(value: str) -> str:
    normalized = value.strip()
    return normalized or "*"


def _normalized_content_type(value: str) -> str:
    normalized = value.strip().lower().split(";", 1)[0]
    return normalized or "unknown"


def _normalized_token(value: str) -> str:
    return "_".join(value.strip().lower().replace("-", " ").split())


def _normalized_text(value: str) -> str:
    return " ".join(value.strip().split())


def _clean_strings(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted({_normalized_text(str(value)) for value in values if str(value).strip()}))


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return _clean_strings(tuple(str(item) for item in value))


def _version_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, int] = {}
    for key, raw_version in value.items():
        if isinstance(raw_version, bool) or not isinstance(raw_version, int) or raw_version < 0:
            raise InvestigationCoverageError("attempted dimension version must be non-negative")
        result[str(key)] = raw_version
    return result


def _non_negative_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvestigationCoverageError(f"{key} must be a non-negative integer")
    return value


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "CampaignReservation",
    "CoverageCellState",
    "CoverageLedgerState",
    "CoverageStage",
    "InvestigationCoverageError",
    "InvestigationCoverageLedger",
    "SurfaceCell",
    "canonical_family",
]
