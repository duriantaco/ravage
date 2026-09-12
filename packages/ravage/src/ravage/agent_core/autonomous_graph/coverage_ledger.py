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

from ravage.agent_core.autonomous_graph.branch_search import (
    BranchOutcomeIndex,
    BranchSearchError,
    seal_planner_feedback_attempt,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.autonomous_graph.models import GraphObjective

_STATE_VERSION = 1
_MAX_ATTEMPTS = 500
_MAX_STATE_BYTES = 16 * 1024 * 1024
_MAX_CELLS = 2_048
_MAX_RESERVATIONS = 256
_MAX_ROUTE_TARGET_REQUESTS = 96


class InvestigationCoverageError(RuntimeError):
    """Raised when durable investigation coverage cannot preserve its invariants."""


class PlannerFeedbackError(InvestigationCoverageError):
    """Raised before mutation when optional planner feedback cannot be sealed."""


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
    pessimistic_target_request_charges: int = 0

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
            "pessimistic_target_request_charges": (
                self.pessimistic_target_request_charges
            ),
        }

    @classmethod
    def from_json(
        cls,
        payload: Mapping[str, object],
    ) -> CoverageLedgerState:
        if payload.get("version") != _STATE_VERSION:
            raise InvestigationCoverageError("unsupported investigation coverage version")
        raw_cells = payload.get("cells")
        raw_reservations = payload.get("reservations", {})
        if not isinstance(raw_cells, Mapping) or not isinstance(raw_reservations, Mapping):
            raise InvestigationCoverageError("coverage cells and reservations must be objects")
        if len(raw_cells) > _MAX_CELLS or len(raw_reservations) > _MAX_RESERVATIONS:
            raise InvestigationCoverageError("coverage state exceeds its object-count limit")
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
        if len(attempts) > _MAX_ATTEMPTS:
            raise InvestigationCoverageError("coverage attempts exceed their history limit")
        state = cls(
            cells=cells,
            reservations=reservations,
            attempts=[dict(attempt) for attempt in attempts],
            total_target_requests=_non_negative_int(payload, "total_target_requests"),
            pessimistic_target_request_charges=_non_negative_int(
                payload,
                "pessimistic_target_request_charges",
            ),
        )
        if (
            state.total_target_requests + state.pessimistic_target_request_charges
            > _MAX_ROUTE_TARGET_REQUESTS
        ):
            raise InvestigationCoverageError(
                "coverage target-request charges exceed the route bound"
            )
        return state


@dataclass(frozen=True)
class PreparedCoverageCompletion:
    """Fully validated coverage transition awaiting one compare-and-swap commit."""

    reservation_id: str
    route_key: str
    cell_id: str
    expected_state_digest: str
    prepared_state_digest: str
    state: CoverageLedgerState


class InvestigationCoverageLedger:
    """Durable route-wide coverage and campaign reservation ledger."""

    def __init__(self, state_path: Path, state: CoverageLedgerState) -> None:
        self.state_path = state_path
        self.state = state
        self._lock = threading.RLock()

    @classmethod
    def open(cls, state_path: Path) -> InvestigationCoverageLedger:
        if state_path.exists():
            if state_path.stat().st_size > _MAX_STATE_BYTES:
                raise InvestigationCoverageError(
                    "investigation coverage exceeds its file-size limit"
                )
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
                next_state = copy.deepcopy(self.state)
                current = CoverageCellState(cell=cell, stage=initial_stage)
                next_state.cells[cell.cell_id] = current
                self._persist_state(next_state)
                self.state = next_state
            elif _STAGE_RANK[initial_stage] > _STAGE_RANK[current.stage]:
                next_state = copy.deepcopy(self.state)
                current = next_state.cells[cell.cell_id]
                current.stage = initial_stage
                current.exhausted = False
                self._persist_state(next_state)
                self.state = next_state
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
            next_state = copy.deepcopy(self.state)
            current = next_state.cells.get(cell.cell_id)
            if current is None:
                current = CoverageCellState(cell=cell)
                next_state.cells[cell.cell_id] = current
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
            existing = next_state.reservations.get(reservation.route_key)
            if existing is not None:
                raise InvestigationCoverageError(
                    "campaign route is already reserved by "
                    f"{existing.node_id}: {normalized_strategy}/{normalized_dimension}"
                )
            next_state.reservations[reservation.route_key] = reservation
            self._persist_state(next_state)
            self.state = next_state
            return reservation

    def cancel(self, reservation: CampaignReservation) -> None:
        with self._lock:
            stored = self.state.reservations.get(reservation.route_key)
            if stored is not None and stored.reservation_id == reservation.reservation_id:
                next_state = copy.deepcopy(self.state)
                del next_state.reservations[reservation.route_key]
                self._persist_state(next_state)
                self.state = next_state

    def charge_failed_reservation(
        self,
        reservation: CampaignReservation,
        *,
        authorized_grant: int,
    ) -> None:
        """Consume an uncertain post-execution grant without inventing observations."""

        if (
            isinstance(authorized_grant, bool)
            or not isinstance(authorized_grant, int)
            or not 1 <= authorized_grant <= _MAX_ROUTE_TARGET_REQUESTS
        ):
            raise InvestigationCoverageError("failed target-request grant is invalid")
        with self._lock:
            next_state = copy.deepcopy(self.state)
            stored = next_state.reservations.get(reservation.route_key)
            if stored is None or stored.reservation_id != reservation.reservation_id:
                raise InvestigationCoverageError("campaign reservation is not active")
            charged = (
                next_state.total_target_requests
                + next_state.pessimistic_target_request_charges
                + authorized_grant
            )
            if charged > _MAX_ROUTE_TARGET_REQUESTS:
                raise InvestigationCoverageError(
                    "route target-request charge exceeds its durable bound"
                )
            del next_state.reservations[reservation.route_key]
            next_state.pessimistic_target_request_charges += authorized_grant
            canonical_state = CoverageLedgerState.from_json(next_state.to_json())
            self._persist_state(canonical_state)
            self.state = canonical_state

    def prepare_completion(  # noqa: PLR0913, PLR0915 - explicit durable attempt result.
        self,
        reservation: CampaignReservation,
        *,
        stage: CoverageStage,
        material_progress: bool,
        evidence_changed: bool,
        outcome: str,
        planner_feedback_enabled: bool = False,
        planner_cell_id: str = "",
        planner_attempt_count_before: int = 0,
        planner_evidence_refs_before: Sequence[str] = (),
        planner_evidence_version_before: int = 0,
        planner_no_progress_streak_before: int = 0,
        planner_previous_feedback_digest: str = "",
        planner_stage_before: CoverageStage = CoverageStage.OBSERVED,
        planner_stage_after: CoverageStage = CoverageStage.OBSERVED,
        planner_target_requests_before: int = 0,
        evidence_refs: Sequence[str] = (),
        target_requests: int = 0,
        hypothesis_fingerprint: str = "",
        agent_spec_fingerprint: str = "",
        belief_revision_id: str = "",
        belief_disposition: str = "",
        executor_receipt_digest: str = "",
        progress_class: str = "empty",
        progress_kinds: Sequence[str] = (),
        validated_batch_digest: str = "",
        hypothesis_path: Sequence[str] = (),
        repeated_observation: bool = False,
        planner_attributed: bool = False,
        planner_state_attributed: bool = False,
    ) -> PreparedCoverageCompletion:
        if target_requests < 0:
            raise InvestigationCoverageError("target request count cannot be negative")
        if planner_feedback_enabled and target_requests > _MAX_ROUTE_TARGET_REQUESTS:
            raise InvestigationCoverageError("target request count exceeds the route bound")
        normalized_progress_class = _normalized_token(progress_class) or "empty"
        if normalized_progress_class not in {
            "empty",
            "support",
            "confirm",
            "disprove",
            "pivot",
            "proof",
        }:
            raise InvestigationCoverageError("planner progress class is unsupported")
        normalized_hypothesis = _normalized_text(hypothesis_fingerprint)
        normalized_hypothesis_path = _clean_identity_path(hypothesis_path)
        if not normalized_hypothesis_path and normalized_hypothesis:
            normalized_hypothesis_path = (normalized_hypothesis,)
        if normalized_hypothesis and normalized_hypothesis_path[0] != normalized_hypothesis:
            raise InvestigationCoverageError(
                "hypothesis path does not start at the attempt hypothesis"
            )
        normalized_progress_kinds = _clean_strings(progress_kinds)
        normalized_batch_digest = validated_batch_digest.strip()
        normalized_outcome = _normalized_text(outcome)
        normalized_evidence_refs = _clean_strings(evidence_refs)
        normalized_planner_evidence_refs_before = _clean_strings(
            planner_evidence_refs_before
        )
        normalized_planner_evidence_refs_after = _clean_strings(
            (*normalized_planner_evidence_refs_before, *normalized_evidence_refs)
        )
        with self._lock:
            expected_state_digest = _digest_json(self.state.to_json())
            next_state = copy.deepcopy(self.state)
            if (
                next_state.total_target_requests
                + next_state.pessimistic_target_request_charges
                + target_requests
                > _MAX_ROUTE_TARGET_REQUESTS
            ):
                raise InvestigationCoverageError(
                    "route target request count exceeds its durable bound"
                )
            stored = next_state.reservations.get(reservation.route_key)
            if stored is None or stored.reservation_id != reservation.reservation_id:
                raise InvestigationCoverageError("campaign reservation is not active")
            current = next_state.cells.get(reservation.cell_id)
            if current is None:
                raise InvestigationCoverageError("campaign coverage cell disappeared")
            merged_evidence_refs = _clean_strings(
                (*current.evidence_refs, *normalized_evidence_refs)
            )
            stage_before = current.stage
            stage_after = (
                stage if _STAGE_RANK[stage] > _STAGE_RANK[current.stage] else current.stage
            )
            evidence_version_before = current.evidence_version
            evidence_version_after = evidence_version_before + int(evidence_changed)
            if planner_feedback_enabled:
                try:
                    feedback_attempt = seal_planner_feedback_attempt(
                        {
                            "reservation_id": reservation.reservation_id,
                            "node_id": reservation.node_id,
                            "cell_id": reservation.cell_id,
                            "planner_cell_id": _normalized_text(planner_cell_id),
                            "planner_attempt_count_before": planner_attempt_count_before,
                            "planner_attempt_count_after": planner_attempt_count_before + 1,
                            "planner_evidence_version_before": planner_evidence_version_before,
                            "planner_evidence_version_after": (
                                planner_evidence_version_before + int(evidence_changed)
                            ),
                            "planner_evidence_refs_before": list(
                                normalized_planner_evidence_refs_before
                            ),
                            "planner_evidence_refs_after": list(
                                normalized_planner_evidence_refs_after
                            ),
                            "planner_no_progress_streak_before": (
                                planner_no_progress_streak_before
                            ),
                            "planner_no_progress_streak_after": (
                                0
                                if material_progress
                                else planner_no_progress_streak_before + 1
                            ),
                            "planner_previous_feedback_digest": (
                                planner_previous_feedback_digest
                            ),
                            "planner_stage_before": planner_stage_before.value,
                            "planner_stage_after": planner_stage_after.value,
                            "planner_target_requests_before": planner_target_requests_before,
                            "planner_target_requests_after": (
                                planner_target_requests_before + target_requests
                            ),
                            "strategy": reservation.strategy,
                            "dimension": reservation.dimension,
                            "reservation_evidence_version": reservation.evidence_version,
                            "evidence_version_before": evidence_version_before,
                            "evidence_version_after": evidence_version_after,
                            "stage_before": stage_before.value,
                            "stage": stage_after.value,
                            "material_progress": material_progress,
                            "evidence_changed": evidence_changed,
                            "outcome": normalized_outcome,
                            "progress_class": normalized_progress_class,
                            "progress_kinds": list(normalized_progress_kinds),
                            "planner_attributed": planner_attributed,
                            "planner_state_attributed": planner_state_attributed,
                            "validated_batch_digest": normalized_batch_digest,
                            "hypothesis_path": list(normalized_hypothesis_path),
                            "repeated_observation": repeated_observation,
                            "evidence_refs": list(normalized_evidence_refs),
                            "target_requests": target_requests,
                            "hypothesis_fingerprint": normalized_hypothesis,
                            "agent_spec_fingerprint": _normalized_text(agent_spec_fingerprint),
                            "belief_revision_id": _normalized_text(belief_revision_id),
                            "belief_disposition": _normalized_text(belief_disposition),
                            "executor_receipt_digest": _normalized_text(
                                executor_receipt_digest
                            ),
                        }
                    )
                except BranchSearchError as exc:
                    raise PlannerFeedbackError(
                        f"cannot persist planner feedback: {exc}"
                    ) from exc
                if planner_state_attributed and sum(
                    attempt.get("planner_state_attributed") is True
                    for attempt in next_state.attempts
                ) >= _MAX_ATTEMPTS:
                    raise PlannerFeedbackError(
                        "cannot persist planner feedback: replay history is full"
                    )
            else:
                feedback_attempt = {
                    "reservation_id": reservation.reservation_id,
                    "node_id": reservation.node_id,
                    "cell_id": reservation.cell_id,
                    "strategy": reservation.strategy,
                    "dimension": reservation.dimension,
                    "evidence_version_before": reservation.evidence_version,
                    "evidence_version_after": evidence_version_after,
                    "stage": stage_after.value,
                    "material_progress": material_progress,
                    "evidence_changed": evidence_changed,
                    "outcome": normalized_outcome,
                    "evidence_refs": list(normalized_evidence_refs),
                    "target_requests": target_requests,
                    "hypothesis_fingerprint": hypothesis_fingerprint.strip(),
                    "agent_spec_fingerprint": agent_spec_fingerprint.strip(),
                    "belief_revision_id": belief_revision_id.strip(),
                    "belief_disposition": belief_disposition.strip(),
                    "executor_receipt_digest": executor_receipt_digest.strip(),
                }
            current.attempt_count += 1
            current.target_requests += target_requests
            current.last_dimension = reservation.dimension
            current.last_outcome = normalized_outcome
            current.attempted_dimensions[f"{reservation.strategy}:{reservation.dimension}"] = (
                reservation.evidence_version
            )
            current.stage = stage_after
            current.evidence_version = evidence_version_after
            if material_progress:
                current.no_progress_streak = 0
                current.exhausted = False
            else:
                current.no_progress_streak += 1
            current.evidence_refs = merged_evidence_refs
            next_state.total_target_requests += target_requests
            next_state.attempts.append(feedback_attempt)
            while len(next_state.attempts) > _MAX_ATTEMPTS:
                removable = next(
                    (
                        index
                        for index, attempt in enumerate(next_state.attempts)
                        if attempt.get("planner_state_attributed") is not True
                    ),
                    None,
                )
                if removable is None:
                    raise InvestigationCoverageError(
                        "planner feedback history cannot discard a replay root"
                    )
                next_state.attempts.pop(removable)
            del next_state.reservations[reservation.route_key]
            if planner_feedback_enabled:
                try:
                    BranchOutcomeIndex.from_attempts(next_state.attempts)
                except BranchSearchError as exc:
                    raise PlannerFeedbackError(
                        f"cannot persist planner feedback: {exc}"
                    ) from exc
            canonical_state = CoverageLedgerState.from_json(next_state.to_json())
            prepared_state_digest = _digest_json(canonical_state.to_json())
            encoded_size = len(
                json.dumps(canonical_state.to_json(), ensure_ascii=False, sort_keys=True).encode()
            )
            if encoded_size > _MAX_STATE_BYTES:
                raise InvestigationCoverageError(
                    "investigation coverage exceeds its file-size limit"
                )
            return PreparedCoverageCompletion(
                reservation_id=reservation.reservation_id,
                route_key=reservation.route_key,
                cell_id=reservation.cell_id,
                expected_state_digest=expected_state_digest,
                prepared_state_digest=prepared_state_digest,
                state=canonical_state,
            )

    def commit_prepared(
        self,
        prepared: PreparedCoverageCompletion,
    ) -> CoverageCellState:
        """Commit a prepared transition iff the ledger has not changed."""
        if not isinstance(prepared, PreparedCoverageCompletion):
            raise InvestigationCoverageError("coverage completion plan is invalid")
        with self._lock:
            if _digest_json(self.state.to_json()) != prepared.expected_state_digest:
                raise InvestigationCoverageError("coverage completion plan is stale")
            if _digest_json(prepared.state.to_json()) != prepared.prepared_state_digest:
                raise InvestigationCoverageError("coverage completion plan was modified")
            stored = self.state.reservations.get(prepared.route_key)
            if stored is None or stored.reservation_id != prepared.reservation_id:
                raise InvestigationCoverageError("campaign reservation is not active")
            next_state = copy.deepcopy(prepared.state)
            self._persist_state(next_state)
            self.state = next_state
            current = self.state.cells.get(prepared.cell_id)
            if current is None:  # The prepared schema validation makes this unreachable.
                raise InvestigationCoverageError("prepared coverage cell disappeared")
            return copy.deepcopy(current)

    def complete(
        self,
        reservation: CampaignReservation,
        **completion: object,
    ) -> CoverageCellState:
        """Compatibility API: validate completely, then commit once."""
        prepared = self.prepare_completion(
            reservation,
            **completion,  # type: ignore[arg-type]
        )
        return self.commit_prepared(prepared)

    def mark_exhausted(self, cell_id: str) -> CoverageCellState:
        with self._lock:
            current = self.state.cells.get(cell_id)
            if current is None:
                raise InvestigationCoverageError(f"unknown coverage cell: {cell_id}")
            next_state = copy.deepcopy(self.state)
            current = next_state.cells[cell_id]
            current.exhausted = True
            self._persist_state(next_state)
            self.state = next_state
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
        self._persist_state(self.state)

    def _persist_state(self, state: CoverageLedgerState) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
        content = json.dumps(state.to_json(), indent=2, sort_keys=True) + "\n"
        if len(content.encode()) > _MAX_STATE_BYTES:
            raise InvestigationCoverageError(
                "investigation coverage exceeds its file-size limit"
            )
        temporary.write_text(
            content,
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


def _clean_identity_path(values: Sequence[str]) -> tuple[str, ...]:
    """Normalize a leaf-to-root identity path without destroying its order."""
    path: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = _normalized_text(str(value))
        if not normalized:
            continue
        if normalized in seen:
            message = "hypothesis path contains a duplicate identity"
            raise InvestigationCoverageError(message)
        seen.add(normalized)
        path.append(normalized)
    return tuple(path)


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
    "PlannerFeedbackError",
    "PreparedCoverageCompletion",
    "SurfaceCell",
    "canonical_family",
]
