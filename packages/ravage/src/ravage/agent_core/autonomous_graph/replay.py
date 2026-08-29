# Replay errors identify the exact malformed or untrusted artifact boundary.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.autonomous_graph.evidence import EvidenceBlackboard

if TYPE_CHECKING:
    from pathlib import Path

_TRUSTED_EVENT_KINDS = frozenset(
    {
        "tool_run_command",
        "tool_run_python",
        "tool_run_probe",
        "tool_validate_poc",
    }
)
_MAX_REPLAY_ARTIFACT_BYTES = 1_000_000
_CHECKSUM_PARTS = 2


class GraphReplayError(RuntimeError):
    """Raised when an artifact replay cannot preserve recorded provenance."""


@dataclass(frozen=True)
class ChecksumReceipt:
    manifest_sha256: str
    verified_files: int
    covered_files: frozenset[str] = field(repr=False)

    def to_json(self) -> dict[str, object]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "verified_files": self.verified_files,
        }


@dataclass(frozen=True)
class RecordedToolObservation:
    producer_node_id: str
    action_id: str
    observation_id: str
    source_kind: str
    action: dict[str, object]
    result: ActionResult


@dataclass(frozen=True)
class ReplayReport:
    checksum: ChecksumReceipt
    observations: int
    trusted_observations: int
    unique_raw_records: int
    duplicate_raw_records: int
    material_records: int
    proof_records: int
    source_counts: dict[str, int]
    progress_counts: dict[str, int]
    producer_counts: dict[str, int]
    blackboard_digest: str

    def to_json(self) -> dict[str, object]:
        return {
            "checksum": self.checksum.to_json(),
            "observations": self.observations,
            "trusted_observations": self.trusted_observations,
            "unique_raw_records": self.unique_raw_records,
            "duplicate_raw_records": self.duplicate_raw_records,
            "material_records": self.material_records,
            "proof_records": self.proof_records,
            "source_counts": dict(sorted(self.source_counts.items())),
            "progress_counts": dict(sorted(self.progress_counts.items())),
            "producer_counts": dict(sorted(self.producer_counts.items())),
            "blackboard_digest": self.blackboard_digest,
        }


def replay_case_artifacts(
    *,
    run_root: Path,
    case_id: str,
    blackboard_path: Path,
) -> ReplayReport:
    """Replay checksum-covered executor events without model, target, or Docker."""
    checksum = verify_checksum_manifest(run_root / "artifacts.sha256")
    case_root = _contained_path(run_root, run_root / case_id)
    working_state_path = case_root / "workspace" / "working_state.json"
    _require_checksum_coverage(
        working_state_path,
        checksum_root=run_root,
        checksum=checksum,
    )
    target_url = _target_url(working_state_path)
    blackboard = EvidenceBlackboard(
        target_url=target_url,
        state_path=blackboard_path,
    )
    observations = load_recorded_observations(
        case_root,
        checksum_root=run_root,
        checksum=checksum,
    )
    source_counts: Counter[str] = Counter()
    progress_counts: Counter[str] = Counter()
    producer_counts: Counter[str] = Counter()
    raw_refs: list[str] = []
    trusted = 0

    for observation in observations:
        promotion = blackboard.record_action_result(
            producer_node_id=observation.producer_node_id,
            action=observation.action,
            result=observation.result,
            observation_id=observation.observation_id,
        )
        source_counts[observation.source_kind] += 1
        producer_counts[observation.producer_node_id] += 1
        raw_refs.append(promotion.raw_evidence_ref)
        trusted += int(promotion.source_trusted)
        for receipt in promotion.progress_receipts:
            progress_counts[receipt.kind.value] += 1

    state_payload = blackboard.state.to_json()
    material_records = sum(record.material for record in blackboard.state.records.values())
    proof_records = sum(
        record.kind.value == "proof_confirmed" for record in blackboard.state.records.values()
    )
    unique_raw = len(set(raw_refs))
    return ReplayReport(
        checksum=checksum,
        observations=len(observations),
        trusted_observations=trusted,
        unique_raw_records=unique_raw,
        duplicate_raw_records=len(raw_refs) - unique_raw,
        material_records=material_records,
        proof_records=proof_records,
        source_counts=dict(source_counts),
        progress_counts=dict(progress_counts),
        producer_counts=dict(producer_counts),
        blackboard_digest=_digest_json(state_payload),
    )


def verify_checksum_manifest(path: Path) -> ChecksumReceipt:
    root = path.parent.resolve()
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GraphReplayError(f"cannot read replay checksum manifest: {exc}") from exc
    verified = 0
    covered: set[str] = set()
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != _CHECKSUM_PARTS:
            raise GraphReplayError(f"invalid checksum manifest line {line_number}")
        expected, raw_relative = parts
        if re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
            raise GraphReplayError(f"invalid checksum digest at line {line_number}")
        relative = raw_relative.lstrip("*").strip()
        candidate = _contained_path(root, root / relative)
        normalized_relative = candidate.relative_to(root).as_posix()
        if normalized_relative in covered:
            raise GraphReplayError(f"duplicate checksum artifact: {normalized_relative}")
        if not candidate.is_file():
            raise GraphReplayError(f"checksum artifact is missing: {normalized_relative}")
        actual = _file_digest(candidate)
        if not hmac.compare_digest(actual, expected.lower()):
            raise GraphReplayError(f"checksum artifact mismatch: {normalized_relative}")
        covered.add(normalized_relative)
        verified += 1
    if verified == 0:
        raise GraphReplayError("replay checksum manifest contains no files")
    return ChecksumReceipt(
        manifest_sha256=hashlib.sha256(content.encode()).hexdigest(),
        verified_files=verified,
        covered_files=frozenset(covered),
    )


def load_recorded_observations(
    case_root: Path,
    *,
    checksum_root: Path,
    checksum: ChecksumReceipt,
) -> tuple[RecordedToolObservation, ...]:
    base_workspace = case_root / "workspace"
    workspaces = (
        ("replay-base", base_workspace),
        ("replay-frontier", base_workspace / "autonomous-route"),
    )
    observations: list[RecordedToolObservation] = []
    for producer_prefix, workspace in workspaces:
        events_path = workspace / "events.jsonl"
        if not events_path.is_file():
            continue
        _require_checksum_coverage(
            events_path,
            checksum_root=checksum_root,
            checksum=checksum,
        )
        events = _read_events(events_path)
        actions, outcomes, producers = _event_indexes(
            events,
            producer_prefix=producer_prefix,
        )
        for event in events:
            kind = str(event.get("kind") or "")
            if kind not in _TRUSTED_EVENT_KINDS:
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                raise GraphReplayError(f"{kind} event payload must be an object")
            action_id = str(payload.get("action_id") or "").strip()
            observation_id = str(payload.get("observation_id") or "").strip()
            if not action_id or not observation_id:
                raise GraphReplayError(f"{kind} event lacks action or observation provenance")
            action = actions.get(action_id)
            if action is None:
                raise GraphReplayError(f"recorded tool action is missing: {action_id}")
            observations.append(
                RecordedToolObservation(
                    producer_node_id=producers.get(action_id, producer_prefix),
                    action_id=action_id,
                    observation_id=observation_id,
                    source_kind=kind,
                    action=action,
                    result=_action_result(
                        kind=kind,
                        payload=payload,
                        outcome=outcomes.get(action_id, {}),
                        workspace=workspace,
                        checksum_root=checksum_root,
                        checksum=checksum,
                    ),
                )
            )
    if not observations:
        raise GraphReplayError("case artifacts contain no replayable tool observations")
    return tuple(observations)


def _event_indexes(  # noqa: C901 - explicit decoding of two event schemas.
    events: Sequence[Mapping[str, object]],
    *,
    producer_prefix: str,
) -> tuple[
    dict[str, dict[str, object]],
    dict[str, Mapping[str, object]],
    dict[str, str],
]:
    selected_by_turn: dict[int, dict[str, object]] = {}
    actions: dict[str, dict[str, object]] = {}
    outcomes: dict[str, Mapping[str, object]] = {}
    producers: dict[str, str] = {}

    for event in events:
        kind = str(event.get("kind") or "")
        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            continue
        if kind == "agent_action_selected":
            action = payload.get("action")
            turn = _integer(payload.get("turn"))
            if isinstance(action, Mapping) and turn is not None:
                selected_by_turn[turn] = _json_mapping(action)
        elif kind == "action_started":
            action_id = str(payload.get("action_id") or "").strip()
            turn = _integer(payload.get("turn"))
            if action_id:
                selected = selected_by_turn.get(turn if turn is not None else -1)
                actions[action_id] = selected or _action_from_started(payload)
                producers[action_id] = producer_prefix
        elif kind == "agent_attempt_recorded":
            action_id = str(payload.get("action_id") or "").strip()
            selected = payload.get("selected_action")
            outcome = payload.get("outcome")
            if action_id and isinstance(selected, Mapping):
                actions[action_id] = _json_mapping(selected)
            if action_id and isinstance(outcome, Mapping):
                outcomes[action_id] = outcome
        elif kind == "frontier_action_completed":
            action_id = str(payload.get("action_id") or "").strip()
            action = payload.get("action")
            outcome = payload.get("outcome")
            worker_id = str(payload.get("worker_id") or producer_prefix).strip()
            if action_id and isinstance(action, Mapping):
                actions[action_id] = _json_mapping(action)
                producers[action_id] = f"{producer_prefix}:{worker_id}"
            if action_id and isinstance(outcome, Mapping):
                outcomes[action_id] = outcome
    return actions, outcomes, producers


def _action_from_started(payload: Mapping[str, object]) -> dict[str, object]:
    kind = str(payload.get("action_kind") or "").strip()
    if not kind:
        raise GraphReplayError("action_started event lacks action_kind")
    raw_params = payload.get("params")
    params = _json_mapping(raw_params) if isinstance(raw_params, Mapping) else {}
    return {"action": kind, **params}


def _action_result(  # noqa: PLR0913 - all provenance boundaries are explicit.
    *,
    kind: str,
    payload: Mapping[str, object],
    outcome: Mapping[str, object],
    workspace: Path,
    checksum_root: Path,
    checksum: ChecksumReceipt,
) -> ActionResult:
    observation = _tool_observation(
        kind=kind,
        payload=payload,
        workspace=workspace,
        checksum_root=checksum_root,
        checksum=checksum,
    )
    recognized = payload.get("recognized_proofs")
    proofs = (
        [str(item) for item in recognized if isinstance(item, str) and item]
        if isinstance(recognized, list)
        else []
    )
    ok = _boolean(payload.get("ok"))
    if ok is None:
        ok = _boolean(outcome.get("ok"))
    if ok is None:
        result_payload = payload.get("result")
        if isinstance(result_payload, Mapping):
            ok = _boolean(result_payload.get("ok"))
    result_outcome = str(
        outcome.get("outcome") or outcome.get("classification") or "recorded_observation"
    )
    return ActionResult(
        ok=bool(ok),
        observation=observation,
        stop=_boolean(outcome.get("stop")) is True,
        exit_code=_first_integer(
            payload.get("exit_code"),
            outcome.get("exit_code"),
        ),
        timed_out=(
            _boolean(payload.get("timed_out")) is True or _boolean(outcome.get("timed_out")) is True
        ),
        repeat_count=_integer(payload.get("repeat_count")) or 0,
        outcome=result_outcome,
        flag=proofs[0] if proofs else str(outcome.get("flag") or ""),
        evidence_source_kind=kind,
        evidence_observation=observation,
    )


def _tool_observation(
    *,
    kind: str,
    payload: Mapping[str, object],
    workspace: Path,
    checksum_root: Path,
    checksum: ChecksumReceipt,
) -> str:
    if kind in {"tool_run_probe", "tool_validate_poc"}:
        return _materialize(
            payload.get("result"),
            workspace=workspace,
            checksum_root=checksum_root,
            checksum=checksum,
        )
    stdout = _materialize(
        payload.get("stdout"),
        workspace=workspace,
        checksum_root=checksum_root,
        checksum=checksum,
    )
    stderr = _materialize(
        payload.get("stderr"),
        workspace=workspace,
        checksum_root=checksum_root,
        checksum=checksum,
    )
    return "\n".join(part for part in (stdout, stderr) if part)


def _materialize(
    value: object,
    *,
    workspace: Path,
    checksum_root: Path,
    checksum: ChecksumReceipt,
) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        raw_path = value.get("artifact_path")
        if isinstance(raw_path, str) and raw_path.strip():
            artifact = _contained_path(
                workspace,
                _artifact_path(
                    workspace,
                    raw_path,
                    checksum_root=checksum_root,
                    checksum=checksum,
                ),
            )
            _require_checksum_coverage(
                artifact,
                checksum_root=checksum_root,
                checksum=checksum,
            )
            try:
                size = artifact.stat().st_size
            except OSError as exc:
                raise GraphReplayError(f"cannot inspect replay artifact: {exc}") from exc
            if size > _MAX_REPLAY_ARTIFACT_BYTES:
                raise GraphReplayError("replay artifact exceeds the byte cap")
            try:
                return artifact.read_text(encoding="utf-8")
            except OSError as exc:
                raise GraphReplayError(f"cannot read replay artifact: {exc}") from exc
        return json.dumps(
            _json_mapping(value),
            ensure_ascii=False,
            sort_keys=True,
        )
    if isinstance(value, (list, tuple)):
        return json.dumps(list(value), ensure_ascii=False, sort_keys=True)
    return str(value)


def _artifact_path(
    workspace: Path,
    value: str,
    *,
    checksum_root: Path,
    checksum: ChecksumReceipt,
) -> Path:
    from pathlib import Path  # noqa: PLC0415

    path = Path(value)
    if path.is_absolute():
        return path

    # Run workspaces historically persisted either a workspace-relative path or
    # the relative path by which the whole run was reached from the launch CWD.
    # The latter is not relocatable and naively joining it to `workspace` creates
    # a duplicated `workspace/runs/.../workspace/artifacts/...` path.  Resolve
    # that legacy spelling only when it has exactly one suffix match in the
    # checksum manifest and the covered file is inside this case workspace.
    direct = workspace / path
    raw_posix = path.as_posix().lstrip("./")
    covered_matches: list[Path] = []
    for relative in checksum.covered_files:
        if raw_posix != relative and not raw_posix.endswith(f"/{relative}"):
            continue
        candidate = _contained_path(checksum_root, checksum_root / relative)
        try:
            _contained_path(workspace, candidate)
        except GraphReplayError:
            continue
        covered_matches.append(candidate)
    if len(covered_matches) > 1:
        raise GraphReplayError("replay artifact path has ambiguous checksum coverage")
    return covered_matches[0] if covered_matches else direct


def _read_events(path: Path) -> tuple[dict[str, object], ...]:
    events: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GraphReplayError(f"cannot read replay events: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GraphReplayError(f"invalid replay event JSON at line {line_number}") from exc
        if not isinstance(payload, dict):
            raise GraphReplayError(f"replay event at line {line_number} must be an object")
        events.append(payload)
    return tuple(events)


def _target_url(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GraphReplayError(f"cannot read replay target identity: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise GraphReplayError("replay working state must be an object")
    target_url = str(payload.get("target_url") or "").strip()
    if not target_url:
        raise GraphReplayError("replay working state lacks target identity")
    return target_url


def _contained_path(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise GraphReplayError("replay artifact path escapes its allowed root")
    return resolved


def _require_checksum_coverage(
    path: Path,
    *,
    checksum_root: Path,
    checksum: ChecksumReceipt,
) -> None:
    candidate = _contained_path(checksum_root, path)
    relative = candidate.relative_to(checksum_root.resolve()).as_posix()
    if relative not in checksum.covered_files:
        raise GraphReplayError(f"replay input is not checksum-covered: {relative}")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _json_mapping(value: Mapping[object, object]) -> dict[str, object]:
    return json.loads(
        json.dumps(
            {str(key): item for key, item in value.items()},
            default=str,
        )
    )


def _integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _first_integer(*values: object) -> int | None:
    for value in values:
        parsed = _integer(value)
        if parsed is not None:
            return parsed
    return None


def _boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


__all__ = [
    "ChecksumReceipt",
    "GraphReplayError",
    "RecordedToolObservation",
    "ReplayReport",
    "load_recorded_observations",
    "replay_case_artifacts",
    "verify_checksum_manifest",
]
