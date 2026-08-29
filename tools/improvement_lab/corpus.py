"""
Secret-safe projection of Ravage event logs for offline improvement work.

This module intentionally does *not* replay raw graph observations.  It converts an
``events.jsonl`` stream into a lossy structural trajectory.  Candidate agents may
consume development trajectories, while raw logs and sealed holdouts remain on the
evaluator side of the trust boundary.

The projection is safe by construction:

* event kinds and source fields are explicitly allow-listed;
* arbitrary strings are converted to finite categories or discarded;
* case, run, route, input, and evidence-epoch identities use caller-keyed HMACs;
* request/response bodies, model text, tool output, URLs, paths, and proof material
  are never copied;
* a recursive leak gate validates every capsule before it can be exported.
"""

# The ingestion boundary is intentionally branch-heavy and uses direct, generic
# exceptions so no source material is interpolated into diagnostics.
# ruff: noqa: C901, EM101, EM102, PLR0911, PLR0912, PLR0913, TRY003

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import stat
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Final
from urllib.parse import quote, quote_plus

CAPSULE_SCHEMA_VERSION: Final = "ravage.improvement.trajectory.v1"
CORPUS_SCHEMA_VERSION: Final = "ravage.improvement.corpus.v1"

DEVELOPMENT: Final = "development"
SEALED_HOLDOUT: Final = "sealed_holdout"
_PARTITIONS: Final = frozenset({DEVELOPMENT, SEALED_HOLDOUT})

_MAX_FILE_BYTES: Final = 512 * 1024 * 1024
_MAX_LINE_BYTES: Final = 4 * 1024 * 1024
_MAX_EVENTS: Final = 250_000
_MAX_TURN: Final = 100_000
_MAX_COUNT: Final = 1_000_000_000
_MAX_COST_USD: Final = 1_000_000.0
_MAX_IDENTITY_CHARS: Final = 32_768
_HMAC_HEX_CHARS: Final = 32
_MIN_HMAC_KEY_BYTES: Final = 32
_MAX_SCAN_NODES: Final = 200_000
_MAX_SCAN_DEPTH: Final = 40
_MAX_DESCRIPTOR_CHARS: Final = 256
_MAX_IDENTITY_DEPTH: Final = 3

type JSONValue = bool | int | float | str | Sequence[JSONValue] | Mapping[str, JSONValue] | None


class CorpusError(RuntimeError):
    """Base error for the improvement corpus boundary."""


class CorpusFormatError(CorpusError):
    """The source event stream is missing, ambiguous, or malformed."""


class CorpusLeakError(CorpusError):
    """A projected capsule did not pass the recursive leak gate."""

    def __init__(self, findings: Sequence[LeakFinding]) -> None:
        self.findings = tuple(findings)
        super().__init__(f"candidate corpus rejected by {len(self.findings)} leak check(s)")


class HoldoutAccessError(CorpusError):
    """Candidate-visible export was attempted with sealed holdout material."""


class CorpusSplit(StrEnum):
    """Evaluator partition attached to a trajectory capsule."""

    DEVELOPMENT = DEVELOPMENT
    SEALED_HOLDOUT = SEALED_HOLDOUT


@dataclass(frozen=True)
class LeakFinding:
    """A non-secret-bearing leak diagnostic."""

    location: str
    reason: str


_SELECTION_KINDS: Final = frozenset({"harness_selection"})
_ATTEMPT_KINDS: Final = frozenset({"agent_attempt_recorded"})
_TURN_TRACE_KINDS: Final = frozenset({"harness_turn_trace"})
_EVIDENCE_KINDS: Final = frozenset({"outcome_evidence_observed"})
_CONFIRMED_FINDING_KINDS: Final = frozenset({"finding_confirmed"})
_MODEL_REQUEST_KINDS: Final = frozenset(
    {
        "model_request_started",
        "frontier_model_request_started",
        "autonomous_graph_model_request_started",
    }
)
_MODEL_REPLY_KINDS: Final = frozenset(
    {
        "model_reply",
        "model_reply_received",
        "frontier_model_reply_received",
        "autonomous_graph_model_reply_received",
    }
)
_TRAFFIC_KINDS: Final = frozenset({"traffic_policy_started", "traffic_policy_finished"})
_TERMINAL_KIND_STATUS: Final = {
    "agent_finished": "completed",
    "run_completed": "completed",
    "agent_failed": "failed",
    "run_failed": "failed",
    "frontier_route_failed": "failed",
    "autonomous_graph_failed": "failed",
    "frontier_route_cancelled": "cancelled",
    "autonomous_graph_cancelled": "cancelled",
}
_ALLOWED_EVENT_KINDS: Final = frozenset().union(
    _SELECTION_KINDS,
    _ATTEMPT_KINDS,
    _TURN_TRACE_KINDS,
    _EVIDENCE_KINDS,
    _CONFIRMED_FINDING_KINDS,
    _MODEL_REQUEST_KINDS,
    _MODEL_REPLY_KINDS,
    _TRAFFIC_KINDS,
    _TERMINAL_KIND_STATUS,
)

_ACTION_CATEGORIES: Final = frozenset(
    {"unknown", "other", "recon", "browser", "probe", "exploit", "validate", "report", "wait"}
)
_FAMILIES: Final = frozenset(
    {
        "unknown",
        "other",
        "sqli",
        "xss",
        "idor",
        "ssrf",
        "file_read",
        "command_injection",
        "authentication",
        "authorization",
        "graphql",
        "jwt",
        "upload",
        "redirect",
        "deserialization",
        "xxe",
        "template_injection",
    }
)
_METHODS: Final = frozenset(
    {"unknown", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"}
)
_PHASES: Final = frozenset(
    {"unknown", "other", "recon", "attack", "validation", "reporting", "completed"}
)
_SELECTION_REASONS: Final = frozenset(
    {
        "unknown",
        "other",
        "model",
        "recovery",
        "repeat_guard",
        "safety_guard",
        "progress_router",
        "harness",
    }
)
_ATTEMPT_STATUSES: Final = frozenset(
    {"unknown", "other", "attempted", "progressed", "low_value", "completed", "blocked", "failed"}
)
_OUTCOME_CLASSES: Final = frozenset(
    {
        "unknown",
        "other",
        "neutral",
        "evidence_gain",
        "finding_gain",
        "surface_gain",
        "objective_signal",
        "blocked",
        "repeated",
        "timeout",
        "failed",
    }
)
_PROCESS_STATUSES: Final = frozenset({"unknown", "success", "failure"})
_EVIDENCE_STAGES: Final = frozenset(
    {
        "unknown",
        "none",
        "suspected",
        "verified",
        "exploit_primitive",
        "objective_complete",
        "rejected",
    }
)
_CONTRACT_STATUSES: Final = frozenset(
    {"unknown", "other", "suspected", "verified", "confirmed", "rejected", "incomplete"}
)
_CAPABILITY_CATEGORIES: Final = frozenset(
    {
        "other",
        "surface",
        "authentication",
        "authorization",
        "injection",
        "file_access",
        "browser_execution",
        "code_execution",
        "data_access",
        "network_access",
    }
)
_SIGNAL_CATEGORIES: Final = frozenset(
    {
        "other",
        "surface",
        "error",
        "reflection",
        "differential",
        "authentication",
        "authorization",
        "injection",
        "file_access",
        "browser_execution",
        "code_execution",
        "data_access",
    }
)
_TASK_CATEGORIES: Final = frozenset(
    {"other", "pending", "active", "blocked", "completed", "failed", "skipped"}
)
_ACCOUNTING_STATUSES: Final = frozenset({"unknown", "exact", "lower_bound"})
_COST_STATUSES: Final = frozenset({"unknown", "exact", "lower_bound"})
_TERMINATION_STATUSES: Final = frozenset({"unknown", "completed", "failed", "cancelled"})

_SAFE_LITERAL_VALUES: Final = frozenset().union(
    {CAPSULE_SCHEMA_VERSION, CORPUS_SCHEMA_VERSION},
    _PARTITIONS,
    _ACTION_CATEGORIES,
    _FAMILIES,
    _METHODS,
    _PHASES,
    _SELECTION_REASONS,
    _ATTEMPT_STATUSES,
    _OUTCOME_CLASSES,
    _PROCESS_STATUSES,
    _EVIDENCE_STAGES,
    _CONTRACT_STATUSES,
    _CAPABILITY_CATEGORIES,
    _SIGNAL_CATEGORIES,
    _TASK_CATEGORIES,
    _ACCOUNTING_STATUSES,
    _COST_STATUSES,
    _TERMINATION_STATUSES,
)

_TRAFFIC_COUNT_FIELDS: Final = (
    "physical_request_count",
    "completed_request_count",
    "incomplete_request_count",
    "pending_dispatch_count",
    "reservation_count",
    "cache_hit_count",
    "deduplicated_count",
    "retry_count",
    "blocked_count",
    "circuit_open_count",
    "unmetered_action_count",
)

_SAFE_KEYS: Final = frozenset(
    {
        "schema_version",
        "metadata",
        "partition",
        "candidate_visible",
        "case_id",
        "run_id",
        "capsules",
        "turns",
        "turn",
        "selection",
        "proposed",
        "selected",
        "changed",
        "reason",
        "category",
        "family",
        "method",
        "route_id",
        "route_ids",
        "input_ids",
        "has_parameters",
        "attempt",
        "status",
        "novel",
        "evidence_epoch_before",
        "evidence_epoch_after",
        "evidence_advanced",
        "outcome",
        "ok",
        "stop",
        "timed_out",
        "process_status",
        "classification",
        "repeat_count",
        "state_delta",
        "phase_changed",
        "phase_before",
        "phase_after",
        "facts_delta",
        "hypotheses_delta",
        "actions_delta",
        "attempts_delta",
        "new_capabilities",
        "signal_deltas",
        "task_deltas",
        "delta",
        "evidence",
        "observations",
        "confirmed",
        "stage_counts",
        "contract_counts",
        "family_counts",
        "count",
        "aggregate",
        "turn_count",
        "selection_count",
        "attempt_count",
        "evidence_observation_count",
        "confirmed_finding_count",
        "model_call_count",
        "cost_usd",
        "cost_accounting",
        "ignored_event_count",
        "termination",
        "traffic",
        "accounting_status",
        *_TRAFFIC_COUNT_FIELDS,
    }
)

_SENSITIVE_KEY_RE: Final = re.compile(
    r"(?i)(?:proof|flag|token|secret|password|passwd|pwd|cookie|authorization|credential|"
    r"transcript|working[_-]?state|benchmark|target|url|uri|path|endpoint|payload|body|"
    r"response|command|stdout|stderr|raw|prompt|content|header)"
)
_PROOF_LIKE_RE: Final = re.compile(r"(?i)\b(?:flag|ctf|htb|proof)\s*(?:\{|\[|=|:)")
_AUTH_RE: Final = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{4,}")
_ASSIGNMENT_RE: Final = re.compile(
    r"(?i)\b(?:token|secret|password|passwd|pwd|api[_-]?key|session|cookie)\s*[=:]"
)
_URL_RE: Final = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]{1,15}://|\bwww\.)")
_IP_OR_HOST_RE: Final = re.compile(
    r"(?i)(?:\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b|"
    r"\b(?:localhost|[a-z0-9-]+\.(?:com|net|org|io|dev|test|local))(?::\d{1,5})?\b)"
)
_ABSOLUTE_PATH_RE: Final = re.compile(r"(?:^|\s)(?:/[^\s]+|[A-Za-z]:[\\/][^\s]+)")
_JWT_RE: Final = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_OPAQUE_ID_RE: Final = re.compile(
    rf"^(?:case|run|route|input|epoch)_[0-9a-f]{{{_HMAC_HEX_CHARS}}}$"
)


def ingest_run_dir(
    run_dir: str | Path,
    *,
    hmac_key: bytes,
    partition: str | CorpusSplit = DEVELOPMENT,
    case_identifier: str | None = None,
    run_identifier: str | None = None,
    taints: Iterable[str | bytes] = (),
) -> dict[str, JSONValue]:
    """
    Project the sole supported ``events.jsonl`` beneath ``run_dir``.

    Only ``run_dir/events.jsonl`` and ``run_dir/workspace/events.jsonl`` are
    considered.  Transcripts, mutable working state, benchmark reports, databases,
    terminal logs, graph replay artifacts, and response spill files are never read.
    """
    root = Path(run_dir)
    try:
        root_metadata = root.lstat()
    except OSError:
        raise CorpusFormatError("run directory is missing or is not a directory") from None
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise CorpusFormatError("run directory is missing or is not a directory")

    workspace = root / "workspace"
    try:
        workspace_metadata = workspace.lstat()
    except FileNotFoundError:
        workspace_metadata = None
    except OSError:
        raise CorpusFormatError("run directory metadata is unreadable") from None
    if workspace_metadata is not None and stat.S_ISLNK(workspace_metadata.st_mode):
        raise CorpusFormatError("run directory contains a symlinked workspace")

    candidates = (root / "events.jsonl", root / "workspace" / "events.jsonl")
    existing: list[Path] = []
    for candidate in candidates:
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise CorpusFormatError("events stream metadata is unreadable") from None
        _validated_events_metadata(candidate)
        existing.append(candidate)
    if not existing:
        raise CorpusFormatError("run directory does not contain a supported events stream")
    if len(existing) != 1:
        raise CorpusFormatError("run directory contains ambiguous events streams")
    return ingest_events_jsonl(
        existing[0],
        hmac_key=hmac_key,
        partition=partition,
        case_identifier=case_identifier,
        run_identifier=run_identifier,
        taints=taints,
    )


def ingest_events_jsonl(
    events_path: str | Path,
    *,
    hmac_key: bytes,
    partition: str | CorpusSplit = DEVELOPMENT,
    case_identifier: str | None = None,
    run_identifier: str | None = None,
    taints: Iterable[str | bytes] = (),
) -> dict[str, JSONValue]:
    """Build one structural trajectory capsule from a Ravage event stream."""
    key = _validated_hmac_key(hmac_key)
    split = _validated_partition(partition)
    path = Path(events_path)
    try:
        stream, initial_metadata = _open_validated_events(path)
        with stream:
            digest = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            stream.seek(0)
            fallback_identity = f"events-sha256:{digest.hexdigest()}"
            raw_case_id = _validated_source_identity(
                case_identifier or fallback_identity,
                "case",
            )
            raw_run_id = _validated_source_identity(
                run_identifier or fallback_identity,
                "run",
            )
            builder = _CapsuleBuilder(
                hmac_key=key,
                partition=split,
                raw_case_id=raw_case_id,
                raw_run_id=raw_run_id,
            )
            for line_number, raw_line in enumerate(stream, start=1):
                if line_number > _MAX_EVENTS:
                    raise CorpusFormatError("events stream exceeds the event limit")
                if len(raw_line) > _MAX_LINE_BYTES:
                    raise CorpusFormatError("events stream contains an oversized record")
                if not raw_line.strip():
                    continue
                try:
                    event = _strict_json_loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
                    raise CorpusFormatError(
                        f"events stream contains malformed JSON at record {line_number}"
                    ) from None
                if not isinstance(event, Mapping):
                    raise CorpusFormatError(
                        f"events stream contains a non-object record at record {line_number}"
                    )
                kind = event.get("kind")
                if not isinstance(kind, str):
                    raise CorpusFormatError(
                        "events stream contains a record without a valid kind "
                        f"at record {line_number}"
                    )
                if kind not in _ALLOWED_EVENT_KINDS:
                    builder.ignore_event()
                    continue
                payload = event.get("payload")
                if not isinstance(payload, Mapping):
                    raise CorpusFormatError(
                        f"allow-listed event has a non-object payload at record {line_number}"
                    )
                builder.consume(kind, payload)
            final_metadata = os.fstat(stream.fileno())
            if _file_version(final_metadata) != _file_version(initial_metadata):
                raise CorpusFormatError("events stream changed during ingestion")
    except CorpusError:
        raise
    except OSError:
        raise CorpusFormatError("events stream could not be read") from None

    capsule = builder.finish()
    _validate_capsule_shape(capsule)
    scan_for_leaks(capsule, taints=taints)
    return capsule


# Concise alias for callers that already know the source is JSONL.
ingest_events = ingest_events_jsonl
build_trajectory_capsule = ingest_events_jsonl


def candidate_visible_export(
    capsules: Iterable[Mapping[str, object]],
    *,
    taints: Iterable[str | bytes] = (),
) -> dict[str, JSONValue]:
    """
    Return a validated candidate-facing corpus document.

    The operation is fail-closed: one sealed or malformed capsule prevents the
    entire export.  It never silently drops holdouts, since doing so could conceal a
    partitioning mistake from the evaluator.
    """
    taint_values = tuple(taints)
    projected: list[JSONValue] = []
    for capsule in capsules:
        _validate_capsule_shape(capsule)
        metadata = capsule["metadata"]
        if not isinstance(metadata, Mapping):
            raise CorpusFormatError("capsule metadata is malformed")
        if (
            metadata.get("partition") != DEVELOPMENT
            or metadata.get("candidate_visible") is not True
        ):
            raise HoldoutAccessError("candidate-visible export contains a sealed capsule")
        scan_for_leaks(capsule, taints=taint_values)
        # JSON round-tripping gives callers a detached plain-data copy and rejects
        # non-JSON objects before the final recursive scan.
        try:
            detached = json.loads(json.dumps(capsule, sort_keys=True, allow_nan=False))
        except (TypeError, ValueError):
            raise CorpusFormatError("capsule is not strict JSON data") from None
        projected.append(detached)

    document: dict[str, JSONValue] = {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "capsules": projected,
    }
    scan_for_leaks(document, taints=taint_values)
    return document


def serialize_candidate_corpus(
    capsules: Iterable[Mapping[str, object]],
    *,
    taints: Iterable[str | bytes] = (),
) -> str:
    """Serialize a candidate-visible development corpus as canonical JSON."""
    document = candidate_visible_export(capsules, taints=taints)
    return json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)


def serialize_capsule(
    capsule: Mapping[str, object],
    *,
    taints: Iterable[str | bytes] = (),
) -> str:
    """Serialize one evaluator-side capsule, including a sealed holdout capsule."""
    _validate_capsule_shape(capsule)
    scan_for_leaks(capsule, taints=taints)
    try:
        return json.dumps(capsule, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise CorpusFormatError("capsule is not strict JSON data") from None


def write_capsule(
    destination: str | Path,
    capsule: Mapping[str, object],
    *,
    taints: Iterable[str | bytes] = (),
) -> Path:
    """Atomically write one validated evaluator-side capsule."""
    encoded = serialize_capsule(capsule, taints=taints)
    return _atomic_write_text(Path(destination), encoded + "\n")


def write_candidate_corpus(
    destination: str | Path,
    capsules: Iterable[Mapping[str, object]],
    *,
    taints: Iterable[str | bytes] = (),
) -> Path:
    """Atomically write a validated development-only candidate corpus."""
    encoded = serialize_candidate_corpus(capsules, taints=taints)
    return _atomic_write_text(Path(destination), encoded + "\n")


def find_leaks(
    value: object,
    *,
    taints: Iterable[str | bytes] = (),
) -> tuple[LeakFinding, ...]:
    """
    Recursively find raw or sensitive material in candidate-facing data.

    Strings are fail-closed: only schema literals, finite categorical values, and
    correctly shaped opaque HMAC identifiers are accepted.  Caller-supplied taints
    are checked in raw, URL-encoded, Base64, URL-safe Base64, and hexadecimal forms.
    """
    taint_variants = _taint_variants(taints)
    findings: list[LeakFinding] = []
    seen: set[int] = set()
    nodes = 0

    def visit(item: object, location: str, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_SCAN_NODES:
            findings.append(LeakFinding(location, "structure_limit"))
            return
        if depth > _MAX_SCAN_DEPTH:
            findings.append(LeakFinding(location, "depth_limit"))
            return
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            if abs(item) > _MAX_COUNT:
                findings.append(LeakFinding(location, "numeric_limit"))
            return
        if isinstance(item, float):
            if not math.isfinite(item) or abs(item) > _MAX_COST_USD:
                findings.append(LeakFinding(location, "unsafe_number"))
            return
        if isinstance(item, str):
            reason = _unsafe_string_reason(item, taint_variants)
            if reason:
                findings.append(LeakFinding(location, reason))
            return
        if isinstance(item, Mapping):
            marker = id(item)
            if marker in seen:
                findings.append(LeakFinding(location, "recursive_structure"))
                return
            seen.add(marker)
            for index, (key, nested) in enumerate(item.items()):
                key_location = f"{location}[key#{index}]"
                if not isinstance(key, str):
                    findings.append(LeakFinding(key_location, "non_string_key"))
                    child_location = f"{location}[value#{index}]"
                else:
                    key_reason = _unsafe_key_reason(key, taint_variants)
                    if key_reason:
                        findings.append(LeakFinding(key_location, key_reason))
                    child_location = (
                        f"{location}.{key}" if key in _SAFE_KEYS else f"{location}[value#{index}]"
                    )
                visit(nested, child_location, depth + 1)
            seen.remove(marker)
            return
        if isinstance(item, (list, tuple)):
            marker = id(item)
            if marker in seen:
                findings.append(LeakFinding(location, "recursive_structure"))
                return
            seen.add(marker)
            for index, nested in enumerate(item):
                visit(nested, f"{location}[{index}]", depth + 1)
            seen.remove(marker)
            return
        findings.append(LeakFinding(location, "non_json_value"))

    visit(value, "$", 0)
    return tuple(findings)


def scan_for_leaks(value: object, *, taints: Iterable[str | bytes] = ()) -> None:
    """Raise :class:`CorpusLeakError` when ``value`` is not candidate-safe."""
    findings = find_leaks(value, taints=taints)
    if findings:
        raise CorpusLeakError(findings)


assert_secret_safe = scan_for_leaks


class _CapsuleBuilder:
    def __init__(
        self,
        *,
        hmac_key: bytes,
        partition: str,
        raw_case_id: str,
        raw_run_id: str,
    ) -> None:
        self.key = hmac_key
        self.partition = partition
        self.raw_case_id = raw_case_id
        self.raw_run_id = raw_run_id
        self.case_context = _opaque_identifier(hmac_key, "case", partition, raw_case_id)
        self.run_context = _opaque_identifier(hmac_key, "run", partition, raw_run_id)
        self.turns: dict[int, dict[str, JSONValue]] = {}
        self.action_turns: dict[str, int] = {}
        self.ignored_events = 0
        self.selection_count = 0
        self.attempt_count = 0
        self.evidence_count = 0
        self.evidence_keys: set[str] = set()
        self.confirmed_finding_keys: set[str] = set()
        self.model_request_keys: set[str] = set()
        self.model_reply_keys: set[str] = set()
        self.model_cost = 0.0
        self.cost_known = True
        self.saw_cost = False
        self.reported_total_cost: float | None = None
        self.traffic: dict[str, JSONValue] | None = None
        self.termination = "unknown"
        self.sequence = 0

    def ignore_event(self) -> None:
        self.ignored_events += 1

    def consume(self, kind: str, payload: Mapping[str, object]) -> None:
        self.sequence += 1
        if kind in _SELECTION_KINDS:
            self._consume_selection(payload)
        elif kind in _ATTEMPT_KINDS:
            self._consume_attempt(payload)
        elif kind in _TURN_TRACE_KINDS:
            self._consume_turn_trace(payload)
        elif kind in _EVIDENCE_KINDS:
            self._consume_evidence(payload)
        elif kind in _CONFIRMED_FINDING_KINDS:
            self._consume_confirmed_finding(payload)
        elif kind in _MODEL_REQUEST_KINDS:
            self._consume_model_request(payload)
        elif kind in _MODEL_REPLY_KINDS:
            self._consume_model_reply(payload)
        elif kind in _TRAFFIC_KINDS:
            self._consume_traffic(payload)
        elif kind in _TERMINAL_KIND_STATUS:
            self._consume_terminal(kind, payload)

    def finish(self) -> dict[str, JSONValue]:
        turns: list[JSONValue] = []
        for turn_number in sorted(self.turns):
            turn = self.turns[turn_number]
            evidence = turn.get("evidence")
            if isinstance(evidence, Mapping):
                turn["evidence"] = _finalize_evidence(evidence)
            turns.append(turn)

        model_calls = len(self.model_request_keys) or len(self.model_reply_keys)
        cost = max(self.model_cost, self.reported_total_cost or 0.0)
        if not self.saw_cost and self.reported_total_cost is None:
            cost_status = "unknown"
        elif self.cost_known:
            cost_status = "exact"
        else:
            cost_status = "lower_bound"
        traffic = self.traffic or _empty_traffic()
        return {
            "schema_version": CAPSULE_SCHEMA_VERSION,
            "metadata": {
                "partition": self.partition,
                "candidate_visible": self.partition == DEVELOPMENT,
            },
            "case_id": self.case_context,
            "run_id": self.run_context,
            "turns": turns,
            "aggregate": {
                "turn_count": len(turns),
                "selection_count": self.selection_count,
                "attempt_count": self.attempt_count,
                "evidence_observation_count": self.evidence_count,
                "confirmed_finding_count": len(self.confirmed_finding_keys),
                "model_call_count": model_calls,
                "cost_usd": round(cost, 12),
                "cost_accounting": cost_status,
                "ignored_event_count": self.ignored_events,
                "termination": self.termination,
                "traffic": traffic,
            },
        }

    def _consume_selection(self, payload: Mapping[str, object]) -> None:
        turn_number = _required_turn(payload)
        turn = self._turn(turn_number)
        proposed = _as_mapping(payload.get("proposed_action"))
        selected = _as_mapping(payload.get("selected_action"))
        turn["selection"] = _project_selection(
            proposed,
            selected,
            proposed_route=payload.get("proposed_route"),
            selected_route=payload.get("selected_route"),
            changed=_safe_bool(payload.get("selected_differs_from_model")),
            reason=payload.get("selection_reason"),
            key=self.key,
            case_context=self.case_context,
        )
        self.selection_count += 1
        self._remember_action_turn(payload, turn_number)

    def _consume_attempt(self, payload: Mapping[str, object]) -> None:
        turn_number = _required_turn(payload)
        turn = self._turn(turn_number)
        proposed = _as_mapping(payload.get("proposed_action"))
        selected = _as_mapping(payload.get("selected_action"))
        if "selection" not in turn:
            turn["selection"] = _project_selection(
                proposed,
                selected,
                proposed_route=payload.get("proposed_route"),
                selected_route=payload.get("selected_route"),
                changed=_safe_bool(payload.get("selected_differs_from_model")),
                reason=payload.get("selection_reason"),
                key=self.key,
                case_context=self.case_context,
            )
            self.selection_count += 1
        turn["attempt"] = _project_attempt(
            payload,
            key=self.key,
            case_context=self.case_context,
        )
        self.attempt_count += 1
        self._remember_action_turn(payload, turn_number)

    def _consume_turn_trace(self, payload: Mapping[str, object]) -> None:
        turn_number = _required_turn(payload)
        turn = self._turn(turn_number)
        proposed = _as_mapping(payload.get("proposed_action"))
        selected = _as_mapping(payload.get("selected_action"))
        if "selection" not in turn:
            turn["selection"] = _project_selection(
                proposed,
                selected,
                proposed_route=None,
                selected_route=None,
                changed=_safe_bool(payload.get("selected_differs_from_model")),
                reason=None,
                key=self.key,
                case_context=self.case_context,
            )
            self.selection_count += 1
        trace_attempt = _project_turn_trace_attempt(
            payload,
            key=self.key,
            case_context=self.case_context,
        )
        current = turn.get("attempt")
        if not isinstance(current, Mapping):
            turn["attempt"] = trace_attempt
            self.attempt_count += 1
        else:
            _merge_trace_outcome(current, trace_attempt)
        self._remember_action_turn(payload, turn_number)

    def _consume_evidence(self, payload: Mapping[str, object]) -> None:
        evidence_key = self._event_identity(payload.get("evidence_id"), "evidence")
        stage = _classify_evidence_stage(payload.get("stage"))
        dedupe_key = f"{evidence_key}:{stage}"
        if dedupe_key in self.evidence_keys:
            return
        self.evidence_keys.add(dedupe_key)
        self.evidence_count += 1

        turn_number = _optional_turn(payload)
        if turn_number is None:
            action_id = _bounded_identity_text(payload.get("action_id"))
            if action_id:
                turn_number = self.action_turns.get(action_id)
        if turn_number is None:
            return
        turn = self._turn(turn_number)
        evidence = _turn_evidence(turn)
        evidence["observations"] = _safe_count(evidence.get("observations")) + 1
        _counter_increment(evidence, "stage_counts", stage)
        _counter_increment(
            evidence,
            "contract_counts",
            _classify_contract_status(payload.get("contract_status")),
        )
        _counter_increment(evidence, "family_counts", _classify_family_from_payload(payload))
        if payload.get("confirmed_finding") is True:
            evidence["confirmed"] = _safe_count(evidence.get("confirmed")) + 1
            self._remember_confirmed_finding(payload)

        route_value = payload.get("endpoint") or payload.get("endpoint_url")
        route_id = self._opaque_route(route_value)
        if route_id:
            _append_unique(evidence, "route_ids", route_id)
        input_id = self._opaque_input(payload.get("input"))
        if input_id:
            _append_unique(evidence, "input_ids", input_id)

    def _consume_confirmed_finding(self, payload: Mapping[str, object]) -> None:
        is_new = self._remember_confirmed_finding(payload)
        if not is_new:
            return
        turn_number = _optional_turn(payload)
        if turn_number is None:
            action_id = _bounded_identity_text(payload.get("action_id"))
            if action_id:
                turn_number = self.action_turns.get(action_id)
        if turn_number is not None:
            evidence = _turn_evidence(self._turn(turn_number))
            evidence["confirmed"] = _safe_count(evidence.get("confirmed")) + 1

    def _consume_model_request(self, payload: Mapping[str, object]) -> None:
        request_key = self._event_identity(payload.get("model_request_id"), "model_request")
        self.model_request_keys.add(request_key)

    def _consume_model_reply(self, payload: Mapping[str, object]) -> None:
        request_key = self._event_identity(payload.get("model_request_id"), "model_reply")
        if request_key in self.model_reply_keys:
            return
        self.model_reply_keys.add(request_key)
        cost = _safe_cost(payload.get("cost_usd"))
        known = payload.get("cost_known")
        if cost is not None:
            self.model_cost += cost
            self.saw_cost = True
        elif known is not True:
            self.cost_known = False
        if known is False:
            self.cost_known = False

    def _consume_traffic(self, payload: Mapping[str, object]) -> None:
        snapshot = _as_mapping(payload.get("snapshot"))
        self.traffic = _project_traffic(snapshot)

    def _consume_terminal(self, kind: str, payload: Mapping[str, object]) -> None:
        status = _TERMINAL_KIND_STATUS[kind]
        if kind == "run_completed":
            status = _classify_termination(payload.get("status"), default=status)
        self.termination = status
        cost = _safe_cost(payload.get("cost_usd"))
        if cost is not None:
            self.reported_total_cost = max(self.reported_total_cost or 0.0, cost)
            self.saw_cost = True
        snapshot = _as_mapping(payload.get("traffic_policy_snapshot"))
        if snapshot:
            self.traffic = _project_traffic(snapshot)

    def _turn(self, number: int) -> dict[str, JSONValue]:
        return self.turns.setdefault(number, {"turn": number})

    def _remember_action_turn(self, payload: Mapping[str, object], turn: int) -> None:
        action_id = _bounded_identity_text(payload.get("action_id"))
        if action_id:
            self.action_turns[action_id] = turn

    def _event_identity(self, value: object, namespace: str) -> str:
        text = _bounded_identity_text(value) or f"sequence:{self.sequence}"
        return _opaque_identifier(self.key, namespace, self.run_context, text)

    def _remember_confirmed_finding(self, payload: Mapping[str, object]) -> bool:
        key = self._event_identity(payload.get("finding_id"), "finding")
        previous = len(self.confirmed_finding_keys)
        self.confirmed_finding_keys.add(key)
        return len(self.confirmed_finding_keys) != previous

    def _opaque_route(self, value: object) -> str | None:
        text = _canonical_identity(value)
        if not text:
            return None
        return _opaque_identifier(self.key, "route", self.case_context, text)

    def _opaque_input(self, value: object) -> str | None:
        text = _canonical_identity(value)
        if not text:
            return None
        return _opaque_identifier(self.key, "input", self.case_context, text)


def _project_selection(
    proposed: Mapping[str, object],
    selected: Mapping[str, object],
    *,
    proposed_route: object,
    selected_route: object,
    changed: bool | None,
    reason: object,
    key: bytes,
    case_context: str,
) -> dict[str, JSONValue]:
    proposed_projection = _project_action(
        proposed,
        explicit_route=proposed_route,
        key=key,
        case_context=case_context,
    )
    selected_projection = _project_action(
        selected,
        explicit_route=selected_route,
        key=key,
        case_context=case_context,
    )
    if changed is None:
        changed = proposed_projection != selected_projection
    return {
        "proposed": proposed_projection,
        "selected": selected_projection,
        "changed": changed,
        "reason": _classify_selection_reason(reason),
    }


def _project_action(
    action: Mapping[str, object],
    *,
    explicit_route: object,
    key: bytes,
    case_context: str,
) -> dict[str, JSONValue]:
    route_value = (
        explicit_route
        if _canonical_identity(explicit_route)
        else _find_identity_value(
            action,
            {"route", "endpoint", "endpoint_url", "url", "path", "target_path"},
        )
    )
    route_text = _canonical_identity(route_value)
    route_id = _opaque_identifier(key, "route", case_context, route_text) if route_text else None
    raw_inputs = _find_identity_values(
        action,
        {"input", "input_name", "parameter", "parameter_name", "param", "field", "field_name"},
    )
    input_ids = sorted(
        {
            _opaque_identifier(key, "input", case_context, raw)
            for value in raw_inputs
            if (raw := _canonical_identity(value))
        }
    )
    descriptor_values = _descriptor_values(action)
    return {
        "category": _classify_action(descriptor_values),
        "family": _classify_family(descriptor_values),
        "method": _classify_method(action),
        "route_id": route_id,
        "input_ids": input_ids,
        "has_parameters": bool(_as_mapping(action.get("params")) or raw_inputs),
    }


def _project_attempt(
    payload: Mapping[str, object],
    *,
    key: bytes,
    case_context: str,
) -> dict[str, JSONValue]:
    outcome = _as_mapping(payload.get("outcome"))
    before_raw = _bounded_identity_text(payload.get("evidence_epoch_before"))
    after_raw = _bounded_identity_text(payload.get("evidence_epoch_after"))
    before = _opaque_epoch(key, case_context, before_raw)
    after = _opaque_epoch(key, case_context, after_raw)
    return {
        "status": _classify_attempt_status(payload.get("status")),
        "novel": _safe_bool(payload.get("novel")),
        "evidence_epoch_before": before,
        "evidence_epoch_after": after,
        "evidence_advanced": bool(before and after and before != after),
        "outcome": _project_outcome(outcome),
        "state_delta": _project_state_delta(_as_mapping(payload.get("state_delta"))),
    }


def _project_turn_trace_attempt(
    payload: Mapping[str, object],
    *,
    key: bytes,
    case_context: str,
) -> dict[str, JSONValue]:
    pre_state = _project_state(_as_mapping(payload.get("pre_state")))
    post_state = _project_state(_as_mapping(payload.get("post_state")))
    before = _opaque_epoch(key, case_context, _canonical_identity(pre_state))
    after = _opaque_epoch(key, case_context, _canonical_identity(post_state))
    outcome = _as_mapping(payload.get("outcome"))
    projected_outcome = _project_outcome(outcome)
    novel = _delta_has_progress(_as_mapping(payload.get("state_delta")))
    return {
        "status": "completed"
        if projected_outcome["stop"] is True
        else ("progressed" if novel else "attempted"),
        "novel": novel,
        "evidence_epoch_before": before,
        "evidence_epoch_after": after,
        "evidence_advanced": before != after,
        "outcome": projected_outcome,
        "state_delta": _project_state_delta(_as_mapping(payload.get("state_delta"))),
    }


def _project_outcome(outcome: Mapping[str, object]) -> dict[str, JSONValue]:
    exit_code = _safe_signed_count(outcome.get("exit_code"))
    process_status = "unknown"
    if exit_code is not None:
        process_status = "success" if exit_code == 0 else "failure"
    timed_out = _safe_bool(outcome.get("timed_out"))
    classification = _classify_outcome(outcome.get("classification") or outcome.get("outcome"))
    if timed_out is True:
        classification = "timeout"
    return {
        "ok": _safe_bool(outcome.get("ok")),
        "stop": _safe_bool(outcome.get("stop")),
        "timed_out": timed_out,
        "process_status": process_status,
        "classification": classification,
        "repeat_count": _safe_count(outcome.get("repeat_count")),
    }


def _project_state_delta(delta: Mapping[str, object]) -> dict[str, JSONValue]:
    new_capabilities = sorted(
        {_classify_capability(item) for item in _as_sequence(delta.get("new_primitives"))}
    )
    return {
        "phase_changed": _safe_bool(delta.get("phase_changed")),
        "phase_before": _classify_phase(delta.get("phase_before")),
        "phase_after": _classify_phase(delta.get("phase_after")),
        "facts_delta": _safe_signed_count(delta.get("facts_delta")) or 0,
        "hypotheses_delta": _safe_signed_count(delta.get("hypotheses_delta")) or 0,
        "actions_delta": _safe_signed_count(delta.get("actions_delta")) or 0,
        "attempts_delta": _safe_signed_count(delta.get("attempts_delta")) or 0,
        "new_capabilities": new_capabilities,
        "signal_deltas": _project_categorical_deltas(
            _as_mapping(delta.get("signal_count_delta")),
            _classify_signal,
        ),
        "task_deltas": _project_categorical_deltas(
            _as_mapping(delta.get("task_status_delta")),
            _classify_task,
        ),
    }


def _project_state(state: Mapping[str, object]) -> dict[str, JSONValue]:
    """Project only data needed to derive a v1-compatible structural epoch."""
    new_capabilities = sorted(
        {_classify_capability(item) for item in _as_sequence(state.get("primitives"))}
    )
    return {
        "phase_before": _classify_phase(state.get("phase")),
        "facts_delta": _safe_count(state.get("facts_count")),
        "hypotheses_delta": _safe_count(state.get("hypotheses_count")),
        "actions_delta": _safe_count(state.get("actions_count")),
        "attempts_delta": _safe_count(state.get("attempts_count")),
        "new_capabilities": new_capabilities,
        "signal_deltas": _project_categorical_deltas(
            _as_mapping(state.get("signal_counts")),
            _classify_signal,
        ),
        "task_deltas": _project_categorical_deltas(
            _as_mapping(state.get("task_status_counts")),
            _classify_task,
        ),
    }


def _project_categorical_deltas(
    values: Mapping[str, object],
    classifier: Callable[[object], str],
) -> list[JSONValue]:
    counter: Counter[str] = Counter()
    for raw_category, raw_delta in values.items():
        delta = _safe_signed_count(raw_delta)
        if delta is None or delta == 0:
            continue
        category = classifier(raw_category)
        counter[category] += delta
    return [
        {"category": category, "delta": counter[category]}
        for category in sorted(counter)
        if counter[category]
    ]


def _project_traffic(snapshot: Mapping[str, object]) -> dict[str, JSONValue]:
    projected: dict[str, JSONValue] = {
        field: _safe_count(snapshot.get(field)) for field in _TRAFFIC_COUNT_FIELDS
    }
    projected["accounting_status"] = _classify_accounting(snapshot.get("accounting_status"))
    return projected


def _empty_traffic() -> dict[str, JSONValue]:
    return {
        **dict.fromkeys(_TRAFFIC_COUNT_FIELDS, 0),
        "accounting_status": "unknown",
    }


def _turn_evidence(turn: dict[str, JSONValue]) -> dict[str, JSONValue]:
    existing = turn.get("evidence")
    if isinstance(existing, dict):
        return existing
    value: dict[str, JSONValue] = {
        "observations": 0,
        "confirmed": 0,
        "stage_counts": {},
        "contract_counts": {},
        "family_counts": {},
        "route_ids": [],
        "input_ids": [],
    }
    turn["evidence"] = value
    return value


def _counter_increment(container: dict[str, JSONValue], key: str, category: str) -> None:
    value = container.get(key)
    if not isinstance(value, dict):
        value = {}
        container[key] = value
    value[category] = _safe_count(value.get(category)) + 1


def _append_unique(container: dict[str, JSONValue], key: str, value: str) -> None:
    values = container.get(key)
    if not isinstance(values, list):
        values = []
        container[key] = values
    if value not in values:
        values.append(value)


def _finalize_evidence(evidence: Mapping[str, object]) -> dict[str, JSONValue]:
    def counts(name: str) -> list[JSONValue]:
        raw = _as_mapping(evidence.get(name))
        return [
            {"category": category, "count": _safe_count(raw[category])} for category in sorted(raw)
        ]

    route_ids = sorted(str(item) for item in _as_sequence(evidence.get("route_ids")))
    input_ids = sorted(str(item) for item in _as_sequence(evidence.get("input_ids")))
    return {
        "observations": _safe_count(evidence.get("observations")),
        "confirmed": _safe_count(evidence.get("confirmed")),
        "stage_counts": counts("stage_counts"),
        "contract_counts": counts("contract_counts"),
        "family_counts": counts("family_counts"),
        "route_ids": route_ids,
        "input_ids": input_ids,
    }


def _merge_trace_outcome(current: Mapping[str, object], trace: Mapping[str, object]) -> None:
    if not isinstance(current, dict):
        return
    current_outcome = current.get("outcome")
    trace_outcome = trace.get("outcome")
    if not isinstance(current_outcome, dict) or not isinstance(trace_outcome, Mapping):
        return
    for key in ("timed_out", "process_status"):
        value = current_outcome.get(key)
        if value is None or value == "unknown":
            replacement = trace_outcome.get(key)
            if replacement is None or isinstance(replacement, (bool, int, float, str, list, dict)):
                current_outcome[key] = replacement


def _required_turn(payload: Mapping[str, object]) -> int:
    turn = _optional_turn(payload)
    if turn is None:
        raise CorpusFormatError("trajectory event is missing a valid turn")
    return turn


def _optional_turn(payload: Mapping[str, object]) -> int | None:
    turn = _coerce_int(payload.get("turn"))
    if turn is None:
        return None
    return turn if 0 <= turn <= _MAX_TURN else None


def _safe_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _safe_count(value: object) -> int:
    number = _coerce_int(value)
    if number is None:
        return 0
    return min(max(number, 0), _MAX_COUNT)


def _safe_signed_count(value: object) -> int | None:
    number = _coerce_int(value)
    if number is None:
        return None
    return min(max(number, -_MAX_COUNT), _MAX_COUNT)


def _safe_cost(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number) or not 0 <= number <= _MAX_COST_USD:
        return None
    return number


def _coerce_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if not isinstance(value, (int, float, str)):
        return None
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _validated_hmac_key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) < _MIN_HMAC_KEY_BYTES:
        raise ValueError("hmac_key must be at least 32 bytes")
    return value


def _validated_partition(value: str | CorpusSplit) -> str:
    if isinstance(value, CorpusSplit):
        value = value.value
    if value not in _PARTITIONS:
        raise ValueError("partition must be development or sealed_holdout")
    return value


def _atomic_write_text(destination: Path, text: str) -> Path:
    parent = destination.parent
    if not parent.is_dir():
        raise CorpusFormatError("capsule destination directory does not exist")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise CorpusFormatError("capsule destination metadata is unreadable") from None
    else:
        raise CorpusFormatError("refusing to overwrite an existing capsule destination")
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary_name, destination, follow_symlinks=False)
        except FileExistsError:
            raise CorpusFormatError(
                "refusing to overwrite an existing capsule destination"
            ) from None
        Path(temporary_name).unlink()
        temporary_name = ""
        _fsync_directory(parent)
    except CorpusError:
        raise
    except OSError:
        raise CorpusFormatError("capsule destination could not be written") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            with suppress(OSError):
                Path(temporary_name).unlink(missing_ok=True)
    return destination


def _validated_events_metadata(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError:
        raise CorpusFormatError("events stream metadata is unreadable") from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise CorpusFormatError("events stream must be a regular single-link file")
    if metadata.st_size > _MAX_FILE_BYTES:
        raise CorpusFormatError("events stream exceeds the ingestion byte limit")
    return metadata


def _open_validated_events(path: Path) -> tuple[BinaryIO, os.stat_result]:
    before = _validated_events_metadata(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise CorpusFormatError("events stream could not be opened safely") from None
    try:
        opened = os.fstat(descriptor)
        _ensure_opened_events_match(before, opened)
        return os.fdopen(descriptor, "rb"), opened
    except Exception:
        os.close(descriptor)
        raise


def _ensure_opened_events_match(
    before: os.stat_result,
    opened: os.stat_result,
) -> None:
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or opened.st_size > _MAX_FILE_BYTES
    ):
        raise CorpusFormatError("events stream changed before it could be opened")


def _file_version(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validated_source_identity(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_IDENTITY_CHARS:
        raise ValueError(f"{label}_identifier must be a non-empty bounded string")
    return value


def _opaque_identifier(key: bytes, namespace: str, *parts: str) -> str:
    material = b"ravage-improvement-corpus-v1\x00" + namespace.encode("ascii")
    for part in parts:
        try:
            encoded = part.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise CorpusFormatError("identity material is not valid Unicode") from None
        material += b"\x00" + len(encoded).to_bytes(4, "big") + encoded
    digest = hmac.new(key, material, hashlib.sha256).hexdigest()[:_HMAC_HEX_CHARS]
    public_namespace = (
        namespace if namespace in {"case", "run", "route", "input", "epoch"} else "run"
    )
    return f"{public_namespace}_{digest}"


def _opaque_epoch(key: bytes, case_context: str, value: str | None) -> str | None:
    if not value:
        return None
    return _opaque_identifier(key, "epoch", case_context, value)


def _bounded_identity_text(value: object) -> str | None:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    text = str(value)
    if not text or len(text) > _MAX_IDENTITY_CHARS:
        return None
    return text


def _canonical_identity(value: object) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (str, int, float)):
        text = str(value)
        return text if text and len(text) <= _MAX_IDENTITY_CHARS else None
    if isinstance(value, (Mapping, list, tuple)):
        try:
            text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError, RecursionError):
            return None
        return text if len(text) <= _MAX_IDENTITY_CHARS else None
    return None


def _as_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items() if isinstance(key, str)}


def _as_sequence(value: object) -> Sequence[object]:
    if isinstance(value, (list, tuple)):
        return value
    return ()


def _descriptor_values(action: Mapping[str, object]) -> tuple[str, ...]:
    values: list[str] = []
    descriptor_keys = (
        "action",
        "kind",
        "type",
        "strategy",
        "probe",
        "family",
        "vuln_class",
        "finding_type",
    )
    for key in descriptor_keys:
        value = action.get(key)
        if isinstance(value, str) and len(value) <= _MAX_DESCRIPTOR_CHARS:
            values.append(value)
    params = _as_mapping(action.get("params"))
    for key in ("probe", "family", "vuln_class", "finding_type"):
        value = params.get(key)
        if isinstance(value, str) and len(value) <= _MAX_DESCRIPTOR_CHARS:
            values.append(value)
    return tuple(values)


def _find_identity_value(action: Mapping[str, object], keys: set[str]) -> object:
    values = _find_identity_values(action, keys)
    return values[0] if values else None


def _find_identity_values(action: Mapping[str, object], keys: set[str]) -> list[object]:
    values: list[object] = []
    denied_containers = {
        "body",
        "payload",
        "data",
        "headers",
        "cookies",
        "auth",
        "content",
        "output",
        "response",
        "command",
        "script",
    }

    def walk(value: Mapping[str, object], depth: int) -> None:
        if depth > _MAX_IDENTITY_DEPTH:
            return
        for raw_key, item in value.items():
            key = str(raw_key).casefold()
            if key in denied_containers:
                continue
            if key in keys and _canonical_identity(item):
                values.append(item)
                continue
            if isinstance(item, Mapping) and key in {
                "params",
                "route",
                "request_template",
                "probe",
            }:
                walk(_as_mapping(item), depth + 1)

    walk(action, 0)
    return values[:32]


def _joined_descriptors(values: Iterable[object]) -> str:
    return " ".join(str(value).strip().casefold() for value in values if isinstance(value, str))


def _classify_action(values: Iterable[object]) -> str:
    text = _joined_descriptors(values)
    if not text:
        return "unknown"
    rules = (
        ("report", ("final", "finish", "report", "summar")),
        ("wait", ("wait", "pause", "backoff")),
        ("browser", ("browser", "navigate", "dom", "playwright")),
        ("recon", ("recon", "discover", "crawl", "surface", "enumerat", "fingerprint")),
        ("validate", ("validate", "verify", "confirm", "poc")),
        ("exploit", ("exploit", "extract", "execute", "bypass", "read_file")),
        ("probe", ("probe", "scan", "test", "request", "http")),
    )
    return _first_category(text, rules, default="other")


def _classify_family(values: Iterable[object]) -> str:
    text = _joined_descriptors(values)
    if not text:
        return "unknown"
    rules = (
        ("sqli", ("sqli", "sql_injection", "sql injection")),
        ("xss", ("xss", "cross_site_scripting", "dom_execution")),
        ("idor", ("idor", "object_reference", "bola")),
        ("ssrf", ("ssrf", "server_side_request")),
        ("file_read", ("file_read", "traversal", "lfi", "path traversal")),
        ("command_injection", ("command_injection", "rce", "shell_injection")),
        ("authentication", ("authentication", "login", "session", "credential")),
        ("authorization", ("authorization", "access_control", "privilege")),
        ("graphql", ("graphql",)),
        ("jwt", ("jwt", "json_web")),
        ("upload", ("upload",)),
        ("redirect", ("open_redirect", "redirect")),
        ("deserialization", ("deserial",)),
        ("xxe", ("xxe", "xml_external")),
        ("template_injection", ("ssti", "template_injection")),
    )
    return _first_category(text, rules, default="other")


def _classify_family_from_payload(payload: Mapping[str, object]) -> str:
    return _classify_family(
        payload.get(key) for key in ("vuln_class", "finding_type", "probe", "evidence_kind")
    )


def _classify_method(action: Mapping[str, object]) -> str:
    method = action.get("method")
    if not isinstance(method, str):
        method = _as_mapping(action.get("params")).get("method")
    if not isinstance(method, str):
        return "unknown"
    normalized = method.strip().upper()
    return normalized if normalized in _METHODS else "unknown"


def _classify_selection_reason(value: object) -> str:
    text = _joined_descriptors((value,))
    if not text:
        return "unknown"
    rules = (
        ("model", ("model_proposal", "model")),
        ("recovery", ("recovery", "objective_action")),
        ("repeat_guard", ("repeat", "loop")),
        ("safety_guard", ("safety", "scope", "policy", "guard")),
        ("progress_router", ("progress", "primitive", "closer", "shadow")),
        ("harness", ("harness", "override")),
    )
    return _first_category(text, rules, default="other")


def _classify_attempt_status(value: object) -> str:
    text = _joined_descriptors((value,))
    if text in _ATTEMPT_STATUSES:
        return text
    if "block" in text:
        return "blocked"
    if "fail" in text or "error" in text:
        return "failed"
    if "progress" in text or "novel" in text:
        return "progressed"
    if "complete" in text or "stop" in text:
        return "completed"
    if "low" in text or "repeat" in text:
        return "low_value"
    return "unknown" if not text else "other"


def _classify_outcome(value: object) -> str:
    text = _joined_descriptors((value,))
    if not text:
        return "unknown"
    rules = (
        ("finding_gain", ("finding_confirmed", "verified_vulnerability")),
        ("evidence_gain", ("confirmed_signal", "evidence", "signal_gain")),
        ("surface_gain", ("new_surface", "surface_gain")),
        ("objective_signal", ("flag_candidate", "objective", "goal_signal")),
        ("blocked", ("blocked", "denied", "circuit_open")),
        ("repeated", ("same_as_before", "repeat", "duplicate", "no_progress")),
        ("timeout", ("timeout", "timed_out")),
        ("failed", ("fail", "error", "exception")),
        ("neutral", ("observed", "ok", "neutral", "completed")),
    )
    return _first_category(text, rules, default="other")


def _classify_phase(value: object) -> str:
    text = _joined_descriptors((value,))
    if not text:
        return "unknown"
    rules = (
        ("completed", ("complete", "done", "finished")),
        ("reporting", ("report", "final", "summary")),
        ("validation", ("valid", "verify", "confirm")),
        ("attack", ("attack", "exploit", "probe")),
        ("recon", ("recon", "discover", "surface")),
    )
    return _first_category(text, rules, default="other")


def _classify_evidence_stage(value: object) -> str:
    text = _joined_descriptors((value,))
    if not text or text == "none":
        return "none" if text == "none" else "unknown"
    rules = (
        ("objective_complete", ("flag_captured", "objective_complete", "goal_complete")),
        ("exploit_primitive", ("exploit_primitive", "primitive")),
        ("verified", ("verified", "confirmed")),
        ("suspected", ("suspected", "candidate")),
        ("rejected", ("reject", "false_positive", "invalid")),
    )
    return _first_category(text, rules, default="unknown")


def _classify_contract_status(value: object) -> str:
    text = _joined_descriptors((value,))
    if not text:
        return "unknown"
    rules = (
        ("confirmed", ("confirm",)),
        ("verified", ("verif", "pass")),
        ("suspected", ("suspect", "candidate")),
        ("rejected", ("reject", "invalid", "fail")),
        ("incomplete", ("incomplete", "missing", "partial")),
    )
    return _first_category(text, rules, default="other")


def _classify_capability(value: object) -> str:
    text = _joined_descriptors((value,))
    rules = (
        ("code_execution", ("code_exec", "command_exec", "rce", "shell")),
        ("browser_execution", ("browser", "dom", "script_exec")),
        ("file_access", ("file", "traversal", "lfi")),
        ("network_access", ("ssrf", "network", "callback")),
        ("authentication", ("authn", "login", "session")),
        ("authorization", ("authz", "authorization", "access_control")),
        ("injection", ("inject", "sqli", "xss", "ssti")),
        ("data_access", ("data", "record", "extract")),
        ("surface", ("surface", "endpoint", "route")),
    )
    return _first_category(text, rules, default="other")


def _classify_signal(value: object) -> str:
    text = _joined_descriptors((value,))
    rules = (
        ("code_execution", ("code_exec", "command_exec", "rce", "shell")),
        ("browser_execution", ("browser", "dom", "script")),
        ("file_access", ("file", "traversal", "lfi")),
        ("authentication", ("login", "session", "authn")),
        ("authorization", ("authorization", "authz", "access_control")),
        ("injection", ("inject", "sqli", "xss", "ssti")),
        ("reflection", ("reflect",)),
        ("differential", ("differ", "delta")),
        ("error", ("error", "exception", "stack")),
        ("data_access", ("data", "record", "extract")),
        ("surface", ("surface", "endpoint", "route")),
    )
    return _first_category(text, rules, default="other")


def _classify_task(value: object) -> str:
    text = _joined_descriptors((value,))
    if text in _TASK_CATEGORIES:
        return text
    if "progress" in text or "running" in text:
        return "active"
    if "complete" in text or "done" in text:
        return "completed"
    if "fail" in text or "error" in text:
        return "failed"
    if "block" in text:
        return "blocked"
    if "skip" in text:
        return "skipped"
    if "pend" in text or "todo" in text:
        return "pending"
    return "other"


def _classify_accounting(value: object) -> str:
    text = _joined_descriptors((value,))
    return text if text in _ACCOUNTING_STATUSES else "unknown"


def _classify_termination(value: object, *, default: str = "unknown") -> str:
    text = _joined_descriptors((value,))
    if text in _TERMINATION_STATUSES:
        return text
    if "success" in text or "complete" in text or "pass" in text:
        return "completed"
    if "cancel" in text or "interrupt" in text:
        return "cancelled"
    if "fail" in text or "error" in text:
        return "failed"
    return default


def _first_category(
    text: str,
    rules: Iterable[tuple[str, tuple[str, ...]]],
    *,
    default: str,
) -> str:
    for category, needles in rules:
        if any(needle in text for needle in needles):
            return category
    return default


def _delta_has_progress(delta: Mapping[str, object]) -> bool:
    for key in ("facts_delta", "hypotheses_delta", "actions_delta", "attempts_delta"):
        if (_safe_signed_count(delta.get(key)) or 0) > 0:
            return True
    if _as_sequence(delta.get("new_primitives")):
        return True
    return any(
        (_safe_signed_count(value) or 0) > 0
        for value in _as_mapping(delta.get("signal_count_delta")).values()
    )


def _validate_capsule_shape(capsule: Mapping[str, object]) -> None:
    expected = {"schema_version", "metadata", "case_id", "run_id", "turns", "aggregate"}
    if set(capsule) != expected or capsule.get("schema_version") != CAPSULE_SCHEMA_VERSION:
        raise CorpusFormatError("capsule has an unsupported top-level shape")
    metadata = capsule.get("metadata")
    if not isinstance(metadata, Mapping) or set(metadata) != {"partition", "candidate_visible"}:
        raise CorpusFormatError("capsule metadata is malformed")
    partition = metadata.get("partition")
    if partition not in _PARTITIONS:
        raise CorpusFormatError("capsule partition is invalid")
    if metadata.get("candidate_visible") is not (partition == DEVELOPMENT):
        raise CorpusFormatError("capsule visibility disagrees with its partition")
    for key, namespace in (("case_id", "case"), ("run_id", "run")):
        value = capsule.get(key)
        if (
            not isinstance(value, str)
            or not value.startswith(f"{namespace}_")
            or not _OPAQUE_ID_RE.fullmatch(value)
        ):
            raise CorpusFormatError("capsule identity is not opaque")
    turns = capsule.get("turns")
    aggregate = capsule.get("aggregate")
    if not isinstance(turns, list) or not isinstance(aggregate, Mapping):
        raise CorpusFormatError("capsule trajectory or aggregate is malformed")


def _taint_variants(taints: Iterable[str | bytes]) -> frozenset[str]:
    variants: set[str] = set()
    for taint in taints:
        if isinstance(taint, bytes):
            raw_bytes = taint
            try:
                text = taint.decode("utf-8")
            except UnicodeDecodeError:
                text = ""
        elif isinstance(taint, str):
            text = taint
            raw_bytes = taint.encode("utf-8")
        else:
            raise TypeError("taints must contain only str or bytes values")
        if not raw_bytes:
            continue
        normalized = unicodedata.normalize("NFKC", text) if text else ""
        percent_encoded = quote(text, safe="") if text else ""
        plus_encoded = quote_plus(text, safe="") if text else ""
        standard_b64 = base64.b64encode(raw_bytes).decode("ascii")
        urlsafe_b64 = base64.urlsafe_b64encode(raw_bytes).decode("ascii")
        candidates = {
            text,
            normalized,
            percent_encoded,
            quote(percent_encoded, safe="") if percent_encoded else "",
            plus_encoded,
            quote_plus(plus_encoded, safe="") if plus_encoded else "",
            raw_bytes.hex(),
            standard_b64,
            base64.b64encode(standard_b64.encode("ascii")).decode("ascii"),
            urlsafe_b64,
            urlsafe_b64.rstrip("="),
            base64.urlsafe_b64encode(urlsafe_b64.encode("ascii")).decode("ascii"),
        }
        variants.update(candidate.casefold() for candidate in candidates if candidate)
    return frozenset(variants)


def _unsafe_key_reason(key: str, taints: frozenset[str]) -> str | None:
    folded = unicodedata.normalize("NFKC", key).casefold()
    if any(taint in folded for taint in taints):
        return "tainted_key"
    if key not in _SAFE_KEYS:
        return "unapproved_key"
    if _SENSITIVE_KEY_RE.search(key) and key not in _TRAFFIC_COUNT_FIELDS:
        return "sensitive_key"
    return None


def _unsafe_string_reason(value: str, taints: frozenset[str]) -> str | None:
    folded = unicodedata.normalize("NFKC", value).casefold()
    if any(taint in folded for taint in taints):
        return "tainted_value"
    if value in _SAFE_LITERAL_VALUES or _OPAQUE_ID_RE.fullmatch(value):
        return None
    if _PROOF_LIKE_RE.search(value):
        return "proof_like_value"
    if _AUTH_RE.search(value) or _ASSIGNMENT_RE.search(value) or _JWT_RE.search(value):
        return "credential_like_value"
    if _URL_RE.search(value) or _IP_OR_HOST_RE.search(value):
        return "network_location"
    if _ABSOLUTE_PATH_RE.search(value) or "/" in value or "\\" in value:
        return "literal_path"
    return "unapproved_string"


def _strict_json_loads(raw_line: bytes) -> object:
    def reject_constant(_value: str) -> object:
        raise ValueError

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    return json.loads(
        raw_line,
        parse_constant=reject_constant,
        object_pairs_hook=unique_object,
    )


__all__ = [
    "CAPSULE_SCHEMA_VERSION",
    "CORPUS_SCHEMA_VERSION",
    "DEVELOPMENT",
    "SEALED_HOLDOUT",
    "CorpusError",
    "CorpusFormatError",
    "CorpusLeakError",
    "CorpusSplit",
    "HoldoutAccessError",
    "LeakFinding",
    "assert_secret_safe",
    "build_trajectory_capsule",
    "candidate_visible_export",
    "find_leaks",
    "ingest_events",
    "ingest_events_jsonl",
    "ingest_run_dir",
    "scan_for_leaks",
    "serialize_candidate_corpus",
    "serialize_capsule",
    "write_candidate_corpus",
    "write_capsule",
]
