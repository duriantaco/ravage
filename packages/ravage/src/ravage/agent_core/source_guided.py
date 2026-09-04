# ruff: noqa: EM101, TRY003
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid4

from ravage.agent_core.agent_state import AgentState, append_unique
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.agent_core.surface_graph_ingest import (
    ingest_source_code_candidates,
    project_surface_graph,
)
from ravage.source_analysis import (
    SOURCE_ANALYZER_CONTRACT,
    SOURCE_MAP_SCHEMA,
    SourceChangedError,
    analyze_source_root,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.run_data.workspace import AgentWorkspace

SOURCE_MAP_ARTIFACT = "source-map.json"
MAX_PROMPT_SOURCE_CANDIDATES = 64
MAX_GRAPH_SOURCE_CANDIDATES = 512
MAX_SOURCE_VALIDATION_CANDIDATES = 8
_MAX_SOURCE_QUERY_FIELDS = 32
_MAX_SOURCE_ROUTE_CHARS = 1_024
_SHA256_PREFIX = "sha256:"
_SHA256_DIGEST_LENGTH = len(_SHA256_PREFIX) + 64
_SOURCE_INPUT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:\[\]-]{0,127}$")
_SOURCE_CANDIDATE_ID_RE = re.compile(r"^src-[0-9a-f]{24}$")
_SOURCE_QUERY_VALUE_KINDS = frozenset({"boolean", "integer", "number", "string", "uuid"})
_SOURCE_LIVE_VALIDATION_VALUES = frozenset({"automatic_get_query", "hint_only"})

_SOURCE_MAP_KEYS = frozenset(
    {
        "schema",
        "analyzer_contract",
        "source_digest",
        "candidate_digest",
        "counts",
        "candidates",
    }
)
_SOURCE_COUNT_KEYS = frozenset(
    {
        "files_scanned",
        "bytes_scanned",
        "files_parsed",
        "parse_failures",
        "routes_discovered",
        "route_patterns_skipped",
        "flow_patterns_skipped",
        "candidates_found",
        "symlinks_skipped",
        "directories_scanned",
        "directory_entries_scanned",
        "excluded_directories",
    }
)
_SOURCE_CANDIDATE_KEYS = frozenset(
    {
        "candidate_id",
        "family",
        "method",
        "route",
        "input_name",
        "input_location",
        "framework",
        "route_binding",
        "relative_file",
        "line",
        "sink_kind",
        "reason",
        "live_validation",
        "query_fields",
        "status",
    }
)
_GRAPH_CANDIDATE_KEYS = (
    "candidate_id",
    "family",
    "method",
    "route",
    "input_name",
    "input_location",
    "relative_file",
    "line",
    "sink_kind",
)


@dataclass(frozen=True, slots=True)
class SourceGuidedPreparation:
    analyzer_contract: str
    source_digest: str
    candidate_digest: str
    files_scanned: int
    parse_failures: int
    symlinks_skipped: int
    directories_scanned: int
    directory_entries_scanned: int
    excluded_directories: int
    analysis_complete: bool
    routes_discovered: int
    route_patterns_skipped: int
    flow_patterns_skipped: int
    candidates_found: int
    candidates_ingested: int
    candidate_payloads: tuple[dict[str, object], ...]
    validation_actions: tuple[dict[str, object], ...]
    artifact_path: Path

    def event_payload(self, *, workspace: AgentWorkspace) -> dict[str, object]:
        try:
            artifact = str(self.artifact_path.relative_to(workspace.root))
        except ValueError:
            artifact = self.artifact_path.name
        return {
            "schema": SOURCE_MAP_SCHEMA,
            "analyzer_contract": self.analyzer_contract,
            "source_digest": self.source_digest,
            "candidate_digest": self.candidate_digest,
            "files_scanned": self.files_scanned,
            "parse_failures": self.parse_failures,
            "symlinks_skipped": self.symlinks_skipped,
            "directories_scanned": self.directories_scanned,
            "directory_entries_scanned": self.directory_entries_scanned,
            "excluded_directories": self.excluded_directories,
            "analysis_complete": self.analysis_complete,
            "routes_discovered": self.routes_discovered,
            "route_patterns_skipped": self.route_patterns_skipped,
            "flow_patterns_skipped": self.flow_patterns_skipped,
            "candidates_found": self.candidates_found,
            "candidates_ingested": self.candidates_ingested,
            "validation_probes": [
                str(action.get("probe") or "") for action in self.validation_actions
            ],
            "artifact": artifact,
        }


def prepare_source_guided_analysis(
    *,
    source_root: Path,
    target_url: str,
    state: AgentState,
    workspace: AgentWorkspace,
    resumed: bool,
) -> SourceGuidedPreparation:
    """Analyze local source without exposing its contents or treating it as proof."""
    source_map = analyze_source_root(source_root)
    payload = source_map.to_json()
    candidates, counts, digest, analyzer_contract, candidate_digest = _validated_source_map(payload)
    _assert_resume_binding(
        state,
        source_digest=digest,
        analyzer_contract=analyzer_contract,
        candidate_digest=candidate_digest,
        resumed=resumed,
    )

    artifact_path = workspace.artifacts_dir / SOURCE_MAP_ARTIFACT
    _write_private_json(artifact_path, payload)

    if not state.surface_graph.target_origin:
        state.surface_graph = SurfaceGraphState.for_target(target_url)
    graph_candidates = [
        {key: candidate[key] for key in _GRAPH_CANDIDATE_KEYS if key in candidate}
        for candidate in candidates
        if candidate.get("route_binding") in {"direct", "mounted"}
    ][:MAX_GRAPH_SOURCE_CANDIDATES]
    ingested = ingest_source_code_candidates(
        state.surface_graph,
        graph_candidates,
        target_url=target_url,
    )
    state.surface = project_surface_graph(state.surface_graph, state.surface)
    state.surface.setdefault("target_url", target_url)
    state.surface.setdefault("origin", state.surface_graph.target_origin)

    actions = _validation_actions(candidates)
    validation_ids = {
        candidate_id
        for action in actions
        for candidate_id in _string_items(action.get("source_candidate_ids"))
    }
    prompt_candidates = tuple(
        dict(candidate)
        for candidate in _prompt_source_candidates(
            candidates,
            validation_ids=validation_ids,
            limit=MAX_PROMPT_SOURCE_CANDIDATES,
        )
    )
    analysis_complete = (
        not counts["parse_failures"]
        and not counts["symlinks_skipped"]
        and not counts["route_patterns_skipped"]
        and not counts["flow_patterns_skipped"]
    )
    state.surface["source_candidates"] = list(prompt_candidates)
    state.surface["source_analysis"] = {
        "schema": SOURCE_MAP_SCHEMA,
        "analyzer_contract": analyzer_contract,
        "source_digest": digest,
        "candidate_digest": candidate_digest,
        "files_scanned": counts["files_scanned"],
        "files_parsed": counts["files_parsed"],
        "parse_failures": counts["parse_failures"],
        "symlinks_skipped": counts["symlinks_skipped"],
        "directories_scanned": counts["directories_scanned"],
        "directory_entries_scanned": counts["directory_entries_scanned"],
        "excluded_directories": counts["excluded_directories"],
        "analysis_complete": analysis_complete,
        "routes_discovered": counts["routes_discovered"],
        "route_patterns_skipped": counts["route_patterns_skipped"],
        "flow_patterns_skipped": counts["flow_patterns_skipped"],
        "candidates_found": counts["candidates_found"],
        "candidates_ingested": ingested,
        "artifact": f"artifacts/{SOURCE_MAP_ARTIFACT}",
    }
    coverage_note = ""
    if not analysis_complete:
        coverage_note = (
            "; coverage is incomplete because "
            f"{counts['parse_failures']} file(s) could not be parsed and "
            f"{counts['symlinks_skipped']} symlink(s) and "
            f"{counts['route_patterns_skipped']} dynamic or unsupported route "
            "pattern(s), and "
            f"{counts['flow_patterns_skipped']} unsupported direct-flow pattern(s) "
            "were skipped"
        )
    exclusion_note = ""
    if counts["excluded_directories"]:
        exclusion_note = (
            f"; {counts['excluded_directories']} conventional dependency, cache, "
            "build, VCS, hidden, or temporary directories excluded by policy"
        )
    append_unique(
        state.facts,
        (
            "local source analysis mapped "
            f"{counts['routes_discovered']} route(s) and "
            f"{counts['candidates_found']} unverified candidate(s)"
            f"{exclusion_note}{coverage_note}; source hypotheses require live confirmation"
        ),
        limit=80,
    )
    return SourceGuidedPreparation(
        analyzer_contract=analyzer_contract,
        source_digest=digest,
        candidate_digest=candidate_digest,
        files_scanned=counts["files_scanned"],
        parse_failures=counts["parse_failures"],
        symlinks_skipped=counts["symlinks_skipped"],
        directories_scanned=counts["directories_scanned"],
        directory_entries_scanned=counts["directory_entries_scanned"],
        excluded_directories=counts["excluded_directories"],
        analysis_complete=analysis_complete,
        routes_discovered=counts["routes_discovered"],
        route_patterns_skipped=counts["route_patterns_skipped"],
        flow_patterns_skipped=counts["flow_patterns_skipped"],
        candidates_found=counts["candidates_found"],
        candidates_ingested=ingested,
        candidate_payloads=prompt_candidates,
        validation_actions=actions,
        artifact_path=artifact_path,
    )


def _validated_source_map(  # noqa: C901, PLR0912
    value: object,
) -> tuple[list[dict[str, object]], dict[str, int], str, str, str]:
    if not isinstance(value, Mapping):
        raise TypeError("source analyzer returned a non-object source map")
    unexpected = set(value) - _SOURCE_MAP_KEYS
    if unexpected:
        raise ValueError("source map contains unsupported fields")
    if value.get("schema") != SOURCE_MAP_SCHEMA:
        raise ValueError("source analyzer returned an unsupported source-map schema")
    analyzer_contract = str(value.get("analyzer_contract") or "")
    if analyzer_contract != SOURCE_ANALYZER_CONTRACT:
        raise ValueError("source analyzer returned an unsupported analyzer contract")
    digest = str(value.get("source_digest") or "")
    if not _valid_digest(digest):
        raise ValueError("source analyzer returned an invalid source digest")
    candidate_digest = str(value.get("candidate_digest") or "")
    if not _valid_digest(candidate_digest):
        raise ValueError("source analyzer returned an invalid candidate digest")
    raw_counts = value.get("counts")
    if not isinstance(raw_counts, Mapping) or set(raw_counts) != _SOURCE_COUNT_KEYS:
        raise ValueError("source analyzer returned invalid source-map counts")
    counts: dict[str, int] = {}
    for key in _SOURCE_COUNT_KEYS:
        item = raw_counts.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ValueError("source analyzer returned invalid source-map counts")
        counts[key] = item
    raw_candidates = value.get("candidates")
    if not isinstance(raw_candidates, list):
        raise TypeError("source analyzer returned invalid candidates")
    candidates: list[dict[str, object]] = []
    for item in raw_candidates:
        if not isinstance(item, Mapping) or set(item) != _SOURCE_CANDIDATE_KEYS:
            raise ValueError("source analyzer returned an invalid candidate")
        candidate = {str(key): field for key, field in item.items()}
        if candidate.get("status") != "hypothesis":
            raise ValueError("source candidates must remain unverified hypotheses")
        _validate_source_candidate_contract(candidate)
        candidates.append(candidate)
    if counts["candidates_found"] != len(candidates):
        raise ValueError("source-map candidate count does not match its payload")
    if candidate_digest != _candidate_payload_digest(candidates):
        raise ValueError("source-map candidate digest does not match its payload")
    if counts["files_parsed"] + counts["parse_failures"] != counts["files_scanned"]:
        raise ValueError("source-map file counts are inconsistent")
    return candidates, counts, digest, analyzer_contract, candidate_digest


def _validate_source_candidate_contract(candidate: Mapping[str, object]) -> None:
    candidate_id = str(candidate.get("candidate_id") or "")
    method = str(candidate.get("method") or "")
    route = str(candidate.get("route") or "")
    input_name = str(candidate.get("input_name") or "")
    input_location = str(candidate.get("input_location") or "")
    route_binding = str(candidate.get("route_binding") or "")
    live_validation = str(candidate.get("live_validation") or "")
    line = candidate.get("line")
    if (
        not _SOURCE_CANDIDATE_ID_RE.fullmatch(candidate_id)
        or method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
        or not route.startswith("/")
        or len(route) > _MAX_SOURCE_ROUTE_CHARS
        or not _SOURCE_INPUT_RE.fullmatch(input_name)
        or input_location not in {"body", "cookie", "form", "header", "path", "query", "unknown"}
        or route_binding not in {"direct", "mounted", "relative"}
        or live_validation not in _SOURCE_LIVE_VALIDATION_VALUES
        or isinstance(line, bool)
        or not isinstance(line, int)
        or line <= 0
    ):
        raise ValueError("source analyzer returned an invalid candidate contract")
    query_fields = _validated_query_fields(candidate.get("query_fields"))
    if live_validation == "hint_only" and query_fields:
        raise ValueError("hint-only source candidate cannot include a live query shape")
    if live_validation != "automatic_get_query":
        return
    target_field = next(
        (field for field in query_fields if field[0] == input_name),
        None,
    )
    if (
        str(candidate.get("family") or "") != "sql_injection"
        or method != "GET"
        or input_location != "query"
        or route_binding not in {"direct", "mounted"}
        or "{" in route
        or "}" in route
        or target_field is None
        or target_field[1] != "string"
    ):
        raise ValueError("source analyzer returned an unsafe live-validation contract")


def _validated_query_fields(value: object) -> tuple[tuple[str, str, bool], ...]:
    if not isinstance(value, list) or len(value) > _MAX_SOURCE_QUERY_FIELDS:
        raise ValueError("source analyzer returned an invalid query shape")
    fields: list[tuple[str, str, bool]] = []
    names: set[str] = set()
    for raw_field in value:
        if not isinstance(raw_field, Mapping) or set(raw_field) != {
            "name",
            "required",
            "value_kind",
        }:
            raise ValueError("source analyzer returned an invalid query field")
        name = str(raw_field.get("name") or "")
        value_kind = str(raw_field.get("value_kind") or "")
        required = raw_field.get("required")
        if (
            not _SOURCE_INPUT_RE.fullmatch(name)
            or name in names
            or value_kind not in _SOURCE_QUERY_VALUE_KINDS
            or not isinstance(required, bool)
        ):
            raise ValueError("source analyzer returned an invalid query field")
        names.add(name)
        fields.append((name, value_kind, required))
    return tuple(fields)


def _assert_resume_binding(
    state: AgentState,
    *,
    source_digest: str,
    analyzer_contract: str,
    candidate_digest: str,
    resumed: bool,
) -> None:
    previous = state.surface.get("source_analysis")
    if not resumed:
        return
    if not isinstance(previous, Mapping):
        raise SourceChangedError(
            "cannot add source analysis while resuming a run that was not source-bound"
        )
    previous_digest = str(previous.get("source_digest") or "")
    if not _valid_digest(previous_digest) or previous_digest != source_digest:
        raise SourceChangedError("source tree changed since the saved run; start a fresh workspace")
    if str(previous.get("analyzer_contract") or "") != analyzer_contract:
        raise SourceChangedError(
            "source analyzer contract changed since the saved run; start a fresh workspace"
        )
    previous_candidates = str(previous.get("candidate_digest") or "")
    if not _valid_digest(previous_candidates) or previous_candidates != candidate_digest:
        raise SourceChangedError(
            "source candidate map changed since the saved run; start a fresh workspace"
        )


def assert_source_resume_available(*, state: AgentState, source_root: Path | None) -> None:
    """Fail closed when a source-bound run is resumed without its source tree."""
    previous = state.surface.get("source_analysis")
    if isinstance(previous, Mapping) and source_root is None:
        raise SourceChangedError(
            "saved run is bound to a source tree; resume with the same --source-root"
        )


def _validation_actions(
    candidates: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    grouped: dict[tuple[str, str, str, str], list[str]] = {}
    for candidate in candidates:
        family = str(candidate.get("family") or "").replace("-", "_")
        method = str(candidate.get("method") or "").upper()
        route = str(candidate.get("route") or "")
        location = str(candidate.get("input_location") or "").lower()
        input_name = str(candidate.get("input_name") or "")
        if (
            family not in {"sql_injection", "sqli"}
            or method != "GET"
            or location != "query"
            or candidate.get("live_validation") != "automatic_get_query"
            or "{" in route
            or "}" in route
        ):
            continue
        query_fields = json.dumps(
            candidate.get("query_fields"),
            separators=(",", ":"),
            sort_keys=True,
        )
        shape = (method, route, input_name, query_fields)
        candidate_id = str(candidate.get("candidate_id") or "")
        if shape not in grouped and len(grouped) >= MAX_SOURCE_VALIDATION_CANDIDATES:
            continue
        identifiers = grouped.setdefault(shape, [])
        if candidate_id and not identifiers:
            identifiers.append(candidate_id)
    return tuple(
        {
            "action": "run_probe",
            "probe": "sqli_differential",
            "notes": (
                "validate one exact source-derived GET query SQL hypothesis against "
                "the live in-scope target with a bounded differential"
            ),
            "expected_signal": "paired live response evidence from the mapped route and input",
            "source_candidate_ids": identifiers,
        }
        for identifiers in grouped.values()
    )


def _prompt_source_candidates(
    candidates: Sequence[Mapping[str, object]],
    *,
    validation_ids: set[str],
    limit: int,
) -> tuple[Mapping[str, object], ...]:
    selected: list[Mapping[str, object]] = []
    selected_ids: set[str] = set()

    def include(candidate: Mapping[str, object]) -> None:
        candidate_id = str(candidate.get("candidate_id") or "")
        if candidate_id and candidate_id not in selected_ids and len(selected) < limit:
            selected.append(candidate)
            selected_ids.add(candidate_id)

    for candidate in candidates:
        if str(candidate.get("candidate_id") or "") in validation_ids:
            include(candidate)
    represented_families = {
        str(candidate.get("family") or "").strip().casefold() for candidate in selected
    }
    for candidate in candidates:
        family = str(candidate.get("family") or "").strip().casefold()
        if family and family not in represented_families:
            include(candidate)
            represented_families.add(family)
    for candidate in candidates:
        include(candidate)
    return tuple(selected)


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if str(item))


def _candidate_payload_digest(candidates: Sequence[Mapping[str, object]]) -> str:
    encoded = json.dumps(
        candidates,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _valid_digest(value: str) -> bool:
    if not value.startswith(_SHA256_PREFIX) or len(value) != _SHA256_DIGEST_LENGTH:
        return False
    return all(char in "0123456789abcdef" for char in value[len(_SHA256_PREFIX) :])


def _write_private_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
        path.chmod(0o600)
    except BaseException:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise


__all__ = [
    "SOURCE_MAP_ARTIFACT",
    "SourceGuidedPreparation",
    "assert_source_resume_available",
    "prepare_source_guided_analysis",
]
