"""Structured Python source candidates derived from a frozen repository snapshot."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.source_analysis import (
    SOURCE_ANALYZER_CONTRACT,
    SourceAnalysisError,
    SourceFileSnapshot,
    analyze_source_snapshots,
)

if TYPE_CHECKING:
    from ravage.repository_context import RepositoryContext

SOURCE_CANDIDATE_INDEX_SCHEMA = "ravage.repository-source-candidates.v1"


@dataclass(frozen=True, slots=True)
class RepositorySourceCandidate:
    """One source-to-sink hypothesis bound to captured repository bytes."""

    candidate_id: str
    family: str
    method: str
    route: str
    input_name: str
    input_location: str
    framework: str
    route_binding: str
    path: str
    line: int
    sink_kind: str
    reason: str
    file_digest: str
    snapshot_id: str

    def to_json(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "status": "hypothesis",
            "family": self.family,
            "method": self.method,
            "route": self.route,
            "input_name": self.input_name,
            "input_location": self.input_location,
            "framework": self.framework,
            "route_binding": self.route_binding,
            "path": self.path,
            "line": self.line,
            "sink_kind": self.sink_kind,
            "reason": self.reason,
            "file_digest": self.file_digest,
            "snapshot_id": self.snapshot_id,
        }


@dataclass(frozen=True, slots=True)
class RepositorySourceCandidateIndex:
    """Bounded candidate index and analysis coverage for one repository snapshot."""

    snapshot_id: str
    index_digest: str
    analysis_available: bool
    analysis_error_digest: str | None
    analyzer_contract: str
    source_digest: str
    analyzer_candidate_digest: str
    python_files_analyzed: int
    parse_failures: int
    routes_discovered: int
    route_patterns_skipped: int
    flow_patterns_skipped: int
    candidates: tuple[RepositorySourceCandidate, ...]


def build_repository_source_candidate_index(
    context: RepositoryContext,
) -> RepositorySourceCandidateIndex:
    """Analyze captured Python text without reopening any repository path."""
    captured_python = tuple(source for source in context.files if source.path.endswith(".py"))
    try:
        analysis = analyze_source_snapshots(
            tuple(
                SourceFileSnapshot(
                    relative_file=source.path,
                    data=source.text.encode("utf-8"),
                )
                for source in captured_python
            )
        )
    except SourceAnalysisError as exc:
        return _unavailable_index(
            context,
            error=exc,
        )
    digest_by_path = {source.path: source.digest for source in captured_python}
    candidates = tuple(
        RepositorySourceCandidate(
            candidate_id=candidate.candidate_id,
            family=candidate.family,
            method=candidate.method,
            route=candidate.route,
            input_name=candidate.input_name,
            input_location=candidate.input_location,
            framework=candidate.framework,
            route_binding=candidate.route_binding,
            path=candidate.relative_file,
            line=candidate.line,
            sink_kind=candidate.sink_kind,
            reason=candidate.reason,
            file_digest=digest_by_path[candidate.relative_file],
            snapshot_id=context.snapshot_id,
        )
        for candidate in analysis.candidates
    )
    identity = json.dumps(
        {
            "schema": SOURCE_CANDIDATE_INDEX_SCHEMA,
            "snapshot_id": context.snapshot_id,
            "analyzer_contract": SOURCE_ANALYZER_CONTRACT,
            "candidates": [candidate.to_json() for candidate in candidates],
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return RepositorySourceCandidateIndex(
        snapshot_id=context.snapshot_id,
        index_digest="sha256:" + hashlib.sha256(identity).hexdigest(),
        analysis_available=True,
        analysis_error_digest=None,
        analyzer_contract=SOURCE_ANALYZER_CONTRACT,
        source_digest=analysis.source_digest,
        analyzer_candidate_digest=analysis.candidate_digest,
        python_files_analyzed=analysis.files_scanned,
        parse_failures=analysis.parse_failures,
        routes_discovered=analysis.routes_discovered,
        route_patterns_skipped=analysis.route_patterns_skipped,
        flow_patterns_skipped=analysis.flow_patterns_skipped,
        candidates=candidates,
    )


def disabled_repository_source_candidate_index(
    context: RepositoryContext,
) -> RepositorySourceCandidateIndex:
    """Return explicit disabled telemetry without analyzing captured source."""
    identity = json.dumps(
        {
            "schema": SOURCE_CANDIDATE_INDEX_SCHEMA,
            "snapshot_id": context.snapshot_id,
            "analyzer_contract": SOURCE_ANALYZER_CONTRACT,
            "analysis_status": "disabled",
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return RepositorySourceCandidateIndex(
        snapshot_id=context.snapshot_id,
        index_digest="sha256:" + hashlib.sha256(identity).hexdigest(),
        analysis_available=False,
        analysis_error_digest=None,
        analyzer_contract=SOURCE_ANALYZER_CONTRACT,
        source_digest="",
        analyzer_candidate_digest="",
        python_files_analyzed=0,
        parse_failures=0,
        routes_discovered=0,
        route_patterns_skipped=0,
        flow_patterns_skipped=0,
        candidates=(),
    )


def _unavailable_index(
    context: RepositoryContext,
    *,
    error: SourceAnalysisError,
) -> RepositorySourceCandidateIndex:
    error_digest = (
        "sha256:" + hashlib.sha256(f"{type(error).__name__}:{error}".encode()).hexdigest()
    )
    identity = json.dumps(
        {
            "schema": SOURCE_CANDIDATE_INDEX_SCHEMA,
            "snapshot_id": context.snapshot_id,
            "analyzer_contract": SOURCE_ANALYZER_CONTRACT,
            "analysis_available": False,
            "analysis_error_digest": error_digest,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return RepositorySourceCandidateIndex(
        snapshot_id=context.snapshot_id,
        index_digest="sha256:" + hashlib.sha256(identity).hexdigest(),
        analysis_available=False,
        analysis_error_digest=error_digest,
        analyzer_contract=SOURCE_ANALYZER_CONTRACT,
        source_digest="",
        analyzer_candidate_digest="",
        python_files_analyzed=0,
        parse_failures=0,
        routes_discovered=0,
        route_patterns_skipped=0,
        flow_patterns_skipped=0,
        candidates=(),
    )


__all__ = [
    "SOURCE_CANDIDATE_INDEX_SCHEMA",
    "RepositorySourceCandidate",
    "RepositorySourceCandidateIndex",
    "build_repository_source_candidate_index",
    "disabled_repository_source_candidate_index",
]
