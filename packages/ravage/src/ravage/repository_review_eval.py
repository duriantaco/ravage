"""Ground-truth scoring for diagnostic repository-review evaluations."""

# Validation errors deliberately retain precise schema diagnostics.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from ravage.repository_review import REPOSITORY_REVIEW_SCHEMA

MANIFEST_SCHEMA_VERSION: Final = "ravage.repository-review-eval-manifest.v1"
REVIEW_SCHEMA_VERSION: Final = REPOSITORY_REVIEW_SCHEMA

_MAX_CASES = 1_024
_MAX_EXPECTED_PER_CASE = 100
_MAX_LOCATIONS_PER_EXPECTED = 20
_MAX_FINDINGS = 50
_MAX_EVIDENCE_PER_FINDING = 10
_MAX_ID_CHARS = 128
_MAX_PATH_CHARS = 1_000
_MAX_LINE = 2**31 - 1
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VULN_CLASS_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


class RepositoryReviewEvalInputError(ValueError):
    """An evaluation manifest or repository-review result is malformed."""


@dataclass(frozen=True, order=True)
class EvidenceLocation:
    """An inclusive, repository-relative source interval."""

    path: str
    start_line: int
    end_line: int

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> EvidenceLocation:
        _require_exact_keys(payload, {"path", "start_line", "end_line"}, "evidence location")
        start_line = _line_number(payload.get("start_line"), "evidence start_line")
        end_line = _line_number(payload.get("end_line"), "evidence end_line")
        if end_line < start_line:
            raise RepositoryReviewEvalInputError(
                "evidence end_line must be greater than or equal to start_line"
            )
        return cls(
            path=_relative_path(payload.get("path"), "evidence path"),
            start_line=start_line,
            end_line=end_line,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


@dataclass(frozen=True)
class ExpectedVulnerability:
    """One evaluator-owned weakness and its accepted source locations."""

    vulnerability_id: str
    vuln_class: str
    locations: tuple[EvidenceLocation, ...]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> ExpectedVulnerability:
        _require_exact_keys(payload, {"id", "vuln_class", "locations"}, "expected vulnerability")
        raw_locations = payload.get("locations")
        if not isinstance(raw_locations, list) or not raw_locations:
            raise RepositoryReviewEvalInputError(
                "expected vulnerability locations must be a nonempty JSON list"
            )
        if len(raw_locations) > _MAX_LOCATIONS_PER_EXPECTED:
            raise RepositoryReviewEvalInputError(
                "expected vulnerability exceeds the location limit"
            )
        locations = tuple(
            EvidenceLocation.from_mapping(_mapping(item, "evidence location"))
            for item in raw_locations
        )
        if len(locations) != len(set(locations)):
            raise RepositoryReviewEvalInputError(
                "expected vulnerability contains duplicate evidence locations"
            )
        return cls(
            vulnerability_id=_opaque_id(payload.get("id"), "vulnerability id"),
            vuln_class=_vuln_class(payload.get("vuln_class")),
            locations=locations,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.vulnerability_id,
            "vuln_class": self.vuln_class,
            "locations": [location.to_json() for location in self.locations],
        }


@dataclass(frozen=True)
class RepositoryReviewEvalCase:
    """One source fixture and expected findings for explicitly evaluated classes."""

    case_id: str
    source_root: str
    evaluated_classes: tuple[str, ...]
    expected: tuple[ExpectedVulnerability, ...]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> RepositoryReviewEvalCase:
        _require_exact_keys(
            payload,
            {"id", "source_root", "evaluated_classes", "expected"},
            "evaluation case",
        )
        raw_evaluated_classes = payload.get("evaluated_classes")
        if not isinstance(raw_evaluated_classes, list) or not raw_evaluated_classes:
            raise RepositoryReviewEvalInputError(
                "case evaluated_classes must be a nonempty JSON list"
            )
        evaluated_classes = tuple(_vuln_class(item) for item in raw_evaluated_classes)
        if len(evaluated_classes) != len(set(evaluated_classes)):
            raise RepositoryReviewEvalInputError("case evaluated_classes must be unique")
        raw_expected = payload.get("expected")
        if not isinstance(raw_expected, list):
            raise RepositoryReviewEvalInputError("case expected must be a JSON list")
        if len(raw_expected) > _MAX_EXPECTED_PER_CASE:
            raise RepositoryReviewEvalInputError("case exceeds the expected-vulnerability limit")
        expected = tuple(
            ExpectedVulnerability.from_mapping(_mapping(item, "expected vulnerability"))
            for item in raw_expected
        )
        identities = [item.vulnerability_id for item in expected]
        if len(identities) != len(set(identities)):
            raise RepositoryReviewEvalInputError(
                "expected vulnerability IDs must be unique within a case"
            )
        if any(item.vuln_class not in evaluated_classes for item in expected):
            raise RepositoryReviewEvalInputError(
                "every expected vuln_class must appear in case evaluated_classes"
            )
        return cls(
            case_id=_opaque_id(payload.get("id"), "case id"),
            source_root=_relative_path(payload.get("source_root"), "case source_root"),
            evaluated_classes=evaluated_classes,
            expected=expected,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.case_id,
            "source_root": self.source_root,
            "evaluated_classes": list(self.evaluated_classes),
            "expected": [item.to_json() for item in self.expected],
        }


@dataclass(frozen=True)
class RepositoryReviewEvalManifest:
    """Strict evaluator-owned repository-review case manifest."""

    cases: tuple[RepositoryReviewEvalCase, ...]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> RepositoryReviewEvalManifest:
        _require_exact_keys(payload, {"schema_version", "cases"}, "evaluation manifest")
        if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
            raise RepositoryReviewEvalInputError("evaluation manifest schema_version is invalid")
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise RepositoryReviewEvalInputError("evaluation manifest cases must be nonempty")
        if len(raw_cases) > _MAX_CASES:
            raise RepositoryReviewEvalInputError("evaluation manifest exceeds the case limit")
        cases = tuple(
            RepositoryReviewEvalCase.from_mapping(_mapping(item, "evaluation case"))
            for item in raw_cases
        )
        case_ids = [case.case_id for case in cases]
        if len(case_ids) != len(set(case_ids)):
            raise RepositoryReviewEvalInputError("evaluation case IDs must be unique")
        return cls(cases=cases)

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "cases": [case.to_json() for case in self.cases],
        }


@dataclass(frozen=True)
class EvaluationMetrics:
    """Detection counts with deterministic zero-denominator conventions."""

    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def expected(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def reported(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def precision(self) -> float:
        return self.true_positives / self.reported if self.reported else 1.0

    @property
    def recall(self) -> float:
        return self.true_positives / self.expected if self.expected else 1.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    def to_json(self) -> dict[str, object]:
        return {
            "expected": self.expected,
            "reported": self.reported,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 8),
            "recall": round(self.recall, 8),
            "f1": round(self.f1, 8),
        }


@dataclass(frozen=True)
class VulnerabilityClassScore:
    """Metrics for one canonical vulnerability class."""

    vuln_class: str
    metrics: EvaluationMetrics

    def to_json(self) -> dict[str, object]:
        return {"vuln_class": self.vuln_class, **self.metrics.to_json()}


@dataclass(frozen=True)
class FindingMatch:
    """A one-to-one match and the exact intersecting source interval."""

    expected_id: str
    finding_index: int
    vuln_class: str
    overlap: EvidenceLocation

    def to_json(self) -> dict[str, object]:
        return {
            "expected_id": self.expected_id,
            "finding_index": self.finding_index,
            "vuln_class": self.vuln_class,
            "overlap": self.overlap.to_json(),
        }


@dataclass(frozen=True)
class RepositoryReviewCaseScore:
    """Ground-truth score for one repository-review result."""

    case_id: str
    metrics: EvaluationMetrics
    matches: tuple[FindingMatch, ...]
    unmatched_expected_ids: tuple[str, ...]
    unmatched_finding_indexes: tuple[int, ...]
    unscored_finding_indexes: tuple[int, ...]
    by_vuln_class: tuple[VulnerabilityClassScore, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            **self.metrics.to_json(),
            "matches": [match.to_json() for match in self.matches],
            "unmatched_expected_ids": list(self.unmatched_expected_ids),
            "unmatched_finding_indexes": list(self.unmatched_finding_indexes),
            "unscored_finding_indexes": list(self.unscored_finding_indexes),
            "by_vuln_class": [score.to_json() for score in self.by_vuln_class],
        }


@dataclass(frozen=True)
class RepositoryReviewAggregateScore:
    """Micro-aggregated metrics over independently scored review runs."""

    case_count: int
    metrics: EvaluationMetrics
    by_vuln_class: tuple[VulnerabilityClassScore, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "case_count": self.case_count,
            **self.metrics.to_json(),
            "by_vuln_class": [score.to_json() for score in self.by_vuln_class],
        }


@dataclass(frozen=True)
class _ObservedFinding:
    vuln_class: str
    evidence: tuple[EvidenceLocation, ...]


def score_repository_review(
    case: RepositoryReviewEvalCase,
    review: Mapping[str, object],
) -> RepositoryReviewCaseScore:
    """Score a public repository-review result for a case's evaluated classes."""
    findings = _parse_review_findings(review)
    evaluated_classes = frozenset(case.evaluated_classes)
    evaluated_finding_indexes = tuple(
        index for index, finding in enumerate(findings) if finding.vuln_class in evaluated_classes
    )
    adjacency = [
        tuple(
            expected_index
            for expected_index, expected in enumerate(case.expected)
            if _best_overlap(finding, expected) is not None
        )
        for finding in findings
    ]
    expected_to_finding: list[int | None] = [None] * len(case.expected)

    def assign(finding_index: int, visited: set[int]) -> bool:
        for expected_index in adjacency[finding_index]:
            if expected_index in visited:
                continue
            visited.add(expected_index)
            owner = expected_to_finding[expected_index]
            if owner is None or assign(owner, visited):
                expected_to_finding[expected_index] = finding_index
                return True
        return False

    for candidate_index in evaluated_finding_indexes:
        assign(candidate_index, set())

    matched_finding_indexes = {
        matched_index for matched_index in expected_to_finding if matched_index is not None
    }
    matches: list[FindingMatch] = []
    for expected_index, matched_index in enumerate(expected_to_finding):
        if matched_index is None:
            continue
        expected = case.expected[expected_index]
        overlap = _best_overlap(findings[matched_index], expected)
        assert overlap is not None
        matches.append(
            FindingMatch(
                expected_id=expected.vulnerability_id,
                finding_index=matched_index,
                vuln_class=expected.vuln_class,
                overlap=overlap,
            )
        )

    metrics = EvaluationMetrics(
        true_positives=len(matches),
        false_positives=len(evaluated_finding_indexes) - len(matches),
        false_negatives=len(case.expected) - len(matches),
    )
    unmatched_expected_ids = tuple(
        expected.vulnerability_id
        for index, expected in enumerate(case.expected)
        if expected_to_finding[index] is None
    )
    unmatched_finding_indexes = tuple(
        index for index in evaluated_finding_indexes if index not in matched_finding_indexes
    )
    unscored_finding_indexes = tuple(
        index for index in range(len(findings)) if index not in evaluated_finding_indexes
    )
    return RepositoryReviewCaseScore(
        case_id=case.case_id,
        metrics=metrics,
        matches=tuple(matches),
        unmatched_expected_ids=unmatched_expected_ids,
        unmatched_finding_indexes=unmatched_finding_indexes,
        unscored_finding_indexes=unscored_finding_indexes,
        by_vuln_class=_class_scores(
            case.evaluated_classes,
            case.expected,
            findings,
            matches,
        ),
    )


def aggregate_repository_review_scores(
    scores: Sequence[RepositoryReviewCaseScore],
) -> RepositoryReviewAggregateScore:
    """Micro-aggregate case or repeated-run scores without hiding controls."""
    if not scores:
        raise RepositoryReviewEvalInputError("at least one case score is required")
    totals = EvaluationMetrics(
        true_positives=sum(score.metrics.true_positives for score in scores),
        false_positives=sum(score.metrics.false_positives for score in scores),
        false_negatives=sum(score.metrics.false_negatives for score in scores),
    )
    class_counts: dict[str, Counter[str]] = {}
    for score in scores:
        for item in score.by_vuln_class:
            counts = class_counts.setdefault(item.vuln_class, Counter())
            counts["tp"] += item.metrics.true_positives
            counts["fp"] += item.metrics.false_positives
            counts["fn"] += item.metrics.false_negatives
    return RepositoryReviewAggregateScore(
        case_count=len(scores),
        metrics=totals,
        by_vuln_class=tuple(
            VulnerabilityClassScore(
                vuln_class=vuln_class,
                metrics=EvaluationMetrics(
                    true_positives=counts["tp"],
                    false_positives=counts["fp"],
                    false_negatives=counts["fn"],
                ),
            )
            for vuln_class, counts in sorted(class_counts.items())
        ),
    )


def _parse_review_findings(review: Mapping[str, object]) -> tuple[_ObservedFinding, ...]:
    if review.get("schema") != REVIEW_SCHEMA_VERSION:
        raise RepositoryReviewEvalInputError("repository-review result schema is invalid")
    raw_findings = review.get("findings")
    if not isinstance(raw_findings, list):
        raise RepositoryReviewEvalInputError("repository-review findings must be a JSON list")
    if len(raw_findings) > _MAX_FINDINGS:
        raise RepositoryReviewEvalInputError("repository-review result exceeds the finding limit")
    return tuple(
        _parse_review_finding(_mapping(item, "repository-review finding")) for item in raw_findings
    )


def _parse_review_finding(payload: Mapping[str, object]) -> _ObservedFinding:
    vuln_class = _vuln_class(payload.get("vuln_class"))
    raw_evidence = payload.get("evidence")
    if not isinstance(raw_evidence, list) or not raw_evidence:
        raise RepositoryReviewEvalInputError(
            "repository-review finding evidence must be a nonempty JSON list"
        )
    if len(raw_evidence) > _MAX_EVIDENCE_PER_FINDING:
        raise RepositoryReviewEvalInputError("repository-review finding exceeds the evidence limit")
    evidence = tuple(
        _review_evidence_location(_mapping(item, "repository-review evidence"))
        for item in raw_evidence
    )
    return _ObservedFinding(vuln_class=vuln_class, evidence=evidence)


def _review_evidence_location(payload: Mapping[str, object]) -> EvidenceLocation:
    start_line = _line_number(payload.get("start_line"), "review evidence start_line")
    end_line = _line_number(payload.get("end_line"), "review evidence end_line")
    if end_line < start_line:
        raise RepositoryReviewEvalInputError(
            "review evidence end_line must be greater than or equal to start_line"
        )
    return EvidenceLocation(
        path=_relative_path(payload.get("path"), "review evidence path"),
        start_line=start_line,
        end_line=end_line,
    )


def _best_overlap(
    finding: _ObservedFinding,
    expected: ExpectedVulnerability,
) -> EvidenceLocation | None:
    if finding.vuln_class != expected.vuln_class:
        return None
    overlaps: list[EvidenceLocation] = []
    for observed in finding.evidence:
        for accepted in expected.locations:
            if observed.path != accepted.path:
                continue
            start_line = max(observed.start_line, accepted.start_line)
            end_line = min(observed.end_line, accepted.end_line)
            if start_line <= end_line:
                overlaps.append(EvidenceLocation(observed.path, start_line, end_line))
    if not overlaps:
        return None
    return min(
        overlaps,
        key=lambda item: (-(item.end_line - item.start_line + 1), item.path, item.start_line),
    )


def _class_scores(
    evaluated_classes: Sequence[str],
    expected: Sequence[ExpectedVulnerability],
    findings: Sequence[_ObservedFinding],
    matches: Sequence[FindingMatch],
) -> tuple[VulnerabilityClassScore, ...]:
    expected_counts = Counter(item.vuln_class for item in expected)
    finding_counts = Counter(item.vuln_class for item in findings)
    matched_counts = Counter(item.vuln_class for item in matches)
    return tuple(
        VulnerabilityClassScore(
            vuln_class=vuln_class,
            metrics=EvaluationMetrics(
                true_positives=matched_counts[vuln_class],
                false_positives=finding_counts[vuln_class] - matched_counts[vuln_class],
                false_negatives=expected_counts[vuln_class] - matched_counts[vuln_class],
            ),
        )
        for vuln_class in sorted(evaluated_classes)
    )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise RepositoryReviewEvalInputError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(
    payload: Mapping[str, object],
    expected: set[str],
    label: str,
) -> None:
    if set(payload) != expected:
        raise RepositoryReviewEvalInputError(f"{label} fields do not match the canonical schema")


def _opaque_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_ID_CHARS
        or _OPAQUE_ID_RE.fullmatch(value) is None
    ):
        raise RepositoryReviewEvalInputError(f"{label} must be a canonical opaque identifier")
    return value


def _vuln_class(value: object) -> str:
    if not isinstance(value, str) or _VULN_CLASS_RE.fullmatch(value) is None:
        raise RepositoryReviewEvalInputError(
            "vuln_class must be a canonical lowercase snake_case identifier"
        )
    return value


def _relative_path(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_PATH_CHARS
        or "\x00" in value
        or "\\" in value
    ):
        raise RepositoryReviewEvalInputError(f"{label} must be a bounded relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RepositoryReviewEvalInputError(f"{label} must be a bounded relative POSIX path")
    return value


def _line_number(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_LINE:
        raise RepositoryReviewEvalInputError(f"{label} must be a positive bounded integer")
    return value


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "REVIEW_SCHEMA_VERSION",
    "EvaluationMetrics",
    "EvidenceLocation",
    "ExpectedVulnerability",
    "FindingMatch",
    "RepositoryReviewAggregateScore",
    "RepositoryReviewCaseScore",
    "RepositoryReviewEvalCase",
    "RepositoryReviewEvalInputError",
    "RepositoryReviewEvalManifest",
    "VulnerabilityClassScore",
    "aggregate_repository_review_scores",
    "score_repository_review",
]
