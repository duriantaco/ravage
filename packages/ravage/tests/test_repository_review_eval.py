"""Ground-truth scoring regressions for repository review."""

# Small fixed count assertions are clearer than named constants in these cases.
# ruff: noqa: PLR2004

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from ravage.model_core.providers import ResolvedModelRoute
from ravage.repository_context import RepositoryContext, capture_repository
from ravage.repository_review import (
    RepositoryReviewResult,
    ReviewEvidence,
    ReviewMessage,
    ReviewReply,
    run_repository_review,
)
from ravage.repository_review_eval import (
    MANIFEST_SCHEMA_VERSION,
    REVIEW_SCHEMA_VERSION,
    RepositoryReviewEvalCase,
    RepositoryReviewEvalInputError,
    RepositoryReviewEvalManifest,
    aggregate_repository_review_scores,
    score_repository_review,
    score_repository_review_result,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


_TEST_SNAPSHOT_ID = "sha256:" + "a" * 64


def _expected(
    vulnerability_id: str,
    vuln_class: str,
    *,
    path: str = "src/handler.py",
    start_line: int = 5,
    end_line: int = 8,
) -> dict[str, object]:
    return {
        "id": vulnerability_id,
        "vuln_class": vuln_class,
        "locations": [
            {
                "path": path,
                "start_line": start_line,
                "end_line": end_line,
            }
        ],
    }


def _case(
    case_id: str,
    expected: list[dict[str, object]],
    *,
    evaluated_classes: list[str] | None = None,
    snapshot_id: str = _TEST_SNAPSHOT_ID,
) -> dict[str, object]:
    selected_classes = (
        evaluated_classes or sorted({str(item["vuln_class"]) for item in expected}) or ["idor"]
    )
    return {
        "id": case_id,
        "source_root": f"eval/repository_review/{case_id}",
        "snapshot_id": snapshot_id,
        "evaluated_classes": selected_classes,
        "expected": expected,
    }


def _manifest(*cases: dict[str, object]) -> dict[str, object]:
    return {"schema_version": MANIFEST_SCHEMA_VERSION, "cases": list(cases)}


def _finding(
    vuln_class: str,
    *,
    path: str = "src/handler.py",
    start_line: int = 5,
    end_line: int = 8,
) -> dict[str, object]:
    return {
        "vuln_class": vuln_class,
        "title": "Candidate finding",
        "severity": "high",
        "confidence": "high",
        "description": "Source-backed candidate.",
        "recommendation": "Apply the relevant defensive check.",
        "verification": "source_review_candidate",
        "evidence": [
            {
                "evidence_id": "excerpt-1",
                "path": path,
                "start_line": start_line,
                "end_line": end_line,
                "text_digest": "sha256:" + "1" * 64,
                "file_digest": "sha256:" + "2" * 64,
                "snapshot_id": "sha256:" + "3" * 64,
            }
        ],
    }


def _review(*findings: dict[str, object]) -> dict[str, object]:
    return {
        "schema": REVIEW_SCHEMA_VERSION,
        "mode": "read_only_repository_review",
        "findings": list(findings),
    }


def _route() -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="low",
        selected_tier="low",
        ordinal=1,
        provider="ollama",
        model="scripted-eval-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key_env=None,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=256,
        output_token_limit_parameter="max_tokens",  # noqa: S106 - API parameter name.
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=5.0,
        max_retries=0,
    )


class _TrustedReviewClient:
    def __init__(self) -> None:
        self._replies = [
            {
                "action": "excerpt",
                "args": {"path": "src/handler.py", "start_line": 4, "end_line": 8},
            },
            {
                "action": "final",
                "args": {
                    "summary": "Review complete.",
                    "findings": [
                        {
                            "vuln_class": "idor",
                            "title": "Object lookup is not scoped",
                            "severity": "high",
                            "confidence": "high",
                            "description": "The lookup uses only a request object identifier.",
                            "recommendation": "Constrain the lookup to the authenticated account.",
                            "evidence_ids": ["excerpt-1"],
                        }
                    ],
                },
            },
        ]

    def complete(
        self,
        *,
        messages: Sequence[ReviewMessage],
        route: ResolvedModelRoute,
    ) -> ReviewReply:
        del messages, route
        return ReviewReply(content=json.dumps(self._replies.pop(0)))


def _trusted_review(
    tmp_path: Path,
) -> tuple[RepositoryReviewEvalCase, RepositoryReviewResult, RepositoryContext]:
    source = tmp_path / "src" / "handler.py"
    source.parent.mkdir()
    source.write_text(
        """from datastore import records


def get_record(request):
    record_id = request.path_params["record_id"]
    record = records.find_by_id(record_id)
    if record is None:
        return None
    return record
""",
        encoding="utf-8",
    )
    context = capture_repository(tmp_path)
    case = RepositoryReviewEvalManifest.from_mapping(
        _manifest(
            _case(
                "trusted-review",
                [_expected("record-owner", "idor", start_line=6, end_line=6)],
                snapshot_id=context.snapshot_id,
            )
        )
    ).cases[0]
    result = run_repository_review(
        source_root=tmp_path,
        route=_route(),
        client=_TrustedReviewClient(),
        max_turns=2,
        source_candidates_enabled=False,
    )
    return case, result, context


def _replace_first_evidence(
    result: RepositoryReviewResult,
    evidence: ReviewEvidence,
) -> RepositoryReviewResult:
    finding = replace(result.findings[0], evidence=(evidence,))
    return replace(result, findings=(finding,))


def test_manifest_parses_strict_ground_truth_and_clean_controls() -> None:
    payload = _manifest(
        _case("idor-vulnerable", [_expected("invoice-owner", "idor")]),
        _case("idor-control", []),
    )

    manifest = RepositoryReviewEvalManifest.from_mapping(payload)

    assert manifest.to_json() == payload
    assert manifest.cases[0].snapshot_id == _TEST_SNAPSHOT_ID
    assert manifest.cases[0].expected[0].locations[0].path == "src/handler.py"
    assert manifest.cases[1].expected == ()


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (
            lambda payload: payload.update({"unknown": True}),
            "fields do not match",
        ),
        (
            lambda payload: payload.update({"schema_version": "future-schema"}),
            "schema_version is invalid",
        ),
        (
            lambda payload: payload["cases"][0].update({"source_root": "../escape"}),
            "relative POSIX path",
        ),
        (
            lambda payload: payload["cases"][0].update({"snapshot_id": "sha256:not-a-digest"}),
            "case snapshot_id",
        ),
        (
            lambda payload: payload["cases"][0]["expected"][0].update(
                {"vuln_class": "Command-Injection"}
            ),
            "canonical lowercase snake_case",
        ),
        (
            lambda payload: payload["cases"][0].update(
                {"evaluated_classes": ["command_injection", "command_injection"]}
            ),
            "evaluated_classes must be unique",
        ),
        (
            lambda payload: payload["cases"][0]["expected"][0].update({"vuln_class": "ssrf"}),
            "must appear in case evaluated_classes",
        ),
        (
            lambda payload: payload["cases"][0]["expected"][0]["locations"][0].update(
                {"end_line": 4}
            ),
            "greater than or equal",
        ),
    ],
)
def test_manifest_rejects_ambiguous_or_unsafe_inputs(
    mutate: object,
    error: str,
) -> None:
    payload = _manifest(_case("case-one", [_expected("finding-one", "command_injection")]))
    candidate = deepcopy(payload)
    assert callable(mutate)
    mutate(candidate)

    with pytest.raises(RepositoryReviewEvalInputError, match=error):
        RepositoryReviewEvalManifest.from_mapping(candidate)


def test_manifest_rejects_duplicate_case_and_vulnerability_ids() -> None:
    duplicate_cases = _manifest(_case("same", []), _case("same", []))
    with pytest.raises(RepositoryReviewEvalInputError, match="case IDs must be unique"):
        RepositoryReviewEvalManifest.from_mapping(duplicate_cases)

    duplicate_findings = _manifest(
        _case(
            "one-case",
            [
                _expected("same", "idor"),
                _expected("same", "sql_injection", start_line=20, end_line=21),
            ],
        )
    )
    with pytest.raises(RepositoryReviewEvalInputError, match="vulnerability IDs must be unique"):
        RepositoryReviewEvalManifest.from_mapping(duplicate_findings)


def test_trusted_result_scoring_binds_valid_evidence_to_captured_bytes(tmp_path: Path) -> None:
    case, result, context = _trusted_review(tmp_path)

    score = score_repository_review_result(case, result, context)

    assert score.metrics.true_positives == 1
    assert score.metrics.false_positives == 0
    assert score.metrics.false_negatives == 0


def test_trusted_result_scoring_rejects_mixed_snapshots(tmp_path: Path) -> None:
    case, result, context = _trusted_review(tmp_path)
    other_snapshot = "sha256:" + "f" * 64

    with pytest.raises(RepositoryReviewEvalInputError, match="case snapshot_id"):
        score_repository_review_result(
            replace(case, snapshot_id=other_snapshot),
            result,
            context,
        )
    with pytest.raises(RepositoryReviewEvalInputError, match="result snapshot_id"):
        score_repository_review_result(
            case,
            replace(result, snapshot_id=other_snapshot),
            context,
        )

    original = result.findings[0].evidence[0]
    forged = _replace_first_evidence(
        result,
        replace(original, snapshot_id=other_snapshot),
    )
    with pytest.raises(RepositoryReviewEvalInputError, match="mixed snapshot_id"):
        score_repository_review_result(case, forged, context)


def test_trusted_result_scoring_rejects_forged_evidence_digests(tmp_path: Path) -> None:
    case, result, context = _trusted_review(tmp_path)
    original = result.findings[0].evidence[0]
    forged_file = _replace_first_evidence(
        result,
        replace(original, file_digest="sha256:" + "f" * 64),
    )
    forged_text = _replace_first_evidence(
        result,
        replace(original, text_digest="sha256:" + "f" * 64),
    )

    with pytest.raises(RepositoryReviewEvalInputError, match="file digest"):
        score_repository_review_result(case, forged_file, context)
    with pytest.raises(RepositoryReviewEvalInputError, match="text digest"):
        score_repository_review_result(case, forged_text, context)


def test_trusted_result_scoring_rejects_forged_range_and_text(tmp_path: Path) -> None:
    case, result, context = _trusted_review(tmp_path)
    original = result.findings[0].evidence[0]
    forged_range = _replace_first_evidence(
        result,
        replace(original, end_line=2**31 - 1),
    )
    forged_text = _replace_first_evidence(
        result,
        replace(original, text=original.text + "forged\n"),
    )

    with pytest.raises(RepositoryReviewEvalInputError, match="range"):
        score_repository_review_result(case, forged_range, context)
    with pytest.raises(RepositoryReviewEvalInputError, match="text does not match"):
        score_repository_review_result(case, forged_text, context)


def test_scoring_uses_maximum_one_to_one_class_and_line_overlap() -> None:
    manifest = RepositoryReviewEvalManifest.from_mapping(
        _manifest(
            _case(
                "nearby-findings",
                [
                    _expected("broad-region", "idor", start_line=1, end_line=10),
                    _expected("narrow-region", "idor", start_line=6, end_line=8),
                ],
            )
        )
    )
    # The first finding overlaps both expectations. The second overlaps only the
    # first, so a greedy, non-augmenting matcher would incorrectly score one TP.
    review = _review(
        _finding("idor", start_line=6, end_line=7),
        _finding("idor", start_line=1, end_line=2),
    )

    score = score_repository_review(manifest.cases[0], review)

    assert score.metrics.true_positives == 2
    assert score.metrics.false_positives == 0
    assert score.metrics.false_negatives == 0
    assert {(item.expected_id, item.finding_index) for item in score.matches} == {
        ("broad-region", 1),
        ("narrow-region", 0),
    }
    assert score.unmatched_expected_ids == ()
    assert score.unmatched_finding_indexes == ()


def test_wrong_class_is_unscored_while_wrong_path_and_duplicates_are_false_positives() -> None:
    case = RepositoryReviewEvalManifest.from_mapping(
        _manifest(_case("command-case", [_expected("shell-call", "command_injection")]))
    ).cases[0]
    review = _review(
        _finding("sql_injection"),
        _finding("command_injection", path="src/unrelated.py"),
        _finding("command_injection"),
        _finding("command_injection"),
    )

    score = score_repository_review(case, review)

    assert score.metrics.true_positives == 1
    assert score.metrics.false_positives == 2
    assert score.metrics.false_negatives == 0
    assert score.unmatched_finding_indexes == (1, 3)
    assert score.unscored_finding_indexes == (0,)
    by_class = {item.vuln_class: item.metrics for item in score.by_vuln_class}
    assert by_class["command_injection"].true_positives == 1
    assert by_class["command_injection"].false_positives == 2
    assert "sql_injection" not in by_class


def test_clean_control_scores_any_report_as_a_false_positive() -> None:
    case = RepositoryReviewEvalManifest.from_mapping(_manifest(_case("clean-control", []))).cases[0]

    clean_score = score_repository_review(case, _review())
    noisy_score = score_repository_review(case, _review(_finding("idor")))
    off_class_score = score_repository_review(
        case,
        _review(_finding("command_injection")),
    )

    assert clean_score.metrics.to_json() == {
        "expected": 0,
        "reported": 0,
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
    assert noisy_score.metrics.false_positives == 1
    assert noisy_score.metrics.precision == 0.0
    assert noisy_score.metrics.recall == 1.0
    assert noisy_score.metrics.f1 == 0.0
    assert off_class_score.metrics.false_positives == 0
    assert off_class_score.unscored_finding_indexes == (0,)


def test_aggregate_reports_micro_precision_recall_f1_and_class_breadth() -> None:
    manifest = RepositoryReviewEvalManifest.from_mapping(
        _manifest(
            _case(
                "mixed",
                [
                    _expected("idor-one", "idor", start_line=1, end_line=2),
                    _expected(
                        "sql-one",
                        "sql_injection",
                        path="src/query.py",
                        start_line=10,
                        end_line=12,
                    ),
                ],
                evaluated_classes=["idor", "sql_injection", "command_injection"],
            ),
            _case("clean", []),
        )
    )
    mixed = score_repository_review(
        manifest.cases[0],
        _review(
            _finding("idor", start_line=1, end_line=2),
            _finding("command_injection", path="src/other.py"),
        ),
    )
    clean = score_repository_review(
        manifest.cases[1],
        _review(_finding("idor", path="src/control.py")),
    )

    aggregate = aggregate_repository_review_scores((mixed, clean))

    assert aggregate.case_count == 2
    assert aggregate.metrics.true_positives == 1
    assert aggregate.metrics.false_positives == 2
    assert aggregate.metrics.false_negatives == 1
    assert aggregate.metrics.precision == pytest.approx(1 / 3)
    assert aggregate.metrics.recall == pytest.approx(1 / 2)
    assert aggregate.metrics.f1 == pytest.approx(0.4)
    by_class = {item.vuln_class: item.metrics for item in aggregate.by_vuln_class}
    assert by_class["idor"].true_positives == 1
    assert by_class["idor"].false_positives == 1
    assert by_class["sql_injection"].false_negatives == 1
    assert by_class["command_injection"].false_positives == 1


@pytest.mark.parametrize(
    "review",
    [
        {"schema": "wrong", "findings": []},
        {"schema": REVIEW_SCHEMA_VERSION, "findings": "not-a-list"},
        _review(_finding("Command Injection")),
        _review(_finding("idor", start_line=8, end_line=5)),
        _review({"vuln_class": "idor", "evidence": []}),
    ],
)
def test_scoring_rejects_malformed_review_artifacts(review: dict[str, object]) -> None:
    case = RepositoryReviewEvalManifest.from_mapping(
        _manifest(_case("case-one", [_expected("finding-one", "idor")]))
    ).cases[0]

    with pytest.raises(RepositoryReviewEvalInputError):
        score_repository_review(case, review)


def test_aggregate_rejects_an_empty_run_set() -> None:
    with pytest.raises(RepositoryReviewEvalInputError, match="at least one"):
        aggregate_repository_review_scores(())
