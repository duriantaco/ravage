"""Scripted regressions for the repository-review A/B evaluation runner."""

# Small fixed count assertions make the telemetry expectations easier to audit.
# ruff: noqa: PLR2004

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest
from ravage.model_core.providers import ResolvedModelRoute
from ravage.repository_context import capture_repository
from ravage.repository_review import ReviewMessage, ReviewReply
from ravage.repository_review_eval import MANIFEST_SCHEMA_VERSION
from ravage.repository_review_eval_runner import (
    CANDIDATE_ASSISTED_ARM,
    LITERAL_ONLY_ARM,
    REPORT_SCHEMA_VERSION,
    RepositoryReviewEvalRunnerError,
    load_repository_review_eval_manifest,
    run_repository_review_ab_evaluation,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


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


def _write_manifest(
    path: Path,
    *,
    source_root: str = "fixtures/case-one",
    snapshot_id: str = "sha256:" + "0" * 64,
) -> None:
    payload = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "cases": [
            {
                "id": "case-one",
                "source_root": source_root,
                "snapshot_id": snapshot_id,
                "evaluated_classes": ["sql_injection"],
                "expected": [
                    {
                        "id": "query-one",
                        "vuln_class": "sql_injection",
                        "locations": [
                            {
                                "path": "app.py",
                                "start_line": 7,
                                "end_line": 8,
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_source(repository_root: Path) -> None:
    case_root = repository_root / "fixtures" / "case-one"
    case_root.mkdir(parents=True)
    case_root.joinpath("app.py").write_text(
        """from flask import Flask, request

app = Flask(__name__)

@app.get("/search")
def search():
    term = request.args.get("term")
    return database.execute("SELECT * FROM records WHERE name = '" + term + "'")
""",
        encoding="utf-8",
    )


def _snapshot_id(repository_root: Path) -> str:
    return capture_repository(repository_root / "fixtures" / "case-one").snapshot_id


class _AdaptiveClient:
    def complete(
        self,
        *,
        messages: Sequence[ReviewMessage],
        route: ResolvedModelRoute,
    ) -> ReviewReply:
        del route
        candidate_assisted = "list_source_candidates" in messages[0].content
        if len(messages) == 2:
            action: dict[str, object] = {
                "action": "excerpt",
                "args": {"path": "app.py", "start_line": 5, "end_line": 20},
            }
        else:
            findings: list[dict[str, object]] = []
            if candidate_assisted:
                findings.append(
                    {
                        "vuln_class": "sql_injection",
                        "title": "Request input reaches SQL text",
                        "severity": "high",
                        "confidence": "high",
                        "description": "Query text includes a request value.",
                        "recommendation": "Use a parameterized query.",
                        "evidence_ids": ["excerpt-1"],
                    }
                )
            action = {
                "action": "final",
                "args": {"summary": "Scripted review complete.", "findings": findings},
            }
        return ReviewReply(
            content=json.dumps(action),
            input_tokens=10,
            cached_input_tokens=2,
            output_tokens=3,
            cost_usd=0.05,
            usage_reported=True,
            cost_known=True,
        )


class _InvalidReplyClient:
    def complete(
        self,
        *,
        messages: Sequence[ReviewMessage],
        route: ResolvedModelRoute,
    ) -> ReviewReply:
        del messages, route
        return ReviewReply(
            content="not JSON",
            input_tokens=4,
            output_tokens=2,
            cost_usd=0.25,
            usage_reported=True,
            cost_known=True,
        )


class _NeverCalledClient:
    def complete(
        self,
        *,
        messages: Sequence[ReviewMessage],
        route: ResolvedModelRoute,
    ) -> ReviewReply:
        del messages, route
        message = "model client must not run during failed fixture preflight"
        raise AssertionError(message)


class _MutatingClient(_AdaptiveClient):
    def __init__(self, source: Path) -> None:
        self.source = source
        self.calls = 0

    def complete(
        self,
        *,
        messages: Sequence[ReviewMessage],
        route: ResolvedModelRoute,
    ) -> ReviewReply:
        reply = super().complete(messages=messages, route=route)
        self.calls += 1
        if self.calls == 1:
            self.source.write_text(
                self.source.read_text(encoding="utf-8") + "# changed during evaluation\n",
                encoding="utf-8",
            )
        return reply


def test_manifest_loader_uses_strict_json_and_schema(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path)

    manifest = load_repository_review_eval_manifest(manifest_path)

    assert manifest.cases[0].case_id == "case-one"
    manifest_path.write_text(
        '{"schema_version":"ravage.repository-review-eval-manifest.v1",'
        '"schema_version":"ravage.repository-review-eval-manifest.v1","cases":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="canonical UTF-8 JSON"):
        load_repository_review_eval_manifest(manifest_path)


def test_ab_runner_repeats_both_arms_and_aggregates_detection_and_telemetry(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path / "repository"
    _write_source(repository_root)
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, snapshot_id=_snapshot_id(repository_root))

    report = run_repository_review_ab_evaluation(
        manifest_path=manifest_path,
        repository_root=repository_root,
        route=_route(),
        client=_AdaptiveClient(),
        repeats=2,
        max_turns=2,
        max_cost_usd_per_run=1.0,
        aggregate_cost_ceiling_usd=1.0,
    )

    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    manifest_bytes = manifest_path.read_bytes()
    assert report["manifest"]["file_digest"] == (
        "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    )
    assert report["completion"] == {
        "planned_runs": 4,
        "attempted_runs": 4,
        "completed_runs": 4,
        "failed_runs": 0,
        "skipped_runs": 0,
        "completion_rate": 1.0,
    }
    arms = {item["arm"]: item for item in report["arms"]}
    literal_score = arms[LITERAL_ONLY_ARM]["detection"]["score"]
    assisted_score = arms[CANDIDATE_ASSISTED_ARM]["detection"]["score"]
    assert literal_score["true_positives"] == 0
    assert literal_score["false_negatives"] == 2
    assert assisted_score["true_positives"] == 2
    assert assisted_score["false_negatives"] == 0
    assert report["tools"]["context_actions"] == 4
    assert report["tools"]["files_excerpted"] == 4
    assert report["tools"]["source_candidates_seeded"] == 2
    assert report["model"] == {
        "requests": 8,
        "replies": 8,
        "invalid_replies": 0,
        "input_tokens": 80,
        "cached_input_tokens": 16,
        "output_tokens": 24,
        "actual_cost_usd": 0.4,
        "cost_known": True,
        "unknown_cost_replies": 0,
        "requested_actions": {"excerpt": 4, "final": 4},
    }
    assert [run["arm"] for run in report["runs"]] == [
        LITERAL_ONLY_ARM,
        CANDIDATE_ASSISTED_ARM,
        CANDIDATE_ASSISTED_ARM,
        LITERAL_ONLY_ARM,
    ]
    prompt_digests = [run["model"]["initial_prompt_digest"] for run in report["runs"]]
    assert all(digest.startswith("sha256:") for digest in prompt_digests)
    assert prompt_digests[0] == prompt_digests[3]
    assert prompt_digests[1] == prompt_digests[2]
    assert prompt_digests[0] != prompt_digests[1]
    [stratum] = report["strata"]
    assert stratum["stratum"] == "candidate_bearing"
    assert stratum["completion"]["completed_runs"] == 4
    stratum_arms = {item["arm"]: item for item in stratum["arms"]}
    assert stratum_arms[LITERAL_ONLY_ARM]["detection"]["score"]["true_positives"] == 0
    assert stratum_arms[CANDIDATE_ASSISTED_ARM]["detection"]["score"]["true_positives"] == 2
    [fixture] = report["manifest"]["fixture_snapshots"]
    assert fixture["stratum"] == "candidate_bearing"
    assert fixture["source_candidate_count"] == 1
    assert fixture["snapshot_id"].startswith("sha256:")
    assert all(run["review"] is not None for run in report["runs"])
    assert all(run["score"] is not None for run in report["runs"])
    json.dumps(report, allow_nan=False)


def test_failed_runs_keep_actual_reply_cost_and_stop_at_aggregate_ceiling(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path / "repository"
    _write_source(repository_root)
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, snapshot_id=_snapshot_id(repository_root))

    report = run_repository_review_ab_evaluation(
        manifest_path=manifest_path,
        repository_root=repository_root,
        route=_route(),
        client=_InvalidReplyClient(),
        repeats=2,
        max_turns=1,
        max_cost_usd_per_run=1.0,
        aggregate_cost_ceiling_usd=0.5,
    )

    assert report["budget"] == {
        "ceiling_usd": 0.5,
        "actual_cost_usd": 0.5,
        "exhausted": True,
    }
    assert report["completion"] == {
        "planned_runs": 4,
        "attempted_runs": 2,
        "completed_runs": 0,
        "failed_runs": 2,
        "skipped_runs": 2,
        "completion_rate": 0.0,
    }
    assert report["detection"] == {
        "scored_runs": 0,
        "unscored_runs": 4,
        "score": None,
    }
    assert report["model"]["replies"] == 2
    assert report["model"]["actual_cost_usd"] == 0.5
    assert len(report["failures"]) == 2
    assert all(run["model"]["actual_cost_usd"] == 0.25 for run in report["runs"])
    assert all(run["failure"]["type"] == "RepositoryReviewError" for run in report["runs"])


def test_case_root_symlink_cannot_escape_supplied_repository_root(tmp_path: Path) -> None:
    repository_root = tmp_path / "repository"
    (repository_root / "fixtures").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (repository_root / "fixtures" / "case-one").symlink_to(outside, target_is_directory=True)
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path)

    with pytest.raises(RepositoryReviewEvalRunnerError, match="cannot be a symlink"):
        run_repository_review_ab_evaluation(
            manifest_path=manifest_path,
            repository_root=repository_root,
            route=_route(),
            client=_AdaptiveClient(),
        )


def test_runner_rejects_a_completed_result_after_fixture_snapshot_changes(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path / "repository"
    _write_source(repository_root)
    source = repository_root / "fixtures" / "case-one" / "app.py"
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, snapshot_id=_snapshot_id(repository_root))

    report = run_repository_review_ab_evaluation(
        manifest_path=manifest_path,
        repository_root=repository_root,
        route=_route(),
        client=_MutatingClient(source),
        max_turns=2,
        max_cost_usd_per_run=1.0,
        aggregate_cost_ceiling_usd=1.0,
    )

    assert report["completion"]["completed_runs"] == 1
    assert report["completion"]["failed_runs"] == 1
    first, second = report["runs"]
    assert first["completed"] is True
    assert second["completed"] is False
    assert second["failure"]["type"] == "RepositoryReviewEvalRunnerError"
    assert "pinned snapshot" in second["failure"]["message"]
    assert second["model"]["replies"] == 2


def test_manifest_snapshot_mismatch_fails_before_any_model_request(tmp_path: Path) -> None:
    repository_root = tmp_path / "repository"
    _write_source(repository_root)
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path)

    with pytest.raises(RepositoryReviewEvalRunnerError, match="does not match"):
        run_repository_review_ab_evaluation(
            manifest_path=manifest_path,
            repository_root=repository_root,
            route=_route(),
            client=_NeverCalledClient(),
        )
