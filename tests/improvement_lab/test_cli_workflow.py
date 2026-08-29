from __future__ import annotations

import hashlib
import json
import subprocess
from typing import TYPE_CHECKING

from tools.improvement_lab import cli
from tools.improvement_lab.archive import APPROVAL_SCHEMA_VERSION
from tools.improvement_lab.corpus import candidate_visible_export
from tools.improvement_lab.evaluation import (
    EvaluationConfig,
    RunReceipt,
    evaluation_suite_from_receipts,
)
from tools.improvement_lab.lessons import build_improvement_brief
from tools.improvement_lab.workspace import directory_tree_digest

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

_PROMOTION_REQUIRED_BUT_REJECTED = 3


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603
        ("git", "-C", str(root), *args),  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _source_repo(root: Path) -> None:
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.email", "lab-smoke@example.invalid")
    _git(root, "config", "user.name", "Lab Smoke")
    (root / "app.txt").write_text("champion\n", encoding="utf-8")
    _git(root, "add", "app.txt")
    _git(root, "commit", "-m", "champion")


def _run_receipt(
    *,
    case_id: str,
    repeat: int,
    control: bool,
    side: str,
    detected: int,
) -> dict[str, object]:
    expected = 0 if control else 1
    return {
        "case_id": case_id,
        "cohort": "control" if control else "capability",
        "repeat": repeat,
        "execution_kind": "fixture",
        "status": "completed",
        "is_control": control,
        "case_success": True if control else None,
        "expected_vulnerability_count": expected,
        "run_id": _digest(f"run:{side}:{case_id}:{repeat}"),
        "pair_seed_digest": _digest(f"seed:{case_id}:{repeat}"),
        "target_snapshot_digest": _digest(f"snapshot:{case_id}:{repeat}"),
        "model_fingerprint": _digest("model:fixed"),
        "prompt_fingerprint": _digest(f"prompt:{side}"),
        "metrics": {
            "evidence_backed_vulnerability_count": detected,
            "verified_vulnerability_count": detected,
            "confirmed_finding_count": detected,
            "suspected_vulnerability_count": 0,
            "proof_integrity_failure_count": 0,
            "false_proof_count": 0,
            "request_accounting_mismatch_count": 0,
            "loop_violation_count": 0,
            "provenance_violation_count": 0,
            "secret_leak_violation_count": 0,
            "unmetered_action_count": 0,
            "incomplete_request_count": 0,
            "physical_request_count": 4,
            "model_request_count": 2,
            "cost_usd": 0.1,
            "request_accounting_status": "exact",
        },
    }


def _receipt_sets(*, improved: bool) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    champion: list[dict[str, object]] = []
    candidate: list[dict[str, object]] = []
    for repeat in range(1, 4):
        champion.append(
            _run_receipt(
                case_id="opaque-capability",
                repeat=repeat,
                control=False,
                side="champion",
                detected=0,
            )
        )
        candidate.append(
            _run_receipt(
                case_id="opaque-capability",
                repeat=repeat,
                control=False,
                side="candidate",
                detected=1 if improved else 0,
            )
        )
        for side, output in (("champion", champion), ("candidate", candidate)):
            output.append(
                _run_receipt(
                    case_id="opaque-control",
                    repeat=repeat,
                    control=True,
                    side=side,
                    detected=0,
                )
            )
    return champion, candidate


def _call(
    capsys: pytest.CaptureFixture[str],
    *args: str,
    expected: int = 0,
) -> dict[str, object]:
    assert cli.main(args) == expected
    captured = capsys.readouterr()
    if not captured.out:
        return {}
    payload = json.loads(captured.out)
    assert isinstance(payload, dict)
    return payload


def test_complete_cli_campaign_is_reproducible_and_recoverable(  # noqa: PLR0915
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "source"
    lab = tmp_path / "lab-state"
    work = tmp_path / "disposable-work"
    trusted_tests = tmp_path / "trusted-tests"
    archive = lab / "archive"
    _source_repo(source)
    lab.mkdir()
    work.mkdir()
    trusted_tests.mkdir()
    (trusted_tests / "trusted_referee.py").write_text("raise SystemExit(0)\n", encoding="utf-8")

    _call(capsys, "archive-init", "--archive", str(archive))
    _call(
        capsys,
        "referee-keygen",
        "--private-key",
        str(lab / "referee.private"),
        "--public-key",
        str(lab / "referee.public"),
    )

    corpus = candidate_visible_export([])
    brief = build_improvement_brief(corpus)
    corpus_path = lab / "development-corpus.json"
    brief_path = lab / "capability-brief.json"
    _write_json(corpus_path, corpus)
    _write_json(brief_path, brief)
    corpus_artifact = _call(
        capsys,
        "artifact-add",
        "--archive",
        str(archive),
        "--kind",
        "development_corpus",
        "--visibility",
        "candidate",
        "--file",
        str(corpus_path),
    )
    brief_artifact = _call(
        capsys,
        "artifact-add",
        "--archive",
        str(archive),
        "--kind",
        "capability_brief",
        "--visibility",
        "candidate",
        "--file",
        str(brief_path),
    )

    champion_receipts, improved_receipts = _receipt_sets(improved=True)
    suite = evaluation_suite_from_receipts(
        tuple(RunReceipt.from_mapping(item) for item in champion_receipts),
        trusted_tests_digest=directory_tree_digest(trusted_tests),
        runner_command=("/usr/local/bin/python", "-I", "/trusted-tests/trusted_referee.py"),
    )
    config_path = lab / "evaluation-config.json"
    suite_path = lab / "evaluation-suite.json"
    _write_json(config_path, EvaluationConfig().to_json())
    _write_json(suite_path, suite.to_json())
    campaign = _call(
        capsys,
        "campaign-create",
        "--archive",
        str(archive),
        "--source",
        str(source),
        "--evaluation-config",
        str(config_path),
        "--evaluation-suite",
        str(suite_path),
        "--runner-image",
        f"example.invalid/referee@sha256:{'a' * 64}",
        "--referee-public-key",
        str(lab / "referee.public"),
        "--candidate-artifact-id",
        str(corpus_artifact["artifact_id"]),
        "--candidate-artifact-id",
        str(brief_artifact["artifact_id"]),
    )

    patch_path = lab / "candidate.patch"
    patch_path.write_text(
        """diff --git a/app.txt b/app.txt
--- a/app.txt
+++ b/app.txt
@@ -1 +1 @@
-champion
+candidate
""",
        encoding="utf-8",
    )
    good_config = lab / "candidate-good.json"
    bad_config = lab / "candidate-bad.json"
    _write_json(good_config, {"hypothesis": "generic capability improvement"})
    _write_json(bad_config, {"hypothesis": "negative control candidate"})
    good = _call(
        capsys,
        "candidate-add",
        "--archive",
        str(archive),
        "--artifact-kind",
        "source_patch",
        "--patch",
        str(patch_path),
        "--config",
        str(good_config),
    )
    bad = _call(
        capsys,
        "candidate-add",
        "--archive",
        str(archive),
        "--artifact-kind",
        "source_patch",
        "--patch",
        str(patch_path),
        "--config",
        str(bad_config),
    )

    good_id = str(good["candidate_id"])
    _call(
        capsys,
        "materialize",
        "--source",
        str(source),
        "--lab-root",
        str(work / "manual-materialization"),
        "--archive",
        str(archive),
        "--candidate-id",
        good_id,
    )
    job = _call(
        capsys,
        "offline-job",
        "--source",
        str(source),
        "--lab-root",
        str(work / "offline-materialization"),
        "--archive",
        str(archive),
        "--candidate-id",
        good_id,
        "--candidate-view-root",
        str(work / "candidate-view"),
        "--trusted-tests",
        str(trusted_tests),
        "--job-output",
        str(work / "job-output"),
        "--spec-output",
        str(work / "job.json"),
    )
    assert job["candidate_content_digest"]

    champion_path = lab / "champion-receipts.json"
    improved_path = lab / "improved-receipts.json"
    unchanged_path = lab / "unchanged-receipts.json"
    _write_json(champion_path, champion_receipts)
    _write_json(improved_path, improved_receipts)
    _champion_again, unchanged_receipts = _receipt_sets(improved=False)
    _write_json(unchanged_path, unchanged_receipts)

    good_signed = lab / "good.signed.json"
    good_result = _call(
        capsys,
        "evaluate",
        "--champion",
        str(champion_path),
        "--candidate",
        str(improved_path),
        "--archive",
        str(archive),
        "--candidate-id",
        good_id,
        "--referee-private-key",
        str(lab / "referee.private"),
        "--output",
        str(good_signed),
    )
    assert good_result["accepted"] is True
    good_evaluation = _call(
        capsys,
        "evaluation-add",
        "--archive",
        str(archive),
        "--candidate-id",
        good_id,
        "--signed-evaluation",
        str(good_signed),
    )

    bad_signed = lab / "bad.signed.json"
    bad_result = _call(
        capsys,
        "evaluate",
        "--champion",
        str(champion_path),
        "--candidate",
        str(unchanged_path),
        "--archive",
        str(archive),
        "--candidate-id",
        str(bad["candidate_id"]),
        "--referee-private-key",
        str(lab / "referee.private"),
        "--output",
        str(bad_signed),
        "--require-promotion",
        expected=_PROMOTION_REQUIRED_BUT_REJECTED,
    )
    assert bad_result["accepted"] is False
    bad_evaluation = _call(
        capsys,
        "evaluation-add",
        "--archive",
        str(archive),
        "--candidate-id",
        str(bad["candidate_id"]),
        "--signed-evaluation",
        str(bad_signed),
    )

    tournament = _call(
        capsys,
        "tournament",
        "--archive",
        str(archive),
        "--evaluation-id",
        str(good_evaluation["evaluation_id"]),
        "--evaluation-id",
        str(bad_evaluation["evaluation_id"]),
        "--output",
        str(lab / "tournament.json"),
    )
    assert tournament["winner_candidate_id"] == good_id

    approval_path = lab / "approval.json"
    _write_json(
        approval_path,
        {
            "schema_version": APPROVAL_SCHEMA_VERSION,
            "decision": "accept",
            "candidate_id": good_id,
            "evaluation_id": good_evaluation["evaluation_id"],
            "reviewer": "test-operator",
            "approved_at": "2026-08-26T00:00:00+00:00",
            "statement": "Reviewed candidate lineage and signed evaluation.",
        },
    )
    _call(
        capsys,
        "accept",
        "--archive",
        str(archive),
        "--candidate-id",
        good_id,
        "--evaluation-id",
        str(good_evaluation["evaluation_id"]),
        "--expected-champion-ref",
        str(campaign["champion_ref"]),
        "--approval",
        str(approval_path),
    )
    exported = lab / "exported.patch"
    _call(
        capsys,
        "export",
        "--archive",
        str(archive),
        "--candidate-id",
        good_id,
        "--output",
        str(exported),
    )
    assert exported.read_bytes() == patch_path.read_bytes()

    verified = _call(capsys, "archive-verify", "--archive", str(archive))
    anchor = str(verified.get("archive_checkpoint", verified["ledger_head"]))
    _call(
        capsys,
        "archive-verify",
        "--archive",
        str(archive),
        "--expected-checkpoint",
        anchor,
    )
    recovered = _call(capsys, "archive-recover", "--archive", str(archive))
    assert recovered.get("archive_checkpoint", recovered["ledger_head"]) == anchor
