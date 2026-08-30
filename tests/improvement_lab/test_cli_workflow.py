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
    EvaluationSuite,
    EvaluationSuiteCase,
    RunReceipt,
    canonical_run_receipts_bytes,
    load_canonical_run_receipts,
)
from tools.improvement_lab.execution_attestation import (
    ExecutionBinding,
    ExternalRunObservations,
    FindingVerdict,
    sign_execution_envelope,
    write_signed_execution_envelope,
)
from tools.improvement_lab.lessons import build_improvement_brief
from tools.improvement_lab.offline_executor import freeze_output_tree
from tools.improvement_lab.run_receipt_adapter import finding_reference_digest
from tools.improvement_lab.workspace import directory_tree_digest

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    import pytest

_PROMOTION_REQUIRED_BUT_REJECTED = 3
_RUNNER_IMAGE = f"example.invalid/referee@sha256:{'a' * 64}"


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


def _evaluation_suite(trusted_tests: Path) -> EvaluationSuite:
    cases = tuple(
        EvaluationSuiteCase(
            case_id=case_id,
            cohort="control" if control else "capability",
            execution_kind="fixture",
            repeats=3,
            is_control=control,
            expected_vulnerability_count=0 if control else 1,
            target_snapshot_digests=tuple(
                _digest(f"snapshot:{case_id}:{repeat}") for repeat in range(1, 4)
            ),
        )
        for case_id, control in (
            ("opaque-capability", False),
            ("opaque-control", True),
        )
    )
    return EvaluationSuite(
        cases=cases,
        model_fingerprint=_digest("model:fixed"),
        trusted_tests_digest=directory_tree_digest(trusted_tests),
        runner_command=("/usr/local/bin/python", "-I", "/trusted-tests/trusted_referee.py"),
    )


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


def _write_attested_artifacts(root: Path, *, finding_id: str | None) -> None:
    case_root = root / "case-output"
    workspace = case_root / "workspace"
    workspace.mkdir(parents=True)
    findings = (
        []
        if finding_id is None
        else [{"finding_id": finding_id, "status": "confirmed"}]
    )
    _write_json(
        case_root / "report.json",
        {
            "findings": findings,
            "outcome": {"evidence": []},
            "traffic_accounting": {
                "status": "exact",
                "physical_request_count": 4,
                "incomplete_request_count": 0,
                "unmetered_action_count": 0,
            },
        },
    )
    _write_json(
        workspace / "traffic-policy.json",
        {
            "schema": "ravage.traffic-policy",
            "physical_request_count": 4,
            "incomplete_request_count": 0,
            "unmetered_action_count": 0,
        },
    )


def _build_attested_receipt(  # noqa: PLR0913 - exposes the complete trust binding.
    capsys: pytest.CaptureFixture[str],
    *,
    archive: Path,
    evidence_root: Path,
    campaign: Mapping[str, object],
    candidate: Mapping[str, object],
    suite: EvaluationSuite,
    evaluation_suite_object: str,
    champion_tree: str,
    executor_private_key: bytes,
    suite_case: EvaluationSuiteCase,
    repeat: int,
    side: str,
    detected: int,
) -> RunReceipt:
    candidate_id = str(candidate["candidate_id"])
    execution_scope = (
        candidate_id if side == "candidate" else str(campaign["campaign_id"])
    )
    run_root = evidence_root / side / suite_case.case_id / f"repeat-{repeat}"
    artifact_root = run_root / "artifacts"
    finding_id = (
        None
        if detected == 0
        else f"{candidate_id}:{side}:{suite_case.case_id}:{repeat}:finding"
    )
    _write_attested_artifacts(artifact_root, finding_id=finding_id)
    frozen = freeze_output_tree(artifact_root)
    patch_object = str(candidate["patch_object"])
    envelope = sign_execution_envelope(
        ExecutionBinding(
            campaign_id=str(campaign["campaign_id"]),
            candidate_id=candidate_id if side == "candidate" else None,
            candidate_tree_digest=(
                champion_tree if side == "champion" else patch_object.removeprefix("sha256:")
            ),
            candidate_content_digest=(
                _digest(f"champion:{champion_tree}")
                if side == "champion"
                else patch_object
            ),
            evaluation_suite_object=evaluation_suite_object,
            trusted_tests_digest=suite.trusted_tests_digest,
            runner_image=_RUNNER_IMAGE,
            job_spec_digest=_digest(
                f"job:{execution_scope}:{side}:{suite_case.case_id}:{repeat}"
            ),
            artifact_tree_digest=frozen.digest,
            artifact_case_path="case-output",
            case_id=suite_case.case_id,
            cohort=suite_case.cohort,
            repeat=repeat,
            execution_kind=suite_case.execution_kind,
            evaluation_side=side,
            is_control=suite_case.is_control,
            expected_vulnerability_count=suite_case.expected_vulnerability_count,
            run_id=_digest(
                f"run:{execution_scope}:{side}:{suite_case.case_id}:{repeat}"
            ),
            pair_seed_digest=_digest(f"seed:{suite_case.case_id}:{repeat}"),
            target_snapshot_digest=suite_case.target_snapshot_digests[repeat - 1],
            model_fingerprint=suite.model_fingerprint,
            prompt_fingerprint=_digest(f"prompt:{side}"),
        ),
        ExternalRunObservations(
            status="completed",
            case_success=True if suite_case.is_control else bool(detected),
            physical_request_count=4,
            model_request_count=2,
            cost_usd=0.1,
            request_accounting_status="exact",
            proof_integrity_failure_count=0,
            false_proof_count=0,
            request_accounting_mismatch_count=0,
            loop_violation_count=0,
            provenance_violation_count=0,
            secret_leak_violation_count=0,
            unmetered_action_count=0,
            incomplete_request_count=0,
        ),
        ()
        if finding_id is None
        else (FindingVerdict(finding_reference_digest(finding_id), "confirmed_finding"),),
        private_key=executor_private_key,
    )
    envelope_path = run_root / "execution-envelope.json"
    receipt_path = run_root / "receipt.json"
    write_signed_execution_envelope(envelope_path, envelope)
    result = _call(
        capsys,
        "receipt-build",
        "--archive",
        str(archive),
        "--candidate-id",
        candidate_id,
        "--artifacts",
        str(artifact_root),
        "--execution-envelope",
        str(envelope_path),
        "--output",
        str(receipt_path),
    )
    receipts = load_canonical_run_receipts(receipt_path.read_bytes())
    assert len(receipts) == 1
    receipt = receipts[0]
    assert result["execution_attestation_digest"] == receipt.execution_attestation_digest
    assert result["evaluation_side"] == side
    return receipt


def _build_attested_receipt_set(  # noqa: PLR0913 - binds one full execution matrix.
    capsys: pytest.CaptureFixture[str],
    *,
    archive: Path,
    evidence_root: Path,
    campaign: Mapping[str, object],
    candidate: Mapping[str, object],
    suite: EvaluationSuite,
    evaluation_suite_object: str,
    champion_tree: str,
    executor_private_key: bytes,
    side: str,
    improved: bool,
) -> tuple[RunReceipt, ...]:
    receipts: list[RunReceipt] = []
    for suite_case in suite.cases:
        for repeat in range(1, suite_case.repeats + 1):
            detected = int(
                improved
                and side == "candidate"
                and not suite_case.is_control
            )
            receipts.append(
                _build_attested_receipt(
                    capsys,
                    archive=archive,
                    evidence_root=evidence_root,
                    campaign=campaign,
                    candidate=candidate,
                    suite=suite,
                    evaluation_suite_object=evaluation_suite_object,
                    champion_tree=champion_tree,
                    executor_private_key=executor_private_key,
                    suite_case=suite_case,
                    repeat=repeat,
                    side=side,
                    detected=detected,
                )
            )
    return tuple(receipts)


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
    _call(
        capsys,
        "referee-keygen",
        "--private-key",
        str(lab / "executor.private"),
        "--public-key",
        str(lab / "executor.public"),
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

    suite = _evaluation_suite(trusted_tests)
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
        _RUNNER_IMAGE,
        "--referee-public-key",
        str(lab / "referee.public"),
        "--executor-public-key",
        str(lab / "executor.public"),
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
    suite_object = f"sha256:{hashlib.sha256(suite_path.read_bytes()).hexdigest()}"
    champion_tree = _git(source, "rev-parse", "HEAD^{tree}")
    executor_private_key = (lab / "executor.private").read_bytes()
    champion_receipts = _build_attested_receipt_set(
        capsys,
        archive=archive,
        evidence_root=lab / "champion-execution-evidence",
        campaign=campaign,
        candidate=good,
        suite=suite,
        evaluation_suite_object=suite_object,
        champion_tree=champion_tree,
        executor_private_key=executor_private_key,
        side="champion",
        improved=False,
    )
    improved_receipts = _build_attested_receipt_set(
        capsys,
        archive=archive,
        evidence_root=lab / "good-execution-evidence",
        campaign=campaign,
        candidate=good,
        suite=suite,
        evaluation_suite_object=suite_object,
        champion_tree=champion_tree,
        executor_private_key=executor_private_key,
        side="candidate",
        improved=True,
    )
    unchanged_receipts = _build_attested_receipt_set(
        capsys,
        archive=archive,
        evidence_root=lab / "bad-execution-evidence",
        campaign=campaign,
        candidate=bad,
        suite=suite,
        evaluation_suite_object=suite_object,
        champion_tree=champion_tree,
        executor_private_key=executor_private_key,
        side="candidate",
        improved=False,
    )
    champion_path.write_bytes(canonical_run_receipts_bytes(champion_receipts))
    improved_path.write_bytes(canonical_run_receipts_bytes(improved_receipts))
    unchanged_path.write_bytes(canonical_run_receipts_bytes(unchanged_receipts))

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
