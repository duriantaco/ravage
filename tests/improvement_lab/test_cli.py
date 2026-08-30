from __future__ import annotations

import hashlib
import json
import os
import stat
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from tools.improvement_lab import cli
from tools.improvement_lab.archive import LabArchive
from tools.improvement_lab.attestation import (
    generate_referee_keypair,
    public_key_from_private,
    write_referee_key,
)
from tools.improvement_lab.corpus import CorpusFormatError, candidate_visible_export
from tools.improvement_lab.evaluation import (
    EvaluationConfig,
    RunReceipt,
    canonical_run_receipts_bytes,
    evaluation_suite_from_receipts,
)
from tools.improvement_lab.execution_attestation import (
    ExecutionBinding,
    ExternalRunObservations,
    FindingVerdict,
    SignedExecutionEnvelope,
    canonical_execution_envelope_bytes,
    sign_execution_envelope,
    write_signed_execution_envelope,
)
from tools.improvement_lab.lessons import build_improvement_brief
from tools.improvement_lab.offline_executor import freeze_output_tree

if TYPE_CHECKING:
    from pathlib import Path

_PRIVATE_FILE_MODE = 0o600
_CLI_ERROR = 2
_TWO_CAPSULES = 2
_SECOND_WRITE = 2
_INJECTED_WRITE_FAILURE = "injected sealed write failure"


def _write_events(run_dir: Path, *, turn: int = 1) -> None:
    workspace = run_dir / "workspace"
    workspace.mkdir(parents=True)
    events = (
        {
            "kind": "harness_selection",
            "payload": {
                "turn": turn,
                "proposed_action": {
                    "action": "run_probe",
                    "probe": "sqli_differential",
                    "url": "http://private.invalid/secret-route",
                },
                "selected_action": {
                    "action": "run_probe",
                    "probe": "sqli_differential",
                    "url": "http://private.invalid/secret-route",
                },
                "selected_differs_from_model": False,
                "selection_reason": "model_proposal",
            },
        },
        {
            "kind": "agent_attempt_recorded",
            "payload": {
                "turn": turn,
                "proposed_action": {"action": "run_probe", "probe": "sqli_differential"},
                "selected_action": {"action": "run_probe", "probe": "sqli_differential"},
                "selection_reason": "model_proposal",
                "novel": True,
                "status": "progressed",
                "outcome": {
                    "classification": "confirmed_signal",
                    "ok": True,
                    "repeat_count": 0,
                    "stop": False,
                },
                "state_delta": {"facts_delta": 1},
            },
        },
    )
    (workspace / "events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def _write_private_key(path: Path) -> None:
    path.write_bytes(b"k" * 32)
    path.chmod(0o600)


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _run_receipt(
    *,
    case_id: str,
    repeat: int,
    control: bool,
    detected: int,
    side: str,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "cohort": "control" if control else "capability",
        "repeat": repeat,
        "execution_kind": "fixture",
        "status": "completed",
        "is_control": control,
        "case_success": bool(detected),
        "expected_vulnerability_count": 1,
        "run_id": _digest(f"run:{side}:{case_id}:{repeat}"),
        "execution_attestation_digest": _digest(
            f"attestation:{side}:{case_id}:{repeat}"
        ),
        "pair_seed_digest": _digest(f"seed:{case_id}:{repeat}"),
        "target_snapshot_digest": _digest(f"target:{case_id}"),
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


def _sign_run_receipt(  # noqa: PLR0913 - fixture exposes each signed binding input.
    receipt: RunReceipt,
    *,
    campaign_id: str,
    candidate_id: str,
    evaluation_suite_object: str,
    trusted_tests_digest: str,
    runner_image: str,
    champion_tree: str,
    executor_private_key: bytes,
    side: str,
) -> SignedExecutionEnvelope:
    binding = ExecutionBinding(
        campaign_id=campaign_id,
        candidate_id=None if side == "champion" else candidate_id,
        candidate_tree_digest=(champion_tree if side == "champion" else "f" * 40),
        candidate_content_digest=_digest(
            f"candidate-content:{side}:{receipt.case_id}:{receipt.repeat}"
        ),
        evaluation_suite_object=evaluation_suite_object,
        trusted_tests_digest=trusted_tests_digest,
        runner_image=runner_image,
        job_spec_digest=_digest(f"job:{side}:{receipt.case_id}:{receipt.repeat}"),
        artifact_tree_digest=_digest(
            f"artifacts:{side}:{receipt.case_id}:{receipt.repeat}"
        ),
        artifact_case_path="case",
        case_id=receipt.case_id,
        cohort=receipt.cohort,
        repeat=receipt.repeat,
        execution_kind=receipt.execution_kind,
        evaluation_side=side,
        is_control=receipt.is_control,
        expected_vulnerability_count=receipt.expected_vulnerability_count,
        run_id=receipt.run_id,
        pair_seed_digest=receipt.pair_seed_digest,
        target_snapshot_digest=receipt.target_snapshot_digest,
        model_fingerprint=receipt.model_fingerprint,
        prompt_fingerprint=receipt.prompt_fingerprint,
    )
    observations = ExternalRunObservations(
        status=receipt.status,
        case_success=receipt.case_success,
        physical_request_count=receipt.physical_request_count,
        model_request_count=receipt.model_request_count,
        cost_usd=receipt.cost_usd,
        request_accounting_status=receipt.request_accounting_status,
        proof_integrity_failure_count=receipt.proof_integrity_failure_count,
        false_proof_count=receipt.false_proof_count,
        request_accounting_mismatch_count=receipt.request_accounting_mismatch_count,
        loop_violation_count=receipt.loop_violation_count,
        provenance_violation_count=receipt.provenance_violation_count,
        secret_leak_violation_count=receipt.secret_leak_violation_count,
        unmetered_action_count=receipt.unmetered_action_count,
        incomplete_request_count=receipt.incomplete_request_count,
    )
    verdicts = tuple(
        FindingVerdict(
            finding_digest=_digest(
                f"finding:{side}:{receipt.case_id}:{receipt.repeat}:{index}"
            ),
            stage="confirmed_finding",
        )
        for index in range(receipt.confirmed_finding_count)
    )
    return sign_execution_envelope(
        binding,
        observations,
        verdicts,
        private_key=executor_private_key,
    )


def test_keygen_and_ingest_previous_log_create_private_secret_safe_corpus(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "raw-case-name"
    _write_events(run_dir)
    key_path = tmp_path / "lab" / "corpus.key"
    corpus_path = tmp_path / "lab" / "development.json"

    assert cli.main(("keygen", "--output", str(key_path))) == 0
    capsys.readouterr()
    assert (
        cli.main(
            (
                "ingest",
                str(run_dir),
                "--key-file",
                str(key_path),
                "--output",
                str(corpus_path),
            )
        )
        == 0
    )

    payload = corpus_path.read_text(encoding="utf-8")
    assert "private.invalid" not in payload
    assert "secret-route" not in payload
    assert "raw-case-name" not in payload
    assert stat.S_IMODE(key_path.stat().st_mode) == _PRIVATE_FILE_MODE
    assert stat.S_IMODE(corpus_path.stat().st_mode) == _PRIVATE_FILE_MODE
    assert json.loads(payload)["capsules"]

    capsys.readouterr()
    key_path.chmod(0o644)
    assert (
        cli.main(
            (
                "ingest",
                str(run_dir),
                "--key-file",
                str(key_path),
                "--output",
                str(tmp_path / "rejected.json"),
            )
        )
        == _CLI_ERROR
    )
    assert "group or other" in capsys.readouterr().err


def test_executor_keygen_creates_a_distinct_keypair_with_owner_only_private_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    referee_private = tmp_path / "referee.private"
    referee_public = tmp_path / "referee.public"
    executor_private = tmp_path / "executor.private"
    executor_public = tmp_path / "executor.public"

    assert (
        cli.main(
            (
                "referee-keygen",
                "--private-key",
                str(referee_private),
                "--public-key",
                str(referee_public),
            )
        )
        == 0
    )
    capsys.readouterr()
    assert (
        cli.main(
            (
                "executor-keygen",
                "--private-key",
                str(executor_private),
                "--public-key",
                str(executor_public),
            )
        )
        == 0
    )

    assert executor_private.read_bytes() != referee_private.read_bytes()
    assert executor_public.read_bytes() != referee_public.read_bytes()
    assert public_key_from_private(executor_private.read_bytes()) == (
        executor_public.read_bytes()
    )
    assert stat.S_IMODE(executor_private.stat().st_mode) == _PRIVATE_FILE_MODE
    assert stat.S_IMODE(referee_private.stat().st_mode) == _PRIVATE_FILE_MODE
    assert json.loads(capsys.readouterr().out)["created"] is True


def test_cli_rejects_ambiguous_json_configuration(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ambiguous = tmp_path / "ambiguous.json"
    ambiguous.write_text('{"schema_version":1,"schema_version":2}\n', encoding="utf-8")

    assert (
        cli.main(
            (
                "brief",
                "--corpus",
                str(ambiguous),
                "--output",
                str(tmp_path / "brief.json"),
            )
        )
        == _CLI_ERROR
    )
    assert "duplicate key" in capsys.readouterr().err


def test_replay_cli_persists_only_sanitized_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = tmp_path / "key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o600)
    run_root = tmp_path / "prior"
    run_root.mkdir()
    output = tmp_path / "receipt.json"
    payload = {
        "execution_kind": "historical_replay",
        "promotable": False,
        "totals": {"completed_cases": 2, "errored_cases": 0},
    }
    monkeypatch.setattr(
        cli,
        "replay_previous_run",
        lambda *_args, **_kwargs: SimpleNamespace(to_json=lambda: payload),
    )

    assert (
        cli.main(
            (
                "replay",
                str(run_root),
                "--key-file",
                str(key_path),
                "--output",
                str(output),
            )
        )
        == 0
    )
    assert json.loads(output.read_text(encoding="utf-8")) == payload
    assert stat.S_IMODE(output.stat().st_mode) == _PRIVATE_FILE_MODE


def test_brief_cli_derives_versioned_candidate_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "run"
    _write_events(run_dir)
    key_path = tmp_path / "key"
    corpus_path = tmp_path / "corpus.json"
    brief_path = tmp_path / "brief.json"
    assert cli.main(("keygen", "--output", str(key_path))) == 0
    capsys.readouterr()
    assert (
        cli.main(
            (
                "ingest",
                str(run_dir),
                "--key-file",
                str(key_path),
                "--output",
                str(corpus_path),
            )
        )
        == 0
    )
    capsys.readouterr()

    assert (
        cli.main(
            (
                "brief",
                "--corpus",
                str(corpus_path),
                "--output",
                str(brief_path),
            )
        )
        == 0
    )
    brief = json.loads(brief_path.read_text(encoding="utf-8"))
    assert brief["schema_version"] == "ravage.improvement-brief.v1"
    assert str(brief["brief_digest"]).startswith("sha256:")
    assert stat.S_IMODE(brief_path.stat().st_mode) == _PRIVATE_FILE_MODE


def test_campaign_create_requires_and_forwards_a_separate_executor_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _referee_private, referee_public = generate_referee_keypair()
    _executor_private, executor_public = generate_referee_keypair()
    referee_public_path = tmp_path / "referee.public"
    executor_public_path = tmp_path / "executor.public"
    write_referee_key(referee_public_path, referee_public, public=True)
    write_referee_key(executor_public_path, executor_public, public=True)
    evaluation_config = tmp_path / "evaluation-config.json"
    evaluation_suite = tmp_path / "evaluation-suite.json"
    evaluation_config.write_text("{}\n", encoding="utf-8")
    evaluation_suite.write_text("{}\n", encoding="utf-8")
    argv = (
        "campaign-create",
        "--archive",
        str(tmp_path / "archive"),
        "--source",
        str(tmp_path / "source"),
        "--evaluation-config",
        str(evaluation_config),
        "--evaluation-suite",
        str(evaluation_suite),
        "--runner-image",
        f"example.invalid/referee@sha256:{'d' * 64}",
        "--referee-public-key",
        str(referee_public_path),
        "--executor-public-key",
        str(executor_public_path),
        "--candidate-artifact-id",
        f"artifact_{'a' * 24}",
    )
    executor_option = argv.index("--executor-public-key")
    without_executor = argv[:executor_option] + argv[executor_option + 2 :]
    with pytest.raises(SystemExit) as missing:
        cli.build_parser().parse_args(without_executor)
    assert missing.value.code == _CLI_ERROR
    capsys.readouterr()

    captured: dict[str, object] = {}

    def create_campaign(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"campaign_id": f"campaign_{'b' * 24}"}

    archive = SimpleNamespace(
        create_campaign=create_campaign,
        current_pointer=lambda: {"champion_ref": f"source:{'c' * 40}"},
    )
    monkeypatch.setattr(cli, "_verified_archive", lambda _path: archive)
    monkeypatch.setattr(
        cli,
        "require_clean_champion",
        lambda _path: SimpleNamespace(
            head_commit="c" * 40,
            tree_digest="d" * 40,
            status_digest="e" * 64,
        ),
    )

    assert cli.main(argv) == 0
    assert captured["referee_public_key"] == referee_public
    assert captured["executor_public_key"] == executor_public
    assert captured["executor_public_key"] != captured["referee_public_key"]


def test_evaluate_cli_accepts_only_repeated_matched_improvement(tmp_path: Path) -> None:
    archive_path = tmp_path / "archive"
    archive = LabArchive.initialize(archive_path)
    private_key, public_key = generate_referee_keypair()
    executor_private_key, executor_public_key = generate_referee_keypair()
    private_key_path = tmp_path / "referee.private"
    write_referee_key(private_key_path, private_key, public=False)
    champion_inputs: list[dict[str, object]] = []
    candidate_inputs: list[dict[str, object]] = []
    for repeat in range(1, 4):
        champion_inputs.append(
            _run_receipt(
                case_id="opaque-capability",
                repeat=repeat,
                control=False,
                detected=0,
                side="champion",
            )
        )
        candidate_inputs.append(
            _run_receipt(
                case_id="opaque-capability",
                repeat=repeat,
                control=False,
                detected=1,
                side="candidate",
            )
        )
        champion_inputs.append(
            _run_receipt(
                case_id="opaque-control",
                repeat=repeat,
                control=True,
                detected=1,
                side="champion",
            )
        )
        candidate_inputs.append(
            _run_receipt(
                case_id="opaque-control",
                repeat=repeat,
                control=True,
                detected=1,
                side="candidate",
            )
        )
    parsed_champion = tuple(RunReceipt.from_mapping(item) for item in champion_inputs)
    suite = evaluation_suite_from_receipts(
        parsed_champion,
        trusted_tests_digest=f"sha256:{'e' * 64}",
        runner_command=("/usr/local/bin/python", "-I", "/trusted-tests/trusted_referee.py"),
    )
    corpus = candidate_visible_export([])
    corpus_manifest = archive.record_artifact(
        kind="development_corpus",
        visibility="candidate",
        content=json.dumps(corpus).encode(),
    )
    brief_manifest = archive.record_artifact(
        kind="capability_brief",
        visibility="candidate",
        content=json.dumps(build_improvement_brief(corpus)).encode(),
    )
    campaign = archive.create_campaign(
        champion_commit="a" * 40,
        champion_tree="b" * 40,
        source_status_digest=f"sha256:{'c' * 64}",
        evaluation_config=EvaluationConfig().to_json(),
        evaluation_suite=json.dumps(suite.to_json()).encode(),
        runner_image=f"example.invalid/referee@sha256:{'d' * 64}",
        referee_public_key=public_key,
        executor_public_key=executor_public_key,
        proposal_input_artifact_ids=(
            str(corpus_manifest["artifact_id"]),
            str(brief_manifest["artifact_id"]),
        ),
    )
    candidate_manifest = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=str(archive.current_pointer()["champion_ref"]),
        artifact_kind="source_patch",
        patch=b"candidate patch",
        config={"hypothesis": "test"},
    )
    candidate_id = str(candidate_manifest["candidate_id"])
    signed_receipts: dict[str, list[RunReceipt]] = {
        "champion": [],
        "candidate": [],
    }
    for side, inputs in (
        ("champion", champion_inputs),
        ("candidate", candidate_inputs),
    ):
        for item in inputs:
            envelope = _sign_run_receipt(
                RunReceipt.from_mapping(item),
                campaign_id=str(campaign["campaign_id"]),
                candidate_id=candidate_id,
                evaluation_suite_object=str(campaign["evaluation_suite_object"]),
                trusted_tests_digest=suite.trusted_tests_digest,
                runner_image=str(campaign["runner_image"]),
                champion_tree=str(campaign["champion_tree"]),
                executor_private_key=executor_private_key,
                side=side,
            )
            archive.retain_execution_envelope(
                candidate_id,
                signed_envelope=envelope,
            )
            signed_receipts[side].append(envelope.to_run_receipt())
    champion_path = tmp_path / "champion.json"
    candidate_path = tmp_path / "candidate.json"
    output = tmp_path / "evaluation.json"
    champion_path.write_bytes(canonical_run_receipts_bytes(signed_receipts["champion"]))
    candidate_path.write_bytes(canonical_run_receipts_bytes(signed_receipts["candidate"]))

    assert (
        cli.main(
            (
                "evaluate",
                "--champion",
                str(champion_path),
                "--candidate",
                str(candidate_path),
                "--archive",
                str(archive_path),
                "--candidate-id",
                candidate_id,
                "--referee-private-key",
                str(private_key_path),
                "--output",
                str(output),
            )
        )
        == 0
    )
    result = json.loads(output.read_text(encoding="utf-8"))
    receipt = result["receipt"]
    assert receipt["accepted"] is True
    assert receipt["decision"] == "promote"
    assert receipt["rejections"] == []
    assert result["binding"]["candidate_id"] == candidate_id
    assert (
        cli.main(
            (
                "evaluation-add",
                "--archive",
                str(archive_path),
                "--candidate-id",
                candidate_id,
                "--signed-evaluation",
                str(output),
            )
        )
        == 0
    )


def test_receipt_build_retains_signed_envelope_and_writes_canonical_receipt(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    archive_path = tmp_path / "archive"
    archive = LabArchive.initialize(archive_path)
    _referee_private, referee_public = generate_referee_keypair()
    executor_private, executor_public = generate_referee_keypair()
    suite_inputs = tuple(
        RunReceipt.from_mapping(
            _run_receipt(
                case_id="receipt-case",
                repeat=repeat,
                control=False,
                detected=0,
                side="champion",
            )
        )
        for repeat in range(1, 4)
    )
    suite = evaluation_suite_from_receipts(
        suite_inputs,
        trusted_tests_digest=_digest("trusted-tests"),
        runner_command=("/usr/local/bin/python", "-I", "/trusted-tests/referee.py"),
    )
    corpus = candidate_visible_export([])
    corpus_manifest = archive.record_artifact(
        kind="development_corpus",
        visibility="candidate",
        content=json.dumps(corpus).encode(),
    )
    brief_manifest = archive.record_artifact(
        kind="capability_brief",
        visibility="candidate",
        content=json.dumps(build_improvement_brief(corpus)).encode(),
    )
    runner_image = f"example.invalid/referee@sha256:{'d' * 64}"
    campaign = archive.create_campaign(
        champion_commit="a" * 40,
        champion_tree="b" * 40,
        source_status_digest=_digest("clean-source"),
        evaluation_config=EvaluationConfig().to_json(),
        evaluation_suite=json.dumps(suite.to_json()).encode(),
        runner_image=runner_image,
        referee_public_key=referee_public,
        executor_public_key=executor_public,
        proposal_input_artifact_ids=(
            str(corpus_manifest["artifact_id"]),
            str(brief_manifest["artifact_id"]),
        ),
    )
    candidate = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=str(archive.current_pointer()["champion_ref"]),
        artifact_kind="source_patch",
        patch=b"candidate patch",
        config={"hypothesis": "receipt adapter"},
    )
    candidate_id = str(candidate["candidate_id"])

    artifact_root = tmp_path / "artifacts"
    case_root = artifact_root / "case-one"
    traffic_root = case_root / "workspace"
    traffic_root.mkdir(parents=True)
    (case_root / "report.json").write_text(
        json.dumps(
            {
                "findings": [],
                "outcome": {"evidence": []},
                "traffic_accounting": {
                    "status": "exact",
                    "physical_request_count": 4,
                    "incomplete_request_count": 0,
                    "unmetered_action_count": 0,
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (traffic_root / "traffic-policy.json").write_text(
        json.dumps(
            {
                "schema": "ravage.traffic-policy",
                "physical_request_count": 4,
                "incomplete_request_count": 0,
                "unmetered_action_count": 0,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    frozen = freeze_output_tree(artifact_root)
    suite_receipt = suite_inputs[0]
    envelope = sign_execution_envelope(
        ExecutionBinding(
            campaign_id=str(campaign["campaign_id"]),
            candidate_id=candidate_id,
            candidate_tree_digest="f" * 40,
            candidate_content_digest=_digest("candidate-content"),
            evaluation_suite_object=str(campaign["evaluation_suite_object"]),
            trusted_tests_digest=suite.trusted_tests_digest,
            runner_image=runner_image,
            job_spec_digest=_digest("job-spec"),
            artifact_tree_digest=frozen.digest,
            artifact_case_path="case-one",
            case_id=suite_receipt.case_id,
            cohort=suite_receipt.cohort,
            repeat=suite_receipt.repeat,
            execution_kind=suite_receipt.execution_kind,
            evaluation_side="candidate",
            is_control=suite_receipt.is_control,
            expected_vulnerability_count=suite_receipt.expected_vulnerability_count,
            run_id=_digest("candidate-run"),
            pair_seed_digest=suite_receipt.pair_seed_digest,
            target_snapshot_digest=suite_receipt.target_snapshot_digest,
            model_fingerprint=suite_receipt.model_fingerprint,
            prompt_fingerprint=_digest("candidate-prompt"),
        ),
        ExternalRunObservations(
            status="completed",
            case_success=False,
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
        (),
        private_key=executor_private,
    )
    envelope_path = tmp_path / "execution-envelope.json"
    receipt_path = tmp_path / "receipt.json"
    write_signed_execution_envelope(envelope_path, envelope)

    assert (
        cli.main(
            (
                "receipt-build",
                "--archive",
                str(archive_path),
                "--candidate-id",
                candidate_id,
                "--artifacts",
                str(artifact_root),
                "--execution-envelope",
                str(envelope_path),
                "--output",
                str(receipt_path),
            )
        )
        == 0
    )

    expected_receipt = envelope.to_run_receipt()
    assert receipt_path.read_bytes() == canonical_run_receipts_bytes((expected_receipt,))
    assert stat.S_IMODE(receipt_path.stat().st_mode) == _PRIVATE_FILE_MODE
    assert archive.read_object(
        str(expected_receipt.execution_attestation_digest)
    ) == canonical_execution_envelope_bytes(envelope)
    result = json.loads(capsys.readouterr().out)
    assert result["case_id"] == suite_receipt.case_id
    assert result["evaluation_side"] == "candidate"
    assert result["execution_attestation_digest"] == (
        expected_receipt.execution_attestation_digest
    )
    assert str(result["artifact_id"]).startswith("artifact_")


def test_archive_cli_records_and_verifies_immutable_artifact(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    archive = tmp_path / "archive"
    brief = tmp_path / "brief.json"
    brief.write_text(json.dumps(candidate_visible_export([])) + "\n", encoding="utf-8")

    assert cli.main(("archive-init", "--archive", str(archive))) == 0
    capsys.readouterr()
    assert (
        cli.main(
            (
                "artifact-add",
                "--archive",
                str(archive),
                "--kind",
                "development_corpus",
                "--visibility",
                "candidate",
                "--file",
                str(brief),
            )
        )
        == 0
    )
    recorded = json.loads(capsys.readouterr().out)
    assert str(recorded["artifact_id"]).startswith("artifact_")

    assert cli.main(("archive-verify", "--archive", str(archive))) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["artifacts"] == 1
    assert verified["ledger_events"] == 1

    ledger_head = str(verified["ledger_head"])
    archive_checkpoint = str(verified["archive_checkpoint"])
    assert (
        cli.main(
            (
                "archive-verify",
                "--archive",
                str(archive),
                "--expected-head",
                archive_checkpoint,
            )
        )
        == 0
    )
    capsys.readouterr()

    wrong_head = f"sha256:{'0' * 64}"
    if wrong_head == ledger_head:
        wrong_head = f"sha256:{'1' * 64}"
    assert (
        cli.main(
            (
                "archive-verify",
                "--archive",
                str(archive),
                "--expected-head",
                wrong_head,
            )
        )
        == _CLI_ERROR
    )
    assert "external checkpoint" in capsys.readouterr().err

    manifest = archive / "manifests" / "artifacts" / f"{recorded['artifact_id']}.json"
    manifest.unlink()
    assert cli.main(("archive-verify", "--archive", str(archive))) == _CLI_ERROR
    capsys.readouterr()
    assert cli.main(("archive-recover", "--archive", str(archive))) == 0
    recovered = json.loads(capsys.readouterr().out)
    assert recovered["artifacts"] == 1
    assert recovered["ledger_head"] == ledger_head
    assert recovered["archive_checkpoint"] == archive_checkpoint


def test_ingest_recursively_discovers_nested_runs_without_basename_collisions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    panel = tmp_path / "panel"
    _write_events(panel / "group-a" / "same-case", turn=1)
    _write_events(panel / "group-b" / "same-case", turn=2)
    key = tmp_path / "key"
    output = tmp_path / "corpus.json"
    _write_private_key(key)

    assert (
        cli.main(
            (
                "ingest",
                str(panel),
                "--key-file",
                str(key),
                "--output",
                str(output),
            )
        )
        == 0
    )

    report = json.loads(capsys.readouterr().out)
    capsules = json.loads(output.read_text(encoding="utf-8"))["capsules"]
    assert report["capsules"] == _TWO_CAPSULES
    assert len({capsule["case_id"] for capsule in capsules}) == _TWO_CAPSULES
    assert len({capsule["run_id"] for capsule in capsules}) == _TWO_CAPSULES


def test_ingest_rejects_duplicate_run_content_from_distinct_paths(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    panel = tmp_path / "panel"
    _write_events(panel / "a" / "same-case")
    _write_events(panel / "b" / "same-case")
    key = tmp_path / "key"
    output = tmp_path / "corpus.json"
    _write_private_key(key)

    assert (
        cli.main(
            (
                "ingest",
                str(panel),
                "--key-file",
                str(key),
                "--output",
                str(output),
            )
        )
        == _CLI_ERROR
    )
    assert "duplicate run content" in capsys.readouterr().err
    assert not output.exists()


def test_ingest_fails_closed_on_nested_symlinked_event_stream(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    external = tmp_path / "external"
    _write_events(external)
    panel_workspace = tmp_path / "panel" / "nested" / "case" / "workspace"
    panel_workspace.mkdir(parents=True)
    (panel_workspace / "events.jsonl").symlink_to(external / "workspace" / "events.jsonl")
    key = tmp_path / "key"
    output = tmp_path / "corpus.json"
    _write_private_key(key)

    assert (
        cli.main(
            (
                "ingest",
                str(tmp_path / "panel"),
                "--key-file",
                str(key),
                "--output",
                str(output),
            )
        )
        == _CLI_ERROR
    )
    assert "symlinked entries" in capsys.readouterr().err
    assert not output.exists()


def test_recursive_discovery_rejects_ambiguous_run_streams(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run = tmp_path / "panel" / "run"
    _write_events(run)
    (run / "events.jsonl").write_text("", encoding="utf-8")
    key = tmp_path / "key"
    _write_private_key(key)

    assert (
        cli.main(
            (
                "ingest",
                str(tmp_path / "panel"),
                "--key-file",
                str(key),
                "--output",
                str(tmp_path / "corpus.json"),
            )
        )
        == _CLI_ERROR
    )
    assert "ambiguous events streams" in capsys.readouterr().err


def test_ingest_rejects_unsafe_taint_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for kind in ("permissions", "symlink", "hardlink", "fifo"):
        case_root = tmp_path / kind
        case_root.mkdir()
        run = case_root / "run"
        _write_events(run)
        key = case_root / "key"
        _write_private_key(key)
        base = case_root / "base-taint"
        base.write_bytes(b"private-marker\n")
        base.chmod(0o600)
        taint = case_root / "taint"
        if kind == "permissions":
            taint.write_bytes(b"private-marker\n")
            taint.chmod(0o644)
        elif kind == "symlink":
            taint.symlink_to(base)
        elif kind == "hardlink":
            os.link(base, taint)
        else:
            os.mkfifo(taint)
            taint.chmod(0o600)

        assert (
            cli.main(
                (
                    "ingest",
                    str(run),
                    "--key-file",
                    str(key),
                    "--taint-file",
                    str(taint),
                    "--output",
                    str(case_root / "corpus.json"),
                )
            )
            == _CLI_ERROR
        )
        assert "taint file" in capsys.readouterr().err
        assert not (case_root / "corpus.json").exists()


def test_ingest_accepts_an_owner_only_regular_taint_file(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_events(run)
    key = tmp_path / "key"
    _write_private_key(key)
    taint = tmp_path / "taint"
    taint.write_bytes(b"private-marker\n")
    taint.chmod(0o600)
    output = tmp_path / "corpus.json"

    assert (
        cli.main(
            (
                "ingest",
                str(run),
                "--key-file",
                str(key),
                "--taint-file",
                str(taint),
                "--output",
                str(output),
            )
        )
        == 0
    )
    assert output.is_file()


def test_ingest_refuses_stale_development_and_sealed_outputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run = tmp_path / "run"
    _write_events(run)
    key = tmp_path / "key"
    _write_private_key(key)
    development = tmp_path / "development.json"
    development.write_text("sentinel", encoding="utf-8")
    sealed = tmp_path / "sealed"
    sealed.mkdir()
    sentinel = sealed / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")

    assert (
        cli.main(
            (
                "ingest",
                str(run),
                "--key-file",
                str(key),
                "--output",
                str(development),
            )
        )
        == _CLI_ERROR
    )
    assert development.read_text(encoding="utf-8") == "sentinel"
    capsys.readouterr()

    assert (
        cli.main(
            (
                "ingest",
                str(run),
                "--key-file",
                str(key),
                "--partition",
                "sealed_holdout",
                "--output",
                str(sealed),
            )
        )
        == _CLI_ERROR
    )
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert len(tuple(sealed.iterdir())) == 1
    assert "refusing to reuse" in capsys.readouterr().err


def test_sealed_multi_capsule_publish_is_transactional(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panel = tmp_path / "panel"
    _write_events(panel / "one", turn=1)
    _write_events(panel / "two", turn=2)
    key = tmp_path / "key"
    _write_private_key(key)
    sealed = tmp_path / "sealed"
    real_write = cli.write_capsule
    writes = 0

    def fail_second_write(
        destination: Path,
        capsule: dict[str, object],
        *,
        taints: tuple[bytes, ...],
    ) -> Path:
        nonlocal writes
        writes += 1
        if writes == _SECOND_WRITE:
            raise CorpusFormatError(_INJECTED_WRITE_FAILURE)
        return real_write(destination, capsule, taints=taints)

    monkeypatch.setattr(cli, "write_capsule", fail_second_write)
    assert (
        cli.main(
            (
                "ingest",
                str(panel),
                "--key-file",
                str(key),
                "--partition",
                "sealed_holdout",
                "--output",
                str(sealed),
            )
        )
        == _CLI_ERROR
    )
    assert _INJECTED_WRITE_FAILURE in capsys.readouterr().err
    assert not sealed.exists()
    assert not tuple(tmp_path.glob(".sealed.*.staging"))
