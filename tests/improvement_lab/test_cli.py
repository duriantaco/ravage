from __future__ import annotations

import hashlib
import json
import os
import stat
from types import SimpleNamespace
from typing import TYPE_CHECKING

from tools.improvement_lab import cli
from tools.improvement_lab.archive import LabArchive
from tools.improvement_lab.attestation import generate_referee_keypair, write_referee_key
from tools.improvement_lab.corpus import CorpusFormatError, candidate_visible_export
from tools.improvement_lab.evaluation import (
    EvaluationConfig,
    RunReceipt,
    evaluation_suite_from_receipts,
)
from tools.improvement_lab.lessons import build_improvement_brief

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

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


def _run_receipt(
    *,
    case_id: str,
    repeat: int,
    control: bool,
    detected: int,
    side: str,
) -> dict[str, object]:
    def digest(value: str) -> str:
        return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"

    return {
        "case_id": case_id,
        "cohort": "control" if control else "capability",
        "repeat": repeat,
        "execution_kind": "fixture",
        "status": "completed",
        "is_control": control,
        "case_success": bool(detected),
        "expected_vulnerability_count": 1,
        "run_id": digest(f"run:{side}:{case_id}:{repeat}"),
        "pair_seed_digest": digest(f"seed:{case_id}:{repeat}"),
        "target_snapshot_digest": digest(f"target:{case_id}"),
        "model_fingerprint": digest("model:fixed"),
        "prompt_fingerprint": digest(f"prompt:{side}"),
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


def test_evaluate_cli_accepts_only_repeated_matched_improvement(tmp_path: Path) -> None:
    archive_path = tmp_path / "archive"
    archive = LabArchive.initialize(archive_path)
    private_key, public_key = generate_referee_keypair()
    private_key_path = tmp_path / "referee.private"
    write_referee_key(private_key_path, private_key, public=False)
    champion: list[dict[str, object]] = []
    candidate: list[dict[str, object]] = []
    for repeat in range(1, 4):
        champion.append(
            _run_receipt(
                case_id="opaque-capability",
                repeat=repeat,
                control=False,
                detected=0,
                side="champion",
            )
        )
        candidate.append(
            _run_receipt(
                case_id="opaque-capability",
                repeat=repeat,
                control=False,
                detected=1,
                side="candidate",
            )
        )
        champion.append(
            _run_receipt(
                case_id="opaque-control",
                repeat=repeat,
                control=True,
                detected=1,
                side="champion",
            )
        )
        candidate.append(
            _run_receipt(
                case_id="opaque-control",
                repeat=repeat,
                control=True,
                detected=1,
                side="candidate",
            )
        )
    parsed_champion = tuple(RunReceipt.from_mapping(item) for item in champion)
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
    champion_path = tmp_path / "champion.json"
    candidate_path = tmp_path / "candidate.json"
    output = tmp_path / "evaluation.json"
    champion_path.write_text(json.dumps(champion), encoding="utf-8")
    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")

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
