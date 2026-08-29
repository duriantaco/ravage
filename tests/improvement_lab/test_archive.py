from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from tools.improvement_lab.archive import (
    APPROVAL_SCHEMA_VERSION,
    ArchiveError,
    LabArchive,
)
from tools.improvement_lab.attestation import public_key_from_private, sign_evaluation
from tools.improvement_lab.corpus import candidate_visible_export
from tools.improvement_lab.evaluation import (
    EvaluationConfig,
    EvaluationReceipt,
    RunReceipt,
    evaluate_candidate,
    evaluation_suite_from_receipts,
)
from tools.improvement_lab.lessons import build_improvement_brief

if TYPE_CHECKING:
    from pathlib import Path

_PRIVATE_DIRECTORY_MODE = 0o700
_CHAMPION_COMMIT = "a" * 40
_CHAMPION_TREE = "b" * 40
_STATUS_DIGEST = f"sha256:{'c' * 64}"
_REFEREE_PRIVATE_KEY = b"r" * 32
_REFEREE_PUBLIC_KEY = public_key_from_private(_REFEREE_PRIVATE_KEY)
_RUNNER_IMAGE = f"example.invalid/referee@sha256:{'d' * 64}"
_TWO_CANDIDATES = 2
_THREE_ARTIFACTS = 3
_FIVE_LEDGER_EVENTS = 5
_SIX_LEDGER_EVENTS = 6
_CONCURRENT_OBJECTS = 20


def _archive(tmp_path: Path) -> LabArchive:
    return LabArchive.initialize(tmp_path / "improvement-archive")


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _run_receipt(
    *,
    case_id: str,
    repeat: int,
    control: bool,
    side: str,
    detected: int,
) -> RunReceipt:
    expected = 0 if control else 1
    return RunReceipt.from_mapping(
        {
            "case_id": case_id,
            "cohort": "control" if control else "capability",
            "repeat": repeat,
            "execution_kind": "fixture",
            "status": "completed",
            "is_control": control,
            "case_success": True if control else bool(detected),
            "expected_vulnerability_count": expected,
            "run_id": _digest(f"run:{side}:{case_id}:{repeat}"),
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
                "physical_request_count": 10,
                "model_request_count": 2,
                "cost_usd": 0.1,
                "request_accounting_status": "exact",
            },
        }
    )


def _receipt_sets(*, accepted: bool) -> tuple[tuple[RunReceipt, ...], tuple[RunReceipt, ...]]:
    champion: list[RunReceipt] = []
    candidate: list[RunReceipt] = []
    for repeat in range(1, 4):
        champion.append(
            _run_receipt(
                case_id="capability-case",
                repeat=repeat,
                control=False,
                side="champion",
                detected=0,
            )
        )
        candidate.append(
            _run_receipt(
                case_id="capability-case",
                repeat=repeat,
                control=False,
                side="candidate",
                detected=1 if accepted else 0,
            )
        )
        for side, output in (("champion", champion), ("candidate", candidate)):
            output.append(
                _run_receipt(
                    case_id="control-case",
                    repeat=repeat,
                    control=True,
                    side=side,
                    detected=0,
                )
            )
    return tuple(champion), tuple(candidate)


def _suite_bytes(tag: str = "sealed-a") -> bytes:
    champion, _candidate = _receipt_sets(accepted=True)
    suite = evaluation_suite_from_receipts(
        champion,
        trusted_tests_digest=_digest(f"tests:{tag}"),
        runner_command=("/usr/local/bin/python", "-I", "/trusted-tests/trusted_referee.py"),
    )
    return json.dumps(suite.to_json(), sort_keys=True, separators=(",", ":")).encode()


def _proposal_inputs(archive: LabArchive) -> tuple[str, str]:
    corpus = candidate_visible_export([])
    brief = build_improvement_brief(corpus)
    corpus_manifest = archive.record_artifact(
        kind="development_corpus",
        visibility="candidate",
        content=(json.dumps(corpus, sort_keys=True) + "\n").encode(),
    )
    brief_manifest = archive.record_artifact(
        kind="capability_brief",
        visibility="candidate",
        content=(json.dumps(brief, sort_keys=True) + "\n").encode(),
    )
    return str(corpus_manifest["artifact_id"]), str(brief_manifest["artifact_id"])


def _campaign(archive: LabArchive) -> dict[str, object]:
    return archive.create_campaign(
        champion_commit=_CHAMPION_COMMIT,
        champion_tree=_CHAMPION_TREE,
        source_status_digest=_STATUS_DIGEST,
        evaluation_config=EvaluationConfig().to_json(),
        evaluation_suite=_suite_bytes(),
        runner_image=_RUNNER_IMAGE,
        referee_public_key=_REFEREE_PUBLIC_KEY,
        proposal_input_artifact_ids=_proposal_inputs(archive),
    )


def _signed_evaluation(
    archive: LabArchive,
    candidate_id: str,
    *,
    accepted: bool,
) -> dict[str, object]:
    champion, candidate = _receipt_sets(accepted=accepted)
    binding = archive.prepare_evaluation_binding(
        candidate_id,
        champion_receipts=champion,
        candidate_receipts=candidate,
    )
    receipt = evaluate_candidate(
        champion,
        candidate,
        config=archive.campaign_evaluation_config(candidate_id),
        suite=archive.campaign_evaluation_suite(candidate_id),
    )
    assert receipt.accepted is accepted
    return sign_evaluation(
        receipt,
        binding,
        private_key=_REFEREE_PRIVATE_KEY,
    ).to_json()


def test_archive_objects_are_content_addressed_and_idempotent(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    first = archive.put_bytes(b"candidate patch")
    second = archive.put_bytes(b"candidate patch")

    assert first == second
    assert first.digest.startswith("sha256:")
    assert stat.S_IMODE(archive.root.stat().st_mode) == _PRIVATE_DIRECTORY_MODE
    assert archive.read_object(first.digest) == b"candidate patch"
    verification = archive.verify()
    assert verification.objects == 1
    assert verification.object_bytes == len(b"candidate patch")
    assert verification.verified_bytes >= verification.object_bytes


def test_archive_records_candidate_and_sealed_evaluator_artifacts(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    development = archive.record_artifact(
        kind="development_corpus",
        visibility="candidate",
        content=(json.dumps(candidate_visible_export([])) + "\n").encode(),
    )
    brief_payload = build_improvement_brief(candidate_visible_export([]))
    brief = archive.record_artifact(
        kind="capability_brief",
        visibility="candidate",
        content=(json.dumps(brief_payload) + "\n").encode(),
    )
    sealed = archive.record_artifact(
        kind="sealed_capsule",
        visibility="sealed_evaluator",
        content=b"sealed capsule",
    )

    assert development["artifact_id"] != sealed["artifact_id"]
    assert archive.verify().artifacts == _THREE_ARTIFACTS
    with pytest.raises(ArchiveError, match="cannot be candidate-visible"):
        archive.record_artifact(
            kind="sealed_capsule",
            visibility="candidate",
            content=b"unsafe",
        )

    view = archive.materialize_candidate_view(
        [str(development["artifact_id"]), str(brief["artifact_id"])],
        tmp_path / "candidate-view",
    )
    assert (view / ".improvement-candidate-view.json").is_file()
    with pytest.raises(ArchiveError, match="sealed evaluator"):
        archive.materialize_candidate_view(
            [str(development["artifact_id"]), str(sealed["artifact_id"])],
            tmp_path / "sealed-view",
        )


def test_archive_keeps_every_candidate_and_hash_chained_event(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    parent = archive.current_pointer()["champion_ref"]
    first = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=str(parent),
        artifact_kind="source_patch",
        patch=b"patch one",
        config={"idea": 1},
    )
    second = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=str(parent),
        artifact_kind="source_patch",
        patch=b"patch two",
        config={"idea": 2},
    )

    assert first["candidate_id"] != second["candidate_id"]
    verification = archive.verify()
    assert verification.candidates == _TWO_CANDIDATES
    assert verification.ledger_events == _FIVE_LEDGER_EVENTS
    assert verification.ledger_head.startswith("sha256:")


def test_human_approval_advances_only_lab_pointer_with_cas(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    original_ref = str(archive.current_pointer()["champion_ref"])
    candidate = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=original_ref,
        artifact_kind="policy_patch",
        patch=b"policy",
        config={},
    )
    evaluation = archive.record_evaluation(
        candidate_id=str(candidate["candidate_id"]),
        signed_evaluation=_signed_evaluation(
            archive,
            str(candidate["candidate_id"]),
            accepted=True,
        ),
    )
    approval = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "decision": "accept",
        "candidate_id": candidate["candidate_id"],
        "evaluation_id": evaluation["evaluation_id"],
        "reviewer": "operator",
        "approved_at": "2026-08-26T00:00:00+00:00",
        "statement": "Reviewed the patch and matched evaluation receipt.",
    }

    updated = archive.accept_candidate(
        candidate_id=str(candidate["candidate_id"]),
        evaluation_id=str(evaluation["evaluation_id"]),
        expected_champion_ref=original_ref,
        approval=approval,
    )

    assert updated["champion_ref"] == f"candidate:{candidate['candidate_id']}"
    retried = archive.accept_candidate(
        candidate_id=str(candidate["candidate_id"]),
        evaluation_id=str(evaluation["evaluation_id"]),
        expected_champion_ref=original_ref,
        approval=approval,
    )
    assert retried == updated
    conflicting_approval = {
        **approval,
        "statement": "A different approval must not rewrite committed history.",
    }
    with pytest.raises(ArchiveError, match="acceptance conflicts with this retry"):
        archive.accept_candidate(
            candidate_id=str(candidate["candidate_id"]),
            evaluation_id=str(evaluation["evaluation_id"]),
            expected_champion_ref=original_ref,
            approval=conflicting_approval,
        )
    assert archive.verify().ledger_events == _SIX_LEDGER_EVENTS


def test_rejected_evaluation_cannot_advance_pointer(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    parent = str(archive.current_pointer()["champion_ref"])
    candidate = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=parent,
        artifact_kind="knowledge_pack",
        patch=b"knowledge",
        config={},
    )
    evaluation = archive.record_evaluation(
        candidate_id=str(candidate["candidate_id"]),
        signed_evaluation=_signed_evaluation(
            archive,
            str(candidate["candidate_id"]),
            accepted=False,
        ),
    )
    approval = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "decision": "accept",
        "candidate_id": candidate["candidate_id"],
        "evaluation_id": evaluation["evaluation_id"],
        "reviewer": "operator",
        "approved_at": "2026-08-26T00:00:00+00:00",
        "statement": "Should not be accepted.",
    }

    with pytest.raises(ArchiveError, match="accepted matching evaluation"):
        archive.accept_candidate(
            candidate_id=str(candidate["candidate_id"]),
            evaluation_id=str(evaluation["evaluation_id"]),
            expected_champion_ref=parent,
            approval=approval,
        )


def test_archive_rejects_self_attested_evaluation_mapping(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    candidate = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=str(archive.current_pointer()["champion_ref"]),
        artifact_kind="source_patch",
        patch=b"candidate",
        config={},
    )

    with pytest.raises(ArchiveError, match="candidate-bound referee attestation"):
        archive.record_evaluation(
            candidate_id=str(candidate["candidate_id"]),
            signed_evaluation={
                "accepted": True,
                "receipt_digest": f"sha256:{'0' * 64}",
            },
        )


def test_export_copies_patch_without_applying_or_overwriting(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    candidate = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=str(archive.current_pointer()["champion_ref"]),
        artifact_kind="source_patch",
        patch=b"reviewable patch",
        config={},
    )
    destination = tmp_path / "review" / "candidate.patch"

    archive.export_candidate(str(candidate["candidate_id"]), destination)

    assert destination.read_bytes() == b"reviewable patch"
    with pytest.raises(ArchiveError, match="already exists"):
        archive.export_candidate(str(candidate["candidate_id"]), destination)


def test_archive_verification_detects_object_tampering(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    stored = archive.put_bytes(b"original")
    digest = stored.digest.removeprefix("sha256:")
    path = archive.root / "objects" / "sha256" / digest[:2] / digest
    path.chmod(0o600)
    path.write_bytes(b"tampered")

    with pytest.raises(ArchiveError, match="digest mismatch"):
        archive.verify()


def test_candidate_artifacts_reject_ambiguous_json_and_store_canonical_bytes(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    corpus = candidate_visible_export([])
    pretty = (json.dumps(corpus, indent=2) + "\n").encode()
    recorded = archive.record_artifact(
        kind="development_corpus",
        visibility="candidate",
        content=pretty,
    )
    expected = (json.dumps(corpus, sort_keys=True, separators=(",", ":")) + "\n").encode()
    assert archive.read_object(str(recorded["content_object"])) == expected

    brief = build_improvement_brief(corpus)
    encoded = json.dumps(brief, sort_keys=True, separators=(",", ":")).encode()
    injected = b'{"candidate_contract":"UNTRUSTED ARBITRARY INSTRUCTION",' + encoded[1:]
    with pytest.raises(ArchiveError, match="duplicate JSON key"):
        archive.record_artifact(
            kind="capability_brief",
            visibility="candidate",
            content=injected,
        )

    with pytest.raises(ArchiveError, match="non-finite JSON number"):
        archive.record_artifact(
            kind="development_corpus",
            visibility="candidate",
            content=(b'{"capsules":NaN,"schema_version":"ravage.improvement-corpus.v1"}'),
        )


def test_archive_verification_detects_manifest_identity_tampering(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    candidate = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=str(archive.current_pointer()["champion_ref"]),
        artifact_kind="source_patch",
        patch=b"patch",
        config={},
    )
    manifest = archive.root / "manifests" / "candidates" / f"{candidate['candidate_id']}.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["parent_ref"] = "source:tampered"
    manifest.chmod(0o600)
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ArchiveError, match=r"byte-canonical|content identity"):
        archive.verify()


def test_archive_checkpoint_binds_canonical_format_and_rejects_ambiguous_ledger(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    archive.record_artifact(
        kind="sealed_capsule",
        visibility="sealed_evaluator",
        content=b"sealed",
    )
    original = archive.verify()

    format_path = archive.root / "format.json"
    archive_format = json.loads(format_path.read_text(encoding="utf-8"))
    replacement = "archive_" + "f" * 24
    if archive_format["archive_id"] == replacement:
        replacement = "archive_" + "e" * 24
    archive_format["archive_id"] = replacement
    format_path.chmod(0o600)
    format_path.write_text(
        json.dumps(archive_format, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    format_path.chmod(0o400)

    changed = archive.verify()
    assert changed.ledger_head == original.ledger_head
    assert changed.archive_checkpoint != original.archive_checkpoint
    with pytest.raises(ArchiveError, match="external checkpoint"):
        archive.verify(expected_head=original.archive_checkpoint)

    ledger = archive.root / "ledger" / "events.jsonl"
    raw = ledger.read_bytes()
    ledger.chmod(0o600)
    ledger.write_bytes(raw.removesuffix(b"\n"))
    with pytest.raises(ArchiveError, match="byte-canonical"):
        archive.verify(expected_head=changed.archive_checkpoint)

    ledger.write_bytes(b'{"sequence":999,' + raw[1:])
    with pytest.raises(ArchiveError, match="duplicate JSON key"):
        archive.verify(expected_head=changed.archive_checkpoint)


def test_archive_verification_reconciles_ledger_manifests_and_pointer(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    artifact = archive.record_artifact(
        kind="development_corpus",
        visibility="candidate",
        content=(json.dumps(candidate_visible_export([])) + "\n").encode(),
    )
    manifest = archive.root / "manifests" / "artifacts" / f"{artifact['artifact_id']}.json"
    manifest.unlink()
    with pytest.raises(ArchiveError, match=r"missing manifest|coverage"):
        archive.verify()
    archive.recover()
    assert archive.verify().artifacts == 1

    second = _archive(tmp_path / "pointer-case")
    _campaign(second)
    pointer_path = second.root / "refs" / "lab-champion.json"
    payload = json.loads(pointer_path.read_text(encoding="utf-8"))
    payload["champion_ref"] = f"source:{'f' * 40}"
    pointer_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ArchiveError, match=r"byte-canonical|reconstructed ledger history"):
        second.verify()
    second.recover()
    assert second.verify().campaigns == 1


def test_archive_recovery_completes_in_a_bounded_child_process(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    program = (
        "import sys; from pathlib import Path; "
        "from tools.improvement_lab.archive import LabArchive; "
        "LabArchive.open(Path(sys.argv[1])).recover()"
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", program, os.fspath(archive.root)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert completed.returncode == 0, completed.stderr


def test_archive_concurrent_recovery_and_object_writes_complete(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    program = f"""
import sys
from pathlib import Path
from tools.improvement_lab.archive import LabArchive

archive = LabArchive.open(Path(sys.argv[1]))
if sys.argv[2] == "put":
    for index in range({_CONCURRENT_OBJECTS}):
        archive.put_bytes(("concurrent-object-" + str(index)).encode())
else:
    for _index in range({_CONCURRENT_OBJECTS}):
        archive.recover()
"""
    processes = [
        subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", program, os.fspath(archive.root), action],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for action in ("put", "recover", "put", "recover")
    ]
    try:
        for process in processes:
            _stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    assert archive.verify().objects == _CONCURRENT_OBJECTS


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
@pytest.mark.parametrize(
    ("lock_name", "operation"),
    [(".lock", "recover"), (".objects.lock", "put_bytes")],
)
def test_archive_lock_substitution_fails_closed(
    tmp_path: Path,
    link_kind: str,
    lock_name: str,
    operation: str,
) -> None:
    archive = _archive(tmp_path)
    external = tmp_path / f"external-{lock_name.removeprefix('.')}"
    external.write_bytes(b"")
    external.chmod(0o600)
    lock_path = archive.ledger_root / lock_name
    lock_path.unlink()
    if link_kind == "symlink":
        lock_path.symlink_to(external)
    else:
        os.link(external, lock_path)

    def invoke_operation() -> None:
        if operation == "recover":
            archive.recover()
        else:
            archive.put_bytes(b"object")

    with pytest.raises(ArchiveError, match="archive lock"):
        invoke_operation()
    with pytest.raises(ArchiveError, match="archive lock"):
        archive.verify()


def test_archive_recovery_repairs_partial_projections_and_publication_temps(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    _campaign(archive)
    stored = archive.put_bytes(b"object publication window")
    digest_hex = stored.digest.removeprefix("sha256:")
    object_path = archive.root / "objects" / "sha256" / digest_hex[:2] / digest_hex
    object_temp = object_path.with_name(f".{digest_hex}.1234.deadbeef")
    os.link(object_path, object_temp)

    artifact_manifest = next((archive.root / "manifests" / "artifacts").glob("*.json"))
    artifact_manifest.chmod(0o600)
    artifact_manifest.write_bytes(b"")
    artifact_manifest.chmod(0o400)
    manifest_temp = artifact_manifest.with_name(f".{artifact_manifest.name}.1234.deadbeef")
    manifest_temp.write_bytes(b"partial")
    manifest_temp.chmod(0o400)

    pointer = archive.root / "refs" / "lab-champion.json"
    pointer.chmod(0o600)
    pointer.write_bytes(b"{")
    pointer_temp = pointer.with_name(f".{pointer.name}.1234.deadbeef")
    pointer_temp.write_bytes(b"partial")
    pointer_temp.chmod(0o600)

    ledger = archive.root / "ledger" / "events.jsonl"
    ledger_temp = ledger.with_name(f".{ledger.name}.1234.deadbeef")
    ledger_temp.write_bytes(b"partial")
    ledger_temp.chmod(0o600)

    archive.recover()

    assert not object_temp.exists()
    assert object_path.stat().st_nlink == 1
    assert not manifest_temp.exists()
    assert not pointer_temp.exists()
    assert not ledger_temp.exists()
    assert artifact_manifest.stat().st_size > 0
    assert archive.current_pointer()["campaign_id"]
    archive.verify()


def test_archive_completed_retries_are_idempotent(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    inputs = _proposal_inputs(archive)
    arguments = {
        "champion_commit": _CHAMPION_COMMIT,
        "champion_tree": _CHAMPION_TREE,
        "source_status_digest": _STATUS_DIGEST,
        "evaluation_config": EvaluationConfig().to_json(),
        "evaluation_suite": _suite_bytes(),
        "runner_image": _RUNNER_IMAGE,
        "referee_public_key": _REFEREE_PUBLIC_KEY,
        "proposal_input_artifact_ids": inputs,
    }
    first_campaign = archive.create_campaign(**arguments)
    assert archive.create_campaign(**arguments) == first_campaign
    pointer_path = archive.root / "refs" / "lab-champion.json"
    pointer_path.unlink()
    assert archive.create_campaign(**arguments) == first_campaign
    assert pointer_path.is_file()
    parent = str(archive.current_pointer()["champion_ref"])
    candidate_arguments = {
        "campaign_id": str(first_campaign["campaign_id"]),
        "parent_ref": parent,
        "artifact_kind": "source_patch",
        "patch": b"retry patch",
        "config": {"hypothesis": "retry"},
    }
    candidate = archive.register_candidate(**candidate_arguments)
    assert archive.register_candidate(**candidate_arguments) == candidate
    signed = _signed_evaluation(
        archive,
        str(candidate["candidate_id"]),
        accepted=True,
    )
    evaluation = archive.record_evaluation(
        candidate_id=str(candidate["candidate_id"]),
        signed_evaluation=signed,
    )
    assert (
        archive.record_evaluation(
            candidate_id=str(candidate["candidate_id"]),
            signed_evaluation=signed,
        )
        == evaluation
    )
    assert archive.verify().ledger_events == _FIVE_LEDGER_EVENTS


def test_candidate_brief_must_be_strict_and_match_its_exact_corpus(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    corpus = candidate_visible_export([])
    corpus_manifest = archive.record_artifact(
        kind="development_corpus",
        visibility="candidate",
        content=json.dumps(corpus).encode(),
    )
    brief = build_improvement_brief(corpus)
    brief["candidate_contract"]["promotion_authority"] = "embedded-sensitive-override"
    unsigned = {key: value for key, value in brief.items() if key != "brief_digest"}
    brief["brief_digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    with pytest.raises(ArchiveError, match="capability brief is malformed"):
        archive.record_artifact(
            kind="capability_brief",
            visibility="candidate",
            content=json.dumps(brief).encode(),
        )

    valid_brief = build_improvement_brief(corpus)
    valid_brief["dataset_digest"] = f"sha256:{'9' * 64}"
    unsigned = {key: value for key, value in valid_brief.items() if key != "brief_digest"}
    valid_brief["brief_digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    brief_manifest = archive.record_artifact(
        kind="capability_brief",
        visibility="candidate",
        content=json.dumps(valid_brief).encode(),
    )
    with pytest.raises(ArchiveError, match="does not match its exact corpus"):
        archive.create_campaign(
            champion_commit=_CHAMPION_COMMIT,
            champion_tree=_CHAMPION_TREE,
            source_status_digest=_STATUS_DIGEST,
            evaluation_config=EvaluationConfig().to_json(),
            evaluation_suite=_suite_bytes(),
            runner_image=_RUNNER_IMAGE,
            referee_public_key=_REFEREE_PUBLIC_KEY,
            proposal_input_artifact_ids=(
                str(corpus_manifest["artifact_id"]),
                str(brief_manifest["artifact_id"]),
            ),
        )


def test_stale_sibling_cannot_replace_accepted_candidate(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    parent = str(archive.current_pointer()["champion_ref"])
    candidates = [
        archive.register_candidate(
            campaign_id=str(campaign["campaign_id"]),
            parent_ref=parent,
            artifact_kind="source_patch",
            patch=f"patch-{index}".encode(),
            config={"index": index},
        )
        for index in range(2)
    ]
    evaluations = [
        archive.record_evaluation(
            candidate_id=str(candidate["candidate_id"]),
            signed_evaluation=_signed_evaluation(
                archive,
                str(candidate["candidate_id"]),
                accepted=True,
            ),
        )
        for candidate in candidates
    ]

    def approval(index: int) -> dict[str, object]:
        return {
            "schema_version": APPROVAL_SCHEMA_VERSION,
            "decision": "accept",
            "candidate_id": candidates[index]["candidate_id"],
            "evaluation_id": evaluations[index]["evaluation_id"],
            "reviewer": "operator",
            "approved_at": "2026-08-26T00:00:00+00:00",
            "statement": "Reviewed candidate lineage and signed evaluation.",
        }

    archive.accept_candidate(
        candidate_id=str(candidates[0]["candidate_id"]),
        evaluation_id=str(evaluations[0]["evaluation_id"]),
        expected_champion_ref=parent,
        approval=approval(0),
    )
    current = str(archive.current_pointer()["champion_ref"])
    with pytest.raises(ArchiveError, match="stale"):
        archive.accept_candidate(
            candidate_id=str(candidates[1]["candidate_id"]),
            evaluation_id=str(evaluations[1]["evaluation_id"]),
            expected_champion_ref=current,
            approval=approval(1),
        )


def test_archive_rolls_to_new_reviewed_campaign_after_acceptance(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    parent = str(archive.current_pointer()["champion_ref"])
    candidate = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=parent,
        artifact_kind="source_patch",
        patch=b"winner",
        config={},
    )
    evaluation = archive.record_evaluation(
        candidate_id=str(candidate["candidate_id"]),
        signed_evaluation=_signed_evaluation(
            archive,
            str(candidate["candidate_id"]),
            accepted=True,
        ),
    )
    approval = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "decision": "accept",
        "candidate_id": candidate["candidate_id"],
        "evaluation_id": evaluation["evaluation_id"],
        "reviewer": "operator",
        "approved_at": "2026-08-26T00:00:00+00:00",
        "statement": "Reviewed candidate lineage and signed evaluation.",
    }
    accepted = archive.accept_candidate(
        candidate_id=str(candidate["candidate_id"]),
        evaluation_id=str(evaluation["evaluation_id"]),
        expected_champion_ref=parent,
        approval=approval,
    )

    next_campaign = archive.create_campaign(
        champion_commit="e" * 40,
        champion_tree="f" * 40,
        source_status_digest=f"sha256:{'1' * 64}",
        evaluation_config=EvaluationConfig().to_json(),
        evaluation_suite=_suite_bytes("sealed-b"),
        runner_image=_RUNNER_IMAGE,
        referee_public_key=_REFEREE_PUBLIC_KEY,
        proposal_input_artifact_ids=archive.candidate_input_artifact_ids(
            str(candidate["candidate_id"])
        ),
        expected_previous_ref=str(accepted["champion_ref"]),
    )

    pointer = archive.current_pointer()
    assert pointer["campaign_id"] == next_campaign["campaign_id"]
    assert pointer["champion_ref"] == f"source:{'e' * 40}"
    archive.verify()


def test_evaluation_signature_cannot_be_rebound_or_change_campaign_policy(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    campaign = _campaign(archive)
    parent = str(archive.current_pointer()["champion_ref"])
    first = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=parent,
        artifact_kind="source_patch",
        patch=b"first",
        config={},
    )
    second = archive.register_candidate(
        campaign_id=str(campaign["campaign_id"]),
        parent_ref=parent,
        artifact_kind="source_patch",
        patch=b"second",
        config={},
    )
    signed_first = _signed_evaluation(
        archive,
        str(first["candidate_id"]),
        accepted=True,
    )
    with pytest.raises(ArchiveError, match="does not match"):
        archive.record_evaluation(
            candidate_id=str(second["candidate_id"]),
            signed_evaluation=signed_first,
        )

    champion, candidate_receipts = _receipt_sets(accepted=True)
    binding = archive.prepare_evaluation_binding(
        str(first["candidate_id"]),
        champion_receipts=champion,
        candidate_receipts=candidate_receipts,
    )
    wrong_policy = EvaluationReceipt(
        accepted=True,
        config=EvaluationConfig(max_efficiency_regression=0.25),
        matching={},
        aggregate={},
        stability={},
        rejections=(),
    )
    signed_wrong_policy = sign_evaluation(
        wrong_policy,
        binding,
        private_key=_REFEREE_PRIVATE_KEY,
    ).to_json()
    with pytest.raises(ArchiveError, match="receipt recomputation"):
        archive.record_evaluation(
            candidate_id=str(first["candidate_id"]),
            signed_evaluation=signed_wrong_policy,
        )
