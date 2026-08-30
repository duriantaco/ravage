"""Operator CLI for the isolated Ravage improvement lab."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import stat
import sys
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Final

from tools.improvement_lab.archive import ArchiveError, LabArchive
from tools.improvement_lab.attestation import (
    generate_referee_keypair,
    load_signed_evaluation,
    read_private_key,
    read_public_key,
    referee_key_id,
    sign_evaluation,
    write_referee_key,
    write_signed_evaluation,
)
from tools.improvement_lab.corpus import (
    DEVELOPMENT,
    SEALED_HOLDOUT,
    CorpusError,
    ingest_events_jsonl,
    write_candidate_corpus,
    write_capsule,
)
from tools.improvement_lab.evaluation import (
    evaluate_candidate,
    load_run_receipts,
)
from tools.improvement_lab.execution_attestation import (
    ExecutionAttestationError,
    load_signed_execution_envelope,
)
from tools.improvement_lab.lessons import ImprovementBriefError, build_improvement_brief
from tools.improvement_lab.run_receipt_adapter import (
    RunReceiptAdapterError,
    derive_run_receipt,
    write_run_receipt,
)
from tools.improvement_lab.tournament import (
    TournamentCandidate,
    TournamentError,
    rank_candidates,
)
from tools.improvement_lab.trusted_replay import TrustedReplayError, replay_previous_run
from tools.improvement_lab.workspace import (
    CandidateWorkspaceError,
    build_offline_container_job,
    capture_source_state,
    materialize_candidate,
    require_clean_champion,
)

# Operator errors are deliberately bounded and do not echo raw event content.
# ruff: noqa: EM101, TRY003

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MIN_KEY_FILE_BYTES: Final = 32
_MAX_KEY_FILE_BYTES: Final = 4096
_MAX_TAINT_FILE_BYTES: Final = 1024 * 1024
_MAX_EVENT_DISCOVERY_DEPTH: Final = 12
_MAX_EVENT_DISCOVERY_ENTRIES: Final = 100_000
_MAX_EVENT_STREAMS: Final = 10_000


class ImprovementCliError(RuntimeError):
    """Safe operator-facing CLI error."""


def build_parser() -> argparse.ArgumentParser:  # noqa: PLR0915 - explicit subcommand contract.
    parser = argparse.ArgumentParser(
        prog="ravage-improve",
        description=(
            "Isolated historical replay, candidate archive, and no-regression evaluation lab."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="create an owner-only corpus HMAC key")
    keygen.add_argument("--output", type=Path, required=True)
    keygen.set_defaults(handler=_keygen)

    referee_keygen = subparsers.add_parser(
        "referee-keygen",
        help="create an Ed25519 referee signing keypair",
    )
    referee_keygen.add_argument("--private-key", type=Path, required=True)
    referee_keygen.add_argument("--public-key", type=Path, required=True)
    referee_keygen.set_defaults(handler=_referee_keygen)

    executor_keygen = subparsers.add_parser(
        "executor-keygen",
        help="create a separate Ed25519 execution-attestation keypair",
    )
    executor_keygen.add_argument("--private-key", type=Path, required=True)
    executor_keygen.add_argument("--public-key", type=Path, required=True)
    executor_keygen.set_defaults(handler=_executor_keygen)

    ingest = subparsers.add_parser(
        "ingest",
        help="project prior events into secret-safe structural trajectory capsules",
    )
    ingest.add_argument("paths", type=Path, nargs="+")
    ingest.add_argument("--key-file", type=Path, required=True)
    ingest.add_argument(
        "--partition",
        choices=(DEVELOPMENT, SEALED_HOLDOUT),
        default=DEVELOPMENT,
    )
    ingest.add_argument("--taint-file", type=Path, action="append", default=[])
    ingest.add_argument("--output", type=Path, required=True)
    ingest.set_defaults(handler=_ingest)

    replay = subparsers.add_parser(
        "replay",
        help="re-run checksum-covered prior observations through the current evidence engine",
    )
    replay.add_argument("run_root", type=Path)
    replay.add_argument("--key-file", type=Path, required=True)
    replay.add_argument("--scratch-root", type=Path)
    replay.add_argument("--output", type=Path, required=True)
    replay.set_defaults(handler=_replay)

    brief = subparsers.add_parser(
        "brief",
        help="derive a target-agnostic capability backlog from development capsules",
    )
    brief.add_argument("--corpus", type=Path, required=True)
    brief.add_argument("--output", type=Path, required=True)
    brief.set_defaults(handler=_brief)

    evaluate = subparsers.add_parser(
        "evaluate",
        help="compare repeated matched champion and candidate run receipts",
    )
    evaluate.add_argument("--champion", type=Path, required=True)
    evaluate.add_argument("--candidate", type=Path, required=True)
    evaluate.add_argument("--archive", type=Path, required=True)
    evaluate.add_argument("--candidate-id", required=True)
    evaluate.add_argument("--referee-private-key", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    evaluate.add_argument("--require-promotion", action="store_true")
    evaluate.set_defaults(handler=_evaluate)

    receipt_build = subparsers.add_parser(
        "receipt-build",
        help="derive one receipt from frozen output and a signed executor envelope",
    )
    receipt_build.add_argument("--archive", type=Path, required=True)
    receipt_build.add_argument("--candidate-id", required=True)
    receipt_build.add_argument("--artifacts", type=Path, required=True)
    receipt_build.add_argument("--execution-envelope", type=Path, required=True)
    receipt_build.add_argument("--output", type=Path, required=True)
    receipt_build.set_defaults(handler=_receipt_build)

    source_check = subparsers.add_parser(
        "source-check",
        help="show whether a checkout is safe to pin as an immutable champion",
    )
    source_check.add_argument("source", type=Path)
    source_check.set_defaults(handler=_source_check)

    materialize = subparsers.add_parser(
        "materialize",
        help="apply a registered patch in an independent clone, never in the source checkout",
    )
    materialize.add_argument("--source", type=Path, required=True)
    materialize.add_argument("--lab-root", type=Path, required=True)
    materialize.add_argument("--archive", type=Path, required=True)
    materialize.add_argument("--candidate-id", required=True)
    materialize.set_defaults(handler=_materialize)

    offline = subparsers.add_parser(
        "offline-job",
        help="write a hardened, networkless container job specification",
    )
    offline.add_argument("--source", type=Path, required=True)
    offline.add_argument("--lab-root", type=Path, required=True)
    offline.add_argument("--archive", type=Path, required=True)
    offline.add_argument("--candidate-id", required=True)
    offline.add_argument("--candidate-view-root", type=Path, required=True)
    offline.add_argument("--trusted-tests", type=Path, required=True)
    offline.add_argument("--job-output", type=Path, required=True)
    offline.add_argument("--spec-output", type=Path, required=True)
    offline.set_defaults(handler=_offline_job)

    archive_init = subparsers.add_parser(
        "archive-init",
        help="initialize an owner-only immutable experiment archive",
    )
    archive_init.add_argument("--archive", type=Path, required=True)
    archive_init.set_defaults(handler=_archive_init)

    artifact_add = subparsers.add_parser(
        "artifact-add",
        help="record a corpus, replay, brief, or receipt as an immutable object",
    )
    artifact_add.add_argument("--archive", type=Path, required=True)
    artifact_add.add_argument(
        "--kind",
        choices=(
            "capability_brief",
            "development_corpus",
            "historical_replay",
            "run_receipts",
            "sealed_capsule",
        ),
        required=True,
    )
    artifact_add.add_argument(
        "--visibility",
        choices=("candidate", "sealed_evaluator"),
        required=True,
    )
    artifact_add.add_argument("--file", type=Path, required=True)
    artifact_add.add_argument("--metadata", type=Path)
    artifact_add.set_defaults(handler=_artifact_add)

    campaign = subparsers.add_parser(
        "campaign-create",
        help="pin one clean reviewed source commit as the fixed champion",
    )
    campaign.add_argument("--archive", type=Path, required=True)
    campaign.add_argument("--source", type=Path, required=True)
    campaign.add_argument("--evaluation-config", type=Path, required=True)
    campaign.add_argument("--evaluation-suite", type=Path, required=True)
    campaign.add_argument("--runner-image", required=True)
    campaign.add_argument("--referee-public-key", type=Path, required=True)
    campaign.add_argument("--executor-public-key", type=Path, required=True)
    campaign.add_argument("--candidate-artifact-id", action="append", required=True)
    campaign.add_argument("--expected-previous-ref")
    campaign.set_defaults(handler=_campaign_create)

    candidate = subparsers.add_parser(
        "candidate-add",
        help="archive a candidate patch against the current lab champion",
    )
    candidate.add_argument("--archive", type=Path, required=True)
    candidate.add_argument(
        "--artifact-kind",
        choices=("knowledge_pack", "policy_patch", "source_patch"),
        required=True,
    )
    candidate.add_argument("--patch", type=Path, required=True)
    candidate.add_argument("--config", type=Path, required=True)
    candidate.set_defaults(handler=_candidate_add)

    evaluation_add = subparsers.add_parser(
        "evaluation-add",
        help="bind a digest-verified referee receipt to one candidate",
    )
    evaluation_add.add_argument("--archive", type=Path, required=True)
    evaluation_add.add_argument("--candidate-id", required=True)
    evaluation_add.add_argument("--signed-evaluation", type=Path, required=True)
    evaluation_add.set_defaults(handler=_evaluation_add)

    accept = subparsers.add_parser(
        "accept",
        help="advance only the lab pointer using explicit human approval and CAS",
    )
    accept.add_argument("--archive", type=Path, required=True)
    accept.add_argument("--candidate-id", required=True)
    accept.add_argument("--evaluation-id", required=True)
    accept.add_argument("--expected-champion-ref", required=True)
    accept.add_argument("--approval", type=Path, required=True)
    accept.set_defaults(handler=_accept)

    export = subparsers.add_parser(
        "export",
        help="copy a candidate patch for review without applying it",
    )
    export.add_argument("--archive", type=Path, required=True)
    export.add_argument("--candidate-id", required=True)
    export.add_argument("--output", type=Path, required=True)
    export.set_defaults(handler=_export)

    verify = subparsers.add_parser(
        "archive-verify",
        help="verify all objects, manifests, references, and ledger hashes",
    )
    verify.add_argument("--archive", type=Path, required=True)
    checkpoint = verify.add_mutually_exclusive_group()
    checkpoint.add_argument(
        "--expected-checkpoint",
        help="require the format-bound archive checkpoint from an external record",
    )
    checkpoint.add_argument(
        "--expected-head",
        dest="expected_checkpoint",
        help="legacy alias for --expected-checkpoint",
    )
    verify.set_defaults(handler=_archive_verify)

    recover = subparsers.add_parser(
        "archive-recover",
        help="rebuild derived manifests and pointer from committed ledger events",
    )
    recover.add_argument("--archive", type=Path, required=True)
    recover.set_defaults(handler=_archive_recover)

    tournament = subparsers.add_parser(
        "tournament",
        help="rank accepted candidates without changing the lab champion",
    )
    tournament.add_argument("--archive", type=Path, required=True)
    tournament.add_argument("--evaluation-id", action="append", required=True)
    tournament.add_argument("--output", type=Path, required=True)
    tournament.set_defaults(handler=_tournament)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.handler(args))
    except (
        CandidateWorkspaceError,
        ArchiveError,
        CorpusError,
        ExecutionAttestationError,
        ImprovementCliError,
        ImprovementBriefError,
        RunReceiptAdapterError,
        TrustedReplayError,
        TournamentError,
        ValueError,
    ) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


def _keygen(args: argparse.Namespace) -> int:
    destination = args.output.expanduser()
    if destination.exists() or destination.is_symlink():
        raise ImprovementCliError("refusing to overwrite an existing key file")
    _private_atomic_write(destination, secrets.token_bytes(32))
    _print_json({"created": True, "key_bytes": 32, "output": str(destination)})
    return 0


def _referee_keygen(args: argparse.Namespace) -> int:
    return _ed25519_keygen(args)


def _executor_keygen(args: argparse.Namespace) -> int:
    return _ed25519_keygen(args)


def _ed25519_keygen(args: argparse.Namespace) -> int:
    private_key, public_key = generate_referee_keypair()
    write_referee_key(args.private_key, private_key, public=False)
    try:
        write_referee_key(args.public_key, public_key, public=True)
    except Exception:
        with suppress(OSError):
            args.private_key.unlink(missing_ok=True)
        raise
    _print_json(
        {
            "created": True,
            "private_key": str(args.private_key),
            "public_key": str(args.public_key),
        }
    )
    return 0


def _ingest(args: argparse.Namespace) -> int:
    key = _read_key(args.key_file)
    taints = _read_taints(args.taint_file)
    sources = _discover_event_sources(args.paths)
    capsules = []
    run_ids: set[str] = set()
    for source in sources:
        capsule = ingest_events_jsonl(
            source,
            hmac_key=key,
            partition=args.partition,
            taints=taints,
        )
        run_id = str(capsule["run_id"])
        if run_id in run_ids:
            raise ImprovementCliError("selected event streams contain duplicate run content")
        run_ids.add(run_id)
        capsules.append(capsule)

    output = args.output.expanduser()
    if args.partition == DEVELOPMENT:
        _ensure_output_parent(output)
        write_candidate_corpus(output, capsules, taints=taints)
        output.chmod(0o600)
        output_kind = "candidate_corpus"
    else:
        _write_sealed_capsule_directory(output, capsules, taints=taints)
        output_kind = "sealed_capsule_directory"
    _print_json(
        {
            "capsules": len(capsules),
            "output": str(output),
            "output_kind": output_kind,
            "partition": args.partition,
        }
    )
    return 0


def _replay(args: argparse.Namespace) -> int:
    receipt = replay_previous_run(
        args.run_root,
        hmac_key=_read_key(args.key_file),
        scratch_root=args.scratch_root,
    )
    payload = receipt.to_json()
    _private_atomic_write(
        args.output.expanduser(),
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )
    _print_json(
        {
            "execution_kind": payload["execution_kind"],
            "output": str(args.output),
            "promotable": False,
            "totals": payload["totals"],
        }
    )
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    champion = load_run_receipts(args.champion)
    candidate = load_run_receipts(args.candidate)
    config = archive.campaign_evaluation_config(args.candidate_id)
    suite = archive.campaign_evaluation_suite(args.candidate_id)
    receipt = evaluate_candidate(champion, candidate, config=config, suite=suite)
    binding = archive.prepare_evaluation_binding(
        args.candidate_id,
        champion_receipts=champion,
        candidate_receipts=candidate,
    )
    signed = sign_evaluation(
        receipt,
        binding,
        private_key=read_private_key(args.referee_private_key),
    )
    public_key = archive.campaign_referee_public_key(args.candidate_id)
    if signed.signing_key_id != referee_key_id(public_key):
        raise ImprovementCliError("referee private key does not match the campaign public key")
    write_signed_evaluation(args.output, signed)
    payload = receipt.to_json()
    _print_json(
        {
            "accepted": receipt.accepted,
            "decision": receipt.decision,
            "output": str(args.output),
            "rejection_codes": [item.code for item in receipt.rejections],
            "receipt_digest": payload["receipt_digest"],
        }
    )
    return 3 if args.require_promotion and not receipt.accepted else 0


def _receipt_build(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    public_key = archive.campaign_executor_public_key(args.candidate_id)
    envelope = load_signed_execution_envelope(
        args.execution_envelope,
        public_key=public_key,
    )
    receipt = derive_run_receipt(
        args.artifacts,
        envelope=envelope,
        executor_public_key=public_key,
    )
    retained = archive.retain_execution_envelope(
        args.candidate_id,
        signed_envelope=envelope,
    )
    if retained.get("content_object") != receipt.execution_attestation_digest:
        raise ImprovementCliError(
            "retained execution envelope does not match the derived receipt"
        )
    write_run_receipt(args.output, receipt)
    _print_json(
        {
            "artifact_id": retained["artifact_id"],
            "case_id": receipt.case_id,
            "evaluation_side": envelope.binding.evaluation_side,
            "execution_attestation_digest": receipt.execution_attestation_digest,
            "output": str(args.output),
        }
    )
    return 0


def _brief(args: argparse.Namespace) -> int:
    corpus = _load_json_mapping(args.corpus)
    brief = build_improvement_brief(corpus)
    _private_atomic_write(
        args.output.expanduser(),
        (json.dumps(brief, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )
    gaps = brief["capability_gaps"]
    _print_json(
        {
            "brief_digest": brief["brief_digest"],
            "decision": brief["decision"],
            "gap_count": len(gaps) if isinstance(gaps, list) else 0,
            "output": str(args.output),
        }
    )
    return 0


def _source_check(args: argparse.Namespace) -> int:
    state = capture_source_state(args.source)
    _print_json(
        {
            "clean": state.clean,
            "dirty_entries": state.dirty_entries,
            "head_commit": state.head_commit,
            "status_digest": f"sha256:{state.status_digest}",
            "tree_digest": state.tree_digest,
        }
    )
    return 0 if state.clean else 3


def _materialize(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    manifest, patch = archive.candidate_materialization(args.candidate_id)
    candidate = materialize_candidate(
        source_root=args.source,
        lab_root=args.lab_root,
        candidate_id=args.candidate_id,
        base_commit=str(manifest["base_commit"]),
        patch=patch,
    )
    _print_json(
        {
            "base_commit": candidate.base_commit,
            "candidate_id": candidate.candidate_id,
            "patch_sha256": f"sha256:{candidate.patch_sha256}",
            "workspace": str(candidate.path),
        }
    )
    return 0


def _offline_job(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    manifest, patch = archive.candidate_materialization(args.candidate_id)
    candidate = materialize_candidate(
        source_root=args.source,
        lab_root=args.lab_root,
        candidate_id=args.candidate_id,
        base_commit=str(manifest["base_commit"]),
        patch=patch,
    )
    suite = archive.campaign_evaluation_suite(args.candidate_id)
    episodes = archive.materialize_candidate_view(
        list(archive.candidate_input_artifact_ids(args.candidate_id)),
        args.candidate_view_root,
    )
    job = build_offline_container_job(
        image=archive.candidate_runner_image(args.candidate_id),
        candidate=candidate,
        episodes_root=episodes,
        trusted_tests_root=args.trusted_tests,
        expected_trusted_tests_digest=suite.trusted_tests_digest,
        output_root=args.job_output,
        command=suite.runner_command,
    )
    _private_atomic_write(
        args.spec_output.expanduser(),
        (json.dumps(job.to_json(), sort_keys=True, indent=2) + "\n").encode(),
    )
    _print_json(
        {
            "execution_kind": "offline_candidate_container",
            "network": "none",
            "candidate_id": args.candidate_id,
            "candidate_tree_digest": candidate.candidate_tree_digest,
            "candidate_content_digest": candidate.candidate_content_digest,
            "spec_output": str(args.spec_output),
        }
    )
    return 0


def _archive_init(args: argparse.Namespace) -> int:
    archive = LabArchive.initialize(args.archive)
    verification = archive.verify()
    _print_json({"archive": str(archive.root), "verification": verification.to_json()})
    return 0


def _artifact_add(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    try:
        content = args.file.read_bytes()
    except OSError as exc:
        raise ImprovementCliError("cannot read artifact input") from exc
    metadata = _load_json_mapping(args.metadata) if args.metadata is not None else {}
    manifest = archive.record_artifact(
        kind=args.kind,
        visibility=args.visibility,
        content=content,
        metadata=metadata,
    )
    _print_json(
        {
            "artifact_id": manifest["artifact_id"],
            "content_object": manifest["content_object"],
            "kind": manifest["kind"],
            "visibility": manifest["visibility"],
        }
    )
    return 0


def _campaign_create(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    state = require_clean_champion(args.source)
    config = _load_json_mapping(args.evaluation_config)
    try:
        suite = args.evaluation_suite.read_bytes()
    except OSError as exc:
        raise ImprovementCliError("cannot read evaluation suite manifest") from exc
    manifest = archive.create_campaign(
        champion_commit=state.head_commit,
        champion_tree=state.tree_digest,
        source_status_digest=f"sha256:{state.status_digest}",
        evaluation_config=config,
        evaluation_suite=suite,
        runner_image=args.runner_image,
        referee_public_key=read_public_key(args.referee_public_key),
        executor_public_key=read_public_key(args.executor_public_key),
        proposal_input_artifact_ids=tuple(args.candidate_artifact_id),
        expected_previous_ref=args.expected_previous_ref,
    )
    pointer = archive.current_pointer()
    _print_json(
        {
            "campaign_id": manifest["campaign_id"],
            "champion_ref": pointer["champion_ref"],
        }
    )
    return 0


def _candidate_add(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    pointer = archive.current_pointer()
    try:
        patch = args.patch.read_bytes()
    except OSError as exc:
        raise ImprovementCliError("cannot read candidate patch") from exc
    manifest = archive.register_candidate(
        campaign_id=str(pointer["campaign_id"]),
        parent_ref=str(pointer["champion_ref"]),
        artifact_kind=args.artifact_kind,
        patch=patch,
        config=_load_json_mapping(args.config),
    )
    _print_json(
        {
            "candidate_id": manifest["candidate_id"],
            "parent_ref": manifest["parent_ref"],
            "patch_object": manifest["patch_object"],
        }
    )
    return 0


def _evaluation_add(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    public_key = archive.campaign_referee_public_key(args.candidate_id)
    signed = load_signed_evaluation(args.signed_evaluation, public_key=public_key)
    manifest = archive.record_evaluation(
        candidate_id=args.candidate_id,
        signed_evaluation=signed.to_json(),
    )
    _print_json(
        {
            "accepted": manifest["accepted"],
            "candidate_id": manifest["candidate_id"],
            "evaluation_id": manifest["evaluation_id"],
        }
    )
    return 0


def _accept(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    pointer = archive.accept_candidate(
        candidate_id=args.candidate_id,
        evaluation_id=args.evaluation_id,
        expected_champion_ref=args.expected_champion_ref,
        approval=_load_json_mapping(args.approval),
    )
    _print_json(
        {
            "champion_ref": pointer["champion_ref"],
            "sequence": pointer["sequence"],
        }
    )
    return 0


def _export(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    output = archive.export_candidate(args.candidate_id, args.output)
    _print_json({"candidate_id": args.candidate_id, "output": str(output)})
    return 0


def _archive_verify(args: argparse.Namespace) -> int:
    archive = LabArchive.open(args.archive)
    verification = archive.verify(expected_checkpoint=args.expected_checkpoint)
    _print_json(verification.to_json())
    return 0


def _archive_recover(args: argparse.Namespace) -> int:
    archive = LabArchive.open(args.archive)
    archive.recover()
    verification = archive.verify()
    _print_json(verification.to_json())
    return 0


def _tournament(args: argparse.Namespace) -> int:
    archive = _verified_archive(args.archive)
    entries = []
    for evaluation_id in args.evaluation_id:
        manifest, signed = archive.signed_evaluation(evaluation_id)
        entries.append(
            TournamentCandidate(
                candidate_id=str(manifest["candidate_id"]),
                evaluation_id=evaluation_id,
                receipt=signed.receipt,
                binding=signed.binding,
            )
        )
    result = rank_candidates(entries)
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _private_atomic_write(args.output.expanduser(), encoded)
    artifact = archive.record_artifact(
        kind="tournament_receipt",
        visibility="sealed_evaluator",
        content=encoded,
        metadata={"tournament_digest": result["tournament_digest"]},
    )
    _print_json(
        {
            "eligible_count": result["eligible_count"],
            "output": str(args.output),
            "tournament_artifact_id": artifact["artifact_id"],
            "winner_candidate_id": result["winner_candidate_id"],
        }
    )
    return 0


def _verified_archive(path: Path) -> LabArchive:
    archive = LabArchive.open(path)
    archive.recover()
    archive.verify()
    return archive


def _discover_event_sources(  # noqa: C901,PLR0915 - fail-closed path classification.
    paths: Sequence[Path],
) -> tuple[Path, ...]:
    found: dict[tuple[int, int], Path] = {}
    entries_seen = 0

    def add_event(path: Path, metadata: os.stat_result | None = None) -> None:
        if path.name != "events.jsonl":
            raise ImprovementCliError("event input file must be named events.jsonl")
        try:
            current = metadata if metadata is not None else path.lstat()
        except OSError as exc:
            raise ImprovementCliError("cannot inspect event input") from exc
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
        ):
            raise ImprovementCliError("event stream must be a regular single-link file")
        identity = (current.st_dev, current.st_ino)
        found.setdefault(identity, path.absolute())
        if len(found) > _MAX_EVENT_STREAMS:
            raise ImprovementCliError("event discovery exceeds the stream limit")

    def walk(directory: Path, depth: int) -> int:
        nonlocal entries_seen
        selected = 0
        try:
            iterator = os.scandir(directory)
        except OSError as exc:
            raise ImprovementCliError("cannot inspect event input directory") from exc
        with iterator:
            for entry in iterator:
                entries_seen += 1
                if entries_seen > _MAX_EVENT_DISCOVERY_ENTRIES:
                    raise ImprovementCliError("event discovery exceeds the entry limit")
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise ImprovementCliError("cannot inspect event input entry") from exc
                entry_path = Path(entry.path)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ImprovementCliError(
                        "event input directory must not contain symlinked entries"
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    if depth >= _MAX_EVENT_DISCOVERY_DEPTH:
                        raise ImprovementCliError("event discovery exceeds the depth limit")
                    selected += walk(entry_path, depth + 1)
                elif entry.name == "events.jsonl":
                    add_event(entry_path, metadata)
                    selected += 1
        return selected

    for raw in paths:
        path = raw.expanduser()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ImprovementCliError("event input path is missing") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ImprovementCliError("event input must not be a symlink")
        if stat.S_ISREG(metadata.st_mode):
            add_event(path, metadata)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise ImprovementCliError("event input must be a regular file or directory")
        if walk(path, 0) == 0:
            raise ImprovementCliError("event input directory contains no supported run logs")

    if not found:
        raise ImprovementCliError("no event streams were selected")

    streams = tuple(sorted(found.values(), key=lambda item: item.as_posix()))
    run_roots: dict[Path, Path] = {}
    for stream in streams:
        run_root = stream.parent.parent if stream.parent.name == "workspace" else stream.parent
        previous = run_roots.setdefault(run_root, stream)
        if previous != stream:
            raise ImprovementCliError("run directory contains ambiguous events streams")
    return streams


def _read_key(path: Path) -> bytes:
    data = _read_owner_only_file(
        path,
        label="corpus HMAC key",
        max_bytes=_MAX_KEY_FILE_BYTES,
    )
    if len(data) < _MIN_KEY_FILE_BYTES or len(data) > _MAX_KEY_FILE_BYTES:
        raise ImprovementCliError("corpus HMAC key must contain between 32 and 4096 bytes")
    return data


def _read_taints(paths: Sequence[Path]) -> tuple[bytes, ...]:
    values: list[bytes] = []
    for path in paths:
        data = _read_owner_only_file(
            path,
            label="taint file",
            max_bytes=_MAX_TAINT_FILE_BYTES,
        )
        values.extend(line for line in data.splitlines() if line)
    return tuple(values)


def _read_owner_only_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    candidate = path.expanduser()
    read_error = f"cannot read {label}"
    oversize_error = f"{label} exceeds the byte cap"
    try:
        before = candidate.lstat()
    except OSError as exc:
        raise ImprovementCliError(read_error) from exc
    _validate_owner_only_metadata(before, label=label)
    if before.st_size > max_bytes:
        raise ImprovementCliError(oversize_error)

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        _validate_opened_owner_only_file(before, opened, label=label)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
    except ImprovementCliError:
        raise
    except OSError as exc:
        raise ImprovementCliError(read_error) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > max_bytes:
        raise ImprovementCliError(oversize_error)
    if _private_file_version(after) != _private_file_version(opened):
        changed_error = f"{label} changed while it was being read"
        raise ImprovementCliError(changed_error)
    return data


def _validate_owner_only_metadata(metadata: os.stat_result, *, label: str) -> None:
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        type_error = f"{label} must be a regular single-link file"
        raise ImprovementCliError(type_error)
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        permission_error = f"{label} must not grant group or other permissions"
        raise ImprovementCliError(permission_error)


def _validate_opened_owner_only_file(
    before: os.stat_result,
    opened: os.stat_result,
    *,
    label: str,
) -> None:
    try:
        _validate_owner_only_metadata(opened, label=label)
    except ImprovementCliError:
        changed_error = f"{label} changed before it could be opened safely"
        raise ImprovementCliError(changed_error) from None
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        changed_error = f"{label} changed before it could be opened safely"
        raise ImprovementCliError(changed_error)


def _private_file_version(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _load_json_mapping(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImprovementCliError("cannot read JSON configuration") from exc
    if not isinstance(payload, dict):
        raise ImprovementCliError("JSON configuration must be an object")
    return {str(key): value for key, value in payload.items()}


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ImprovementCliError("JSON configuration contains a duplicate key")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> object:
    message = f"JSON configuration contains unsupported {value}"
    raise ImprovementCliError(message)


def _private_atomic_write(destination: Path, content: bytes) -> None:
    if destination.is_symlink():
        raise ImprovementCliError("output path must not be a symlink")
    _ensure_output_parent(destination)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
        destination.chmod(0o600)
    except OSError as exc:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise ImprovementCliError("cannot write private output") from exc


def _write_sealed_capsule_directory(
    output: Path,
    capsules: Sequence[Mapping[str, object]],
    *,
    taints: Sequence[bytes],
) -> None:
    _require_fresh_sealed_output(output)
    _ensure_output_parent(output)
    _require_fresh_sealed_output(output)
    try:
        temporary = Path(
            tempfile.mkdtemp(
                dir=output.parent,
                prefix=f".{output.name}.",
                suffix=".staging",
            )
        )
        temporary.chmod(0o700)
    except OSError as exc:
        raise ImprovementCliError("cannot create sealed output staging directory") from exc

    published = False
    try:
        for capsule in capsules:
            case_id = str(capsule["case_id"])
            run_id = str(capsule["run_id"])
            write_capsule(
                temporary / f"{case_id}-{run_id}.json",
                capsule,
                taints=taints,
            )
        _require_fresh_sealed_output(output)
        temporary.rename(output)
        published = True
        _fsync_output_parent(output.parent)
    except (CorpusError, ImprovementCliError):
        raise
    except OSError as exc:
        raise ImprovementCliError("cannot publish sealed capsule directory") from exc
    finally:
        if not published:
            with suppress(OSError):
                shutil.rmtree(temporary)


def _require_fresh_sealed_output(output: Path) -> None:
    if _path_entry_exists(output):
        raise ImprovementCliError("refusing to reuse an existing sealed output directory")


def _path_entry_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ImprovementCliError("cannot inspect output path") from exc
    return True


def _fsync_output_parent(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        os.fsync(descriptor)
    except OSError as exc:
        raise ImprovementCliError("cannot synchronize sealed output directory") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _ensure_output_parent(destination: Path) -> None:
    parent = destination.parent
    if parent.is_symlink():
        raise ImprovementCliError("output directory must not be a symlink")
    existed = parent.exists()
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise ImprovementCliError("cannot create output directory") from exc
    if not parent.is_dir():
        raise ImprovementCliError("output parent must be a directory")
    if not existed:
        parent.chmod(0o700)


def _print_json(payload: object) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


__all__ = ["build_parser", "main"]
