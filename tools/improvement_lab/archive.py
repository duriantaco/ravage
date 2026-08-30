"""Immutable candidate archive and human-gated lab champion pointer."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from collections.abc import Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from tools.improvement_lab.attestation import (
    AttestationError,
    EvaluationBinding,
    SignedEvaluation,
    referee_key_id,
    verify_signed_evaluation,
)
from tools.improvement_lab.corpus import (
    CORPUS_SCHEMA_VERSION,
    CorpusError,
    candidate_visible_export,
)
from tools.improvement_lab.evaluation import (
    EvaluationConfig,
    EvaluationReceipt,
    EvaluationSuite,
    RunReceipt,
    canonical_run_receipts_bytes,
    evaluate_candidate,
    load_canonical_run_receipts,
)
from tools.improvement_lab.execution_attestation import (
    ExecutionAttestationError,
    SignedExecutionEnvelope,
    canonical_execution_envelope_bytes,
    execution_envelope_digest,
    load_canonical_execution_envelope_bytes,
    verify_signed_execution_envelope,
)
from tools.improvement_lab.lessons import (
    ImprovementBriefError,
    build_improvement_brief,
    validate_improvement_brief,
)

# Archive failures are deliberate operator boundary diagnostics.
# ruff: noqa: EM101, EM102, TRY003, TRY301

if TYPE_CHECKING:
    from collections.abc import Iterator

ARCHIVE_SCHEMA_VERSION: Final = "ravage.improvement-archive.v1"
CAMPAIGN_SCHEMA_VERSION: Final = "ravage.improvement-campaign.v4"
CANDIDATE_SCHEMA_VERSION: Final = "ravage.improvement-candidate.v2"
EVALUATION_RECORD_SCHEMA_VERSION: Final = "ravage.improvement-evaluation-record.v3"
APPROVAL_SCHEMA_VERSION: Final = "ravage.improvement-human-approval.v1"
_OBJECT_RE = re.compile(r"sha256:([0-9a-f]{64})")
_GIT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
_MAX_OBJECT_BYTES = 128 * 1024 * 1024
_MAX_PARENT_REF_CHARS = 160
_MAX_APPROVAL_FIELD_CHARS = 2000
_MAX_TIMESTAMP_CHARS = 128
_MAX_PUBLICATION_LINKS = 2
_CANDIDATE_INPUT_ARTIFACTS = 2
_PRIVATE_LOCK_MODE = 0o600
_ARCHIVE_ID_RE = re.compile(r"archive_[0-9a-f]{24}")
_OBJECT_TEMP_RE = re.compile(r"\.([0-9a-f]{64})\.([1-9][0-9]*)\.([0-9a-f]{8})")
_PROJECTION_TEMP_RE = re.compile(r"\.(.+)\.([1-9][0-9]*)\.([0-9a-f]{8})")


class ArchiveError(RuntimeError):
    """Raised when archive integrity or promotion authority would be weakened."""


@dataclass(frozen=True)
class StoredObject:
    digest: str
    size: int

    def to_json(self) -> dict[str, object]:
        return {"digest": self.digest, "size": self.size}


@dataclass(frozen=True)
class ArchiveVerification:
    objects: int
    object_bytes: int
    artifacts: int
    campaigns: int
    candidates: int
    evaluations: int
    ledger_events: int
    ledger_head: str
    archive_checkpoint: str
    verified_bytes: int

    def to_json(self) -> dict[str, object]:
        return {
            "objects": self.objects,
            "object_bytes": self.object_bytes,
            "artifacts": self.artifacts,
            "campaigns": self.campaigns,
            "candidates": self.candidates,
            "evaluations": self.evaluations,
            "ledger_events": self.ledger_events,
            "ledger_head": self.ledger_head,
            "archive_checkpoint": self.archive_checkpoint,
            "verified_bytes": self.verified_bytes,
        }


class LabArchive:
    """Owner-only append archive; it never imports or mutates Ravage runtime code."""

    def __init__(self, root: Path) -> None:
        self.root = _real_archive_root(root)
        self.objects_root = self.root / "objects" / "sha256"
        self.manifests_root = self.root / "manifests"
        self.ledger_root = self.root / "ledger"
        self.refs_root = self.root / "refs"

    @classmethod
    def initialize(cls, root: Path) -> LabArchive:
        archive_root = _create_archive_root(root)
        for relative in (
            "objects",
            "objects/sha256",
            "manifests",
            "manifests/campaigns",
            "manifests/candidates",
            "manifests/evaluations",
            "manifests/artifacts",
            "ledger",
            "refs",
        ):
            _private_directory(archive_root / relative)
        format_path = archive_root / "format.json"
        if not format_path.exists():
            _write_new_file(
                format_path,
                _canonical_bytes(
                    {
                        "schema_version": ARCHIVE_SCHEMA_VERSION,
                        "archive_id": f"archive_{secrets.token_hex(12)}",
                        "created_at": _now(),
                    }
                ),
                mode=0o400,
            )
        archive = cls(archive_root)
        archive.verify()
        return archive

    @classmethod
    def open(cls, root: Path) -> LabArchive:
        archive = cls(root)
        archive._load_format()
        return archive

    def recover(self) -> None:
        """Rebuild derived manifests and pointer after an event commit interruption."""
        with self._lock():
            self._recover_locked()

    def _recover_locked(self) -> None:
        """Recover projections while the archive ledger lock is held."""
        event_to_manifest = {
            "artifact_recorded": "artifacts",
            "campaign_created": "campaigns",
            "candidate_registered": "candidates",
            "evaluation_recorded": "evaluations",
        }
        self._cleanup_publication_temps_locked()
        events, _head = self._verified_ledger_events()
        manifests: dict[str, dict[str, dict[str, object]]] = {
            kind: {} for kind in ("artifacts", "campaigns", "candidates", "evaluations")
        }
        for event in events:
            manifest_kind = event_to_manifest.get(str(event.get("kind") or ""))
            if manifest_kind is None:
                continue
            subject_id = str(event.get("subject_id") or "")
            payload = _decode_json_object(
                self.read_object(str(event.get("payload_object") or "")),
                label="archive recovery payload",
            )
            _verify_manifest_payload(self, kind=manifest_kind, payload=payload)
            if payload.get(f"{manifest_kind[:-1]}_id") != subject_id:
                raise ArchiveError("archive recovery event identity is invalid")
            self._write_manifest(manifest_kind, subject_id, payload, repair=True)
            manifests[manifest_kind][subject_id] = payload
        reconstructed = self._reconcile_history(
            events,
            manifests=manifests,
            pointer=None,
            require_pointer_match=False,
        )
        pointer_path = self.refs_root / "lab-champion.json"
        try:
            current = self._load_pointer(required=False)
        except ArchiveError:
            current = None
        if reconstructed is None:
            if pointer_path.exists() or pointer_path.is_symlink():
                _unlink_projection(pointer_path, label="lab champion pointer")
        elif current != reconstructed:
            self._replace_pointer_projection_locked(reconstructed)

    def put_bytes(self, content: bytes) -> StoredObject:
        if not isinstance(content, bytes) or len(content) > _MAX_OBJECT_BYTES:
            raise ArchiveError("archive object is invalid or exceeds the byte cap")
        with self._object_lock():
            return self._put_bytes_locked(content)

    def _put_bytes_locked(self, content: bytes) -> StoredObject:
        digest_hex = hashlib.sha256(content).hexdigest()
        destination = self._object_path(f"sha256:{digest_hex}")
        _private_directory(destination.parent)
        if destination.exists() or destination.is_symlink():
            _verify_regular_file(destination, expected_digest=digest_hex)
            return StoredObject(digest=f"sha256:{digest_hex}", size=len(content))
        temporary = destination.with_name(f".{digest_hex}.{os.getpid()}.{secrets.token_hex(4)}")
        _write_new_file(temporary, content, mode=0o400)
        try:
            os.link(temporary, destination)
            _fsync_directory(destination.parent)
        except FileExistsError:
            _verify_regular_file(destination, expected_digest=digest_hex)
        except OSError as exc:
            raise ArchiveError("cannot publish immutable archive object") from exc
        finally:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        _verify_regular_file(destination, expected_digest=digest_hex)
        return StoredObject(digest=f"sha256:{digest_hex}", size=len(content))

    def put_json(self, payload: object) -> StoredObject:
        return self.put_bytes(_canonical_bytes(payload))

    def read_object(self, digest: str) -> bytes:
        path = self._object_path(digest)
        expected = _object_hex(digest)
        _verify_regular_file(path, expected_digest=expected)
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ArchiveError("cannot read immutable archive object") from exc

    def create_campaign(  # noqa: PLR0913 - campaign identity is deliberately explicit.
        self,
        *,
        champion_commit: str,
        champion_tree: str,
        source_status_digest: str,
        evaluation_config: object,
        evaluation_suite: bytes,
        runner_image: str,
        referee_public_key: bytes,
        executor_public_key: bytes,
        proposal_input_artifact_ids: Sequence[str],
        expected_previous_ref: str | None = None,
    ) -> dict[str, object]:
        self.recover()
        commit = _git_id(champion_commit, label="champion commit")
        tree = _git_id(champion_tree, label="champion tree")
        status_digest = _sha256_digest(source_status_digest, label="source status digest")
        if not isinstance(evaluation_config, Mapping):
            raise ArchiveError("campaign evaluation config must be an object")
        try:
            validated_config = EvaluationConfig.from_mapping(evaluation_config)
            key_id = referee_key_id(referee_public_key)
            executor_key_id = referee_key_id(executor_public_key)
            if executor_key_id == key_id:
                raise ArchiveError("campaign executor and referee keys must be distinct")
            EvaluationBinding(
                campaign_id=f"campaign_{'0' * 24}",
                candidate_id=f"candidate_{'0' * 24}",
                candidate_parent_ref=f"source:{commit}",
                champion_commit=commit,
                champion_tree=tree,
                candidate_patch_object=f"sha256:{'0' * 64}",
                candidate_config_object=f"sha256:{'0' * 64}",
                evaluation_config_object=f"sha256:{'0' * 64}",
                evaluation_suite_object=f"sha256:{'0' * 64}",
                runner_image=runner_image,
                champion_receipts_object=f"sha256:{'0' * 64}",
                candidate_receipts_object=f"sha256:{'0' * 64}",
            )
        except (AttestationError, ValueError) as exc:
            raise ArchiveError("campaign evaluation trust configuration is invalid") from exc
        try:
            validated_suite = EvaluationSuite.from_bytes(evaluation_suite)
        except ValueError as exc:
            raise ArchiveError("campaign evaluation suite is invalid") from exc
        if any(case.repeats < validated_config.min_repeats for case in validated_suite.cases):
            raise ArchiveError("campaign evaluation suite does not satisfy its repeat policy")
        config_object = self.put_json(validated_config.to_json())
        suite_object = self.put_json(validated_suite.to_json())
        public_key_object = self.put_bytes(referee_public_key)
        executor_public_key_object = self.put_bytes(executor_public_key)
        validated_inputs = self._validated_candidate_input_artifacts(proposal_input_artifact_ids)
        input_set_object = self.put_json(
            {"schema_version": 1, "artifact_ids": list(validated_inputs)}
        )
        identity = {
            "champion_commit": commit,
            "champion_tree": tree,
            "source_status_digest": status_digest,
            "evaluation_config_object": config_object.digest,
            "evaluation_suite_object": suite_object.digest,
            "runner_image": runner_image,
            "referee_public_key_object": public_key_object.digest,
            "referee_key_id": key_id,
            "executor_public_key_object": executor_public_key_object.digest,
            "executor_key_id": executor_key_id,
            "proposal_input_set_object": input_set_object.digest,
        }
        campaign_id = f"campaign_{_digest_json(identity)[:24]}"
        manifest: dict[str, object] = {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": campaign_id,
            **identity,
            "created_at": _now(),
        }
        with self._lock():
            if self._event_payload_locked("campaign_created", campaign_id) is not None:
                return self._publish_manifest_event_locked(
                    manifest_kind="campaigns",
                    event_kind="campaign_created",
                    identifier=campaign_id,
                    proposed=manifest,
                )
            pointer = self._load_pointer(required=False)
            if pointer is not None:
                if pointer.get("candidate_id") is None:
                    raise ArchiveError("an active lab campaign already exists")
                if (
                    expected_previous_ref is None
                    or pointer.get("champion_ref") != expected_previous_ref
                ):
                    raise ArchiveError(
                        "new campaign requires the accepted previous lab champion ref"
                    )
            manifest = self._publish_manifest_event_locked(
                manifest_kind="campaigns",
                event_kind="campaign_created",
                identifier=campaign_id,
                proposed=manifest,
            )
            champion_ref = f"source:{commit}"
            self._write_pointer_locked(
                {
                    "schema_version": 1,
                    "sequence": 0,
                    "campaign_id": campaign_id,
                    "champion_ref": champion_ref,
                    "candidate_id": None,
                    "evaluation_id": None,
                    "approval_object": None,
                },
                expected_ref=expected_previous_ref,
            )
        return manifest

    def record_artifact(
        self,
        *,
        kind: str,
        visibility: str,
        content: bytes,
        metadata: object | None = None,
    ) -> dict[str, object]:
        self.recover()
        if kind not in {
            "capability_brief",
            "development_corpus",
            "historical_replay",
            "run_receipts",
            "sealed_capsule",
            "tournament_receipt",
        }:
            raise ArchiveError("archive artifact kind is unsupported")
        if visibility not in {"candidate", "sealed_evaluator"}:
            raise ArchiveError("archive artifact visibility is unsupported")
        if kind == "sealed_capsule" and visibility != "sealed_evaluator":
            raise ArchiveError("sealed capsule cannot be candidate-visible")
        if visibility == "candidate":
            if kind not in {"capability_brief", "development_corpus"}:
                raise ArchiveError("only validated development inputs may be candidate-visible")
            if metadata is not None and metadata != {}:
                raise ArchiveError("candidate-visible artifact metadata must be empty")
            content = _canonicalize_candidate_artifact(kind=kind, content=content)
        return self._record_artifact(
            kind=kind,
            visibility=visibility,
            content=content,
            metadata=metadata,
        )

    def retain_execution_envelope(
        self,
        candidate_id: str,
        *,
        signed_envelope: SignedExecutionEnvelope,
    ) -> dict[str, object]:
        """Verify and retain one canonical executor envelope as a sealed artifact."""
        self.recover()
        _archive_id(candidate_id, "candidate")
        public_key = self.campaign_executor_public_key(candidate_id)
        try:
            verified = verify_signed_execution_envelope(
                signed_envelope.to_json(),
                public_key=public_key,
            )
        except (AttributeError, ExecutionAttestationError) as exc:
            raise ArchiveError("execution envelope is not a valid executor attestation") from exc
        self._validate_execution_envelope_binding(candidate_id, verified)
        content = canonical_execution_envelope_bytes(verified)
        expected_digest = execution_envelope_digest(verified)
        manifest = self._record_artifact(
            kind="execution_attestation",
            visibility="sealed_evaluator",
            content=content,
            metadata={
                "candidate_id": candidate_id,
                "evaluation_side": verified.binding.evaluation_side,
                "run_id": verified.binding.run_id,
            },
        )
        if manifest.get("content_object") != expected_digest:
            raise ArchiveError("retained execution envelope has an unexpected CAS identity")
        return manifest

    def _record_artifact(
        self,
        *,
        kind: str,
        visibility: str,
        content: bytes,
        metadata: object | None,
    ) -> dict[str, object]:
        content_object = self.put_bytes(content)
        metadata_object = self.put_json(metadata or {})
        identity = {
            "kind": kind,
            "visibility": visibility,
            "content_object": content_object.digest,
            "metadata_object": metadata_object.digest,
        }
        artifact_id = f"artifact_{_digest_json(identity)[:24]}"
        manifest: dict[str, object] = {
            "schema_version": 1,
            "artifact_id": artifact_id,
            **identity,
            "created_at": _now(),
        }
        with self._lock():
            return self._publish_manifest_event_locked(
                manifest_kind="artifacts",
                event_kind="artifact_recorded",
                identifier=artifact_id,
                proposed=manifest,
            )

    def register_candidate(
        self,
        *,
        campaign_id: str,
        parent_ref: str,
        artifact_kind: str,
        patch: bytes,
        config: object,
    ) -> dict[str, object]:
        self.recover()
        _archive_id(campaign_id, "campaign")
        if artifact_kind not in {"knowledge_pack", "policy_patch", "source_patch"}:
            raise ArchiveError("candidate artifact kind is unsupported")
        if not parent_ref or len(parent_ref) > _MAX_PARENT_REF_CHARS:
            raise ArchiveError("candidate parent reference is invalid")
        campaign = self._load_manifest("campaigns", campaign_id)
        patch_object = self.put_bytes(patch)
        config_object = self.put_json(config)
        identity = {
            "campaign_id": campaign_id,
            "parent_ref": parent_ref,
            "artifact_kind": artifact_kind,
            "patch_object": patch_object.digest,
            "config_object": config_object.digest,
            "proposal_input_set_object": campaign["proposal_input_set_object"],
            "base_commit": campaign["champion_commit"],
        }
        candidate_id = f"candidate_{_digest_json(identity)[:24]}"
        manifest: dict[str, object] = {
            "schema_version": CANDIDATE_SCHEMA_VERSION,
            "candidate_id": candidate_id,
            **identity,
            "created_at": _now(),
        }
        with self._lock():
            if self._event_payload_locked("candidate_registered", candidate_id) is not None:
                return self._publish_manifest_event_locked(
                    manifest_kind="candidates",
                    event_kind="candidate_registered",
                    identifier=candidate_id,
                    proposed=manifest,
                )
            pointer = self._required_pointer()
            if pointer["campaign_id"] != campaign_id:
                raise ArchiveError("candidate campaign is not the active lab campaign")
            if pointer["champion_ref"] != parent_ref:
                raise ArchiveError("candidate parent is not the current lab champion")
            source_parent = f"source:{campaign['champion_commit']}"
            if parent_ref != source_parent or pointer.get("candidate_id") is not None:
                raise ArchiveError(
                    "campaign generation is closed; start a new campaign from the reviewed winner"
                )
            return self._publish_manifest_event_locked(
                manifest_kind="candidates",
                event_kind="candidate_registered",
                identifier=candidate_id,
                proposed=manifest,
            )

    def record_evaluation(
        self,
        *,
        candidate_id: str,
        signed_evaluation: dict[str, object],
    ) -> dict[str, object]:
        self.recover()
        _archive_id(candidate_id, "candidate")
        candidate = self._load_manifest("candidates", candidate_id)
        campaign = self._load_manifest("campaigns", str(candidate["campaign_id"]))
        public_key = self.read_object(str(campaign["referee_public_key_object"]))
        try:
            signed = verify_signed_evaluation(signed_evaluation, public_key=public_key)
            expected_binding = self.evaluation_binding(
                candidate_id,
                champion_receipts_object=signed.binding.champion_receipts_object,
                candidate_receipts_object=signed.binding.candidate_receipts_object,
                require_current=True,
            )
        except (AttestationError, ValueError) as exc:
            raise ArchiveError(
                "evaluation is not a valid candidate-bound referee attestation"
            ) from exc
        if signed.binding != expected_binding:
            raise ArchiveError(
                "evaluation attestation does not match the archived candidate campaign"
            )
        raw_config = _decode_json_object(
            self.read_object(str(campaign["evaluation_config_object"])),
            label="campaign evaluation config",
        )
        try:
            campaign_config = EvaluationConfig.from_mapping(raw_config)
        except ValueError as exc:
            raise ArchiveError("campaign evaluation config is invalid") from exc
        recomputed = self._recompute_evaluation(signed.binding, config=campaign_config)
        if signed.receipt.to_json() != recomputed.to_json():
            raise ArchiveError("signed evaluation does not match archived receipt recomputation")
        signed_object = self.put_json(signed.to_json())
        identity = {
            "campaign_id": candidate["campaign_id"],
            "candidate_id": candidate_id,
            "signed_evaluation_object": signed_object.digest,
            "champion_receipts_object": signed.binding.champion_receipts_object,
            "candidate_receipts_object": signed.binding.candidate_receipts_object,
            "accepted": signed.receipt.accepted,
        }
        evaluation_id = f"evaluation_{_digest_json(identity)[:24]}"
        manifest: dict[str, object] = {
            "schema_version": EVALUATION_RECORD_SCHEMA_VERSION,
            "evaluation_id": evaluation_id,
            **identity,
            "created_at": _now(),
        }
        with self._lock():
            if self._event_payload_locked("evaluation_recorded", evaluation_id) is not None:
                return self._publish_manifest_event_locked(
                    manifest_kind="evaluations",
                    event_kind="evaluation_recorded",
                    identifier=evaluation_id,
                    proposed=manifest,
                )
            pointer = self._required_pointer()
            if (
                pointer.get("campaign_id") != candidate["campaign_id"]
                or pointer.get("champion_ref") != candidate["parent_ref"]
            ):
                raise ArchiveError("evaluation candidate is stale relative to the lab champion")
            return self._publish_manifest_event_locked(
                manifest_kind="evaluations",
                event_kind="evaluation_recorded",
                identifier=evaluation_id,
                proposed=manifest,
            )

    def evaluation_binding(
        self,
        candidate_id: str,
        *,
        champion_receipts_object: str,
        candidate_receipts_object: str,
        require_current: bool = True,
    ) -> EvaluationBinding:
        candidate = self._load_manifest("candidates", candidate_id)
        campaign = self._load_manifest("campaigns", str(candidate["campaign_id"]))
        if require_current:
            pointer = self._required_pointer()
            if (
                pointer.get("campaign_id") != candidate["campaign_id"]
                or pointer.get("champion_ref") != candidate["parent_ref"]
            ):
                raise ArchiveError("candidate is stale relative to the active lab champion")
        try:
            champion = load_canonical_run_receipts(self.read_object(champion_receipts_object))
            candidate_receipts = load_canonical_run_receipts(
                self.read_object(candidate_receipts_object)
            )
        except ValueError as exc:
            raise ArchiveError("evaluation binding receipt objects are invalid") from exc
        if not champion or not candidate_receipts:
            raise ArchiveError("evaluation binding receipt objects are empty")
        self._verify_receipt_execution_envelopes(
            candidate_id,
            champion_receipts=champion,
            candidate_receipts=candidate_receipts,
        )
        try:
            return EvaluationBinding(
                campaign_id=str(candidate["campaign_id"]),
                candidate_id=candidate_id,
                candidate_parent_ref=str(candidate["parent_ref"]),
                champion_commit=str(campaign["champion_commit"]),
                champion_tree=str(campaign["champion_tree"]),
                candidate_patch_object=str(candidate["patch_object"]),
                candidate_config_object=str(candidate["config_object"]),
                evaluation_config_object=str(campaign["evaluation_config_object"]),
                evaluation_suite_object=str(campaign["evaluation_suite_object"]),
                runner_image=str(campaign["runner_image"]),
                champion_receipts_object=champion_receipts_object,
                candidate_receipts_object=candidate_receipts_object,
            )
        except AttestationError as exc:
            raise ArchiveError("archive cannot construct a valid evaluation binding") from exc

    def prepare_evaluation_binding(
        self,
        candidate_id: str,
        *,
        champion_receipts: Sequence[RunReceipt],
        candidate_receipts: Sequence[RunReceipt],
    ) -> EvaluationBinding:
        """Retain canonical raw receipt sets before a referee signs their result."""
        self.recover()
        self._verify_receipt_execution_envelopes(
            candidate_id,
            champion_receipts=champion_receipts,
            candidate_receipts=candidate_receipts,
        )
        champion_object = self.put_bytes(canonical_run_receipts_bytes(champion_receipts))
        candidate_object = self.put_bytes(canonical_run_receipts_bytes(candidate_receipts))
        return self.evaluation_binding(
            candidate_id,
            champion_receipts_object=champion_object.digest,
            candidate_receipts_object=candidate_object.digest,
        )

    def campaign_evaluation_config(self, candidate_id: str) -> EvaluationConfig:
        candidate = self._load_manifest("candidates", candidate_id)
        campaign = self._load_manifest("campaigns", str(candidate["campaign_id"]))
        payload = _decode_json_object(
            self.read_object(str(campaign["evaluation_config_object"])),
            label="campaign evaluation config",
        )
        try:
            return EvaluationConfig.from_mapping(payload)
        except ValueError as exc:
            raise ArchiveError("campaign evaluation config is invalid") from exc

    def campaign_evaluation_suite(self, candidate_id: str) -> EvaluationSuite:
        candidate = self._load_manifest("candidates", candidate_id)
        campaign = self._load_manifest("campaigns", str(candidate["campaign_id"]))
        try:
            return EvaluationSuite.from_bytes(
                self.read_object(str(campaign["evaluation_suite_object"]))
            )
        except ValueError as exc:
            raise ArchiveError("campaign evaluation suite is invalid") from exc

    def _recompute_evaluation(
        self,
        binding: EvaluationBinding,
        *,
        config: EvaluationConfig | None = None,
    ) -> EvaluationReceipt:
        try:
            champion = load_canonical_run_receipts(
                self.read_object(binding.champion_receipts_object)
            )
            candidate = load_canonical_run_receipts(
                self.read_object(binding.candidate_receipts_object)
            )
        except ValueError as exc:
            raise ArchiveError("archived evaluation receipt sets are invalid") from exc
        self._verify_receipt_execution_envelopes(
            binding.candidate_id,
            champion_receipts=champion,
            candidate_receipts=candidate,
        )
        selected = config or self.campaign_evaluation_config(binding.candidate_id)
        suite = self.campaign_evaluation_suite(binding.candidate_id)
        return evaluate_candidate(champion, candidate, config=selected, suite=suite)

    def campaign_referee_public_key(self, candidate_id: str) -> bytes:
        candidate = self._load_manifest("candidates", candidate_id)
        campaign = self._load_manifest("campaigns", str(candidate["campaign_id"]))
        return self.read_object(str(campaign["referee_public_key_object"]))

    def campaign_executor_public_key(self, candidate_id: str) -> bytes:
        candidate = self._load_manifest("candidates", candidate_id)
        campaign = self._load_manifest("campaigns", str(candidate["campaign_id"]))
        return self.read_object(str(campaign["executor_public_key_object"]))

    def _verify_receipt_execution_envelopes(
        self,
        candidate_id: str,
        *,
        champion_receipts: Sequence[RunReceipt],
        candidate_receipts: Sequence[RunReceipt],
    ) -> None:
        public_key = self.campaign_executor_public_key(candidate_id)
        seen: set[str] = set()
        for side, receipts in (
            ("champion", champion_receipts),
            ("candidate", candidate_receipts),
        ):
            for receipt in receipts:
                if receipt.execution_kind not in {"fixture", "live"}:
                    continue
                digest = receipt.execution_attestation_digest
                if digest is None:
                    raise ArchiveError("promotable receipt lacks an execution attestation")
                if digest in seen:
                    raise ArchiveError(
                        "execution envelope is reused across promotion receipt sets"
                    )
                seen.add(digest)
                content = self.read_object(digest)
                try:
                    signed = load_canonical_execution_envelope_bytes(
                        content,
                        public_key=public_key,
                    )
                except ExecutionAttestationError as exc:
                    raise ArchiveError(
                        "receipt execution envelope is not a valid executor attestation"
                    ) from exc
                if execution_envelope_digest(signed) != digest:
                    raise ArchiveError("receipt execution envelope CAS identity is invalid")
                self._validate_execution_envelope_binding(candidate_id, signed)
                if signed.binding.evaluation_side != side:
                    raise ArchiveError("receipt execution envelope is bound to the wrong side")
                if signed.to_run_receipt().to_json() != receipt.to_json():
                    raise ArchiveError(
                        "receipt differs from its signed execution attestation"
                    )

    def _validate_execution_envelope_binding(
        self,
        candidate_id: str,
        signed: SignedExecutionEnvelope,
    ) -> None:
        candidate = self._load_manifest("candidates", candidate_id)
        campaign = self._load_manifest("campaigns", str(candidate["campaign_id"]))
        suite = self.campaign_evaluation_suite(candidate_id)
        binding = signed.binding
        if (
            binding.campaign_id != candidate["campaign_id"]
            or binding.candidate_id != candidate_id
            or binding.evaluation_suite_object != campaign["evaluation_suite_object"]
            or binding.trusted_tests_digest != suite.trusted_tests_digest
            or binding.runner_image != campaign["runner_image"]
        ):
            raise ArchiveError(
                "execution envelope does not match the archived candidate campaign"
            )
        if (
            binding.evaluation_side == "champion"
            and binding.candidate_tree_digest != campaign["champion_tree"]
        ):
            raise ArchiveError(
                "champion execution envelope does not match the campaign tree"
            )

    def candidate_runner_image(self, candidate_id: str) -> str:
        candidate = self._load_manifest("candidates", candidate_id)
        campaign = self._load_manifest("campaigns", str(candidate["campaign_id"]))
        return str(campaign["runner_image"])

    def accept_candidate(
        self,
        *,
        candidate_id: str,
        evaluation_id: str,
        expected_champion_ref: str,
        approval: dict[str, object],
    ) -> dict[str, object]:
        self.recover()
        candidate = self._load_manifest("candidates", candidate_id)
        evaluation = self._load_manifest("evaluations", evaluation_id)
        if evaluation.get("candidate_id") != candidate_id or evaluation.get("accepted") is not True:
            raise ArchiveError("candidate lacks an accepted matching evaluation")
        self.evaluation_receipt(evaluation_id)
        _validate_approval(approval, candidate_id=candidate_id, evaluation_id=evaluation_id)
        approval_object = self.put_json(approval)
        with self._lock():
            existing = self._event_payload_locked("candidate_accepted", candidate_id)
            if existing is not None:
                if (
                    existing.get("evaluation_id") != evaluation_id
                    or existing.get("approval_object") != approval_object.digest
                ):
                    raise ArchiveError("completed candidate acceptance conflicts with this retry")
                if self._required_pointer() != existing:
                    raise ArchiveError("accepted candidate pointer projection requires recovery")
                return existing
            pointer = self._required_pointer()
            if pointer["champion_ref"] != expected_champion_ref:
                raise ArchiveError("lab champion changed; compare-and-swap refused promotion")
            if candidate.get("parent_ref") != pointer["champion_ref"]:
                raise ArchiveError("candidate was evaluated against a stale lab champion")
            if pointer["campaign_id"] != candidate["campaign_id"]:
                raise ArchiveError("candidate is not part of the active lab campaign")
            sequence = pointer.get("sequence")
            if isinstance(sequence, bool) or not isinstance(sequence, int):
                raise ArchiveError("lab champion pointer sequence is invalid")
            updated: dict[str, object] = {
                "schema_version": 1,
                "sequence": sequence + 1,
                "campaign_id": pointer["campaign_id"],
                "champion_ref": f"candidate:{candidate_id}",
                "candidate_id": candidate_id,
                "evaluation_id": evaluation_id,
                "approval_object": approval_object.digest,
            }
            self._append_event_locked("candidate_accepted", candidate_id, updated)
            self._write_pointer_locked(updated, expected_ref=expected_champion_ref)
        return updated

    def export_candidate(self, candidate_id: str, destination: Path) -> Path:
        candidate = self._load_manifest("candidates", candidate_id)
        content = self.read_object(str(candidate["patch_object"]))
        target = destination.expanduser()
        if target.exists() or target.is_symlink():
            raise ArchiveError("candidate export destination already exists")
        if target.parent.is_symlink():
            raise ArchiveError("candidate export parent must not be a symlink")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _write_new_file(target, content, mode=0o600)
        return target

    def candidate_materialization(self, candidate_id: str) -> tuple[dict[str, object], bytes]:
        with self._lock():
            candidate = self._load_manifest("candidates", candidate_id)
            pointer = self._required_pointer()
            if pointer.get("campaign_id") != candidate.get("campaign_id") or pointer.get(
                "champion_ref"
            ) != candidate.get("parent_ref"):
                raise ArchiveError("candidate is stale and cannot be materialized")
            patch = self.read_object(str(candidate["patch_object"]))
        return candidate, patch

    def materialize_candidate_view(
        self,
        artifact_ids: list[str],
        destination: Path,
    ) -> Path:
        validated_ids = self._validated_candidate_input_artifacts(artifact_ids)
        target = destination.expanduser()
        if target.exists() or target.is_symlink():
            raise ArchiveError("candidate view destination must be fresh")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.parent.is_symlink():
            raise ArchiveError("candidate view parent must not be a symlink")
        temporary = target.with_name(f".{target.name}.{os.getpid()}.{secrets.token_hex(4)}")
        temporary.mkdir(mode=0o700)
        entries: list[dict[str, object]] = []
        try:
            for artifact_id in validated_ids:
                manifest = self._load_manifest("artifacts", artifact_id)
                kind = str(manifest.get("kind") or "")
                if manifest.get("visibility") != "candidate" or kind not in {
                    "development_corpus",
                    "capability_brief",
                }:
                    raise ArchiveError("candidate view cannot contain sealed evaluator artifacts")
                content = self.read_object(str(manifest["content_object"]))
                _validate_candidate_artifact(kind=kind, content=content)
                filename = f"{artifact_id}-{kind}.json"
                _write_new_file(temporary / filename, content, mode=0o400)
                entries.append(
                    {
                        "artifact_id": artifact_id,
                        "kind": kind,
                        "content_object": manifest["content_object"],
                        "filename": filename,
                    }
                )
            marker = {
                "schema_version": 1,
                "archive_id": self._load_format()["archive_id"],
                "entries": entries,
            }
            _write_new_file(
                temporary / ".improvement-candidate-view.json",
                _canonical_bytes(marker),
                mode=0o400,
            )
            temporary.replace(target)
            _fsync_directory(target.parent)
        except Exception:
            with suppress(OSError):
                shutil.rmtree(temporary)
            raise
        return target.resolve(strict=True)

    def candidate_input_artifact_ids(self, candidate_id: str) -> tuple[str, ...]:
        candidate = self._load_manifest("candidates", candidate_id)
        payload = _decode_json_object(
            self.read_object(str(candidate["proposal_input_set_object"])),
            label="candidate proposal input set",
        )
        if set(payload) != {"schema_version", "artifact_ids"} or payload.get("schema_version") != 1:
            raise ArchiveError("candidate proposal input set is malformed")
        raw_ids = payload.get("artifact_ids")
        if not isinstance(raw_ids, list) or not all(isinstance(item, str) for item in raw_ids):
            raise ArchiveError("candidate proposal input identities are malformed")
        return self._validated_candidate_input_artifacts(tuple(raw_ids))

    def _validated_candidate_input_artifacts(
        self,
        artifact_ids: Sequence[str],
    ) -> tuple[str, ...]:
        normalized = tuple(sorted(str(item) for item in artifact_ids))
        if len(normalized) != _CANDIDATE_INPUT_ARTIFACTS or len(normalized) != len(set(normalized)):
            raise ArchiveError(
                "candidate inputs require exactly one corpus and its capability brief"
            )
        contents: dict[str, bytes] = {}
        for artifact_id in normalized:
            manifest = self._load_manifest("artifacts", artifact_id)
            kind = str(manifest.get("kind") or "")
            if manifest.get("visibility") != "candidate" or kind not in {
                "development_corpus",
                "capability_brief",
            }:
                raise ArchiveError("candidate inputs cannot contain sealed evaluator artifacts")
            if kind in contents:
                raise ArchiveError("candidate inputs contain duplicate artifact kinds")
            content = self.read_object(str(manifest["content_object"]))
            _validate_candidate_artifact(kind=kind, content=content)
            contents[kind] = content
        if set(contents) != {"development_corpus", "capability_brief"}:
            raise ArchiveError("candidate inputs are missing the corpus or capability brief")
        corpus = _decode_json_object(contents["development_corpus"], label="development corpus")
        brief = _decode_json_object(contents["capability_brief"], label="capability brief")
        try:
            rebuilt = build_improvement_brief(corpus)
        except (CorpusError, ImprovementBriefError) as exc:
            raise ArchiveError("candidate input corpus cannot rebuild its brief") from exc
        if rebuilt != brief:
            raise ArchiveError("candidate capability brief does not match its exact corpus")
        return normalized

    def current_pointer(self) -> dict[str, object]:
        return dict(self._required_pointer())

    def evaluation_receipt(
        self,
        evaluation_id: str,
    ) -> tuple[dict[str, object], EvaluationReceipt]:
        manifest, signed = self.signed_evaluation(evaluation_id)
        return manifest, signed.receipt

    def signed_evaluation(
        self,
        evaluation_id: str,
    ) -> tuple[dict[str, object], SignedEvaluation]:
        manifest = self._load_manifest("evaluations", evaluation_id)
        candidate = self._load_manifest("candidates", str(manifest["candidate_id"]))
        campaign = self._load_manifest("campaigns", str(manifest["campaign_id"]))
        raw = _decode_json_object(
            self.read_object(str(manifest["signed_evaluation_object"])),
            label="signed evaluation",
        )
        try:
            signed = verify_signed_evaluation(
                raw,
                public_key=self.read_object(str(campaign["referee_public_key_object"])),
            )
            expected = self.evaluation_binding(
                str(candidate["candidate_id"]),
                champion_receipts_object=signed.binding.champion_receipts_object,
                candidate_receipts_object=signed.binding.candidate_receipts_object,
                require_current=False,
            )
        except (AttestationError, ValueError) as exc:
            raise ArchiveError("archived signed evaluation is invalid") from exc
        if signed.binding != expected:
            raise ArchiveError("archived evaluation binding no longer matches its candidate")
        config = self.campaign_evaluation_config(str(candidate["candidate_id"]))
        recomputed = self._recompute_evaluation(signed.binding, config=config)
        if signed.receipt.to_json() != recomputed.to_json():
            raise ArchiveError("archived evaluation differs from receipt-set recomputation")
        if (
            manifest.get("champion_receipts_object") != signed.binding.champion_receipts_object
            or manifest.get("candidate_receipts_object") != signed.binding.candidate_receipts_object
        ):
            raise ArchiveError("archived evaluation receipt objects differ from its manifest")
        if signed.receipt.accepted is not manifest.get("accepted"):
            raise ArchiveError("archived evaluation decision differs from its manifest")
        return manifest, signed

    def verify(
        self,
        *,
        expected_checkpoint: str | None = None,
        expected_head: str | None = None,
    ) -> ArchiveVerification:
        """Verify one lock-consistent archive snapshot."""
        with self._lock(), self._object_lock():
            return self._verify_locked(
                expected_checkpoint=expected_checkpoint,
                expected_head=expected_head,
            )

    def _verify_locked(  # noqa: C901, PLR0912, PLR0915 - explicit integrity walk.
        self,
        *,
        expected_checkpoint: str | None = None,
        expected_head: str | None = None,
    ) -> ArchiveVerification:
        if expected_checkpoint is not None and expected_head is not None:
            raise ArchiveError("supply only one expected archive checkpoint")
        archive_format = self._load_format()
        _require_exact_directory_entries(
            self.root,
            expected={"format.json", "objects", "manifests", "ledger", "refs"},
        )
        _require_exact_directory_entries(self.root / "objects", expected={"sha256"})
        _require_exact_directory_entries(
            self.manifests_root,
            expected={"artifacts", "campaigns", "candidates", "evaluations"},
        )
        _require_allowed_directory_entries(
            self.ledger_root,
            allowed={".lock", ".objects.lock", "events.jsonl"},
        )
        _require_allowed_directory_entries(
            self.refs_root,
            allowed={"lab-champion.json"},
        )
        for lock_name in (".lock", ".objects.lock"):
            lock_path = self.ledger_root / lock_name
            if lock_path.exists() or lock_path.is_symlink():
                _verify_regular_file(lock_path, allow_links=False)
        object_count = 0
        object_bytes = 0
        verified_bytes = (self.root / "format.json").stat().st_size
        if self.objects_root.exists():
            for prefix in sorted(self.objects_root.iterdir()):
                _require_real_directory(prefix, label="object prefix")
                if re.fullmatch(r"[0-9a-f]{2}", prefix.name) is None:
                    raise ArchiveError("archive object prefix is invalid")
                for path in sorted(prefix.iterdir()):
                    if not re.fullmatch(r"[0-9a-f]{64}", path.name):
                        raise ArchiveError("archive object has an invalid filename")
                    if path.name[:2] != prefix.name:
                        raise ArchiveError("archive object is stored under the wrong prefix")
                    _verify_regular_file(path, expected_digest=path.name)
                    object_count += 1
                    object_bytes += path.stat().st_size
        counts = {}
        manifests: dict[str, dict[str, dict[str, object]]] = {}
        for kind in ("artifacts", "campaigns", "candidates", "evaluations"):
            directory = self.manifests_root / kind
            count = 0
            loaded: dict[str, dict[str, object]] = {}
            if directory.exists():
                _require_real_directory(directory, label="manifest directory")
                for path in sorted(directory.iterdir()):
                    if path.suffix != ".json":
                        raise ArchiveError("archive manifest directory has an unexpected entry")
                    _verify_regular_file(path)
                    payload = _read_json(path)
                    identifier = str(payload.get(kind[:-1] + "_id") or "")
                    if path.stem != identifier:
                        raise ArchiveError("archive manifest filename and identity disagree")
                    _verify_manifest_payload(self, kind=kind, payload=payload)
                    loaded[identifier] = payload
                    count += 1
                    verified_bytes += path.stat().st_size
            counts[kind] = count
            manifests[kind] = loaded
        ledger_events, head = self._verified_ledger_events()
        ledger_path = self.ledger_root / "events.jsonl"
        if ledger_path.exists():
            verified_bytes += ledger_path.stat().st_size
        pointer = self._load_pointer(required=False)
        if pointer is not None:
            verified_bytes += (self.refs_root / "lab-champion.json").stat().st_size
        self._reconcile_history(ledger_events, manifests=manifests, pointer=pointer)
        for evaluation_id in manifests["evaluations"]:
            self.evaluation_receipt(evaluation_id)
        checkpoint = _archive_checkpoint(archive_format, ledger_head=head)
        external_checkpoint = (
            expected_checkpoint if expected_checkpoint is not None else expected_head
        )
        if external_checkpoint is not None:
            anchored = _sha256_digest(
                external_checkpoint,
                label="expected archive checkpoint",
            )
            if checkpoint != anchored:
                raise ArchiveError("archive differs from the external checkpoint")
        return ArchiveVerification(
            objects=object_count,
            object_bytes=object_bytes,
            artifacts=counts["artifacts"],
            campaigns=counts["campaigns"],
            candidates=counts["candidates"],
            evaluations=counts["evaluations"],
            ledger_events=len(ledger_events),
            ledger_head=head,
            archive_checkpoint=checkpoint,
            verified_bytes=verified_bytes + object_bytes,
        )

    def _reconcile_history(  # noqa: C901, PLR0912, PLR0915 - explicit state machine.
        self,
        events: list[dict[str, object]],
        *,
        manifests: dict[str, dict[str, dict[str, object]]],
        pointer: dict[str, object] | None,
        require_pointer_match: bool = True,
    ) -> dict[str, object] | None:
        event_to_manifest = {
            "artifact_recorded": "artifacts",
            "campaign_created": "campaigns",
            "candidate_registered": "candidates",
            "evaluation_recorded": "evaluations",
        }
        seen: dict[str, set[str]] = {kind: set() for kind in manifests}
        reconstructed: dict[str, object] | None = None
        for event in events:
            kind = str(event.get("kind") or "")
            subject_id = str(event.get("subject_id") or "")
            raw_payload = _decode_json_object(
                self.read_object(str(event.get("payload_object") or "")),
                label="archive ledger payload",
            )
            manifest_kind = event_to_manifest.get(kind)
            if manifest_kind is not None:
                manifest = manifests[manifest_kind].get(subject_id)
                if manifest is None:
                    raise ArchiveError("archive ledger references a missing manifest")
                if subject_id in seen[manifest_kind]:
                    raise ArchiveError("archive ledger repeats a manifest event")
                if raw_payload != manifest:
                    raise ArchiveError("archive ledger payload and manifest disagree")
                seen[manifest_kind].add(subject_id)

            if kind == "artifact_recorded":
                continue
            if kind == "campaign_created":
                if reconstructed is not None and reconstructed.get("candidate_id") is None:
                    raise ArchiveError(
                        "archive ledger starts a campaign before closing the prior one"
                    )
                campaign = manifests["campaigns"][subject_id]
                reconstructed = {
                    "schema_version": 1,
                    "sequence": 0,
                    "campaign_id": subject_id,
                    "champion_ref": f"source:{campaign['champion_commit']}",
                    "candidate_id": None,
                    "evaluation_id": None,
                    "approval_object": None,
                }
                continue
            if kind == "candidate_registered":
                if reconstructed is None:
                    raise ArchiveError("archive candidate predates its campaign")
                registered_candidate = manifests["candidates"][subject_id]
                if (
                    registered_candidate.get("campaign_id") != reconstructed.get("campaign_id")
                    or registered_candidate.get("parent_ref") != reconstructed.get("champion_ref")
                    or reconstructed.get("candidate_id") is not None
                ):
                    raise ArchiveError("archive candidate lineage is invalid")
                continue
            if kind == "evaluation_recorded":
                if reconstructed is None:
                    raise ArchiveError("archive evaluation predates its campaign")
                evaluation = manifests["evaluations"][subject_id]
                candidate_id = str(evaluation.get("candidate_id") or "")
                evaluated_candidate = manifests["candidates"].get(candidate_id)
                if (
                    evaluated_candidate is None
                    or candidate_id not in seen["candidates"]
                    or evaluation.get("campaign_id") != reconstructed.get("campaign_id")
                    or evaluated_candidate.get("parent_ref") != reconstructed.get("champion_ref")
                ):
                    raise ArchiveError("archive evaluation lineage is invalid")
                continue
            if kind == "candidate_accepted":
                if reconstructed is None:
                    raise ArchiveError("archive acceptance predates its campaign")
                accepted_candidate = manifests["candidates"].get(subject_id)
                evaluation_id = str(raw_payload.get("evaluation_id") or "")
                accepted_evaluation = manifests["evaluations"].get(evaluation_id)
                if (
                    accepted_candidate is None
                    or subject_id not in seen["candidates"]
                    or accepted_evaluation is None
                    or evaluation_id not in seen["evaluations"]
                    or accepted_evaluation.get("candidate_id") != subject_id
                    or accepted_evaluation.get("accepted") is not True
                    or accepted_candidate.get("campaign_id") != reconstructed.get("campaign_id")
                    or accepted_candidate.get("parent_ref") != reconstructed.get("champion_ref")
                ):
                    raise ArchiveError("archive acceptance lineage is invalid")
                sequence = reconstructed.get("sequence")
                if isinstance(sequence, bool) or not isinstance(sequence, int):
                    raise ArchiveError("archive reconstructed pointer sequence is invalid")
                approval_object = str(raw_payload.get("approval_object") or "")
                approval = _decode_json_object(
                    self.read_object(approval_object),
                    label="archive human approval",
                )
                _validate_approval(
                    approval,
                    candidate_id=subject_id,
                    evaluation_id=evaluation_id,
                )
                expected_pointer = {
                    "schema_version": 1,
                    "sequence": sequence + 1,
                    "campaign_id": reconstructed["campaign_id"],
                    "champion_ref": f"candidate:{subject_id}",
                    "candidate_id": subject_id,
                    "evaluation_id": evaluation_id,
                    "approval_object": approval_object,
                }
                if raw_payload != expected_pointer:
                    raise ArchiveError("archive acceptance payload is not the expected pointer")
                reconstructed = expected_pointer
                continue
            raise ArchiveError("archive ledger contains an unsupported event kind")

        for manifest_kind, indexed in manifests.items():
            if seen[manifest_kind] != set(indexed):
                raise ArchiveError("archive manifest and ledger coverage disagree")
        if require_pointer_match and pointer != reconstructed:
            raise ArchiveError("archive lab pointer does not match reconstructed ledger history")
        return reconstructed

    def _load_format(self) -> dict[str, object]:
        path = self.root / "format.json"
        _verify_regular_file(path)
        payload = _read_json(path)
        if set(payload) != {"schema_version", "archive_id", "created_at"}:
            raise ArchiveError("archive format fields are invalid")
        if payload.get("schema_version") != ARCHIVE_SCHEMA_VERSION:
            raise ArchiveError("archive format is unsupported")
        if _ARCHIVE_ID_RE.fullmatch(str(payload.get("archive_id") or "")) is None:
            raise ArchiveError("archive format identity is invalid")
        _timestamp(payload.get("created_at"), label="archive creation timestamp")
        return payload

    def _object_path(self, digest: str) -> Path:
        digest_hex = _object_hex(digest)
        return self.objects_root / digest_hex[:2] / digest_hex

    def _manifest_path(self, kind: str, identifier: str) -> Path:
        if kind not in {"artifacts", "campaigns", "candidates", "evaluations"}:
            raise ArchiveError("archive manifest kind is unsupported")
        _archive_id(identifier, kind[:-1])
        return self.manifests_root / kind / f"{identifier}.json"

    def _write_manifest(
        self,
        kind: str,
        identifier: str,
        payload: object,
        *,
        repair: bool = False,
    ) -> None:
        path = self._manifest_path(kind, identifier)
        encoded = _canonical_bytes(payload)
        if path.exists() or path.is_symlink():
            if not repair:
                _verify_regular_file(path)
                if path.read_bytes() != encoded:
                    raise ArchiveError("immutable archive manifest already has different content")
                return
            try:
                _verify_regular_file(path)
                if path.read_bytes() == encoded:
                    return
            except ArchiveError:
                pass
        _atomic_replace_file(path, encoded, mode=0o400)

    def _publish_manifest_event_locked(
        self,
        *,
        manifest_kind: str,
        event_kind: str,
        identifier: str,
        proposed: dict[str, object],
    ) -> dict[str, object]:
        existing = self._event_payload_locked(event_kind, identifier)
        if existing is not None:
            if not _same_retry_payload(existing, proposed):
                raise ArchiveError("completed archive operation was retried with different content")
            self._write_manifest(manifest_kind, identifier, existing, repair=True)
            return existing
        path = self._manifest_path(manifest_kind, identifier)
        committed = proposed
        if path.exists() or path.is_symlink():
            committed = self._load_manifest(manifest_kind, identifier)
            if not _same_retry_payload(committed, proposed):
                raise ArchiveError("incomplete archive operation has conflicting manifest content")
        self._append_event_locked(event_kind, identifier, committed)
        self._write_manifest(manifest_kind, identifier, committed, repair=True)
        return committed

    def _load_manifest(self, kind: str, identifier: str) -> dict[str, object]:
        path = self._manifest_path(kind, identifier)
        _verify_regular_file(path)
        return _read_json(path)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        with _exclusive_private_lock(self.ledger_root / ".lock"):
            yield

    @contextmanager
    def _object_lock(self) -> Iterator[None]:
        with _exclusive_private_lock(self.ledger_root / ".objects.lock"):
            yield

    def _cleanup_publication_temps_locked(self) -> None:
        """Remove or finish only archive-owned publication temp patterns."""
        with self._object_lock():
            self._cleanup_object_publication_temps_locked()
        _cleanup_projection_temps(self.ledger_root, kind="ledger")
        _cleanup_projection_temps(self.refs_root, kind="refs")
        for manifest_kind in ("artifacts", "campaigns", "candidates", "evaluations"):
            _cleanup_projection_temps(
                self.manifests_root / manifest_kind,
                kind=manifest_kind,
            )

    def _cleanup_object_publication_temps_locked(self) -> None:  # noqa: C901, PLR0912
        _require_real_directory(self.objects_root, label="archive object directory")
        for prefix in sorted(self.objects_root.iterdir()):
            if re.fullmatch(r"[0-9a-f]{2}", prefix.name) is None or not prefix.is_dir():
                continue
            _require_real_directory(prefix, label="archive object prefix")
            changed = False
            for temporary in sorted(prefix.iterdir()):
                match = _OBJECT_TEMP_RE.fullmatch(temporary.name)
                if match is None:
                    continue
                digest_hex = match.group(1)
                if digest_hex[:2] != prefix.name:
                    continue
                try:
                    item_stat = temporary.lstat()
                except OSError as exc:
                    raise ArchiveError("cannot inspect archive object temporary") from exc
                if (
                    temporary.is_symlink()
                    or not stat.S_ISREG(item_stat.st_mode)
                    or item_stat.st_uid != os.getuid()
                    or stat.S_IMODE(item_stat.st_mode) & 0o077
                    or item_stat.st_nlink not in {1, _MAX_PUBLICATION_LINKS}
                ):
                    raise ArchiveError("archive object temporary is unsafe to recover")
                with suppress(OSError):
                    temporary.chmod(0o400)
                _verify_regular_file(
                    temporary,
                    expected_digest=digest_hex,
                    allow_links=True,
                )
                destination = prefix / digest_hex
                if destination.exists() or destination.is_symlink():
                    _verify_regular_file(
                        destination,
                        expected_digest=digest_hex,
                        allow_links=True,
                    )
                    if item_stat.st_nlink == _MAX_PUBLICATION_LINKS and not temporary.samefile(
                        destination
                    ):
                        raise ArchiveError("archive object temporary has an unexpected hard link")
                else:
                    if item_stat.st_nlink != 1:
                        raise ArchiveError("archive object temporary has an unexpected hard link")
                    try:
                        os.link(temporary, destination)
                    except OSError as exc:
                        raise ArchiveError("cannot finish archive object publication") from exc
                try:
                    temporary.unlink()
                except OSError as exc:
                    raise ArchiveError("cannot clean archive object temporary") from exc
                _verify_regular_file(destination, expected_digest=digest_hex)
                changed = True
            if changed:
                _fsync_directory(prefix)

    def _event_payload_locked(
        self,
        kind: str,
        subject_id: str,
    ) -> dict[str, object] | None:
        events, _head = self._verified_ledger_events()
        matches = [
            event
            for event in events
            if event.get("kind") == kind and event.get("subject_id") == subject_id
        ]
        if len(matches) > 1:
            raise ArchiveError("archive ledger repeats one operation identity")
        if not matches:
            return None
        return _decode_json_object(
            self.read_object(str(matches[0]["payload_object"])),
            label="archive event payload",
        )

    def _append_event_locked(
        self,
        kind: str,
        subject_id: str,
        payload: object,
    ) -> dict[str, object]:
        events, previous = self._verified_ledger_events()
        payload_object = self.put_json(payload)
        matching = [
            event
            for event in events
            if event.get("kind") == kind and event.get("subject_id") == subject_id
        ]
        if matching:
            if len(matching) != 1 or matching[0].get("payload_object") != payload_object.digest:
                raise ArchiveError("archive event operation identity conflicts with prior content")
            return matching[0]
        unsigned = {
            "schema_version": 1,
            "sequence": len(events) + 1,
            "timestamp": _now(),
            "kind": kind,
            "subject_id": subject_id,
            "payload_object": payload_object.digest,
            "previous_event_digest": previous,
        }
        event = {**unsigned, "event_digest": f"sha256:{_digest_json(unsigned)}"}
        ledger = self.ledger_root / "events.jsonl"
        prior = ledger.read_bytes() if ledger.exists() else b""
        if prior and not prior.endswith(b"\n"):
            raise ArchiveError("archive ledger has an incomplete trailing event")
        _atomic_replace_file(ledger, prior + _canonical_bytes(event), mode=0o600)
        return event

    def _verify_ledger(self) -> tuple[int, str]:
        events, head = self._verified_ledger_events()
        return len(events), head

    def _verified_ledger_events(self) -> tuple[list[dict[str, object]], str]:  # noqa: C901
        ledger = self.ledger_root / "events.jsonl"
        if not ledger.exists():
            return [], ""
        _verify_regular_file(ledger, allow_links=False)
        previous = ""
        verified: list[dict[str, object]] = []
        try:
            ledger_content = ledger.read_bytes()
        except OSError as exc:
            raise ArchiveError("cannot read archive event ledger") from exc
        lines = ledger_content.splitlines()
        for count, raw in enumerate(lines, start=1):
            if not raw:
                raise ArchiveError("archive ledger contains an empty event")
            event = _strict_json_object(raw, label="archive ledger event")
            expected_fields = {
                "schema_version",
                "sequence",
                "timestamp",
                "kind",
                "subject_id",
                "payload_object",
                "previous_event_digest",
                "event_digest",
            }
            if set(event) != expected_fields or event.get("schema_version") != 1:
                raise ArchiveError("archive ledger event fields are invalid")
            if raw != _canonical_bytes(event)[:-1]:
                raise ArchiveError("archive ledger event is not byte-canonical")
            if not isinstance(event, dict):
                raise ArchiveError("archive ledger event must be an object")
            kind = str(event.get("kind") or "")
            subject_kinds = {
                "artifact_recorded": "artifact",
                "campaign_created": "campaign",
                "candidate_registered": "candidate",
                "evaluation_recorded": "evaluation",
                "candidate_accepted": "candidate",
            }
            subject_kind = subject_kinds.get(kind)
            if subject_kind is None:
                raise ArchiveError("archive ledger contains an unsupported event kind")
            _archive_id(str(event.get("subject_id") or ""), subject_kind)
            _timestamp(event.get("timestamp"), label="archive ledger timestamp")
            digest = _sha256_digest(
                str(event.get("event_digest") or ""),
                label="archive event digest",
            )
            unsigned = {key: value for key, value in event.items() if key != "event_digest"}
            if event.get("sequence") != count or event.get("previous_event_digest") != previous:
                raise ArchiveError("archive ledger sequence or hash chain is invalid")
            expected = f"sha256:{_digest_json(unsigned)}"
            if digest != expected:
                raise ArchiveError("archive ledger event digest is invalid")
            self.read_object(str(event.get("payload_object") or ""))
            verified.append(dict(event))
            previous = digest
        if ledger_content != b"".join(_canonical_bytes(event) for event in verified):
            raise ArchiveError("archive ledger is not byte-canonical")
        return verified, previous

    def _load_pointer(self, *, required: bool) -> dict[str, object] | None:
        path = self.refs_root / "lab-champion.json"
        if not path.exists():
            if required:
                raise ArchiveError("lab champion pointer does not exist")
            return None
        _verify_regular_file(path, allow_links=False)
        payload = _read_json(path)
        required_fields = {
            "schema_version",
            "sequence",
            "campaign_id",
            "champion_ref",
            "candidate_id",
            "evaluation_id",
            "approval_object",
        }
        if set(payload) != required_fields or payload.get("schema_version") != 1:
            raise ArchiveError("lab champion pointer is malformed")
        return payload

    def _required_pointer(self) -> dict[str, object]:
        pointer = self._load_pointer(required=True)
        if pointer is None:
            raise ArchiveError("lab champion pointer does not exist")
        return pointer

    def _write_pointer_locked(
        self,
        payload: dict[str, object],
        *,
        expected_ref: str | None,
    ) -> None:
        current = self._load_pointer(required=False)
        if expected_ref is None and current is not None:
            raise ArchiveError("lab champion pointer already exists")
        if expected_ref is not None and (
            current is None or current.get("champion_ref") != expected_ref
        ):
            raise ArchiveError("lab champion compare-and-swap precondition failed")
        self._replace_pointer_projection_locked(payload)

    def _replace_pointer_projection_locked(self, payload: dict[str, object]) -> None:
        destination = self.refs_root / "lab-champion.json"
        _atomic_replace_file(destination, _canonical_bytes(payload), mode=0o600)


@contextmanager
def _exclusive_private_lock(lock_path: Path) -> Iterator[None]:
    """Acquire one owner-only archive lock without following substituted links."""
    descriptor = -1
    locked = False
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, _PRIVATE_LOCK_MODE)
        _verify_lock_descriptor(lock_path, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        _verify_lock_descriptor(lock_path, descriptor)
        yield
    except ArchiveError:
        raise
    except OSError as exc:
        raise ArchiveError("cannot acquire the private archive lock") from exc
    finally:
        if descriptor >= 0:
            if locked:
                with suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _verify_lock_descriptor(lock_path: Path, descriptor: int) -> None:
    try:
        descriptor_stat = os.fstat(descriptor)
        path_stat = lock_path.lstat()
    except OSError as exc:
        raise ArchiveError("archive lock file is unsafe") from exc
    if (
        lock_path.is_symlink()
        or not stat.S_ISREG(descriptor_stat.st_mode)
        or descriptor_stat.st_uid != os.getuid()
        or descriptor_stat.st_nlink != 1
        or stat.S_IMODE(descriptor_stat.st_mode) != _PRIVATE_LOCK_MODE
        or descriptor_stat.st_dev != path_stat.st_dev
        or descriptor_stat.st_ino != path_stat.st_ino
    ):
        raise ArchiveError("archive lock file is unsafe")


def _validate_approval(
    approval: dict[str, object],
    *,
    candidate_id: str,
    evaluation_id: str,
) -> None:
    required = {
        "schema_version",
        "decision",
        "candidate_id",
        "evaluation_id",
        "reviewer",
        "approved_at",
        "statement",
    }
    if set(approval) != required:
        raise ArchiveError("human approval fields do not match the canonical schema")
    if approval.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        raise ArchiveError("human approval schema is unsupported")
    if approval.get("decision") != "accept":
        raise ArchiveError("human approval decision must be accept")
    if (
        approval.get("candidate_id") != candidate_id
        or approval.get("evaluation_id") != evaluation_id
    ):
        raise ArchiveError("human approval does not match candidate and evaluation")
    for field in ("reviewer", "approved_at", "statement"):
        value = approval.get(field)
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > _MAX_APPROVAL_FIELD_CHARS
        ):
            raise ArchiveError("human approval contains an invalid required field")


def _verify_manifest_payload(
    archive: LabArchive,
    *,
    kind: str,
    payload: dict[str, object],
) -> None:
    schemas = {
        "artifacts": 1,
        "campaigns": CAMPAIGN_SCHEMA_VERSION,
        "candidates": CANDIDATE_SCHEMA_VERSION,
        "evaluations": EVALUATION_RECORD_SCHEMA_VERSION,
    }
    identity_fields = {
        "artifacts": ("kind", "visibility", "content_object", "metadata_object"),
        "campaigns": (
            "champion_commit",
            "champion_tree",
            "source_status_digest",
            "evaluation_config_object",
            "evaluation_suite_object",
            "runner_image",
            "referee_public_key_object",
            "referee_key_id",
            "executor_public_key_object",
            "executor_key_id",
            "proposal_input_set_object",
        ),
        "candidates": (
            "campaign_id",
            "parent_ref",
            "artifact_kind",
            "patch_object",
            "config_object",
            "proposal_input_set_object",
            "base_commit",
        ),
        "evaluations": (
            "campaign_id",
            "candidate_id",
            "signed_evaluation_object",
            "champion_receipts_object",
            "candidate_receipts_object",
            "accepted",
        ),
    }
    identifier_field = f"{kind[:-1]}_id"
    required_fields = {
        "schema_version",
        identifier_field,
        "created_at",
        *identity_fields[kind],
    }
    if set(payload) != required_fields:
        raise ArchiveError("archive manifest fields are invalid")
    if payload.get("schema_version") != schemas[kind]:
        raise ArchiveError("archive manifest schema is invalid")
    _timestamp(payload.get("created_at"), label="archive manifest timestamp")
    identity = {field: payload.get(field) for field in identity_fields[kind]}
    expected_id = f"{kind[:-1]}_{_digest_json(identity)[:24]}"
    if payload.get(identifier_field) != expected_id:
        raise ArchiveError("archive manifest content identity is invalid")
    for field, value in payload.items():
        if field.endswith("_object"):
            archive.read_object(str(value or ""))
    if kind == "campaigns":
        try:
            referee_id = referee_key_id(
                archive.read_object(str(payload["referee_public_key_object"]))
            )
            executor_id = referee_key_id(
                archive.read_object(str(payload["executor_public_key_object"]))
            )
        except AttestationError as exc:
            raise ArchiveError("archive campaign public key is invalid") from exc
        if (
            payload.get("referee_key_id") != referee_id
            or payload.get("executor_key_id") != executor_id
            or referee_id == executor_id
        ):
            raise ArchiveError("archive campaign key identities are invalid")


def _create_archive_root(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ArchiveError("archive root must not be a symlink")
    candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = candidate.resolve(strict=True)
    if resolved in {Path("/").resolve(), Path.home().resolve()}:
        raise ArchiveError("archive root is too broad")
    resolved.chmod(0o700)
    return resolved


def _real_archive_root(path: Path) -> Path:
    candidate = path.expanduser()
    _require_real_directory(candidate, label="archive root")
    return candidate.resolve(strict=True)


def _private_directory(path: Path) -> Path:
    if path.is_symlink():
        raise ArchiveError("archive directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _require_real_directory(path, label="archive directory")
    path.chmod(0o700)
    return path


def _require_real_directory(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ArchiveError(f"{label} must be a real directory")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ArchiveError(f"{label} must not grant group or other permissions")


def _require_exact_directory_entries(path: Path, *, expected: set[str]) -> None:
    _require_real_directory(path, label="archive directory")
    actual = {entry.name for entry in path.iterdir()}
    if actual != expected:
        raise ArchiveError("archive directory entries do not match the canonical layout")


def _require_allowed_directory_entries(path: Path, *, allowed: set[str]) -> None:
    _require_real_directory(path, label="archive directory")
    actual = {entry.name for entry in path.iterdir()}
    if not actual <= allowed:
        raise ArchiveError("archive directory contains an unexpected entry")


def _write_new_file(path: Path, content: bytes, *, mode: int) -> None:
    if path.is_symlink():
        raise ArchiveError("archive output path must not be a symlink")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(mode)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise ArchiveError("cannot create immutable archive file") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_replace_file(path: Path, content: bytes, *, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}")
    _write_new_file(temporary, content, mode=mode)
    try:
        temporary.replace(path)
        path.chmod(mode)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise ArchiveError("cannot atomically replace archive projection") from exc
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _same_retry_payload(existing: Mapping[str, object], proposed: Mapping[str, object]) -> bool:
    return {key: value for key, value in existing.items() if key != "created_at"} == {
        key: value for key, value in proposed.items() if key != "created_at"
    }


def _verify_regular_file(
    path: Path,
    *,
    expected_digest: str | None = None,
    allow_links: bool = False,
) -> None:
    try:
        stat_result = path.lstat()
    except OSError as exc:
        raise ArchiveError("archive file is missing or unreadable") from exc
    if path.is_symlink() or not path.is_file():
        raise ArchiveError("archive entry must be a regular file")
    if stat.S_IMODE(stat_result.st_mode) & 0o077:
        raise ArchiveError("archive file must not grant group or other permissions")
    if not allow_links and stat_result.st_nlink != 1:
        raise ArchiveError("archive file must not have hard links")
    if expected_digest is not None:
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise ArchiveError("archive object is unreadable") from exc
        if actual != expected_digest:
            raise ArchiveError("archive object digest mismatch")


def _read_json(path: Path) -> dict[str, object]:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ArchiveError("archive JSON is unreadable") from exc
    return _decode_json_object(content, label="archive JSON")


def _decode_json_object(content: bytes, *, label: str) -> dict[str, object]:
    payload = _strict_json_object(content, label=label)
    if content != _canonical_bytes(payload):
        raise ArchiveError(f"{label} is not byte-canonical")
    return payload


def _strict_json_object(content: bytes | str, *, label: str) -> dict[str, object]:
    def reject_constant(_value: str) -> object:
        raise ArchiveError(f"{label} contains a non-finite JSON number")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ArchiveError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        payload = json.loads(
            content,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (UnicodeError, ValueError) as exc:
        raise ArchiveError(f"{label} is unreadable") from exc
    if not isinstance(payload, dict):
        raise ArchiveError(f"{label} must be an object")
    return {str(key): value for key, value in payload.items()}


def _canonicalize_candidate_artifact(*, kind: str, content: bytes) -> bytes:
    payload = _strict_json_object(content, label="candidate-visible artifact")
    if kind == "development_corpus":
        if payload.get("schema_version") != CORPUS_SCHEMA_VERSION:
            raise ArchiveError("candidate-visible corpus schema is unsupported")
        capsules = payload.get("capsules")
        if not isinstance(capsules, list):
            raise ArchiveError("candidate-visible corpus capsules are malformed")
        try:
            rebuilt = candidate_visible_export(capsules)
        except CorpusError as exc:
            raise ArchiveError("candidate-visible corpus failed the secret boundary") from exc
        if rebuilt != payload:
            raise ArchiveError("candidate-visible corpus is not canonical")
    elif kind == "capability_brief":
        try:
            validate_improvement_brief(payload)
        except (CorpusError, ImprovementBriefError) as exc:
            raise ArchiveError("candidate-visible capability brief is malformed") from exc
    else:
        raise ArchiveError("candidate-visible artifact kind is unsupported")
    return _canonical_bytes(payload)


def _validate_candidate_artifact(*, kind: str, content: bytes) -> None:
    if content != _canonicalize_candidate_artifact(kind=kind, content=content):
        raise ArchiveError("candidate-visible artifact is not byte-canonical")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _object_hex(value: str) -> str:
    match = _OBJECT_RE.fullmatch(value)
    if match is None:
        raise ArchiveError("archive object digest is invalid")
    return match.group(1)


def _archive_id(value: str, kind: str) -> str:
    if re.fullmatch(
        r"(?:artifact|campaign|candidate|evaluation)_[0-9a-f]{24}", value
    ) is None or not value.startswith(f"{kind}_"):
        raise ArchiveError("archive manifest identity is invalid")
    return value


def _git_id(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if _GIT_ID_RE.fullmatch(normalized) is None:
        raise ArchiveError(f"{label} is invalid")
    return normalized


def _sha256_digest(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if _OBJECT_RE.fullmatch(normalized) is None:
        raise ArchiveError(f"{label} must be a sha256 digest")
    return normalized


def _timestamp(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TIMESTAMP_CHARS:
        raise ArchiveError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ArchiveError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ArchiveError(f"{label} must include a timezone")
    return value


def _archive_checkpoint(format_payload: Mapping[str, object], *, ledger_head: str) -> str:
    format_digest = f"sha256:{hashlib.sha256(_canonical_bytes(format_payload)).hexdigest()}"
    checkpoint = {
        "schema_version": 1,
        "format_digest": format_digest,
        "ledger_head": ledger_head,
    }
    return f"sha256:{_digest_json(checkpoint)}"


def _unlink_projection(path: Path, *, label: str) -> None:
    try:
        item_stat = path.lstat()
        if not (path.is_symlink() or stat.S_ISREG(item_stat.st_mode)):
            raise ArchiveError(f"{label} is not a replaceable projection")
        path.unlink()
        _fsync_directory(path.parent)
    except OSError as exc:
        raise ArchiveError(f"cannot remove malformed {label}") from exc


def _cleanup_projection_temps(directory: Path, *, kind: str) -> None:  # noqa: C901
    _require_real_directory(directory, label="archive projection directory")
    changed = False
    for temporary in sorted(directory.iterdir()):
        match = _PROJECTION_TEMP_RE.fullmatch(temporary.name)
        if match is None:
            continue
        base_name = match.group(1)
        valid = False
        if kind == "ledger":
            valid = base_name == "events.jsonl"
        elif kind == "refs":
            valid = base_name == "lab-champion.json"
        elif kind in {
            "artifacts",
            "campaigns",
            "candidates",
            "evaluations",
        } and base_name.endswith(".json"):
            try:
                _archive_id(base_name.removesuffix(".json"), kind[:-1])
                valid = True
            except ArchiveError:
                valid = False
        if not valid:
            continue
        try:
            item_stat = temporary.lstat()
        except OSError as exc:
            raise ArchiveError("cannot inspect archive projection temporary") from exc
        if (
            temporary.is_symlink()
            or not stat.S_ISREG(item_stat.st_mode)
            or item_stat.st_uid != os.getuid()
            or item_stat.st_nlink != 1
            or stat.S_IMODE(item_stat.st_mode) & 0o077
        ):
            raise ArchiveError("archive projection temporary is unsafe to recover")
        try:
            temporary.unlink()
        except OSError as exc:
            raise ArchiveError("cannot clean archive projection temporary") from exc
        changed = True
    if changed:
        _fsync_directory(directory)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _digest_json(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "APPROVAL_SCHEMA_VERSION",
    "ARCHIVE_SCHEMA_VERSION",
    "ArchiveError",
    "ArchiveVerification",
    "LabArchive",
    "StoredObject",
]
