"""Strict external-executor attestations for promotion-grade run receipts."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tools.improvement_lab.attestation import (
    AttestationError,
    public_key_from_private,
    referee_key_id,
)
from tools.improvement_lab.evaluation import RunReceipt, canonical_json

if TYPE_CHECKING:
    from pathlib import Path

# Errors crossing this trust boundary are deliberately bounded and content-free.
# ruff: noqa: EM101, EM102, TRY003, TRY300, TRY301

EXECUTION_ATTESTATION_SCHEMA_VERSION: Final = (
    "ravage.improvement-execution-attestation.v1"
)
EXECUTION_BINDING_SCHEMA_VERSION: Final = "ravage.improvement-execution-binding.v2"
EXECUTION_OBSERVATIONS_SCHEMA_VERSION: Final = (
    "ravage.improvement-execution-observations.v1"
)

_ID_RE: Final = re.compile(r"(?:campaign|candidate)_[0-9a-f]{24}")
_GIT_TREE_RE: Final = re.compile(r"[0-9a-f]{40,64}")
_SHA256_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE_RE: Final = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_OPAQUE_ID_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SIGNATURE_RE: Final = re.compile(r"[0-9a-f]{128}")

_KEY_BYTES: Final = 32
_MAX_SIGNED_BYTES: Final = 16 * 1024 * 1024
_MAX_VERDICTS: Final = 100_000
_MAX_COUNT: Final = 1_000_000_000
_MAX_COST_USD: Final = 1_000_000_000.0
_MAX_REPEAT: Final = 100
_MAX_ARTIFACT_CASE_PATH_CHARS: Final = 512
_MAX_TEXT_CHARS: Final = 1024
_EXECUTION_KINDS: Final = frozenset({"fixture", "live"})
_EVALUATION_SIDES: Final = frozenset({"champion", "candidate"})
_STATUSES: Final = frozenset({"completed", "failed", "timeout", "error"})
_ACCOUNTING_STATUSES: Final = frozenset(
    {"invalid", "unavailable", "unspecified", "lower_bound", "reported", "exact"}
)
_COUNTED_ACCOUNTING_STATUSES: Final = frozenset({"lower_bound", "reported", "exact"})
_FINDING_STAGES: Final = (
    "suspected_vulnerability",
    "evidence_backed_vulnerability",
    "verified_vulnerability",
    "confirmed_finding",
)
_FINDING_STAGE_RANK: Final = {
    stage: rank for rank, stage in enumerate(_FINDING_STAGES, start=1)
}


class ExecutionAttestationError(AttestationError):
    """Raised when an external execution envelope is malformed or unverifiable."""


@dataclass(frozen=True)
class ExecutionBinding:
    """Evaluator-owned identities that pin one exact external execution."""

    campaign_id: str
    candidate_id: str
    candidate_tree_digest: str
    candidate_content_digest: str
    evaluation_suite_object: str
    trusted_tests_digest: str
    runner_image: str
    job_spec_digest: str
    artifact_tree_digest: str
    artifact_case_path: str
    case_id: str
    cohort: str
    repeat: int
    execution_kind: str
    evaluation_side: str
    is_control: bool
    expected_vulnerability_count: int | None
    run_id: str
    pair_seed_digest: str
    target_snapshot_digest: str
    model_fingerprint: str
    prompt_fingerprint: str

    def __post_init__(self) -> None:
        if (
            _ID_RE.fullmatch(self.campaign_id) is None
            or not self.campaign_id.startswith("campaign_")
        ):
            raise ExecutionAttestationError("execution campaign identity is invalid")
        if (
            _ID_RE.fullmatch(self.candidate_id) is None
            or not self.candidate_id.startswith("candidate_")
        ):
            raise ExecutionAttestationError("execution candidate identity is invalid")
        if _GIT_TREE_RE.fullmatch(self.candidate_tree_digest) is None:
            raise ExecutionAttestationError("execution candidate tree digest is invalid")
        for label, value in (
            ("candidate content", self.candidate_content_digest),
            ("evaluation suite object", self.evaluation_suite_object),
            ("trusted tests", self.trusted_tests_digest),
            ("job specification", self.job_spec_digest),
            ("artifact tree", self.artifact_tree_digest),
            ("run", self.run_id),
            ("pair seed", self.pair_seed_digest),
            ("target snapshot", self.target_snapshot_digest),
            ("model", self.model_fingerprint),
            ("prompt", self.prompt_fingerprint),
        ):
            if _SHA256_RE.fullmatch(value) is None:
                raise ExecutionAttestationError(f"execution {label} digest is invalid")
        if _IMAGE_RE.fullmatch(self.runner_image) is None:
            raise ExecutionAttestationError("execution runner image must be pinned by sha256")
        _validate_artifact_case_path(self.artifact_case_path)
        _validate_opaque_id(self.case_id, "case_id")
        _validate_opaque_id(self.cohort, "cohort")
        _validate_int(self.repeat, "repeat", minimum=1, maximum=_MAX_REPEAT)
        if self.execution_kind not in _EXECUTION_KINDS:
            raise ExecutionAttestationError("execution kind must be fixture or live")
        if self.evaluation_side not in _EVALUATION_SIDES:
            raise ExecutionAttestationError(
                "evaluation_side must be champion or candidate"
            )
        if not isinstance(self.is_control, bool):
            raise ExecutionAttestationError("is_control must be a boolean")
        _validate_optional_int(
            self.expected_vulnerability_count,
            "expected_vulnerability_count",
        )

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": EXECUTION_BINDING_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "candidate_id": self.candidate_id,
            "candidate_tree_digest": self.candidate_tree_digest,
            "candidate_content_digest": self.candidate_content_digest,
            "evaluation_suite_object": self.evaluation_suite_object,
            "trusted_tests_digest": self.trusted_tests_digest,
            "runner_image": self.runner_image,
            "job_spec_digest": self.job_spec_digest,
            "artifact_tree_digest": self.artifact_tree_digest,
            "artifact_case_path": self.artifact_case_path,
            "case_id": self.case_id,
            "cohort": self.cohort,
            "repeat": self.repeat,
            "execution_kind": self.execution_kind,
            "evaluation_side": self.evaluation_side,
            "is_control": self.is_control,
            "expected_vulnerability_count": self.expected_vulnerability_count,
            "run_id": self.run_id,
            "pair_seed_digest": self.pair_seed_digest,
            "target_snapshot_digest": self.target_snapshot_digest,
            "model_fingerprint": self.model_fingerprint,
            "prompt_fingerprint": self.prompt_fingerprint,
        }

    @classmethod
    def from_mapping(cls, payload: object) -> ExecutionBinding:
        if not isinstance(payload, dict):
            raise ExecutionAttestationError("execution binding must be an object")
        expected = {
            "schema_version",
            "campaign_id",
            "candidate_id",
            "candidate_tree_digest",
            "candidate_content_digest",
            "evaluation_suite_object",
            "trusted_tests_digest",
            "runner_image",
            "job_spec_digest",
            "artifact_tree_digest",
            "artifact_case_path",
            "case_id",
            "cohort",
            "repeat",
            "execution_kind",
            "evaluation_side",
            "is_control",
            "expected_vulnerability_count",
            "run_id",
            "pair_seed_digest",
            "target_snapshot_digest",
            "model_fingerprint",
            "prompt_fingerprint",
        }
        if set(payload) != expected:
            raise ExecutionAttestationError(
                "execution binding fields do not match the canonical schema"
            )
        if payload.get("schema_version") != EXECUTION_BINDING_SCHEMA_VERSION:
            raise ExecutionAttestationError("execution binding schema is unsupported")
        return cls(
            campaign_id=_text(payload["campaign_id"], "campaign_id"),
            candidate_id=_text(payload["candidate_id"], "candidate_id"),
            candidate_tree_digest=_text(
                payload["candidate_tree_digest"], "candidate_tree_digest"
            ),
            candidate_content_digest=_text(
                payload["candidate_content_digest"], "candidate_content_digest"
            ),
            evaluation_suite_object=_text(
                payload["evaluation_suite_object"], "evaluation_suite_object"
            ),
            trusted_tests_digest=_text(
                payload["trusted_tests_digest"], "trusted_tests_digest"
            ),
            runner_image=_text(payload["runner_image"], "runner_image"),
            job_spec_digest=_text(payload["job_spec_digest"], "job_spec_digest"),
            artifact_tree_digest=_text(
                payload["artifact_tree_digest"], "artifact_tree_digest"
            ),
            artifact_case_path=_text(
                payload["artifact_case_path"], "artifact_case_path"
            ),
            case_id=_text(payload["case_id"], "case_id"),
            cohort=_text(payload["cohort"], "cohort"),
            repeat=_integer(payload["repeat"], "repeat"),
            execution_kind=_text(payload["execution_kind"], "execution_kind"),
            evaluation_side=_text(payload["evaluation_side"], "evaluation_side"),
            is_control=_boolean(payload["is_control"], "is_control"),
            expected_vulnerability_count=_optional_integer(
                payload["expected_vulnerability_count"],
                "expected_vulnerability_count",
            ),
            run_id=_text(payload["run_id"], "run_id"),
            pair_seed_digest=_text(payload["pair_seed_digest"], "pair_seed_digest"),
            target_snapshot_digest=_text(
                payload["target_snapshot_digest"], "target_snapshot_digest"
            ),
            model_fingerprint=_text(payload["model_fingerprint"], "model_fingerprint"),
            prompt_fingerprint=_text(payload["prompt_fingerprint"], "prompt_fingerprint"),
        )


@dataclass(frozen=True)
class FindingVerdict:
    """One secret-free finding identity and its highest evaluator-approved stage."""

    finding_digest: str
    stage: str

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.finding_digest) is None:
            raise ExecutionAttestationError("finding verdict digest is invalid")
        if self.stage not in _FINDING_STAGE_RANK:
            raise ExecutionAttestationError("finding verdict stage is unsupported")

    def to_json(self) -> dict[str, object]:
        return {"finding_digest": self.finding_digest, "stage": self.stage}

    @classmethod
    def from_mapping(cls, payload: object) -> FindingVerdict:
        if not isinstance(payload, dict) or set(payload) != {"finding_digest", "stage"}:
            raise ExecutionAttestationError(
                "finding verdict fields do not match the canonical schema"
            )
        return cls(
            finding_digest=_text(payload["finding_digest"], "finding_digest"),
            stage=_text(payload["stage"], "stage"),
        )


@dataclass(frozen=True)
class ExternalRunObservations:
    """Evaluator-owned, secret-free observations from one frozen run artifact tree."""

    status: str
    case_success: bool | None
    physical_request_count: int | None
    model_request_count: int | None
    cost_usd: float | None
    request_accounting_status: str
    proof_integrity_failure_count: int
    false_proof_count: int
    request_accounting_mismatch_count: int
    loop_violation_count: int
    provenance_violation_count: int
    secret_leak_violation_count: int
    unmetered_action_count: int
    incomplete_request_count: int

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ExecutionAttestationError("execution status is unsupported")
        if self.case_success is not None and not isinstance(self.case_success, bool):
            raise ExecutionAttestationError("case_success must be a boolean or null")
        _validate_optional_int(self.physical_request_count, "physical_request_count")
        _validate_optional_int(self.model_request_count, "model_request_count")
        _validate_optional_cost(self.cost_usd)
        if self.request_accounting_status not in _ACCOUNTING_STATUSES:
            raise ExecutionAttestationError("request accounting status is unsupported")
        if (
            self.request_accounting_status in _COUNTED_ACCOUNTING_STATUSES
            and self.physical_request_count is None
        ):
            raise ExecutionAttestationError(
                "counted request accounting requires a physical request count"
            )
        for name in _SAFETY_COUNTER_NAMES:
            _validate_int(getattr(self, name), name, minimum=0, maximum=_MAX_COUNT)

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": EXECUTION_OBSERVATIONS_SCHEMA_VERSION,
            "status": self.status,
            "case_success": self.case_success,
            "physical_request_count": self.physical_request_count,
            "model_request_count": self.model_request_count,
            "cost_usd": self.cost_usd,
            "request_accounting_status": self.request_accounting_status,
            **{name: getattr(self, name) for name in _SAFETY_COUNTER_NAMES},
        }

    @classmethod
    def from_mapping(cls, payload: object) -> ExternalRunObservations:
        if not isinstance(payload, dict):
            raise ExecutionAttestationError("execution observations must be an object")
        expected = {
            "schema_version",
            "status",
            "case_success",
            "physical_request_count",
            "model_request_count",
            "cost_usd",
            "request_accounting_status",
            *_SAFETY_COUNTER_NAMES,
        }
        if set(payload) != expected:
            raise ExecutionAttestationError(
                "execution observation fields do not match the canonical schema"
            )
        if payload.get("schema_version") != EXECUTION_OBSERVATIONS_SCHEMA_VERSION:
            raise ExecutionAttestationError("execution observation schema is unsupported")
        return cls(
            status=_text(payload["status"], "status"),
            case_success=_optional_boolean(payload["case_success"], "case_success"),
            physical_request_count=_optional_integer(
                payload["physical_request_count"], "physical_request_count"
            ),
            model_request_count=_optional_integer(
                payload["model_request_count"], "model_request_count"
            ),
            cost_usd=_optional_float(payload["cost_usd"], "cost_usd"),
            request_accounting_status=_text(
                payload["request_accounting_status"], "request_accounting_status"
            ),
            **{
                name: _integer(payload[name], name)
                for name in _SAFETY_COUNTER_NAMES
            },
        )


_SAFETY_COUNTER_NAMES: Final = (
    "proof_integrity_failure_count",
    "false_proof_count",
    "request_accounting_mismatch_count",
    "loop_violation_count",
    "provenance_violation_count",
    "secret_leak_violation_count",
    "unmetered_action_count",
    "incomplete_request_count",
)


@dataclass(frozen=True)
class SignedExecutionEnvelope:
    """A canonical execution binding and observations signed by a trusted executor."""

    binding: ExecutionBinding
    observations: ExternalRunObservations
    finding_verdicts: tuple[FindingVerdict, ...]
    signing_key_id: str
    signature: str

    def __post_init__(self) -> None:
        _validate_finding_verdicts(self.finding_verdicts)
        _validated_key_id(self.signing_key_id)
        _validated_signature(self.signature)

    def unsigned_json(self) -> dict[str, object]:
        return {
            "schema_version": EXECUTION_ATTESTATION_SCHEMA_VERSION,
            "binding": self.binding.to_json(),
            "observations": self.observations.to_json(),
            "finding_verdicts": [item.to_json() for item in self.finding_verdicts],
            "signing_key_id": self.signing_key_id,
        }

    def to_json(self) -> dict[str, object]:
        return {**self.unsigned_json(), "signature": self.signature}

    def to_run_receipt(self) -> RunReceipt:
        """Derive the referee receipt without accepting caller-supplied detection totals."""
        stage_counts = _finding_stage_counts(self.finding_verdicts)
        return RunReceipt(
            case_id=self.binding.case_id,
            cohort=self.binding.cohort,
            repeat=self.binding.repeat,
            execution_kind=self.binding.execution_kind,
            status=self.observations.status,
            is_control=self.binding.is_control,
            case_success=self.observations.case_success,
            expected_vulnerability_count=self.binding.expected_vulnerability_count,
            evidence_backed_vulnerability_count=stage_counts[
                "evidence_backed_vulnerability"
            ],
            verified_vulnerability_count=stage_counts["verified_vulnerability"],
            confirmed_finding_count=stage_counts["confirmed_finding"],
            suspected_vulnerability_count=stage_counts["suspected_vulnerability"],
            proof_integrity_failure_count=self.observations.proof_integrity_failure_count,
            false_proof_count=self.observations.false_proof_count,
            request_accounting_mismatch_count=(
                self.observations.request_accounting_mismatch_count
            ),
            loop_violation_count=self.observations.loop_violation_count,
            provenance_violation_count=self.observations.provenance_violation_count,
            secret_leak_violation_count=self.observations.secret_leak_violation_count,
            unmetered_action_count=self.observations.unmetered_action_count,
            incomplete_request_count=self.observations.incomplete_request_count,
            physical_request_count=self.observations.physical_request_count,
            model_request_count=self.observations.model_request_count,
            cost_usd=self.observations.cost_usd,
            request_accounting_status=self.observations.request_accounting_status,
            run_id=self.binding.run_id,
            execution_attestation_digest=execution_envelope_digest(self),
            pair_seed_digest=self.binding.pair_seed_digest,
            target_snapshot_digest=self.binding.target_snapshot_digest,
            model_fingerprint=self.binding.model_fingerprint,
            prompt_fingerprint=self.binding.prompt_fingerprint,
        )


def sign_execution_envelope(
    binding: ExecutionBinding,
    observations: ExternalRunObservations,
    finding_verdicts: tuple[FindingVerdict, ...],
    *,
    private_key: bytes,
) -> SignedExecutionEnvelope:
    """Sign one exact execution envelope with a raw Ed25519 private key."""
    private = _load_private_key(private_key)
    public_bytes = public_key_from_private(private_key)
    key_id = referee_key_id(public_bytes)
    verdicts = _validate_finding_verdicts(finding_verdicts)
    unsigned = {
        "schema_version": EXECUTION_ATTESTATION_SCHEMA_VERSION,
        "binding": binding.to_json(),
        "observations": observations.to_json(),
        "finding_verdicts": [item.to_json() for item in verdicts],
        "signing_key_id": key_id,
    }
    encoded = canonical_json(unsigned).encode()
    if len(encoded) > _MAX_SIGNED_BYTES:
        raise ExecutionAttestationError("execution attestation exceeds the byte cap")
    return SignedExecutionEnvelope(
        binding=binding,
        observations=observations,
        finding_verdicts=verdicts,
        signing_key_id=key_id,
        signature=private.sign(encoded).hex(),
    )


def verify_signed_execution_envelope(
    payload: object,
    *,
    public_key: bytes,
) -> SignedExecutionEnvelope:
    """Validate exact schemas, key identity, and signature before exposing observations."""
    if not isinstance(payload, dict):
        raise ExecutionAttestationError("signed execution attestation must be an object")
    expected = {
        "schema_version",
        "binding",
        "observations",
        "finding_verdicts",
        "signing_key_id",
        "signature",
    }
    if set(payload) != expected:
        raise ExecutionAttestationError(
            "signed execution attestation fields do not match the canonical schema"
        )
    if payload.get("schema_version") != EXECUTION_ATTESTATION_SCHEMA_VERSION:
        raise ExecutionAttestationError("signed execution attestation schema is unsupported")
    public = _load_public_key(public_key)
    key_id = _text(payload["signing_key_id"], "signing_key_id")
    if key_id != referee_key_id(public_key):
        raise ExecutionAttestationError("signed execution attestation uses the wrong key")
    signature = _text(payload["signature"], "signature")
    if _SIGNATURE_RE.fullmatch(signature) is None:
        raise ExecutionAttestationError("signed execution attestation signature is invalid")
    binding = ExecutionBinding.from_mapping(payload.get("binding"))
    observations = ExternalRunObservations.from_mapping(payload.get("observations"))
    raw_verdicts = payload.get("finding_verdicts")
    if not isinstance(raw_verdicts, list):
        raise ExecutionAttestationError("finding_verdicts must be a list")
    verdicts = _validate_finding_verdicts(
        tuple(FindingVerdict.from_mapping(item) for item in raw_verdicts)
    )
    unsigned = {
        "schema_version": EXECUTION_ATTESTATION_SCHEMA_VERSION,
        "binding": binding.to_json(),
        "observations": observations.to_json(),
        "finding_verdicts": [item.to_json() for item in verdicts],
        "signing_key_id": key_id,
    }
    encoded = canonical_json(unsigned).encode()
    if len(encoded) > _MAX_SIGNED_BYTES:
        raise ExecutionAttestationError("execution attestation exceeds the byte cap")
    try:
        public.verify(bytes.fromhex(signature), encoded)
    except InvalidSignature as exc:
        raise ExecutionAttestationError(
            "signed execution attestation signature verification failed"
        ) from exc
    return SignedExecutionEnvelope(binding, observations, verdicts, key_id, signature)


def write_signed_execution_envelope(
    path: Path,
    signed: SignedExecutionEnvelope,
) -> None:
    """Write one owner-only canonical envelope without overwriting an existing path."""
    verified_shape = SignedExecutionEnvelope(
        ExecutionBinding.from_mapping(signed.binding.to_json()),
        ExternalRunObservations.from_mapping(signed.observations.to_json()),
        _validate_finding_verdicts(signed.finding_verdicts),
        _validated_key_id(signed.signing_key_id),
        _validated_signature(signed.signature),
    )
    encoded = canonical_execution_envelope_bytes(verified_shape)
    if len(encoded) > _MAX_SIGNED_BYTES:
        raise ExecutionAttestationError("execution attestation exceeds the byte cap")
    _private_atomic_write(path, encoded)


def load_signed_execution_envelope(
    path: Path,
    *,
    public_key: bytes,
) -> SignedExecutionEnvelope:
    """Read, byte-canonicalize, and verify one bounded external execution envelope."""
    raw = _read_bounded(path, label="signed execution attestation", maximum=_MAX_SIGNED_BYTES)
    return load_canonical_execution_envelope_bytes(raw, public_key=public_key)


def load_canonical_execution_envelope_bytes(
    content: bytes,
    *,
    public_key: bytes,
) -> SignedExecutionEnvelope:
    """Strictly parse canonical retained bytes and verify the executor signature."""
    if not isinstance(content, bytes) or not content or len(content) > _MAX_SIGNED_BYTES:
        raise ExecutionAttestationError(
            "signed execution attestation is empty or exceeds the byte cap"
        )
    try:
        payload = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExecutionAttestationError("signed execution attestation JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise ExecutionAttestationError("signed execution attestation must be an object")
    try:
        canonical = (canonical_json(payload) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise ExecutionAttestationError("signed execution attestation JSON is invalid") from exc
    if content != canonical:
        raise ExecutionAttestationError("signed execution attestation is not byte-canonical")
    return verify_signed_execution_envelope(payload, public_key=public_key)


def execution_envelope_digest(signed: SignedExecutionEnvelope) -> str:
    """Return the CAS digest of the exact canonical signed-envelope bytes."""
    return f"sha256:{hashlib.sha256(canonical_execution_envelope_bytes(signed)).hexdigest()}"


def canonical_execution_envelope_bytes(signed: SignedExecutionEnvelope) -> bytes:
    """Return the byte form written to disk and retained by the archive."""
    return (canonical_json(signed.to_json()) + "\n").encode()


def _finding_stage_counts(verdicts: tuple[FindingVerdict, ...]) -> dict[str, int]:
    return {
        "suspected_vulnerability": sum(
            item.stage == "suspected_vulnerability" for item in verdicts
        ),
        "evidence_backed_vulnerability": sum(
            _FINDING_STAGE_RANK[item.stage]
            >= _FINDING_STAGE_RANK["evidence_backed_vulnerability"]
            for item in verdicts
        ),
        "verified_vulnerability": sum(
            _FINDING_STAGE_RANK[item.stage]
            >= _FINDING_STAGE_RANK["verified_vulnerability"]
            for item in verdicts
        ),
        "confirmed_finding": sum(item.stage == "confirmed_finding" for item in verdicts),
    }


def _validate_finding_verdicts(
    verdicts: tuple[FindingVerdict, ...],
) -> tuple[FindingVerdict, ...]:
    if not isinstance(verdicts, tuple):
        raise ExecutionAttestationError("finding_verdicts must be a tuple")
    if len(verdicts) > _MAX_VERDICTS:
        raise ExecutionAttestationError("finding verdict count exceeds the supported bound")
    if any(not isinstance(item, FindingVerdict) for item in verdicts):
        raise ExecutionAttestationError("finding verdict entry is invalid")
    digests = tuple(item.finding_digest for item in verdicts)
    if len(digests) != len(set(digests)):
        raise ExecutionAttestationError("finding verdict digests must be distinct")
    if digests != tuple(sorted(digests)):
        raise ExecutionAttestationError("finding verdicts must use canonical digest order")
    return verdicts


def _validate_artifact_case_path(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_ARTIFACT_CASE_PATH_CHARS
        or "\\" in value
        or "\0" in value
    ):
        raise ExecutionAttestationError("artifact_case_path is invalid")
    if value == ".":
        return
    if value.startswith("/") or value.endswith("/"):
        raise ExecutionAttestationError("artifact_case_path must be relative and normalized")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ExecutionAttestationError("artifact_case_path must be relative and normalized")
    if PurePosixPath(value).as_posix() != value:
        raise ExecutionAttestationError("artifact_case_path must be relative and normalized")


def _validate_opaque_id(value: object, label: str) -> None:
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        raise ExecutionAttestationError(f"execution {label} is invalid")


def _validate_int(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ExecutionAttestationError(f"{label} is outside the supported bounds")


def _validate_optional_int(value: object, label: str) -> None:
    if value is not None:
        _validate_int(value, label, minimum=0, maximum=_MAX_COUNT)


def _validate_optional_cost(value: object) -> None:
    if value is None:
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= _MAX_COST_USD
    ):
        raise ExecutionAttestationError("cost_usd is outside the supported bounds")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\0" in value:
        raise ExecutionAttestationError(f"{label} is invalid")
    if len(value) > _MAX_TEXT_CHARS:
        raise ExecutionAttestationError(f"{label} exceeds the character cap")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExecutionAttestationError(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ExecutionAttestationError(f"{label} must be a boolean")
    return value


def _optional_boolean(value: object, label: str) -> bool | None:
    return None if value is None else _boolean(value, label)


def _optional_float(value: object, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ExecutionAttestationError(f"{label} must be numeric or null")
    return float(value)


def _validated_key_id(value: object) -> str:
    key_id = _text(value, "signing_key_id")
    if _SHA256_RE.fullmatch(key_id) is None:
        raise ExecutionAttestationError("signing key identity is invalid")
    return key_id


def _validated_signature(value: object) -> str:
    signature = _text(value, "signature")
    if _SIGNATURE_RE.fullmatch(signature) is None:
        raise ExecutionAttestationError("signed execution attestation signature is invalid")
    return signature


def _load_private_key(content: bytes) -> Ed25519PrivateKey:
    if not isinstance(content, bytes) or len(content) != _KEY_BYTES:
        raise ExecutionAttestationError("executor private key must contain 32 raw bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(content)
    except ValueError as exc:
        raise ExecutionAttestationError("executor private key is invalid") from exc


def _load_public_key(content: bytes) -> Ed25519PublicKey:
    if not isinstance(content, bytes) or len(content) != _KEY_BYTES:
        raise ExecutionAttestationError("executor public key must contain 32 raw bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(content)
    except ValueError as exc:
        raise ExecutionAttestationError("executor public key is invalid") from exc


def _read_bounded(path: Path, *, label: str, maximum: int) -> bytes:
    candidate = path.expanduser()
    descriptor = -1
    try:
        before = candidate.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise ExecutionAttestationError(f"{label} must be a regular single-link file")
        if before.st_size > maximum:
            raise ExecutionAttestationError(f"{label} exceeds the byte cap")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if _file_version(before) != _file_version(opened):
            raise ExecutionAttestationError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        if len(raw) > maximum:
            raise ExecutionAttestationError(f"{label} exceeds the byte cap")
        if _file_version(opened) != _file_version(after):
            raise ExecutionAttestationError(f"{label} changed while it was read")
        return raw
    except ExecutionAttestationError:
        raise
    except OSError as exc:
        raise ExecutionAttestationError(f"cannot read {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _private_atomic_write(path: Path, content: bytes) -> None:
    target = path.expanduser()
    if target.exists() or target.is_symlink():
        raise ExecutionAttestationError("execution attestation output already exists")
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = target.parent.lstat()
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise ExecutionAttestationError(
                "execution attestation output parent must be a real directory"
            )
        temporary = target.with_name(f".{target.name}.{os.getpid()}.{secrets.token_hex(4)}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(target)
            target.chmod(0o600)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
    except ExecutionAttestationError:
        raise
    except OSError as exc:
        raise ExecutionAttestationError("cannot write execution attestation") from exc


def _file_version(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionAttestationError(
                "signed execution attestation contains a duplicate JSON key"
            )
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> object:
    raise ExecutionAttestationError(
        f"signed execution attestation contains unsupported {value}"
    )


__all__ = [
    "EXECUTION_ATTESTATION_SCHEMA_VERSION",
    "EXECUTION_BINDING_SCHEMA_VERSION",
    "EXECUTION_OBSERVATIONS_SCHEMA_VERSION",
    "ExecutionAttestationError",
    "ExecutionBinding",
    "ExternalRunObservations",
    "FindingVerdict",
    "SignedExecutionEnvelope",
    "canonical_execution_envelope_bytes",
    "execution_envelope_digest",
    "load_canonical_execution_envelope_bytes",
    "load_signed_execution_envelope",
    "sign_execution_envelope",
    "verify_signed_execution_envelope",
    "write_signed_execution_envelope",
]
