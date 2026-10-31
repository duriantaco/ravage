"""Neutral contracts shared by evaluator-owned comparison components.

These types describe one bounded execution row.  They deliberately do not
decide whether a row is eligible for a public comparison: a process backend's
declaration is not independent containment evidence, and campaign scheduling,
scoring, and no-retry policy belong in a higher layer.

Money is normalized to :class:`~decimal.Decimal` and serialized as canonical
decimal text.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from types import MappingProxyType

TARGET_URL_ENV = "RAVAGE_XBEN_TARGET_URL"
DESCRIPTION_ENV = "RAVAGE_XBEN_DESCRIPTION"
COMPARISON_GATEWAY_TOKEN_ENV = "RAVAGE_COMPARISON_GATEWAY_TOKEN"
OUTER_PROCESS_GROUP_ENV = "RAVAGE_COMPARISON_OUTER_PROCESS_GROUP"
OUTER_PROCESS_GROUP_VALUE = "joined_evaluator_group_v1"

_SYSTEM_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_ENVIRONMENT_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,127}")
_MAX_DECIMAL_TEXT_CHARS = 100
_MAX_DECIMAL_ADJUSTED_EXPONENT = 28
_MAX_WALL_SECONDS = 24 * 60 * 60
_MAX_MODEL_REQUESTS = 4096
_MAX_TARGET_REQUESTS = 1_000_000
_MAX_ARGV_BYTES = 256 * 1024
_MAX_TARGET_PROVENANCE_BYTES = 8 * 1024 * 1024
_MAX_TARGET_PROVENANCE_NODES = 100_000
_MAX_TARGET_PROVENANCE_DEPTH = 64
_DECIMAL_INPUT_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")

__all__ = (
    "COMPARISON_GATEWAY_TOKEN_ENV",
    "DESCRIPTION_ENV",
    "OUTER_PROCESS_GROUP_ENV",
    "OUTER_PROCESS_GROUP_VALUE",
    "TARGET_URL_ENV",
    "ComparisonContractError",
    "ExternalAgentCommand",
    "ExternalExecutionLimits",
    "ExternalTarget",
    "decimal_text",
)


class ComparisonContractError(ValueError):
    """Raised when a row contract is malformed or internally inconsistent."""


@dataclass(frozen=True, init=False)
class ExternalExecutionLimits:
    """Exact per-row ceilings that an execution backend must enforce."""

    wall_seconds: int
    max_model_requests: int
    max_target_requests: int
    max_cost_usd: Decimal

    def __init__(
        self,
        wall_seconds: int,
        max_model_requests: int,
        max_target_requests: int,
        max_cost_usd: Decimal | str | int,
    ) -> None:
        for label, value, maximum in (
            ("wall timeout", wall_seconds, _MAX_WALL_SECONDS),
            ("model request limit", max_model_requests, _MAX_MODEL_REQUESTS),
            ("target request limit", max_target_requests, _MAX_TARGET_REQUESTS),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
                raise ComparisonContractError(
                    f"{label} must be a positive integer no greater than {maximum}"
                )
        object.__setattr__(self, "wall_seconds", wall_seconds)
        object.__setattr__(self, "max_model_requests", max_model_requests)
        object.__setattr__(self, "max_target_requests", max_target_requests)
        object.__setattr__(self, "max_cost_usd", _positive_decimal(max_cost_usd))

    def to_json(self) -> dict[str, object]:
        return {
            "wall_seconds": self.wall_seconds,
            "max_model_requests": self.max_model_requests,
            "max_target_requests": self.max_target_requests,
            "max_cost_usd": decimal_text(self.max_cost_usd),
        }


@dataclass(frozen=True)
class ExternalAgentCommand:
    """A generic agent command and its single declared score artifact."""

    name: str
    system_id: str
    command: tuple[str, ...] = field(repr=False)
    artifact_path: str
    limits: ExternalExecutionLimits
    reasoning_effort: str
    provider: str = ""
    model: str = ""
    adapter_version: str = ""
    environment: Mapping[str, str] = field(default_factory=dict, repr=False)
    environment_allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or not self.name
            or self.name != self.name.strip()
            or len(self.name) > 100
            or not _bounded_utf8(self.name, 400)
        ):
            raise ComparisonContractError("agent name is invalid")
        if not isinstance(self.system_id, str) or _SYSTEM_ID_RE.fullmatch(self.system_id) is None:
            raise ComparisonContractError("agent system ID is invalid")
        if not isinstance(self.limits, ExternalExecutionLimits):
            raise ComparisonContractError("agent execution limits are invalid")
        if not isinstance(self.command, tuple) or not self.command or len(self.command) > 256:
            raise ComparisonContractError("agent command is empty or too long")
        if any(
            not isinstance(part, str)
            or not part
            or not _bounded_utf8(part, 16 * 1024)
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
            for part in self.command
        ):
            raise ComparisonContractError("agent command contains an invalid argument")
        if sum(len(part.encode("utf-8")) + 1 for part in self.command) > _MAX_ARGV_BYTES:
            raise ComparisonContractError("agent command exceeds its total byte limit")
        if not Path(self.command[0]).is_absolute():
            raise ComparisonContractError("agent executable must be an absolute path")
        if not isinstance(self.artifact_path, str):
            raise ComparisonContractError("agent artifact path must be safely relative")
        artifact = PurePosixPath(self.artifact_path)
        if (
            not self.artifact_path
            or len(self.artifact_path) > 500
            or artifact.is_absolute()
            or not artifact.parts
            or ".." in artifact.parts
            or "\\" in self.artifact_path
            or artifact.as_posix() != self.artifact_path
            or not _bounded_utf8(self.artifact_path, 2000)
            or any(
                not part or any(ord(character) < 32 or ord(character) == 127 for character in part)
                for part in artifact.parts
            )
        ):
            raise ComparisonContractError("agent artifact path must be safely relative")
        for label, value, maximum in (
            ("reasoning effort", self.reasoning_effort, 50),
            ("provider", self.provider, 200),
            ("model", self.model, 200),
            ("adapter version", self.adapter_version, 200),
        ):
            if (
                not isinstance(value, str)
                or value != value.strip()
                or len(value) > maximum
                or not _bounded_utf8(value, maximum * 4)
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise ComparisonContractError(f"agent {label} is invalid")
        if not self.reasoning_effort:
            raise ComparisonContractError("agent reasoning effort is required")
        try:
            environment = dict(self.environment)
        except (TypeError, ValueError) as exc:
            raise ComparisonContractError("agent environment is invalid") from exc
        if len(environment) > 128 or any(
            not isinstance(name, str)
            or _ENVIRONMENT_NAME_RE.fullmatch(name) is None
            or not isinstance(value, str)
            or not _bounded_utf8(value, 16 * 1024)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            for name, value in environment.items()
        ):
            raise ComparisonContractError("agent environment is invalid")
        if not isinstance(self.environment_allowlist, tuple) or any(
            not isinstance(name, str) or _ENVIRONMENT_NAME_RE.fullmatch(name) is None
            for name in self.environment_allowlist
        ):
            raise ComparisonContractError("agent environment allowlist is invalid")
        if len(set(self.environment_allowlist)) != len(self.environment_allowlist) or set(
            self.environment_allowlist
        ) != set(environment):
            raise ComparisonContractError(
                "agent environment must exactly match its declared allowlist"
            )
        object.__setattr__(self, "environment", MappingProxyType(environment))


@dataclass(frozen=True, init=False)
class ExternalTarget:
    """A live target plus opaque state returned to its backend at teardown."""

    instance_id: str
    target_url: str
    _build_provenance_json: bytes = field(repr=False)
    backend_handle: object | None = field(default=None, repr=False, compare=False)

    def __init__(
        self,
        instance_id: str,
        target_url: str,
        build_provenance: Mapping[str, object] | None = None,
        backend_handle: object | None = None,
    ) -> None:
        if (
            not isinstance(instance_id, str)
            or not instance_id
            or len(instance_id) > 200
            or not _bounded_utf8(instance_id, 800)
        ):
            raise ComparisonContractError("target instance ID is invalid")
        if (
            not isinstance(target_url, str)
            or not target_url
            or len(target_url) > 4096
            or not _bounded_utf8(target_url, 16 * 1024)
        ):
            raise ComparisonContractError("target URL is invalid")
        try:
            normalized = _bounded_json_value(
                {} if build_provenance is None else build_provenance,
                active=set(),
                depth=0,
            )
            if not isinstance(normalized, dict):  # pragma: no cover - top-level input contract.
                raise TypeError("target provenance must be an object")
            body = json.dumps(
                normalized,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
            raise ComparisonContractError("target build provenance is invalid") from exc
        if len(body) > _MAX_TARGET_PROVENANCE_BYTES:
            raise ComparisonContractError("target build provenance exceeds its byte limit")
        object.__setattr__(self, "instance_id", instance_id)
        object.__setattr__(self, "target_url", target_url)
        object.__setattr__(self, "_build_provenance_json", body)
        object.__setattr__(self, "backend_handle", backend_handle)

    @property
    def build_provenance(self) -> Mapping[str, object]:
        """Return a detached JSON snapshot so callers cannot mutate the target identity."""

        payload = json.loads(self._build_provenance_json)
        if not isinstance(payload, dict):  # pragma: no cover - constructor invariant.
            raise ComparisonContractError("target build provenance snapshot is invalid")
        return payload


def decimal_text(value: Decimal) -> str:
    """Return finite decimal money without exponent or insignificant zeros."""

    if not isinstance(value, Decimal) or not value.is_finite():
        raise ComparisonContractError("money value must be a finite Decimal")
    if value.is_zero():
        return "0"
    if abs(value.adjusted()) > _MAX_DECIMAL_ADJUSTED_EXPONENT:
        raise ComparisonContractError("money value exponent is outside the supported range")
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if rendered == "-0":
        return "0"
    if len(rendered) > _MAX_DECIMAL_TEXT_CHARS:
        raise ComparisonContractError("money value is too long")
    return rendered


def _positive_decimal(value: Decimal | str | int) -> Decimal:
    if isinstance(value, bool):
        raise ComparisonContractError("cost limit must be finite and positive")
    if isinstance(value, int):
        if value.bit_length() > 100:
            raise ComparisonContractError("cost limit is too large")
        raw = str(value)
    elif isinstance(value, str):
        raw = value
    elif isinstance(value, Decimal):
        try:
            raw = str(value)
        except (ValueError, OverflowError) as exc:
            raise ComparisonContractError("cost limit is invalid") from exc
    else:
        raise ComparisonContractError(
            "cost limit must be exact Decimal, decimal text, or an integer"
        )
    if (
        not raw
        or raw != raw.strip()
        or len(raw) > _MAX_DECIMAL_TEXT_CHARS
        or (isinstance(value, str) and _DECIMAL_INPUT_RE.fullmatch(raw) is None)
    ):
        raise ComparisonContractError("cost limit must be normalized decimal text")
    try:
        parsed = Decimal(raw)
    except InvalidOperation as exc:
        raise ComparisonContractError("cost limit must be valid decimal text") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ComparisonContractError("cost limit must be finite and positive")
    # Validate exponent and serialized size before the value enters a receipt.
    decimal_text(parsed)
    return parsed


def _bounded_utf8(value: str, maximum_bytes: int) -> bool:
    try:
        return len(value.encode("utf-8")) <= maximum_bytes
    except UnicodeError:
        return False


def _bounded_json_value(
    value: object,
    *,
    active: set[int],
    depth: int,
    state: list[int] | None = None,
) -> object:
    if state is None:
        state = [0, 0]
    state[0] += 1
    if state[0] > _MAX_TARGET_PROVENANCE_NODES or depth > _MAX_TARGET_PROVENANCE_DEPTH:
        raise ValueError("target provenance structure exceeds its limit")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value.bit_length() > 63:
            raise ValueError("target provenance integer exceeds its limit")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("target provenance number is not finite")
        return value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        state[1] += len(encoded)
        if state[1] > _MAX_TARGET_PROVENANCE_BYTES:
            raise ValueError("target provenance text exceeds its limit")
        return value
    if not isinstance(value, Mapping | list | tuple):
        raise TypeError("target provenance contains a non-JSON value")
    identity = id(value)
    if identity in active:
        raise ValueError("target provenance is recursive")
    active.add(identity)
    try:
        if isinstance(value, Mapping):
            normalized: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("target provenance keys must be strings")
                normalized_key = _bounded_json_value(
                    key,
                    active=active,
                    depth=depth + 1,
                    state=state,
                )
                normalized[str(normalized_key)] = _bounded_json_value(
                    item,
                    active=active,
                    depth=depth + 1,
                    state=state,
                )
            return normalized
        return [
            _bounded_json_value(item, active=active, depth=depth + 1, state=state) for item in value
        ]
    finally:
        active.remove(identity)
