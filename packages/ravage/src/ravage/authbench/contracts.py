from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

MANIFEST_SCHEMA_VERSION = "ravage.authbench.manifest.v1"
RESULT_SCHEMA_VERSION = "ravage.authbench.result.v1"


@dataclass(frozen=True, slots=True)
class AuthBenchIdentity:
    identity_id: str
    username: str
    password: str

    def __post_init__(self) -> None:
        _require_nonempty(self.identity_id, "identity_id")
        _require_nonempty(self.username, "username")
        _require_nonempty(self.password, "password")

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.identity_id,
            "username": self.username,
            "password": self.password,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuthBenchIdentity:
        return cls(
            identity_id=_string(value, "id"),
            username=_string(value, "username"),
            password=_string(value, "password"),
        )


@dataclass(frozen=True, slots=True)
class AuthBenchCaseSpec:
    case_id: str
    title: str
    entrypoint: str
    objective: str
    identities: tuple[AuthBenchIdentity, ...]

    def __post_init__(self) -> None:
        _require_nonempty(self.case_id, "case_id")
        _require_nonempty(self.title, "title")
        _require_nonempty(self.objective, "objective")
        if not self.entrypoint.startswith("/"):
            raise ValueError("entrypoint must be an absolute path")
        identity_ids = [identity.identity_id for identity in self.identities]
        if len(identity_ids) != len(set(identity_ids)):
            raise ValueError(f"duplicate identity in case {self.case_id}")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.case_id,
            "title": self.title,
            "entrypoint": self.entrypoint,
            "objective": self.objective,
            "identities": [identity.to_dict() for identity in self.identities],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuthBenchCaseSpec:
        identities = _mapping_list(value, "identities")
        return cls(
            case_id=_string(value, "id"),
            title=_string(value, "title"),
            entrypoint=_string(value, "entrypoint"),
            objective=_string(value, "objective"),
            identities=tuple(AuthBenchIdentity.from_dict(item) for item in identities),
        )


@dataclass(frozen=True, slots=True)
class AuthBenchManifest:
    benchmark_id: str
    revision: int
    cases: tuple[AuthBenchCaseSpec, ...]
    schema_version: str = MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError(f"unsupported AuthBench manifest schema: {self.schema_version}")
        _require_nonempty(self.benchmark_id, "benchmark_id")
        if self.revision < 1:
            raise ValueError("revision must be positive")
        case_ids = [case.case_id for case in self.cases]
        if not case_ids:
            raise ValueError("manifest must contain at least one case")
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("manifest contains duplicate case ids")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "benchmark_id": self.benchmark_id,
            "revision": self.revision,
            "cases": [case.to_dict() for case in self.cases],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuthBenchManifest:
        cases = _mapping_list(value, "cases")
        return cls(
            schema_version=_string(value, "schema_version"),
            benchmark_id=_string(value, "benchmark_id"),
            revision=_integer(value, "revision"),
            cases=tuple(AuthBenchCaseSpec.from_dict(item) for item in cases),
        )


@dataclass(frozen=True, slots=True)
class AuthBenchObservation:
    authenticated: bool | None = None
    identities: tuple[str, ...] = ()
    refresh_performed: bool = False
    unsafe_request_replayed: bool | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "authenticated": self.authenticated,
            "identities": list(self.identities),
            "refresh_performed": self.refresh_performed,
            "unsafe_request_replayed": self.unsafe_request_replayed,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuthBenchObservation:
        return cls(
            authenticated=_optional_bool(value, "authenticated"),
            identities=tuple(_string_list(value, "identities")),
            refresh_performed=_boolean(value, "refresh_performed"),
            unsafe_request_replayed=_optional_bool(value, "unsafe_request_replayed"),
        )


@dataclass(frozen=True, slots=True)
class AuthBenchCheck:
    name: str
    passed: bool
    detail: str

    def __post_init__(self) -> None:
        _require_nonempty(self.name, "check name")
        _require_nonempty(self.detail, "check detail")

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuthBenchCheck:
        return cls(
            name=_string(value, "name"),
            passed=_boolean(value, "passed"),
            detail=_string(value, "detail"),
        )


@dataclass(frozen=True, slots=True)
class AuthBenchCaseResult:
    case_id: str
    passed: bool
    checks: tuple[AuthBenchCheck, ...]
    observation: AuthBenchObservation
    error: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.case_id, "case_id")
        if not self.checks and self.error is None:
            raise ValueError("case result needs checks or an error")

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "passed": self.passed,
            "checks": [check.to_dict() for check in self.checks],
            "observation": self.observation.to_dict(),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuthBenchCaseResult:
        checks = _mapping_list(value, "checks")
        observation = _mapping(value, "observation")
        return cls(
            case_id=_string(value, "case_id"),
            passed=_boolean(value, "passed"),
            checks=tuple(AuthBenchCheck.from_dict(item) for item in checks),
            observation=AuthBenchObservation.from_dict(observation),
            error=_optional_string(value, "error"),
        )


@dataclass(frozen=True, slots=True)
class AuthBenchResult:
    benchmark_id: str
    manifest_schema_version: str
    manifest_revision: int
    cases: tuple[AuthBenchCaseResult, ...]
    schema_version: str = RESULT_SCHEMA_VERSION
    passed: bool = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != RESULT_SCHEMA_VERSION:
            raise ValueError(f"unsupported AuthBench result schema: {self.schema_version}")
        if self.manifest_schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError(f"unsupported source manifest schema: {self.manifest_schema_version}")
        _require_nonempty(self.benchmark_id, "benchmark_id")
        if self.manifest_revision < 1:
            raise ValueError("manifest_revision must be positive")
        object.__setattr__(
            self, "passed", bool(self.cases) and all(case.passed for case in self.cases)
        )

    @property
    def passed_cases(self) -> int:
        return sum(case.passed for case in self.cases)

    @property
    def total_cases(self) -> int:
        return len(self.cases)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "benchmark_id": self.benchmark_id,
            "manifest_schema_version": self.manifest_schema_version,
            "manifest_revision": self.manifest_revision,
            "passed": self.passed,
            "score": {"passed": self.passed_cases, "total": self.total_cases},
            "cases": [case.to_dict() for case in self.cases],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuthBenchResult:
        cases = _mapping_list(value, "cases")
        result = cls(
            schema_version=_string(value, "schema_version"),
            benchmark_id=_string(value, "benchmark_id"),
            manifest_schema_version=_string(value, "manifest_schema_version"),
            manifest_revision=_integer(value, "manifest_revision"),
            cases=tuple(AuthBenchCaseResult.from_dict(item) for item in cases),
        )
        declared_passed = _boolean(value, "passed")
        if declared_passed != result.passed:
            raise ValueError("result passed field does not match case results")
        return result


def _require_nonempty(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _string(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError(f"{key} must be a string")
    return item


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str):
        raise ValueError(f"{key} must be a string or null")
    return item


def _boolean(value: Mapping[str, object], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise ValueError(f"{key} must be a boolean")
    return item


def _optional_bool(value: Mapping[str, object], key: str) -> bool | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, bool):
        raise ValueError(f"{key} must be a boolean or null")
    return item


def _integer(value: Mapping[str, object], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"{key} must be an integer")
    return item


def _mapping(value: Mapping[str, object], key: str) -> Mapping[str, object]:
    item = value.get(key)
    if not isinstance(item, Mapping):
        raise ValueError(f"{key} must be an object")
    return item


def _mapping_list(value: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    item = value.get(key)
    if not isinstance(item, list) or any(not isinstance(entry, Mapping) for entry in item):
        raise ValueError(f"{key} must be a list of objects")
    return [entry for entry in item if isinstance(entry, Mapping)]


def _string_list(value: Mapping[str, object], key: str) -> list[str]:
    item: Any = value.get(key)
    if not isinstance(item, list) or any(not isinstance(entry, str) for entry in item):
        raise ValueError(f"{key} must be a list of strings")
    return item
