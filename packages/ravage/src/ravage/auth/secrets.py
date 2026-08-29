# ruff: noqa: EM101, EM102, TC003, TRY003
from __future__ import annotations

import re
from collections import ChainMap
from collections.abc import Mapping
from dataclasses import dataclass
from os import environ
from pathlib import Path
from typing import TYPE_CHECKING, Never, Protocol, SupportsIndex, cast, final

if TYPE_CHECKING:
    from collections.abc import MutableMapping

_SECRET_REF_PART = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_ENVIRONMENT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REDACTED = "[REDACTED]"


class SecretResolutionError(LookupError):
    """
    A secret reference could not be resolved.

    Error messages identify the reference, never its resolved value.
    """


class EnvironmentFileError(ValueError):
    """A secret environment file could not be read or parsed safely."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class SecretRef:
    """A non-secret pointer to a value held by an external secret provider."""

    provider: str
    key: str

    def __post_init__(self) -> None:
        if not _SECRET_REF_PART.fullmatch(self.provider):
            raise ValueError("secret provider must be a simple non-empty name")
        if not _SECRET_REF_PART.fullmatch(self.key):
            raise ValueError("secret key must be a simple non-empty name")

    @classmethod
    def env(cls, name: str) -> SecretRef:
        return cls(provider="environment", key=name)

    def to_public_dict(self) -> dict[str, str]:
        provider = "environment" if self.provider == "env" else self.provider
        return {"provider": provider, "key": self.key}


@final
class SecretValue:
    """
    An explicitly revealable secret with redacted display semantics.

    ``reveal`` is intentionally the only API that returns the plaintext. The
    object refuses pickle serialization and has no instance dictionary, which
    keeps common loggers and generic JSON encoders from accidentally exposing
    the value.
    """

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("secret value must be text")
        self.__value = value

    def reveal(self) -> str:
        return self.__value

    def __bool__(self) -> bool:
        return bool(self.__value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({_REDACTED})"

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, format_spec: str) -> str:
        del format_spec
        return _REDACTED

    def __reduce__(self) -> Never:
        raise TypeError("secret values cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("secret values cannot be serialized")


class SecretResolver(Protocol):
    """Resolves non-secret references at the point authentication needs them."""

    def resolve(self, reference: SecretRef) -> SecretValue: ...


@final
class SecretSnapshotResolver:
    """Resolve from one immutable per-run snapshot of already resolved values."""

    __slots__ = ("__values",)

    def __init__(self, values: Mapping[SecretRef, SecretValue]) -> None:
        self.__values = dict(values)

    def resolve(self, reference: SecretRef) -> SecretValue:
        try:
            return self.__values[reference]
        except KeyError:
            message = (
                "secret reference is outside the managed authentication snapshot: "
                f"{reference.provider}:{reference.key}"
            )
            raise SecretResolutionError(message) from None

    def __repr__(self) -> str:
        return f"{type(self).__name__}({_REDACTED})"

    def __reduce__(self) -> Never:
        raise TypeError("secret snapshot resolvers cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("secret snapshot resolvers cannot be serialized")


class EnvironmentSecretResolver:
    """Resolve environment references without copying the process environment."""

    __slots__ = ("__values",)

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self.__values = environ if values is None else values

    def resolve(self, reference: SecretRef) -> SecretValue:
        if reference.provider not in {"env", "environment"}:
            raise SecretResolutionError(f"unsupported secret provider: {reference.provider}")
        try:
            value = self.__values[reference.key]
        except KeyError:
            raise SecretResolutionError(
                f"secret reference is not available: environment:{reference.key}"
            ) from None
        if not isinstance(value, str):
            raise SecretResolutionError(
                f"secret reference did not resolve to text: environment:{reference.key}"
            )
        return SecretValue(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({_REDACTED})"

    def __reduce__(self) -> Never:
        raise TypeError("secret resolvers cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("secret resolvers cannot be serialized")


def environment_secret_resolver(
    *,
    environment: Mapping[str, str] | None = None,
    env_file: Path | None = None,
) -> EnvironmentSecretResolver:
    """Resolve env-file values before inherited values without mutating either source."""
    base_environment = environ if environment is None else environment
    if env_file is None:
        return EnvironmentSecretResolver(base_environment)
    file_values = read_environment_file(env_file)
    # ChainMap is read-only through EnvironmentSecretResolver. The cast is only
    # needed because ChainMap's typing is narrower than the Mapping API accepted
    # here; neither input is mutated.
    mutable_base = cast("MutableMapping[str, str]", base_environment)
    overlay = ChainMap(file_values, mutable_base)
    return EnvironmentSecretResolver(overlay)


def read_environment_file(path: Path) -> dict[str, str]:
    """Parse a strict dotenv subset without expanding or exposing values."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        raise EnvironmentFileError(
            "env_file_not_found",
            "the requested environment file does not exist",
        ) from None
    except (OSError, UnicodeError):
        raise EnvironmentFileError(
            "env_file_unreadable",
            "the requested environment file could not be read as UTF-8 text",
        ) from None

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        assignment = raw_line.strip()
        if not assignment or assignment.startswith("#"):
            continue
        if assignment.startswith("export"):
            suffix = assignment[len("export") :]
            if suffix and suffix[0].isspace():
                assignment = suffix.lstrip()
        if "=" not in assignment:
            raise _invalid_environment_line(line_number)
        key, raw_value = assignment.split("=", 1)
        key = key.strip()
        if not _ENVIRONMENT_KEY.fullmatch(key):
            raise _invalid_environment_line(line_number)
        values[key] = _parse_environment_value(raw_value, line_number=line_number)
    return values


def _parse_environment_value(raw_value: str, *, line_number: int) -> str:
    value = raw_value.strip()
    if not value or value.startswith("#"):
        return ""
    if value[0] not in {"'", '"'}:
        return re.split(r"\s+#", value, maxsplit=1)[0].rstrip()

    quote = value[0]
    parsed: list[str] = []
    index = 1
    while index < len(value):
        character = value[index]
        if character == quote:
            remainder = value[index + 1 :].strip()
            if remainder and not remainder.startswith("#"):
                raise _invalid_environment_line(line_number)
            return "".join(parsed)
        if quote == '"' and character == "\\":
            index += 1
            if index >= len(value):
                raise _invalid_environment_line(line_number)
            escaped = value[index]
            decoded = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
            parsed.append(decoded.get(escaped, f"\\{escaped}"))
        else:
            parsed.append(character)
        index += 1
    raise _invalid_environment_line(line_number)


def _invalid_environment_line(line_number: int) -> EnvironmentFileError:
    return EnvironmentFileError(
        "env_file_invalid",
        f"environment file line {line_number} is not a KEY=VALUE assignment",
    )


class MappingSecretResolver:
    """In-memory resolver intended for injected runtimes and focused tests."""

    __slots__ = ("__provider", "__values")

    def __init__(self, values: Mapping[str, str], *, provider: str = "memory") -> None:
        if not _SECRET_REF_PART.fullmatch(provider):
            raise ValueError("secret provider must be a simple non-empty name")
        copied: dict[str, SecretValue] = {}
        for key, value in values.items():
            if not isinstance(key, str) or not _SECRET_REF_PART.fullmatch(key):
                raise ValueError("secret key must be a simple non-empty name")
            copied[key] = SecretValue(value)
        self.__provider = provider
        self.__values = copied

    def resolve(self, reference: SecretRef) -> SecretValue:
        if reference.provider != self.__provider:
            raise SecretResolutionError(f"unsupported secret provider: {reference.provider}")
        try:
            return self.__values[reference.key]
        except KeyError:
            raise SecretResolutionError(
                f"secret reference is not available: {reference.provider}:{reference.key}"
            ) from None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(provider={self.__provider!r}, values={_REDACTED})"

    def __reduce__(self) -> Never:
        raise TypeError("secret resolvers cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("secret resolvers cannot be serialized")
