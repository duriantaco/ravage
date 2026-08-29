"""Secret-safe authentication scaffolding for engagement briefs."""

# Scaffold validation errors intentionally preserve actionable CLI context.
# ruff: noqa: EM101, EM102, PLR0913, TRY003

from __future__ import annotations

import copy
import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urljoin, urlsplit, urlunsplit

import yaml  # type: ignore[import-untyped]
from pentest_schemas import EngagementBrief
from pydantic import ValidationError

from ravage.run_data.brief import first_http_target
from ravage.web_core.scope_policy import is_local_url, same_origin, url_in_scope_entries

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

ScaffoldAuthMethod = Literal["form", "bearer", "static_header"]

_SUPPORTED_METHODS: frozenset[str] = frozenset({"form", "bearer", "static_header"})
_METHOD_ALIASES = {"header": "static_header"}
_ENV_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=",
    re.MULTILINE,
)
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HTTP_SCHEMES = frozenset({"http", "https"})


class AuthScaffoldError(ValueError):
    """Authentication configuration could not be generated safely."""


@dataclass(frozen=True, slots=True)
class AuthScaffoldResult:
    """Non-secret summary of an authentication scaffold operation."""

    brief_path: Path
    env_path: Path
    alias: str
    method: ScaffoldAuthMethod
    login_url: str | None
    health_url: str
    environment_keys: tuple[str, ...]
    added_env_keys: tuple[str, ...]
    preserved_env_keys: tuple[str, ...]
    replaced: bool


def scaffold_auth_identity(
    brief_path: str | Path,
    *,
    alias: str,
    method: ScaffoldAuthMethod | str,
    env_path: str | Path | None = None,
    login_url: str | None = None,
    health_url: str | None = None,
    roles: Sequence[str] = ("authenticated",),
    form_fields: Mapping[str, str] | None = None,
    secret_env: str | None = None,
    header_name: str = "X-API-Key",
    health_method: Literal["GET", "HEAD"] = "GET",
    health_statuses: Sequence[int] = (200,),
    authenticated_marker: str | None = None,
    unauthenticated_marker: str | None = None,
    follow_redirects: bool = False,
    replace: bool = False,
) -> AuthScaffoldResult:
    """
    Add one executable authentication identity to an existing brief.

    Only environment-variable references are written to YAML. Missing variables
    are appended as empty placeholders to a private environment file; existing
    assignments are preserved byte-for-byte.
    """
    resolved_brief_path = Path(brief_path).expanduser()
    resolved_env_path = (
        Path(env_path).expanduser()
        if env_path is not None
        else resolved_brief_path.parent / ".env.ravage"
    )
    _assert_safe_paths(resolved_brief_path, resolved_env_path)

    payload = _load_brief_payload(resolved_brief_path)
    current_brief = _validate_brief(payload, prefix="invalid engagement brief")
    try:
        primary_target = first_http_target(current_brief)
    except ValueError as exc:
        raise AuthScaffoldError(str(exc)) from None
    normalized_method = _normalize_method(method)
    if authenticated_marker is None and unauthenticated_marker is None:
        raise AuthScaffoldError(
            "a health marker is required to distinguish an authenticated session"
        )

    resolved_health_url = resolve_auth_url(primary_target, health_url or primary_target)
    _require_runtime_target_url(
        primary_target,
        resolved_health_url,
        brief=current_brief,
        label="health-check URL",
    )

    identity, resolved_login_url, environment_keys = _identity_payload(
        alias=alias,
        method=normalized_method,
        primary_target=primary_target,
        login_url=login_url,
        health_url=resolved_health_url,
        roles=roles,
        form_fields=form_fields,
        secret_env=secret_env,
        header_name=header_name,
        health_method=health_method,
        health_statuses=health_statuses,
        authenticated_marker=authenticated_marker,
        unauthenticated_marker=unauthenticated_marker,
        follow_redirects=follow_redirects,
    )
    if resolved_login_url is not None:
        _require_runtime_target_url(
            primary_target,
            resolved_login_url,
            brief=current_brief,
            label="login URL",
        )

    updated_payload = copy.deepcopy(payload)
    identities = _mutable_identities(updated_payload)
    matching_indexes = [
        index
        for index, configured in enumerate(identities)
        if isinstance(configured, dict) and configured.get("alias") == alias
    ]
    if matching_indexes and not replace:
        raise AuthScaffoldError(
            f"identity {alias!r} already exists; pass replace=True to update it"
        )
    if len(matching_indexes) > 1:
        raise AuthScaffoldError(f"engagement brief contains duplicate identity {alias!r}")

    replaced = bool(matching_indexes)
    if replaced:
        identities[matching_indexes[0]] = identity
    else:
        identities.append(identity)
    _validate_brief(updated_payload, prefix="generated authentication configuration is invalid")

    existing_env_text = _read_environment_text(resolved_env_path)
    updated_env_text, added_env_keys, preserved_env_keys = _append_env_placeholders(
        existing_env_text,
        alias=alias,
        method=normalized_method,
        environment_keys=environment_keys,
    )
    brief_text = yaml.safe_dump(updated_payload, sort_keys=False)

    try:
        _atomic_write_text(resolved_env_path, updated_env_text, mode=0o600)
    except OSError as exc:
        raise AuthScaffoldError(f"could not update environment file: {exc}") from exc
    brief_mode = stat.S_IMODE(resolved_brief_path.stat().st_mode)
    try:
        _atomic_write_text(resolved_brief_path, brief_text, mode=brief_mode)
    except OSError as exc:
        raise AuthScaffoldError(f"could not update engagement brief: {exc}") from exc

    return AuthScaffoldResult(
        brief_path=resolved_brief_path,
        env_path=resolved_env_path,
        alias=alias,
        method=normalized_method,
        login_url=resolved_login_url,
        health_url=resolved_health_url,
        environment_keys=environment_keys,
        added_env_keys=added_env_keys,
        preserved_env_keys=preserved_env_keys,
        replaced=replaced,
    )


def resolve_auth_url(primary_target: str, value: str) -> str:
    """Resolve an absolute or target-relative auth URL to an HTTP(S) URL."""
    candidate = value.strip()
    if not candidate:
        raise AuthScaffoldError("authentication URL cannot be empty")
    target = urlsplit(primary_target)
    if target.scheme.lower() not in _HTTP_SCHEMES or target.hostname is None:
        raise AuthScaffoldError("the primary in-scope target must be an HTTP(S) URL")
    if target.username is not None or target.password is not None:
        raise AuthScaffoldError("the primary target URL cannot contain credentials")

    parsed_candidate = urlsplit(candidate)
    if parsed_candidate.scheme:
        resolved = candidate
    else:
        if candidate.startswith("//"):
            raise AuthScaffoldError("network-relative authentication URLs are not supported")
        base_path = target.path or "/"
        if not base_path.endswith("/"):
            base_path = f"{base_path}/"
        base = urlunsplit((target.scheme, target.netloc, base_path, "", ""))
        resolved = urljoin(base, candidate)

    parsed = urlsplit(resolved)
    if parsed.scheme.lower() not in _HTTP_SCHEMES or parsed.hostname is None:
        raise AuthScaffoldError("authentication URL must resolve to an HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise AuthScaffoldError("authentication URLs cannot contain credentials")
    if parsed.fragment:
        raise AuthScaffoldError("authentication URLs cannot contain fragments")
    return resolved


def default_secret_environment_key(alias: str, secret_name: str) -> str:
    """Return the conventional environment key for a named identity secret."""
    normalized_alias = _environment_component(alias)
    normalized_secret = _environment_component(secret_name)
    key = f"RAVAGE_{normalized_alias}_{normalized_secret}"
    if not _ENV_KEY_RE.fullmatch(key):
        raise AuthScaffoldError("could not derive a valid environment-variable name")
    return key


def _identity_payload(
    *,
    alias: str,
    method: ScaffoldAuthMethod,
    primary_target: str,
    login_url: str | None,
    health_url: str,
    roles: Sequence[str],
    form_fields: Mapping[str, str] | None,
    secret_env: str | None,
    header_name: str,
    health_method: str,
    health_statuses: Sequence[int],
    authenticated_marker: str | None,
    unauthenticated_marker: str | None,
    follow_redirects: bool,
) -> tuple[dict[str, object], str | None, tuple[str, ...]]:
    resolved_login_url: str | None = None
    if method == "form":
        if secret_env is not None:
            raise AuthScaffoldError("form authentication uses form_fields, not secret_env")
        resolved_login_url = resolve_auth_url(primary_target, login_url or "/login")
        configured_fields = dict(
            form_fields
            or {
                "username": default_secret_environment_key(alias, "username"),
                "password": default_secret_environment_key(alias, "password"),
            }
        )
        if not configured_fields:
            raise AuthScaffoldError("form authentication requires at least one secret field")
        _validate_environment_keys(configured_fields.values())
        flow: dict[str, object] = {
            "kind": "form",
            "endpoint": {"url": resolved_login_url, "scope": "target"},
            "secret_refs": {
                name: {"provider": "environment", "key": env_key}
                for name, env_key in configured_fields.items()
            },
        }
        environment_keys = tuple(dict.fromkeys(configured_fields.values()))
    elif method == "bearer":
        _reject_form_only_options(login_url=login_url, form_fields=form_fields)
        token_env = secret_env or default_secret_environment_key(alias, "token")
        _validate_environment_keys((token_env,))
        flow = {
            "kind": "bearer",
            "secret_refs": {
                "token": {"provider": "environment", "key": token_env},
            },
        }
        environment_keys = (token_env,)
    else:
        _reject_form_only_options(login_url=login_url, form_fields=form_fields)
        header_env = secret_env or default_secret_environment_key(alias, "api_key")
        _validate_environment_keys((header_env,))
        flow = {
            "kind": "static_header",
            "static_header": {
                "name": header_name,
                "value": {"provider": "environment", "key": header_env},
            },
        }
        environment_keys = (header_env,)

    health_check: dict[str, object] = {
        "endpoint": {"url": health_url, "scope": "target"},
        "method": health_method,
        "success_statuses": list(health_statuses),
        "follow_redirects": follow_redirects,
    }
    if authenticated_marker is not None:
        health_check["authenticated_marker"] = authenticated_marker
    if unauthenticated_marker is not None:
        health_check["unauthenticated_marker"] = unauthenticated_marker
    return (
        {
            "alias": alias,
            "roles": list(roles),
            "flow": flow,
            "health_check": health_check,
        },
        resolved_login_url,
        environment_keys,
    )


def _load_brief_payload(path: Path) -> dict[str, object]:
    if not path.exists():
        raise AuthScaffoldError(f"engagement brief does not exist: {path}")
    if not path.is_file() or path.is_symlink():
        raise AuthScaffoldError("engagement brief must be a regular, non-symlink file")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = ""
        if mark is not None:
            location = f" at line {mark.line + 1}, column {mark.column + 1}"
        raise AuthScaffoldError(f"could not parse engagement brief YAML{location}") from exc
    except (OSError, UnicodeError) as exc:
        raise AuthScaffoldError(f"could not read engagement brief: {exc}") from exc
    if not isinstance(raw, dict):
        raise AuthScaffoldError("engagement brief must be a YAML mapping")
    return raw


def _validate_brief(payload: dict[str, object], *, prefix: str) -> EngagementBrief:
    try:
        return EngagementBrief.model_validate_json(json.dumps(payload))
    except (TypeError, ValueError, ValidationError) as exc:
        detail = _validation_error_detail(exc) if isinstance(exc, ValidationError) else str(exc)
        raise AuthScaffoldError(f"{prefix}: {detail}") from exc


def _validation_error_detail(exc: ValidationError) -> str:
    error = exc.errors(include_url=False, include_input=False)[0]
    location = ".".join(str(part) for part in error.get("loc", ()))
    message = str(error.get("msg", "validation failed"))
    return f"{location}: {message}" if location else message


def _mutable_identities(payload: dict[str, object]) -> list[object]:
    authentication = payload.get("authentication")
    if authentication is None:
        authentication = {"identities": []}
        payload["authentication"] = authentication
    if not isinstance(authentication, dict):
        raise AuthScaffoldError("authentication must be a YAML mapping")
    identities = authentication.get("identities")
    if not isinstance(identities, list):
        raise AuthScaffoldError("authentication.identities must be a YAML list")
    return identities


def _append_env_placeholders(
    existing: str,
    *,
    alias: str,
    method: ScaffoldAuthMethod,
    environment_keys: tuple[str, ...],
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    configured = frozenset(_ENV_ASSIGNMENT_RE.findall(existing))
    added = tuple(key for key in environment_keys if key not in configured)
    preserved = tuple(key for key in environment_keys if key in configured)
    if not added:
        return existing, added, preserved

    updated = existing
    if updated and not updated.endswith("\n"):
        updated += "\n"
    if updated and not updated.endswith("\n\n"):
        updated += "\n"
    updated += f"# Ravage authentication: {alias} ({method})\n"
    updated += "".join(f"{key}=\n" for key in added)
    return updated, added, preserved


def _read_environment_text(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AuthScaffoldError(f"could not read environment file: {exc}") from exc


def _atomic_write_text(path: Path, content: str, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(file_descriptor, mode)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="") as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.replace(path)
        _fsync_directory(path.parent)
    except BaseException:
        with suppress(OSError):
            os.close(file_descriptor)
        with suppress(OSError):
            temporary_path.unlink()
        raise


def _fsync_directory(path: Path) -> None:
    with suppress(OSError):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _assert_safe_paths(brief_path: Path, env_path: Path) -> None:
    if env_path.is_symlink() or (env_path.exists() and not env_path.is_file()):
        raise AuthScaffoldError("environment path must be a regular, non-symlink file")
    if brief_path.resolve(strict=False) == env_path.resolve(strict=False):
        raise AuthScaffoldError("engagement brief and environment file must be different paths")
    if brief_path.exists() and env_path.exists() and brief_path.samefile(env_path):
        raise AuthScaffoldError("engagement brief and environment file cannot share one file")


def _normalize_method(method: str) -> ScaffoldAuthMethod:
    normalized = method.strip().lower().replace("-", "_")
    normalized = _METHOD_ALIASES.get(normalized, normalized)
    if normalized not in _SUPPORTED_METHODS:
        supported = ", ".join(sorted(_SUPPORTED_METHODS))
        raise AuthScaffoldError(f"unsupported authentication method; choose one of: {supported}")
    return cast("ScaffoldAuthMethod", normalized)


def _require_runtime_target_url(
    primary_target: str,
    candidate: str,
    *,
    brief: EngagementBrief,
    label: str,
) -> None:
    if candidate.lower().startswith("http://") and not is_local_url(candidate):
        raise AuthScaffoldError(f"{label} requires HTTPS outside localhost development")
    if not same_origin(primary_target, candidate):
        raise AuthScaffoldError(
            f"{label} must use the primary target origin; cross-origin login is not supported"
        )
    if not url_in_scope_entries(
        candidate,
        in_scope=brief.scope.in_scope,
        out_of_scope=brief.scope.out_of_scope,
    ):
        raise AuthScaffoldError(f"{label} is outside the engagement scope: {candidate}")


def _validate_environment_keys(keys: Iterable[str]) -> None:
    invalid = next((key for key in keys if not _ENV_KEY_RE.fullmatch(key)), None)
    if invalid is not None:
        raise AuthScaffoldError(f"invalid environment-variable name: {invalid!r}")


def _reject_form_only_options(
    *,
    login_url: str | None,
    form_fields: Mapping[str, str] | None,
) -> None:
    if login_url is not None or form_fields is not None:
        raise AuthScaffoldError("login_url and form_fields are only valid for form authentication")


def _environment_component(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    if not normalized:
        raise AuthScaffoldError("identity and secret names must contain a letter or number")
    return normalized


__all__ = [
    "AuthScaffoldError",
    "AuthScaffoldResult",
    "ScaffoldAuthMethod",
    "default_secret_environment_key",
    "resolve_auth_url",
    "scaffold_auth_identity",
]
