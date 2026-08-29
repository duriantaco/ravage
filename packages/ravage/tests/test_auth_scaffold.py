from __future__ import annotations

# ruff: noqa: S106
import json
import stat
from typing import TYPE_CHECKING

import pytest
import ravage.auth.scaffold as scaffold_module
import yaml  # type: ignore[import-untyped]
from pentest_schemas import EngagementBrief
from ravage.auth.scaffold import (
    AuthScaffoldError,
    resolve_auth_url,
    scaffold_auth_identity,
)

if TYPE_CHECKING:
    from pathlib import Path

_PRIVATE_FILE_MODE = 0o600


def _write_brief(path: Path, *, target: str = "https://target.test/") -> None:
    payload = {
        "engagement_id": "11111111-1111-4111-8111-111111111111",
        "scope": {"in_scope": [target], "out_of_scope": []},
        "roe": {"max_rps": 10},
        "objectives": ["web_application_assessment"],
        "budget": {"max_cost_usd": 1.0, "max_runtime_min": 5},
        "context": {"owner": "security-team"},
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _load_brief(path: Path) -> tuple[dict[str, object], EngagementBrief]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw, EngagementBrief.model_validate_json(json.dumps(raw))


def test_scaffold_form_identity_resolves_urls_and_creates_private_env_file(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / "credentials.env"
    _write_brief(brief_path)

    result = scaffold_auth_identity(
        brief_path,
        alias="alice",
        method="form",
        env_path=env_path,
        login_url="/sign-in",
        health_url="account",
        roles=("customer",),
        form_fields={
            "email": "RAVAGE_ALICE_EMAIL",
            "password": "RAVAGE_ALICE_PASSWORD",
        },
        authenticated_marker="Account settings",
        unauthenticated_marker="Sign in",
    )

    raw, brief = _load_brief(brief_path)
    assert raw["context"] == {"owner": "security-team"}
    assert brief.authentication is not None
    identity = brief.authentication.identities[0]
    assert identity.alias == "alice"
    assert identity.flow.endpoint is not None
    assert identity.flow.endpoint.url == "https://target.test/sign-in"
    assert identity.health_check.endpoint.url == "https://target.test/account"
    assert identity.flow.secret_refs["email"].key == "RAVAGE_ALICE_EMAIL"
    assert env_path.read_text(encoding="utf-8") == (
        "# Ravage authentication: alice (form)\nRAVAGE_ALICE_EMAIL=\nRAVAGE_ALICE_PASSWORD=\n"
    )
    assert stat.S_IMODE(env_path.stat().st_mode) == _PRIVATE_FILE_MODE
    assert result.added_env_keys == (
        "RAVAGE_ALICE_EMAIL",
        "RAVAGE_ALICE_PASSWORD",
    )
    assert result.preserved_env_keys == ()
    assert result.login_url == "https://target.test/sign-in"
    assert result.health_url == "https://target.test/account"
    assert not result.replaced


def test_form_defaults_to_login_and_username_password_fields(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)

    result = scaffold_auth_identity(
        brief_path,
        alias="member-one",
        method="form",
        authenticated_marker="Sign out",
    )

    _, brief = _load_brief(brief_path)
    assert brief.authentication is not None
    identity = brief.authentication.identities[0]
    assert identity.flow.endpoint is not None
    assert identity.flow.endpoint.url == "https://target.test/login"
    assert set(identity.flow.secret_refs) == {"username", "password"}
    assert result.environment_keys == (
        "RAVAGE_MEMBER_ONE_USERNAME",
        "RAVAGE_MEMBER_ONE_PASSWORD",
    )


def test_scaffold_uses_first_http_target_when_scope_starts_with_a_host(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    payload = yaml.safe_load(brief_path.read_text(encoding="utf-8"))
    payload["scope"]["in_scope"] = ["10.0.0.0/8", "https://target.test/"]
    brief_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    result = scaffold_auth_identity(
        brief_path,
        alias="alice",
        method="form",
        health_url="account",
        authenticated_marker="Account",
    )

    assert result.login_url == "https://target.test/login"
    assert result.health_url == "https://target.test/account"


def test_scaffold_preserves_existing_environment_values_byte_for_byte(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env.ravage"
    _write_brief(brief_path)
    existing = (
        "# operator-owned values\n"
        "export RAVAGE_SERVICE_TOKEN = actual-token-value\n"
        "UNRELATED=keep-me"
    )
    env_path.write_text(existing, encoding="utf-8")
    env_path.chmod(0o644)

    result = scaffold_auth_identity(
        brief_path,
        alias="service",
        method="bearer",
        env_path=env_path,
        health_url="/api/me",
        authenticated_marker='"subject"',
    )

    assert env_path.read_text(encoding="utf-8") == existing
    assert stat.S_IMODE(env_path.stat().st_mode) == _PRIVATE_FILE_MODE
    assert result.added_env_keys == ()
    assert result.preserved_env_keys == ("RAVAGE_SERVICE_TOKEN",)
    assert "actual-token-value" not in brief_path.read_text(encoding="utf-8")


def test_duplicate_alias_is_refused_without_writing_and_can_be_replaced(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env.ravage"
    _write_brief(brief_path)
    scaffold_auth_identity(
        brief_path,
        alias="partner",
        method="header",
        env_path=env_path,
        health_url="/api/whoami",
        authenticated_marker="partner",
    )
    original_brief = brief_path.read_bytes()
    original_env = env_path.read_bytes()

    with pytest.raises(AuthScaffoldError, match="already exists"):
        scaffold_auth_identity(
            brief_path,
            alias="partner",
            method="bearer",
            env_path=env_path,
            health_url="/api/me",
            authenticated_marker="partner",
        )

    assert brief_path.read_bytes() == original_brief
    assert env_path.read_bytes() == original_env

    result = scaffold_auth_identity(
        brief_path,
        alias="partner",
        method="bearer",
        env_path=env_path,
        secret_env="PARTNER_REPLACEMENT_TOKEN",
        health_url="/api/me",
        authenticated_marker="partner",
        replace=True,
    )

    _, brief = _load_brief(brief_path)
    assert brief.authentication is not None
    assert len(brief.authentication.identities) == 1
    assert brief.authentication.identities[0].flow.kind == "bearer"
    assert "RAVAGE_PARTNER_API_KEY=\n" in env_path.read_text(encoding="utf-8")
    assert "PARTNER_REPLACEMENT_TOKEN=\n" in env_path.read_text(encoding="utf-8")
    assert result.replaced


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/login", "https://target.test/login"),
        ("login", "https://target.test/application/login"),
        ("https://target.test/sign-in?next=%2F", "https://target.test/sign-in?next=%2F"),
    ],
)
def test_resolve_auth_url_supports_absolute_and_target_relative_values(
    value: str,
    expected: str,
) -> None:
    assert resolve_auth_url("https://target.test/application", value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "//other.test/login",
        "ftp://target.test/login",
        "https://user:pass@target.test/login",
        "/x#y",
    ],
)
def test_resolve_auth_url_rejects_ambiguous_or_unsafe_values(value: str) -> None:
    with pytest.raises(AuthScaffoldError):
        resolve_auth_url("https://target.test/", value)


def test_scaffold_rejects_out_of_scope_or_cross_origin_endpoints_before_writing(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env.ravage"
    _write_brief(brief_path, target="https://target.test/application")
    original = brief_path.read_bytes()

    with pytest.raises(AuthScaffoldError, match="outside the engagement scope"):
        scaffold_auth_identity(
            brief_path,
            alias="alice",
            method="form",
            env_path=env_path,
            login_url="/login",
            health_url="account",
            authenticated_marker="Account",
        )
    assert brief_path.read_bytes() == original
    assert not env_path.exists()

    with pytest.raises(AuthScaffoldError, match="primary target origin"):
        scaffold_auth_identity(
            brief_path,
            alias="alice",
            method="bearer",
            env_path=env_path,
            health_url="https://identity.test/me",
            authenticated_marker="alice",
        )
    assert brief_path.read_bytes() == original
    assert not env_path.exists()


def test_scaffold_rejects_remote_plain_http_before_writing(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env.ravage"
    _write_brief(brief_path, target="http://target.test/")
    original = brief_path.read_bytes()

    with pytest.raises(AuthScaffoldError, match="requires HTTPS"):
        scaffold_auth_identity(
            brief_path,
            alias="service",
            method="bearer",
            env_path=env_path,
            authenticated_marker="service",
        )

    assert brief_path.read_bytes() == original
    assert not env_path.exists()


def test_scaffold_rejects_an_env_file_hard_linked_to_the_brief(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env.ravage"
    _write_brief(brief_path)
    env_path.hardlink_to(brief_path)
    original = brief_path.read_bytes()

    with pytest.raises(AuthScaffoldError, match="cannot share one file"):
        scaffold_auth_identity(
            brief_path,
            alias="service",
            method="bearer",
            env_path=env_path,
            authenticated_marker="service",
        )

    assert brief_path.read_bytes() == original


def test_scaffold_requires_health_marker_and_does_not_create_files(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env.ravage"
    _write_brief(brief_path)
    original = brief_path.read_bytes()

    with pytest.raises(AuthScaffoldError, match="health marker is required"):
        scaffold_auth_identity(
            brief_path,
            alias="service",
            method="bearer",
            env_path=env_path,
        )

    assert brief_path.read_bytes() == original
    assert not env_path.exists()


def test_environment_replacement_failure_leaves_original_files_intact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env.ravage"
    _write_brief(brief_path)
    env_path.write_text("UNCHANGED=value\n", encoding="utf-8")
    original_brief = brief_path.read_bytes()
    original_env = env_path.read_bytes()

    def fail_replace(source: str | Path, destination: str | Path) -> None:
        del source, destination
        message = "simulated replacement failure"
        raise OSError(message)

    monkeypatch.setattr(scaffold_module.os, "replace", fail_replace)
    with pytest.raises(AuthScaffoldError, match="could not update environment file"):
        scaffold_auth_identity(
            brief_path,
            alias="service",
            method="bearer",
            env_path=env_path,
            authenticated_marker="service",
        )

    assert brief_path.read_bytes() == original_brief
    assert env_path.read_bytes() == original_env
    assert not list(tmp_path.glob(".*.tmp"))
