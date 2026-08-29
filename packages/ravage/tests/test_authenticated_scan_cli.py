from __future__ import annotations

import json
from collections import Counter
from http.cookiejar import Cookie
from pathlib import Path

import pytest
import yaml
from ravage import __main__ as cli
from ravage.auth import SecretValue
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.run_data.brief import load_engagement_brief
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

_TARGET_URL = "http://127.0.0.1:18742/"


def _cookie(name: str, value: str) -> Cookie:
    return Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain="127.0.0.1",
        domain_specified=False,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=False,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": ""},
        rfc2109=False,
    )


def _write_brief(path: Path) -> None:
    payload = {
        "engagement_id": "11111111-1111-4111-8111-111111111111",
        "scope": {"in_scope": [_TARGET_URL], "out_of_scope": []},
        "roe": {"max_rps": 10},
        "objectives": ["web_application_assessment"],
        "budget": {"max_cost_usd": 1.0, "max_runtime_min": 5},
        "authentication": {
            "identities": [
                {
                    "alias": "service",
                    "roles": ["api"],
                    "flow": {
                        "kind": "bearer",
                        "secret_refs": {
                            "token": {
                                "provider": "environment",
                                "key": "RAVAGE_SCAN_SERVICE_TOKEN",
                            }
                        },
                    },
                    "health_check": {
                        "endpoint": {
                            "url": f"{_TARGET_URL}api/me",
                            "scope": "target",
                        },
                        "success_statuses": [200],
                        "authenticated_marker": "service-account",
                    },
                },
                {
                    "alias": "operator",
                    "roles": ["admin"],
                    "flow": {
                        "kind": "oauth2_oidc",
                        "endpoint": {
                            "url": "https://identity.example.test/login",
                            "scope": "auth_dependency",
                        },
                    },
                    "health_check": {
                        "endpoint": {
                            "url": f"{_TARGET_URL}admin",
                            "scope": "target",
                        },
                        "success_statuses": [200],
                    },
                },
            ]
        },
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _write_form_brief(path: Path) -> None:
    payload = {
        "engagement_id": "22222222-2222-4222-8222-222222222222",
        "scope": {"in_scope": [_TARGET_URL], "out_of_scope": []},
        "roe": {"max_rps": 10},
        "objectives": ["web_application_assessment"],
        "budget": {"max_cost_usd": 1.0, "max_runtime_min": 5},
        "authentication": {
            "identities": [
                {
                    "alias": "admin",
                    "roles": ["admin"],
                    "flow": {
                        "kind": "form",
                        "endpoint": {"url": f"{_TARGET_URL}login", "scope": "target"},
                        "secret_refs": {
                            "username": {"provider": "environment", "key": "ADMIN_USER"},
                            "password": {"provider": "environment", "key": "ADMIN_PASSWORD"},
                            "password_confirmation": {
                                "provider": "environment",
                                "key": "ADMIN_PASSWORD",
                            },
                        },
                    },
                    "health_check": {
                        "endpoint": {"url": f"{_TARGET_URL}me", "scope": "target"},
                        "success_statuses": [200],
                        "authenticated_marker": "account-ready",
                    },
                }
            ]
        },
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_scan_reuses_selected_authenticated_session_without_leaking_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_brief(brief)
    secret = "FLAG{configured-service-token-must-not-leak}"
    response_cookie = "FLAG{runtime-session-cookie-must-not-leak}"
    unrelated_token = "opaque-runtime-token-material"
    proof = "FLAG{authz_boundary_8f31c9}"
    monkeypatch.setenv("RAVAGE_SCAN_SERVICE_TOKEN", secret)
    health_calls: list[str] = []
    probe_headers: list[dict[str, str] | None] = []

    def request(
        session: ProbeSession,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        del data, headers, timeout_seconds
        health_calls.append(url)
        assert session.default_headers["Authorization"] == f"Bearer {secret}"
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="service-account",
        )

    def run_probe(*args: object, **kwargs: object) -> ProbeRunResult:
        del args
        session = kwargs.get("session")
        probe_headers.append(
            dict(session.default_headers) if isinstance(session, ProbeSession) else None
        )
        if isinstance(session, ProbeSession):
            inherited = session.fork()
            anonymous = session.fork(inherit_identity=False)
            assert inherited.default_headers["Authorization"] == f"Bearer {secret}"
            assert inherited.managed_identity_generation == session.managed_identity_generation
            assert "Authorization" not in anonymous.default_headers
            assert anonymous.managed_identity_generation is None
            session.cookies.set_cookie(_cookie("session", response_cookie))
        return ProbeRunResult(
            ok=True,
            probe="surface_map",
            summary=f"authenticated with {secret}",
            findings=[
                {
                    "response": {
                        "headers": {
                            "Content-Type": "text/plain",
                            "Set-Cookie": f"session={response_cookie}; HttpOnly",
                        },
                        "body": f"Authorization: Bearer {secret}; opaque={response_cookie}",
                    },
                    "token": f"{unrelated_token}:{proof}",
                }
            ],
            requests=[
                {
                    "status": 200,
                    "cookies": [f"session={response_cookie}"],
                    "body_snippet": f"access_token={secret}",
                }
            ],
        )

    monkeypatch.setattr(ProbeSession, "request", request)
    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)

    cli.main(
        [
            "scan",
            str(brief),
            "--identity",
            "service",
            "--probe",
            "surface_map",
            "--probe",
            "default_credentials",
            "--run-dir",
            str(run_dir),
        ]
    )

    output = capsys.readouterr().out
    assert health_calls == [f"{_TARGET_URL}api/me", f"{_TARGET_URL}api/me"]
    assert probe_headers == [
        {"Authorization": f"Bearer {secret}"},
        None,
    ]
    assert secret not in output
    assert unrelated_token not in output
    assert "flag:found" in output
    assert proof in output
    assert "events.jsonl" in output
    for artifact in run_dir.rglob("*"):
        if not artifact.is_file():
            continue
        content = artifact.read_bytes()
        assert secret.encode() not in content
        assert response_cookie.encode() not in content
        assert unrelated_token.encode() not in content

    summary = json.loads((run_dir / "scan-summary.json").read_text(encoding="utf-8"))
    assert summary["flags"] == [proof]


def test_authenticated_scan_selection_refuses_explicit_unmanaged_probe() -> None:
    with pytest.raises(SystemExit, match="browser_boundary.*raw WebSocket"):
        cli._authenticated_scan_selection(["surface_map", "browser_boundary"], explicit=True)


def test_authenticated_scan_selection_filters_default_and_all_catalogs() -> None:
    selected, skipped = cli._authenticated_scan_selection(
        ["surface_map", "browser_boundary", "cms_exposure", "dom_execution"],
        explicit=False,
    )

    assert selected == ["surface_map"]
    assert set(skipped) == {"browser_boundary", "cms_exposure", "dom_execution"}


@pytest.mark.parametrize("identity", ["service", "operator"])
def test_scan_with_only_anonymous_probes_does_not_authenticate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    identity: str,
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_brief(brief)
    monkeypatch.delenv("RAVAGE_SCAN_SERVICE_TOKEN", raising=False)
    seen_sessions: list[object] = []

    def run_probe(*args: object, **kwargs: object) -> ProbeRunResult:
        del args
        seen_sessions.append(kwargs.get("session"))
        return ProbeRunResult(
            ok=True,
            probe="default_credentials",
            summary="anonymous boundary exercised",
        )

    def unexpected_request(*args: object, **kwargs: object) -> ProbeResponse:
        del args, kwargs
        raise AssertionError("anonymous-only selection must not authenticate")

    monkeypatch.setattr(ProbeSession, "request", unexpected_request)
    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)

    cli.main(
        [
            "scan",
            str(brief),
            "--identity",
            identity,
            "--probe",
            "default_credentials",
            "--run-dir",
            str(run_dir),
        ]
    )

    assert seen_sessions == [None]


def test_scan_identity_requires_a_matching_authentication_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief = tmp_path / "brief.yaml"
    _write_brief(brief)
    monkeypatch.setenv("RAVAGE_SCAN_SERVICE_TOKEN", "available")

    with pytest.raises(SystemExit, match="unknown identity"):
        cli.main(
            [
                "scan",
                str(brief),
                "--identity",
                "missing",
                "--probe",
                "surface_map",
                "--run-dir",
                str(tmp_path / "run"),
            ]
        )

    manifest = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "finished"
    assert manifest["phase"] == "scan_failed"
    assert manifest["result_label"] == "failed"
    assert manifest["is_active"] is False


def test_scan_identity_reports_the_missing_secret_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief = tmp_path / "brief.yaml"
    _write_brief(brief)
    monkeypatch.delenv("RAVAGE_SCAN_SERVICE_TOKEN", raising=False)

    with pytest.raises(SystemExit, match="environment:RAVAGE_SCAN_SERVICE_TOKEN"):
        cli.main(
            [
                "scan",
                str(brief),
                "--identity",
                "service",
                "--probe",
                "surface_map",
                "--run-dir",
                str(tmp_path / "run"),
            ]
        )


def test_configured_scan_snapshots_unique_secrets_and_classifies_traffic_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_form_brief(brief_path)
    brief = load_engagement_brief(brief_path)
    resolver_calls: list[str] = []
    recorders: list[object] = []

    class CountingResolver:
        def resolve(self, reference: object) -> SecretValue:
            key = str(getattr(reference, "key"))
            resolver_calls.append(key)
            return SecretValue("admin" if key == "ADMIN_USER" else "1")

    class CapturingRecorder:
        def __init__(self, _store: object, **kwargs: object) -> None:
            self.known = tuple(kwargs.get("known_secrets") or ())
            self.segment_secrets: set[str] = set()
            recorders.append(self)

        def register_url_segment_secret_values(self, values: object) -> None:
            self.segment_secrets.update(str(value) for value in values)  # type: ignore[arg-type]

        def __call__(self, _event: dict[str, object]) -> None:
            return None

    def request(
        self: ProbeSession,
        method: str,
        url: str,
        **_kwargs: object,
    ) -> ProbeResponse:
        body = "account-ready"
        if url.endswith("/login") and method.upper() == "GET":
            body = (
                '<form method="post" action="/login">'
                '<input name="username"><input name="password" type="password">'
                "</form>"
            )
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body=body,
        )

    monkeypatch.setattr(cli, "ProbeTrafficRecorder", CapturingRecorder)
    monkeypatch.setattr(ProbeSession, "request", request)

    owner, redactor = cli._configured_scan_session(
        brief=brief,
        target_url=_TARGET_URL,
        identity="admin",
        timeout_seconds=5,
        allow_remote_target=False,
        secret_resolver=CountingResolver(),
        traffic_store=object(),  # type: ignore[arg-type]
        traffic_capture_session_id="scan-auth-test",
    )
    try:
        assert Counter(resolver_calls) == Counter({"ADMIN_USER": 1, "ADMIN_PASSWORD": 1})
        [recorder] = recorders
        assert recorder.known == ()  # type: ignore[attr-defined]
        assert recorder.segment_secrets == {"1"}  # type: ignore[attr-defined]
        assert redactor.redact_text("/administrator") == "/administrator"
        assert redactor.contains_secret("FLAG{admin}")
        assert not redactor.contains_secret("FLAG{scan_real_7e91c4}")
    finally:
        owner.close()


def test_authenticated_scan_probe_exception_is_generic_and_secret_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_brief(brief)
    secret = "scan-exception-secret-must-not-leak"
    monkeypatch.setenv("RAVAGE_SCAN_SERVICE_TOKEN", secret)

    def request(
        _session: ProbeSession,
        method: str,
        url: str,
        **_kwargs: object,
    ) -> ProbeResponse:
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="service-account",
        )

    def fail_probe(*_args: object, **_kwargs: object) -> ProbeRunResult:
        raise RuntimeError(f"target reflected {secret}")

    monkeypatch.setattr(ProbeSession, "request", request)
    monkeypatch.setattr(cli, "run_builtin_probe", fail_probe)

    with pytest.raises(SystemExit, match="scan probe 'surface_map' failed"):
        cli.main(
            [
                "scan",
                str(brief),
                "--identity",
                "service",
                "--probe",
                "surface_map",
                "--run-dir",
                str(run_dir),
            ]
        )

    assert secret not in capsys.readouterr().out
    for artifact in run_dir.rglob("*"):
        if artifact.is_file():
            assert secret.encode() not in artifact.read_bytes()
