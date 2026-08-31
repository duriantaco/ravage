from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

import pytest
import yaml
from ravage import __main__ as cli
from ravage.traffic.policy import (
    RequestIntent,
    TrafficOutcome,
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyMode,
)
from ravage.web_core.http_probe import ProbeResponse

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from ravage.traffic.policy import TrafficPolicySnapshot


_TARGET = "http://127.0.0.1:18759/"
_PLAN_SCHEMA = "ravage.authorization-matrix.plan.v1"
_MARKER_ENV = "RAVAGE_MATRIX_ORDER_MARKER"
_MARKER = "order-owner-proof-phrase"
_AUTH_SECRET = "matrix-auth-secret-value"  # noqa: S105 - redaction sentinel.
_RAW_RESPONSE = "raw response content must not persist"
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_ARGPARSE_ERROR = 2
_REQUEST_LIMIT = 9
_REQUEST_RATE = 0.25
_VIOLATION_REQUEST_COUNT = 4


@dataclass
class _Clock:
    value: float = 1_000.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += max(float(seconds), 0.0)


class _FakeMatrixRuntime:
    def __init__(
        self,
        *,
        policy: TrafficPolicyController,
        identities: Sequence[str],
        marker: str,
        behavior: str,
    ) -> None:
        self.policy = policy
        self.identities = tuple(identities)
        self.initial_traffic_snapshot = policy.snapshot()
        self.marker = marker
        self.behavior = behavior
        self.requests: list[tuple[str | None, str, str]] = []
        self.close_calls = 0

    def roles(self, identity_alias: str) -> tuple[str, ...]:
        return {
            "alice": ("customer", "owner"),
            "bob": ("customer",),
        }[identity_alias]

    def request(
        self,
        identity_alias: str | None,
        method: str,
        url: str,
    ) -> ProbeResponse:
        self.requests.append((identity_alias, method, url))
        status, body = self._response_for(identity_alias)
        intent = RequestIntent(
            method,
            url,
            lane="authorization_matrix",
            identity_alias=identity_alias or "anonymous",
            cacheable=False,
            retryable=False,
        )
        decision = self.policy.acquire(intent)
        assert decision.lease is not None
        self.policy.begin_dispatch(decision.lease)
        self.policy.complete(decision.lease, TrafficOutcome(status=status))
        return ProbeResponse(
            method=method,
            url=url,
            status=status,
            final_url=url,
            elapsed_ms=1,
            headers={"Authorization": f"Bearer {_AUTH_SECRET}"},
            body=body,
        )

    def traffic_snapshot(self) -> TrafficPolicySnapshot:
        return self.policy.snapshot()

    def close(self) -> None:
        self.close_calls += 1

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def _response_for(self, identity_alias: str | None) -> tuple[int, str]:
        if identity_alias == "alice":
            return 200, (
                f"marker={self.marker}; authorization=Bearer {_AUTH_SECRET}; {_RAW_RESPONSE}"
            )
        if self.behavior == "violation":
            return 200, f"marker={self.marker}; {_RAW_RESPONSE}"
        if self.behavior == "inconclusive":
            return 503, _RAW_RESPONSE
        return 403, f"access denied; {_RAW_RESPONSE}"


def test_auth_matrix_help_documents_required_inputs_and_safety_controls(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["auth", "matrix", "--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "usage: ravage auth matrix" in output
    assert "brief" in output
    assert "plan" in output
    assert "--run-dir" in output
    assert "--max-physical-requests" in output
    assert "--traffic-max-rps" in output
    assert "--authorized-remote-target" in output
    assert "read-only authorization checks" in output


def test_auth_matrix_requires_two_configured_identities_before_loading_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    _write_brief(brief, identities=("alice",))

    def unexpected_plan_load(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the plan must not load before the identity-count check")

    monkeypatch.setattr(cli, "load_authorization_matrix_plan", unexpected_plan_load)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["auth", "matrix", str(brief), str(tmp_path / "missing-plan.yaml")])

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert "requires at least two configured identities" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_remote_matrix_fails_closed_before_plan_or_runtime_network_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    remote_target = "https://matrix.example.test/"
    _write_brief(brief, target=remote_target)

    def unexpected_call(*_args: object, **_kwargs: object) -> None:
        pytest.fail("remote refusal must happen before plan loading or runtime construction")

    monkeypatch.setattr(cli, "load_authorization_matrix_plan", unexpected_call)
    monkeypatch.setattr(cli, "build_managed_authorization_matrix", unexpected_call)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["auth", "matrix", str(brief), str(tmp_path / "missing-plan.yaml")])

    assert exc_info.value.code == _ARGPARSE_ERROR
    error = capsys.readouterr().err
    assert "remote targets require --authorized-remote-target" in error
    assert "Traceback" not in error
    assert not (tmp_path / "runs").exists()


def test_out_of_scope_target_error_does_not_echo_raw_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    raw_secret = "scope-query-secret"  # noqa: S105 - redaction sentinel.
    explicit_target = f"{_TARGET}outside?token={raw_secret}"
    _write_brief(brief, target=f"{_TARGET}allowed/")

    def unexpected_plan_load(*_args: object, **_kwargs: object) -> None:
        pytest.fail("target scope validation must happen before plan loading")

    monkeypatch.setattr(cli, "load_authorization_matrix_plan", unexpected_plan_load)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "auth",
                "matrix",
                str(brief),
                str(tmp_path / "missing-plan.yaml"),
                "--target-url",
                explicit_target,
            ]
        )

    assert exc_info.value.code == _ARGPARSE_ERROR
    error = capsys.readouterr().err
    assert "target is invalid or outside engagement scope" in error
    assert raw_secret not in error
    assert explicit_target not in error


@pytest.mark.parametrize(
    ("case", "scope_target", "expected_error"),
    [
        (
            {
                "id": "unsafe_method",
                "method": "POST",
                "url": f"{_TARGET}orders/483920",
                "owner": "alice",
                "marker_env": _MARKER_ENV,
                "expect": {"alice": "allow", "bob": "deny"},
            },
            _TARGET,
            "invalid authorization matrix plan: authorization matrix cases permit GET only",
        ),
        (
            {
                "id": "wrong_origin",
                "url": "http://127.0.0.1:18760/orders/483920",
                "owner": "alice",
                "marker_env": _MARKER_ENV,
                "expect": {"alice": "allow", "bob": "deny"},
            },
            _TARGET,
            "must use the target origin",
        ),
        (
            {
                "id": "outside_scope",
                "url": f"{_TARGET}private/orders/483920",
                "owner": "alice",
                "marker_env": _MARKER_ENV,
                "expect": {"alice": "allow", "bob": "deny"},
            },
            f"{_TARGET}allowed/",
            "is outside engagement scope",
        ),
        (
            {
                "id": "one_identity",
                "url": f"{_TARGET}orders/483920",
                "owner": "alice",
                "marker_env": _MARKER_ENV,
                "expect": {"alice": "allow", "anonymous": "deny"},
            },
            _TARGET,
            "plan must compare at least two configured identities",
        ),
    ],
)
def test_auth_matrix_validates_plan_origin_scope_and_selected_identities(  # noqa: PLR0913
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: Mapping[str, object],
    scope_target: str,
    expected_error: str,
) -> None:
    brief = tmp_path / "brief.yaml"
    plan = tmp_path / "plan.yaml"
    _write_brief(brief, target=scope_target)
    _write_plan(plan, case)

    def unexpected_build(*_args: object, **_kwargs: object) -> None:
        pytest.fail("invalid plans must not construct the network runtime")

    monkeypatch.setattr(cli, "build_managed_authorization_matrix", unexpected_build)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["auth", "matrix", str(brief), str(plan)])

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert expected_error in capsys.readouterr().err


def test_local_clear_run_uses_one_low_noise_policy_and_private_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    plan = tmp_path / "plan.yaml"
    run_dir = tmp_path / "matrix-run"
    case = _case(url=f"{_TARGET}orders/483920?account_id=7733")
    _write_brief(brief)
    _write_plan(plan, case)
    monkeypatch.setenv(_MARKER_ENV, _MARKER)
    capture = _install_runtime(
        monkeypatch,
        behavior="clear",
        marker=_MARKER,
    )

    cli.main(
        _matrix_args(
            brief,
            plan,
            run_dir,
            max_physical_requests=_REQUEST_LIMIT,
            traffic_max_rps=_REQUEST_RATE,
        )
    )

    output = capsys.readouterr().out
    receipt_path = run_dir / "authorization-matrix.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    policy = capture["policy"]
    runtime = capture["runtime"]
    builder_kwargs = capture["builder_kwargs"]
    assert isinstance(policy, TrafficPolicyController)
    assert isinstance(runtime, _FakeMatrixRuntime)
    assert isinstance(builder_kwargs, dict)
    assert "AUTH MATRIX" in output
    assert "order_access" in output
    assert "3 physical requests" in output
    assert "mode=0600" in output
    assert receipt["verdict"] == "no_violation"
    assert receipt["traffic_delta"] == {
        "blocked_count": 0,
        "cache_hit_count": 0,
        "circuit_open_count": 0,
        "completed_request_count": 3,
        "current_accounting_status": "exact",
        "deduplicated_count": 0,
        "incomplete_request_count": 0,
        "initial_accounting_status": "exact",
        "pending_dispatch_count": 0,
        "physical_request_count": 3,
        "reservation_count": 0,
        "retry_count": 0,
        "unmetered_action_count": 0,
    }
    assert policy.config.mode is TrafficPolicyMode.ENFORCE
    assert policy.config.max_physical_requests == _REQUEST_LIMIT
    assert policy.config.max_rps == _REQUEST_RATE
    assert policy.config.cache_enabled is True
    assert policy.config.deduplicate is True
    assert builder_kwargs["identities"] == ("alice", "bob")
    assert builder_kwargs["traffic_policy"] is policy
    assert runtime.policy is policy
    assert runtime.close_calls == 1
    assert stat.S_IMODE(run_dir.stat().st_mode) == _PRIVATE_DIRECTORY_MODE
    assert stat.S_IMODE(receipt_path.stat().st_mode) == _PRIVATE_FILE_MODE


def test_marker_backed_violation_needs_no_ctf_flag_and_receipt_is_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    plan = tmp_path / "plan.yaml"
    run_dir = tmp_path / "matrix-run"
    concrete_id = "483920"
    second_id = "998877"
    query_value = "query-secret-value"
    query_id = "7733"
    case = _case(
        url=(
            f"{_TARGET}accounts/{concrete_id}/orders/{second_id}"
            f"?access_token={query_value}&item_id={query_id}"
        )
    )
    _write_brief(brief)
    _write_plan(plan, case)
    monkeypatch.setenv(_MARKER_ENV, _MARKER)
    monkeypatch.setenv("RAVAGE_ALICE_TOKEN", _AUTH_SECRET)
    _install_runtime(monkeypatch, behavior="violation", marker=_MARKER)

    with pytest.raises(SystemExit) as exc_info:
        cli.main([*_matrix_args(brief, plan, run_dir), "--json"])

    assert exc_info.value.code == 1
    stdout_payload = json.loads(capsys.readouterr().out)
    receipt_payload = json.loads(
        (run_dir / "authorization-matrix.json").read_text(encoding="utf-8")
    )
    assert stdout_payload == receipt_payload
    assert receipt_payload["verdict"] == "confirmed_violation"
    assert receipt_payload["cases"][0]["violation_actors"] == ["bob"]
    assert receipt_payload["cases"][0]["reason_codes"] == ["denied_actor_marker_exposed"]
    assert receipt_payload["traffic_delta"]["physical_request_count"] == _VIOLATION_REQUEST_COUNT
    assert receipt_payload["traffic_delta"]["completed_request_count"] == _VIOLATION_REQUEST_COUNT
    serialized = json.dumps(receipt_payload, sort_keys=True)
    for forbidden in (
        _MARKER,
        _AUTH_SECRET,
        _RAW_RESPONSE,
        concrete_id,
        second_id,
        query_value,
        query_id,
        "flag{",
    ):
        assert forbidden not in serialized
    safe_url = receipt_payload["cases"][0]["url"]
    assert ":id" in safe_url
    assert "%5BREDACTED%5D" in safe_url


def test_missing_marker_produces_inconclusive_receipt_without_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    plan = tmp_path / "plan.yaml"
    run_dir = tmp_path / "matrix-run"
    missing_marker_env = "RAVAGE_MATRIX_MISSING_MARKER"
    case = _case(url=f"{_TARGET}orders/483920", marker_env=missing_marker_env)
    _write_brief(brief)
    _write_plan(plan, case)
    monkeypatch.delenv(missing_marker_env, raising=False)
    capture = _install_runtime(monkeypatch, behavior="inconclusive", marker=_MARKER)

    with pytest.raises(SystemExit) as exc_info:
        cli.main([*_matrix_args(brief, plan, run_dir), "--json"])

    assert exc_info.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    runtime = capture["runtime"]
    assert isinstance(runtime, _FakeMatrixRuntime)
    assert payload["verdict"] == "inconclusive"
    assert payload["cases"][0]["reason_codes"] == ["marker_unavailable"]
    assert payload["cases"][0]["observations"] == []
    assert payload["traffic_delta"]["physical_request_count"] == 0
    assert payload["traffic_delta"]["current_accounting_status"] == "exact"
    assert runtime.requests == []


def _install_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    behavior: str,
    marker: str,
) -> dict[str, object]:
    capture: dict[str, object] = {}
    clock = _Clock()

    class PolicyFactory:
        @staticmethod
        def open(
            state_path: str | Path,
            *,
            target_url: str,
            config: TrafficPolicyConfig,
            **_kwargs: object,
        ) -> TrafficPolicyController:
            policy = TrafficPolicyController.open(
                state_path,
                target_url=target_url,
                config=config,
                clock=clock,
                sleep=clock.sleep,
            )
            capture["policy"] = policy
            return policy

    def fake_build(**kwargs: object) -> _FakeMatrixRuntime:
        identities = kwargs["identities"]
        policy = kwargs["traffic_policy"]
        assert isinstance(identities, tuple)
        assert all(isinstance(alias, str) for alias in identities)
        assert isinstance(policy, TrafficPolicyController)
        runtime = _FakeMatrixRuntime(
            policy=policy,
            identities=identities,
            marker=marker,
            behavior=behavior,
        )
        capture["builder_kwargs"] = dict(kwargs)
        capture["runtime"] = runtime
        return runtime

    monkeypatch.setattr(cli, "TrafficPolicyController", PolicyFactory)
    monkeypatch.setattr(cli, "build_managed_authorization_matrix", fake_build)
    return capture


def _matrix_args(
    brief: Path,
    plan: Path,
    run_dir: Path,
    *,
    max_physical_requests: int = 20,
    traffic_max_rps: float = 0.5,
) -> list[str]:
    return [
        "auth",
        "matrix",
        str(brief),
        str(plan),
        "--run-dir",
        str(run_dir),
        "--max-physical-requests",
        str(max_physical_requests),
        "--traffic-max-rps",
        str(traffic_max_rps),
    ]


def _case(
    *,
    url: str,
    marker_env: str = _MARKER_ENV,
) -> dict[str, object]:
    return {
        "id": "order_access",
        "method": "GET",
        "url": url,
        "owner": "alice",
        "marker_env": marker_env,
        "expect": {"alice": "allow", "bob": "deny"},
    }


def _write_plan(path: Path, case: Mapping[str, object]) -> None:
    path.write_text(
        yaml.safe_dump(
            {"schema": _PLAN_SCHEMA, "cases": [dict(case)]},
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _write_brief(
    path: Path,
    *,
    target: str = _TARGET,
    identities: Sequence[str] = ("alice", "bob"),
) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "engagement_id": "33333333-3333-4333-8333-333333333333",
                "scope": {"in_scope": [target], "out_of_scope": []},
                "roe": {"max_rps": 5},
                "objectives": ["api_security_assessment"],
                "budget": {"max_cost_usd": 1.0, "max_runtime_min": 5},
                "context": {"description": "Authorized matrix CLI test."},
                "authentication": {
                    "identities": [
                        {
                            "alias": alias,
                            "roles": ["owner", "customer"] if alias == "alice" else ["customer"],
                            "flow": {
                                "kind": "bearer",
                                "secret_refs": {
                                    "token": {
                                        "key": f"RAVAGE_{alias.upper()}_TOKEN",
                                    }
                                },
                            },
                            "health_check": {
                                "endpoint": {
                                    "url": f"{target.rstrip('/')}/health",
                                    "scope": "target",
                                },
                                "authenticated_marker": "signed-in",
                            },
                        }
                        for alias in identities
                    ]
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
