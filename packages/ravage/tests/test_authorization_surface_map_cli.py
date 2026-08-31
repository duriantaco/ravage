# ruff: noqa: PLR2004
from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

import pytest
import yaml
from ravage import __main__ as cli
from ravage.agent_core.surface_graph import SurfaceGraphState, SurfaceParameter
from ravage.auth.authorization_matrix import TrafficSnapshotDelta
from ravage.auth.authorization_surface_map import (
    AuthorizationSurfaceActorResult,
    AuthorizationSurfaceCandidate,
    AuthorizationSurfaceMapResult,
)
from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicyController, TrafficPolicyMode

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


_TARGET = "http://127.0.0.1:18759/"
_ARGPARSE_ERROR = 2
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600


@dataclass
class _FakeManagedRuntime:
    close_calls: int = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close_calls += 1


def test_auth_surface_map_help_explains_bounds_and_candidate_semantics(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["auth", "map", "--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "usage: ravage auth map" in output
    assert "--identity" in output
    assert "--include-anonymous" in output
    assert "--max-urls" in output
    assert "--max-physical-requests" in output
    assert "--traffic-max-rps" in output
    assert "--authorized-remote-target" in output
    assert "not confirmed vulnerabilities" in output


def test_remote_surface_map_fails_before_runtime_without_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    _write_brief(brief, target="https://surface.example.test/")

    def unexpected_build(**_kwargs: object) -> None:
        pytest.fail("remote refusal must happen before runtime construction")

    monkeypatch.setattr(cli, "build_managed_authorization_matrix", unexpected_build)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["auth", "map", str(brief)])

    assert exc_info.value.code == _ARGPARSE_ERROR
    assert "remote targets require --authorized-remote-target" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_unknown_or_single_identity_fails_before_creating_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "surface-run"
    _write_brief(brief)

    with pytest.raises(SystemExit) as single:
        cli.main(
            [
                "auth",
                "map",
                str(brief),
                "--identity",
                "alice",
                "--run-dir",
                str(run_dir),
            ]
        )
    assert single.value.code == _ARGPARSE_ERROR
    assert "requires at least two" in capsys.readouterr().err
    assert not run_dir.exists()

    with pytest.raises(SystemExit) as unknown:
        cli.main(
            [
                "auth",
                "map",
                str(brief),
                "--identity",
                "alice",
                "--identity",
                "mallory",
                "--run-dir",
                str(run_dir),
            ]
        )
    assert unknown.value.code == _ARGPARSE_ERROR
    assert "unknown configured identity" in capsys.readouterr().err
    assert not run_dir.exists()


def test_complete_surface_map_writes_private_sanitized_candidate_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "surface-run"
    _write_brief(brief)
    result = _result(complete=True)
    capture = _install_fakes(monkeypatch, result)

    cli.main(
        [
            "auth",
            "map",
            str(brief),
            "--identity",
            "bob",
            "--identity",
            "alice",
            "--include-anonymous",
            "--run-dir",
            str(run_dir),
            "--max-urls",
            "5",
            "--max-physical-requests",
            "37",
            "--traffic-max-rps",
            "0.25",
        ]
    )

    output = capsys.readouterr().out
    receipt_path = run_dir / "authorization-surface-map.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    kwargs = capture["builder_kwargs"]
    policy = capture["policy"]
    runtime = capture["runtime"]
    run_kwargs = capture["run_kwargs"]
    assert isinstance(kwargs, dict)
    assert isinstance(policy, TrafficPolicyController)
    assert isinstance(runtime, _FakeManagedRuntime)
    assert isinstance(run_kwargs, dict)
    assert kwargs["identities"] == ("alice", "bob")
    assert kwargs["traffic_policy"] is policy
    assert run_kwargs["include_anonymous"] is True
    assert run_kwargs["max_urls"] == 5
    assert policy.config.mode is TrafficPolicyMode.ENFORCE
    assert policy.config.max_physical_requests == 37
    assert policy.config.max_rps == 0.25
    assert runtime.close_calls == 1
    assert receipt == result.to_json()
    assert receipt["complete"] is True
    assert receipt["candidates"][0]["review_ready"] is True
    assert stat.S_IMODE(run_dir.stat().st_mode) == _DIRECTORY_MODE
    assert stat.S_IMODE(receipt_path.stat().st_mode) == _FILE_MODE
    assert "AUTH SURFACE MAP" in output
    assert "Candidates are not vulnerabilities" in output
    assert "ravage auth matrix" in output
    assert "483920" not in json.dumps(receipt)
    assert "query-secret-value" not in json.dumps(receipt)


def test_incomplete_json_receipt_is_written_then_exits_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "surface-run"
    _write_brief(brief)
    result = _result(complete=False)
    _install_fakes(monkeypatch, result)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "auth",
                "map",
                str(brief),
                "--run-dir",
                str(run_dir),
                "--json",
            ]
        )

    assert exc_info.value.code == 1
    stdout = json.loads(capsys.readouterr().out)
    receipt = json.loads((run_dir / "authorization-surface-map.json").read_text(encoding="utf-8"))
    assert stdout == receipt == result.to_json()
    assert receipt["complete"] is False
    assert receipt["candidates"][0]["review_ready"] is False


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    result: AuthorizationSurfaceMapResult,
) -> dict[str, object]:
    capture: dict[str, object] = {}

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
            )
            capture["policy"] = policy
            return policy

    def fake_build(**kwargs: object) -> _FakeManagedRuntime:
        runtime = _FakeManagedRuntime()
        capture["builder_kwargs"] = dict(kwargs)
        capture["runtime"] = runtime
        return runtime

    def fake_run(
        target_url: str,
        *,
        runtime: object,
        **kwargs: object,
    ) -> AuthorizationSurfaceMapResult:
        capture["run_target"] = target_url
        capture["run_runtime"] = runtime
        capture["run_kwargs"] = dict(kwargs)
        return result

    monkeypatch.setattr(cli, "TrafficPolicyController", PolicyFactory)
    monkeypatch.setattr(cli, "build_managed_authorization_matrix", fake_build)
    monkeypatch.setattr(cli, "run_authorization_surface_map", fake_run)
    return capture


def _result(*, complete: bool) -> AuthorizationSurfaceMapResult:
    graph = SurfaceGraphState.for_target(_TARGET)
    operation = graph.add(
        url=f"{_TARGET}accounts/483920?token=query-secret-value",
        method="GET",
        parameters=(SurfaceParameter.create(name="token", location="query"),),
        source_kind="native_recon",
        identity_alias="alice",
        access_level="declared",
        scope_decision="allowed",
        replayability="not_replayable",
    )
    candidate = AuthorizationSurfaceCandidate(
        candidate_id="asm_0123456789abcdef01234567",
        operation_id=operation.operation_id,
        method="GET",
        route_shape=operation.route_shape,
        parameters=operation.parameters,
        discovered_by=("alice",),
        not_discovered_by=("bob",),
        actor_evidence=(),
        reason_codes=("identity_visibility_difference",),
        review_ready=complete,
    )
    zero = TrafficSnapshotDelta(
        physical_request_count=0,
        completed_request_count=0,
        incomplete_request_count=0,
        pending_dispatch_count=0,
        reservation_count=0,
        cache_hit_count=0,
        deduplicated_count=0,
        retry_count=0,
        blocked_count=0,
        circuit_open_count=0,
        unmetered_action_count=0,
        initial_accounting_status="exact",
        current_accounting_status="exact",
    )
    return AuthorizationSurfaceMapResult(
        complete=complete,
        coverage_limited=False,
        reason_codes=() if complete else ("traffic_policy_blocked",),
        coverage_reason_codes=(),
        actors=(
            AuthorizationSurfaceActorResult(
                actor="alice",
                roles=("owner",),
                mapped_url_count=1,
                observation_count=2,
                success_count=2,
                denied_count=0,
                redirect_count=0,
                inconclusive_count=0,
                complete=complete,
            ),
            AuthorizationSurfaceActorResult(
                actor="bob",
                roles=("customer",),
                mapped_url_count=1,
                observation_count=2,
                success_count=0,
                denied_count=2,
                redirect_count=0,
                inconclusive_count=0,
                complete=complete,
            ),
        ),
        candidates=(candidate,),
        surface_graph=graph,
        traffic_delta=zero,
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
                "engagement_id": "44444444-4444-4444-8444-444444444444",
                "scope": {"in_scope": [target], "out_of_scope": []},
                "roe": {"max_rps": 5},
                "objectives": ["api_security_assessment"],
                "budget": {"max_cost_usd": 1.0, "max_runtime_min": 5},
                "context": {"description": "Authorized role-aware surface test."},
                "authentication": {
                    "identities": [
                        {
                            "alias": alias,
                            "roles": ["owner"] if alias == "alice" else ["customer"],
                            "flow": {
                                "kind": "bearer",
                                "secret_refs": {"token": {"key": f"TOKEN_{alias.upper()}"}},
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
