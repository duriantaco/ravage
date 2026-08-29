from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.runtime_manifest import (
    GraphRuntimeManifest,
    GraphRuntimeManifestError,
    bind_runtime_manifest,
)

if TYPE_CHECKING:
    from pathlib import Path

_SHA256_HEX_CHARS = 64


@dataclass(frozen=True)
class _Route:
    provider: str
    model: str
    ordinal: int
    base_url: str = (
        "https://route-user:route-password@models.example/v1"
        "?api-version=2026-07-01&api_key=route-secret"
    )
    api_key_env: str = "MODEL_API_KEY"
    missing_env: tuple[str, ...] = ()
    requested_tier: str = "high"
    selected_tier: str = "high"
    reasoning_effort: str = "high"
    max_output_tokens: int = 4_096
    output_token_limit_parameter: str = "max_output_tokens"  # noqa: S105
    input_cost_per_1m_tokens: float = 1.0
    output_cost_per_1m_tokens: float = 2.0
    cached_input_cost_per_1m_tokens: float = 0.25
    timeout_seconds: float = 30.0
    max_retries: int = 2
    opaque_marker: str = "must-not-persist"


@dataclass(frozen=True)
class _Endpoint:
    route: _Route


def _effective_policy(  # noqa: PLR0913 - drift dimensions are explicit test inputs.
    *,
    model_policy: str = "role-model:critic",
    runtime_profile: str = "runtime:scoped-http",
    tool_policy: str = "tools:critic",
    session_policy: str = "fresh_typed",
    allowed_tools: frozenset[str] = frozenset({"http_request"}),
    credential: str = "policy-secret-a",
) -> dict[str, object]:
    return {
        "roles": {
            "critic": {
                "model_policy_key": model_policy,
                "runtime_profile_key": runtime_profile,
                "tool_policy_key": tool_policy,
                "session_policy_key": session_policy,
            }
        },
        "tool_policies": {tool_policy: allowed_tools},
        "runtime_profiles": (runtime_profile,),
        "credentials": {"api_key": credential},
    }


def _manifest(  # noqa: PLR0913 - route identity inputs are explicit.
    *,
    model: str = "model-a",
    base_url: str = (
        "https://route-user:route-password@models.example/v1"
        "?api-version=2026-07-01&api_key=route-secret"
    ),
    api_key_env: str = "MODEL_API_KEY",
    timeout_seconds: float = 30.0,
    policy_payload: dict[str, object] | None = None,
    instructions: str = "Use the scoped HTTP runtime only.",
) -> GraphRuntimeManifest:
    return GraphRuntimeManifest.create(
        graph_id="graph-1",
        execution_mode="local",
        model_policies={
            "role-model:critic": (
                _Endpoint(
                    _Route(
                        provider="provider-a",
                        model=model,
                        ordinal=1,
                        base_url=base_url,
                        api_key_env=api_key_env,
                        timeout_seconds=timeout_seconds,
                    )
                ),
            ),
        },
        capabilities=("run_probe", "http_request", "run_probe"),
        policy_payload=(policy_payload if policy_payload is not None else _effective_policy()),
        instructions=instructions,
    )


def test_runtime_manifest_round_trips_without_credentials(tmp_path: Path) -> None:
    path = tmp_path / "runtime-policy-manifest.json"
    manifest = _manifest()

    bind_runtime_manifest(path, expected=manifest, resumed=False)

    assert GraphRuntimeManifest.load(path) == manifest
    persisted = path.read_text(encoding="utf-8")
    assert "must-not-persist" not in persisted
    assert "route-password" not in persisted
    assert "route-secret" not in persisted
    assert "MODEL_API_KEY" not in persisted
    assert "policy-secret-a" not in persisted
    assert "Use the scoped HTTP runtime only" not in persisted
    assert manifest.capabilities == ("http_request", "run_probe")
    assert len(manifest.policy_payload_digest) == _SHA256_HEX_CHARS
    assert len(manifest.instructions_digest) == _SHA256_HEX_CHARS


def test_runtime_manifest_rejects_policy_drift_on_resume(tmp_path: Path) -> None:
    path = tmp_path / "runtime-policy-manifest.json"
    bind_runtime_manifest(path, expected=_manifest(), resumed=False)

    with pytest.raises(GraphRuntimeManifestError, match="does not match"):
        bind_runtime_manifest(path, expected=_manifest(model="model-b"), resumed=True)


def test_runtime_manifest_is_required_for_resume(tmp_path: Path) -> None:
    with pytest.raises(GraphRuntimeManifestError, match="missing"):
        bind_runtime_manifest(
            tmp_path / "runtime-policy-manifest.json",
            expected=_manifest(),
            resumed=True,
        )


@pytest.mark.parametrize(
    "policy_payload",
    [
        _effective_policy(model_policy="role-model:validator"),
        _effective_policy(runtime_profile="runtime:sandboxed-process"),
        _effective_policy(tool_policy="tools:validator"),
        _effective_policy(session_policy="node_isolated"),
        _effective_policy(allowed_tools=frozenset({"http_request", "run_probe"})),
    ],
)
def test_runtime_manifest_binds_every_effective_role_policy_dimension(
    policy_payload: dict[str, object],
) -> None:
    baseline = _manifest()
    changed = _manifest(policy_payload=policy_payload)

    assert changed.policy_payload_digest != baseline.policy_payload_digest
    assert changed != baseline


def test_runtime_manifest_binds_instructions_and_route_configuration() -> None:
    baseline = _manifest()

    assert _manifest(instructions="Use a different runtime prompt.") != baseline
    assert _manifest(timeout_seconds=45.0) != baseline
    assert (
        _manifest(
            base_url=("https://models.example/v2?api-version=2026-07-01&api_key=another-secret")
        )
        != baseline
    )


def test_runtime_manifest_redacts_credential_rotation_from_policy_identity() -> None:
    baseline = _manifest()
    rotated = _manifest(
        base_url=(
            "https://other-user:other-password@models.example/v1"
            "?api-version=2026-07-01&api_key=rotated-route-secret"
        ),
        api_key_env="ROTATED_MODEL_API_KEY",
        policy_payload=_effective_policy(credential="policy-secret-b"),
    )

    assert rotated == baseline


def test_runtime_manifest_policy_digest_is_order_independent() -> None:
    first = _effective_policy(allowed_tools=frozenset({"run_probe", "http_request"}))
    second = {
        "runtime_profiles": ("runtime:scoped-http",),
        "credentials": {"api_key": "different-secret"},
        "tool_policies": {
            "tools:critic": frozenset({"http_request", "run_probe"}),
        },
        "roles": first["roles"],
    }

    assert _manifest(policy_payload=first) == _manifest(policy_payload=second)
