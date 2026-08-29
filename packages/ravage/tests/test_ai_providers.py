from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from ravage.model_core.providers import (
    load_model_registry,
    ready_model_routes,
    render_model_routes,
    resolve_model_routes,
)

if TYPE_CHECKING:
    from pathlib import Path

OPENAI_MINI_STANDARD_PRICES = (0.75, 0.075, 4.5)


def test_local_ollama_profile_is_ready_without_api_key() -> None:
    registry = load_model_registry(env={})

    routes = resolve_model_routes(
        registry,
        profile_name="local-ollama",
        tier="mid",
        env={},
    )

    assert len(routes) == 1
    assert routes[0].ready
    assert routes[0].provider == "ollama"
    assert routes[0].model == "qwen2.5-coder:14b"
    assert routes[0].base_url == "http://localhost:11434/v1"


def test_hosted_openai_profile_reports_missing_key() -> None:
    registry = load_model_registry(env={})

    routes = resolve_model_routes(
        registry,
        profile_name="hosted-openai",
        tier="high",
        env={},
    )

    assert not routes[0].ready
    assert routes[0].missing_env == ("OPENAI_API_KEY",)
    assert ready_model_routes(routes) == ()


def test_hosted_openai_low_route_has_pinned_standard_pricing() -> None:
    env = {"OPENAI_API_KEY": "test-key"}
    registry = load_model_registry(env=env)

    route = resolve_model_routes(
        registry,
        profile_name="hosted-openai",
        tier="low",
        env=env,
    )[0]

    assert route.model == "gpt-5.4-mini-2026-03-17"
    assert (
        route.input_cost_per_1m_tokens,
        route.cached_input_cost_per_1m_tokens,
        route.output_cost_per_1m_tokens,
    ) == OPENAI_MINI_STANDARD_PRICES


def test_hosted_openai_unknown_model_override_remains_unpriced() -> None:
    env = {
        "OPENAI_API_KEY": "test-key",
        "RAVAGE_OPENAI_LOW_MODEL": "custom-future-model",
    }
    registry = load_model_registry(env=env)

    route = resolve_model_routes(
        registry,
        profile_name="hosted-openai",
        tier="low",
        env=env,
    )[0]

    assert route.model == "custom-future-model"
    assert route.input_cost_per_1m_tokens is None
    assert route.cached_input_cost_per_1m_tokens is None
    assert route.output_cost_per_1m_tokens is None


def test_hosted_openai_known_alias_override_uses_standard_pricing() -> None:
    env = {
        "OPENAI_API_KEY": "test-key",
        "RAVAGE_OPENAI_LOW_MODEL": "gpt-5.4-mini",
    }
    registry = load_model_registry(env=env)

    route = resolve_model_routes(
        registry,
        profile_name="hosted-openai",
        tier="low",
        env=env,
    )[0]

    assert (
        route.input_cost_per_1m_tokens,
        route.cached_input_cost_per_1m_tokens,
        route.output_cost_per_1m_tokens,
    ) == OPENAI_MINI_STANDARD_PRICES


def test_hosted_anthropic_profile_uses_native_api_key() -> None:
    registry = load_model_registry(env={"ANTHROPIC_API_KEY": "sk-ant-test"})

    routes = resolve_model_routes(
        registry,
        profile_name="hosted-anthropic",
        tier="low",
        env={"ANTHROPIC_API_KEY": "sk-ant-test"},
    )

    assert len(routes) == 1
    assert routes[0].ready
    assert routes[0].provider == "anthropic"
    assert routes[0].model == "claude-haiku-4-5"
    assert routes[0].base_url == "https://api.anthropic.com"
    assert routes[0].api_key_env == "ANTHROPIC_API_KEY"


def test_env_templates_override_model_and_base_url(tmp_path: Path) -> None:
    config_path = tmp_path / "models.yaml"
    config_path.write_text(
        """
profiles:
  local:
    default_tier: mid
    routes:
      mid:
        - provider: custom_openai
          model: ${CUSTOM_MODEL}
          base_url: ${CUSTOM_BASE_URL:http://127.0.0.1:9999/v1}
          api_key_required: false
""".lstrip(),
        encoding="utf-8",
    )

    registry = load_model_registry(
        config_path,
        env={"CUSTOM_MODEL": "my-local-model"},
    )
    routes = resolve_model_routes(
        registry,
        profile_name="local",
        tier="mid",
        env={},
    )

    assert routes[0].model == "my-local-model"
    assert routes[0].base_url == "http://127.0.0.1:9999/v1"
    assert routes[0].ready


def test_fallback_order_preserves_missing_then_ready_route() -> None:
    registry = load_model_registry(env={})

    routes = resolve_model_routes(
        registry,
        profile_name="mixed-fallback",
        tier="high",
        env={},
    )

    assert [route.provider for route in routes] == ["openai", "ollama"]
    assert [route.ready for route in routes] == [False, True]
    assert [route.provider for route in ready_model_routes(routes)] == ["ollama"]


def test_render_model_routes_is_human_readable() -> None:
    registry = load_model_registry(env={})

    lines = render_model_routes(
        registry,
        profile_name="mixed-fallback",
        tier="high",
        env={},
    )

    assert lines[0] == (
        "[models] profile=mixed-fallback requested_tier=high selected_tier=high routes=2 ready=1"
    )
    assert "provider=openai" in lines[1]
    assert "missing_env=OPENAI_API_KEY" in lines[1]
    assert "provider=ollama" in lines[2]
    assert "ready=true" in lines[2]


def test_unknown_model_profile_lists_available_profiles() -> None:
    registry = load_model_registry(env={})

    with pytest.raises(ValueError, match="unknown model profile"):
        resolve_model_routes(
            registry,
            profile_name="missing",
            tier="mid",
            env={},
        )
