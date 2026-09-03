from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from ravage.model_core.providers import (
    ModelTier,
    ProviderKind,
    load_model_registry,
    ready_model_routes,
    render_model_routes,
    resolve_model_routes,
    route_is_nonbillable_local,
)

if TYPE_CHECKING:
    from pathlib import Path

OPENAI_MINI_STANDARD_PRICES = (0.75, 0.075, 4.5)
GPT_5_4_HIGH_OUTPUT_TOKENS = 16_384
ANTHROPIC_STANDARD_ROUTES = (
    ("high", "claude-opus-4-7", (5.0, 0.5, 25.0)),
    ("mid", "claude-sonnet-4-6", (3.0, 0.3, 15.0)),
    ("low", "claude-haiku-4-5-20251001", (1.0, 0.1, 5.0)),
)
ABLITERATION_STANDARD_ROUTES = (
    ("high", "abliterated-model-large-v2", (5.0, 0.5, 5.0)),
    ("mid", "abliterated-model-large", (5.0, 0.5, 5.0)),
    ("low", "abliterated-model", (3.0, 0.3, 3.0)),
)
UNSUPPORTED_DIRECT_PROVIDERS: tuple[ProviderKind, ...] = (
    "gemini",
    "openrouter",
    "azure",
    "bedrock",
    "vertex",
    "groq",
    "together",
    "fireworks",
    "mistral",
    "deepseek",
)


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
    assert route_is_nonbillable_local(routes[0])


def test_remote_endpoint_under_local_provider_label_requires_pricing() -> None:
    env = {"OLLAMA_BASE_URL": "https://paid-model.example/v1"}
    registry = load_model_registry(env=env)

    route = resolve_model_routes(
        registry,
        profile_name="local-ollama",
        tier="mid",
        env=env,
    )[0]

    assert route.base_url == "https://paid-model.example/v1"
    assert not route_is_nonbillable_local(route)
    assert route.missing_pricing == (
        "input_cost_per_1m_tokens",
        "cached_input_cost_per_1m_tokens",
        "output_cost_per_1m_tokens",
    )
    assert not route.ready


def test_credentialed_loopback_route_requires_pricing(tmp_path: Path) -> None:
    config_path = tmp_path / "models.yaml"
    config_path.write_text(
        """
profiles:
  credentialed-local:
    routes:
      mid:
        - provider: ollama
          model: private-local-model
          base_url: http://127.0.0.1:11434/v1
          api_key_env: LOCAL_MODEL_API_KEY
""".lstrip(),
        encoding="utf-8",
    )
    env = {"LOCAL_MODEL_API_KEY": "test-key"}
    registry = load_model_registry(config_path, env=env)

    route = resolve_model_routes(
        registry,
        profile_name="credentialed-local",
        tier="mid",
        env=env,
    )[0]

    assert not route_is_nonbillable_local(route)
    assert route.missing_pricing
    assert not route.ready


def test_required_credential_without_environment_variable_is_invalid(tmp_path: Path) -> None:
    config_path = tmp_path / "models.yaml"
    config_path.write_text(
        """
profiles:
  invalid-local:
    routes:
      mid:
        - provider: ollama
          model: private-local-model
          base_url: http://127.0.0.1:11434/v1
          api_key_required: true
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="api_key_env is required when api_key_required is true",
    ):
        load_model_registry(config_path, env={})


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


def test_hosted_openai_gpt_5_4_high_profile_is_pinned_and_accountable() -> None:
    env = {"OPENAI_API_KEY": "test-key"}
    registry = load_model_registry(env=env)

    route = resolve_model_routes(
        registry,
        profile_name="hosted-openai-gpt-5.4-high",
        tier="high",
        env=env,
    )[0]

    assert route.ready
    assert route.model == "gpt-5.4-2026-03-05"
    assert route.reasoning_effort == "high"
    assert route.max_output_tokens == GPT_5_4_HIGH_OUTPUT_TOKENS
    assert (
        route.input_cost_per_1m_tokens,
        route.cached_input_cost_per_1m_tokens,
        route.output_cost_per_1m_tokens,
    ) == (2.5, 0.25, 15.0)


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
    assert route.missing_pricing == (
        "input_cost_per_1m_tokens",
        "cached_input_cost_per_1m_tokens",
        "output_cost_per_1m_tokens",
    )
    assert not route.ready
    assert ready_model_routes((route,)) == ()


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


@pytest.mark.parametrize(("tier", "model", "prices"), ANTHROPIC_STANDARD_ROUTES)
def test_hosted_anthropic_profile_has_pinned_accountable_pricing(
    tier: ModelTier,
    model: str,
    prices: tuple[float, float, float],
) -> None:
    env = {"ANTHROPIC_API_KEY": "sk-ant-test"}
    registry = load_model_registry(env=env)

    routes = resolve_model_routes(
        registry,
        profile_name="hosted-anthropic",
        tier=tier,
        env=env,
    )

    assert len(routes) == 1
    assert routes[0].ready
    assert routes[0].provider == "anthropic"
    assert routes[0].model == model
    assert routes[0].base_url == "https://api.anthropic.com"
    assert routes[0].api_key_env == "ANTHROPIC_API_KEY"
    assert (
        routes[0].input_cost_per_1m_tokens,
        routes[0].cached_input_cost_per_1m_tokens,
        routes[0].output_cost_per_1m_tokens,
    ) == prices


def test_hosted_anthropic_unknown_override_is_not_ready_for_paid_call() -> None:
    env = {
        "ANTHROPIC_API_KEY": "sk-ant-test",
        "RAVAGE_ANTHROPIC_LOW_MODEL": "claude-future-unknown",
    }
    registry = load_model_registry(env=env)

    route = resolve_model_routes(
        registry,
        profile_name="hosted-anthropic",
        tier="low",
        env=env,
    )[0]

    assert not route.ready
    assert route.missing_env == ()
    assert route.missing_pricing


@pytest.mark.parametrize(("tier", "model", "prices"), ABLITERATION_STANDARD_ROUTES)
def test_hosted_abliteration_profile_has_accountable_pricing(
    tier: ModelTier,
    model: str,
    prices: tuple[float, float, float],
) -> None:
    env = {"ABLIT_KEY": "ak-test"}
    registry = load_model_registry(env=env)

    route = resolve_model_routes(
        registry,
        profile_name="hosted-abliteration",
        tier=tier,
        env=env,
    )[0]

    assert route.ready
    assert route.provider == "abliteration"
    assert route.model == model
    assert route.base_url == "https://api.abliteration.ai/v1"
    assert route.api_key_env == "ABLIT_KEY"
    assert (
        route.input_cost_per_1m_tokens,
        route.cached_input_cost_per_1m_tokens,
        route.output_cost_per_1m_tokens,
    ) == prices


def test_hosted_abliteration_unknown_override_is_not_ready_for_paid_call() -> None:
    env = {
        "ABLIT_KEY": "ak-test",
        "RAVAGE_ABLITERATION_LOW_MODEL": "future-abliterated-model",
    }
    registry = load_model_registry(env=env)

    route = resolve_model_routes(
        registry,
        profile_name="hosted-abliteration",
        tier="low",
        env=env,
    )[0]

    assert not route.ready
    assert route.missing_env == ()
    assert route.missing_pricing


def test_universal_litellm_requires_explicit_pricing_before_it_is_ready() -> None:
    registry = load_model_registry(env={})

    route = resolve_model_routes(
        registry,
        profile_name="universal-litellm",
        tier="mid",
        env={},
    )[0]

    assert route.base_url == "http://localhost:4000/v1"
    assert not route_is_nonbillable_local(route)
    assert not route.ready
    assert route.missing_pricing == (
        "input_cost_per_1m_tokens",
        "cached_input_cost_per_1m_tokens",
        "output_cost_per_1m_tokens",
    )
    lines = render_model_routes(
        registry,
        profile_name="universal-litellm",
        tier="mid",
        env={},
    )
    assert "ready=false" in lines[1]
    assert (
        "missing_pricing=input_cost_per_1m_tokens,"
        "cached_input_cost_per_1m_tokens,output_cost_per_1m_tokens"
    ) in lines[1]


def test_remote_custom_route_requires_all_explicit_prices(tmp_path: Path) -> None:
    config_path = tmp_path / "models.yaml"
    config_path.write_text(
        """
profiles:
  remote:
    routes:
      mid:
        - provider: custom_openai
          model: custom-paid-model
          base_url: https://model.example/v1
          api_key_required: false
          input_cost_per_1m_tokens: 1.0
          output_cost_per_1m_tokens: 2.0
""".lstrip(),
        encoding="utf-8",
    )
    registry = load_model_registry(config_path, env={})

    route = resolve_model_routes(
        registry,
        profile_name="remote",
        tier="mid",
        env={},
    )[0]

    assert not route.ready
    assert not route_is_nonbillable_local(route)
    assert route.missing_pricing == ("cached_input_cost_per_1m_tokens",)


def test_remote_custom_route_is_ready_with_explicit_cache_aware_prices(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "models.yaml"
    config_path.write_text(
        """
profiles:
  remote:
    routes:
      mid:
        - provider: custom_openai
          model: custom-paid-model
          base_url: https://model.example/v1
          api_key_required: false
          input_cost_per_1m_tokens: 1.0
          cached_input_cost_per_1m_tokens: 1.0
          output_cost_per_1m_tokens: 2.0
""".lstrip(),
        encoding="utf-8",
    )
    registry = load_model_registry(config_path, env={})

    route = resolve_model_routes(
        registry,
        profile_name="remote",
        tier="mid",
        env={},
    )[0]

    assert route.ready
    assert route.missing_pricing == ()


@pytest.mark.parametrize("provider", UNSUPPORTED_DIRECT_PROVIDERS)
def test_schema_only_provider_kind_cannot_become_directly_ready(
    tmp_path: Path,
    provider: ProviderKind,
) -> None:
    config_path = tmp_path / "models.yaml"
    config_path.write_text(
        f"""
profiles:
  unsupported:
    routes:
      mid:
        - provider: {provider}
          model: provider-model
          base_url: https://provider.example/v1
          api_key_required: false
          input_cost_per_1m_tokens: 1.0
          cached_input_cost_per_1m_tokens: 1.0
          output_cost_per_1m_tokens: 2.0
""".lstrip(),
        encoding="utf-8",
    )
    registry = load_model_registry(config_path, env={})

    route = resolve_model_routes(
        registry,
        profile_name="unsupported",
        tier="mid",
        env={},
    )[0]

    assert route.missing_env == ()
    assert route.missing_pricing == ()
    assert route.transport_issue == "unsupported_direct_provider"
    assert not route.ready
    lines = render_model_routes(
        registry,
        profile_name="unsupported",
        tier="mid",
        env={},
    )
    assert "transport_issue=unsupported_direct_provider" in lines[1]


@pytest.mark.parametrize(
    ("provider", "base_url", "issue"),
    [
        ("custom_openai", None, "custom_openai_base_url_required"),
        ("openai", "https://gateway.example/v1", "openai_native_base_url_required"),
        (
            "anthropic",
            "https://gateway.example",
            "anthropic_native_base_url_required",
        ),
        (
            "abliteration",
            "https://gateway.example/v1",
            "abliteration_native_base_url_required",
        ),
    ],
)
def test_direct_transport_rejects_ambiguous_gateway_configuration(
    tmp_path: Path,
    provider: ProviderKind,
    base_url: str | None,
    issue: str,
) -> None:
    base_url_line = f"          base_url: {base_url}\n" if base_url is not None else ""
    config_path = tmp_path / "models.yaml"
    config_path.write_text(
        (
            f"""
profiles:
  ambiguous:
    routes:
      mid:
        - provider: {provider}
          model: provider-model
{base_url_line}          api_key_required: false
          input_cost_per_1m_tokens: 1.0
          cached_input_cost_per_1m_tokens: 1.0
          output_cost_per_1m_tokens: 2.0
""".lstrip()
        ),
        encoding="utf-8",
    )
    registry = load_model_registry(config_path, env={})

    route = resolve_model_routes(
        registry,
        profile_name="ambiguous",
        tier="mid",
        env={},
    )[0]

    assert route.transport_issue == issue
    assert not route.ready


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
          input_cost_per_1m_tokens: 0.0
          cached_input_cost_per_1m_tokens: 0.0
          output_cost_per_1m_tokens: 0.0
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


def test_loopback_custom_gateway_still_requires_explicit_pricing(tmp_path: Path) -> None:
    config_path = tmp_path / "models.yaml"
    config_path.write_text(
        """
profiles:
  local-gateway:
    routes:
      mid:
        - provider: custom_openai
          model: unknown-upstream
          base_url: http://127.0.0.1:9999/v1
          api_key_required: false
""".lstrip(),
        encoding="utf-8",
    )

    route = resolve_model_routes(
        load_model_registry(config_path, env={}),
        profile_name="local-gateway",
        tier="mid",
        env={},
    )[0]

    assert not route_is_nonbillable_local(route)
    assert not route.ready
    assert route.missing_pricing == (
        "input_cost_per_1m_tokens",
        "cached_input_cost_per_1m_tokens",
        "output_cost_per_1m_tokens",
    )


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
