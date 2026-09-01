from __future__ import annotations

import os
import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlparse

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

type ModelTier = Literal["high", "mid", "low"]
type ProviderKind = Literal[
    "openai",
    "anthropic",
    "gemini",
    "openrouter",
    "litellm",
    "ollama",
    "lmstudio",
    "llamacpp",
    "vllm",
    "custom_openai",
    "azure",
    "bedrock",
    "vertex",
    "groq",
    "together",
    "fireworks",
    "mistral",
    "deepseek",
]
type ReasoningEffort = Literal["low", "medium", "high", "xhigh"]
type OutputTokenLimitParameter = Literal["max_completion_tokens", "max_tokens", "none"]
DEFAULT_OUTPUT_TOKEN_LIMIT_PARAMETER: OutputTokenLimitParameter = "max_tokens"  # noqa: S105

LOCAL_PROVIDERS: frozenset[ProviderKind] = frozenset({"ollama", "lmstudio", "llamacpp", "vllm"})
DEFAULT_API_KEY_ENV: dict[ProviderKind, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GOOGLE_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "azure": "AZURE_OPENAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "together": "TOGETHER_API_KEY",
    "fireworks": "FIREWORKS_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}
DEFAULT_BASE_URL: dict[ProviderKind, str] = {
    "anthropic": "https://api.anthropic.com",
    "ollama": "http://localhost:11434/v1",
    "lmstudio": "http://localhost:1234/v1",
    "llamacpp": "http://localhost:8080/v1",
    "vllm": "http://localhost:8000/v1",
    "litellm": "http://localhost:4000/v1",
}
OPENAI_NATIVE_BASE_URL = "https://api.openai.com/v1"
ANTHROPIC_NATIVE_BASE_URL = "https://api.anthropic.com"
DIRECT_CHAT_PROVIDERS: frozenset[ProviderKind] = frozenset(
    {
        "openai",
        "anthropic",
        "litellm",
        "custom_openai",
        *LOCAL_PROVIDERS,
    }
)
TIER_ORDER: tuple[ModelTier, ...] = ("high", "mid", "low")
ENV_TEMPLATE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class TokenPrices:
    input_per_1m: float
    cached_input_per_1m: float
    output_per_1m: float


# OpenAI Standard pricing per 1M tokens, verified 2026-08-15.
# https://developers.openai.com/api/docs/pricing
OPENAI_STANDARD_TOKEN_PRICES: dict[str, TokenPrices] = {
    "gpt-5.4": TokenPrices(2.5, 0.25, 15.0),
    "gpt-5.4-2026-03-05": TokenPrices(2.5, 0.25, 15.0),
    "gpt-5.4-mini": TokenPrices(0.75, 0.075, 4.5),
    "gpt-5.4-mini-2026-03-17": TokenPrices(0.75, 0.075, 4.5),
}
OPENAI_LONG_CONTEXT_THRESHOLD_TOKENS = 272_000
OPENAI_STANDARD_LONG_CONTEXT_TOKEN_PRICES: dict[str, TokenPrices] = {
    "gpt-5.4": TokenPrices(5.0, 0.5, 22.5),
    "gpt-5.4-2026-03-05": TokenPrices(5.0, 0.5, 22.5),
}


def openai_standard_token_prices(
    model: str,
    *,
    input_tokens: int = 0,
) -> TokenPrices | None:
    if input_tokens > OPENAI_LONG_CONTEXT_THRESHOLD_TOKENS:
        long_context = OPENAI_STANDARD_LONG_CONTEXT_TOKEN_PRICES.get(model)
        if long_context is not None:
            return long_context
    return OPENAI_STANDARD_TOKEN_PRICES.get(model)


# Claude API Standard pricing per 1M tokens, verified 2026-08-30.
# https://platform.claude.com/docs/en/about-claude/pricing
# https://platform.claude.com/docs/en/about-claude/model-deprecations
# https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions
ANTHROPIC_STANDARD_TOKEN_PRICES: dict[str, TokenPrices] = {
    "claude-opus-4-7": TokenPrices(5.0, 0.5, 25.0),
    "claude-sonnet-4-6": TokenPrices(3.0, 0.3, 15.0),
    "claude-haiku-4-5": TokenPrices(1.0, 0.1, 5.0),
    "claude-haiku-4-5-20251001": TokenPrices(1.0, 0.1, 5.0),
}


def anthropic_standard_token_prices(model: str) -> TokenPrices | None:
    return ANTHROPIC_STANDARD_TOKEN_PRICES.get(model)


DEFAULT_MODEL_CONFIG: dict[str, object] = {
    "profiles": {
        "local-ollama": {
            "default_tier": "mid",
            "routes": {
                "high": [
                    {
                        "provider": "ollama",
                        "model": "${RAVAGE_OLLAMA_MODEL:qwen2.5-coder:32b}",
                        "base_url": "${OLLAMA_BASE_URL:http://localhost:11434/v1}",
                        "api_key_required": False,
                    }
                ],
                "mid": [
                    {
                        "provider": "ollama",
                        "model": "${RAVAGE_OLLAMA_MODEL:qwen2.5-coder:14b}",
                        "base_url": "${OLLAMA_BASE_URL:http://localhost:11434/v1}",
                        "api_key_required": False,
                    }
                ],
                "low": [
                    {
                        "provider": "ollama",
                        "model": "${RAVAGE_OLLAMA_MODEL:qwen2.5-coder:7b}",
                        "base_url": "${OLLAMA_BASE_URL:http://localhost:11434/v1}",
                        "api_key_required": False,
                    }
                ],
            },
        },
        "local-lmstudio": {
            "default_tier": "mid",
            "routes": {
                "high": [
                    {
                        "provider": "lmstudio",
                        "model": "${RAVAGE_LMSTUDIO_MODEL:local-model}",
                        "base_url": "${LMSTUDIO_BASE_URL:http://localhost:1234/v1}",
                        "api_key_required": False,
                    }
                ],
                "mid": [
                    {
                        "provider": "lmstudio",
                        "model": "${RAVAGE_LMSTUDIO_MODEL:local-model}",
                        "base_url": "${LMSTUDIO_BASE_URL:http://localhost:1234/v1}",
                        "api_key_required": False,
                    }
                ],
                "low": [
                    {
                        "provider": "lmstudio",
                        "model": "${RAVAGE_LMSTUDIO_MODEL:local-model}",
                        "base_url": "${LMSTUDIO_BASE_URL:http://localhost:1234/v1}",
                        "api_key_required": False,
                    }
                ],
            },
        },
        "local-vllm": {
            "default_tier": "mid",
            "routes": {
                "high": [
                    {
                        "provider": "vllm",
                        "model": "${RAVAGE_VLLM_MODEL:local-model}",
                        "base_url": "${VLLM_BASE_URL:http://localhost:8000/v1}",
                        "api_key_required": False,
                    }
                ],
                "mid": [
                    {
                        "provider": "vllm",
                        "model": "${RAVAGE_VLLM_MODEL:local-model}",
                        "base_url": "${VLLM_BASE_URL:http://localhost:8000/v1}",
                        "api_key_required": False,
                    }
                ],
                "low": [
                    {
                        "provider": "vllm",
                        "model": "${RAVAGE_VLLM_MODEL:local-model}",
                        "base_url": "${VLLM_BASE_URL:http://localhost:8000/v1}",
                        "api_key_required": False,
                    }
                ],
            },
        },
        "universal-litellm": {
            "default_tier": "mid",
            "routes": {
                "high": [
                    {
                        "provider": "litellm",
                        "model": "${RAVAGE_LITELLM_HIGH_MODEL:openai/gpt-5.4}",
                        "base_url": "${LITELLM_BASE_URL:http://localhost:4000/v1}",
                        "api_key_required": False,
                    }
                ],
                "mid": [
                    {
                        "provider": "litellm",
                        "model": "${RAVAGE_LITELLM_MID_MODEL:openai/gpt-5.4}",
                        "base_url": "${LITELLM_BASE_URL:http://localhost:4000/v1}",
                        "api_key_required": False,
                    }
                ],
                "low": [
                    {
                        "provider": "litellm",
                        "model": "${RAVAGE_LITELLM_LOW_MODEL:openai/gpt-5.4-mini}",
                        "base_url": "${LITELLM_BASE_URL:http://localhost:4000/v1}",
                        "api_key_required": False,
                    }
                ],
            },
        },
        "hosted-openai": {
            "default_tier": "mid",
            "routes": {
                "high": [
                    {
                        "provider": "openai",
                        "model": "${RAVAGE_OPENAI_HIGH_MODEL:gpt-5.4-2026-03-05}",
                        "api_key_env": "OPENAI_API_KEY",
                        "max_output_tokens": 4096,
                        "output_token_limit_parameter": "max_completion_tokens",
                    }
                ],
                "mid": [
                    {
                        "provider": "openai",
                        "model": "${RAVAGE_OPENAI_MID_MODEL:gpt-5.4-2026-03-05}",
                        "api_key_env": "OPENAI_API_KEY",
                        "max_output_tokens": 4096,
                        "output_token_limit_parameter": "max_completion_tokens",
                    }
                ],
                "low": [
                    {
                        "provider": "openai",
                        "model": "${RAVAGE_OPENAI_LOW_MODEL:gpt-5.4-mini-2026-03-17}",
                        "api_key_env": "OPENAI_API_KEY",
                        "max_output_tokens": 4096,
                        "output_token_limit_parameter": "max_completion_tokens",
                    }
                ],
            },
        },
        "hosted-openai-gpt-5.4-high": {
            "default_tier": "high",
            "routes": {
                "high": [
                    {
                        "provider": "openai",
                        "model": "gpt-5.4-2026-03-05",
                        "api_key_env": "OPENAI_API_KEY",
                        "reasoning_effort": "high",
                        "max_output_tokens": 16384,
                        "output_token_limit_parameter": "max_completion_tokens",
                    }
                ],
            },
        },
        "hosted-anthropic": {
            "default_tier": "mid",
            "routes": {
                "high": [
                    {
                        "provider": "anthropic",
                        "model": "${RAVAGE_ANTHROPIC_HIGH_MODEL:claude-opus-4-7}",
                        "api_key_env": "ANTHROPIC_API_KEY",
                        "max_output_tokens": 4096,
                    }
                ],
                "mid": [
                    {
                        "provider": "anthropic",
                        "model": "${RAVAGE_ANTHROPIC_MID_MODEL:claude-sonnet-4-6}",
                        "api_key_env": "ANTHROPIC_API_KEY",
                        "max_output_tokens": 4096,
                    }
                ],
                "low": [
                    {
                        "provider": "anthropic",
                        "model": (
                            "${RAVAGE_ANTHROPIC_LOW_MODEL:"
                            "claude-haiku-4-5-20251001}"
                        ),
                        "api_key_env": "ANTHROPIC_API_KEY",
                        "max_output_tokens": 4096,
                    }
                ],
            },
        },
        "mixed-fallback": {
            "default_tier": "mid",
            "routes": {
                "high": [
                    {
                        "provider": "openai",
                        "model": "${RAVAGE_OPENAI_HIGH_MODEL:gpt-5.4}",
                        "api_key_env": "OPENAI_API_KEY",
                        "max_output_tokens": 4096,
                        "output_token_limit_parameter": "max_completion_tokens",
                    },
                    {
                        "provider": "ollama",
                        "model": "${RAVAGE_OLLAMA_MODEL:qwen2.5-coder:32b}",
                        "base_url": "${OLLAMA_BASE_URL:http://localhost:11434/v1}",
                        "api_key_required": False,
                    },
                ],
                "mid": [
                    {
                        "provider": "litellm",
                        "model": "${RAVAGE_LITELLM_MID_MODEL:openai/gpt-5.4}",
                        "base_url": "${LITELLM_BASE_URL:http://localhost:4000/v1}",
                        "api_key_required": False,
                    },
                    {
                        "provider": "ollama",
                        "model": "${RAVAGE_OLLAMA_MODEL:qwen2.5-coder:14b}",
                        "base_url": "${OLLAMA_BASE_URL:http://localhost:11434/v1}",
                        "api_key_required": False,
                    },
                ],
                "low": [
                    {
                        "provider": "ollama",
                        "model": "${RAVAGE_OLLAMA_MODEL:qwen2.5-coder:7b}",
                        "base_url": "${OLLAMA_BASE_URL:http://localhost:11434/v1}",
                        "api_key_required": False,
                    }
                ],
            },
        },
    }
}


class ModelRoute(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True)

    provider: ProviderKind
    model: str = Field(min_length=1)
    base_url: str | None = None
    api_key_env: str | None = None
    required_env: list[str] = Field(default_factory=list)
    api_key_required: bool | None = None
    reasoning_effort: ReasoningEffort | None = None
    max_output_tokens: int = Field(default=1024, gt=0)
    output_token_limit_parameter: OutputTokenLimitParameter = DEFAULT_OUTPUT_TOKEN_LIMIT_PARAMETER
    input_cost_per_1m_tokens: float | None = Field(default=None, ge=0)
    cached_input_cost_per_1m_tokens: float | None = Field(default=None, ge=0)
    output_cost_per_1m_tokens: float | None = Field(default=None, ge=0)
    timeout_seconds: float = Field(default=120.0, gt=0)
    max_retries: int = Field(default=2, ge=0)
    notes: str | None = None

    @field_validator("model", "base_url", "api_key_env", "notes")
    @classmethod
    def _strip_non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            message = "value must not be empty"
            raise ValueError(message)
        return stripped

    @field_validator("api_key_env")
    @classmethod
    def _validate_api_key_env(cls, value: str | None) -> str | None:
        if value is not None and ENV_NAME.fullmatch(value) is None:
            message = f"invalid environment variable name: {value}"
            raise ValueError(message)
        return value

    @field_validator("required_env")
    @classmethod
    def _validate_required_env(cls, value: list[str]) -> list[str]:
        for env_name in value:
            if ENV_NAME.fullmatch(env_name) is None:
                message = f"invalid environment variable name: {env_name}"
                raise ValueError(message)
        return value

    @model_validator(mode="after")
    def _required_api_key_has_environment_variable(self) -> ModelRoute:
        if self._default_api_key_required() and self.effective_api_key_env() is None:
            message = "api_key_env is required when api_key_required is true"
            raise ValueError(message)
        return self

    def effective_base_url(self) -> str | None:
        return self.base_url or DEFAULT_BASE_URL.get(self.provider)

    def required_env_names(self) -> tuple[str, ...]:
        names: list[str] = []
        for env_name in self.required_env:
            if env_name not in names:
                names.append(env_name)

        api_key_env = self.effective_api_key_env()
        if api_key_env is not None and api_key_env not in names:
            names.append(api_key_env)
        return tuple(names)

    def effective_api_key_env(self) -> str | None:
        if self.api_key_env is not None:
            return self.api_key_env
        if self._default_api_key_required():
            return DEFAULT_API_KEY_ENV.get(self.provider)
        return None

    def _default_api_key_required(self) -> bool:
        if self.api_key_required is not None:
            return self.api_key_required
        if self.provider in LOCAL_PROVIDERS:
            return False
        if self.provider in {"litellm", "custom_openai"}:
            return False
        return self.provider in DEFAULT_API_KEY_ENV


class ModelProfile(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True)

    default_tier: ModelTier = "mid"
    routes: dict[ModelTier, list[ModelRoute]] = Field(min_length=1)
    role_tiers: dict[str, ModelTier] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _has_usable_routes(self) -> ModelProfile:
        if not any(self.routes.values()):
            message = "profile must define at least one route"
            raise ValueError(message)
        return self


class ModelRegistry(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True)

    profiles: dict[str, ModelProfile] = Field(min_length=1)

    @field_validator("profiles")
    @classmethod
    def _validate_profile_names(cls, value: dict[str, ModelProfile]) -> dict[str, ModelProfile]:
        for name in value:
            if not name.strip():
                message = "profile names must not be empty"
                raise ValueError(message)
        return value


@dataclass(frozen=True)
class ResolvedModelRoute:
    requested_tier: ModelTier
    selected_tier: ModelTier
    ordinal: int
    provider: ProviderKind
    model: str
    base_url: str | None
    api_key_env: str | None
    missing_env: tuple[str, ...]
    reasoning_effort: ReasoningEffort | None
    max_output_tokens: int
    output_token_limit_parameter: OutputTokenLimitParameter
    input_cost_per_1m_tokens: float | None
    output_cost_per_1m_tokens: float | None
    timeout_seconds: float
    max_retries: int
    cached_input_cost_per_1m_tokens: float | None = None
    api_key_required: bool = False

    @property
    def ready(self) -> bool:
        return not self.missing_env and not self.missing_pricing and self.transport_issue is None

    @property
    def missing_pricing(self) -> tuple[str, ...]:
        if not _route_requires_accountable_pricing(self):
            return ()
        prices = (
            ("input_cost_per_1m_tokens", self.input_cost_per_1m_tokens),
            ("cached_input_cost_per_1m_tokens", self.cached_input_cost_per_1m_tokens),
            ("output_cost_per_1m_tokens", self.output_cost_per_1m_tokens),
        )
        return tuple(name for name, value in prices if value is None)

    @property
    def transport_issue(self) -> str | None:
        return model_route_transport_issue(self)


def load_model_registry(
    path: Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> ModelRegistry:
    raw = _read_raw_registry(path)
    active_env = _active_env(env)
    expanded = _expand_env_templates(raw, active_env)
    if not isinstance(expanded, dict):
        message = "model registry must be a YAML mapping"
        raise TypeError(message)
    return ModelRegistry.model_validate(expanded)


def resolve_model_routes(
    registry: ModelRegistry,
    *,
    profile_name: str,
    tier: ModelTier,
    env: Mapping[str, str] | None = None,
) -> tuple[ResolvedModelRoute, ...]:
    profile = _profile_by_name(registry, profile_name)
    selected_tier, routes = _select_routes(profile, tier)
    active_env = _active_env(env)

    resolved_routes: list[ResolvedModelRoute] = []
    for index, route in enumerate(routes, start=1):
        resolved_route = _resolve_model_route(
            route=route,
            ordinal=index,
            requested_tier=tier,
            selected_tier=selected_tier,
            env=active_env,
        )
        resolved_routes.append(resolved_route)
    return tuple(resolved_routes)


def ready_model_routes(routes: Sequence[ResolvedModelRoute]) -> tuple[ResolvedModelRoute, ...]:
    ready_routes: list[ResolvedModelRoute] = []
    for route in routes:
        if route.ready:
            ready_routes.append(route)
    return tuple(ready_routes)


def render_model_routes(
    registry: ModelRegistry,
    *,
    profile_name: str,
    tier: ModelTier,
    env: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    routes = resolve_model_routes(registry, profile_name=profile_name, tier=tier, env=env)
    lines = [_model_routes_summary_line(profile_name=profile_name, tier=tier, routes=routes)]
    for route in routes:
        lines.append(_model_route_detail_line(route))
    return tuple(lines)


def _active_env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    if env is None:
        return os.environ
    return env


def _profile_by_name(registry: ModelRegistry, profile_name: str) -> ModelProfile:
    profile = registry.profiles.get(profile_name)
    if profile is not None:
        return profile

    available = ", ".join(sorted(registry.profiles))
    message = f"unknown model profile {profile_name!r}; available: {available}"
    raise ValueError(message)


def _resolve_model_route(
    *,
    route: ModelRoute,
    ordinal: int,
    requested_tier: ModelTier,
    selected_tier: ModelTier,
    env: Mapping[str, str],
) -> ResolvedModelRoute:
    input_cost, cached_input_cost, output_cost = _effective_token_prices(route)
    return ResolvedModelRoute(
        requested_tier=requested_tier,
        selected_tier=selected_tier,
        ordinal=ordinal,
        provider=route.provider,
        model=route.model,
        base_url=route.effective_base_url(),
        api_key_env=route.effective_api_key_env(),
        missing_env=_missing_env_names(route, env),
        reasoning_effort=route.reasoning_effort,
        max_output_tokens=route.max_output_tokens,
        output_token_limit_parameter=route.output_token_limit_parameter,
        input_cost_per_1m_tokens=input_cost,
        output_cost_per_1m_tokens=output_cost,
        timeout_seconds=route.timeout_seconds,
        max_retries=route.max_retries,
        cached_input_cost_per_1m_tokens=cached_input_cost,
        api_key_required=route._default_api_key_required(),
    )


def _effective_token_prices(
    route: ModelRoute,
) -> tuple[float | None, float | None, float | None]:
    configured = (
        route.input_cost_per_1m_tokens,
        route.cached_input_cost_per_1m_tokens,
        route.output_cost_per_1m_tokens,
    )
    if any(value is not None for value in configured):
        return configured
    if route.base_url is not None:
        return configured
    if route.provider == "openai":
        known = openai_standard_token_prices(route.model)
    elif route.provider == "anthropic":
        known = anthropic_standard_token_prices(route.model)
    else:
        known = None
    if known is None:
        return configured
    return known.input_per_1m, known.cached_input_per_1m, known.output_per_1m


def _route_requires_accountable_pricing(route: ResolvedModelRoute) -> bool:
    return not route_is_nonbillable_local(route)


def route_is_nonbillable_local(route: ResolvedModelRoute) -> bool:
    """Return whether a built-in local provider is credentialless and loopback-only."""
    if route.provider not in LOCAL_PROVIDERS:
        return False
    if route.api_key_env is not None or route.api_key_required:
        return False
    hostname = (urlparse(route.base_url or "").hostname or "").lower().rstrip(".")
    if hostname == "localhost":
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def model_route_transport_issue(route: ResolvedModelRoute) -> str | None:
    if route.provider not in DIRECT_CHAT_PROVIDERS:
        return "unsupported_direct_provider"
    base_url = (route.base_url or "").rstrip("/")
    if route.provider == "custom_openai" and not base_url:
        return "custom_openai_base_url_required"
    if route.provider == "openai" and base_url and base_url != OPENAI_NATIVE_BASE_URL:
        return "openai_native_base_url_required"
    if route.provider == "anthropic" and base_url != ANTHROPIC_NATIVE_BASE_URL:
        return "anthropic_native_base_url_required"
    return None


def model_route_transport_error(route: ResolvedModelRoute) -> str | None:
    issue = model_route_transport_issue(route)
    if issue == "unsupported_direct_provider":
        return (
            f"provider={route.provider} has no direct chat transport; "
            "use provider=custom_openai or provider=litellm with a configured gateway"
        )
    if issue == "custom_openai_base_url_required":
        return "provider=custom_openai requires an explicit base_url"
    if issue == "openai_native_base_url_required":
        return (
            f"provider=openai only supports {OPENAI_NATIVE_BASE_URL}; "
            "use provider=custom_openai for a gateway"
        )
    if issue == "anthropic_native_base_url_required":
        return (
            f"provider=anthropic only supports {ANTHROPIC_NATIVE_BASE_URL}; "
            "use provider=litellm for a gateway"
        )
    return None


def _missing_env_names(route: ModelRoute, env: Mapping[str, str]) -> tuple[str, ...]:
    missing_names: list[str] = []
    for env_name in route.required_env_names():
        if not env.get(env_name):
            missing_names.append(env_name)
    return tuple(missing_names)


def _model_routes_summary_line(
    *,
    profile_name: str,
    tier: ModelTier,
    routes: Sequence[ResolvedModelRoute],
) -> str:
    selected_tier = _selected_tier_for_summary(routes, tier)
    ready_count = _ready_route_count(routes)
    return (
        f"[models] profile={profile_name} requested_tier={tier} "
        f"selected_tier={selected_tier} "
        f"routes={len(routes)} ready={ready_count}"
    )


def _selected_tier_for_summary(
    routes: Sequence[ResolvedModelRoute],
    requested_tier: ModelTier,
) -> ModelTier:
    if routes:
        return routes[0].selected_tier
    return requested_tier


def _ready_route_count(routes: Sequence[ResolvedModelRoute]) -> int:
    count = 0
    for route in routes:
        if route.ready:
            count += 1
    return count


def _model_route_detail_line(route: ResolvedModelRoute) -> str:
    parts = [
        f"[models:route] #{route.ordinal}",
        f"provider={route.provider}",
        f"model={route.model}",
        f"ready={str(route.ready).lower()}",
    ]
    if route.base_url is not None:
        parts.append(f"base_url={route.base_url}")
    if route.reasoning_effort is not None:
        parts.append(f"reasoning_effort={route.reasoning_effort}")
    if route.missing_env:
        missing_env = ",".join(route.missing_env)
        parts.append(f"missing_env={missing_env}")
    if route.missing_pricing:
        missing_pricing = ",".join(route.missing_pricing)
        parts.append(f"missing_pricing={missing_pricing}")
    if route.transport_issue is not None:
        parts.append(f"transport_issue={route.transport_issue}")
    return " ".join(parts)


def _read_raw_registry(path: Path | None) -> object:
    if path is None:
        return DEFAULT_MODEL_CONFIG
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _select_routes(
    profile: ModelProfile,
    tier: ModelTier,
) -> tuple[ModelTier, list[ModelRoute]]:
    direct_routes = profile.routes.get(tier)
    if direct_routes:
        return tier, direct_routes

    default_routes = profile.routes.get(profile.default_tier)
    if default_routes:
        return profile.default_tier, default_routes

    for fallback_tier in TIER_ORDER:
        fallback_routes = profile.routes.get(fallback_tier)
        if fallback_routes:
            return fallback_tier, fallback_routes

    message = "profile must define at least one route"
    raise ValueError(message)


def _expand_env_templates(value: object, env: Mapping[str, str]) -> object:
    if isinstance(value, str):
        return _expand_env_string(value, env)
    if isinstance(value, list):
        return _expand_env_list(value, env)
    if isinstance(value, dict):
        return _expand_env_mapping(value, env)
    return value


def _expand_env_string(value: str, env: Mapping[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        return _replace_env_template(match, env)

    return ENV_TEMPLATE.sub(replace, value)


def _expand_env_list(values: list[object], env: Mapping[str, str]) -> list[object]:
    expanded_values: list[object] = []
    for item in values:
        expanded_values.append(_expand_env_templates(item, env))
    return expanded_values


def _expand_env_mapping(
    values: dict[object, object],
    env: Mapping[str, str],
) -> dict[object, object]:
    expanded_values: dict[object, object] = {}
    for key, item in values.items():
        expanded_values[key] = _expand_env_templates(item, env)
    return expanded_values


def _replace_env_template(match: re.Match[str], env: Mapping[str, str]) -> str:
    name = match.group(1)
    default = match.group(2)
    if name in env:
        return env[name]
    if default is not None:
        return default
    return ""
