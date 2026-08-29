from __future__ import annotations

import urllib.error
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.ai_agent import ChatClient
from ravage.model_core.providers import ResolvedModelRoute

if TYPE_CHECKING:
    from collections.abc import Mapping


def test_openai_compatible_chat_client_requests_json_object_response() -> None:
    client = _CapturingChatClient(_route())

    reply = client.chat([{"role": "user", "content": "return json"}])

    assert reply.content == '{"action":"final","summary":"done"}'
    assert client.request_body["response_format"] == {"type": "json_object"}
    assert reply.usage_reported is True
    assert reply.cost_known is False
    assert reply.response_model == "stub-returned-model"
    assert reply.response_id == "chatcmpl_test"
    assert reply.system_fingerprint == "fp_test"
    assert reply.service_tier == "default"


def test_direct_openai_chat_client_requests_standard_service_tier() -> None:
    route = replace(
        _route(
            input_cost_per_1m_tokens=0.75,
            cached_input_cost_per_1m_tokens=0.075,
            output_cost_per_1m_tokens=4.5,
        ),
        provider="openai",
        model="gpt-5.4-mini",
        base_url=None,
    )
    client = _CapturingChatClient(route)
    client.response_model = "gpt-5.4-mini-2026-03-17"

    reply = client.chat([{"role": "user", "content": "return json"}])

    assert client.request_body["service_tier"] == "default"
    assert reply.cost_known is True


@pytest.mark.parametrize(
    ("response_model", "service_tier"),
    [
        ("gpt-5.4", "default"),
        ("gpt-5.4-mini-2026-03-17", "flex"),
    ],
)
def test_direct_openai_chat_client_rejects_unexpected_pricing_metadata(
    response_model: str,
    service_tier: str,
) -> None:
    route = replace(
        _route(
            input_cost_per_1m_tokens=0.75,
            cached_input_cost_per_1m_tokens=0.075,
            output_cost_per_1m_tokens=4.5,
        ),
        provider="openai",
        model="gpt-5.4-mini-2026-03-17",
        base_url=None,
    )
    client = _CapturingChatClient(route)
    client.response_model = response_model
    client.response_service_tier = service_tier

    reply = client.chat([{"role": "user", "content": "return json"}])

    assert reply.cost_known is False
    assert reply.cost_usd == 0.0


def test_direct_openai_chat_client_uses_long_context_prices() -> None:
    route = replace(
        _route(
            input_cost_per_1m_tokens=2.5,
            cached_input_cost_per_1m_tokens=0.25,
            output_cost_per_1m_tokens=15.0,
        ),
        provider="openai",
        model="gpt-5.4-2026-03-05",
        base_url=None,
    )
    client = _CapturingChatClient(route)
    client.response_model = route.model
    client.prompt_tokens = 272_001

    reply = client.chat([{"role": "user", "content": "return json"}])

    assert reply.cost_known is True
    assert reply.cost_usd == pytest.approx(1.360455)


def test_openai_compatible_chat_client_prices_cached_input_separately() -> None:
    client = _CapturingChatClient(
        _route(
            input_cost_per_1m_tokens=2.5,
            cached_input_cost_per_1m_tokens=0.25,
            output_cost_per_1m_tokens=15.0,
        )
    )

    reply = client.chat([{"role": "user", "content": "return json"}])

    assert reply.input_tokens == 1_000
    assert reply.cached_input_tokens == 400
    assert reply.output_tokens == 100
    assert reply.cost_usd == 0.0031
    assert reply.cost_known is True


def test_openai_compatible_chat_client_requires_cached_price_for_cached_usage() -> None:
    client = _CapturingChatClient(
        _route(
            input_cost_per_1m_tokens=2.5,
            output_cost_per_1m_tokens=15.0,
        )
    )

    reply = client.chat([{"role": "user", "content": "return json"}])

    assert reply.usage_reported is True
    assert reply.cached_input_tokens == 400
    assert reply.cost_known is False
    assert reply.cost_usd == 0.0


def test_openai_compatible_chat_client_marks_missing_usage_unaccountable() -> None:
    client = _MissingUsageChatClient(
        _route(
            input_cost_per_1m_tokens=2.5,
            cached_input_cost_per_1m_tokens=0.25,
            output_cost_per_1m_tokens=15.0,
        )
    )

    reply = client.chat([{"role": "user", "content": "return json"}])

    assert reply.usage_reported is False
    assert reply.cost_known is False
    assert reply.cost_usd == 0.0
    assert reply.response_model == "stub-returned-model"
    assert reply.response_id == "chatcmpl_without_usage"


def test_chat_client_extends_retries_for_transient_url_errors(monkeypatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("ravage.agent_core.ai_agent.time.sleep", sleeps.append)
    client = _TransientFailureChatClient(_route(max_retries=0), failures=5)

    reply = client.chat([{"role": "user", "content": "return json"}])

    assert reply.content == '{"action":"final","summary":"done"}'
    assert client.calls == 6
    assert sleeps == [1.0, 2.0, 4.0, 8.0, 8.0]


def test_chat_client_does_not_retry_paid_transport_failures(monkeypatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("ravage.agent_core.ai_agent.time.sleep", sleeps.append)
    client = _TransientFailureChatClient(
        _route(
            max_retries=5,
            input_cost_per_1m_tokens=2.5,
            output_cost_per_1m_tokens=15.0,
        ),
        failures=1,
    )

    with pytest.raises(RuntimeError, match="model route failed"):
        client.chat([{"role": "user", "content": "return json"}])

    assert client.calls == 1
    assert sleeps == []


class _CapturingChatClient(ChatClient):
    request_body: Mapping[str, object]
    response_model = "stub-returned-model"
    response_service_tier = "default"
    prompt_tokens = 1_000

    def _post_json(
        self,
        url: str,
        body: Mapping[str, object],
        *,
        anthropic: bool = False,
    ) -> dict[str, object]:
        expected_base_url = (self.route.base_url or "https://api.openai.com/v1").rstrip("/")
        assert url == f"{expected_base_url}/chat/completions"
        assert anthropic is False
        self.request_body = body
        return {
            "id": "chatcmpl_test",
            "model": self.response_model,
            "system_fingerprint": "fp_test",
            "service_tier": self.response_service_tier,
            "choices": [{"message": {"content": '{"action":"final","summary":"done"}'}}],
            "usage": {
                "prompt_tokens": self.prompt_tokens,
                "prompt_tokens_details": {"cached_tokens": 400},
                "completion_tokens": 100,
            },
        }


class _MissingUsageChatClient(_CapturingChatClient):
    def _post_json(
        self,
        url: str,
        body: Mapping[str, object],
        *,
        anthropic: bool = False,
    ) -> dict[str, object]:
        assert url == "http://model.test/v1/chat/completions"
        assert anthropic is False
        self.request_body = body
        return {
            "id": "chatcmpl_without_usage",
            "model": "stub-returned-model",
            "choices": [{"message": {"content": '{"action":"final","summary":"done"}'}}],
        }


class _TransientFailureChatClient(_CapturingChatClient):
    def __init__(self, route: ResolvedModelRoute, *, failures: int) -> None:
        super().__init__(route)
        self.failures = failures
        self.calls = 0

    def _post_json(
        self,
        url: str,
        body: Mapping[str, object],
        *,
        anthropic: bool = False,
    ) -> dict[str, object]:
        self.calls += 1
        if self.calls <= self.failures:
            raise urllib.error.URLError("temporary dns failure")
        return super()._post_json(url, body, anthropic=anthropic)


def _route(
    *,
    max_retries: int = 0,
    input_cost_per_1m_tokens: float | None = None,
    cached_input_cost_per_1m_tokens: float | None = None,
    output_cost_per_1m_tokens: float | None = None,
) -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="mid",
        selected_tier="mid",
        ordinal=0,
        provider="custom_openai",
        model="stub",
        base_url="http://model.test/v1",
        api_key_env=None,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=256,
        output_token_limit_parameter="max_tokens",
        input_cost_per_1m_tokens=input_cost_per_1m_tokens,
        output_cost_per_1m_tokens=output_cost_per_1m_tokens,
        timeout_seconds=1,
        max_retries=max_retries,
        cached_input_cost_per_1m_tokens=cached_input_cost_per_1m_tokens,
    )
