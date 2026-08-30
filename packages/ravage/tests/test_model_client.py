from __future__ import annotations

import json
import urllib.request
from typing import Self

import pytest
from ravage.agent_core.ai_agent import (
    ChatMessage,
    ProviderChatClient,
)
from ravage.model_core.providers import ProviderKind, ResolvedModelRoute


def test_native_anthropic_client_posts_messages_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = {"action": "final", "args": {"summary": "done"}, "rationale": "complete"}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-test-key")
    requests_seen: list[dict[str, object]] = []

    def fake_urlopen(
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> StubHTTPResponse:
        assert timeout > 0
        headers = {name.lower(): value for name, value in request.header_items()}
        assert request.data is not None
        requests_seen.append(
            {
                "url": request.full_url,
                "headers": headers,
                "payload": json.loads(request.data.decode("utf-8")),
            }
        )
        return StubHTTPResponse(
            {
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": json.dumps(action)}],
                "model": "claude-haiku-4-5-20251001",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
        )

    monkeypatch.setattr(
        "ravage.agent_core.ai_agent.urllib.request.urlopen",
        fake_urlopen,
    )

    route = _route(
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        base_url="https://api.anthropic.com",
    )

    reply = ProviderChatClient().complete(
        messages=[
            ChatMessage(role="system", content="system one"),
            ChatMessage(role="system", content="system two"),
            ChatMessage(role="user", content="first user"),
            ChatMessage(role="user", content="second user"),
            ChatMessage(role="assistant", content='{"action":"discover_attack_surface"}'),
            ChatMessage(role="user", content="next observation"),
        ],
        route=route,
    )

    assert json.loads(reply.content) == action
    assert reply.cost_known is True
    assert reply.cost_usd == pytest.approx(0.000006)
    assert reply.response_model == "claude-haiku-4-5-20251001"
    assert requests_seen == [
        {
            "url": "https://api.anthropic.com/v1/messages",
            "headers": {
                "x-api-key": "anthropic-test-key",
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            "payload": {
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 256,
                "system": "system one\n\nsystem two",
                "messages": [
                    {"role": "user", "content": "first user"},
                    {"role": "user", "content": "second user"},
                    {"role": "assistant", "content": '{"action":"discover_attack_surface"}'},
                    {"role": "user", "content": "next observation"},
                ],
            },
        }
    ]


class StubHTTPResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _route(
    *,
    provider: ProviderKind,
    model: str,
    base_url: str | None,
) -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="low",
        selected_tier="low",
        ordinal=1,
        provider=provider,
        model=model,
        base_url=base_url,
        api_key_env="ANTHROPIC_API_KEY",
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=256,
        output_token_limit_parameter="max_tokens",  # noqa: S106 - parameter name, not a secret.
        input_cost_per_1m_tokens=1.0,
        output_cost_per_1m_tokens=5.0,
        timeout_seconds=5.0,
        max_retries=0,
        cached_input_cost_per_1m_tokens=0.1,
    )
