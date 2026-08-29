from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Self

from ravage.agent_core.ai_agent import (
    ChatMessage,
    ProviderChatClient,
)
from ravage.model_core.providers import ProviderKind, ResolvedModelRoute

if TYPE_CHECKING:
    import pytest


def test_native_anthropic_client_posts_messages_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = {"action": "final", "args": {"summary": "done"}, "rationale": "complete"}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-test-key")

    with AnthropicStubServer(action) as server:
        route = _route(provider="anthropic", model="claude-haiku-4-5", base_url=server.base_url)

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
    assert server.requests_seen == [
        {
            "headers": {
                "x-api-key": "anthropic-test-key",
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            "payload": {
                "model": "claude-haiku-4-5",
                "max_tokens": 256,
                "temperature": 0,
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


class AnthropicStubHandler(BaseHTTPRequestHandler):
    action: dict[str, object]
    requests_seen: list[dict[str, object]]

    def do_POST(self) -> None:
        if self.path != "/v1/messages":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        self.requests_seen.append(
            {
                "headers": {
                    "x-api-key": self.headers.get("x-api-key", ""),
                    "anthropic-version": self.headers.get("anthropic-version", ""),
                    "content-type": self.headers.get("content-type", ""),
                },
                "payload": json.loads(raw_body),
            }
        )
        response_payload = {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": json.dumps(self.action)}],
            "model": "claude-haiku-4-5",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        response_body = json.dumps(response_payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return


class AnthropicStubServer:
    def __init__(self, action: dict[str, object]) -> None:
        self._handler: type[AnthropicStubHandler] = type(
            "PerTestAnthropicStubHandler",
            (AnthropicStubHandler,),
            {"action": action, "requests_seen": []},
        )
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def requests_seen(self) -> list[dict[str, object]]:
        return self._handler.requests_seen


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
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=5.0,
        max_retries=0,
    )
