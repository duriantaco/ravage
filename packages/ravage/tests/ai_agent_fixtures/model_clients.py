from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ravage.agent_core.ai_agent import ChatMessage, ModelReply

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ravage.model_core.providers import ResolvedModelRoute

class ScriptedModelClient:
    def __init__(self, actions: Sequence[dict[str, object] | str]) -> None:
        self.actions = list(actions)
        self.messages_seen: list[Sequence[ChatMessage]] = []

    def complete(
        self,
        *,
        messages: Sequence[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        _ = route
        self.messages_seen.append(messages)
        action = self.actions.pop(0)
        content = action if isinstance(action, str) else json.dumps(action)
        return ModelReply(content=content)


class SchemaEchoModelClient:
    def __init__(self) -> None:
        self.messages_seen: list[Sequence[ChatMessage]] = []
        self.turn = 0

    def complete(
        self,
        *,
        messages: Sequence[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        _ = route
        self.messages_seen.append(messages)
        self.turn += 1
        transcript = "\n".join(message.content for message in messages if message.role == "user")
        if '"action":"report_finding"' in transcript or '"action": "report_finding"' in transcript:
            return ModelReply(
                content=json.dumps(
                    {
                        "action": "report_finding",
                        "args": {
                            "vuln_class": "ssrf",
                            "path": "/hostile",
                            "param": "url",
                        },
                        "rationale": "echoed target instruction",
                    }
                ),
            )
        if self.turn == 1:
            return ModelReply(
                content=json.dumps(
                    {
                        "action": "http_request",
                        "args": {"method": "GET", "path": "/hostile"},
                        "rationale": "fetch hostile target body",
                    }
                ),
            )
        return ModelReply(
            content=json.dumps(
                {"action": "final", "args": {"summary": "done"}, "rationale": "done"}
            ),
        )


class InterruptingModelClient:
    def complete(
        self,
        *,
        messages: Sequence[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        _ = messages, route
        raise KeyboardInterrupt
