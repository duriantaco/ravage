"""Exact-model transport for the read-only review gate; no fallback models."""

from __future__ import annotations

import math
from dataclasses import replace
from typing import TYPE_CHECKING

from ravage.agent_core.ai_agent import ChatClient
from ravage.model_core.providers import load_model_registry, resolve_model_routes
from ravage.repository_review import ReviewReply

MAX_INPUT_BOUND = 100_000

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from ravage.model_core.providers import ResolvedModelRoute
    from ravage.repository_review import ReviewMessage

    from tools.review_quality_gate.gate import Policy


class ExactReviewClient:
    """Preserve production review prompts and verify every provider response."""

    def __init__(
        self,
        policy: Policy,
        *,
        allow_paid_models: bool,
        progress: Callable[[int, float], None] | None = None,
    ) -> None:
        if not allow_paid_models:
            msg = "live review quality evaluation requires --allow-paid-models"
            raise ValueError(msg)
        route = resolve_model_routes(
            load_model_registry(), profile_name="hosted-openai-gpt-5.4-high", tier="high"
        )[0]
        if (
            not route.ready
            or route.provider != "openai"
            or route.model != policy.model
            or route.reasoning_effort != policy.reasoning_effort
            or route.base_url not in (None, "https://api.openai.com/v1")
            or route.input_cost_per_1m_tokens != policy.input_price
            or route.output_cost_per_1m_tokens != policy.output_price
            or route.output_token_limit_parameter != "max_completion_tokens"  # noqa: S105
        ):
            msg = "quality gate requires the pinned native GPT-5.4 high route and prices"
            raise ValueError(msg)
        self.route = replace(
            route,
            base_url=None,
            max_output_tokens=policy.max_output_tokens,
            timeout_seconds=60,
            max_retries=0,
        )
        self.transport = ChatClient(self.route)
        self.policy = policy
        self.calls = 0
        self.verified_calls = 0
        self.cost_usd = 0.0
        self.failed = False
        self.progress = progress

    def complete(
        self, *, messages: Sequence[ReviewMessage], route: ResolvedModelRoute
    ) -> ReviewReply:
        if self.failed:
            msg = "evaluation stopped after an unverified provider call"
            raise RuntimeError(msg)
        if route != self.route:
            msg = "model route changed during evaluation"
            raise ValueError(msg)
        payload = [{"role": item.role, "content": item.content} for item in messages]
        # UTF-8 bytes conservatively bound tokenizer units, with framing allowance.
        input_bound = sum(len(item.content.encode()) + 64 for item in messages) + 128
        request_bound = (
            input_bound * self.policy.input_price
            + self.policy.max_output_tokens * self.policy.output_price
        ) / 1_000_000
        if (
            input_bound > MAX_INPUT_BOUND
            or self.cost_usd + request_bound > self.policy.max_cost_usd
        ):
            msg = "remaining quality-gate budget cannot cover the next bounded request"
            raise RuntimeError(msg)
        self.calls += 1
        try:
            reply = self.transport.chat(payload)
        except (RuntimeError, ValueError, OSError):
            self.failed = True
            raise
        if (
            not reply.usage_reported
            or not reply.cost_known
            or not math.isfinite(reply.cost_usd)
            or reply.cost_usd < 0
        ):
            self.failed = True
            msg = "provider did not return complete usage and cost accounting"
            raise RuntimeError(msg)
        self.cost_usd += reply.cost_usd
        if reply.response_model != self.policy.model or self.cost_usd > self.policy.max_cost_usd:
            self.failed = True
            msg = "provider response violated the model identity or cost contract"
            raise RuntimeError(msg)
        self.verified_calls += 1
        if self.progress is not None:
            self.progress(self.verified_calls, self.cost_usd)
        return ReviewReply(
            content=reply.content,
            input_tokens=reply.input_tokens,
            cached_input_tokens=reply.cached_input_tokens,
            output_tokens=reply.output_tokens,
            cost_usd=reply.cost_usd,
            usage_reported=True,
            cost_known=True,
        )
