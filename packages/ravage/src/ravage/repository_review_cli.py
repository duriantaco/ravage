"""CLI entry point for bounded, model-assisted repository review."""

# argparse errors intentionally keep actionable configuration details.

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from yaml import YAMLError  # type: ignore[import-untyped]

from ravage.model_core.providers import (
    ModelTier,
    ResolvedModelRoute,
    load_model_registry,
    ready_model_routes,
    resolve_model_routes,
)
from ravage.repository_context import ContextLimitError, ContextReadError
from ravage.repository_review import (
    DEFAULT_REVIEW_MAX_COST_USD,
    DEFAULT_REVIEW_MAX_TURNS,
    DEFAULT_REVIEW_OBJECTIVE,
    RepositoryReviewError,
    ReviewMessage,
    ReviewReply,
    run_repository_review,
    validate_repository_review_options,
    validate_repository_review_route,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import TextIO

    from ravage.repository_review import ReviewModelClient


class ProviderReviewClient:
    """Narrow adapter around Ravage's existing model transport."""

    def complete(
        self,
        *,
        messages: Sequence[ReviewMessage],
        route: ResolvedModelRoute,
    ) -> ReviewReply:
        # Keep the review engine independent from the active attack-agent module.
        from ravage.agent_core.ai_agent import ChatMessage, ProviderChatClient  # noqa: PLC0415

        reply = ProviderChatClient().complete(
            messages=[ChatMessage(role=item.role, content=item.content) for item in messages],
            route=route,
        )
        return ReviewReply(
            content=reply.content,
            input_tokens=reply.input_tokens,
            cached_input_tokens=reply.cached_input_tokens,
            output_tokens=reply.output_tokens,
            cost_usd=reply.cost_usd,
            usage_reported=reply.usage_reported,
            cost_known=reply.cost_known,
        )


def handle_repository_review_command(
    args: list[str],
    *,
    stdout: TextIO | None = None,
    model_client: ReviewModelClient | None = None,
) -> dict[str, object]:
    """Run model-guided review without constructing target or process tooling."""
    parser = argparse.ArgumentParser(
        prog="ravage review",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Review one local repository through bounded, read-only source context. "
            "No project code or target tools are executed."
        ),
    )
    parser.add_argument("source_root", type=Path, help="non-symlink local repository directory")
    parser.add_argument(
        "--objective",
        default=DEFAULT_REVIEW_OBJECTIVE,
        help="defensive review objective sent to the model",
    )
    parser.add_argument("--model-config", type=Path, help="model registry YAML path")
    parser.add_argument(
        "--model-profile",
        default="local-ollama",
        help="model registry profile",
    )
    parser.add_argument(
        "--model-tier",
        choices=["high", "mid", "low"],
        default="mid",
        help="requested model tier",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=DEFAULT_REVIEW_MAX_TURNS,
        help="model-call limit (1-64)",
    )
    parser.add_argument(
        "--max-cost-usd",
        type=float,
        default=DEFAULT_REVIEW_MAX_COST_USD,
        help="configured model-cost ceiling with a conservative pre-request bound",
    )
    parser.add_argument(
        "--allow-paid-models",
        action="store_true",
        help=(
            "allow a paid-risk or hosted model route to receive requested source text, "
            "including search results and excerpts"
        ),
    )
    parsed = parser.parse_args(args)

    try:
        objective = validate_repository_review_options(
            objective=parsed.objective,
            max_turns=parsed.max_turns,
            max_cost_usd=parsed.max_cost_usd,
        )
        route = ready_repository_review_route(
            model_config=parsed.model_config,
            model_profile=parsed.model_profile,
            model_tier=parsed.model_tier,
        )
        validate_repository_review_route(
            route,
            allow_paid_models=parsed.allow_paid_models,
        )
    except (OSError, RuntimeError, TypeError, ValueError, YAMLError) as exc:
        parser.error(str(exc))

    try:
        result = run_repository_review(
            source_root=parsed.source_root,
            route=route,
            client=model_client or ProviderReviewClient(),
            objective=objective,
            max_turns=parsed.max_turns,
            max_cost_usd=parsed.max_cost_usd,
            allow_paid_models=parsed.allow_paid_models,
        )
    except (ContextLimitError, ContextReadError) as exc:
        parser.error(str(exc))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")

    payload = result.to_json()
    rendered = (
        json.dumps(payload, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    )
    (stdout or sys.stdout).write(rendered)
    return payload


def ready_repository_review_route(
    *,
    model_config: Path | None,
    model_profile: str,
    model_tier: ModelTier,
) -> ResolvedModelRoute:
    registry = load_model_registry(model_config)
    routes = resolve_model_routes(
        registry,
        profile_name=model_profile,
        tier=model_tier,
    )
    ready = ready_model_routes(routes)
    if ready:
        return ready[0]
    missing = sorted({name for route in routes for name in route.missing_env})
    missing_pricing = sorted({name for route in routes for name in route.missing_pricing})
    transport_issues = sorted(
        {route.transport_issue for route in routes if route.transport_issue is not None}
    )
    details: list[str] = []
    if missing:
        details.append(f"missing env: {', '.join(missing)}")
    if missing_pricing:
        details.append(f"missing pricing: {', '.join(missing_pricing)}")
    if transport_issues:
        details.append(f"transport issues: {', '.join(transport_issues)}")
    suffix = f"; {'; '.join(details)}" if details else ""
    message = f"no ready model route for profile {model_profile!r} at tier {model_tier}{suffix}"
    raise RepositoryReviewError(message)


__all__ = [
    "ProviderReviewClient",
    "handle_repository_review_command",
    "ready_repository_review_route",
]
