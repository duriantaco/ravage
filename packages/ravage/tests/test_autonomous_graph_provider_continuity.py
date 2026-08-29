# ruff: noqa: CPY001

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from ravage.agent_core.ai_agent import ChatMessage, ModelReply
from ravage.agent_core.autonomous_graph.coordinator import GraphCoordinator
from ravage.agent_core.autonomous_graph.model_bridge import (
    AccountedGraphModelPortfolio,
    GraphModelEndpoint,
)
from ravage.agent_core.autonomous_graph.models import (
    GraphLimits,
    GraphObjective,
    GraphState,
    GraphStatus,
)
from ravage.agent_core.autonomous_graph.provider_continuity import (
    GraphModelContinuityRequiredError,
    ProviderFailureKind,
    classify_provider_failure,
)
from ravage.agent_core.autonomous_graph.scheduler import ProgressiveGraphScheduler
from ravage.agent_core.autonomous_graph.sessions import GraphSessionStore
from ravage.agent_core.autonomous_graph.worker import (
    GraphToolResult,
    GraphWorker,
    ProofGateResult,
    WorkerStepKind,
)
from ravage.model_core.providers import ResolvedModelRoute

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path
    from typing import Any

ENGAGEMENT_ID = UUID("99999999-9999-4999-9999-999999999999")
MODEL_COST_USD = 0.05
EXPECTED_MODEL_REQUESTS = 2


class RecordingAudit:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def record(
        self,
        *,
        engagement_id: UUID,
        actor: str,
        action: str,
        payload: Mapping[str, Any],
        cost_usd: float = 0.0,
    ) -> None:
        self.records.append(
            {
                "engagement_id": engagement_id,
                "actor": actor,
                "action": action,
                "payload": dict(payload),
                "cost_usd": cost_usd,
            }
        )


class FailingClient:
    def __init__(self, message: str) -> None:
        self.message = message
        self.calls = 0

    def complete(
        self,
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        del messages, route
        self.calls += 1
        raise RuntimeError(self.message)


class FinishingClient:
    def __init__(self) -> None:
        self.calls = 0

    def complete(
        self,
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        del messages
        self.calls += 1
        return ModelReply(
            content=json.dumps(
                {
                    "kind": "finish",
                    "payload": {
                        "summary": "bounded continuity turn completed",
                        "evidence_refs": [],
                    },
                }
            ),
            cost_usd=MODEL_COST_USD,
            usage_reported=True,
            cost_known=True,
            response_model=route.model,
        )


class NeverExecutor:
    async def __call__(
        self,
        node_id: str,
        tool: str,
        arguments: dict[str, object],
    ) -> GraphToolResult:
        del node_id, tool, arguments
        message = "continuity test must not execute a target tool"
        raise AssertionError(message)


class RejectingProofGate:
    async def __call__(
        self,
        node_id: str,
        evidence_refs: tuple[str, ...],
    ) -> ProofGateResult:
        del node_id, evidence_refs
        return ProofGateResult(accepted=False, reason="not used")


def _route(
    *,
    ordinal: int,
    provider: str,
    model: str,
) -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="mid",
        selected_tier="mid",
        ordinal=ordinal,
        provider=provider,  # type: ignore[arg-type]
        model=model,
        base_url="http://127.0.0.1:11434/v1",
        api_key_env=None,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=512,
        output_token_limit_parameter="max_tokens",  # noqa: S106
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=30,
        max_retries=0,
    )


def _objective() -> GraphObjective:
    return GraphObjective.create(
        family="graph_coordination",
        instruction="coordinate one bounded route",
        strategy="evidence_gated_specialist_graph",
        expected_signal="proof or bounded exhaustion",
    )


def test_provider_failure_classifier_is_fail_closed() -> None:
    quota = classify_provider_failure(RuntimeError("HTTP 429 quota exceeded"))
    bad_request = classify_provider_failure(RuntimeError("invalid request payload"))
    timeout = classify_provider_failure(TimeoutError("request timed out"))

    assert quota.kind is ProviderFailureKind.QUOTA
    assert quota.retryable is True
    assert bad_request.retryable is False
    assert timeout.retryable is False


@pytest.mark.asyncio
async def test_portfolio_moves_once_after_explicit_quota_failure() -> None:
    audit = RecordingAudit()
    failing = FailingClient("HTTP 429 quota exceeded")
    finishing = FinishingClient()
    portfolio = AccountedGraphModelPortfolio(
        endpoints=(
            GraphModelEndpoint(
                client=failing,
                route=_route(
                    ordinal=1,
                    provider="openai",
                    model="primary",
                ),
            ),
            GraphModelEndpoint(
                client=finishing,
                route=_route(
                    ordinal=2,
                    provider="ollama",
                    model="continuity",
                ),
            ),
        ),
        audit=audit,
        engagement_id=ENGAGEMENT_ID,
    )

    with pytest.raises(GraphModelContinuityRequiredError) as captured:
        await portfolio("node-001", [{"role": "user", "content": "continue"}])

    reply = await portfolio(
        "node-001",
        [{"role": "user", "content": "continue"}],
    )

    assert captured.value.failure.kind is ProviderFailureKind.QUOTA
    assert reply.cost_usd == MODEL_COST_USD
    assert failing.calls == 1
    assert finishing.calls == 1
    assert portfolio.active_endpoint.route.model == "continuity"
    assert [record["action"] for record in audit.records] == [
        "model_request_started",
        "model_request_failed",
        "provider_continuity_selected",
        "model_request_started",
        "model_reply_received",
    ]


@pytest.mark.asyncio
async def test_non_retryable_failure_does_not_rotate_provider() -> None:
    audit = RecordingAudit()
    failing = FailingClient("invalid request payload")
    finishing = FinishingClient()
    portfolio = AccountedGraphModelPortfolio(
        endpoints=(
            GraphModelEndpoint(
                client=failing,
                route=_route(
                    ordinal=1,
                    provider="openai",
                    model="primary",
                ),
            ),
            GraphModelEndpoint(
                client=finishing,
                route=_route(
                    ordinal=2,
                    provider="ollama",
                    model="continuity",
                ),
            ),
        ),
        audit=audit,
        engagement_id=ENGAGEMENT_ID,
    )

    with pytest.raises(RuntimeError, match="invalid request"):
        await portfolio("node-001", [{"role": "user", "content": "continue"}])

    assert portfolio.active_endpoint.route.model == "primary"
    assert finishing.calls == 0
    assert "provider_continuity_selected" not in {str(record["action"]) for record in audit.records}


@pytest.mark.asyncio
async def test_worker_accounts_interrupted_call_and_one_continuity_retry(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "graph.json"
    coordinator = GraphCoordinator.start(
        graph_id="provider-continuity-worker",
        root_objective=_objective(),
        limits=GraphLimits(
            max_model_requests=4,
            proof_reserve_model_requests=1,
        ),
        root_lease_limit=1,
        state_path=state_path,
    )
    audit = RecordingAudit()
    portfolio = AccountedGraphModelPortfolio(
        endpoints=(
            GraphModelEndpoint(
                client=FailingClient("HTTP 429 quota exceeded"),
                route=_route(
                    ordinal=1,
                    provider="openai",
                    model="primary",
                ),
            ),
            GraphModelEndpoint(
                client=FinishingClient(),
                route=_route(
                    ordinal=2,
                    provider="ollama",
                    model="continuity",
                ),
            ),
        ),
        audit=audit,
        engagement_id=ENGAGEMENT_ID,
    )
    worker = GraphWorker(
        coordinator=coordinator,
        scheduler=ProgressiveGraphScheduler(coordinator),
        sessions=GraphSessionStore.open(tmp_path / "sessions"),
        complete=portfolio,
        execute=NeverExecutor(),
        proof_gate=RejectingProofGate(),
    )

    result = await worker.step("node-001")
    persisted = GraphState.load(state_path)
    node = persisted.nodes["node-001"]

    assert result.kind is WorkerStepKind.FINISHED
    assert persisted.status is GraphStatus.EXHAUSTED
    assert persisted.model_requests_started == EXPECTED_MODEL_REQUESTS
    assert persisted.model_requests_completed == EXPECTED_MODEL_REQUESTS
    assert persisted.interrupted_model_requests == 1
    assert node.provider_continuity_retries == 1
    assert node.lease_used == 1
    assert node.spent_cost_usd == MODEL_COST_USD
