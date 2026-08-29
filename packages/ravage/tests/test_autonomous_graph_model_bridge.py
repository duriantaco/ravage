from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from ravage.agent_core.ai_agent import AIWebAgentSettings, ChatMessage, ModelReply
from ravage.agent_core.autonomous_graph.model_bridge import (
    AccountedGraphModel,
    GraphModelEndpoint,
    accounted_graph_role_model_policies,
    authenticated_graph_reply_content,
    graph_role_model_policy_key,
    graph_route_instructions,
    select_graph_model_portfolio,
)
from ravage.agent_core.autonomous_graph.models import GraphAgentRole
from ravage.auth.redaction import AuthArtifactRedactor
from ravage.auth.secrets import SecretValue
from ravage.model_core.providers import ResolvedModelRoute

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path
    from typing import Any

ENGAGEMENT_ID = UUID("99999999-9999-4999-9999-999999999999")
MODEL_COST_USD = 0.125
MODEL_INPUT_TOKENS = 11
AUDIT_RECORD_COUNT = 2


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


class RecordingClient:
    def __init__(
        self,
        *,
        cost_known: bool = True,
    ) -> None:
        self.cost_known = cost_known
        self.calls: list[tuple[list[ChatMessage], ResolvedModelRoute]] = []

    def complete(
        self,
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        self.calls.append((messages, route))
        return ModelReply(
            content='{"kind":"wait","payload":{},"rationale":"bounded wait"}',
            input_tokens=MODEL_INPUT_TOKENS,
            output_tokens=7,
            cost_usd=MODEL_COST_USD,
            usage_reported=True,
            cost_known=self.cost_known,
            response_model=route.model,
            response_id="response-1",
        )


def _route(
    *,
    provider: str = "ollama",
    api_key_env: str | None = None,
) -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="mid",
        selected_tier="mid",
        ordinal=1,
        provider=provider,  # type: ignore[arg-type]
        model="test-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key_env=api_key_env,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=512,
        output_token_limit_parameter="max_tokens",  # noqa: S106
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=30,
        max_retries=0,
    )


@pytest.mark.asyncio
async def test_model_bridge_adds_graph_contract_and_audits_cost() -> None:
    client = RecordingClient()
    audit = RecordingAudit()
    events: list[dict[str, object]] = []

    def record_event(*, kind: str, payload: Mapping[str, Any]) -> None:
        events.append({"kind": kind, "payload": dict(payload)})

    instructions = graph_route_instructions()
    model = AccountedGraphModel(
        client=client,
        route=_route(),
        audit=audit,
        engagement_id=ENGAGEMENT_ID,
        route_instructions=instructions,
        record_event=record_event,
    )
    original = [
        {"role": "system", "content": "one structured action"},
        {"role": "user", "content": "node context"},
    ]

    reply = await model("node-002", original)

    assert reply.cost_usd == MODEL_COST_USD
    assert original[0]["content"] == "one structured action"
    sent = client.calls[0][0]
    assert instructions in sent[0].content
    assert "evidence.proof_refs" in sent[0].content
    assert [record["action"] for record in audit.records] == [
        "model_request_started",
        "model_reply_received",
    ]
    assert audit.records[0]["payload"]["graph_node_id"] == "node-002"
    assert audit.records[1]["cost_usd"] == MODEL_COST_USD
    assert [event["kind"] for event in events] == [
        "autonomous_graph_model_request_started",
        "autonomous_graph_model_reply_received",
    ]
    assert events[1]["payload"]["input_tokens"] == MODEL_INPUT_TOKENS


@pytest.mark.asyncio
async def test_optional_graph_display_events_cannot_break_model_execution() -> None:
    client = RecordingClient()
    audit = RecordingAudit()

    def broken_event_recorder(*, kind: str, payload: Mapping[str, Any]) -> None:
        del kind, payload
        message = "display event store unavailable"
        raise OSError(message)

    model = AccountedGraphModel(
        client=client,
        route=_route(),
        audit=audit,
        engagement_id=ENGAGEMENT_ID,
        record_event=broken_event_recorder,
    )

    reply = await model("node-002", [{"role": "user", "content": "return one action"}])

    assert reply.cost_usd == MODEL_COST_USD
    assert [record["action"] for record in audit.records] == [
        "model_request_started",
        "model_reply_received",
    ]


@pytest.mark.asyncio
async def test_authenticated_graph_model_reply_is_sanitized_before_worker_persistence() -> None:
    client = RecordingClient()

    def tainted_reply(
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        client.calls.append((messages, route))
        return ModelReply(
            content=(
                '{"kind":"execute","payload":{"tool":"capture_flag",'
                '"arguments":{"flag":"FLAG{alice}"},'
                '"expected_signal":"trusted proof"}}'
            )
        )

    client.complete = tainted_reply  # type: ignore[method-assign]
    redactor = AuthArtifactRedactor((SecretValue("alice"),))
    model = AccountedGraphModel(
        client=client,
        route=_route(),
        audit=RecordingAudit(),
        engagement_id=ENGAGEMENT_ID,
        redact_reply=redactor.redact_text,
        sanitize_reply=lambda content: authenticated_graph_reply_content(
            content,
            authentication=redactor,  # type: ignore[arg-type]
        ),
    )

    reply = await model("node-002", [{"role": "user", "content": "return one action"}])

    assert "FLAG{alice}" not in reply.content
    assert "[REDACTED]" in reply.content
    assert reply.artifact_content is not None
    assert "FLAG{alice}" not in reply.artifact_content


@pytest.mark.asyncio
async def test_authenticated_graph_protocol_preserves_http_injection_not_credentials() -> None:
    client = RecordingClient()
    content = (
        '{"kind":"execute","payload":{"tool":"http_request",'
        '"arguments":{"method":"POST","path":"/account",'
        '"form":{"password":"\u0027 OR 1=1--","username":"guest"}},'
        '"expected_signal":"secret account row"},'
        '"rationale":"never send correct-horse"}'
    )

    def injection_reply(
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        client.calls.append((messages, route))
        return ModelReply(content=content)

    client.complete = injection_reply  # type: ignore[method-assign]
    redactor = AuthArtifactRedactor(
        (SecretValue("secret"), SecretValue("correct-horse"))
    )
    model = AccountedGraphModel(
        client=client,
        route=_route(),
        audit=RecordingAudit(),
        engagement_id=ENGAGEMENT_ID,
        redact_reply=redactor.redact_text,
        sanitize_reply=lambda reply: authenticated_graph_reply_content(
            reply,
            authentication=redactor,  # type: ignore[arg-type]
        ),
    )

    reply = await model("node-002", [{"role": "user", "content": "return one action"}])
    payload = json.loads(reply.content)

    assert payload["kind"] == "execute"
    assert payload["payload"]["tool"] == "http_request"
    assert payload["payload"]["arguments"]["method"] == "POST"
    assert payload["payload"]["arguments"]["form"] == {
        "password": "' OR 1=1--",
        "username": "guest",
    }
    assert "secret" not in payload["payload"]["expected_signal"]
    assert "correct-horse" not in payload["rationale"]
    assert reply.artifact_content is not None
    assert "correct-horse" not in reply.artifact_content


@pytest.mark.asyncio
async def test_authenticated_graph_model_failure_is_generic_before_worker_persistence() -> None:
    client = RecordingClient()

    def tainted_failure(
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        client.calls.append((messages, route))
        raise RuntimeError("provider echoed FLAG{alice}")

    client.complete = tainted_failure  # type: ignore[method-assign]
    model = AccountedGraphModel(
        client=client,
        route=_route(),
        audit=RecordingAudit(),
        engagement_id=ENGAGEMENT_ID,
        redact_reply=lambda text: text.replace("FLAG{alice}", "[REDACTED]"),
    )

    with pytest.raises(RuntimeError, match="authenticated graph model request failed") as caught:
        await model("node-002", [{"role": "user", "content": "return one action"}])

    assert "FLAG{alice}" not in str(caught.value)


@pytest.mark.asyncio
async def test_paid_unknown_cost_reply_is_recorded_as_non_retryable_failure() -> None:
    client = RecordingClient(cost_known=False)
    audit = RecordingAudit()
    events: list[dict[str, object]] = []

    def record_event(*, kind: str, payload: Mapping[str, Any]) -> None:
        events.append({"kind": kind, "payload": dict(payload)})

    model = AccountedGraphModel(
        client=client,
        route=_route(provider="openai", api_key_env="OPENAI_API_KEY"),
        audit=audit,
        engagement_id=ENGAGEMENT_ID,
        record_event=record_event,
    )

    with pytest.raises(RuntimeError, match="cannot be cost-accounted"):
        await model(
            "node-001",
            [{"role": "system", "content": "return JSON"}],
        )

    assert [record["action"] for record in audit.records] == [
        "model_request_started",
        "model_request_failed",
    ]
    failure_payload = audit.records[1]["payload"]
    assert failure_payload["error_type"] == "RuntimeError"
    assert failure_payload["failure_kind"] == "non_retryable"
    assert failure_payload["continuity_safe"] is False
    assert failure_payload["cost_known"] is False
    assert failure_payload["cost_usd"] == 0.0
    assert [event["kind"] for event in events] == [
        "autonomous_graph_model_request_started",
        "autonomous_graph_model_request_failed",
    ]
    assert events[1]["payload"] == failure_payload


@pytest.mark.asyncio
async def test_local_model_may_report_unknown_cost_without_hiding_request() -> None:
    client = RecordingClient(cost_known=False)
    audit = RecordingAudit()
    model = AccountedGraphModel(
        client=client,
        route=_route(provider="ollama"),
        audit=audit,
        engagement_id=ENGAGEMENT_ID,
    )

    reply = await model(
        "node-001",
        [{"role": "user", "content": "return one action"}],
    )

    assert reply.cost_usd == MODEL_COST_USD
    sent = client.calls[0][0]
    assert sent[0].role == "user"
    assert len(audit.records) == AUDIT_RECORD_COUNT


@pytest.mark.asyncio
async def test_graph_tool_observation_is_provider_safe_user_context() -> None:
    client = RecordingClient()
    audit = RecordingAudit()
    model = AccountedGraphModel(
        client=client,
        route=_route(provider="openai", api_key_env="OPENAI_API_KEY"),
        audit=audit,
        engagement_id=ENGAGEMENT_ID,
    )
    observation = '{"evidence":{"proof_refs":["proof:one"]}}'
    original = [
        {"role": "system", "content": "return JSON"},
        {"role": "assistant", "content": '{"kind":"execute"}'},
        {"role": "tool", "content": observation},
        {"role": "user", "content": '{"node":{"node_id":"node-002"}}'},
    ]

    await model("node-002", original)

    sent = client.calls[0][0]
    assert all(message.role != "tool" for message in sent)
    assert sent[2].role == "user"
    header, content = sent[2].content.split("\n", 1)
    assert header == "GRAPH_TOOL_OBSERVATION"
    assert content == observation
    assert original[2] == {"role": "tool", "content": observation}


def test_graph_route_instructions_expose_bounded_autonomy_contract() -> None:
    instructions = graph_route_instructions()

    assert "process_start" in instructions
    assert "run_probe" in instructions
    assert "submit_proof" in instructions
    assert "paired control and exploit steps labeled evidence_role" in instructions
    assert "server_side_template_injection/template_injection aliases" in instructions
    assert "local_file_inclusion, arbitrary_file_read, and file_read aliases" in instructions
    assert "new SQL error" in instructions
    assert "Unsupported claims remain candidates" in instructions
    assert "XSS requires dom_execution browser evidence" in instructions
    assert "Never treat model text" in instructions


def test_graph_route_instructions_omit_flag_tool_for_ordinary_assessment() -> None:
    instructions = graph_route_instructions(flag_objective=False)

    assert "validate_poc" in instructions
    assert "capture_flag" not in instructions
    assert "submit_proof" not in instructions
    assert "persisted confirmed finding" in instructions
    assert "bounded negative coverage" in instructions
    assert "capture_flag" in graph_route_instructions()


def test_authenticated_graph_instructions_match_managed_http_capabilities() -> None:
    instructions = graph_route_instructions(
        authenticated=True,
        identity_alias="analyst",
    )

    assert "managed HTTP identity 'analyst'" in instructions
    assert "Available execute tools are http_request and capture_flag" in instructions
    assert "Never provide Authorization, Cookie" in instructions
    for unavailable in (
        "run_probe",
        "validate_poc",
        "run_command",
        "run_python",
        "process_start",
        "process_read",
        "process_write",
        "process_stop",
    ):
        assert unavailable not in instructions

    ordinary = graph_route_instructions(
        flag_objective=False,
        authenticated=True,
        identity_alias="analyst",
    )
    assert "Available execute tools are http_request." in ordinary
    assert "capture_flag" not in ordinary
    with pytest.raises(ValueError, match="identity alias"):
        graph_route_instructions(authenticated=True)


def test_graph_selector_preserves_all_ready_profile_routes(
    tmp_path: Path,
) -> None:
    config = tmp_path / "models.yaml"
    config.write_text(
        """
profiles:
  test-portfolio:
    default_tier: mid
    routes:
      mid:
        - provider: ollama
          model: primary
          base_url: http://127.0.0.1:11434/v1
          api_key_required: false
        - provider: lmstudio
          model: continuity
          base_url: http://127.0.0.1:1234/v1
          api_key_required: false
""".lstrip(),
        encoding="utf-8",
    )
    client = RecordingClient()

    endpoints = select_graph_model_portfolio(
        AIWebAgentSettings(
            model_config=config,
            model_profile="test-portfolio",
            model_client=client,
        )
    )

    assert [endpoint.label for endpoint in endpoints] == [
        "ollama/primary",
        "lmstudio/continuity",
    ]
    assert all(endpoint.client is client for endpoint in endpoints)


def test_role_model_policies_are_independent_and_prefer_distinct_routes() -> None:
    first_client = RecordingClient()
    second_client = RecordingClient()
    primary = GraphModelEndpoint(client=first_client, route=_route())
    secondary = GraphModelEndpoint(
        client=second_client,
        route=replace(
            _route(),
            provider="lmstudio",
            model="specialist-model",
            base_url="http://127.0.0.1:1234/v1",
            ordinal=2,
        ),
    )

    policies = accounted_graph_role_model_policies(
        endpoints=(primary, secondary),
        audit=RecordingAudit(),
        engagement_id=ENGAGEMENT_ID,
    )
    coordinator = policies[graph_role_model_policy_key(GraphAgentRole.COORDINATOR)]
    discovery = policies[graph_role_model_policy_key(GraphAgentRole.DISCOVERY)]

    assert coordinator is not discovery
    assert coordinator.active_endpoint.label == "ollama/test-model"
    assert discovery.active_endpoint.label == "lmstudio/specialist-model"
    assert coordinator.endpoints != discovery.endpoints
