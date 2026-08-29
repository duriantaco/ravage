# ruff: noqa: TC003

from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    ChatMessage,
    ModelReply,
)
from ravage.agent_core.autonomous_graph import remote_production
from ravage.agent_core.autonomous_graph.config import graph_config_for_budget
from ravage.agent_core.autonomous_graph.model_bridge import GraphModelEndpoint
from ravage.agent_core.autonomous_graph.models import GraphObjective
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
)
from ravage.agent_core.autonomous_graph.remote_production import (
    RemoteGraphProductionError,
    run_remote_http_graph_route,
)
from ravage.agent_core.autonomous_graph.run_store import ActionLifecycle, RunStore
from ravage.agent_core.autonomous_graph.scoped_http import (
    ScopedHttpTransportRequest,
    ScopedHttpTransportResponse,
)
from ravage.model_core.providers import ResolvedModelRoute
from ravage.traffic.manifest import read_traffic_manifest
from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicyController
from ravage.traffic.store import TrafficStore

TARGET_URL = "https://authorized.example/app"
TARGET_ADDRESS = "203.0.113.50"
ENGAGEMENT_ID = UUID("77777777-7777-4777-8777-777777777777")
DEFAULT_NODE_COUNT = 2


class RemoteFixtureClient:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.turns: dict[str, int] = {}
        self.investigation_contexts: list[dict[str, object]] = []
        self._lock = threading.Lock()

    def complete(
        self,
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        del route
        context = json.loads(
            next(
                message.content
                for message in reversed(messages)
                if message.role == "user" and '"node"' in message.content
            )
        )
        node_id = str(context["node"]["node_id"])
        node_name = str(context["node"]["name"])
        investigation = context["investigation"]
        assert isinstance(investigation, dict)
        active_children = [
            item for item in context["graph"]["active_nodes"] if item["parent_id"] == node_id
        ]
        with self._lock:
            turn = self.turns.get(node_id, 0)
            self.turns[node_id] = turn + 1
            self.calls.append(node_id)
            self.investigation_contexts.append(investigation)
        if node_name == "remote-http-coordinator" and active_children:
            action = {
                "kind": "wait",
                "payload": {"timeout_seconds": 0},
                "rationale": "wait for the scoped specialist",
            }
        elif node_name.startswith("remote-http-specialist") and turn == 0:
            action = {
                "kind": "execute",
                "payload": {
                    "tool": "http_request",
                    "arguments": {
                        "method": "GET",
                        "path": "/app/status",
                    },
                    "expected_signal": "authorized target response",
                },
                "rationale": "one bounded request",
            }
        else:
            action = {
                "kind": "finish",
                "payload": {
                    "summary": "bounded HTTP route complete",
                    "evidence_refs": [],
                },
                "rationale": "close finite work",
            }
        return ModelReply(
            content=json.dumps(action),
            cost_usd=0.0,
            usage_reported=True,
            cost_known=True,
        )


class RecordingTransport:
    def __init__(
        self,
        *,
        runtime_manifest_identity: str = "tests.remote.recording-transport:v1",
    ) -> None:
        self.runtime_manifest_identity = runtime_manifest_identity
        self.calls: list[ScopedHttpTransportRequest] = []

    def send(
        self,
        request: ScopedHttpTransportRequest,
    ) -> ScopedHttpTransportResponse:
        self.calls.append(request)
        return ScopedHttpTransportResponse(
            status=200,
            url=request.url,
            headers={"Content-Type": "text/plain"},
            body=b"authorized response",
            elapsed_ms=5,
        )


def _resolve_target_address(_host: str, _port: int) -> tuple[str, ...]:
    return (TARGET_ADDRESS,)


def _resolve_alternate_target_address(_host: str, _port: int) -> tuple[str, ...]:
    return ("203.0.113.51",)


def _route() -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="mid",
        selected_tier="mid",
        ordinal=1,
        provider="ollama",
        model="remote-fixture",
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


def _write_brief(path: Path) -> None:
    path.write_text(
        f"""
engagement_id: "{ENGAGEMENT_ID}"
scope:
  in_scope:
    - "{TARGET_URL}"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "web_application_assessment"
budget:
  max_cost_usd: 2.0
  max_runtime_min: 10
context:
  description: "Explicitly authorized remote web assessment."
""".lstrip(),
        encoding="utf-8",
    )


def _settings(tmp_path: Path, client: RemoteFixtureClient) -> AIWebAgentSettings:
    return AIWebAgentSettings(
        db_path=tmp_path / "audit.db",
        model_client=client,
        allow_remote_target=True,
    )


def test_remote_route_executes_only_scoped_http_and_persists_receipts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    workspace = tmp_path / "workspace"
    _write_brief(brief_path)
    client = RemoteFixtureClient()
    monkeypatch.setattr(
        remote_production,
        "select_graph_model_portfolio",
        lambda _settings: (
            GraphModelEndpoint(
                client=client,
                route=_route(),
            ),
        ),
    )
    transport = RecordingTransport()

    result = run_remote_http_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=_settings(tmp_path, client),
        workspace_dir=workspace,
        config=graph_config_for_budget(
            8,
            operational_profile=GraphOperationalProfileName.LOW_NOISE,
        ),
        transport=transport,
        resolver=_resolve_target_address,
    )

    receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    traffic_manifest = read_traffic_manifest(workspace)
    traffic_exchanges = TrafficStore.open(workspace).exchanges()
    http_state = json.loads((workspace / "remote-http-state.json").read_text(encoding="utf-8"))
    belief_state = json.loads(
        (workspace / "investigation-beliefs.json").read_text(encoding="utf-8")
    )
    assert result.resumed is False
    assert result.target_requests == 1
    assert len(transport.calls) == 1
    assert transport.calls[0].url == "https://authorized.example/app/status"
    assert receipt["capabilities"] == ["http_request"]
    assert receipt["ownership_epoch"] > 0
    assert receipt["ownership_release_status"] == "guarded_pending_release"
    assert receipt["shell_enabled"] is False
    assert receipt["browser_enabled"] is False
    assert receipt["operational_profile"]["name"] == "low-noise"
    assert receipt["traffic"] == result.traffic
    assert result.traffic["status"] == "completed"
    assert result.traffic["agent_http_exchange_count"] == 1
    assert traffic_manifest.completed_at
    assert len(traffic_exchanges) == 1
    assert traffic_exchanges[0].source == "agent_http"
    assert traffic_exchanges[0].source_observation_id.startswith("http:obs-")
    assert http_state["request_count"] == 1
    assert (workspace / "remote-graph-manifest.json").is_file()
    assert (workspace / "remote-runtime-policy-manifest.json").is_file()
    assert (workspace / "remote-evidence-blackboard.json").is_file()
    assert belief_state["version"] == 1
    assert client.investigation_contexts
    assert all("belief" in context for context in client.investigation_contexts)
    run_store = RunStore.open(workspace / "graph-run-store.sqlite3")
    durable = run_store.recovery_snapshot("workspace:autonomous-graph")
    assert durable.lease is None
    assert len(durable.actions) == 1
    assert durable.actions[0].lifecycle is ActionLifecycle.SETTLED


def test_remote_success_receipt_failure_emits_epoch_scoped_error_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    workspace = tmp_path / "workspace"
    _write_brief(brief_path)
    client = RemoteFixtureClient()
    monkeypatch.setattr(
        remote_production,
        "select_graph_model_portfolio",
        lambda _settings: (GraphModelEndpoint(client=client, route=_route()),),
    )
    write_receipt = remote_production._write_remote_receipt  # noqa: SLF001
    failure_message = "synthetic remote receipt failure"

    def fail_success_receipt(path: Path, **kwargs: object) -> None:
        if kwargs.get("run_error") is None:
            raise OSError(failure_message)
        write_receipt(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(remote_production, "_write_remote_receipt", fail_success_receipt)

    with pytest.raises(OSError, match=failure_message):
        run_remote_http_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            settings=_settings(tmp_path, client),
            workspace_dir=workspace,
            config=graph_config_for_budget(
                8,
                operational_profile=GraphOperationalProfileName.LOW_NOISE,
            ),
            transport=RecordingTransport(),
            resolver=_resolve_target_address,
        )

    immutable_paths = tuple(workspace.glob("remote-graph-receipt.epoch-*.error.json"))
    assert len(immutable_paths) == 1
    failure = json.loads(immutable_paths[0].read_text(encoding="utf-8"))
    assert failure["status"] == "error"
    assert failure["error_type"] == "OSError"
    assert failure["traffic"]["status"] == "completed"


def test_terminal_remote_graph_resumes_without_replaying_target_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    workspace = tmp_path / "workspace"
    _write_brief(brief_path)
    client = RemoteFixtureClient()
    monkeypatch.setattr(
        remote_production,
        "select_graph_model_portfolio",
        lambda _settings: (
            GraphModelEndpoint(
                client=client,
                route=_route(),
            ),
        ),
    )
    config = graph_config_for_budget(
        8,
        operational_profile=GraphOperationalProfileName.LOW_NOISE,
    )
    first_transport = RecordingTransport()
    run_remote_http_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=_settings(tmp_path, client),
        workspace_dir=workspace,
        config=config,
        transport=first_transport,
        resolver=_resolve_target_address,
    )
    resumed_transport = RecordingTransport()

    resumed = run_remote_http_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=_settings(tmp_path, client),
        workspace_dir=workspace,
        config=config,
        transport=resumed_transport,
        resolver=_resolve_target_address,
    )

    assert resumed.resumed is True
    assert resumed.target_requests == 1
    assert resumed.traffic["resumed"] is True
    assert resumed.traffic["agent_http_exchange_count"] == 1
    assert resumed_transport.calls == []


def test_remote_resume_rejects_changed_declared_transport_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    workspace = tmp_path / "workspace"
    _write_brief(brief_path)
    client = RemoteFixtureClient()
    monkeypatch.setattr(
        remote_production,
        "select_graph_model_portfolio",
        lambda _settings: (GraphModelEndpoint(client=client, route=_route()),),
    )
    config = graph_config_for_budget(
        8,
        operational_profile=GraphOperationalProfileName.LOW_NOISE,
    )
    first_identity = "tests.remote.transport:route-a:do-not-persist"
    run_remote_http_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=_settings(tmp_path, client),
        workspace_dir=workspace,
        config=config,
        transport=RecordingTransport(runtime_manifest_identity=first_identity),
        resolver=_resolve_target_address,
    )
    calls_after_first = len(client.calls)
    changed_transport = RecordingTransport(
        runtime_manifest_identity="tests.remote.transport:route-b"
    )

    with pytest.raises(RuntimeError, match="runtime policy manifest does not match"):
        run_remote_http_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            settings=_settings(tmp_path, client),
            workspace_dir=workspace,
            config=config,
            transport=changed_transport,
            resolver=_resolve_target_address,
        )

    assert len(client.calls) == calls_after_first
    assert changed_transport.calls == []
    assert first_identity not in (
        workspace / "remote-runtime-policy-manifest.json"
    ).read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_remote_failure_receipt_is_epoch_scoped_and_does_not_mask_error(
    tmp_path: Path,
) -> None:
    ownership_epoch = 9
    profile = remote_production.graph_operational_profile(
        GraphOperationalProfileName.STANDARD,
        roe_max_rps=5,
        max_total_requests=10,
    )
    ownership = type("Owned", (), {"assert_owned": lambda _self: None})()
    receipt_path = tmp_path / "remote-graph-receipt.json"

    await remote_production._publish_remote_failure_receipts(  # noqa: SLF001
        receipt_path=receipt_path,
        result=None,
        run_error=RuntimeError("synthetic remote failure"),
        profile=profile,
        ownership=ownership,
        ownership_epoch=ownership_epoch,
        owner_id="remote-http:123:ownerxyz",
    )

    shared = json.loads(receipt_path.read_text(encoding="utf-8"))
    immutable_paths = await asyncio.to_thread(
        lambda: tuple(tmp_path.glob("remote-graph-receipt.epoch-*.error.json"))
    )
    assert shared["status"] == "error"
    assert shared["ownership_epoch"] == ownership_epoch
    assert shared["ownership_release_status"] == "guarded_failure_pending_release"
    assert len(immutable_paths) == 1


def test_remote_runtime_policy_binds_full_scope_and_proof_setting(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    brief_path.write_text(
        brief_path.read_text(encoding="utf-8").replace(
            "  out_of_scope: []",
            '  out_of_scope:\n    - "https://blocked.example"',
        ),
        encoding="utf-8",
    )
    brief = remote_production.load_engagement_brief(brief_path)
    profile = remote_production.graph_operational_profile(
        GraphOperationalProfileName.STANDARD,
        roe_max_rps=brief.roe.max_rps,
        max_total_requests=10,
    )
    settings = _settings(tmp_path, RemoteFixtureClient())
    policy = remote_production._remote_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=settings,
        profile=profile,
        transport=None,
        resolver=None,
    )
    changed = remote_production._remote_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=replace(settings, proof_recognition_enabled=True),
        profile=profile,
        transport=None,
        resolver=None,
    )

    assert policy["scope"]["out_of_scope"] == ["https://blocked.example"]  # type: ignore[index]
    assert policy["proof_recognition_enabled"] is False
    assert changed["proof_recognition_enabled"] is True


def test_remote_runtime_policy_distinguishes_named_callable_resolvers(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    brief = remote_production.load_engagement_brief(brief_path)
    profile = remote_production.graph_operational_profile(
        GraphOperationalProfileName.STANDARD,
        roe_max_rps=brief.roe.max_rps,
        max_total_requests=10,
    )
    settings = _settings(tmp_path, RemoteFixtureClient())

    first = remote_production._remote_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=settings,
        profile=profile,
        transport=None,
        resolver=_resolve_target_address,
    )
    second = remote_production._remote_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=settings,
        profile=profile,
        transport=None,
        resolver=_resolve_alternate_target_address,
    )

    assert first["resolver_identity"] != second["resolver_identity"]
    assert "builtins.function" not in json.dumps((first, second), sort_keys=True)


def test_remote_custom_components_without_stable_identity_fail_closed(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    brief = remote_production.load_engagement_brief(brief_path)
    profile = remote_production.graph_operational_profile(
        GraphOperationalProfileName.STANDARD,
        roe_max_rps=brief.roe.max_rps,
        max_total_requests=10,
    )
    settings = _settings(tmp_path, RemoteFixtureClient())

    with pytest.raises(RuntimeError, match="runtime_manifest_identity"):
        remote_production._remote_execution_policy(  # noqa: SLF001
            brief=brief,
            settings=settings,
            profile=profile,
            transport=object(),
            resolver=None,
        )
    with pytest.raises(RuntimeError, match="runtime_manifest_identity"):
        remote_production._remote_execution_policy(  # noqa: SLF001
            brief=brief,
            settings=settings,
            profile=profile,
            transport=None,
            resolver=lambda _host, _port: (TARGET_ADDRESS,),
        )


@pytest.mark.asyncio
async def test_remote_resume_rejects_pending_model_billing_without_mutation(
    tmp_path: Path,
) -> None:
    objective = GraphObjective.create(
        family="web_application_assessment",
        instruction="Assess the authorized HTTP surface",
        endpoint="/app",
        strategy="scoped_http_evidence_loop",
        expected_signal="target-observed HTTP evidence",
    )
    objectives = (objective,)
    root = remote_production._remote_root_objective(objectives)  # noqa: SLF001
    config = graph_config_for_budget(8)
    expected = remote_production._expected_manifest(  # noqa: SLF001
        target_url=TARGET_URL,
        scope=(TARGET_URL,),
        config=config,
        root_objective=root,
        objectives=objectives,
    )
    state_path = tmp_path / "remote-graph-state.json"
    manifest_path = tmp_path / "remote-graph-manifest.json"
    coordinator, resumed = await remote_production._open_remote_coordinator(  # noqa: SLF001
        state_path=state_path,
        manifest_path=manifest_path,
        expected=expected,
        config=config,
        root_objective=root,
        objectives=objectives,
        available_model_routes=1,
    )
    assert resumed is False
    await coordinator.begin_model_request(coordinator.state.root_node_id)
    persisted_before = state_path.read_bytes()

    with pytest.raises(RemoteGraphProductionError, match="durable billing reconciliation"):
        await remote_production._open_remote_coordinator(  # noqa: SLF001
            state_path=state_path,
            manifest_path=manifest_path,
            expected=expected,
            config=config,
            root_objective=root,
            objectives=objectives,
            available_model_routes=1,
        )

    assert state_path.read_bytes() == persisted_before


def test_remote_graph_defaults_to_one_specialist_without_cost_reservations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    coordinator_client = RemoteFixtureClient()
    specialist_client = RemoteFixtureClient()
    monkeypatch.setattr(
        remote_production,
        "select_graph_model_portfolio",
        lambda _settings: (
            GraphModelEndpoint(client=coordinator_client, route=_route()),
            GraphModelEndpoint(
                client=specialist_client,
                route=replace(
                    _route(),
                    provider="lmstudio",
                    model="remote-specialist-fixture",
                    base_url="http://127.0.0.1:1234/v1",
                    ordinal=2,
                ),
            ),
        ),
    )

    workspace = tmp_path / "workspace"
    result = run_remote_http_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=_settings(tmp_path, coordinator_client),
        workspace_dir=workspace,
        config=graph_config_for_budget(8),
        transport=RecordingTransport(),
        resolver=_resolve_target_address,
    )

    assert "node-001" in coordinator_client.calls
    assert "node-002" not in coordinator_client.calls
    assert specialist_client.calls
    assert set(specialist_client.calls) == {"node-002"}
    assert result.graph.race_groups == {}
    assert len(result.graph.nodes) == DEFAULT_NODE_COUNT

    resumed = run_remote_http_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        settings=_settings(tmp_path, coordinator_client),
        workspace_dir=workspace,
        config=graph_config_for_budget(8),
        transport=RecordingTransport(),
        resolver=_resolve_target_address,
    )

    assert resumed.resumed is True
    assert resumed.graph.race_groups == {}
    assert len(resumed.graph.nodes) == DEFAULT_NODE_COUNT


def test_remote_route_requires_explicit_authorization(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)

    with pytest.raises(RemoteGraphProductionError, match="explicit"):
        run_remote_http_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            settings=AIWebAgentSettings(
                db_path=tmp_path / "audit.db",
                allow_remote_target=False,
            ),
            workspace_dir=tmp_path / "workspace",
            config=graph_config_for_budget(8),
        )


def test_remote_route_binds_the_existing_whole_run_traffic_policy(tmp_path: Path) -> None:
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=5),
    )
    settings = AIWebAgentSettings(traffic_policy_reference=policy.to_reference())

    bound = remote_production._remote_traffic_policy(
        settings,
        target_url=TARGET_URL,
    )

    assert bound is not None
    assert bound.state_path == policy.state_path


def test_low_noise_remote_graph_rejects_a_missing_whole_run_policy() -> None:
    with pytest.raises(RemoteGraphProductionError, match="requires an existing"):
        remote_production._remote_traffic_policy(
            AIWebAgentSettings(traffic_policy_mode="low-noise"),
            target_url=TARGET_URL,
        )


def test_remote_runtime_policy_binds_the_exact_traffic_ledger(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    brief = remote_production.load_engagement_brief(brief_path)
    profile = remote_production.graph_operational_profile(
        GraphOperationalProfileName.LOW_NOISE,
        roe_max_rps=brief.roe.max_rps,
        max_total_requests=5,
    )
    first = TrafficPolicyController.open(
        tmp_path / "first-traffic.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=5),
    )
    second = TrafficPolicyController.open(
        tmp_path / "second-traffic.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=5),
    )

    first_policy = remote_production._remote_execution_policy(
        brief=brief,
        settings=AIWebAgentSettings(
            traffic_policy_mode="low-noise",
            traffic_policy_reference=first.to_reference(),
        ),
        profile=profile,
        transport=None,
        resolver=None,
        target_url=TARGET_URL,
    )
    second_policy = remote_production._remote_execution_policy(
        brief=brief,
        settings=AIWebAgentSettings(
            traffic_policy_mode="low-noise",
            traffic_policy_reference=second.to_reference(),
        ),
        profile=profile,
        transport=None,
        resolver=None,
        target_url=TARGET_URL,
    )

    assert first_policy["traffic_policy"] != second_policy["traffic_policy"]
