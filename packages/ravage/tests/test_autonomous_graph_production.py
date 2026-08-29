from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    ChatMessage,
    ModelReply,
)
from ravage.agent_core.autonomous_graph import production
from ravage.agent_core.autonomous_graph.model_bridge import GraphModelEndpoint
from ravage.agent_core.autonomous_graph.models import GraphObjective
from ravage.agent_core.autonomous_graph.production import (
    PersistentAgentActionCall,
    run_autonomous_graph_route,
)
from ravage.agent_core.autonomous_graph.run_store import RunStore
from ravage.agent_core.autonomous_graph.runtime import RuntimeCleanupReceipt
from ravage.agent_core.autonomous_graph.traffic_lifecycle import GraphTrafficLifecycle
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
    FrontierObjective,
)
from ravage.agent_core.frontier_shared_runtime import SharedToolRuntime
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.auth.redaction import AuthArtifactRedactor
from ravage.auth.secrets import SecretValue
from ravage.model_core.providers import ResolvedModelRoute
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import FakeToolRuntime, NoProcessToolRuntime
from ravage.traffic.contracts import build_captured_http_exchange
from ravage.traffic.manifest import read_traffic_manifest
from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicyController
from ravage.traffic.recorders import ProbeTrafficRecorder

TARGET_URL = "http://127.0.0.1:8765"
ENGAGEMENT_ID = UUID("99999999-9999-4999-9999-999999999999")
BASE_REQUESTS = 40
BASE_COST_USD = 0.5
ENGAGEMENT_COST_USD = 3.0
MODEL_COST_USD = 0.1
EXPECTED_GRAPH_REQUESTS = 3
ROUTE_RUN_COUNT = 2
INVESTIGATION_CELLS = 2


class VerifiedFakeToolRuntime(FakeToolRuntime):
    network_isolation_verified = True

    def __init__(
        self,
        *,
        runtime_manifest_identity: str = "tests.local.verified-fake-runtime:v1",
    ) -> None:
        super().__init__()
        self.runtime_manifest_identity = runtime_manifest_identity
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


class FakeProcessRuntime:
    network_isolation_verified = True

    def __init__(self) -> None:
        self.close_count = 0

    def close(self) -> RuntimeCleanupReceipt:
        self.close_count += 1
        return RuntimeCleanupReceipt(
            verified=True,
            processes_before=(),
            processes_after=(),
            backend={"verified": True, "kind": "fake"},
        )


class FakeGraphAuthentication:
    def __init__(
        self,
        identity: str,
        *,
        sensitive_value: str = "not-policy-material",
        traffic_policy: TrafficPolicyController | None = None,
    ) -> None:
        self.identity = identity
        self.secret = sensitive_value
        self.traffic_policy = traffic_policy
        self.redactor = AuthArtifactRedactor((SecretValue(sensitive_value),))
        self.request_gate: Callable[[str, str], None] | None = None

    def configure_request_gate(
        self,
        gate: Callable[[str, str], None] | None,
    ) -> None:
        self.request_gate = gate

    def assert_traffic_policy(self, candidate: TrafficPolicyController | None) -> None:
        if self.traffic_policy is None or candidate is not self.traffic_policy:
            raise ValueError("traffic policy binding mismatch")

    def session_for_probe(self, *, timeout_seconds: int = 10) -> FakeGraphAuthentication:
        del timeout_seconds
        return self

    def retire_probe_session(self, session: object) -> None:
        assert session is self

    def request(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        message = "policy tests do not dispatch HTTP"
        raise AssertionError(message)

    def redact_text(self, value: str) -> str:
        return self.redactor.redact_text(value)

    def contains_secret(self, value: str) -> bool:
        return self.redactor.contains_secret(value)

    def redact_protocol(
        self,
        value: object,
        *,
        protected_keys: object,
        protected_field_values: object,
    ) -> object:
        return self.redactor.redact_protocol(
            value,
            protected_keys=protected_keys,  # type: ignore[arg-type]
            protected_field_values=protected_field_values,  # type: ignore[arg-type]
        )


class GraphFixtureClient:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def complete(
        self,
        *,
        messages: list[ChatMessage],
        route: ResolvedModelRoute,
    ) -> ModelReply:
        del route
        context = json.loads(
            next(message.content for message in reversed(messages) if message.role == "user")
        )
        node_id = str(context["node"]["node_id"])
        active_children = [
            node for node in context["graph"]["active_nodes"] if node["parent_id"] == node_id
        ]
        with self._lock:
            self.calls.append(node_id)
        if active_children:
            action = {
                "kind": "wait",
                "payload": {"timeout_seconds": 0},
                "rationale": "wait for the seeded specialist",
            }
        else:
            action = {
                "kind": "finish",
                "payload": {
                    "summary": "bounded specialist work complete",
                    "evidence_refs": [],
                },
                "rationale": "return bounded control",
            }
        return ModelReply(
            content=json.dumps(action),
            cost_usd=MODEL_COST_USD,
            usage_reported=True,
            cost_known=True,
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
  - "capture_flag"
budget:
  max_cost_usd: {ENGAGEMENT_COST_USD}
  max_runtime_min: 10
context:
  description: "Authorized local web security exercise"
""".lstrip(),
        encoding="utf-8",
    )


def _base(
    tmp_path: Path,
    *,
    authenticated_identity: str = "",
) -> BaseRouteOutcome:
    path = tmp_path / "base-working-state.json"
    state = AgentState(
        turn=BASE_REQUESTS,
        facts=["search form accepts a query parameter"],
        signals={"endpoints": ["/search"], "parameters": ["query"]},
    )
    if authenticated_identity:
        state.surface["authenticated_identity"] = authenticated_identity
    save_agent_state(
        path,
        target_url=TARGET_URL,
        state=state,
    )
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=BASE_REQUESTS,
        state_digest=hashlib.sha256(path.read_bytes()).hexdigest(),
        state_ref=str(path),
        cost_usd=BASE_COST_USD,
    )


def _objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_differential",
        endpoint="/search",
        inputs=("query",),
        payload_class="specialist:sqli_differential",
        expected_signal="target-observed SQL differential or bounded disproof",
    )


def _route() -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="mid",
        selected_tier="mid",
        ordinal=1,
        provider="ollama",
        model="fixture-model",
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


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    client: GraphFixtureClient,
    process_runtimes: list[FakeProcessRuntime],
    secondary_client: GraphFixtureClient | None = None,
) -> None:
    def make_process_runtime(**_kwargs: object) -> FakeProcessRuntime:
        runtime = FakeProcessRuntime()
        process_runtimes.append(runtime)
        return runtime

    monkeypatch.setattr(production, "_make_process_runtime", make_process_runtime)
    endpoints = [GraphModelEndpoint(client=client, route=_route())]
    if secondary_client is not None:
        endpoints.append(
            GraphModelEndpoint(
                client=secondary_client,
                route=replace(
                    _route(),
                    provider="lmstudio",
                    model="specialist-fixture-model",
                    base_url="http://127.0.0.1:1234/v1",
                    ordinal=2,
                ),
            )
        )
    monkeypatch.setattr(
        production,
        "select_graph_model_portfolio",
        lambda _settings: tuple(endpoints),
    )
    monkeypatch.setattr(
        production,
        "reverify_tool_runtime_cleanup",
        lambda _runtime: (
            {
                "cleanup": {
                    "verified": True,
                    "status": "verified",
                }
            },
        ),
    )


def test_authenticated_graph_accepts_only_the_explicit_no_process_runtime() -> None:
    runtime = SharedToolRuntime(NoProcessToolRuntime(reason="managed HTTP only"))

    production._require_verified_tool_runtime(runtime, authenticated=True)
    with pytest.raises(production.GraphProductionError, match="verified target-scoped"):
        production._require_verified_tool_runtime(runtime, authenticated=False)


def test_graph_rejects_frozen_base_identity_mismatch_before_model_or_graph_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    route_dir = tmp_path / "graph-route"
    model_selection_calls: list[object] = []

    def select_models(settings: object) -> tuple[()]:
        model_selection_calls.append(settings)
        return ()

    monkeypatch.setattr(production, "select_graph_model_portfolio", select_models)

    with pytest.raises(production.GraphProductionError, match="does not match"):
        run_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=_base(tmp_path, authenticated_identity="analyst"),
            settings=AIWebAgentSettings(
                authentication=FakeGraphAuthentication("administrator"),  # type: ignore[arg-type]
            ),
            workspace_dir=route_dir,
            objectives=(_objective(),),
        )

    assert model_selection_calls == []
    assert not route_dir.exists()


def test_graph_rejects_authenticated_resume_without_auth_before_model_or_graph_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    route_dir = tmp_path / "graph-route"
    route_dir.mkdir()
    resumed_state = AgentState()
    resumed_state.surface["authenticated_identity"] = "analyst"
    save_agent_state(
        route_dir / "working_state.json",
        target_url=TARGET_URL,
        state=resumed_state,
    )
    model_selection_calls: list[object] = []

    def select_models(settings: object) -> tuple[()]:
        model_selection_calls.append(settings)
        return ()

    monkeypatch.setattr(production, "select_graph_model_portfolio", select_models)

    with pytest.raises(production.GraphProductionError, match="without managed authentication"):
        run_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=_base(tmp_path),
            settings=AIWebAgentSettings(),
            workspace_dir=route_dir,
            objectives=(_objective(),),
        )

    assert model_selection_calls == []
    assert not (route_dir / "graph-run-store.sqlite3").exists()


@pytest.mark.parametrize(
    ("relative_path", "payload"),
    [
        (
            "sessions/node-001.jsonl",
            '{"role":"assistant","content":"legacy not-policy-material"}\n',
        ),
        (
            "evidence-blackboard.json",
            '{"records":[{"observation":"legacy not-policy-material"}]}\n',
        ),
    ],
)
def test_graph_rejects_tainted_restored_artifacts_before_model_or_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    payload: str,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    route_dir = tmp_path / "graph-route"
    artifact = route_dir / relative_path
    artifact.parent.mkdir(parents=True)
    artifact.write_text(payload, encoding="utf-8")
    model_selection_calls: list[object] = []

    def select_models(settings: object) -> tuple[()]:
        model_selection_calls.append(settings)
        return ()

    monkeypatch.setattr(production, "select_graph_model_portfolio", select_models)

    with pytest.raises(production.GraphProductionError, match="untrusted authentication"):
        run_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=_base(tmp_path, authenticated_identity="analyst"),
            settings=AIWebAgentSettings(
                authentication=FakeGraphAuthentication("analyst"),  # type: ignore[arg-type]
            ),
            workspace_dir=route_dir,
            objectives=(_objective(),),
        )

    assert model_selection_calls == []
    assert not (route_dir / "graph-run-store.sqlite3").exists()


def test_production_graph_uses_copied_state_exact_budget_and_cleanup(  # noqa: PLR0915
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base(tmp_path)
    frozen_before = Path(base.state_ref).read_bytes()
    runtime = VerifiedFakeToolRuntime()
    client = GraphFixtureClient()
    process_runtimes: list[FakeProcessRuntime] = []
    _install_fakes(
        monkeypatch,
        client=client,
        process_runtimes=process_runtimes,
    )
    real_http_executor = production.ScopedGraphHttpExecutor
    traffic_observers: list[object] = []

    def capture_http_executor(**kwargs: object) -> object:
        traffic_observers.append(kwargs.get("traffic_observer"))
        return real_http_executor(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(production, "ScopedGraphHttpExecutor", capture_http_executor)
    timeline: list[str] = []
    original_process_close = FakeProcessRuntime.close
    original_audit_close = production.ThreadOwnedAudit.close

    def tracked_process_close(runtime: FakeProcessRuntime) -> RuntimeCleanupReceipt:
        receipt = original_process_close(runtime)
        timeline.append("process_cleanup")
        return receipt

    def tracked_audit_close(audit: production.ThreadOwnedAudit) -> None:
        original_audit_close(audit)
        timeline.append("audit_cleanup")

    def record_event(event: object) -> None:
        assert isinstance(event, dict)
        if event.get("kind") == "autonomous_graph_finished":
            timeline.append("autonomous_graph_finished")

    monkeypatch.setattr(FakeProcessRuntime, "close", tracked_process_close)
    monkeypatch.setattr(production.ThreadOwnedAudit, "close", tracked_audit_close)
    route_dir = tmp_path / "graph-route"

    result = run_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=AIWebAgentSettings(
            workspace_dir=tmp_path / "base-workspace",
            tool_runtime=runtime,
            model_client=client,
            event_sink=record_event,
        ),
        workspace_dir=route_dir,
        objectives=(_objective(),),
    )

    assert Path(base.state_ref).read_bytes() == frozen_before
    assert (route_dir / "working_state.json").is_file()
    assert result.route_model_requests == EXPECTED_GRAPH_REQUESTS
    assert result.total_model_requests == BASE_REQUESTS + EXPECTED_GRAPH_REQUESTS
    assert result.route_cost_usd == pytest.approx(EXPECTED_GRAPH_REQUESTS * MODEL_COST_USD)
    assert result.graph.limits.max_cost_usd == ENGAGEMENT_COST_USD - BASE_COST_USD
    assert result.cleanup_verified is True
    assert result.investigation["enabled"] is True
    assert result.investigation["coverage_cells"] == INVESTIGATION_CELLS
    assert runtime.close_count == 1
    assert len(process_runtimes) == 1
    assert process_runtimes[0].close_count == 1
    receipt = json.loads((route_dir / "graph-route-receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "completed"
    assert receipt["ownership_epoch"] > 0
    assert receipt["ownership_release_status"] == "guarded_pending_release"
    assert receipt["process_cleanup"]["verified"] is True
    assert receipt["graph"]["investigation"]["enabled"] is True
    assert receipt["traffic"] == result.traffic
    assert result.traffic["status"] == "completed"
    assert result.traffic["agent_http_exchange_count"] == 0
    assert len(traffic_observers) == 1
    assert isinstance(traffic_observers[0], ProbeTrafficRecorder)
    assert read_traffic_manifest(route_dir).completed_at
    assert (
        json.loads((route_dir / "graph-http-state.json").read_text(encoding="utf-8"))[
            "request_count"
        ]
        == 0
    )
    assert (route_dir / "runtime-policy-manifest.json").is_file()
    run_store = RunStore.open(route_dir / "graph-run-store.sqlite3")
    assert run_store.recovery_snapshot("workspace:autonomous-graph").lease is None
    assert timeline[-3:] == [
        "process_cleanup",
        "audit_cleanup",
        "autonomous_graph_finished",
    ]


def test_authenticated_graph_never_constructs_or_attaches_process_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    client = GraphFixtureClient()
    process_runtimes: list[FakeProcessRuntime] = []
    _install_fakes(
        monkeypatch,
        client=client,
        process_runtimes=process_runtimes,
    )
    real_executor = production.EvidenceGraphExecutor
    attached_process_executors: list[object | None] = []

    def capture_executor(**kwargs: object) -> object:
        attached_process_executors.append(kwargs.get("process_executor"))
        return real_executor(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(production, "EvidenceGraphExecutor", capture_executor)
    base_settings = AIWebAgentSettings(
        workspace_dir=tmp_path / "base-workspace",
        tool_runtime=VerifiedFakeToolRuntime(),
        model_client=client,
    )
    traffic_policy = TrafficPolicyController.open(
        tmp_path / "authenticated-traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )
    settings = SimpleNamespace(
        **{
            **vars(base_settings),
            "authentication": FakeGraphAuthentication(
                "analyst",
                traffic_policy=traffic_policy,
            ),
        }
    )

    result = run_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=_base(tmp_path, authenticated_identity="analyst"),
        settings=settings,  # type: ignore[arg-type]
        workspace_dir=tmp_path / "authenticated-graph-route",
        objectives=(_objective(),),
    )

    assert process_runtimes == []
    assert attached_process_executors == [None]
    assert result.process_cleanup == {
        "verified": True,
        "processes_before": [],
        "processes_after": [],
        "backend": {
            "verified": True,
            "kind": "disabled",
            "reason": "managed_authentication_http_only",
        },
    }


def test_authenticated_graph_model_failure_never_persists_secret_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingClient(GraphFixtureClient):
        def complete(
            self,
            *,
            messages: list[ChatMessage],
            route: ResolvedModelRoute,
        ) -> ModelReply:
            del messages, route
            raise RuntimeError("provider exposed FLAG{not-policy-material}")

    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    client = FailingClient()
    _install_fakes(monkeypatch, client=client, process_runtimes=[])
    base_settings = AIWebAgentSettings(
        workspace_dir=tmp_path / "base-workspace",
        tool_runtime=VerifiedFakeToolRuntime(),
        model_client=client,
    )
    traffic_policy = TrafficPolicyController.open(
        tmp_path / "authenticated-failure-traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )
    settings = SimpleNamespace(
        **{
            **vars(base_settings),
            "authentication": FakeGraphAuthentication(
                "analyst",
                traffic_policy=traffic_policy,
            ),
        }
    )
    route_dir = tmp_path / "authenticated-graph-failure"

    run_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=_base(tmp_path, authenticated_identity="analyst"),
        settings=settings,  # type: ignore[arg-type]
        workspace_dir=route_dir,
        objectives=(_objective(),),
    )

    for artifact in route_dir.rglob("*"):
        if artifact.is_file():
            assert b"FLAG{not-policy-material}" not in artifact.read_bytes()
            assert b"provider exposed" not in artifact.read_bytes()


def test_authenticated_graph_rejects_base_without_identity_binding(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)

    with pytest.raises(production.GraphProductionError, match="without an authenticated identity"):
        run_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=_base(tmp_path),
            settings=AIWebAgentSettings(
                authentication=FakeGraphAuthentication("analyst"),  # type: ignore[arg-type]
            ),
            workspace_dir=tmp_path / "authenticated-graph-route",
            objectives=(_objective(),),
        )


def test_graph_workspace_failure_is_emitted_after_process_and_audit_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    client = GraphFixtureClient()
    process_runtimes: list[FakeProcessRuntime] = []
    _install_fakes(
        monkeypatch,
        client=client,
        process_runtimes=process_runtimes,
    )
    timeline: list[str] = []
    failure_message = "synthetic process cleanup failure"

    class FailingProcessRuntime(FakeProcessRuntime):
        def close(self) -> RuntimeCleanupReceipt:
            self.close_count += 1
            timeline.append("process_cleanup")
            raise OSError(failure_message)

    def make_failing_process_runtime(**_kwargs: object) -> FakeProcessRuntime:
        runtime = FailingProcessRuntime()
        process_runtimes.append(runtime)
        return runtime

    original_audit_close = production.ThreadOwnedAudit.close

    def tracked_audit_close(audit: production.ThreadOwnedAudit) -> None:
        original_audit_close(audit)
        timeline.append("audit_cleanup")

    events: list[dict[str, object]] = []

    def record_event(event: object) -> None:
        assert isinstance(event, dict)
        events.append(dict(event))
        kind = str(event.get("kind") or "")
        if kind.startswith("autonomous_graph_f") or kind.endswith("_cancelled"):
            timeline.append(kind)

    monkeypatch.setattr(production, "_make_process_runtime", make_failing_process_runtime)
    monkeypatch.setattr(production.ThreadOwnedAudit, "close", tracked_audit_close)

    with pytest.raises(OSError, match=failure_message):
        run_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=_base(tmp_path),
            settings=AIWebAgentSettings(
                workspace_dir=tmp_path / "base-workspace",
                tool_runtime=VerifiedFakeToolRuntime(),
                model_client=client,
                event_sink=record_event,
            ),
            workspace_dir=tmp_path / "graph-route",
            objectives=(_objective(),),
        )

    terminal_events = [
        event
        for event in events
        if event["kind"]
        in {
            "autonomous_graph_finished",
            "autonomous_graph_failed",
            "autonomous_graph_cancelled",
        }
    ]
    assert len(terminal_events) == 1
    assert terminal_events[0]["kind"] == "autonomous_graph_failed"
    terminal_payload = terminal_events[0]["payload"]
    assert isinstance(terminal_payload, dict)
    assert set(terminal_payload) == {"error_type", "graph_id", "traffic"}
    assert terminal_payload["error_type"] == "OSError"
    assert str(terminal_payload["graph_id"])
    traffic = terminal_payload["traffic"]
    assert isinstance(traffic, dict)
    assert traffic["status"] == "completed"
    assert timeline[-3:] == [
        "process_cleanup",
        "audit_cleanup",
        "autonomous_graph_failed",
    ]


def test_success_receipt_failure_emits_epoch_scoped_error_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base(tmp_path)
    runtime = VerifiedFakeToolRuntime()
    client = GraphFixtureClient()
    process_runtimes: list[FakeProcessRuntime] = []
    _install_fakes(
        monkeypatch,
        client=client,
        process_runtimes=process_runtimes,
    )
    route_dir = tmp_path / "graph-route"
    write_receipt = production._write_route_receipt  # noqa: SLF001
    failure_message = "synthetic receipt failure"

    def fail_success_receipt(path: Path, **kwargs: object) -> None:
        if kwargs.get("run_error") is None:
            raise OSError(failure_message)
        write_receipt(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(production, "_write_route_receipt", fail_success_receipt)

    with pytest.raises(OSError, match=failure_message):
        run_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                workspace_dir=tmp_path / "base-workspace",
                tool_runtime=runtime,
                model_client=client,
            ),
            workspace_dir=route_dir,
            objectives=(_objective(),),
        )

    immutable_paths = tuple(route_dir.glob("graph-route-receipt.epoch-*.error.json"))
    assert len(immutable_paths) == 1
    failure = json.loads(immutable_paths[0].read_text(encoding="utf-8"))
    assert failure["status"] == "error"
    assert failure["error_type"] == "OSError"
    assert failure["traffic"]["status"] == "completed"


def test_terminal_graph_resume_spends_zero_additional_model_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base(tmp_path)
    runtime = VerifiedFakeToolRuntime()
    client = GraphFixtureClient()
    process_runtimes: list[FakeProcessRuntime] = []
    _install_fakes(
        monkeypatch,
        client=client,
        process_runtimes=process_runtimes,
    )
    settings = AIWebAgentSettings(
        workspace_dir=tmp_path / "base-workspace",
        tool_runtime=runtime,
        model_client=client,
    )
    route_dir = tmp_path / "graph-route"
    first = run_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=settings,
        workspace_dir=route_dir,
        objectives=(_objective(),),
    )
    calls_after_first = len(client.calls)

    resumed = run_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=settings,
        workspace_dir=route_dir,
        objectives=(_objective(),),
    )

    assert calls_after_first == EXPECTED_GRAPH_REQUESTS
    assert len(client.calls) == calls_after_first
    assert resumed.route.resumed is True
    assert resumed.traffic["resumed"] is True
    assert resumed.traffic["agent_http_exchange_count"] == 0
    assert resumed.route_model_requests == first.route_model_requests
    assert resumed.route_cost_usd == first.route_cost_usd
    assert len(process_runtimes) == ROUTE_RUN_COUNT


def test_graph_resume_rejects_changed_declared_tool_runtime_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base(tmp_path)
    client = GraphFixtureClient()
    process_runtimes: list[FakeProcessRuntime] = []
    _install_fakes(
        monkeypatch,
        client=client,
        process_runtimes=process_runtimes,
    )
    route_dir = tmp_path / "graph-route"
    first_identity = "tests.local.runtime:network-policy-a:do-not-persist"
    run_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=AIWebAgentSettings(
            workspace_dir=tmp_path / "base-workspace",
            tool_runtime=VerifiedFakeToolRuntime(
                runtime_manifest_identity=first_identity,
            ),
            model_client=client,
        ),
        workspace_dir=route_dir,
        objectives=(_objective(),),
    )
    calls_after_first = len(client.calls)

    with pytest.raises(RuntimeError, match="runtime policy manifest does not match"):
        run_autonomous_graph_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                workspace_dir=tmp_path / "base-workspace",
                tool_runtime=VerifiedFakeToolRuntime(
                    runtime_manifest_identity="tests.local.runtime:network-policy-b",
                ),
                model_client=client,
            ),
            workspace_dir=route_dir,
            objectives=(_objective(),),
        )

    assert len(client.calls) == calls_after_first
    assert first_identity not in (route_dir / "runtime-policy-manifest.json").read_text(
        encoding="utf-8"
    )


def test_custom_tool_runtime_without_declared_identity_fails_closed(tmp_path: Path) -> None:
    class UndeclaredToolRuntime(FakeToolRuntime):
        network_isolation_verified = True

    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    brief = production.load_engagement_brief(brief_path)
    runtime = UndeclaredToolRuntime()

    with pytest.raises(RuntimeError, match="runtime_manifest_identity"):
        production._production_execution_policy(  # noqa: SLF001
            brief=brief,
            settings=AIWebAgentSettings(tool_runtime=runtime),
            config=production.GraphRouteConfig(),
            tool_runtime=runtime,
        )


def test_production_graph_routes_coordinator_and_specialist_to_distinct_models(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    primary = GraphFixtureClient()
    specialist = GraphFixtureClient()
    process_runtimes: list[FakeProcessRuntime] = []
    _install_fakes(
        monkeypatch,
        client=primary,
        secondary_client=specialist,
        process_runtimes=process_runtimes,
    )

    run_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=_base(tmp_path),
        settings=AIWebAgentSettings(
            workspace_dir=tmp_path / "base-workspace",
            tool_runtime=VerifiedFakeToolRuntime(),
            model_client=primary,
        ),
        workspace_dir=tmp_path / "graph-route",
        objectives=(_objective(),),
    )

    assert "node-001" in primary.calls
    assert "node-002" not in primary.calls
    assert specialist.calls == ["node-002"]


def test_optional_learning_failure_cannot_mask_route_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        production,
        "record_route_lessons",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("learning store unavailable")),
    )

    production._record_route_learning(  # noqa: SLF001 - integration boundary.
        tmp_path,
        memory_settings=None,
    )

    receipt = json.loads((tmp_path / "graph-learning-receipt.json").read_text(encoding="utf-8"))
    assert receipt == {
        "error_type": "OSError",
        "reason": "learning store unavailable",
        "status": "rejected",
        "version": 1,
    }


@pytest.mark.asyncio
async def test_failure_receipts_are_epoch_scoped_and_published_while_owned(
    tmp_path: Path,
) -> None:
    ownership_epoch = 7
    ownership = SimpleNamespace(assert_owned=lambda: None)

    await production._publish_route_failure_receipts(  # noqa: SLF001
        workspace_dir=tmp_path,
        route_result=None,
        process_cleanup={"verified": False},
        tool_cleanup=(),
        run_error=RuntimeError("synthetic route failure"),
        ownership=ownership,
        ownership_epoch=ownership_epoch,
        owner_id="local:123:ownerabc",
    )

    shared = json.loads((tmp_path / "graph-route-receipt.json").read_text(encoding="utf-8"))
    immutable_paths = await asyncio.to_thread(
        lambda: tuple(tmp_path.glob("graph-route-receipt.epoch-*.error.json"))
    )
    assert shared["status"] == "error"
    assert shared["error_type"] == "RuntimeError"
    assert shared["ownership_epoch"] == ownership_epoch
    assert shared["ownership_release_status"] == "guarded_failure_pending_release"
    assert len(immutable_paths) == 1


def test_runtime_policy_identity_binds_full_scope_and_safety_settings(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    brief_path.write_text(
        brief_path.read_text(encoding="utf-8").replace(
            "  out_of_scope: []",
            '  out_of_scope:\n    - "http://blocked.example"',
        ),
        encoding="utf-8",
    )
    brief = production.load_engagement_brief(brief_path)
    settings = AIWebAgentSettings(
        tool_runtime=VerifiedFakeToolRuntime(),
        proof_recognition_enabled=False,
    )
    policy = production._production_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=settings,
        config=production.GraphRouteConfig(),
        tool_runtime=settings.tool_runtime,
    )
    changed = production._production_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=replace(settings, proof_recognition_enabled=True),
        config=production.GraphRouteConfig(),
        tool_runtime=settings.tool_runtime,
    )

    assert policy["scope"]["out_of_scope"] == ["http://blocked.example"]  # type: ignore[index]
    assert policy["proof_recognition_enabled"] is False
    assert changed["proof_recognition_enabled"] is True
    assert "authentication" not in policy
    assert production._scope_policy_identity(brief.scope) != (TARGET_URL,)  # noqa: SLF001


def test_authenticated_runtime_policy_binds_alias_and_exposes_only_managed_http(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    brief = production.load_engagement_brief(brief_path)
    base_settings = AIWebAgentSettings(tool_runtime=VerifiedFakeToolRuntime())
    authentication = FakeGraphAuthentication("analyst")
    settings_payload = {**vars(base_settings), "authentication": authentication}
    settings = SimpleNamespace(**settings_payload)

    policy = production._production_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=settings,
        config=production.GraphRouteConfig(),
        tool_runtime=base_settings.tool_runtime,
    )
    _runtime_key, tool_policies, _role_policies = production._production_runtime_policy_components(  # noqa: SLF001
        authenticated=True,
    )

    assert policy["authentication"] == {
        "configured": True,
        "identity": "analyst",
        "transport": "managed_scoped_http",
    }
    assert authentication.secret not in json.dumps(policy, sort_keys=True)
    assert all(tools <= {"http_request", "capture_flag"} for tools in tool_policies.values())
    assert any("http_request" in tools for tools in tool_policies.values())
    for blocked in (
        "process_read",
        "process_start",
        "process_stop",
        "process_write",
        "run_command",
        "run_probe",
        "run_python",
        "validate_poc",
    ):
        assert all(blocked not in tools for tools in tool_policies.values())

    changed_payload = {
        **vars(base_settings),
        "authentication": FakeGraphAuthentication("administrator"),
    }
    changed = SimpleNamespace(**changed_payload)
    changed_policy = production._production_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=changed,
        config=production.GraphRouteConfig(),
        tool_runtime=base_settings.tool_runtime,
    )
    assert changed_policy != policy

    endpoint = GraphModelEndpoint(client=object(), route=_route())
    manifest_path = tmp_path / "runtime-policy-manifest.json"
    manifest = production.GraphRuntimeManifest.create(
        graph_id="authenticated-graph",
        execution_mode="local-target-scoped",
        model_policies={"coordinator": (endpoint,)},
        capabilities=tuple(
            production._graph_execution_tools(  # noqa: SLF001
                flag_objective=True,
                authenticated=True,
            )
        ),
        policy_payload={"execution_policy": policy},
        instructions="authenticated graph",
    )
    production.bind_runtime_manifest(manifest_path, expected=manifest, resumed=False)
    changed_manifest = production.GraphRuntimeManifest.create(
        graph_id="authenticated-graph",
        execution_mode="local-target-scoped",
        model_policies={"coordinator": (endpoint,)},
        capabilities=tuple(
            production._graph_execution_tools(  # noqa: SLF001
                flag_objective=True,
                authenticated=True,
            )
        ),
        policy_payload={"execution_policy": changed_policy},
        instructions="authenticated graph",
    )
    with pytest.raises(RuntimeError, match="does not match"):
        production.bind_runtime_manifest(
            manifest_path,
            expected=changed_manifest,
            resumed=True,
        )
    assert authentication.secret not in manifest_path.read_text(encoding="utf-8")


def test_non_flag_runtime_removes_flag_closure_and_releases_proof_reserve(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    brief = production.load_engagement_brief(brief_path)
    settings = AIWebAgentSettings(
        tool_runtime=VerifiedFakeToolRuntime(),
        proof_recognition_enabled=True,
    )
    config = production._route_config_for_mission(  # noqa: SLF001
        production.GraphRouteConfig(),
        flag_objective=False,
    )
    _runtime_key, tool_policies, _role_policies = production._production_runtime_policy_components(  # noqa: SLF001
        flag_objective=False,
    )
    policy = production._production_execution_policy(  # noqa: SLF001
        brief=brief,
        settings=settings,
        config=config,
        tool_runtime=settings.tool_runtime,
        flag_objective=False,
    )

    assert config.limits.proof_reserve_model_requests == 0
    assert all("capture_flag" not in tools for tools in tool_policies.values())
    assert policy["proof_recognition_enabled"] is False
    assert policy["mission"] == "vulnerability_assessment"


def test_persistent_action_call_executes_sql_probe_on_graph_scoped_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    query_url = f"{TARGET_URL}/search.php"
    polluted_url = f"{TARGET_URL}/graphql/"
    state = AgentState(
        surface={
            "endpoints": [
                {"url": polluted_url, "hints": ["query"], "priority": 100},
                {"url": query_url, "hints": ["query"], "priority": 18},
            ],
            "parameters": [
                {
                    "name": "transport",
                    "locations": [polluted_url],
                    "priority": 100,
                }
            ],
        },
        signals={
            "endpoints": [polluted_url, query_url],
            "parameters": ["transport", "filter", "email"],
            "forms": ['<form action=\\"search.php\\" method=\\"POST\\">'],
        },
    )
    original_surface = json.loads(json.dumps(state.surface))
    objective = GraphObjective.create(
        family="sql_injection",
        instruction="Calibrate the observed query contract",
        endpoint=query_url,
        inputs=("filter", "email"),
        strategy="sqli_differential",
        expected_signal="typed differential or bounded disproof",
    )
    coordinator = SimpleNamespace(
        state=SimpleNamespace(
            model_requests_started=3,
            nodes={"worker": SimpleNamespace(objective=objective)},
        )
    )
    captured: dict[str, AgentState] = {}
    authentication = object()

    def fake_execute_action(
        _action: dict[str, object],
        **kwargs: object,
    ) -> ActionResult:
        scoped_state = kwargs["state"]
        assert isinstance(scoped_state, AgentState)
        captured["state"] = scoped_state
        assert kwargs["authentication"] is authentication
        scoped_state.last_observation = {"observation_id": "obs-scoped"}
        scoped_state.signals["sql_constraints"] = ["filter blocks UNION"]
        return ActionResult(
            ok=True,
            observation="bounded SQL differential observed",
        )

    monkeypatch.setattr(production, "execute_action", fake_execute_action)
    workspace = AgentWorkspace.open(tmp_path / "graph-workspace")
    action_call = PersistentAgentActionCall(
        target_url=TARGET_URL,
        base_model_requests=BASE_REQUESTS,
        coordinator=coordinator,
        runtime=VerifiedFakeToolRuntime(),
        state=state,
        workspace=workspace,
        audit=object(),
        engagement_id=ENGAGEMENT_ID,
        proof_recognition_enabled=True,
        authentication=authentication,  # type: ignore[arg-type]
    )

    execution = action_call(
        node_id="worker",
        action={"action": "run_probe", "probe": "sqli_differential"},
        action_id="action-scoped",
    )

    scoped_state = captured["state"]
    assert scoped_state is not state
    assert polluted_url not in json.dumps(scoped_state.to_json())
    assert state.surface == original_surface
    assert state.turn == BASE_REQUESTS + 3
    assert state.last_observation == {"observation_id": "obs-scoped"}
    assert state.signals["sql_constraints"] == ["filter blocks UNION"]
    assert execution.observation_id == "obs-scoped"
    events = [
        json.loads(line) for line in workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert any(event["kind"] == "graph_probe_scope" for event in events)
    action_events = [
        event
        for event in events
        if event["kind"] in {"autonomous_graph_action_started", "autonomous_graph_action_finished"}
    ]
    assert [event["kind"] for event in action_events] == [
        "autonomous_graph_action_started",
        "autonomous_graph_action_finished",
    ]
    assert action_events[0]["payload"] == {
        "action_id": "action-scoped",
        "action_kind": "run_probe",
        "node_id": "worker",
    }
    assert action_events[1]["payload"] == {
        "action_id": "action-scoped",
        "action_kind": "run_probe",
        "node_id": "worker",
        "ok": True,
        "outcome": "observed",
        "timed_out": False,
    }


def test_surface_graph_traffic_binding_batches_projection_and_preserves_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    traffic = GraphTrafficLifecycle.open(
        tmp_path / "graph-route",
        target_url=TARGET_URL,
        in_scope=(TARGET_URL,),
        out_of_scope=(),
        capture_session_id="surface-graph-batch",
        graph_resume_expected=False,
    )
    state = AgentState(surface_graph=SurfaceGraphState.for_target(TARGET_URL))
    state.surface_graph.add(
        url=f"{TARGET_URL}/api/items",
        method="GET",
        source_kind="openapi",
    )
    projections: list[int] = []
    real_project = production.project_surface_graph

    def project(graph: SurfaceGraphState, legacy: object) -> dict[str, object]:
        projections.append(len(graph.operations or {}))
        return real_project(graph, legacy)  # type: ignore[arg-type]

    monkeypatch.setattr(production, "project_surface_graph", project)
    binding = production._bind_surface_graph_traffic(
        traffic,
        state=state,
        target_url=TARGET_URL,
    )
    assert len(projections) == 1

    for index in range(2):
        stored = traffic.recorder(
            {
                "disposition": "sent",
                "source_observation_id": f"http-observation-{index}",
                "resource_type": "agent_http",
                "method": "GET",
                "url": f"{TARGET_URL}/api/items",
                "request_headers": {},
                "response_status": 200,
                "response_url": f"{TARGET_URL}/api/items",
                "response_headers": {"Content-Type": "application/json"},
                "response_body": b"{}",
            }
        )
        assert stored is not None

    assert len(projections) == 1
    binding.finalize()
    assert len(projections) == 2
    [operation] = (state.surface_graph.operations or {}).values()
    assert operation.provenance == ("openapi", "probe")


def test_surface_graph_binding_imports_already_captured_browser_exchange(
    tmp_path: Path,
) -> None:
    traffic = GraphTrafficLifecycle.open(
        tmp_path / "graph-route-browser",
        target_url=TARGET_URL,
        in_scope=(TARGET_URL,),
        out_of_scope=(),
        capture_session_id="surface-graph-browser",
        graph_resume_expected=False,
    )
    traffic.store.append_exchange(
        build_captured_http_exchange(
            capture_session_id="surface-graph-browser",
            source="browser_capture",
            source_observation_id="browser-observation-1",
            identity_alias="anonymous",
            method="POST",
            url=f"{TARGET_URL}/browser/checkout/123?coupon=private-value",
            request_headers={"Content-Type": "application/json"},
            request_body={"sku": "private-value"},
            request_sent=True,
            response_status=201,
            scope_decision="allowed",
            replayability="requires_authorization",
            known_secrets=("private-value",),
        )
    )
    state = AgentState(surface_graph=SurfaceGraphState.for_target(TARGET_URL))

    binding = production._bind_surface_graph_traffic(
        traffic,
        state=state,
        target_url=TARGET_URL,
    )
    binding.finalize()

    [operation] = (state.surface_graph.operations or {}).values()
    assert operation.provenance == ("browser",)
    assert operation.route_shape == "/browser/checkout/{int}"
    assert {(item.name, item.location) for item in operation.parameters} == {
        ("coupon", "query"),
        ("sku", "body"),
    }
    assert "private-value" not in json.dumps(state.surface_graph.to_json())


def test_surface_graph_sink_failure_is_nonfatal_to_strict_traffic_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    traffic = GraphTrafficLifecycle.open(
        tmp_path / "graph-route",
        target_url=TARGET_URL,
        in_scope=(TARGET_URL,),
        out_of_scope=(),
        capture_session_id="surface-graph-nonfatal",
        graph_resume_expected=False,
    )
    events: list[dict[str, object]] = []
    binding = production._bind_surface_graph_traffic(
        traffic,
        state=AgentState(),
        target_url=TARGET_URL,
        record_event=lambda **event: events.append(event),
    )

    def fail_ingestion(
        _graph: SurfaceGraphState,
        _exchange: object,
    ) -> object:
        message = "malformed graph exchange"
        raise ValueError(message)

    monkeypatch.setattr(SurfaceGraphState, "ingest_exchange", fail_ingestion)
    stored = traffic.recorder(
        {
            "disposition": "sent",
            "source_observation_id": "http-observation",
            "resource_type": "agent_http",
            "method": "GET",
            "url": f"{TARGET_URL}/health",
            "request_headers": {},
            "response_status": 200,
            "response_url": f"{TARGET_URL}/health",
            "response_headers": {},
            "response_body": b"ok",
        }
    )
    binding.finalize()

    assert stored is not None
    assert len(traffic.store.exchanges()) == 1
    assert binding.errors == ["exchange:ValueError"]
    assert events[0]["kind"] == "surface_graph_ingest_warning"


def test_surface_graph_binding_rejects_wrong_target_before_recorder_binding(
    tmp_path: Path,
) -> None:
    traffic = GraphTrafficLifecycle.open(
        tmp_path / "graph-route",
        target_url=TARGET_URL,
        in_scope=(TARGET_URL,),
        out_of_scope=(),
        capture_session_id="surface-graph-origin",
        graph_resume_expected=False,
    )
    state = AgentState(surface_graph=SurfaceGraphState.for_target("http://127.0.0.1:9999"))

    with pytest.raises(production.GraphProductionError, match="different target origin"):
        production._bind_surface_graph_traffic(
            traffic,
            state=state,
            target_url=TARGET_URL,
        )


def test_production_graph_reuses_anonymous_policy_and_skips_managed_auth_wrapper(
    tmp_path: Path,
) -> None:
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )
    settings = AIWebAgentSettings(traffic_policy_reference=policy.to_reference())

    bound = production._graph_traffic_policy(
        settings,
        target_url=TARGET_URL,
        authenticated=False,
    )

    assert bound is not None
    assert bound.state_path == policy.state_path
    with pytest.raises(production.GraphProductionError, match="managed identity owner"):
        production._graph_traffic_policy(
            settings,
            target_url=TARGET_URL,
            authenticated=True,
        )


def test_low_noise_graph_rejects_a_missing_whole_run_policy() -> None:
    settings = AIWebAgentSettings(traffic_policy_mode="low-noise")

    with pytest.raises(production.GraphProductionError, match="requires an existing"):
        production._graph_traffic_policy(
            settings,
            target_url=TARGET_URL,
            authenticated=False,
        )


def test_authenticated_graph_rejects_an_unbound_identity_owner() -> None:
    settings = SimpleNamespace(
        authentication=FakeGraphAuthentication("analyst"),
        traffic_policy_reference=None,
        traffic_policy_mode="observe",
    )

    with pytest.raises(production.GraphProductionError, match="bound whole-run"):
        production._graph_traffic_policy(
            settings,  # type: ignore[arg-type]
            target_url=TARGET_URL,
            authenticated=True,
        )


def test_graph_runtime_policy_binds_the_exact_traffic_ledger(tmp_path: Path) -> None:
    first = TrafficPolicyController.open(
        tmp_path / "first-traffic.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=20),
    )
    second = TrafficPolicyController.open(
        tmp_path / "second-traffic.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=20),
    )

    first_binding = production._traffic_policy_manifest_binding(first)
    second_binding = production._traffic_policy_manifest_binding(second)

    assert first_binding["config"] == second_binding["config"]
    assert first_binding["target_origin"] == second_binding["target_origin"]
    assert first_binding["binding_sha256"] != second_binding["binding_sha256"]


def test_enforced_policy_removes_every_uncaptured_network_tool_from_graph_schemas() -> None:
    tools = production._graph_execution_tools(
        True,
        authenticated=False,
        traffic_policy_enforced=True,
    )
    _runtime_key, tool_policies, _role_policies = (
        production._production_runtime_policy_components(
            flag_objective=True,
            authenticated=False,
            traffic_policy_enforced=True,
        )
    )

    opaque = {
        "process_start",
        "process_read",
        "process_write",
        "process_stop",
        "run_command",
        "run_probe",
        "run_python",
        "validate_poc",
    }
    assert tools.isdisjoint(opaque)
    assert all(policy.isdisjoint(opaque) for policy in tool_policies.values())
    assert production._allowed_graph_action_tools(
        flag_objective=True,
        authenticated=False,
        traffic_policy_enforced=True,
    ) == frozenset({"capture_flag"})


def test_enforced_policy_route_never_constructs_or_attaches_process_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    client = GraphFixtureClient()
    process_runtimes: list[FakeProcessRuntime] = []
    _install_fakes(
        monkeypatch,
        client=client,
        process_runtimes=process_runtimes,
    )
    attached_process_executors: list[object] = []
    real_executor = production.EvidenceGraphExecutor

    def capture_executor(**kwargs: object) -> object:
        attached_process_executors.append(kwargs.get("process_executor"))
        return real_executor(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(production, "EvidenceGraphExecutor", capture_executor)
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=20),
    )

    result = run_autonomous_graph_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=_base(tmp_path),
        settings=AIWebAgentSettings(
            workspace_dir=tmp_path / "base-workspace",
            tool_runtime=VerifiedFakeToolRuntime(),
            model_client=client,
            traffic_policy_reference=policy.to_reference(),
        ),
        workspace_dir=tmp_path / "graph-route",
        objectives=(_objective(),),
    )

    assert process_runtimes == []
    assert attached_process_executors == [None]
    assert result.process_cleanup["backend"] == {
        "verified": True,
        "kind": "disabled",
        "reason": "whole_run_low_noise_enforced",
    }
