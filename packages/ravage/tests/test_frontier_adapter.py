from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core import frontier_adapter
from ravage.agent_core.agent_state import AgentState, load_agent_state, save_agent_state
from ravage.agent_core.ai_agent import AIWebAgentSettings, ModelReply
from ravage.agent_core.frontier_adapter import run_frontier_route
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
    FrontierObjective,
    FrontierRoute,
    FrontierRouteConfig,
    FrontierRouteStatus,
)
from ravage.agent_core.frontier_timeout_hygiene import (
    FrontierTimeoutHygieneRuntime,
    TimeoutCleanupRecord,
)
from ravage.auth import AuthArtifactRedactor, SecretValue
from ravage.model_core.providers import load_model_registry, resolve_model_routes
from ravage.runtime import FakeToolRuntime, ToolResult
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
ENGAGEMENT_ID = "99999999-9999-4999-9999-999999999999"
REMAINING_COST_USD = 0.25
TIMEOUT_ROUTE_REQUESTS = 2
TIMEOUT_FINALIZE_CALLS = 3


class OneReplyClient:
    def __init__(self, reply: ModelReply) -> None:
        self.reply = reply
        self.calls: list[list[dict[str, str]]] = []

    def chat(self, messages: list[dict[str, str]]) -> ModelReply:
        self.calls.append(messages)
        return self.reply


class SequenceReplyClient:
    def __init__(self, replies: list[ModelReply]) -> None:
        self.replies = list(replies)
        self.calls: list[list[dict[str, str]]] = []

    def chat(self, messages: list[dict[str, str]]) -> ModelReply:
        self.calls.append(messages)
        return self.replies.pop(0)


class ClosingFakeRuntime(FakeToolRuntime):
    def __init__(self, results: dict[str, ToolResult] | None = None) -> None:
        super().__init__(results)
        self.closed = False
        self.context = ""

    def write_free_roam_context(self, text: str) -> None:
        self.context = text

    def close(self) -> None:
        self.closed = True


class SequenceRuntime(ClosingFakeRuntime):
    def __init__(self, results: list[ToolResult]) -> None:
        super().__init__()
        self.sequence = list(results)

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        self.calls.append(
            (
                "run_command",
                {
                    "command": command,
                    "target_url": target_url,
                    "timeout_seconds": timeout_seconds,
                },
            )
        )
        return self.sequence.pop(0)


class EngineError(RuntimeError):
    pass


class CleanupError(RuntimeError):
    pass


class FakeAuthentication:
    identity = "analyst"

    def __init__(self, secret: str = "correct-horse") -> None:
        self.redactor = AuthArtifactRedactor((SecretValue(secret),))

    def contains_secret(self, value: str) -> bool:
        return self.redactor.contains_secret(value)

    def redact_text(self, value: str) -> str:
        return self.redactor.redact_text(value)


class AuditCloseError(RuntimeError):
    pass


class RaisingReplyClient:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def chat(self, _messages: list[dict[str, str]]) -> ModelReply:
        raise self.error


class FailingCloseRuntime(ClosingFakeRuntime):
    def close(self) -> None:
        self.closed = True
        message = "frontier runtime cleanup failed"
        raise CleanupError(message)


class FailingInitialCleanupRuntime(FrontierTimeoutHygieneRuntime):
    def __init__(self, inner: ClosingFakeRuntime) -> None:
        super().__init__(inner)
        self.finalize_calls = 0

    def finalize_cleanup(self) -> tuple[TimeoutCleanupRecord, ...]:
        self.finalize_calls += 1
        if self.finalize_calls == 1:
            message = "initial timeout cleanup failed"
            raise CleanupError(message)
        return super().finalize_cleanup()


class ObservingRuntime(ClosingFakeRuntime):
    def __init__(
        self,
        *,
        events: list[dict[str, object]],
        result: ToolResult,
    ) -> None:
        super().__init__({"run_command": result})
        self.events = events
        self.event_at_execution: dict[str, object] | None = None

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        if self.events:
            self.event_at_execution = dict(self.events[-1])
        return super().run_command(
            command=command,
            target_url=target_url,
            timeout_seconds=timeout_seconds,
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
  max_cost_usd: 2.0
  max_runtime_min: 10
context:
  description: "Authorized local web security exercise"
""".lstrip(),
        encoding="utf-8",
    )


def _base_state(path: Path, *, authenticated_identity: str = "") -> BaseRouteOutcome:
    path.parent.mkdir(parents=True, exist_ok=True)
    state = AgentState(
        turn=40,
        facts=["debug endpoint exposes command-shaped input"],
        signals={"endpoints": ["/debug"], "parameters": ["command"]},
    )
    if authenticated_identity:
        state.surface["authenticated_identity"] = authenticated_identity
        state.surface["session_mode"] = f"identity:{authenticated_identity}"
    save_agent_state(path, target_url=TARGET_URL, state=state)
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=40,
        state_digest="base-digest",
        state_ref=str(path),
        cost_usd=0.5,
    )


def _objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="command_injection",
        probe="command_boundary",
        endpoint="/debug",
        inputs=("command",),
        payload_class="specialist:command_boundary",
        expected_signal="target-observed command execution proof",
        evidence_refs=("base-state:base-digest",),
    )


def _events(workspace_dir: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (workspace_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]


def _raise_after_audit_close(monkeypatch: pytest.MonkeyPatch) -> None:
    original_close = frontier_adapter.AuditStore.close

    def close_then_fail(audit: frontier_adapter.AuditStore) -> None:
        original_close(audit)
        message = "frontier audit close failed"
        raise AuditCloseError(message)

    monkeypatch.setattr(frontier_adapter.AuditStore, "close", close_then_fail)


def test_credentialless_remote_route_cannot_bypass_frontier_cost_accounting(
    tmp_path: Path,
) -> None:
    config = tmp_path / "models.yaml"
    config.write_text(
        """
profiles:
  remote:
    routes:
      mid:
        - provider: custom_openai
          model: paid-remote-model
          base_url: https://paid-model.example/v1
          api_key_required: false
          input_cost_per_1m_tokens: 1.0
          cached_input_cost_per_1m_tokens: 1.0
          output_cost_per_1m_tokens: 2.0
""".lstrip(),
        encoding="utf-8",
    )
    registry = load_model_registry(config, env={})
    route = resolve_model_routes(
        registry,
        profile_name="remote",
        tier="mid",
        env={},
    )[0]

    with pytest.raises(RuntimeError, match="cannot be cost-accounted"):
        frontier_adapter._require_accountable_reply(  # noqa: SLF001
            route=route,
            reply=ModelReply(content="{}", usage_reported=False, cost_known=False),
        )


def test_legacy_observe_frontier_creates_the_canonical_run_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_root = tmp_path / "base-workspace"
    base = _base_state(base_root / "working_state.json")

    def unexpected_open(**_kwargs: object) -> TrafficPolicyController:
        pytest.fail("legacy observe fallback must create its canonical ledger directly")

    monkeypatch.setattr(frontier_adapter, "_open_run_traffic_policy", unexpected_open)

    controller = frontier_adapter._frontier_traffic_policy(  # noqa: SLF001
        settings=AIWebAgentSettings(traffic_policy_mode="observe"),
        base=base,
        target_url=TARGET_URL,
        roe_max_rps=5,
    )

    ledger_path = base_root / "traffic-policy.json"
    assert controller.state_path.resolve(strict=True) == ledger_path.resolve(strict=True)
    assert controller.config == TrafficPolicyConfig()
    assert controller.snapshot().unmetered_action_count == 1
    assert controller.snapshot().accounting_status == "lower_bound"


def test_low_noise_frontier_requires_a_policy_reference_even_when_ledger_exists(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-workspace"
    base = _base_state(base_root / "working_state.json")
    TrafficPolicyController.open(
        base_root / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=300),
    )

    with pytest.raises(TrafficPolicyError, match="traffic policy reference"):
        frontier_adapter._frontier_traffic_policy(  # noqa: SLF001
            settings=AIWebAgentSettings(traffic_policy_mode="low-noise"),
            base=base,
            target_url=TARGET_URL,
            roe_max_rps=5,
        )


def test_low_noise_frontier_accepts_the_matching_run_reference(tmp_path: Path) -> None:
    base_root = tmp_path / "base-workspace"
    base = _base_state(base_root / "working_state.json")
    config = TrafficPolicyConfig.low_noise(
        max_physical_requests=17,
        max_rps=0.25,
    )
    canonical = TrafficPolicyController.open(
        base_root / "traffic-policy.json",
        target_url=TARGET_URL,
        config=config,
    )

    controller = frontier_adapter._frontier_traffic_policy(  # noqa: SLF001
        settings=AIWebAgentSettings(
            traffic_policy_mode="low-noise",
            traffic_policy_max_physical_requests=17,
            traffic_policy_max_rps=0.25,
            traffic_policy_reference=canonical.to_reference(),
        ),
        base=base,
        target_url=TARGET_URL,
        roe_max_rps=5,
    )

    assert controller.state_path == canonical.state_path
    assert controller.config == config
    assert controller.target_origin == canonical.target_origin


def test_frontier_accepts_a_canonical_alias_reference_and_returns_run_controller(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-workspace"
    base = _base_state(base_root / "working_state.json")
    canonical = TrafficPolicyController.open(
        base_root / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )
    (base_root / "path-alias").mkdir()
    reference = canonical.to_reference()
    reference["state_path"] = str(base_root / "path-alias" / ".." / "traffic-policy.json")

    controller = frontier_adapter._frontier_traffic_policy(  # noqa: SLF001
        settings=AIWebAgentSettings(traffic_policy_reference=reference),
        base=base,
        target_url=TARGET_URL,
        roe_max_rps=5,
    )

    assert controller.state_path == canonical.state_path
    assert controller.state_path.resolve(strict=True) == canonical.state_path.resolve(strict=True)
    assert controller.config == canonical.config
    assert controller.target_origin == canonical.target_origin


@pytest.mark.parametrize("mismatch", ["state_path", "config", "target_origin"])
def test_frontier_rejects_each_referenced_policy_binding_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    base_root = tmp_path / "base-workspace"
    base = _base_state(base_root / "working_state.json")
    canonical = TrafficPolicyController.open(
        base_root / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )
    if mismatch == "state_path":
        referenced = TrafficPolicyController.open(
            base_root / "other-policy.json",
            target_url=TARGET_URL,
            config=canonical.config,
        )
    elif mismatch == "config":
        referenced = TrafficPolicyController(
            canonical.state_path,
            canonical.target_origin,
            TrafficPolicyConfig.low_noise(max_physical_requests=300),
        )
    else:
        referenced = TrafficPolicyController(
            canonical.state_path,
            "http://127.0.0.1:8766",
            canonical.config,
        )

    def mismatched_reference(
        _cls: type[TrafficPolicyController],
        _reference: object,
        *,
        require_existing: bool = True,
    ) -> TrafficPolicyController:
        del require_existing
        return referenced

    monkeypatch.setattr(
        TrafficPolicyController,
        "from_reference",
        classmethod(mismatched_reference),
    )

    with pytest.raises(TrafficPolicyError, match="does not match the base run ledger"):
        frontier_adapter._frontier_traffic_policy(  # noqa: SLF001
            settings=AIWebAgentSettings(
                traffic_policy_reference=canonical.to_reference(),
            ),
            base=base,
            target_url=TARGET_URL,
            roe_max_rps=5,
        )


def test_adapter_runs_engine_through_existing_model_and_executor_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    proof = "flag{adapter-target-proof}"
    model = OneReplyClient(
        ModelReply(
            content=json.dumps(
                {
                    "action": "run_command",
                    "command": "check the authorized target",
                    "expected_signal": "target proof",
                }
            ),
            cost_usd=0.1,
        )
    )
    runtime = ClosingFakeRuntime(
        {
            "run_command": ToolResult(
                ok=True,
                tool="run_command",
                command=("check",),
                exit_code=0,
                stdout=proof,
                stderr="",
            )
        }
    )
    workspace_dir = tmp_path / "frontier"
    captured: dict[str, object] = {}
    original_execute_action = frontier_adapter.execute_action

    def capture_traffic_policy(*args: object, **kwargs: object) -> object:
        captured["traffic_policy"] = kwargs.get("traffic_policy")
        return original_execute_action(*args, **kwargs)

    monkeypatch.setattr(frontier_adapter, "execute_action", capture_traffic_policy)

    route = run_frontier_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=AIWebAgentSettings(
            db_path=tmp_path / "audit.db",
            workspace_dir=tmp_path / "base-workspace",
            model_client=model,
            tool_runtime=runtime,
            proof_recognition_enabled=True,
        ),
        workspace_dir=workspace_dir,
        config=FrontierRouteConfig(
            max_model_requests=4,
            counterfactual_lease=4,
            proof_lease=4,
        ),
        objectives=(_objective(),),
    )

    assert route.status is FrontierRouteStatus.SOLVED
    assert route.model_requests_started == 1
    assert model.calls
    assert runtime.closed is True
    assert TARGET_URL in runtime.context
    assert (workspace_dir / "frontier-route.json").exists()
    assert proof not in json.dumps(route.to_json())
    assert isinstance(captured["traffic_policy"], TrafficPolicyController)


def test_adapter_persists_timeout_cleanup_and_requires_liveness_before_resuming(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    model = SequenceReplyClient(
        [
            ModelReply(
                content=json.dumps(
                    {
                        "action": "run_command",
                        "command": "check authorized command boundary once",
                        "expected_signal": "one target response",
                        "timeout_seconds": 20,
                    }
                ),
                cost_usd=0.01,
            ),
            ModelReply(
                content=json.dumps(
                    {
                        "action": "run_command",
                        "command": "repeat the known terminating target control once",
                        "expected_signal": "one fresh liveness control response",
                        "timeout_seconds": 10,
                    }
                ),
                cost_usd=0.01,
            ),
        ]
    )
    runtime = SequenceRuntime(
        [
            ToolResult(
                ok=False,
                tool="run_command",
                command=("sh", "-lc", "check authorized command boundary once"),
                exit_code=None,
                stdout="",
                stderr="",
                error="timed out after 20s",
                timed_out=True,
            ),
            ToolResult(
                ok=True,
                tool="run_command",
                command=("sh", "-lc", "repeat known control once"),
                exit_code=0,
                stdout="target responded to liveness control",
                stderr="",
            ),
        ]
    )
    workspace_dir = tmp_path / "frontier"

    route = run_frontier_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=AIWebAgentSettings(
            db_path=tmp_path / "audit.db",
            model_client=model,
            tool_runtime=runtime,
        ),
        workspace_dir=workspace_dir,
        config=FrontierRouteConfig(
            max_model_requests=TIMEOUT_ROUTE_REQUESTS,
            scout_lease=TIMEOUT_ROUTE_REQUESTS,
            counterfactual_lease=TIMEOUT_ROUTE_REQUESTS,
            proof_lease=TIMEOUT_ROUTE_REQUESTS,
        ),
        objectives=(_objective(),),
    )

    events = [
        json.loads(line)
        for line in (workspace_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    kinds = [event["kind"] for event in events]
    second_request = "\n".join(message["content"] for message in model.calls[1])
    state = load_agent_state(workspace_dir / "working_state.json")

    assert route.model_requests_started == TIMEOUT_ROUTE_REQUESTS
    assert "frontier_timeout_cleanup" in kinds
    assert "frontier_timeout_recovery_required" in kinds
    assert "frontier_timeout_recovery_resolved" in kinds
    assert '"cleanup_status": "not_applicable"' in second_request
    assert "previously terminating liveness/calibration control" in second_request
    assert state is not None
    assert len(state.signals["frontier_timeout_recoveries_resolved"]) == 1
    assert runtime.closed is True


def test_adapter_caps_route_cost_at_the_remaining_engagement_budget(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    base = BaseRouteOutcome(
        **{
            **base.to_json(),
            "termination": BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
            "cost_usd": 2.0 - REMAINING_COST_USD,
        }
    )
    model = OneReplyClient(
        ModelReply(
            content='{"action":"final","summary":"return control"}',
            cost_usd=REMAINING_COST_USD,
        )
    )
    runtime = ClosingFakeRuntime()

    route = run_frontier_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=AIWebAgentSettings(
            db_path=tmp_path / "audit.db",
            model_client=model,
            tool_runtime=runtime,
        ),
        workspace_dir=tmp_path / "frontier",
        config=FrontierRouteConfig(max_cost_usd=1.0),
        objectives=(_objective(),),
    )

    assert route.config.max_cost_usd == REMAINING_COST_USD
    assert route.status is FrontierRouteStatus.COST_BUDGET_EXHAUSTED


def test_adapter_resumes_the_route_working_state_instead_of_reloading_base(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    workspace_dir = tmp_path / "frontier"
    workspace_dir.mkdir()
    route_config = FrontierRouteConfig(
        max_model_requests=4,
        counterfactual_lease=4,
        proof_lease=4,
        max_cost_usd=1.5,
    )
    route = FrontierRoute.start(
        base=base,
        initial_objective=_objective(),
        scope=(TARGET_URL,),
        config=route_config,
    )
    route.save(workspace_dir / "frontier-route.json")
    save_agent_state(
        workspace_dir / "working_state.json",
        target_url=TARGET_URL,
        state=AgentState(
            turn=41,
            facts=["route-only observation survived process restart"],
        ),
    )
    model = OneReplyClient(ModelReply(content='{"action":"final","summary":"return control"}'))

    run_frontier_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=AIWebAgentSettings(
            db_path=tmp_path / "audit.db",
            model_client=model,
            tool_runtime=ClosingFakeRuntime(),
        ),
        workspace_dir=workspace_dir,
        config=FrontierRouteConfig(
            max_model_requests=4,
            counterfactual_lease=4,
            proof_lease=4,
        ),
        objectives=(_objective(),),
    )

    assert "route-only observation survived process restart" in json.dumps(model.calls)


def test_authenticated_frontier_rejects_stale_tainted_session_before_route_or_model(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(
        tmp_path / "base-working-state.json",
        authenticated_identity="analyst",
    )
    workspace_dir = tmp_path / "frontier"
    sessions = workspace_dir / "frontier-sessions"
    sessions.mkdir(parents=True)
    (sessions / "worker-001.jsonl").write_text(
        json.dumps({"role": "assistant", "content": "legacy correct-horse leak"}) + "\n",
        encoding="utf-8",
    )
    model = OneReplyClient(ModelReply(content='{"action":"final","summary":"done"}'))

    with pytest.raises(ValueError, match="untrusted authentication material"):
        run_frontier_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                db_path=tmp_path / "audit.db",
                model_client=model,
                tool_runtime=ClosingFakeRuntime(),
                authentication=FakeAuthentication(),  # type: ignore[arg-type]
            ),
            workspace_dir=workspace_dir,
            objectives=(_objective(),),
        )

    assert model.calls == []
    assert not (workspace_dir / "frontier-route.json").exists()


def test_authenticated_frontier_rejects_tainted_route_before_model(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(
        tmp_path / "base-working-state.json",
        authenticated_identity="analyst",
    )
    workspace_dir = tmp_path / "frontier"
    workspace_dir.mkdir()
    config = FrontierRouteConfig(max_cost_usd=1.5)
    tainted_objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_differential",
        endpoint="/search",
        inputs=("query",),
        payload_class="specialist:sqli_differential",
        expected_signal="correct-horse",
    )
    FrontierRoute.start(
        base=base,
        initial_objective=tainted_objective,
        scope=(TARGET_URL,),
        config=config,
    ).save(workspace_dir / "frontier-route.json")
    save_agent_state(
        workspace_dir / "working_state.json",
        target_url=TARGET_URL,
        state=AgentState(
            surface={
                "authenticated_identity": "analyst",
                "session_mode": "identity:analyst",
            }
        ),
    )
    model = OneReplyClient(ModelReply(content='{"action":"final","summary":"done"}'))

    with pytest.raises(ValueError, match="untrusted authentication material"):
        run_frontier_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                db_path=tmp_path / "audit.db",
                model_client=model,
                tool_runtime=ClosingFakeRuntime(),
                authentication=FakeAuthentication(),  # type: ignore[arg-type]
            ),
            workspace_dir=workspace_dir,
            config=config,
            objectives=(tainted_objective,),
        )

    assert model.calls == []


def test_adapter_emits_safe_action_start_before_execution_and_finishes_after_cleanup(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    events: list[dict[str, object]] = []
    model_authored_command = "printf never-render-this-sensitive-value"
    proof = "flag{frontier-action-start-proof}"
    runtime = ObservingRuntime(
        events=events,
        result=ToolResult(
            ok=True,
            tool="run_command",
            command=("sh", "-lc", model_authored_command),
            exit_code=0,
            stdout=proof,
            stderr="",
        ),
    )
    terminal_cleanup_states: list[bool] = []

    def record_event(event: Mapping[str, object]) -> None:
        events.append(dict(event))
        if event.get("kind") in {
            "frontier_route_cancelled",
            "frontier_route_failed",
            "frontier_route_finished",
        }:
            terminal_cleanup_states.append(runtime.closed)

    route = run_frontier_route(
        brief_path=brief_path,
        target_url=TARGET_URL,
        base=base,
        settings=AIWebAgentSettings(
            db_path=tmp_path / "audit.db",
            model_client=OneReplyClient(
                ModelReply(
                    content=json.dumps(
                        {
                            "action": "run_command",
                            "command": model_authored_command,
                        }
                    ),
                    cost_usd=0.01,
                )
            ),
            tool_runtime=runtime,
            proof_recognition_enabled=True,
            event_sink=record_event,
        ),
        workspace_dir=tmp_path / "frontier",
        objectives=(_objective(),),
    )

    started = runtime.event_at_execution
    assert route.status is FrontierRouteStatus.SOLVED
    assert started is not None
    assert started["kind"] == "frontier_action_started"
    payload = started["payload"]
    assert isinstance(payload, dict)
    assert set(payload) == {
        "action_id",
        "action_kind",
        "objective_fingerprint",
        "repeat_count",
        "role",
        "route_model_request",
        "route_model_request_budget",
        "worker_id",
        "worker_lease",
        "worker_request",
    }
    assert payload["action_kind"] == "run_command"
    assert model_authored_command not in json.dumps(payload)
    completed = next(event for event in events if event["kind"] == "frontier_action_completed")
    completed_payload = completed["payload"]
    assert isinstance(completed_payload, dict)
    assert completed_payload["action_id"] == payload["action_id"]
    terminal = [event for event in events if event["kind"] == "frontier_route_finished"]
    assert len(terminal) == 1
    assert terminal_cleanup_states == [True]


def test_adapter_primary_failure_survives_cleanup_and_audit_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    runtime = FailingCloseRuntime()
    workspace_dir = tmp_path / "frontier"
    _raise_after_audit_close(monkeypatch)

    with pytest.raises(EngineError, match="model transport failed"):
        run_frontier_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                db_path=tmp_path / "audit.db",
                model_client=RaisingReplyClient(EngineError("model transport failed")),
                tool_runtime=runtime,
            ),
            workspace_dir=workspace_dir,
            objectives=(_objective(),),
        )

    terminal = _events(workspace_dir)[-1]
    assert terminal["kind"] == "frontier_route_failed"
    assert terminal["payload"]["error_type"] == "EngineError"
    assert terminal["payload"]["cleanup_error_type"] == "CleanupError"
    assert terminal["payload"]["audit_error_type"] == "AuditCloseError"
    assert runtime.closed is True


def test_adapter_cleanup_failure_wins_over_later_audit_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    workspace_dir = tmp_path / "frontier"
    _raise_after_audit_close(monkeypatch)

    with pytest.raises(CleanupError, match="runtime cleanup failed"):
        run_frontier_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                db_path=tmp_path / "audit.db",
                model_client=OneReplyClient(
                    ModelReply(content='{"action":"final","summary":"return control"}')
                ),
                tool_runtime=FailingCloseRuntime(),
            ),
            workspace_dir=workspace_dir,
            objectives=(_objective(),),
        )

    terminal = _events(workspace_dir)[-1]
    assert terminal["kind"] == "frontier_route_failed"
    assert terminal["payload"]["error_type"] == "CleanupError"
    assert terminal["payload"]["audit_error_type"] == "AuditCloseError"
    assert not any(event["kind"] == "frontier_route_finished" for event in _events(workspace_dir))


def test_adapter_closes_inner_runtime_after_initial_timeout_cleanup_failure(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    workspace_dir = tmp_path / "frontier"
    inner = ClosingFakeRuntime()
    runtime = FailingInitialCleanupRuntime(inner)

    with pytest.raises(CleanupError, match="initial timeout cleanup failed"):
        run_frontier_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                db_path=tmp_path / "audit.db",
                model_client=OneReplyClient(
                    ModelReply(content='{"action":"final","summary":"return control"}')
                ),
                tool_runtime=runtime,
            ),
            workspace_dir=workspace_dir,
            objectives=(_objective(),),
        )

    terminal = _events(workspace_dir)[-1]
    assert inner.closed is True
    assert runtime.finalize_calls == TIMEOUT_FINALIZE_CALLS
    assert terminal["kind"] == "frontier_route_failed"
    assert terminal["payload"]["error_type"] == "CleanupError"


def test_adapter_audit_close_failure_emits_failed_instead_of_finished(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    workspace_dir = tmp_path / "frontier"
    _raise_after_audit_close(monkeypatch)

    with pytest.raises(AuditCloseError, match="audit close failed"):
        run_frontier_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                db_path=tmp_path / "audit.db",
                model_client=OneReplyClient(
                    ModelReply(content='{"action":"final","summary":"return control"}')
                ),
                tool_runtime=ClosingFakeRuntime(),
            ),
            workspace_dir=workspace_dir,
            objectives=(_objective(),),
        )

    terminal = _events(workspace_dir)[-1]
    assert terminal["kind"] == "frontier_route_failed"
    assert terminal["payload"]["error_type"] == "AuditCloseError"
    assert not any(event["kind"] == "frontier_route_finished" for event in _events(workspace_dir))


def test_adapter_keyboard_interrupt_emits_cancelled_without_masking_interrupt(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    _write_brief(brief_path)
    base = _base_state(tmp_path / "base-working-state.json")
    workspace_dir = tmp_path / "frontier"

    with pytest.raises(KeyboardInterrupt):
        run_frontier_route(
            brief_path=brief_path,
            target_url=TARGET_URL,
            base=base,
            settings=AIWebAgentSettings(
                db_path=tmp_path / "audit.db",
                model_client=RaisingReplyClient(KeyboardInterrupt()),
                tool_runtime=ClosingFakeRuntime(),
            ),
            workspace_dir=workspace_dir,
            objectives=(_objective(),),
        )

    terminal = _events(workspace_dir)[-1]
    assert terminal["kind"] == "frontier_route_cancelled"
    assert terminal["payload"]["status"] == "cancelled"
    assert terminal["payload"]["error_type"] == "KeyboardInterrupt"
