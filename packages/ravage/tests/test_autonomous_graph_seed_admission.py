# ruff: noqa: CPY001

from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.seed_admission import (
    graph_seed_admission_reason,
)
from ravage.agent_core.frontier_route import (
    FrontierObjective,
    FrontierObjectiveBasis,
)

TARGET_URL = "http://127.0.0.1:8765/"


def _command_objective(
    *,
    endpoint: str,
    inputs: tuple[str, ...],
) -> FrontierObjective:
    return FrontierObjective.create(
        family="command_injection",
        probe="command_boundary",
        endpoint=endpoint,
        inputs=inputs,
        payload_class="confirmed_primitive:command_exec_confirmed:request_contract",
        expected_signal="one target-observed command differential",
        evidence_refs=("base-state:" + ("a" * 64),),
        basis=FrontierObjectiveBasis.BASE_FRONTIER,
    )


def test_polluted_signal_only_command_path_is_not_admitted() -> None:
    state = AgentState(
        surface={
            "endpoints": [
                {"url": TARGET_URL, "hints": [], "priority": 9},
                {
                    "url": f"{TARGET_URL}accounts/login/",
                    "hints": ["auth"],
                    "priority": 21,
                },
            ],
            "forms": [
                {
                    "action": f"{TARGET_URL}accounts/login/",
                    "method": "POST",
                    "categories": ["auth", "command_boundary", "csrf"],
                    "inputs": [
                        {"name": "username", "type": "text"},
                        {"name": "password", "type": "password"},
                    ],
                }
            ],
        },
        signals={
            "endpoints": ["/css", "/0.2", "/amd64"],
            "parameters": ["username", "password"],
            "markers": ["command_boundary_signal"],
        },
        primitives={"command_exec_confirmed": 3},
    )
    objective = _command_objective(
        endpoint="/css",
        inputs=("username", "password"),
    )

    assert (
        graph_seed_admission_reason(
            state,
            objective,
            target_url=TARGET_URL,
        )
        == "command_seed_requires_structured_surface_contract"
    )


def test_auth_form_category_alone_does_not_admit_command_work() -> None:
    endpoint = f"{TARGET_URL}accounts/login/"
    state = AgentState(
        surface={
            "endpoints": [{"url": endpoint, "hints": ["auth"]}],
            "forms": [
                {
                    "action": endpoint,
                    "method": "POST",
                    "categories": ["auth", "command_boundary"],
                    "inputs": [
                        {"name": "username", "type": "text"},
                        {"name": "password", "type": "password"},
                    ],
                }
            ],
        }
    )

    assert (
        graph_seed_admission_reason(
            state,
            _command_objective(endpoint=endpoint, inputs=("username",)),
            target_url=TARGET_URL,
        )
        == "command_seed_lacks_command_shaped_input_contract"
    )


def test_structured_command_input_contract_is_admitted() -> None:
    endpoint = f"{TARGET_URL}diagnose"
    state = AgentState(
        surface={
            "endpoints": [{"url": endpoint, "hints": ["diagnostic"]}],
            "forms": [
                {
                    "action": endpoint,
                    "method": "POST",
                    "categories": ["command_boundary"],
                    "inputs": [{"name": "host", "type": "text"}],
                }
            ],
            "parameters": [
                {
                    "name": "host",
                    "locations": [endpoint],
                    "sources": ["form:post"],
                }
            ],
        }
    )

    assert (
        graph_seed_admission_reason(
            state,
            _command_objective(endpoint=endpoint, inputs=("host",)),
            target_url=TARGET_URL,
        )
        == ""
    )
