from __future__ import annotations

from typing import TYPE_CHECKING

from ravage.agent_core.frontier_contract_memory import (
    ContractRouteContext,
    has_remembered_request_contract,
)
from ravage.agent_core.frontier_replay_contract import (
    authoritative_replay_for_objective,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.frontier_route import FrontierObjective

_CONFIRMED_REQUEST_CONTRACT_SUFFIX = ":request_contract"
_SQL_FAMILY = "sql_injection"


def objective_requires_observed_request_contract(
    objective: FrontierObjective,
) -> bool:
    return (
        objective.family == _SQL_FAMILY
        and objective.payload_class.startswith("confirmed_primitive:")
        and objective.payload_class.endswith(_CONFIRMED_REQUEST_CONTRACT_SUFFIX)
    )


def objective_has_observed_request_contract(
    state: AgentState,
    objective: FrontierObjective,
    *,
    target_url: str,
) -> bool:
    replay = authoritative_replay_for_objective(
        state,
        objective,
        target_url=target_url,
    )
    return (replay is not None and replay.authoritative) or (
        has_remembered_request_contract(
            state,
            context=ContractRouteContext(
                target_url=target_url,
                family=objective.family,
                objective_endpoint=objective.endpoint,
                objective_inputs=objective.inputs,
            ),
        )
    )


def observed_request_contract_constraints() -> tuple[str, ...]:
    return (
        (
            "Before handoff, persist a same-origin request contract observed in target "
            "output; an inferred method or field list is insufficient."
        ),
        (
            "Fetch the assigned page or client script, or inspect trusted structured form "
            "output, and preserve its exact method, endpoint, fields, and constants."
        ),
        (
            "When inspecting client code, emit the complete enclosing request call and "
            "closed data/form object. Filtered matching lines cannot prove object boundaries "
            "or omitted constant fields."
        ),
    )


def observed_request_contract_message(objective: FrontierObjective) -> str:
    inputs = ", ".join(objective.inputs) or "the assigned input"
    return (
        "COORDINATOR_OBSERVED_CONTRACT_GATE\n"
        "Handoff rejected. No matching same-origin request contract has been persisted "
        "from target-produced tool output. Fetch the assigned page or client script, "
        "or inspect trusted structured form output, for "
        f"endpoint={objective.endpoint}, input={inputs}; preserve the exact method, "
        "fields, and constant values. Emit the complete enclosing request call and "
        "closed data/form object rather than filtered matching lines. Do not infer the "
        "contract from an attempted "
        "request. The rejected model request remains charged; global request, worker, "
        "scope, and cost limits remain enforced."
    )


__all__ = [
    "objective_has_observed_request_contract",
    "objective_requires_observed_request_contract",
    "observed_request_contract_constraints",
    "observed_request_contract_message",
]
