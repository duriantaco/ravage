from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from ravage.agent_core.agent_state import append_unique
from ravage.agent_core.frontier_request_contract import (
    ObservedRequestContract,
    observed_request_contracts,
)

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_CONTRACT_SIGNAL = "frontier_request_contracts"
_SUPERSEDED_SQL_REPLAY_SIGNAL = "frontier_superseded_sqli_replays"
_MAX_SIGNAL_ITEMS = 30
_CONTROL_FIELDS = frozenset(
    {
        "action",
        "button",
        "csrf",
        "csrf_token",
        "submit",
        "token",
        "_token",
    }
)


@dataclass(frozen=True)
class ContractMemoryUpdate:
    contracts: tuple[ObservedRequestContract, ...] = ()
    superseded_sql_replays: int = 0


@dataclass(frozen=True)
class ContractRouteContext:
    target_url: str
    family: str
    objective_endpoint: str
    objective_inputs: tuple[str, ...]


def remember_observed_request_contracts(
    state: AgentState,
    observation: str,
    *,
    context: ContractRouteContext,
) -> ContractMemoryUpdate:
    """Persist target-defined contracts in the route copy of agent state."""
    contracts = tuple(
        contract
        for contract in observed_request_contracts(observation)
        if _contract_matches_objective(
            contract,
            target_url=context.target_url,
            objective_endpoint=context.objective_endpoint,
            objective_inputs=context.objective_inputs,
        )
    )
    if not contracts:
        return ContractMemoryUpdate()

    superseded = 0
    for contract in contracts:
        absolute_url = _absolute_endpoint(context.target_url, contract.endpoint)
        memory = _contract_memory_payload(contract, absolute_url=absolute_url)
        _append_json_signal(state, _CONTRACT_SIGNAL, memory)
        _append_json_signal(
            state,
            "request_templates",
            _request_template_payload(contract, absolute_url=absolute_url),
        )
        if "sql" in context.family.lower():
            superseded += _project_sql_replay(
                state,
                contract,
                absolute_url=absolute_url,
                objective_inputs=context.objective_inputs,
            )
    return ContractMemoryUpdate(
        contracts=contracts,
        superseded_sql_replays=superseded,
    )


def remembered_request_contracts(state: AgentState) -> list[dict[str, object]]:
    contracts: list[dict[str, object]] = []
    for raw in state.signals.get(_CONTRACT_SIGNAL, [])[-12:]:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict):
            contracts.append(dict(payload))
    return contracts


def has_remembered_request_contract(
    state: AgentState,
    *,
    context: ContractRouteContext,
) -> bool:
    """Return whether trusted route memory contains this objective's contract."""
    for payload in remembered_request_contracts(state):
        try:
            contract = ObservedRequestContract.from_json(payload)
        except ValueError:
            continue
        if _contract_matches_objective(
            contract,
            target_url=context.target_url,
            objective_endpoint=context.objective_endpoint,
            objective_inputs=context.objective_inputs,
        ):
            return True
    return False


def _contract_matches_objective(
    contract: ObservedRequestContract,
    *,
    target_url: str,
    objective_endpoint: str,
    objective_inputs: tuple[str, ...],
) -> bool:
    if not _same_origin_or_relative(contract.endpoint, target_url=target_url):
        return False
    objective_path = _normalized_path(objective_endpoint)
    endpoint_matches = (
        not objective_endpoint
        or objective_path in {"", "/"}
        or _normalized_path(contract.endpoint) == objective_path
    )
    if not endpoint_matches:
        return False
    expected_inputs = {item.strip().lower() for item in objective_inputs if item.strip()}
    if not expected_inputs:
        return True
    contract_fields = {field.name.lower() for field in contract.fields}
    return bool(expected_inputs & contract_fields)


def _same_origin_or_relative(endpoint: str, *, target_url: str) -> bool:
    parsed = urlsplit(endpoint)
    if not parsed.scheme and not parsed.netloc:
        return True
    return _origin(endpoint) == _origin(target_url)


def _contract_memory_payload(
    contract: ObservedRequestContract,
    *,
    absolute_url: str,
) -> dict[str, object]:
    return {
        **contract.to_json(),
        "url": absolute_url,
        "source": "target_observed_client_contract",
    }


def _request_template_payload(
    contract: ObservedRequestContract,
    *,
    absolute_url: str,
) -> dict[str, object]:
    return {
        "method": contract.method,
        "url": absolute_url,
        "fields": _contract_fields(contract),
        "source": "frontier_target_observation",
    }


def _project_sql_replay(
    state: AgentState,
    contract: ObservedRequestContract,
    *,
    absolute_url: str,
    objective_inputs: tuple[str, ...],
) -> int:
    payload_field = _payload_field(contract, objective_inputs=objective_inputs)
    if not payload_field:
        return 0
    fields = _contract_fields(contract)
    replay = {
        "method": contract.method,
        "url": absolute_url,
        "payload_field": payload_field,
        "form": fields,
        "required_fields": list(fields),
        "constant_fields": {
            field.name: field.constant_value
            for field in contract.fields
            if field.constant_value is not None
        },
        "encoding": "application/x-www-form-urlencoded",
        "replay_hint": (
            "Replay this target-observed contract verbatim and change only payload_field."
        ),
        "source": "frontier_target_observation",
    }

    kept: list[str] = []
    superseded: list[str] = []
    for raw in state.signals.get("sqli_replays", []):
        parsed = _json_mapping(raw)
        if not parsed or not _same_replay_input_and_origin(
            parsed,
            replay,
            payload_field=payload_field,
        ):
            kept.append(raw)
            continue
        if _replay_satisfies_contract(parsed, replay):
            kept.append(raw)
            continue
        superseded.append(raw)

    encoded_replay = json.dumps(replay, sort_keys=True)
    if encoded_replay not in kept:
        kept.append(encoded_replay)
    state.signals["sqli_replays"] = kept[-_MAX_SIGNAL_ITEMS:]
    for raw in superseded:
        append_unique(
            state.signals.setdefault(_SUPERSEDED_SQL_REPLAY_SIGNAL, []),
            raw,
            limit=_MAX_SIGNAL_ITEMS,
        )
    _append_json_signal(
        state,
        "sqli_inputs",
        {
            "input": payload_field,
            "kind": "replay",
            "url": absolute_url,
        },
    )
    return len(superseded)


def _payload_field(
    contract: ObservedRequestContract,
    *,
    objective_inputs: tuple[str, ...],
) -> str:
    fields = {field.name.lower(): field.name for field in contract.fields}
    for objective_input in objective_inputs:
        match = fields.get(objective_input.strip().lower())
        if match:
            return match
    for field in contract.fields:
        if field.name.lower() not in _CONTROL_FIELDS:
            return field.name
    return ""


def _contract_fields(contract: ObservedRequestContract) -> dict[str, str]:
    return {
        field.name: "" if field.constant_value is None else field.constant_value
        for field in contract.fields
    }


def _same_replay_input_and_origin(
    existing: dict[str, object],
    candidate: dict[str, object],
    *,
    payload_field: str,
) -> bool:
    existing_input = str(existing.get("payload_field") or existing.get("input") or "")
    if existing_input.lower() != payload_field.lower():
        return False
    existing_url = str(existing.get("url") or "")
    candidate_url = str(candidate.get("url") or "")
    return _origin(existing_url) == _origin(candidate_url)


def _replay_satisfies_contract(
    existing: dict[str, object],
    candidate: dict[str, object],
) -> bool:
    if (
        str(existing.get("method") or "GET").upper()
        != str(candidate.get("method") or "GET").upper()
    ):
        return False
    if _normalized_path(str(existing.get("url") or "")) != _normalized_path(
        str(candidate.get("url") or "")
    ):
        return False
    existing_fields = existing.get("form")
    required_fields = candidate.get("required_fields")
    if not isinstance(existing_fields, dict) or not isinstance(required_fields, list):
        return False
    return all(str(field) in existing_fields for field in required_fields)


def _append_json_signal(
    state: AgentState,
    key: str,
    payload: dict[str, object],
) -> None:
    append_unique(
        state.signals.setdefault(key, []),
        json.dumps(payload, sort_keys=True),
        limit=_MAX_SIGNAL_ITEMS,
    )


def _json_mapping(raw: object) -> dict[str, object]:
    try:
        payload = json.loads(str(raw))
    except (TypeError, ValueError):
        return {}
    return dict(payload) if isinstance(payload, dict) else {}


def _absolute_endpoint(target_url: str, endpoint: str) -> str:
    return urljoin(f"{target_url.rstrip('/')}/", endpoint)


def _normalized_path(value: str) -> str:
    path = urlsplit(value).path.strip()
    if not path:
        return "/"
    return f"/{path.strip('/')}"


def _origin(value: str) -> tuple[str, str]:
    parsed = urlsplit(value)
    return parsed.scheme.lower(), parsed.netloc.lower()


__all__ = [
    "ContractMemoryUpdate",
    "ContractRouteContext",
    "has_remembered_request_contract",
    "remember_observed_request_contracts",
    "remembered_request_contracts",
]
