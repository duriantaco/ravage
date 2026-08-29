from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import append_unique

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.frontier_route import FrontierObjective

_SIGNAL = "frontier_sql_oracle_contracts"
_MAX_SIGNAL_ITEMS = 30
_MAX_DOCUMENTS = 24
_MAX_DEPTH = 10
_MAX_CONTROL_MARKERS = 32
_MAX_REQUEST_OBJECT_LOOKBACK = 32_000
_REQUIRED_CONTROL_REPETITIONS = 2
_TRUE_EXPRESSIONS = frozenset({"1=1", "2=2"})
_FALSE_EXPRESSIONS = frozenset({"1=0", "1=2", "2=1"})
_TRUE_NAMES = frozenset({"true", "true_body", "true_marker", "true_response", "true_signature"})
_FALSE_NAMES = frozenset(
    {"false", "false_body", "false_marker", "false_response", "false_signature"}
)
_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<quote>['\"])(?P<value>[^\r\n'\"]{1,2000})(?P=quote)"
)
_BOOLEAN_PHASE_MARKER = re.compile(r'"phase"\s*:\s*"boolean_probe"')


@dataclass(frozen=True)
class SqlOracleContract:
    family: str
    endpoint: str
    input_name: str
    method: str
    true_status: int | None
    true_body: str
    false_status: int | None
    false_body: str
    source: str
    fingerprint: str

    @classmethod
    def create(  # noqa: PLR0913 - explicit fields are the trust boundary.
        cls,
        *,
        family: str,
        endpoint: str,
        input_name: str,
        method: str,
        true_status: int | None,
        true_body: str,
        false_status: int | None,
        false_body: str,
        source: str,
    ) -> SqlOracleContract:
        payload = {
            "family": family.strip().lower(),
            "endpoint": endpoint.strip(),
            "input_name": input_name.strip(),
            "method": method.strip().upper(),
            "true_status": true_status,
            "true_body": _normalized_body(true_body),
            "false_status": false_status,
            "false_body": _normalized_body(false_body),
            "source": source.strip().lower(),
        }
        fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return cls(fingerprint=fingerprint, **payload)

    def to_json(self) -> dict[str, object]:
        return {
            "family": self.family,
            "endpoint": self.endpoint,
            "input_name": self.input_name,
            "method": self.method,
            "true_status": self.true_status,
            "true_body": self.true_body,
            "false_status": self.false_status,
            "false_body": self.false_body,
            "source": self.source,
            "fingerprint": self.fingerprint,
            "authority": "repeated_target_controls",
            "truth_rule": "1=1 and 2=2",
            "false_rule": "1=0 and 2=1",
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> SqlOracleContract:
        contract = cls.create(
            family=str(payload.get("family") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            input_name=str(payload.get("input_name") or ""),
            method=str(payload.get("method") or ""),
            true_status=_optional_int(payload.get("true_status")),
            true_body=str(payload.get("true_body") or ""),
            false_status=_optional_int(payload.get("false_status")),
            false_body=str(payload.get("false_body") or ""),
            source=str(payload.get("source") or ""),
        )
        stored = str(payload.get("fingerprint") or "")
        if stored and stored != contract.fingerprint:
            raise ValueError
        return contract


@dataclass(frozen=True)
class SqlOracleAssignmentIssue:
    code: str
    contract_fingerprint: str
    assigned_true: str
    assigned_false: str

    def to_json(self) -> dict[str, object]:
        return {
            "code": self.code,
            "contract_fingerprint": self.contract_fingerprint,
            "assigned_true": self.assigned_true,
            "assigned_false": self.assigned_false,
        }


@dataclass(frozen=True)
class _ResponseSignature:
    status: int | None
    body: str
    digest_hint: str

    @property
    def identity(self) -> tuple[int | None, str]:
        return self.status, self.digest_hint or _body_digest(self.body)


def remember_sql_oracle_contracts(
    state: AgentState,
    observation: str,
    *,
    objective: FrontierObjective,
) -> tuple[SqlOracleContract, ...]:
    contracts = sql_oracle_contracts_from_observation(
        observation,
        objective=objective,
    )
    for contract in contracts:
        append_unique(
            state.signals.setdefault(_SIGNAL, []),
            json.dumps(contract.to_json(), sort_keys=True),
            limit=_MAX_SIGNAL_ITEMS,
        )
    return contracts


def sql_oracle_contracts_from_observation(
    observation: str,
    *,
    objective: FrontierObjective,
) -> tuple[SqlOracleContract, ...]:
    if objective.family != "sql_injection":
        return ()
    contracts: list[SqlOracleContract] = []
    seen: set[str] = set()
    for document in _json_documents(observation):
        for payload in _walk_mappings(document):
            requests = payload.get("requests")
            if not isinstance(requests, list):
                continue
            for contract in _contracts_from_requests(requests, objective=objective):
                if contract.fingerprint in seen:
                    continue
                seen.add(contract.fingerprint)
                contracts.append(contract)
    if not contracts:
        for contract in _contracts_from_requests(
            _standalone_boolean_requests(observation),
            objective=objective,
        ):
            if contract.fingerprint in seen:
                continue
            seen.add(contract.fingerprint)
            contracts.append(contract)
    return tuple(contracts)


def authoritative_sql_oracle_for_objective(
    state: AgentState,
    objective: FrontierObjective,
) -> SqlOracleContract | None:
    objective_inputs = {item.lower() for item in objective.inputs}
    for raw in reversed(state.signals.get(_SIGNAL, [])):
        try:
            payload = json.loads(str(raw))
            if not isinstance(payload, Mapping):
                continue
            contract = SqlOracleContract.from_json(payload)
        except (TypeError, ValueError):
            continue
        if contract.family != objective.family:
            continue
        if _normalized_path(contract.endpoint) != _normalized_path(objective.endpoint):
            continue
        if objective_inputs and contract.input_name.lower() not in objective_inputs:
            continue
        return contract
    return None


def remembered_sql_oracle_contracts(
    state: AgentState,
    *,
    objective: FrontierObjective,
) -> list[dict[str, object]]:
    contract = authoritative_sql_oracle_for_objective(state, objective)
    return [contract.to_json()] if contract is not None else []


def sql_oracle_constraints(
    contract: SqlOracleContract | None,
) -> tuple[str, ...]:
    if contract is None:
        return ()
    return (
        (
            "Repeated target controls established the Boolean oracle: predicates 1=1 and "
            f"2=2 return {contract.true_body!r}; predicates 1=0 and 2=1 return "
            f"{contract.false_body!r}."
        ),
        (
            "Preserve that mapping exactly during extraction. A UNION/error response or "
            "an arbitrary baseline response cannot redefine which branch is true."
        ),
    )


def detect_sql_oracle_assignment_issue(
    objective: FrontierObjective,
    action: Mapping[str, object],
    contract: SqlOracleContract | None,
) -> SqlOracleAssignmentIssue | None:
    if (
        contract is None
        or objective.family != "sql_injection"
        or str(action.get("action") or "") not in {"run_command", "run_python"}
    ):
        return None
    source = str(action.get("code") or action.get("command") or "")
    assignments = _literal_assignments(source)
    assigned_true = _first_assignment(assignments, _TRUE_NAMES)
    assigned_false = _first_assignment(assignments, _FALSE_NAMES)
    if not assigned_true or not assigned_false:
        return None
    true_value = _normalized_body(assigned_true)
    false_value = _normalized_body(assigned_false)
    if true_value == contract.false_body and false_value == contract.true_body:
        code = "confirmed_oracle_inverted"
    elif true_value != contract.true_body or false_value != contract.false_body:
        code = "confirmed_oracle_redefined"
    else:
        return None
    return SqlOracleAssignmentIssue(
        code=code,
        contract_fingerprint=contract.fingerprint,
        assigned_true=true_value,
        assigned_false=false_value,
    )


def sql_oracle_guard_message(
    contract: SqlOracleContract,
    issue: SqlOracleAssignmentIssue,
) -> str:
    return (
        "COORDINATOR_SQL_ORACLE_GUARD\n"
        "Action not executed. Repeated target-observed tautology and contradiction "
        "controls already fixed the Boolean response mapping, and this extractor "
        f"would {issue.code.replace('_', ' ')}. The model request remains charged.\n"
        f"Use true={contract.true_body!r} for 1=1/2=2 and "
        f"false={contract.false_body!r} for 1=0/2=1 on "
        f"{contract.method} {contract.endpoint}. Do not infer truth from UNION/error "
        "responses. Keep the global request, worker, scope, and cost limits unchanged."
    )


def sql_oracle_correction_objective(
    objective: FrontierObjective,
    contract: SqlOracleContract,
) -> FrontierObjective:
    from ravage.agent_core.frontier_route import (  # noqa: PLC0415
        FrontierObjective,
        FrontierObjectiveBasis,
    )

    return FrontierObjective.create(
        family=objective.family,
        probe=objective.probe,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=(
            "Continue the bounded extractor with the coordinator-verified Boolean "
            f"mapping: true predicates 1=1/2=2 return {contract.true_body!r}; false "
            f"predicates 1=0/2=1 return {contract.false_body!r}. Preserve the request "
            "contract, bracket-check recovered values, and reject UNION/error responses "
            "as truth labels."
        ),
        evidence_refs=tuple(
            dict.fromkeys((*objective.evidence_refs, f"sql-oracle:{contract.fingerprint}"))
        ),
        basis=FrontierObjectiveBasis.NOVEL_COUNTERFACTUAL,
    )


def _contracts_from_requests(
    requests: Sequence[object],
    *,
    objective: FrontierObjective,
) -> tuple[SqlOracleContract, ...]:
    groups: dict[
        tuple[str, str, str],
        dict[str, list[_ResponseSignature]],
    ] = {}
    for raw in requests:
        if not isinstance(raw, Mapping):
            continue
        if str(raw.get("phase") or "").lower() != "boolean_probe":
            continue
        expression = _normalized_expression(str(raw.get("expr") or ""))
        if expression not in _TRUE_EXPRESSIONS | _FALSE_EXPRESSIONS:
            continue
        target = raw.get("target")
        target_mapping = target if isinstance(target, Mapping) else {}
        endpoint = str(
            target_mapping.get("url") or raw.get("url") or raw.get("final_url") or ""
        ).strip()
        input_name = str(target_mapping.get("input") or "").strip()
        method = str(target_mapping.get("method") or raw.get("method") or "").upper()
        body = str(raw.get("body_snippet") or raw.get("body") or "").strip()
        if (
            not endpoint
            or not input_name
            or not method
            or not body
            or _normalized_path(endpoint) != _normalized_path(objective.endpoint)
            or (
                objective.inputs
                and input_name.lower() not in {item.lower() for item in objective.inputs}
            )
        ):
            continue
        key = (endpoint, input_name, method)
        group = groups.setdefault(key, {"true": [], "false": []})
        label = "true" if expression in _TRUE_EXPRESSIONS else "false"
        group[label].append(
            _ResponseSignature(
                status=_optional_int(raw.get("status")),
                body=_normalized_body(body),
                digest_hint=str(raw.get("body_sha_hint") or ""),
            )
        )

    contracts: list[SqlOracleContract] = []
    for (endpoint, input_name, method), group in groups.items():
        true_signature = _stable_signature(group["true"])
        false_signature = _stable_signature(group["false"])
        if (
            true_signature is None
            or false_signature is None
            or true_signature.identity == false_signature.identity
        ):
            continue
        contracts.append(
            SqlOracleContract.create(
                family=objective.family,
                endpoint=endpoint,
                input_name=input_name,
                method=method,
                true_status=true_signature.status,
                true_body=true_signature.body,
                false_status=false_signature.status,
                false_body=false_signature.body,
                source="structured_sqli_specialist_controls",
            )
        )
    return tuple(contracts)


def _stable_signature(
    values: Sequence[_ResponseSignature],
) -> _ResponseSignature | None:
    if len(values) < _REQUIRED_CONTROL_REPETITIONS or len({item.identity for item in values}) != 1:
        return None
    return values[0]


def _json_documents(observation: str) -> tuple[object, ...]:
    try:
        root = json.loads(observation)
    except (TypeError, ValueError):
        return ()
    documents: list[object] = [root]
    seen_strings: set[str] = set()
    queue: list[tuple[object, int]] = [(root, 0)]
    while queue and len(documents) < _MAX_DOCUMENTS:
        value, depth = queue.pop(0)
        if depth > _MAX_DEPTH:
            continue
        if isinstance(value, Mapping):
            queue.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            queue.extend((child, depth + 1) for child in value)
        elif isinstance(value, str) and value not in seen_strings:
            seen_strings.add(value)
            try:
                nested = json.loads(value)
            except ValueError:
                continue
            documents.append(nested)
            queue.append((nested, depth + 1))
    return tuple(documents)


def _standalone_boolean_requests(observation: str) -> tuple[Mapping[str, object], ...]:
    """Recover complete request objects from a middle-clipped specialist document."""
    decoder = json.JSONDecoder()
    requests: list[Mapping[str, object]] = []
    seen: set[str] = set()
    markers = tuple(_BOOLEAN_PHASE_MARKER.finditer(observation))[-_MAX_CONTROL_MARKERS:]
    for marker in markers:
        lower_bound = max(0, marker.start() - _MAX_REQUEST_OBJECT_LOOKBACK)
        for start in range(marker.start(), lower_bound - 1, -1):
            if observation[start] != "{":
                continue
            try:
                candidate, end = decoder.raw_decode(observation[start:])
            except ValueError:
                continue
            if start + end <= marker.start() or not isinstance(candidate, Mapping):
                continue
            if str(candidate.get("phase") or "").lower() != "boolean_probe":
                continue
            identity = json.dumps(candidate, sort_keys=True, default=str)
            if identity not in seen:
                seen.add(identity)
                requests.append(candidate)
            break
    return tuple(requests)


def _walk_mappings(value: object, *, depth: int = 0) -> tuple[Mapping[str, object], ...]:
    if depth > _MAX_DEPTH:
        return ()
    if isinstance(value, Mapping):
        return (
            value,
            *(item for child in value.values() for item in _walk_mappings(child, depth=depth + 1)),
        )
    if isinstance(value, list):
        return tuple(item for child in value for item in _walk_mappings(child, depth=depth + 1))
    return ()


def _literal_assignments(source: str) -> dict[str, str]:
    assignments = {
        match.group("name").lower(): match.group("value") for match in _ASSIGNMENT.finditer(source)
    }
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return assignments
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                assignments[target.id.lower()] = value.value
    return assignments


def _first_assignment(
    assignments: Mapping[str, str],
    names: frozenset[str],
) -> str:
    return next((assignments[name] for name in names if name in assignments), "")


def _normalized_expression(value: str) -> str:
    return value.strip().lower().removesuffix(" confirm").replace(" ", "")


def _normalized_body(value: str) -> str:
    stripped = value.strip()
    try:
        payload = json.loads(stripped)
    except (TypeError, ValueError):
        return " ".join(stripped.split())
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _body_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalized_path(value: str) -> str:
    path = urlsplit(value).path.strip()
    return f"/{path.strip('/')}" if path else "/"


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


__all__ = [
    "SqlOracleAssignmentIssue",
    "SqlOracleContract",
    "authoritative_sql_oracle_for_objective",
    "detect_sql_oracle_assignment_issue",
    "remember_sql_oracle_contracts",
    "remembered_sql_oracle_contracts",
    "sql_oracle_constraints",
    "sql_oracle_contracts_from_observation",
    "sql_oracle_correction_objective",
    "sql_oracle_guard_message",
]
