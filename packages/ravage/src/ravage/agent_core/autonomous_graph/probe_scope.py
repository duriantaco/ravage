# Probe scoping is graph-only and never mutates the frozen inherited state.
# ruff: noqa: CPY001

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState

if TYPE_CHECKING:
    from ravage.agent_core.autonomous_graph.models import GraphObjective

_FORM_ACTION = re.compile(
    r"\baction\s*=\s*[\"']?([^\"'\s>]+)",
    flags=re.IGNORECASE,
)
_FORM_METHOD = re.compile(
    r"\bmethod\s*=\s*[\"']?([A-Za-z]+)",
    flags=re.IGNORECASE,
)
_SQL_PROBES = frozenset(
    {
        "filtered_query_bypass",
        "preg_match_subject",
        "sqli_differential",
        "sqli_exploit",
    }
)
_SCOPED_SIGNAL_KEYS = frozenset(
    {
        "endpoints",
        "forms",
        "parameters",
        "sqli_inputs",
        "sqli_replays",
    }
)


@dataclass(frozen=True)
class GraphProbeScope:
    state: AgentState
    applied: bool
    endpoint: str = ""
    inputs: tuple[str, ...] = ()
    reason: str = ""


def scope_graph_probe_state(
    state: AgentState,
    *,
    objective: GraphObjective,
    action: Mapping[str, object],
) -> GraphProbeScope:
    probe = str(action.get("probe") or "").strip()
    endpoint = _canonical_url(objective.endpoint)
    inputs = _clean_inputs(objective.inputs)
    if (
        action.get("action") != "run_probe"
        or objective.family != "sql_injection"
        or probe not in _SQL_PROBES
        or not endpoint
        or not inputs
    ):
        return GraphProbeScope(
            state=state,
            applied=False,
            reason="graph_probe_scope_not_applicable",
        )
    scoped = AgentState.from_json(state.to_json())
    matching_forms = _matching_structured_forms(
        state,
        endpoint=endpoint,
    )
    observed_method = _observed_form_method(
        state,
        endpoint=endpoint,
    )
    if not matching_forms and observed_method:
        matching_forms = [
            {
                "action": endpoint,
                "method": observed_method,
                "inputs": [
                    {
                        "name": name,
                        "type": "text",
                        "value": "",
                    }
                    for name in inputs
                ],
                "categories": ["query", "graph_objective"],
            }
        ]
    scoped.surface["endpoints"] = [
        {
            "url": endpoint,
            "hints": ["query", "graph_objective"],
            "priority": 1_000,
            "sources": ["graph_objective"],
        }
    ]
    scoped.surface["parameters"] = (
        []
        if matching_forms
        else [
            {
                "name": name,
                "locations": [endpoint],
                "sources": ["graph_objective"],
                "hints": ["graph_objective"],
                "priority": 1_000,
            }
            for name in inputs
        ]
    )
    scoped.surface["forms"] = matching_forms
    scoped.surface["pages"] = []
    scoped.surface["request_templates"] = _matching_request_templates(
        state,
        endpoint=endpoint,
        inputs=inputs,
    )
    preserved_signals = {
        key: list(values)
        for key, values in scoped.signals.items()
        if key not in _SCOPED_SIGNAL_KEYS
    }
    preserved_signals.update(
        {
            "endpoints": [endpoint],
            "parameters": [] if matching_forms else list(inputs),
            "forms": _matching_form_signals(state, endpoint=endpoint),
            "sqli_inputs": _matching_json_signals(
                state.signals.get("sqli_inputs", []),
                endpoint=endpoint,
                inputs=inputs,
                input_key="input",
            ),
            "sqli_replays": _matching_json_signals(
                state.signals.get("sqli_replays", []),
                endpoint=endpoint,
                inputs=inputs,
                input_key="payload_field",
            ),
        }
    )
    scoped.signals = preserved_signals
    return GraphProbeScope(
        state=scoped,
        applied=True,
        endpoint=endpoint,
        inputs=inputs,
        reason="sql_probe_bound_to_graph_objective_contract",
    )


def _matching_structured_forms(
    state: AgentState,
    *,
    endpoint: str,
) -> list[dict[str, object]]:
    raw_forms = state.surface.get("forms")
    if not isinstance(raw_forms, Sequence) or isinstance(raw_forms, str):
        return []
    forms: list[dict[str, object]] = []
    for raw in raw_forms:
        if not isinstance(raw, Mapping):
            continue
        action = _resolve_url(
            str(raw.get("action") or ""),
            base=endpoint,
        )
        if _same_url(action, endpoint):
            forms.append(dict(raw))
    return forms


def _observed_form_method(
    state: AgentState,
    *,
    endpoint: str,
) -> str:
    for raw in state.signals.get("forms", []):
        text = _normalized_form_text(raw)
        action_match = _FORM_ACTION.search(text)
        if action_match is None:
            continue
        action = _resolve_url(action_match.group(1), base=endpoint)
        if not _same_url(action, endpoint):
            continue
        method_match = _FORM_METHOD.search(text)
        return method_match.group(1).upper() if method_match is not None else "GET"
    return ""


def _matching_form_signals(
    state: AgentState,
    *,
    endpoint: str,
) -> list[str]:
    matches: list[str] = []
    for raw in state.signals.get("forms", []):
        text = _normalized_form_text(raw)
        action_match = _FORM_ACTION.search(text)
        if action_match is None:
            continue
        action = _resolve_url(action_match.group(1), base=endpoint)
        if _same_url(action, endpoint):
            matches.append(text)
    return matches


def _matching_request_templates(
    state: AgentState,
    *,
    endpoint: str,
    inputs: tuple[str, ...],
) -> list[dict[str, object]]:
    raw_templates = state.surface.get("request_templates")
    if not isinstance(raw_templates, Sequence) or isinstance(raw_templates, str):
        return []
    matches: list[dict[str, object]] = []
    for raw in raw_templates:
        if not isinstance(raw, Mapping):
            continue
        url = _canonical_url(str(raw.get("url") or raw.get("endpoint") or ""))
        input_name = str(raw.get("payload_field") or raw.get("input") or "").strip()
        if _same_url(url, endpoint) and (not input_name or input_name in inputs):
            matches.append(dict(raw))
    return matches


def _matching_json_signals(
    values: Sequence[str],
    *,
    endpoint: str,
    inputs: tuple[str, ...],
    input_key: str,
) -> list[str]:
    matches: list[str] = []
    for raw in values:
        try:
            payload = json.loads(str(raw))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, Mapping):
            continue
        url = _canonical_url(str(payload.get("url") or ""))
        input_name = str(payload.get(input_key) or "").strip()
        if _same_url(url, endpoint) and input_name in inputs:
            matches.append(str(raw))
    return matches


def _clean_inputs(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


def _normalized_form_text(value: object) -> str:
    return str(value).replace('\\"', '"').replace("\\'", "'")


def _resolve_url(value: str, *, base: str) -> str:
    return _canonical_url(urljoin(base, value.strip()))


def _canonical_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    hostname = parsed.hostname.lower()
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = hostname if port in {None, default_port} else f"{hostname}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def _same_url(left: str, right: str) -> bool:
    return _canonical_url(left).rstrip("/") == _canonical_url(right).rstrip("/")


__all__ = [
    "GraphProbeScope",
    "scope_graph_probe_state",
]
