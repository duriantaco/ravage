# Graph seed admission is additive and trusts structured base observations only.
# ruff: noqa: C901, CPY001, PLR0911, PLR0912

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit, urlunsplit

if TYPE_CHECKING:
    from ravage.agent_core.frontier_route import FrontierObjective

_COMMAND_INPUT_MARKERS = (
    "address",
    "cmd",
    "command",
    "domain",
    "host",
    "hostname",
    "ip",
    "server",
    "target",
    "url",
)
_STATIC_SUFFIXES = frozenset(
    {
        ".css",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".map",
        ".png",
        ".svg",
        ".woff",
        ".woff2",
    }
)
_ENDPOINT_ONLY_PROBES = frozenset(
    {
        "api_behavior",
        "browser_boundary",
        "cms_exposure",
        "direct_exposure",
        "werkzeug_console",
    }
)


def graph_seed_admission_reason(
    state: object,
    objective: FrontierObjective,
    *,
    target_url: str,
) -> str:
    """Return an empty string when a graph seed has a trusted request contract."""
    # Older/fallback base states may contain only normalized signals. Preserve
    # their legacy frontier, but once a structured surface map exists it becomes
    # authoritative and contradictory signal-only routes are not admissible.
    if not _has_structured_inventory(state):
        return ""
    endpoint = _scoped_endpoint(objective.endpoint, target_url=target_url)
    if not endpoint:
        return _reason(objective, "requires_scoped_structured_endpoint")
    path = urlsplit(endpoint).path
    if path.startswith("/static/") or PurePosixPath(path).suffix.lower() in _STATIC_SUFFIXES:
        return _reason(objective, "rejects_static_asset_endpoint")

    structured = _structured_contract(state, endpoint=endpoint, target_url=target_url)
    if structured is None:
        return _reason(objective, "requires_structured_surface_contract")
    bound_inputs, endpoint_hints, form_categories = structured
    objective_inputs = {str(item).strip().lower() for item in objective.inputs if str(item).strip()}
    if (
        objective_inputs
        and objective.probe not in _ENDPOINT_ONLY_PROBES
        and not objective_inputs.intersection(bound_inputs)
    ):
        return _reason(objective, "inputs_not_bound_to_endpoint")

    if objective.family != "command_injection" and objective.probe != "command_boundary":
        return ""
    command_input = any(
        any(marker in name for marker in _COMMAND_INPUT_MARKERS)
        for name in bound_inputs.intersection(objective_inputs)
    )
    explicit_endpoint_hint = bool(
        endpoint_hints.intersection({"command", "command_boundary", "diagnostic"})
    )
    auth_only_form = "auth" in form_categories and not command_input
    if auth_only_form or not (command_input or explicit_endpoint_hint):
        return "command_seed_lacks_command_shaped_input_contract"
    return ""


def _reason(objective: FrontierObjective, suffix: str) -> str:
    family = (
        "command"
        if objective.family == "command_injection" or objective.probe == "command_boundary"
        else objective.family.strip().lower().replace("-", "_")
    )
    return f"{family}_seed_{suffix}"


def _structured_contract(
    state: object,
    *,
    endpoint: str,
    target_url: str,
) -> tuple[set[str], set[str], set[str]] | None:
    surface = getattr(state, "surface", {})
    if not isinstance(surface, Mapping):
        return None
    observed_endpoint = False
    bound_inputs: set[str] = set()
    endpoint_hints: set[str] = set()
    form_categories: set[str] = set()

    for raw in _mapping_sequence(surface.get("endpoints")):
        candidate = _scoped_endpoint(str(raw.get("url") or ""), target_url=target_url)
        if candidate != endpoint:
            continue
        observed_endpoint = True
        endpoint_hints.update(_strings(raw.get("hints")))

    for raw in _mapping_sequence(surface.get("pages")):
        candidate = _scoped_endpoint(
            str(raw.get("final_url") or raw.get("url") or ""),
            target_url=target_url,
        )
        if candidate == endpoint:
            observed_endpoint = True

    for raw in _mapping_sequence(surface.get("forms")):
        candidate = _scoped_endpoint(
            str(raw.get("action") or raw.get("page") or ""),
            target_url=target_url,
        )
        if candidate != endpoint:
            continue
        observed_endpoint = True
        form_categories.update(_strings(raw.get("categories")))
        for item in _mapping_sequence(raw.get("inputs")):
            name = str(item.get("name") or "").strip().lower()
            if name:
                bound_inputs.add(name)

    for raw in _mapping_sequence(surface.get("parameters")):
        locations = {
            candidate
            for value in _strings(raw.get("locations"))
            if (candidate := _scoped_endpoint(value, target_url=target_url))
        }
        if endpoint not in locations:
            continue
        name = str(raw.get("name") or raw.get("input") or "").strip().lower()
        if name:
            bound_inputs.add(name)

    if not observed_endpoint:
        return None
    return bound_inputs, endpoint_hints, form_categories


def _has_structured_inventory(state: object) -> bool:
    surface = getattr(state, "surface", {})
    if not isinstance(surface, Mapping):
        return False
    return any(
        _mapping_sequence(surface.get(key)) for key in ("endpoints", "forms", "pages", "parameters")
    )


def _scoped_endpoint(value: str, *, target_url: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    candidate = urljoin(target_url.rstrip("/") + "/", raw)
    target = urlsplit(target_url)
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if (parsed.hostname, parsed.port) != (target.hostname, target.port):
        return ""
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/") or "/",
            "",
            "",
        )
    )


def _mapping_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _strings(value: object) -> set[str]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return set()
    return {str(item).strip().lower() for item in value if str(item).strip()}


__all__ = ["graph_seed_admission_reason"]
