"""Pure, deterministic planning for the adaptive deterministic scanner."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.surface_graph import SurfaceOperation, SurfaceParameter
from ravage.probe_suite_parts.result import ProbeRunResult

SCAN_PLAN_SCHEMA = "ravage.scan-plan.v1"

# These are the historical default probes.  Adaptive planning is additive: a
# lack of surface evidence must never make the established default scan smaller.
DEFAULT_SCAN_PROBES = (
    "surface_map",
    "secret_sweep",
    "direct_exposure",
    "api_behavior",
    "csrf_session",
    "browser_boundary",
)

DISCOVERY_SCAN_PROBES = (
    "surface_map",
    "secret_sweep",
    "direct_exposure",
    "api_behavior",
    "browser_boundary",
)

BREADTH_SCAN_PROBES = (
    "stateful_session",
    "csrf_session",
    "input_reflection",
    "xss_context",
    "default_credentials",
    "server_rendering",
    "ssti_fingerprint",
    "data_query",
    "sqli_differential",
    "cms_exposure",
    "command_boundary",
    "ssrf_boundary",
    "file_fetch_parser",
    "xxe_boundary",
    "cookie_deserialization",
    "captcha_form_state",
    "graphql_exploit",
    "idor_boundary",
)

DEPTH_SCAN_PROBES = (
    "sqli_exploit",
    "filtered_query_bypass",
    "preg_match_subject",
    "reflection_value_boundary",
    "file_read_extract",
    "jwt_exploit",
    "werkzeug_console",
    "dom_execution",
    "sqli_auth_transition",
    "ssti_deferred_context_closure",
    "xss_filter_constraint",
)

SCAN_PROBE_CATALOG = (
    *DISCOVERY_SCAN_PROBES,
    *BREADTH_SCAN_PROBES,
    *DEPTH_SCAN_PROBES,
)

SCAN_PROBE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "browser_boundary": ("surface_map",),
    "captcha_form_state": ("stateful_session",),
    "cms_exposure": ("direct_exposure",),
    "cookie_deserialization": ("stateful_session",),
    "csrf_session": ("stateful_session",),
    "dom_execution": ("xss_context", "xss_filter_constraint"),
    "file_read_extract": ("file_fetch_parser",),
    "filtered_query_bypass": ("sqli_differential",),
    "graphql_exploit": ("api_behavior",),
    "idor_boundary": ("api_behavior", "stateful_session"),
    "jwt_exploit": ("api_behavior", "stateful_session"),
    "preg_match_subject": ("sqli_differential",),
    "reflection_value_boundary": ("input_reflection",),
    "sqli_auth_transition": ("sqli_exploit",),
    "sqli_exploit": ("data_query", "sqli_differential"),
    "ssti_deferred_context_closure": ("ssti_fingerprint",),
    "ssti_fingerprint": ("server_rendering",),
    "werkzeug_console": ("direct_exposure",),
    "xss_context": ("input_reflection",),
    "xss_filter_constraint": ("xss_context",),
}


class ScanPlanPhase(StrEnum):
    """Stable breadth-before-depth execution phase."""

    DISCOVERY = "discovery"
    BREADTH = "breadth"
    DEPTH = "depth"


class ScanPlanStatus(StrEnum):
    """Coverage state for one catalog probe."""

    SELECTED = "selected"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class ScanPlanDecision:
    """Immutable, reportable decision for one probe in the catalog."""

    probe: str
    phase: ScanPlanPhase
    status: ScanPlanStatus
    reasons: tuple[str, ...]
    dependencies: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "probe": self.probe,
            "phase": self.phase.value,
            "status": self.status.value,
            "reasons": list(self.reasons),
            "dependencies": list(self.dependencies),
        }


@dataclass(frozen=True, slots=True)
class ScanPlan:
    """Pending probes plus a complete coverage decision ledger."""

    probes: tuple[str, ...]
    decisions: tuple[ScanPlanDecision, ...]
    evidence_facts: tuple[str, ...]

    def decision_for(self, probe: str) -> ScanPlanDecision:
        for decision in self.decisions:
            if decision.probe == probe:
                return decision
        raise KeyError(probe)

    def to_json(self) -> dict[str, object]:
        counts = {
            status.value: sum(decision.status is status for decision in self.decisions)
            for status in ScanPlanStatus
        }
        return {
            "schema": SCAN_PLAN_SCHEMA,
            "probes": list(self.probes),
            "evidence_facts": list(self.evidence_facts),
            "counts": counts,
            "decisions": [decision.to_json() for decision in self.decisions],
        }


_PHASE_BY_PROBE = {
    **dict.fromkeys(DISCOVERY_SCAN_PROBES, ScanPlanPhase.DISCOVERY),
    **dict.fromkeys(BREADTH_SCAN_PROBES, ScanPlanPhase.BREADTH),
    **dict.fromkeys(DEPTH_SCAN_PROBES, ScanPlanPhase.DEPTH),
}
_CANONICAL_INDEX = {probe: index for index, probe in enumerate(SCAN_PROBE_CATALOG)}

_GENERIC_INPUT_PROBES = ("input_reflection", "data_query", "sqli_differential")
_FACT_PROBES: dict[str, tuple[str, ...]] = {
    "command_input": ("command_boundary",),
    "cookie_input": ("cookie_deserialization",),
    "file_input": ("file_fetch_parser",),
    "graphql_operation": ("graphql_exploit",),
    "object_reference": ("idor_boundary",),
    "template_input": ("server_rendering", "ssti_fingerprint"),
    "url_input": ("ssrf_boundary",),
    "xml_input": ("xxe_boundary",),
}

# A finding can route work only when both its producer and exact finding type
# match.  Free-form state text and a finding emitted under another probe name do
# not satisfy this trust boundary.
_TRUSTED_FINDING_ROUTES: dict[tuple[str, str], tuple[str, ...]] = {
    ("api_behavior", "graphql_exposed_proof"): ("graphql_exploit",),
    ("api_behavior", "jwt_observed"): ("jwt_exploit",),
    ("file_fetch_parser", "file_fetch_parser_signal"): ("file_read_extract",),
    ("file_fetch_parser", "file_read_extracted_content"): ("file_read_extract",),
    ("file_fetch_parser", "file_read_extracted_proof"): ("file_read_extract",),
    ("file_fetch_parser", "php_include_execution"): ("file_read_extract",),
    ("input_reflection", "form_input_delta"): (
        "xss_context",
        "reflection_value_boundary",
    ),
    ("input_reflection", "input_delta"): (
        "xss_context",
        "reflection_value_boundary",
    ),
    ("sqli_differential", "blind_sql_injection_boolean_signal"): (
        "sqli_exploit",
        "filtered_query_bypass",
    ),
    ("sqli_differential", "blind_sql_injection_timing_signal"): (
        "sqli_exploit",
        "filtered_query_bypass",
    ),
    ("sqli_differential", "sql_injection_error_signal"): (
        "sqli_exploit",
        "filtered_query_bypass",
    ),
    ("sqli_differential", "sqli_auth_bypass_proof"): (
        "sqli_exploit",
        "sqli_auth_transition",
    ),
    ("sqli_differential", "sqli_auth_bypass_signal"): (
        "sqli_exploit",
        "sqli_auth_transition",
    ),
    ("sqli_differential", "sqli_objective_value_bypass_proof"): (
        "sqli_exploit",
        "filtered_query_bypass",
    ),
    ("sqli_differential", "sqli_objective_value_bypass_signal"): (
        "sqli_exploit",
        "filtered_query_bypass",
    ),
    ("sqli_exploit", "sqli_auth_bypass_session"): ("sqli_auth_transition",),
    ("ssti_fingerprint", "ssti_engine_execution"): ("ssti_deferred_context_closure",),
    ("ssti_fingerprint", "ssti_extracted_proof"): ("ssti_deferred_context_closure",),
    ("ssti_fingerprint", "ssti_fingerprint_signal"): ("ssti_deferred_context_closure",),
    ("xss_context", "xss_reflection_context"): (
        "xss_filter_constraint",
        "dom_execution",
    ),
    ("xss_filter_constraint", "xss_filter_constraint_proof"): ("dom_execution",),
}

_OBJECT_PARAMETER_NAMES = frozenset(
    {
        "account_id",
        "customer_id",
        "document_id",
        "id",
        "invoice_id",
        "item_id",
        "object_id",
        "order_id",
        "org_id",
        "organization_id",
        "project_id",
        "tenant_id",
        "user_id",
    }
)
_FILE_PARAMETER_NAMES = frozenset(
    {
        "doc",
        "document",
        "file",
        "filename",
        "filepath",
        "include",
        "page",
        "path",
        "upload",
    }
)
_URL_PARAMETER_NAMES = frozenset(
    {
        "callback",
        "dest",
        "destination",
        "feed",
        "next",
        "redirect",
        "target",
        "uri",
        "url",
        "webhook",
    }
)
_COMMAND_PARAMETER_NAMES = frozenset({"cmd", "command", "exec", "execute", "process", "shell"})
_TEMPLATE_PARAMETER_NAMES = frozenset({"layout", "render", "renderer", "template", "theme", "view"})
_COOKIE_PARAMETER_NAMES = frozenset({"cookie", "session", "session_cookie"})
_FILE_DATA_TYPES = frozenset({"binary", "byte", "file", "path", "upload"})
_URL_DATA_TYPES = frozenset({"uri", "url"})
_XML_DATA_TYPES = frozenset({"soap", "xml"})
_COMMAND_DATA_TYPES = frozenset({"command", "shell"})
_TEMPLATE_DATA_TYPES = frozenset({"template"})
_XML_CONTENT_TYPES = frozenset({"application/soap+xml", "application/xml", "text/xml"})
_SIGNAL_FACTS: dict[str, str] = {
    "command_inputs": "command_input",
    "command_parameters": "command_input",
    "cookies": "cookie_input",
    "file_inputs": "file_input",
    "file_read_inputs": "file_input",
    "graphql_endpoints": "graphql_operation",
    "graphql_operations": "graphql_operation",
    "idor_candidates": "object_reference",
    "object_ids": "object_reference",
    "object_parameters": "object_reference",
    "ssrf_inputs": "url_input",
    "template_inputs": "template_input",
    "template_parameters": "template_input",
    "upload_inputs": "file_input",
    "url_inputs": "url_input",
    "url_parameters": "url_input",
    "xml_endpoints": "xml_input",
    "xml_inputs": "xml_input",
}


def build_adaptive_scan_plan(
    state: AgentState,
    *,
    prior_results: Sequence[ProbeRunResult] = (),
    catalog: Sequence[str] = SCAN_PROBE_CATALOG,
) -> ScanPlan:
    """Build a stable, breadth-before-depth plan without mutating inputs."""
    if not isinstance(state, AgentState):
        message = "state must be an AgentState"
        raise TypeError(message)
    normalized_catalog = _normalize_catalog(catalog)
    results = _trusted_results(prior_results)
    completed = frozenset(result.probe for result in results)
    facts = _surface_facts(state)
    reasons = _selection_reasons(facts=facts, results=results)
    catalog_set = frozenset(normalized_catalog)
    applicable = set(reasons) & catalog_set
    _add_dependencies(applicable, reasons=reasons, catalog=catalog_set, completed=completed)
    blocked = _blocked_probes(
        applicable,
        catalog=catalog_set,
        completed=completed,
        reasons=reasons,
    )
    pending = applicable - completed - blocked
    probes = _dependency_ordered(pending, completed=completed)
    return ScanPlan(
        probes=probes,
        decisions=_build_decisions(
            normalized_catalog,
            completed=completed,
            blocked=blocked,
            pending=pending,
            reasons=reasons,
        ),
        evidence_facts=tuple(sorted(facts)),
    )


def _selection_reasons(
    *,
    facts: frozenset[str],
    results: tuple[ProbeRunResult, ...],
) -> dict[str, set[str]]:
    reasons: dict[str, set[str]] = {}
    for probe in DEFAULT_SCAN_PROBES:
        _add_reason(reasons, probe, "required_default")
    if "parameter" in facts:
        for probe in _GENERIC_INPUT_PROBES:
            _add_reason(reasons, probe, "surface:parameter")
    for fact in sorted(facts):
        for probe in _FACT_PROBES.get(fact, ()):
            _add_reason(reasons, probe, f"surface:{fact}")
    for result in results:
        _add_result_reasons(reasons, result)
    return reasons


def _add_result_reasons(reasons: dict[str, set[str]], result: ProbeRunResult) -> None:
    for finding_type in _finding_types(result):
        route = _TRUSTED_FINDING_ROUTES.get((result.probe, finding_type), ())
        for probe in route:
            _add_reason(reasons, probe, f"finding:{result.probe}:{finding_type}")


def _build_decisions(
    catalog: Sequence[str],
    *,
    completed: frozenset[str],
    blocked: set[str],
    pending: set[str],
    reasons: dict[str, set[str]],
) -> tuple[ScanPlanDecision, ...]:
    return tuple(
        _decision_for_probe(
            probe,
            completed=completed,
            blocked=blocked,
            pending=pending,
            reasons=reasons,
        )
        for probe in _ordered_catalog(catalog)
    )


def _decision_for_probe(
    probe: str,
    *,
    completed: frozenset[str],
    blocked: set[str],
    pending: set[str],
    reasons: dict[str, set[str]],
) -> ScanPlanDecision:
    if probe in completed:
        status = ScanPlanStatus.COMPLETED
        probe_reasons = set(reasons.get(probe, ())) | {"trusted_result:completed"}
    elif probe in blocked:
        status = ScanPlanStatus.BLOCKED
        probe_reasons = reasons.get(probe, set())
    elif probe in pending:
        status = ScanPlanStatus.SELECTED
        probe_reasons = reasons.get(probe, set())
    else:
        status = ScanPlanStatus.NOT_APPLICABLE
        probe_reasons = set()
    return ScanPlanDecision(
        probe=probe,
        phase=_phase_for(probe),
        status=status,
        reasons=tuple(sorted(probe_reasons)),
        dependencies=SCAN_PROBE_DEPENDENCIES.get(probe, ()),
    )


def _normalize_catalog(catalog: Sequence[str]) -> tuple[str, ...]:
    if isinstance(catalog, (str, bytes)):
        message = "catalog must be a sequence of probe names"
        raise TypeError(message)
    probes = tuple(str(probe).strip() for probe in catalog)
    if any(not probe for probe in probes):
        message = "catalog probe names cannot be empty"
        raise ValueError(message)
    if len(probes) != len(set(probes)):
        message = "catalog probe names must be unique"
        raise ValueError(message)
    return probes


def _trusted_results(results: Sequence[ProbeRunResult]) -> tuple[ProbeRunResult, ...]:
    if isinstance(results, (str, bytes)):
        message = "prior_results must contain ProbeRunResult objects"
        raise TypeError(message)
    trusted = tuple(results)
    if any(not isinstance(result, ProbeRunResult) for result in trusted):
        message = "prior_results must contain ProbeRunResult objects"
        raise TypeError(message)
    return trusted


def _finding_types(result: ProbeRunResult) -> tuple[str, ...]:
    finding_types = {
        str(finding.get("type") or "").strip()
        for finding in result.findings
        if isinstance(finding, Mapping) and str(finding.get("type") or "").strip()
    }
    return tuple(sorted(finding_types))


def _add_reason(reasons: dict[str, set[str]], probe: str, reason: str) -> None:
    reasons.setdefault(probe, set()).add(reason)


def _add_dependencies(
    applicable: set[str],
    *,
    reasons: dict[str, set[str]],
    catalog: frozenset[str],
    completed: frozenset[str],
) -> None:
    pending = sorted(applicable, key=_probe_sort_key)
    while pending:
        probe = pending.pop(0)
        for dependency in SCAN_PROBE_DEPENDENCIES.get(probe, ()):
            if dependency in completed or dependency not in catalog:
                continue
            _add_reason(reasons, dependency, f"dependency:{probe}")
            if dependency not in applicable:
                applicable.add(dependency)
                pending.append(dependency)
                pending.sort(key=_probe_sort_key)


def _blocked_probes(
    applicable: set[str],
    *,
    catalog: frozenset[str],
    completed: frozenset[str],
    reasons: dict[str, set[str]],
) -> set[str]:
    blocked: set[str] = set()
    changed = True
    while changed:
        changed = False
        for probe in sorted(applicable, key=_probe_sort_key):
            if probe in blocked or probe in completed:
                continue
            dependencies = SCAN_PROBE_DEPENDENCIES.get(probe, ())
            missing = next(
                (
                    dependency
                    for dependency in dependencies
                    if dependency not in completed
                    and (dependency not in catalog or dependency in blocked)
                ),
                "",
            )
            if not missing:
                continue
            blocked.add(probe)
            _add_reason(reasons, probe, f"missing_dependency:{missing}")
            changed = True
    return blocked


def _dependency_ordered(
    pending: set[str],
    *,
    completed: frozenset[str],
) -> tuple[str, ...]:
    remaining = set(pending)
    ordered: list[str] = []
    satisfied = set(completed)
    while remaining:
        ready = [
            probe
            for probe in remaining
            if all(
                dependency in satisfied or dependency not in pending
                for dependency in SCAN_PROBE_DEPENDENCIES.get(probe, ())
            )
        ]
        if not ready:
            unresolved = ", ".join(sorted(remaining))
            message = f"cyclic adaptive scan probe dependencies: {unresolved}"
            raise RuntimeError(message)
        probe = min(ready, key=_probe_sort_key)
        ordered.append(probe)
        satisfied.add(probe)
        remaining.remove(probe)
    return tuple(ordered)


def _ordered_catalog(catalog: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(catalog, key=_probe_sort_key))


def _probe_sort_key(probe: str) -> tuple[int, int, str]:
    phase = _phase_for(probe)
    phase_rank = {
        ScanPlanPhase.DISCOVERY: 0,
        ScanPlanPhase.BREADTH: 1,
        ScanPlanPhase.DEPTH: 2,
    }[phase]
    return phase_rank, _CANONICAL_INDEX.get(probe, len(_CANONICAL_INDEX)), probe


def _phase_for(probe: str) -> ScanPlanPhase:
    return _PHASE_BY_PROBE.get(probe, ScanPlanPhase.BREADTH)


def _surface_facts(state: AgentState) -> frozenset[str]:
    facts: set[str] = set()
    operations = state.surface_graph.operations or {}
    for operation in sorted(operations.values(), key=lambda item: item.operation_id):
        _facts_from_operation(facts, operation)
    _facts_from_legacy_surface(facts, state.surface)
    _facts_from_signals(facts, state.signals)
    return frozenset(facts)


def _facts_from_operation(facts: set[str], operation: SurfaceOperation) -> None:
    if operation.parameters:
        facts.add("parameter")
    if (
        operation.selector.startswith(("Query.", "Mutation.", "Subscription."))
        or "graphql" in operation.provenance
        or "graphql" in operation.hints
    ):
        facts.add("graphql_operation")
    if "{" in operation.route_shape:
        facts.add("object_reference")
    _facts_from_metadata(
        facts,
        content_types=operation.content_types,
        hints=operation.hints,
    )
    for parameter in operation.parameters:
        _facts_from_parameter(facts, parameter)


def _facts_from_parameter(facts: set[str], parameter: SurfaceParameter) -> None:
    name = parameter.name.casefold()
    data_type = parameter.data_type.casefold()
    if parameter.location == "graphql":
        facts.add("graphql_operation")
    if parameter.location == "cookie" or name in _COOKIE_PARAMETER_NAMES:
        facts.add("cookie_input")
    if parameter.location == "path" or name in _OBJECT_PARAMETER_NAMES:
        facts.add("object_reference")
    if name in _FILE_PARAMETER_NAMES or data_type in _FILE_DATA_TYPES:
        facts.add("file_input")
    if name in _URL_PARAMETER_NAMES or data_type in _URL_DATA_TYPES:
        facts.add("url_input")
    if name in _COMMAND_PARAMETER_NAMES or data_type in _COMMAND_DATA_TYPES:
        facts.add("command_input")
    if name in _TEMPLATE_PARAMETER_NAMES or data_type in _TEMPLATE_DATA_TYPES:
        facts.add("template_input")
    if data_type in _XML_DATA_TYPES:
        facts.add("xml_input")


def _facts_from_metadata(
    facts: set[str],
    *,
    content_types: Sequence[str] = (),
    hints: Sequence[str] = (),
) -> None:
    normalized_content_types = {
        str(value).split(";", 1)[0].strip().casefold() for value in content_types
    }
    normalized_hints = {str(value).strip().casefold() for value in hints}
    if normalized_content_types & _XML_CONTENT_TYPES or normalized_hints & {"soap", "xml"}:
        facts.add("xml_input")
    if "graphql" in normalized_hints:
        facts.add("graphql_operation")
    if normalized_hints & {"command", "exec", "shell"}:
        facts.add("command_input")
    if normalized_hints & {"file", "include", "upload"}:
        facts.add("file_input")
    if normalized_hints & {"render", "template", "view"}:
        facts.add("template_input")
    if normalized_hints & {"callback", "ssrf", "url", "webhook"}:
        facts.add("url_input")


def _facts_from_legacy_surface(facts: set[str], surface: Mapping[str, object]) -> None:
    _facts_from_legacy_parameters(facts, surface.get("parameters"))
    _facts_from_legacy_templates(facts, surface.get("request_templates"))
    _facts_from_legacy_endpoints(facts, surface.get("endpoints"))
    _facts_from_legacy_forms(facts, surface.get("forms"))


def _facts_from_legacy_parameters(facts: set[str], value: object) -> None:
    for raw_parameter in _mapping_items(value):
        name = str(raw_parameter.get("name") or "").strip()
        locations = _string_items(raw_parameter.get("sources"))
        locations += _string_items(raw_parameter.get("location"))
        data_types = _string_items(raw_parameter.get("data_types"))
        data_types += _string_items(raw_parameter.get("data_type"))
        if name:
            facts.add("parameter")
            _facts_from_parameter(
                facts,
                SurfaceParameter.create(
                    name=name,
                    location=_legacy_parameter_location(locations),
                    data_type=data_types[0] if data_types else "unknown",
                ),
            )


def _facts_from_legacy_templates(facts: set[str], value: object) -> None:
    for template in _mapping_items(value):
        fields = template.get("fields")
        if isinstance(fields, Mapping) and fields:
            facts.add("parameter")
        selector = str(template.get("selector") or "")
        if selector.startswith(("Query.", "Mutation.", "Subscription.")):
            facts.add("graphql_operation")
        _facts_from_metadata(
            facts,
            content_types=_string_items(template.get("content_types")),
            hints=_string_items(template.get("hints")),
        )


def _facts_from_legacy_endpoints(facts: set[str], value: object) -> None:
    for endpoint in _mapping_items(value):
        if "{" in str(endpoint.get("url") or ""):
            facts.add("object_reference")
        _facts_from_metadata(
            facts,
            content_types=_string_items(endpoint.get("content_types")),
            hints=_string_items(endpoint.get("hints")),
        )


def _facts_from_legacy_forms(facts: set[str], value: object) -> None:
    for form in _mapping_items(value):
        for raw_input in _mapping_items(form.get("inputs")):
            name = str(raw_input.get("name") or "").strip()
            if not name:
                continue
            facts.add("parameter")
            input_type = str(raw_input.get("type") or "unknown")
            _facts_from_parameter(
                facts,
                SurfaceParameter.create(
                    name=name,
                    location="form",
                    data_type=input_type,
                ),
            )
        _facts_from_metadata(
            facts,
            content_types=_string_items(form.get("enctype")),
        )


def _facts_from_signals(facts: set[str], signals: Mapping[str, Sequence[str]]) -> None:
    for key in sorted(signals):
        values = signals.get(key)
        if not values:
            continue
        normalized_key = str(key).strip().casefold()
        if normalized_key in {"forms", "parameters", "request_templates"}:
            facts.add("parameter")
        fact = _SIGNAL_FACTS.get(normalized_key)
        if fact:
            facts.add(fact)


def _mapping_items(value: object, *, limit: int = 512) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value[:limit] if isinstance(item, Mapping))


def _string_items(value: object, *, limit: int = 64) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if not isinstance(value, Sequence) or isinstance(value, bytes):
        return []
    return [str(item) for item in value[:limit] if str(item).strip()]


def _legacy_parameter_location(values: Sequence[str]) -> str:
    for value in values:
        normalized = value.rsplit(":", 1)[-1].strip().casefold()
        if normalized in {"body", "cookie", "form", "graphql", "header", "path", "query"}:
            return normalized
    return "unknown"


__all__ = [
    "BREADTH_SCAN_PROBES",
    "DEFAULT_SCAN_PROBES",
    "DEPTH_SCAN_PROBES",
    "DISCOVERY_SCAN_PROBES",
    "SCAN_PLAN_SCHEMA",
    "SCAN_PROBE_CATALOG",
    "SCAN_PROBE_DEPENDENCIES",
    "ScanPlan",
    "ScanPlanDecision",
    "ScanPlanPhase",
    "ScanPlanStatus",
    "build_adaptive_scan_plan",
]
