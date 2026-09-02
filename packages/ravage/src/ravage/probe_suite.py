from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
from urllib.parse import urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents import xss_filter_constraint
from ravage.deterministic_agents.reflection_value import probe_reflection_value_boundary
from ravage.deterministic_agents.ssrf import probe_ssrf_boundary
from ravage.probe_suite_parts.command.command import probe_command_boundary
from ravage.probe_suite_parts.dom import probe_dom_execution
from ravage.probe_suite_parts.general.general import (
    probe_api_behavior,
    probe_default_credentials_runner,
    probe_direct_exposure,
    probe_file_fetch_parser,
    probe_file_read_extract_runner,
    probe_idor_boundary_runner,
    probe_input_reflection,
    probe_secret_sweep,
    probe_server_rendering,
    probe_ssti_fingerprint_runner,
    probe_stateful_session,
    probe_surface_map,
    probe_xss_context,
)
from ravage.probe_suite_parts.result import ProbeName, ProbeRunResult
from ravage.probe_suite_parts.sqli.sqli import (
    probe_data_query,
    probe_filtered_query_bypass,
    probe_preg_match_subject,
    probe_sqli_differential,
    probe_sqli_exploit_runner,
)
from ravage.probe_suite_parts.support import _probe_catalog, _safe_host_header
from ravage.probes.captcha_form_state import probe_captcha_form_state
from ravage.probes.cms.cms_exposure import probe_cms_exposure
from ravage.probes.cookie.cookie_deserialization import probe_cookie_deserialization
from ravage.probes.graphql_exploit import probe_graphql_exploit
from ravage.probes.jwt_exploit import probe_jwt_exploit
from ravage.probes.sqli_auth_transition import (
    PROBE_NAME as SQLI_AUTH_TRANSITION_PROBE_NAME,
)
from ravage.probes.sqli_auth_transition import (
    PROBE_PURPOSE as SQLI_AUTH_TRANSITION_PROBE_PURPOSE,
)
from ravage.probes.sqli_auth_transition import probe_sqli_auth_transition
from ravage.probes.ssti_deferred_context import (
    PROBE_NAME as SSTI_DEFERRED_CONTEXT_PROBE_NAME,
)
from ravage.probes.ssti_deferred_context import (
    PROBE_PURPOSE as SSTI_DEFERRED_CONTEXT_PROBE_PURPOSE,
)
from ravage.probes.ssti_deferred_context import (
    probe_ssti_deferred_context_closure,
)
from ravage.probes.web_boundaries import probe_browser_boundary, probe_csrf_session
from ravage.probes.werkzeug_console import probe_werkzeug_console
from ravage.probes.xxe import probe_xxe_boundary
from ravage.runtime.browser import EXEC_BINDING, browser_backend_status, render_request, render_url
from ravage.traffic.policy import TrafficPolicyController
from ravage.web_core.http_probe import ProbeSession, ProbeTrafficPolicyStopError

ProbeHandler = Callable[[ProbeSession, AgentState], ProbeRunResult]
_ANONYMOUS_SESSION_PROBES = frozenset(
    {
        "default_credentials",
        SQLI_AUTH_TRANSITION_PROBE_NAME,
        "stateful_session",
    }
)
_EXTERNAL_PROCESS_PROBES = frozenset({"captcha_form_state", "dom_execution"})
_AUTHENTICATED_UNAVAILABLE_PROBES = {
    "browser_boundary": (
        "raw WebSocket transport cannot traverse the managed identity owner or preserve "
        "its credentials and refresh semantics"
    ),
    "captcha_form_state": "requires an external process that cannot receive managed credentials",
    "cms_exposure": "managed binary downloads require an owner-controlled adapter",
    "dom_execution": "requires an external process that cannot receive managed credentials",
}


def available_probes() -> list[dict[str, str]]:
    probes: list[dict[str, str]] = []
    catalog = (
        *_probe_catalog(),
        (SQLI_AUTH_TRANSITION_PROBE_NAME, SQLI_AUTH_TRANSITION_PROBE_PURPOSE),
        (SSTI_DEFERRED_CONTEXT_PROBE_NAME, SSTI_DEFERRED_CONTEXT_PROBE_PURPOSE),
        (xss_filter_constraint.PROBE_NAME, xss_filter_constraint.PROBE_PURPOSE),
    )
    for name, purpose in catalog:
        probes.append({"name": name, "purpose": purpose})
    return probes


def probe_requires_anonymous_session(probe: str) -> bool:
    """Whether a probe must establish and verify its own authentication boundary."""
    return probe in _ANONYMOUS_SESSION_PROBES


def probe_requires_external_process(probe: str) -> bool:
    """Whether a probe can launch a local process outside the managed HTTP owner."""
    return probe in _EXTERNAL_PROCESS_PROBES


def authenticated_probe_unavailability(probe: str) -> str:
    """Explain why a probe cannot preserve a managed attack identity."""
    return _AUTHENTICATED_UNAVAILABLE_PROBES.get(probe, "")


def authenticated_unavailable_probes() -> dict[str, str]:
    """Return the stable managed-auth probe exclusion catalog."""
    return dict(_AUTHENTICATED_UNAVAILABLE_PROBES)


def _canonical_host_default_headers(state: AgentState) -> dict[str, str] | None:
    for value in state.signals.get("canonical_hosts", []):
        host = str(value).strip()
        if _safe_host_header(host):
            return {"Host": host}
    return None


def run_builtin_probe(  # noqa: PLR0913
    probe: ProbeName,
    *,
    target_url: str,
    state: AgentState,
    timeout_seconds: int = 10,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] | None = None,
    out_of_scope: Sequence[str] = (),
    max_rps: float | None = None,
    session: ProbeSession | None = None,
    traffic_observer: Callable[[dict[str, object]], None] | None = None,
    traffic_policy: TrafficPolicyController | None = None,
    traffic_policy_reference: dict[str, object] | None = None,
) -> ProbeRunResult:
    default_headers = _canonical_host_default_headers(state)
    if session is not None:
        _validate_supplied_session(target_url=target_url, session=session)
        if traffic_policy is not None or traffic_policy_reference is not None:
            message = "traffic policy cannot be supplied with an existing session"
            raise ValueError(message)
        if traffic_observer is not None:
            message = (
                "traffic_observer cannot be supplied with an existing session; "
                "configure the observer when constructing ProbeSession"
            )
            raise ValueError(message)
        _merge_canonical_host(session=session, default_headers=default_headers)
    else:
        scoped_session = (
            allow_remote_target
            or in_scope is not None
            or bool(out_of_scope)
            or max_rps is not None
            or traffic_policy is not None
            or traffic_policy_reference is not None
        )
        if scoped_session:
            session = ProbeSession(
                target_url,
                timeout_seconds=timeout_seconds,
                default_headers=default_headers,
                allow_remote_target=allow_remote_target,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
                max_rps=max_rps,
                traffic_observer=traffic_observer,
                traffic_policy=traffic_policy,
                traffic_policy_reference=traffic_policy_reference,
            )
        elif default_headers:
            session = ProbeSession(
                target_url,
                timeout_seconds=timeout_seconds,
                default_headers=default_headers,
                traffic_observer=traffic_observer,
            )
        elif traffic_observer is not None:
            session = ProbeSession(
                target_url,
                timeout_seconds=timeout_seconds,
                traffic_observer=traffic_observer,
            )
        else:
            # Keep the original constructor shape for lightweight injected sessions
            # used by deterministic probe consumers and tests.
            session = ProbeSession(target_url, timeout_seconds=timeout_seconds)
    handler = _probe_handlers().get(probe)
    request_count_before = int(getattr(session, "physical_request_count", 0))
    if handler is None:
        return ProbeRunResult(
            ok=False,
            probe=probe,
            summary=f"unknown probe: {probe}",
            errors=[f"unknown probe: {probe}"],
        )
    result = _execute_probe_handler(
        probe,
        handler=handler,
        session=session,
        state=state,
    )
    request_count_after = int(getattr(session, "physical_request_count", request_count_before))
    count_status = result.http_request_count_status
    if probe == "dom_execution":
        # Browser navigation and subresources are outside ProbeSession until the
        # browser runtime is wired to the whole-run egress policy.
        count_status = "lower_bound"
    return replace(
        result,
        http_request_count=max(0, request_count_after - request_count_before),
        http_request_count_status=count_status,
    )


def _execute_probe_handler(
    probe: str,
    *,
    handler: ProbeHandler,
    session: ProbeSession,
    state: AgentState,
) -> ProbeRunResult:
    """Run one handler with a probe-local cutoff for futile policy blocks."""
    try:
        stop_on_blocks = getattr(session, "stop_on_repeated_policy_blocks", None)
        if not callable(stop_on_blocks):
            # Preserve compatibility with lightweight injected sessions used by
            # deterministic consumers; the guard is an execution-harness feature.
            return handler(session, state)
        with stop_on_blocks():
            return handler(session, state)
    except ProbeTrafficPolicyStopError as exc:
        block_word = "block" if exc.consecutive_blocks == 1 else "blocks"
        return ProbeRunResult(
            ok=False,
            probe=probe,
            summary=(
                "traffic policy stopped the probe after "
                f"{exc.consecutive_blocks} consecutive pre-dispatch {block_word}: "
                f"{exc.reason}"
            ),
            requests=[dict(item) for item in exc.blocked_responses],
        )


def _validate_supplied_session(*, target_url: str, session: ProbeSession) -> None:
    if not isinstance(session, ProbeSession):
        message = "session must be a ProbeSession"
        raise TypeError(message)
    requested = _canonical_probe_target(target_url)
    if requested != _canonical_probe_target(session.target_url):
        message = "provided probe session belongs to a different target"
        raise ValueError(message)


def _canonical_probe_target(target_url: str) -> str:
    parsed = urlsplit(target_url)
    if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
        message = "target URL must use http or https and include a host"
        raise ValueError(message)
    if parsed.username is not None or parsed.password is not None:
        message = "target URL cannot contain userinfo"
        raise ValueError(message)
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _merge_canonical_host(
    *,
    session: ProbeSession,
    default_headers: dict[str, str] | None,
) -> None:
    if not default_headers:
        return
    expected = default_headers["Host"]
    for name, value in session.default_headers.items():
        if name.lower() != "host":
            continue
        if value != expected:
            message = "provided probe session has a conflicting canonical Host"
            raise ValueError(message)
        return
    session.default_headers["Host"] = expected


def _probe_handlers() -> dict[str, ProbeHandler]:
    return {
        "surface_map": probe_surface_map,
        "secret_sweep": probe_secret_sweep,
        "input_reflection": probe_input_reflection,
        "xss_context": probe_xss_context,
        "stateful_session": probe_stateful_session,
        "csrf_session": probe_csrf_session,
        "default_credentials": probe_default_credentials_runner,
        "server_rendering": probe_server_rendering,
        "ssti_fingerprint": probe_ssti_fingerprint_runner,
        SSTI_DEFERRED_CONTEXT_PROBE_NAME: probe_ssti_deferred_context_closure,
        "data_query": probe_data_query,
        "sqli_differential": probe_sqli_differential,
        "sqli_exploit": probe_sqli_exploit_runner,
        SQLI_AUTH_TRANSITION_PROBE_NAME: probe_sqli_auth_transition,
        "filtered_query_bypass": probe_filtered_query_bypass,
        "preg_match_subject": probe_preg_match_subject,
        "direct_exposure": probe_direct_exposure,
        "cms_exposure": probe_cms_exposure,
        "command_boundary": probe_command_boundary,
        "ssrf_boundary": probe_ssrf_boundary,
        "reflection_value_boundary": probe_reflection_value_boundary,
        xss_filter_constraint.PROBE_NAME: xss_filter_constraint.probe_xss_filter_constraint,
        "file_fetch_parser": probe_file_fetch_parser,
        "file_read_extract": probe_file_read_extract_runner,
        "xxe_boundary": probe_xxe_boundary,
        "cookie_deserialization": probe_cookie_deserialization,
        "captcha_form_state": probe_captcha_form_state,
        "jwt_exploit": probe_jwt_exploit,
        "graphql_exploit": probe_graphql_exploit,
        "werkzeug_console": probe_werkzeug_console,
        "api_behavior": probe_api_behavior,
        "browser_boundary": probe_browser_boundary,
        "idor_boundary": probe_idor_boundary_runner,
        "dom_execution": _probe_dom_execution,
    }


def _probe_dom_execution(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return probe_dom_execution(
        session,
        state,
        exec_binding=EXEC_BINDING,
        browser_backend_status_fn=browser_backend_status,
        render_url_fn=render_url,
        render_request_fn=render_request,
    )


__all__ = [
    "EXEC_BINDING",
    "ProbeRunResult",
    "authenticated_probe_unavailability",
    "authenticated_unavailable_probes",
    "available_probes",
    "browser_backend_status",
    "probe_requires_anonymous_session",
    "probe_requires_external_process",
    "render_url",
    "run_builtin_probe",
]
