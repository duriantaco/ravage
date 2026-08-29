from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.agent_strategy import strategy_cards_for_state
from ravage.agent_core.observation_memory import should_shift_strategy
from ravage.agent_core.primitive_state import primitive_directives

PROBE_CANDIDATE_MARKERS = (
    "<form",
    "sql",
    "mysql",
    "sqlite",
    "search",
    "filtered",
    "preg_match",
    "template",
    "ssti",
    "reflected",
    "xss",
    "user_id",
    "account_id",
    "order_id",
    "profile",
    "file",
    "path",
    "upload",
    "xml",
    "command",
    "admin",
    "backup",
    "config",
    "cors",
    "websocket",
    "localstorage",
    "sessionstorage",
)
SQLI_MARKERS = (
    "sql_injection_confirmed",
    "sql_injection_error_signal",
    "blind_sql_injection",
    "sql_error_leak_primitive",
    "database error marker observed",
)
FILTERED_QUERY_MARKERS = ("filtered", "some item is filtered", "no results", "user exists", "search.php")
PREG_MATCH_MARKERS = ("preg_match", "array given", "expects parameter 2")
FORM_STATE_MARKERS = ("captcha", "challenge", "verification code", "security code", "invalid captcha", "invalid code", "csrf")
SESSION_BOUNDARY_MARKERS = (
    "csrf",
    "xsrf",
    "authenticity_token",
    "session",
    "set-cookie",
    "samesite",
    "httponly",
    "logout",
)
WEB_BOUNDARY_MARKERS = (
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "cors",
    "clickjack",
    "x-frame-options",
    "frame-ancestors",
    "websocket",
    "ws://",
    "wss://",
    "localstorage",
    "sessionstorage",
)
EXPOSURE_MARKERS = ("admin", "config", "backup", ".env", "debug", "source", "php")
REFLECTION_MARKERS = ("reflected", "reflection", "html sink", "innerhtml", "xss")
XSS_CONTEXT_MARKERS = ("xss_reflection_context", "html_attribute", "html_body", "js_string")
CLIENT_XSS_OBJECTIVE_MARKERS = ("xss", "cross-site scripting", "alert(", "browser-executed", "client-side")
XSS_VALUE_GATE_MARKERS = (
    "instead of \"xss\"",
    "instead of 'xss'",
    "did an alert",
    "expected alert",
    "expected dialog",
    "wrong value",
    "incorrect value",
    "typeerror",
)
TEMPLATE_EVIDENCE_MARKERS = (
    "ssti_fingerprint_signal",
    "ssti_engine_execution",
    "templatesyntaxerror",
    "template syntaxerror",
    "{{",
    "{%",
    "jinja",
    "twig",
    "freemarker",
    "mako",
    "velocity",
)
IDOR_MARKERS = ("idor", "user_id", "account_id", "order_id", "file_id", "doc_id", "profile", "uuid", "authorization")
FILE_READ_MARKERS = ("file_read_confirmed", "root:x:0:0", "local file read")
QUERY_LIKE_MARKERS = (
    "sql",
    "sqlite",
    "mysql",
    "postgres",
    "search",
    "filter",
    "query",
    "job_type",
    "/jobs",
    "jobs",
    "sort",
    "where",
    "login",
    "username",
    "email",
    "password",
    "user_id",
    "account_id",
    "order_id",
    "product_id",
    "item_id",
    "category_id",
    "search.php",
    "login.php",
)


def select_phase(state: AgentState) -> str:
    if state.flags:
        if state.surface.get("continue_after_proof") is True:
            return "exploit"
        return "done"
    if state.primitives:
        return "exploit"
    open_tasks = _open_tasks(state)
    if open_tasks:
        top = str(open_tasks[0].get("id") or "")
        if top in {"surface-map", "flag-and-secret-sweep"} and state.turn <= 2:
            return "recon"
        if state.signals.get("reflections") or _top_tasks_are_exploit_work(open_tasks):
            return "exploit"
    if len(state.signals.get("pages", [])) < 1 and state.turn <= 1:
        return "recon"
    if state.signals.get("reflections") or state.signals.get("markers"):
        return "exploit"
    if len(state.actions) >= 3:
        return "exploit"
    return "recon"


def planner_directives(state: AgentState) -> list[str]:
    directives: list[str] = []
    directives.extend(primitive_directives(state))
    if state.phase == "recon":
        directives.append("Prefer mapping missing surfaces before deep exploitation.")
    if state.phase == "exploit":
        directives.append("Choose one evidence-backed hypothesis and test it deeply.")
    if state.flags and state.surface.get("continue_after_proof") is True:
        directives.append(
            "This is a multi-finding engagement: a captured proof completes one branch, "
            "not the assessment. Continue with untested open tasks and distinct vulnerability families."
        )
    if should_shift_strategy(state):
        directives.append("Recent actions are stagnant; change endpoint, parameter, session, or strategy.")
    if (
        _has_login_surface_evidence(state)
        and not _has_authenticated_session_evidence(state)
        and not _has_password_change_idor_evidence(state)
    ):
        directives.append(
            "Login/password surface exists and no authenticated session is confirmed; run_probe default_credentials "
            "before SQLi or custom auth-form payload loops."
        )
    if _has_credentialed_service_evidence(state):
        directives.append(
            "Credentials or auxiliary service access are in play. After any successful shell, SSH, or command execution, "
            "preserve exact-case filenames from source/config and run proof closure with case-insensitive discovery "
            "plus exact reads of $HOME/FLAG.txt, $HOME/flag.txt, /FLAG.txt, /flag.txt, /tmp/FLAG.txt, "
            "/app/FLAG.txt, /var/www/html/FLAG.txt, /root/FLAG.txt, and lowercase variants before returning to recon."
        )
        directives.append(
            "For credentialed SSH/service follow-up, prefer run_python with Paramiko. If Python modules are missing, "
            "let Docker fallback run it. Host-side tools must use scoped_service_ports.host_endpoint; Docker/tool-image "
            "tools must use scoped_service_ports.docker_endpoint. Always preserve the scoped external port, and when "
            "source shows an in-container localhost:22 service, map it to the auxiliary scoped localhost:<port> rather "
            "than trying unscoped port 22. "
            "if falling back to OpenSSH password auth, use expect with the exact extracted password rather than "
            "piping the password to ssh stdin. Keep SSH command strings simply quoted or build them with shlex.quote."
        )
    if _recent_custom_action_count(state, limit=4) >= 2 and _has_probe_candidate_evidence(state):
        directives.append(
            "Recent custom command/python actions are piling up; choose a matching run_probe specialist next unless no listed probe covers the evidence."
        )
    if _has_sqli_evidence(state) or state.signals.get("sqli_inputs"):
        directives.append(
            "Confirmed SQLi evidence exists; keep the data-query task active and avoid switching back to static/source sweeps unless SQL extraction is exhausted."
        )
    if _has_query_request_template(state):
        directives.append(
            "Observed query-shaped request template exists; run_probe sqli_differential before unrelated boundary probes or custom payload loops."
        )
    if _active_task(state, "data-query"):
        if _has_preg_match_evidence(state):
            directives.append(
                "PHP preg_match/type-confusion evidence exists; run_probe preg_match_subject before more custom regex loops."
            )
        elif _has_form_state_evidence(state):
            directives.append(
                "The query/auth form appears gated by captcha/code/CSRF state; run_probe captcha_form_state before more SQL/auth payload loops."
            )
        elif _has_sqli_evidence(state):
            directives.append(
                "SQLi evidence exists; prefer run_probe sqli_exploit before ad hoc extraction loops."
            )
        elif _has_filtered_query_evidence(state):
            directives.append(
                "Search/login filtering evidence exists; run_probe filtered_query_bypass before more custom payload loops."
            )
        elif _has_query_like_evidence(state):
            directives.append(
                "Data-query task is active; prefer run_probe sqli_differential when forms, parameters, or SQL markers change."
            )
        else:
            directives.append(
                "Generic input surface exists without query/search/login/SQL evidence; map response influence with run_probe input_reflection before SQL specialists."
            )
        secret_sweep = _task(state, "flag-and-secret-sweep")
        if secret_sweep and _int_value(secret_sweep.get("attempts")) >= 2:
            directives.append(
                "Stop repeating secret_sweep after empty passes; run direct_exposure or data-query work such as sqli_differential instead."
            )
    if _active_task(state, "flag-and-secret-sweep") and _has_exposure_evidence(state):
        directives.append(
            "Admin/config/backup/debug evidence exists; prefer run_probe direct_exposure before custom path loops."
        )
    if _active_task(state, "file-fetch-parser"):
        if _has_file_read_evidence(state):
            directives.append(
                "Confirmed local file-read evidence exists; run_probe file_read_extract before more custom path or procfs loops."
            )
        else:
            directives.append(
                "File/path/parser task is active; prefer run_probe file_fetch_parser before custom traversal loops. "
                "For unsafe upload parsers/deserializers, closure may require a non-reflected side effect and follow-up GET."
            )
    if _active_task(state, "input-reflection"):
        if _has_client_xss_objective(state) and _has_xss_value_gate_evidence(state):
            directives.append(
                "The visible objective is client-side XSS and the page reports a dialog/value mismatch; run_probe "
                "reflection_value_boundary next to try the visible expected value on the reflected input before "
                "more browser payload loops. Do not switch to SSTI without explicit template/SSTI markers."
            )
        elif _has_client_xss_objective(state) and (state.signals.get("reflections") or _has_reflection_evidence(state)):
            directives.append(
                "The visible objective is client-side XSS and reflected input evidence exists; run_probe dom_execution "
                "to verify execution and extract any returned proof. If xss_context timed out, do not detour to "
                "ssti_fingerprint unless the observation has explicit template/SSTI markers."
            )
        elif _has_client_execution_without_proof(state):
            directives.append(
                "Browser execution is confirmed but no proof was extracted; run_probe reflection_value_boundary before custom value or path loops."
            )
        elif _has_xss_context_evidence(state):
            directives.append(
                "XSS reflection context evidence exists; run_probe reflection_value_boundary before manual payload loops, then use dom_execution if browser execution still needs confirmation."
            )
        elif state.signals.get("reflections") or _has_reflection_evidence(state):
            directives.append(
                "Reflected input evidence exists; run_probe xss_context before hand-written XSS payload loops."
            )
    if not state.flags and (state.signals.get("xss_contexts") or _has_xss_context_evidence(state)):
        directives.append(
            "XSS sink context is confirmed; keep exploiting that sink with run_probe "
            "reflection_value_boundary (server-verified dialog sentinels) and run_probe dom_execution. "
            "After a timeout, vary the XSS payload family or use dom_execution; do not repeat the "
            "same timed-out path or drift to unrelated SQLi/SSRF/exposure probes."
        )
    if _active_task(state, "server-rendering"):
        if _has_client_xss_objective(state) and _has_xss_context_evidence(state) and not _has_template_evidence(state):
            directives.append(
                "The active task may be labeled server-rendering, but the visible objective and evidence are client-side XSS. "
                "Do not run ssti_fingerprint unless explicit template/SSTI markers appear; continue XSS filter profiling, "
                "reflection_value_boundary, and dom_execution with a materially different payload family."
            )
        else:
            directives.append(
                "Server-rendering task is active; prefer run_probe ssti_fingerprint with harmless expression probes before engine-specific escalation."
            )
    if _has_authenticated_template_render_evidence(state):
        directives.append(
            "Authenticated upload/include/template or calculation-rendering evidence exists; run_probe ssti_fingerprint next "
            "so the specialist can preserve the session and test upload-to-include or expression-context SSTI before IDOR, SQLi, or direct exposure."
        )
    if _has_password_change_idor_evidence(state):
        directives.append(
            "Password-change IDOR evidence exists; run_probe idor_boundary so the specialist can register/log in, "
            "submit the password-change request with alternate userId values, and verify privileged login before manual loops."
        )
    if _active_task(state, "stateful-session") and _has_idor_evidence(state):
        directives.append(
            "Object-ID or authorization-boundary evidence exists; run_probe idor_boundary before manual ID enumeration loops."
        )
    if _active_task(state, "stateful-session") and _has_session_boundary_evidence(state):
        directives.append(
            "CSRF/session lifecycle evidence exists; run_probe csrf_session to test token omission/reuse, logout invalidation, and cookie attributes instead of only preserving tokens."
        )
    if _active_task(state, "api-behavior") and _has_web_boundary_evidence(state):
        directives.append(
            "Browser trust-boundary evidence exists; run_probe browser_boundary to test CORS, frame policy, WebSocket Origin handling, and browser storage before custom curl loops."
        )
    active_task_ids = _active_task_ids(state, limit=5)
    if active_task_ids:
        directives.append("Select one active task id and make measurable progress on it: " + ", ".join(active_task_ids) + ".")
    if state.signals.get("reflections"):
        directives.append("A reflected input exists; test sink context and interpreter behavior carefully.")
    if state.signals.get("forms") and not state.signals.get("cookies"):
        directives.append("Forms exist; inspect CSRF/cookie/session behavior before mutating state.")
    if not directives:
        directives.append("Run the next action that maximizes new evidence toward flag capture.")
    return directives


def ranked_strategy_cards(
    *,
    description: str,
    state: AgentState,
    limit: int = 5,
) -> list[dict[str, object]]:
    return strategy_cards_for_state(
        description=description,
        signals=state.signals,
        facts=state.facts,
        limit=limit,
    )


def _open_tasks(state: AgentState) -> list[dict[str, object]]:
    tasks: list[dict[str, object]] = []
    for task in state.tasks:
        if _task_is_open(task):
            tasks.append(task)
    return tasks


def _task_is_open(task: dict[str, object]) -> bool:
    return task.get("status") in {"pending", "in_progress"}


def _top_tasks_are_exploit_work(open_tasks: list[dict[str, object]]) -> bool:
    exploit_task_ids = {
        "input-reflection",
        "stateful-session",
        "server-rendering",
        "data-query",
        "file-fetch-parser",
        "command-boundary",
        "api-behavior",
    }
    for task in open_tasks[:3]:
        task_id = str(task.get("id") or "")
        if task_id in exploit_task_ids:
            return True
    return False


def _active_task_ids(state: AgentState, *, limit: int) -> list[str]:
    task_ids: list[str] = []
    for task in state.tasks:
        if not _task_is_open(task):
            continue
        task_id = str(task.get("id") or "")
        if task_id:
            task_ids.append(task_id)
        if len(task_ids) >= limit:
            break
    return task_ids


def _active_task(state: AgentState, task_id: str) -> bool:
    for task in state.tasks:
        if task.get("id") == task_id and _task_is_open(task):
            return True
    return False


def _task(state: AgentState, task_id: str) -> dict[str, object] | None:
    for task in state.tasks:
        if task.get("id") == task_id:
            return task
    return None


def _recent_probe_names(state: AgentState, *, limit: int) -> set[str]:
    names: set[str] = set()
    for action in state.actions[-limit:]:
        if action.get("action") != "run_probe":
            continue
        probe_name = str(action.get("probe") or "")
        if probe_name:
            names.add(probe_name)
    return names


def _recent_custom_action_count(state: AgentState, *, limit: int) -> int:
    count = 0
    for action in state.actions[-limit:]:
        if action.get("action") in {"run_command", "run_python"}:
            count += 1
    return count


def _has_probe_candidate_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=PROBE_CANDIDATE_MARKERS,
        signal_keys=("markers", "forms", "parameters", "reflections"),
        fact_limit=20,
        hypothesis_limit=12,
    )


def _has_sqli_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(state, markers=SQLI_MARKERS, signal_keys=("markers",), fact_limit=20)


def _has_filtered_query_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=FILTERED_QUERY_MARKERS,
        signal_keys=("markers",),
        fact_limit=20,
        hypothesis_limit=12,
    )


def _has_query_like_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=QUERY_LIKE_MARKERS,
        signal_keys=("markers", "forms", "parameters", "endpoints"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=8,
    )


def _has_query_request_template(state: AgentState) -> bool:
    for raw_template in state.signals.get("request_templates", []):
        text = str(raw_template).lower()
        markers = (
            "job_type",
            "/jobs",
            "search",
            "query",
            "filter",
            "category",
            "product_id",
            "item_id",
            "user_id",
            "account_id",
        )
        if any(marker in text for marker in markers):
            return True
    return False


def _has_preg_match_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=PREG_MATCH_MARKERS,
        signal_keys=("markers",),
        fact_limit=20,
        hypothesis_limit=12,
    )


def _has_form_state_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=FORM_STATE_MARKERS,
        signal_keys=("markers", "forms", "cookies"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=8,
    )


def _has_session_boundary_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=SESSION_BOUNDARY_MARKERS,
        signal_keys=("markers", "forms", "cookies", "endpoints"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=8,
    )


def _has_web_boundary_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=WEB_BOUNDARY_MARKERS,
        signal_keys=("markers", "endpoints", "links"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=8,
    )


def _has_exposure_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=EXPOSURE_MARKERS,
        signal_keys=("markers",),
        fact_limit=20,
        hypothesis_limit=12,
    )


def _has_reflection_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=REFLECTION_MARKERS,
        signal_keys=("markers",),
        fact_limit=20,
        hypothesis_limit=12,
    )


def _has_client_xss_objective(state: AgentState) -> bool:
    description = str(state.surface.get("visible_description") or "").lower()
    if not description:
        return False
    return any(marker in description for marker in CLIENT_XSS_OBJECTIVE_MARKERS)


def _has_xss_context_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=XSS_CONTEXT_MARKERS,
        signal_keys=("markers",),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=8,
    )


def _has_xss_value_gate_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=XSS_VALUE_GATE_MARKERS,
        signal_keys=("markers", "reflections", "xss_contexts"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=10,
    )


def _has_template_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=TEMPLATE_EVIDENCE_MARKERS,
        signal_keys=("markers", "xss_contexts"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=8,
    )


def _has_client_execution_without_proof(state: AgentState) -> bool:
    if state.flags:
        return False
    text = _evidence_text(
        state,
        signal_keys=("markers", "reflections", "xss_contexts"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=10,
    )
    if "client_side_execution" not in text:
        return False
    return "client_side_proof_extraction" not in text


def _has_idor_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=IDOR_MARKERS,
        signal_keys=("markers", "parameters", "endpoints"),
        fact_limit=20,
        hypothesis_limit=12,
    )


def _has_password_change_idor_evidence(state: AgentState) -> bool:
    text = _evidence_text(
        state,
        signal_keys=("markers", "parameters", "endpoints"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=8,
    )
    text = f"{text} {state.surface.get('visible_description') or ''}".lower()
    idor_evidence = any(
        marker in text
        for marker in (
            "idor",
            "insecure direct object",
            "authorization",
            "user_id",
            "userid",
            "profile",
        )
    )
    password_change_evidence = any(
        marker in text
        for marker in (
            "password",
            "change_password",
            "update_password",
            "oldpassword",
            "newpassword",
            "confirmpassword",
        )
    )
    return idor_evidence and password_change_evidence


def _has_file_read_evidence(state: AgentState) -> bool:
    return bool(state.signals.get("file_read_inputs")) or _has_evidence_marker(
        state,
        markers=FILE_READ_MARKERS,
        signal_keys=("markers", "file_read_inputs"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=10,
    )


def _has_login_surface_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=("login", "signin", "sign-in", "username", "password", "basic auth"),
        signal_keys=("forms", "markers", "endpoints"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=6,
    )


def _has_credentialed_service_evidence(state: AgentState) -> bool:
    text = _evidence_text(
        state,
        signal_keys=("markers", "endpoints"),
        fact_limit=24,
        hypothesis_limit=12,
        action_limit=10,
    )
    service_markers = (
        "ssh",
        "sftp",
        "paramiko",
        "ftp",
        "telnet",
        "auxiliary",
        "raw tcp",
        "non-http",
        "port",
    )
    secret_markers = (
        "password",
        "credential",
        "username",
        "private key",
        "id_rsa",
        "token",
        "base64",
    )
    return any(marker in text for marker in service_markers) and any(marker in text for marker in secret_markers)


def _has_authenticated_session_evidence(state: AgentState) -> bool:
    return _has_evidence_marker(
        state,
        markers=(
            "default_credentials_valid",
            "session_followup_proof",
            "auth_session_followup_signal",
            "auth_workflow_completed_signal",
            "authenticated session",
            "set-cookie",
        ),
        signal_keys=("markers", "cookies"),
        fact_limit=20,
        hypothesis_limit=12,
        action_limit=8,
    )


def _has_authenticated_template_render_evidence(state: AgentState) -> bool:
    text = _evidence_text(
        state,
        signal_keys=("markers", "forms", "endpoints", "parameters", "cookies"),
        fact_limit=30,
        hypothesis_limit=20,
        action_limit=12,
    ).lower()
    if not any(
        marker in text
        for marker in (
            "default_credentials_valid",
            "auth_session_followup_signal",
            "authenticated",
            "session=",
            "cookie",
        )
    ):
        return False
    return any(
        marker in text
        for marker in (
            "multipart/form-data",
            '"type": "file"',
            "image",
            "avatar",
            "photo",
            "upload",
            "include",
            "template",
            "error_type",
            "filename",
            "amortization",
            "loan",
            "payment",
            "term",
            "calculator",
            "total_loan",
            "server-side rendering",
            "expression",
            "preview",
            "message",
            "notify",
            "schedule",
            "remind",
            "reminder",
        )
    )


def _has_evidence_marker(
    state: AgentState,
    *,
    markers: tuple[str, ...],
    signal_keys: tuple[str, ...],
    fact_limit: int = 0,
    hypothesis_limit: int = 0,
    action_limit: int = 0,
) -> bool:
    text = _evidence_text(
        state,
        signal_keys=signal_keys,
        fact_limit=fact_limit,
        hypothesis_limit=hypothesis_limit,
        action_limit=action_limit,
    )
    for marker in markers:
        if marker in text:
            return True
    return False


def _evidence_text(
    state: AgentState,
    *,
    signal_keys: tuple[str, ...],
    fact_limit: int = 0,
    hypothesis_limit: int = 0,
    action_limit: int = 0,
) -> str:
    parts: list[str] = []
    for key in signal_keys:
        parts.extend(state.signals.get(key, ()))
    if fact_limit > 0:
        parts.extend(state.facts[-fact_limit:])
    if hypothesis_limit > 0:
        parts.extend(state.hypotheses[-hypothesis_limit:])
    if action_limit > 0:
        parts.extend(str(action) for action in state.actions[-action_limit:])
    return " ".join(parts).lower()


def _int_value(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return default
