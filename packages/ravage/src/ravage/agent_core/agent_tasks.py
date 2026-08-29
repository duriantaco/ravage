from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass

from ravage.agent_core.agent_state import AgentState

TASK_STATUSES = {"pending", "in_progress", "done", "blocked"}
ACTIVE_TASK_STATUSES = {"pending", "in_progress"}
PROGRESS_OUTCOMES = {"confirmed_signal", "finding_confirmed", "new_surface"}
BLOCKING_OUTCOMES = {"blocked", "same_as_before"}
DATA_QUERY_SURFACE_MARKERS = (
    "sql",
    "sqlite",
    "mysql",
    "postgres",
    "search",
    "filter",
    "query",
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


@dataclass(frozen=True)
class _TaskSurface:
    counts: dict[str, object]
    workflows: list[str]
    forms: list[dict[str, object]]
    parameters: list[dict[str, object]]
    endpoints: list[dict[str, object]]
    reflected: list[dict[str, object]]
    markers: list[str]
    text: str
    idor_surface: bool


def refresh_mission_board(
    state: AgentState,
    *,
    description: str,
    surface: dict[str, object],
) -> None:
    existing = _tasks_by_id(state.tasks)
    generated = _generated_tasks(description=description, surface=surface, state=state)
    generated_ids = _task_ids(generated)
    merged: list[dict[str, object]] = []

    for task in generated:
        task_id = str(task.get("id") or "")
        previous = existing.get(task_id)
        if previous:
            _preserve_task_progress(task, previous)
        merged.append(task)

    for task in state.tasks:
        task_id = str(task.get("id") or "")
        if task_id == "flag-and-secret-sweep" and not _flag_objective_enabled(surface):
            continue
        if task_id and task_id not in generated_ids:
            merged.append(task)

    merged.sort(key=_mission_task_sort_key)
    state.tasks = merged[:30]


def active_tasks_for_prompt(state: AgentState, *, limit: int = 8) -> list[dict[str, object]]:
    active: list[dict[str, object]] = []
    for task in state.tasks:
        if _status(task.get("status")) in ACTIVE_TASK_STATUSES:
            active.append(task)
    if not active:
        active = state.tasks
    active.sort(key=_prompt_task_sort_key)
    prompt_tasks: list[dict[str, object]] = []
    for task in active[:limit]:
        prompt_tasks.append(
            {
                "id": task.get("id"),
                "title": task.get("title"),
                "status": task.get("status"),
                "priority": task.get("priority"),
                "rationale": task.get("rationale"),
                "next_steps": task.get("next_steps"),
                "evidence": task.get("evidence"),
                "attempts": task.get("attempts", 0),
                "last_outcome": task.get("last_outcome", ""),
            }
        )
    return prompt_tasks


def update_mission_from_action(
    state: AgentState,
    *,
    action: Mapping[str, object],
    outcome: Mapping[str, object],
) -> None:
    task = _task_for_action(state, action)
    if task is None:
        return

    attempts = _increment_attempts(task)
    result = _outcome_result(outcome)
    observation = _outcome_observation(outcome)

    task["last_outcome"] = result
    _record_task_evidence(task, action=action, result=result, observation=observation)
    task["status"] = _status_after_action(
        task=task,
        action=action,
        result=result,
        attempts=attempts,
        observation=observation,
        state=state,
    )


def mission_board_summary(state: AgentState) -> dict[str, object]:
    counts = _empty_status_counts()
    for task in state.tasks:
        counts[_status(task.get("status"))] += 1
    return {
        "counts": counts,
        "active": active_tasks_for_prompt(state, limit=6),
    }


def _increment_attempts(task: dict[str, object]) -> int:
    attempts = _int(task.get("attempts")) + 1
    task["attempts"] = attempts
    return attempts


def _outcome_result(outcome: Mapping[str, object]) -> str:
    return str(outcome.get("outcome") or "observed")


def _outcome_observation(outcome: Mapping[str, object]) -> str:
    return str(outcome.get("observation") or "")


def _record_task_evidence(
    task: dict[str, object],
    *,
    action: Mapping[str, object],
    result: str,
    observation: str,
) -> None:
    evidence = _evidence_snippet(action=action, outcome=result, observation=observation)
    if evidence:
        task["evidence"] = _merge_strings(task.get("evidence"), [evidence])


def _status_after_action(
    *,
    task: dict[str, object],
    action: Mapping[str, object],
    result: str,
    attempts: int,
    observation: str,
    state: AgentState,
) -> str:
    current_status = _status(task.get("status"))
    task_id = str(task.get("id") or "")

    if _action_completed_task(action=action, result=result):
        return "done"
    if _flag_sweep_has_gone_stale(task_id=task_id, result=result, attempts=attempts):
        return "blocked"
    if _flag_sweep_has_low_value_signal(
        task_id=task_id,
        result=result,
        attempts=attempts,
        observation=observation,
    ):
        return "blocked"
    if _data_query_should_continue(task_id=task_id, result=result, attempts=attempts, state=state):
        return "in_progress"
    if _file_read_should_continue(task_id=task_id, result=result, attempts=attempts, state=state):
        return "in_progress"
    if result in PROGRESS_OUTCOMES:
        return "in_progress"
    if _blocking_attempts_exhausted(result=result, attempts=attempts):
        return "blocked"
    if current_status == "pending":
        return "in_progress"
    return current_status


def _action_completed_task(*, action: Mapping[str, object], result: str) -> bool:
    if result in {"finding_confirmed", "flag_candidate"}:
        return True
    return action.get("action") == "capture_flag"


def _flag_sweep_has_gone_stale(*, task_id: str, result: str, attempts: int) -> bool:
    if task_id != "flag-and-secret-sweep":
        return False
    return result in {"observed", "new_surface"} and attempts >= 2


def _flag_sweep_has_low_value_signal(
    *,
    task_id: str,
    result: str,
    attempts: int,
    observation: str,
) -> bool:
    if task_id != "flag-and-secret-sweep":
        return False
    if result != "confirmed_signal":
        return False
    if attempts < 4:
        return False
    return not _high_value_secret_signal(observation)


def _data_query_should_continue(
    *,
    task_id: str,
    result: str,
    attempts: int,
    state: AgentState,
) -> bool:
    if task_id != "data-query":
        return False
    if result not in BLOCKING_OUTCOMES:
        return False
    if attempts >= 12:
        return False
    return _has_confirmed_data_query_signal(state)


def _file_read_should_continue(
    *,
    task_id: str,
    result: str,
    attempts: int,
    state: AgentState,
) -> bool:
    if task_id != "file-fetch-parser":
        return False
    if result not in BLOCKING_OUTCOMES:
        return False
    if attempts >= 10:
        return False
    return _has_confirmed_file_read_signal(state)


def _blocking_attempts_exhausted(*, result: str, attempts: int) -> bool:
    return result in BLOCKING_OUTCOMES and attempts >= 3


def _generated_tasks(
    *,
    description: str,
    surface: dict[str, object],
    state: AgentState,
) -> list[dict[str, object]]:
    task_surface = _task_surface(description=description, surface=surface, state=state)
    tasks = _base_tasks(task_surface, flag_objective=_flag_objective_enabled(surface))

    _add_input_tasks(tasks, task_surface)
    _add_server_rendering_task(tasks, task_surface)
    _add_data_query_task(tasks, task_surface)
    _add_file_fetch_parser_task(tasks, task_surface)
    _add_command_boundary_task(tasks, task_surface)
    _add_api_behavior_task(tasks, task_surface)

    tasks.sort(key=_generated_task_sort_key)
    return tasks[:20]


def _task_surface(
    *,
    description: str,
    surface: dict[str, object],
    state: AgentState,
) -> _TaskSurface:
    counts = _dict(surface.get("counts"))
    workflows = _workflow_names(surface)
    forms = _surface_forms(surface=surface, state=state)
    parameters = _surface_parameters(surface=surface, state=state)
    endpoints = _list_of_dicts(surface.get("endpoints"))
    reflected = _surface_reflections(surface=surface, state=state)
    markers = _surface_markers(surface=surface, state=state)
    text = _surface_text(
        description=description,
        surface=surface,
        workflows=workflows,
        markers=markers,
    )
    idor_surface = _has_idor_surface(parameters, endpoints, text)
    return _TaskSurface(
        counts=counts,
        workflows=workflows,
        forms=forms,
        parameters=parameters,
        endpoints=endpoints,
        reflected=reflected,
        markers=markers,
        text=text,
        idor_surface=idor_surface,
    )


def _surface_forms(*, surface: dict[str, object], state: AgentState) -> list[dict[str, object]]:
    forms = _list_of_dicts(surface.get("forms"))
    forms.extend(_forms_from_signal_values(state.signals.get("forms", [])[:12]))
    return _dedupe_dict_items(forms, limit=24)


def _surface_parameters(*, surface: dict[str, object], state: AgentState) -> list[dict[str, object]]:
    parameters = _list_of_dicts(surface.get("parameters"))
    parameters.extend(_parameters_from_signal_values(state.signals.get("parameters", [])[:24]))
    return _dedupe_dict_items(parameters, limit=40)


def _surface_reflections(*, surface: dict[str, object], state: AgentState) -> list[dict[str, object]]:
    reflected = _list_of_dicts(surface.get("reflections"))
    if reflected:
        return reflected
    return _reflections_from_signal_values(state.signals.get("reflections", [])[:8])


def _surface_text(
    *,
    description: str,
    surface: dict[str, object],
    workflows: list[str],
    markers: list[str],
) -> str:
    values: list[str] = []
    values.append(description)
    values.append(json.dumps(surface.get("technologies", []), sort_keys=True))
    values.append(json.dumps(workflows, sort_keys=True))
    values.append(json.dumps(markers, sort_keys=True))
    return " ".join(values).lower()


def _base_tasks(
    task_surface: _TaskSurface,
    *,
    flag_objective: bool,
) -> list[dict[str, object]]:
    tasks: list[dict[str, object]] = []
    tasks.append(_surface_map_task(task_surface))
    if flag_objective:
        tasks.append(_flag_and_secret_sweep_task(task_surface))
    return tasks


def _flag_objective_enabled(surface: Mapping[str, object]) -> bool:
    # Mission metadata was absent in older saved states, which were flag-oriented.
    return surface.get("flag_objective") is not False


def _surface_map_task(task_surface: _TaskSurface) -> dict[str, object]:
    return _task(
        "surface-map",
        "Map reachable HTTP surface",
        _surface_map_priority(task_surface.counts),
        "The agent needs a current inventory before deep exploitation.",
        [
            "Fetch root with headers and cookies.",
            "Crawl same-origin links and collect forms, scripts, redirects, and status codes.",
            "Save useful responses for later comparison.",
        ],
        evidence=[_surface_count_evidence(task_surface.counts)],
    )


def _flag_and_secret_sweep_task(task_surface: _TaskSurface) -> dict[str, object]:
    priority = 75 + _bonus(
        task_surface.text,
        ("debug", "backup", "config", ".git", "robots", "source_map"),
    )
    return _task(
        "flag-and-secret-sweep",
        "Sweep exposed files and responses for flags or secrets",
        priority,
        "Many proof strings are exposed through reachable files, source maps, configs, logs, or debug output.",
        [
            "Check robots.txt, sitemap.xml, common backup/config files, source maps, and JavaScript.",
            "Search fetched content for flag-like strings, credentials, and paths.",
            "Use discovered credentials only against the in-scope target.",
            "When credentials grant shell or service access, preserve exact-case filenames from source/config and close with case-insensitive proof-file discovery plus exact upper/lower path reads.",
            "For SSH credentials, use run_python/Paramiko or expect-based OpenSSH with the exact extracted password against the scoped external service port; do not pipe passwords into ssh stdin or replace a decoded password with the username.",
        ],
        evidence=_evidence_for(
            "exposed secret workflow",
            task_surface.workflows,
            task_surface.markers,
        ),
    )


def _add_input_tasks(tasks: list[dict[str, object]], task_surface: _TaskSurface) -> None:
    if not _has_input_surface(task_surface):
        return
    tasks.append(_input_reflection_task(task_surface))
    tasks.append(_stateful_session_task(task_surface))


def _input_reflection_task(task_surface: _TaskSurface) -> dict[str, object]:
    priority = 86 + _reflection_bonus(task_surface)
    return _task(
        "input-reflection",
        "Map controllable inputs and response influence",
        priority,
        "Inputs are the common route to XSS, template evaluation, query manipulation, command execution, and file reads.",
        [
            "Submit unique benign markers to one input at a time.",
            "Compare baseline and marker responses, including headers, redirects, and follow-up pages.",
            "Record exact sink context before trying stronger probes.",
            "Use run_probe xss_context for reflected sinks, then run_probe reflection_value_boundary for proof/value-gated branches before custom value loops.",
            "Run run_probe ssti_fingerprint only when reflected output includes explicit template syntax, engine errors, or arithmetic evaluation clues.",
            "Use run_probe dom_execution when execution still needs browser confirmation after sink context is mapped.",
        ],
        evidence=_input_evidence(
            forms=task_surface.forms,
            parameters=task_surface.parameters,
            reflected=task_surface.reflected,
        ),
    )


def _stateful_session_task(task_surface: _TaskSurface) -> dict[str, object]:
    priority = 72
    priority += _idor_bonus(task_surface)
    priority += _bonus(
        task_surface.text,
        ("login", "register", "session", "csrf", "account", "profile", "user_id", "order_id"),
    )
    return _task(
        "stateful-session",
        "Understand accounts, sessions, CSRF, and object boundaries",
        priority,
        "Auth and session behavior often hides flags behind low-privilege accounts or object ID boundaries.",
        [
            "Create or log into a low-privilege account if the target allows it.",
            "Track cookies and CSRF tokens per request.",
            "Use run_probe csrf_session to test token omission/reuse, logout invalidation, fixation hints, and cookie attributes.",
            "Compare accessible object IDs and role-gated pages before assuming injection is needed.",
            "Use run_probe idor_boundary when endpoints or forms expose user, account, order, file, or resource IDs.",
        ],
        evidence=_evidence_for(
            "session and role workflow",
            task_surface.workflows,
            task_surface.markers,
        ),
    )


def _add_server_rendering_task(tasks: list[dict[str, object]], task_surface: _TaskSurface) -> None:
    if not _has_server_rendering_surface(task_surface):
        return
    tasks.append(_server_rendering_task(task_surface))


def _server_rendering_task(task_surface: _TaskSurface) -> dict[str, object]:
    priority = 82 + _reflection_bonus(task_surface)
    return _task(
        "server-rendering",
        "Test reflected sinks for server-side interpretation",
        priority,
        "A reflected value that is transformed by the server can become a path to template or expression evaluation.",
        [
            "Use harmless arithmetic and string probes in the confirmed sink.",
            "Compare literal echo against evaluated output and framework errors.",
            "Use run_probe ssti_fingerprint to identify likely template syntax before engine-specific escalation.",
            "Only escalate after proving evaluation behavior.",
        ],
        evidence=_evidence_for(
            "server-side rendering workflow",
            task_surface.workflows,
            task_surface.markers,
        ),
    )


def _add_data_query_task(tasks: list[dict[str, object]], task_surface: _TaskSurface) -> None:
    if not _has_data_query_surface(task_surface):
        return
    tasks.append(_data_query_task(task_surface))


def _data_query_task(task_surface: _TaskSurface) -> dict[str, object]:
    query_shaped = _has_query_shaped_surface(task_surface)
    priority = 76
    if query_shaped:
        priority += 16
        priority += _form_bonus(task_surface)
    priority += _bonus(
        task_surface.text,
        ("sql", "sqlite", "mysql", "postgres", "search", "filter"),
    )
    return _task(
        "data-query",
        "Test whether inputs influence data queries",
        priority,
        "Search, login, sort, filter, and ID parameters can alter database result sets or errors.",
        [
            "Establish baseline responses for normal values.",
            "Try balanced boolean, syntax, and timing comparisons with response length/status/timing checks.",
            "Use run_probe sqli_differential for paired SQLi/blind-SQLi checks before ad hoc payload loops.",
            "After a SQLi signal, use run_probe sqli_exploit for extraction before writing custom scripts.",
            "If captcha/code/CSRF state blocks submissions, use run_probe captcha_form_state before more SQL payloads.",
            "If PHP preg_match or username[] array warnings appear, use run_probe preg_match_subject before custom regex loops.",
            "Prefer one parameter at a time and record the differential signal.",
        ],
        evidence=_evidence_for("data query workflow", task_surface.workflows, task_surface.markers),
    )


def _add_file_fetch_parser_task(tasks: list[dict[str, object]], task_surface: _TaskSurface) -> None:
    if not _has_file_or_fetch_surface(
        task_surface.parameters,
        task_surface.endpoints,
        task_surface.text,
        task_surface.workflows,
    ):
        return
    tasks.append(_file_fetch_parser_task(task_surface))


def _file_fetch_parser_task(task_surface: _TaskSurface) -> dict[str, object]:
    priority = 80 + _bonus(
        task_surface.text,
        ("file", "path", "upload", "xml", "soap", "url", "webhook"),
    )
    return _task(
        "file-fetch-parser",
        "Investigate file, URL fetch, upload, and parser behavior",
        priority,
        "File paths, uploads, XML, redirects, and URL fetchers can expose local files, SSRF-only endpoints, or parser bugs.",
        [
            "Identify where referenced or uploaded content is read back.",
            "Use harmless local path, URL, XML, and content-type probes matched to the observed workflow.",
            "After a confirmed local file read, run_probe file_read_extract before custom path/procfs loops.",
            "Follow response differences before attempting sensitive reads.",
        ],
        evidence=_file_fetch_parser_evidence(task_surface),
    )


def _add_command_boundary_task(tasks: list[dict[str, object]], task_surface: _TaskSurface) -> None:
    if not _has_command_boundary_surface(task_surface):
        return
    tasks.append(_command_boundary_task(task_surface))


def _command_boundary_task(task_surface: _TaskSurface) -> dict[str, object]:
    priority = 78 + _command_boundary_bonus(task_surface)
    return _task(
        "command-boundary",
        "Check command-shaped inputs for OS boundary crossing",
        priority,
        "Host/domain utilities, URL validators, service health checks, script endpoints, and OGNL/Struts surfaces can pass user input to shell commands or OS tools.",
        [
            "Start with benign output or timing probes.",
            "Vary separators, encodings, headers, and argument placement based on observed errors.",
            "On URL validators or service dashboards, test the preserved form/query template as both fetch behavior and possible shell command input.",
            "Use confirmed command influence to read the flag only after proving the boundary.",
        ],
        evidence=_evidence_for(
            "command boundary workflow",
            task_surface.workflows,
            task_surface.markers,
        ),
    )


def _add_api_behavior_task(tasks: list[dict[str, object]], task_surface: _TaskSurface) -> None:
    if not task_surface.endpoints:
        return
    if not _has_api_endpoint_hint(task_surface.endpoints):
        return
    tasks.append(_api_behavior_task())


def _api_behavior_task() -> dict[str, object]:
    return _task(
        "api-behavior",
        "Map API behavior and hidden methods",
        74,
        "API endpoints often expose object reads, debug routes, alternate methods, or schema introspection.",
        [
            "Inspect OPTIONS, content types, JSON errors, and documented routes in JavaScript.",
            "Use run_probe browser_boundary when CORS, WebSocket, frame policy, or browser storage evidence appears.",
            "Check schema or route discovery where GraphQL/API hints exist.",
            "Probe object IDs and authorization boundaries carefully.",
        ],
        evidence=["api or graphql endpoint hint observed"],
    )


def _surface_map_priority(counts: dict[str, object]) -> int:
    if _int(counts.get("pages")) == 0:
        return 100
    return 70


def _surface_count_evidence(counts: dict[str, object]) -> str:
    pages = counts.get("pages", 0)
    forms = counts.get("forms", 0)
    endpoints = counts.get("endpoints", 0)
    return f"pages={pages} forms={forms} endpoints={endpoints}"


def _has_input_surface(task_surface: _TaskSurface) -> bool:
    if task_surface.forms:
        return True
    if task_surface.parameters:
        return True
    if task_surface.idor_surface:
        return True
    return "input mapping" in task_surface.workflows


def _has_server_rendering_surface(task_surface: _TaskSurface) -> bool:
    if task_surface.reflected:
        return True
    return "server-side rendering workflow" in task_surface.workflows


def _has_data_query_surface(task_surface: _TaskSurface) -> bool:
    if task_surface.forms:
        return True
    if task_surface.parameters:
        return True
    return _contains_marker(
        task_surface.text,
        ("sql", "sqlite", "mysql", "postgres", "query", "search"),
    )


def _has_query_shaped_surface(task_surface: _TaskSurface) -> bool:
    text = " ".join(
        (
            task_surface.text,
            json.dumps(task_surface.forms, sort_keys=True),
            json.dumps(task_surface.parameters, sort_keys=True),
            json.dumps(task_surface.endpoints, sort_keys=True),
        )
    ).lower()
    return _contains_marker(text, DATA_QUERY_SURFACE_MARKERS)


def _has_command_boundary_surface(task_surface: _TaskSurface) -> bool:
    text = " ".join(
        (
            task_surface.text,
            json.dumps(task_surface.forms, sort_keys=True),
            json.dumps(task_surface.parameters, sort_keys=True),
            json.dumps(task_surface.endpoints, sort_keys=True),
        )
    ).lower()
    if _contains_marker(
        text,
        (
            "ping",
            "nslookup",
            "traceroute",
            "domain",
            "command",
            "host",
            "cmd",
            "command execution",
            "code execution",
            "execute code",
            "shell",
            "exec",
            "rce",
            "ognl",
            "struts",
            "healthcheck",
            "script",
        ),
    ):
        return True
    if _contains_marker(text, ("url", "uri", "endpoint")) and _contains_marker(
        text,
        ("validate", "validator", "availability", "status", "health", "check", "service dashboard"),
    ):
        return True
    return _contains_marker(text, ("remind", "reminder", "notify", "schedule", "scheduler", "cron", "job", "task")) and _contains_marker(
        text,
        ("date", "time", "message", "target", "value"),
    )


def _file_fetch_parser_evidence(task_surface: _TaskSurface) -> list[str]:
    evidence: list[str] = []
    evidence.extend(
        _evidence_for(
            "file read or upload workflow",
            task_surface.workflows,
            task_surface.markers,
        )
    )
    evidence.extend(
        _evidence_for(
            "server-side fetch workflow",
            task_surface.workflows,
            task_surface.markers,
        )
    )
    evidence.extend(
        _evidence_for(
            "structured parser workflow",
            task_surface.workflows,
            task_surface.markers,
        )
    )
    return evidence


def _reflection_bonus(task_surface: _TaskSurface) -> int:
    if task_surface.reflected:
        return 12
    return 0


def _idor_bonus(task_surface: _TaskSurface) -> int:
    if task_surface.idor_surface:
        return 10
    return 0


def _form_bonus(task_surface: _TaskSurface) -> int:
    if task_surface.forms:
        return 8
    return 0


def _command_boundary_bonus(task_surface: _TaskSurface) -> int:
    text = " ".join(
        (
            task_surface.text,
            json.dumps(task_surface.forms, sort_keys=True),
            json.dumps(task_surface.parameters, sort_keys=True),
            json.dumps(task_surface.endpoints, sort_keys=True),
            " ".join(task_surface.workflows),
            " ".join(task_surface.markers),
        )
    ).lower()
    bonus = 0
    if "command_boundary" in text:
        bonus += 12
    if _contains_marker(text, ("command execution", "code execution", "execute code", "shell", "rce", "ognl", "struts")):
        bonus += 12
    if _contains_marker(text, (".action", "jsessionid", "java", "/tmp", "tmp/")):
        bonus += 8
    if _contains_marker(text, ("healthcheck", "script", "service dashboard", "api/set", "name/set", "/app/")):
        bonus += 8
    if _contains_marker(text, ("url", "uri", "endpoint")) and _contains_marker(
        text,
        ("validate", "validator", "availability", "status", "health", "check"),
    ):
        bonus += 8
    if task_surface.forms:
        bonus += 4
    return min(bonus, 24)


def _task(
    task_id: str,
    title: str,
    priority: int,
    rationale: str,
    next_steps: list[str],
    *,
    evidence: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": task_id,
        "title": title,
        "priority": max(1, min(priority, 100)),
        "status": "pending",
        "attempts": 0,
        "rationale": rationale,
        "next_steps": next_steps,
        "evidence": _clean_evidence(evidence),
        "last_outcome": "",
    }


def _task_for_action(state: AgentState, action: Mapping[str, object]) -> dict[str, object] | None:
    inferred = _task_id_for_known_action(action)
    if inferred:
        for task in state.tasks:
            if task.get("id") == inferred:
                return task
    explicit = str(action.get("task_id") or "").strip()
    if explicit:
        for task in state.tasks:
            if task.get("id") == explicit:
                return task
    text = _action_text(action)
    for task in state.tasks:
        task_id = str(task.get("id") or "")
        title = str(task.get("title") or "").lower()
        if _task_id_matches_action_text(task_id, text):
            return task
        if _title_matches_action_text(title, text):
            return task
    return None


def _task_id_for_known_action(action: Mapping[str, object]) -> str:
    probe = str(action.get("probe") or "").strip()
    if probe == "secret_sweep":
        return "flag-and-secret-sweep"
    if probe in {"input_reflection", "xss_context", "dom_execution", "reflection_value_boundary"}:
        return "input-reflection"
    if probe in {"server_rendering", "ssti_fingerprint"}:
        return "server-rendering"
    if probe in {"stateful_session", "csrf_session", "idor_boundary"}:
        return "stateful-session"
    if probe in {"api_behavior", "browser_boundary", "jwt_exploit", "graphql_exploit"}:
        return "api-behavior"
    if probe in {"data_query", "filtered_query_bypass", "preg_match_subject", "sqli_differential", "sqli_exploit"}:
        return "data-query"
    if probe in {"file_fetch_parser", "file_read_extract"}:
        return "file-fetch-parser"
    if probe == "command_boundary":
        return "command-boundary"
    if str(action.get("strategy") or "").strip() == "data_query":
        return "data-query"
    text = _action_text(action)
    if "secret_hunting" in text or "source/backup" in text or "backup/config" in text:
        return "flag-and-secret-sweep"
    return ""


def _evidence_snippet(
    *,
    action: Mapping[str, object],
    outcome: str,
    observation: str,
) -> str:
    note = str(action.get("notes") or action.get("expected_signal") or action.get("strategy") or "")
    snippets = []
    lower = observation.lower()
    for marker in (
        "set-cookie",
        "<form",
        "traceback",
        "exception",
        "sql",
        "sqlite",
        "mysql",
        "jwt",
        "xml",
        "graphql",
        "xss_reflection_context",
        "client_side_execution",
        "ssti_fingerprint_signal",
        "idor_boundary",
    ):
        if marker in lower:
            snippets.append(marker)
    base = f"{outcome}: {note}".strip(": ")
    if snippets:
        base += " markers=" + ",".join(sorted(set(snippets)))
    return base[:300]


def _high_value_secret_signal(observation: str) -> bool:
    lower = observation.lower()
    return _contains_marker(
        lower,
        (
            "flag{",
            "htb{",
            "ctf{",
            "api_key",
            "secret_key",
            "password=",
            "password:",
            "private key",
            "db_password",
            "source code",
            "<?php",
        ),
    )


def _has_confirmed_data_query_signal(state: AgentState) -> bool:
    text = " ".join(
        [
            " ".join(state.signals.get("markers", [])),
            " ".join(state.signals.get("sqli_inputs", [])),
            " ".join(state.facts[-20:]),
            " ".join(state.hypotheses[-12:]),
        ]
    ).lower()
    return _contains_marker(
        text,
        (
            "sql_injection_confirmed",
            "sql_injection_error_signal",
            "blind_sql_injection",
            "sql syntax",
            "mysql",
            "sqlite",
            "postgres",
            "sqli_inputs",
            "preg_match",
            "array given",
            "user exists",
            "some item is filtered",
        ),
    )


def _has_confirmed_file_read_signal(state: AgentState) -> bool:
    text = " ".join(
        [
            " ".join(state.signals.get("markers", [])),
            " ".join(state.signals.get("file_read_inputs", [])),
            " ".join(state.facts[-20:]),
        ]
    ).lower()
    return bool(state.signals.get("file_read_inputs")) or _contains_marker(
        text,
        (
            "file_read_confirmed",
            "file_read_primitive",
            "root:x:0:0",
            "local file read",
        ),
    )


def _input_evidence(
    *,
    forms: list[dict[str, object]],
    parameters: list[dict[str, object]],
    reflected: list[dict[str, object]],
) -> list[str]:
    evidence: list[str] = []
    if forms:
        evidence.append(f"{len(forms)} form(s) observed")
    if parameters:
        names = _item_names(parameters, limit=8)
        evidence.append(f"parameters: {names}")
    if reflected:
        names = _item_names(reflected, limit=8)
        evidence.append(f"reflected parameters: {names}")
    return evidence


def _evidence_for(workflow: str, workflows: list[str], markers: list[str]) -> list[str]:
    evidence = []
    if workflow in workflows:
        evidence.append(workflow)
    for marker in markers[:8]:
        if marker and marker not in evidence:
            evidence.append(f"marker:{marker}")
    return evidence[:10]


def _has_file_or_fetch_surface(
    parameters: list[dict[str, object]],
    endpoints: list[dict[str, object]],
    text: str,
    workflows: list[str],
) -> bool:
    if _has_any_workflow(
        workflows,
        ("file read or upload workflow", "server-side fetch workflow", "structured parser workflow"),
    ):
        return True
    if _contains_marker(text, ("file", "path", "upload", "xml", "soap", "url", "webhook", "redirect")):
        return True
    for item in parameters + endpoints:
        item_text = json.dumps(item, sort_keys=True).lower()
        if _contains_marker(item_text, ("file", "url", "upload", "xml", "structured")):
            return True
    return False


def _has_idor_surface(parameters: list[dict[str, object]], endpoints: list[dict[str, object]], text: str) -> bool:
    if _contains_marker(text, ("idor", "user_id", "account_id", "order_id", "profile", "authorization")):
        return True
    for item in parameters + endpoints:
        payload = json.dumps(item, sort_keys=True).lower()
        if _contains_marker(payload, ("user_id", "account_id", "order_id", "file_id", "doc_id", "profile", "uuid")):
            return True
    return False


def _workflow_names(surface: dict[str, object]) -> list[str]:
    names: list[str] = []
    for item in _list_of_dicts(surface.get("candidate_workflows")):
        name = str(item.get("name") or "")
        if name:
            names.append(name)
    return names


def _merge_strings(first: object, second: object) -> list[str]:
    merged: list[str] = []
    for value in _list(first) + _list(second):
        text = re.sub(r"\s+", " ", str(value)).strip()
        if text and text not in merged:
            merged.append(text)
    return merged[-12:]


def _status(value: object) -> str:
    text = str(value or "pending")
    return text if text in TASK_STATUSES else "pending"


def _status_rank(value: str) -> int:
    return {"in_progress": 0, "pending": 1, "blocked": 2, "done": 3}.get(value, 1)


def _tasks_by_id(tasks: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    indexed: dict[str, dict[str, object]] = {}
    for task in tasks:
        task_id = str(task.get("id") or "")
        if task_id:
            indexed[task_id] = task
    return indexed


def _task_ids(tasks: list[dict[str, object]]) -> set[str]:
    task_ids: set[str] = set()
    for task in tasks:
        task_id = str(task.get("id") or "")
        if task_id:
            task_ids.add(task_id)
    return task_ids


def _preserve_task_progress(task: dict[str, object], previous: dict[str, object]) -> None:
    task["status"] = _status(previous.get("status"))
    task["attempts"] = _int(previous.get("attempts"))
    task["evidence"] = _merge_strings(previous.get("evidence"), task.get("evidence"))
    task["last_outcome"] = str(previous.get("last_outcome") or "")


def _mission_task_sort_key(task: dict[str, object]) -> tuple[int, int, str]:
    status_rank = _status_rank(str(task.get("status")))
    priority = -_int(task.get("priority"))
    task_id = str(task.get("id") or "")
    return status_rank, priority, task_id


def _prompt_task_sort_key(task: dict[str, object]) -> tuple[int, int, int]:
    status_rank = _status_rank(str(task.get("status")))
    priority = -_int(task.get("priority"))
    attempts = _int(task.get("attempts"))
    return status_rank, priority, attempts


def _generated_task_sort_key(task: dict[str, object]) -> tuple[int, str]:
    priority = -_int(task.get("priority"))
    task_id = str(task.get("id") or "")
    return priority, task_id


def _empty_status_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for status in TASK_STATUSES:
        counts[status] = 0
    return counts


def _surface_markers(*, surface: dict[str, object], state: AgentState) -> list[str]:
    markers: list[str] = []
    for item in _list(surface.get("markers")):
        markers.append(str(item).lower())
    for item in state.signals.get("markers", [])[:12]:
        markers.append(str(item).lower())
    return markers


def _clean_evidence(evidence: list[str] | None) -> list[str]:
    cleaned: list[str] = []
    if evidence is None:
        return cleaned
    for item in evidence:
        if item:
            cleaned.append(item)
    return cleaned


def _action_text(action: Mapping[str, object]) -> str:
    values: list[str] = []
    for key in ("strategy", "notes", "expected_signal", "fallback"):
        value = str(action.get(key) or "")
        if value:
            values.append(value)
    return " ".join(values).lower()


def _task_id_matches_action_text(task_id: str, text: str) -> bool:
    if task_id in text:
        return True
    parts = task_id.split("-")[:2]
    for part in parts:
        if part not in text:
            return False
    return bool(parts)


def _item_names(items: list[dict[str, object]], *, limit: int) -> str:
    names: list[str] = []
    for item in items[:limit]:
        names.append(str(item.get("name") or ""))
    return ", ".join(names)


def _bonus(text: str, words: tuple[str, ...]) -> int:
    score = 0
    for word in words:
        if word in text:
            score += 4
    return score


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))
    return items


def _dict(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _has_any_workflow(workflows: list[str], candidates: tuple[str, ...]) -> bool:
    for candidate in candidates:
        if candidate in workflows:
            return True
    return False


def _has_api_endpoint_hint(endpoints: list[dict[str, object]]) -> bool:
    for endpoint in endpoints:
        hints = str(endpoint.get("hints") or "")
        text = json.dumps(endpoint, sort_keys=True).lower()
        if "api" in hints or "graphql" in hints or "websocket" in text or "ws://" in text or "wss://" in text:
            return True
    return False


def _title_matches_action_text(title: str, text: str) -> bool:
    if not title:
        return False
    for word in title.split():
        if len(word) > 5 and word in text:
            return True
    return False


def _forms_from_signal_values(values: list[str]) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for index, value in enumerate(values):
        try:
            decoded = json.loads(str(value))
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, dict):
            forms.append(decoded)
            continue
        forms.append(
            {
                "id": f"signal-form-{index}",
                "action": "",
                "categories": ["generic_input"],
                "inputs": [],
            }
        )
    return forms


def _dedupe_dict_items(items: list[dict[str, object]], *, limit: int) -> list[dict[str, object]]:
    deduped: dict[str, dict[str, object]] = {}
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in deduped:
            deduped[key] = item
    return list(deduped.values())[:limit]


def _parameters_from_signal_values(values: list[str]) -> list[dict[str, object]]:
    parameters: list[dict[str, object]] = []
    for name in values:
        parameters.append(
            {
                "name": name,
                "sources": ["signal"],
                "locations": [],
                "hints": [],
                "priority": 10,
            }
        )
    return parameters


def _reflections_from_signal_values(values: list[str]) -> list[dict[str, object]]:
    reflected: list[dict[str, object]] = []
    for value in values:
        reflected.append({"name": value[:80], "source": "signal", "url": ""})
    return reflected


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
