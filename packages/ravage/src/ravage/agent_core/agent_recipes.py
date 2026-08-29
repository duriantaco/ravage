from __future__ import annotations

from ravage.agent_core.agent_state import AgentState


def recipes_for_active_tasks(state: AgentState, *, limit: int = 6) -> list[dict[str, object]]:
    recipes: list[dict[str, object]] = []
    active_ids = _active_task_ids(state, limit=limit)
    for task_id in active_ids:
        recipe = _RECIPES.get(task_id)
        if recipe:
            recipes.append(_recipe_payload(task_id, recipe))
    return recipes


def _active_task_ids(state: AgentState, *, limit: int) -> list[str]:
    task_ids: list[str] = []
    for task in state.tasks:
        if len(task_ids) >= limit:
            break
        if not _task_is_active(task):
            continue
        task_id = str(task.get("id") or "")
        if task_id:
            task_ids.append(task_id)
    return task_ids


def _task_is_active(task: dict[str, object]) -> bool:
    status = task.get("status")
    return status in {"pending", "in_progress"}


def _recipe_payload(task_id: str, recipe: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {"task_id": task_id}
    for key, value in recipe.items():
        payload[key] = value
    return payload


_RECIPES: dict[str, dict[str, object]] = {
    "surface-map": {
        "purpose": "Build a fresh request/response inventory.",
        "good_first_actions": [
            "run_probe surface_map to fetch common paths and summarize notable pages.",
            "curl -i -sS -L -c /tmp/ravage.cookies -b /tmp/ravage.cookies \"$RAVAGE_TARGET_URL\"",
            "Use Python urllib to crawl same-origin links if the built-in recon missed scripts or forms.",
        ],
        "record": ["status", "redirect chain", "set-cookie", "forms", "links", "scripts", "interesting files"],
    },
    "flag-and-secret-sweep": {
        "purpose": "Find flags or secrets exposed without exploitation.",
        "good_first_actions": [
            "run_probe secret_sweep to check common exposed files, scripts, configs, and known endpoints.",
            "run_probe direct_exposure to check likely admin/debug/config/backup/source paths with concise body capture.",
            "Request robots.txt, sitemap.xml, exposed VCS/config paths, backup archives, and visible JavaScript/source maps.",
            "Search saved responses for flag-like strings, credentials, filesystem paths, and hidden endpoints.",
            "If credentials open a shell or raw service, reuse the exact extracted password on the scoped external service port, run case-insensitive proof-file discovery, and read exact source-named paths plus upper/lower FLAG.txt variants.",
        ],
        "record": ["exact URL", "status", "matched secret or path", "follow-up endpoint"],
    },
    "input-reflection": {
        "purpose": "Prove whether a specific input changes output.",
        "good_first_actions": [
            "run_probe input_reflection to submit unique markers through mapped query parameters and forms.",
            "Pick one parameter/form input and submit a unique marker with a fresh cookie jar.",
            "Compare baseline versus marker response status, length, body snippets, redirects, and headers.",
            "After a reflected sink is found, run_probe dom_execution to confirm in a real browser whether the input actually executes (XSS) rather than only reflecting.",
        ],
        "record": ["input name", "method", "action URL", "marker", "sink location", "response delta", "browser execution confirmed?"],
    },
    "stateful-session": {
        "purpose": "Understand login/register/session/CSRF behavior.",
        "good_first_actions": [
            "run_probe stateful_session to exercise auth-like forms with cookies and hidden field defaults.",
            "Fetch the form, extract hidden fields, then submit a low-privilege account with a cookie jar.",
            "After login, request account/profile/admin-looking paths and compare object IDs.",
        ],
        "record": ["csrf field", "cookie names", "login status", "redirect", "identity evidence", "gated routes"],
    },
    "server-rendering": {
        "purpose": "Check whether reflected input is evaluated by a server-side renderer.",
        "good_first_actions": [
            "run_probe server_rendering to test harmless arithmetic expressions in mapped inputs.",
            "In a confirmed reflected sink, compare literal marker output with harmless arithmetic/string expressions.",
            "Use framework errors or escaping behavior to adapt syntax; do not jump to file reads first.",
        ],
        "record": ["sink context", "literal result", "evaluated result", "error text", "escaping/filtering"],
    },
    "data-query": {
        "purpose": "Check whether an input changes database query behavior.",
        "good_first_actions": [
            "run_probe sqli_differential to perform paired SQLi/blind-SQLi checks across mapped params, forms, and query-like endpoints.",
            "After a SQLi signal, run_probe sqli_exploit to reuse the working request template for error/UNION/boolean extraction and credential/auth-bypass replay.",
            "On login forms, test both username-side and password-side SQLi closure; transformed password fields often make password payloads non-viable.",
            "If form submissions return captcha/code/CSRF failures, run_probe captcha_form_state before more SQL/auth payload loops.",
            "When search/login responses show blocked SQL keywords or filtered output, run_probe filtered_query_bypass before manual payload loops.",
            "When PHP preg_match warnings or username[] type confusion appears, run_probe preg_match_subject before manual regex loops.",
            "run_probe data_query to collect SQL-shaped syntax and boolean response deltas.",
            "For one parameter, collect baseline response, true-like perturbation, false-like perturbation, and timing sample.",
            "Compare status, length, stable phrases, row counts, error markers, and elapsed time.",
        ],
        "record": ["parameter", "baseline length", "true/false lengths", "error marker", "timing delta", "oracle stability"],
    },
    "file-fetch-parser": {
        "purpose": "Investigate file paths, upload reads, URL fetchers, redirects, and structured parsers.",
        "good_first_actions": [
            "run_probe file_fetch_parser to try safe path, URL, and parser readback probes on matching inputs.",
            "Identify where referenced/uploaded content is read back before attempting sensitive targets.",
            "For unsafe upload parsers/deserializers, a non-reflected side effect plus follow-up GET can be the closure; do not require the parser return value to be reflected.",
            "Use harmless path, URL, XML, and content-type probes that match the observed endpoint.",
        ],
        "record": ["input", "fetch/readback evidence", "parser errors", "allowed schemes/types", "path normalization"],
    },
    "command-boundary": {
        "purpose": "Check whether command-shaped inputs cross an OS boundary.",
        "good_first_actions": [
            "run_probe command_boundary to test benign shell boundary markers against command-like inputs.",
            "Send benign separators or timing probes that produce observable differences without destructive effects.",
            "Treat URL validators, service dashboards, health checks, script endpoints, and API setter/getter relationships as command-boundary candidates when the objective or page text mentions command/code execution.",
            "When a page exposes proxy/service mappings, test the mapped same-origin paths and scoped auxiliary origins before repeating unrelated probes.",
            "Compare command errors, elapsed time, and controlled echo output.",
        ],
        "record": ["input", "separator/encoding", "elapsed time", "controlled output", "error text"],
    },
    "api-behavior": {
        "purpose": "Map JSON/API/GraphQL behavior and authorization boundaries.",
        "good_first_actions": [
            "run_probe api_behavior to inspect OPTIONS, JSON, and GraphQL-like endpoint behavior.",
            "Inspect OPTIONS, content types, JavaScript route references, schema/introspection behavior, and JSON error shapes.",
            "Probe object IDs and methods with a valid low-privilege session when available.",
        ],
        "record": ["endpoint", "method", "content type", "schema/errors", "object boundary signal"],
    },
}
