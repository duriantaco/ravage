from __future__ import annotations

from dataclasses import dataclass

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.primitive_state import routed_probes

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
COMMAND_BOUNDARY_SURFACE_MARKERS = (
    "command_boundary",
    "command execution",
    "code execution",
    "execute code",
    "shell",
    "exec",
    "rce",
    "ognl",
    "struts",
    ".action",
    "jsessionid",
    "/tmp",
    "healthcheck",
    "script",
    "service dashboard",
    "api/set",
    "name/set",
    "/app/",
    "url validator",
    "availability checker",
)


@dataclass(frozen=True)
class SpecialistCard:
    name: str
    stage: str
    probe: str
    task_id: str
    purpose: str
    triggers: tuple[str, ...]
    handoff: str

    def to_json(self, *, score: int = 0) -> dict[str, object]:
        return {
            "name": self.name,
            "stage": self.stage,
            "probe": self.probe,
            "task_id": self.task_id,
            "purpose": self.purpose,
            "triggers": list(self.triggers),
            "handoff": self.handoff,
            "score": score,
        }


SPECIALIST_BOOK: tuple[SpecialistCard, ...] = (
    SpecialistCard(
        name="sql_differential_verifier",
        stage="exploit",
        probe="sqli_differential",
        task_id="data-query",
        purpose="Run paired syntax, boolean, and timing checks across mapped forms, query parameters, and query-like endpoints.",
        triggers=QUERY_LIKE_MARKERS,
        handoff="Run before custom SQL payload loops when forms or query-like inputs exist but SQLi is not yet confirmed.",
    ),
    SpecialistCard(
        name="sql_verifier_extractor",
        stage="exploit",
        probe="sqli_exploit",
        task_id="data-query",
        purpose="Reuse a confirmed SQLi request template for bounded error, UNION, boolean extraction, credential replay, and username/password auth-bypass closure.",
        triggers=(
            "sql_injection_confirmed",
            "sql syntax",
            "mysql",
            "sqlite",
            "blind_sql_injection",
            "sql_extracted_proof",
            "sqli_inputs",
        ),
        handoff="Run after sqli_differential reports a SQL signal; it handles proof extraction and username-side/password-side login bypass before hand-written loops.",
    ),
    SpecialistCard(
        name="filtered_query_bypass",
        stage="exploit",
        probe="filtered_query_bypass",
        task_id="data-query",
        purpose="Probe search/login inputs that show filtering, row-existence changes, or blocked SQL keywords with bounded bypass variants.",
        triggers=("some item is filtered", "filtered", "no results", "user exists", "search.php", "login.php"),
        handoff="Run when normal values affect result text but obvious SQL payloads are blocked or produce generic filtered responses.",
    ),
    SpecialistCard(
        name="preg_match_subject_probe",
        stage="exploit",
        probe="preg_match_subject",
        task_id="data-query",
        purpose="Exercise PHP preg_match subject behavior on search-like inputs, including array type probes and proof-shaped subjects.",
        triggers=("preg_match", "preg_match_subject_type_signal", "expects parameter 2", "array given", "user exists", "search.php"),
        handoff="Run when PHP preg_match warnings or exact-match user search behavior appears; it is a bounded specialist, not a free-form regex loop.",
    ),
    SpecialistCard(
        name="captcha_form_state_helper",
        stage="exploit",
        probe="captcha_form_state",
        task_id="data-query",
        purpose="Refresh CSRF/captcha/code form state, solve visible or weak-cookie challenges, and emit replay templates for SQL/auth probes.",
        triggers=("captcha", "challenge", "verification code", "security code", "invalid captcha", "invalid code", "csrf", "csrf_token"),
        handoff="Run before repeating SQL/auth payloads against forms that reject requests due to captcha/code/CSRF state.",
    ),
    SpecialistCard(
        name="direct_exposure_sweeper",
        stage="recon",
        probe="direct_exposure",
        task_id="flag-and-secret-sweep",
        purpose="Check visible and likely hidden same-origin admin, config, backup, source, and debug paths with concise body capture.",
        triggers=(
            "admin",
            "backup",
            ".env",
            "config",
            "debug",
            "source",
            "404",
            "php",
            "cve",
            "actuator",
            "openapi",
            "swagger",
            "package.json",
            "direct_exposure_candidate",
            "direct_exposure_proof",
            "version disclosure",
        ),
        handoff="Run before repeating manual file loops; it records exact URLs, statuses, and secret/proof-like body snippets.",
    ),
    SpecialistCard(
        name="cms_backup_exposure",
        stage="recon",
        probe="cms_exposure",
        task_id="flag-and-secret-sweep",
        purpose="Inspect same-origin CMS/WordPress backup-plugin configs, logs, manifests, and backup artifacts for exposed secrets or proofs.",
        triggers=("wordpress", "wp-content", "wp-json", "backup", "plugin", "cms", "backup-migration"),
        handoff="Run when WordPress/CMS or backup-plugin evidence appears; it follows public config/log/manifests instead of broad manual path loops.",
    ),
    SpecialistCard(
        name="api_graphql_jwt_mapper",
        stage="recon",
        probe="api_behavior",
        task_id="api-behavior",
        purpose="Map OPTIONS/API behavior, GraphQL introspection, and observed JWT claims without inventing credentials.",
        triggers=("api", "graphql", "graphiql", "openapi", "swagger", "jwt", "bearer", "authorization", "token"),
        handoff="Run when API, GraphQL, JWT, bearer-token, OpenAPI, or Swagger evidence appears before custom curl loops.",
    ),
    SpecialistCard(
        name="browser_boundary_tester",
        stage="exploit",
        probe="browser_boundary",
        task_id="api-behavior",
        purpose="Probe CORS, frame policy/clickjacking, WebSocket Origin/auth behavior, and localStorage/sessionStorage secret exposure.",
        triggers=(
            "cors",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "clickjack",
            "x-frame-options",
            "frame-ancestors",
            "websocket",
            "web socket",
            "ws://",
            "wss://",
            "localstorage",
            "sessionstorage",
            "browser_storage_secret_exposure",
            "cors_misconfiguration_signal",
        ),
        handoff="Run when API/browser boundary evidence appears; it sends Origin/preflight requests, checks frame headers, tests WebSocket Origin, and inspects browser storage assignments.",
    ),
    SpecialistCard(
        name="jwt_exploiter",
        stage="exploit",
        probe="jwt_exploit",
        task_id="api-behavior",
        purpose="Forge observed JWTs (alg:none, weak-secret crack-and-resign, RS256->HS256 confusion) with escalated claims and replay into protected endpoints.",
        triggers=("jwt_observed", "jwt", "bearer", "alg", "eyj", "authorization", "token", "hs256", "rs256"),
        handoff="Run after a JWT is observed; it tampers and replays rather than just decoding, so prefer it over re-running api_behavior.",
    ),
    SpecialistCard(
        name="graphql_exploiter",
        stage="exploit",
        probe="graphql_exploit",
        task_id="api-behavior",
        purpose="Introspect the GraphQL schema, generate sensitive-field queries, alias-batch object-id traversal, and enumerate mutations.",
        triggers=("graphql", "graphiql", "__schema", "introspection", "graphql_schema_signal", "graphql_schema_mapped", "mutation", "query {"),
        handoff="Run after GraphQL/introspection evidence; it generates schema-driven queries rather than re-mapping, so prefer it over re-running api_behavior.",
    ),
    SpecialistCard(
        name="xss_context_mapper",
        stage="exploit",
        probe="xss_context",
        task_id="input-reflection",
        purpose="Map reflected canary context and surviving XSS syntax before browser verification.",
        triggers=("reflected", "reflection", "xss", "html sink", "comment", "message", "search", "input_reflection"),
        handoff="Run after controllable input is found; use its context/filter profile to choose whether dom_execution is worthwhile.",
    ),
    SpecialistCard(
        name="browser_xss_verifier",
        stage="exploit",
        probe="dom_execution",
        task_id="input-reflection",
        purpose="Use a real browser to distinguish reflected text from actual client-side script execution.",
        triggers=("xss_reflection_context", "reflected", "xss", "script", "html sink", "onerror", "innerhtml", "svg"),
        handoff="Run after xss_context or input_reflection finds an executable-looking sink; browser execution is the proof, not plain reflection.",
    ),
    SpecialistCard(
        name="reflection_value_boundary",
        stage="exploit",
        probe="reflection_value_boundary",
        task_id="input-reflection",
        purpose="Use visible page text, titles, assets, and reflected forms to test bounded value branches and preserve any changed request template.",
        triggers=("client_side_execution", "incorrect value", "typeerror", "reflected", "input_delta", "html_body", "RAVAGE_FETCH_SCAN"),
        handoff="Run after reflected input or browser execution is confirmed but proof paths are empty; it replaces broad hand-written value loops.",
    ),
    SpecialistCard(
        name="ssti_fingerprint_verifier",
        stage="exploit",
        probe="ssti_fingerprint",
        task_id="server-rendering",
        purpose="Fingerprint server-side template evaluation with harmless arithmetic and identity probes.",
        triggers=(
            "template",
            "ssti",
            "jinja",
            "twig",
            "freemarker",
            "server-side rendering",
            "reflected",
            "reflection",
            "html sink",
            "{{",
            "expression",
        ),
        handoff="Run harmless fingerprint probes before any engine-specific file or command payload.",
    ),
    SpecialistCard(
        name="server_template_verifier",
        stage="exploit",
        probe="server_rendering",
        task_id="server-rendering",
        purpose="Compatibility SSTI verifier for harmless template/expression evaluation.",
        triggers=("template", "jinja", "server-side rendering", "{{", "expression"),
        handoff="Prefer ssti_fingerprint when available; use this compatibility probe if the model selects server_rendering.",
    ),
    SpecialistCard(
        name="idor_boundary_tester",
        stage="exploit",
        probe="idor_boundary",
        task_id="stateful-session",
        purpose="Mutate object identifiers, trusted identity headers, and simple encoded identity cookies for access-control boundary failures.",
        triggers=(
            "access_token",
            "authorization",
            "bearer",
            "cookie",
            "idor",
            "object",
            "user_id",
            "account_id",
            "profile",
            "order",
            "invoice",
            "document",
            "uuid",
        ),
        handoff="Run after endpoints/forms expose object IDs or authenticated account/profile flows; compare concrete responses before claiming impact.",
    ),
    SpecialistCard(
        name="default_credentials_tester",
        stage="exploit",
        probe="default_credentials",
        task_id="stateful-session",
        purpose="Try bounded generic default credentials on login/basic-auth surfaces, then sweep the authenticated session for proof-bearing pages.",
        triggers=("login", "signin", "sign-in", "username", "password", "admin", "default credentials", "basic auth"),
        handoff="Run when a login/password surface exists and no authenticated session is confirmed; it should precede generic SQLi guessing on auth forms.",
    ),
    SpecialistCard(
        name="csrf_session_boundary_tester",
        stage="exploit",
        probe="csrf_session",
        task_id="stateful-session",
        purpose="Test state-changing forms for CSRF omission/reuse, logout invalidation, fixation hints, and weak session cookie attributes.",
        triggers=(
            "csrf",
            "xsrf",
            "authenticity_token",
            "session",
            "set-cookie",
            "samesite",
            "httponly",
            "logout",
            "profile",
            "settings",
            "transfer",
            "update",
            "csrf_omission_accepted",
            "logout_invalidation_failed",
        ),
        handoff="Run when forms/cookies/session state appear; it performs negative CSRF tests instead of only preserving tokens for normal workflow replay.",
    ),
    SpecialistCard(
        name="file_fetch_parser_verifier",
        stage="exploit",
        probe="file_fetch_parser",
        task_id="file-fetch-parser",
        purpose="Check path, URL-fetch, upload, parser, and unsafe deserialization inputs for file read, readback, or side-effect closure.",
        triggers=(
            "file",
            "path",
            "upload",
            "xml",
            "url",
            "webhook",
            "import",
            "pickle",
            "yaml",
            "deserialize",
            "deserialization",
            "file_fetch_parser_signal",
            "apache_2_4_path_traversal_surface",
        ),
        handoff="Run when inputs or endpoints imply files, URLs, XML, imports, uploads, unsafe deserialization, or parser-controlled content; it can verify non-reflected parser side effects with follow-up reads.",
    ),
    SpecialistCard(
        name="xxe_boundary_tester",
        stage="exploit",
        probe="xxe_boundary",
        task_id="file-fetch-parser",
        purpose="Probe XML, SOAP, SVG upload, and XML import surfaces with bounded external-entity file-read payloads and readback closure.",
        triggers=("xxe", "xml", "soap", "wsdl", "svg", "doctype", "entity", "import", "upload", "xxe_extracted_proof"),
        handoff="Run when XML/SOAP/SVG/import evidence appears; it preserves the request template and varies entity targets before generic file-parser work.",
    ),
    SpecialistCard(
        name="file_read_extractor",
        stage="exploit",
        probe="file_read_extract",
        task_id="file-fetch-parser",
        purpose="Reuse a confirmed local file-read/include request template for bounded source, flag, and PHP include-execution extraction.",
        triggers=(
            "file_read_confirmed",
            "file_read_primitive",
            "file_fetch_parser_signal",
            "file_read_listed_file_proof",
            "file_read_listed_file_secret",
            "apache_2_4_path_traversal_surface",
            "apache/2.4.49",
            "apache/2.4.50",
            "root:x:0:0",
            "passwd",
            "local file read",
        ),
        handoff="Run immediately after file_fetch_parser or another action proves local file read; do not keep hand-writing path guesses first.",
    ),
    SpecialistCard(
        name="werkzeug_console_exploiter",
        stage="exploit",
        probe="werkzeug_console",
        task_id="flag-and-secret-sweep",
        purpose="Complete an exposed Werkzeug debugger console: extract SECRET, eval Python when unlocked, compute the PIN from leaked machine bits, or abandon.",
        triggers=(
            "werkzeug_console_exposed",
            "werkzeug_console_unlocked",
            "werkzeug debugger",
            "traceback (most recent call last)",
            "console-mode",
        ),
        handoff="Run when an exposed /console or Werkzeug debugger appears; it completes the eval flow rather than inspecting debugger JS by hand.",
    ),
    SpecialistCard(
        name="cookie_deserialization_exploiter",
        stage="exploit",
        probe="cookie_deserialization",
        task_id="file-fetch-parser",
        purpose="Forge response-returning pickle/YAML gadgets into serialized session cookies, then reflect or read back the proof.",
        triggers=("cookie", "session", "pickle", "base64", "serialized", "deserialize", "deserialization", "yaml", "__reduce__", "set-cookie"),
        handoff="Run when a session cookie decodes to a serialized object (base64 pickle/YAML); it uses subprocess.check_output/os.popen().read() gadgets, never os.system.",
    ),
    SpecialistCard(
        name="command_boundary_verifier",
        stage="exploit",
        probe="command_boundary",
        task_id="command-boundary",
        purpose="Test command-shaped host/domain/scheduler, URL-validator, script/service, and OGNL/Struts inputs with benign output and timing boundaries.",
        triggers=(
            "ping",
            "nslookup",
            "traceroute",
            "host",
            "domain",
            "command",
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
            "service dashboard",
            "validate",
            "validator",
            "availability",
            "remind",
            "reminder",
            "notify",
            "schedule",
        ),
        handoff="Run before manual shell payload loops; use controlled echo/timing evidence and preserve URL validator or service setter templates.",
    ),
    SpecialistCard(
        name="ssrf_boundary_tester",
        stage="exploit",
        probe="ssrf_boundary",
        task_id="file-fetch-parser",
        purpose="Probe URL-fetch inputs for bounded loopback/internal fetch behavior with preserved request templates.",
        triggers=("url", "uri", "webhook", "callback", "fetch", "proxy", "redirect", "avatar", "import"),
        handoff="Run when a parameter or form appears to make the server fetch a URL; keep payloads local/loopback and bounded.",
    ),
)


def available_specialists() -> list[dict[str, object]]:
    specialists: list[dict[str, object]] = []
    for card in SPECIALIST_BOOK:
        specialists.append(card.to_json())
    return specialists


def recommended_specialists(state: AgentState, *, limit: int = 6) -> list[dict[str, object]]:
    text = _state_text(state)
    client_xss_objective = _has_client_xss_objective(state)
    command_boundary_evidence = _has_command_boundary_evidence(state)
    reflection_evidence = state.signals.get("reflections") or "reflected" in text or "reflection" in text
    explicit_template_evidence = _contains_marker(
        text,
        (
            "ssti",
            "jinja",
            "twig",
            "freemarker",
            "{{",
            "{%",
            "templatesyntaxerror",
            "template syntaxerror",
            "ssti_fingerprint_signal",
            "ssti_engine_execution",
        ),
    )
    primitive_boosts = routed_probes(state)
    scored: list[tuple[int, SpecialistCard]] = []
    for card in SPECIALIST_BOOK:
        score = _trigger_score(text, card.triggers)
        if card.probe in _recent_probe_names(state, limit=5):
            score -= 2
        # A confirmed primitive deterministically pins its exploit specialist to
        # the top of the recommendations, ahead of keyword-only matches.
        score += primitive_boosts.get(card.probe, 0)
        if card.probe == "sqli_exploit" and state.signals.get("sqli_inputs"):
            score += 4
        if card.probe == "sqli_differential" and _has_query_like_evidence(state):
            score += 3
        if card.probe == "sqli_differential" and _has_query_request_template(state):
            score += 14
        if card.probe == "filtered_query_bypass" and "sqli_differential" in _recent_probe_names(state, limit=8):
            score += 2
        if card.probe == "preg_match_subject" and _contains_marker(text, ("preg_match", "preg_match_subject_type_signal")):
            score += 3
        if card.probe == "captcha_form_state" and _contains_marker(
            text,
            ("captcha", "challenge", "verification code", "security code", "invalid captcha", "invalid code", "csrf"),
        ):
            score += 5
        if card.probe == "xss_context" and (state.signals.get("reflections") or "reflected" in text):
            score += 4
            if _contains_marker(text, ("xss", "script", "onerror", "onload", "html sink")):
                score += 3
            if client_xss_objective and "xss_context" in _recent_probe_names(state, limit=5):
                score -= 5
        if card.probe == "dom_execution" and ("xss_reflection_context" in text or "client_side_execution" in text):
            score += 3
        if card.probe == "dom_execution" and client_xss_objective and reflection_evidence:
            score += 10
        if card.probe == "reflection_value_boundary" and _contains_marker(
            text,
            (
                "client_side_execution",
                "xss_reflection_context",
                "expected value",
                "incorrect value",
                "typeerror",
                "ravage_fetch_scan",
                "input_delta",
            ),
        ):
            score += 5
        if card.probe == "reflection_value_boundary" and client_xss_objective and _contains_marker(text, XSS_VALUE_GATE_MARKERS):
            score += 14
        if card.probe == "command_boundary" and command_boundary_evidence:
            score += 14
            if _contains_marker(text, ("command execution", "code execution", "execute code", "ognl", "struts", ".action", "/tmp")):
                score += 6
            if reflection_evidence and _contains_marker(text, ("xss", "script", "html sink")) and not _contains_marker(
                text,
                (
                    "command execution",
                    "code execution",
                    "execute code",
                    "shell",
                    "exec",
                    "rce",
                    "ognl",
                    "struts",
                    "healthcheck",
                    "service dashboard",
                    "cmd",
                    "ping",
                ),
            ):
                score -= 14
        if (
            command_boundary_evidence
            and not client_xss_objective
            and not (reflection_evidence and _contains_marker(text, ("xss", "html sink", "onerror", "onload")))
            and card.probe in {"xss_context", "dom_execution", "reflection_value_boundary"}
        ):
            score -= 8
        if card.probe == "ssti_fingerprint" and (
            (state.signals.get("reflections") and not client_xss_objective)
            or explicit_template_evidence
        ):
            score += 5
        if card.probe == "ssti_fingerprint" and client_xss_objective and reflection_evidence and not explicit_template_evidence:
            score -= 20
        if card.probe == "ssti_fingerprint" and _has_authenticated_template_render_evidence(state):
            score += 12
        if card.probe == "idor_boundary" and _has_authenticated_template_render_evidence(state):
            score -= 4
        if card.probe == "api_behavior" and _contains_marker(
            text,
            ("api", "graphql", "graphiql", "openapi", "swagger", "jwt", "bearer", "authorization", "token"),
        ):
            score += 4
        if card.probe == "browser_boundary" and _contains_marker(
            text,
            (
                "cors",
                "access-control-allow-origin",
                "access-control-allow-credentials",
                "clickjack",
                "x-frame-options",
                "frame-ancestors",
                "websocket",
                "ws://",
                "wss://",
                "localstorage",
                "sessionstorage",
                "browser_storage_secret_exposure",
                "cors_misconfiguration_signal",
                "websocket_cross_origin_handshake_signal",
            ),
        ):
            score += 7
        if card.probe == "jwt_exploit" and _contains_marker(text, ("jwt_observed", "jwt", "bearer", "eyj", "alg")):
            score += 5
        if card.probe == "graphql_exploit" and _contains_marker(text, ("graphql", "graphiql", "__schema", "introspection", "graphql_schema")):
            score += 5
        if card.probe == "cms_exposure" and _contains_marker(
            text,
            (
                "wordpress",
                "wp-content",
                "wp-json",
                "wp-blog",
                "wp-admin",
                "wp-login",
                "wp-includes",
                "wp-config",
                "backup",
                "backup-migration",
                "plugin",
            ),
        ):
            score += 6
        if card.probe == "werkzeug_console" and _contains_marker(
            text,
            (
                "werkzeug_console_exposed",
                "werkzeug_console_unlocked",
                "werkzeug debugger",
                "traceback (most recent call last)",
                "console-mode",
            ),
        ):
            score += 5
        if card.probe == "idor_boundary" and _contains_marker(text, ("user_id", "account_id", "profile", "order_id", "idor", "authorization")):
            score += 4
        if card.probe == "idor_boundary" and _has_password_change_idor_evidence(state):
            score += 24
        if card.probe == "default_credentials" and _has_login_surface_evidence(state):
            score += 6
        if card.probe == "csrf_session" and (
            state.signals.get("forms")
            and _contains_marker(
                text,
                (
                    "csrf",
                    "xsrf",
                    "authenticity_token",
                    "session",
                    "set-cookie",
                    "samesite",
                    "httponly",
                    "logout",
                    "profile",
                    "settings",
                    "transfer",
                    "update",
                ),
            )
        ):
            score += 7
        if card.probe == "direct_exposure" and _contains_marker(
            text,
            (
                "direct_exposure_candidate",
                "direct_exposure_proof",
                "direct_exposure_listed_file_proof",
                "direct_exposure_listed_file_secret",
            ),
        ):
            score += 6
        if card.probe == "file_read_extract" and (
            state.signals.get("file_read_inputs")
            or _contains_marker(
                text,
                (
                    "file_read_confirmed",
                    "file_read_primitive",
                    "file_fetch_parser_signal",
                    "file_read_listed_file_proof",
                    "file_read_listed_file_secret",
                    "root:x:0:0",
                ),
            )
        ):
            score += 6
        if card.probe == "file_fetch_parser" and _contains_marker(
            text,
            ("file_fetch_parser_signal", "pickle", "yaml", "deserialize", "deserialization", "object/apply"),
        ):
            score += 5
        if card.probe == "xxe_boundary" and _contains_marker(
            text,
            ("xxe", "xml", "soap", "wsdl", "svg", "doctype", "entity", "import", "xxe_file_read_signal", "xxe_extracted_proof"),
        ):
            score += 6
        if card.probe == "cookie_deserialization":
            if _has_php_auth_cookie_surface(state):
                score += 18
            if _contains_marker(
                text,
                (
                    "php deserialization",
                    "unserialize",
                    "serialized cookie",
                    "base64 cookie",
                    "insecure_deserialization",
                ),
            ) or (
                _contains_marker(text, ("deserialize", "deserialization", "serialized"))
                and _has_login_surface_evidence(state)
            ):
                score += 7
            if state.signals.get("cookies") and (
                _contains_marker(text, ("pickle", "base64", "serialized", "deserialize", "deserialization", "__reduce__", "!!python", "insecure_deserialization_cookie"))
                or _has_base64ish_cookie(state)
            ):
                score += 5
        if card.probe == "ssrf_boundary" and _contains_marker(
            text,
            (
                "url",
                "uri",
                "webhook",
                "callback",
                "fetch",
                "proxy",
                "redirect",
                "ssrf_boundary_signal",
                "ssrf_internal_path_signal",
                "ssrf_extracted_secret",
                "ssrf_extracted_proof",
            ),
        ):
            score += 4
        score -= _stagnant_probe_penalty(state, card.probe)
        if score > 0:
            scored.append((score, card))
    scored.sort(key=lambda item: (-item[0], item[1].name))
    recommendations: list[dict[str, object]] = []
    for score, card in scored[:limit]:
        recommendations.append(card.to_json(score=score))
    return recommendations


def _state_text(state: AgentState) -> str:
    values: list[str] = [state.phase]
    values.append(_recent_facts_text(state))
    values.append(_recent_hypotheses_text(state))
    values.append(_signal_text(state))
    values.append(str(state.surface))
    values.append(_recent_action_text(state))
    return _join_present(values).lower()


def _has_query_like_evidence(state: AgentState) -> bool:
    return _contains_marker(_state_text(state), QUERY_LIKE_MARKERS)


def _has_query_request_template(state: AgentState) -> bool:
    for raw_template in state.signals.get("request_templates", []):
        text = str(raw_template).lower()
        if _contains_marker(
            text,
            (
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
            ),
        ):
            return True
    return False


def _has_login_surface_evidence(state: AgentState) -> bool:
    text = _state_text(state)
    if "default_credentials_valid" in text or "session_followup_proof" in text or "auth_workflow_completed_signal" in text:
        return False
    return _contains_marker(text, ("login", "signin", "sign-in", "password", "basic auth", "auth form", "session login"))


def _has_password_change_idor_evidence(state: AgentState) -> bool:
    text = _state_text(state)
    idor_evidence = _contains_marker(
        text,
        (
            "idor",
            "insecure direct object",
            "authorization",
            "user_id",
            "userid",
            "profile",
        ),
    )
    password_change_evidence = _contains_marker(
        text,
        (
            "change password",
            "password reset",
            "reset password",
            "another user's password",
            "change_password",
            "update_password",
            "oldpassword",
            "newpassword",
            "confirmpassword",
        ),
    )
    return idor_evidence and password_change_evidence


def _has_php_auth_cookie_surface(state: AgentState) -> bool:
    text = _state_text(state)
    php_surface = _contains_marker(
        text,
        (
            ".php",
            "x-powered-by': 'php",
            '"x-powered-by": "php',
            "x-powered-by: php",
            "phpsessid",
        ),
    )
    if not php_surface:
        return False
    auth_surface = _contains_marker(text, ("login", "signin", "sign-in", "username", "password"))
    registration_surface = _contains_marker(
        text,
        ("register", "signup", "sign-up", "create a new account"),
    )
    cookie_surface = _contains_marker(text, ("set-cookie", "phpsessid", "session cookie", "cookie"))
    return auth_surface and registration_surface and cookie_surface


def _has_client_xss_objective(state: AgentState) -> bool:
    description = str(state.surface.get("visible_description") or "").lower()
    if not description:
        return False
    return _contains_marker(description, ("xss", "cross-site scripting", "alert(", "browser-executed", "client-side"))


def _has_command_boundary_evidence(state: AgentState) -> bool:
    text = _state_text(state)
    if _contains_marker(text, COMMAND_BOUNDARY_SURFACE_MARKERS):
        return True
    return _contains_marker(text, ("url", "uri", "endpoint")) and _contains_marker(
        text,
        ("validate", "validator", "availability", "status", "health", "check"),
    )


def _has_authenticated_template_render_evidence(state: AgentState) -> bool:
    text = _state_text(state)
    if not _contains_marker(
        text,
        (
            "default_credentials_valid",
            "auth_session_followup_signal",
            "authenticated",
            "cookie",
            "set-cookie",
            "session=",
        ),
    ):
        return False
    upload_or_include = _contains_marker(
        text,
        (
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
            "path",
        ),
    )
    calculation_render = _contains_marker(
        text,
        (
            "amortization",
            "loan",
            "payment",
            "term",
            "calculator",
            "total_loan",
            "render_template",
            "server-side rendering",
            "expression",
            "preview",
            "message",
            "notify",
            "schedule",
            "remind",
            "reminder",
        ),
    )
    return upload_or_include or calculation_render


def _recent_facts_text(state: AgentState) -> str:
    return " ".join(state.facts[-30:])


def _recent_hypotheses_text(state: AgentState) -> str:
    return " ".join(state.hypotheses[-20:])


def _signal_text(state: AgentState) -> str:
    values: list[str] = []
    for signal_values in state.signals.values():
        for value in signal_values[-20:]:
            values.append(str(value))
    return " ".join(values)


def _recent_action_text(state: AgentState) -> str:
    values: list[str] = []
    for action in state.actions[-12:]:
        for value in action.values():
            if not value:
                continue
            values.append(str(value))
    return " ".join(values)


def _join_present(values: list[str]) -> str:
    present: list[str] = []
    for value in values:
        if value:
            present.append(value)
    return " ".join(present)


def _recent_probe_names(state: AgentState, *, limit: int) -> set[str]:
    names: set[str] = set()
    for action in state.actions[-limit:]:
        if action.get("action") != "run_probe":
            continue
        probe_name = str(action.get("probe") or "")
        if probe_name:
            names.add(probe_name)
    return names


def _stagnant_probe_penalty(state: AgentState, probe: str) -> int:
    penalty = 0
    for action in reversed(state.actions[-10:]):
        if action.get("action") != "run_probe" or str(action.get("probe") or "") != probe:
            continue
        outcome = str(action.get("outcome") or "")
        repeat_count = _int_value(action.get("repeat_count"))
        if outcome in {"same_as_before", "blocked"} or repeat_count > 2:
            penalty += 8 + max(0, repeat_count - 2) * 3
        elif outcome in {"observed", "interesting"}:
            break
    return min(penalty, 40)


def _trigger_score(text: str, triggers: tuple[str, ...]) -> int:
    score = 0
    for trigger in triggers:
        if trigger.lower() in text:
            score += 1
    return score


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _has_base64ish_cookie(state: AgentState) -> bool:
    for cookie in state.signals.get("cookies", []):
        text = str(cookie)
        if "=" not in text:
            continue
        value = text.split("=", 1)[1].split(";", 1)[0].strip()
        if len(value) >= 4 and any(char.isalpha() for char in value) and all(char.isalnum() or char in "_-+/=." for char in value):
            return True
    return False


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
