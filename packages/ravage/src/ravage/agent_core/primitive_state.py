from __future__ import annotations

from dataclasses import dataclass, field

from ravage.agent_core.agent_state import AgentState

STALE_PRIMITIVE_TURNS = 2
EXHAUSTED_PROBE_LOOKBACK = 8


@dataclass(frozen=True)
class PrimitiveRule:
    name: str
    probe: str
    task_id: str
    directive: str
    markers: tuple[str, ...] = ()
    signal_keys: tuple[str, ...] = ()
    closure_probes: tuple[str, ...] = ()
    tier: int = 0
    blockers: tuple[str, ...] = field(default=())


PRIMITIVE_RULES: tuple[PrimitiveRule, ...] = (
    PrimitiveRule(
        name="apache_traversal_surface",
        probe="file_read_extract",
        task_id="file-fetch-parser",
        directive=(
            "An Apache 2.4.49/2.4.50 server banner indicates the public path traversal/RCE "
            "surface may be present. Run run_probe file_read_extract so the bounded Apache "
            "traversal templates can try file reads and CGI shell readback before unrelated "
            "form workflows."
        ),
        markers=(
            "apache_2_4_path_traversal_surface",
            "apache/2.4.49",
            "apache/2.4.50",
        ),
        tier=1,
    ),
    PrimitiveRule(
        name="file_read_confirmed",
        probe="file_read_extract",
        task_id="file-fetch-parser",
        directive=(
            "Local file read is confirmed. Run run_probe file_read_extract to read source, "
            "config, and flag files with the confirmed request template and close the proof. "
            "Do not go back to path guessing or surface recon."
        ),
        markers=(
            "file_read_primitive",
            "file_fetch_parser_signal",
            "file_read_extracted_content",
            "file_read_extracted_proof",
            "file_read_listed_file_proof",
            "file_read_listed_file_secret",
            "direct_exposure_listed_file_proof",
            "direct_exposure_listed_file_secret",
            "php_include_execution",
            "php_include_extracted_proof",
            "file_read_confirmed",
            "root:x:0:0",
            "local file read evidence observed",
        ),
        signal_keys=("file_read_inputs",),
    ),
    PrimitiveRule(
        name="xxe_confirmed",
        probe="xxe_boundary",
        task_id="file-fetch-parser",
        directive=(
            "XXE file-read behavior is confirmed. Run run_probe xxe_boundary to vary "
            "entity file targets and SVG/XML delivery on the same parser surface until "
            "a proof-bearing file is read. Do not restart generic file/path probing first."
        ),
        markers=("xxe_file_read_signal", "xxe_extracted_proof"),
    ),
    PrimitiveRule(
        name="xxe_surface_observed",
        probe="xxe_boundary",
        task_id="file-fetch-parser",
        directive=(
            "A SOAP/WSDL/XML processing surface is observed. Run run_probe xxe_boundary "
            "with any authenticated cookies/headers and operation-shaped XML payloads before "
            "drifting to unrelated authenticated-object or command probes."
        ),
        markers=("soap_service", "/soap", "/wsdl", "wsdl", "soap", "xml"),
        tier=1,
    ),
    PrimitiveRule(
        name="blind_sqli_confirmed",
        probe="sqli_exploit",
        task_id="data-query",
        directive=(
            "Blind SQL injection (boolean/timing) is confirmed. Run run_probe sqli_exploit and "
            "drive compact binary/character extraction, credential replay, and username/password "
            "auth-bypass closure. Do not keep hand-probing the boolean/timing oracle."
        ),
        markers=(
            "blind_sql_injection_boolean_signal",
            "blind_sql_injection_timing_signal",
        ),
        closure_probes=("sqli_differential",),
    ),
    PrimitiveRule(
        name="sqli_confirmed",
        probe="sqli_exploit",
        task_id="data-query",
        directive=(
            "SQL injection is confirmed. Run run_probe sqli_exploit to extract with the "
            "confirmed template (error/UNION/boolean), replay credentials, and try username-side "
            "as well as password-side auth bypass. Do not treat warnings or path leaks as closure, "
            "and do not drift back to static sweeps or recon while extraction is unfinished."
        ),
        markers=(
            "sql_injection_confirmed",
            "sql_injection_error_signal",
            "sql_error_leak_primitive",
            "sql_union_primitive",
            "sql_boolean_primitive",
            "sql_extracted_proof",
        ),
        signal_keys=("sqli_inputs",),
        closure_probes=("sqli_differential",),
    ),
    PrimitiveRule(
        name="command_exec_confirmed",
        probe="command_boundary",
        task_id="command-boundary",
        directive=(
            "Command injection with output is confirmed. Run run_probe command_boundary to read "
            "served files / flag paths through the command channel and close the proof."
        ),
        markers=("command_boundary_proof", "command_boundary_signal"),
    ),
    PrimitiveRule(
        name="command_blind_confirmed",
        probe="command_boundary",
        task_id="command-boundary",
        directive=(
            "Blind command injection (timing) is confirmed without an output channel. Run "
            "run_probe command_boundary and pivot to a proof: write to a served path then read "
            "it back, or convert the timing oracle into a file-read confirmation."
        ),
        markers=("command_boundary_timing_signal",),
    ),
    PrimitiveRule(
        name="ssrf_confirmed",
        probe="ssrf_boundary",
        task_id="file-fetch-parser",
        directive=(
            "SSRF/internal URL fetch behavior is confirmed. Run run_probe ssrf_boundary "
            "to reuse the URL-fetch template, vary loopback/internal bases and proof/admin/"
            "metadata paths, and close with a target response proof. Do not drift back to "
            "generic recon or unrelated file/path probing while the SSRF primitive is live."
        ),
        markers=(
            "ssrf_boundary_signal",
            "ssrf_internal_path_signal",
            "ssrf_extracted_secret",
            "ssrf_extracted_proof",
        ),
    ),
    PrimitiveRule(
        name="ssti_confirmed",
        probe="ssti_fingerprint",
        task_id="server-rendering",
        directive=(
            "Server-side template evaluation is confirmed. Run run_probe ssti_fingerprint, then "
            "drive the engine-specific file/env/command proof while preserving required params "
            "and session. Do not restart fingerprinting from scratch."
        ),
        markers=(
            "ssti_fingerprint_signal",
            "ssti_engine_execution",
            "ssti_extracted_proof",
            "ssti_stored_signal",
            "deferred_form_flow_signal",
        ),
    ),
    PrimitiveRule(
        name="client_xss_confirmed",
        probe="reflection_value_boundary",
        task_id="input-reflection",
        directive=(
            "Client-side script execution is confirmed but no proof was extracted. Run run_probe "
            "reflection_value_boundary (server-verified dialog sentinels), then run_probe "
            "dom_execution. After a timeout, vary the XSS payload family on the same sink; do not "
            "drift to unrelated SQLi/SSRF/exposure probes."
        ),
        markers=("client_side_execution",),
        blockers=("client_side_proof_extraction",),
    ),
    PrimitiveRule(
        name="werkzeug_console_unlocked",
        probe="werkzeug_console",
        task_id="flag-and-secret-sweep",
        directive=(
            "A Werkzeug debugger console is confirmed unlocked. Run run_probe werkzeug_console "
            "to eval Python through the debugger contract and read a proof."
        ),
        markers=("werkzeug_console_unlocked",),
    ),
    PrimitiveRule(
        name="werkzeug_console_exposed",
        probe="werkzeug_console",
        task_id="flag-and-secret-sweep",
        directive=(
            "A Werkzeug debugger console is exposed. Run run_probe werkzeug_console to extract the "
            "SECRET and eval Python when the console is unlocked (or compute the PIN from leaked "
            "machine bits). Do not keep inspecting the debugger JavaScript by hand."
        ),
        markers=("werkzeug_console_exposed",),
        blockers=("werkzeug_console_locked",),
        tier=1,
    ),
    PrimitiveRule(
        name="serialized_cookie_confirmed",
        probe="cookie_deserialization",
        task_id="file-fetch-parser",
        directive=(
            "A serialized session cookie was detected. Run run_probe cookie_deserialization to "
            "forge a response-returning pickle/YAML gadget (subprocess.check_output / "
            "os.popen().read()) into the cookie and read the proof back. Do not write os.system "
            "gadgets whose output only hits server stdout."
        ),
        markers=("insecure_deserialization_cookie_signal", "cookie_deserialization_marker"),
    ),
    PrimitiveRule(
        name="idor_confirmed",
        probe="idor_boundary",
        task_id="stateful-session",
        directive=(
            "An authorization/object-id boundary failure is confirmed. Run run_probe "
            "idor_boundary to enumerate the neighboring objects and read back the protected "
            "data that proves the access-control break."
        ),
        markers=(
            "idor_boundary_signal",
            "idor_boundary_followup_signal",
            "idor_boundary_followup_exposed_secret",
            "idor_boundary_exposed_secret",
            "idor_cookie_identity_signal",
            "idor_cookie_identity_exposed_secret",
            "idor_identity_header_exposed_secret",
            "vertical_idor_privilege_field",
        ),
    ),
    PrimitiveRule(
        name="default_credentials_confirmed",
        probe="stateful_session",
        task_id="stateful-session",
        directive=(
            "Default credentials are confirmed. Treat authentication as context, not as IDOR "
            "evidence: use stateful_session to map the authenticated workflow, then triage and "
            "mutate the forms and API operations it reveals. Run an "
            "authorization specialist only after an object or role boundary is actually observed."
        ),
        markers=("default_credentials_valid",),
        tier=1,
    ),
    PrimitiveRule(
        name="auth_workflow_confirmed",
        probe="stateful_session",
        task_id="stateful-session",
        directive=(
            "A multi-step auth/registration workflow is the strongest path. Run run_probe "
            "stateful_session to drive the wizard with privilege/premium escalation and read the "
            "completed-state proof. Do not drift to unrelated SQLi/SSRF/file probes while this is "
            "the live path."
        ),
        markers=(
            "auth_workflow_completed_signal",
            "auth_workflow_progress_signal",
            "privilege_escalation_signal",
        ),
    ),
    PrimitiveRule(
        name="csrf_session_boundary_confirmed",
        probe="csrf_session",
        task_id="stateful-session",
        directive=(
            "CSRF or session-management abuse is confirmed. Run run_probe csrf_session to "
            "reuse the state-changing request template, test token omission/reuse and logout "
            "invalidation, then sweep the resulting page/session for a proof. Do not merely "
            "preserve CSRF tokens for normal workflow replay."
        ),
        markers=(
            "csrf_omission_accepted",
            "csrf_omission_extracted_proof",
            "csrf_token_reuse_signal",
            "csrf_token_reuse_extracted_proof",
            "logout_invalidation_failed",
        ),
    ),
    PrimitiveRule(
        name="browser_boundary_confirmed",
        probe="browser_boundary",
        task_id="api-behavior",
        directive=(
            "A browser trust-boundary weakness is confirmed. Run run_probe browser_boundary "
            "to reuse Origin/preflight/WebSocket/storage evidence, capture any exposed proof, "
            "and avoid unrelated injection paths until this browser-boundary route is exhausted."
        ),
        markers=(
            "cors_misconfiguration_signal",
            "cors_extracted_proof",
            "websocket_cross_origin_handshake_signal",
            "browser_storage_secret_exposure",
        ),
    ),
    PrimitiveRule(
        name="cms_exposure_observed",
        probe="cms_exposure",
        task_id="flag-and-secret-sweep",
        directive=(
            "A CMS backup/plugin/version exposure is confirmed. Run run_probe cms_exposure "
            "to follow backup manifests, plugin metadata, logs, and archive artifacts to a "
            "proof-bearing file. Do not switch to generic direct_exposure until this queue is exhausted."
        ),
        markers=("cms_backup_artifact", "cms_plugin_version_signal"),
        tier=1,
    ),
    PrimitiveRule(
        name="direct_exposure_observed",
        probe="direct_exposure",
        task_id="flag-and-secret-sweep",
        directive=(
            "A same-origin direct exposure or listed-file disclosure is confirmed. Run "
            "run_probe direct_exposure to follow admin/debug/config/backup/source paths and "
            "listed sensitive files to a proof-bearing response. Do not switch to broad manual "
            "path guessing until this direct exposure queue is exhausted."
        ),
        markers=(
            "direct_exposure_proof",
            "direct_exposure_candidate",
            "direct_exposure_listed_file_proof",
            "direct_exposure_listed_file_secret",
        ),
        tier=1,
    ),
    PrimitiveRule(
        name="jwt_observed",
        probe="jwt_exploit",
        task_id="api-behavior",
        directive=(
            "A JWT and its claims were observed. Run run_probe jwt_exploit to forge tampered "
            "tokens (alg:none, weak-secret crack-and-resign, RS256->HS256 key confusion), escalate "
            "identity/role claims, and replay into protected endpoints. Do not just re-decode it."
        ),
        markers=("jwt_observed", "jwt_secret_cracked", "jwt_forgery_signal"),
        tier=1,
    ),
    PrimitiveRule(
        name="graphql_schema_available",
        probe="graphql_exploit",
        task_id="api-behavior",
        directive=(
            "A GraphQL schema/introspection surface is available. Run run_probe graphql_exploit to "
            "generate sensitive-field queries from the schema, alias-batch object-id traversal, and "
            "enumerate mutations. Do not just re-introspect with api_behavior."
        ),
        markers=("graphql_schema_signal", "graphql_exposed_proof", "graphql_schema_mapped"),
        tier=1,
    ),
)

_RULES_BY_NAME = {rule.name: rule for rule in PRIMITIVE_RULES}


def primitive_rule(name: str) -> PrimitiveRule | None:
    return _RULES_BY_NAME.get(name)


def _evidence_text(state: AgentState) -> str:
    parts: list[str] = []
    for values in state.signals.values():
        parts.extend(str(value) for value in values[-20:])
    parts.extend(state.facts[-30:])
    parts.extend(state.hypotheses[-20:])
    parts.append(str(state.surface))
    return " ".join(parts).lower()


def _rule_confirmed(rule: PrimitiveRule, state: AgentState, text: str) -> bool:
    for blocker in rule.blockers:
        if blocker in text:
            return False
    for key in rule.signal_keys:
        if state.signals.get(key):
            return True
    return any(marker.lower() in text for marker in rule.markers)


def derive_primitives(state: AgentState) -> list[str]:
    text = _evidence_text(state)
    return [rule.name for rule in PRIMITIVE_RULES if _rule_confirmed(rule, state, text)]


def promote_primitives(state: AgentState) -> list[str]:
    newly: list[str] = []
    for name in derive_primitives(state):
        if name not in state.primitives:
            state.primitives[name] = state.turn
            newly.append(name)
    return newly


def _live_primitive_names(state: AgentState) -> list[str]:
    if state.flags and state.surface.get("continue_after_proof") is not True:
        return []
    text = _evidence_text(state)
    names: list[str] = []
    for rule in PRIMITIVE_RULES:
        if rule.name not in state.primitives:
            continue
        # A primitive whose blocker now holds (e.g. proof extracted) is no longer
        # a live lock target even though it was confirmed earlier.
        if any(blocker in text for blocker in rule.blockers):
            continue
        # In a multi-proof run, a proof closes only the primitive whose typed
        # specialist produced it.  A proof from an unrelated branch must not
        # release every other confirmed exploit primitive.
        if _primitive_branch_has_proof(state, rule):
            continue
        names.append(rule.name)
    return names


def _primitive_branch_has_proof(state: AgentState, rule: PrimitiveRule) -> bool:
    promoted_turn = state.primitives.get(rule.name, state.turn)
    accepted_probes = {rule.probe, *rule.closure_probes}
    for index, attempt in enumerate(state.attempts):
        if _attempt_added_branch_proof(
            attempt,
            preceding_attempts=state.attempts[:index],
            promoted_turn=promoted_turn,
            accepted_probes=accepted_probes,
        ):
            return True
    return False


def _attempt_added_branch_proof(
    attempt: dict[str, object],
    *,
    preceding_attempts: list[dict[str, object]],
    promoted_turn: int,
    accepted_probes: set[str],
) -> bool:
    selected = attempt.get("selected_action")
    delta = attempt.get("state_delta")
    if not isinstance(selected, dict) or not isinstance(delta, dict):
        return False
    attempt_turn = _int_value(attempt.get("turn"))
    if attempt_turn < promoted_turn or _int_value(delta.get("flags_delta")) <= 0:
        return False
    if selected.get("action") == "run_probe":
        return str(selected.get("probe") or "") in accepted_probes
    if selected.get("action") != "capture_flag":
        return False
    preceding_probe = _nearest_evidence_producing_probe(
        preceding_attempts,
        promoted_turn=promoted_turn,
        capture_turn=attempt_turn,
    )
    return preceding_probe in accepted_probes


def _nearest_evidence_producing_probe(
    attempts: list[dict[str, object]],
    *,
    promoted_turn: int,
    capture_turn: int,
) -> str:
    for attempt in reversed(attempts):
        turn = _int_value(attempt.get("turn"))
        if turn < promoted_turn:
            break
        if turn >= capture_turn:
            continue
        selected = attempt.get("selected_action")
        outcome = attempt.get("outcome")
        if not isinstance(selected, dict) or not isinstance(outcome, dict):
            continue
        kind = str(selected.get("action") or "")
        if kind not in {"run_command", "run_python", "run_probe", "validate_poc"}:
            continue
        if outcome.get("ok") is not True:
            continue
        classification = str(outcome.get("classification") or "")
        if classification in {"blocked", "same_as_before"}:
            continue
        if kind != "run_probe":
            return ""
        return str(selected.get("probe") or "")
    return ""


def locked_primitive(state: AgentState) -> str | None:
    """Highest-priority confirmed, directly exploitable (tier 0) primitive."""
    for name in _live_primitive_names(state):
        rule = _RULES_BY_NAME[name]
        if rule.tier == 0:
            return name
    return None


def locked_probe(state: AgentState) -> str | None:
    name = locked_primitive(state)
    rule = _RULES_BY_NAME.get(name) if name else None
    return rule.probe if rule else None


def probe_recently_exhausted(state: AgentState, probe: str) -> bool:
    if not probe:
        return False
    for action in reversed(state.actions[-EXHAUSTED_PROBE_LOOKBACK:]):
        if action.get("action") != "run_probe" or str(action.get("probe") or "") != probe:
            continue
        outcome = str(action.get("outcome") or "")
        repeat_count = _int_value(action.get("repeat_count"))
        if outcome in {
            "confirmed_signal",
            "finding_confirmed",
            "new_surface",
            "flag_candidate",
        } or _action_attempt_advanced_evidence(state, action):
            return False
        if outcome in {"same_as_before", "blocked"} or repeat_count >= 3:
            return True
    return False


def _action_attempt_advanced_evidence(
    state: AgentState,
    action: dict[str, object],
) -> bool:
    action_turn = _int_value(action.get("turn"))
    for attempt in reversed(state.attempts):
        if _int_value(attempt.get("turn")) != action_turn:
            continue
        selected = attempt.get("selected_action")
        if not isinstance(selected, dict):
            continue
        if selected.get("action") != "run_probe" or str(selected.get("probe") or "") != str(
            action.get("probe") or ""
        ):
            continue
        before = str(attempt.get("evidence_epoch_before") or "")
        after = str(attempt.get("evidence_epoch_after") or "")
        if before and after and before != after:
            return True
        delta = attempt.get("state_delta")
        if isinstance(delta, dict) and delta.get("new_primitives"):
            return True
        attempt_outcome = attempt.get("outcome")
        if isinstance(attempt_outcome, dict) and str(
            attempt_outcome.get("classification") or ""
        ) in {
            "confirmed_signal",
            "finding_confirmed",
            "new_surface",
            "flag_candidate",
        }:
            return True
        return False
    return False


def routed_probes(state: AgentState) -> dict[str, int]:
    boosts: dict[str, int] = {}
    locked = locked_probe(state)
    for name in _live_primitive_names(state):
        rule = _RULES_BY_NAME[name]
        exhausted = probe_recently_exhausted(state, rule.probe)
        if exhausted:
            boost = 20
        else:
            boost = 100 if rule.probe == locked else (40 if rule.tier == 1 else 80)
        boosts[rule.probe] = max(boosts.get(rule.probe, 0), boost)
    return boosts


def primitive_directives(state: AgentState) -> list[str]:
    names = _live_primitive_names(state)
    if not names:
        return []
    directives: list[str] = []
    locked = locked_primitive(state)
    head = locked or names[0]
    rule = _RULES_BY_NAME[head]
    exhausted = probe_recently_exhausted(state, rule.probe)
    if exhausted:
        directives.append(
            f"PRIMITIVE CONFIRMED: {head}. The default closer run_probe {rule.probe} was just exhausted "
            "or blocked as a repeat. Do not rerun it unchanged; use the confirmed replay/template with a "
            "materially different closure method, a more specific specialist, or the next confirmed primitive."
        )
    else:
        directives.append(f"PRIMITIVE CONFIRMED: {head}. {rule.directive}")
    age = state.turn - state.primitives.get(head, state.turn)
    if rule.tier == 0 and age >= STALE_PRIMITIVE_TURNS and not exhausted:
        directives.append(
            f"BUDGET: {head} was confirmed {age} turns ago without a captured proof. Stop "
            f"surface/recon and unrelated-vulnerability probes; run run_probe {rule.probe} now "
            "and close signal -> exploit -> proof."
        )
    other = [name for name in names if name != head]
    if other:
        directives.append("Other confirmed primitives queued behind it: " + ", ".join(other) + ".")
    return directives


def _int_value(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return 0
