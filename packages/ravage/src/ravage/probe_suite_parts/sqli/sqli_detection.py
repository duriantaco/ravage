from __future__ import annotations

from ravage.web_core.http_probe import ProbeResponse
from ravage.probe_suite_parts.sqli.sqli_targets import _sqli_target_brief
from ravage.probe_suite_parts.support import _contains_word, _has_new_result_marker, _response_result_markers
from ravage.web_core.proof_recognizer import recognize_proofs

def _looks_filtered_response(body: str) -> bool:
    lowered = body.lower()
    return _contains_word(
        lowered,
        (
            "filtered",
            "blocked",
            "blacklist",
            "forbidden keyword",
            "not allowed",
            "waf",
            "invalid character",
        ),
    )

def _query_result_expanded(response: ProbeResponse, *, baseline: ProbeResponse, admin: ProbeResponse) -> bool:
    if response.status is None:
        return False
    lowered = response.body.lower()
    if _looks_filtered_response(response.body):
        return False
    if _contains_word(lowered, ("flag{", "password", "secret", "token", "admin panel")):
        return True
    if "user exists" in lowered and "user exists" not in baseline.body.lower():
        return True
    if len(response.body) > max(len(baseline.body), len(admin.body)) + 25:
        return True
    return _has_new_result_marker(response.body, baseline.body)

def recognize_probe_like_proof(body: str) -> bool:
    return bool(recognize_proofs(body))

def _sql_error_markers(body: str) -> list[str]:
    lowered = body.lower()
    markers = []
    for marker in (
        "sql syntax",
        "sqlite",
        "mysql",
        "mysqli",
        "postgres",
        "pdoexception",
        "odbc",
        "unclosed quotation",
        "unterminated quoted",
        "syntax error",
        "warning:",
        # extractvalue/updatexml error-based channel and common cross-engine
        # signatures (Oracle, PDO/SQLSTATE, Postgres, MSSQL).
        "xpath syntax error",
        "you have an error in your sql",
        "sqlstate",
        "ora-",
        "psqlexception",
        "quoted string not properly terminated",
        "conversion failed",
    ):
        if marker in lowered:
            markers.append(marker)
    return markers

def _boolean_sql_signal(
    true_response: ProbeResponse,
    false_response: ProbeResponse,
    baseline: ProbeResponse,
    *,
    true_payload: str,
    false_payload: str,
) -> bool:
    if true_response.status is None or false_response.status is None:
        return False
    if _sql_error_markers(true_response.body) or _sql_error_markers(false_response.body):
        return False
    if _same_response_template_after_reflection(
        true_response.body,
        false_response.body,
        response_payload=true_payload,
        baseline_payload=false_payload,
    ):
        return False
    length_delta = abs(len(true_response.body) - len(false_response.body))
    status_delta = true_response.status != false_response.status
    true_changed = len(true_response.body) != len(baseline.body) or true_response.status != baseline.status
    false_changed = len(false_response.body) != len(baseline.body) or false_response.status != baseline.status
    true_markers = set(_response_result_markers(true_response.body))
    false_markers = set(_response_result_markers(false_response.body))
    phrase_delta = bool(true_markers ^ false_markers)
    return status_delta or length_delta >= 25 or (phrase_delta and (true_changed or false_changed))

def _same_response_template_after_reflection(
    response_body: str,
    baseline_body: str,
    *,
    response_payload: str,
    baseline_payload: str,
) -> bool:
    if not response_payload or response_payload not in response_body:
        return False
    if baseline_payload and baseline_payload not in baseline_body:
        return False
    response_normalized = _normalize_reflected_value(response_body, response_payload)
    baseline_normalized = _normalize_reflected_value(baseline_body, baseline_payload)
    return response_normalized == baseline_normalized

def _normalize_reflected_value(body: str, value: str) -> str:
    if not value:
        return body
    normalized = body
    for variant in _reflected_value_variants(value):
        normalized = normalized.replace(variant, "__RAVAGE_REFLECTED_VALUE__")
    return normalized

def _reflected_value_variants(value: str) -> tuple[str, ...]:
    return (
        value,
        value.replace("'", "&#x27;"),
        value.replace("'", "&#39;"),
        value.replace('"', "&quot;"),
        value.replace("<", "&lt;").replace(">", "&gt;"),
    )

def _sqli_probe_summary(
    response: ProbeResponse,
    target: dict[str, object],
    *,
    probe_kind: str,
    body_chars: int,
    payload: str | None = None,
) -> dict[str, object]:
    summary = response.summary(body_chars=body_chars)
    summary["target"] = _sqli_target_brief(target)
    summary["probe_kind"] = probe_kind
    if payload is not None:
        summary["payload"] = payload
    return summary

def _new_sql_error_markers(markers: list[str], baseline_body: str) -> list[str]:
    baseline_markers = set(_sql_error_markers(baseline_body))
    new_markers: list[str] = []
    for marker in markers:
        if marker not in baseline_markers:
            new_markers.append(marker)
    return new_markers
