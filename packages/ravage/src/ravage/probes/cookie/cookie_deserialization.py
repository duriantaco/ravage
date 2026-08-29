from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probes.cookie.cookie_deserialization_body import _probe_body_deserialization_inputs
from ravage.probes.cookie.cookie_deserialization_cookie import _exploit_cookie
from ravage.probes.cookie.cookie_deserialization_discovery import _candidate_cookies
from ravage.probes.cookie.cookie_deserialization_format import CookieFormat, classify_cookie_value
from ravage.probes.cookie.cookie_deserialization_php import _tamper_php_cookie
from ravage.web_core.http_probe import ProbeSession

_COOKIE_BUDGET = 60


def probe_cookie_deserialization(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _COOKIE_BUDGET

    candidates = _candidate_cookies(session, state, requests)
    serialized = _serialized_cookie_candidates(candidates, findings)
    cookie_jar = dict(candidates)

    for name, value, fmt in serialized:
        if budget <= 0:
            break
        if not fmt.exploitable:
            continue
        if fmt.kind == "php":
            budget = _tamper_php_cookie(
                session,
                name=name,
                value=value,
                fmt=fmt,
                cookie_jar=cookie_jar,
                findings=findings,
                requests=requests,
                budget=budget,
            )
        else:
            budget = _exploit_cookie(
                session,
                name=name,
                fmt=fmt,
                cookie_jar=cookie_jar,
                findings=findings,
                requests=requests,
                budget=budget,
            )
        if _has_finding(findings, "cookie_deserialization_extracted_proof"):
            break

    if budget > 0 and not _has_finding(findings, "body_deserialization_extracted_proof"):
        budget = _probe_body_deserialization_inputs(
            session,
            state,
            findings=findings,
            requests=requests,
            budget=budget,
        )

    return ProbeRunResult(
        ok=bool(findings),
        probe="cookie_deserialization",
        summary=(
            f"cookies inspected={len(candidates)}, serialized={len(serialized)}, "
            f"findings={len(findings)}, requests={len(requests)}"
        ),
        findings=findings[:40],
        requests=requests[:60],
    )


def _serialized_cookie_candidates(
    candidates: list[tuple[str, str]],
    findings: list[dict[str, object]],
) -> list[tuple[str, str, CookieFormat]]:
    serialized: list[tuple[str, str, CookieFormat]] = []
    for name, value in candidates:
        fmt = classify_cookie_value(value)
        if fmt.kind == "none":
            continue
        serialized.append((name, value, fmt))
        findings.append(_serialized_cookie_signal(name, fmt))
    return serialized


def _serialized_cookie_signal(name: str, fmt: CookieFormat) -> dict[str, object]:
    return {
        "type": "insecure_deserialization_cookie_signal",
        "cookie": name,
        "format": fmt.kind,
        "signed": fmt.signed,
        "encoding": fmt.encoding,
        "next": (
            "Forge a response-returning gadget into this cookie and replay it; "
            "signed (Flask/JWT) cookies need the secret first."
        ),
    }


def _has_finding(findings: list[dict[str, object]], finding_type: str) -> bool:
    for finding in findings:
        if finding.get("type") == finding_type:
            return True
    return False
