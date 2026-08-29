from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from ravage.web_core.http_probe import ProbeResponse, ProbeSession

if TYPE_CHECKING:
    from collections.abc import Callable

    from ravage.traffic.policy import TrafficPolicyController


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    summary: str
    steps: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    http_request_count: int = 0
    http_request_count_status: str = "exact"

    def to_text(self) -> str:
        return json.dumps(
            {
                "ok": self.ok,
                "summary": self.summary,
                "steps": self.steps,
                "errors": self.errors,
                "http_request_count": self.http_request_count,
                "http_request_count_status": self.http_request_count_status,
            },
            indent=2,
            sort_keys=True,
        )


def validate_http_poc(
    *,
    target_url: str,
    steps: object,
    timeout_seconds: int = 10,
    on_step: Callable[[dict[str, object]], None] | None = None,
    allow_remote_target: bool = False,
    in_scope: Sequence[str] | None = None,
    out_of_scope: Sequence[str] = (),
    max_rps: float | None = None,
    session: ProbeSession | None = None,
    request: Callable[..., ProbeResponse] | None = None,
    redact: Callable[[object], object] | None = None,
    traffic_policy: TrafficPolicyController | None = None,
    traffic_policy_reference: dict[str, object] | None = None,
) -> ValidationResult:
    if not isinstance(steps, list) or not steps:
        return ValidationResult(
            ok=False,
            summary="validate_poc requires a non-empty steps list",
            errors=["missing steps"],
        )
    if session is not None and request is not None:
        raise ValueError("validate_http_poc accepts either session or request, not both")
    if (session is not None or request is not None) and (
        traffic_policy is not None or traffic_policy_reference is not None
    ):
        raise ValueError("a supplied PoC transport already owns its traffic policy")
    if session is not None and _canonical_target(session.target_url) != _canonical_target(
        target_url
    ):
        raise ValueError("validate_http_poc session belongs to a different target")
    if session is None and request is None:
        session = ProbeSession(
            target_url,
            timeout_seconds=timeout_seconds,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            max_rps=max_rps,
            traffic_policy=traffic_policy,
            traffic_policy_reference=traffic_policy_reference,
        )
    request_count_before = int(getattr(session, "physical_request_count", 0))
    results: list[dict[str, object]] = []
    errors: list[str] = []
    required_checks = 0
    passed_checks = 0
    for index, raw_step in enumerate(steps[:12], start=1):
        if not isinstance(raw_step, dict):
            errors.append(f"step {index} is not an object")
            continue
        response = _execute_step(
            session,
            raw_step,
            target_url=target_url,
            request=request,
            timeout_seconds=timeout_seconds,
        )
        step_result = _evaluate_step(index=index, step=raw_step, response=response)
        safe_step_result = _redacted_mapping(step_result, redact=redact)
        _notify_step(
            on_step,
            index=index,
            step=raw_step,
            response=response,
            result=step_result,
            redact=redact,
        )
        results.append(safe_step_result)
        _extend_step_errors(errors, safe_step_result)
        required_checks += _int_value(step_result.get("required_checks"))
        passed_checks += _int_value(step_result.get("passed_checks"))
    ok = _validation_ok(
        results=results,
        errors=errors,
        required_checks=required_checks,
        passed_checks=passed_checks,
    )
    summary = _validation_summary(
        required_checks=required_checks,
        passed_checks=passed_checks,
    )
    return ValidationResult(
        ok=ok,
        summary=_redacted_text(summary, redact=redact),
        steps=results,
        errors=[_redacted_text(error, redact=redact) for error in errors],
        http_request_count=(
            max(0, int(getattr(session, "physical_request_count", 0)) - request_count_before)
            if session is not None
            else 0
        ),
        http_request_count_status="exact" if session is not None else "lower_bound",
    )


def _canonical_target(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit(
        (parsed.scheme.casefold(), parsed.netloc.casefold(), parsed.path or "/", parsed.query, "")
    )


def _notify_step(
    on_step: Callable[[dict[str, object]], None] | None,
    *,
    index: int,
    step: dict[str, Any],
    response: ProbeResponse,
    result: dict[str, object],
    redact: Callable[[object], object] | None,
) -> None:
    if on_step is None:
        return
    form = step.get("form")
    ok = result.get("passed")
    on_step(
        _redacted_mapping(
            {
                "index": index,
                "method": str(step.get("method") or "GET"),
                "url": str(step.get("url") or ""),
                "form": form if isinstance(form, dict) else None,
                "status": response.status,
                "ok": ok if isinstance(ok, bool) else None,
                "headers": dict(response.headers) if isinstance(response.headers, dict) else {},
                "body": response.body,
            },
            redact=redact,
        )
    )


def _execute_step(
    session: ProbeSession | None,
    step: dict[str, Any],
    *,
    target_url: str,
    request: Callable[..., ProbeResponse] | None,
    timeout_seconds: int,
) -> ProbeResponse:
    method = str(step.get("method") or "GET").upper()
    url = str(step.get("url") or target_url)
    headers = _string_dict(step.get("headers"))
    form = _string_dict(step.get("form"))
    if form:
        data = urlencode(form).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded", **headers}
        method = "POST"
    else:
        body = step.get("body")
        data = _request_body_bytes(body)
    if request is not None:
        return request(
            method,
            url,
            data=data,
            headers=headers,
            timeout_seconds=timeout_seconds,
        )
    if session is None:
        raise RuntimeError("validate_http_poc request lane is unavailable")
    return session.request(method, url, data=data, headers=headers)


def _redacted_mapping(
    value: dict[str, object],
    *,
    redact: Callable[[object], object] | None,
) -> dict[str, object]:
    if redact is None:
        return value
    safe = redact(value)
    if not isinstance(safe, dict):
        raise TypeError("validate_http_poc redactor must preserve mapping values")
    return {str(key): item for key, item in safe.items()}


def _redacted_text(
    value: str,
    *,
    redact: Callable[[object], object] | None,
) -> str:
    if redact is None:
        return value
    safe = redact(value)
    if not isinstance(safe, str):
        raise TypeError("validate_http_poc redactor must preserve text values")
    return safe


def _extend_step_errors(errors: list[str], step_result: dict[str, object]) -> None:
    raw_errors = step_result.get("errors")
    if not isinstance(raw_errors, list):
        return
    for error in raw_errors:
        if error:
            errors.append(str(error))


def _validation_ok(
    *,
    results: list[dict[str, object]],
    errors: list[str],
    required_checks: int,
    passed_checks: int,
) -> bool:
    if required_checks == 0:
        return _all_steps_have_no_errors(results)
    return required_checks == passed_checks and not errors


def _validation_summary(*, required_checks: int, passed_checks: int) -> str:
    if required_checks == 0:
        return "replayed HTTP sequence without explicit expectations"
    return f"replayed HTTP sequence; checks passed {passed_checks}/{required_checks}"


def _all_steps_have_no_errors(results: list[dict[str, object]]) -> bool:
    for result in results:
        if result.get("errors"):
            return False
    return True


def _request_body_bytes(body: object) -> bytes | None:
    if body is None:
        return None
    return str(body).encode("utf-8")


def _evaluate_step(
    *,
    index: int,
    step: dict[str, Any],
    response: ProbeResponse,
) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    errors: list[str] = []
    expected_status = step.get("expect_status")
    if expected_status is not None:
        expected_status_code = _int_or_none(expected_status)
        passed = response.status == expected_status_code
        checks.append({"kind": "status", "expected": expected_status_code, "passed": passed})
        if not passed:
            errors.append(f"step {index} expected status {expected_status}, got {response.status}")
    expected_contains = str(step.get("expect_contains") or "")
    if expected_contains:
        passed = expected_contains in response.body or expected_contains in json.dumps(
            response.headers
        )
        checks.append({"kind": "contains", "expected": expected_contains[:160], "passed": passed})
        if not passed:
            errors.append(f"step {index} expected response to contain {expected_contains[:80]!r}")
    return {
        "index": index,
        "request": {
            "method": str(step.get("method") or "GET").upper(),
            "url": str(step.get("url") or ""),
            "has_body": step.get("body") is not None or bool(step.get("form")),
        },
        "response": response.summary(body_chars=300),
        "checks": checks,
        "required_checks": len(checks),
        "passed_checks": _passed_check_count(checks),
        "errors": errors,
    }


def _passed_check_count(checks: list[dict[str, object]]) -> int:
    count = 0
    for check in checks:
        if check.get("passed"):
            count += 1
    return count


def _string_dict(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        result[str(key)] = str(item)
    return result


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
