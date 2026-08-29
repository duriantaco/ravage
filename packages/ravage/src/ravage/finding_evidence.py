from __future__ import annotations

from typing import TYPE_CHECKING

from ravage.web_core.scope_policy import url_in_scope

if TYPE_CHECKING:
    from pentest_schemas import Scope


def confirmed_finding_evidence_failures(
    payload: dict[str, object],
    *,
    scope: Scope | None = None,
) -> tuple[str, ...]:
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        return ("missing proof",)
    failures = [
        f"missing proof.{key}"
        for key in ("http_request_final", "response_final", "impact_description")
        if not _has_evidence_value(proof.get(key))
    ]
    exploit_steps = payload.get("exploit_steps")
    if not isinstance(exploit_steps, list) or not exploit_steps:
        failures.append("missing exploit_steps")
    if scope is not None and not _endpoint_in_scope(payload, scope):
        failures.append("endpoint.url is outside engagement scope")
    return tuple(failures)


def _has_evidence_value(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return any(_has_evidence_value(value.get(key)) for key in ("snippet", "artifact_path"))
    return bool(value)


def _endpoint_in_scope(payload: dict[str, object], scope: Scope) -> bool:
    endpoint = payload.get("endpoint")
    if not isinstance(endpoint, dict):
        return False
    url = str(endpoint.get("url") or "")
    if not url:
        return False
    return url_in_scope(url, scope=scope)
