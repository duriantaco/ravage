from __future__ import annotations

import json
import secrets

from ravage.agent_core.agent_state import AgentState
from ravage.probes.cookie.cookie_deserialization_payloads import (
    _READBACK_FETCH,
    _body_deserialization_payloads,
)
from ravage.probes.cookie.cookie_deserialization_shared import _request_summary
from ravage.probes.cookie.cookie_deserialization_targets import (
    _body_deserialization_target_brief,
    _body_deserialization_targets,
    _form_auth_headers,
)
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    form_defaults,
    inject_query_param,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_BODY_DESER_TARGET_LIMIT = 8

_BODY_DESER_PAYLOAD_LIMIT = 10


def _probe_body_deserialization_inputs(
    session: ProbeSession,
    state: AgentState,
    *,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    budget: int,
) -> int:
    token = "RAVAGE_DESER_" + secrets.token_hex(6)
    targets = _body_deserialization_targets(session, state)
    payloads = _body_deserialization_payloads(token)
    for target in targets[:_BODY_DESER_TARGET_LIMIT]:
        if budget <= 0:
            break
        for payload in payloads[:_BODY_DESER_PAYLOAD_LIMIT]:
            if budget <= 0:
                break
            budget -= 1
            response = _submit_body_deserialization_payload(session, target, str(payload["value"]))
            requests.append(
                response.summary(body_chars=260)
                | {
                    "probe_kind": "body_deserialization_payload",
                    "target": _body_deserialization_target_brief(target),
                    "gadget": payload["kind"],
                    "encoding": payload["encoding"],
                }
            )
            if _record_body_proof(
                response.body,
                findings,
                target=target,
                gadget=str(payload["kind"]),
                encoding=str(payload["encoding"]),
                channel="response",
            ):
                return budget
            _record_body_marker_if_seen(
                response.body,
                findings,
                token=token,
                target=target,
                gadget=str(payload["kind"]),
                encoding=str(payload["encoding"]),
            )
            if payload.get("readback"):
                budget = _readback_body_deserialization(
                    session,
                    token=token,
                    findings=findings,
                    requests=requests,
                    target=target,
                    gadget=str(payload["kind"]),
                    encoding=str(payload["encoding"]),
                    budget=budget,
                )
                if _has_body_deserialization_proof(findings):
                    return budget
    return budget


def _submit_body_deserialization_payload(
    session: ProbeSession, target: dict[str, object], value: str
) -> ProbeResponse:
    kind = str(target.get("kind") or "query_param")
    url = str(target.get("url") or session.target_url)
    input_name = str(target.get("input") or "payload")
    raw_form = target.get("form")
    if kind == "form" and isinstance(raw_form, dict):
        form = dict(raw_form)
        fields = form_defaults(form, marker_name=input_name, marker=value)
        headers = _form_auth_headers(form)
        method = str(form.get("method") or "GET").upper()
        if method == "POST":
            return session.post_form(url, fields, headers=headers or None)
        query_url = url
        for name, raw in fields.items():
            query_url = inject_query_param(query_url, name, raw)
        return session.get(query_url, headers=headers or None)
    if kind == "json_post":
        body = json.dumps({input_name: value}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        return session.request("POST", url, data=body, headers=headers)
    return session.get(inject_query_param(url, input_name, value))


def _readback_body_deserialization(
    session: ProbeSession,
    *,
    token: str,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    target: dict[str, object],
    gadget: str,
    encoding: str,
    budget: int,
) -> int:
    for template in _READBACK_FETCH:
        if budget <= 0:
            break
        budget -= 1
        url = template.format(name=token)
        response = session.get(url)
        requests.append(
            _request_summary(response, url=url, cookie="", gadget="body_readback")
            | {"target": _body_deserialization_target_brief(target)}
        )
        if _record_body_proof(
            response.body,
            findings,
            target=target,
            gadget=gadget,
            encoding=encoding,
            channel="readback",
        ):
            break
    return budget


def _record_body_proof(
    body: str,
    findings: list[dict[str, object]],
    *,
    target: dict[str, object],
    gadget: str,
    encoding: str,
    channel: str,
) -> bool:
    proofs = recognize_proofs(body)
    if not proofs:
        return False
    findings.append(
        {
            "type": "body_deserialization_extracted_proof",
            "target": _body_deserialization_target_brief(target),
            "gadget": gadget,
            "encoding": encoding,
            "channel": channel,
            "proofs": proofs,
            "proof": proofs[0],
        }
    )
    return True


def _record_body_marker_if_seen(
    body: str,
    findings: list[dict[str, object]],
    *,
    token: str,
    target: dict[str, object],
    gadget: str,
    encoding: str,
) -> None:
    if token not in body:
        return
    if _has_body_deserialization_marker(findings):
        return
    findings.append(
        {
            "type": "body_deserialization_marker",
            "target": _body_deserialization_target_brief(target),
            "gadget": gadget,
            "encoding": encoding,
            "detail": (
                "gadget marker reflected: body/parameter deserialization confirmed "
                "without a flag yet"
            ),
        }
    )


def _has_body_deserialization_marker(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "body_deserialization_marker":
            return True
    return False


def _has_body_deserialization_proof(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "body_deserialization_extracted_proof":
            return True
    return False
