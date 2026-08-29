from __future__ import annotations

import json
import re
from typing import Any
from uuid import uuid4

_BENCHMARK_FLAG_RE = re.compile(r"flag\{[^{}\s]{1,240}\}", flags=re.IGNORECASE)
_DRIVER_EVENT_PREFIX = "RAVAGE_DRIVER_EVENT "


def build_candidate_proof_bundle(
    observation: object,
    *,
    target_origin: str,
    scope: object,
) -> dict[str, object] | None:
    if not isinstance(observation, dict):
        return None

    structured = _structured_driver_bundle(
        observation,
        target_origin=target_origin,
        scope=scope,
    )
    if structured is not None:
        return _sanitize_bundle(structured)

    if _list_of_dicts(observation.get("provenance_steps")):
        return _sanitize_bundle(
            _workflow_bundle(observation, target_origin=target_origin, scope=scope)
        )

    vuln_class = _vuln_class(observation)
    if not vuln_class:
        return None

    if _is_free_roam_observation(observation):
        return _sanitize_bundle(
            _free_roam_bundle(
                observation,
                vuln_class=vuln_class,
                target_origin=target_origin,
                scope=scope,
            )
        )

    return _sanitize_bundle(
        _two_step_bundle(
            observation,
            vuln_class=vuln_class,
            target_origin=target_origin,
            scope=scope,
        )
    )


def _structured_driver_bundle(
    observation: dict[str, object],
    *,
    target_origin: str,
    scope: object,
) -> dict[str, object] | None:
    for event in _structured_driver_events(observation):
        if event.get("kind") != "proof_candidate":
            continue
        bundle = dict(event)
        bundle.pop("kind", None)
        bundle.setdefault("schema_version", "ravage.proof_bundle.v1")
        bundle.setdefault("bundle_id", _bundle_id())
        bundle.setdefault("target_origin", target_origin)
        bundle.setdefault("scope", _scope_json(scope))
        bundle.setdefault("verifier", _inconclusive_verifier())
        return bundle
    return None


def _structured_driver_events(observation: dict[str, object]) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    controller_verdict = _dict_value(observation.get("controller_verdict"))
    events.extend(_list_of_dicts(controller_verdict.get("driver_events")))

    stdout = str(observation.get("stdout") or "")
    for line in stdout.splitlines():
        if not line.startswith(_DRIVER_EVENT_PREFIX):
            continue
        raw = line.removeprefix(_DRIVER_EVENT_PREFIX).strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            events.append(dict(data))
    return events


def _workflow_bundle(
    observation: dict[str, object],
    *,
    target_origin: str,
    scope: object,
) -> dict[str, object]:
    vuln_class = _vuln_class(observation) or "unknown"
    steps = [_baseline_step(observation)]
    for item in _list_of_dicts(observation.get("provenance_steps")):
        steps.append(_step_from_provenance_item(item, target_origin))

    source_step = _step_id(steps, "stored-submit", fallback_index=1)
    observed_step = _step_id(steps, "stored-render", fallback_index=len(steps) - 1)
    source_value = _first_text(observation, "source_token", "matched_payload")
    observed_value = _first_text(observation, "observed_value")

    return _base_bundle(
        title="Stored workflow proof",
        hypothesis="A submitted value is rendered by a later workflow step.",
        vuln_class=vuln_class,
        target_origin=target_origin,
        scope=scope,
        steps=steps,
        provenance=[
            {
                "source_step_id": source_step,
                "source_value": source_value or _source_value(observation, vuln_class),
                "observed_step_id": observed_step,
                "observed_value": observed_value or _observed_value(observation, vuln_class),
                "relation": "submitted workflow input caused the later observed output",
            }
        ],
        controls=[
            {
                "control_id": "baseline-control",
                "kind": "baseline",
                "step_ids": [_step_id(steps, "baseline"), observed_step],
                "expected_result": "The baseline workflow should not show the mutated value.",
                "observed_result": _first_text(observation, "baseline_response_snippet")
                or "baseline did not include the observed value",
                "passed": True,
            }
        ],
        replay={
            "summary": "Replay the baseline, submit the workflow mutation, then read the later render step.",
            "steps": [_step_replay(step) for step in steps],
            "required_state": ["same session and workflow state"],
        },
    )


def _two_step_bundle(
    observation: dict[str, object],
    *,
    vuln_class: str,
    target_origin: str,
    scope: object,
) -> dict[str, object]:
    baseline = _baseline_step(observation)
    mutation = _mutation_step(observation, vuln_class)
    source_value = _source_value(observation, vuln_class)
    observed_value = _observed_value(observation, vuln_class)

    return _base_bundle(
        title=_title(vuln_class),
        hypothesis=_hypothesis(vuln_class),
        vuln_class=vuln_class,
        target_origin=target_origin,
        scope=scope,
        steps=[baseline, mutation],
        provenance=[
            {
                "source_step_id": mutation["step_id"],
                "source_value": source_value,
                "observed_step_id": mutation["step_id"],
                "observed_value": observed_value,
                "relation": _relation(vuln_class),
            }
        ],
        controls=[
            {
                "control_id": "baseline-control",
                "kind": "authorization_boundary"
                if vuln_class == "idor"
                else "baseline",
                "step_ids": [baseline["step_id"], mutation["step_id"]],
                "expected_result": "The baseline request should not contain the proof observation.",
                "observed_result": _first_text(observation, "baseline_response_snippet")
                or "baseline response differed from the mutated response",
                "passed": True,
            }
        ],
        replay={
            "summary": "Replay the baseline request, then replay the mutated proof request.",
            "steps": [_step_replay(baseline), _step_replay(mutation)],
            "required_state": ["same target scope", "same session when authentication is required"],
        },
    )


def _free_roam_bundle(
    observation: dict[str, object],
    *,
    vuln_class: str,
    target_origin: str,
    scope: object,
) -> dict[str, object]:
    proof_request = _first_text(observation, "proof_request") or "run proof candidate"
    proof_text = _combined_proof_text(observation)
    source_value = _source_value(observation, vuln_class)
    observed_value = _observed_value(observation, vuln_class)

    mutation = {
        "step_id": "candidate-mutation",
        "kind": "mutation",
        "description": "Run the candidate exploit or driver action.",
        "actor": "attacker",
        "http": {
            "method": _method_from_request(proof_request),
            "url": target_origin,
            "request": proof_request,
            "response_status": _status(observation.get("status_code")),
            "response_snippet": proof_text or "candidate action completed",
        },
        "observation": "The candidate action exercised the suspected vulnerable boundary.",
    }
    observed = {
        "step_id": "candidate-observation",
        "kind": "observation",
        "description": "Observe the candidate proof output.",
        "actor": "attacker",
        "http": {
            "method": "GET",
            "url": target_origin,
            "request": "observe candidate proof output",
            "response_status": _status(observation.get("status_code")),
            "response_snippet": proof_text or "candidate proof output observed",
        },
        "observation": proof_text or "The candidate output changed after the mutation.",
    }

    return _base_bundle(
        title=_title(vuln_class),
        hypothesis=_hypothesis(vuln_class),
        vuln_class=vuln_class,
        target_origin=target_origin,
        scope=scope,
        steps=[mutation, observed],
        provenance=[
            {
                "source_step_id": "candidate-mutation",
                "source_value": source_value,
                "observed_step_id": "candidate-observation",
                "observed_value": observed_value,
                "relation": _relation(vuln_class),
            }
        ],
        controls=[
            {
                "control_id": "candidate-control",
                "kind": "baseline",
                "step_ids": ["candidate-mutation", "candidate-observation"],
                "expected_result": "The proof observation should be tied to the candidate action.",
                "observed_result": observed_value,
                "passed": True,
            }
        ],
        replay={
            "summary": "Replay the candidate action and inspect the observed proof output.",
            "steps": [proof_request, "Inspect the response or driver output for the observed value."],
            "required_state": ["same target scope"],
        },
    )


def _base_bundle(
    *,
    title: str,
    hypothesis: str,
    vuln_class: str,
    target_origin: str,
    scope: object,
    steps: list[dict[str, Any]],
    provenance: list[dict[str, object]],
    controls: list[dict[str, object]],
    replay: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "ravage.proof_bundle.v1",
        "bundle_id": _bundle_id(),
        "title": title,
        "hypothesis": hypothesis,
        "scope": _scope_json(scope),
        "target_origin": target_origin,
        "vuln_class": vuln_class,
        "steps": steps,
        "provenance": provenance,
        "controls": controls,
        "replay": replay,
        "verifier": _inconclusive_verifier(),
    }


def _baseline_step(observation: dict[str, object]) -> dict[str, object]:
    return {
        "step_id": "baseline",
        "kind": "baseline",
        "description": "Send the baseline request for comparison.",
        "actor": "attacker",
        "http": {
            "method": _method(observation),
            "url": _first_text(observation, "baseline_url", "endpoint", "url"),
            "request": _first_text(observation, "baseline_request") or "baseline request",
            "response_status": _status(observation.get("baseline_status_code")),
            "response_snippet": _first_text(observation, "baseline_response_snippet")
            or "baseline response",
        },
        "observation": "The baseline response did not contain the proof observation.",
    }


def _mutation_step(observation: dict[str, object], vuln_class: str) -> dict[str, object]:
    return {
        "step_id": _mutation_step_id(vuln_class),
        "kind": "mutation",
        "description": _mutation_description(vuln_class),
        "actor": "attacker",
        "http": {
            "method": _method(observation),
            "url": _first_text(observation, "url", "endpoint"),
            "request": _first_text(observation, "proof_request") or "mutated proof request",
            "response_status": _status(observation.get("status_code")),
            "response_snippet": _first_text(observation, "proof_response_snippet")
            or "proof response",
        },
        "observation": _first_text(observation, "indicator") or _mutation_step_id(vuln_class),
    }


def _step_from_provenance_item(item: dict[str, object], target_origin: str) -> dict[str, object]:
    return {
        "step_id": str(item.get("step_id") or "workflow-step"),
        "kind": _proof_step_kind(item.get("kind")),
        "description": str(item.get("description") or "Replay a workflow proof step."),
        "actor": "attacker",
        "http": {
            "method": _http_method(item.get("method")),
            "url": str(item.get("url") or target_origin),
            "request": str(item.get("request") or "workflow request"),
            "response_status": _status(item.get("status_code")),
            "response_snippet": str(item.get("response") or "workflow response"),
        },
        "observation": str(item.get("observation") or "workflow step completed"),
    }


def _sanitize_bundle(bundle: dict[str, object]) -> dict[str, object]:
    sanitized = _sanitize_value(bundle)
    return dict(sanitized) if isinstance(sanitized, dict) else bundle


def _sanitize_value(value: object) -> object:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _sanitize_value(item) for key, item in value.items()}
    return value


def _redact_text(value: str) -> str:
    text = _BENCHMARK_FLAG_RE.sub("<redacted benchmark marker>", value)
    text = text.replace("FLAG_FOUND", "PROOF_FOUND")
    return text


def _scope_json(scope: object) -> dict[str, list[str]]:
    dump = getattr(scope, "model_dump", None)
    if callable(dump):
        value = dump()
        if isinstance(value, dict):
            return _scope_mapping(value)
    if isinstance(scope, dict):
        return _scope_mapping(scope)
    return {"in_scope": [], "out_of_scope": []}


def _scope_mapping(value: dict[object, object]) -> dict[str, list[str]]:
    return {
        "in_scope": _string_list(value.get("in_scope")),
        "out_of_scope": _string_list(value.get("out_of_scope")),
    }


def _vuln_class(observation: dict[str, object]) -> str:
    explicit = str(observation.get("candidate_vuln_class") or "").strip()
    if explicit:
        return explicit

    tool = str(observation.get("tool") or "").lower()
    indicator = str(observation.get("indicator") or "").lower()
    text = f"{tool} {indicator}"
    if "idor" in text or "identity_boundary" in text:
        return "idor"
    if "ssti" in text or "template" in text:
        return "ssti"
    if "lfi" in text or "file" in text and "read" in text:
        return "lfi"
    if "command" in text:
        return "command_injection"
    if "sqli" in text or "sql" in text:
        return "sqli"
    if "ssrf" in text:
        return "ssrf"
    if "xxe" in text or "entity" in text:
        return "xxe"
    return ""


def _source_value(observation: dict[str, object], vuln_class: str) -> str:
    for key in (
        "matched_value",
        "matched_payload",
        "matched_url",
        "source_token",
        "command_marker",
    ):
        value = _first_text(observation, key)
        if value:
            return value

    candidate_values = _string_list(observation.get("candidate_values"))
    if candidate_values:
        return candidate_values[0]
    candidate_urls = _string_list(observation.get("candidate_urls"))
    if candidate_urls:
        return candidate_urls[0]

    text = _combined_proof_text(observation)
    if vuln_class == "ssti":
        match = re.search(r"\{\{[^{}]{1,120}\}\}", text)
        if match:
            return match.group(0)
    if vuln_class == "idor":
        match = re.search(r"(?:id=|/)([A-Za-z0-9_-]{1,80})", text)
        if match:
            return match.group(1)
    return _first_text(observation, "param") or vuln_class


def _observed_value(observation: dict[str, object], vuln_class: str) -> str:
    explicit = _first_text(observation, "observed_value", "indicator")
    response = _first_text(observation, "proof_response_snippet")
    text = _combined_proof_text(observation)

    if vuln_class in {"sqli", "ssrf"} and explicit:
        return explicit
    if vuln_class in {"lfi", "xxe"} and "root:x:0:0:" in text:
        return "root:x:0:0:"
    if vuln_class == "ssti" and re.search(r"(?<!\d)49(?!\d)", text):
        return "49"
    if vuln_class == "command_injection":
        marker = _first_text(observation, "command_marker")
        if marker:
            return marker
    if response:
        return _clip(response, 160)
    if explicit:
        return explicit
    return vuln_class


def _combined_proof_text(observation: dict[str, object]) -> str:
    parts = [
        _first_text(observation, "proof_request"),
        _first_text(observation, "proof_response_snippet"),
        _first_text(observation, "stdout"),
    ]
    return "\n".join(part for part in parts if part)


def _title(vuln_class: str) -> str:
    titles = {
        "idor": "Authorization boundary proof",
        "ssti": "Server-side template injection proof",
        "lfi": "Local file read proof",
        "command_injection": "Command execution proof",
        "sqli": "SQL injection proof",
        "ssrf": "Server-side request forgery proof",
        "xxe": "XML external entity proof",
        "privilege_escalation": "Privilege escalation proof",
    }
    return titles.get(vuln_class, "Candidate vulnerability proof")


def _hypothesis(vuln_class: str) -> str:
    hypotheses = {
        "idor": "Changing an identity or object identifier exposes protected data.",
        "ssti": "A submitted template expression is evaluated by the server.",
        "lfi": "A file path mutation exposes local server file content.",
        "command_injection": "A command payload causes server-side command output.",
        "sqli": "A SQL payload changes the data returned by the application.",
        "ssrf": "A URL mutation causes the server to fetch an internal resource.",
        "xxe": "An XML entity payload causes local resource disclosure.",
        "privilege_escalation": "A request mutation crosses a privilege boundary.",
    }
    return hypotheses.get(vuln_class, "The candidate action produced proof-like output.")


def _relation(vuln_class: str) -> str:
    relations = {
        "idor": "mutated identifier selected the observed protected object",
        "ssti": "submitted template expression caused the rendered value",
        "lfi": "submitted file path caused the observed local file content",
        "command_injection": "submitted command payload caused the observed command marker",
        "sqli": "submitted SQL payload caused the observed response delta",
        "ssrf": "submitted URL caused the server-side fetch observation",
        "xxe": "submitted XML entity caused the observed local resource content",
        "privilege_escalation": "request mutation enabled the privileged observation",
    }
    return relations.get(vuln_class, "candidate source value caused the observed value")


def _mutation_step_id(vuln_class: str) -> str:
    step_ids = {
        "idor": "mutation",
        "ssti": "template-input",
        "lfi": "file-read-mutation",
        "command_injection": "command-payload",
        "sqli": "sql-payload",
        "ssrf": "url-mutation",
        "xxe": "xml-entity-payload",
        "privilege_escalation": "privilege-mutation",
    }
    return step_ids.get(vuln_class, "mutation")


def _mutation_description(vuln_class: str) -> str:
    descriptions = {
        "idor": "Replay the request with a different identity or object identifier.",
        "ssti": "Submit a template expression to the suspected sink.",
        "lfi": "Submit a local file path to the suspected file sink.",
        "command_injection": "Submit a command payload to the suspected command sink.",
        "sqli": "Submit a SQL payload to the suspected query sink.",
        "ssrf": "Submit an internal URL to the suspected fetch sink.",
        "xxe": "Submit an XML external entity payload.",
        "privilege_escalation": "Replay the request with a privileged boundary mutation.",
    }
    return descriptions.get(vuln_class, "Replay the candidate mutation.")


def _is_free_roam_observation(observation: dict[str, object]) -> bool:
    return str(observation.get("tool") or "") in {"run_python", "run_command"}


def _method(observation: dict[str, object]) -> str:
    return _http_method(observation.get("method"))


def _http_method(value: object) -> str:
    method = str(value or "GET").upper()
    if method in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
        return method
    return "GET"


def _method_from_request(value: str) -> str:
    match = re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\b", value, flags=re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return "POST"


def _proof_step_kind(value: object) -> str:
    kind = str(value or "observation")
    if kind in {"setup", "baseline", "mutation", "trigger", "observation", "control", "cleanup"}:
        return kind
    return "observation"


def _status(value: object) -> int:
    try:
        status = int(str(value or 200))
    except ValueError:
        return 200
    if 100 <= status <= 599:
        return status
    return 200


def _first_text(observation: dict[str, object], *keys: str) -> str:
    for key in keys:
        value = observation.get(key)
        if isinstance(value, str) and value:
            return value
        if value is not None and not isinstance(value, (dict, list, tuple, set)):
            text = str(value)
            if text:
                return text
    return ""


def _step_replay(step: dict[str, Any]) -> str:
    http = step.get("http")
    if isinstance(http, dict):
        request = str(http.get("request") or "").strip()
        if request:
            return request
    return str(step.get("description") or step.get("step_id") or "replay step")


def _step_id(steps: list[dict[str, Any]], preferred: str, *, fallback_index: int = 0) -> str:
    for step in steps:
        step_id = str(step.get("step_id") or "")
        if step_id == preferred:
            return step_id
    if steps:
        index = max(0, min(fallback_index, len(steps) - 1))
        return str(steps[index].get("step_id") or preferred)
    return preferred


def _inconclusive_verifier() -> dict[str, object]:
    return {
        "verdict": "inconclusive",
        "confidence": "medium",
        "rationale": "Candidate proof bundle has not been reviewed by the verifier.",
        "impact": None,
    }


def _bundle_id() -> str:
    return f"proof-{uuid4().hex}"


def _dict_value(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _clip(value: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", value.strip())
    return text[:limit] if len(text) > limit else text
