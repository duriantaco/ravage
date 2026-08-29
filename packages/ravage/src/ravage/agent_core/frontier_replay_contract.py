from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, unquote_plus, urljoin, urlsplit, urlunsplit

from ravage.agent_core.frontier_route import FrontierObjective

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_EVIDENCE_REF_PREFIX = "replay-contract:"
_LEGACY_EVIDENCE_REF_PREFIX = "base-replay:"
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_TRUSTED_REPLAY_SOURCES = frozenset({"frontier_target_observation", "replay"})
_REPLAY_SIGNALS: dict[str, tuple[str, ...]] = {
    "sql_injection": ("sqli_replays",),
    "authentication": ("auth_replays",),
    "object_authorization": ("idor_replays",),
    "path_traversal": ("file_read_replays",),
    "server_side_request_forgery": ("ssrf_replays",),
    "xml_external_entity": ("xxe_replays",),
}
_URL_LITERAL = re.compile(
    r"(?is)(?:https?://[^\s'\"<>]+|(?P<quote>['\"])(?P<path>/[^'\"\s<>]*)"
    r"(?P=quote))"
)
_EXPLICIT_POST = (
    re.compile(r"(?is)\b(?:requests|session|client)\.post\s*\("),
    re.compile(r"(?is)\bcurl\b[^\n]*\s(?:-x|--request)\s+post\b"),
    re.compile(r"(?is)\bmethod\s*=\s*['\"]post['\"]"),
    re.compile(r"(?is)\burllib\.request\.request\s*\([^)]*\bdata\s*="),
    re.compile(r"(?is)\brequest\s*\([^)]*\bdata\s*="),
)
_EXPLICIT_GET = (
    re.compile(r"(?is)\b(?:requests|session|client)\.get\s*\("),
    re.compile(r"(?is)\bcurl\b[^\n]*\s(?:-x|--request)\s+get\b"),
    re.compile(r"(?is)\bmethod\s*=\s*['\"]get['\"]"),
)
_SOURCE_FIELDS = frozenset({"code", "command", "steps"})


@dataclass(frozen=True)
class AuthoritativeReplayContract:
    """Trusted replay projection; authoritative only when target-observed."""

    family: str
    method: str
    endpoint: str
    observed_url: str
    payload_field: str
    payload_location: str
    required_fields: tuple[str, ...]
    fixed_parameters: tuple[tuple[str, str], ...]
    encoding: str
    source: str
    fingerprint: str

    @classmethod
    def create(  # noqa: PLR0913 - the fields are the persisted contract boundary.
        cls,
        *,
        family: str,
        method: str,
        endpoint: str,
        observed_url: str,
        payload_field: str,
        payload_location: str,
        required_fields: Sequence[str] = (),
        fixed_parameters: Sequence[tuple[str, str]] = (),
        encoding: str = "",
        source: str,
    ) -> AuthoritativeReplayContract:
        normalized = {
            "family": family.strip().lower(),
            "method": method.strip().upper(),
            "endpoint": endpoint.strip(),
            "observed_url": observed_url.strip(),
            "payload_field": payload_field.strip(),
            "payload_location": payload_location.strip().lower(),
            "required_fields": sorted(
                {str(name).strip() for name in required_fields if str(name).strip()}
            ),
            "fixed_parameters": sorted(
                {
                    (str(name).strip(), str(value))
                    for name, value in fixed_parameters
                    if str(name).strip()
                }
            ),
            "encoding": encoding.strip().lower(),
            "source": source.strip().lower(),
        }
        fingerprint = hashlib.sha256(
            json.dumps(normalized, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return cls(
            family=str(normalized["family"]),
            method=str(normalized["method"]),
            endpoint=str(normalized["endpoint"]),
            observed_url=str(normalized["observed_url"]),
            payload_field=str(normalized["payload_field"]),
            payload_location=str(normalized["payload_location"]),
            required_fields=tuple(normalized["required_fields"]),
            fixed_parameters=tuple(normalized["fixed_parameters"]),
            encoding=str(normalized["encoding"]),
            source=str(normalized["source"]),
            fingerprint=fingerprint,
        )

    @property
    def evidence_ref(self) -> str:
        return f"{_EVIDENCE_REF_PREFIX}{self.fingerprint}"

    @property
    def authoritative(self) -> bool:
        return self.source == "frontier_target_observation"

    def to_json(self) -> dict[str, object]:
        return {
            "method": self.method,
            "endpoint": self.endpoint,
            "observed_replay_url": self.observed_url,
            "payload_field": self.payload_field,
            "payload_location": self.payload_location,
            "required_fields": list(self.required_fields),
            "fixed_parameters": [
                {"name": name, "value": value} for name, value in self.fixed_parameters
            ],
            "encoding": self.encoding,
            "source": self.source,
            "authority": "target_observed" if self.authoritative else "candidate",
            "fingerprint": self.fingerprint,
            "replay_rule": (
                "Preserve this target-observed contract exactly."
                if self.authoritative
                else "Validate this candidate against target-produced client evidence."
            ),
        }


@dataclass(frozen=True)
class ReplayContractIssue:
    code: str
    expected_method: str
    expected_endpoint: str
    payload_field: str
    contract_fingerprint: str
    missing_fields: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "code": self.code,
            "expected_method": self.expected_method,
            "expected_endpoint": self.expected_endpoint,
            "payload_field": self.payload_field,
            "contract_fingerprint": self.contract_fingerprint,
            "missing_fields": list(self.missing_fields),
        }


def authoritative_replay_for_family(
    state: AgentState,
    *,
    family: str,
    target_url: str,
    preferred_inputs: Sequence[str] = (),
) -> AuthoritativeReplayContract | None:
    """Select the newest complete same-origin replay emitted by trusted tooling."""
    preferred = {str(item).strip().lower() for item in preferred_inputs if str(item).strip()}
    candidates: list[AuthoritativeReplayContract] = []
    for key in _REPLAY_SIGNALS.get(family, ()):
        for raw in reversed(state.signals.get(key, [])):
            contract = _parse_replay(
                raw,
                family=family,
                target_url=target_url,
            )
            if contract is not None:
                candidates.append(contract)
    if not candidates:
        return None
    if preferred:
        matching = [item for item in candidates if item.payload_field.lower() in preferred]
        if matching:
            return matching[0]
    return candidates[0]


def authoritative_replay_for_objective(
    state: AgentState,
    objective: FrontierObjective,
    *,
    target_url: str,
) -> AuthoritativeReplayContract | None:
    fingerprint = _objective_replay_fingerprint(objective.evidence_refs)
    if not fingerprint:
        return None
    for key in _REPLAY_SIGNALS.get(objective.family, ()):
        for raw in reversed(state.signals.get(key, [])):
            contract = _parse_replay(
                raw,
                family=objective.family,
                target_url=target_url,
            )
            if contract is not None and contract.fingerprint == fingerprint:
                return contract
    return None


def replay_contract_constraints(
    contract: AuthoritativeReplayContract | None,
) -> tuple[str, ...]:
    if contract is None:
        return ()
    fixed = ", ".join(name for name, _value in contract.fixed_parameters) or "none"
    required = ", ".join(contract.required_fields) or contract.payload_field
    if not contract.authoritative:
        return (
            (
                "The coordinator has a tool-produced replay candidate, not a validated "
                "request contract. Validate it against same-origin target-produced HTML, "
                "client script, or structured form output."
            ),
            (
                f"Candidate method={contract.method}, endpoint={contract.endpoint}, "
                f"payload_location={contract.payload_location}, "
                f"payload_field={contract.payload_field}."
            ),
            (
                "A newer target-observed client contract may supersede this candidate. "
                "Do not carry an inferred transport into later payload or proof work."
            ),
        )
    return (
        (
            "The coordinator has an authoritative target-observed replay contract; it takes "
            "precedence over generic forms, request templates, and model-authored guesses."
        ),
        (
            f"Replay method={contract.method}, endpoint={contract.endpoint}, "
            f"payload_location={contract.payload_location}, "
            f"payload_field={contract.payload_field}, required_fields={required}, "
            f"fixed_parameters={fixed}."
        ),
        "Do not change the transport while changing payload semantics or proof channel.",
    )


def replay_contract_expected_clause(
    contract: AuthoritativeReplayContract,
) -> str:
    fixed = ",".join(f"{name}={value}" for name, value in contract.fixed_parameters) or "none"
    required = ",".join(contract.required_fields) or contract.payload_field
    if contract.authoritative:
        prefix = "Preserve the target-observed replay exactly"
        suffix = ""
    else:
        prefix = "Candidate base-tool replay to validate"
        suffix = " A newer same-origin target-observed client contract may supersede it."
    return (
        f" {prefix}: method={contract.method}, endpoint={contract.endpoint}, "
        f"payload_location={contract.payload_location}, "
        f"payload_field={contract.payload_field}, required_fields={required}, "
        f"fixed_parameters={fixed}.{suffix}"
    )


def rebase_frontier_objective(
    objective: FrontierObjective,
    contract: AuthoritativeReplayContract,
) -> FrontierObjective:
    """Move one pending objective to a newer target-observed replay contract."""
    if objective.family != contract.family:
        return objective
    evidence_refs = tuple(
        ref for ref in objective.evidence_refs if not _is_replay_evidence_ref(ref)
    )
    expected_signal = _without_replay_clause(objective.expected_signal)
    return FrontierObjective.create(
        family=objective.family,
        probe=objective.probe,
        endpoint=contract.endpoint,
        inputs=(contract.payload_field,),
        payload_class=objective.payload_class,
        expected_signal=(expected_signal + replay_contract_expected_clause(contract)),
        evidence_refs=(*evidence_refs, contract.evidence_ref),
        basis=objective.basis,
    )


def detect_replay_contract_issue(  # noqa: PLR0911 - each contradiction is explicit.
    action: Mapping[str, object],
    contract: AuthoritativeReplayContract | None,
    *,
    allow_candidate_correction: bool = False,
) -> ReplayContractIssue | None:
    """Reject explicit contradictions without trying to infer every possible script."""
    if contract is None or str(action.get("action") or "") not in {
        "run_command",
        "run_python",
        "validate_poc",
    }:
        return None
    if allow_candidate_correction and not contract.authoritative:
        return None
    source = _action_source(action)
    if not source:
        return None
    if contract.method == "GET" and any(pattern.search(source) for pattern in _EXPLICIT_POST):
        return _issue(contract, "authoritative_get_replayed_as_post")
    if contract.method == "POST" and any(pattern.search(source) for pattern in _EXPLICIT_GET):
        return _issue(contract, "authoritative_post_replayed_as_get")
    if _conflicting_payload_endpoint(source, contract):
        return _issue(contract, "authoritative_endpoint_changed")
    missing_fields = tuple(
        field for field in contract.required_fields if not _token_present(source, field)
    )
    if contract.authoritative and missing_fields:
        return _issue(
            contract,
            "authoritative_required_fields_omitted",
            missing_fields=missing_fields,
        )
    return None


def replay_contract_guard_message(
    contract: AuthoritativeReplayContract,
    issue: ReplayContractIssue,
) -> str:
    fixed = ", ".join(f"{name}={value!r}" for name, value in contract.fixed_parameters) or "none"
    if contract.authoritative:
        heading = "COORDINATOR_AUTHORITATIVE_REPLAY_GUARD"
        reason = (
            "Target-produced client evidence established a concrete replay contract, "
            "and this action contradicts it."
        )
    else:
        heading = "COORDINATOR_REPLAY_CANDIDATE_GUARD"
        reason = (
            "This non-contract stage contradicts the current tool-produced replay "
            "candidate. Only the assigned request-contract stage may replace it with "
            "same-origin target-produced evidence."
        )
    return (
        f"{heading}\n"
        f"Action not executed. {reason} The model request remains charged.\n"
        f"Reason: {issue.code}. Preserve method={contract.method}, "
        f"endpoint={contract.endpoint}, payload_location={contract.payload_location}, "
        f"payload_field={contract.payload_field}, "
        f"required_fields={','.join(contract.required_fields)}, "
        f"fixed_parameters={fixed}.\n"
        "Change the assigned payload or proof dimension inside that contract; do not "
        "substitute a generic form or inferred transport."
    )


def _parse_replay(
    raw: object,
    *,
    family: str,
    target_url: str,
) -> AuthoritativeReplayContract | None:
    try:
        payload = json.loads(str(raw))
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, Mapping):
        return None
    source = str(payload.get("source") or "").strip().lower()
    method = str(payload.get("method") or "").strip().upper()
    raw_url = str(payload.get("url") or "").strip()
    payload_field = str(payload.get("payload_field") or payload.get("input") or "").strip()
    if (
        source not in _TRUSTED_REPLAY_SOURCES
        or method not in _HTTP_METHODS
        or not raw_url
        or not payload_field
    ):
        return None
    observed_url = urljoin(f"{target_url.rstrip('/')}/", raw_url)
    if _origin(observed_url) != _origin(target_url):
        return None
    parsed = urlsplit(observed_url)
    endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    query = tuple(parse_qsl(parsed.query, keep_blank_values=True))
    form = _mapping_pairs(payload.get("form"))
    required_fields = _string_sequence(payload.get("required_fields"))
    if source == "frontier_target_observation" and not required_fields:
        required_fields = tuple(name for name, _value in form)
    constant_fields = _mapping_pairs(payload.get("constant_fields"))
    if not constant_fields:
        constant_fields = tuple(
            (name, value) for name, value in form if value and name.lower() != payload_field.lower()
        )
    fixed = tuple(
        (name, value)
        for name, value in (*query, *constant_fields)
        if name.lower() != payload_field.lower()
    )
    location = "query" if method == "GET" else "body"
    encoding = str(payload.get("encoding") or "").strip()
    return AuthoritativeReplayContract.create(
        family=family,
        method=method,
        endpoint=endpoint,
        observed_url=observed_url,
        payload_field=payload_field,
        payload_location=location,
        required_fields=required_fields,
        fixed_parameters=fixed,
        encoding=encoding,
        source=source,
    )


def _mapping_pairs(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        return ()
    return tuple((str(name), str(item)) for name, item in value.items())


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _is_replay_evidence_ref(value: object) -> bool:
    ref = str(value)
    return ref.startswith((_EVIDENCE_REF_PREFIX, _LEGACY_EVIDENCE_REF_PREFIX))


def _without_replay_clause(value: str) -> str:
    result = value
    for marker in (
        " Preserve the authoritative base-tool replay exactly:",
        " Candidate base-tool replay to validate:",
        " Preserve the target-observed replay exactly:",
    ):
        result = result.partition(marker)[0]
    return result.rstrip()


def _objective_replay_fingerprint(evidence_refs: Sequence[str]) -> str:
    for ref in evidence_refs:
        value = str(ref)
        if value.startswith(_EVIDENCE_REF_PREFIX):
            return value.removeprefix(_EVIDENCE_REF_PREFIX)
        if value.startswith(_LEGACY_EVIDENCE_REF_PREFIX):
            return value.removeprefix(_LEGACY_EVIDENCE_REF_PREFIX)
    return ""


def _action_source(action: Mapping[str, object]) -> str:
    values = [str(action.get(key) or "") for key in _SOURCE_FIELDS]
    raw = "\n".join(value for value in values if value).lower()
    decoded = unquote_plus(raw)
    return raw if decoded == raw else f"{raw}\n{decoded}"


def _conflicting_payload_endpoint(
    source: str,
    contract: AuthoritativeReplayContract,
) -> bool:
    expected = urlsplit(contract.endpoint)
    candidates: list[str] = []
    for match in _URL_LITERAL.finditer(source):
        value = match.group(0).strip("'\"")
        if value.startswith("/"):
            value = urljoin(f"{contract.endpoint.rstrip('/')}/", value)
        parsed = urlsplit(value.rstrip(")]},;"))
        if parsed.scheme not in {"http", "https"}:
            continue
        if _origin(value) != (expected.scheme.lower(), expected.netloc.lower()):
            continue
        candidates.append(parsed.path or "/")
    if not candidates:
        return False
    expected_path = expected.path or "/"
    return expected_path not in candidates and contract.payload_field.lower() in source


def _token_present(source: str, token: str) -> bool:
    normalized = token.strip().lower()
    if not normalized:
        return True
    return bool(
        re.search(
            rf"(?<![\w$.-]){re.escape(normalized)}(?![\w$.-])",
            source,
        )
    )


def _issue(
    contract: AuthoritativeReplayContract,
    code: str,
    *,
    missing_fields: Sequence[str] = (),
) -> ReplayContractIssue:
    return ReplayContractIssue(
        code=code,
        expected_method=contract.method,
        expected_endpoint=contract.endpoint,
        payload_field=contract.payload_field,
        contract_fingerprint=contract.fingerprint,
        missing_fields=tuple(missing_fields),
    )


def _origin(value: str) -> tuple[str, str]:
    parsed = urlsplit(value)
    return parsed.scheme.lower(), parsed.netloc.lower()


__all__ = [
    "AuthoritativeReplayContract",
    "ReplayContractIssue",
    "authoritative_replay_for_family",
    "authoritative_replay_for_objective",
    "detect_replay_contract_issue",
    "rebase_frontier_objective",
    "replay_contract_constraints",
    "replay_contract_expected_clause",
    "replay_contract_guard_message",
]
