from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ravage.agent_core.frontier_observation_text import output_observation_texts

_GUARD_PREFIX = "COORDINATOR_REQUEST_CONTRACT_GUARD "
_RESOLVED_PREFIX = "COORDINATOR_REQUEST_CONTRACT_RESOLVED "
_MAX_CONTRACT_CONTEXT_CHARS = 4_000
_MAX_FIELDS = 16
_MAX_FIELD_NAME_CHARS = 128
_MAX_ENDPOINT_CHARS = 512
_MAX_STRUCTURED_DEPTH = 8
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_DATA_BLOCK = re.compile(
    r"(?is)\b(?:data|body|form|params)\s*:\s*\{(?P<body>[^{}]{1,2400})\}"
    r"\s*(?=,|\}\s*\)?\s*;)"
)
_FIELD = re.compile(
    r"(?x)(?:^|,)\s*(?P<key>['\"]?[A-Za-z_$][\w$.-]*['\"]?)\s*:\s*"
    r"(?P<value>['\"][^'\"]{0,512}['\"]|[A-Za-z_$][\w$.-]*|-?\d+(?:\.\d+)?|true|false|null)"
)
_URL = re.compile(r"(?is)\burl\s*:\s*['\"](?P<value>[^'\"]{1,512})['\"]")
_METHOD = re.compile(r"(?is)\b(?:type|method)\s*:\s*['\"](?P<value>get|post|put|patch|delete)['\"]")
_HIDDEN_INPUT = re.compile(r"(?is)<input\b(?P<attrs>[^>]{1,1600})>")
_ATTRIBUTE = re.compile(
    r"(?is)\b(?P<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*"
    r"(?P<quote>['\"])(?P<value>.*?)(?P=quote)"
)


class InvalidRequestContractIssueError(ValueError):
    pass


@dataclass(frozen=True)
class ObservedRequestContract:
    endpoint: str
    method: str
    fields: tuple[RequestContractField, ...]
    fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        endpoint: str,
        method: str,
        fields: Sequence[RequestContractField],
    ) -> ObservedRequestContract:
        normalized_fields = tuple(
            dict.fromkeys(
                field for field in fields if field.name and len(field.name) <= _MAX_FIELD_NAME_CHARS
            )
        )[:_MAX_FIELDS]
        endpoint_value = endpoint.strip()
        method_value = method.strip().upper()
        payload = {
            "endpoint": endpoint_value,
            "method": method_value,
            "fields": [field.to_json() for field in normalized_fields],
        }
        fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return cls(
            endpoint=endpoint_value,
            method=method_value,
            fields=normalized_fields,
            fingerprint=fingerprint,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "fields": [field.to_json() for field in self.fields],
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> ObservedRequestContract:
        raw_fields = payload.get("fields")
        fields = (
            tuple(
                RequestContractField.from_json(item)
                for item in raw_fields
                if isinstance(item, Mapping)
            )
            if isinstance(raw_fields, list)
            else ()
        )
        contract = cls.create(
            endpoint=str(payload.get("endpoint") or ""),
            method=str(payload.get("method") or ""),
            fields=fields,
        )
        stored = str(payload.get("fingerprint") or "")
        if stored and stored != contract.fingerprint:
            raise InvalidRequestContractIssueError
        return contract


@dataclass(frozen=True)
class RequestContractField:
    name: str
    constant_value: str | None = None

    def to_json(self) -> dict[str, object]:
        return {"name": self.name, "constant_value": self.constant_value}

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RequestContractField:
        value = payload.get("constant_value")
        return cls(
            name=str(payload.get("name") or "").strip(),
            constant_value=None if value is None else str(value),
        )


@dataclass(frozen=True)
class RequestContractIssue:
    endpoint: str
    method: str
    fields: tuple[RequestContractField, ...]
    missing_fields: tuple[str, ...]
    fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        endpoint: str,
        method: str,
        fields: Sequence[RequestContractField],
        missing_fields: Sequence[str],
    ) -> RequestContractIssue:
        normalized_fields = tuple(
            dict.fromkeys(
                field for field in fields if field.name and len(field.name) <= _MAX_FIELD_NAME_CHARS
            )
        )[:_MAX_FIELDS]
        normalized_missing = tuple(
            dict.fromkeys(str(item).strip() for item in missing_fields if str(item).strip())
        )
        endpoint_value = endpoint.strip()
        method_value = method.strip().upper()
        payload = {
            "endpoint": endpoint_value,
            "method": method_value,
            "fields": [field.to_json() for field in normalized_fields],
        }
        fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return cls(
            endpoint=endpoint_value,
            method=method_value,
            fields=normalized_fields,
            missing_fields=normalized_missing,
            fingerprint=fingerprint,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "fields": [field.to_json() for field in self.fields],
            "missing_fields": list(self.missing_fields),
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, object]) -> RequestContractIssue:
        raw_fields = payload.get("fields")
        fields = (
            tuple(
                RequestContractField.from_json(item)
                for item in raw_fields
                if isinstance(item, Mapping)
            )
            if isinstance(raw_fields, list)
            else ()
        )
        raw_missing = payload.get("missing_fields")
        missing = tuple(str(item) for item in raw_missing) if isinstance(raw_missing, list) else ()
        issue = cls.create(
            endpoint=str(payload.get("endpoint") or ""),
            method=str(payload.get("method") or ""),
            fields=fields,
            missing_fields=missing,
        )
        stored = str(payload.get("fingerprint") or "")
        if stored and stored != issue.fingerprint:
            raise InvalidRequestContractIssueError
        return issue


def detect_request_contract_issue(
    action: Mapping[str, object],
    observation: str,
) -> RequestContractIssue | None:
    """Detect a replay that omitted fields defined by target-produced client code."""
    source = _action_source(action)
    if not source or not observation:
        return None
    candidates: list[RequestContractIssue] = []
    for contract in observed_request_contracts(observation):
        if not _action_attempts_contract(
            source,
            endpoint=contract.endpoint,
            method=contract.method,
        ):
            continue
        missing = tuple(
            field.name for field in contract.fields if not _field_assignment_present(source, field)
        )
        if not missing:
            continue
        candidates.append(
            RequestContractIssue.create(
                endpoint=contract.endpoint,
                method=contract.method,
                fields=contract.fields,
                missing_fields=missing,
            )
        )

    hidden_fields = _hidden_fields(observation)
    if hidden_fields:
        missing = tuple(
            field.name for field in hidden_fields if not _field_assignment_present(source, field)
        )
        if missing and _looks_like_form_submission(source):
            candidates.append(
                RequestContractIssue.create(
                    endpoint="target-observed form",
                    method="POST",
                    fields=hidden_fields,
                    missing_fields=missing,
                )
            )
    if not candidates:
        return None
    return max(candidates, key=lambda item: (len(item.missing_fields), len(item.fields)))


def observed_request_contracts(observation: str) -> tuple[ObservedRequestContract, ...]:
    """Extract request contracts from target-produced code or structured tool output."""
    contracts: list[ObservedRequestContract] = []
    seen: set[str] = set()

    def remember(contract: ObservedRequestContract) -> None:
        if contract.fingerprint in seen:
            return
        seen.add(contract.fingerprint)
        contracts.append(contract)

    for source in output_observation_texts(observation):
        for match in _DATA_BLOCK.finditer(source):
            start = max(0, match.start() - _MAX_CONTRACT_CONTEXT_CHARS)
            context = source[start : match.start()]
            endpoint = _last_match(_URL, context)
            method = _last_match(_METHOD, context).upper()
            fields = _parse_fields(match.group("body"))
            if not endpoint or not method or not fields:
                continue
            contract = ObservedRequestContract.create(
                endpoint=endpoint,
                method=method,
                fields=fields,
            )
            remember(contract)
    for contract in _structured_request_contracts(observation):
        remember(contract)
    return tuple(contracts)


def _structured_request_contracts(
    observation: str,
) -> tuple[ObservedRequestContract, ...]:
    try:
        payload = json.loads(observation, strict=False)
    except (TypeError, ValueError):
        return ()
    contracts: list[ObservedRequestContract] = []
    for item in _walk_mappings(payload):
        nested_form = item.get("form")
        form = nested_form if isinstance(nested_form, Mapping) else item
        if not all(key in form for key in ("action", "method", "inputs")):
            continue
        endpoint = str(form.get("action") or "").strip()
        method = str(form.get("method") or "").strip().upper()
        fields = _structured_fields(form.get("inputs"))
        if (
            not endpoint
            or len(endpoint) > _MAX_ENDPOINT_CHARS
            or method not in _HTTP_METHODS
            or not fields
        ):
            continue
        contracts.append(
            ObservedRequestContract.create(
                endpoint=endpoint,
                method=method,
                fields=fields,
            )
        )
    return tuple(contracts)


def _walk_mappings(value: object, *, depth: int = 0) -> tuple[Mapping[str, object], ...]:
    if depth > _MAX_STRUCTURED_DEPTH:
        return ()
    if isinstance(value, Mapping):
        current = (value,)
        nested = tuple(
            item for child in value.values() for item in _walk_mappings(child, depth=depth + 1)
        )
        return current + nested
    if isinstance(value, list):
        return tuple(item for child in value for item in _walk_mappings(child, depth=depth + 1))
    return ()


def _structured_fields(value: object) -> tuple[RequestContractField, ...]:
    fields: list[RequestContractField] = []
    if isinstance(value, Mapping):
        for name, raw_constant in value.items():
            constant = None if raw_constant is None or raw_constant == "" else str(raw_constant)
            fields.append(RequestContractField(name=str(name).strip(), constant_value=constant))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                name = str(item.get("name") or "").strip()
                raw_constant = item.get("value")
                constant = None if raw_constant is None or raw_constant == "" else str(raw_constant)
                fields.append(RequestContractField(name=name, constant_value=constant))
            else:
                fields.append(RequestContractField(name=str(item).strip()))
    return tuple(
        dict.fromkeys(
            field for field in fields if field.name and len(field.name) <= _MAX_FIELD_NAME_CHARS
        )
    )[:_MAX_FIELDS]


def action_satisfies_contract(
    action: Mapping[str, object],
    issue: RequestContractIssue,
) -> bool:
    source = _action_source(action)
    if not source:
        return False
    if issue.endpoint != "target-observed form" and not _action_attempts_contract(
        source,
        endpoint=issue.endpoint,
        method=issue.method,
    ):
        return False
    return all(_field_assignment_present(source, field) for field in issue.fields)


def guard_message(issue: RequestContractIssue) -> str:
    contract = _human_contract(issue)
    missing = ", ".join(issue.missing_fields)
    payload = json.dumps(issue.to_json(), sort_keys=True)
    return (
        f"{_GUARD_PREFIX}{payload}\n"
        "The coordinator rejects route exhaustion because the attempted replay omitted "
        f"target-observed request-contract field(s): {missing}. Preserve {contract}; "
        "change only the assigned exploit input on the next action."
    )


def resolved_message(issue: RequestContractIssue) -> str:
    return f"{_RESOLVED_PREFIX}{issue.fingerprint}"


def pending_contract_issue(
    messages: Sequence[Mapping[str, str]],
) -> RequestContractIssue | None:
    resolved: set[str] = set()
    for message in reversed(messages):
        content = str(message.get("content") or "")
        if content.startswith(_RESOLVED_PREFIX):
            resolved.add(content.removeprefix(_RESOLVED_PREFIX).strip())
            continue
        if not content.startswith(_GUARD_PREFIX):
            continue
        encoded = content.removeprefix(_GUARD_PREFIX).splitlines()[0]
        try:
            payload = json.loads(encoded)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, Mapping):
            continue
        try:
            issue = RequestContractIssue.from_json(payload)
        except ValueError:
            continue
        if issue.fingerprint not in resolved:
            return issue
    return None


def _parse_fields(body: str) -> tuple[RequestContractField, ...]:
    fields: list[RequestContractField] = []
    for match in _FIELD.finditer(body):
        name = match.group("key").strip("'\"")
        raw_value = match.group("value").strip()
        constant = raw_value[1:-1] if raw_value[:1] in {"'", '"'} else None
        fields.append(RequestContractField(name=name, constant_value=constant))
    return tuple(dict.fromkeys(fields))[:_MAX_FIELDS]


def _hidden_fields(observation: str) -> tuple[RequestContractField, ...]:
    fields: list[RequestContractField] = []
    for match in _HIDDEN_INPUT.finditer(observation):
        attrs = {
            item.group("name").lower(): item.group("value")
            for item in _ATTRIBUTE.finditer(match.group("attrs"))
        }
        if attrs.get("type", "").lower() != "hidden" or not attrs.get("name"):
            continue
        fields.append(
            RequestContractField(
                name=attrs["name"],
                constant_value=attrs.get("value"),
            )
        )
    return tuple(dict.fromkeys(fields))[:_MAX_FIELDS]


def _action_source(action: Mapping[str, object]) -> str:
    kind = str(action.get("action") or "")
    if kind == "run_python":
        return str(action.get("code") or "")
    if kind == "run_command":
        return str(action.get("command") or "")
    if kind == "validate_poc":
        return json.dumps(action.get("steps") or [], sort_keys=True)
    return ""


def _action_attempts_contract(source: str, *, endpoint: str, method: str) -> bool:
    endpoint_variants = {endpoint, endpoint.lstrip("/"), f"/{endpoint.lstrip('/')}"}
    if not any(value and value in source for value in endpoint_variants):
        return False
    method_lower = method.lower()
    if re.search(rf"(?i)\b{re.escape(method_lower)}\b", source):
        return True
    return method_lower == "post" and _looks_like_form_submission(source)


def _looks_like_form_submission(source: str) -> bool:
    lowered = source.lower()
    return any(marker in lowered for marker in ("--data", "-d ", "urlencode(", "data=", "form="))


def _field_assignment_present(source: str, field: RequestContractField) -> bool:
    name = re.escape(field.name)
    key = rf"(?:['\"]{name}['\"]|\b{name}\b)"
    if field.constant_value is None:
        return bool(
            re.search(rf"(?is){key}\s*[:=]", source) or re.search(rf"(?i)(?:^|[?&]){name}=", source)
        )
    value = re.escape(field.constant_value)
    literal = rf"(?:['\"]{value}['\"]|\b{value}\b)"
    return bool(
        re.search(rf"(?is){key}\s*[:=]\s*{literal}", source)
        or re.search(rf"(?i)(?:^|[?&]){name}={value}(?:[&#'\"\s]|$)", source)
    )


def _last_match(pattern: re.Pattern[str], value: str) -> str:
    found = [match.group("value") for match in pattern.finditer(value)]
    return found[-1].strip() if found else ""


def _human_contract(issue: RequestContractIssue) -> str:
    fields = []
    for field in issue.fields:
        if field.constant_value is None:
            fields.append(field.name)
        else:
            fields.append(f"{field.name}={field.constant_value}")
    return f"{issue.method} {issue.endpoint} with fields {', '.join(fields)}"


__all__ = [
    "ObservedRequestContract",
    "RequestContractField",
    "RequestContractIssue",
    "action_satisfies_contract",
    "detect_request_contract_issue",
    "guard_message",
    "observed_request_contracts",
    "pending_contract_issue",
    "resolved_message",
]
