from __future__ import annotations

from collections.abc import Callable

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

from .models import (
    BaselineValue,
    BriefTarget,
    ReplayTarget,
    SendTarget,
    ValueExpr,
    _AuthBypassCase,
    _BooleanPrimitive,
    _ErrorPrimitive,
    _TimingPrimitive,
    _TimingProbeOutcome,
    _UnionPrimitive,
)


class ExtractorContext:
    session: ProbeSession
    state: AgentState
    targets: list[dict[str, object]]
    send_target: SendTarget
    target_brief: BriefTarget
    replay_target: ReplayTarget
    baseline_value: BaselineValue
    budget: int
    requests: list[dict[str, object]]
    findings: list[dict[str, object]]
    errors: list[str]
    proofs: list[str]
    _timing_confirmed: bool
    _timing_attempted: bool
    _timing_stop: bool
    _timing_deadline: float

    def _send(
        self,
        target: dict[str, object],
        payload: str,
        *,
        phase: str,
        expr: str = "",
    ) -> ProbeResponse | None:
        raise NotImplementedError

    def _record_response(
        self,
        response: ProbeResponse,
        *,
        target: dict[str, object],
        phase: str,
        payload: str,
        expr: str,
    ) -> None:
        raise NotImplementedError

    def _find_error_primitive(self, target: dict[str, object]) -> _ErrorPrimitive | None:
        raise NotImplementedError

    def _extract_error_based(self, primitive: _ErrorPrimitive) -> None:
        raise NotImplementedError

    def _error_leak(self, primitive: _ErrorPrimitive, expr: str) -> str:
        raise NotImplementedError

    def _enumerate_tables(self, primitive: _ErrorPrimitive, schema_match: str) -> list[str]:
        raise NotImplementedError

    def _enumerate_columns(
        self,
        primitive: _ErrorPrimitive,
        tables: list[str],
        schema_match: str,
    ) -> dict[str, list[str]]:
        raise NotImplementedError

    def _extract_table_values(
        self,
        primitive: _ErrorPrimitive,
        tables: list[str],
        columns_by_table: dict[str, list[str]],
    ) -> list[dict[str, object]]:
        raise NotImplementedError

    def _append_error_summary(
        self,
        primitive: _ErrorPrimitive,
        tables: list[str],
        columns_by_table: dict[str, list[str]],
        rows: list[dict[str, object]],
        login_findings: list[dict[str, object]] | None = None,
    ) -> None:
        raise NotImplementedError

    def _extract_fast_error_values(
        self,
        primitive: _ErrorPrimitive,
        *,
        max_requests: int,
    ) -> list[dict[str, object]]:
        raise NotImplementedError

    def _chunked_error_value(
        self,
        primitive: _ErrorPrimitive,
        table: str,
        column: str,
        row_index: int,
    ) -> str:
        raise NotImplementedError

    def _find_union_primitive(self, target: dict[str, object]) -> _UnionPrimitive | None:
        raise NotImplementedError

    def _extract_union_based(self, primitive: _UnionPrimitive) -> None:
        raise NotImplementedError

    def _union_direct_common_values(self, primitive: _UnionPrimitive) -> list[dict[str, object]]:
        raise NotImplementedError

    def _union_leak(self, primitive: _UnionPrimitive, expr: str) -> str:
        raise NotImplementedError

    def _union_tables(self, primitive: _UnionPrimitive) -> list[str]:
        raise NotImplementedError

    def _union_columns(
        self,
        primitive: _UnionPrimitive,
        tables: list[str],
        database_name: str,
    ) -> dict[str, list[str]]:
        raise NotImplementedError

    def _union_values(
        self,
        primitive: _UnionPrimitive,
        tables: list[str],
        columns_by_table: dict[str, list[str]],
    ) -> list[dict[str, object]]:
        raise NotImplementedError

    def _find_boolean_primitive(self, target: dict[str, object]) -> _BooleanPrimitive | None:
        raise NotImplementedError

    def _extract_boolean_blind(self, primitive: _BooleanPrimitive) -> None:
        raise NotImplementedError

    def _extract_timing_blind(self, primitive: _TimingPrimitive) -> None:
        raise NotImplementedError

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
        raise NotImplementedError

    def _register_blind_proof(self, value: str, target: dict[str, object], phase: str) -> None:
        raise NotImplementedError

    def _blind_schema_extraction(
        self,
        eval_condition: Callable[[str], bool],
        target: dict[str, object],
        phase: str,
        extracted: list[dict[str, object]],
    ) -> None:
        raise NotImplementedError

    def _blind_extract_raw(
        self,
        eval_condition: Callable[[str], bool],
        expr: str,
        dialect: str,
    ) -> str:
        raise NotImplementedError

    def _blind_length(self, eval_condition: Callable[[str], bool], expr: str) -> int:
        raise NotImplementedError

    def _blind_char_code(
        self,
        eval_condition: Callable[[str], bool],
        expr: str,
        position: int,
        dialect: str,
    ) -> int:
        raise NotImplementedError

    def _extract_blind_value(
        self,
        eval_condition: Callable[[str], bool],
        table: str,
        column: str,
        row_index: int,
        candidates: tuple[tuple[ValueExpr, str], ...],
    ) -> str:
        raise NotImplementedError

    def _first_blind_value(
        self,
        eval_condition: Callable[[str], bool],
        table: str,
        columns: tuple[str, ...],
        row_index: int,
        candidates: tuple[tuple[ValueExpr, str], ...],
    ) -> str:
        raise NotImplementedError

    def _bool_eval(self, primitive: _BooleanPrimitive, condition: str) -> bool:
        raise NotImplementedError

    def _timing_eval(self, primitive: _TimingPrimitive, condition: str) -> bool:
        raise NotImplementedError

    def _find_timing_primitive(self, target: dict[str, object]) -> _TimingPrimitive | None:
        raise NotImplementedError

    def _check_timing_template(
        self,
        *,
        target: dict[str, object],
        template: str,
        dialect: str,
        delay: float,
    ) -> _TimingProbeOutcome:
        raise NotImplementedError

    def _record_timing_primitive(self, primitive: _TimingPrimitive) -> None:
        raise NotImplementedError

    def _try_logins(self, credentials: list[tuple[str, str]]) -> list[dict[str, object]]:
        raise NotImplementedError

    def _try_credential_pair(self, username: str, password: str) -> dict[str, object] | None:
        raise NotImplementedError

    def _try_login_replay(
        self,
        target: dict[str, object],
        *,
        username: str,
        password: str,
    ) -> dict[str, object] | None:
        raise NotImplementedError

    def _record_login_replay_response(
        self,
        response: ProbeResponse,
        *,
        url: str,
        username: str,
        password: str,
    ) -> None:
        raise NotImplementedError

    def _record_login_replay_home(self, response: ProbeResponse) -> None:
        raise NotImplementedError

    def _try_sqli_auth_bypass(
        self,
        usernames: list[str],
        *,
        include_fallback: bool = False,
        max_requests: int | None = None,
        reserve_budget: int = 0,
    ) -> list[dict[str, object]]:
        raise NotImplementedError

    def _try_sqli_auth_bypass_target(
        self,
        target: dict[str, object],
        *,
        candidate_users: list[str],
        start_budget: int,
        max_requests: int | None,
        reserve_budget: int,
    ) -> dict[str, object] | None:
        raise NotImplementedError

    def _try_sqli_auth_bypass_case(
        self,
        target: dict[str, object],
        *,
        url: str,
        case: _AuthBypassCase,
    ) -> dict[str, object] | None:
        raise NotImplementedError

    def _record_auth_bypass_response(
        self,
        response: ProbeResponse,
        *,
        url: str,
        case: _AuthBypassCase,
    ) -> None:
        raise NotImplementedError

    def _handle_successful_auth_bypass(
        self,
        session: ProbeSession,
        *,
        url: str,
        case: _AuthBypassCase,
        response: ProbeResponse,
    ) -> dict[str, object]:
        raise NotImplementedError

    def _register_auth_bypass_proofs(
        self,
        *,
        url: str,
        case: _AuthBypassCase,
        response: ProbeResponse,
        followups: list[ProbeResponse],
    ) -> bool:
        raise NotImplementedError

    def _auth_bypass_budget_exhausted(
        self,
        start_budget: int,
        *,
        max_requests: int | None,
        reserve_budget: int,
    ) -> bool:
        raise NotImplementedError

    def _sqli_auth_followup(
        self,
        session: ProbeSession,
        response: ProbeResponse,
    ) -> tuple[list[ProbeResponse], list[dict[str, object]]]:
        raise NotImplementedError

    def _try_authenticated_uploads(
        self,
        session: ProbeSession,
        forms: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        raise NotImplementedError
