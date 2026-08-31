# Bounded probe execution is isolated to the autonomous graph route.

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.template_form_closure import (
    PROBE_NAME as TEMPLATE_FORM_CLOSURE_PROBE_NAME,
)
from ravage.agent_core.autonomous_graph.template_form_closure import (
    probe_template_form_closure,
)
from ravage.probe_suite import (
    _canonical_host_default_headers,
    _probe_handlers,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.web_core.http_probe import (
    MAX_BODY_BYTES,
    ProbeNetworkContext,
    ProbeResponse,
    ProbeSession,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from ravage.agent_core.agent_state import AgentState

_BUDGET_EXHAUSTED = "graph_target_request_budget_exhausted"


@dataclass
class _SharedTargetRequestBudget:
    limit: int
    used: int = 0
    denied: int = 0

    def __post_init__(self) -> None:
        if self.limit <= 0:
            message = "graph target request limit must be greater than zero"
            raise ValueError(message)
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            if self.used >= self.limit:
                self.denied += 1
                return False
            self.used += 1
            return True

    def receipt(self) -> dict[str, object]:
        with self._lock:
            return {
                "limit": self.limit,
                "used": self.used,
                "denied": self.denied,
                "exhausted": self.used >= self.limit,
                "scope": "autonomous_graph_run_probe_only",
            }


class BoundedGraphProbeSession(ProbeSession):
    """ProbeSession with one request counter shared by every forked identity."""

    def __init__(  # noqa: PLR0913
        self,
        target_url: str,
        *,
        timeout_seconds: int,
        request_budget: _SharedTargetRequestBudget,
        default_headers: dict[str, str] | None = None,
        allow_remote_target: bool = False,
        in_scope: Sequence[str] | None = None,
        out_of_scope: Sequence[str] = (),
        max_rps: float | None = None,
        resolver: Callable[[str, int], Sequence[str]] | None = None,
        network_context: ProbeNetworkContext | None = None,
        _request_pacer: object | None = None,
        _dns_pins: dict[tuple[str, int], tuple[str, ...]] | None = None,
        _dns_pin_lock: threading.Lock | None = None,
        traffic_observer: Callable[[dict[str, object]], None] | None = None,
        traffic_policy_reference: dict[str, object] | None = None,
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        super().__init__(
            target_url,
            timeout_seconds=timeout_seconds,
            default_headers=default_headers,
            allow_remote_target=allow_remote_target,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            max_rps=max_rps,
            resolver=None if network_context is not None else resolver,
            network_context=network_context,
            _request_pacer=_request_pacer,  # type: ignore[arg-type]
            _dns_pins=None if network_context is not None else _dns_pins,
            _dns_pin_lock=None if network_context is not None else _dns_pin_lock,
            traffic_observer=traffic_observer,
            traffic_policy_reference=traffic_policy_reference,
            max_body_bytes=max_body_bytes,
        )
        self._request_budget = request_budget

    def fork(
        self,
        *,
        timeout_seconds: int | None = None,
        inherit_identity: bool | None = None,
        max_body_bytes: int | None = None,
    ) -> BoundedGraphProbeSession:
        del inherit_identity
        return type(self)(
            self.target_url,
            timeout_seconds=(self.timeout_seconds if timeout_seconds is None else timeout_seconds),
            request_budget=self._request_budget,
            default_headers=self.default_headers,
            allow_remote_target=self.allow_remote_target,
            in_scope=self.scope_in_scope,
            out_of_scope=self.scope_out_of_scope,
            max_rps=self.max_rps,
            network_context=self.network_context,
            _request_pacer=self._request_pacer,
            traffic_observer=self._traffic_observer,
            traffic_policy_reference=self.traffic_policy_reference(),
            max_body_bytes=self.max_body_bytes if max_body_bytes is None else max_body_bytes,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        max_body_bytes: int | None = None,
    ) -> ProbeResponse:
        rewritten = self._rewrite_canonical_url(url)
        absolute = self.absolute(rewritten)
        if self.in_scope(absolute) and not self._request_budget.acquire():
            response = ProbeResponse(
                method=method.upper(),
                url=absolute,
                status=None,
                final_url=absolute,
                elapsed_ms=0,
                error=_BUDGET_EXHAUSTED,
            )
            self._observe_traffic(
                response,
                disposition="blocked",
                reason=response.error,
            )
            return response
        if timeout_seconds is None:
            if max_body_bytes is None:
                return super().request(method, rewritten, data=data, headers=headers)
            return super().request(
                method,
                rewritten,
                data=data,
                headers=headers,
                max_body_bytes=max_body_bytes,
            )
        if max_body_bytes is None:
            return super().request(
                method,
                rewritten,
                data=data,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
        return super().request(
            method,
            rewritten,
            data=data,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_body_bytes=max_body_bytes,
        )


def run_bounded_graph_probe(  # noqa: PLR0913 - explicit subprocess contract.
    probe: str,
    *,
    target_url: str,
    state: AgentState,
    timeout_seconds: int,
    target_request_limit: int,
    traffic_policy_reference: dict[str, object] | None = None,
) -> tuple[ProbeRunResult, dict[str, object]]:
    budget = _SharedTargetRequestBudget(target_request_limit)
    raw_in_scope = state.surface.get("scope_in_scope")
    raw_out_of_scope = state.surface.get("scope_out_of_scope")
    in_scope = [str(item) for item in raw_in_scope] if isinstance(raw_in_scope, list) else None
    out_of_scope = (
        [str(item) for item in raw_out_of_scope] if isinstance(raw_out_of_scope, list) else []
    )
    raw_max_rps = state.surface.get("scope_max_rps")
    max_rps = int(raw_max_rps) if isinstance(raw_max_rps, int) else None
    session = BoundedGraphProbeSession(
        target_url,
        timeout_seconds=timeout_seconds,
        request_budget=budget,
        default_headers=_canonical_host_default_headers(state),
        allow_remote_target=state.surface.get("allow_remote_target") is True,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        max_rps=max_rps,
        traffic_policy_reference=traffic_policy_reference,
    )
    handler = _graph_probe_handlers().get(probe)
    if handler is None:
        result = ProbeRunResult(
            ok=False,
            probe=probe,
            summary=f"unknown probe: {probe}",
            errors=[f"unknown probe: {probe}"],
        )
    else:
        result = handler(session, state)
    receipt = budget.receipt()
    if receipt["denied"]:
        result = ProbeRunResult(
            ok=result.ok,
            probe=result.probe,
            summary=(
                f"{result.summary}; graph target-request grant exhausted "
                f"at {receipt['used']}/{receipt['limit']}"
            ),
            findings=result.findings,
            requests=result.requests,
            errors=[
                *result.errors,
                json.dumps(
                    {
                        "error": _BUDGET_EXHAUSTED,
                        **receipt,
                    },
                    sort_keys=True,
                ),
            ],
        )
    return result, receipt


def _graph_probe_handlers() -> dict[str, Callable[[ProbeSession, AgentState], ProbeRunResult]]:
    handlers = dict(_probe_handlers())
    handlers[TEMPLATE_FORM_CLOSURE_PROBE_NAME] = probe_template_form_closure
    return handlers


__all__ = [
    "BoundedGraphProbeSession",
    "_graph_probe_handlers",
    "run_bounded_graph_probe",
]
