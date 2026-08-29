from __future__ import annotations

from typing import Callable, TypeVar

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeSession

_ResultT = TypeVar("_ResultT")


def probe_idor_boundary(
    session: ProbeSession,
    state: AgentState,
    result_cls: Callable[..., _ResultT],
) -> _ResultT:
    from ravage.probes.specialists.idor import probe_idor_boundary as _probe_idor_boundary

    return _probe_idor_boundary(session, state, result_cls)


__all__ = ["probe_idor_boundary"]
