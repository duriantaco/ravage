from __future__ import annotations

from typing import Callable, TypeVar

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeSession

_ResultT = TypeVar("_ResultT")


def probe_ssti_fingerprint(
    session: ProbeSession,
    state: AgentState,
    result_cls: Callable[..., _ResultT],
    *,
    probe_name: str,
) -> _ResultT:
    from ravage.probes.specialists.ssti import (
        probe_ssti_fingerprint as _probe_ssti_fingerprint,
    )

    return _probe_ssti_fingerprint(
        session,
        state,
        result_cls,
        probe_name=probe_name,
    )


__all__ = ["probe_ssti_fingerprint"]
