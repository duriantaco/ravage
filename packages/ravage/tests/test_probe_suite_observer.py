from __future__ import annotations

import pytest
from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite import run_builtin_probe
from ravage.web_core.http_probe import ProbeSession


def test_run_builtin_probe_rejects_observer_with_supplied_session() -> None:
    target_url = "http://127.0.0.1:8765/"
    session = ProbeSession(target_url)

    with pytest.raises(
        ValueError,
        match="traffic_observer cannot be supplied with an existing session",
    ):
        run_builtin_probe(
            "surface_map",
            target_url=target_url,
            state=AgentState(),
            session=session,
            traffic_observer=lambda _event: None,
        )
