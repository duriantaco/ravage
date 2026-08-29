from __future__ import annotations

from ravage.web_core.http_probe import ProbeSession


def _short_command_session(session: ProbeSession) -> ProbeSession:
    return session.fork(timeout_seconds=min(session.timeout_seconds, 3))
