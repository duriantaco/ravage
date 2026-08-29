from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from ravage.agent_core import frontier_shared_runtime
from ravage.agent_core.frontier_shared_runtime import (
    SharedToolRuntime,
    reverify_tool_runtime_cleanup,
)
from ravage.runtime import DockerToolRuntime, ExternalToolRuntime

if TYPE_CHECKING:
    import pytest


def test_persistent_tool_workdir_survives_route_process_shutdown(tmp_path: Path) -> None:
    workdir = tmp_path / "tool-workspace"
    first_inner = ExternalToolRuntime()
    first = SharedToolRuntime(first_inner, persistent_workdir=workdir)

    assert first_inner.workdir == workdir
    (workdir / "worker-note.txt").write_text("preserved route state", encoding="utf-8")
    first.close()
    first.shutdown()

    assert (workdir / "worker-note.txt").read_text(encoding="utf-8") == ("preserved route state")

    second_inner = ExternalToolRuntime()
    second = SharedToolRuntime(second_inner, persistent_workdir=workdir)

    assert second_inner.workdir == workdir
    assert (second_inner.workdir / "worker-note.txt").exists()
    second.shutdown()


def test_injected_runtime_keeps_normal_close_semantics() -> None:
    inner = ExternalToolRuntime()
    original_workdir = inner.workdir
    shared = SharedToolRuntime(inner)

    shared.close()
    assert original_workdir.exists()

    shared.shutdown()
    assert not original_workdir.exists()
    shared.shutdown()


def test_route_cleanup_reverification_refreshes_the_scoped_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path = tmp_path / "tool-network.json"
    scoped_network = SimpleNamespace(
        session_id="route-timeout-session",
        evidence_path=evidence_path,
        cleanup_evidence={"cleanup": {"verified": False}},
    )
    docker_runtime = object.__new__(DockerToolRuntime)
    docker_runtime.scoped_network = scoped_network
    shared = SharedToolRuntime(docker_runtime)
    calls: list[tuple[str, Path]] = []
    verified = {"cleanup": {"status": "verified", "verified": True}}

    def fake_cleanup(
        session_id: str,
        *,
        evidence_path: str | Path | None = None,
    ) -> dict[str, object]:
        assert isinstance(evidence_path, Path)
        calls.append((session_id, evidence_path))
        return verified

    monkeypatch.setattr(
        frontier_shared_runtime,
        "cleanup_scoped_network_session",
        fake_cleanup,
    )

    receipts = reverify_tool_runtime_cleanup(shared)

    assert calls == [("route-timeout-session", evidence_path)]
    assert receipts == (verified,)
    assert scoped_network.cleanup_evidence == verified
