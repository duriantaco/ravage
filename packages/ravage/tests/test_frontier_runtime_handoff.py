from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from ravage.agent_core import frontier_runtime_handoff
from ravage.agent_core.ai_agent import AIWebAgentSettings
from ravage.agent_core.frontier_runtime_handoff import (
    cleanup_autonomous_runtime_sessions,
    prepare_frontier_runtime,
)
from ravage.agent_core.frontier_shared_runtime import (
    SharedToolRuntime,
    shared_tool_session_id,
)
from ravage.runtime import DockerToolRuntime, FakeToolRuntime

if TYPE_CHECKING:
    import pytest


ENGAGEMENT_ID = "99999999-9999-4999-9999-999999999999"


class ClosingRuntime(FakeToolRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


class FakeScopedNetwork:
    def __init__(self, *, evidence_path: Path) -> None:
        self.session_id = shared_tool_session_id(ENGAGEMENT_ID, role="base")
        self.evidence_path = evidence_path
        self.cleanup_evidence: dict[str, object] | None = None
        self.close_count = 0

    def close(self) -> dict[str, object]:
        self.close_count += 1
        receipt = _cleanup_receipt(self.session_id)
        self.cleanup_evidence = receipt
        return receipt


def _factory_base_runtime(tmp_path: Path) -> tuple[SharedToolRuntime, FakeScopedNetwork]:
    scoped_network = FakeScopedNetwork(evidence_path=tmp_path / "tool-network.json")
    inner = object.__new__(DockerToolRuntime)
    inner.scoped_network = scoped_network
    runtime = SharedToolRuntime(
        inner,
        factory_owned=True,
        session_role="base",
    )
    runtime.persistent_workdir = tmp_path / "autonomous-route" / "tool-workspace"
    runtime.persistent_workdir.mkdir(parents=True)
    return runtime, scoped_network


def _cleanup_receipt(
    session_id: str,
    *,
    verified: bool = True,
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "setup": {"status": "succeeded"},
        "cleanup": {
            "status": "verified" if verified else "error",
            "verified": verified,
            "recorded_at": "2026-07-22T00:00:00+00:00",
            "containers_before": ["old-tool"],
            "networks_before": ["old-network"],
            "containers_after": [] if verified else ["old-tool"],
            "networks_after": [],
            "errors": [] if verified else ["still present"],
            "commands": [{"stdout": "must-not-enter-handoff-receipt"}],
        },
    }


def test_verified_handoff_rotates_session_and_preserves_tool_workdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path = tmp_path / "tool-network.json"
    evidence_path.write_text(
        json.dumps(
            {
                "session_id": shared_tool_session_id(ENGAGEMENT_ID, role="base"),
                "setup": {"status": "succeeded"},
                "cleanup": {"status": "verified", "verified": True},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RAVAGE_TOOL_NETWORK_EVIDENCE_PATH", str(evidence_path))
    base_runtime, scoped_network = _factory_base_runtime(tmp_path)
    frontier_inner = ClosingRuntime()
    frontier_runtime = SharedToolRuntime(
        frontier_inner,
        persistent_workdir=base_runtime.persistent_workdir,
        factory_owned=True,
        session_role="frontier",
    )
    monkeypatch.setattr(
        frontier_runtime_handoff,
        "reverify_tool_runtime_cleanup",
        lambda _runtime: (_cleanup_receipt(scoped_network.session_id),),
    )

    def make_runtime(*args: object, **kwargs: object) -> SharedToolRuntime:
        del args
        assert kwargs["session_role"] == "frontier"
        placeholder = json.loads(evidence_path.read_text(encoding="utf-8"))
        assert placeholder["session_id"] == shared_tool_session_id(
            ENGAGEMENT_ID,
            role="frontier",
        )
        assert placeholder["setup"]["status"] == "unknown"
        assert "cleanup" not in placeholder
        return frontier_runtime

    monkeypatch.setattr(
        frontier_runtime_handoff,
        "make_shared_tool_runtime",
        make_runtime,
    )

    result = prepare_frontier_runtime(
        settings=AIWebAgentSettings(
            workspace_dir=tmp_path,
            tool_runtime_mode="docker",
        ),
        brief=SimpleNamespace(engagement_id=ENGAGEMENT_ID),
        workspace_dir=tmp_path / "autonomous-route",
        base_runtime=base_runtime,
    )

    assert result.verified is True
    assert result.rotated is True
    assert result.runtime is frontier_runtime
    assert result.runtime is not base_runtime
    assert result.runtime.persistent_workdir == base_runtime.persistent_workdir
    assert scoped_network.close_count == 1
    receipt_text = (tmp_path / "autonomous-route" / "runtime-handoff.json").read_text(
        encoding="utf-8"
    )
    receipt = json.loads(receipt_text)
    assert receipt["status"] == "frontier_runtime_created"
    assert receipt["persistent_workdir_preserved"] is True
    assert "commands" not in receipt_text
    assert "must-not-enter-handoff-receipt" not in receipt_text


def test_unverified_base_cleanup_blocks_route_runtime_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_runtime, scoped_network = _factory_base_runtime(tmp_path)
    monkeypatch.setattr(
        frontier_runtime_handoff,
        "reverify_tool_runtime_cleanup",
        lambda _runtime: (_cleanup_receipt(scoped_network.session_id, verified=False),),
    )

    def unexpected_runtime(*args: object, **kwargs: object) -> SharedToolRuntime:
        del args, kwargs
        message = "frontier runtime must not be created"
        raise AssertionError(message)

    monkeypatch.setattr(
        frontier_runtime_handoff,
        "make_shared_tool_runtime",
        unexpected_runtime,
    )

    result = prepare_frontier_runtime(
        settings=AIWebAgentSettings(
            workspace_dir=tmp_path,
            tool_runtime_mode="docker",
        ),
        brief=SimpleNamespace(engagement_id=ENGAGEMENT_ID),
        workspace_dir=tmp_path / "autonomous-route",
        base_runtime=base_runtime,
    )

    assert result.verified is False
    assert result.runtime is None
    assert result.reason == "route_handoff_hygiene_unverified"
    receipt = json.loads(
        (tmp_path / "autonomous-route" / "runtime-handoff.json").read_text(encoding="utf-8")
    )
    assert receipt["status"] == "blocked"
    assert receipt["base_cleanup"][0]["containers_after"] == ["old-tool"]


def test_parent_cleanup_covers_base_and_frontier_session_generations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path = tmp_path / "tool-network.json"
    base_session = shared_tool_session_id(ENGAGEMENT_ID, role="base")
    frontier_session = shared_tool_session_id(ENGAGEMENT_ID, role="frontier")
    evidence_path.write_text(
        json.dumps(
            {
                "session_id": frontier_session,
                "setup": {"status": "succeeded"},
                "cleanup": {"status": "verified", "verified": True},
            }
        ),
        encoding="utf-8",
    )
    calls: list[tuple[str, Path | None]] = []

    def cleanup(
        session_id: str,
        *,
        evidence_path: str | Path | None = None,
    ) -> dict[str, object]:
        path = Path(evidence_path) if evidence_path is not None else None
        calls.append((session_id, path))
        receipt = _cleanup_receipt(session_id)
        if path is not None:
            receipt["setup"] = {"status": "succeeded"}
        return receipt

    monkeypatch.setattr(
        frontier_runtime_handoff,
        "cleanup_scoped_network_session",
        cleanup,
    )

    result = cleanup_autonomous_runtime_sessions(
        ENGAGEMENT_ID,
        evidence_path=evidence_path,
    )

    assert calls == [(base_session, None), (frontier_session, evidence_path)]
    assert result["autonomous_route_cleanup"]["verified"] is True
    summaries = result["autonomous_route_cleanup"]["sessions"]
    assert [item["session_id"] for item in summaries] == [
        base_session,
        frontier_session,
    ]


def test_parent_cleanup_marks_any_unclean_generation_unverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path = tmp_path / "tool-network.json"
    base_session = shared_tool_session_id(ENGAGEMENT_ID, role="base")
    frontier_session = shared_tool_session_id(ENGAGEMENT_ID, role="frontier")
    evidence_path.write_text(
        json.dumps(
            {
                "session_id": frontier_session,
                "setup": {"status": "succeeded"},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        frontier_runtime_handoff,
        "cleanup_scoped_network_session",
        lambda session_id, **_kwargs: _cleanup_receipt(
            session_id,
            verified=session_id != base_session,
        ),
    )

    result = cleanup_autonomous_runtime_sessions(
        ENGAGEMENT_ID,
        evidence_path=evidence_path,
    )

    assert result["autonomous_route_cleanup"]["status"] == "error"
    assert result["autonomous_route_cleanup"]["verified"] is False
