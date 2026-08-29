# ruff: noqa: PLR0913

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.capability_gaps import (
    CapabilityGapBacklog,
    CapabilityGapError,
    build_capability_gap_backlog,
)
from ravage.agent_core.autonomous_graph.learning import RouteLesson

if TYPE_CHECKING:
    from pathlib import Path

MINIMUM_FAILED_RUNS = 2
TOTAL_TARGET_REQUESTS = 8


def _lesson(
    source: str,
    *,
    sequence: int = 0,
    progress: bool = False,
    proof: bool = False,
    loop_stopped: bool = True,
    target_requests: int = 3,
) -> RouteLesson:
    verification = (
        {
            "hypothesis_fingerprint": "hypothesis:" + "b" * 64,
            "agent_spec_fingerprint": "agent-spec:" + "c" * 64,
            "belief_revision_id": "belief:" + "d" * 64,
            "belief_disposition": "confirmed" if proof else "supported",
            "executor_receipt_digest": "executor-receipt:" + "e" * 64,
        }
        if progress or proof
        else {}
    )
    return RouteLesson.create(
        source_digest=source,
        sequence=sequence,
        family="template_injection",
        probe="bounded_context_closure",
        dimension="context_variable_matrix",
        outcome="proof_confirmed" if proof else "bounded_exhaustion",
        material_progress=progress or proof,
        proof_confirmed=proof,
        loop_stopped=loop_stopped,
        target_requests=target_requests,
        **verification,
    )


def test_gap_requires_repeated_independent_failure_receipts() -> None:
    one_run = build_capability_gap_backlog((_lesson("route-source:one"),))
    repeated = build_capability_gap_backlog(
        (
            _lesson("route-source:one"),
            _lesson("route-source:two", target_requests=5),
        )
    )

    assert one_run.gaps == ()
    assert len(repeated.gaps) == 1
    gap = repeated.gaps[0]
    assert gap.status == "needs_specialist"
    assert gap.independent_runs == MINIMUM_FAILED_RUNS
    assert gap.failed_runs == MINIMUM_FAILED_RUNS
    assert gap.target_requests == TOTAL_TARGET_REQUESTS
    assert gap.priority > 0


def test_gap_distinguishes_closure_and_reliability_deficits() -> None:
    closure = build_capability_gap_backlog(
        (
            _lesson("route-source:one", progress=True),
            _lesson("route-source:two"),
            _lesson("route-source:three"),
        )
    )
    reliability = build_capability_gap_backlog(
        (
            _lesson("route-source:one", proof=True, loop_stopped=False),
            _lesson("route-source:two"),
            _lesson("route-source:three"),
        )
    )

    assert closure.gaps[0].status == "needs_closure"
    assert reliability.gaps[0].status == "needs_reliability"


def test_backlog_is_secret_free_atomic_and_tamper_evident(tmp_path: Path) -> None:
    backlog = build_capability_gap_backlog(
        (
            _lesson("route-source:" + "a" * 64),
            _lesson("route-source:" + "b" * 64),
        )
    )
    path = tmp_path / "capability-backlog.json"
    backlog.save(path)
    encoded = path.read_text(encoding="utf-8")

    assert CapabilityGapBacklog.load(path) == backlog
    assert "target.example" not in encoded
    assert "proof-secret" not in encoded

    tampered = json.loads(encoded)
    tampered["gaps"][0]["priority"] += 1
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(CapabilityGapError, match="ID mismatch"):
        CapabilityGapBacklog.load(path)
