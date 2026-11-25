from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ravage.live_dashboard_view import _metrics, _viewer_run_block

if TYPE_CHECKING:
    from typing import Any


def _start(request_id: str = "one", *, row_id: int = 1) -> dict[str, Any]:
    return {
        "id": row_id,
        "action": "model_request_started",
        "payload": {"model_request_id": request_id},
    }


def _reply(
    cost: object, *, known: object = True, row_id: int = 2, request_id: str = "one"
) -> dict[str, Any]:
    return {
        "id": row_id,
        "action": "model_reply_received",
        "cost_usd": cost,
        "payload": {
            "cost_known": known, "usage_reported": True, "model_request_id": request_id,
        },
    }


@pytest.mark.parametrize("rows", [[], [{"id": 1, "action": "run_started", "cost_usd": 0}]])
def test_absent_model_cost_is_unknown(rows: list[dict[str, Any]]) -> None:
    metrics = _metrics([], rows, [], [])
    assert metrics["cost_usd_total"] is None
    assert metrics["cost_status"] == "unknown"


@pytest.mark.parametrize("cost", [None, False, -1, float("nan"), float("inf")])
def test_invalid_model_cost_is_unknown(cost: object) -> None:
    metrics = _metrics([], [_start(), _reply(cost)], [], [])
    assert metrics["cost_usd_total"] is None
    assert metrics["cost_status"] == "unknown"


def test_unknown_zero_receipt_does_not_claim_a_free_model_call() -> None:
    metrics = _metrics([], [_start(), _reply(0, known=False)], [], [])
    assert metrics["cost_usd_total"] is None
    assert metrics["cost_status"] == "unknown"
    known = _metrics([], [_start(), _reply(0)], [], [])
    assert known["cost_usd_total"] == 0
    assert known["cost_status"] == "known"


def test_mixed_receipts_preserve_only_known_charges_as_a_partial_subtotal() -> None:
    rows = [
        _start(), _reply(1.25), _start("two", row_id=3),
        _reply(99, known=False, row_id=4, request_id="two"),
    ]
    metrics = _metrics([], rows, [], [])
    assert metrics["cost_usd_total"] == 1.25
    assert metrics["cost_status"] == "partial"


def test_bounded_audit_tail_does_not_claim_a_whole_run_total() -> None:
    metrics = _metrics([], [_start(row_id=201), _reply(1.25, row_id=202)], [], [])
    assert metrics["cost_usd_total"] == 1.25
    assert metrics["cost_status"] == "partial"


def test_pending_request_keeps_the_recorded_cost_partial() -> None:
    rows = [
        _start(),
        _reply(1.25),
        _start("pending", row_id=3),
    ]
    metrics = _metrics([], rows, [], [])
    assert metrics["cost_status"] == "partial"
    run = _viewer_run_block(
        events=[],
        audit_rows=rows,
        working_state={},
        lab={},
        metrics=metrics,
        manifest=None,
        mode="replay",
        target_url="",
    )
    assert run["cost_usd"] == 1.25
    assert run["cost_status"] == "partial"


@pytest.mark.parametrize("mutation", ["missing_id", "orphan", "duplicate", "missing_usage", "ordering"])
def test_invalid_receipts_do_not_create_known_cost(mutation: str) -> None:
    start, reply = _start(), _reply(0.25)
    rows = [start, reply]
    if mutation == "missing_id":
        start["payload"].pop("model_request_id")
        reply["payload"].pop("model_request_id")
    elif mutation == "orphan":
        reply["payload"]["model_request_id"] = "other"
    elif mutation == "duplicate":
        rows.append(dict(reply))
    elif mutation == "ordering":
        rows.reverse()
    else:
        reply["payload"]["usage_reported"] = False
    metrics = _metrics([], rows, [], [])
    assert metrics["cost_usd_total"] is None
    assert metrics["cost_status"] == "unknown"
