from __future__ import annotations

from dataclasses import replace
from decimal import localcontext

import pytest
from ravage.xben_parts.comparison_budgets import (
    ArmResourceBudgets,
    CostBudgetPartition,
    IntegerBudgetPartition,
)


def test_arm_budgets_use_measured_metric_names_and_equal_system_totals() -> None:
    budgets = _budgets()

    assert budgets.to_json() == {
        "model_gateway_requests_started": {"total": 40, "base": 16, "graph": 24},
        "model_gateway_charged_cost_usd": {
            "total": "0.25",
            "base": "0.1",
            "graph": "0.15",
        },
        "target_gateway_observed_requests": {
            "total": 1000,
            "base": 400,
            "graph": 600,
        },
        "wall_clock_seconds": {"total": 600, "base": 240, "graph": 360},
    }
    ravage = budgets.for_system("ravage")
    reference = budgets.for_system("reference")
    assert set(ravage) == {"base", "graph"}
    assert set(reference) == {"total"}
    for metric in reference["total"]:
        if metric == "model_gateway_charged_cost_usd":
            assert reference["total"][metric] == "0.25"
        else:
            assert reference["total"][metric] == (ravage["base"][metric] + ravage["graph"][metric])


def test_decimal_partition_is_exact_under_low_ambient_precision() -> None:
    with localcontext() as context:
        context.prec = 2
        low_precision = CostBudgetPartition.build(
            total="0.25",
            base="0.1234567890123456789",
            graph="0.1265432109876543211",
        )
    with localcontext() as context:
        context.prec = 80
        high_precision = CostBudgetPartition.build(
            total="0.25",
            base="0.1234567890123456789",
            graph="0.1265432109876543211",
        )

    assert low_precision == high_precision
    assert low_precision.to_json() == {
        "total": "0.25",
        "base": "0.1234567890123456789",
        "graph": "0.1265432109876543211",
    }


@pytest.mark.parametrize(
    ("values", "exception", "message"),
    [
        ((3, 1, 1), ValueError, "sum exactly"),
        ((True, 1, 1), TypeError, "must be an integer"),
        ((2, 0, 2), ValueError, "must be positive"),
    ],
)
def test_integer_partitions_reject_invalid_lanes(
    values: tuple[object, object, object],
    exception: type[Exception],
    message: str,
) -> None:
    with pytest.raises(exception, match=message):
        IntegerBudgetPartition(total=values[0], base=values[1], graph=values[2])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("values", "exception", "message"),
    [
        (("1", 0.5, "0.5"), TypeError, "exact integer"),
        (("NaN", "0.5", "0.5"), ValueError, "finite"),
        (("1", "0", "1"), ValueError, "finite, positive"),
        (("1000000.01", "0.01", "1000000"), ValueError, "ceiling"),
    ],
)
def test_decimal_partitions_reject_inexact_or_invalid_lanes(
    values: tuple[object, object, object],
    exception: type[Exception],
    message: str,
) -> None:
    with pytest.raises(exception, match=message):
        CostBudgetPartition.build(  # type: ignore[arg-type]
            total=values[0],
            base=values[1],
            graph=values[2],
        )


def test_near_sum_is_rejected_under_low_ambient_precision() -> None:
    with localcontext() as context:
        context.prec = 2
        with pytest.raises(ValueError, match="sum exactly"):
            CostBudgetPartition.build(total="0.3", base="0.1", graph="0.2001")


@pytest.mark.parametrize(
    ("field", "partition", "message"),
    [
        (
            "model_gateway_requests_started",
            IntegerBudgetPartition(total=4097, base=1, graph=4096),
            "model gateway requests",
        ),
        (
            "target_gateway_observed_requests",
            IntegerBudgetPartition(total=1_000_001, base=1, graph=1_000_000),
            "target gateway observed requests",
        ),
        (
            "wall_clock_seconds",
            IntegerBudgetPartition(total=86_401, base=1, graph=86_400),
            "wall-clock seconds",
        ),
    ],
)
def test_arm_budgets_reject_unbounded_resource_totals(
    field: str,
    partition: IntegerBudgetPartition,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(_budgets(), **{field: partition})


def test_budget_selectors_reject_unknown_lane_or_system() -> None:
    partition = IntegerBudgetPartition(total=3, base=1, graph=2)
    with pytest.raises(ValueError, match="budget lane"):
        partition.value_for("other")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="ravage or reference"):
        _budgets().for_system("other")  # type: ignore[arg-type]


def _budgets() -> ArmResourceBudgets:
    return ArmResourceBudgets.build(
        total_model_gateway_requests_started=40,
        base_model_gateway_requests_started=16,
        graph_model_gateway_requests_started=24,
        total_model_gateway_charged_cost_usd="0.25",
        base_model_gateway_charged_cost_usd="0.10",
        graph_model_gateway_charged_cost_usd="0.15",
        total_target_gateway_observed_requests=1000,
        base_target_gateway_observed_requests=400,
        graph_target_gateway_observed_requests=600,
        total_wall_clock_seconds=600,
        base_wall_clock_seconds=240,
        graph_wall_clock_seconds=360,
    )
