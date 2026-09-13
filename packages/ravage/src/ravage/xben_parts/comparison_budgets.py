"""Exact per-arm resource budgets for paired comparison runs."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Context, Decimal, InvalidOperation, localcontext
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ravage.xben_parts.comparison_semantics import ComparisonSystem

ComparisonBudgetLane = Literal["total", "base", "graph"]

_MAX_MODEL_REQUESTS = 4096
_MAX_TARGET_REQUESTS = 1_000_000
_MAX_WALL_SECONDS = 86_400
_MAX_COST_USD = Decimal(1_000_000)
_MAX_COST_TEXT_CHARS = 100
_MAX_COST_DIGITS = 64
_MAX_COST_ADJUSTED_EXPONENT = 28
_COST_CONTEXT = Context(prec=128)


@dataclass(frozen=True, slots=True)
class IntegerBudgetPartition:
    """Positive base and graph integer lanes under one exact total."""

    total: int
    base: int
    graph: int

    def __post_init__(self) -> None:
        for name, value in (("total", self.total), ("base", self.base), ("graph", self.graph)):
            _positive_integer(value, name=name)
        if self.base + self.graph != self.total:
            message = "base and graph integer budgets must sum exactly to total"
            raise ValueError(message)

    def value_for(self, lane: ComparisonBudgetLane) -> int:
        if lane == "total":
            return self.total
        if lane == "base":
            return self.base
        if lane == "graph":
            return self.graph
        message = "comparison budget lane must be total, base, or graph"
        raise ValueError(message)

    def to_json(self) -> dict[str, int]:
        return {"total": self.total, "base": self.base, "graph": self.graph}


@dataclass(frozen=True, slots=True)
class CostBudgetPartition:
    """Positive exact USD-cost base and graph lanes under one exact total."""

    total: Decimal
    base: Decimal
    graph: Decimal

    def __post_init__(self) -> None:
        total = _exact_cost(self.total)
        base = _exact_cost(self.base)
        graph = _exact_cost(self.graph)
        object.__setattr__(self, "total", total)
        object.__setattr__(self, "base", base)
        object.__setattr__(self, "graph", graph)
        with localcontext(_COST_CONTEXT):
            allocated = base + graph
        if allocated != total:
            message = "base and graph cost budgets must sum exactly to total"
            raise ValueError(message)

    @classmethod
    def build(
        cls,
        *,
        total: int | str | Decimal,
        base: int | str | Decimal,
        graph: int | str | Decimal,
    ) -> CostBudgetPartition:
        return cls(total=_exact_cost(total), base=_exact_cost(base), graph=_exact_cost(graph))

    def value_for(self, lane: ComparisonBudgetLane) -> Decimal:
        if lane == "total":
            return self.total
        if lane == "base":
            return self.base
        if lane == "graph":
            return self.graph
        message = "comparison budget lane must be total, base, or graph"
        raise ValueError(message)

    def to_json(self) -> dict[str, str]:
        return {
            "total": _canonical_cost(self.total),
            "base": _canonical_cost(self.base),
            "graph": _canonical_cost(self.graph),
        }


@dataclass(frozen=True, slots=True)
class ArmResourceBudgets:
    """Measured resources for each scored arm, with reserved Ravage lanes."""

    model_gateway_requests_started: IntegerBudgetPartition
    model_gateway_charged_cost_usd: CostBudgetPartition
    target_gateway_observed_requests: IntegerBudgetPartition
    wall_clock_seconds: IntegerBudgetPartition

    def __post_init__(self) -> None:
        for name, value, maximum in (
            (
                "model gateway requests started",
                self.model_gateway_requests_started,
                _MAX_MODEL_REQUESTS,
            ),
            (
                "target gateway observed requests",
                self.target_gateway_observed_requests,
                _MAX_TARGET_REQUESTS,
            ),
            ("wall-clock seconds", self.wall_clock_seconds, _MAX_WALL_SECONDS),
        ):
            if not isinstance(value, IntegerBudgetPartition):
                message = f"{name} must be an IntegerBudgetPartition"
                raise TypeError(message)
            if value.total > maximum:
                message = f"total {name} cannot exceed {maximum}"
                raise ValueError(message)
        if not isinstance(self.model_gateway_charged_cost_usd, CostBudgetPartition):
            message = "model gateway charged cost must be a CostBudgetPartition"
            raise TypeError(message)

    @classmethod
    def build(  # noqa: PLR0913 - every published resource and lane stays explicit.
        cls,
        *,
        total_model_gateway_requests_started: int,
        base_model_gateway_requests_started: int,
        graph_model_gateway_requests_started: int,
        total_model_gateway_charged_cost_usd: int | str | Decimal,
        base_model_gateway_charged_cost_usd: int | str | Decimal,
        graph_model_gateway_charged_cost_usd: int | str | Decimal,
        total_target_gateway_observed_requests: int,
        base_target_gateway_observed_requests: int,
        graph_target_gateway_observed_requests: int,
        total_wall_clock_seconds: int,
        base_wall_clock_seconds: int,
        graph_wall_clock_seconds: int,
    ) -> ArmResourceBudgets:
        return cls(
            model_gateway_requests_started=IntegerBudgetPartition(
                total=total_model_gateway_requests_started,
                base=base_model_gateway_requests_started,
                graph=graph_model_gateway_requests_started,
            ),
            model_gateway_charged_cost_usd=CostBudgetPartition.build(
                total=total_model_gateway_charged_cost_usd,
                base=base_model_gateway_charged_cost_usd,
                graph=graph_model_gateway_charged_cost_usd,
            ),
            target_gateway_observed_requests=IntegerBudgetPartition(
                total=total_target_gateway_observed_requests,
                base=base_target_gateway_observed_requests,
                graph=graph_target_gateway_observed_requests,
            ),
            wall_clock_seconds=IntegerBudgetPartition(
                total=total_wall_clock_seconds,
                base=base_wall_clock_seconds,
                graph=graph_wall_clock_seconds,
            ),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "model_gateway_requests_started": self.model_gateway_requests_started.to_json(),
            "model_gateway_charged_cost_usd": (self.model_gateway_charged_cost_usd.to_json()),
            "target_gateway_observed_requests": (self.target_gateway_observed_requests.to_json()),
            "wall_clock_seconds": self.wall_clock_seconds.to_json(),
        }

    def for_system(self, system: ComparisonSystem) -> dict[str, object]:
        """Project Ravage's reserved lanes or the reference arm's equivalent total."""
        if system == "ravage":
            return {"base": self._lane_json("base"), "graph": self._lane_json("graph")}
        if system == "reference":
            return {"total": self._lane_json("total")}
        message = "comparison system must be ravage or reference"
        raise ValueError(message)

    def _lane_json(self, lane: ComparisonBudgetLane) -> dict[str, object]:
        return {
            "model_gateway_requests_started": self.model_gateway_requests_started.value_for(lane),
            "model_gateway_charged_cost_usd": _canonical_cost(
                self.model_gateway_charged_cost_usd.value_for(lane)
            ),
            "target_gateway_observed_requests": (
                self.target_gateway_observed_requests.value_for(lane)
            ),
            "wall_clock_seconds": self.wall_clock_seconds.value_for(lane),
        }


def _canonical_cost(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _positive_integer(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"{name} must be an integer"
        raise TypeError(message)
    if value <= 0:
        message = f"{name} must be positive"
        raise ValueError(message)
    return value


def _exact_cost(value: int | str | Decimal) -> Decimal:
    cost = _cost_decimal(value)
    if not cost.is_finite() or not 0 < cost <= _MAX_COST_USD:
        message = "cost must be finite, positive, and within the comparison ceiling"
        raise ValueError(message)
    if len(cost.as_tuple().digits) > _MAX_COST_DIGITS:
        message = "cost has too many significant digits"
        raise ValueError(message)
    if abs(cost.adjusted()) > _MAX_COST_ADJUSTED_EXPONENT:
        message = "cost exponent is outside the supported range"
        raise ValueError(message)
    return cost


def _cost_decimal(value: int | str | Decimal) -> Decimal:
    if isinstance(value, (bool, float)):
        message = "cost must be an exact integer, string, or Decimal"
        raise TypeError(message)
    if isinstance(value, str):
        if value != value.strip() or not value or len(value) > _MAX_COST_TEXT_CHARS:
            message = "cost text is empty, unnormalized, or too long"
            raise ValueError(message)
    elif isinstance(value, int):
        if value <= 0 or value > int(_MAX_COST_USD):
            message = "cost must be positive and within the comparison ceiling"
            raise ValueError(message)
    elif not isinstance(value, Decimal):
        message = "cost must be an exact integer, string, or Decimal"
        raise TypeError(message)
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        message = "cost is not a valid decimal"
        raise ValueError(message) from exc


__all__ = [
    "ArmResourceBudgets",
    "ComparisonBudgetLane",
    "CostBudgetPartition",
    "IntegerBudgetPartition",
]
