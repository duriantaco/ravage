from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ravage.agent_core.frontier_route import FrontierObjective

_SQL_FAMILY = "sql_injection"
_CONFIRMED_PREFIX = "confirmed_primitive:"
_LOW_NAMES = frozenset({"lo", "low", "lower"})
_MID_NAMES = frozenset({"mid", "middle", "pivot"})
_STRICT_GREATER = re.compile(r"(?<![<>=!])>(?!=)")


@dataclass(frozen=True)
class ExtractorCorrectnessIssue:
    code: str
    functions: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {"code": self.code, "functions": list(self.functions)}


def detect_extractor_correctness_issue(
    objective: FrontierObjective,
    action: Mapping[str, object],
) -> ExtractorCorrectnessIssue | None:
    """Reject a strict-greater binary search that returns the lower boundary."""
    if (
        objective.family != _SQL_FAMILY
        or not objective.payload_class.startswith(_CONFIRMED_PREFIX)
        or str(action.get("action") or "") != "run_python"
    ):
        return None
    source = str(action.get("code") or "")
    if not source or not _STRICT_GREATER.search(source):
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    unsafe = tuple(
        function.name
        for function in _functions(tree)
        if _has_strict_greater_search(function, source)
        and _uses_unadjusted_lower_boundary(function)
    )
    if not unsafe:
        return None
    return ExtractorCorrectnessIssue(
        code="strict_greater_off_by_one",
        functions=unsafe[:8],
    )


def extractor_correctness_constraints(
    objective: FrontierObjective,
) -> tuple[str, ...]:
    if objective.family != _SQL_FAMILY or not objective.payload_class.startswith(_CONFIRMED_PREFIX):
        return ()
    return (
        (
            "For a strict value > midpoint oracle, the binary-search lower boundary is "
            "one below the recovered exact value; return lower + 1, not lower."
        ),
        (
            "Before replaying an extracted value, bracket-check its length and characters "
            "against the target oracle, then require a target-observed success transition."
        ),
    )


def extractor_correctness_message(
    objective: FrontierObjective,
    issue: ExtractorCorrectnessIssue,
) -> str:
    functions = ", ".join(issue.functions) or "the extractor"
    return (
        "COORDINATOR_EXTRACTOR_CORRECTNESS_GATE\n"
        "Action not executed. The proposed strict-greater binary search returns its "
        f"unadjusted lower boundary in {functions}. For a predicate value > midpoint, "
        "that boundary is one below the exact value: recover lower + 1 (including "
        "length), then bracket-check the result with target-observed predicates before "
        f"replay on endpoint={objective.endpoint}. The rejected model request remains "
        "charged; global request, worker, scope, and cost limits remain enforced."
    )


def _functions(tree: ast.AST) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    return tuple(
        node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _has_strict_greater_search(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
) -> bool:
    function_source = ast.get_source_segment(source, function) or ""
    if not _STRICT_GREATER.search(function_source):
        return False
    if not any(
        marker in function_source.lower() for marker in ("oracle(", "eval_condition(", "condition(")
    ):
        return False
    assigned_low_from_mid = False
    assigned_high_from_mid_minus_one = False
    for node in _nodes_without_nested_functions(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        target, value = _single_assignment(node)
        if target is None or value is None:
            continue
        if target.id in _LOW_NAMES and _name_in(value, _MID_NAMES):
            assigned_low_from_mid = True
        if (
            target.id in {"hi", "high", "upper"}
            and isinstance(value, ast.BinOp)
            and isinstance(value.op, ast.Sub)
            and _name_in(value.left, _MID_NAMES)
            and isinstance(value.right, ast.Constant)
            and value.right.value == 1
        ):
            assigned_high_from_mid_minus_one = True
    return assigned_low_from_mid and assigned_high_from_mid_minus_one


def _uses_unadjusted_lower_boundary(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    for node in _nodes_without_nested_functions(function):
        if isinstance(node, ast.Return) and _is_unadjusted_lower(node.value):
            return True
        if isinstance(node, ast.Call) and _is_chr_of_lower(node):
            return True
    return False


def _nodes_without_nested_functions(function: ast.AST) -> tuple[ast.AST, ...]:
    nodes: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(function))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        nodes.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return tuple(nodes)


def _single_assignment(
    node: ast.Assign | ast.AnnAssign,
) -> tuple[ast.Name | None, ast.expr | None]:
    if isinstance(node, ast.AnnAssign):
        target = node.target
        value = node.value
    elif len(node.targets) == 1:
        target = node.targets[0]
        value = node.value
    else:
        return None, None
    return (target if isinstance(target, ast.Name) else None), value


def _name_in(node: ast.AST, names: frozenset[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in names


def _is_unadjusted_lower(node: ast.expr | None) -> bool:
    if _name_in(node, _LOW_NAMES):
        return True
    return isinstance(node, ast.Call) and _is_chr_of_lower(node)


def _is_chr_of_lower(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Name)
        and node.func.id == "chr"
        and len(node.args) == 1
        and _name_in(node.args[0], _LOW_NAMES)
    )


__all__ = [
    "ExtractorCorrectnessIssue",
    "detect_extractor_correctness_issue",
    "extractor_correctness_constraints",
    "extractor_correctness_message",
]
