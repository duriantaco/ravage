"""Score structural route authorization without executing source or sending traffic."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal, cast

from ravage.agent_core.source_context import SourceContextExecutor
from ravage.agent_core.source_navigation import build_source_navigation_policy
from ravage.repository_context import ContextLimits, capture_repository

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "packages/ravage/tests/fixtures/source_navigation_eval/cases.json"
ROUTE_FIELDS = 2
type Route = tuple[str, str]
type Category = Literal["supported", "negative", "unsupported"]


@dataclass(frozen=True)
class Case:
    name: str
    framework: str
    category: Category
    description: str
    files: dict[str, str]
    expected: frozenset[Route]
    forbidden: frozenset[Route]
    max_file_bytes: int = 512 * 1024


def _routes(value: object) -> frozenset[Route]:
    if not isinstance(value, list) or any(
        not isinstance(row, list)
        or len(row) != ROUTE_FIELDS
        or row[0] not in {"GET", "HEAD", "OPTIONS"}
        or not isinstance(row[1], str)
        or not row[1].startswith("/")
        for row in value
    ):
        message = "routes must be [method, relative path] pairs"
        raise ValueError(message)
    pairs = frozenset((row[0], row[1]) for row in value)
    if len(pairs) != len(value):
        message = "duplicate route labels"
        raise ValueError(message)
    return pairs


def load_cases(path: Path = MANIFEST) -> tuple[Case, ...]:
    """Read manually labelled source text; labels never come from the analyzer."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "ravage.source-navigation-corpus.v1":
        message = "unsupported source navigation corpus"
        raise ValueError(message)
    cases: list[Case] = []
    for row in document["cases"]:
        category = row["category"]
        if category not in {"supported", "negative", "unsupported"}:
            message = "unknown corpus category"
            raise ValueError(message)
        files = row["files"]
        if (
            not isinstance(files, dict)
            or not files
            or any(
                not isinstance(name, str)
                or not Path(name).parts
                or Path(name).is_absolute()
                or ".." in Path(name).parts
                or not isinstance(source, str)
                for name, source in files.items()
            )
        ):
            message = "fixture files must be relative paths with text contents"
            raise ValueError(message)
        expected = _routes(row["expected_routes"])
        forbidden = _routes(row["forbidden_routes"])
        if expected & forbidden or (category == "supported") != bool(expected):
            message = "route labels contradict their category"
            raise ValueError(message)
        cases.append(
            Case(
                name=row["id"],
                framework=row["framework"],
                category=category,
                description=row["description"],
                files=files,
                expected=expected,
                forbidden=forbidden,
                max_file_bytes=row.get("max_file_bytes", 512 * 1024),
            )
        )
    if not cases or len({case.name for case in cases}) != len(cases):
        message = "corpus must contain unique cases"
        raise ValueError(message)
    return tuple(cases)


def materialize(case: Case, root: Path) -> None:
    """Write only the supplied fixture strings into a caller-owned temporary directory."""
    for name, source in case.files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def score_routes(expected: frozenset[Route], actual: frozenset[Route]) -> dict[str, object]:
    """Report exact-set errors; a high route count alone is not success."""
    return {
        "true_positives": len(expected & actual),
        "false_negatives": len(expected - actual),
        "false_positives": len(actual - expected),
        "missed_routes": sorted(expected - actual),
        "unexpected_routes": sorted(actual - expected),
    }


def evaluate_case(case: Case, *, reverse: bool = False) -> dict[str, object]:
    """Supply complete bounded excerpts in both orders to test inventory and provenance."""
    with TemporaryDirectory(prefix="ravage-route-corpus-") as temporary:
        root = Path(temporary)
        materialize(case, root)
        context = capture_repository(root, limits=ContextLimits(max_file_bytes=case.max_file_bytes))
        policy = build_source_navigation_policy(context)
        evidence = policy.begin_evidence(require_task=True)
        executor = SourceContextExecutor(context)
        errors: list[str] = []
        for source in sorted(context.files, key=lambda item: item.path, reverse=reverse):
            for start in range(1, len(source.text.splitlines()) + 1, 80):
                execution = executor.execute(
                    {
                        "action": "source_context",
                        "task_id": "surface-map",
                        "operation": "excerpt",
                        "args": {"path": source.path, "start_line": start, "end_line": start + 79},
                    }
                )
                if not execution.ok or not evidence.observe(
                    execution.observation, task_id="surface-map"
                ):
                    errors.append(f"read failed: {source.path}:{start}")
                    break
        actual = frozenset(evidence.authorized_http_routes())
        score = score_routes(case.expected, actual)
        # Check the action gate too: advertised routes and usable routes must agree.
        denied_expected = []
        accepted_forbidden = []
        for method, path in case.expected | case.forbidden:
            permitted = evidence.permits_http_action(
                {
                    "action": "http_request",
                    "task_id": "surface-map",
                    "method": method,
                    "path": path,
                }
            )
            if (method, path) in case.expected and not permitted:
                denied_expected.append((method, path))
            if (method, path) in case.forbidden and permitted:
                accepted_forbidden.append((method, path))
        return {
            "id": case.name,
            "framework": case.framework,
            "category": case.category,
            "description": case.description,
            "read_order": "reverse" if reverse else "forward",
            "snapshot_id": context.snapshot_id,
            "expected_routes": sorted(case.expected),
            "authorized_routes": sorted(actual),
            **score,
            "denied_expected": sorted(denied_expected),
            "accepted_forbidden": sorted(accepted_forbidden),
            "source_reads": evidence.observation_count,
            "observation_chars": executor.observation_chars_used,
            "omissions": [{"path": item.path, "reason": item.reason} for item in context.omissions],
            "errors": errors,
            "passed": actual == case.expected
            and not (errors or denied_expected or accepted_forbidden),
        }


def evaluate_corpus(path: Path = MANIFEST) -> dict[str, object]:
    cases = load_cases(path)
    rows = [evaluate_case(case, reverse=reverse) for case in cases for reverse in (False, True)]
    counts = Counter(case.category for case in cases)
    tp = sum(cast("int", row["true_positives"]) for row in rows)
    fn = sum(cast("int", row["false_negatives"]) for row in rows)
    fp = sum(cast("int", row["false_positives"]) for row in rows)
    return {
        "schema": "ravage.source-navigation-evaluation.v1",
        "corpus_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "claim_limit": (
            "Structural authorization on fully supplied diagnostic fixtures; not model search "
            "quality, runtime route identity, vulnerability recall, or competitor parity."
        ),
        "case_count": len(cases),
        "evaluations": len(rows),
        "categories": dict(counts),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "supported_route_recall": tp / (tp + fn) if tp + fn else None,
        "route_precision": tp / (tp + fp) if tp + fp else None,
        "model_calls": 0,
        "cost_usd": 0.0,
        "http_requests": 0,
        "passed": all(row["passed"] for row in rows),
        "cases": rows,
    }
