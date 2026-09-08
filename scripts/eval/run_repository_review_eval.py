from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_SRC = ROOT / "packages" / "ravage" / "src"
if str(PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(PACKAGE_SRC))

from ravage.repository_review import (  # noqa: E402
    DEFAULT_REVIEW_MAX_TURNS,
    DEFAULT_REVIEW_OBJECTIVE,
)
from ravage.repository_review_cli import (  # noqa: E402
    ProviderReviewClient,
    ready_repository_review_route,
)
from ravage.repository_review_eval_runner import (  # noqa: E402
    RepositoryReviewEvalRunnerError,
    run_repository_review_ab_evaluation,
)

DEFAULT_MANIFEST = ROOT / "packages" / "ravage" / "tests" / ("repository_review_eval_manifest.json")
DEFAULT_REQUIRED_MODEL = "gpt-5.4-2026-03-05"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run paired literal-only and structured-candidate repository reviews "
            "against the committed diagnostic corpus."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, help="write the JSON report to this path")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--objective", default=DEFAULT_REVIEW_OBJECTIVE)
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--model-profile", default="hosted-openai")
    parser.add_argument("--model-tier", choices=["high", "mid", "low"], default="mid")
    parser.add_argument(
        "--require-model",
        default=DEFAULT_REQUIRED_MODEL,
        help="abort if route resolution selects another model",
    )
    parser.add_argument("--max-turns", type=int, default=DEFAULT_REVIEW_MAX_TURNS)
    parser.add_argument("--max-cost-usd-per-run", type=float, default=0.25)
    parser.add_argument("--aggregate-cost-ceiling-usd", type=float, default=1.0)
    parser.add_argument(
        "--allow-paid-models",
        action="store_true",
        help="allow the selected hosted route to receive fixture source excerpts",
    )
    parsed = parser.parse_args(argv)

    try:
        route = ready_repository_review_route(
            model_config=parsed.model_config,
            model_profile=parsed.model_profile,
            model_tier=parsed.model_tier,
        )
        if route.model != parsed.require_model:
            message = f"resolved model {route.model!r}; required {parsed.require_model!r}"
            raise RepositoryReviewEvalRunnerError(message)
        report = run_repository_review_ab_evaluation(
            manifest_path=parsed.manifest,
            repository_root=parsed.repository_root,
            route=route,
            client=ProviderReviewClient(),
            repeats=parsed.repeats,
            objective=parsed.objective,
            max_turns=parsed.max_turns,
            max_cost_usd_per_run=parsed.max_cost_usd_per_run,
            aggregate_cost_ceiling_usd=parsed.aggregate_cost_ceiling_usd,
            allow_paid_models=parsed.allow_paid_models,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        parser.exit(2, f"{parser.prog}: {exc}\n")

    rendered = (
        json.dumps(
            report,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if parsed.output is None:
        sys.stdout.write(rendered)
    else:
        _write_private_report(parsed.output, rendered)
        sys.stdout.write(str(parsed.output.resolve()) + "\n")

    completion = report.get("completion")
    if not isinstance(completion, dict):
        return 1
    return 0 if completion.get("completed_runs") == completion.get("planned_runs") else 1


def _write_private_report(path: Path, rendered: str) -> None:
    destination = path.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.{uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        temporary.replace(destination)
        destination.chmod(0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
