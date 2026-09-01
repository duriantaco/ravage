from __future__ import annotations

import argparse
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from ravage.xben_parts.models import DEFAULT_BENCHMARKS_ROOT, XbenSettings
from ravage.xben_parts.runner import run_xben

DEFAULT_DEMO_CASE_ID = "XBEN-009-24"
DEFAULT_DEMO_MODEL_PROFILE = "hosted-openai-gpt-5.4-high"
DEFAULT_DEMO_COST_LIMIT_USD = 1.5
DEFAULT_DEMO_MAX_TURNS = 10
DEFAULT_DEMO_TIMEOUT_SECONDS = 600
DEFAULT_DEMO_INPUT_TOKEN_CEILING = 20_000
DEFAULT_DEMO_MIN_FREE_GIB = 10


def handle_demo_command(
    args: list[str],
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    parser = argparse.ArgumentParser(
        prog="ravage demo",
        description="Run a short, live Ravage demonstration on an authorized local target.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    xben_parser = subparsers.add_parser(
        "xben",
        help="build, attack, score, and remove one local XBEN target",
        description=(
            "Build a fresh local XBEN target, attack it with GPT-5.4 high, "
            "score the result, and remove the target."
        ),
    )
    xben_parser.add_argument("--benchmarks-root", type=Path)
    xben_parser.add_argument("--case-id", default=DEFAULT_DEMO_CASE_ID)
    xben_parser.add_argument("--output-dir", type=Path)
    xben_parser.add_argument(
        "--preflight",
        action="store_true",
        help="validate Docker, the model route, budgets, and the selected case without attacking",
    )
    parsed = parser.parse_args(args)

    active_env = os.environ if env is None else env
    benchmarks_root = _benchmarks_root(parsed.benchmarks_root, env=active_env)
    case_path = benchmarks_root / parsed.case_id
    if not case_path.is_dir():
        xben_parser.error(
            f"XBEN case not found: {case_path}. Set XBEN_ROOT or pass --benchmarks-root."
        )

    output_dir = parsed.output_dir or _fresh_output_dir(parsed.case_id)
    settings = XbenSettings(
        benchmarks_root=benchmarks_root,
        output_dir=output_dir,
        ids=(parsed.case_id,),
        preflight=parsed.preflight,
        mode="black-box",
        comparison_profile="none",
        agent_mode="ctf-free-roam",
        recovery_profile="off",
        model_profile=DEFAULT_DEMO_MODEL_PROFILE,
        model_tier="high",
        max_turns=DEFAULT_DEMO_MAX_TURNS,
        case_timeout_seconds=DEFAULT_DEMO_TIMEOUT_SECONDS,
        max_model_requests_per_case=DEFAULT_DEMO_MAX_TURNS,
        max_cost_usd=DEFAULT_DEMO_COST_LIMIT_USD,
        min_free_gib=DEFAULT_DEMO_MIN_FREE_GIB,
        allow_paid_models=True,
        input_token_ceiling_per_model_call=DEFAULT_DEMO_INPUT_TOKEN_CEILING,
        concurrency=1,
        docker_platform="linux/amd64",
        tool_runtime="host",
        flag_mode="exact",
        operator_log_root=output_dir / "operator-logs",
        stream_agent_output=True,
        cockpit=False,
        keep_target=False,
        prune_case_images=True,
        target_ttl_seconds=DEFAULT_DEMO_TIMEOUT_SECONDS,
    )
    try:
        report = run_xben(settings)
    except ValueError as exc:
        xben_parser.error(str(exc))

    if not parsed.preflight and not _single_case_solved(report):
        raise SystemExit(1)
    return report


def _benchmarks_root(explicit: Path | None, *, env: Mapping[str, str]) -> Path:
    if explicit is not None:
        return explicit.expanduser()
    configured = env.get("XBEN_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_BENCHMARKS_ROOT


def _fresh_output_dir(case_id: str) -> Path:
    case_slug = case_id.lower().replace("-", "_")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return Path("runs/demo") / f"{case_slug}_{timestamp}"


def _single_case_solved(report: Mapping[str, object]) -> bool:
    summary = report.get("summary")
    if not isinstance(summary, Mapping):
        return False
    return summary.get("total") == 1 and summary.get("solved") == 1
