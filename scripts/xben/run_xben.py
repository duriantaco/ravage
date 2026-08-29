from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ravage.runtime import DEFAULT_TOOL_IMAGE
from ravage.xben_parts.models import (
    DEFAULT_BENCHMARKS_ROOT,
    DEFAULT_MIN_FREE_GIB,
    XbenSettings,
)
from ravage.xben_parts.runner import run_xben


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Ravage against the official XBOW/XBEN validation benchmark."
    )
    parser.add_argument("--benchmarks-root", type=Path, default=DEFAULT_BENCHMARKS_ROOT)
    parser.add_argument("--output-dir", type=Path, default=Path("runs/xben"))
    parser.add_argument("--all", action="store_true", dest="all_cases")
    parser.add_argument("--range", dest="case_range")
    parser.add_argument("--ids", nargs="*", default=[])
    parser.add_argument("--exclude-ids", nargs="*", default=[])
    parser.add_argument("--sample", type=int)
    parser.add_argument("--sample-seed", type=int)
    parser.add_argument("--levels", nargs="*", type=int, default=[])
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list", action="store_true", dest="list_cases")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument(
        "--mode",
        choices=["black-box", "white-box", "source-aware"],
        default="black-box",
        help=(
            "Benchmark context mode. black-box exposes only the challenge "
            "description; white-box exposes source and description; source-aware "
            "is a compatibility alias for white-box."
        ),
    )
    parser.add_argument(
        "--comparison-profile",
        choices=["mapta-awe-xben", "none"],
        default="mapta-awe-xben",
        help=(
            "Preflight comparability contract. mapta-awe-xben blocks runs that "
            "do not match the published URL + challenge-description black-box "
            "setup; use none only for deliberately non-comparable diagnostics."
        ),
    )
    parser.add_argument("--agent", choices=["ai-web"], default="ai-web")
    parser.add_argument(
        "--agent-mode",
        choices=["hybrid", "ctf-free-roam"],
        default="ctf-free-roam",
        help="ai-web execution mode. XBEN defaults to MAPTA-style CTF free-roam.",
    )
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--model-profile", default="local-ollama")
    parser.add_argument("--model-tier", choices=["high", "mid", "low"], default="mid")
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument(
        "--knowledge-pack",
        type=Path,
        help="path to Agent Skills-style SKILL.md files to inject as selected knowledge cards",
    )
    parser.add_argument("--knowledge-pack-limit", type=int, default=4)
    parser.add_argument("--knowledge-pack-max-chars", type=int, default=6_000)
    parser.add_argument("--case-timeout-seconds", type=int, default=1800)
    parser.add_argument("--max-model-requests-per-case", type=int, default=40)
    parser.add_argument("--max-cost-usd", type=float)
    parser.add_argument("--min-free-gib", type=int, default=DEFAULT_MIN_FREE_GIB)
    parser.add_argument("--allow-paid-models", action="store_true")
    parser.add_argument("--allow-degraded", action="store_true")
    parser.add_argument("--input-token-ceiling-per-model-call", type=int, default=12_000)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--docker-platform", default="linux/amd64")
    parser.add_argument("--tool-runtime", choices=["host", "docker", "auto"], default="host")
    parser.add_argument("--tool-image", default=DEFAULT_TOOL_IMAGE)
    parser.add_argument("--flag-mode", choices=["exact", "pattern"], default="exact")
    parser.add_argument("--operator-log-root", type=Path, default=Path("logs"))
    parser.add_argument(
        "--cockpit",
        action="store_true",
        help=(
            "Start the live operator cockpit before Docker build and keep the "
            "target alive after the run until you press Ctrl-C. Implies "
            "--keep-target."
        ),
    )
    parser.add_argument("--cockpit-host", default="127.0.0.1")
    parser.add_argument("--cockpit-port", type=int, default=8787)
    parser.add_argument(
        "--keep-target",
        action="store_true",
        help="Leave the target Docker project running after each case for the cockpit.",
    )
    parser.add_argument(
        "--prune-case-images",
        action="store_true",
        help="Remove each case image after teardown to bound benchmark disk growth.",
    )
    parser.add_argument(
        "--target-ttl-seconds",
        type=int,
        default=1800,
        help="How long the cockpit keeps a finished target alive before reaping it.",
    )
    args = parser.parse_args()
    keep_target = args.keep_target or args.cockpit

    settings = XbenSettings(
        benchmarks_root=args.benchmarks_root,
        output_dir=args.output_dir,
        all_cases=args.all_cases,
        case_range=args.case_range,
        ids=tuple(args.ids),
        exclude_ids=tuple(args.exclude_ids),
        sample=args.sample,
        sample_seed=args.sample_seed,
        levels=tuple(args.levels),
        resume=args.resume,
        retry_failed=args.retry_failed,
        dry_run=args.dry_run,
        list_cases=args.list_cases,
        preflight=args.preflight,
        mode=args.mode,
        comparison_profile=args.comparison_profile,
        agent="ai-web",
        agent_mode=args.agent_mode,
        model_config=args.model_config,
        model_profile=args.model_profile,
        model_tier=args.model_tier,
        max_turns=args.max_turns,
        knowledge_pack_path=args.knowledge_pack,
        knowledge_pack_limit=args.knowledge_pack_limit,
        knowledge_pack_max_chars=args.knowledge_pack_max_chars,
        case_timeout_seconds=args.case_timeout_seconds,
        max_model_requests_per_case=args.max_model_requests_per_case,
        max_cost_usd=args.max_cost_usd,
        min_free_gib=args.min_free_gib,
        allow_paid_models=args.allow_paid_models,
        allow_degraded=args.allow_degraded,
        input_token_ceiling_per_model_call=args.input_token_ceiling_per_model_call,
        concurrency=args.concurrency,
        docker_platform=args.docker_platform,
        tool_runtime=args.tool_runtime,
        tool_image=args.tool_image,
        flag_mode=args.flag_mode,
        operator_log_root=args.operator_log_root,
        cockpit=args.cockpit,
        cockpit_host=args.cockpit_host,
        cockpit_port=args.cockpit_port,
        keep_target=keep_target,
        prune_case_images=args.prune_case_images,
        target_ttl_seconds=args.target_ttl_seconds,
    )

    try:
        run_xben(settings)
    except ValueError as exc:
        sys.stderr.write(f"[xben:blocked] {exc}\n")
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
