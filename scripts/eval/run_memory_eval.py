from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ravage.benchmark import BenchmarkOverrides
from ravage.memory import DEFAULT_MEMORY_DB_PATH
from ravage.memory_eval import run_memory_eval


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare a controlled benchmark with memory off vs memory read."
    )
    parser.add_argument("--benchmark", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("runs/memory-eval"))
    parser.add_argument("--memory-db-path", type=Path, default=DEFAULT_MEMORY_DB_PATH)
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--model-profile")
    parser.add_argument("--model-tier", choices=["high", "mid", "low"])
    parser.add_argument("--max-turns", type=int)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--agent-skill", type=Path)
    parser.add_argument("--allow-paid-models", action="store_true")
    parser.add_argument("--max-model-requests", type=int)
    parser.add_argument("--max-cost-usd", type=float)
    parser.add_argument("--input-token-ceiling-per-model-call", type=int, default=12_000)
    args = parser.parse_args()

    overrides = BenchmarkOverrides(
        model_config_path=args.model_config,
        model_profile=args.model_profile,
        model_tier=args.model_tier,
        max_turns=args.max_turns,
        case_ids=tuple(args.case),
        case_limit=args.limit,
        allow_paid_models=args.allow_paid_models,
        max_model_requests=args.max_model_requests,
        max_cost_usd=args.max_cost_usd,
        input_token_ceiling_per_model_call=args.input_token_ceiling_per_model_call,
        agent_skill_path=args.agent_skill,
    )
    try:
        report = run_memory_eval(
            manifest_path=args.benchmark,
            output_dir=args.output_dir,
            memory_db_path=args.memory_db_path,
            overrides=overrides,
        )
    except ValueError as exc:
        sys.stderr.write(f"[memory-eval:blocked] {exc}\n")
        raise SystemExit(2) from None
    if not report.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
