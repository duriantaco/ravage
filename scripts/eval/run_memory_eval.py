from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ravage.memory_eval import MemoryEvalUnavailableError, run_memory_eval


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Retired memory A/B evaluation entry point. Active memory evaluation is "
            "unavailable; this command exits 2 without running models or writing reports."
        )
    )
    # Keep legacy options parseable so existing invocations get the same clear error.
    parser.add_argument("--benchmark", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--memory-db-path", type=Path)
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--model-profile")
    parser.add_argument("--model-tier", choices=["high", "mid", "low"])
    parser.add_argument("--max-turns", type=int)
    parser.add_argument("--case", action="append")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--agent-skill", type=Path)
    parser.add_argument("--allow-paid-models", action="store_true")
    parser.add_argument("--max-model-requests", type=int)
    parser.add_argument("--max-cost-usd", type=float)
    parser.add_argument("--input-token-ceiling-per-model-call", type=int)
    parser.parse_args()

    try:
        run_memory_eval()
    except MemoryEvalUnavailableError as exc:
        sys.stderr.write(f"[memory-eval:unavailable] {exc}\n")
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
