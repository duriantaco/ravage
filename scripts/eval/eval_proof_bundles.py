from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ravage.proof_bundle_eval import (
    evaluate_proof_bundle_cases,
    load_proof_bundle_eval_cases,
    write_proof_bundle_eval_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Score recorded proof-bundle verdicts against labeled offline JSONL cases. "
            "This checks fixture consistency; it does not independently verify exploits. "
            "Exit codes: 0 = all cases pass, 1 = evaluation failures, 2 = invalid/empty input."
        )
    )
    parser.add_argument("cases", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--live-verifier", action="store_true", help="Unavailable legacy option (exits 2)."
    )
    parser.add_argument("--model-config", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--model-profile", help=argparse.SUPPRESS)
    parser.add_argument("--model-tier", choices=["high", "mid", "low"], help=argparse.SUPPRESS)
    parser.add_argument("--allow-paid-models", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.live_verifier or any(
        (args.model_config, args.model_profile, args.model_tier, args.allow_paid_models)
    ):
        parser.error("live model verification is unavailable; use recorded offline verdicts")

    try:
        cases = load_proof_bundle_eval_cases(args.cases)
        report = evaluate_proof_bundle_cases(cases)
        if args.output is not None:
            write_proof_bundle_eval_report(report, args.output)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"[proof-bundle-eval:invalid] {exc}\n")
        raise SystemExit(2) from None

    sys.stdout.write(json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n")
    if not report.total:
        raise SystemExit(2)
    if report.failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
