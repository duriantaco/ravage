"""CLI for the create-only paired known-site website regression."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.known_site_regression.harness import (
    KnownSiteRegressionError,
    verify_known_site_regression,
)
from tools.known_site_regression.production import (
    execute_from_config,
    prepare_from_config,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare, execute once, or offline-verify the public known-site website regression. "
            "Results are never SOTA, unseen, or holdout evidence."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser(
        "prepare",
        help="retain a no-live-action preflight and frozen contract draft",
    )
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)

    execute = subparsers.add_parser(
        "execute",
        help="execute the exact prepared two-arm campaign once",
    )
    execute.add_argument("--executor-config", type=Path, required=True)
    execute.add_argument("--campaign-dir", type=Path, required=True)

    verify = subparsers.add_parser(
        "verify",
        help="recompute a sealed campaign entirely offline",
    )
    verify.add_argument("--campaign-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            payload, _path = prepare_from_config(args.config, args.output_dir)
            status = 0 if payload.get("ready") is True else 2
        elif args.command == "execute":
            # There is intentionally no built-in shared-daemon or placeholder
            # provider.  The reviewed dual-daemon module must be integrated as
            # an exact injected KnownSiteIsolationProvider before this command
            # can cross the entropy boundary.
            payload = execute_from_config(
                args.campaign_dir,
                executor_config_path=args.executor_config,
            )
            status = 0 if payload.get("valid_for_paired_known_site_regression") is True else 2
        else:
            payload = verify_known_site_regression(args.campaign_dir)
            status = (
                0
                if payload.get("structurally_valid") is True
                and payload.get("valid_for_paired_known_site_regression") is True
                else 2
            )
    except (OSError, KnownSiteRegressionError) as exc:
        sys.stderr.write(f"[known-site:blocked] {exc}\n")
        return 2
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return status


__all__ = ["main"]
