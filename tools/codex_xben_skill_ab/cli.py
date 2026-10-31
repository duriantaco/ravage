# ruff: noqa: T201
"""Command-line entry point for the paired Codex XBEN skill diagnostic."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from .harness import (
    DEFAULT_MAX_REQUESTS,
    PINNED_XBEN_COMMIT,
    CampaignConfig,
    HarnessError,
    run_campaign,
    run_preflight,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run fresh-target Codex skill-off/skill-on pairs on XBEN-058."
    )
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--source-repo",
        type=Path,
        default=Path(".reference_repos/xben-eval-a16cb1ba"),
    )
    parser.add_argument(
        "--skill-dir",
        type=Path,
        default=Path("skills/ravage-safe-reproduction"),
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--seed", type=int, default=58)
    parser.add_argument("--model", default="gpt-5.4")
    parser.add_argument(
        "--auth-file",
        type=Path,
        help="alternate Codex auth.json to copy into isolated workers",
    )
    parser.add_argument(
        "--login-method",
        choices=["chatgpt", "api"],
        default="chatgpt",
        help="authentication method required by isolated Codex workers",
    )
    parser.add_argument("--reasoning-effort", default="high")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    parser.add_argument("--source-commit", default=PINNED_XBEN_COMMIT)
    parser.add_argument("--preflight-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    project_root = args.project_root.resolve()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_dir or Path("runs/codex-xben-skill-ab") / stamp
    if not output_dir.is_absolute():
        output_dir = project_root / output_dir

    def resolve_from_project(path: Path) -> Path:
        return path if path.is_absolute() else project_root / path

    config = CampaignConfig(
        project_root=project_root,
        source_repo=resolve_from_project(args.source_repo),
        output_dir=output_dir,
        skill_dir=resolve_from_project(args.skill_dir),
        repeats=args.repeats,
        seed=args.seed,
        model=args.model,
        auth_file=resolve_from_project(args.auth_file) if args.auth_file else None,
        login_method=args.login_method,
        reasoning_effort=args.reasoning_effort,
        timeout_seconds=args.timeout_seconds,
        max_requests=args.max_requests,
        source_commit=args.source_commit,
    )
    try:
        if args.preflight_only:
            payload = run_preflight(config)
            print(f"preflight valid: {payload['valid']}")
            print(f"permission boundary: {payload['permission_boundary']}")
            return 0 if payload["valid"] else 2
        campaign = run_campaign(config)
    except (HarnessError, OSError) as exc:
        print(f"error: {exc}")
        return 2
    print(f"report: {config.output_dir / 'REPORT.md'}")
    print(f"completed pairs: {campaign['completed_pairs']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
