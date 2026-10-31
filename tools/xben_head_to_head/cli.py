# ruff: noqa: T201
"""CLI for the local Codex + Ravage skill versus Strix XBEN diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_MODEL = "gpt-5.4-2026-03-05"
DEFAULT_REASONING_EFFORT = "high"
DEFAULT_SELECTION_SEED = 20260916
DEFAULT_XBEN_COMMIT = "a16cb1ba0701b20d63913846536fc7b0672082af"
DEFAULT_STRIX_COMMIT = "95e085eb6ce29c72ff84313b012cd2c9e9c1cfe5"
DEFAULT_STRIX_IMAGE = (
    "ghcr.io/usestrix/strix-sandbox@"
    "sha256:f6906c3114e504fd1a218fcf028d7a0e46851118403a438b63956de6ea7c4331"
)
FIXED_CASE_IDS = (
    "XBEN-009-24",
    "XBEN-021-24",
    "XBEN-027-24",
    "XBEN-032-24",
    "XBEN-038-24",
    "XBEN-053-24",
    "XBEN-057-24",
    "XBEN-058-24",
    "XBEN-064-24",
    "XBEN-066-24",
    "XBEN-068-24",
    "XBEN-071-24",
    "XBEN-075-24",
    "XBEN-078-24",
    "XBEN-079-24",
    "XBEN-081-24",
    "XBEN-082-24",
    "XBEN-090-24",
    "XBEN-091-24",
    "XBEN-096-24",
)

_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


@dataclass(frozen=True)
class _CampaignApi:
    config_type: Callable[..., object]
    run_preflight: Callable[[object], Mapping[str, Any]]
    run_campaign: Callable[[object], Mapping[str, Any]]


def _load_campaign_api() -> _CampaignApi:
    from .campaign import CampaignConfig, run_campaign, run_preflight

    return _CampaignApi(CampaignConfig, run_preflight, run_campaign)


def _common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--source-repo",
        type=Path,
        default=Path(".reference_repos/xben-eval-a16cb1ba"),
        help="clean XBEN worktree at the pinned source commit",
    )
    parser.add_argument(
        "--skill-dir",
        type=Path,
        default=Path("skills/ravage-safe-reproduction"),
        help="Ravage skill exposed only to the Codex arm",
    )
    parser.add_argument(
        "--codex-executable",
        type=Path,
        help="Codex CLI path; defaults to the first codex on PATH",
    )
    parser.add_argument(
        "--codex-executable-sha256",
        help="optional expected Codex launcher SHA-256; otherwise computed before preflight",
    )
    parser.add_argument(
        "--strix-executable",
        type=Path,
        default=Path(".reference_repos/strix-eval-20260911/.venv/bin/strix"),
    )
    parser.add_argument(
        "--strix-executable-sha256",
        help="optional expected Strix launcher SHA-256; otherwise computed before preflight",
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "minimal", "low", "medium", "high", "xhigh", "max"),
        default=DEFAULT_REASONING_EFFORT,
    )
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    parser.add_argument("--codex-max-http-requests", type=int, default=64)
    parser.add_argument("--strix-max-budget-usd", type=float, default=3.0)
    parser.add_argument("--strix-max-turns", type=int, default=160)
    parser.add_argument("--source-commit", default=DEFAULT_XBEN_COMMIT)
    parser.add_argument("--strix-source-commit", default=DEFAULT_STRIX_COMMIT)
    parser.add_argument("--strix-image", default=DEFAULT_STRIX_IMAGE)
    parser.add_argument("--selection-seed", type=int, default=DEFAULT_SELECTION_SEED)
    parser.add_argument(
        "--api-key-env",
        default="OPENAI_API_KEY",
        help="environment variable holding the paid API credential; values are never logged",
    )
    return parser


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run a fixed-case, local diagnostic comparison of Codex + the Ravage skill and "
            "Strix. This is not an official/public XBEN score."
        )
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    common = _common_parser()
    subparsers.add_parser(
        "preflight",
        parents=[common],
        help="validate pinned inputs and runtime prerequisites without starting a target",
    )
    canary = subparsers.add_parser(
        "canary",
        parents=[common],
        help="run one paid matched case before the full campaign",
    )
    canary.add_argument("--case", choices=FIXED_CASE_IDS, default=FIXED_CASE_IDS[0])
    canary.add_argument(
        "--execute-paid",
        action="store_true",
        help="confirm that this command may use the configured paid API credential",
    )
    full = subparsers.add_parser(
        "full",
        parents=[common],
        help="run the fixed 20-case/40-row paid comparison",
    )
    full.add_argument(
        "--execute-paid",
        action="store_true",
        help="required confirmation for the paid 20-case campaign",
    )
    return parser


def main(argv: list[str] | None = None) -> int:  # noqa: C901
    args = _parser().parse_args(argv)
    if args.mode in {"canary", "full"} and not args.execute_paid:
        _emit_error(
            {
                "error": "paid_execution_confirmation_required",
                "mode": args.mode,
                "hint": f"re-run {args.mode} with --execute-paid after reviewing the budget",
            }
        )
        return 2
    if _ENV_NAME_RE.fullmatch(args.api_key_env) is None:
        _emit_error({"error": "invalid_api_key_environment_name"})
        return 2
    api_key = os.environ.get(args.api_key_env, "")
    if args.mode in {"canary", "full"} and not api_key:
        _emit_error(
            {
                "error": "paid_api_key_missing",
                "environment_variable": args.api_key_env,
            }
        )
        return 2

    try:
        project_root = args.project_root.expanduser().resolve(strict=True)
        case_ids = (args.case,) if args.mode == "canary" else FIXED_CASE_IDS
        output_dir = _output_dir(args, project_root=project_root)
        codex_executable = _codex_executable(args, project_root=project_root)
        strix_executable = _project_path(args.strix_executable, project_root=project_root)
        config_api = _load_campaign_api()
        config = config_api.config_type(
            project_root=project_root,
            source_repo=_project_path(args.source_repo, project_root=project_root),
            output_dir=output_dir,
            skill_dir=_project_path(args.skill_dir, project_root=project_root),
            codex_executable=codex_executable,
            codex_executable_sha256=_executable_pin(
                codex_executable,
                supplied=args.codex_executable_sha256,
            ),
            strix_executable=strix_executable,
            strix_executable_sha256=_executable_pin(
                strix_executable,
                supplied=args.strix_executable_sha256,
            ),
            api_key=api_key,
            case_ids=tuple(case_ids),
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            timeout_seconds=args.timeout_seconds,
            codex_max_http_requests=args.codex_max_http_requests,
            strix_max_budget_usd=args.strix_max_budget_usd,
            strix_max_turns=args.strix_max_turns,
            source_commit=args.source_commit,
            strix_source_commit=args.strix_source_commit,
            strix_image=args.strix_image,
            selection_seed=args.selection_seed,
        )
        result = (
            config_api.run_preflight(config)
            if args.mode == "preflight"
            else config_api.run_campaign(config)
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        _emit_error(
            {
                "error": type(exc).__name__,
                "message": _redact(str(exc), (api_key,)),
            }
        )
        return 2

    public_result = _public_json(result, secrets=(api_key,))
    _emit(
        {
            "mode": args.mode,
            "model": args.model,
            "reasoning_effort": args.reasoning_effort,
            "case_ids": list(case_ids),
            "output_dir": str(output_dir),
            "result": public_result,
        }
    )
    if args.mode == "preflight" and isinstance(result, Mapping):
        readiness = result.get("ready", result.get("valid"))
        if readiness is False:
            return 2
    return 0


def _project_path(path: Path, *, project_root: Path) -> Path:
    expanded = path.expanduser()
    return (expanded if expanded.is_absolute() else project_root / expanded).resolve(strict=False)


def _output_dir(args: argparse.Namespace, *, project_root: Path) -> Path:
    if args.output_dir is not None:
        return _project_path(args.output_dir, project_root=project_root)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return project_root / "runs" / "xben-head-to-head" / f"{stamp}-{args.mode}"


def _codex_executable(args: argparse.Namespace, *, project_root: Path) -> Path:
    if args.codex_executable is not None:
        return _project_path(args.codex_executable, project_root=project_root)
    discovered = shutil.which("codex")
    if discovered is None:
        return project_root / ".missing-codex-executable"
    return Path(discovered).resolve(strict=False)


def _executable_pin(path: Path, *, supplied: str | None) -> str:
    if supplied is not None:
        normalized = supplied.strip().lower()
        if _SHA256_RE.fullmatch(normalized) is None:
            raise ValueError("executable SHA-256 pin is invalid")
        return normalized
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            return ""
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        # Preflight owns the public explanation for an unavailable executable.
        return ""


def _public_json(value: object, *, secrets: Sequence[str]) -> object:
    if isinstance(value, Mapping):
        return {
            _redact(str(key), secrets): _public_json(item, secrets=secrets)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [_public_json(item, secrets=secrets) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        return _redact(value, secrets)
    if value is None or isinstance(value, bool | int | float):
        return value
    return _redact(str(value), secrets)


def _redact(value: str, secrets: Sequence[str]) -> str:
    redacted = value
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def _emit(payload: Mapping[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _emit_error(payload: Mapping[str, object]) -> None:
    sys.stderr.write(json.dumps(payload, sort_keys=True, allow_nan=False) + "\n")


__all__ = [
    "DEFAULT_MODEL",
    "DEFAULT_REASONING_EFFORT",
    "FIXED_CASE_IDS",
    "main",
]
