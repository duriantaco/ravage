from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml  # type: ignore[import-untyped]

from ravage.xben_parts.models import DEFAULT_BENCHMARKS_ROOT, XbenSettings
from ravage.xben_parts.runner import run_xben

DEFAULT_DEMO_CASE_ID = "XBEN-009-24"
DEFAULT_DEMO_MODEL_PROFILE = "hosted-openai-gpt-5.4-high"
DEFAULT_DEMO_COST_LIMIT_USD = 1.5
DEFAULT_DEMO_MAX_TURNS = 10
DEFAULT_DEMO_TIMEOUT_SECONDS = 600
DEFAULT_DEMO_INPUT_TOKEN_CEILING = 20_000
DEFAULT_DEMO_MIN_FREE_GIB = 10

TESTFIRE_TARGET_URL = "https://demo.testfire.net/login.jsp?mode=demo"
TESTFIRE_SCOPE_URLS = (
    "https://demo.testfire.net/login.jsp",
    "https://demo.testfire.net/doLogin",
    "https://demo.testfire.net/bank/main.jsp",
)
TESTFIRE_AUTHORIZATION_URL = (
    "https://help.hcl-software.com/appscan/ASoC/"
    "appseccloud_results_samplescans_2.html"
)
TESTFIRE_MAX_TURNS = 6
TESTFIRE_MAX_COST_USD = 1.5
TESTFIRE_MAX_RUNTIME_MIN = 8
TESTFIRE_MAX_PHYSICAL_REQUESTS = 24
TESTFIRE_MAX_RPS = 0.5
TESTFIRE_ROE_MAX_RPS = 1

AttackRunner = Callable[[list[str]], object]


def handle_demo_command(
    args: list[str],
    *,
    env: Mapping[str, str] | None = None,
    attack_runner: AttackRunner | None = None,
) -> dict[str, object] | object:
    parser = argparse.ArgumentParser(
        prog="ravage demo",
        description="Run a short, live Ravage demonstration on an authorized target.",
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
    testfire_parser = subparsers.add_parser(
        "testfire",
        help="run a bounded assessment of HCL's deliberately vulnerable banking demo",
        description=(
            "Assess HCL's deliberately vulnerable TestFire website using its published "
            "DAST demo URL. The hostname is fixed and cannot be overridden."
        ),
    )
    testfire_parser.add_argument(
        "--authorized-remote-target",
        action="store_true",
        help=(
            "acknowledge the published HCL authorization and send bounded traffic to "
            "demo.testfire.net"
        ),
    )
    testfire_parser.add_argument("--output-dir", type=Path)
    parsed = parser.parse_args(args)

    if parsed.command == "testfire":
        if not parsed.authorized_remote_target:
            testfire_parser.error(
                "this public demo requires --authorized-remote-target; review HCL's "
                f"published DAST sample target first: {TESTFIRE_AUTHORIZATION_URL}"
            )
        if attack_runner is None:
            message = "the TestFire demo requires the Ravage attack runner"
            raise RuntimeError(message)
        try:
            return _run_testfire_demo(
                output_dir=parsed.output_dir,
                attack_runner=attack_runner,
            )
        except ValueError as exc:
            testfire_parser.error(str(exc))

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


def _run_testfire_demo(
    *,
    output_dir: Path | None,
    attack_runner: AttackRunner,
) -> object:
    run_dir = output_dir or _fresh_output_dir("testfire")
    brief_path = _write_testfire_brief(run_dir)
    return attack_runner(
        [
            str(brief_path),
            "--target-url",
            TESTFIRE_TARGET_URL,
            "--run-dir",
            str(run_dir),
            "--agent-mode",
            "ctf-free-roam",
            "--model-profile",
            DEFAULT_DEMO_MODEL_PROFILE,
            "--model-tier",
            "high",
            "--max-turns",
            str(TESTFIRE_MAX_TURNS),
            "--traffic-policy",
            "low-noise",
            "--max-physical-requests",
            str(TESTFIRE_MAX_PHYSICAL_REQUESTS),
            "--traffic-max-rps",
            str(TESTFIRE_MAX_RPS),
            "--traffic-request-profile",
            "testfire-login-demo",
            "--authorized-remote-target",
            "--tool-runtime",
            "docker",
            "--no-tool-recon",
            "--show-agent-actions",
            "--allow-paid-models",
            "--report",
        ]
    )


def _write_testfire_brief(run_dir: Path) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    brief_path = run_dir / "brief.yaml"
    if brief_path.exists() or brief_path.is_symlink():
        message = f"refusing to overwrite existing demo brief: {brief_path}"
        raise ValueError(message)
    payload = {
        "engagement_id": str(uuid4()),
        "scope": {
            "in_scope": list(TESTFIRE_SCOPE_URLS),
            "out_of_scope": [],
        },
        "roe": {
            "max_rps": TESTFIRE_ROE_MAX_RPS,
            "no_destructive_actions": True,
            "data_handling": "placeholders_only",
        },
        "objectives": ["web_application_assessment"],
        "budget": {
            "max_cost_usd": TESTFIRE_MAX_COST_USD,
            "max_runtime_min": TESTFIRE_MAX_RUNTIME_MIN,
        },
        "context": {
            "description": (
                "HCL AppScan's deliberately vulnerable TestFire banking website, "
                "published as a dynamic application security testing demo target."
            ),
            "win_condition": (
                "Confirm one non-destructive, evidence-backed web vulnerability and stop."
            ),
            "stop_after_first_finding": True,
            "rules": [
                "Stay on the exact https://demo.testfire.net origin and the curated "
                "login routes exposed by the traffic policy.",
                "Do not follow or test links, redirects, hosts, or ports outside that origin.",
                "Use only read-only or harmless proof requests; do not create accounts, "
                "transfer funds, upload files, change data, or test denial of service.",
                "Stop after one executor-validated vulnerability is confirmed.",
            ],
            "authorization_reference": TESTFIRE_AUTHORIZATION_URL,
        },
    }
    with brief_path.open("x", encoding="utf-8") as stream:
        yaml.safe_dump(payload, stream, sort_keys=False)
    return brief_path


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
