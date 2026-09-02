from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import yaml  # type: ignore[import-untyped]

from ravage.auth.secrets import EnvironmentFileError, read_environment_file
from ravage.setup_checks import discover_env_file
from ravage.traffic.policy import PORTSWIGGER_DEMO_REQUEST_PROFILE
from ravage.xben_parts.models import DEFAULT_BENCHMARKS_ROOT, XbenSettings
from ravage.xben_parts.runner import run_xben

DEFAULT_DEMO_CASE_ID = "XBEN-009-24"
DEFAULT_DEMO_MODEL_PROFILE = "hosted-openai-gpt-5.4-high"
DEFAULT_DEMO_COST_LIMIT_USD = 1.5
DEFAULT_DEMO_MAX_TURNS = 10
DEFAULT_DEMO_TIMEOUT_SECONDS = 600
DEFAULT_DEMO_INPUT_TOKEN_CEILING = 20_000
DEFAULT_DEMO_MIN_FREE_GIB = 10

PORTSWIGGER_TARGET_URL = "https://vulnerable-website.com/catalog?category=Accessories"
PORTSWIGGER_SCOPE_URLS = ("https://vulnerable-website.com/catalog",)
PORTSWIGGER_AUTHORIZATION_URL = (
    "https://portswigger.net/burp/documentation/dast/setup/trial-deployment/"
    "run-your-first-scan"
)
PORTSWIGGER_MAX_TURNS = 4
PORTSWIGGER_MAX_COST_USD = 1.5
PORTSWIGGER_MAX_RUNTIME_MIN = 8
PORTSWIGGER_MAX_PHYSICAL_REQUESTS = 24
PORTSWIGGER_MAX_RPS = 0.5
PORTSWIGGER_ROE_MAX_RPS = 1

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
    portswigger_parser = subparsers.add_parser(
        "portswigger",
        help="run a bounded assessment of PortSwigger's deliberately vulnerable shop",
        description=(
            "Assess PortSwigger's deliberately vulnerable Gin & Juice Shop using its "
            "published scanner-test URL. The hostname is fixed and cannot be overridden."
        ),
        epilog=(
            f"Target:\n  {PORTSWIGGER_TARGET_URL}\n\n"
            f"Published authorization:\n  {PORTSWIGGER_AUTHORIZATION_URL}\n\n"
            "Configuration:\n"
            "  No engagement YAML is required; the preset writes a locked brief into "
            "the run directory.\n"
            "  OPENAI_API_KEY comes from the process environment, .env.ravage or .env "
            "in the current directory, or --env-file.\n"
            "  The target, GPT-5.4-high model, scope, 24-request limit, 0.5-RPS limit, "
            "and safety rules are preset-owned.\n"
            "  Run artifacts: brief.yaml, stdout.log, report.json, workspace/, and "
            "audit.db under runs/demo/portswigger_<UTC timestamp> by default.\n"
            "  --preflight checks local key presence, output-path usability, and the "
            "locked preset only; it sends no target or model requests and does not "
            "validate the key with OpenAI."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    portswigger_parser.add_argument(
        "--authorized-remote-target",
        action="store_true",
        help=(
            "acknowledge PortSwigger's published scanner-test target and send bounded "
            "traffic to vulnerable-website.com"
        ),
    )
    portswigger_parser.add_argument(
        "--allow-paid-models",
        action="store_true",
        help="acknowledge that the pinned OpenAI model can incur charges",
    )
    portswigger_parser.add_argument(
        "--preflight",
        action="store_true",
        help="validate local setup and the locked preset without network requests",
    )
    portswigger_parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "run artifacts directory; defaults to "
            "runs/demo/portswigger_<UTC timestamp>"
        ),
    )
    portswigger_parser.add_argument(
        "--env-file",
        type=Path,
        help="provider secrets file; defaults to .env.ravage or .env in this directory",
    )
    parsed = parser.parse_args(args)
    active_env = os.environ if env is None else env

    if parsed.command == "portswigger":
        if not parsed.preflight and not parsed.authorized_remote_target:
            portswigger_parser.error(
                "this public demo requires --authorized-remote-target; review "
                "PortSwigger's published scanner-test target first: "
                f"{PORTSWIGGER_AUTHORIZATION_URL}"
            )
        if not parsed.preflight and not parsed.allow_paid_models:
            portswigger_parser.error(
                "this demo uses a paid OpenAI route; pass --allow-paid-models to "
                "acknowledge possible charges"
            )
        resolved_env_file = parsed.env_file or discover_env_file()
        try:
            _validate_portswigger_provider_setup(
                env_file=resolved_env_file,
                environment=active_env,
            )
            _validate_portswigger_output_dir(parsed.output_dir)
        except (EnvironmentFileError, ValueError) as exc:
            portswigger_parser.error(str(exc))
        if parsed.preflight:
            return _portswigger_preflight_result(
                env_file=resolved_env_file,
                output_dir=parsed.output_dir,
            )
        if attack_runner is None:
            message = "the PortSwigger demo requires the Ravage attack runner"
            raise RuntimeError(message)
        try:
            return _run_portswigger_demo(
                output_dir=parsed.output_dir,
                env_file=resolved_env_file,
                attack_runner=attack_runner,
            )
        except (RuntimeError, ValueError) as exc:
            portswigger_parser.error(str(exc))

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


def _run_portswigger_demo(
    *,
    output_dir: Path | None,
    env_file: Path | None,
    attack_runner: AttackRunner,
) -> object:
    run_dir = output_dir or _fresh_output_dir("portswigger")
    brief_path = _write_portswigger_brief(run_dir)
    command = [
        str(brief_path),
        "--target-url",
        PORTSWIGGER_TARGET_URL,
        "--run-dir",
        str(run_dir),
        "--agent-mode",
        "ctf-free-roam",
        "--model-profile",
        DEFAULT_DEMO_MODEL_PROFILE,
        "--model-tier",
        "high",
        "--max-turns",
        str(PORTSWIGGER_MAX_TURNS),
        "--traffic-policy",
        "low-noise",
        "--max-physical-requests",
        str(PORTSWIGGER_MAX_PHYSICAL_REQUESTS),
        "--traffic-max-rps",
        str(PORTSWIGGER_MAX_RPS),
        "--traffic-request-profile",
        PORTSWIGGER_DEMO_REQUEST_PROFILE,
        "--authorized-remote-target",
        "--tool-runtime",
        "docker",
        "--no-tool-recon",
        "--show-agent-actions",
        "--allow-paid-models",
        "--report",
    ]
    if env_file is not None:
        command.extend(("--env-file", str(env_file)))
    result = attack_runner(command)
    _require_portswigger_demo_finding(run_dir)
    return result


def _validate_portswigger_provider_setup(
    *,
    env_file: Path | None,
    environment: Mapping[str, str],
) -> None:
    file_values: Mapping[str, str] = {}
    if env_file is not None:
        file_values = read_environment_file(env_file)
    process_key = str(environment.get("OPENAI_API_KEY") or "").strip()
    file_key = str(file_values.get("OPENAI_API_KEY") or "").strip()
    if process_key or file_key:
        return
    raise ValueError(
        "OPENAI_API_KEY is required for the pinned GPT-5.4-high demo; set it in "
        ".env.ravage, the process environment, or a file passed with --env-file"
    )


def _portswigger_preflight_result(
    *,
    env_file: Path | None,
    output_dir: Path | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "ready",
        "network_requests": 0,
        "target": PORTSWIGGER_TARGET_URL,
        "authorization": PORTSWIGGER_AUTHORIZATION_URL,
        "model_profile": DEFAULT_DEMO_MODEL_PROFILE,
        "max_turns": PORTSWIGGER_MAX_TURNS,
        "max_physical_requests": PORTSWIGGER_MAX_PHYSICAL_REQUESTS,
        "max_rps": PORTSWIGGER_MAX_RPS,
        "env_file": str(env_file) if env_file is not None else "process environment",
        "output_dir": (
            str(output_dir)
            if output_dir is not None
            else "runs/demo/portswigger_<UTC timestamp>"
        ),
    }
    print("RAVAGE // PORTSWIGGER PREFLIGHT", flush=True)
    print(f"{'status':<12}ready · no network requests sent", flush=True)
    print(f"{'target':<12}{PORTSWIGGER_TARGET_URL}", flush=True)
    print(f"{'authority':<12}{PORTSWIGGER_AUTHORIZATION_URL}", flush=True)
    print(f"{'model':<12}GPT-5.4 high · paid route", flush=True)
    print(
        f"{'limits':<12}{PORTSWIGGER_MAX_PHYSICAL_REQUESTS} requests · "
        f"{PORTSWIGGER_MAX_RPS:g} RPS · {PORTSWIGGER_MAX_TURNS} turns",
        flush=True,
    )
    print(f"{'env':<12}{payload['env_file']}", flush=True)
    print(f"{'output':<12}{payload['output_dir']}", flush=True)
    return payload


def _validate_portswigger_output_dir(output_dir: Path | None) -> None:
    candidate = output_dir or Path("runs/demo")
    if candidate.is_symlink():
        message = f"demo output path must not be a symbolic link: {candidate}"
        raise ValueError(message)
    if candidate.exists() and not candidate.is_dir():
        message = f"demo output path is not a directory: {candidate}"
        raise ValueError(message)
    writable_parent = candidate
    while not writable_parent.exists() and writable_parent != writable_parent.parent:
        writable_parent = writable_parent.parent
    if not writable_parent.is_dir():
        message = f"demo output parent is not a directory: {writable_parent}"
        raise ValueError(message)
    if not os.access(writable_parent, os.W_OK | os.X_OK):
        message = f"demo output path is not writable: {candidate}"
        raise ValueError(message)
    if output_dir is None or not output_dir.exists():
        return

    brief_path = output_dir / "brief.yaml"
    if brief_path.is_symlink():
        message = f"refusing to reuse existing demo brief: {brief_path}"
        raise ValueError(message)
    if brief_path.exists() and not _is_matching_portswigger_brief(brief_path):
        message = f"refusing to reuse existing demo brief: {brief_path}"
        raise ValueError(message)
    try:
        entries = tuple(output_dir.iterdir())
    except OSError as exc:
        message = f"cannot inspect demo output directory: {output_dir}"
        raise ValueError(message) from exc
    allowed_entries = {brief_path} if brief_path.exists() else set()
    if set(entries) != allowed_entries:
        message = (
            "demo output directory already contains run artifacts; choose a fresh "
            "--output-dir or omit it for a timestamped directory"
        )
        raise ValueError(message)


def _require_portswigger_demo_finding(run_dir: Path) -> None:
    report_path = run_dir / "report.json"
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        print(
            f"[demo:error] live run produced no readable report · {report_path}",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(1)
    summary = report.get("executive_summary") if isinstance(report, dict) else None
    finding_count = summary.get("finding_count") if isinstance(summary, dict) else None
    if isinstance(finding_count, int) and not isinstance(finding_count, bool) and finding_count > 0:
        return
    print(
        f"[demo:error] no vulnerability was confirmed · report={report_path}",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(1)


def _write_portswigger_brief(run_dir: Path) -> Path:
    if run_dir.exists() and not run_dir.is_dir():
        message = f"demo output path is not a directory: {run_dir}"
        raise ValueError(message)
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        message = f"cannot create demo output directory: {run_dir}"
        raise ValueError(message) from exc
    brief_path = run_dir / "brief.yaml"
    if brief_path.is_symlink():
        message = f"refusing to overwrite existing demo brief: {brief_path}"
        raise ValueError(message)
    if brief_path.exists():
        if _is_matching_portswigger_brief(brief_path):
            return brief_path
        message = f"refusing to overwrite existing demo brief: {brief_path}"
        raise ValueError(message)
    payload = _portswigger_brief_payload()
    try:
        with brief_path.open("x", encoding="utf-8") as stream:
            yaml.safe_dump(payload, stream, sort_keys=False)
    except OSError as exc:
        message = f"cannot write demo brief: {brief_path}"
        raise ValueError(message) from exc
    return brief_path


def _portswigger_brief_payload(*, engagement_id: str | None = None) -> dict[str, object]:
    return {
        "engagement_id": engagement_id or str(uuid4()),
        "scope": {
            "in_scope": list(PORTSWIGGER_SCOPE_URLS),
            "out_of_scope": [],
        },
        "roe": {
            "max_rps": PORTSWIGGER_ROE_MAX_RPS,
            "no_destructive_actions": True,
            "data_handling": "placeholders_only",
        },
        "objectives": ["sql_injection"],
        "budget": {
            "max_cost_usd": PORTSWIGGER_MAX_COST_USD,
            "max_runtime_min": PORTSWIGGER_MAX_RUNTIME_MIN,
        },
        "context": {
            "description": (
                "PortSwigger's deliberately vulnerable Gin & Juice Shop, published "
                "for evaluating web vulnerability scanners."
            ),
            "win_condition": (
                "Confirm the catalog category SQL injection with a non-destructive "
                "boolean differential and stop."
            ),
            "stop_after_first_finding": True,
            "rules": [
                "Stay on the exact https://vulnerable-website.com origin and the "
                "curated catalog route exposed by the traffic policy.",
                "Do not follow or test links, redirects, hosts, or ports outside that origin.",
                "Use only read-only or harmless proof requests; do not create accounts, "
                "transfer funds, upload files, change data, or test denial of service.",
                "Stop after one executor-validated vulnerability is confirmed.",
            ],
            "authorization_reference": PORTSWIGGER_AUTHORIZATION_URL,
        },
    }


def _is_matching_portswigger_brief(path: Path) -> bool:
    try:
        existing = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return False
    if not isinstance(existing, dict):
        return False
    engagement_id = existing.get("engagement_id")
    if not isinstance(engagement_id, str):
        return False
    try:
        UUID(engagement_id)
    except ValueError:
        return False
    return existing == _portswigger_brief_payload(engagement_id=engagement_id)


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
