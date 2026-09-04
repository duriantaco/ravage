# CLI validation errors intentionally retain actionable call-site context.
# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import argparse
import difflib
import json
import math
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from contextlib import closing, redirect_stderr, redirect_stdout, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import yaml  # type: ignore[import-untyped]

from ravage import authbench, cli_tool_check, cli_tools, package_version
from ravage.agent_core.action_executor import (
    record_probe_result,
    record_verified_probe_findings,
)
from ravage.agent_core.agent_state import (
    AgentState,
    append_unique,
    load_agent_state,
    resolve_agent_state_path,
    save_agent_state,
)
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    resolve_source_root,
    route_has_paid_transport_risk,
    run_ai_web_agent,
)
from ravage.agent_core.attack_surface import merge_surface_state, surface_from_recon
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
)
from ravage.agent_core.autonomous_route_selection import (
    AUTONOMOUS_ROUTE_ENGINES,
    run_selected_autonomous_route,
)
from ravage.agent_core.observation_analysis import merge_recon_state
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.agent_core.surface_graph_ingest import (
    ingest_recon_surface,
    project_surface_graph,
)
from ravage.agent_knowledge import describe_knowledge_pack
from ravage.agent_knowledge.cli import handle_skills_command
from ravage.auth import (
    ANONYMOUS_ACTOR,
    AuthArtifactRedactor,
    AuthorizationMatrixPlanError,
    AuthorizationMatrixRuntimeError,
    AuthorizationVerdict,
    AuthScaffoldError,
    AuthScaffoldResult,
    ConfiguredAuthenticationError,
    EnvironmentFileError,
    ManagedAttackAuthentication,
    SecretRef,
    SecretResolutionError,
    SecretResolver,
    SecretSnapshotResolver,
    SecretValue,
    SessionError,
    SessionManager,
    assert_secure_configured_auth_transport,
    build_authenticated_attack_runtime,
    build_managed_authorization_matrix,
    default_secret_environment_key,
    environment_secret_resolver,
    identity_profile_from_config,
    is_contextual_identity_secret_name,
    load_authorization_matrix_plan,
    read_environment_file,
    run_auth_preflight,
    run_authorization_matrix,
    run_authorization_surface_map,
    scaffold_auth_identity,
)
from ravage.benchmark import BenchmarkOverrides, run_benchmark
from ravage.cli_run_display import (
    DisplayMode,
    RunDisplay,
    confirmed_finding_result_line,
    redacted_artifact_path,
    redacted_target_url,
    sanitize_transcript_text,
)
from ravage.cli_ui import badge, banner, status_line, tone
from ravage.code_bug import build_code_bug_invocation
from ravage.competitor_harness import (
    preflight_competitor_harness,
    report_competitor_harness,
    run_competitor_harness,
)
from ravage.finding_evidence import confirmed_finding_evidence_failures
from ravage.labs import handle_lab_command
from ravage.live_dashboard import (
    DashboardSettings,
    build_dashboard_state,
    serve_dashboard,
    settings_from_run_dir,
)
from ravage.model_core.providers import (
    ModelTier,
    load_model_registry,
    ready_model_routes,
    resolve_model_routes,
)
from ravage.outcome_evidence import load_validated_captured_flags
from ravage.probe_suite import (
    authenticated_probe_unavailability,
    available_probes,
    probe_requires_anonymous_session,
    run_builtin_probe,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.report import (
    ProFeatureRequiredError,
    ensure_report_output_supported,
    write_pentest_report,
)
from ravage.report_artifact import write_json_report_artifact
from ravage.run_data.audit import AuditStore
from ravage.run_data.brief import first_http_target, load_engagement_brief
from ravage.run_data.run_manifest import (
    MANIFEST_NAME,
    STATUS_AGENT_RUNNING,
    STATUS_FINISHED,
    RunManifest,
    read_manifest,
    write_manifest,
)
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import DEFAULT_TOOL_IMAGE
from ravage.runtime.common import assert_http_url
from ravage.runtime.scoped_network import ScopedNetworkError
from ravage.satcom.cli import handle_satcom_command
from ravage.scan_coverage import (
    PlannerProbeDecision,
    ProbeCoverageOutcome,
    ProbeDisposition,
    RequestAccountingStatus,
    ScanCoverageCertificate,
    ScanCoverageRecorder,
    write_scan_coverage_certificate,
)
from ravage.scan_planner import (
    DEFAULT_SCAN_PROBES,
    SCAN_PROBE_CATALOG,
    ScanPlan,
    ScanPlanDecision,
    ScanPlanStatus,
    build_adaptive_scan_plan,
)
from ravage.scan_planner import (
    DISCOVERY_SCAN_PROBES as _SCAN_DISCOVERY_PROBES,
)
from ravage.scan_planner import (
    SCAN_PROBE_DEPENDENCIES as _SCAN_PROBE_DEPENDENCIES,
)
from ravage.self_adapter import build_ravage_competitor_result
from ravage.setup_checks import (
    discover_brief,
    discover_env_file,
    docker_compose_diagnostic,
    labs_diagnostic,
    local_model_diagnostic,
    playwright_diagnostic,
    run_location_diagnostic,
    target_reachability_diagnostic,
)
from ravage.traffic.cli import handle_traffic_command
from ravage.traffic.manifest import (
    TrafficRunError,
    TrafficRunManifest,
    write_traffic_manifest,
)
from ravage.traffic.policy import (
    TrafficPolicyBlocked,
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyError,
    TrafficPolicyMode,
    load_traffic_policy_snapshot,
)
from ravage.traffic.recorders import ProbeTrafficRecorder
from ravage.traffic.store import TrafficStore, TrafficStoreError
from ravage.web_core.http_probe import ProbeSession
from ravage.web_core.proof_recognizer import recognize_proofs
from ravage.web_core.recon import run_recon
from ravage.web_core.scope_policy import (
    assert_authorized_target,
    assert_scoped_same_origin,
    is_local_url,
    same_origin,
)
from ravage.xben_parts.demo import handle_demo_command
from ravage.xben_parts.models import DEFAULT_BENCHMARKS_ROOT, XbenSettings
from ravage.xben_parts.runner import run_xben

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any, TextIO

    from pentest_schemas import EngagementBrief

TOOL_RUNTIME_BINARIES = (
    "curl",
    "python3",
    "nmap",
    "ffuf",
    "katana",
    "nuclei",
    "sqlmap",
    "nikto",
    "openssl",
    "ncat",
    "nc",
)
_MAX_ATTACK_RESULT_EVENT_CHARS = 1_000_000
_MAX_RESULT_IDENTIFIER_CHARS = 64
_MAX_SCAN_PROOF_SCAN_CHARS = 8_000_000
_MAX_SCAN_PROOF_VALUE_CHARS = 650_000
_MAX_SCAN_PROOF_NODES = 20_000
_MAX_SCAN_OBSERVATION_CHARS = 10_000
_MAX_SCAN_TRANSCRIPT_CHARS = 80_000
_MAX_SCAN_COVERAGE_REASON_CODES = 8
_TESTFIRE_MAX_PHYSICAL_REQUESTS = 24
_TESTFIRE_MAX_REQUEST_BODY_BYTES = 1_024
_TESTFIRE_MAX_RPS = 0.5
_TESTFIRE_REQUEST_PROFILE = "testfire-login-demo"

_TOP_LEVEL_COMMANDS = (
    "attack",
    "audit",
    "auth",
    "authbench",
    "benchmark",
    "brief",
    "code-bug",
    "competitors",
    "dashboard",
    "demo",
    "doctor",
    "help",
    "init",
    "lab",
    "observe",
    "report",
    "satcom",
    "scan",
    "setup",
    "skills",
    "tools",
    "traffic",
    "xben",
)


@dataclass(frozen=True)
class _AttackResultEvent:
    source: str
    path: Path
    line_number: int
    event: dict[str, object]


@dataclass(frozen=True)
class _ScanProbeExecution:
    probe: str
    result: ProbeRunResult
    policy_blocked: bool = False
    opaque_unmetered: bool = False


_SCAN_UNMETERED_PROBES = frozenset({"dom_execution"})

BRIEF_DESCRIPTION_TODO = (
    "TODO: describe the target, challenge text, rules, credentials, and win condition."
)

DESCRIPTION_PLACEHOLDER_PREFIXES = (
    "todo:",
    "tbd",
    "fill this in",
    "describe the target",
)


def main(argv: list[str] | None = None) -> None:  # noqa: C901, PLR0911, PLR0912, PLR0915
    args_list = sys.argv[1:] if argv is None else argv
    if not args_list or args_list[0] in {"-h", "--help"}:
        _top_level_help()
        raise SystemExit(0)
    if args_list[0] == "--version":
        _write_line(f"ravage {package_version()}")
        raise SystemExit(0)
    if args_list[:1] == ["help"]:
        if len(args_list) == 1:
            _top_level_help()
            raise SystemExit(0)
        main([args_list[1], "--help"])
        return
    if args_list[:1] == ["--benchmark"]:
        _benchmark_compat(args_list)
        return
    if args_list[:1] in (["--attack.yml"], ["--attack.yaml"]):
        _attack_config(Path(args_list[0].removeprefix("--")))
        return
    if args_list[:2] == ["audit", "verify"]:
        _audit_verify(args_list[2:])
        return
    if args_list[:1] == ["attack"]:
        _attack(args_list[1:])
        return
    if args_list[:1] == ["code-bug"]:
        _code_bug(args_list[1:])
        return
    if args_list[:1] == ["scan"]:
        _scan(args_list[1:])
        return
    if args_list[:1] == ["auth"]:
        _auth(args_list[1:])
        return
    if args_list[:1] == ["traffic"]:
        handle_traffic_command(args_list[1:])
        return
    if args_list[:1] == ["brief"]:
        _brief(args_list[1:])
        return
    if args_list[:1] == ["init"]:
        _init(args_list[1:])
        return
    if args_list[:1] == ["setup"]:
        _setup(args_list[1:])
        return
    if args_list[:1] == ["doctor"]:
        _doctor(args_list[1:])
        return
    if args_list[:1] == ["tools"]:
        _tools(args_list[1:])
        return
    if args_list[:1] == ["skills"]:
        handle_skills_command(args_list[1:])
        return
    if args_list[:1] == ["satcom"]:
        handle_satcom_command(args_list[1:])
        return
    if args_list[:1] == ["competitors"]:
        _competitors(args_list[1:])
        return
    if args_list[:1] == ["demo"]:
        handle_demo_command(args_list[1:], attack_runner=_attack)
        return
    if args_list[:1] in (["xben"], ["benchmark"]):
        _xben(args_list[1:])
        return
    if args_list[:1] == ["authbench"]:
        _authbench(args_list[1:])
        return
    if args_list[:1] == ["dashboard"]:
        _dashboard(args_list[1:])
        return
    if args_list[:1] == ["observe"]:
        _observe(args_list[1:])
        return
    if args_list[:1] == ["lab"]:
        handle_lab_command(args_list[1:])
        return
    if args_list[:1] == ["report"]:
        _report(args_list[1:])
        return

    if args_list and not args_list[0].startswith("-"):
        _unknown_command(args_list[0])

    parser = argparse.ArgumentParser(prog="ravage")
    parser.add_argument("--version", action="version", version=f"%(prog)s {package_version()}")
    parser.add_argument("--brief", type=Path, required=True)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--db-path", type=Path)
    parser.add_argument("--workspace-dir", type=Path)
    parser.add_argument(
        "--source-root",
        type=Path,
        help="local source directory for source-assisted analysis",
    )
    parser.add_argument("--resume-from", type=Path)
    parser.add_argument("--agent", choices=["ai-web"], default="ai-web")
    parser.add_argument(
        "--agent-mode",
        choices=["ctf-free-roam", "hybrid"],
        default="ctf-free-roam",
    )
    parser.add_argument("--model-config", type=Path)
    parser.add_argument(
        "--identity",
        help="use one managed identity from brief.authentication for target HTTP actions",
    )
    parser.add_argument("--auth-env-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--model-profile", default="local-ollama")
    parser.add_argument("--model-tier", choices=["high", "mid", "low"], default="mid")
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument(
        "--traffic-policy",
        choices=["observe", "low-noise"],
        help=(
            "whole-run physical HTTP policy; defaults to low-noise for authorized remote "
            "targets and observe for local targets"
        ),
    )
    parser.add_argument(
        "--max-physical-requests",
        type=int,
        help="whole-run physical HTTP request cap in low-noise mode (default: 300)",
    )
    parser.add_argument(
        "--traffic-max-rps",
        type=float,
        help="strictly sub-1 whole-run HTTP dispatch rate in low-noise mode (default: 0.5)",
    )
    parser.add_argument(
        "--traffic-request-profile",
        choices=[_TESTFIRE_REQUEST_PROFILE],
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--recovery-profile",
        choices=["off", "recovery-v1"],
        default="off",
    )
    parser.add_argument(
        "--autonomous-route",
        action="store_true",
        help="after an unsolved base run, enter the bounded autonomous route",
    )
    parser.add_argument(
        "--autonomous-route-engine",
        choices=AUTONOMOUS_ROUTE_ENGINES,
        default="frontier",
    )
    parser.add_argument("--autonomous-route-max-requests", type=int, default=24)
    parser.add_argument(
        "--operational-profile",
        choices=[item.value for item in GraphOperationalProfileName],
        default=GraphOperationalProfileName.STANDARD.value,
    )
    parser.add_argument("--knowledge-pack", type=Path)
    parser.add_argument("--knowledge-pack-sha256", help=argparse.SUPPRESS)
    parser.add_argument("--knowledge-pack-limit", type=int, default=4)
    parser.add_argument("--knowledge-pack-max-chars", type=int, default=6_000)
    parser.add_argument(
        "--tool-runtime",
        choices=["host", "docker", "auto"],
        default="docker",
        help="process runtime; host execution requires this explicit --tool-runtime host opt-in",
    )
    parser.add_argument(
        "--authorized-remote-target",
        action="store_true",
        help="confirm explicit authorization for a remote target listed in the brief",
    )
    parser.add_argument("--tool-image", default=DEFAULT_TOOL_IMAGE)
    parser.add_argument(
        "--display",
        choices=["auto", "live", "plain", "quiet"],
        default="auto",
        help="run progress display (default: live on a terminal, plain when piped)",
    )
    parser.add_argument(
        "--show-agent-actions",
        action="store_true",
        help="show concrete probe requests and response observations as they happen",
    )
    parser.add_argument("--allow-degraded", action="store_true")
    parser.add_argument("--allow-paid-models", action="store_true")
    parser.add_argument("--tool-recon", action="store_true")
    parser.add_argument("--tool-recon-tool", action="append", default=[])
    parser.add_argument("--tool-recon-ports", default="")
    parser.add_argument(
        "--allow-empty-description",
        action="store_true",
        help=(
            "run without brief context.description; intended only for deliberate "
            "blind generic recon"
        ),
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="write a redacted pentest report after the agent finishes",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        help="report output path; core supports .md/.json; .pdf/.docx require Ravage Pro",
    )
    parser.add_argument(
        "--benchmark-proof-recognition",
        dest="proof_recognition_enabled",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(args_list)

    _pin_parsed_knowledge_pack(parser, args)
    if args.agent != "ai-web":
        parser.error("only --agent ai-web is supported")
    if args.autonomous_route and args.recovery_profile != "off":
        parser.error("--autonomous-route requires --recovery-profile off")
    if args.report_path is not None:
        _validate_report_output(parser, args.report_path)
    brief = load_engagement_brief(args.brief)
    try:
        args.source_root = resolve_source_root(explicit=args.source_root)
    except ValueError as exc:
        parser.error(str(exc))
    args.identity = _selected_attack_identity(
        parser,
        brief=brief,
        requested=args.identity,
        default_when_single=False,
    )
    _require_attack_description(
        parser,
        brief=brief,
        brief_path=args.brief,
        allow_empty=args.allow_empty_description,
    )
    _require_paid_model_opt_in(
        parser,
        model_config=args.model_config,
        model_profile=args.model_profile,
        model_tier=args.model_tier,
        allow_paid_models=args.allow_paid_models,
    )
    _validate_attack_resume_identity_before_authentication(
        parser,
        resume_from=args.resume_from,
        workspace_dir=args.workspace_dir,
        requested_identity=args.identity,
    )
    remote_target = not is_local_url(args.target_url)
    if remote_target and args.traffic_policy is None:
        args.traffic_policy = "low-noise"
    traffic_workspace = args.workspace_dir or (
        _attack_resume_workspace(args.resume_from)
        if args.resume_from is not None
        else Path("runs/ravage-agent/workspace")
    )
    if args.resume_from is not None or (traffic_workspace / "working_state.json").is_file():
        _inherit_resume_traffic_policy_args(
            parser,
            args,
            workspace=traffic_workspace,
        )
    _resolve_traffic_policy_args(
        parser,
        args,
        default_mode="low-noise" if remote_target else "observe",
        roe_max_rps=brief.roe.max_rps,
    )
    if args.traffic_policy == "low-noise":
        args.tool_recon = False
        args.tool_recon_tool = []
        args.tool_recon_ports = ""
    if remote_target and not args.authorized_remote_target:
        parser.error("remote targets require --authorized-remote-target")
    if remote_target and args.tool_runtime == "host" and args.identity is None:
        parser.error("authorized remote targets require --tool-runtime docker or auto")
    if (
        remote_target
        and args.identity is None
        and args.autonomous_route
        and args.autonomous_route_engine != "agent-graph"
    ):
        parser.error(
            "authorized remote autonomous routing requires --autonomous-route-engine agent-graph"
        )
    try:
        assert_authorized_target(
            args.target_url,
            scope=brief.scope,
            allow_remote_target=args.authorized_remote_target,
            agent_name="ravage",
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from None

    attack_authentication = None
    run_display = None
    try:
        traffic_policy = TrafficPolicyController.open(
            traffic_workspace / "traffic-policy.json",
            target_url=args.target_url,
            config=_traffic_policy_config(args),
            require_existing=(
                (
                    args.resume_from is not None
                    or (traffic_workspace / "working_state.json").is_file()
                )
                and not bool(getattr(args, "legacy_resume_without_traffic_ledger", False))
            ),
        )
        if bool(getattr(args, "legacy_resume_without_traffic_ledger", False)):
            traffic_policy.record_unmetered_action()
    except (OSError, TrafficPolicyError, ValueError) as exc:
        parser.error(f"cannot initialize traffic policy: {_concise_cli_error(exc)}")
    try:
        if args.identity is not None:
            auth_env_file = args.auth_env_file or discover_env_file(brief_path=args.brief)
            try:
                auth_resolver = environment_secret_resolver(env_file=auth_env_file)
                if brief.authentication is None:
                    raise ConfiguredAuthenticationError(
                        "the engagement brief has no authentication"
                    )
                attack_authentication = build_authenticated_attack_runtime(
                    config=brief.authentication,
                    target_url=args.target_url,
                    identity=args.identity,
                    timeout_seconds=10,
                    allow_remote_target=args.authorized_remote_target,
                    in_scope=brief.scope.in_scope,
                    out_of_scope=brief.scope.out_of_scope,
                    max_rps=brief.roe.max_rps,
                    secret_resolver=auth_resolver,
                    traffic_policy=traffic_policy,
                )
            except (
                ConfiguredAuthenticationError,
                EnvironmentFileError,
                SecretResolutionError,
                SessionError,
                ValueError,
            ) as exc:
                parser.error(
                    f"cannot authenticate identity {args.identity!r}: {_concise_cli_error(exc)}"
                )
        run_display = _attack_event_sink(
            mode=args.display,
            show_agent_actions=args.show_agent_actions,
        )
        settings = AIWebAgentSettings(
            db_path=args.db_path,
            report_path=args.report_path,
            report_agent=args.report,
            resume_from=args.resume_from,
            workspace_dir=args.workspace_dir,
            source_root=args.source_root,
            model_config=args.model_config,
            model_profile=args.model_profile,
            model_tier=args.model_tier,
            agent_mode=args.agent_mode,
            max_turns=args.max_turns,
            recovery_profile=args.recovery_profile,
            autonomous_route=args.autonomous_route,
            knowledge_pack_path=args.knowledge_pack,
            knowledge_pack_sha256=args.knowledge_pack_sha256,
            knowledge_pack_limit=args.knowledge_pack_limit,
            knowledge_pack_max_chars=args.knowledge_pack_max_chars,
            tool_runtime_mode=args.tool_runtime,
            tool_image=args.tool_image,
            allow_remote_target=args.authorized_remote_target,
            allow_degraded=args.allow_degraded,
            tool_recon=args.tool_recon,
            tool_recon_tools=tuple(args.tool_recon_tool),
            tool_recon_ports=args.tool_recon_ports,
            proof_recognition_enabled=(
                args.proof_recognition_enabled or "capture_flag" in brief.objectives
            ),
            event_sink=run_display,
            authentication=attack_authentication,
            traffic_policy_mode=args.traffic_policy,
            traffic_policy_max_physical_requests=args.max_physical_requests,
            traffic_policy_max_rps=args.traffic_max_rps,
            traffic_policy_config=traffic_policy.config,
            traffic_policy_reference=traffic_policy.to_reference(),
        )
        if args.autonomous_route:
            _run_autonomous_route_with_final_report(
                brief_path=args.brief,
                target_url=args.target_url,
                settings=settings,
                engine=args.autonomous_route_engine,
                max_model_requests=args.autonomous_route_max_requests,
                operational_profile=GraphOperationalProfileName(args.operational_profile),
            )
        else:
            run_ai_web_agent(
                brief_path=args.brief,
                target_url=args.target_url,
                settings=settings,
            )
    except ScopedNetworkError as exc:
        message = redacted_artifact_path(exc) or "Docker runtime setup failed"
        sys.stderr.write(f"{badge('fail', 'fail', stream=sys.stderr)} {message}\n")
        raise SystemExit(1) from None
    finally:
        try:
            if run_display is not None:
                run_display.close()
        finally:
            if attack_authentication is not None:
                attack_authentication.close()


def _run_autonomous_route_with_final_report(  # noqa: PLR0913
    *,
    brief_path: Path,
    target_url: str,
    settings: AIWebAgentSettings,
    engine: str,
    max_model_requests: int,
    operational_profile: GraphOperationalProfileName,
) -> object:
    """Run every autonomous phase before producing the one authoritative report."""
    report_requested = settings.report_path is not None or settings.report_agent
    route_settings = settings
    if report_requested:
        route_settings = replace(settings, report_path=None, report_agent=False)

    result: object | None = None
    error: BaseException | None = None
    try:
        result = run_selected_autonomous_route(
            engine=engine,
            max_model_requests=max_model_requests,
            brief_path=brief_path,
            target_url=target_url,
            settings=route_settings,
            operational_profile=operational_profile,
        )
    except BaseException as exc:
        error = exc
        raise
    else:
        return result
    finally:
        if report_requested:
            workspace_dir = settings.workspace_dir or Path("runs/ravage-agent/workspace")
            report_path = settings.report_path or workspace_dir.parent / "report.md"
            status = _autonomous_route_report_status(result=result, error=error)
            error_detail = f"{type(error).__name__}: {error}" if error else None
            if error_detail is not None and settings.authentication is not None:
                error_detail = (
                    f"{type(error).__name__}: [REDACTED]"
                    if settings.authentication.contains_secret(error_detail)
                    else settings.authentication.redact_text(error_detail)
                )
            write_pentest_report(
                brief_path=brief_path,
                target_url=target_url,
                workspace_dir=workspace_dir,
                output_path=report_path,
                status=status,
                completed=error is None and status == "completed",
                audit_db_path=settings.db_path or workspace_dir / "audit.db",
                error=error_detail,
            )


def _autonomous_route_report_status(
    *,
    result: object | None,
    error: BaseException | None,
) -> str:
    if error is not None:
        return "interrupted" if isinstance(error, KeyboardInterrupt) else "error"
    terminal_status = _autonomous_route_terminal_status(result)
    if not terminal_status or terminal_status in {"completed", "solved"}:
        return "completed"
    if terminal_status in {"cancelled", "failed", "interrupted"}:
        return terminal_status
    return "incomplete"


def _autonomous_route_terminal_status(result: object | None) -> str:
    route = getattr(result, "route", None)
    if route is not None:
        status = getattr(route, "status", None)
        if status is None:
            status = getattr(getattr(route, "graph", None), "status", None)
        if status is not None:
            return str(status).strip().lower()
    base = getattr(result, "base", None)
    termination = getattr(base, "termination", None)
    return str(termination or "").strip().lower()


def _top_level_help() -> None:
    _write_line(
        "\n".join(
            [
                banner("SCOPED WEB PENTEST AGENT", f"ravage {package_version()}"),
                "",
                "Start here — localhost app:",
                (
                    "  ravage init http://127.0.0.1:3000 "
                    "--brief ravage-brief.yaml --env-file .env.ravage"
                ),
                "Start here — authorized URL (Docker for process-capable attacks):",
                (
                    "  ravage init https://staging.example.test "
                    "--brief ravage-brief.yaml --env-file .env.ravage"
                ),
                "  Review the files, then copy the single [next] command.",
                "Check this install:",
                "  ravage doctor",
                "Protected app (managed authenticated scan or attack):",
                (
                    "  ravage init http://127.0.0.1:3000 "
                    "--brief ravage-brief.yaml --env-file .env.ravage --auth form "
                    "--auth-login /login --auth-health /account --auth-marker Logout"
                ),
                "Optional:",
                "  ravage scan BRIEF.yaml --probe surface_map --report",
                "  ravage attack BRIEF.yaml --identity user [options]",
                "  ravage scan --list-probes",
                "  ravage auth add BRIEF.yaml --type form --health /account --marker Logout",
                "  ravage traffic capture http://127.0.0.1:3000",
                "  ravage demo xben",
                "  ravage demo testfire --authorized-remote-target",
                "  ravage lab list",
                "  ravage authbench",
                "",
                "Commands:",
                "  ravage attack BRIEF.yaml [options]",
                ("  ravage attack BRIEF.yaml --authorized-remote-target"),
                (
                    "  ravage attack BRIEF.yaml --authorized-remote-target "
                    "--traffic-policy observe --tool-runtime docker"
                ),
                ("  ravage attack BRIEF.yaml --identity user --authorized-remote-target"),
                "  ravage code-bug BRIEF.yaml --skills PATH [attack/options]",
                "  ravage code-bug xben --skills PATH [selection/options]",
                "  ravage scan BRIEF.yaml [options]",
                "  ravage auth {add,list,check,map,matrix} BRIEF.yaml",
                "  ravage traffic {capture,list,show,replay,diff}",
                "  ravage xben [selection/options]",
                "  ravage authbench [--json]",
                "  ravage brief template --target-url URL",
                "  ravage init URL",
                "  ravage doctor [--workflow scan|attack|traffic|lab]",
                "  ravage setup check --brief BRIEF.yaml",
                "  ravage tools check",
                "  ravage tools list",
                "  ravage skills {list,validate} [PATH|builtin]",
                "  ravage satcom inspect ARTIFACT --format {tle,ccsds-space-packets}",
                "  ravage competitors {preflight,run,report,adapt-ravage}",
                "  ravage demo {xben,testfire}",
                "  ravage lab {list,show,up,down}",
                "  ravage observe RUN_DIR",
                "  ravage report RUN_DIR --brief BRIEF.yaml",
                "  ravage audit verify RUN_DIR",
                "",
                (
                    "Attack quality depends on context.description, challenge "
                    "descriptions and live target evidence."
                ),
                (
                    "Remote traffic stays disabled unless --authorized-remote-target is set; "
                    "remote shell and scanner tools are forced into scoped Docker egress."
                ),
                "Legacy direct agent form is still supported:",
                "  ravage --brief BRIEF.yaml --target-url URL [options]",
            ]
        )
    )


def _unknown_command(command: str) -> None:
    matches = difflib.get_close_matches(command, _TOP_LEVEL_COMMANDS, n=1, cutoff=0.55)
    suggestion = f" Did you mean `ravage {matches[0]}`?" if matches else ""
    raise SystemExit(
        f"unknown Ravage command: {command!r}.{suggestion} "
        "Run `ravage --help` to see available commands."
    )


def _auth(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="ravage auth",
        description="Configure and verify authenticated deterministic scans.",
        epilog=(
            "Quick start:\n"
            "  ravage auth add BRIEF.yaml --type form --login /login "
            "--health /account --marker Logout --env-file .env.ravage\n"
            "  # Fill in the generated values, then run the printed [next] commands."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    add = subparsers.add_parser(
        "add",
        help="add an identity without hand-writing YAML",
        description="Add a form, bearer, or header identity to an existing brief.",
        epilog=(
            "Example:\n"
            "  ravage auth add ravage-brief.yaml --identity user --type form "
            "--login /login --health /account --marker Logout "
            "--env-file .env.ravage"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add.add_argument("brief", type=Path, help="engagement brief YAML to update")
    add.add_argument("--identity", default="user", help="identity alias; defaults to user")
    add.add_argument(
        "--type",
        choices=["form", "bearer", "header"],
        default="form",
        help="login method; defaults to form",
    )
    add.add_argument(
        "--env-file",
        type=Path,
        help="private secrets file; defaults to .env.ravage beside the brief",
    )
    add.add_argument(
        "--login",
        "--login-url",
        dest="login_url",
        help="form login URL or target-relative path; defaults to /login",
    )
    add.add_argument(
        "--health",
        "--health-url",
        dest="health_url",
        required=True,
        help="protected URL used to prove login worked",
    )
    add.add_argument(
        "--marker",
        dest="authenticated_marker",
        help="text present only in an authenticated health response",
    )
    add.add_argument(
        "--unauthenticated-marker",
        help="text that proves the health response is logged out",
    )
    add.add_argument("--username-field", default="username", help="form username field")
    add.add_argument("--password-field", default="password", help="form password field")
    add.add_argument("--username-env", help="custom username environment-variable name")
    add.add_argument("--password-env", help="custom password environment-variable name")
    add.add_argument("--secret-env", help="custom bearer/header environment-variable name")
    add.add_argument(
        "--header",
        dest="header_name",
        default="X-API-Key",
        help="header name for --type header; defaults to X-API-Key",
    )
    add.add_argument(
        "--role",
        action="append",
        dest="roles",
        default=[],
        help="identity role; repeatable",
    )
    add.add_argument(
        "--health-status",
        action="append",
        type=int,
        default=[],
        help="accepted health status; repeatable; defaults to 200",
    )
    add.add_argument(
        "--follow-redirects",
        action="store_true",
        help="allow redirects during the health check",
    )
    add.add_argument("--replace", action="store_true", help="replace the same alias")
    add.add_argument("--json", action="store_true", help="print a machine-readable result")

    list_parser = subparsers.add_parser("list", help="list configured identities")
    list_parser.add_argument("brief", type=Path, help="engagement brief YAML")
    list_parser.add_argument("--json", action="store_true", help="print JSON")

    check = subparsers.add_parser(
        "check",
        help="verify secrets, login, and the protected health check",
    )
    check.add_argument("brief", type=Path, help="engagement brief YAML")
    check.add_argument("--identity", help="defaults to the only configured identity")
    check.add_argument(
        "--env-file",
        type=Path,
        help="secrets file; auto-detects .env.ravage when omitted",
    )
    check.add_argument("--target-url", help="override the first HTTP(S) scoped target")
    check.add_argument("--timeout-seconds", type=int, default=10, help="1-60; defaults to 10")
    check.add_argument(
        "--allow-remote-target",
        "--authorized-remote-target",
        dest="allow_remote_target",
        action="store_true",
        help="confirm explicit authorization to check a remote target",
    )
    check.add_argument("--json", action="store_true", help="print a machine-readable result")

    matrix = subparsers.add_parser(
        "matrix",
        help="compare one resource across isolated identities",
        description=(
            "Run explicit, read-only authorization checks across configured identities "
            "and an optional anonymous actor."
        ),
        epilog=(
            "Example:\n"
            "  ravage auth matrix ravage-brief.yaml authorization-matrix.yaml "
            "--env-file .env.ravage"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    matrix.add_argument("brief", type=Path, help="engagement brief YAML")
    matrix.add_argument("plan", type=Path, help="authorization matrix plan YAML")
    matrix.add_argument(
        "--env-file",
        type=Path,
        help="secrets file; auto-detects .env.ravage when omitted",
    )
    matrix.add_argument("--target-url", help="override the first HTTP(S) scoped target")
    matrix.add_argument(
        "--run-dir",
        type=Path,
        help="fresh private output directory; defaults below runs/",
    )
    matrix.add_argument(
        "--timeout-seconds",
        type=int,
        default=10,
        help="1-60 seconds per request; defaults to 10",
    )
    matrix.add_argument(
        "--max-physical-requests",
        type=int,
        default=100,
        help="whole-run request cap, including login and health checks; defaults to 100",
    )
    matrix.add_argument(
        "--traffic-max-rps",
        type=float,
        default=0.5,
        help="whole-run dispatch rate below 1 RPS; defaults to 0.5",
    )
    matrix.add_argument(
        "--allow-remote-target",
        "--authorized-remote-target",
        dest="allow_remote_target",
        action="store_true",
        help="confirm explicit authorization to test a remote target",
    )
    matrix.add_argument("--json", action="store_true", help="print the sanitized receipt")

    surface_map = subparsers.add_parser(
        "map",
        help="compare discovered routes across isolated identities",
        description=(
            "Build a read-only, role-aware surface map. Differences are review "
            "candidates, not confirmed vulnerabilities."
        ),
        epilog=(
            "Example:\n"
            "  ravage auth map ravage-brief.yaml --identity alice --identity bob "
            "--env-file .env.ravage"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    surface_map.add_argument("brief", type=Path, help="engagement brief YAML")
    surface_map.add_argument(
        "--identity",
        action="append",
        dest="identities",
        default=[],
        help="configured identity to compare; repeatable; defaults to all",
    )
    surface_map.add_argument(
        "--include-anonymous",
        action="store_true",
        help="also compare a separate anonymous actor",
    )
    surface_map.add_argument(
        "--env-file",
        type=Path,
        help="secrets file; auto-detects .env.ravage when omitted",
    )
    surface_map.add_argument("--target-url", help="override the first HTTP(S) scoped target")
    surface_map.add_argument(
        "--run-dir",
        type=Path,
        help="fresh private output directory; defaults below runs/",
    )
    surface_map.add_argument(
        "--timeout-seconds",
        type=int,
        default=10,
        help="1-60 seconds per request; defaults to 10",
    )
    surface_map.add_argument(
        "--max-urls",
        type=int,
        default=8,
        help="bounded union frontier; 1-50, defaults to 8",
    )
    surface_map.add_argument(
        "--max-physical-requests",
        type=int,
        default=200,
        help="whole-run cap including login and health checks; defaults to 200",
    )
    surface_map.add_argument(
        "--traffic-max-rps",
        type=float,
        default=0.5,
        help="whole-run dispatch rate below 1 RPS; defaults to 0.5",
    )
    surface_map.add_argument(
        "--allow-remote-target",
        "--authorized-remote-target",
        dest="allow_remote_target",
        action="store_true",
        help="confirm explicit authorization to map a remote target",
    )
    surface_map.add_argument("--json", action="store_true", help="print the sanitized receipt")

    parsed = parser.parse_args(args)
    if parsed.command == "add":
        _auth_add(add, parsed)
        return
    if parsed.command == "list":
        _auth_list(list_parser, parsed)
        return
    if parsed.command == "check":
        _auth_check(check, parsed)
        return
    if parsed.command == "map":
        _auth_map(surface_map, parsed)
        return
    _auth_matrix(matrix, parsed)


def _auth_add(parser: argparse.ArgumentParser, parsed: argparse.Namespace) -> None:
    if parsed.authenticated_marker is None and parsed.unauthenticated_marker is None:
        parser.error("auth add requires --marker or --unauthenticated-marker")
    try:
        form_fields = None
        if parsed.type == "form":
            form_fields = {
                parsed.username_field: parsed.username_env
                or default_secret_environment_key(parsed.identity, "username"),
                parsed.password_field: parsed.password_env
                or default_secret_environment_key(parsed.identity, "password"),
            }
        result = scaffold_auth_identity(
            parsed.brief,
            alias=parsed.identity,
            method=parsed.type,
            env_path=parsed.env_file,
            login_url=parsed.login_url,
            health_url=parsed.health_url,
            roles=tuple(parsed.roles or ["authenticated"]),
            form_fields=form_fields,
            secret_env=parsed.secret_env,
            header_name=parsed.header_name,
            health_statuses=tuple(parsed.health_status or [200]),
            authenticated_marker=parsed.authenticated_marker,
            unauthenticated_marker=parsed.unauthenticated_marker,
            follow_redirects=parsed.follow_redirects,
            replace=parsed.replace,
        )
    except (AuthScaffoldError, OSError, ValueError) as exc:
        parser.error(_concise_cli_error(exc))

    payload = {
        "identity": result.alias,
        "flow": result.method,
        "brief": str(result.brief_path),
        "env_file": str(result.env_path),
        "login_url": result.login_url or "",
        "health_url": result.health_url,
        "environment_keys": list(result.environment_keys),
        "added_environment_keys": list(result.added_env_keys),
        "preserved_environment_keys": list(result.preserved_env_keys),
        "replaced": result.replaced,
    }
    if parsed.json:
        _write_line(json.dumps(payload, indent=2, sort_keys=True))
        return

    action = "updated" if result.replaced else "added"
    _write_line(banner("AUTH", "identity configuration"))
    _write_line(f"{badge(action, 'ok')} {result.alias} · {result.method}")
    _write_line(f"{'brief':<10}{result.brief_path}")
    _write_line(f"{'env':<10}{result.env_path} · mode=0600")
    if result.added_env_keys:
        _write_line(
            f"{badge('edit', 'warn')} set {', '.join(result.added_env_keys)} in {result.env_path}"
        )
    elif result.preserved_env_keys:
        _write_line(
            f"{badge('kept', 'info')} existing values preserved for "
            f"{', '.join(result.preserved_env_keys)}"
        )
    _write_auth_next_commands(
        brief_path=result.brief_path,
        env_path=result.env_path,
        identity=result.alias,
        target_url=result.health_url,
    )


def _auth_list(parser: argparse.ArgumentParser, parsed: argparse.Namespace) -> None:
    brief = _load_engagement_brief_for_cli(parser, parsed.brief)
    identities = [] if brief.authentication is None else list(brief.authentication.identities)
    payload: list[dict[str, object]] = []
    for identity in identities:
        environment_keys: list[str] = []
        if brief.authentication is not None:
            with suppress(ConfiguredAuthenticationError):
                profile = identity_profile_from_config(brief.authentication, identity.alias)
                environment_keys = [
                    reference.key
                    for reference in profile.secrets.values()
                    if reference.provider in {"env", "environment"}
                ]
        payload.append(
            {
                "identity": identity.alias,
                "flow": identity.flow.kind,
                "roles": list(identity.roles),
                "login_url": (
                    identity.flow.endpoint.url if identity.flow.endpoint is not None else ""
                ),
                "health_url": identity.health_check.endpoint.url,
                "authenticated_marker": identity.health_check.authenticated_marker or "",
                "unauthenticated_marker": identity.health_check.unauthenticated_marker or "",
                "environment_keys": environment_keys,
            }
        )
    if parsed.json:
        _write_line(json.dumps({"identities": payload}, indent=2, sort_keys=True))
        return
    _write_line(banner("AUTH", "configured identities"))
    if not payload:
        _write_line(f"{badge('none', 'warn')} no authentication identities configured")
        _write_line(
            f"{badge('next', 'info')} ravage auth add "
            f"{shlex.quote(str(parsed.brief))} --health /account --marker Logout"
        )
        return
    for item in payload:
        login = f" · login={item['login_url']}" if item["login_url"] else ""
        identity_label = str(item["identity"])
        _write_line(
            f"{badge(identity_label, 'ok')} {item['flow']} · health={item['health_url']}{login}"
        )
        roles = item["roles"]
        if isinstance(roles, list) and roles:
            _write_line(f"{'roles':<10}{', '.join(str(role) for role in roles)}")
        authenticated_marker = str(item["authenticated_marker"])
        unauthenticated_marker = str(item["unauthenticated_marker"])
        markers = [
            value
            for value in (
                f"present={authenticated_marker}" if authenticated_marker else "",
                f"absent={unauthenticated_marker}" if unauthenticated_marker else "",
            )
            if value
        ]
        if markers:
            _write_line(f"{'markers':<10}{' · '.join(markers)}")
        displayed_environment_keys = item["environment_keys"]
        if isinstance(displayed_environment_keys, list) and displayed_environment_keys:
            _write_line(
                f"{'secrets':<10}{', '.join(str(key) for key in displayed_environment_keys)}"
            )


def _auth_check(parser: argparse.ArgumentParser, parsed: argparse.Namespace) -> None:
    brief = _load_engagement_brief_for_cli(parser, parsed.brief)
    identities = [] if brief.authentication is None else list(brief.authentication.identities)
    identity = parsed.identity
    if identity is None:
        if len(identities) == 1:
            identity = identities[0].alias
        elif not identities:
            parser.error("the engagement brief has no authentication identities")
        else:
            available = ", ".join(configured.alias for configured in identities)
            parser.error(f"choose --identity from: {available}")
    target_url = _target_url_from_brief(parsed.brief, explicit=parsed.target_url)
    env_file = parsed.env_file or _discover_auth_env_file(parsed.brief)
    if not parsed.json:
        _write_line(banner("AUTH CHECK", f"{identity} · target login preflight"))
        _write_line(f"{'target':<10}{redacted_target_url(target_url)}")
        _write_line(f"{'env':<10}{env_file or 'process environment'}")
        _write_line(
            f"{badge('checking', 'info')} configuration, secrets, login, and health "
            f"(timeout={max(1, min(parsed.timeout_seconds, 60))}s/request)"
        )
    result = run_auth_preflight(
        brief,
        identity,
        target_url,
        env_file=env_file,
        timeout_seconds=max(1, min(parsed.timeout_seconds, 60)),
        allow_remote_target=parsed.allow_remote_target,
    )
    if parsed.json:
        _write_line(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        for stage in result.stages:
            state = (
                "ok"
                if stage.status.value == "passed"
                else ("fail" if stage.status.value == "failed" else "skip")
            )
            _write_line(status_line(state, stage.name, f"{stage.detail} · {stage.reason_code}"))
        if result.passed:
            _write_line(f"{badge('ready', 'ok')} authenticated scan can start")
            _write_auth_next_commands(
                brief_path=parsed.brief,
                env_path=env_file,
                identity=identity,
                target_url=target_url,
                include_check=False,
            )
    if not result.passed:
        raise SystemExit(1)


def _auth_map(parser: argparse.ArgumentParser, parsed: argparse.Namespace) -> None:
    brief = _load_engagement_brief_for_cli(parser, parsed.brief)
    authentication = brief.authentication
    if authentication is None or len(authentication.identities) < 2:
        parser.error("authorization surface map requires at least two configured identities")
    configured_identities = tuple(
        identity.alias for identity in authentication.identities
    )
    selected_identities = tuple(
        sorted(
            {
                str(alias).strip()
                for alias in (parsed.identities or configured_identities)
                if str(alias).strip()
            }
        )
    )
    if len(selected_identities) < 2:
        parser.error("authorization surface map requires at least two configured identities")
    unknown_identities = tuple(
        alias for alias in selected_identities if alias not in configured_identities
    )
    if unknown_identities:
        parser.error("authorization surface map contains an unknown configured identity")

    target_url = _target_url_from_brief(parsed.brief, explicit=parsed.target_url)
    if not is_local_url(target_url) and not parsed.allow_remote_target:
        parser.error("remote targets require --authorized-remote-target")
    try:
        assert_authorized_target(
            target_url,
            scope=brief.scope,
            allow_remote_target=parsed.allow_remote_target,
            agent_name="authorization surface map",
        )
    except ValueError:
        parser.error("authorization surface target is invalid or outside engagement scope")

    if not 1 <= parsed.timeout_seconds <= 60:
        parser.error("--timeout-seconds must be between 1 and 60")
    if not 1 <= parsed.max_urls <= 50:
        parser.error("--max-urls must be between 1 and 50")
    parsed.traffic_policy = "low-noise"
    _resolve_traffic_policy_args(
        parser,
        parsed,
        default_mode="low-noise",
        roe_max_rps=brief.roe.max_rps,
    )

    env_file = parsed.env_file or _discover_auth_env_file(parsed.brief)
    try:
        secret_resolver = environment_secret_resolver(env_file=env_file)
    except EnvironmentFileError as exc:
        parser.error(f"cannot load authentication secrets: {_concise_cli_error(exc)}")

    run_dir = parsed.run_dir or _default_run_dir(parsed.brief, "auth-surface-map")
    if run_dir.exists() or run_dir.is_symlink():
        parser.error("authorization surface run directory must be new and empty")
    try:
        run_dir.mkdir(parents=True, mode=0o700)
        run_dir.chmod(0o700)
        traffic_policy = TrafficPolicyController.open(
            run_dir / "traffic-policy.json",
            target_url=target_url,
            config=_traffic_policy_config(parsed),
        )
    except (OSError, TrafficPolicyError, ValueError) as exc:
        parser.error(f"cannot initialize authorization surface map: {_concise_cli_error(exc)}")

    try:
        with build_managed_authorization_matrix(
            config=authentication,
            target_url=target_url,
            identities=selected_identities,
            timeout_seconds=parsed.timeout_seconds,
            allow_remote_target=parsed.allow_remote_target,
            in_scope=brief.scope.in_scope,
            out_of_scope=brief.scope.out_of_scope,
            max_rps=float(parsed.traffic_max_rps),
            secret_resolver=secret_resolver,
            traffic_policy=traffic_policy,
        ) as runtime:
            result = run_authorization_surface_map(
                target_url,
                runtime=runtime,
                include_anonymous=parsed.include_anonymous,
                max_urls=parsed.max_urls,
            )
    except (
        AuthorizationMatrixRuntimeError,
        ConfiguredAuthenticationError,
        SecretResolutionError,
        SessionError,
        ValueError,
    ) as exc:
        parser.error(f"authorization surface map could not run: {_concise_cli_error(exc)}")

    receipt_path = run_dir / "authorization-surface-map.json"
    try:
        _atomic_write_cli_text(
            receipt_path,
            json.dumps(result.to_json(), indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )
    except OSError as exc:
        parser.error(f"cannot write authorization surface receipt: {_concise_cli_error(exc)}")

    if parsed.json:
        _write_line(json.dumps(result.to_json(), indent=2, sort_keys=True))
    else:
        _write_line(banner("AUTH SURFACE MAP", "role-aware read-only discovery"))
        _write_line(f"{'target':<12}{redacted_target_url(target_url)}")
        state = badge("complete", "ok") if result.complete else badge("incomplete", "warn")
        _write_line(f"{state} {len(result.candidates)} review candidates")
        for actor in result.actors:
            _write_line(
                f"{'actor':<12}{actor.actor} · {actor.mapped_url_count} URLs · "
                f"{actor.observation_count} observations"
            )
        for candidate in result.candidates:
            reasons = ", ".join(candidate.reason_codes)
            _write_line(
                f"{badge('candidate', 'warn')} {candidate.method} "
                f"{candidate.route_shape} · {reasons}"
            )
        if result.coverage_limited:
            coverage = ", ".join(result.coverage_reason_codes)
            _write_line(f"{badge('coverage limited', 'warn')} {coverage}")
        traffic = result.traffic_delta
        _write_line(
            f"{'traffic':<12}{traffic.physical_request_count} physical requests · "
            f"accounting={traffic.current_accounting_status}"
        )
        _write_line(f"{badge('receipt', 'info')} {receipt_path} · mode=0600")
        _write_line(
            f"{badge('next', 'info')} Candidates are not vulnerabilities. "
            "Confirm a known resource with `ravage auth matrix`."
        )

    if not result.complete:
        raise SystemExit(1)


def _auth_matrix(parser: argparse.ArgumentParser, parsed: argparse.Namespace) -> None:
    brief = _load_engagement_brief_for_cli(parser, parsed.brief)
    authentication = brief.authentication
    if authentication is None or len(authentication.identities) < 2:
        parser.error("authorization matrix requires at least two configured identities")
    configured_identities = tuple(
        identity.alias for identity in authentication.identities
    )

    target_url = _target_url_from_brief(parsed.brief, explicit=parsed.target_url)
    if not is_local_url(target_url) and not parsed.allow_remote_target:
        parser.error("remote targets require --authorized-remote-target")
    try:
        assert_authorized_target(
            target_url,
            scope=brief.scope,
            allow_remote_target=parsed.allow_remote_target,
            agent_name="authorization matrix",
        )
    except ValueError:
        parser.error("authorization matrix target is invalid or outside engagement scope")

    try:
        plan = load_authorization_matrix_plan(
            parsed.plan,
            known_identities=configured_identities,
        )
    except AuthorizationMatrixPlanError as exc:
        parser.error(f"invalid authorization matrix plan: {_concise_cli_error(exc)}")

    selected_identities = tuple(
        sorted(
            {
                actor
                for case in plan.cases
                for actor in case.expect
                if actor != ANONYMOUS_ACTOR
            }
        )
    )
    if len(selected_identities) < 2:
        parser.error("authorization matrix plan must compare at least two configured identities")
    for case in plan.cases:
        if not same_origin(target_url, case.url):
            parser.error(f"matrix case {case.case_id!r} must use the target origin")
        try:
            assert_scoped_same_origin(
                target_url,
                case.url,
                scope=brief.scope,
                allow_remote_target=parsed.allow_remote_target,
            )
        except ValueError:
            parser.error(f"matrix case {case.case_id!r} is outside engagement scope")

    if not 1 <= parsed.timeout_seconds <= 60:
        parser.error("--timeout-seconds must be between 1 and 60")
    parsed.traffic_policy = "low-noise"
    _resolve_traffic_policy_args(
        parser,
        parsed,
        default_mode="low-noise",
        roe_max_rps=brief.roe.max_rps,
    )

    env_file = parsed.env_file or _discover_auth_env_file(parsed.brief)
    try:
        secret_resolver = environment_secret_resolver(env_file=env_file)
    except EnvironmentFileError as exc:
        parser.error(f"cannot load authentication secrets: {_concise_cli_error(exc)}")

    run_dir = parsed.run_dir or _default_run_dir(parsed.brief, "auth-matrix")
    if run_dir.exists() or run_dir.is_symlink():
        parser.error("authorization matrix run directory must be new and empty")
    try:
        run_dir.mkdir(parents=True, mode=0o700)
        run_dir.chmod(0o700)
        traffic_policy = TrafficPolicyController.open(
            run_dir / "traffic-policy.json",
            target_url=target_url,
            config=_traffic_policy_config(parsed),
        )
    except (OSError, TrafficPolicyError, ValueError) as exc:
        parser.error(f"cannot initialize authorization matrix: {_concise_cli_error(exc)}")

    try:
        with build_managed_authorization_matrix(
            config=authentication,
            target_url=target_url,
            identities=selected_identities,
            timeout_seconds=parsed.timeout_seconds,
            allow_remote_target=parsed.allow_remote_target,
            in_scope=brief.scope.in_scope,
            out_of_scope=brief.scope.out_of_scope,
            max_rps=float(parsed.traffic_max_rps),
            secret_resolver=secret_resolver,
            traffic_policy=traffic_policy,
        ) as runtime:
            result = run_authorization_matrix(
                plan,
                runtime=runtime,
                secret_resolver=secret_resolver,
            )
    except (
        AuthorizationMatrixRuntimeError,
        ConfiguredAuthenticationError,
        SecretResolutionError,
        SessionError,
        ValueError,
    ) as exc:
        parser.error(f"authorization matrix could not run: {_concise_cli_error(exc)}")

    receipt_path = run_dir / "authorization-matrix.json"
    try:
        _atomic_write_cli_text(
            receipt_path,
            json.dumps(result.to_json(), indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )
    except OSError as exc:
        parser.error(f"cannot write authorization matrix receipt: {_concise_cli_error(exc)}")

    if parsed.json:
        _write_line(json.dumps(result.to_json(), indent=2, sort_keys=True))
    else:
        _write_line(banner("AUTH MATRIX", "isolated read-only authorization checks"))
        _write_line(f"{'target':<10}{redacted_target_url(target_url)}")
        for case in result.cases:
            if case.verdict is AuthorizationVerdict.CONFIRMED_VIOLATION:
                actors = ", ".join(case.violation_actors)
                _write_line(f"{badge('vulnerable', 'fail')} {case.case_id} · exposed to {actors}")
            elif case.verdict is AuthorizationVerdict.NO_VIOLATION:
                _write_line(f"{badge('no violation', 'ok')} {case.case_id}")
            else:
                reasons = ", ".join(case.reason_codes) or "comparison was not conclusive"
                _write_line(f"{badge('inconclusive', 'warn')} {case.case_id} · {reasons}")
        traffic = result.traffic_delta
        _write_line(
            f"{'traffic':<10}{traffic.physical_request_count} physical requests · "
            f"accounting={traffic.current_accounting_status}"
        )
        _write_line(f"{badge('receipt', 'info')} {receipt_path} · mode=0600")

    if result.verdict is not AuthorizationVerdict.NO_VIOLATION:
        raise SystemExit(1)


def _discover_auth_env_file(brief_path: Path) -> Path | None:
    candidates = (
        brief_path.parent / ".env.ravage",
        brief_path.parent / ".env",
    )
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        if candidate.is_file():
            return candidate
    return None


def _write_auth_next_commands(
    *,
    brief_path: Path,
    env_path: Path | None,
    identity: str,
    target_url: str,
    include_check: bool = True,
) -> None:
    env_option = f" --env-file {shlex.quote(str(env_path))}" if env_path is not None else ""
    remote_option = " --authorized-remote-target" if not is_local_url(target_url) else ""
    quoted_brief = shlex.quote(str(brief_path))
    quoted_identity = shlex.quote(identity)
    if include_check:
        _write_line(
            f"{badge('next', 'info')} ravage auth check {quoted_brief} "
            f"--identity {quoted_identity}{env_option}{remote_option}"
        )
    _write_line(
        f"{badge('next', 'info')} ravage scan {quoted_brief} --identity {quoted_identity}"
        f"{env_option}{remote_option} --all-probes --report"
    )
    _write_line(
        f"{badge('agent', 'info')} ravage attack {quoted_brief} --identity {quoted_identity}"
        f"{env_option}{remote_option} --allow-paid-models --report"
    )


def _authbench(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="ravage authbench",
        description="Validate Ravage's managed authentication-session substrate.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the versioned machine-readable result instead of human output",
    )
    parsed = parser.parse_args(args)

    result = authbench.run_authbench(authbench.ManagedSessionAuthBenchStrategy())
    if parsed.json:
        _write_line(json.dumps(result.to_dict(), sort_keys=True))
    else:
        _write_line(banner("AUTHBENCH", "managed authentication-session acceptance"))
        for case in result.cases:
            state = "pass" if case.passed else "fail"
            detail = _authbench_failure_detail(case)
            suffix = f" — {detail}" if detail else ""
            _write_line(f"{badge(state, 'ok' if case.passed else 'fail')} {case.case_id}{suffix}")
        summary_state = "pass" if result.passed else "fail"
        _write_line(
            f"{badge(summary_state, 'ok' if result.passed else 'fail')} "
            f"{result.passed_cases}/{result.total_cases} cases"
        )
    if not result.passed:
        raise SystemExit(1)


def _authbench_failure_detail(case: object) -> str:
    error = getattr(case, "error", None)
    if isinstance(error, str) and error:
        return error
    failed_checks = [
        str(check.name)
        for check in getattr(case, "checks", ())
        if not bool(getattr(check, "passed", False))
    ]
    return ", ".join(failed_checks)


def _benchmark_compat(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="ravage --benchmark",
        description="Run the localhost manifest regression harness.",
    )
    parser.add_argument("--benchmark", type=Path, required=True, dest="manifest")
    parser.add_argument("--output-dir", type=Path, default=Path("runs/benchmark"))
    parser.add_argument("--benchmark-model-config", type=Path)
    parser.add_argument("--benchmark-model-profile", default="local-ollama")
    parser.add_argument(
        "--benchmark-model-tier",
        choices=["high", "mid", "low"],
        default="mid",
    )
    parser.add_argument("--benchmark-max-turns", type=int, default=40)
    parsed = parser.parse_args(args)
    report = run_benchmark(
        manifest_path=parsed.manifest,
        output_dir=parsed.output_dir,
        overrides=BenchmarkOverrides(
            max_turns=parsed.benchmark_max_turns,
            model_profile=parsed.benchmark_model_profile,
            model_config=parsed.benchmark_model_config,
            model_tier=parsed.benchmark_model_tier,
        ),
    )
    if not bool(report.get("passed")):
        raise SystemExit(1)


def _attack_config(path: Path) -> None:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SystemExit(f"unable to load attack config {path}: {exc}") from None
    if not isinstance(payload, dict):
        raise SystemExit(f"attack config {path} must contain a mapping")
    mode = str(payload.get("mode") or "")
    if mode != "benchmark":
        raise SystemExit(f"unsupported attack config mode {mode!r}; expected 'benchmark'")
    raw_benchmark = payload.get("benchmark")
    if not isinstance(raw_benchmark, dict):
        raise SystemExit("attack config benchmark section must contain a mapping")
    base = path.resolve().parent
    manifest = _config_path(raw_benchmark.get("manifest"), base=base, required=True)
    output_dir = _config_path(
        raw_benchmark.get("output_dir") or "runs/benchmark",
        base=base,
        required=True,
    )
    raw_model = raw_benchmark.get("model")
    model = raw_model if isinstance(raw_model, dict) else {}
    model_config = _config_path(model.get("config"), base=base, required=False)
    report = run_benchmark(
        manifest_path=manifest,
        output_dir=output_dir,
        overrides=BenchmarkOverrides(
            max_turns=int(raw_benchmark.get("max_turns") or 40),
            model_profile=str(model.get("profile") or "local-ollama"),
            model_config=model_config,
            model_tier=str(model.get("tier") or "mid"),
        ),
    )
    if not bool(report.get("passed")):
        raise SystemExit(1)


def _config_path(value: object, *, base: Path, required: bool) -> Path | None:
    if value is None or not str(value).strip():
        if required:
            raise SystemExit("attack config is missing a required path")
        return None
    path = Path(str(value))
    return path if path.is_absolute() else (base / path).resolve()


def _code_bug(args: list[str]) -> None:
    invocation = build_code_bug_invocation(args)
    if invocation.command == "help":
        _write_line(invocation.help_text)
        raise SystemExit(0)
    if invocation.command == "attack":
        _attack(list(invocation.args))
        return
    if invocation.command == "xben":
        _xben(list(invocation.args))
        return


def _pin_parsed_knowledge_pack(
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
) -> None:
    path = getattr(parsed, "knowledge_pack", None)
    expected_sha256 = getattr(parsed, "knowledge_pack_sha256", None)
    try:
        metadata = describe_knowledge_pack(path, expected_sha256=expected_sha256)
    except (FileNotFoundError, OSError, ValueError) as exc:
        parser.error(str(exc))
    parsed.knowledge_pack_sha256 = None if metadata is None else metadata.sha256


def _resolve_traffic_policy_args(  # noqa: C901, PLR0912 - fail-closed profile checks.
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
    *,
    default_mode: str,
    roe_max_rps: float,
) -> None:
    mode = str(getattr(parsed, "traffic_policy", None) or default_mode)
    request_limit = getattr(parsed, "max_physical_requests", None)
    requested_rps = getattr(parsed, "traffic_max_rps", None)
    request_profile = getattr(parsed, "traffic_request_profile", None)
    if request_profile == _TESTFIRE_REQUEST_PROFILE:
        if getattr(parsed, "autonomous_route", False):
            parser.error("the TestFire request profile disables autonomous routing")
        if getattr(parsed, "recovery_profile", "off") != "off":
            parser.error("the TestFire request profile disables recovery roles")
        if mode != "low-noise":
            parser.error("the TestFire request profile requires --traffic-policy low-noise")
        if request_limit is None:
            request_limit = _TESTFIRE_MAX_PHYSICAL_REQUESTS
        elif request_limit > _TESTFIRE_MAX_PHYSICAL_REQUESTS:
            parser.error("the TestFire request profile permits at most 24 physical requests")
        if requested_rps is None:
            requested_rps = _TESTFIRE_MAX_RPS
        elif requested_rps > _TESTFIRE_MAX_RPS:
            parser.error("the TestFire request profile permits at most 0.5 RPS")
    if request_limit is not None and request_limit <= 0:
        parser.error("--max-physical-requests must be a positive integer")
    if requested_rps is not None and (
        not math.isfinite(float(requested_rps)) or requested_rps <= 0 or requested_rps >= 1
    ):
        parser.error("--traffic-max-rps must be greater than zero and strictly below 1")
    if mode == "observe":
        if request_limit is not None or requested_rps is not None:
            parser.error(
                "--max-physical-requests and --traffic-max-rps require --traffic-policy low-noise"
            )
        parsed.traffic_policy = mode
        return
    if mode != "low-noise":
        parser.error(f"unsupported traffic policy: {mode}")
    if not math.isfinite(float(roe_max_rps)) or roe_max_rps <= 0:
        parser.error("engagement max RPS must be positive and finite")
    effective_rps = min(float(requested_rps or 0.5), float(roe_max_rps))
    if not math.isfinite(effective_rps) or effective_rps <= 0 or effective_rps >= 1:
        parser.error("effective low-noise traffic RPS must be greater than zero and below 1")
    parsed.traffic_policy = mode
    parsed.max_physical_requests = request_limit or 300
    parsed.traffic_max_rps = effective_rps


def _traffic_policy_config(parsed: argparse.Namespace) -> TrafficPolicyConfig:
    if parsed.traffic_policy == "low-noise":
        config = TrafficPolicyConfig.low_noise(
            max_physical_requests=int(parsed.max_physical_requests),
            max_rps=float(parsed.traffic_max_rps),
        )
        if getattr(parsed, "traffic_request_profile", None) == _TESTFIRE_REQUEST_PROFILE:
            return replace(
                config,
                allowed_request_routes=(
                    "GET /bank/main.jsp",
                    "GET /login.jsp",
                    "HEAD /bank/main.jsp",
                    "HEAD /login.jsp",
                    "POST /doLogin",
                ),
                allowed_query_fields=("mode",),
                allowed_explicit_headers=(
                    "accept",
                    "accept-encoding",
                    "content-type",
                    "user-agent",
                ),
                allowed_form_fields=("btnSubmit", "passw", "uid"),
                max_request_body_bytes=_TESTFIRE_MAX_REQUEST_BODY_BYTES,
                request_value_profile=_TESTFIRE_REQUEST_PROFILE,
                require_public_addresses=True,
            )
        return config
    return TrafficPolicyConfig()


def _resume_traffic_policy_workspace(parsed: argparse.Namespace) -> Path | None:
    resume_from = getattr(parsed, "resume_from", None)
    if isinstance(resume_from, Path):
        candidate = _attack_resume_workspace(resume_from)
        return candidate if (candidate / "working_state.json").is_file() else None
    if not bool(getattr(parsed, "resume", False)):
        return None
    workspace_dir = getattr(parsed, "workspace_dir", None)
    if isinstance(workspace_dir, Path):
        candidate = workspace_dir
    else:
        run_dir = getattr(parsed, "run_dir", None)
        if not isinstance(run_dir, Path):
            return None
        candidate = run_dir / "workspace"
    return candidate if (candidate / "working_state.json").is_file() else None


def _inherit_resume_traffic_policy_args(
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
    *,
    workspace: Path,
) -> None:
    ledger_path = workspace / "traffic-policy.json"
    legacy_lock_path = ledger_path.with_name(f"{ledger_path.name}.lock")
    requested_mode = getattr(parsed, "traffic_policy", None)
    legacy_observe_compatible = (
        requested_mode in {None, "observe"}
        and getattr(parsed, "max_physical_requests", None) is None
        and getattr(parsed, "traffic_max_rps", None) is None
    )
    if (
        not ledger_path.exists()
        and not ledger_path.is_symlink()
        and not legacy_lock_path.exists()
        and legacy_observe_compatible
    ):
        # State created before whole-run traffic accounting can resume only in
        # non-enforcing observe mode.  The child creates a new ledger and marks
        # it lower-bound before authentication or target traffic begins.
        parsed.traffic_policy = "observe"
        parsed.legacy_resume_without_traffic_ledger = True
        return
    try:
        inspection = load_traffic_policy_snapshot(ledger_path)
    except (OSError, TrafficPolicyError, ValueError) as exc:
        parser.error(
            "cannot resume attack without its valid traffic policy ledger: "
            f"{_concise_cli_error(exc)}"
        )
    saved = inspection.config
    saved_mode = "low-noise" if saved.mode is TrafficPolicyMode.ENFORCE else "observe"
    if getattr(parsed, "traffic_policy", None) is None:
        parsed.traffic_policy = saved_mode
    if saved_mode != "low-noise" or parsed.traffic_policy != "low-noise":
        return
    if getattr(parsed, "max_physical_requests", None) is None:
        parsed.max_physical_requests = saved.max_physical_requests
    if getattr(parsed, "traffic_max_rps", None) is None:
        parsed.traffic_max_rps = saved.max_rps

def _attack(  # noqa: C901, PLR0912, PLR0915 - CLI options are intentionally explicit.
    args: list[str],
) -> None:
    parser = argparse.ArgumentParser(
        prog="ravage attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Run the scoped ai-web pentest agent against a local target or an "
            "explicitly authorized remote URL."
        ),
        epilog=(
            "Start with: ravage init URL (or ravage init --target-url URL)\n"
            "  --brief ravage-brief.yaml --env-file .env.ravage.\n"
            "Ravage loads that private env file directly; do not shell-source it.\n"
            "Review scope, rules, budget, context.description, and context.win_condition,\n"
            "then follow the printed [next] command.\n"
            "Authorized remote URLs always require --authorized-remote-target.\n"
            "Unauthenticated process-capable remote runs also require --tool-runtime docker.\n"
            "A selected managed identity uses HTTP-only execution and blocks command, Python,\n"
            "and process lanes.\n"
            "Process tools use Docker by default. --tool-runtime host is an explicit opt-in\n"
            "for trusted localhost targets and runs model-selected code on this machine.\n"
            "To print only a brief, use ravage brief template --target-url URL.\n"
            "Put useful target notes, challenge descriptions and success criteria in the brief."
        ),
    )
    parser.add_argument("brief", type=Path, nargs="?", help="engagement brief YAML")
    parser.add_argument("--target-url", help="override the first HTTP(S) URL in scope.in_scope")
    parser.add_argument(
        "--run-dir",
        type=Path,
        help="run directory; defaults to runs/<brief>-<timestamp>",
    )
    parser.add_argument("--db-path", type=Path)
    parser.add_argument("--workspace-dir", type=Path)
    parser.add_argument(
        "--source-root",
        type=Path,
        help="local source directory for source-assisted analysis",
    )
    parser.add_argument(
        "--resume-from",
        type=Path,
        help=("existing run directory, workspace, working_state.json, or report to resume"),
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help=(
            "load model provider and authentication secret variables without shell "
            "sourcing; defaults to .env.ravage or .env beside the brief"
        ),
    )
    parser.add_argument(
        "--identity",
        help=(
            "use one managed identity from brief.authentication; defaults to the only "
            "configured identity"
        ),
    )
    parser.add_argument(
        "--agent-mode",
        choices=["ctf-free-roam", "hybrid"],
        default="ctf-free-roam",
    )
    parser.add_argument("--model-config", type=Path)
    parser.add_argument(
        "--model-profile",
        help="model profile; inferred from configured provider keys when omitted",
    )
    parser.add_argument("--model-tier", choices=["high", "mid", "low"])
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument(
        "--traffic-policy",
        choices=["observe", "low-noise"],
        help=(
            "whole-run physical HTTP policy; defaults to low-noise for authorized remote "
            "targets and observe for local targets"
        ),
    )
    parser.add_argument(
        "--max-physical-requests",
        type=int,
        help="whole-run physical HTTP request cap in low-noise mode (default: 300)",
    )
    parser.add_argument(
        "--traffic-max-rps",
        type=float,
        help="strictly sub-1 whole-run HTTP dispatch rate in low-noise mode (default: 0.5)",
    )
    parser.add_argument(
        "--traffic-request-profile",
        choices=[_TESTFIRE_REQUEST_PROFILE],
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--recovery-profile",
        choices=["off", "recovery-v1"],
        default="off",
        help="opt into bounded sequential recovery roles",
    )
    parser.add_argument(
        "--autonomous-route",
        action="store_true",
        help="after an unsolved base run, enter the bounded autonomous route",
    )
    parser.add_argument(
        "--autonomous-route-engine",
        choices=AUTONOMOUS_ROUTE_ENGINES,
        default="frontier",
    )
    parser.add_argument("--autonomous-route-max-requests", type=int, default=24)
    parser.add_argument(
        "--operational-profile",
        choices=[item.value for item in GraphOperationalProfileName],
        help=(
            "agent-graph structured HTTP profile; authorized remote graph runs default to low-noise"
        ),
    )
    parser.add_argument(
        "--authorized-remote-target",
        action="store_true",
        help=("confirm explicit authorization for a remote target listed in the brief"),
    )
    parser.add_argument(
        "--knowledge-pack",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--knowledge-pack-sha256", help=argparse.SUPPRESS)
    parser.add_argument("--knowledge-pack-limit", type=int, default=4, help=argparse.SUPPRESS)
    parser.add_argument(
        "--knowledge-pack-max-chars",
        type=int,
        default=6_000,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--tool-runtime",
        choices=["host", "docker", "auto"],
        help=(
            "runtime for command/Python/process tools; authenticated attacks use the "
            "managed HTTP-only lane instead; defaults to Docker and host requires explicit opt-in"
        ),
    )
    parser.add_argument("--tool-image", default=DEFAULT_TOOL_IMAGE)
    parser.add_argument(
        "--display",
        choices=["auto", "live", "plain", "quiet"],
        default="auto",
        help="run progress display (default: live on a terminal, plain when piped)",
    )
    parser.add_argument(
        "--show-agent-actions",
        action="store_true",
        help="show concrete probe requests and response observations as they happen",
    )
    tool_recon = parser.add_mutually_exclusive_group()
    tool_recon.add_argument("--tool-recon", dest="tool_recon", action="store_true")
    tool_recon.add_argument("--no-tool-recon", dest="tool_recon", action="store_false")
    parser.set_defaults(tool_recon=True)
    parser.add_argument("--tool-recon-tool", action="append", default=[])
    parser.add_argument("--tool-recon-ports", default="")
    parser.add_argument("--allow-degraded", action="store_true")
    parser.add_argument(
        "--allow-paid-models",
        action="store_true",
        help="acknowledge and allow a paid-risk model route",
    )
    parser.add_argument(
        "--allow-empty-description",
        action="store_true",
        help=(
            "run without brief context.description; intended only for deliberate "
            "blind generic recon"
        ),
    )
    parser.add_argument(
        "--memory",
        choices=["off"],
        default="off",
        help=(
            "accepted for benchmark/reproducibility parity; active ai-web "
            "memory is not wired in this CLI"
        ),
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="write a redacted report after the agent finishes",
    )
    parser.add_argument("--report-path", type=Path)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="continue from an existing run workspace; otherwise existing attack state is refused",
    )
    parsed = parser.parse_args(args)
    _pin_parsed_knowledge_pack(parser, parsed)
    if parsed.autonomous_route and parsed.recovery_profile != "off":
        parser.error("--autonomous-route requires --recovery-profile off")
    if parsed.brief is None:
        parser.error("an engagement brief is required; run `ravage init URL` first")

    target_url = _target_url_from_brief(parsed.brief, explicit=parsed.target_url)
    brief = load_engagement_brief(parsed.brief)
    try:
        parsed.source_root = resolve_source_root(explicit=parsed.source_root)
    except ValueError as exc:
        parser.error(str(exc))
    parsed.identity = _selected_attack_identity(
        parser,
        brief=brief,
        requested=parsed.identity,
        default_when_single=True,
    )
    try:
        auth_environment_keys = _attack_auth_environment_keys(
            brief=brief,
            identity=parsed.identity,
        )
    except ConfiguredAuthenticationError as exc:
        parser.error(f"cannot configure attack identity: {_concise_cli_error(exc)}")
    env_file = parsed.env_file or discover_env_file(brief_path=parsed.brief)
    if env_file is not None:
        try:
            _load_attack_environment(
                env_file,
                excluded_keys=auth_environment_keys,
            )
        except (EnvironmentFileError, OSError, UnicodeError) as exc:
            parser.error(f"cannot load environment file {env_file}: {_concise_cli_error(exc)}")
    parsed.model_profile = parsed.model_profile or (
        _preferred_model_profile() if env_file is not None else "local-ollama"
    )
    parsed.model_tier = parsed.model_tier or (
        "low" if parsed.model_profile.startswith("hosted-") else "mid"
    )

    _require_attack_description(
        parser,
        brief=brief,
        brief_path=parsed.brief,
        allow_empty=parsed.allow_empty_description,
    )
    _require_paid_model_opt_in(
        parser,
        model_config=parsed.model_config,
        model_profile=parsed.model_profile,
        model_tier=parsed.model_tier,
        allow_paid_models=parsed.allow_paid_models,
    )
    remote_target = not is_local_url(target_url)
    if remote_target and parsed.traffic_policy is None:
        parsed.traffic_policy = "low-noise"
    resume_traffic_workspace = _resume_traffic_policy_workspace(parsed)
    if resume_traffic_workspace is not None:
        _inherit_resume_traffic_policy_args(
            parser,
            parsed,
            workspace=resume_traffic_workspace,
        )
    _resolve_traffic_policy_args(
        parser,
        parsed,
        default_mode="low-noise" if remote_target else "observe",
        roe_max_rps=brief.roe.max_rps,
    )
    if parsed.traffic_policy == "low-noise":
        parsed.tool_recon = False
        parsed.tool_recon_tool = []
        parsed.tool_recon_ports = ""
    if remote_target and not parsed.authorized_remote_target:
        parser.error("remote targets require --authorized-remote-target")
    if remote_target and parsed.tool_runtime == "host" and parsed.identity is None:
        parser.error("authorized remote targets require --tool-runtime docker or auto")
    if (
        remote_target
        and parsed.identity is None
        and parsed.autonomous_route
        and parsed.autonomous_route_engine != "agent-graph"
    ):
        parser.error(
            "authorized remote autonomous routing requires --autonomous-route-engine agent-graph"
        )
    parsed.tool_runtime = parsed.tool_runtime or "docker"
    if parsed.operational_profile is not None and parsed.autonomous_route_engine != "agent-graph":
        parser.error("--operational-profile applies only to the agent-graph route")
    profile = GraphOperationalProfileName(
        parsed.operational_profile
        or (
            GraphOperationalProfileName.LOW_NOISE.value
            if remote_target
            else GraphOperationalProfileName.STANDARD.value
        )
    )
    try:
        assert_authorized_target(
            target_url,
            scope=brief.scope,
            allow_remote_target=parsed.authorized_remote_target,
            agent_name="attack",
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from None

    run_dir = parsed.run_dir or _default_run_dir(parsed.brief, "attack")
    resume_workspace = (
        _attack_resume_workspace(parsed.resume_from)
        if parsed.resume_from is not None and parsed.run_dir is None
        else None
    )
    if resume_workspace is not None:
        run_dir = resume_workspace.parent
    db_path = parsed.db_path or run_dir / "audit.db"
    workspace_dir = parsed.workspace_dir or resume_workspace or run_dir / "workspace"
    report_path = parsed.report_path
    if (
        report_path is None
        and parsed.resume_from is not None
        and parsed.resume_from.is_file()
        and parsed.resume_from.name != "working_state.json"
    ):
        report_path = parsed.resume_from
    if parsed.report and report_path is None:
        report_path = run_dir / "report.json"
    if report_path is not None:
        _validate_report_output(parser, report_path)
    _assert_fresh_attack_workspace(
        run_dir=run_dir,
        workspace_dir=workspace_dir,
        resume=parsed.resume or parsed.resume_from is not None,
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_line(banner("ATTACK"))
    _write_line(f"{'target':<10}{redacted_target_url(target_url)}")
    _write_line(f"{'run':<10}{redacted_artifact_path(run_dir)}")
    _write_line(f"{'workspace':<10}{redacted_artifact_path(workspace_dir)}")
    _write_line(f"{'audit':<10}{redacted_artifact_path(db_path)}")
    if parsed.identity:
        _write_line(f"{'identity':<10}{parsed.identity} · managed HTTP session")
    if env_file is not None:
        _write_line(f"{'env':<10}{redacted_artifact_path(env_file)}")
    if report_path is not None:
        _write_line(f"{'report':<10}{redacted_artifact_path(report_path)}")
    if parsed.traffic_policy == "low-noise":
        _write_line(
            f"{'traffic':<10}low-noise · {parsed.traffic_max_rps:g} RPS · "
            f"{parsed.max_physical_requests} physical requests max"
        )
    else:
        _write_line(f"{'traffic':<10}observe · physical requests accounted without enforcement")

    if parsed.model_profile.startswith("local-"):
        _write_line(
            "note       local models are useful for setup and iteration; "
            "hosted routes generally provide stronger autonomous closure"
        )
    if remote_target and parsed.identity:
        _write_line("scope      remote target traffic uses the managed HTTP identity lane")
    elif remote_target and parsed.traffic_policy == "low-noise":
        _write_line("scope      remote target traffic uses the native metered HTTP lane")
    elif remote_target:
        _write_line("scope      remote tools are forced through the target-scoped Docker network")
    command = _local_attack_command(
        parsed=parsed,
        target_url=target_url,
        db_path=db_path,
        workspace_dir=workspace_dir,
        report_path=report_path,
        profile=profile,
        auth_env_file=env_file,
    )
    try:
        returncode = _run_subprocess_tee_stdout(command, run_dir / "stdout.log")
    except BaseException:
        with suppress(Exception):
            _write_attack_result(
                run_dir=run_dir,
                brief_path=parsed.brief,
                workspace_dir=workspace_dir,
                audit_path=db_path,
                report_path=report_path,
                flag_objective="capture_flag" in brief.objectives,
                target_url=target_url,
            )
        raise
    _write_attack_result(
        run_dir=run_dir,
        brief_path=parsed.brief,
        workspace_dir=workspace_dir,
        audit_path=db_path,
        report_path=report_path,
        flag_objective="capture_flag" in brief.objectives,
        target_url=target_url,
    )
    if returncode:
        raise SystemExit(returncode)
    _write_line(f"{badge('done', 'ok')} run_dir={run_dir}")


def _write_attack_result(  # noqa: C901, PLR0912, PLR0913, PLR0915
    *,
    run_dir: Path,
    brief_path: Path,
    workspace_dir: Path,
    audit_path: Path,
    report_path: Path | None,
    flag_objective: bool,
    target_url: str = "",
) -> None:
    event_paths = _attack_result_event_paths(workspace_dir)

    brief = None
    with suppress(OSError, TypeError, ValueError, yaml.YAMLError):
        brief = load_engagement_brief(brief_path)
    active_engagement_id = str(getattr(brief, "engagement_id", "") or "")
    active_scope = getattr(brief, "scope", None)

    finding_keys: set[str] = set()
    finding_summaries: list[tuple[str, str, str, str, str]] = []
    severity_counts: dict[str, int] = {}
    candidate_signals = 0
    status = "incomplete"
    termination_reason = "terminal_event_missing"
    saw_event = False
    for record in _iter_attack_result_events(event_paths):
        saw_event = True
        event = record.event
        kind = str(event.get("kind") or "")
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if kind == "finding_confirmed":
            if not active_engagement_id:
                continue
            if str(payload.get("engagement_id") or "") != active_engagement_id:
                continue
            if confirmed_finding_evidence_failures(payload, scope=active_scope):
                continue
            finding_summary = confirmed_finding_result_line(payload)
            if not finding_summary:
                continue
            finding_key = _safe_result_record_id(payload.get("finding_id"))
            event_id = _safe_result_record_id(event.get("event_id"))
            if not finding_key or not event_id:
                continue
            if finding_key in finding_keys:
                continue
            finding_keys.add(finding_key)
            finding_summaries.append(
                (
                    finding_summary,
                    record.source,
                    redacted_artifact_path(record.path),
                    event_id,
                    finding_key,
                )
            )
            severity = str(payload.get("severity") or "informational").strip().lower()
            if severity not in {"critical", "high", "medium", "low", "informational"}:
                severity = "informational"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            continue
        if kind == "tool_run_probe":
            display_summary = payload.get("display_summary")
            if isinstance(display_summary, dict):
                candidate_signals += _safe_non_negative_int(display_summary.get("findings"))
            continue
        if kind == "agent_finished":
            recorded_status = str(payload.get("status") or "").strip().lower()
            if recorded_status in {
                "completed",
                "cancelled",
                "failed",
                "incomplete",
            }:
                status = recorded_status
            termination_reason = _attack_result_termination_reason(payload)
            continue
        if kind in {"frontier_route_finished", "autonomous_graph_finished"}:
            route_status = _safe_result_identifier(payload.get("status"))
            if route_status:
                status = route_status
                termination_reason = (
                    route_status if _result_status_is_warning(route_status, "") else ""
                )
            continue
        if kind in {"frontier_route_failed", "autonomous_graph_failed"}:
            status = "failed"
            termination_reason = ""
            continue
        if kind in {"frontier_route_cancelled", "autonomous_graph_cancelled"}:
            status = "cancelled"
            termination_reason = ""

    if not saw_event:
        termination_reason = "setup_or_runtime_failure"
    canonical_report_path = run_dir / "report.json"
    if brief is not None:
        report_status, report_completed = _canonical_attack_report_status(status)
        markdown_report_path, professional_report_path = _existing_attack_report_artifacts(
            report_path
        )
        write_json_report_artifact(
            brief_path=brief_path,
            target_url=target_url or first_http_target(brief),
            workspace_dir=workspace_dir,
            output_path=canonical_report_path,
            status=report_status,
            completed=report_completed,
            audit_db_path=audit_path,
            termination_reason=termination_reason,
            markdown_report_path=markdown_report_path,
            professional_report_path=professional_report_path,
        )
    validated_flags = load_validated_captured_flags(
        db_path=audit_path,
        workspace_path=workspace_dir,
        engagement_id=active_engagement_id or None,
    )
    finding_count = len(finding_keys)
    _write_line(banner("RESULT"))
    status_label = _attack_result_status_label(status, termination_reason)
    if _result_status_is_warning(status, termination_reason):
        status_label = f"warning · {status_label}"
    _write_line(f"{'status':<10}{status_label}")
    _write_line(f"{'traffic':<10}{_attack_result_traffic_summary(workspace_dir)}")
    if finding_count:
        details = [f"{finding_count} {_plural(finding_count, 'vulnerability')}"]
        for severity in ("critical", "high", "medium", "low", "informational"):
            count = severity_counts.get(severity, 0)
            if count:
                details.append(f"{severity.title()} {count}")
        _write_line(f"{'confirmed':<10}{' · '.join(details)}")
        for index, finding in enumerate(finding_summaries, start=1):
            summary, source, source_path, event_id, finding_id = finding
            _write_line(f"{f'finding {index}':<10}{summary}")
            _write_line(
                f"{f'source {index}':<10}{source} · {source_path} · "
                f"event={event_id} · finding={finding_id}"
            )
    else:
        _write_line(f"{'confirmed':<10}no vulnerabilities confirmed in this run")
    if candidate_signals:
        _write_line(
            f"{'signals':<10}{candidate_signals} probe "
            f"{_plural(candidate_signals, 'observation')} (not confirmations)"
        )
    if flag_objective or validated_flags:
        _write_line(
            f"{'proof':<10}{len(validated_flags)} {_plural(len(validated_flags), 'flag')} found"
        )
    safe_run_dir = redacted_artifact_path(run_dir)
    safe_workspace_dir = redacted_artifact_path(workspace_dir)
    stdout_path = run_dir / "stdout.log"
    if run_dir.exists():
        _write_line(f"{'run':<10}{safe_run_dir}")
    if stdout_path.exists():
        _write_line(f"{'log':<10}{redacted_artifact_path(stdout_path)}")
    if workspace_dir.exists():
        _write_line(f"{'workspace':<10}{safe_workspace_dir}")
    if report_path is not None and report_path.exists() and report_path != canonical_report_path:
        _write_line(f"{'report':<10}{redacted_artifact_path(report_path)}")
    if canonical_report_path.exists():
        _write_line(f"{'report':<10}{redacted_artifact_path(canonical_report_path)}")
    for source, events_path in event_paths:
        _write_line(f"{'events':<10}{source} · {redacted_artifact_path(events_path)}")
    if audit_path.exists():
        _write_line(f"{'audit':<10}{redacted_artifact_path(audit_path)}")

    report_exists = canonical_report_path.exists() or (
        report_path is not None and report_path.exists()
    )
    report_command = _attack_result_report_command(run_dir=run_dir, brief_path=brief_path)
    if not report_exists:
        _write_line(f"{'report':<10}not generated")
        _write_line(f"{'report cmd':<11}{report_command}")

    if not saw_event:
        if stdout_path.exists():
            next_step = (
                f"review {redacted_artifact_path(stdout_path)}, fix the setup/runtime "
                "failure, then rerun"
            )
        else:
            next_step = "fix the setup/runtime failure, then rerun the attack"
    elif finding_count and report_exists:
        next_step = "review the report for evidence, replay steps, and remediation"
    elif candidate_signals:
        next_step = "review the evidence; candidate signals still need validation"
    else:
        next_step = "review the evidence and report before drawing conclusions"
    _write_line(f"{'next':<10}{next_step}")


def _attack_result_traffic_summary(workspace_dir: Path) -> str:
    ledger_path = workspace_dir / "traffic-policy.json"
    if not ledger_path.exists():
        return "unavailable · traffic policy ledger missing"
    try:
        inspection = load_traffic_policy_snapshot(ledger_path)
    except (OSError, TrafficPolicyError, ValueError):
        return "unavailable · traffic policy ledger unreadable"
    snapshot = inspection.snapshot
    parts = [
        f"{snapshot.physical_request_count} physical requests",
        snapshot.accounting_status.replace("_", " "),
    ]
    if inspection.config.max_physical_requests is not None:
        parts.append(f"cap {inspection.config.max_physical_requests}")
    incomplete = snapshot.incomplete_request_count + snapshot.pending_dispatch_count
    if incomplete:
        parts.append(f"incomplete {incomplete}")
    if snapshot.unmetered_action_count:
        parts.append(f"opaque actions {snapshot.unmetered_action_count}")
    return " · ".join(parts)


def _attack_result_report_command(*, run_dir: Path, brief_path: Path) -> str:
    run_arg = shlex.quote(str(run_dir))
    brief_arg = shlex.quote(str(brief_path))
    return f"ravage report {run_arg} --brief {brief_arg}"


def _attack_result_event_paths(workspace_dir: Path) -> tuple[tuple[str, Path], ...]:
    candidates = (
        ("base", workspace_dir / "events.jsonl"),
        ("route", workspace_dir / "autonomous-route" / "events.jsonl"),
        ("graph", workspace_dir / "autonomous-route" / "agent-graph" / "events.jsonl"),
    )
    return tuple((source, path) for source, path in candidates if path.is_file())


def _iter_attack_result_events(
    paths: tuple[tuple[str, Path], ...],
) -> Iterator[_AttackResultEvent]:
    for source, path in paths:
        with (
            suppress(OSError, UnicodeError),
            path.open(encoding="utf-8", errors="replace") as stream,
        ):
            for line_number, line in enumerate(stream, start=1):
                if len(line) > _MAX_ATTACK_RESULT_EVENT_CHARS:
                    continue
                with suppress(json.JSONDecodeError):
                    event = json.loads(line)
                    if isinstance(event, dict):
                        yield _AttackResultEvent(
                            source=source,
                            path=path,
                            line_number=line_number,
                            event=event,
                        )


def _attack_result_termination_reason(payload: dict[str, object]) -> str:
    for key in ("termination_reason", "terminal_reason", "stop_reason"):
        reason = _safe_result_identifier(payload.get(key))
        if reason:
            return reason
    if payload.get("max_turns_reached") is True:
        return "max_turns_reached"
    if payload.get("cost_budget_exhausted") is True:
        return "cost_budget_exhausted"
    return ""


def _attack_result_status_label(status: str, termination_reason: str) -> str:
    value = termination_reason if status == "incomplete" and termination_reason else status
    return value.replace("_", " ")


def _canonical_attack_report_status(status: str) -> tuple[str, bool]:
    if status in {"completed", "solved"}:
        return "completed", True
    if status in {"failed", "error"}:
        return "error", False
    if status in {"cancelled", "interrupted"}:
        return "interrupted", False
    return "incomplete", False


def _existing_attack_report_artifacts(
    report_path: Path | None,
) -> tuple[Path | None, Path | None]:
    """Return optional report artifacts that were already written by the child run."""
    if report_path is None:
        return None, None
    suffix = report_path.suffix.lower()
    markdown_candidate = report_path if suffix in {"", ".md"} else report_path.with_suffix(".md")
    professional_candidate = report_path if suffix in {".pdf", ".docx"} else None
    markdown = markdown_candidate if markdown_candidate.is_file() else None
    professional = (
        professional_candidate
        if professional_candidate is not None and professional_candidate.is_file()
        else None
    )
    return markdown, professional


def _result_status_is_warning(status: str, termination_reason: str) -> bool:
    return (
        status.endswith("_exhausted")
        or status
        in {
            "exhausted",
            "incomplete",
            "interrupted",
            "running",
            "stalled",
            "stopped",
        }
        or termination_reason in {"cost_budget_exhausted", "max_turns_reached"}
    )


def _safe_result_identifier(value: object) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    if not text or len(text) > _MAX_RESULT_IDENTIFIER_CHARS:
        return ""
    return text if all(char.isalnum() or char == "_" for char in text) else ""


def _safe_result_record_id(value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > _MAX_RESULT_IDENTIFIER_CHARS:
        return ""
    return text if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", text) else ""


def _safe_non_negative_int(value: object) -> int:
    try:
        return max(0, int(str(value)))
    except (TypeError, ValueError):
        return 0


def _plural(count: int, singular: str) -> str:
    return singular if count == 1 else f"{singular}s"


def _local_attack_command(  # noqa: C901, PLR0912, PLR0913
    *,
    parsed: argparse.Namespace,
    target_url: str,
    db_path: Path,
    workspace_dir: Path,
    report_path: Path | None,
    profile: GraphOperationalProfileName,
    auth_env_file: Path | None = None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "ravage",
        "--brief",
        str(parsed.brief),
        "--target-url",
        target_url,
        "--db-path",
        str(db_path),
        "--workspace-dir",
        str(workspace_dir),
        "--agent",
        "ai-web",
        "--agent-mode",
        parsed.agent_mode,
        "--model-profile",
        parsed.model_profile,
        "--model-tier",
        parsed.model_tier,
        "--max-turns",
        str(parsed.max_turns),
        "--traffic-policy",
        parsed.traffic_policy,
        "--recovery-profile",
        parsed.recovery_profile,
        "--tool-runtime",
        parsed.tool_runtime,
        "--tool-image",
        parsed.tool_image,
        "--display",
        parsed.display,
    ]
    if parsed.traffic_policy == "low-noise":
        command.extend(
            [
                "--max-physical-requests",
                str(parsed.max_physical_requests),
                "--traffic-max-rps",
                str(parsed.traffic_max_rps),
            ]
        )
    if parsed.traffic_request_profile:
        command.extend(["--traffic-request-profile", parsed.traffic_request_profile])
    if parsed.model_config is not None:
        command.extend(["--model-config", str(parsed.model_config)])
    if parsed.source_root is not None:
        command.extend(["--source-root", str(parsed.source_root)])
    if parsed.identity:
        command.extend(["--identity", str(parsed.identity)])
    if parsed.identity and auth_env_file is not None:
        command.extend(["--auth-env-file", str(auth_env_file)])
    if parsed.resume_from is not None:
        command.extend(["--resume-from", str(parsed.resume_from)])
    if parsed.report:
        command.append("--report")
    if report_path is not None:
        command.extend(["--report-path", str(report_path)])
    if parsed.allow_degraded:
        command.append("--allow-degraded")
    if parsed.allow_paid_models:
        command.append("--allow-paid-models")
    if parsed.show_agent_actions:
        command.append("--show-agent-actions")
    if parsed.authorized_remote_target:
        command.append("--authorized-remote-target")
    if parsed.allow_empty_description:
        command.append("--allow-empty-description")
    if parsed.tool_recon:
        command.append("--tool-recon")
    for tool in parsed.tool_recon_tool:
        command.extend(["--tool-recon-tool", str(tool)])
    if parsed.tool_recon_ports:
        command.extend(["--tool-recon-ports", str(parsed.tool_recon_ports)])
    if parsed.autonomous_route:
        command.extend(
            [
                "--autonomous-route",
                "--autonomous-route-engine",
                parsed.autonomous_route_engine,
                "--autonomous-route-max-requests",
                str(parsed.autonomous_route_max_requests),
                "--operational-profile",
                profile.value,
            ]
        )
    if parsed.knowledge_pack is not None:
        command.extend(["--knowledge-pack", str(parsed.knowledge_pack)])
        command.extend(["--knowledge-pack-sha256", str(parsed.knowledge_pack_sha256)])
    command.extend(["--knowledge-pack-limit", str(parsed.knowledge_pack_limit)])
    command.extend(["--knowledge-pack-max-chars", str(parsed.knowledge_pack_max_chars)])
    return command


def _run_subprocess_tee_stdout(argv: list[str], stdout_path: Path) -> int:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    if argv[:3] == [sys.executable, "-m", "ravage"]:
        with stdout_path.open("w", encoding="utf-8") as transcript:
            stdout_tee = _TeeStream(sys.stdout, transcript)
            stderr_tee = _TeeStream(sys.stderr, transcript)
            try:
                with redirect_stdout(stdout_tee), redirect_stderr(stderr_tee):
                    main(argv[3:])
            except SystemExit as exc:
                return _exit_code(exc.code)
        return 0
    try:
        with stdout_path.open("w", encoding="utf-8") as transcript:
            process = subprocess.Popen(  # noqa: S603
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                safe_line = sanitize_transcript_text(line)
                sys.stdout.write(safe_line)
                sys.stdout.flush()
                transcript.write(safe_line)
                transcript.flush()
            return process.wait()
    except OSError as exc:
        sys.stderr.write(f"attack process failed to start: {exc}\n")
        return 1


class _TeeStream:
    def __init__(self, *streams: TextIO) -> None:
        self._streams = streams

    @property
    def primary_stream(self) -> TextIO:
        return self._streams[0]

    @property
    def transcript_streams(self) -> tuple[TextIO, ...]:
        return self._streams[1:]

    def write(self, value: str) -> int:
        for index, stream in enumerate(self._streams):
            write = getattr(stream, "write", None)
            if callable(write):
                write(value if index == 0 else sanitize_transcript_text(value))
        return len(value)

    def flush(self) -> None:
        for stream in self._streams:
            flush = getattr(stream, "flush", None)
            if callable(flush):
                flush()

    def isatty(self) -> bool:
        return False


def _exit_code(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    return 1


def _assert_fresh_attack_workspace(*, run_dir: Path, workspace_dir: Path, resume: bool) -> None:
    existing = [
        path
        for path in (
            workspace_dir / "working_state.json",
            workspace_dir / "events.jsonl",
            workspace_dir / "transcript.jsonl",
            workspace_dir / "remote-graph-state.json",
            run_dir / "report.json",
            run_dir / "report.md",
        )
        if path.exists()
    ]
    if not existing or resume:
        return
    details = ", ".join(str(path) for path in existing[:3])
    message = (
        "attack run directory already contains prior state; use a fresh --run-dir "
        f"or pass --resume to continue it. Existing files: {details}"
    )
    raise SystemExit(message)


def _assert_fresh_scan_workspace(
    *,
    run_dir: Path,
    workspace_dir: Path,
    db_path: Path,
) -> None:
    """Reject accidental scan-state reuse until an exact resume contract exists."""
    existing = [
        path
        for path in (
            workspace_dir / "traffic-policy.json",
            workspace_dir / "working_state.json",
            workspace_dir / "events.jsonl",
            workspace_dir / "transcript.jsonl",
            db_path,
            run_dir / "scan-summary.json",
            run_dir / "scan-coverage.json",
            run_dir / "report.json",
            run_dir / "report.md",
        )
        if path.exists()
    ]
    if not existing:
        return
    details = ", ".join(str(path) for path in existing[:3])
    raise SystemExit(
        "scan run directory already contains prior state; use a fresh --run-dir. "
        f"Existing files: {details}"
    )


class _AttackEventSink:
    def __init__(self, *, mode: DisplayMode, show_agent_actions: bool = False) -> None:
        self.show_agent_actions = show_agent_actions
        output = sys.stdout
        if isinstance(output, _TeeStream):
            self._displays = [
                RunDisplay(
                    mode=mode,
                    stream=output.primary_stream,
                    show_agent_actions=show_agent_actions,
                )
            ]
            transcript_mode: DisplayMode = "quiet" if mode == "quiet" else "plain"
            self._displays.extend(
                RunDisplay(
                    mode=transcript_mode,
                    stream=stream,
                    show_agent_actions=show_agent_actions,
                )
                for stream in output.transcript_streams
            )
        else:
            self._displays = [
                RunDisplay(
                    mode=mode,
                    stream=output,
                    show_agent_actions=show_agent_actions,
                )
            ]

    def __call__(self, event: Mapping[str, Any]) -> None:
        for display in self._displays:
            with suppress(Exception):
                display(event)

    def close(self) -> None:
        for display in self._displays:
            with suppress(Exception):
                display.close()


def _attack_event_sink(
    *,
    mode: DisplayMode = "auto",
    show_agent_actions: bool = False,
) -> _AttackEventSink:
    return _AttackEventSink(mode=mode, show_agent_actions=show_agent_actions)


def _scan(args: list[str]) -> None:  # noqa: C901, PLR0912, PLR0915
    parser = argparse.ArgumentParser(
        prog="ravage scan",
        description="Run deterministic built-in probes without model calls.",
        epilog=(
            "Use --all-probes for the broad, high-traffic in-tree catalog; it may "
            "generate thousands of bounded requests. Repeat --probe for a focused "
            "run, especially against authorized remote targets."
        ),
    )
    parser.add_argument(
        "brief",
        type=Path,
        nargs="?",
        help="engagement brief YAML (not required with --list-probes)",
    )
    parser.add_argument("--target-url", help="override the first HTTP(S) URL in scope.in_scope")
    parser.add_argument(
        "--run-dir",
        type=Path,
        help="run directory; defaults to runs/<brief>-scan-<timestamp>",
    )
    parser.add_argument("--db-path", type=Path)
    parser.add_argument("--workspace-dir", type=Path)
    parser.add_argument(
        "--probe",
        action="append",
        dest="probes",
        default=[],
        help="probe name to run; repeatable",
    )
    parser.add_argument(
        "--all-probes",
        action="store_true",
        help="run the broad catalog; may generate thousands of bounded requests",
    )
    parser.add_argument(
        "--list-probes",
        action="store_true",
        help="list built-in probe names and exit",
    )
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument(
        "--traffic-policy",
        choices=["observe", "low-noise"],
        help=(
            "whole-run physical HTTP policy; defaults to low-noise for authorized "
            "remote targets and observe for local targets"
        ),
    )
    parser.add_argument(
        "--max-physical-requests",
        type=int,
        help="whole-run physical HTTP request cap in low-noise mode (default: 300)",
    )
    parser.add_argument(
        "--traffic-max-rps",
        type=float,
        help="strictly sub-1 whole-run HTTP dispatch rate in low-noise mode (default: 0.5)",
    )
    parser.add_argument(
        "--identity",
        help="use one named identity from brief.authentication for eligible probes",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help=(
            "load authentication secret variables from this file; with --identity, "
            "defaults to .env.ravage or .env beside the brief"
        ),
    )
    parser.add_argument(
        "--tool-runtime",
        choices=["host", "docker", "auto"],
        default="host",
        help=("accepted for command compatibility; deterministic scan probes run in-process"),
    )
    parser.add_argument(
        "--tool-image",
        default=DEFAULT_TOOL_IMAGE,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--allow-remote-target",
        "--authorized-remote-target",
        dest="allow_remote_target",
        action="store_true",
        help="confirm explicit authorization to scan a remote target listed in the brief",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="write a redacted report after the scan finishes",
    )
    parser.add_argument("--report-path", type=Path)
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the final scan summary as JSON",
    )
    parsed = parser.parse_args(args)

    if parsed.list_probes:
        _write_line(banner("SCAN PROBES"))
        for probe in available_probes():
            name = probe["name"]
            default_marker = " · default" if name in DEFAULT_SCAN_PROBES else ""
            _write_line(f"{tone(name, 'info')}{default_marker}")
            _write_line(f"  {probe['purpose']}")
        return
    if parsed.brief is None:
        parser.error("an engagement brief is required; run `ravage init URL` first")

    env_file = parsed.env_file
    if parsed.identity and env_file is None:
        env_file = _discover_auth_env_file(parsed.brief)
    auth_secret_resolver: SecretResolver | None = None
    if env_file is not None:
        try:
            auth_secret_resolver = environment_secret_resolver(env_file=env_file)
        except EnvironmentFileError as exc:
            parser.error(f"cannot load environment file {env_file}: {exc.detail}")
    brief = _load_engagement_brief_for_cli(parser, parsed.brief)
    target_url = _target_url_from_brief(parsed.brief, explicit=parsed.target_url)
    if not is_local_url(target_url) and not parsed.allow_remote_target:
        parser.error("remote targets require --authorized-remote-target")
    try:
        assert_authorized_target(
            target_url,
            scope=brief.scope,
            allow_remote_target=parsed.allow_remote_target,
            agent_name="scan",
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    _resolve_traffic_policy_args(
        parser,
        parsed,
        default_mode=("observe" if is_local_url(target_url) else "low-noise"),
        roe_max_rps=brief.roe.max_rps,
    )

    adaptive_scan = not parsed.probes and not parsed.all_probes
    adaptive_catalog = tuple(SCAN_PROBE_CATALOG)
    skipped_authenticated_probes: dict[str, str] = {}
    if adaptive_scan and parsed.identity:
        eligible, skipped_authenticated_probes = _authenticated_scan_selection(
            list(adaptive_catalog),
            explicit=False,
        )
        adaptive_catalog = tuple(eligible)
        selected_probes: list[str] = []
    else:
        selected_probes = (
            []
            if adaptive_scan
            else _selected_scan_probes(parsed.probes, all_probes=parsed.all_probes)
        )
    if parsed.identity and not adaptive_scan:
        selected_probes, skipped_authenticated_probes = _authenticated_scan_selection(
            selected_probes,
            explicit=bool(parsed.probes),
        )
        if skipped_authenticated_probes and not parsed.json:
            skipped = ", ".join(sorted(skipped_authenticated_probes))
            _write_line(
                f"{badge('auth:skip', 'warn')} unmanaged authenticated transports omitted: "
                f"{skipped}"
            )
    run_dir = parsed.run_dir or _default_run_dir(parsed.brief, "scan")
    workspace_dir = parsed.workspace_dir or run_dir / "workspace"
    db_path = parsed.db_path or run_dir / "audit.db"
    report_path = parsed.report_path
    if parsed.report and report_path is None:
        report_path = run_dir / "report.md"
    if report_path is not None:
        _validate_report_output(parser, report_path)

    run_dir.mkdir(parents=True, exist_ok=True)
    _assert_fresh_scan_workspace(
        run_dir=run_dir,
        workspace_dir=workspace_dir,
        db_path=db_path,
    )
    workspace = AgentWorkspace.open(workspace_dir)
    try:
        traffic_policy = TrafficPolicyController.open(
            workspace_dir / "traffic-policy.json",
            target_url=target_url,
            config=_traffic_policy_config(parsed),
        )
    except (OSError, TrafficPolicyError, ValueError) as exc:
        parser.error(f"cannot initialize scan traffic policy: {_concise_cli_error(exc)}")
    traffic_capture_session_id = f"scan-{uuid4().hex[:12]}"
    traffic_recorder_errors: list[str] = []
    traffic_store: TrafficStore | None = None
    traffic_manifest: TrafficRunManifest | None = None
    anonymous_traffic_recorder: ProbeTrafficRecorder | None = None
    try:
        candidate_manifest = TrafficRunManifest.create(
            target_url=target_url,
            capture_session_id=traffic_capture_session_id,
            in_scope=tuple(str(item) for item in brief.scope.in_scope),
            out_of_scope=tuple(str(item) for item in brief.scope.out_of_scope),
        )
        candidate_store = TrafficStore.create(workspace_dir, require_empty=True)
        write_traffic_manifest(workspace_dir, candidate_manifest)
        traffic_store = candidate_store
        traffic_manifest = candidate_manifest
        anonymous_traffic_recorder = ProbeTrafficRecorder(
            candidate_store,
            capture_session_id=traffic_capture_session_id,
            error_sink=traffic_recorder_errors,
        )
    except (OSError, TrafficRunError, TrafficStoreError):
        # Request history is auxiliary. A pre-existing/unsafe store or a scope
        # that cannot be represented without leaking path values must never
        # prevent the deterministic scan itself from running.
        traffic_recorder_errors.append(
            "traffic history was disabled because its private store or redacted "
            "scope manifest could not be initialized"
        )
    audit = AuditStore(db_path, scope=brief.scope)
    surface_graph = SurfaceGraphState.for_target(target_url)
    state = AgentState(summary="deterministic scan", surface_graph=surface_graph)
    state.surface["target_url"] = target_url
    state.surface["origin"] = surface_graph.target_origin
    state.surface["scope_in_scope"] = list(brief.scope.in_scope)
    state.surface["scope_out_of_scope"] = list(brief.scope.out_of_scope)
    state.surface["scope_max_rps"] = brief.roe.max_rps
    state.surface["allow_remote_target"] = parsed.allow_remote_target
    state.surface["scan_planner_mode"] = "adaptive" if adaptive_scan else "fixed"
    adaptive_plan: ScanPlan | None = None
    if adaptive_scan:
        adaptive_plan = build_adaptive_scan_plan(state, catalog=adaptive_catalog)
        selected_probes = list(adaptive_plan.probes)
    write_manifest(
        run_dir,
        RunManifest(
            run_id=run_dir.name,
            status=STATUS_AGENT_RUNNING,
            phase="scan",
            target_url=target_url,
            workspace_dir=str(workspace_dir),
            db_path=str(db_path),
        ),
    )
    start_payload: dict[str, object] = {
        "target_url": target_url,
        "probes": selected_probes,
        "planner_mode": "adaptive" if adaptive_scan else "fixed",
        "traffic_accounting": _scan_traffic_accounting(traffic_policy),
    }
    if parsed.identity:
        start_payload["identity"] = parsed.identity
        start_payload["skipped_authenticated_probes"] = skipped_authenticated_probes
    audit.record(
        engagement_id=brief.engagement_id,
        actor="scan",
        action="scan_started",
        payload=start_payload,
    )
    workspace.record_event(kind="scan_started", payload=start_payload)
    if adaptive_plan is not None:
        _record_adaptive_scan_plan(
            adaptive_plan,
            iteration=0,
            workspace=workspace,
            audit=audit,
            engagement_id=brief.engagement_id,
        )

    probe_observations_count = 0
    confirmed_findings_count = 0
    observed_request_count = 0
    observed_http_response_count = 0
    transport_errors: list[str] = []
    executions: list[_ScanProbeExecution] = []
    planner_frontier_exhausted = False
    coverage_certificate: ScanCoverageCertificate | None = None
    planner_mode = (
        "adaptive" if adaptive_scan else ("all_probes" if parsed.all_probes else "explicit")
    )
    auth_owner: ManagedAttackAuthentication | None = None
    artifact_redactor = AuthArtifactRedactor()
    try:
        if parsed.identity:
            try:
                _validate_configured_scan_identity(brief, parsed.identity)
                if not parsed.json and env_file is not None:
                    _write_line(f"{badge('auth:env', 'info')} {env_file}")
                if any(not probe_requires_anonymous_session(probe) for probe in selected_probes):
                    if not parsed.json:
                        _write_line(
                            f"{badge('auth:check', 'info')} identity={parsed.identity} · "
                            "validating secrets, login, and health"
                        )
                    auth_owner, artifact_redactor = _configured_scan_session(
                        brief=brief,
                        target_url=target_url,
                        identity=parsed.identity,
                        timeout_seconds=max(1, min(parsed.timeout_seconds, 60)),
                        allow_remote_target=parsed.allow_remote_target,
                        secret_resolver=auth_secret_resolver,
                        traffic_store=traffic_store,
                        traffic_capture_session_id=traffic_capture_session_id,
                        traffic_recorder_errors=traffic_recorder_errors,
                        traffic_policy=traffic_policy,
                    )
                    if not parsed.json:
                        _write_line(
                            f"{badge('auth:ok', 'ok')} identity={parsed.identity} · "
                            "authenticated session ready"
                        )
                elif not parsed.json:
                    _write_line(
                        f"{badge('auth:skip', 'warn')} identity={parsed.identity} · "
                        "selected probes intentionally run anonymously"
                    )
            except (
                ConfiguredAuthenticationError,
                SecretResolutionError,
                SessionError,
                ValueError,
            ) as exc:
                raise SystemExit(
                    f"cannot authenticate identity {parsed.identity!r}: {exc}"
                ) from None
        if adaptive_scan:
            recon_payload = _seed_adaptive_scan_recon(
                target_url=target_url,
                brief=brief,
                state=state,
                workspace=workspace,
                audit=audit,
                traffic_policy=traffic_policy,
                timeout_seconds=parsed.timeout_seconds,
                allow_remote_target=parsed.allow_remote_target,
            )
            recon_request_count = recon_payload.get("http_request_count")
            if isinstance(recon_request_count, int) and not isinstance(
                recon_request_count, bool
            ):
                observed_request_count += recon_request_count
            recon_pages = recon_payload.get("pages")
            if isinstance(recon_pages, list):
                observed_http_response_count += sum(
                    isinstance(page, Mapping)
                    and isinstance(page.get("status"), int)
                    and not isinstance(page.get("status"), bool)
                    for page in recon_pages
                )
            recon_errors = recon_payload.get("errors")
            if isinstance(recon_errors, list):
                for error in recon_errors:
                    detail = str(error).strip()
                    if detail and detail not in transport_errors:
                        transport_errors.append(detail)
            adaptive_plan = build_adaptive_scan_plan(state, catalog=adaptive_catalog)
            _record_adaptive_scan_plan(
                adaptive_plan,
                iteration=1,
                workspace=workspace,
                audit=audit,
                engagement_id=brief.engagement_id,
            )
            save_agent_state(workspace.state_path, target_url=target_url, state=state)
        fixed_probes = tuple(selected_probes)
        fixed_cursor = 0
        probe_index = 0
        while True:
            if adaptive_scan:
                assert adaptive_plan is not None
                if not adaptive_plan.probes:
                    planner_frontier_exhausted = True
                    break
                probe = adaptive_plan.probes[0]
            else:
                if fixed_cursor >= len(fixed_probes):
                    planner_frontier_exhausted = True
                    break
                probe = fixed_probes[fixed_cursor]
                fixed_cursor += 1
            probe_index += 1
            use_authenticated_session = (
                auth_owner is not None and not probe_requires_anonymous_session(probe)
            )
            probe_session = None
            if use_authenticated_session and auth_owner is not None:
                try:
                    probe_session = auth_owner.session_for_probe(
                        timeout_seconds=max(1, min(parsed.timeout_seconds, 60))
                    )
                except SessionError as exc:
                    raise SystemExit(
                        f"identity {parsed.identity!r} is no longer authenticated: {exc}"
                    ) from None
            try:
                try:
                    blocked_before = traffic_policy.snapshot().blocked_count
                    blocked_reason = _guard_scan_probe_traffic(
                        probe,
                        traffic_policy=traffic_policy,
                    )
                    if blocked_reason:
                        result = ProbeRunResult(
                            ok=False,
                            probe=probe,
                            summary=f"blocked by whole-run traffic policy: {blocked_reason}",
                            errors=[blocked_reason],
                        )
                    else:
                        result = run_builtin_probe(
                            probe,
                            target_url=target_url,
                            state=state,
                            timeout_seconds=max(1, min(parsed.timeout_seconds, 120)),
                            allow_remote_target=parsed.allow_remote_target,
                            in_scope=brief.scope.in_scope,
                            out_of_scope=brief.scope.out_of_scope,
                            max_rps=brief.roe.max_rps,
                            session=probe_session,
                            traffic_observer=(
                                None if use_authenticated_session else anonymous_traffic_recorder
                            ),
                            traffic_policy=(
                                None if use_authenticated_session else traffic_policy
                            ),
                        )
                finally:
                    if probe_session is not None and auth_owner is not None:
                        auth_owner.retire_probe_session(probe_session)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:  # noqa: BLE001 - target failures must not escape artifacts.
                raise SystemExit(f"scan probe {probe!r} failed") from None
            blocked_after = traffic_policy.snapshot().blocked_count
            policy_blocked = bool(blocked_reason) or (
                blocked_after > blocked_before and not _scan_result_has_http_response(result)
            )
            executions.append(
                _ScanProbeExecution(
                    probe=probe,
                    result=result,
                    policy_blocked=policy_blocked,
                    opaque_unmetered=(probe in _SCAN_UNMETERED_PROBES and not blocked_reason),
                )
            )
            for request in result.requests:
                if not isinstance(request, dict):
                    continue
                observed_request_count += 1
                status = request.get("status")
                if isinstance(status, int) and not isinstance(status, bool):
                    observed_http_response_count += 1
                error = str(request.get("error") or "").strip()
                if error and error not in transport_errors:
                    transport_errors.append(error)
            probe_observations_count += len(result.findings)
            raw_payload = {
                "probe": probe,
                "ok": result.ok,
                "summary": result.summary,
                "findings": result.findings,
                "requests": result.requests,
                "errors": result.errors,
                "http_request_count": result.http_request_count,
                "http_request_count_status": result.http_request_count_status,
                "session_mode": (
                    f"identity:{parsed.identity}" if use_authenticated_session else "anonymous"
                ),
            }
            recognized_proofs = [
                proof
                for proof in _recognize_scan_result_proofs(raw_payload)
                if not artifact_redactor.contains_secret(proof)
            ]
            payload = _require_scan_payload(artifact_redactor.redact(raw_payload))
            text = json.dumps(payload, indent=2, sort_keys=True)
            safe_summary = artifact_redactor.redact_text(result.summary)
            action_id = f"scan-{probe_index:03d}-{probe}"
            session_mode = (
                f"identity:{parsed.identity}" if use_authenticated_session else "anonymous"
            )
            probe_result = record_probe_result(
                text,
                ok=result.ok,
                kind="tool_run_probe",
                state=state,
                workspace=workspace,
                audit=audit,
                engagement_id=brief.engagement_id,
                proof_recognition_enabled=False,
                action_id=action_id,
                repeat_count=1,
                timed_out=False,
                max_observation_chars=_MAX_SCAN_OBSERVATION_CHARS,
                max_transcript_chars=_MAX_SCAN_TRANSCRIPT_CHARS,
                session_mode=session_mode,
                authentication=auth_owner,
            )
            scan_payload = dict(payload)
            scan_payload["action_id"] = action_id
            scan_payload["source_observation_id"] = str(
                state.last_observation.get("observation_id") or ""
            )
            audit.record(
                engagement_id=brief.engagement_id,
                actor="tool",
                action="scan_probe",
                payload=scan_payload,
            )
            workspace.record_event(kind="scan_probe", payload=scan_payload)
            state.turn = probe_index
            state.actions.append(
                {
                    "action": "run_probe",
                    "probe": probe,
                    "ok": result.ok,
                    "summary": safe_summary,
                }
            )
            record_verified_probe_findings(
                probe=probe,
                probe_text=text,
                result=probe_result,
                target_url=target_url,
                state=state,
                workspace=workspace,
                audit=audit,
                engagement_id=brief.engagement_id,
                action_id=action_id,
            )
            _capture_scan_proofs(
                recognized_proofs,
                state=state,
                workspace=workspace,
                audit=audit,
                engagement_id=brief.engagement_id,
                evidence=f"scan_probe:{probe}",
                emit_live=not parsed.json,
            )
            save_agent_state(workspace.state_path, target_url=target_url, state=state)
            if not parsed.json:
                marker = "ok" if result.ok else "no-hit"
                style = "ok" if result.ok else "muted"
                session_label = parsed.identity if use_authenticated_session else "anonymous"
                _write_line(
                    f"{badge(f'scan:{marker}', style)} "
                    f"{badge(session_label, 'info')} {tone(probe, 'info')} {safe_summary}"
                )
            if adaptive_scan:
                adaptive_plan = build_adaptive_scan_plan(
                    state,
                    prior_results=tuple(execution.result for execution in executions),
                    catalog=adaptive_catalog,
                )
                _record_adaptive_scan_plan(
                    adaptive_plan,
                    iteration=probe_index + 1,
                    workspace=workspace,
                    audit=audit,
                    engagement_id=brief.engagement_id,
                )
        _require_scan_target_reached(
            observed_requests=observed_request_count,
            observed_responses=observed_http_response_count,
            transport_errors=transport_errors,
            redactor=artifact_redactor,
        )
        confirmed_findings_count = audit.count_findings(
            status="confirmed",
            engagement_id=brief.engagement_id,
        )
        coverage_certificate = _build_scan_coverage_certificate(
            target_url=target_url,
            planner_mode=planner_mode,
            adaptive_plan=adaptive_plan if adaptive_scan else None,
            executions=executions,
            skipped_probes=skipped_authenticated_probes,
            planner_frontier_exhausted=planner_frontier_exhausted,
            traffic_policy=traffic_policy,
        )
        coverage_path = write_scan_coverage_certificate(
            run_dir / "scan-coverage.json",
            coverage_certificate,
        )
        completed_payload = {
            "probes_run": len(executions),
            "confirmed_findings_count": confirmed_findings_count,
            "flags_count": len(state.flags),
            "planner_mode": planner_mode,
            "coverage_status": coverage_certificate.status.value,
            "coverage_completion_basis": coverage_certificate.completion_basis,
            "coverage_limitations": list(coverage_certificate.limitations),
            "coverage_artifact": coverage_path.name,
            "traffic_accounting": _scan_traffic_accounting(traffic_policy),
        }
        audit.record(
            engagement_id=brief.engagement_id,
            actor="scan",
            action="scan_completed",
            payload=completed_payload,
        )
        workspace.record_event(kind="scan_completed", payload=completed_payload)
    except BaseException as exc:
        failure_payload: dict[str, object] = {
            "error_type": type(exc).__name__,
            "identity": parsed.identity or "",
            "traffic_accounting": _scan_traffic_accounting(traffic_policy),
        }
        with suppress(Exception):
            audit.record(
                engagement_id=brief.engagement_id,
                actor="scan",
                action="scan_failed",
                payload=failure_payload,
            )
        with suppress(Exception):
            workspace.record_event(kind="scan_failed", payload=failure_payload)
        with suppress(Exception):
            write_manifest(
                run_dir,
                RunManifest(
                    run_id=run_dir.name,
                    status=STATUS_FINISHED,
                    phase="scan_failed",
                    target_url=target_url,
                    workspace_dir=str(workspace_dir),
                    db_path=str(db_path),
                    result_label="failed",
                ),
            )
        raise
    finally:
        if auth_owner is not None:
            auth_owner.close()
        if traffic_manifest is not None:
            try:
                write_traffic_manifest(workspace_dir, traffic_manifest.complete())
            except (OSError, TrafficRunError):
                traffic_recorder_errors.append(
                    "traffic history was recorded but its completion metadata could not be saved"
                )
        audit.close()

    report_output = ""
    if report_path is not None:
        report = write_pentest_report(
            brief_path=parsed.brief,
            target_url=target_url,
            workspace_dir=workspace_dir,
            output_path=report_path,
            status="completed",
            completed=True,
            audit_db_path=db_path,
        )
        artifacts = report.get("artifacts")
        if isinstance(artifacts, dict):
            report_output = str(artifacts.get("markdown_report_path") or report_path)

    traffic_requests = 0
    traffic_contracts = 0
    if traffic_store is not None:
        try:
            measured_requests = len(traffic_store.exchanges())
            measured_contracts = len(traffic_store.contracts())
        except TrafficStoreError:
            traffic_recorder_errors.append(
                "traffic history was recorded but its final counts could not be read"
            )
        else:
            traffic_requests = measured_requests
            traffic_contracts = measured_contracts

    summary = {
        "run_dir": str(run_dir),
        "workspace_dir": str(workspace_dir),
        "audit_db": str(db_path),
        "target_url": target_url,
        "identity": parsed.identity or "",
        "planner_mode": planner_mode,
        "probes_run": len(executions),
        "probes_executed": [execution.probe for execution in executions],
        "skipped_authenticated_probes": skipped_authenticated_probes,
        "probe_observations_count": probe_observations_count,
        "confirmed_findings_count": confirmed_findings_count,
        "traffic_requests": traffic_requests,
        "traffic_contracts": traffic_contracts,
        "traffic_recorder_errors": traffic_recorder_errors,
        "traffic_accounting": _scan_traffic_accounting(traffic_policy),
        "coverage": (
            {
                "artifact": str(run_dir / "scan-coverage.json"),
                "status": coverage_certificate.status.value,
                "completion_basis": coverage_certificate.completion_basis,
                "limitations": list(coverage_certificate.limitations),
            }
            if coverage_certificate is not None
            else {}
        ),
        "flags": list(state.flags),
        "report": report_output,
    }
    (run_dir / "scan-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(
        run_dir,
        RunManifest(
            run_id=run_dir.name,
            status=STATUS_FINISHED,
            phase="scan",
            target_url=target_url,
            workspace_dir=str(workspace_dir),
            db_path=str(db_path),
            result_label="completed",
            flag_found=bool(state.flags),
        ),
    )
    if parsed.json:
        _write_line(json.dumps(summary, indent=2, sort_keys=True))
    else:
        _write_line(f"{badge('scan:done', 'ok')} run_dir={run_dir}")
        _write_line(f"{badge('workspace', 'info')} {workspace_dir}")
        _write_line(f"{badge('audit', 'info')} {db_path}")
        if traffic_recorder_errors:
            _write_line(
                f"{badge('traffic:warning', 'warn')} "
                f"{len(traffic_recorder_errors)} warning(s) · see scan-summary.json"
            )
        if report_output:
            _write_line(f"{badge('report', 'info')} {report_output}")


def _require_scan_target_reached(
    *,
    observed_requests: int,
    observed_responses: int,
    transport_errors: list[str],
    redactor: AuthArtifactRedactor,
) -> None:
    if not observed_requests or observed_responses:
        return
    detail = (
        redactor.redact_text(transport_errors[0])
        if transport_errors
        else "the transport returned no HTTP status"
    )
    raise SystemExit(
        "target unreachable: no HTTP response was received across "
        f"{observed_requests} request(s) ({detail}). Start the application, "
        "check the target URL, then rerun the scan."
    )


def _guard_scan_probe_traffic(
    probe: str,
    *,
    traffic_policy: TrafficPolicyController,
) -> str:
    """Account for opaque target transports and fail closed in enforced mode."""
    if probe not in _SCAN_UNMETERED_PROBES:
        return ""
    try:
        traffic_policy.record_unmetered_action()
    except TrafficPolicyBlocked as exc:
        return str(exc)
    return ""


def _scan_traffic_accounting(
    traffic_policy: TrafficPolicyController,
) -> dict[str, object]:
    try:
        snapshot = traffic_policy.snapshot()
    except (OSError, TrafficPolicyError, ValueError):
        return {
            "status": "unavailable",
            "provenance": "traffic_policy_ledger_unreadable",
        }
    config = traffic_policy.config
    remaining = (
        None
        if config.max_physical_requests is None
        else max(
            config.max_physical_requests
            - snapshot.physical_request_count
            - snapshot.reservation_count,
            0,
        )
    )
    return {
        "status": snapshot.accounting_status,
        "provenance": "workspace_traffic_policy_ledger",
        "mode": config.mode.value,
        "max_rps": config.max_rps,
        "max_physical_requests": config.max_physical_requests,
        "remaining_physical_requests": remaining,
        **snapshot.to_json(),
    }


def _record_adaptive_scan_plan(
    plan: ScanPlan,
    *,
    iteration: int,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
) -> None:
    payload = plan.to_json()
    payload["iteration"] = iteration
    audit.record(
        engagement_id=engagement_id,
        actor="scan",
        action="scan_plan_updated",
        payload=payload,
    )
    workspace.record_event(kind="scan_plan_updated", payload=payload)


def _seed_adaptive_scan_recon(  # noqa: PLR0913
    *,
    target_url: str,
    brief: EngagementBrief,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    traffic_policy: TrafficPolicyController,
    timeout_seconds: int,
    allow_remote_target: bool,
) -> dict[str, object]:
    """Feed native HTML/JS/form discovery into the canonical surface graph."""
    try:
        recon = run_recon(
            target_url,
            max_pages=12,
            timeout_seconds=max(1, min(timeout_seconds, 60)),
            allow_remote_target=allow_remote_target,
            in_scope=brief.scope.in_scope,
            out_of_scope=brief.scope.out_of_scope,
            max_rps=brief.roe.max_rps,
            traffic_policy=traffic_policy,
        )
    except Exception as exc:  # noqa: BLE001 - recon is additive, not a run gate.
        payload = {
            "error_type": type(exc).__name__,
            "error": _concise_cli_error(exc),
        }
        audit.record(
            engagement_id=brief.engagement_id,
            actor="scan",
            action="scan_recon_failed",
            payload=payload,
        )
        workspace.record_event(kind="scan_recon_failed", payload=payload)
        append_unique(state.facts, "adaptive native recon incomplete", limit=80)
        return {
            "pages": [],
            "errors": [str(payload["error"])],
            "http_request_count": 0,
        }

    recon_payload: dict[str, object] = recon.to_json()
    audit.record(
        engagement_id=brief.engagement_id,
        actor="scan",
        action="scan_recon_completed",
        payload=recon_payload,
    )
    workspace.record_event(kind="scan_recon_completed", payload=recon_payload)
    merge_recon_state(state, recon_payload)
    preserved_surface = dict(state.surface)
    context = brief.context if isinstance(brief.context, Mapping) else {}
    surface = surface_from_recon(
        target_url=target_url,
        description=str(context.get("description") or ""),
        recon_payload=recon_payload,
    )
    ingest_recon_surface(state.surface_graph, recon_payload, identity_alias="anonymous")
    surface = project_surface_graph(state.surface_graph, surface)
    merge_surface_state(state, surface)
    state.surface.update(preserved_surface)
    graph_payload = {
        "operations": len(state.surface_graph.operations or {}),
        "identity_observations": len(state.surface_graph.observations or {}),
        "sources": sorted(
            {
                source
                for operation in (state.surface_graph.operations or {}).values()
                for source in operation.provenance
            }
        ),
    }
    audit.record(
        engagement_id=brief.engagement_id,
        actor="scan",
        action="scan_surface_graph_updated",
        payload=graph_payload,
    )
    workspace.record_event(kind="scan_surface_graph_updated", payload=graph_payload)
    return recon_payload


def _build_scan_coverage_certificate(  # noqa: C901, PLR0913
    *,
    target_url: str,
    planner_mode: str,
    adaptive_plan: ScanPlan | None,
    executions: list[_ScanProbeExecution],
    skipped_probes: Mapping[str, str],
    planner_frontier_exhausted: bool,
    traffic_policy: TrafficPolicyController,
) -> ScanCoverageCertificate:
    recorder = ScanCoverageRecorder()
    execution_ids: list[tuple[str, _ScanProbeExecution]] = []
    recorded_probe_ids: set[str] = set()
    next_rank = 0
    if adaptive_plan is not None:
        execution_by_probe = {execution.probe: execution for execution in executions}
        for rank, decision in enumerate(adaptive_plan.decisions):
            terminal_disposition = None
            if decision.status is ScanPlanStatus.NOT_APPLICABLE:
                terminal_disposition = ProbeDisposition.NOT_APPLICABLE
            elif decision.status is ScanPlanStatus.BLOCKED:
                terminal_disposition = ProbeDisposition.UNSUPPORTED
            recorder.record_planner_decision(
                PlannerProbeDecision(
                    probe_id=decision.probe,
                    family=decision.phase.value,
                    rank=rank,
                    surface_key=target_url,
                    reason_codes=_coverage_reason_codes(decision),
                    terminal_disposition=terminal_disposition,
                )
            )
            recorded_probe_ids.add(decision.probe)
            execution = execution_by_probe.get(decision.probe)
            if execution is not None:
                execution_ids.append((decision.probe, execution))
        next_rank = len(adaptive_plan.decisions)
    else:
        occurrences: dict[str, int] = {}
        for rank, execution in enumerate(executions):
            occurrence = occurrences.get(execution.probe, 0) + 1
            occurrences[execution.probe] = occurrence
            probe_id = (
                execution.probe if occurrence == 1 else f"{execution.probe}.{occurrence}"
            )
            recorder.record_planner_decision(
                PlannerProbeDecision(
                    probe_id=probe_id,
                    family=planner_mode,
                    rank=rank,
                    surface_key=target_url,
                    reason_codes=(
                        "operator_selected" if planner_mode == "explicit" else "full_catalog",
                    ),
                )
            )
            recorded_probe_ids.add(probe_id)
            execution_ids.append((probe_id, execution))
        next_rank = len(executions)
    for probe, _reason in sorted(skipped_probes.items()):
        if probe in recorded_probe_ids:
            continue
        recorder.record_planner_decision(
            PlannerProbeDecision(
                probe_id=probe,
                family="unsupported",
                rank=next_rank,
                surface_key=target_url,
                reason_codes=("managed_transport_unavailable",),
                terminal_disposition=ProbeDisposition.UNSUPPORTED,
            )
        )
        next_rank += 1
    for probe_id, execution in execution_ids:
        recorder.record_probe_outcome(_scan_probe_coverage_outcome(probe_id, execution))
    try:
        traffic_snapshot = traffic_policy.snapshot()
    except (OSError, TrafficPolicyError, ValueError):
        traffic_snapshot = None
    return recorder.finalize(
        planner_frontier_exhausted=planner_frontier_exhausted,
        traffic_snapshot=traffic_snapshot,
        traffic_config=traffic_policy.config,
    )


def _coverage_reason_codes(decision: ScanPlanDecision) -> tuple[str, ...]:
    reasons = tuple(sorted(set(decision.reasons)))
    if len(reasons) <= _MAX_SCAN_COVERAGE_REASON_CODES:
        return reasons
    return (
        *reasons[: _MAX_SCAN_COVERAGE_REASON_CODES - 1],
        "reason_codes_truncated",
    )


def _scan_probe_coverage_outcome(
    probe_id: str,
    execution: _ScanProbeExecution,
) -> ProbeCoverageOutcome:
    result = execution.result
    if execution.policy_blocked:
        disposition = ProbeDisposition.BLOCKED_BUDGET
        reason_codes = ("traffic_policy_blocked",)
    elif result.findings:
        disposition = ProbeDisposition.COMPLETED_FINDING
        reason_codes = ()
    elif _scan_probe_transport_incomplete(result):
        disposition = ProbeDisposition.TRANSPORT_INCOMPLETE
        reason_codes = ("transport_incomplete",)
    else:
        disposition = ProbeDisposition.COMPLETED_NO_FINDING
        reason_codes = ()
    if execution.opaque_unmetered:
        accounting_status = RequestAccountingStatus.LOWER_BOUND
        reason_codes = (*reason_codes, "opaque_transport")
    else:
        try:
            accounting_status = RequestAccountingStatus(result.http_request_count_status)
        except (TypeError, ValueError):
            accounting_status = RequestAccountingStatus.UNAVAILABLE
    return ProbeCoverageOutcome(
        probe_id=probe_id,
        disposition=disposition,
        finding_count=len(result.findings),
        physical_request_count=result.http_request_count,
        request_accounting_status=accounting_status,
        reason_codes=tuple(sorted(set(reason_codes))),
    )


def _scan_probe_transport_incomplete(result: ProbeRunResult) -> bool:
    if _scan_result_has_http_response(result):
        return False
    request_errors = any(
        isinstance(request, Mapping) and str(request.get("error") or "").strip()
        for request in result.requests
    )
    return bool(result.errors or request_errors)


def _scan_result_has_http_response(result: ProbeRunResult) -> bool:
    return any(
        isinstance(request, Mapping)
        and isinstance(request.get("status"), int)
        and not isinstance(request.get("status"), bool)
        for request in result.requests
    )


def _configured_scan_session(  # noqa: PLR0913
    *,
    brief: EngagementBrief,
    target_url: str,
    identity: str,
    timeout_seconds: int,
    allow_remote_target: bool,
    traffic_policy: TrafficPolicyController,
    secret_resolver: SecretResolver | None = None,
    traffic_store: TrafficStore | None = None,
    traffic_capture_session_id: str = "",
    traffic_recorder_errors: list[str] | None = None,
) -> tuple[ManagedAttackAuthentication, AuthArtifactRedactor]:
    authentication = brief.authentication
    if authentication is None:
        raise ValueError("the engagement brief has no authentication identities")
    assert_secure_configured_auth_transport(
        authentication,
        target_url=target_url,
        alias=identity,
    )
    selected = identity_profile_from_config(authentication, identity)
    resolver = environment_secret_resolver() if secret_resolver is None else secret_resolver
    resolved_secret_values: dict[SecretRef, SecretValue] = {}
    named_secret_values: dict[str, SecretValue] = {}
    for name, reference in selected.secrets.items():
        value = resolved_secret_values.get(reference)
        if value is None:
            value = resolver.resolve(reference)
            resolved_secret_values[reference] = value
        if not value:
            raise SecretResolutionError(
                f"secret reference is empty: {reference.provider}:{reference.key}"
            )
        named_secret_values[name] = value
    traffic_observer = None
    if traffic_store is not None:
        traffic_observer = ProbeTrafficRecorder(
            traffic_store,
            capture_session_id=traffic_capture_session_id or "scan-auth",
            identity_alias=identity,
            known_secrets=(
                value.reveal()
                for name, value in named_secret_values.items()
                if not is_contextual_identity_secret_name(name) and len(value.reveal()) >= 12
            ),
            error_sink=traffic_recorder_errors,
        )
        traffic_observer.register_url_segment_secret_values(
            value.reveal()
            for name, value in named_secret_values.items()
            if not is_contextual_identity_secret_name(name)
        )
    base_session = ProbeSession(
        target_url,
        timeout_seconds=timeout_seconds,
        allow_remote_target=allow_remote_target,
        in_scope=brief.scope.in_scope,
        out_of_scope=brief.scope.out_of_scope,
        max_rps=brief.roe.max_rps,
        traffic_observer=traffic_observer,
        traffic_policy=traffic_policy,
    )
    manager = SessionManager(
        base_session,
        (selected,),
        secret_resolver=SecretSnapshotResolver(resolved_secret_values),
    )
    try:
        handle = manager.acquire(identity)
    except (KeyboardInterrupt, SystemExit):
        manager.close()
        raise
    except Exception:  # noqa: BLE001 - target/login details must not escape the boundary.
        manager.close()
        raise SessionError("managed authentication initialization failed") from None
    redactor = AuthArtifactRedactor()
    redactor.register_named_secret_values(named_secret_values)
    owner = ManagedAttackAuthentication(
        identity=identity,
        manager=manager,
        handle=handle,
        redactor=redactor,
        traffic_policy=traffic_policy,
    )
    return owner, redactor


def _require_scan_payload(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        message = "scan result redaction produced an invalid payload"
        raise TypeError(message)
    return value


def _validate_configured_scan_identity(brief: EngagementBrief, identity: str) -> None:
    authentication = brief.authentication
    if authentication is None:
        raise ValueError("the engagement brief has no authentication identities")
    if any(configured.alias == identity for configured in authentication.identities):
        return
    available = ", ".join(configured.alias for configured in authentication.identities)
    raise ConfiguredAuthenticationError(f"unknown identity; configured identities: {available}")


def _brief(args: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="ravage brief")
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser("template", help="print a starter engagement brief")
    template.add_argument("--target-url", required=True)
    template.add_argument(
        "--objective",
        action="append",
        dest="objectives",
        default=[],
        help="objective to include; defaults to web_application_assessment",
    )
    template.add_argument("--max-cost-usd", type=float, default=5.0)
    template.add_argument("--max-runtime-min", type=int, default=30)
    template.add_argument(
        "--description",
        default=BRIEF_DESCRIPTION_TODO,
        help="target/challenge description to place under context.description",
    )
    parsed = parser.parse_args(args)

    if parsed.command == "template":
        try:
            assert_http_url(parsed.target_url)
        except ValueError as exc:
            parser.error(str(exc))
        payload = _brief_template_payload(
            target_url=parsed.target_url,
            objectives=parsed.objectives or ["web_application_assessment"],
            max_cost_usd=parsed.max_cost_usd,
            max_runtime_min=parsed.max_runtime_min,
            description=parsed.description,
        )
        _write_line(yaml.safe_dump(payload, sort_keys=False).rstrip())


def _init(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="ravage init",
        description="Create a scoped brief and private environment file.",
        epilog=(
            "Authenticated form example:\n"
            "  ravage init http://127.0.0.1:3000 "
            "--brief ravage-brief.yaml --env-file .env.ravage --auth form "
            "--auth-login /login --auth-health /account --auth-marker Logout"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="localhost or explicitly authorized target URL",
    )
    parser.add_argument("--target-url", help="localhost or explicitly authorized target URL")
    parser.add_argument(
        "--brief",
        type=Path,
        default=Path("brief.yaml"),
        help="brief to create; defaults to brief.yaml",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env.ravage"),
        help="private env file to create; defaults to .env.ravage",
    )
    parser.add_argument(
        "--description",
        default=BRIEF_DESCRIPTION_TODO,
        help="target/challenge description to place under context.description",
    )
    parser.add_argument(
        "--auth",
        choices=["form", "bearer", "header"],
        help="also configure one managed identity for auth checks, scans, and attacks",
    )
    parser.add_argument("--auth-identity", default="user", help="alias; defaults to user")
    parser.add_argument(
        "--auth-login",
        help="form login URL or target-relative path; defaults to /login",
    )
    parser.add_argument(
        "--auth-username-field",
        default="username",
        help="form username/email field; defaults to username",
    )
    parser.add_argument(
        "--auth-password-field",
        default="password",
        help="form password field; defaults to password",
    )
    parser.add_argument(
        "--auth-health",
        help="protected URL used to prove login worked; required with --auth",
    )
    parser.add_argument(
        "--auth-marker",
        help="text present only in an authenticated health response",
    )
    parser.add_argument(
        "--auth-unauthenticated-marker",
        help="text that proves the health response is logged out",
    )
    parser.add_argument(
        "--auth-header",
        default="X-API-Key",
        help="header name for --auth header; defaults to X-API-Key",
    )
    parser.add_argument(
        "--auth-secret-env",
        help="custom bearer/header environment-variable name",
    )
    parser.add_argument("--force", action="store_true", help="replace existing output files")
    parsed = parser.parse_args(args)
    if parsed.target and parsed.target_url and parsed.target != parsed.target_url:
        parser.error("pass the target as a positional URL or --target-url, not both")
    parsed.target_url = parsed.target_url or parsed.target
    auth_result = _create_init_files(parser, parsed)
    _write_line(banner("INIT"))
    _write_line(f"{badge('created', 'ok')} brief={parsed.brief}")
    _write_line(f"{badge('created', 'ok')} env={parsed.env_file}")
    edit_action = (
        "replace TODO values and review"
        if parsed.description == BRIEF_DESCRIPTION_TODO
        else "review"
    )
    _write_line(
        f"{badge('edit', 'warn')} {edit_action} scope, rules, budget, and context in {parsed.brief}"
    )
    quoted_env_file = shlex.quote(str(parsed.env_file))
    quoted_brief = shlex.quote(str(parsed.brief))
    remote_target = not is_local_url(parsed.target_url)
    remote_flag = " --authorized-remote-target" if remote_target else ""
    runtime_flag = ""
    if auth_result is None:
        _write_line(
            f"{badge('next', 'info')} ravage scan {quoted_brief}{remote_flag} "
            "--probe surface_map --report"
        )
        _write_line(
            f"{badge('check', 'info')} ravage doctor --workflow scan "
            f"--brief {quoted_brief}{remote_flag}"
        )
        _write_line(
            f"{badge('agent', 'info')} ravage attack {quoted_brief}{remote_flag} "
            f"--env-file {quoted_env_file}{runtime_flag} --allow-paid-models --report"
        )
    else:
        _write_line(
            f"{badge('auth:added', 'ok')} {auth_result.alias} · {auth_result.method} · "
            f"set {', '.join(auth_result.environment_keys)} in {auth_result.env_path}"
        )
        _write_auth_next_commands(
            brief_path=parsed.brief,
            env_path=parsed.env_file,
            identity=auth_result.alias,
            target_url=parsed.target_url,
        )
    if auth_result is None:
        _write_line(
            f"{badge('optional', 'info')} ravage doctor --workflow attack "
            f"--brief {quoted_brief} --env-file {quoted_env_file}{remote_flag}"
        )
        _write_line(
            f"{badge('optional', 'info')} ravage auth add {quoted_brief} --type form "
            "--health /account --marker Logout"
        )


def _create_init_files(
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
) -> AuthScaffoldResult | None:
    _validate_init_output_paths(parser, parsed.brief, parsed.env_file, force=parsed.force)
    if not parsed.target_url:
        parser.error("a target URL is required; use `ravage init URL` or --target-url URL")
    try:
        assert_http_url(parsed.target_url)
    except ValueError as exc:
        parser.error(str(exc))
    _validate_init_auth_options(parser, parsed)

    brief_text = yaml.safe_dump(
        _brief_template_payload(
            target_url=parsed.target_url,
            objectives=["web_application_assessment"],
            max_cost_usd=5.0,
            max_runtime_min=30,
            description=parsed.description,
        ),
        sort_keys=False,
    )
    env_text = (
        "# Ravage authentication secrets\n"
        if parsed.auth
        else (
            "# Ravage model provider settings\n"
            "OPENAI_API_KEY=\n"
            "ANTHROPIC_API_KEY=\n"
            "ABLIT_KEY=\n"
            "RAVAGE_OPENAI_LOW_MODEL=gpt-5.4-mini-2026-03-17\n"
            "RAVAGE_OPENAI_MID_MODEL=gpt-5.4-2026-03-05\n"
            "RAVAGE_ANTHROPIC_LOW_MODEL=claude-haiku-4-5-20251001\n"
            "RAVAGE_ANTHROPIC_MID_MODEL=claude-sonnet-4-6\n"
            "RAVAGE_ABLITERATION_LOW_MODEL=abliterated-model\n"
            "RAVAGE_ABLITERATION_MID_MODEL=abliterated-model-large\n"
        )
    )
    auth_result = None
    if parsed.auth:
        try:
            with tempfile.TemporaryDirectory(prefix="ravage-init-") as staging_directory:
                staging_root = Path(staging_directory)
                staged_brief = staging_root / "brief.yaml"
                staged_env = staging_root / ".env.ravage"
                staged_brief.write_text(brief_text, encoding="utf-8")
                staged_env.write_text(env_text, encoding="utf-8")
                staged_env.chmod(0o600)
                form_fields = None
                if parsed.auth == "form":
                    form_fields = {
                        parsed.auth_username_field: default_secret_environment_key(
                            parsed.auth_identity,
                            "username",
                        ),
                        parsed.auth_password_field: default_secret_environment_key(
                            parsed.auth_identity,
                            "password",
                        ),
                    }
                staged_result = scaffold_auth_identity(
                    staged_brief,
                    alias=parsed.auth_identity,
                    method=parsed.auth,
                    env_path=staged_env,
                    login_url=parsed.auth_login,
                    health_url=parsed.auth_health,
                    form_fields=form_fields,
                    secret_env=parsed.auth_secret_env,
                    header_name=parsed.auth_header,
                    authenticated_marker=parsed.auth_marker,
                    unauthenticated_marker=parsed.auth_unauthenticated_marker,
                )
                brief_text = staged_brief.read_text(encoding="utf-8")
                env_text = staged_env.read_text(encoding="utf-8")
                auth_result = replace(
                    staged_result,
                    brief_path=parsed.brief,
                    env_path=parsed.env_file,
                )
        except (AuthScaffoldError, OSError, UnicodeError, ValueError) as exc:
            parser.error(f"could not configure authentication: {_concise_cli_error(exc)}")

    try:
        parsed.brief.parent.mkdir(parents=True, exist_ok=True)
        parsed.env_file.parent.mkdir(parents=True, exist_ok=True)
        brief_mode = parsed.brief.stat().st_mode & 0o777 if parsed.brief.exists() else 0o644
        _atomic_write_cli_text(parsed.brief, brief_text, mode=brief_mode)
        _atomic_write_cli_text(parsed.env_file, env_text, mode=0o600)
    except (OSError, UnicodeError) as exc:
        parser.error(f"could not create init files: {_concise_cli_error(exc)}")
    return auth_result


def _validate_init_auth_options(
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
) -> None:
    if parsed.auth is None:
        if any(
            value is not None
            for value in (
                parsed.auth_login,
                parsed.auth_health,
                parsed.auth_marker,
                parsed.auth_unauthenticated_marker,
                parsed.auth_secret_env,
            )
        ):
            parser.error("authentication options require --auth")
        return
    if not parsed.auth_health:
        parser.error("--auth requires --auth-health")
    if not (parsed.auth_marker or parsed.auth_unauthenticated_marker):
        parser.error("--auth requires --auth-marker or --auth-unauthenticated-marker")
    if parsed.auth != "form" and parsed.auth_login is not None:
        parser.error("--auth-login is only valid with --auth form")
    if parsed.auth == "form" and parsed.auth_secret_env is not None:
        parser.error("--auth-secret-env is only valid with --auth bearer or header")


def _validate_init_output_paths(
    parser: argparse.ArgumentParser,
    brief_path: Path,
    env_path: Path,
    *,
    force: bool,
) -> None:
    if brief_path.resolve(strict=False) == env_path.resolve(strict=False):
        parser.error("--brief and --env-file must be different paths")
    for path in (brief_path, env_path):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            parser.error(f"output path must be a regular, non-symlink file: {path}")
        if path.exists() and not force:
            raise SystemExit(f"{path} already exists; pass --force to overwrite")
    if brief_path.exists() and env_path.exists() and brief_path.samefile(env_path):
        parser.error("--brief and --env-file cannot refer to the same file")


def _atomic_write_cli_text(path: Path, content: str, *, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.chmod(mode)
        temporary_path.replace(path)
    finally:
        with suppress(FileNotFoundError):
            temporary_path.unlink()


def _setup(args: list[str]) -> None:
    if not args:
        _run_setup_check([], prog="ravage setup")
        return
    if args[0] == "check":
        _run_setup_check(args[1:], prog="ravage setup check")
        return
    parser = argparse.ArgumentParser(
        prog="ravage setup",
        description="Check core installation or one workflow's readiness.",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("check", help="run setup diagnostics")
    parser.parse_args(args)
    parser.error("supported setup command: check")


def _doctor(args: list[str]) -> None:
    _run_setup_check(args, prog="ravage doctor")


def _run_setup_check(  # noqa: C901, PLR0912, PLR0915
    args: list[str],
    *,
    prog: str,
) -> None:
    parser = argparse.ArgumentParser(
        prog=prog,
        description=("Diagnose the core install or verify everything needed for one workflow."),
    )
    parser.add_argument(
        "--workflow",
        "--for",
        dest="workflow",
        choices=["core", "scan", "attack", "traffic", "lab"],
        help="make workflow-specific optional capabilities required",
    )
    parser.add_argument("--brief", type=Path)
    parser.add_argument("--target-url")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--model-profile")
    parser.add_argument("--model-tier", choices=["high", "mid", "low"])
    parser.add_argument(
        "--traffic-policy",
        choices=["observe", "low-noise"],
        help=(
            "attack transport profile; authorized remote attacks default to native "
            "HTTP-only low-noise mode"
        ),
    )
    parser.add_argument(
        "--tool-runtime",
        choices=["host", "docker", "auto"],
        default="docker",
        help="attack process runtime; host execution requires an explicit opt-in",
    )
    parser.add_argument("--tool-image", default=DEFAULT_TOOL_IMAGE)
    parser.add_argument("--run-root", type=Path, default=Path("runs"))
    parser.add_argument("--skip-tools", action="store_true")
    parser.add_argument(
        "--authorized-remote-target",
        action="store_true",
        help="allow one bounded reachability request to an in-scope remote target",
    )
    parser.add_argument("--json", action="store_true")
    parsed = parser.parse_args(args)

    workflow = parsed.workflow or ("attack" if parsed.brief is not None else "core")
    brief_path = parsed.brief
    if brief_path is None and workflow in {"attack", "scan"}:
        brief_path = discover_brief()
    env_file = parsed.env_file
    if env_file is None and workflow == "attack":
        env_file = discover_env_file(brief_path=brief_path)

    checks: list[dict[str, object]] = [
        _setup_check_python(),
        _setup_check_entrypoint(),
        _setup_check_package(),
        run_location_diagnostic(parsed.run_root).to_dict(),
    ]
    if env_file is not None:
        if not env_file.is_file():
            checks.append(
                {
                    "name": "environment",
                    "status": "fail",
                    "detail": f"environment file does not exist: {env_file}",
                    "fix": "Create it with `ravage init URL` or pass the correct --env-file.",
                }
            )
        else:
            try:
                _load_env_file(env_file)
            except (OSError, UnicodeError) as exc:
                checks.append(
                    {
                        "name": "environment",
                        "status": "fail",
                        "detail": _concise_cli_error(exc),
                        "fix": f"Make {env_file} readable and retry.",
                    }
                )
            else:
                checks.append(
                    {
                        "name": "environment",
                        "status": "ok",
                        "detail": f"loaded variables from {env_file} without shell execution",
                    }
                )

    brief: EngagementBrief | None = None
    target_url = parsed.target_url or ""
    if workflow in {"attack", "scan"} and brief_path is None:
        checks.append(
            {
                "name": "brief",
                "status": "fail",
                "detail": "no engagement brief was supplied or discovered",
                "fix": "Run `ravage init URL`, or pass --brief BRIEF.yaml.",
            }
        )
    elif brief_path is not None:
        try:
            brief = load_engagement_brief(brief_path)
            target_url = parsed.target_url or first_http_target(brief)
        except Exception as exc:  # noqa: BLE001 - diagnostics collect expected failures.
            checks.append(
                {
                    "name": "brief",
                    "status": "fail",
                    "detail": _concise_cli_error(exc),
                    "fix": f"Correct {brief_path}, or regenerate it with `ravage init URL`.",
                }
            )
        else:
            checks.append(
                {
                    "name": "brief",
                    "status": "ok",
                    "detail": (
                        f"scope_entries={len(brief.scope.in_scope)} "
                        f"target={redacted_target_url(target_url)}"
                    ),
                }
            )
            if workflow == "attack":
                description_issue = _brief_description_issue(brief)
                checks.append(
                    {
                        "name": "description",
                        "status": "fail" if description_issue else "ok",
                        "detail": (
                            f"{description_issue}; edit context.description in {brief_path}"
                            if description_issue
                            else "context.description provided"
                        ),
                        **(
                            {"fix": f"Replace the TODO in {brief_path} with useful target context."}
                            if description_issue
                            else {}
                        ),
                    }
                )

    remote_target = bool(target_url and not is_local_url(target_url))
    attack_traffic_policy = str(
        parsed.traffic_policy or ("low-noise" if remote_target else "observe")
    )
    if target_url and brief is not None:
        if not is_local_url(target_url) and not parsed.authorized_remote_target:
            remote_requirement = (
                "this authenticated attack uses the managed HTTP lane and does not require Docker"
                if workflow == "attack" and brief.authentication is not None
                else (
                    "the default attack uses native metered HTTP and does not require Docker"
                    if attack_traffic_policy == "low-noise"
                    else "the selected process-capable attack requires the Docker tool runtime"
                )
                if workflow == "attack"
                else "this workflow requires explicit remote-target authorization"
            )
            checks.append(
                {
                    "name": "target",
                    "status": "fail",
                    "detail": ("remote target declared but not contacted; " + remote_requirement),
                    "fix": "Review scope, then rerun with --authorized-remote-target.",
                }
            )
        else:
            checks.append(
                target_reachability_diagnostic(
                    target_url,
                    in_scope=tuple(str(item) for item in brief.scope.in_scope),
                    out_of_scope=tuple(str(item) for item in brief.scope.out_of_scope),
                    max_rps=brief.roe.max_rps,
                    allow_remote_target=parsed.authorized_remote_target,
                    required=True,
                ).to_dict()
            )
    elif workflow == "traffic":
        if not target_url:
            checks.append(
                {
                    "name": "target",
                    "status": "fail",
                    "detail": "traffic readiness requires a target URL",
                    "fix": "Pass --target-url URL and rerun this check.",
                }
            )
        else:
            checks.append(
                target_reachability_diagnostic(
                    target_url,
                    in_scope=(target_url,),
                    out_of_scope=(),
                    max_rps=None,
                    allow_remote_target=parsed.authorized_remote_target,
                    required=True,
                ).to_dict()
            )

    parsed.model_profile = parsed.model_profile or _preferred_model_profile()
    parsed.model_tier = parsed.model_tier or (
        "low" if parsed.model_profile.startswith("hosted-") else "mid"
    )
    if workflow == "attack":
        checks.append(
            _setup_model_check(
                model_config=parsed.model_config,
                model_profile=parsed.model_profile,
                model_tier=parsed.model_tier,
                env_file=env_file,
            )
        )

    if workflow == "core":
        checks.extend(
            (
                docker_compose_diagnostic(required=False).to_dict(),
                labs_diagnostic(required=False).to_dict(),
                playwright_diagnostic(required=False).to_dict(),
            )
        )
    elif workflow == "traffic":
        checks.append(playwright_diagnostic(required=True).to_dict())
    elif workflow == "lab":
        checks.extend(
            (
                docker_compose_diagnostic(required=True).to_dict(),
                labs_diagnostic(required=True).to_dict(),
            )
        )
    elif workflow == "scan":
        checks.append(
            {
                "name": "tools",
                "status": "ok",
                "detail": "deterministic scan probes run in-process; no model or Docker required",
            }
        )
    elif workflow == "attack" and brief is not None and brief.authentication is not None:
        checks.append(
            {
                "name": "tools",
                "status": "ok",
                "detail": (
                    "managed authenticated attack uses scoped in-process HTTP; "
                    "process and Docker runtimes are intentionally unavailable"
                ),
            }
        )
    elif workflow == "attack" and attack_traffic_policy == "low-noise":
        checks.append(
            {
                "name": "tools",
                "status": "ok",
                "detail": (
                    "low-noise attack uses scoped native metered HTTP; "
                    "process and Docker runtimes are intentionally unavailable"
                ),
            }
        )
    elif parsed.skip_tools:
        checks.append({"name": "tools", "status": "ok", "detail": "skipped by --skip-tools"})
    else:
        checks.append(
            _setup_check_tools(
                tool_image=parsed.tool_image,
                require_docker=parsed.tool_runtime != "host",
            )
        )

    payload = {
        "schema": "ravage.setup_check.v2",
        "ok": not any(item["status"] == "fail" for item in checks),
        "workflow": workflow,
        "brief": str(brief_path or ""),
        "environment_file": str(env_file or ""),
        "target_url": redacted_target_url(target_url) if target_url else "",
        "checks": checks,
    }
    if parsed.json:
        _write_line(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _write_line(banner("DOCTOR", f"{workflow} workflow"))
        for item in checks:
            _write_line(status_line(item["status"], item["name"], item["detail"]))
            fix = str(item.get("fix") or "")
            if fix and item["status"] != "ok":
                _write_line(f"{badge('fix', 'info')} {fix}")
        if payload["ok"]:
            _write_line(f"{badge('ready', 'ok')} {workflow} workflow prerequisites are ready")
            _write_setup_next_command(
                workflow=workflow,
                brief_path=brief_path,
                env_file=env_file,
                target_url=target_url,
                model_profile=parsed.model_profile,
                model_tier=parsed.model_tier,
                traffic_policy=attack_traffic_policy,
                managed_http=bool(brief is not None and brief.authentication is not None),
                tool_runtime=parsed.tool_runtime,
            )
    if not payload["ok"]:
        raise SystemExit(1)


def _setup_model_check(
    *,
    model_config: Path | None,
    model_profile: str,
    model_tier: ModelTier,
    env_file: Path | None,
) -> dict[str, object]:
    try:
        registry = load_model_registry(model_config)
        routes = resolve_model_routes(
            registry,
            profile_name=model_profile,
            tier=model_tier,
        )
        ready = ready_model_routes(routes)
    except Exception as exc:  # noqa: BLE001 - setup check reports failures.
        return {
            "name": "model",
            "status": "fail",
            "detail": _concise_cli_error(exc),
            "fix": "Check the model profile/configuration and rerun `ravage doctor`.",
        }
    if ready:
        route = ready[0]
        route_base_url = str(getattr(route, "base_url", "") or "")
        if route_base_url and is_local_url(route_base_url):
            api_key_env = str(getattr(route, "api_key_env", "") or "")
            return local_model_diagnostic(
                provider=str(route.provider),
                model=str(route.model),
                base_url=route_base_url,
                api_key=os.environ.get(api_key_env, "") if api_key_env else "",
                required=True,
            ).to_dict()
        return {
            "name": "model",
            "status": "ok",
            "detail": f"{route.provider}/{route.model}",
        }
    missing = sorted({env for route in routes for env in route.missing_env})
    location = f" in {env_file}" if env_file is not None else ""
    transport_issues = sorted(
        {route.transport_issue for route in routes if route.transport_issue is not None}
    )
    if transport_issues:
        return {
            "name": "model",
            "status": "fail",
            "detail": "unsupported model transport: " + ", ".join(transport_issues),
            "fix": "Use native OpenAI/Anthropic or a configured custom_openai/LiteLLM gateway.",
        }
    if missing:
        return {
            "name": "model",
            "status": "fail",
            "detail": "missing env: " + ", ".join(missing),
            "fix": f"Set {', '.join(missing)}{location}, then rerun this check.",
        }
    missing_pricing = sorted({field for route in routes for field in route.missing_pricing})
    if missing_pricing:
        return {
            "name": "model",
            "status": "fail",
            "detail": "missing pricing: " + ", ".join(missing_pricing),
            "fix": "Add explicit current token prices to the model route, then rerun this check.",
        }
    return {
        "name": "model",
        "status": "fail",
        "detail": "no usable model route",
        "fix": "Check the model profile/configuration and rerun this check.",
    }


def _write_setup_next_command(  # noqa: PLR0913
    *,
    workflow: str,
    brief_path: Path | None,
    env_file: Path | None,
    target_url: str,
    model_profile: str,
    model_tier: str,
    traffic_policy: str = "observe",
    managed_http: bool = False,
    tool_runtime: str = "docker",
) -> None:
    remote_flag = (
        " --authorized-remote-target" if target_url and not is_local_url(target_url) else ""
    )
    if workflow == "core":
        _write_line(
            f"{badge('next', 'info')} ravage init http://127.0.0.1:3000 "
            '--description "Authorized assessment of my local app."'
        )
        return
    if workflow == "lab":
        _write_line(f"{badge('next', 'info')} ravage lab up ravage-acme-box")
        return
    if workflow == "traffic":
        target = redacted_target_url(target_url) if target_url else "http://127.0.0.1:3000"
        _write_line(
            f"{badge('next', 'info')} ravage traffic capture {shlex.quote(target)}{remote_flag}"
        )
        return
    if brief_path is None:
        return
    quoted_brief = shlex.quote(str(brief_path))
    if workflow == "scan":
        _write_line(
            f"{badge('next', 'info')} ravage scan {quoted_brief}{remote_flag} "
            "--probe surface_map --report"
        )
        return
    env_option = f" --env-file {shlex.quote(str(env_file))}" if env_file is not None else ""
    remote_target = bool(target_url and not is_local_url(target_url))
    if managed_http:
        transport_options = (
            " --traffic-policy observe"
            if remote_target and traffic_policy == "observe"
            else " --traffic-policy low-noise"
            if not remote_target and traffic_policy == "low-noise"
            else ""
        )
    elif traffic_policy == "low-noise":
        transport_options = " --traffic-policy low-noise" if not remote_target else ""
    elif remote_target:
        transport_options = " --traffic-policy observe --tool-runtime docker"
    else:
        transport_options = " --tool-runtime host" if tool_runtime == "host" else ""
    paid = " --allow-paid-models" if model_profile.startswith("hosted-") else ""
    _write_line(
        f"{badge('next', 'info')} ravage attack {quoted_brief}{remote_flag}{env_option} "
        f"--model-profile {model_profile} --model-tier {model_tier} "
        f"{transport_options.strip()}{paid} --report"
    )


def _tools(args: list[str]) -> None:  # noqa: C901 - subcommand dispatch is explicit.
    parser = argparse.ArgumentParser(prog="ravage tools")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list external tool names Ravage may use")
    check = subparsers.add_parser("check", help="check host and Docker tool availability")
    check.add_argument("--image", default=DEFAULT_TOOL_IMAGE)
    check.add_argument("--json", action="store_true")
    install = subparsers.add_parser(
        "install",
        help="print or execute a bounded external-tool installation plan",
    )
    install.add_argument(
        "--method",
        choices=["auto", "docker", "apt", "brew", "manual"],
        default="auto",
    )
    install.add_argument(
        "--image",
        default=DEFAULT_TOOL_IMAGE,
        help="local image tag; custom tags are built from the local Dockerfile",
    )
    install.add_argument(
        "--no-cache",
        action="store_true",
        help="skip the published-image pull and force a clean local Docker build",
    )
    install.add_argument("--execute", action="store_true")
    parsed = parser.parse_args(args)

    if parsed.command == "list":
        for tool in TOOL_RUNTIME_BINARIES:
            _write_line(tool)
        return
    if parsed.command == "install":
        result = cli_tools.install_tools(
            method=parsed.method,
            execute=parsed.execute,
            image=parsed.image,
            no_cache=parsed.no_cache,
        )
        if parsed.execute:
            raise SystemExit(result)
        return

    report = _tool_check_report(image=parsed.image)
    if parsed.json:
        _write_line(json.dumps(report, indent=2, sort_keys=True))
        return

    _write_line(banner("TOOLS"))
    _write_line(tone("Host tools", "info"))
    host = report.get("host")
    if isinstance(host, dict):
        for name in TOOL_RUNTIME_BINARIES:
            item = host.get(name)
            if not isinstance(item, dict):
                continue
            status = "ok" if item.get("available") else "missing"
            detail = str(item.get("path") or item.get("source") or "")
            error = str(item.get("error") or "")
            suffix = " ".join(part for part in (detail, error) if part)
            _write_line(f"  {name:<11}{status:<8}{suffix}".rstrip())
    docker = report.get("docker")
    if isinstance(docker, dict):
        status = "ok" if docker.get("available") else "missing"
        style = "ok" if status == "ok" else "warn"
        _write_line(f"{tone('Docker image', 'info')}: {parsed.image} {badge(status, style)}")
        error = str(docker.get("error") or "")
        if error:
            _write_line(f"  {tone(error, 'warn')}")
    _write_line("")
    _write_line("WHERE TO INSTALL TOOLS")
    _write_line("  Host: PATH, .tools/bin, or RAVAGE_<TOOL>_BIN overrides")
    _write_line("  Installer: scripts/install_tools.sh --execute")
    guidance = report.get("runtime_guidance")
    if isinstance(guidance, list):
        for line in guidance:
            _write_line(f"  {line}")
    _write_line(f"{badge('next', 'info')} {report.get('recommendation') or ''}")


def _competitors(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="ravage competitors",
        description="Run isolated head-to-head agent comparison harnesses.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser("preflight", help="check harness config and host readiness")
    preflight.add_argument("--config", type=Path, required=True)
    preflight.add_argument("--output-dir", type=Path, default=Path("runs/competitors/preflight"))
    preflight.add_argument("--min-free-gib", type=int)

    run = subparsers.add_parser("run", help="run the configured competitor matrix")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--output-dir", type=Path, default=Path("runs/competitors/head-to-head"))
    run.add_argument("--min-free-gib", type=int)

    report = subparsers.add_parser("report", help="regenerate leaderboard files from a run")
    report.add_argument("run_dir", type=Path)

    adapt = subparsers.add_parser("adapt-ravage", help="adapt one Ravage benchmark case result")
    adapt.add_argument("--benchmark-report", type=Path, required=True)
    adapt.add_argument("--case-id", required=True)
    adapt.add_argument("--output", type=Path, required=True)

    parsed = parser.parse_args(args)
    if parsed.command == "preflight":
        result = preflight_competitor_harness(
            config_path=parsed.config,
            output_dir=parsed.output_dir,
            min_free_gib=parsed.min_free_gib,
        )
        _write_line(
            "competitors preflight "
            f"blocked={str(result.blocked).lower()} "
            f"free_gib={result.free_gib} "
            f"report={result.report_path}"
        )
        if result.blocked:
            for reason in result.block_reasons:
                _write_line(f"- {reason}")
            raise SystemExit(2)
        return

    if parsed.command == "run":
        preflight_result = preflight_competitor_harness(
            config_path=parsed.config,
            output_dir=parsed.output_dir,
            min_free_gib=parsed.min_free_gib,
        )
        if preflight_result.blocked:
            _write_line(f"competitors run blocked preflight={preflight_result.report_path}")
            for reason in preflight_result.block_reasons:
                _write_line(f"- {reason}")
            raise SystemExit(2)
        result = run_competitor_harness(config_path=parsed.config, output_dir=parsed.output_dir)
        summary = result.get("summary", {})
        _write_line(
            "competitors run "
            f"runs={summary.get('runs', 0)} "
            f"report={parsed.output_dir / 'report.json'}"
        )
        return

    if parsed.command == "report":
        result = report_competitor_harness(parsed.run_dir)
        summary = result.get("summary", {})
        _write_line(
            "competitors report "
            f"runs={summary.get('runs', 0)} "
            f"leaderboard={parsed.run_dir / 'leaderboard.md'}"
        )
        return

    if parsed.command == "adapt-ravage":
        payload = build_ravage_competitor_result(
            benchmark_report_path=parsed.benchmark_report,
            case_id=parsed.case_id,
        )
        parsed.output.parent.mkdir(parents=True, exist_ok=True)
        parsed.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        _write_line(f"competitors adapt-ravage output={parsed.output}")
        return


def _xben(args: list[str]) -> None:  # noqa: PLR0915 - benchmark options are explicit.
    parser = argparse.ArgumentParser(
        prog="ravage xben",
        description="Run Ravage against the XBOW/XBEN benchmark set.",
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
    )
    parser.add_argument(
        "--comparison-profile",
        choices=["mapta-awe-xben", "none"],
        default="mapta-awe-xben",
    )
    parser.add_argument(
        "--agent-mode",
        choices=["hybrid", "ctf-free-roam"],
        default="ctf-free-roam",
    )
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--model-profile", default="local-ollama")
    parser.add_argument("--model-tier", choices=["high", "mid", "low"], default="mid")
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument(
        "--recovery-profile",
        choices=["off", "recovery-v1"],
        default="off",
    )
    parser.add_argument("--autonomous-route", action="store_true")
    parser.add_argument(
        "--autonomous-route-engine",
        choices=AUTONOMOUS_ROUTE_ENGINES,
        default="frontier",
    )
    parser.add_argument("--autonomous-route-max-requests", type=int, default=24)
    parser.add_argument(
        "--knowledge-pack",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--knowledge-pack-sha256", help=argparse.SUPPRESS)
    parser.add_argument("--knowledge-pack-limit", type=int, default=4, help=argparse.SUPPRESS)
    parser.add_argument(
        "--knowledge-pack-max-chars",
        type=int,
        default=6_000,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--case-timeout-seconds", type=int, default=1800)
    parser.add_argument("--max-model-requests-per-case", type=int, default=40)
    parser.add_argument("--max-cost-usd", type=float)
    parser.add_argument("--min-free-gib", type=int, default=20)
    parser.add_argument("--allow-paid-models", action="store_true")
    parser.add_argument("--require-clean-source", action="store_true")
    parser.add_argument("--allow-degraded", action="store_true")
    parser.add_argument("--input-token-ceiling-per-model-call", type=int, default=12_000)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--docker-platform", default="linux/amd64")
    parser.add_argument("--tool-runtime", choices=["host", "docker", "auto"], default="host")
    parser.add_argument("--tool-image", default=DEFAULT_TOOL_IMAGE)
    parser.add_argument("--flag-mode", choices=["exact", "pattern"], default="exact")
    parser.add_argument("--operator-log-root", type=Path)
    parser.add_argument(
        "--stream-agent-output",
        action="store_true",
        help="show each child attack step while retaining the per-case agent.stdout artifact",
    )
    parser.add_argument("--cockpit", action="store_true")
    parser.add_argument("--cockpit-host", default="127.0.0.1")
    parser.add_argument("--cockpit-port", type=int, default=8787)
    parser.add_argument("--keep-target", action="store_true")
    parser.add_argument("--prune-case-images", action="store_true")
    parser.add_argument("--target-ttl-seconds", type=int, default=1800)
    parsed = parser.parse_args(args)
    _pin_parsed_knowledge_pack(parser, parsed)
    if parsed.autonomous_route and parsed.recovery_profile != "off":
        parser.error("--autonomous-route requires --recovery-profile off")

    settings = XbenSettings(
        benchmarks_root=parsed.benchmarks_root,
        output_dir=parsed.output_dir,
        all_cases=parsed.all_cases,
        case_range=parsed.case_range,
        ids=tuple(parsed.ids),
        exclude_ids=tuple(parsed.exclude_ids),
        sample=parsed.sample,
        sample_seed=parsed.sample_seed,
        levels=tuple(parsed.levels),
        resume=parsed.resume,
        retry_failed=parsed.retry_failed,
        dry_run=parsed.dry_run,
        list_cases=parsed.list_cases,
        preflight=parsed.preflight,
        mode=parsed.mode,
        comparison_profile=parsed.comparison_profile,
        agent="ai-web",
        agent_mode=parsed.agent_mode,
        recovery_profile=parsed.recovery_profile,
        autonomous_route=parsed.autonomous_route,
        autonomous_route_engine=parsed.autonomous_route_engine,
        autonomous_route_max_requests=parsed.autonomous_route_max_requests,
        model_config=parsed.model_config,
        model_profile=parsed.model_profile,
        model_tier=parsed.model_tier,
        max_turns=parsed.max_turns,
        knowledge_pack_path=parsed.knowledge_pack,
        knowledge_pack_sha256=parsed.knowledge_pack_sha256,
        knowledge_pack_limit=parsed.knowledge_pack_limit,
        knowledge_pack_max_chars=parsed.knowledge_pack_max_chars,
        case_timeout_seconds=parsed.case_timeout_seconds,
        max_model_requests_per_case=parsed.max_model_requests_per_case,
        max_cost_usd=parsed.max_cost_usd,
        min_free_gib=parsed.min_free_gib,
        allow_paid_models=parsed.allow_paid_models,
        require_clean_source=parsed.require_clean_source,
        allow_degraded=parsed.allow_degraded,
        input_token_ceiling_per_model_call=parsed.input_token_ceiling_per_model_call,
        concurrency=parsed.concurrency,
        docker_platform=parsed.docker_platform,
        flag_mode=parsed.flag_mode,
        tool_runtime=parsed.tool_runtime,
        tool_image=parsed.tool_image,
        operator_log_root=parsed.operator_log_root or parsed.output_dir / "operator-logs",
        stream_agent_output=parsed.stream_agent_output,
        cockpit=parsed.cockpit,
        cockpit_host=parsed.cockpit_host,
        cockpit_port=parsed.cockpit_port,
        keep_target=parsed.keep_target or parsed.cockpit,
        prune_case_images=parsed.prune_case_images,
        target_ttl_seconds=parsed.target_ttl_seconds,
    )
    try:
        run_xben(settings)
    except ValueError as exc:
        sys.stderr.write(f"[xben:blocked] {exc}\n")
        raise SystemExit(2) from None


def _target_url_from_brief(brief_path: Path, *, explicit: str | None) -> str:
    if explicit:
        return explicit
    try:
        return first_http_target(load_engagement_brief(brief_path))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _default_run_dir(brief_path: Path, kind: str) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    stem = _safe_path_stem(brief_path.stem) or "brief"
    return Path("runs") / f"{stem}-{kind}-{timestamp}"


def _safe_path_stem(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in value)


def _brief_template_payload(
    *,
    target_url: str,
    objectives: list[str],
    max_cost_usd: float,
    max_runtime_min: int,
    description: str,
) -> dict[str, object]:
    flag_objective = "capture_flag" in {str(objective).strip().lower() for objective in objectives}
    if flag_objective:
        win_condition = "Capture an exact flag value from executor-observed target evidence."
        evidence_rule = "Do not assume proof or flag values; extract them from target evidence."
    else:
        win_condition = (
            "Confirm and report evidence-backed vulnerabilities in the in-scope application."
        )
        evidence_rule = "Do not claim a vulnerability without executor-validated target evidence."
    return {
        "engagement_id": str(uuid4()),
        "scope": {
            "in_scope": [target_url],
            "out_of_scope": [],
        },
        "roe": {
            "max_rps": 5,
            "no_destructive_actions": True,
            "data_handling": "placeholders_only",
        },
        "objectives": objectives,
        "budget": {
            "max_cost_usd": max_cost_usd,
            "max_runtime_min": max_runtime_min,
        },
        "context": {
            "description": description,
            "win_condition": win_condition,
            "rules": [
                "Stay within the in-scope target URL(s).",
                evidence_rule,
                "Do not perform destructive actions.",
            ],
        },
    }


def _require_attack_description(
    parser: argparse.ArgumentParser,
    *,
    brief: object,
    brief_path: Path,
    allow_empty: bool,
) -> None:
    if allow_empty:
        return
    issue = _brief_description_issue(brief)
    if not issue:
        return
    message = (
        f"{issue}. Add context.description to {brief_path}, or pass "
        "--allow-empty-description only for deliberate blind generic recon."
    )
    parser.error(message)


def _require_paid_model_opt_in(
    parser: argparse.ArgumentParser,
    *,
    model_config: Path | None,
    model_profile: str,
    model_tier: ModelTier,
    allow_paid_models: bool,
) -> None:
    registry = load_model_registry(model_config)
    routes = resolve_model_routes(
        registry,
        profile_name=model_profile,
        tier=model_tier,
    )
    ready = ready_model_routes(routes)
    if not ready or not route_has_paid_transport_risk(ready[0]):
        return
    if allow_paid_models:
        return
    route = ready[0]
    parser.error(
        "paid-risk model route selected; pass --allow-paid-models to permit "
        f"provider={route.provider} model={route.model}"
    )


def _brief_description_issue(brief: object) -> str:
    context = getattr(brief, "context", {})
    if not isinstance(context, dict):
        return "brief context must be a mapping with context.description"

    raw_description = context.get("description")
    description = str(raw_description or "").strip()
    if not description:
        return "brief is missing context.description"

    lowered = description.lower()
    if lowered == BRIEF_DESCRIPTION_TODO.lower():
        return "brief context.description is still the generated TODO"
    for prefix in DESCRIPTION_PLACEHOLDER_PREFIXES:
        if lowered.startswith(prefix):
            return "brief context.description still looks like a placeholder"
    return ""


def _validate_attack_resume_identity_before_authentication(
    parser: argparse.ArgumentParser,
    *,
    resume_from: Path | None,
    workspace_dir: Path | None,
    requested_identity: str | None,
) -> None:
    workspace_state_path = (
        workspace_dir or Path("runs/ravage-agent/workspace")
    ) / "working_state.json"
    state_path = resolve_agent_state_path(
        resume_from,
        workspace_state_path=workspace_state_path,
    )
    if resume_from is not None and not state_path.is_file():
        parser.error(f"cannot resume attack: canonical agent state does not exist: {state_path}")
    if not state_path.is_file():
        return
    try:
        state = load_agent_state(state_path)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error(f"cannot read resume state {state_path}: {_concise_cli_error(exc)}")
    if state is None:
        parser.error(f"cannot read resume state {state_path}: no agent state found")
    restored_identity = str(
        (state.surface if state is not None else {}).get("authenticated_identity") or ""
    ).strip()
    if requested_identity and not restored_identity:
        parser.error("cannot resume agent state without its authenticated identity binding")
    if restored_identity and not requested_identity:
        parser.error("cannot resume authenticated agent state without --identity")
    if restored_identity and restored_identity != requested_identity:
        parser.error(
            "cannot resume authenticated agent state with a different identity: "
            f"state={restored_identity!r} requested={requested_identity!r}"
        )


def _attack_resume_workspace(resume_from: Path) -> Path:
    """Return the canonical workspace directory for a public attack resume argument."""
    if resume_from.is_dir():
        direct_state = resume_from / "working_state.json"
        if direct_state.is_file() or resume_from.name == "workspace":
            return resume_from
        return resume_from / "workspace"
    if resume_from.name == "working_state.json":
        return resume_from.parent
    return resume_from.parent / "workspace"


def _selected_scan_probes(requested: list[str], *, all_probes: bool) -> list[str]:
    catalog = [item["name"] for item in available_probes()]
    known = set(catalog)
    selected = (
        _dependency_ordered_scan_probes(catalog)
        if all_probes
        else list(requested or DEFAULT_SCAN_PROBES)
    )
    unknown = [probe for probe in selected if probe not in known]
    if unknown:
        choices = ", ".join(sorted(known))
        message = f"unknown probe(s): {', '.join(unknown)}; choices: {choices}"
        raise SystemExit(message)
    return selected


def _dependency_ordered_scan_probes(catalog: list[str]) -> list[str]:
    """Return a stable breadth-before-depth order for the complete probe catalog."""
    known = set(catalog)
    pending = list(catalog)
    selected: list[str] = []
    completed: set[str] = set()
    while pending:
        for index, probe in enumerate(pending):
            dependencies = set(_SCAN_PROBE_DEPENDENCIES.get(probe, ()))
            if probe not in _SCAN_DISCOVERY_PROBES:
                dependencies.update(item for item in _SCAN_DISCOVERY_PROBES if item in known)
            if all(
                dependency not in known or dependency in completed
                for dependency in dependencies
            ):
                selected.append(probe)
                completed.add(probe)
                pending.pop(index)
                break
        else:
            unresolved = ", ".join(pending)
            raise RuntimeError(f"cyclic deterministic scan probe dependencies: {unresolved}")
    return selected


def _authenticated_scan_selection(
    selected: list[str],
    *,
    explicit: bool,
) -> tuple[list[str], dict[str, str]]:
    skipped = {
        probe: reason for probe in selected if (reason := authenticated_probe_unavailability(probe))
    }
    if skipped and explicit:
        details = "; ".join(f"{probe}: {reason}" for probe, reason in sorted(skipped.items()))
        raise SystemExit(f"authenticated scan cannot run selected probe(s): {details}")
    return [probe for probe in selected if probe not in skipped], skipped


def _recognize_scan_result_proofs(value: object) -> list[str]:
    """Recognize proofs in bounded raw memory without persisting credential material."""
    stack = [value]
    proofs: list[str] = []
    remaining_chars = _MAX_SCAN_PROOF_SCAN_CHARS
    nodes_scanned = 0
    while stack and remaining_chars > 0 and nodes_scanned < _MAX_SCAN_PROOF_NODES:
        current = stack.pop()
        nodes_scanned += 1
        if isinstance(current, str):
            limit = min(len(current), remaining_chars, _MAX_SCAN_PROOF_VALUE_CHARS)
            remaining_chars -= limit
            for proof in recognize_proofs(current[:limit]):
                if proof not in proofs:
                    proofs.append(proof)
            continue
        if isinstance(current, bytes):
            stack.append(current[:_MAX_SCAN_PROOF_VALUE_CHARS].decode("utf-8", errors="replace"))
            continue
        if isinstance(current, Mapping):
            for key, item in reversed(tuple(current.items())):
                stack.append(item)
                if isinstance(key, str):
                    stack.append(key)
            continue
        if isinstance(current, (list, tuple, set, frozenset)):
            stack.extend(reversed(tuple(current)))
    return proofs


def _capture_scan_proofs(  # noqa: PLR0913
    proofs: list[str],
    *,
    state: AgentState,
    workspace: AgentWorkspace,
    audit: AuditStore,
    engagement_id: UUID,
    evidence: str,
    emit_live: bool,
) -> None:
    for proof in proofs:
        if proof in state.flags:
            continue
        state.flags.append(proof)
        payload = {
            "flag": proof,
            "evidence": evidence,
            "recognizer": "scan_probe_output",
        }
        audit.record(
            engagement_id=engagement_id,
            actor="scan",
            action="flag_captured",
            payload=payload,
        )
        event_id = workspace.record_event(kind="flag_captured", payload=payload)
        if emit_live:
            _write_line(f"{badge('flag:found', 'ok')} {proof}")
            _write_line(
                f"{badge('look', 'info')} {workspace.events_path} · "
                f"event={event_id} · field=payload.flag"
            )


def _load_env_file(path: Path) -> None:
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)


def _load_attack_environment(path: Path, *, excluded_keys: set[str]) -> None:
    """Load model/runtime variables while keeping selected auth secrets out of the process env."""
    for key, value in read_environment_file(path).items():
        if key not in excluded_keys:
            os.environ.setdefault(key, value)


def _selected_attack_identity(
    parser: argparse.ArgumentParser,
    *,
    brief: EngagementBrief,
    requested: str | None,
    default_when_single: bool,
) -> str | None:
    authentication = brief.authentication
    if authentication is None:
        if requested:
            parser.error("--identity requires brief.authentication")
        return None
    aliases = tuple(identity.alias for identity in authentication.identities)
    if requested:
        if requested not in aliases:
            parser.error(f"unknown attack identity; choose from: {', '.join(aliases)}")
        return requested
    if default_when_single and len(aliases) == 1:
        return aliases[0]
    if len(aliases) == 1:
        parser.error(
            "this brief configures authentication; pass "
            f"--identity {aliases[0]} to select its managed session"
        )
    parser.error(
        f"this brief configures multiple identities; choose --identity from: {', '.join(aliases)}"
    )


def _attack_auth_environment_keys(
    *,
    brief: EngagementBrief,
    identity: str | None,
) -> set[str]:
    if brief.authentication is None or identity is None:
        return set()
    keys: set[str] = set()
    for configured in brief.authentication.identities:
        references = list(configured.flow.secret_refs.values())
        if configured.flow.static_header is not None:
            references.append(configured.flow.static_header.value)
        if configured.flow.totp is not None:
            references.append(configured.flow.totp.secret)
        keys.update(
            reference.key
            for reference in references
            if reference.provider in {"env", "environment"}
        )
    return keys


def _preferred_model_profile() -> str:
    if os.environ.get("OPENAI_API_KEY", "").strip():
        return "hosted-openai"
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return "hosted-anthropic"
    if os.environ.get("ABLIT_KEY", "").strip():
        return "hosted-abliteration"
    return "local-ollama"


def _load_engagement_brief_for_cli(
    parser: argparse.ArgumentParser,
    path: Path,
) -> EngagementBrief:
    try:
        return load_engagement_brief(path)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        parser.error(f"invalid engagement brief {path}: {_concise_cli_error(exc)}")


def _concise_cli_error(exc: BaseException) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        with suppress(Exception):
            items = errors()
            if isinstance(items, list) and items:
                first = items[0]
                if isinstance(first, dict):
                    location = ".".join(str(part) for part in first.get("loc", ()))
                    message = str(first.get("msg") or "validation failed")
                    suffix = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
                    return f"{location}: {message}{suffix}" if location else f"{message}{suffix}"
    first_line = str(exc).strip().splitlines()[:1]
    return first_line[0] if first_line else type(exc).__name__


def _setup_check_python() -> dict[str, object]:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    ok = sys.version_info >= (3, 12) and sys.version_info < (3, 13)
    return {
        "name": "python",
        "status": "ok" if ok else "fail",
        "detail": f"Python {version}; Ravage expects >=3.12,<3.13",
    }


def _setup_check_entrypoint() -> dict[str, object]:
    path_text = shutil.which("ravage")
    if not path_text:
        return {
            "name": "entrypoint",
            "status": "ok",
            "detail": "running from python module; console script not found on PATH",
        }
    stale = _stale_entrypoint_detail(Path(path_text))
    if stale:
        return {"name": "entrypoint", "status": "fail", "detail": stale}
    return {"name": "entrypoint", "status": "ok", "detail": path_text}


def _setup_check_package() -> dict[str, object]:
    return {
        "name": "package",
        "status": "ok",
        "detail": f"ravage {package_version()}",
    }


def _stale_entrypoint_detail(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    if "orchestrator" in text:
        return f"{path} looks like an old orchestrator entrypoint; run scripts/bootstrap.sh"
    return None


def _setup_check_tools(*, tool_image: str, require_docker: bool = False) -> dict[str, object]:
    report = _tool_check_report(image=tool_image)
    recommendation = str(report.get("recommendation") or "")
    host = report.get("host")
    docker = report.get("docker")
    host_ready = False
    docker_ready = False
    if isinstance(host, dict):
        host_ready = bool(host.get("curl", {}).get("available")) and bool(
            host.get("python3", {}).get("available")
        )
    if isinstance(docker, dict):
        docker_ready = bool(docker.get("ready"))
    ready = docker_ready if require_docker else host_ready or docker_ready
    if require_docker and not docker_ready:
        recommendation = (
            f"Docker is required for the selected attack runtime; {recommendation}"
        ).rstrip(
            "; "
        )
    return {
        "name": "tools",
        "status": "ok" if ready else "fail",
        "detail": recommendation,
    }


def _tool_check_report(*, image: str) -> dict[str, object]:
    return cli_tool_check.tool_check_report(image=image)


def _host_tool_status() -> dict[str, dict[str, object]]:
    status: dict[str, dict[str, object]] = {}
    for tool in TOOL_RUNTIME_BINARIES:
        env_name = f"RAVAGE_{tool.upper()}_BIN".replace("-", "_")
        override = os.environ.get(env_name)
        if override:
            path = Path(override)
            status[tool] = {
                "available": path.exists(),
                "path": override,
                "source": env_name,
            }
            continue
        resolved = shutil.which(tool)
        status[tool] = {
            "available": bool(resolved),
            "path": resolved or "",
            "source": "PATH" if resolved else "",
        }
    return status


def _docker_tool_status(*, image: str) -> dict[str, object]:  # noqa: PLR0911
    docker_path = shutil.which("docker")
    if not docker_path:
        return {
            "available": False,
            "image": image,
            "tools": {},
            "error": "Docker command not found",
        }
    try:
        inspect = subprocess.run(  # noqa: S603
            [docker_path, "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": False,
            "image": image,
            "tools": {},
            "error": "Docker image inspect timed out",
        }
    except OSError as exc:
        return {"available": False, "image": image, "tools": {}, "error": str(exc)}
    if inspect.returncode != 0:
        error = (inspect.stderr or inspect.stdout or "Docker image not found").strip()
        return {"available": False, "image": image, "tools": {}, "error": error}

    command = " ; ".join(
        f"command -v {tool} >/dev/null && echo {tool}:ok || echo {tool}:missing"
        for tool in TOOL_RUNTIME_BINARIES
    )
    try:
        probe = subprocess.run(  # noqa: S603
            [docker_path, "run", "--rm", image, "sh", "-lc", command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "image": image,
            "id": inspect.stdout.strip(),
            "tools": {},
            "error": "Docker tool probe timed out",
        }
    except OSError as exc:
        return {
            "available": True,
            "image": image,
            "id": inspect.stdout.strip(),
            "tools": {},
            "error": str(exc),
        }
    tools: dict[str, dict[str, object]] = {}
    for line in (probe.stdout or "").splitlines():
        name, _, state = line.partition(":")
        if name:
            tools[name] = {"available": state.strip() == "ok"}
    return {
        "available": probe.returncode == 0,
        "image": image,
        "id": inspect.stdout.strip(),
        "tools": tools,
        "error": (probe.stderr or "").strip(),
    }


def _audit_verify(args: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="ravage audit verify")
    parser.add_argument("path", type=Path)
    parsed = parser.parse_args(args)

    db_path = _require_audit_db(parser, parsed.path)
    try:
        with closing(AuditStore(db_path)) as audit:
            ok, row_id = audit.verify()
            rows = audit.count_rows()
    except (OSError, sqlite3.Error, ValueError) as exc:
        parser.error(f"could not verify audit database {db_path}: {_concise_cli_error(exc)}")

    if ok:
        _write_line(f"audit verify OK rows={rows} db={db_path}")
        return

    _write_line(f"audit verify FAILED row_id={row_id} rows={rows} db={db_path}")
    raise SystemExit(1)


def _audit_db_path(path: Path) -> Path:
    if path.is_dir():
        return path / "audit.db"
    return path


def _require_audit_db(parser: argparse.ArgumentParser, path: Path) -> Path:
    if not path.exists():
        parser.error(
            f"run path or audit database does not exist: {path}; "
            "pass an existing RUN_DIR or audit.db"
        )
    db_path = _audit_db_path(path)
    if not db_path.is_file():
        parser.error(
            f"audit database not found: {db_path}; "
            "pass a run directory containing audit.db or the database file itself"
        )
    error = _audit_db_schema_error(db_path)
    if error:
        parser.error(f"invalid Ravage audit database {db_path}: {error}")
    return db_path


def _audit_db_schema_error(path: Path) -> str:
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'audit_log'
                LIMIT 1
                """
            ).fetchone()
    except (OSError, sqlite3.Error, ValueError) as exc:
        return _concise_cli_error(exc)
    if row is None:
        return "required audit_log table is missing"
    return ""


def _dashboard(args: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="ravage dashboard")
    parser.add_argument("--workspace-dir", type=Path, required=True)
    parser.add_argument("--db-path", type=Path)
    parser.add_argument("--stdout-path", type=Path)
    parser.add_argument("--docker-log-path", type=Path)
    parser.add_argument("--lab-manifest", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--json", action="store_true", help="print dashboard state and exit")
    parsed = parser.parse_args(args)

    settings = DashboardSettings(
        workspace_dir=parsed.workspace_dir,
        db_path=parsed.db_path,
        stdout_path=parsed.stdout_path,
        docker_log_path=parsed.docker_log_path,
        lab_manifest_path=parsed.lab_manifest,
    )
    if parsed.json:
        _write_line(
            json.dumps(build_dashboard_state(settings), indent=2, sort_keys=True, default=str)
        )
        return
    serve_dashboard(settings, host=parsed.host, port=parsed.port)


def _observe(args: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="ravage observe")
    parser.add_argument(
        "run_dir",
        type=Path,
        help=(
            "A single run directory, or a run root (e.g. runs/xben) to follow "
            "the currently active case and drop into replay when it finishes."
        ),
    )
    parser.add_argument("--lab-manifest", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--json", action="store_true", help="print dashboard state and exit")
    parsed = parser.parse_args(args)

    _require_ravage_run(parser, parsed.run_dir, allow_run_root=True)
    if parsed.lab_manifest is not None and not parsed.lab_manifest.is_file():
        parser.error(f"lab manifest does not exist or is not a file: {parsed.lab_manifest}")
    settings = _observe_settings(parsed.run_dir, lab_manifest_path=parsed.lab_manifest)
    try:
        if parsed.json:
            _write_line(
                json.dumps(
                    build_dashboard_state(settings),
                    indent=2,
                    sort_keys=True,
                    default=str,
                )
            )
            return
        serve_dashboard(settings, host=parsed.host, port=parsed.port)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(f"could not observe {parsed.run_dir}: {_concise_cli_error(exc)}")


def _report(args: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="ravage report")
    parser.add_argument(
        "run_dir",
        type=Path,
        help="run directory containing workspace/, or a workspace directory itself",
    )
    parser.add_argument("--brief", type=Path, required=True)
    parser.add_argument("--target-url")
    parser.add_argument(
        "--output",
        "--report-path",
        dest="output",
        type=Path,
        help="report output path; core supports .md/.json; .pdf/.docx require Ravage Pro",
    )
    parser.add_argument("--status", default="completed")
    parsed = parser.parse_args(args)

    _require_ravage_run(parser, parsed.run_dir)
    workspace_dir = _workspace_from_report_arg(parsed.run_dir)
    run_dir = workspace_dir.parent if workspace_dir.name == "workspace" else parsed.run_dir
    _load_engagement_brief_for_cli(parser, parsed.brief)
    manifest = read_manifest(run_dir)
    output_path = parsed.output or run_dir / "report.md"
    _validate_report_output(parser, output_path)
    try:
        report = write_pentest_report(
            brief_path=parsed.brief,
            target_url=parsed.target_url or (manifest.target_url if manifest else ""),
            workspace_dir=workspace_dir,
            output_path=output_path,
            status=parsed.status,
            completed=parsed.status == "completed",
            audit_db_path=run_dir / "audit.db",
        )
    except (OSError, sqlite3.Error, TypeError, ValueError, yaml.YAMLError) as exc:
        parser.error(f"could not generate report: {_concise_cli_error(exc)}")
    raw_artifacts = report.get("artifacts")
    artifacts = raw_artifacts if isinstance(raw_artifacts, dict) else {}
    _write_line(f"report written {artifacts.get('markdown_report_path') or output_path}")


def _validate_report_output(parser: argparse.ArgumentParser, output_path: Path) -> None:
    try:
        ensure_report_output_supported(output_path)
    except (ProFeatureRequiredError, ValueError) as exc:
        parser.error(str(exc))


def _workspace_from_report_arg(run_dir: Path) -> Path:
    if (run_dir / "workspace").is_dir():
        return run_dir / "workspace"
    return run_dir


_RUN_WORKSPACE_MARKERS = (
    "events.jsonl",
    "transcript.jsonl",
    "working_state.json",
    "scan-summary.json",
)


def _require_ravage_run(
    parser: argparse.ArgumentParser,
    path: Path,
    *,
    allow_run_root: bool = False,
) -> None:
    if not path.exists():
        parser.error(f"run path does not exist: {path}; pass an existing Ravage RUN_DIR")
    if not path.is_dir():
        parser.error(f"run path is not a directory: {path}")

    if _valid_run_directory(parser, path):
        return

    if not allow_run_root:
        parser.error(
            f"no Ravage run artifacts found in {path}; expected run.json, "
            "workspace/events.jsonl, or audit.db"
        )

    try:
        child_manifests = tuple(path.glob(f"*/{MANIFEST_NAME}"))
    except OSError as exc:
        parser.error(f"could not inspect run path {path}: {_concise_cli_error(exc)}")
    for manifest_path in child_manifests:
        if manifest_path.is_file() and read_manifest(manifest_path.parent) is not None:
            return
    parser.error(
        f"no Ravage run artifacts found in {path}; expected run.json, "
        "workspace/events.jsonl, or audit.db"
    )


def _valid_run_directory(parser: argparse.ArgumentParser, path: Path) -> bool:
    run_dir = path
    if not (run_dir / MANIFEST_NAME).exists() and path.name == "workspace":
        run_dir = path.parent
    manifest_path = run_dir / MANIFEST_NAME
    if manifest_path.exists():
        if not manifest_path.is_file() or read_manifest(run_dir) is None:
            parser.error(f"invalid Ravage run manifest: {manifest_path}")
        return True

    workspace = path / "workspace" if (path / "workspace").is_dir() else path
    if any((workspace / marker).is_file() for marker in _RUN_WORKSPACE_MARKERS):
        return True
    if (workspace / "terminal").is_dir() or (workspace / "traffic").is_dir():
        return True

    audit_path = run_dir / "audit.db"
    if not audit_path.is_file():
        return False
    error = _audit_db_schema_error(audit_path)
    if error:
        parser.error(f"invalid Ravage audit database {audit_path}: {error}")
    return True


def _observe_settings(run_dir: Path, *, lab_manifest_path: Path | None) -> DashboardSettings:
    is_single_run = (
        (run_dir / MANIFEST_NAME).exists()
        or (run_dir / "workspace").exists()
        or (run_dir / "events.jsonl").exists()
    )
    if is_single_run:
        return settings_from_run_dir(run_dir, lab_manifest_path=lab_manifest_path)
    # A run root: follow whichever case is currently active.
    return DashboardSettings(
        workspace_dir=run_dir,
        run_root=run_dir,
        lab_manifest_path=lab_manifest_path,
    )


def _write_line(value: str) -> None:
    sys.stdout.write(value + "\n")


if __name__ == "__main__":
    main()
