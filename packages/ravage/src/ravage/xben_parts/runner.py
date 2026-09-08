from __future__ import annotations

import hashlib
import json
import platform
import secrets
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from ravage.agent_core.frontier_runtime_handoff import (
    cleanup_autonomous_runtime_sessions,
)
from ravage.agent_knowledge import describe_knowledge_pack
from ravage.live_dashboard import (
    CockpitServer,
    DashboardSettings,
    start_cockpit,
)
from ravage.model_core.providers import (
    ResolvedModelRoute,
    load_model_registry,
    ready_model_routes,
    resolve_model_routes,
    route_is_nonbillable_local,
)
from ravage.outcome_evidence import load_run_outcome
from ravage.run_data.run_manifest import (
    STATUS_AGENT_RUNNING,
    STATUS_FINISHED,
    STATUS_STARTING_TARGET,
    STATUS_TORN_DOWN,
    RunManifest,
    update_manifest,
    write_manifest,
)
from ravage.runtime.scoped_network import cleanup_scoped_network_session
from ravage.xben_parts.agent import _run_agent_subprocess
from ravage.xben_parts.cases import (
    _case_setup_issue_payloads,
    _hint_policy_for_mode,
    _metadata_issues_for_mode,
    _mode_includes_source,
    _write_case_brief,
    load_xben_cases,
    selected_xben_cases,
)
from ravage.xben_parts.docker_ops import (
    XbenEvidenceCaptureError,
    _build_case,
    _collect_docker_logs,
    _compose_file_for_case,
    _down_case,
    _published_ports_for_case,
    _restart_case_web_service,
    _target_url_for,
    _up_case,
    _wait_for_target,
)
from ravage.xben_parts.logs import (
    _case_solution_route,
    _count_case_events,
    _count_case_model_routes,
    _existing_to_result,
    _find_flag,
    _model_usage,
    _operator_case_log_path,
    _read_existing_results,
    _should_skip_existing,
    _write_clean_case_log,
    _write_report,
)
from ravage.xben_parts.models import (
    METADATA_ISSUE_DISPLAY_LIMIT,
    PREFLIGHT_CASE_SAMPLE_LIMIT,
    CaseStatus,
    XbenCase,
    XbenCaseResult,
    XbenPreflight,
    XbenSettings,
)
from ravage.xben_parts.route_stage_policy import agent_stage_timeout_policy
from ravage.xben_parts.target_startup_policy import (
    should_restart_web_service_after_readiness_error,
)
from ravage.xben_parts.util import (
    _architecture_warning,
    _estimate_cost_usd,
    _line,
    _print_startup,
    _route_to_json,
    _run_id,
)

if TYPE_CHECKING:
    from typing import TextIO

_ALLOWED_XBEN_MODES = {"black-box", "white-box", "source-aware"}
_GIB = 1024**3
_ALLOWED_COMPARISON_PROFILES = {"none", "mapta-awe-xben"}
_MAPTA_AWE_CASE_TIMEOUT_SECONDS = 600
_CANONICAL_XBEN_IDS = tuple(f"XBEN-{index:03d}-24" for index in range(1, 105))
_TOOL_NETWORK_POLICY = "target-only-v1"
_DOCKER_IMAGE_INVENTORY_COMMAND = ("docker", "image", "ls", "--quiet", "--no-trunc")
_DOCKER_PREFLIGHT_TIMEOUT_SECONDS = 30
_DOCKER_PREFLIGHT_ERROR_LIMIT = 500


@dataclass(frozen=True)
class _CasePaths:
    case_dir: Path
    db_path: Path
    workspace_path: Path
    stdout_path: Path
    docker_log_path: Path


@dataclass(frozen=True)
class _CaseRunIdentity:
    project: str
    flag: str


@dataclass(frozen=True)
class _CaseExecutionOutcome:
    target_url: str | None
    found_flag: str | None
    status: CaseStatus
    solved: bool
    error: str | None


@dataclass(frozen=True)
class _KeptTarget:
    case: XbenCase
    identity: _CaseRunIdentity
    case_dir: Path


def _maybe_start_cockpit(*, settings: XbenSettings, stdout: TextIO) -> CockpitServer | None:
    if not settings.cockpit:
        return None
    dashboard = DashboardSettings(
        workspace_dir=settings.output_dir,
        run_root=settings.output_dir,
    )
    cockpit = start_cockpit(
        dashboard,
        host=settings.cockpit_host,
        port=settings.cockpit_port,
    )
    _line(stdout, "xben:cockpit", f"live console at {cockpit.url} (Ctrl-C to close and tear down)")
    return cockpit


def _await_cockpit_close(*, cockpit: CockpitServer, stdout: TextIO) -> None:
    _line(stdout, "xben:cockpit", f"run finished; target kept alive at {cockpit.url}")
    _line(stdout, "xben:cockpit", "press Ctrl-C to tear the target down and exit")
    try:
        cockpit.wait_forever()
    except KeyboardInterrupt:
        _line(stdout, "xben:cockpit", "closing cockpit and tearing down target")
    finally:
        cockpit.shutdown()


def _teardown_kept(*, settings: XbenSettings, kept: _KeptTarget | None) -> None:
    if kept is None:
        return
    _down_case(settings=settings, case=kept.case, project=kept.identity.project)
    update_manifest(
        kept.case_dir,
        status=STATUS_TORN_DOWN,
        target_alive=False,
        teardown_at=datetime.now(UTC).isoformat(),
    )


def _selection_payload(settings: XbenSettings, cases: Sequence[XbenCase]) -> dict[str, object]:
    case_payloads: list[dict[str, object]] = []
    for case in cases:
        case_payloads.append(case.to_json())
    return {
        "benchmark": "xbow-validation-benchmarks",
        "mode": settings.mode,
        "comparison_profile": settings.comparison_profile,
        "recovery_profile": settings.recovery_profile,
        "autonomous_route": settings.autonomous_route,
        "autonomous_route_engine": settings.autonomous_route_engine,
        "autonomous_route_max_requests": settings.autonomous_route_max_requests,
        "hint_policy": _hint_policy_for_mode(settings.mode),
        "benchmarks_root": str(settings.benchmarks_root),
        "selected_cases": len(cases),
        "cases": case_payloads,
    }


def run_xben(settings: XbenSettings, *, stdout: TextIO = sys.stdout) -> dict[str, object]:
    settings = _pin_xben_knowledge_pack(settings)
    _validate_settings(settings)
    selected_cases = selected_xben_cases(settings)
    _print_startup(stdout, settings=settings, selected_cases=selected_cases)
    if settings.dry_run or settings.list_cases:
        payload = _selection_payload(settings, selected_cases)
        settings.output_dir.mkdir(parents=True, exist_ok=True)
        path = settings.output_dir / "selection.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _line(stdout, "xben:selection", f"cases={len(selected_cases)} path={path}")
        for case in selected_cases:
            _line(
                stdout,
                "xben:case",
                f"id={case.benchmark_id} level={case.level}",
            )
        return payload

    _assert_xben_resume_knowledge_pack_contract(
        settings,
        settings.output_dir / "report.json",
    )
    preflight = preflight_xben(settings, selected_cases=selected_cases)
    preflight.write()
    _line(
        stdout,
        "xben:preflight",
        f"blocked={str(preflight.blocked).lower()} report={preflight.report_path}",
    )
    if settings.preflight:
        return preflight.payload
    if preflight.blocked:
        reasons = "; ".join(preflight.block_reasons)
        message = f"xben preflight blocked: {reasons}; preflight={preflight.report_path}"
        raise ValueError(message)

    settings.output_dir.mkdir(parents=True, exist_ok=True)
    _line(stdout, "xben:operator-log-root", f"path={settings.operator_log_root}")
    existing = _read_existing_results(settings.output_dir / "report.json")
    results: list[XbenCaseResult] = []
    _write_report(settings=settings, results=results, selected_cases=selected_cases)
    run_id = _run_id(settings.output_dir)
    cockpit = _maybe_start_cockpit(settings=settings, stdout=stdout)
    kept: _KeptTarget | None = None
    termination_reason: str | None = None
    interruption: KeyboardInterrupt | None = None
    for case in selected_cases:
        existing_result = existing.get(case.benchmark_id)
        if existing_result is not None and _should_skip_existing(existing_result, settings):
            result = _existing_to_result(existing_result)
            results.append(result)
            _line(stdout, "xben:case", f"id={case.benchmark_id} status=skipped solved=true")
            _write_clean_case_log(result)
            _write_report(settings=settings, results=results, selected_cases=selected_cases)
            continue
        remaining_cost_usd = _remaining_cost_budget(settings=settings, results=results)
        if remaining_cost_usd is not None and remaining_cost_usd <= 0:
            termination_reason = "cost_cap_exhausted"
            _line(
                stdout,
                "xben:budget",
                f"cost cap reached at ${settings.max_cost_usd:.6f}; remaining cases not started",
            )
            break
        disk_payload = _disk_preflight_payload(settings)
        free_gib = cast("float", disk_payload["free_gib"])
        if free_gib < settings.min_free_gib:
            termination_reason = "disk_floor_reached"
            _line(
                stdout,
                "xben:disk",
                (
                    f"free disk {free_gib} GiB below required "
                    f"{settings.min_free_gib} GiB; remaining cases not started"
                ),
            )
            break
        # Only one kept target stays live at a time so batch runs do not leak
        # containers; the cockpit follows whichever case is currently active.
        _teardown_kept(settings=settings, kept=kept)
        kept = None
        try:
            result = run_xben_case(
                settings=settings,
                case=case,
                run_id=run_id,
                stdout=stdout,
                cost_limit_usd=remaining_cost_usd,
            )
        except KeyboardInterrupt as exc:
            interruption = exc
            termination_reason = "keyboard_interrupt"
            _line(stdout, "xben:interrupted", f"id={case.benchmark_id} cleanup=attempted")
            break
        except Exception as exc:  # noqa: BLE001 - fatal lifecycle errors abort the matrix.
            termination_reason = "fatal_runner_error"
            _write_fatal_run_error(settings=settings, case=case, error=exc)
            _line(stdout, "xben:fatal", f"id={case.benchmark_id} {exc}")
            break
        results.append(result)
        _write_report(settings=settings, results=results, selected_cases=selected_cases)
        if result.unmatched_model_attempts:
            termination_reason = "unaccounted_model_attempt"
            _line(
                stdout,
                "xben:budget",
                (
                    f"id={case.benchmark_id} unmatched paid model attempt; "
                    "matrix stopped with exact cost unknown"
                ),
            )
            break
        if settings.keep_target:
            kept = _KeptTarget(
                case=case,
                identity=_case_run_identity(case=case, run_id=run_id),
                case_dir=settings.output_dir / case.benchmark_id,
            )

    if cockpit is not None and interruption is None:
        _await_cockpit_close(cockpit=cockpit, stdout=stdout)
    elif cockpit is not None:
        cockpit.shutdown()
    _teardown_kept(settings=settings, kept=kept)

    if termination_reason is None:
        termination_reason = "completed"
    report = _write_report(
        settings=settings,
        results=results,
        selected_cases=selected_cases,
        finalized=True,
        termination_reason=termination_reason,
    )
    summary = cast("Mapping[str, object]", report["summary"])
    _line(
        stdout,
        "xben:summary",
        (
            f"solved={summary['solved']}/{summary['total']} "
            f"errored={summary['errored']} timeout={summary['timeout']} "
            f"quota_error={summary.get('quota_error', 0)} "
            f"report={settings.output_dir / 'report.json'}"
        ),
    )
    if interruption is not None:
        raise interruption
    if report.get("run_status") != "complete":
        message = (
            "XBEN run incomplete: "
            f"completed={summary['completed']} total={summary['total']} "
            f"reason={termination_reason}; report={settings.output_dir / 'report.json'}"
        )
        raise RuntimeError(message)
    return report


def preflight_xben(  # noqa: C901
    settings: XbenSettings,
    *,
    selected_cases: Sequence[XbenCase] | None = None,
) -> XbenPreflight:
    settings = _pin_xben_knowledge_pack(settings)
    _validate_settings(settings)
    cases = _preflight_cases(settings, selected_cases)
    block_reasons: list[str] = []
    disk_payload = _disk_preflight_payload(settings)
    if float(disk_payload["free_gib"]) < settings.min_free_gib:
        block_reasons.append(
            f"free disk {disk_payload['free_gib']} GiB below required {settings.min_free_gib} GiB"
        )
    docker_image_inventory = _docker_image_inventory_health()
    if not bool(docker_image_inventory["healthy"]):
        block_reasons.append(
            f"Docker image inventory health check failed: {docker_image_inventory['error']}"
        )
    source_provenance = {
        "ravage": _git_source_state(Path.cwd()),
        "benchmarks": _git_source_state(settings.benchmarks_root),
    }
    tool_image_provenance: dict[str, object] | None = None
    if settings.tool_runtime == "docker" and bool(docker_image_inventory["healthy"]):
        tool_image_provenance = _docker_image_provenance(settings.tool_image)
    if tool_image_provenance is not None and not bool(tool_image_provenance["available"]):
        block_reasons.append(f"Docker tool image is unavailable: {settings.tool_image}")
    if settings.require_clean_source:
        for label, state in source_provenance.items():
            if not bool(state.get("available")):
                block_reasons.append(f"{label} source is not a readable Git worktree")
            elif bool(state.get("dirty")):
                block_reasons.append(f"{label} source worktree is dirty")
    if not settings.benchmarks_root.exists():
        block_reasons.append(f"benchmarks root not found: {settings.benchmarks_root}")
    if settings.concurrency != 1:
        block_reasons.append("concurrency > 1 is not implemented yet")
    if not cases:
        block_reasons.append("no benchmark cases selected")
    knowledge_pack_payload: dict[str, object] | None = None
    try:
        knowledge_pack_payload = _knowledge_pack_preflight_payload(settings)
    except (FileNotFoundError, ValueError) as exc:
        block_reasons.append(str(exc))
    metadata_issues = _metadata_issues_for_mode(settings, cases)
    if metadata_issues:
        shown = "; ".join(metadata_issues[:METADATA_ISSUE_DISPLAY_LIMIT])
        suffix = _hidden_metadata_issue_suffix(metadata_issues)
        block_reasons.append(f"invalid metadata for {settings.mode} cases: {shown}{suffix}")
    comparison_payload = _comparison_profile_payload(settings=settings, cases=cases)
    comparison_issues = cast("Sequence[str]", comparison_payload["issues"])
    if comparison_issues:
        block_reasons.append(
            "comparison profile "
            f"{settings.comparison_profile} mismatch: {'; '.join(comparison_issues)}"
        )
    missing_compose = _cases_missing_compose(cases)
    if missing_compose:
        shown = ", ".join(missing_compose[:PREFLIGHT_CASE_SAMPLE_LIMIT])
        if len(missing_compose) > PREFLIGHT_CASE_SAMPLE_LIMIT:
            shown += f", ... ({len(missing_compose)} total)"
        if not settings.allow_degraded:
            block_reasons.append(f"missing docker compose file for selected cases: {shown}")

    registry = load_model_registry(settings.model_config)
    routes = resolve_model_routes(
        registry,
        profile_name=settings.model_profile,
        tier=settings.model_tier,
    )
    ready_routes = ready_model_routes(routes)
    missing_env = _missing_route_env_names(routes)
    if not ready_routes:
        block_reasons.append(f"no ready model routes; missing env: {', '.join(missing_env)}")
    priced_routes = _routes_for_cost_and_risk(ready_routes=ready_routes, routes=routes)
    paid_risk = _has_paid_model_risk(priced_routes)
    if paid_risk and not settings.allow_paid_models:
        block_reasons.append("paid-risk model route selected; pass --allow-paid-models")

    strict_model_request_ceiling = len(cases) * settings.max_model_requests_per_case
    route_model_request_ceiling = (
        len(cases) * settings.autonomous_route_max_requests if settings.autonomous_route else 0
    )
    stage_timeout_policy = agent_stage_timeout_policy(settings)
    model_request_ceiling = strict_model_request_ceiling + route_model_request_ceiling
    input_ceiling = model_request_ceiling * settings.input_token_ceiling_per_model_call
    output_ceiling = _output_token_ceiling(
        routes=priced_routes[:1],
        model_request_ceiling=model_request_ceiling,
    )
    estimated_cost = _estimate_cost_usd(
        routes=priced_routes[:1],
        input_tokens=input_ceiling,
        output_tokens=output_ceiling,
    )
    cost_warnings: list[str] = []
    cost_cap_enforceable = _routes_have_complete_pricing(priced_routes[:1])
    if paid_risk and settings.max_cost_usd is not None and not cost_cap_enforceable:
        block_reasons.append(
            "paid model cost cap cannot be enforced because route pricing is incomplete"
        )
    if (
        settings.max_cost_usd is not None
        and estimated_cost is not None
        and estimated_cost > settings.max_cost_usd
    ):
        cost_warnings.append(
            f"policy estimate ${estimated_cost:.4f} exceeds runtime cap "
            f"${settings.max_cost_usd:.4f}; execution will stop at the cap"
        )

    payload: dict[str, object] = {
        "captured_at": datetime.now(UTC).isoformat(),
        "command_argv": list(sys.argv),
        "benchmark": "xbow-validation-benchmarks",
        "mode": settings.mode,
        "comparison_profile": comparison_payload,
        "hint_policy": _hint_policy_for_mode(settings.mode),
        "agent_mode": settings.agent_mode,
        "recovery_profile": settings.recovery_profile,
        "autonomous_route": settings.autonomous_route,
        "autonomous_route_engine": settings.autonomous_route_engine,
        "autonomous_route_max_requests": settings.autonomous_route_max_requests,
        "benchmarks_root": str(settings.benchmarks_root),
        "output_dir": str(settings.output_dir),
        "selected_cases": len(cases),
        "total_available_cases": _total_available_cases(settings),
        "blocked": bool(block_reasons),
        "block_reasons": block_reasons,
        "allow_paid_models": settings.allow_paid_models,
        "allow_degraded": settings.allow_degraded,
        "paid_risk": paid_risk,
        "model_profile": settings.model_profile,
        "model_tier": settings.model_tier,
        "model_request_ceiling": model_request_ceiling,
        "strict_model_request_ceiling": strict_model_request_ceiling,
        "autonomous_route_model_request_ceiling": route_model_request_ceiling,
        "agent_stage_timeouts": stage_timeout_policy.to_json(),
        "input_token_ceiling": input_ceiling,
        "input_token_policy_estimate": input_ceiling,
        "output_token_ceiling": output_ceiling,
        "estimated_cost_usd": estimated_cost,
        "max_cost_usd": settings.max_cost_usd,
        "disk": disk_payload,
        "min_free_gib": settings.min_free_gib,
        "docker_image_inventory": docker_image_inventory,
        "require_clean_source": settings.require_clean_source,
        "source_provenance": source_provenance,
        "model_config": _model_config_provenance(settings.model_config),
        "operator_log_root": str(settings.operator_log_root),
        "cost_cap_enforceable": cost_cap_enforceable,
        "cost_warnings": cost_warnings,
        "docker_platform": settings.docker_platform,
        "tool_runtime": settings.tool_runtime,
        "tool_network_policy": _TOOL_NETWORK_POLICY,
        "tool_image": settings.tool_image,
        "tool_image_provenance": tool_image_provenance,
        "knowledge_pack": knowledge_pack_payload,
        "memory_mode": settings.memory_mode,
        "memory_db_path": _optional_path_text(settings.memory_db_path),
        "proof_bundle_verifier": settings.proof_bundle_verifier,
        "require_proof_bundle_findings": settings.require_proof_bundle_findings,
        "proof_bundle_auto_enforced": False,
        "host_architecture": platform.machine(),
        "architecture_warning": _architecture_warning(settings),
        "setup_issues": _case_setup_issue_payloads(cases),
        "routes": _routes_payload(routes),
        "cases": _cases_payload(cases),
    }
    return XbenPreflight(
        report_path=settings.output_dir / "preflight.json",
        blocked=bool(block_reasons),
        block_reasons=tuple(block_reasons),
        payload=payload,
    )


def run_xben_case(
    *,
    settings: XbenSettings,
    case: XbenCase,
    run_id: str,
    stdout: TextIO,
    cost_limit_usd: float | None = None,
) -> XbenCaseResult:
    paths = _case_paths(settings=settings, case=case)
    paths.case_dir.mkdir(parents=True, exist_ok=True)
    _clear_previous_case_outputs(paths)
    identity = _case_run_identity(case=case, run_id=run_id)
    _write_created_manifest(settings=settings, case=case, identity=identity, paths=paths)
    started = time.monotonic()
    try:
        outcome = _run_case_lifecycle(
            settings=settings,
            case=case,
            identity=identity,
            paths=paths,
            stdout=stdout,
            cost_limit_usd=cost_limit_usd,
        )
        result = _case_result(
            settings=settings,
            case=case,
            identity=identity,
            paths=paths,
            outcome=outcome,
            started=started,
        )
        update_manifest(
            paths.case_dir,
            status=STATUS_FINISHED if settings.keep_target else STATUS_TORN_DOWN,
            phase=outcome.status,
            target_alive=settings.keep_target,
            flag_found=outcome.solved,
            result_label=outcome.status,
        )
        _write_clean_case_log(result)
        _emit_case_result(stdout=stdout, result=result)
    except KeyboardInterrupt as exc:
        _finalize_interrupted_case(
            settings=settings,
            case=case,
            identity=identity,
            paths=paths,
            interruption=exc,
        )
        raise
    else:
        return result


def _write_created_manifest(
    *,
    settings: XbenSettings,
    case: XbenCase,
    identity: _CaseRunIdentity,
    paths: _CasePaths,
) -> None:
    write_manifest(
        paths.case_dir,
        RunManifest(
            run_id=case.benchmark_id,
            benchmark_id=case.benchmark_id,
            docker_project=identity.project,
            keep_target=settings.keep_target,
            ttl_seconds=settings.target_ttl_seconds,
            max_turns=settings.max_turns,
            workspace_dir=str(paths.workspace_path),
            db_path=str(paths.db_path),
            docker_log_path=str(paths.docker_log_path),
            stdout_path=str(paths.stdout_path),
            lab_manifest_path=str(case.path / "benchmark.yaml"),
        ),
    )


def _case_paths(*, settings: XbenSettings, case: XbenCase) -> _CasePaths:
    case_dir = settings.output_dir / case.benchmark_id
    return _CasePaths(
        case_dir=case_dir,
        db_path=case_dir / "audit.db",
        workspace_path=case_dir / "workspace",
        stdout_path=case_dir / "agent.stdout",
        docker_log_path=case_dir / "docker.log",
    )


def _case_run_identity(*, case: XbenCase, run_id: str) -> _CaseRunIdentity:
    project = f"ravage-{case.benchmark_id.lower()}-{run_id}".replace("_", "-")
    # The proof value must not be derivable from agent-visible run names, paths,
    # timestamps, or case identifiers. It is retained only by the parent runner,
    # injected into the target during its build, and written to results after the
    # agent has exited.
    flag = f"flag{{ravage_{secrets.token_hex(32)}}}"
    return _CaseRunIdentity(project=project, flag=flag)


def _clear_previous_case_outputs(paths: _CasePaths) -> None:
    for path in (paths.db_path, paths.stdout_path, paths.docker_log_path):
        if path.exists():
            path.unlink()
    if paths.workspace_path.exists():
        shutil.rmtree(paths.workspace_path)


def _run_case_lifecycle(
    *,
    settings: XbenSettings,
    case: XbenCase,
    identity: _CaseRunIdentity,
    paths: _CasePaths,
    stdout: TextIO,
    cost_limit_usd: float | None,
) -> _CaseExecutionOutcome:
    target_url: str | None = None
    interrupted = False
    try:
        update_manifest(paths.case_dir, status=STATUS_STARTING_TARGET, phase=STATUS_STARTING_TARGET)
        target_url = _start_case_target(
            settings=settings,
            case=case,
            identity=identity,
            stdout=stdout,
        )
        update_manifest(
            paths.case_dir,
            status=STATUS_AGENT_RUNNING,
            phase=STATUS_AGENT_RUNNING,
            target_url=target_url,
            target_ready_at=datetime.now(UTC).isoformat(),
        )
        _line(
            stdout,
            "xben:agent",
            f"id={case.benchmark_id} status=running log={paths.stdout_path}",
        )
        try:
            found_flag = _run_agent_and_find_flag(
                settings=settings,
                case=case,
                identity=identity,
                paths=paths,
                target_url=target_url,
                cost_limit_usd=cost_limit_usd,
                stdout=stdout,
            )
        except Exception:
            _line(stdout, "xben:agent", f"id={case.benchmark_id} status=failed")
            raise
        else:
            _line(
                stdout,
                "xben:agent",
                (
                    f"id={case.benchmark_id} status=complete "
                    f"solved={str(found_flag is not None).lower()}"
                ),
            )
        solved = found_flag is not None
        return _CaseExecutionOutcome(
            target_url=target_url,
            found_flag=found_flag,
            status=_status_from_solved(solved),
            solved=solved,
            error=None,
        )
    except KeyboardInterrupt:
        interrupted = True
        raise
    except XbenEvidenceCaptureError:
        # Missing image identity makes the referee record unauditable. Abort the
        # matrix instead of classifying it as an ordinary case error.
        raise
    except Exception as exc:  # noqa: BLE001 - benchmark errors become case rows.
        return _failed_case_outcome(exc, target_url=target_url, stdout_path=paths.stdout_path)
    finally:
        if not interrupted:
            _line(stdout, "xben:teardown", f"id={case.benchmark_id} status=running")
            try:
                _teardown_case(settings=settings, case=case, identity=identity, paths=paths)
            except Exception:
                _line(stdout, "xben:teardown", f"id={case.benchmark_id} status=failed")
                raise
            else:
                teardown_status = "target-kept" if settings.keep_target else "complete"
                _line(
                    stdout,
                    "xben:teardown",
                    f"id={case.benchmark_id} status={teardown_status}",
                )


def _finalize_interrupted_case(
    *,
    settings: XbenSettings,
    case: XbenCase,
    identity: _CaseRunIdentity,
    paths: _CasePaths,
    interruption: KeyboardInterrupt,
) -> None:
    teardown_succeeded, cleanup_errors = _attempt_interrupted_case_teardown(
        settings=settings,
        case=case,
        identity=identity,
        paths=paths,
    )
    finished_at = datetime.now(UTC).isoformat()
    try:
        update_manifest(
            paths.case_dir,
            status=STATUS_TORN_DOWN if teardown_succeeded else STATUS_FINISHED,
            phase="interrupted",
            target_alive=not teardown_succeeded,
            flag_found=False,
            result_label="interrupted",
            finished_at=finished_at,
            teardown_at=finished_at if teardown_succeeded else "",
        )
    except Exception as exc:  # noqa: BLE001 - preserve the operator interrupt.
        cleanup_errors = (*cleanup_errors, exc)
    for error in cleanup_errors:
        detail = str(error).strip() or type(error).__name__
        interruption.add_note(
            f"XBEN interruption cleanup warning ({type(error).__name__}): {detail}"
        )


def _attempt_interrupted_case_teardown(
    *,
    settings: XbenSettings,
    case: XbenCase,
    identity: _CaseRunIdentity,
    paths: _CasePaths,
) -> tuple[bool, tuple[BaseException, ...]]:
    errors: list[BaseException] = []
    try:
        _collect_docker_logs(
            settings=settings,
            case=case,
            project=identity.project,
            path=paths.docker_log_path,
        )
    except BaseException as exc:  # noqa: BLE001 - cleanup must survive a second interrupt.
        errors.append(exc)
    try:
        _down_case(settings=settings, case=case, project=identity.project)
    except BaseException as exc:  # noqa: BLE001 - preserve the primary operator interrupt.
        errors.append(exc)
        return False, tuple(errors)
    return True, tuple(errors)


def _start_case_target(
    *,
    settings: XbenSettings,
    case: XbenCase,
    identity: _CaseRunIdentity,
    stdout: TextIO,
) -> str:
    _line(stdout, "xben:case", f"id={case.benchmark_id} status=starting")
    _line(stdout, "xben:build", f"id={case.benchmark_id} status=running")
    _build_case(settings=settings, case=case, project=identity.project, flag=identity.flag)
    _line(stdout, "xben:build", f"id={case.benchmark_id} status=complete")
    _line(stdout, "xben:target", f"id={case.benchmark_id} status=starting")
    _up_case(settings=settings, case=case, project=identity.project)
    target_url = _target_url_for(settings=settings, case=case, project=identity.project)
    _line(
        stdout,
        "xben:target",
        f"id={case.benchmark_id} status=waiting url={target_url}",
    )
    try:
        _wait_for_target(settings=settings, target_url=target_url)
    except RuntimeError as exc:
        if not should_restart_web_service_after_readiness_error(exc):
            raise
        _line(stdout, "xben:target", f"id={case.benchmark_id} status=restarting")
        _restart_case_web_service(settings=settings, case=case, project=identity.project)
        target_url = _target_url_for(settings=settings, case=case, project=identity.project)
        _wait_for_target(settings=settings, target_url=target_url)
    _line(
        stdout,
        "xben:target",
        f"id={case.benchmark_id} status=ready url={target_url}",
    )
    return target_url


def _run_agent_and_find_flag(
    *,
    settings: XbenSettings,
    case: XbenCase,
    identity: _CaseRunIdentity,
    paths: _CasePaths,
    target_url: str,
    cost_limit_usd: float | None,
    stdout: TextIO | None = None,
) -> str | None:
    tool_network_session_id = str(uuid4())
    tool_network_evidence_path = paths.case_dir / "tool-network.json"
    published_ports = _published_ports_for_case(
        settings=settings,
        case=case,
        project=identity.project,
    )
    brief_path = _write_case_brief(
        case_dir=paths.case_dir,
        case=case,
        target_url=target_url,
        settings=settings,
        published_ports=published_ports,
        cost_limit_usd=cost_limit_usd,
        engagement_id=tool_network_session_id,
    )
    with paths.stdout_path.open("w", encoding="utf-8") as case_stdout:
        try:
            _run_agent_subprocess(
                settings=settings,
                brief_path=brief_path,
                target_url=target_url,
                db_path=paths.db_path,
                workspace_path=paths.workspace_path,
                stdout=case_stdout,
                source_root=(case.path if _mode_includes_source(settings.mode) else None),
                live_stdout=(stdout if settings.stream_agent_output else None),
                tool_network_evidence_path=(
                    tool_network_evidence_path if settings.tool_runtime == "docker" else None
                ),
            )
        finally:
            if settings.tool_runtime == "docker":
                try:
                    if settings.autonomous_route:
                        network_evidence = cleanup_autonomous_runtime_sessions(
                            tool_network_session_id,
                            evidence_path=tool_network_evidence_path,
                        )
                    else:
                        network_evidence = cleanup_scoped_network_session(
                            tool_network_session_id,
                            evidence_path=tool_network_evidence_path,
                        )
                except Exception as exc:
                    message = f"Docker tool isolation cleanup evidence failed: {exc}"
                    raise XbenEvidenceCaptureError(message) from exc
                _require_scoped_tool_network_evidence(network_evidence)
                if settings.autonomous_route:
                    _require_autonomous_runtime_cleanup(network_evidence)
    return _find_flag(
        flag=identity.flag,
        db_path=paths.db_path,
        workspace_path=paths.workspace_path,
        stdout_path=paths.stdout_path,
        flag_mode=settings.flag_mode,
    )


def _require_scoped_tool_network_evidence(evidence: Mapping[str, object]) -> None:
    setup = evidence.get("setup")
    cleanup = evidence.get("cleanup")
    setup_payload = setup if isinstance(setup, Mapping) else {}
    cleanup_payload = cleanup if isinstance(cleanup, Mapping) else {}
    if setup_payload.get("status") != "succeeded":
        detail = str(setup_payload.get("error") or "setup evidence missing")
        raise XbenEvidenceCaptureError(f"Docker tool isolation setup was not proven: {detail}")
    if cleanup_payload.get("status") != "verified" or cleanup_payload.get("verified") is not True:
        errors = cleanup_payload.get("errors")
        detail = str(errors or "cleanup evidence missing")
        raise XbenEvidenceCaptureError(f"Docker tool isolation cleanup was not verified: {detail}")


def _require_autonomous_runtime_cleanup(evidence: Mapping[str, object]) -> None:
    cleanup = evidence.get("autonomous_route_cleanup")
    payload = cleanup if isinstance(cleanup, Mapping) else {}
    if payload.get("status") == "verified" and payload.get("verified") is True:
        return
    sessions = payload.get("sessions")
    detail = str(sessions or "autonomous runtime cleanup evidence missing")
    message = f"autonomous runtime cleanup was not verified: {detail}"
    raise XbenEvidenceCaptureError(message)


def _failed_case_outcome(
    exc: Exception,
    *,
    target_url: str | None,
    stdout_path: Path | None = None,
) -> _CaseExecutionOutcome:
    status = _status_for_exception(exc, stdout_path=stdout_path)
    return _CaseExecutionOutcome(
        target_url=target_url,
        found_flag=None,
        status=status,
        solved=False,
        error=_error_message_for_exception(exc, stdout_path=stdout_path),
    )


def _status_for_exception(exc: Exception, *, stdout_path: Path | None = None) -> CaseStatus:
    if isinstance(exc, subprocess.TimeoutExpired):
        return "timeout"
    if _looks_like_model_quota_error(str(exc) + "\n" + _stdout_error_context(stdout_path)):
        return "quota_error"
    return "errored"


def _error_message_for_exception(exc: Exception, *, stdout_path: Path | None = None) -> str:
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"timeout after {exc.timeout}s"
    context = _stdout_error_context(stdout_path)
    if _looks_like_model_quota_error(str(exc) + "\n" + context):
        return "model quota exhausted or rate limited: " + _quota_error_summary(context or str(exc))
    return str(exc)


def _stdout_error_context(path: Path | None) -> str:
    if path is None or not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    excerpt_chars = 4000
    if len(text) <= excerpt_chars * 2:
        return text
    return (
        text[:excerpt_chars] + "\n...[buffered stdout middle omitted]...\n" + text[-excerpt_chars:]
    )


def _looks_like_model_quota_error(text: str) -> bool:
    lowered = text.lower()
    return (
        "insufficient_quota" in lowered
        or "exceeded your current quota" in lowered
        or ("http error 429" in lowered and "openai" in lowered)
        or ("model http 429" in lowered and "quota" in lowered)
    )


def _quota_error_summary(text: str) -> str:
    compact = " ".join(text.split())
    if "insufficient_quota" in compact:
        return "insufficient_quota"
    if "HTTP Error 429" in compact:
        return "HTTP Error 429"
    return compact[:240] or "quota/rate limit"


def _teardown_case(
    *,
    settings: XbenSettings,
    case: XbenCase,
    identity: _CaseRunIdentity,
    paths: _CasePaths,
) -> None:
    _collect_docker_logs(
        settings=settings,
        case=case,
        project=identity.project,
        path=paths.docker_log_path,
    )
    if settings.keep_target:
        # Leave the target Docker project running so the cockpit iframe stays
        # live. The dashboard's TTL reaper / teardown button owns shutdown.
        return
    _down_case(settings=settings, case=case, project=identity.project)


def _case_result(
    *,
    settings: XbenSettings,
    case: XbenCase,
    identity: _CaseRunIdentity,
    paths: _CasePaths,
    outcome: _CaseExecutionOutcome,
    started: float,
) -> XbenCaseResult:
    event_counts = _count_case_events(
        paths.db_path,
        workspace_path=paths.workspace_path,
    )
    base_model_request_count, route_model_request_count = _count_case_model_routes(paths.db_path)
    usage = _model_usage(paths.db_path)
    route_cost_known = _selected_route_cost_is_known(settings)
    cost_known = route_cost_known and bool(usage["cost_accounting_complete"])
    known_reply_cost_usd = float(usage["cost_usd"])
    unmatched_model_attempts = int(usage["unmatched_attempts"])
    per_unmatched_charge_usd = _configured_per_request_budget_estimate_usd(settings)
    budget_charge_usd = _case_budget_charge_usd(
        known_reply_cost_usd=known_reply_cost_usd,
        unmatched_model_attempts=unmatched_model_attempts,
        per_unmatched_charge_usd=per_unmatched_charge_usd,
    )
    run_outcome = load_run_outcome(
        db_path=paths.db_path,
        workspace_path=paths.workspace_path,
        expected_flag=identity.flag,
    )
    return XbenCaseResult(
        benchmark_id=case.benchmark_id,
        name=case.name,
        level=case.level,
        target_url=outcome.target_url,
        flag=identity.flag,
        found_flag=outcome.found_flag,
        status=outcome.status,
        solved=outcome.solved,
        elapsed_seconds=time.monotonic() - started,
        model_request_count=event_counts.model_request_count,
        http_request_count=event_counts.http_request_count,
        db_path=paths.db_path,
        workspace_path=paths.workspace_path,
        transcript_path=paths.workspace_path / "transcript.jsonl",
        events_path=paths.workspace_path / "events.jsonl",
        artifacts_path=paths.workspace_path / "artifacts",
        stdout_path=paths.stdout_path,
        clean_log_path=_operator_case_log_path(settings, case.benchmark_id),
        docker_log_path=paths.docker_log_path,
        error=outcome.error,
        http_request_count_status=event_counts.http_request_count_status,
        http_request_count_provenance=event_counts.http_request_count_provenance,
        http_unmetered_action_count=event_counts.http_unmetered_action_count,
        http_incomplete_request_count=event_counts.http_incomplete_request_count,
        tool_action_count=event_counts.tool_action_count,
        base_model_request_count=base_model_request_count,
        autonomous_route_model_request_count=route_model_request_count,
        solution_route=_case_solution_route(paths.db_path, solved=outcome.solved),
        input_tokens=int(usage["input_tokens"]),
        cached_input_tokens=int(usage["cached_input_tokens"]),
        output_tokens=int(usage["output_tokens"]),
        cost_usd=known_reply_cost_usd if cost_known else None,
        cost_status="known" if cost_known else "unknown",
        cost_provenance=("referee_computed_from_provider_usage" if cost_known else None),
        known_reply_cost_usd=known_reply_cost_usd,
        unmatched_model_attempts=unmatched_model_attempts,
        budget_charge_per_unmatched_attempt_usd=per_unmatched_charge_usd,
        budget_charge_usd=budget_charge_usd,
        budget_charge_status=(
            "estimated"
            if budget_charge_usd is not None and unmatched_model_attempts
            else "known"
            if budget_charge_usd is not None
            else "unknown"
        ),
        budget_charge_provenance=(
            "known_reply_cost_plus_policy_input_estimate"
            if budget_charge_usd is not None and unmatched_model_attempts
            else "known_reply_cost"
            if budget_charge_usd is not None
            else None
        ),
        response_models=cast("tuple[str, ...]", usage["response_models"]),
        system_fingerprints=cast("tuple[str, ...]", usage["system_fingerprints"]),
        service_tiers=cast("tuple[str, ...]", usage["service_tiers"]),
        outcome_stage=run_outcome.stage.value,
        outcome_evidence_count=run_outcome.evidence_count,
        confirmed_finding_count=run_outcome.confirmed_finding_count,
        outcome_vulnerability_classes=run_outcome.vulnerability_classes,
    )


def _selected_route_cost_is_known(settings: XbenSettings) -> bool:
    route = _selected_ready_route(settings)
    if route is None:
        return False
    return (
        route.input_cost_per_1m_tokens is not None
        and route.cached_input_cost_per_1m_tokens is not None
        and route.output_cost_per_1m_tokens is not None
    )


def _selected_ready_route(settings: XbenSettings) -> ResolvedModelRoute | None:
    registry = load_model_registry(settings.model_config)
    routes = ready_model_routes(
        resolve_model_routes(
            registry,
            profile_name=settings.model_profile,
            tier=settings.model_tier,
        )
    )
    if not routes:
        return None
    return routes[0]


def _configured_per_request_budget_estimate_usd(
    settings: XbenSettings,
) -> float | None:
    route = _selected_ready_route(settings)
    if route is None:
        return None
    input_rate = route.input_cost_per_1m_tokens
    output_rate = route.output_cost_per_1m_tokens
    if input_rate is None or output_rate is None:
        return None
    cached_rate = route.cached_input_cost_per_1m_tokens
    conservative_input_rate = max(input_rate, cached_rate or input_rate)
    input_charge = settings.input_token_ceiling_per_model_call / 1_000_000 * conservative_input_rate
    output_charge = route.max_output_tokens / 1_000_000 * output_rate
    return float(input_charge + output_charge)


def _case_budget_charge_usd(
    *,
    known_reply_cost_usd: float,
    unmatched_model_attempts: int,
    per_unmatched_charge_usd: float | None,
) -> float | None:
    if unmatched_model_attempts <= 0:
        return known_reply_cost_usd
    if per_unmatched_charge_usd is None:
        return None
    return known_reply_cost_usd + unmatched_model_attempts * per_unmatched_charge_usd


def _remaining_cost_budget(
    *,
    settings: XbenSettings,
    results: Sequence[XbenCaseResult],
) -> float | None:
    if settings.max_cost_usd is None:
        return None
    charges = [result.budget_charge_usd for result in results]
    if any(charge is None for charge in charges):
        message = "cannot enforce XBEN cost cap because a budget charge is unknown"
        raise RuntimeError(message)
    spent = sum(float(charge) for charge in charges if charge is not None)
    return max(round(settings.max_cost_usd - spent, 6), 0.0)


def _emit_case_result(*, stdout: TextIO, result: XbenCaseResult) -> None:
    _line(
        stdout,
        "xben:case",
        (
            f"id={result.benchmark_id} status={result.status} "
            f"solved={str(result.solved).lower()} outcome={result.outcome_stage} "
            f"http_requests={result.http_request_count} "
            f"http_count_status={result.http_request_count_status} "
            f"seconds={result.elapsed_seconds:.1f}"
        ),
    )
    if result.error:
        _line(stdout, "xben:error", f"id={result.benchmark_id} {result.error}")


def _preflight_cases(
    settings: XbenSettings,
    selected_cases: Sequence[XbenCase] | None,
) -> tuple[XbenCase, ...]:
    if selected_cases is not None:
        return tuple(selected_cases)
    return selected_xben_cases(settings)


def _write_fatal_run_error(
    *,
    settings: XbenSettings,
    case: XbenCase,
    error: Exception,
) -> Path:
    path = settings.output_dir / case.benchmark_id / "fatal-run-error.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "benchmark_id": case.benchmark_id,
        "error_type": type(error).__name__,
        "error": str(error),
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


def _validate_settings(settings: XbenSettings) -> None:
    if settings.min_free_gib < 0:
        msg = "min_free_gib must be non-negative"
        raise ValueError(msg)
    if settings.autonomous_route and settings.autonomous_route_max_requests <= 0:
        msg = "autonomous_route_max_requests must be positive"
        raise ValueError(msg)
    if settings.autonomous_route_engine not in {"frontier", "agent-graph"}:
        msg = "autonomous_route_engine must be frontier or agent-graph"
        raise ValueError(msg)
    if settings.mode not in _ALLOWED_XBEN_MODES:
        allowed = ", ".join(sorted(_ALLOWED_XBEN_MODES))
        msg = f"unsupported XBEN mode {settings.mode!r}; use one of: {allowed}"
        raise ValueError(msg)
    if settings.comparison_profile not in _ALLOWED_COMPARISON_PROFILES:
        allowed = ", ".join(sorted(_ALLOWED_COMPARISON_PROFILES))
        msg = (
            f"unsupported XBEN comparison profile {settings.comparison_profile!r}; "
            f"use one of: {allowed}"
        )
        raise ValueError(msg)


def _disk_preflight_payload(settings: XbenSettings) -> dict[str, object]:
    probe = settings.output_dir.expanduser().resolve()
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    return {
        "path": str(probe),
        "free_gib": round(usage.free / _GIB, 3),
        "total_gib": round(usage.total / _GIB, 3),
    }


def _git_source_state(path: Path) -> dict[str, object]:
    root = _git_text(path, "rev-parse", "--show-toplevel")
    if root is None:
        return {"available": False, "path": str(path.expanduser().resolve())}
    root_path = Path(root)
    status_text = _git_text(root_path, "status", "--porcelain=v1")
    status = [] if status_text is None else [line for line in status_text.splitlines() if line]
    return {
        "available": True,
        "root": str(root_path),
        "commit": _git_text(root_path, "rev-parse", "HEAD"),
        "tree": _git_text(root_path, "rev-parse", "HEAD^{tree}"),
        "dirty": bool(status),
        "status_porcelain": status,
    }


def _git_text(path: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _model_config_provenance(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        return {"path": str(resolved), "sha256": None}
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return {"path": str(resolved), "sha256": digest}


def _docker_image_inventory_health() -> dict[str, object]:
    command = list(_DOCKER_IMAGE_INVENTORY_COMMAND)
    try:
        completed = subprocess.run(  # noqa: S603 - fixed read-only Docker command.
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=_DOCKER_PREFLIGHT_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return {
            "healthy": False,
            "command": command,
            "failure_kind": "command_not_found",
            "error": "docker command was not found",
        }
    except subprocess.TimeoutExpired:
        return {
            "healthy": False,
            "command": command,
            "failure_kind": "timeout",
            "error": (
                "docker image inventory command timed out after "
                f"{_DOCKER_PREFLIGHT_TIMEOUT_SECONDS} seconds"
            ),
        }
    except OSError as exc:
        return {
            "healthy": False,
            "command": command,
            "failure_kind": "execution_error",
            "error": _bounded_preflight_error(f"could not run docker image inventory: {exc}"),
        }
    if completed.returncode != 0:
        output = completed.stderr.strip() or completed.stdout.strip()
        detail = f"docker image inventory command exited with status {completed.returncode}"
        if output:
            detail = f"{detail}: {output}"
        return {
            "healthy": False,
            "command": command,
            "failure_kind": "command_failed",
            "exit_code": completed.returncode,
            "error": _bounded_preflight_error(detail),
        }
    image_ids = {line.strip() for line in completed.stdout.splitlines() if line.strip()}
    return {
        "healthy": True,
        "command": command,
        "failure_kind": None,
        "exit_code": completed.returncode,
        "image_count": len(image_ids),
        "error": None,
    }


def _bounded_preflight_error(value: str) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= _DOCKER_PREFLIGHT_ERROR_LIMIT:
        return normalized
    return normalized[: _DOCKER_PREFLIGHT_ERROR_LIMIT - 3] + "..."


def _docker_image_provenance(image: str) -> dict[str, object]:
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", image],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "reference": image, "error": str(exc)}
    if completed.returncode != 0:
        return {
            "available": False,
            "reference": image,
            "error": completed.stderr.strip() or completed.stdout.strip(),
        }
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return {"available": False, "reference": image, "error": str(exc)}
    if not isinstance(raw, list) or not raw or not isinstance(raw[0], dict):
        return {"available": False, "reference": image, "error": "invalid inspect payload"}
    payload = raw[0]
    root_fs = payload.get("RootFS")
    layers = root_fs.get("Layers") if isinstance(root_fs, dict) else []
    return {
        "available": True,
        "reference": image,
        "id": payload.get("Id"),
        "repo_digests": payload.get("RepoDigests") or [],
        "created": payload.get("Created"),
        "architecture": payload.get("Architecture"),
        "os": payload.get("Os"),
        "size": payload.get("Size"),
        "rootfs_layers": layers if isinstance(layers, list) else [],
    }


def _comparison_profile_payload(
    *,
    settings: XbenSettings,
    cases: Sequence[XbenCase],
) -> dict[str, object]:
    if settings.comparison_profile == "none":
        return {
            "name": "none",
            "comparable": False,
            "enforced": False,
            "issues": [],
        }
    issues = _mapta_awe_profile_issues(settings=settings, cases=cases)
    return {
        "name": settings.comparison_profile,
        "comparable": not issues,
        "enforced": True,
        "issues": issues,
        "required": {
            "case_ids": list(_CANONICAL_XBEN_IDS),
            "mode": "black-box",
            "agent_mode": "ctf-free-roam",
            "case_timeout_seconds": _MAPTA_AWE_CASE_TIMEOUT_SECONDS,
            "objective": "capture_flag",
            "max_turns": 40,
            "max_model_requests_per_case": 40,
            "autonomous_route": False,
            "flag_mode": "exact",
            "tool_runtime": "docker",
            "tool_network_policy": _TOOL_NETWORK_POLICY,
            "visible_to_agent": ["target_url", "description", "rules", "win_condition"],
            "withheld_from_agent": [
                "benchmark tags",
                "vulnerability classifications",
                "case name/id",
                "level",
                "source",
                "database schema",
                "logs",
                "internal config",
                "memory hints",
            ],
        },
    }


def _mapta_awe_profile_issues(
    *,
    settings: XbenSettings,
    cases: Sequence[XbenCase],
) -> list[str]:
    issues: list[str] = []
    hint_policy = _hint_policy_for_mode(settings.mode)
    selected_ids = tuple(case.benchmark_id for case in cases)
    if not settings.all_cases:
        issues.append("--all must be set")
    if settings.ids or settings.exclude_ids or settings.case_range or settings.levels:
        issues.append("case filters and exclusions must be empty")
    if settings.sample is not None or settings.sample_seed is not None:
        issues.append("sampling must be disabled")
    if selected_ids != _CANONICAL_XBEN_IDS:
        missing = sorted(set(_CANONICAL_XBEN_IDS) - set(selected_ids))
        extra = sorted(set(selected_ids) - set(_CANONICAL_XBEN_IDS))
        issues.append(
            "selected cases must be exactly canonical XBEN-001-24..XBEN-104-24 "
            f"in order; missing={missing} extra={extra}"
        )
    if settings.resume or settings.retry_failed:
        issues.append("resume and retry_failed must be disabled")
    if settings.output_dir.exists():
        issues.append("output_dir must not exist before the frozen run")
    if settings.cockpit or settings.keep_target:
        issues.append("cockpit and keep_target must be disabled")
    if not settings.prune_case_images:
        issues.append("prune_case_images must be enabled for the frozen full run")
    if settings.knowledge_pack_path is not None:
        issues.append("knowledge packs must be disabled")
    if settings.allow_degraded:
        issues.append("allow_degraded must be false")
    if not settings.require_clean_source:
        issues.append("require_clean_source must be enabled")
    if settings.flag_mode != "exact":
        issues.append("flag_mode must be exact")
    if settings.concurrency != 1:
        issues.append("concurrency must be 1")
    if settings.tool_runtime != "docker":
        issues.append("tool_runtime must be docker-isolated")
    if not _immutable_image_reference(settings.tool_image):
        issues.append("tool_image must be pinned by sha256 digest or image ID")
    if not _path_is_within(settings.operator_log_root, settings.output_dir):
        issues.append("operator_log_root must be inside output_dir")
    if settings.max_turns != 40:
        issues.append("max_turns must be 40")
    if settings.max_model_requests_per_case != 40:
        issues.append("max_model_requests_per_case must be 40")
    if settings.autonomous_route:
        issues.append("autonomous_route must be disabled for the strict 40-request comparison")
    if settings.mode != "black-box":
        issues.append("mode must be black-box")
    if settings.agent_mode != "ctf-free-roam":
        issues.append("agent_mode must be ctf-free-roam")
    if settings.case_timeout_seconds != _MAPTA_AWE_CASE_TIMEOUT_SECONDS:
        issues.append(
            "case_timeout_seconds must be "
            f"{_MAPTA_AWE_CASE_TIMEOUT_SECONDS} for the MAPTA/AWE 10-minute budget"
        )
    if hint_policy.get("source_available") is not False:
        issues.append("source_available must be false")
    if hint_policy.get("description_visible") is not True:
        issues.append("description_visible must be true")
    if hint_policy.get("metadata_assisted") is not False:
        issues.append("metadata_assisted must be false")
    if hint_policy.get("source_aware") is not False:
        issues.append("source_aware must be false")
    if settings.memory_mode is not None or settings.memory_db_path is not None:
        issues.append("memory hints must be disabled")
    missing_descriptions = [case.benchmark_id for case in cases if not case.description.strip()]
    if missing_descriptions:
        shown = ", ".join(missing_descriptions[:PREFLIGHT_CASE_SAMPLE_LIMIT])
        if len(missing_descriptions) > PREFLIGHT_CASE_SAMPLE_LIMIT:
            shown += f", ... ({len(missing_descriptions)} total)"
        issues.append(f"all selected cases must have benchmark descriptions: {shown}")
    return issues


def _immutable_image_reference(image: str) -> bool:
    text = image.strip().lower()
    return text.startswith("sha256:") or "@sha256:" in text


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(root.expanduser().resolve())
    except ValueError:
        return False
    return True


def _hidden_metadata_issue_suffix(metadata_issues: Sequence[str]) -> str:
    if len(metadata_issues) <= METADATA_ISSUE_DISPLAY_LIMIT:
        return ""
    hidden_count = len(metadata_issues) - METADATA_ISSUE_DISPLAY_LIMIT
    return f"; +{hidden_count} more"


def _cases_missing_compose(cases: Sequence[XbenCase]) -> list[str]:
    missing: list[str] = []
    for case in cases:
        if _compose_file_for_case(case.path) is None:
            missing.append(case.benchmark_id)
    return missing


def _missing_route_env_names(routes: Sequence[ResolvedModelRoute]) -> list[str]:
    names: set[str] = set()
    for route in routes:
        for env_name in route.missing_env:
            names.add(env_name)
    return sorted(names)


def _routes_for_cost_and_risk(
    *,
    ready_routes: Sequence[ResolvedModelRoute],
    routes: Sequence[ResolvedModelRoute],
) -> tuple[ResolvedModelRoute, ...]:
    if ready_routes:
        return tuple(ready_routes)
    return tuple(routes)


def _has_paid_model_risk(routes: Sequence[ResolvedModelRoute]) -> bool:
    for route in routes:
        if not route_is_nonbillable_local(route):
            return True
    return False


def _routes_have_complete_pricing(routes: Sequence[ResolvedModelRoute]) -> bool:
    if not routes:
        return False
    return all(
        route.input_cost_per_1m_tokens is not None
        and route.cached_input_cost_per_1m_tokens is not None
        and route.output_cost_per_1m_tokens is not None
        for route in routes
    )


def _output_token_ceiling(
    *,
    routes: Sequence[ResolvedModelRoute],
    model_request_ceiling: int,
) -> int:
    tokens_per_request = 0
    for route in routes:
        tokens_per_request += route.max_output_tokens
    return tokens_per_request * model_request_ceiling


def _total_available_cases(settings: XbenSettings) -> int:
    if not settings.benchmarks_root.exists():
        return 0
    return len(load_xben_cases(settings.benchmarks_root))


def _optional_path_text(path: Path | None) -> str | None:
    if path is None:
        return None
    return str(path)


def _knowledge_pack_preflight_payload(settings: XbenSettings) -> dict[str, object] | None:
    metadata = describe_knowledge_pack(
        settings.knowledge_pack_path,
        expected_sha256=settings.knowledge_pack_sha256,
    )
    if metadata is None:
        return None
    payload = metadata.to_json()
    payload["card_limit"] = settings.knowledge_pack_limit
    payload["max_chars"] = settings.knowledge_pack_max_chars
    return payload


def _pin_xben_knowledge_pack(settings: XbenSettings) -> XbenSettings:
    metadata = describe_knowledge_pack(
        settings.knowledge_pack_path,
        expected_sha256=settings.knowledge_pack_sha256,
    )
    digest = None if metadata is None else metadata.sha256
    if settings.knowledge_pack_sha256 == digest:
        return settings
    return replace(settings, knowledge_pack_sha256=digest)


def _assert_xben_resume_knowledge_pack_contract(
    settings: XbenSettings,
    report_path: Path,
) -> None:
    if not (settings.resume or settings.retry_failed) or not report_path.exists():
        return
    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("xben resume requires a readable existing report") from exc
    if not isinstance(raw, dict) or "knowledge_pack" not in raw:
        raise ValueError("xben resume report has no knowledge-pack run contract")
    existing = _reported_knowledge_pack_contract(raw.get("knowledge_pack"))
    current = _xben_knowledge_pack_contract(settings)
    if existing != current:
        raise ValueError(
            "xben resume/retry knowledge-pack contract does not match the existing report"
        )


def _xben_knowledge_pack_contract(settings: XbenSettings) -> dict[str, object]:
    metadata = describe_knowledge_pack(
        settings.knowledge_pack_path,
        expected_sha256=settings.knowledge_pack_sha256,
    )
    if metadata is None:
        return {"enabled": False}
    return {
        "enabled": True,
        "schema_version": metadata.schema_version,
        "sha256": metadata.sha256,
        "skill_count": metadata.skill_count,
        "card_limit": settings.knowledge_pack_limit,
        "max_chars": settings.knowledge_pack_max_chars,
    }


def _reported_knowledge_pack_contract(value: object) -> dict[str, object]:
    if value is None:
        return {"enabled": False}
    if not isinstance(value, Mapping):
        raise ValueError("xben resume report has an invalid knowledge-pack run contract")
    required = ("schema_version", "sha256", "skill_count", "card_limit", "max_chars")
    if any(key not in value for key in required):
        raise ValueError("xben resume report has an incomplete knowledge-pack run contract")
    return {
        "enabled": True,
        "schema_version": str(value["schema_version"]),
        "sha256": str(value["sha256"]),
        "skill_count": int(value["skill_count"]),
        "card_limit": int(value["card_limit"]),
        "max_chars": int(value["max_chars"]),
    }


def _routes_payload(routes: Sequence[ResolvedModelRoute]) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for route in routes:
        payload.append(_route_to_json(route))
    return payload


def _cases_payload(cases: Sequence[XbenCase]) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for case in cases:
        payload.append(case.to_json())
    return payload


def _status_from_solved(solved: bool) -> CaseStatus:
    if solved:
        return "solved"
    return "failed"
