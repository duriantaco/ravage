from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from dataclasses import replace
from io import StringIO
from pathlib import Path  # noqa: TC003 - pytest evaluates tmp_path annotations at runtime.
from types import SimpleNamespace
from typing import cast

import pytest
import yaml  # type: ignore[import-untyped]
from ravage.run_data.brief import load_engagement_brief
from ravage.traffic import (
    RequestIntent,
    TrafficDecisionKind,
    TrafficOutcome,
    TrafficPolicyConfig,
    TrafficPolicyController,
)
from ravage.xben_parts.agent import _run_agent_subprocess
from ravage.xben_parts.cases import (
    _read_metadata,
    _write_case_brief,
    load_xben_cases,
    selected_xben_cases,
)
from ravage.xben_parts.docker_ops import (
    XbenEvidenceCaptureError,
    _down_case,
    _patch_legacy_xben_dockerfiles,
    _source_file_hashes,
    _source_tree_sha256,
    _up_case,
    _write_build_source_provenance,
)
from ravage.xben_parts.logs import (
    _count_case_events,
    _existing_to_result,
    _find_flag,
    _is_scoreable_flag_candidate,
    _model_usage,
    _read_existing_results,
    _write_clean_case_log,
    _write_report,
)
from ravage.xben_parts.models import (
    XbenCase,
    XbenCaseResult,
    XbenPreflight,
    XbenSettings,
)
from ravage.xben_parts.runner import (
    _case_budget_charge_usd,
    _case_run_identity,
    _CasePaths,
    _CaseRunIdentity,
    _remaining_cost_budget,
    _require_autonomous_runtime_cleanup,
    _require_scoped_tool_network_evidence,
    _run_agent_and_find_flag,
    _start_case_target,
    _status_for_exception,
    preflight_xben,
    run_xben,
)
from ravage.xben_setup_parts.context import docker_build_context_issues

MODEL_REQUEST_CEILING = 2
AUTONOMOUS_ROUTE_REQUEST_CEILING = 3
ESTIMATED_COST_USD = 0.004296
LEGACY_PATCHED_FILE_COUNT = 2
MYSQL_ARM_PATCHED_FILE_COUNT = 2
PYMYSQL_REQUIREMENTS_PATCHED_FILE_COUNT = 1
URL_TIMEOUT_SECONDS = 3
WAIT_RETRY_CALL_COUNT = 2
SSH_TEST_HOST_PORT = 49_222
FLAG_SECRET_BYTES = 32
PHYSICAL_REQUEST_COUNT = 800
LEGACY_TOOL_ACTION_COUNT = 14
MODEL_REQUEST_COUNT = 2
INCOMPLETE_REQUEST_COUNT = 7


@pytest.fixture(autouse=True)
def _healthy_docker_image_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "ravage.xben_parts.runner._docker_image_inventory_health",
        lambda: {
            "healthy": True,
            "command": ["docker", "image", "ls", "--quiet", "--no-trunc"],
            "failure_kind": None,
            "exit_code": 0,
            "image_count": 0,
            "error": None,
        },
    )


def _write_case(
    root: Path,
    benchmark_id: str,
    *,
    level: int,
    tags: list[str],
    description: str = "Test challenge description.",
    with_compose: bool = True,
) -> None:
    case_dir = root / benchmark_id
    case_dir.mkdir(parents=True)
    case_dir.joinpath("benchmark.yaml").write_text(
        f"""
name: {benchmark_id} Test Case
level: {level}
tags:
{chr(10).join(f"- {tag}" for tag in tags)}
content:
  - kind: description
    content_type: text/markdown
    content: {description}
main-service: web
main-service-port: 80
""".lstrip(),
        encoding="utf-8",
    )
    if not with_compose:
        return
    case_dir.joinpath("docker-compose.yml").write_text(
        """
services:
  web:
    image: nginx
    ports:
      - "8080:80"
""".lstrip(),
        encoding="utf-8",
    )


def _write_build_case(root: Path, benchmark_id: str, *, missing_copy_source: bool) -> None:
    case_dir = root / benchmark_id
    app_dir = case_dir / "service"
    app_dir.mkdir(parents=True)
    case_dir.joinpath("benchmark.yaml").write_text(
        f"""
name: {benchmark_id} Build Case
level: 1
tags:
  - web
content:
  - kind: description
    content_type: text/markdown
    content: Test challenge description.
main-service: web
main-service-port: 80
""".lstrip(),
        encoding="utf-8",
    )
    case_dir.joinpath("docker-compose.yml").write_text(
        """
services:
  web:
    build: ./service
    ports:
      - "8080:80"
""".lstrip(),
        encoding="utf-8",
    )
    app_dir.joinpath("present.txt").write_text("ok", encoding="utf-8")
    if not missing_copy_source:
        app_dir.joinpath("requirements.txt").write_text("", encoding="utf-8")
    app_dir.joinpath("Dockerfile").write_text(
        """
FROM python:3.11-slim
COPY requirements.txt /app/requirements.txt
COPY --from=builder /wheelhouse /wheelhouse
COPY ["present.txt", "/app/present.txt"]
""".lstrip(),
        encoding="utf-8",
    )


def _allow_xben_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def unblocked_preflight(
        settings: XbenSettings,
        *,
        selected_cases: object = None,
    ) -> XbenPreflight:
        del selected_cases
        return XbenPreflight(
            report_path=settings.output_dir / "preflight.json",
            blocked=False,
            block_reasons=(),
            payload={"blocked": False},
        )

    monkeypatch.setattr("ravage.xben_parts.runner.preflight_xben", unblocked_preflight)


def _stub_case_result(
    *,
    case: XbenCase,
    output_dir: Path,
    unmatched_model_attempts: int = 0,
) -> XbenCaseResult:
    case_dir = output_dir / case.benchmark_id
    unmatched = unmatched_model_attempts > 0
    return XbenCaseResult(
        benchmark_id=case.benchmark_id,
        name=case.name,
        level=case.level,
        target_url="http://127.0.0.1:12345",
        flag="flag{target_secret}",
        found_flag=None,
        status="errored" if unmatched else "failed",
        solved=False,
        elapsed_seconds=1.0,
        model_request_count=1,
        http_request_count=0,
        db_path=case_dir / "audit.db",
        workspace_path=case_dir / "workspace",
        transcript_path=case_dir / "workspace" / "transcript.jsonl",
        events_path=case_dir / "workspace" / "events.jsonl",
        artifacts_path=case_dir / "workspace" / "artifacts",
        stdout_path=case_dir / "agent.stdout",
        clean_log_path=case_dir / "case.log",
        docker_log_path=case_dir / "docker.log",
        error="provider transport failed" if unmatched else None,
        cost_usd=None if unmatched else 0.01,
        cost_status="unknown" if unmatched else "known",
        cost_provenance=None if unmatched else "referee_computed_from_provider_usage",
        known_reply_cost_usd=0.01,
        unmatched_model_attempts=unmatched_model_attempts,
        budget_charge_per_unmatched_attempt_usd=0.15,
        budget_charge_usd=0.16 if unmatched else 0.01,
        budget_charge_status="estimated" if unmatched else "known",
        budget_charge_provenance=(
            "known_reply_cost_plus_policy_input_estimate" if unmatched else "known_reply_cost"
        ),
    )


def test_xben_uses_physical_traffic_ledger_not_tool_action_count(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE audit_log (action TEXT)")
        conn.executemany(
            "INSERT INTO audit_log (action) VALUES (?)",
            [("model_request_started",)] * MODEL_REQUEST_COUNT
            + [("tool_run_probe",)] * LEGACY_TOOL_ACTION_COUNT,
        )
    controller = TrafficPolicyController.open(
        workspace / "traffic-policy.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(),
    )
    ledger = json.loads(controller.state_path.read_text(encoding="utf-8"))
    ledger["physical_request_count"] = PHYSICAL_REQUEST_COUNT
    ledger["completed_request_count"] = PHYSICAL_REQUEST_COUNT - INCOMPLETE_REQUEST_COUNT
    ledger["incomplete_request_count"] = INCOMPLETE_REQUEST_COUNT
    controller.state_path.write_text(json.dumps(ledger), encoding="utf-8")

    counts = _count_case_events(db_path, workspace_path=workspace)

    assert counts.model_request_count == MODEL_REQUEST_COUNT
    assert counts.http_request_count == PHYSICAL_REQUEST_COUNT
    assert counts.http_request_count != LEGACY_TOOL_ACTION_COUNT
    assert counts.tool_action_count == LEGACY_TOOL_ACTION_COUNT
    assert counts.http_request_count_status == "exact"
    assert counts.http_request_count_provenance == "workspace_traffic_policy_ledger"
    assert counts.http_unmetered_action_count == 0
    assert counts.http_incomplete_request_count == INCOMPLETE_REQUEST_COUNT


def test_xben_marks_raw_network_lanes_as_lower_bound(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    controller = TrafficPolicyController.open(
        workspace / "traffic-policy.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(),
    )
    controller.record_unmetered_action()

    counts = _count_case_events(
        tmp_path / "missing-audit.db",
        workspace_path=workspace,
    )

    assert counts.http_request_count == 0
    assert counts.http_request_count_status == "lower_bound"
    assert counts.http_unmetered_action_count == 1
    assert counts.http_request_count_provenance == "workspace_traffic_policy_ledger"


def test_xben_marks_terminal_pending_dispatch_as_incomplete(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    controller = TrafficPolicyController.open(
        workspace / "traffic-policy.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(),
    )
    decision = controller.acquire(RequestIntent(method="GET", url="http://127.0.0.1/pending"))
    assert decision.kind is TrafficDecisionKind.DISPATCH
    assert decision.lease is not None
    controller.begin_dispatch(decision.lease)

    counts = _count_case_events(
        tmp_path / "missing-audit.db",
        workspace_path=workspace,
    )

    assert counts.http_request_count == 1
    assert counts.http_incomplete_request_count == 1
    assert counts.http_request_count_status == "exact"


def test_xben_missing_or_unreadable_ledger_never_relabels_tool_actions(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE audit_log (action TEXT)")
        conn.executemany(
            "INSERT INTO audit_log (action) VALUES (?)",
            [("tool_run_command",)] * LEGACY_TOOL_ACTION_COUNT,
        )

    counts = _count_case_events(db_path, workspace_path=workspace)

    assert counts.http_request_count == 0
    assert counts.http_request_count_status == "unavailable"
    assert counts.http_request_count_provenance == "traffic_policy_ledger_missing"
    assert counts.tool_action_count == LEGACY_TOOL_ACTION_COUNT

    controller = TrafficPolicyController.open(
        workspace / "traffic-policy.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(),
    )
    controller.state_path.write_text("{malformed", encoding="utf-8")
    unreadable = _count_case_events(db_path, workspace_path=workspace)
    assert unreadable.http_request_count == 0
    assert unreadable.http_request_count_status == "unavailable"
    assert unreadable.http_request_count_provenance == "traffic_policy_ledger_unreadable"
    assert unreadable.tool_action_count == LEGACY_TOOL_ACTION_COUNT


def test_xben_resume_reconciles_reported_accounting_with_durable_ledger(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db_path = tmp_path / "legacy-audit.db"
    with sqlite3.connect(db_path):
        pass
    controller = TrafficPolicyController.open(
        workspace / "traffic-policy.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(),
    )
    decision = controller.acquire(RequestIntent(method="GET", url="http://127.0.0.1/actual"))
    assert decision.kind is TrafficDecisionKind.DISPATCH
    assert decision.lease is not None
    controller.begin_dispatch(decision.lease)
    controller.complete(decision.lease, TrafficOutcome(status=200))

    result = _existing_to_result(
        {
            "benchmark_id": "XBEN-001-24",
            "status": "failed",
            "solved": False,
            "db_path": str(db_path),
            "workspace_path": str(workspace),
            "http_request_count": 999,
            "http_request_count_status": "exact",
            "http_request_count_provenance": "workspace_traffic_policy_ledger",
            "tool_action_count": 999,
        }
    )

    assert result.http_request_count == 1
    assert result.http_request_count_status == "exact"
    assert result.http_request_count_provenance == "workspace_traffic_policy_ledger"
    assert result.tool_action_count == 0


def test_xben_resume_downgrades_missing_modern_ledger(tmp_path: Path) -> None:
    result = _existing_to_result(
        {
            "benchmark_id": "XBEN-001-24",
            "status": "failed",
            "solved": False,
            "workspace_path": str(tmp_path / "missing-workspace"),
            "http_request_count": 999,
            "http_request_count_status": "exact",
            "http_request_count_provenance": "workspace_traffic_policy_ledger",
        }
    )

    assert result.http_request_count == 0
    assert result.http_request_count_status == "unavailable"
    assert result.http_request_count_provenance == "traffic_policy_ledger_missing"


def test_xben_selection_supports_range_and_level(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["xss"])
    _write_case(root, "XBEN-002-24", level=2, tags=["sqli"])
    _write_case(root, "XBEN-003-24", level=1, tags=["idor"])

    selected = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            case_range="1-3",
            levels=(1,),
        )
    )

    assert [case.benchmark_id for case in selected] == ["XBEN-001-24", "XBEN-003-24"]


def test_xben_case_identity_uses_unique_secret_not_run_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    case = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
        )
    )[0]
    token_chars = FLAG_SECRET_BYTES * 2
    tokens = iter(("a" * token_chars, "b" * token_chars))

    def token_hex(nbytes: int) -> str:
        assert nbytes == FLAG_SECRET_BYTES
        return next(tokens)

    monkeypatch.setattr("ravage.xben_parts.runner.secrets.token_hex", token_hex)
    run_id = "public_run_name_20260712013932"

    first = _case_run_identity(case=case, run_id=run_id)
    second = _case_run_identity(case=case, run_id=run_id)

    assert first.project == second.project
    assert first.flag == f"flag{{ravage_{'a' * token_chars}}}"
    assert second.flag == f"flag{{ravage_{'b' * token_chars}}}"
    assert first.flag != second.flag
    for identity in (first, second):
        assert run_id not in identity.flag
        assert case.benchmark_id.lower().replace("-", "_") not in identity.flag
        assert identity.flag not in identity.project


def test_parent_cleans_scoped_tool_network_when_agent_times_out(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    case = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
        )
    )[0]
    settings = XbenSettings(
        benchmarks_root=root,
        output_dir=tmp_path / "runs",
        tool_runtime="docker",
    )
    case_dir = settings.output_dir / case.benchmark_id
    case_dir.mkdir(parents=True)
    paths = _CasePaths(
        case_dir=case_dir,
        stdout_path=case_dir / "agent.stdout",
        db_path=case_dir / "audit.db",
        workspace_path=case_dir / "workspace",
        docker_log_path=case_dir / "docker.log",
    )
    identity = _CaseRunIdentity(project="project", flag="flag{expected}")
    cleanup_sessions: list[str] = []

    monkeypatch.setattr(
        "ravage.xben_parts.runner._published_ports_for_case",
        lambda **kwargs: (),
    )

    def write_brief(**kwargs: object) -> Path:
        path = case_dir / "brief.yaml"
        path.write_text("engagement_id: test\n", encoding="utf-8")
        return path

    monkeypatch.setattr("ravage.xben_parts.runner._write_case_brief", write_brief)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._run_agent_subprocess",
        lambda **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="ravage", timeout=600)
        ),
    )

    def cleanup(session_id: str, **kwargs: object) -> dict[str, object]:
        cleanup_sessions.append(session_id)
        return {
            "setup": {"status": "succeeded"},
            "cleanup": {"status": "verified", "verified": True},
        }

    monkeypatch.setattr(
        "ravage.xben_parts.runner.cleanup_scoped_network_session",
        cleanup,
    )

    with pytest.raises(subprocess.TimeoutExpired):
        _run_agent_and_find_flag(
            settings=settings,
            case=case,
            identity=identity,
            paths=paths,
            target_url="http://localhost:18080",
            cost_limit_usd=1.0,
        )

    assert len(cleanup_sessions) == 1

    monkeypatch.setattr(
        "ravage.xben_parts.runner.cleanup_scoped_network_session",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("evidence write failed")),
    )
    with pytest.raises(
        XbenEvidenceCaptureError,
        match="cleanup evidence failed: evidence write failed",
    ):
        _run_agent_and_find_flag(
            settings=settings,
            case=case,
            identity=identity,
            paths=paths,
            target_url="http://localhost:18080",
            cost_limit_usd=1.0,
        )


def test_parent_cleans_all_autonomous_runtime_generations_when_agent_times_out(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    case = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
        )
    )[0]
    settings = XbenSettings(
        benchmarks_root=root,
        output_dir=tmp_path / "runs",
        tool_runtime="docker",
        autonomous_route=True,
    )
    case_dir = settings.output_dir / case.benchmark_id
    case_dir.mkdir(parents=True)
    paths = _CasePaths(
        case_dir=case_dir,
        stdout_path=case_dir / "agent.stdout",
        db_path=case_dir / "audit.db",
        workspace_path=case_dir / "workspace",
        docker_log_path=case_dir / "docker.log",
    )
    identity = _CaseRunIdentity(project="project", flag="flag{expected}")
    engagement_ids: list[str] = []
    cleanup_calls: list[tuple[str, Path]] = []

    monkeypatch.setattr(
        "ravage.xben_parts.runner._published_ports_for_case",
        lambda **_kwargs: (),
    )

    def write_brief(**kwargs: object) -> Path:
        engagement_ids.append(str(kwargs["engagement_id"]))
        path = case_dir / "brief.yaml"
        path.write_text("engagement_id: test\n", encoding="utf-8")
        return path

    monkeypatch.setattr("ravage.xben_parts.runner._write_case_brief", write_brief)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._run_agent_subprocess",
        lambda **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="ravage", timeout=600)
        ),
    )

    def cleanup_all(
        engagement_id: str,
        *,
        evidence_path: str | Path,
    ) -> dict[str, object]:
        cleanup_calls.append((engagement_id, Path(evidence_path)))
        return {
            "setup": {"status": "succeeded"},
            "cleanup": {"status": "verified", "verified": True},
            "autonomous_route_cleanup": {
                "status": "verified",
                "verified": True,
            },
        }

    monkeypatch.setattr(
        "ravage.xben_parts.runner.cleanup_autonomous_runtime_sessions",
        cleanup_all,
    )
    monkeypatch.setattr(
        "ravage.xben_parts.runner.cleanup_scoped_network_session",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError((args, kwargs))),
    )

    with pytest.raises(subprocess.TimeoutExpired):
        _run_agent_and_find_flag(
            settings=settings,
            case=case,
            identity=identity,
            paths=paths,
            target_url="http://localhost:18080",
            cost_limit_usd=1.0,
        )

    assert cleanup_calls == [(engagement_ids[0], case_dir / "tool-network.json")]


def test_scoped_tool_network_evidence_fails_closed() -> None:
    with pytest.raises(XbenEvidenceCaptureError, match="setup was not proven"):
        _require_scoped_tool_network_evidence(
            {
                "setup": {"status": "error", "error": "network create failed"},
                "cleanup": {"status": "verified", "verified": True},
            }
        )

    with pytest.raises(XbenEvidenceCaptureError, match="autonomous runtime cleanup"):
        _require_autonomous_runtime_cleanup(
            {
                "autonomous_route_cleanup": {
                    "status": "error",
                    "verified": False,
                    "sessions": [{"session_id": "unclean-base"}],
                }
            }
        )

    with pytest.raises(XbenEvidenceCaptureError, match="cleanup was not verified"):
        _require_scoped_tool_network_evidence(
            {
                "setup": {"status": "succeeded"},
                "cleanup": {"status": "error", "verified": False},
            }
        )


def test_xben_records_post_patch_benchmark_tree_digest(tmp_path: Path) -> None:
    case_path = tmp_path / "benchmarks" / "XBEN-001-24"
    case_path.mkdir(parents=True)
    source = case_path / "Dockerfile"
    source.write_text("FROM python:3.12\n", encoding="utf-8")
    case = XbenCase(
        benchmark_id="XBEN-001-24",
        path=case_path,
        name="case",
        level=1,
        description="description",
        main_service="web",
        main_service_port=80,
    )
    settings = XbenSettings(output_dir=tmp_path / "run")

    before = _source_tree_sha256(case_path)
    before_files = _source_file_hashes(case_path)
    source.write_text("FROM python:3.13\n", encoding="utf-8")
    after_files = _source_file_hashes(case_path)
    provenance_path = _write_build_source_provenance(
        settings=settings,
        case=case,
        patched_files=1,
        pre_patch_tree_sha256=before,
        before_files=before_files,
        after_files=after_files,
    )
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))

    assert payload["compatibility_files_changed"] == 1
    assert payload["pre_patch_tree_sha256"] == before
    assert payload["post_patch_tree_sha256"] == _source_tree_sha256(case_path)
    assert payload["post_patch_tree_sha256"] != before
    assert payload["changed_files"] == [
        {
            "path": "Dockerfile",
            "change": "modified",
            "before_sha256": before_files["Dockerfile"],
            "after_sha256": after_files["Dockerfile"],
        }
    ]


def test_xben_teardown_can_remove_only_case_local_images(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    case = load_xben_cases(root)[0]
    commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("ravage.xben_parts.docker_ops.subprocess.run", run)

    output_dir = tmp_path / "run"
    _down_case(
        settings=XbenSettings(output_dir=output_dir, prune_case_images=True),
        case=case,
        project="ravage-case",
    )

    assert commands == [
        [
            "docker",
            "compose",
            "-p",
            "ravage-case",
            "down",
            "--remove-orphans",
            "-v",
            "--rmi",
            "local",
        ]
    ]
    teardown = json.loads(
        (output_dir / case.benchmark_id / "teardown.json").read_text(encoding="utf-8")
    )
    assert teardown["status"] == "succeeded"
    assert teardown["returncode"] == 0


def test_xben_up_wraps_any_image_provenance_failure_as_fatal_evidence_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    case = load_xben_cases(root)[0]
    monkeypatch.setattr("ravage.xben_parts.docker_ops._run_command", lambda *args, **kwargs: None)

    def fail_capture(**kwargs: object) -> None:
        del kwargs
        raise OSError("Docker inspect unavailable")

    monkeypatch.setattr(
        "ravage.xben_parts.docker_ops._record_compose_image_provenance",
        fail_capture,
    )

    with pytest.raises(XbenEvidenceCaptureError, match="could not capture Docker image provenance"):
        _up_case(
            settings=XbenSettings(output_dir=tmp_path / "run"),
            case=case,
            project="ravage-case",
        )


def test_xben_teardown_failure_writes_evidence_and_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    case = load_xben_cases(root)[0]
    output_dir = tmp_path / "run"

    monkeypatch.setattr(
        "ravage.xben_parts.docker_ops.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=17,
            stdout="",
            stderr="volume cleanup failed",
        ),
    )

    with pytest.raises(RuntimeError, match="Docker teardown failed.*volume cleanup failed"):
        _down_case(
            settings=XbenSettings(output_dir=output_dir),
            case=case,
            project="ravage-case",
        )

    teardown = json.loads(
        (output_dir / case.benchmark_id / "teardown.json").read_text(encoding="utf-8")
    )
    assert teardown["status"] == "error"
    assert teardown["returncode"] == 17
    assert teardown["stderr"] == "volume cleanup failed"


def test_xben_runner_classifies_model_quota_errors_from_agent_stdout(tmp_path: Path) -> None:
    stdout = tmp_path / "agent.stdout"
    stdout.write_text(
        """
urllib.error.HTTPError: HTTP Error 429: Too Many Requests
RuntimeError: model HTTP 429: {"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}
""".strip(),
        encoding="utf-8",
    )

    status = _status_for_exception(RuntimeError("agent exited with code 1"), stdout_path=stdout)

    assert status == "quota_error"


def test_xben_runner_finds_quota_traceback_before_long_buffered_stdout(
    tmp_path: Path,
) -> None:
    stdout = tmp_path / "agent.stdout"
    stdout.write_text(
        (
            'RuntimeError: model HTTP 429: {"code":"insufficient_quota"}\n'
            + "buffered turn output\n" * 1000
        ),
        encoding="utf-8",
    )

    status = _status_for_exception(
        RuntimeError("agent exited with code 1"),
        stdout_path=stdout,
    )

    assert status == "quota_error"


def test_xben_selection_supports_seeded_sample_and_excluded_ids(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    sample_size = 2
    for case_id in ("XBEN-001-24", "XBEN-002-24", "XBEN-003-24", "XBEN-004-24"):
        _write_case(root, case_id, level=1, tags=["web"])

    selected_once = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            exclude_ids=("XBEN-002-24",),
            sample=sample_size,
            sample_seed=1337,
        )
    )
    selected_twice = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            exclude_ids=("XBEN-002-24",),
            sample=sample_size,
            sample_seed=1337,
        )
    )

    assert [case.benchmark_id for case in selected_once] == [
        case.benchmark_id for case in selected_twice
    ]
    assert len(selected_once) == sample_size
    assert all(case.benchmark_id != "XBEN-002-24" for case in selected_once)


def test_xben_seeded_sample_excludes_cases_without_default_compose(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["web"])
    _write_case(root, "XBEN-002-24", level=1, tags=["web"], with_compose=False)
    _write_case(root, "XBEN-003-24", level=1, tags=["web"])

    selected = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            sample=3,
            sample_seed=1337,
        )
    )
    targeted = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-002-24",),
            sample=1,
            sample_seed=1337,
        )
    )

    assert [case.benchmark_id for case in selected] == ["XBEN-001-24", "XBEN-003-24"]
    assert [case.benchmark_id for case in targeted] == ["XBEN-002-24"]


def test_xben_seeded_sample_excludes_cases_with_missing_build_sources(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_build_case(root, "XBEN-001-24", missing_copy_source=False)
    _write_build_case(root, "XBEN-002-24", missing_copy_source=True)
    _write_build_case(root, "XBEN-003-24", missing_copy_source=False)

    selected = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            sample=3,
            sample_seed=1337,
        )
    )
    targeted = selected_xben_cases(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-002-24",),
            sample=1,
            sample_seed=1337,
        )
    )

    issues = docker_build_context_issues(root / "XBEN-002-24")

    assert [case.benchmark_id for case in selected] == ["XBEN-001-24", "XBEN-003-24"]
    assert [case.benchmark_id for case in targeted] == ["XBEN-002-24"]
    assert issues == ("missing COPY source in service: requirements.txt",)


def test_xben_preflight_reports_setup_issues_without_blocking_targeted_runs(
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_build_case(root, "XBEN-001-24", missing_copy_source=True)

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
        )
    )

    assert preflight.blocked is False
    assert preflight.payload["setup_issues"] == [
        {
            "benchmark_id": "XBEN-001-24",
            "issue_type": "docker_build_context",
            "issues": ["missing COPY source in service: requirements.txt"],
        }
    ]


def test_xben_preflight_blocks_black_box_with_missing_description(
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    case_dir = root / "XBEN-001-24"
    case_dir.mkdir(parents=True)
    case_dir.joinpath("docker-compose.yml").write_text(
        """
services:
  web:
    image: nginx
    ports:
      - "8080:80"
""".lstrip(),
        encoding="utf-8",
    )

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
            mode="black-box",
        )
    )

    assert preflight.blocked is True
    reason = next(
        reason
        for reason in preflight.block_reasons
        if "invalid metadata for black-box cases" in reason
    )
    assert "XBEN-001-24" in reason
    assert "missing metadata file" in reason
    assert "missing description" in reason
    assert "tags=[]" not in reason


def test_xben_preflight_allows_black_box_metadata_without_level(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    case_dir = root / "XBEN-001-24"
    case_dir.mkdir(parents=True)
    case_dir.joinpath("benchmark.json").write_text(
        json.dumps(
            {
                "name": "XBEN-001-24",
                "description": "Security benchmark challenge",
                "win_condition": "flag",
            }
        ),
        encoding="utf-8",
    )
    case_dir.joinpath("docker-compose.yml").write_text(
        """
services:
  web:
    image: nginx
    ports:
      - "8080:80"
""".lstrip(),
        encoding="utf-8",
    )

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
            mode="black-box",
        )
    )

    assert not any(
        "invalid metadata for black-box cases" in reason for reason in preflight.block_reasons
    )


def test_xben_preflight_enforces_mapta_awe_comparison_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    for index in range(1, 105):
        _write_case(root, f"XBEN-{index:03d}-24", level=1, tags=["idor"])
    monkeypatch.setattr(
        "ravage.xben_parts.runner._git_source_state",
        lambda path: {
            "available": True,
            "root": str(path),
            "commit": "a" * 40,
            "tree": "b" * 40,
            "dirty": False,
            "status_porcelain": [],
        },
    )
    monkeypatch.setattr(
        "ravage.xben_parts.runner._docker_image_provenance",
        lambda image: {
            "available": True,
            "reference": image,
            "id": image,
            "rootfs_layers": [],
        },
    )
    output_dir = tmp_path / "runs"

    settings = XbenSettings(
        benchmarks_root=root,
        output_dir=output_dir,
        all_cases=True,
        mode="black-box",
        comparison_profile="mapta-awe-xben",
        case_timeout_seconds=600,
        require_clean_source=True,
        tool_runtime="docker",
        tool_image="sha256:" + "c" * 64,
        prune_case_images=True,
        operator_log_root=output_dir / "operator-logs",
    )
    preflight = preflight_xben(settings)

    assert preflight.blocked is False
    profile = preflight.payload["comparison_profile"]
    assert isinstance(profile, dict)
    assert profile["name"] == "mapta-awe-xben"
    assert profile["comparable"] is True
    assert profile["enforced"] is True
    assert profile["issues"] == []

    output_dir.mkdir()
    stale = preflight_xben(settings)
    stale_profile = stale.payload["comparison_profile"]
    assert isinstance(stale_profile, dict)
    assert "output_dir must not exist before the frozen run" in stale_profile["issues"]


def test_xben_preflight_blocks_mapta_awe_profile_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            mode="white-box",
            comparison_profile="mapta-awe-xben",
            agent_mode="hybrid",
            autonomous_route=True,
            case_timeout_seconds=1800,
        )
    )

    assert preflight.blocked is True
    profile = preflight.payload["comparison_profile"]
    assert isinstance(profile, dict)
    assert profile["comparable"] is False
    issues = profile["issues"]
    assert isinstance(issues, list)
    assert "mode must be black-box" in issues
    assert "agent_mode must be ctf-free-roam" in issues
    assert "autonomous_route must be disabled for the strict 40-request comparison" in issues
    assert any("case_timeout_seconds must be 600" in issue for issue in issues)
    assert "source_available must be false" in issues
    assert any(
        "comparison profile mapta-awe-xben mismatch" in reason for reason in preflight.block_reasons
    )


def test_xben_rejects_tag_assisted_modes(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])

    with pytest.raises(ValueError, match="unsupported XBEN mode 'black-box-with-tags'"):
        run_xben(
            XbenSettings(
                benchmarks_root=root,
                output_dir=tmp_path / "runs",
                all_cases=True,
                dry_run=True,
                mode="black-box-with-tags",  # type: ignore[arg-type]
            )
        )


def test_xben_start_target_restarts_web_service_once_after_5xx_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    settings = XbenSettings(benchmarks_root=root, output_dir=tmp_path / "runs")
    case = selected_xben_cases(settings)[0]
    calls: list[str] = []

    class Identity:
        project = "test-project"
        flag = "flag{expected}"

    def fake_wait(*, settings: XbenSettings, target_url: str) -> None:
        del settings
        calls.append(f"wait:{target_url}")
        if calls.count(f"wait:{target_url}") == 1:
            raise RuntimeError(f"target did not become reachable at {target_url}: HTTP 500")

    def fake_restart(**kwargs: object) -> None:
        calls.append(f"restart:{kwargs.get('project')}")

    monkeypatch.setattr("ravage.xben_parts.runner._build_case", lambda **kwargs: None)
    monkeypatch.setattr("ravage.xben_parts.runner._up_case", lambda **kwargs: None)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._target_url_for",
        lambda **kwargs: "http://localhost:12345",
    )
    monkeypatch.setattr("ravage.xben_parts.runner._wait_for_target", fake_wait)
    monkeypatch.setattr("ravage.xben_parts.runner._restart_case_web_service", fake_restart)

    target_url = _start_case_target(
        settings=settings,
        case=case,
        identity=Identity(),  # type: ignore[arg-type]
        stdout=StringIO(),
    )

    assert target_url == "http://localhost:12345"
    assert calls == [
        "wait:http://localhost:12345",
        "restart:test-project",
        "wait:http://localhost:12345",
    ]


def test_xben_preflight_blocks_paid_routes_without_explicit_allowance(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])
    model_config = tmp_path / "models.yaml"
    model_config.write_text(
        """
profiles:
  hosted:
    default_tier: low
    routes:
      low:
        - provider: openai
          model: gpt-test
          api_key_required: false
          input_cost_per_1m_tokens: 1.0
          output_cost_per_1m_tokens: 2.0
          output_token_limit_parameter: max_completion_tokens
""".lstrip(),
        encoding="utf-8",
    )

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            model_config=model_config,
            model_profile="hosted",
            model_tier="low",
            max_model_requests_per_case=MODEL_REQUEST_CEILING,
            input_token_ceiling_per_model_call=100,
            tool_runtime="docker",
            tool_image="ravage-kali:test",
            memory_mode="learn",
            memory_db_path=tmp_path / "memory.db",
        )
    )

    assert preflight.blocked
    assert any("paid-risk model route selected" in reason for reason in preflight.block_reasons)
    assert preflight.payload["selected_cases"] == 1
    assert preflight.payload["model_request_ceiling"] == MODEL_REQUEST_CEILING
    assert preflight.payload["estimated_cost_usd"] == ESTIMATED_COST_USD
    assert preflight.payload["tool_runtime"] == "docker"
    assert preflight.payload["tool_image"] == "ravage-kali:test"
    assert preflight.payload["memory_mode"] == "learn"
    assert preflight.payload["memory_db_path"] == str(tmp_path / "memory.db")


def test_xben_preflight_accounts_for_base_and_autonomous_route_request_ceilings(
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            max_model_requests_per_case=MODEL_REQUEST_CEILING,
            autonomous_route=True,
            autonomous_route_max_requests=AUTONOMOUS_ROUTE_REQUEST_CEILING,
            min_free_gib=0,
        )
    )

    assert preflight.payload["strict_model_request_ceiling"] == MODEL_REQUEST_CEILING
    assert preflight.payload["autonomous_route_model_request_ceiling"] == (
        AUTONOMOUS_ROUTE_REQUEST_CEILING
    )
    assert preflight.payload["model_request_ceiling"] == (
        MODEL_REQUEST_CEILING + AUTONOMOUS_ROUTE_REQUEST_CEILING
    )
    assert preflight.payload["agent_stage_timeouts"] == {
        "base_stage_seconds": 1800,
        "autonomous_route_stage_seconds": 120,
        "subprocess_seconds": 1920,
    }


def test_xben_preflight_uses_priced_runtime_cap_instead_of_blocking_worst_case(
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])
    model_config = tmp_path / "models.yaml"
    model_config.write_text(
        """
profiles:
  hosted:
    default_tier: low
    routes:
      low:
        - provider: openai
          model: gpt-test
          api_key_required: false
          input_cost_per_1m_tokens: 1.0
          output_cost_per_1m_tokens: 2.0
""".lstrip(),
        encoding="utf-8",
    )

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            model_config=model_config,
            model_profile="hosted",
            model_tier="low",
            max_model_requests_per_case=MODEL_REQUEST_CEILING,
            input_token_ceiling_per_model_call=100,
            max_cost_usd=0.001,
            allow_paid_models=True,
        )
    )

    assert preflight.blocked is False
    assert preflight.payload["cost_cap_enforceable"] is True
    assert preflight.payload["estimated_cost_usd"] == ESTIMATED_COST_USD
    assert preflight.payload["cost_warnings"]


def test_xben_preflight_blocks_unpriced_paid_cost_cap(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])
    model_config = tmp_path / "models.yaml"
    model_config.write_text(
        """
profiles:
  hosted:
    default_tier: low
    routes:
      low:
        - provider: openai
          model: gpt-test
          api_key_required: false
""".lstrip(),
        encoding="utf-8",
    )

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            model_config=model_config,
            model_profile="hosted",
            model_tier="low",
            max_cost_usd=1.0,
            allow_paid_models=True,
        )
    )

    assert preflight.blocked
    assert preflight.payload["cost_cap_enforceable"] is False
    assert any("pricing is incomplete" in reason for reason in preflight.block_reasons)


def test_xben_preflight_blocks_low_free_disk(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])
    gib = 1024**3
    monkeypatch.setattr(
        "ravage.xben_parts.runner.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=100 * gib, free=3 * gib),
    )

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
            min_free_gib=20,
        )
    )

    assert preflight.blocked
    disk_payload = preflight.payload["disk"]
    assert isinstance(disk_payload, dict)
    assert disk_payload["free_gib"] == 3.0
    assert any(
        "free disk 3.0 GiB below required 20 GiB" in reason for reason in preflight.block_reasons
    )


def test_xben_preflight_blocks_missing_docker_tool_image(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    monkeypatch.setattr(
        "ravage.xben_parts.runner._docker_image_provenance",
        lambda image: {"available": False, "reference": image, "error": "not found"},
    )

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
            tool_runtime="docker",
            tool_image="sha256:" + "d" * 64,
        )
    )

    assert preflight.blocked
    assert any("Docker tool image is unavailable" in reason for reason in preflight.block_reasons)


def test_xben_preflight_can_require_clean_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])

    def source_state(path: Path) -> dict[str, object]:
        return {
            "available": True,
            "root": str(path),
            "commit": "a" * 40,
            "tree": "b" * 40,
            "dirty": path == root,
            "status_porcelain": [" M Dockerfile"] if path == root else [],
        }

    monkeypatch.setattr("ravage.xben_parts.runner._git_source_state", source_state)

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            ids=("XBEN-001-24",),
            require_clean_source=True,
        )
    )

    assert preflight.blocked
    assert "benchmarks source worktree is dirty" in preflight.block_reasons
    source_provenance = preflight.payload["source_provenance"]
    assert isinstance(source_provenance, dict)
    benchmarks_provenance = source_provenance["benchmarks"]
    assert isinstance(benchmarks_provenance, dict)
    assert benchmarks_provenance["dirty"] is True


def test_xben_cost_cap_marks_partial_matrix_incomplete_and_exits_nonzero(
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])
    _write_case(root, "XBEN-002-24", level=1, tags=["idor"])
    output_dir = tmp_path / "runs"

    with pytest.raises(RuntimeError, match="XBEN run incomplete"):
        run_xben(
            XbenSettings(
                benchmarks_root=root,
                output_dir=output_dir,
                all_cases=True,
                max_cost_usd=0.0,
            ),
            stdout=StringIO(),
        )

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == "incomplete"
    assert report["termination_reason"] == "cost_cap_exhausted"
    assert report["summary"]["completed"] == 0
    assert report["summary"]["total"] == 2


def test_xben_rechecks_disk_floor_before_each_case(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-101-24", level=1, tags=["sqli"])
    _write_case(root, "XBEN-102-24", level=1, tags=["idor"])
    output_dir = tmp_path / "runs"
    calls: list[str] = []
    _allow_xben_run(monkeypatch)
    free_gib = iter((8.0, 1.0))

    monkeypatch.setattr(
        "ravage.xben_parts.runner.shutil.disk_usage",
        lambda _path: SimpleNamespace(
            total=20 * (1024**3),
            used=12 * (1024**3),
            free=next(free_gib) * (1024**3),
        ),
    )

    def run_case(**kwargs: object) -> XbenCaseResult:
        case = cast("XbenCase", kwargs["case"])
        calls.append(case.benchmark_id)
        return _stub_case_result(case=case, output_dir=output_dir)

    monkeypatch.setattr("ravage.xben_parts.runner.run_xben_case", run_case)

    with pytest.raises(RuntimeError, match="reason=disk_floor_reached"):
        run_xben(
            XbenSettings(
                benchmarks_root=root,
                output_dir=output_dir,
                all_cases=True,
                min_free_gib=5,
            ),
            stdout=StringIO(),
        )

    assert calls == ["XBEN-101-24"]
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == "incomplete"
    assert report["termination_reason"] == "disk_floor_reached"
    assert report["summary"]["completed"] == 1
    assert report["summary"]["total"] == 2


def test_xben_unaccounted_attempt_stops_before_the_next_case(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-103-24", level=1, tags=["sqli"])
    _write_case(root, "XBEN-104-24", level=1, tags=["idor"])
    output_dir = tmp_path / "runs"
    calls: list[str] = []
    _allow_xben_run(monkeypatch)

    def run_case(**kwargs: object) -> XbenCaseResult:
        case = cast("XbenCase", kwargs["case"])
        calls.append(case.benchmark_id)
        return _stub_case_result(
            case=case,
            output_dir=output_dir,
            unmatched_model_attempts=1,
        )

    monkeypatch.setattr("ravage.xben_parts.runner.run_xben_case", run_case)

    with pytest.raises(RuntimeError, match="reason=unaccounted_model_attempt"):
        run_xben(
            XbenSettings(
                benchmarks_root=root,
                output_dir=output_dir,
                all_cases=True,
            ),
            stdout=StringIO(),
        )

    assert calls == ["XBEN-103-24"]
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == "incomplete"
    assert report["termination_reason"] == "unaccounted_model_attempt"
    assert report["summary"]["completed"] == 1
    assert report["summary"]["total"] == 2


def test_xben_unaccounted_attempt_on_case_104_is_incomplete_and_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-104-24", level=1, tags=["idor"])
    output_dir = tmp_path / "runs"
    _allow_xben_run(monkeypatch)

    def run_case(**kwargs: object) -> XbenCaseResult:
        case = cast("XbenCase", kwargs["case"])
        return _stub_case_result(
            case=case,
            output_dir=output_dir,
            unmatched_model_attempts=1,
        )

    monkeypatch.setattr("ravage.xben_parts.runner.run_xben_case", run_case)

    with pytest.raises(RuntimeError, match="reason=unaccounted_model_attempt"):
        run_xben(
            XbenSettings(
                benchmarks_root=root,
                output_dir=output_dir,
                all_cases=True,
            ),
            stdout=StringIO(),
        )

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == "incomplete"
    assert report["termination_reason"] == "unaccounted_model_attempt"
    assert report["summary"]["completed"] == 1
    assert report["summary"]["total"] == 1
    assert report["summary"]["cost_status"] == "unknown"
    assert report["summary"]["budget_charge_status"] == "estimated"
    assert report["cases"][0]["budget_charge_status"] == "estimated"


def test_xben_image_provenance_failure_aborts_the_matrix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    output_dir = tmp_path / "runs"
    _allow_xben_run(monkeypatch)
    monkeypatch.setattr("ravage.xben_parts.runner._build_case", lambda **kwargs: None)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._up_case",
        lambda **kwargs: (_ for _ in ()).throw(
            XbenEvidenceCaptureError("no Docker project containers found after compose up")
        ),
    )
    monkeypatch.setattr(
        "ravage.xben_parts.runner._collect_docker_logs",
        lambda **kwargs: None,
    )
    monkeypatch.setattr("ravage.xben_parts.runner._down_case", lambda **kwargs: None)

    with pytest.raises(RuntimeError, match="reason=fatal_runner_error"):
        run_xben(
            XbenSettings(
                benchmarks_root=root,
                output_dir=output_dir,
                all_cases=True,
            ),
            stdout=StringIO(),
        )

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == "incomplete"
    assert report["termination_reason"] == "fatal_runner_error"
    assert report["summary"]["completed"] == 0
    fatal = json.loads(
        (output_dir / "XBEN-001-24" / "fatal-run-error.json").read_text(encoding="utf-8")
    )
    assert fatal["error_type"] == "XbenEvidenceCaptureError"


def test_xben_teardown_failure_aborts_the_matrix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["idor"])
    output_dir = tmp_path / "runs"
    _allow_xben_run(monkeypatch)
    monkeypatch.setattr("ravage.xben_parts.runner._build_case", lambda **kwargs: None)
    monkeypatch.setattr("ravage.xben_parts.runner._up_case", lambda **kwargs: None)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._target_url_for",
        lambda **kwargs: "http://127.0.0.1:12345",
    )
    monkeypatch.setattr("ravage.xben_parts.runner._wait_for_target", lambda **kwargs: None)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._run_agent_and_find_flag",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "ravage.xben_parts.runner._collect_docker_logs",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "ravage.xben_parts.runner._down_case",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("Docker teardown failed")),
    )

    with pytest.raises(RuntimeError, match="reason=fatal_runner_error"):
        run_xben(
            XbenSettings(
                benchmarks_root=root,
                output_dir=output_dir,
                all_cases=True,
            ),
            stdout=StringIO(),
        )

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == "incomplete"
    assert report["termination_reason"] == "fatal_runner_error"
    assert report["summary"]["completed"] == 0
    fatal = json.loads(
        (output_dir / "XBEN-001-24" / "fatal-run-error.json").read_text(encoding="utf-8")
    )
    assert fatal["error"] == "Docker teardown failed"


def test_xben_dry_run_writes_selection_without_model_or_docker(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["sqli"])
    stdout = StringIO()

    payload = run_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            dry_run=True,
        ),
        stdout=stdout,
    )

    assert payload["selected_cases"] == 1
    assert (tmp_path / "runs" / "selection.json").exists()
    assert "[xben:selection] cases=1" in stdout.getvalue()


def test_xben_modes_make_hint_policy_explicit(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["xss", "idor"])
    case = selected_xben_cases(
        XbenSettings(benchmarks_root=root, output_dir=tmp_path / "runs", all_cases=True)
    )[0]

    black_box_brief = _write_case_brief(
        case_dir=tmp_path / "black-box",
        case=case,
        target_url="http://127.0.0.1:8765",
        settings=XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            mode="black-box",
        ),
    )
    hybrid_brief = _write_case_brief(
        case_dir=tmp_path / "hybrid",
        case=case,
        target_url="http://127.0.0.1:8765",
        settings=XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            mode="black-box",
            agent_mode="hybrid",
        ),
    )
    white_brief = _write_case_brief(
        case_dir=tmp_path / "white-box",
        case=case,
        target_url="http://127.0.0.1:8765",
        settings=XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            mode="white-box",
        ),
    )

    black_box = json.loads(json.dumps(yaml.safe_load(black_box_brief.read_text(encoding="utf-8"))))
    hybrid = json.loads(json.dumps(yaml.safe_load(hybrid_brief.read_text(encoding="utf-8"))))
    white = json.loads(json.dumps(yaml.safe_load(white_brief.read_text(encoding="utf-8"))))

    assert black_box["context"]["description"] == "Test challenge description."
    assert "name" not in black_box["context"]
    assert "benchmark_id" not in black_box["context"]
    assert "benchmark" not in black_box["context"]
    assert "mode" not in black_box["context"]
    assert "hint_policy" not in black_box["context"]
    assert "level" not in black_box["context"]
    assert "source_root" not in black_box["context"]
    assert "tags" not in black_box["context"]
    assert "benchmark_hints" not in black_box["context"]
    assert "tool_recon" not in black_box["context"]
    assert "tool_recon" not in hybrid["context"]
    assert black_box["objectives"] == ["capture_flag"]
    assert white["context"]["source_root"] == str(case.path)
    assert white["context"]["allowed_source_roots"] == [str(root)]
    assert "tags" not in white["context"]
    assert "benchmark_id" not in white["context"]


def test_xben_black_box_brief_keeps_description_without_generated_hypotheses(
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(
        root,
        "XBEN-001-24",
        level=1,
        tags=["xss"],
        description="Upload an XML profile picture from a remote URL and read the generated page.",
    )
    case = selected_xben_cases(
        XbenSettings(benchmarks_root=root, output_dir=tmp_path / "runs", all_cases=True)
    )[0]

    brief_path = _write_case_brief(
        case_dir=tmp_path / "black-box",
        case=case,
        target_url="http://127.0.0.1:8765",
        settings=XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            mode="black-box",
        ),
    )

    brief = yaml.safe_load(brief_path.read_text(encoding="utf-8"))
    assert brief["objectives"] == ["capture_flag"]
    assert brief["context"]["description"] == (
        "Upload an XML profile picture from a remote URL and read the generated page."
    )
    assert "tags" not in brief["context"]
    assert "benchmark_hints" not in brief["context"]
    load_engagement_brief(brief_path)


def test_xben_black_box_brief_keeps_benchmark_description_hints_without_case_id(
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(
        root,
        "XBEN-001-24",
        level=1,
        tags=["idor"],
        description="XBEN-001-24 Simple IDOR POST",
    )
    case = selected_xben_cases(
        XbenSettings(benchmarks_root=root, output_dir=tmp_path / "runs", all_cases=True)
    )[0]

    brief_path = _write_case_brief(
        case_dir=tmp_path / "black-box",
        case=case,
        target_url="http://127.0.0.1:8765",
        settings=XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            mode="black-box",
        ),
    )

    brief = yaml.safe_load(brief_path.read_text(encoding="utf-8"))
    assert brief["context"]["description"] == "Simple IDOR POST"
    assert "XBEN-001-24" not in brief_path.read_text(encoding="utf-8")
    assert "Simple IDOR POST" in brief_path.read_text(encoding="utf-8")


def test_xben_clean_case_log_summarizes_tool_calls(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    events_path = workspace / "events.jsonl"
    events_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-06-22T00:00:00+00:00",
                        "kind": "agent_action_selected",
                        "payload": {
                            "action": {
                                "action": "run_command",
                                "command": "curl -i http://127.0.0.1:8000/",
                            }
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-06-22T00:00:01+00:00",
                        "kind": "tool_run_command",
                        "payload": {"command": ["sh", "-lc", "curl -i http://127.0.0.1:8000/"]},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-06-22T00:00:02+00:00",
                        "kind": "flag_captured",
                        "payload": {"flag": "flag{example}"},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = XbenCaseResult(
        benchmark_id="XBEN-001-24",
        name="case",
        level=1,
        target_url="http://127.0.0.1:8000",
        flag="flag{expected}",
        found_flag="flag{example}",
        status="solved",
        solved=True,
        elapsed_seconds=2.0,
        model_request_count=0,
        http_request_count=1,
        db_path=tmp_path / "audit.db",
        workspace_path=workspace,
        transcript_path=workspace / "transcript.jsonl",
        events_path=events_path,
        artifacts_path=workspace / "artifacts",
        stdout_path=tmp_path / "agent.stdout",
        clean_log_path=tmp_path / "case.log",
        docker_log_path=tmp_path / "docker.log",
        error=None,
        http_request_count_status="exact",
        http_request_count_provenance="workspace_traffic_policy_ledger",
        tool_action_count=1,
    )

    _write_clean_case_log(result)

    clean = result.clean_log_path.read_text(encoding="utf-8")
    assert "Tool call: tool_run_command (total: 1)" in clean
    assert "Command executed: curl -i http://127.0.0.1:8000/" in clean
    assert "Main command 'curl' usage count: 1" in clean
    assert "Flags detected: ['flag{example}']" in clean
    assert "HTTP request accounting: count=1; status=exact" in clean
    assert "provenance=workspace_traffic_policy_ledger" in clean
    assert "tool_actions=1" in clean


def test_xben_clean_case_log_does_not_claim_unverified_flags(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    events_path = workspace / "events.jsonl"
    events_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-06-22T00:00:02+00:00",
                "kind": "flag_captured",
                "payload": {"flag": "flag{agent_guess}"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    result = XbenCaseResult(
        benchmark_id="XBEN-001-24",
        name="case",
        level=1,
        target_url="http://127.0.0.1:8000",
        flag="flag{expected}",
        found_flag=None,
        status="failed",
        solved=False,
        elapsed_seconds=2.0,
        model_request_count=0,
        http_request_count=1,
        db_path=tmp_path / "audit.db",
        workspace_path=workspace,
        transcript_path=workspace / "transcript.jsonl",
        events_path=events_path,
        artifacts_path=workspace / "artifacts",
        stdout_path=tmp_path / "agent.stdout",
        clean_log_path=tmp_path / "case.log",
        docker_log_path=tmp_path / "docker.log",
        error=None,
    )

    _write_clean_case_log(result)

    clean = result.clean_log_path.read_text(encoding="utf-8")
    assert "Flags detected:" not in clean
    assert "Agent-claimed flags (not verified by scorer): ['flag{agent_guess}']" in clean
    assert "solved=false" in clean


def test_xben_does_not_auto_enforce_proof_bundles_from_metadata_tags(
    tmp_path: Path,
) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-031-24", level=1, tags=["command_injection"])
    _write_case(root, "XBEN-001-24", level=2, tags=["idor", "default_credentials"])
    _write_case(root, "XBEN-022-24", level=2, tags=["ssti"])
    _write_case(root, "XBEN-019-24", level=1, tags=["lfi"])
    _write_case(root, "XBEN-097-24", level=2, tags=["path_traversal"])
    _write_case(root, "XBEN-052-24", level=1, tags=["privilege_escalation"])
    _write_case(root, "XBEN-039-24", level=1, tags=["sqli"])
    _write_case(root, "XBEN-020-24", level=1, tags=["ssrf"])
    _write_case(root, "XBEN-032-24", level=1, tags=["xxe"])
    cases = selected_xben_cases(
        XbenSettings(benchmarks_root=root, output_dir=tmp_path / "runs", all_cases=True)
    )

    preflight = preflight_xben(
        XbenSettings(
            benchmarks_root=root,
            output_dir=tmp_path / "runs",
            all_cases=True,
            mode="black-box",
            allow_degraded=True,
        ),
        selected_cases=cases,
    )

    assert preflight.payload["proof_bundle_verifier"] is False
    assert preflight.payload["require_proof_bundle_findings"] is False
    assert preflight.payload["proof_bundle_auto_enforced"] is False


def test_xben_brief_includes_published_service_ports(tmp_path: Path) -> None:
    root = tmp_path / "benchmarks"
    _write_case(root, "XBEN-001-24", level=1, tags=["web"])
    case = selected_xben_cases(
        XbenSettings(benchmarks_root=root, output_dir=tmp_path / "runs", all_cases=True)
    )[0]

    brief_path = _write_case_brief(
        case_dir=tmp_path / "brief",
        case=case,
        target_url="http://127.0.0.1:8765",
        settings=XbenSettings(benchmarks_root=root, output_dir=tmp_path / "runs"),
        published_ports=(
            {
                "service": "web",
                "container_port": 22,
                "host": "127.0.0.1",
                "host_port": SSH_TEST_HOST_PORT,
                "protocol": "tcp",
            },
        ),
    )

    brief = yaml.safe_load(brief_path.read_text(encoding="utf-8"))
    assert brief["scope"]["in_scope"] == [
        "http://127.0.0.1:8765",
        f"http://127.0.0.1:{SSH_TEST_HOST_PORT}",
    ]
    assert "published_ports" not in brief["context"]


def test_xben_patches_legacy_fixture_dockerfiles_before_build(tmp_path: Path) -> None:
    case_dir = tmp_path / "XBEN-001-24"
    mysql_dir = case_dir / "mysql"
    app_dir = case_dir / "app"
    mysql_dir.mkdir(parents=True)
    app_dir.mkdir()
    mysql_dockerfile = mysql_dir / "Dockerfile"
    app_dockerfile = app_dir / "Dockerfile"
    mysql_dockerfile.write_text("FROM mysql:5.7.15\n", encoding="utf-8")
    app_dockerfile.write_text(
        """
FROM httpd:2.4.49
RUN apt-get update && apt-get install -y curl
""".lstrip(),
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(case_dir)
    second_count = _patch_legacy_xben_dockerfiles(case_dir)

    assert patched_count == LEGACY_PATCHED_FILE_COUNT
    assert second_count == 0
    assert mysql_dockerfile.read_text(encoding="utf-8") == "FROM mysql:5.7\n"
    app_text = app_dockerfile.read_text(encoding="utf-8")
    assert "ravage-xben-legacy-apt-compat" in app_text
    assert "archive.debian.org" in app_text
    assert "apt-get install -y curl" in app_text


def test_xben_patches_legacy_php_apache_dockerfiles_before_build(tmp_path: Path) -> None:
    case_dir = tmp_path / "XBEN-001-24"
    app_dir = case_dir / "php"
    app_dir.mkdir(parents=True)
    app_dockerfile = app_dir / "Dockerfile"
    app_dockerfile.write_text(
        """
FROM php:7.1-apache
RUN apt-get update && apt-get install -y curl
""".lstrip(),
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(case_dir)
    second_count = _patch_legacy_xben_dockerfiles(case_dir)

    assert patched_count == 1
    assert second_count == 0
    app_text = app_dockerfile.read_text(encoding="utf-8")
    assert "ravage-xben-legacy-apt-compat" in app_text
    assert "archive.debian.org" in app_text


def test_xben_declares_flag_build_args_before_dockerfile_use(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-flag-case"
    app_dir = case_dir / "app"
    app_dir.mkdir(parents=True)
    app_dockerfile = app_dir / "Dockerfile"
    app_dockerfile.write_text(
        """
FROM python:3.8-slim
ENV FLAG=${FLAG}
COPY . .
ARG FLAG
""".lstrip(),
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(case_dir)
    second_count = _patch_legacy_xben_dockerfiles(case_dir)

    assert patched_count == 1
    assert second_count == 0
    assert app_dockerfile.read_text(encoding="utf-8").splitlines() == [
        "FROM python:3.8-slim",
        "ARG FLAG",
        "ENV FLAG=${FLAG}",
        "COPY . .",
        "ARG FLAG",
    ]


def test_xben_normalizes_legacy_hardcoded_flag_env(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-hardcoded-flag-case"
    app_dir = case_dir / "app"
    app_dir.mkdir(parents=True)
    app_dockerfile = app_dir / "Dockerfile"
    app_dockerfile.write_text(
        """
FROM php:7.4-apache
ARG FLAG
ENV FLAG=$FLAG
ENV FLAG="flag{legacy_fixture_static_value}"
ENV CTF_FLAG="flag{legacy_fixture_static_value}"
""".lstrip(),
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(case_dir)
    second_count = _patch_legacy_xben_dockerfiles(case_dir)

    assert patched_count == 1
    assert second_count == 0
    assert app_dockerfile.read_text(encoding="utf-8").splitlines() == [
        "FROM php:7.4-apache",
        "ARG FLAG",
        "ENV FLAG=$FLAG",
        "ENV FLAG=$FLAG",
        "ENV CTF_FLAG=$FLAG",
    ]


def test_xben_patches_legacy_haproxy_dockerfiles_before_build(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-proxy-case"
    proxy_dir = case_dir / "edge"
    proxy_dir.mkdir(parents=True)
    proxy_dockerfile = proxy_dir / "Dockerfile"
    proxy_dockerfile.write_text(
        """
FROM haproxy:2.0.8
RUN apt-get update && apt-get install -y curl
""".lstrip(),
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(case_dir)
    second_count = _patch_legacy_xben_dockerfiles(case_dir)

    assert patched_count == 1
    assert second_count == 0
    proxy_text = proxy_dockerfile.read_text(encoding="utf-8")
    assert "ravage-xben-legacy-apt-compat" in proxy_text
    assert "archive.debian.org" in proxy_text
    assert "apt-get install -y curl" in proxy_text


def test_xben_patches_mysql_sidecar_for_arm_compatibility(tmp_path: Path) -> None:
    case_dir = tmp_path / "XBEN-001-24"
    mysql_dir = case_dir / "mysql"
    mysql_dir.mkdir(parents=True)
    mysql_dockerfile = mysql_dir / "Dockerfile"
    compose_file = case_dir / "docker-compose.yml"
    mysql_dockerfile.write_text("FROM mysql:5.7\n", encoding="utf-8")
    compose_file.write_text(
        """
services:
  db:
    # ravage-xben-mysql-arm64-compat
    platform: linux/arm64/v8
    image: mysql:5.7
    expose:
      - 3306:3306
  web:
    build: ./app
""".lstrip(),
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(
        case_dir,
        force_mysql_arm_compat=True,
    )
    second_count = _patch_legacy_xben_dockerfiles(
        case_dir,
        force_mysql_arm_compat=True,
    )

    assert patched_count == MYSQL_ARM_PATCHED_FILE_COUNT
    assert second_count == 0
    assert mysql_dockerfile.read_text(encoding="utf-8") == "FROM mariadb:10.11\n"
    compose_text = compose_file.read_text(encoding="utf-8")
    assert "ravage-xben-mysql-arm64-compat" not in compose_text
    assert "platform: linux/arm64/v8" not in compose_text
    assert "image: mariadb:10.11" in compose_text


def test_xben_patches_hardcoded_amd64_mysql_sidecar_for_arm_compatibility(
    tmp_path: Path,
) -> None:
    case_dir = tmp_path / "XBEN-001-24"
    mysql_dir = case_dir / "mysql"
    mysql_dir.mkdir(parents=True)
    mysql_dockerfile = mysql_dir / "Dockerfile"
    mysql_dockerfile.write_text(
        "FROM --platform=linux/amd64 mysql:5.7\n",
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(
        case_dir,
        force_mysql_arm_compat=True,
    )
    second_count = _patch_legacy_xben_dockerfiles(
        case_dir,
        force_mysql_arm_compat=True,
    )

    assert patched_count == 1
    assert second_count == 0
    assert mysql_dockerfile.read_text(encoding="utf-8") == "FROM mariadb:10.11\n"


def test_xben_patches_fixed_host_ports_to_dynamic_ports(tmp_path: Path) -> None:
    case_dir = tmp_path / "XBEN-004-24"
    case_dir.mkdir(parents=True)
    compose_file = case_dir / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  web:
    image: nginx
    ports:
      - "5000:5000"
      - '127.0.0.1:8080:80'
""".lstrip(),
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(case_dir)
    second_count = _patch_legacy_xben_dockerfiles(case_dir)

    assert patched_count == 1
    assert second_count == 0
    compose_text = compose_file.read_text(encoding="utf-8")
    assert '"5000:5000"' not in compose_text
    assert "'127.0.0.1:8080:80'" not in compose_text
    assert '      - "5000"' in compose_text
    assert "      - '80'" in compose_text


def test_xben_patches_duplicate_service_mapping_keys(tmp_path: Path) -> None:
    case_dir = tmp_path / "XBEN-001-24"
    case_dir.mkdir(parents=True)
    compose_file = case_dir / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  web:
    image: nginx
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8080:80"
    depends_on:
      db:
        condition: service_healthy
  db:
    image: postgres
""".lstrip(),
        encoding="utf-8",
    )

    patched_count = _patch_legacy_xben_dockerfiles(case_dir)
    second_count = _patch_legacy_xben_dockerfiles(case_dir)

    assert patched_count == 1
    assert second_count == 0
    parsed = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
    assert parsed["services"]["web"]["ports"] == ["80"]
    assert parsed["services"]["web"]["depends_on"] == {"db": {"condition": "service_healthy"}}


def test_xben_patches_pymysql_requirements_for_mysql8_auth(tmp_path: Path) -> None:
    case_dir = tmp_path / "XBEN-001-24"
    app_dir = case_dir / "app"
    app_dir.mkdir(parents=True)
    requirements = app_dir / "requirements.txt"
    requirements.write_text("Flask\nPyMySQL\n", encoding="utf-8")

    patched_count = _patch_legacy_xben_dockerfiles(case_dir)
    second_count = _patch_legacy_xben_dockerfiles(case_dir)

    assert patched_count == PYMYSQL_REQUIREMENTS_PATCHED_FILE_COUNT
    assert second_count == 0
    requirements_text = requirements.read_text(encoding="utf-8")
    assert "PyMySQL" in requirements_text
    assert "cryptography" in requirements_text


def test_xben_flag_scoring_reads_audit_and_workspace(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    workspace.joinpath("artifacts").mkdir()
    stdout_path = tmp_path / "agent.stdout"
    stdout_path.write_text("", encoding="utf-8")
    flag = "flag{ravage_test_xben_001_24}"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                engagement_id TEXT,
                actor TEXT,
                action TEXT,
                payload_json TEXT,
                cost_usd REAL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE findings (
                finding_id TEXT,
                engagement_id TEXT,
                vuln_class TEXT,
                status TEXT,
                validator_vote TEXT,
                payload_json TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO audit_log (action, payload_json) VALUES (?, ?)",
            (
                "flag_captured",
                json.dumps(
                    {
                        "flag": flag,
                        "evidence": "tool_run_probe",
                        "recognizer": "benchmark_terminal_fallback",
                    }
                ),
            ),
        )

    assert (
        _find_flag(
            flag=flag,
            db_path=db_path,
            workspace_path=workspace,
            stdout_path=stdout_path,
            flag_mode="exact",
        )
        == flag
    )


def test_xben_exact_scoring_rejects_unverified_stdout_flag(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    stdout_path = tmp_path / "agent.stdout"
    flag = "flag{unguessable_target_secret}"
    stdout_path.write_text(f"I claim {flag}\n", encoding="utf-8")

    assert (
        _find_flag(
            flag=flag,
            db_path=tmp_path / "missing.db",
            workspace_path=workspace,
            stdout_path=stdout_path,
            flag_mode="exact",
        )
        is None
    )


def test_xben_exact_scoring_rejects_manual_flag_capture_event(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    stdout_path = tmp_path / "agent.stdout"
    stdout_path.write_text("", encoding="utf-8")
    flag = "flag{manual_claim_is_not_tool_evidence}"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE audit_log (action TEXT, payload_json TEXT)")
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?)",
            ("flag_captured", json.dumps({"flag": flag, "evidence": flag})),
        )

    assert (
        _find_flag(
            flag=flag,
            db_path=db_path,
            workspace_path=workspace,
            stdout_path=stdout_path,
            flag_mode="exact",
        )
        is None
    )


def test_xben_model_usage_fails_closed_when_a_reply_lacks_cost_provenance(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE audit_log (action TEXT, payload_json TEXT, cost_usd REAL)")
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?)",
            (
                "model_request_started",
                json.dumps({"model_request_id": "request-known"}),
                0.0,
            ),
        )
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?)",
            (
                "model_reply_received",
                json.dumps(
                    {
                        "model_request_id": "request-known",
                        "input_tokens": 100,
                        "cached_input_tokens": 10,
                        "output_tokens": 20,
                        "usage_reported": True,
                        "cost_known": True,
                        "response_model": "gpt-snapshot",
                        "system_fingerprint": "fp_one",
                        "service_tier": "default",
                    }
                ),
                0.01,
            ),
        )
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?)",
            (
                "model_request_started",
                json.dumps({"model_request_id": "request-unknown"}),
                0.0,
            ),
        )
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?)",
            (
                "model_reply_received",
                json.dumps(
                    {
                        "model_request_id": "request-unknown",
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "usage_reported": False,
                        "cost_known": False,
                    }
                ),
                0.0,
            ),
        )

    usage = _model_usage(db_path)

    assert usage["cost_accounting_complete"] is False
    assert usage["requests"] == 2
    assert usage["replies"] == 2
    assert usage["accountable_replies"] == 1
    assert usage["unmatched_attempts"] == 1
    assert usage["cost_usd"] == 0.01
    assert usage["response_models"] == ("gpt-snapshot",)
    assert usage["system_fingerprints"] == ("fp_one",)
    assert usage["service_tiers"] == ("default",)


def test_xben_model_usage_marks_transport_failure_as_unmatched_attempt(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE audit_log (action TEXT, payload_json TEXT, cost_usd REAL)")
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?)",
            (
                "model_request_started",
                json.dumps({"model_request_id": "transport-failure"}),
                0.0,
            ),
        )

    usage = _model_usage(db_path)

    assert usage["requests"] == 1
    assert usage["replies"] == 0
    assert usage["unmatched_attempts"] == 1
    assert usage["cost_accounting_complete"] is False
    assert usage["cost_usd"] == 0.0


def test_xben_multi_case_cap_sums_conservative_budget_charges() -> None:
    first = SimpleNamespace(cost_usd=None, budget_charge_usd=0.4)
    second = SimpleNamespace(cost_usd=0.2, budget_charge_usd=0.35)
    settings = XbenSettings(max_cost_usd=1.0)

    remaining = _remaining_cost_budget(
        settings=settings,
        results=cast("list[XbenCaseResult]", [first, second]),
    )

    assert remaining == 0.25
    third = SimpleNamespace(cost_usd=None, budget_charge_usd=0.3)
    exhausted = _remaining_cost_budget(
        settings=settings,
        results=cast("list[XbenCaseResult]", [first, second, third]),
    )
    assert exhausted == 0.0


def test_xben_case_budget_charge_adds_policy_estimate_for_unmatched_attempt() -> None:
    charge = _case_budget_charge_usd(
        known_reply_cost_usd=0.25,
        unmatched_model_attempts=2,
        per_unmatched_charge_usd=0.14144,
    )

    assert charge == pytest.approx(0.53288)


def test_xben_report_separates_exact_cost_from_conservative_budget_charge(
    tmp_path: Path,
) -> None:
    exact_requests = 3
    lower_bound_requests = 4
    unmetered_actions = 2
    incomplete_requests = 1
    exact_tool_actions = 5
    lower_bound_tool_actions = 6
    case_one = XbenCase(
        benchmark_id="XBEN-001-24",
        path=tmp_path / "case-one",
        name="case one",
        level=1,
        description="one",
        main_service=None,
        main_service_port=None,
    )
    case_two = replace(
        case_one,
        benchmark_id="XBEN-002-24",
        path=tmp_path / "case-two",
        name="case two",
    )
    result_one = XbenCaseResult(
        benchmark_id=case_one.benchmark_id,
        name=case_one.name,
        level=case_one.level,
        target_url=None,
        flag="flag{one}",
        found_flag=None,
        status="errored",
        solved=False,
        elapsed_seconds=1.0,
        model_request_count=1,
        http_request_count=exact_requests,
        db_path=tmp_path / "one.db",
        workspace_path=tmp_path / "one-workspace",
        transcript_path=tmp_path / "one-transcript.jsonl",
        events_path=tmp_path / "one-events.jsonl",
        artifacts_path=tmp_path / "one-artifacts",
        stdout_path=tmp_path / "one.stdout",
        clean_log_path=tmp_path / "one.log",
        docker_log_path=tmp_path / "one-docker.log",
        error="transport failure",
        http_request_count_status="exact",
        http_request_count_provenance="workspace_traffic_policy_ledger",
        tool_action_count=exact_tool_actions,
        cost_usd=None,
        cost_status="unknown",
        known_reply_cost_usd=0.1,
        unmatched_model_attempts=1,
        budget_charge_per_unmatched_attempt_usd=0.15,
        budget_charge_usd=0.25,
        budget_charge_status="estimated",
        budget_charge_provenance=("known_reply_cost_plus_policy_input_estimate"),
    )
    result_two = replace(
        result_one,
        benchmark_id=case_two.benchmark_id,
        name=case_two.name,
        flag="flag{two}",
        status="failed",
        error=None,
        http_request_count=lower_bound_requests,
        http_request_count_status="lower_bound",
        http_unmetered_action_count=unmetered_actions,
        http_incomplete_request_count=incomplete_requests,
        tool_action_count=lower_bound_tool_actions,
        cost_usd=0.2,
        cost_status="known",
        cost_provenance="referee_computed_from_provider_usage",
        known_reply_cost_usd=0.2,
        unmatched_model_attempts=0,
        budget_charge_usd=0.2,
        budget_charge_provenance="known_reply_cost",
    )
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    settings = XbenSettings(output_dir=output_dir)

    report = _write_report(
        settings=settings,
        results=[result_one, result_two],
        selected_cases=[case_one, case_two],
    )

    summary = report["summary"]
    assert isinstance(summary, dict)
    assert summary["cost_usd"] is None
    assert summary["cost_status"] == "unknown"
    assert summary["known_reply_cost_usd"] == pytest.approx(0.3)
    assert summary["unmatched_model_attempts"] == 1
    assert summary["budget_charge_usd"] == pytest.approx(0.45)
    assert summary["budget_charge_status"] == "estimated"
    assert summary["budget_charge_provenance"] == ("known_reply_cost_plus_policy_input_estimate")
    assert summary["http_requests"] == exact_requests + lower_bound_requests
    assert summary["http_request_count_status"] == "lower_bound"
    assert summary["http_request_count_provenance"] == "workspace_traffic_policy_ledger"
    assert summary["http_request_count_statuses"] == {"exact": 1, "lower_bound": 1}
    assert summary["http_unmetered_actions"] == unmetered_actions
    assert summary["http_incomplete_requests"] == incomplete_requests
    assert summary["tool_actions"] == exact_tool_actions + lower_bound_tool_actions


def test_xben_pattern_scoring_ignores_flag_placeholders() -> None:
    assert not _is_scoreable_flag_candidate("flag{...}")
    assert not _is_scoreable_flag_candidate("flag{REDACTED}")
    assert _is_scoreable_flag_candidate("flag{real_target_value}")


def test_xben_reads_root_benchmark_json_metadata(tmp_path: Path) -> None:
    case_dir = tmp_path / "XBEN-010-24"
    case_dir.mkdir()
    level = 2
    case_dir.joinpath("benchmark.json").write_text(
        json.dumps(
            {
                "name": "Root JSON Case",
                "level": level,
                "tags": ["ssrf"],
                "description": "metadata from root json",
            }
        ),
        encoding="utf-8",
    )

    metadata = _read_metadata(case_dir)

    assert metadata["name"] == "Root JSON Case"
    assert metadata["level"] == level
    assert metadata["tags"] == ["ssrf"]


def test_xben_resume_ignores_truncated_report_json(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"cases": [', encoding="utf-8")

    assert _read_existing_results(report) == {}


def test_xben_agent_subprocess_invokes_ravage_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        stdout = cast("StringIO", kwargs["stdout"])
        stdout.write("ok\n")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("ravage.xben_parts.agent.subprocess.run", fake_run)
    monkeypatch.delenv("DOCKER_DEFAULT_PLATFORM", raising=False)

    stdout = StringIO()
    _run_agent_subprocess(
        settings=XbenSettings(
            output_dir=tmp_path / "runs",
            agent_mode="hybrid",
            model_profile="demo-profile",
            model_tier="high",
            max_turns=7,
            tool_runtime="docker",
            tool_image="ravage-tools:test",
            allow_degraded=True,
        ),
        brief_path=tmp_path / "brief.yaml",
        target_url="http://127.0.0.1:8000",
        db_path=tmp_path / "audit.db",
        workspace_path=tmp_path / "workspace",
        stdout=stdout,
    )

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:5] == [
        sys.executable,
        "-m",
        "ravage",
        "attack",
        str(tmp_path / "brief.yaml"),
    ]
    assert cmd[cmd.index("--run-dir") + 1] == str(tmp_path)
    assert "orchestrator" not in cmd
    assert "--agent" not in cmd
    assert "--benchmark-proof-recognition" not in cmd
    assert "--allow-degraded" in cmd
    assert cmd[cmd.index("--agent-mode") + 1] == "hybrid"
    assert cmd[cmd.index("--model-profile") + 1] == "demo-profile"
    assert cmd[cmd.index("--model-tier") + 1] == "high"
    assert cmd[cmd.index("--max-turns") + 1] == "7"
    assert cmd[cmd.index("--tool-runtime") + 1] == "docker"
    assert cmd[cmd.index("--tool-image") + 1] == "ravage-tools:test"
    assert cmd[cmd.index("--target-url") + 1] == "http://127.0.0.1:8000"
    assert cmd[cmd.index("--db-path") + 1] == str(tmp_path / "audit.db")
    assert cmd[cmd.index("--workspace-dir") + 1] == str(tmp_path / "workspace")
    assert "--tool-recon" not in cmd
    assert "--recovery-profile" not in cmd
    env = captured["env"]
    assert isinstance(env, dict)
    assert "packages/ravage/src:packages/schemas/src" in env["PYTHONPATH"]
    assert "DOCKER_DEFAULT_PLATFORM" not in env


def test_xben_agent_subprocess_passes_public_attack_optional_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    knowledge_pack = tmp_path / "knowledge" / "hunt-idor"
    knowledge_pack.mkdir(parents=True)
    knowledge_pack.joinpath("SKILL.md").write_text(
        "---\n"
        "name: hunt-idor\n"
        "description: Investigate authorized object boundaries.\n"
        "---\n"
        "Use paired identity controls.\n",
        encoding="utf-8",
    )

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        stdout = cast("StringIO", kwargs["stdout"])
        stdout.write("ok\n")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("ravage.xben_parts.agent.subprocess.run", fake_run)

    _run_agent_subprocess(
        settings=XbenSettings(
            output_dir=tmp_path / "runs",
            max_turns=1,
            model_config=tmp_path / "models.yaml",
            knowledge_pack_path=tmp_path / "knowledge",
            allow_paid_models=True,
            allow_degraded=True,
            recovery_profile="recovery-v1",
        ),
        brief_path=tmp_path / "brief.yaml",
        target_url="http://127.0.0.1:8000",
        db_path=tmp_path / "audit.db",
        workspace_path=tmp_path / "workspace",
        stdout=StringIO(),
    )

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[cmd.index("--model-config") + 1] == str(tmp_path / "models.yaml")
    assert cmd[cmd.index("--knowledge-pack") + 1] == str(tmp_path / "knowledge")
    assert len(cmd[cmd.index("--knowledge-pack-sha256") + 1]) == 64
    assert cmd[cmd.index("--recovery-profile") + 1] == "recovery-v1"
    assert "--allow-paid-models" in cmd
