from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from ravage.agent_core.action_executor import ActionResult, execute_action
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    _open_run_traffic_policy,
    _request_profile_probe_action,
)
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import ToolResult, ToolRuntime
from ravage.traffic.policy import (
    PORTSWIGGER_DEMO_REQUEST_PROFILE,
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyError,
)


class _TrackingRuntime(ToolRuntime):
    def __init__(self) -> None:
        self.command_calls = 0

    def run_command(
        self,
        *,
        command: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        del command, target_url, timeout_seconds
        self.command_calls += 1
        return ToolResult(
            ok=True,
            tool="command",
            command=("true",),
            exit_code=0,
            stdout="ok",
            stderr="",
        )

    def run_python(
        self,
        *,
        code: str,
        target_url: str,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        return self.run_command(
            command=code,
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )


def _execute_command(
    tmp_path: Path,
    *,
    runtime: _TrackingRuntime,
    controller: TrafficPolicyController,
) -> ActionResult:
    audit = AuditStore(tmp_path / "audit.db")
    try:
        return execute_action(
            {"action": "run_command", "command": "true"},
            target_url="http://127.0.0.1/",
            runtime=runtime,
            state=AgentState(),
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=10_000,
            max_transcript_chars=80_000,
            traffic_policy=controller,
        )
    finally:
        audit.close()


def test_observe_policy_marks_opaque_command_accounting_lower_bound(tmp_path: Path) -> None:
    controller = TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(),
    )
    runtime = _TrackingRuntime()

    outcome = _execute_command(tmp_path, runtime=runtime, controller=controller)

    assert outcome.ok is True
    assert runtime.command_calls == 1
    snapshot = controller.snapshot()
    assert snapshot.unmetered_action_count == 1
    assert snapshot.accounting_status == "lower_bound"


def test_low_noise_policy_blocks_opaque_command_before_runtime(tmp_path: Path) -> None:
    controller = TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig.low_noise(max_physical_requests=10),
    )
    runtime = _TrackingRuntime()

    outcome = _execute_command(tmp_path, runtime=runtime, controller=controller)

    assert outcome.ok is False
    assert outcome.outcome == "blocked"
    assert runtime.command_calls == 0
    assert controller.snapshot().blocked_count == 1


def test_low_noise_policy_blocks_browser_probe_before_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig.low_noise(max_physical_requests=10),
    )
    monkeypatch.setattr(
        "ravage.agent_core.action_executor.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("browser subprocess must not start"),
    )
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {"action": "run_probe", "probe": "dom_execution"},
            target_url="http://127.0.0.1/",
            runtime=_TrackingRuntime(),
            state=AgentState(),
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=10_000,
            max_transcript_chars=80_000,
            traffic_policy=controller,
        )
    finally:
        audit.close()

    assert outcome.outcome == "blocked"
    assert controller.snapshot().blocked_count == 1


def test_probe_subprocess_receives_same_durable_policy_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(),
    )
    captured: dict[str, object] = {}

    def fake_run(*_args: object, **kwargs: object) -> argparse.Namespace:
        captured.update(json.loads(str(kwargs["input"])))
        return argparse.Namespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "status": "ok",
                    "ok": True,
                    "text": json.dumps(
                        {
                            "probe": "surface_map",
                            "ok": True,
                            "summary": "done",
                            "findings": [],
                            "requests": [],
                            "errors": [],
                        }
                    ),
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("ravage.agent_core.action_executor.subprocess.run", fake_run)
    audit = AuditStore(tmp_path / "audit.db")
    try:
        outcome = execute_action(
            {"action": "run_probe", "probe": "surface_map"},
            target_url="http://127.0.0.1/",
            runtime=_TrackingRuntime(),
            state=AgentState(),
            workspace=AgentWorkspace.open(tmp_path / "workspace"),
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=10_000,
            max_transcript_chars=80_000,
            traffic_policy=controller,
        )
    finally:
        audit.close()

    assert outcome.ok is True
    reference = captured["traffic_policy_reference"]
    assert isinstance(reference, dict)
    assert reference["state_path"] == str(controller.state_path)


def test_workspace_policy_resume_rejects_changed_low_noise_configuration(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    first = AIWebAgentSettings(
        traffic_policy_mode="low-noise",
        traffic_policy_max_physical_requests=20,
        traffic_policy_max_rps=0.5,
    )
    controller = _open_run_traffic_policy(
        settings=first,
        workspace=workspace,
        target_url="http://127.0.0.1/",
        roe_max_rps=5,
    )

    assert controller.state_path == workspace.root / "traffic-policy.json"
    assert controller.config.max_rps == 0.5
    changed = AIWebAgentSettings(
        traffic_policy_mode="low-noise",
        traffic_policy_max_physical_requests=21,
        traffic_policy_max_rps=0.5,
    )
    with pytest.raises(TrafficPolicyError, match="configuration"):
        _open_run_traffic_policy(
            settings=changed,
            workspace=workspace,
            target_url="http://127.0.0.1/",
            roe_max_rps=5,
        )


def test_policy_reference_cannot_weaken_settings(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    observed = TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(),
    )
    settings = AIWebAgentSettings(
        traffic_policy_mode="low-noise",
        traffic_policy_max_physical_requests=20,
        traffic_policy_max_rps=0.5,
        traffic_policy_reference=observed.to_reference(),
    )

    with pytest.raises(TrafficPolicyError, match="does not match agent settings"):
        _open_run_traffic_policy(
            settings=settings,
            workspace=workspace,
            target_url="http://127.0.0.1/",
            roe_max_rps=5,
        )


def _portswigger_profile_config() -> TrafficPolicyConfig:
    return replace(
        TrafficPolicyConfig.low_noise(max_physical_requests=24, max_rps=0.5),
        allowed_request_routes=("GET /catalog", "HEAD /catalog"),
        allowed_query_fields=("category", "searchterm"),
        allowed_explicit_headers=("accept", "accept-encoding", "user-agent"),
        allowed_form_fields=(),
        max_request_body_bytes=1_024,
        request_value_profile=PORTSWIGGER_DEMO_REQUEST_PROFILE,
        require_public_addresses=True,
    )


def test_policy_reference_preserves_code_owned_request_restrictions(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    config = _portswigger_profile_config()
    expected = TrafficPolicyController.open(
        workspace.root / "traffic-policy.json",
        target_url="https://vulnerable-website.com/catalog?category=Accessories",
        config=config,
    )
    settings = AIWebAgentSettings(
        traffic_policy_mode="low-noise",
        traffic_policy_max_physical_requests=24,
        traffic_policy_max_rps=0.5,
        traffic_policy_config=config,
        traffic_policy_reference=expected.to_reference(),
    )

    opened = _open_run_traffic_policy(
        settings=settings,
        workspace=workspace,
        target_url="https://vulnerable-website.com/catalog?category=Accessories",
        roe_max_rps=0.5,
    )

    assert opened.config == config


def test_portswigger_profile_preserves_the_models_compatible_sql_probe() -> None:
    proposed = {
        "action": "run_probe",
        "probe": "sqli_differential",
        "notes": "test category only",
    }
    settings = AIWebAgentSettings(
        traffic_policy_config=_portswigger_profile_config()
    )

    selected = _request_profile_probe_action(
        settings=settings,
        proposed_action=proposed,
    )

    assert selected == proposed


def test_portswigger_profile_rejects_unrelated_harness_probe_routing() -> None:
    settings = AIWebAgentSettings(
        traffic_policy_config=_portswigger_profile_config()
    )

    selected = _request_profile_probe_action(
        settings=settings,
        proposed_action={"action": "run_probe", "probe": "xss_context"},
    )

    assert selected is not None
    assert selected["probe"] == "sqli_differential"
    assert selected["strategy"] == "scope_locked_request_profile"


def test_ordinary_policy_does_not_lock_agent_probe_selection() -> None:
    selected = _request_profile_probe_action(
        settings=AIWebAgentSettings(traffic_policy_config=TrafficPolicyConfig()),
        proposed_action={"action": "run_probe", "probe": "xss_context"},
    )

    assert selected is None


def test_resume_rejects_missing_workspace_policy_ledger(tmp_path: Path) -> None:
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.state_path.write_text("{}", encoding="utf-8")

    with pytest.raises(TrafficPolicyError, match="does not exist"):
        _open_run_traffic_policy(
            settings=AIWebAgentSettings(),
            workspace=workspace,
            target_url="http://127.0.0.1/",
            roe_max_rps=5,
        )
