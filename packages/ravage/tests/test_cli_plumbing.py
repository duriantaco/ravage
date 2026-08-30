from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Self

import pytest
from ravage import __main__ as cli
from ravage import __version__, cli_tool_check, cli_tools
from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
)
from ravage.setup_checks import SetupDiagnostic
from ravage.traffic import TrafficPolicyConfig, TrafficPolicyController

EXPECTED_MODEL_REQUESTS = 4
MANUAL_INSTALL_NO_COMMANDS_EXIT = 2
INSTALL_FAILURE_EXIT = 13
RESULT_ENGAGEMENT_ID = "88888888-8888-4888-8888-888888888888"

BRIEF_YAML = """
engagement_id: "88888888-8888-4888-8888-888888888888"
scope:
  in_scope:
    - "http://127.0.0.1:8765"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "sql_injection"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 10
context:
  description: "Local test app with a vulnerable search endpoint."
  win_condition: "Validate the SQL injection finding."
  rules:
    - "Stay on the local target."
""".lstrip()

BRIEF_WITHOUT_DESCRIPTION_YAML = """
engagement_id: "88888888-8888-4888-8888-888888888888"
scope:
  in_scope:
    - "http://127.0.0.1:8765"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "capture_flag"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 10
""".lstrip()


@pytest.mark.parametrize("value", ["-0.1", "0", "1", "1.5", "nan", "inf", "-inf"])
def test_low_noise_cli_rejects_non_sub_one_rps(value: str) -> None:
    parser = argparse.ArgumentParser()
    parsed = argparse.Namespace(
        traffic_policy="low-noise",
        max_physical_requests=None,
        traffic_max_rps=float(value),
    )

    with pytest.raises(SystemExit):
        cli._resolve_traffic_policy_args(  # noqa: SLF001
            parser,
            parsed,
            default_mode="observe",
            roe_max_rps=5,
        )


def test_low_noise_cli_defaults_to_half_rps_and_300_physical_requests() -> None:
    parser = argparse.ArgumentParser()
    parsed = argparse.Namespace(
        traffic_policy=None,
        max_physical_requests=None,
        traffic_max_rps=None,
    )

    cli._resolve_traffic_policy_args(  # noqa: SLF001
        parser,
        parsed,
        default_mode="low-noise",
        roe_max_rps=5,
    )

    assert parsed.traffic_policy == "low-noise"
    assert parsed.max_physical_requests == 300
    assert parsed.traffic_max_rps == 0.5
    config = cli._traffic_policy_config(parsed)  # noqa: SLF001
    assert config.max_physical_requests == 300
    assert config.max_rps == 0.5


def test_observe_cli_rejects_enforcement_only_limits() -> None:
    parser = argparse.ArgumentParser()
    parsed = argparse.Namespace(
        traffic_policy="observe",
        max_physical_requests=12,
        traffic_max_rps=None,
    )

    with pytest.raises(SystemExit):
        cli._resolve_traffic_policy_args(  # noqa: SLF001
            parser,
            parsed,
            default_mode="observe",
            roe_max_rps=5,
        )


def test_local_cli_defaults_to_observe_without_enforcement_limits() -> None:
    parser = argparse.ArgumentParser()
    parsed = argparse.Namespace(
        traffic_policy=None,
        max_physical_requests=None,
        traffic_max_rps=None,
    )

    cli._resolve_traffic_policy_args(  # noqa: SLF001
        parser,
        parsed,
        default_mode="observe",
        roe_max_rps=5,
    )

    assert parsed.traffic_policy == "observe"
    assert cli._traffic_policy_config(parsed).mode.value == "observe"  # noqa: SLF001


def test_resume_inherits_omitted_saved_low_noise_policy(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    controller = cli.TrafficPolicyController.open(
        workspace / "traffic-policy.json",
        target_url="http://127.0.0.1/",
        config=cli.TrafficPolicyConfig.low_noise(
            max_physical_requests=37,
            max_rps=0.25,
        ),
    )
    parsed = argparse.Namespace(
        traffic_policy=None,
        max_physical_requests=None,
        traffic_max_rps=None,
    )
    parser = argparse.ArgumentParser()

    cli._inherit_resume_traffic_policy_args(  # noqa: SLF001
        parser,
        parsed,
        workspace=workspace,
    )
    cli._resolve_traffic_policy_args(  # noqa: SLF001
        parser,
        parsed,
        default_mode="observe",
        roe_max_rps=5,
    )

    assert parsed.traffic_policy == "low-noise"
    assert parsed.max_physical_requests == 37
    assert parsed.traffic_max_rps == 0.25
    assert cli._traffic_policy_config(parsed) == controller.config  # noqa: SLF001


def test_resume_preserves_explicit_policy_override_for_mismatch_rejection(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    controller = cli.TrafficPolicyController.open(
        workspace / "traffic-policy.json",
        target_url="http://127.0.0.1/",
        config=cli.TrafficPolicyConfig.low_noise(
            max_physical_requests=37,
            max_rps=0.25,
        ),
    )
    parsed = argparse.Namespace(
        traffic_policy="low-noise",
        max_physical_requests=38,
        traffic_max_rps=None,
    )
    parser = argparse.ArgumentParser()

    cli._inherit_resume_traffic_policy_args(  # noqa: SLF001
        parser,
        parsed,
        workspace=workspace,
    )
    cli._resolve_traffic_policy_args(  # noqa: SLF001
        parser,
        parsed,
        default_mode="observe",
        roe_max_rps=5,
    )

    assert parsed.max_physical_requests == 38
    with pytest.raises(cli.TrafficPolicyError, match="configuration changed"):
        cli.TrafficPolicyController.open(
            controller.state_path,
            target_url="http://127.0.0.1/",
            config=cli._traffic_policy_config(parsed),  # noqa: SLF001
            require_existing=True,
        )


def test_legacy_observe_resume_marks_missing_traffic_ledger_for_lower_bound(
    tmp_path: Path,
) -> None:
    parser = argparse.ArgumentParser()
    parsed = argparse.Namespace(
        traffic_policy=None,
        max_physical_requests=None,
        traffic_max_rps=None,
    )

    cli._inherit_resume_traffic_policy_args(  # noqa: SLF001
        parser,
        parsed,
        workspace=tmp_path / "workspace",
    )

    assert parsed.traffic_policy == "observe"
    assert parsed.legacy_resume_without_traffic_ledger is True


def test_low_noise_resume_rejects_missing_traffic_policy_ledger(tmp_path: Path) -> None:
    parser = argparse.ArgumentParser()
    parsed = argparse.Namespace(
        traffic_policy="low-noise",
        max_physical_requests=300,
        traffic_max_rps=0.5,
    )

    with pytest.raises(SystemExit):
        cli._inherit_resume_traffic_policy_args(  # noqa: SLF001
            parser,
            parsed,
            workspace=tmp_path / "workspace",
        )


def test_legacy_observe_resume_creates_lower_bound_ledger_before_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_path = workspace / "working_state.json"
    save_agent_state(
        state_path,
        target_url="http://127.0.0.1:8765",
        state=AgentState(turn=1),
    )
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "run_ai_web_agent", lambda **kwargs: seen.update(kwargs))

    cli.main(
        [
            "--brief",
            str(brief_path),
            "--target-url",
            "http://127.0.0.1:8765",
            "--workspace-dir",
            str(workspace),
            "--resume-from",
            str(state_path),
            "--model-profile",
            "local-ollama",
            "--display",
            "quiet",
        ]
    )

    inspection = cli.load_traffic_policy_snapshot(workspace / "traffic-policy.json")
    assert inspection.snapshot.accounting_status == "lower_bound"
    assert inspection.snapshot.unmetered_action_count == 1
    settings = seen["settings"]
    assert settings.traffic_policy_mode == "observe"
    assert settings.traffic_policy_reference is not None


def test_legacy_direct_remote_agent_defaults_to_canonical_low_noise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote_url = "https://authorized.example/app"
    brief_path = tmp_path / "remote-brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", remote_url),
        encoding="utf-8",
    )
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "run_ai_web_agent", lambda **kwargs: seen.update(kwargs))

    cli.main(
        [
            "--brief",
            str(brief_path),
            "--target-url",
            remote_url,
            "--workspace-dir",
            str(tmp_path / "workspace"),
            "--authorized-remote-target",
            "--display",
            "quiet",
        ]
    )

    settings = seen["settings"]
    assert settings.traffic_policy_mode == "low-noise"
    assert settings.traffic_policy_max_physical_requests == 300
    assert settings.traffic_policy_max_rps == 0.5
    assert settings.tool_runtime_mode == "docker"


def test_legacy_direct_remote_resume_never_silently_downgrades_to_observe(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    remote_url = "https://authorized.example/app"
    brief_path = tmp_path / "remote-brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", remote_url),
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_path = workspace / "working_state.json"
    save_agent_state(state_path, target_url=remote_url, state=AgentState(turn=1))

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "--brief",
                str(brief_path),
                "--target-url",
                remote_url,
                "--workspace-dir",
                str(workspace),
                "--resume-from",
                str(state_path),
                "--authorized-remote-target",
                "--display",
                "quiet",
            ]
        )

    assert exc_info.value.code == 2
    assert "valid traffic policy ledger" in capsys.readouterr().err


def test_legacy_direct_host_runtime_requires_explicit_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "run_ai_web_agent", lambda **kwargs: seen.update(kwargs))

    cli.main(
        [
            "--brief",
            str(brief_path),
            "--target-url",
            "http://127.0.0.1:8765",
            "--workspace-dir",
            str(tmp_path / "workspace"),
            "--tool-runtime",
            "host",
            "--display",
            "quiet",
        ]
    )

    assert seen["settings"].tool_runtime_mode == "host"


def test_observe_resume_rejects_corrupt_traffic_policy_ledger(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "traffic-policy.json").write_text("{malformed", encoding="utf-8")
    parser = argparse.ArgumentParser()
    parsed = argparse.Namespace(
        traffic_policy=None,
        max_physical_requests=None,
        traffic_max_rps=None,
    )

    with pytest.raises(SystemExit):
        cli._inherit_resume_traffic_policy_args(  # noqa: SLF001
            parser,
            parsed,
            workspace=workspace,
        )


def _write_result_brief(
    tmp_path: Path,
    *,
    filename: str = "brief.yaml",
    in_scope: str = "https://example.test",
) -> Path:
    brief_path = tmp_path / filename
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", in_scope),
        encoding="utf-8",
    )
    return brief_path


def _result_finding(
    finding_id: str,
    *,
    engagement_id: str = RESULT_ENGAGEMENT_ID,
    url: str = "https://example.test/search?q=test",
    vuln_class: str = "sql_injection",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "finding_id": finding_id,
        "engagement_id": engagement_id,
        "status": "confirmed",
        "vuln_class": vuln_class,
        "severity": "high",
        "endpoint": {"method": "GET", "url": url},
        "exploit_steps": [{"http_request": "GET /search"}],
        "proof": {
            "http_request_final": "GET /search",
            "response_final": "security differential",
            "impact_description": "Attacker-controlled behavior was confirmed.",
        },
    }
    return payload


def test_cli_version_reports_semver(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--version"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out.strip()
    assert output == f"ravage {__version__}"
    assert re.fullmatch(r"ravage \d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", output)


def test_cli_top_level_help_shows_setup_flow(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "ravage init" in output
    assert "ravage setup check" in output
    assert "ravage brief template" in output
    assert "ravage code-bug" in output
    assert "ravage tools check" in output
    assert "Start here — localhost app" in output
    assert "Start here — authorized URL" in output
    assert "Optional:" in output
    assert "challenge descriptions and live target evidence" in output


def test_attack_help_explains_both_runtime_paths(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["attack", "--help"])

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "ravage init URL" in output
    assert "follow the printed [next]" in output
    assert "--authorized-remote-target" in output
    assert "--tool-runtime docker" in output


class OpenAIStubHandler(BaseHTTPRequestHandler):
    actions: list[dict[str, object]]
    requests_seen: list[dict[str, object]]

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        request_payload = json.loads(raw_body)
        self.requests_seen.append(request_payload)
        action = self.actions.pop(0)
        response_payload = {
            "id": "chatcmpl-cli-test",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(action),
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        response_body = json.dumps(response_payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return


class OpenAIStubServer:
    def __init__(self, actions: list[dict[str, object]]) -> None:
        self._handler: type[OpenAIStubHandler] = type(
            "CliOpenAIStubHandler",
            (OpenAIStubHandler,),
            {"actions": actions, "requests_seen": []},
        )
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/v1"

    @property
    def requests_seen(self) -> list[dict[str, object]]:
        return self._handler.requests_seen


def test_cli_tools_list_includes_allowlisted_runtime_tools(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(["tools", "list"])

    output = capsys.readouterr().out
    assert "nmap\n" in output
    assert "nikto\n" in output
    assert "ncat\n" in output
    assert "openssl\n" in output


def test_cli_brief_template_defaults_to_broad_assessment(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(["brief", "template", "--target-url", "http://127.0.0.1:8080"])

    payload = json.loads(json.dumps(cli.yaml.safe_load(capsys.readouterr().out)))
    assert payload["scope"]["in_scope"] == ["http://127.0.0.1:8080"]
    assert payload["objectives"] == ["web_application_assessment"]
    assert payload["context"]["description"].startswith("TODO:")
    assert "evidence-backed vulnerabilities" in payload["context"]["win_condition"]
    assert "flag" not in payload["context"]["win_condition"].lower()
    assert all("flag" not in rule.lower() for rule in payload["context"]["rules"])
    assert payload["context"]["rules"]


def test_cli_brief_template_accepts_remote_url_without_sending_traffic(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(
        [
            "brief",
            "template",
            "--target-url",
            "https://staging.example.test/app",
        ]
    )

    payload = cli.yaml.safe_load(capsys.readouterr().out)
    assert payload["scope"]["in_scope"] == ["https://staging.example.test/app"]


def test_cli_brief_template_accepts_capture_flag_objective_without_hints(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(
        [
            "brief",
            "template",
            "--target-url",
            "http://127.0.0.1:8080",
            "--objective",
            "capture_flag",
        ]
    )

    payload = json.loads(json.dumps(cli.yaml.safe_load(capsys.readouterr().out)))
    assert payload["objectives"] == ["capture_flag"]
    assert payload["context"]["description"].startswith("TODO:")
    assert "exact flag value" in payload["context"]["win_condition"]
    assert any("proof or flag values" in rule for rule in payload["context"]["rules"])


def test_cli_init_writes_env_and_brief(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    env_path = tmp_path / ".env"
    brief_path = tmp_path / "brief.yaml"

    cli.main(
        [
            "init",
            "--target-url",
            "http://127.0.0.1:8080",
            "--env-file",
            str(env_path),
            "--brief",
            str(brief_path),
        ]
    )

    env_text = env_path.read_text(encoding="utf-8")
    payload = cli.yaml.safe_load(brief_path.read_text(encoding="utf-8"))
    output = capsys.readouterr().out
    assert "OPENAI_API_KEY=" in env_text
    assert "RAVAGE_OPENAI_LOW_MODEL=gpt-5.4-mini-2026-03-17" in env_text
    assert payload["scope"]["in_scope"] == ["http://127.0.0.1:8080"]
    assert payload["objectives"] == ["web_application_assessment"]
    assert payload["context"]["description"].startswith("TODO:")
    assert "evidence-backed vulnerabilities" in payload["context"]["win_condition"]
    assert all("flag" not in rule.lower() for rule in payload["context"]["rules"])
    assert "ravage doctor --workflow scan" in output
    assert "ravage scan" in output
    assert "--probe surface_map --report" in output
    assert "[optional]" in output
    assert f"source {env_path}" not in output
    assert f"--env-file {env_path}" in output
    assert "--tool-runtime host" not in output
    assert "--model-profile hosted-openai" not in output


def test_cli_init_remote_url_prints_authorized_attack_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env"

    cli.main(
        [
            "init",
            "--target-url",
            "https://staging.example.test/app",
            "--brief",
            str(brief_path),
            "--env-file",
            str(env_path),
        ]
    )

    output = capsys.readouterr().out
    assert "--authorized-remote-target" in output
    assert "--tool-runtime docker" not in output


def test_cli_init_refuses_to_overwrite_existing_files(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    brief_path = tmp_path / "brief.yaml"
    env_path.write_text("OPENAI_API_KEY=existing\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="already exists"):
        cli.main(["init", "--env-file", str(env_path), "--brief", str(brief_path)])


def test_cli_setup_check_reports_ready_setup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env"
    ravage_command = tmp_path / "bin" / "ravage"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    env_path.write_text("OPENAI_API_KEY=test-key\n", encoding="utf-8")

    def fake_which(command: str) -> str | None:
        return str(ravage_command) if command == "ravage" else None

    def fake_tool_check_report(*, image: str) -> dict[str, object]:
        assert image
        return {
            "docker": {"available": True, "ready": True, "tools": {}, "error": None},
            "recommendation": "use --tool-runtime auto or --tool-runtime docker",
        }

    monkeypatch.setattr(cli.shutil, "which", fake_which)
    monkeypatch.setattr(
        cli,
        "_stale_entrypoint_detail",
        lambda _path: None,
    )
    monkeypatch.setattr(cli, "_tool_check_report", fake_tool_check_report)
    monkeypatch.setattr(
        cli,
        "target_reachability_diagnostic",
        lambda *_args, **_kwargs: SetupDiagnostic(
            name="target",
            status="ok",
            detail="HTTP 200 from local test target",
        ),
    )

    cli.main(
        [
            "setup",
            "check",
            "--brief",
            str(brief_path),
            "--env-file",
            str(env_path),
            "--model-profile",
            "hosted-openai",
            "--model-tier",
            "low",
        ]
    )

    output = capsys.readouterr().out
    assert "[ok] python" in output
    assert "[ok] entrypoint" in output
    assert "[ok] tools" in output
    assert "[ok] model" in output
    assert "[ok] brief" in output
    assert "[next]" in output
    assert "--tool-runtime host" not in output
    assert "--allow-paid-models --report" in output


def test_cli_setup_check_accepts_remote_low_noise_without_docker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "remote-brief.yaml"
    env_path = tmp_path / ".env.ravage"
    ravage_command = tmp_path / "bin" / "ravage"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", "https://staging.example.test"),
        encoding="utf-8",
    )
    env_path.write_text("OPENAI_API_KEY=test-key\n", encoding="utf-8")

    monkeypatch.setattr(
        cli.shutil,
        "which",
        lambda command: str(ravage_command) if command == "ravage" else None,
    )
    monkeypatch.setattr(cli, "_stale_entrypoint_detail", lambda _path: None)
    monkeypatch.setattr(
        cli,
        "target_reachability_diagnostic",
        lambda *_args, **_kwargs: SetupDiagnostic(
            name="target",
            status="ok",
            detail="HTTP 200 from authorized remote target",
        ),
    )
    def unexpected_tools(**_kwargs: object) -> dict[str, object]:
        pytest.fail("default remote low-noise doctor must not require a process runtime")

    monkeypatch.setattr(cli, "_setup_check_tools", unexpected_tools)

    cli.main(
        [
            "setup",
            "check",
            "--brief",
            str(brief_path),
            "--env-file",
            str(env_path),
            "--model-profile",
            "hosted-openai",
            "--model-tier",
            "low",
            "--authorized-remote-target",
        ]
    )

    output = capsys.readouterr().out
    assert "[ok] target" in output
    assert "authorized remote target" in output
    assert "low-noise attack uses scoped native metered HTTP" in output
    assert "--authorized-remote-target" in output
    assert "--tool-runtime docker" not in output


def test_cli_setup_check_requires_docker_for_explicit_remote_observe_lane(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "remote-brief.yaml"
    env_path = tmp_path / ".env.ravage"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", "https://staging.example.test"),
        encoding="utf-8",
    )
    env_path.write_text("OPENAI_API_KEY=test-key\n", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "target_reachability_diagnostic",
        lambda *_args, **_kwargs: SetupDiagnostic(
            name="target",
            status="ok",
            detail="HTTP 200 from authorized remote target",
        ),
    )

    def check_tools(*, tool_image: str, require_docker: bool) -> dict[str, object]:
        assert tool_image
        assert require_docker is True
        return {"name": "tools", "status": "ok", "detail": "Docker ready"}

    monkeypatch.setattr(cli, "_setup_check_tools", check_tools)

    cli.main(
        [
            "doctor",
            "--workflow",
            "attack",
            "--brief",
            str(brief_path),
            "--env-file",
            str(env_path),
            "--model-profile",
            "hosted-openai",
            "--model-tier",
            "low",
            "--authorized-remote-target",
            "--traffic-policy",
            "observe",
        ]
    )

    output = capsys.readouterr().out
    assert "Docker ready" in output
    assert "--traffic-policy observe --tool-runtime docker" in output


def test_cli_setup_check_rejects_unacknowledged_remote_brief(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "remote-brief.yaml"
    env_path = tmp_path / ".env.ravage"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", "https://staging.example.test"),
        encoding="utf-8",
    )
    env_path.write_text("OPENAI_API_KEY=test-key\n", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "_setup_check_tools",
        lambda **_kwargs: {"name": "tools", "status": "ok", "detail": "ready"},
    )

    with pytest.raises(SystemExit) as captured:
        cli.main(
            [
                "doctor",
                "--workflow",
                "attack",
                "--brief",
                str(brief_path),
                "--env-file",
                str(env_path),
                "--model-profile",
                "hosted-openai",
                "--model-tier",
                "low",
            ]
        )

    assert captured.value.code == 1
    output = capsys.readouterr().out
    assert "[fail] target" in output
    assert "--authorized-remote-target" in output
    assert "prerequisites are ready" not in output


def test_authenticated_remote_doctor_does_not_require_docker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "remote-auth-brief.yaml"
    env_path = tmp_path / ".env.ravage"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", "https://staging.example.test")
        + """
authentication:
  identities:
    - alias: service
      roles: [api]
      flow:
        kind: bearer
        secret_refs:
          token:
            provider: environment
            key: SERVICE_TOKEN
      health_check:
        endpoint:
          url: https://staging.example.test/api/me
          scope: target
        success_statuses: [200]
""",
        encoding="utf-8",
    )
    env_path.write_text("OPENAI_API_KEY=test-key\nSERVICE_TOKEN=test-token\n", encoding="utf-8")

    def unexpected_tools(**_kwargs: object) -> dict[str, object]:
        pytest.fail("managed authenticated doctor must not require a process runtime")

    monkeypatch.setattr(cli, "_setup_check_tools", unexpected_tools)

    with pytest.raises(SystemExit) as captured:
        cli.main(
            [
                "doctor",
                "--workflow",
                "attack",
                "--brief",
                str(brief_path),
                "--env-file",
                str(env_path),
                "--model-profile",
                "hosted-openai",
                "--model-tier",
                "low",
            ]
        )

    assert captured.value.code == 1
    output = capsys.readouterr().out
    assert "does not require Docker" in output
    assert "process and Docker runtimes are intentionally unavailable" in output


def test_setup_check_requires_docker_for_remote_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "_tool_check_report",
        lambda *, image: {
            "host": {
                "curl": {"available": True},
                "python3": {"available": True},
            },
            "docker": {"available": False, "error": f"missing {image}"},
            "recommendation": "start Docker",
        },
    )

    local = cli._setup_check_tools(tool_image="ravage-kali:latest")  # noqa: SLF001
    remote = cli._setup_check_tools(  # noqa: SLF001
        tool_image="ravage-kali:latest", require_docker=True
    )

    assert local["status"] == "ok"
    assert remote["status"] == "fail"
    assert "Docker is required for the selected attack runtime" in str(remote["detail"])


def test_setup_check_rejects_installed_but_unready_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "_tool_check_report",
        lambda *, image: {
            "host": {},
            "docker": {
                "available": True,
                "ready": False,
                "error": "Docker tool probe timed out",
                "image": image,
            },
            "recommendation": "fix the Docker runtime check",
        },
    )

    diagnostic = cli._setup_check_tools(  # noqa: SLF001
        tool_image="ravage-kali:latest",
        require_docker=True,
    )

    assert diagnostic["status"] == "fail"
    assert "Docker is required" in str(diagnostic["detail"])


def test_cli_setup_check_fails_when_description_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env"
    brief_path.write_text(BRIEF_WITHOUT_DESCRIPTION_YAML, encoding="utf-8")
    env_path.write_text("OPENAI_API_KEY=test-key\n", encoding="utf-8")

    ready_route = SimpleNamespace(
        provider="openai",
        model="gpt-test",
        missing_env=(),
        ready=True,
    )

    monkeypatch.setattr(
        cli,
        "_setup_check_python",
        lambda: {"name": "python", "status": "ok", "detail": "Python 3.12"},
    )
    monkeypatch.setattr(
        cli,
        "_setup_check_entrypoint",
        lambda: {"name": "entrypoint", "status": "ok", "detail": "ok"},
    )
    monkeypatch.setattr(
        cli,
        "_setup_check_tools",
        lambda *, tool_image, require_docker=False: {
            "name": "tools",
            "status": "ok",
            "detail": f"{tool_image} require_docker={require_docker}",
        },
    )
    monkeypatch.setattr(cli, "load_model_registry", lambda _path: object())
    monkeypatch.setattr(cli, "resolve_model_routes", lambda *_args, **_kwargs: [ready_route])
    monkeypatch.setattr(cli, "ready_model_routes", tuple)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "setup",
                "check",
                "--brief",
                str(brief_path),
                "--env-file",
                str(env_path),
                "--model-profile",
                "hosted-openai",
                "--model-tier",
                "low",
            ]
        )

    output = capsys.readouterr().out
    assert exc_info.value.code == 1
    assert "[fail] description" in output
    assert "context.description" in output


def test_cli_setup_check_fails_with_missing_model_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    env_path = tmp_path / ".env"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    env_path.write_text("", encoding="utf-8")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def fake_setup_check_tools(
        *, tool_image: str, require_docker: bool = False
    ) -> dict[str, object]:
        assert tool_image
        assert require_docker is True
        return {"name": "tools", "status": "ok", "detail": "ok"}

    monkeypatch.setattr(
        cli,
        "_setup_check_python",
        lambda: {"name": "python", "status": "ok", "detail": "Python 3.12"},
    )
    monkeypatch.setattr(
        cli,
        "_setup_check_entrypoint",
        lambda: {"name": "entrypoint", "status": "ok", "detail": "ok"},
    )
    monkeypatch.setattr(cli, "_setup_check_tools", fake_setup_check_tools)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "setup",
                "check",
                "--brief",
                str(brief_path),
                "--env-file",
                str(env_path),
                "--model-profile",
                "hosted-openai",
                "--model-tier",
                "low",
            ]
        )

    output = capsys.readouterr().out
    assert exc_info.value.code == 1
    assert "[fail] model" in output
    assert "OPENAI_API_KEY" in output


def test_setup_check_probes_ready_local_model_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = SimpleNamespace(
        provider="ollama",
        model="qwen2.5-coder:14b",
        base_url="http://localhost:11434/v1",
        api_key_env=None,
        missing_env=(),
        ready=True,
    )
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(cli, "load_model_registry", lambda _path: object())
    monkeypatch.setattr(cli, "resolve_model_routes", lambda *_args, **_kwargs: [route])
    monkeypatch.setattr(cli, "ready_model_routes", tuple)

    def probe(**kwargs: object) -> SetupDiagnostic:
        calls.append(kwargs)
        return SetupDiagnostic("model", "ok", "local model is available")

    monkeypatch.setattr(cli, "local_model_diagnostic", probe)

    diagnostic = cli._setup_model_check(  # noqa: SLF001
        model_config=None,
        model_profile="local-ollama",
        model_tier="mid",
        env_file=None,
    )

    assert diagnostic["status"] == "ok"
    assert calls == [
        {
            "provider": "ollama",
            "model": "qwen2.5-coder:14b",
            "base_url": "http://localhost:11434/v1",
            "api_key": "",
            "required": True,
        }
    ]


def test_cli_setup_check_detects_stale_entrypoint(tmp_path: Path) -> None:
    stale_path = tmp_path / "ravage"
    stale_path.write_text("from orchestrator import main\n", encoding="utf-8")

    detail = cli._stale_entrypoint_detail(stale_path)  # noqa: SLF001

    assert detail is not None
    assert "old orchestrator entrypoint" in detail


def test_cli_attack_help_points_to_brief_template(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["attack", "--help"])

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "ravage brief template" in output
    assert "challenge descriptions and" in output
    assert "--authorized-remote-target" in output
    assert "--operational-profile" in output


def test_cli_attack_remote_target_stays_blocked_without_explicit_authorization(
    tmp_path: Path,
) -> None:
    remote_url = "https://authorized.example/app"
    brief_path = tmp_path / "remote-brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", remote_url),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "attack",
                str(brief_path),
                "--target-url",
                remote_url,
                "--autonomous-route",
                "--autonomous-route-engine",
                "agent-graph",
            ]
        )

    assert exc_info.value.code == 2


def test_cli_scan_runs_explicitly_authorized_remote_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    remote_url = "https://staging.example.test/app"
    brief_path = tmp_path / "remote-brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", remote_url),
        encoding="utf-8",
    )
    seen: dict[str, object] = {}

    def fake_probe(_probe: str, **kwargs: object) -> SimpleNamespace:
        seen.update(kwargs)
        return SimpleNamespace(
            ok=True,
            summary="scoped remote probe",
            findings=[],
            requests=[],
            errors=[],
            to_text=lambda: "{}",
        )

    monkeypatch.setattr(cli, "run_builtin_probe", fake_probe)
    cli.main(
        [
            "scan",
            str(brief_path),
            "--authorized-remote-target",
            "--probe",
            "surface_map",
            "--run-dir",
            str(tmp_path / "scan-run"),
        ]
    )

    assert seen["target_url"] == remote_url
    assert seen["allow_remote_target"] is True
    assert seen["in_scope"] == [remote_url]


def test_cli_attack_remote_target_runs_full_agent_without_agent_graph(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    remote_url = "https://authorized.example/app"
    brief_path = tmp_path / "remote-brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", remote_url),
        encoding="utf-8",
    )

    run_dir = tmp_path / "run"
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "run_ai_web_agent", lambda **kwargs: seen.update(kwargs))

    cli.main(
        [
            "attack",
            str(brief_path),
            "--target-url",
            remote_url,
            "--run-dir",
            str(run_dir),
            "--authorized-remote-target",
        ]
    )

    settings = seen["settings"]
    assert seen["target_url"] == remote_url
    assert settings.allow_remote_target is True
    assert settings.tool_runtime_mode == "docker"
    assert settings.traffic_policy_mode == "low-noise"
    assert settings.traffic_policy_max_physical_requests == 300
    assert settings.traffic_policy_max_rps == 0.5
    assert settings.traffic_policy_reference is not None
    output = capsys.readouterr().out
    assert "remote target traffic uses the native metered HTTP lane" in output
    assert "remote tools are forced" not in output


def test_cli_attack_routes_explicit_remote_target_to_full_low_noise_agent_graph(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    remote_url = "https://authorized.example/app"
    brief_path = tmp_path / "remote-brief.yaml"
    run_dir = tmp_path / "run"
    brief_path.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", remote_url),
        encoding="utf-8",
    )
    seen: dict[str, object] = {}

    def fake_graph_route(**kwargs: object) -> object:
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(
        cli,
        "run_selected_autonomous_route",
        fake_graph_route,
    )

    cli.main(
        [
            "attack",
            str(brief_path),
            "--target-url",
            remote_url,
            "--run-dir",
            str(run_dir),
            "--authorized-remote-target",
            "--autonomous-route",
            "--autonomous-route-engine",
            "agent-graph",
            "--autonomous-route-max-requests",
            "8",
        ]
    )

    settings = seen["settings"]
    assert settings.allow_remote_target is True
    assert settings.tool_runtime_mode == "docker"
    assert settings.traffic_policy_mode == "low-noise"
    assert settings.traffic_policy_reference is not None
    assert seen["operational_profile"] is GraphOperationalProfileName.LOW_NOISE
    assert seen["max_model_requests"] == 8
    assert seen["engine"] == "agent-graph"


def test_cli_attack_blocks_missing_description(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_WITHOUT_DESCRIPTION_YAML, encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["attack", str(brief_path)])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "context.description" in captured.err
    assert "--allow-empty-description" in captured.err


def test_cli_attack_warns_for_local_model_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")

    def fake_run(_argv: list[str], _stdout_path: Path) -> int:
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)

    cli.main(
        [
            "attack",
            str(brief_path),
            "--run-dir",
            str(tmp_path / "local-run"),
            "--model-profile",
            "local-ollama",
            "--no-tool-recon",
        ]
    )

    output = capsys.readouterr().out
    assert "local models are useful for setup and iteration" in output


def test_cli_attack_does_not_warn_for_hosted_model_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        assert "--allow-paid-models" in argv
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    cli.main(
        [
            "attack",
            str(brief_path),
            "--run-dir",
            str(tmp_path / "hosted-run"),
            "--model-profile",
            "hosted-openai",
            "--allow-paid-models",
            "--no-tool-recon",
        ]
    )

    output = capsys.readouterr().out
    assert "local models are useful for setup and iteration" not in output


def test_cli_attack_blocks_paid_route_without_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "attack",
                str(brief_path),
                "--model-profile",
                "hosted-openai",
                "--no-tool-recon",
            ]
        )

    assert exc_info.value.code == 2
    assert "paid-risk model route selected" in capsys.readouterr().err


def test_cli_attack_forwards_display_mode_to_agent_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)

    cli.main(
        [
            "attack",
            str(brief_path),
            "--run-dir",
            str(tmp_path / "display-run"),
            "--display",
            "quiet",
            "--no-tool-recon",
        ]
    )

    command = calls[0]
    assert command[command.index("--display") + 1] == "quiet"


def test_attack_result_distinguishes_confirmed_findings_from_candidate_signals(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _write_result_brief(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    traffic_policy = TrafficPolicyController.open(
        workspace / "traffic-policy.json",
        target_url="http://127.0.0.1:8765",
        config=TrafficPolicyConfig(),
    )
    traffic_policy.record_unmetered_action()
    events_path = workspace / "events.jsonl"
    events = [
        {
            "kind": "tool_run_probe",
            "payload": {
                "display_summary": {
                    "findings": 3,
                    "finding_types": ["xss_reflection_context"],
                }
            },
        },
        {
            "event_id": "event-finding-1",
            "kind": "finding_confirmed",
            "payload": {
                "finding_id": "finding-1",
                "engagement_id": RESULT_ENGAGEMENT_ID,
                "status": "confirmed",
                "vuln_class": "idor",
                "severity": "high",
                "endpoint": {
                    "method": "GET",
                    "url": "https://example.test/account?token=do-not-print",
                    "params": [{"name": "account_id"}],
                },
                "exploit_steps": [{"http_request": "GET /account"}],
                "proof": {
                    "http_request_final": "GET /account",
                    "response_final": "FLAG{do-not-print}",
                    "impact_description": "Another account can be accessed.",
                },
            },
        },
        {"kind": "agent_finished", "payload": {"status": "completed"}},
    ]
    events_path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    audit_path = tmp_path / "audit.db"
    audit_path.write_text("", encoding="utf-8")
    report_path = tmp_path / "report.md"
    report_path.write_text("# report\n", encoding="utf-8")

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=brief_path,
        workspace_dir=workspace,
        audit_path=audit_path,
        report_path=report_path,
        flag_objective=False,
    )

    output = capsys.readouterr().out
    assert "RAVAGE // RESULT" in output
    assert "traffic   0 physical requests · lower bound · opaque actions 1" in output
    assert "confirmed 1 vulnerability · High 1" in output
    assert "finding 1 High · idor · GET /account · parameters=account_id" in output
    assert f"source 1  base · {events_path} · event=event-finding-1 · finding=finding-1" in output
    assert "signals   3 probe observations (not confirmations)" in output
    assert f"report    {report_path}" in output
    assert f"events    base · {events_path}" in output
    assert "proof     " not in output
    assert "do-not-print" not in output
    canonical_report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert canonical_report["artifacts"]["markdown_report_path"] == str(report_path)


def test_attack_result_reports_flag_only_for_flag_objectives(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _write_result_brief(tmp_path, filename="brief with spaces.yaml")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    events_path = workspace / "events.jsonl"
    events_path.write_text(
        "".join(
            json.dumps(event) + "\n"
            for event in (
                {
                    "kind": "tool_run_probe",
                    "payload": {
                        "observation_id": "observation-proof",
                        "action_id": "action-proof",
                        "recognized_proofs": ["FLAG{never-render-this}"],
                    },
                },
                {
                    "kind": "flag_captured",
                    "payload": {
                        "flag": "FLAG{never-render-this}",
                        "engagement_id": RESULT_ENGAGEMENT_ID,
                        "source_observation_id": "observation-proof",
                        "source_kind": "tool_run_probe",
                        "action_id": "action-proof",
                    },
                },
            )
        ),
        encoding="utf-8",
    )

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=brief_path,
        workspace_dir=workspace,
        audit_path=tmp_path / "missing.db",
        report_path=None,
        flag_objective=True,
    )

    output = capsys.readouterr().out
    assert "proof     1 flag found" in output
    assert f"report    {tmp_path / 'report.json'}" in output
    assert "never-render-this" not in output


def test_attack_result_does_not_count_unlinked_stale_proof_event(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _write_result_brief(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "events.jsonl").write_text(
        json.dumps(
            {
                "kind": "flag_captured",
                "payload": {
                    "flag": "FLAG{stale-unit-proof}",
                    "engagement_id": RESULT_ENGAGEMENT_ID,
                    "source_observation_id": "missing-observation",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=brief_path,
        workspace_dir=workspace,
        audit_path=tmp_path / "missing.db",
        report_path=None,
        flag_objective=True,
    )

    output = capsys.readouterr().out
    assert "proof     0 flags found" in output
    assert "stale-unit-proof" not in output
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["captured_proofs"]["count"] == 0
    assert report["run"]["flag_found"] is False


def test_attack_result_ignores_unverified_findings_and_reads_autonomous_events(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _write_result_brief(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "events.jsonl").write_text(
        "\n".join(
            (
                json.dumps(
                    {
                        "event_id": "event-unverified",
                        "kind": "finding_confirmed",
                        "payload": {
                            "finding_id": "unverified",
                            "engagement_id": RESULT_ENGAGEMENT_ID,
                            "status": "confirmed",
                            "vuln_class": "sql_injection",
                            "severity": "critical",
                        },
                    }
                ),
                json.dumps(
                    {
                        "kind": "agent_finished",
                        "payload": {
                            "status": "incomplete",
                            "termination_reason": "max_turns_reached",
                        },
                    }
                ),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    graph_workspace = workspace / "autonomous-route" / "agent-graph"
    graph_workspace.mkdir(parents=True)
    route_events = workspace / "autonomous-route" / "events.jsonl"
    route_events.write_text(
        json.dumps(
            {
                "event_id": "event-route-started",
                "kind": "frontier_route_started",
                "payload": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    graph_events = graph_workspace / "events.jsonl"
    graph_events.write_text(
        "\n".join(
            (
                json.dumps(
                    {
                        "event_id": "event-verified",
                        "kind": "finding_confirmed",
                        "payload": {
                            "finding_id": "verified",
                            "engagement_id": RESULT_ENGAGEMENT_ID,
                            "status": "confirmed",
                            "vuln_class": "path_traversal",
                            "severity": "medium",
                            "endpoint": {
                                "method": "GET",
                                "url": "https://example.test/files/12345?name=secret",
                                "params": [{"name": "name"}],
                            },
                            "exploit_steps": [{"http_request": "GET /files/:id"}],
                            "proof": {
                                "http_request_final": "GET /files/:id",
                                "response_final": "File contents returned",
                                "impact_description": "Arbitrary files can be read.",
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "kind": "autonomous_graph_finished",
                        "payload": {"status": "completed"},
                    }
                ),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=brief_path,
        workspace_dir=workspace,
        audit_path=tmp_path / "missing.db",
        report_path=None,
        flag_objective=False,
    )

    output = capsys.readouterr().out
    assert "status    completed" in output
    assert "confirmed 1 vulnerability · Medium 1" in output
    assert "finding 1 Medium · path traversal · GET /files/:id · parameters=name" in output
    assert f"source 1  graph · {graph_events} · event=event-verified · finding=verified" in output
    assert "sql injection" not in output
    assert f"events    base · {workspace / 'events.jsonl'}" in output
    assert f"events    route · {route_events}" in output
    assert f"events    graph · {graph_events}" in output
    assert f"report    {tmp_path / 'report.json'}" in output
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["status"] == "completed"
    assert report["completed"] is True
    assert report["captured_proofs"]["count"] == 0
    assert [finding["finding_id"] for finding in report["findings"]] == ["verified"]
    assert not (tmp_path / "report.md").exists()


def test_attack_result_fails_closed_for_mixed_engagement_and_scope_events(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _write_result_brief(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    events = [
        {
            "event_id": "event-accepted",
            "kind": "finding_confirmed",
            "payload": _result_finding("accepted"),
        },
        {
            "event_id": "event-missing-engagement",
            "kind": "finding_confirmed",
            "payload": _result_finding("missing-engagement") | {"engagement_id": ""},
        },
        {
            "event_id": "event-other-engagement",
            "kind": "finding_confirmed",
            "payload": _result_finding(
                "other-engagement",
                engagement_id="99999999-9999-4999-8999-999999999999",
                vuln_class="path_traversal",
            ),
        },
        {
            "event_id": "event-out-of-scope",
            "kind": "finding_confirmed",
            "payload": _result_finding(
                "out-of-scope",
                url="https://outside.example/search?q=test",
                vuln_class="cross_site_scripting",
            ),
        },
        {
            "event_id": "event-finished",
            "kind": "agent_finished",
            "payload": {"status": "completed"},
        },
    ]
    events_path = workspace / "events.jsonl"
    events_path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=brief_path,
        workspace_dir=workspace,
        audit_path=tmp_path / "missing.db",
        report_path=None,
        flag_objective=False,
    )

    output = capsys.readouterr().out
    assert "confirmed 1 vulnerability · High 1" in output
    assert "guard" not in output.lower()
    assert "event=event-accepted · finding=accepted" in output
    for rejected in (
        "missing-engagement",
        "other-engagement",
        "out-of-scope",
        "path traversal",
        "cross site scripting",
    ):
        assert rejected not in output


def test_attack_result_prints_report_command_when_configured_report_is_absent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _write_result_brief(tmp_path, filename="brief with spaces.yaml")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "events.jsonl").write_text(
        json.dumps(
            {
                "event_id": "event-finished",
                "kind": "agent_finished",
                "payload": {"status": "completed"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    missing_report = tmp_path / "configured-but-missing.json"

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=brief_path,
        workspace_dir=workspace,
        audit_path=tmp_path / "missing.db",
        report_path=missing_report,
        flag_objective=False,
    )

    output = capsys.readouterr().out
    assert f"report    {tmp_path / 'report.json'}" in output
    assert f"report    {missing_report}" not in output


def test_attack_result_without_events_surfaces_existing_failure_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = _write_result_brief(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    stdout_path = tmp_path / "stdout.log"
    stdout_path.write_text("docker preflight failed\n", encoding="utf-8")
    audit_path = tmp_path / "audit.db"
    audit_path.write_text("", encoding="utf-8")

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=brief_path,
        workspace_dir=workspace,
        audit_path=audit_path,
        report_path=None,
        flag_objective=False,
    )

    output = capsys.readouterr().out
    assert "RAVAGE // RESULT" in output
    assert "status    warning · setup or runtime failure" in output
    assert f"run       {tmp_path}" in output
    assert f"log       {stdout_path}" in output
    assert f"workspace {workspace}" in output
    assert f"audit     {audit_path}" in output
    assert f"report    {tmp_path / 'report.json'}" in output
    assert f"next      review {stdout_path}, fix the setup/runtime failure, then rerun" in output
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["status"] == "incomplete"
    assert report["completed"] is False
    assert report["findings"] == []


@pytest.mark.parametrize(
    ("reason", "label"),
    [
        ("max_turns_reached", "max turns reached"),
        ("cost_budget_exhausted", "cost budget exhausted"),
    ],
)
def test_attack_result_marks_incomplete_terminal_reason_as_warning(
    reason: str,
    label: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "events.jsonl").write_text(
        json.dumps(
            {
                "kind": "agent_finished",
                "payload": {"status": "incomplete", "termination_reason": reason},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=tmp_path / "brief.yaml",
        workspace_dir=workspace,
        audit_path=tmp_path / "missing.db",
        report_path=None,
        flag_objective=False,
    )

    assert f"status    warning · {label}" in capsys.readouterr().out


def test_attack_result_without_terminal_event_is_incomplete(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "events.jsonl").write_text(
        json.dumps(
            {
                "kind": "tool_run_probe",
                "payload": {"display_summary": {"findings": 1}},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    cli._write_attack_result(  # noqa: SLF001
        run_dir=tmp_path,
        brief_path=tmp_path / "brief.yaml",
        workspace_dir=workspace,
        audit_path=tmp_path / "missing.db",
        report_path=None,
        flag_objective=False,
    )

    output = capsys.readouterr().out
    assert "status    warning · terminal event missing" in output
    assert "status    completed" not in output


def test_attack_runtime_exception_still_prints_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    run_dir = tmp_path / "run"

    def fail_after_terminal_event(argv: list[str], _stdout_path: Path) -> int:
        workspace = Path(argv[argv.index("--workspace-dir") + 1])
        workspace.mkdir(parents=True)
        (workspace / "events.jsonl").write_text(
            "".join(
                json.dumps(event) + "\n"
                for event in (
                    {
                        "event_id": "event-before-failure",
                        "kind": "finding_confirmed",
                        "payload": _result_finding(
                            "finding-before-failure",
                            url="http://127.0.0.1:8765/search?q=test",
                        ),
                    },
                    {
                        "kind": "agent_finished",
                        "payload": {"status": "failed", "error_type": "RuntimeError"},
                    },
                )
            ),
            encoding="utf-8",
        )
        message = "simulated agent failure"
        raise RuntimeError(message)

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fail_after_terminal_event)

    with pytest.raises(RuntimeError, match="simulated agent failure"):
        cli.main(
            [
                "attack",
                str(brief_path),
                "--run-dir",
                str(run_dir),
                "--no-tool-recon",
            ]
        )

    output = capsys.readouterr().out
    assert "RAVAGE // RESULT" in output
    assert "status    failed" in output
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["status"] == "error"
    assert report["completed"] is False
    assert [finding["finding_id"] for finding in report["findings"]] == [
        "finding-before-failure"
    ]
    assert not (run_dir / "report.md").exists()


def test_cli_tools_check_reports_host_and_docker_availability(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    nmap_path = tmp_path / "nmap.exe"
    nmap_path.write_text("", encoding="utf-8")
    nmap_path.chmod(0o755)

    def fake_which(tool: str) -> str | None:
        return f"/usr/bin/{tool}" if tool in {"curl", "python3"} else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout="sha256:test\n", stderr="")
        if argv[:3] == ["docker", "run", "--rm"]:
            stdout = "\n".join(
                f"{tool}\t/usr/bin/{tool}" for tool in cli_tools.TOOL_RUNTIME_BINARIES
            )
            return subprocess.CompletedProcess(argv, 0, stdout=stdout + "\n", stderr="")
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tool_check.subprocess, "run", fake_run)
    monkeypatch.setenv("RAVAGE_NMAP_BIN", str(nmap_path))

    cli.main(["tools", "check", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["host"]["curl"]["available"] is True
    assert report["host"]["nmap"]["available"] is True
    assert report["host"]["nmap"]["source"] == "RAVAGE_NMAP_BIN"
    assert report["docker"]["available"] is True
    assert report["docker"]["tools"]["nikto"]["available"] is True
    assert any("Target VM" in line for line in report["runtime_guidance"])
    assert report["recommendation"] == "use --tool-runtime auto or --tool-runtime docker"

    cli.main(["tools", "check"])
    output = capsys.readouterr().out
    assert "WHERE TO INSTALL TOOLS" in output
    assert "RAVAGE_<TOOL>_BIN" in output
    assert "scripts/install_tools.sh --execute" in output
    assert "Target VM" in output


def test_cli_tools_check_handles_missing_docker_binary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(_tool: str) -> str | None:
        return None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tool_check.subprocess, "run", fake_run)

    cli.main(["tools", "check", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["docker"]["available"] is False
    assert "Docker command not found" in report["docker"]["error"]


def test_cli_tools_check_handles_docker_inspect_timeout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, timeout=10)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tool_check.subprocess, "run", fake_run)

    cli.main(["tools", "check", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["docker"]["available"] is False
    assert report["docker"]["error"] == "Docker image inspect timed out"


def test_cli_tools_check_handles_docker_tool_probe_timeout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if argv[:3] == ["/usr/bin/docker", "image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout="sha256:test\n", stderr="")
        raise subprocess.TimeoutExpired(argv, timeout=30)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tool_check.subprocess, "run", fake_run)

    cli.main(["tools", "check", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["docker"]["available"] is True
    assert report["docker"]["id"] == "sha256:test"
    assert report["docker"]["error"] == "Docker tool probe timed out"


def test_cli_tools_check_prints_missing_for_invalid_override(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(_tool: str) -> str | None:
        return None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="no docker")

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tool_check.subprocess, "run", fake_run)
    monkeypatch.setenv("RAVAGE_NMAP_BIN", "/private/tmp/no-such-ravage-nmap")

    cli.main(["tools", "check"])

    output = capsys.readouterr().out
    assert "nmap       missing /private/tmp/no-such-ravage-nmap" in output
    assert "configured path does not exist" in output


def test_cli_tools_check_treats_ncat_and_nc_as_equivalent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        if tool in {"docker", "ncat"}:
            return None
        return f"/usr/bin/{tool}"

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="no docker")

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tool_check.subprocess, "run", fake_run)

    cli.main(["tools", "check", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["host"]["ncat"]["available"] is False
    assert report["host"]["nc"]["available"] is True
    assert report["recommendation"] == "host runtime is ready"


def test_cli_tools_install_auto_prefers_brew_when_docker_is_absent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/opt/homebrew/bin/brew" if tool == "brew" else None

    def blocked_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tools.sys, "platform", "darwin")
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", blocked_run)

    cli.main(["tools", "install"])

    output = capsys.readouterr().out
    assert "requested  auto" in output
    assert "method     brew" in output
    assert "brew install" in output


def test_cli_tools_install_auto_uses_apt_on_linux_without_docker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/usr/bin/apt-get" if tool == "apt-get" else None

    def blocked_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tools.sys, "platform", "linux")
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", blocked_run)

    cli.main(["tools", "install"])

    output = capsys.readouterr().out
    assert "requested  auto" in output
    assert "method     apt" in output
    assert "sudo apt-get install" in output
    assert "ffuf" not in next(
        line for line in output.splitlines() if "sudo apt-get install" in line
    )
    assert "golang-go" not in output
    assert ".tools/go-root" in output
    assert "GOBIN=.tools/bin" in output


def test_cli_tools_install_uses_local_go_when_available(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    local_go = tmp_path / ".tools" / "go-root" / "bin" / "go"
    local_go.parent.mkdir(parents=True)
    local_go.write_text("", encoding="utf-8")

    def fake_which(tool: str) -> str | None:
        return "/usr/bin/apt-get" if tool == "apt-get" else None

    def blocked_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(argv)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_tools.sys, "platform", "linux")
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", blocked_run)

    cli.main(["tools", "install", "--method", "apt"])

    output = capsys.readouterr().out
    assert ".tools/go-root/bin/go install github.com/ffuf/ffuf/v2@latest" in output
    assert "curl -L -o .tools/downloads/go" not in output


def test_cli_tools_check_finds_repo_local_tools(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    ffuf = tmp_path / ".tools" / "bin" / "ffuf"
    ffuf.parent.mkdir(parents=True)
    ffuf.write_text("", encoding="utf-8")
    ffuf.chmod(0o755)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_tool_check.shutil, "which", lambda _tool: None)
    monkeypatch.setattr(
        cli_tool_check.subprocess,
        "run",
        lambda argv, **_: subprocess.CompletedProcess(argv, 1, stdout="", stderr="no docker"),
    )

    cli.main(["tools", "check", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["host"]["ffuf"]["available"] is True
    assert report["host"]["ffuf"]["source"] == ".tools/bin"


def test_cli_tools_install_manual_execute_exits_without_running_commands(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def blocked_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tools.subprocess, "run", blocked_run)

    exit_code: object = None
    try:
        cli.main(["tools", "install", "--method", "manual", "--execute"])
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == MANUAL_INSTALL_NO_COMMANDS_EXIT
    assert "No automatic install commands" in capsys.readouterr().out


def test_cli_tools_install_execute_stops_on_first_failed_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, INSTALL_FAILURE_EXIT)

    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)

    exit_code: object = None
    try:
        cli.main(["tools", "install", "--method", "apt", "--execute"])
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == INSTALL_FAILURE_EXIT
    assert calls == [["sudo", "apt-get", "update"]]


def test_cli_tools_install_dry_run_prints_docker_plan_without_running(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def blocked_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", blocked_run)

    cli.main(["tools", "install", "--method", "docker"])

    output = capsys.readouterr().out
    assert "INSTALL PLAN" in output
    assert "method     docker" in output
    assert "/usr/bin/docker pull ghcr.io/duriantaco/ravage-kali:latest" in output
    assert (
        "/usr/bin/docker tag ghcr.io/duriantaco/ravage-kali:latest ravage-kali:latest"
    ) in output
    assert "local fallback (rerun with --no-cache if the pull fails)" in output
    assert "/usr/bin/docker build" in output
    assert "unsigned local fallback" in output
    assert "ravage tools check --image ravage-kali:latest" in output
    assert "DRY RUN" in output


def test_cli_tools_install_dry_run_never_executes_download_commands(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        paths = {
            "docker": "/usr/bin/docker",
            "brew": "/opt/homebrew/bin/brew",
            "apt-get": "/usr/bin/apt-get",
        }
        return paths.get(tool)

    def blocked_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", blocked_run)

    for method in ("docker", "apt", "brew", "manual"):
        cli.main(["tools", "install", "--method", method])
        output = capsys.readouterr().out
        assert "execute    false" in output
        assert "DRY RUN" in output


def test_cli_tools_install_no_cache_forces_local_build_plan(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)

    cli.main(["tools", "install", "--method", "docker", "--no-cache"])

    output = capsys.readouterr().out
    assert "docker pull" not in output
    assert "local fallback (rerun with --no-cache if the pull fails)" not in output
    assert (
        "/usr/bin/docker build -t ravage-kali:latest -f sandbox/kali.Dockerfile --no-cache sandbox"
    ) in output


def test_cli_tools_install_execute_runs_selected_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_tools, "_running_under_wsl", lambda: False)

    exit_code: object = None
    try:
        cli.main(
            [
                "tools",
                "install",
                "--method",
                "docker",
                "--image",
                "ravage-test:tools",
                "--no-cache",
                "--execute",
            ]
        )
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == 0

    assert calls == [
        [
            "/usr/bin/docker",
            "info",
            "--format",
            "{{.ServerVersion}}",
        ],
        [
            "/usr/bin/docker",
            "build",
            "-t",
            "ravage-test:tools",
            "-f",
            "sandbox/kali.Dockerfile",
            "--no-cache",
            "sandbox",
        ],
    ]


def test_cli_tools_install_default_docker_execute_pulls_and_tags_without_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)
    monkeypatch.setattr(
        cli_tools,
        "verify_published_tool_image",
        lambda **_: "ghcr.io/duriantaco/ravage-kali@sha256:verified",
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["tools", "install", "--method", "docker", "--execute"])

    assert exc_info.value.code == 0
    assert calls == [
        ["/usr/bin/docker", "info", "--format", "{{.ServerVersion}}"],
        ["/usr/bin/docker", "pull", "ghcr.io/duriantaco/ravage-kali:latest"],
        [
            "/usr/bin/docker",
            "tag",
            "ghcr.io/duriantaco/ravage-kali:latest",
            "ravage-kali:latest",
        ],
    ]


def test_cli_tools_install_pull_failure_does_not_start_large_local_build(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[list[str]] = []

    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        returncode = 17 if argv[1] == "pull" else 0
        return subprocess.CompletedProcess(argv, returncode)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["tools", "install", "--method", "docker", "--execute"])

    assert exc_info.value.code == 17
    assert [call[1] for call in calls] == ["info", "pull"]
    error = capsys.readouterr().err
    assert "no local build was started" in error
    assert "--no-cache" in error


def test_cli_tools_install_tag_failure_does_not_hide_error_with_local_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        returncode = 19 if argv[1] == "tag" else 0
        return subprocess.CompletedProcess(argv, returncode)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)
    monkeypatch.setattr(
        cli_tools,
        "verify_published_tool_image",
        lambda **_: "ghcr.io/duriantaco/ravage-kali@sha256:verified",
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["tools", "install", "--method", "docker", "--execute"])

    assert exc_info.value.code == 19
    assert [call[1] for call in calls] == ["info", "pull", "tag"]


def test_cli_tools_install_signature_failure_never_tags_or_builds(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[list[str]] = []

    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    def failed_verification(**_: object) -> str:
        raise cli_tools.ToolImageError("signature verification failed")

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_tools, "verify_published_tool_image", failed_verification)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["tools", "install", "--method", "docker", "--execute"])

    assert exc_info.value.code == 1
    assert [call[1] for call in calls] == ["info", "pull"]
    assert "signature verification failed" in capsys.readouterr().err


def test_cli_tools_install_docker_execute_preflights_daemon(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[list[str]] = []

    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[:2] == ["/usr/bin/docker", "info"]:
            return subprocess.CompletedProcess(
                argv,
                1,
                stdout="",
                stderr="Cannot connect to the Docker daemon",
            )
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_tools, "_running_under_wsl", lambda: False)

    exit_code: object = None
    try:
        cli.main(["tools", "install", "--method", "docker", "--execute"])
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == 1
    assert calls == [["/usr/bin/docker", "info", "--format", "{{.ServerVersion}}"]]
    error = capsys.readouterr().err
    assert "docker daemon is not reachable" in error
    assert "Start the Docker daemon" in error


def test_cli_tools_install_docker_preflight_handles_error_output_with_zero_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[list[str]] = []

    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[:2] == ["/usr/bin/docker", "info"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout="permission denied while trying to connect to the Docker daemon socket",
                stderr="",
            )
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)

    exit_code: object = None
    try:
        cli.main(["tools", "install", "--method", "docker", "--execute"])
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == 1
    assert calls == [["/usr/bin/docker", "info", "--format", "{{.ServerVersion}}"]]
    assert "permission denied" in capsys.readouterr().err


def test_cli_tools_install_docker_preflight_timeout_is_actionable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, 30)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["tools", "install", "--method", "docker", "--execute"])

    assert exc_info.value.code == 1
    assert "docker preflight timed out after 30 seconds" in capsys.readouterr().err


def test_cli_tools_install_docker_preflight_prints_wsl_guidance(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["/usr/bin/docker", "info"]:
            return subprocess.CompletedProcess(
                argv,
                1,
                stdout="",
                stderr="Cannot connect to the Docker daemon",
            )
        raise AssertionError(argv)

    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_tools, "_running_under_wsl", lambda: True)

    exit_code: object = None
    try:
        cli.main(["tools", "install", "--method", "docker", "--execute"])
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "Detected WSL" in error
    assert "WSL Integration" in error
    assert "wsl --shutdown" in error


def test_cli_tools_install_uses_bundled_dockerfile_outside_checkout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def fake_which(tool: str) -> str | None:
        return "/usr/bin/docker" if tool == "docker" else None

    def blocked_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(argv)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_tool_check.shutil, "which", fake_which)
    monkeypatch.setattr(cli_tools.subprocess, "run", blocked_run)

    cli.main(["tools", "install", "--method", "docker"])

    output = capsys.readouterr().out
    assert "/usr/bin/docker build -t ravage-kali:latest -" in output
    assert "< bundled kali.Dockerfile" in output


def test_cli_attack_resume_defaults_to_previous_run_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    previous_run = tmp_path / "previous-run"
    previous_run.mkdir()
    report_path = previous_run / "report.json"
    report_path.write_text("{}", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)

    cli.main(["attack", str(brief_path), "--resume-from", str(report_path), "--no-tool-recon"])

    output = capsys.readouterr().out
    assert f"run       {previous_run}" in output
    assert calls
    command = calls[0]
    assert command[command.index("--db-path") + 1] == str(previous_run / "audit.db")
    assert command[command.index("--report-path") + 1] == str(previous_run / "report.json")
    assert command[command.index("--workspace-dir") + 1] == str(previous_run / "workspace")
    assert command[command.index("--resume-from") + 1] == str(report_path)
    assert "--tool-recon" not in command


def test_cli_ai_web_passes_report_agent_flag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run_ai_web_agent(
        *,
        brief_path: Path,
        target_url: str,
        settings: cli.AIWebAgentSettings,
    ) -> Path:
        captured["brief_path"] = brief_path
        captured["target_url"] = target_url
        captured["settings"] = settings
        return tmp_path / "audit.db"

    monkeypatch.setattr(cli, "run_ai_web_agent", fake_run_ai_web_agent)

    cli.main(
        [
            "--brief",
            str(brief_path),
            "--target-url",
            "http://127.0.0.1:8765",
            "--agent",
            "ai-web",
            "--report",
        ]
    )

    settings = captured["settings"]
    assert captured["brief_path"] == brief_path
    assert captured["target_url"] == "http://127.0.0.1:8765"
    assert isinstance(settings, cli.AIWebAgentSettings)
    assert settings.report_agent is True
    assert settings.tool_runtime_mode == "docker"


def test_cli_attack_forwards_report_agent_flag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    run_dir = tmp_path / "attack-run"
    calls: list[list[str]] = []

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)

    cli.main(["attack", str(brief_path), "--run-dir", str(run_dir), "--report"])

    assert calls
    command = calls[0]
    assert "--report" in command
    assert command[command.index("--report-path") + 1] == str(run_dir / "report.json")
    assert command[command.index("--tool-runtime") + 1] == "docker"


def test_cli_attack_preserves_explicit_local_host_runtime_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    run_dir = tmp_path / "attack-run"
    calls: list[list[str]] = []

    def fake_run(argv: list[str], _stdout_path: Path) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(cli, "_run_subprocess_tee_stdout", fake_run)

    cli.main(
        [
            "attack",
            str(brief_path),
            "--run-dir",
            str(run_dir),
            "--tool-runtime",
            "host",
        ]
    )

    command = calls[0]
    assert command[command.index("--tool-runtime") + 1] == "host"


def test_cli_benchmark_uses_openai_compatible_stub_end_to_end(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        f"""
cases:
  - id: cli-ai-web-vulnerable-search
    agent: ai-web
    brief: {brief_path}
    target_url: http://127.0.0.1:8765
    fixture: vulnerable_openapi
    expect:
      present:
        - vuln_class: sql_injection
          endpoint_path: /search
          param: q
      absent:
        - vuln_class: sql_injection
          endpoint_path: /hash
          param: data
    budget:
      max_seconds: 10.0
      max_http_requests: 40
""".lstrip(),
        encoding="utf-8",
    )
    actions: list[dict[str, object]] = [
        {"action": "discover_attack_surface", "args": {}, "rationale": "map"},
        {
            "action": "test_sqli_param",
            "args": {
                "path": "/search",
                "method": "GET",
                "param": "q",
                "location": "query",
            },
            "rationale": "probe",
        },
        {
            "action": "report_sqli",
            "args": {"path": "/search", "param": "q"},
            "rationale": "confirmed",
        },
        {"action": "final", "args": {"summary": "done"}, "rationale": "complete"},
    ]

    with OpenAIStubServer(actions) as server:
        model_config_path = tmp_path / "models.yaml"
        model_config_path.write_text(
            f"""
profiles:
  cli-stub:
    default_tier: mid
    routes:
      mid:
        - provider: custom_openai
          model: cli-stub-model
          base_url: {server.base_url}
          api_key_required: false
""".lstrip(),
            encoding="utf-8",
        )
        output_dir = tmp_path / "reports"
        env = os.environ.copy()
        env["PYTHONPATH"] = (
            f"{repo_root / 'packages/ravage/src'}:{repo_root / 'packages/schemas/src'}"
        )

        result = subprocess.run(  # noqa: S603 - fixed argv runs this repo's CLI in a test.
            [
                sys.executable,
                "-m",
                "ravage",
                "--benchmark",
                str(manifest_path),
                "--output-dir",
                str(output_dir),
                "--benchmark-model-config",
                str(model_config_path),
                "--benchmark-model-profile",
                "cli-stub",
                "--benchmark-model-tier",
                "mid",
                "--benchmark-max-turns",
                "4",
            ],
            check=False,
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

        assert result.returncode == 0, result.stdout + result.stderr
        assert len(server.requests_seen) == EXPECTED_MODEL_REQUESTS
        assert server.requests_seen[0]["model"] == "cli-stub-model"

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["summary"]["true_positives"] == 1
    assert report["summary"]["false_positives"] == 0
    finding = report["cases"][0]["actual_findings"][0]
    assert finding["engagement_id"] == RESULT_ENGAGEMENT_ID
    events_path = output_dir / "cli-ai-web-vulnerable-search.workspace" / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    assert sum(event["kind"] == "finding_confirmed" for event in events) == 1


def test_cli_accepts_attack_yaml_shorthand(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        """
cases:
  - id: cli-config-ai-web-vulnerable-search
    agent: ai-web
    brief: brief.yaml
    target_url: http://127.0.0.1:8765
    fixture: vulnerable_openapi
    expect:
      present:
        - vuln_class: sql_injection
          endpoint_path: /search
          param: q
    budget:
      max_seconds: 10.0
      max_http_requests: 40
""".lstrip(),
        encoding="utf-8",
    )
    actions: list[dict[str, object]] = [
        {"action": "discover_attack_surface", "args": {}, "rationale": "map"},
        {
            "action": "test_sqli_param",
            "args": {
                "path": "/search",
                "method": "GET",
                "param": "q",
                "location": "query",
            },
            "rationale": "probe",
        },
        {
            "action": "report_sqli",
            "args": {"path": "/search", "param": "q"},
            "rationale": "confirmed",
        },
        {"action": "final", "args": {"summary": "done"}, "rationale": "complete"},
    ]

    with OpenAIStubServer(actions) as server:
        model_config_path = tmp_path / "models.yaml"
        model_config_path.write_text(
            f"""
profiles:
  cli-stub:
    default_tier: mid
    routes:
      mid:
        - provider: custom_openai
          model: cli-stub-model
          base_url: {server.base_url}
          api_key_required: false
""".lstrip(),
            encoding="utf-8",
        )
        attack_config = tmp_path / "attack.yml"
        attack_config.write_text(
            """
mode: benchmark
benchmark:
  manifest: manifest.yaml
  output_dir: reports-config
  max_turns: 4
  model:
    config: models.yaml
    profile: cli-stub
    tier: mid
""".lstrip(),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = (
            f"{repo_root / 'packages/ravage/src'}:{repo_root / 'packages/schemas/src'}"
        )

        result = subprocess.run(
            [sys.executable, "-m", "ravage", "--attack.yml"],
            check=False,
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

        assert result.returncode == 0, result.stdout + result.stderr
        assert len(server.requests_seen) == EXPECTED_MODEL_REQUESTS

    report = json.loads((tmp_path / "reports-config" / "report.json").read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["summary"]["true_positives"] == 1
