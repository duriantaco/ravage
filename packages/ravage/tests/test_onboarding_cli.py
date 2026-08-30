from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import pytest
from ravage import __main__ as cli
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.run_data.run_manifest import read_manifest
from ravage.setup_checks import SetupDiagnostic

if TYPE_CHECKING:
    from pathlib import Path

_ARGPARSE_ERROR = 2

BRIEF_YAML = """
engagement_id: "77777777-7777-4777-8777-777777777777"
scope:
  in_scope:
    - "http://127.0.0.1:8765"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "web_application_assessment"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 10
context:
  description: "Local application used for a Ravage onboarding test."
  win_condition: "Produce evidence-backed findings without destructive actions."
  rules:
    - "Stay on the local target."
""".lstrip()


def test_init_accepts_positional_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    env = tmp_path / ".env.ravage"

    cli.main(
        [
            "init",
            "http://127.0.0.1:3000",
            "--brief",
            str(brief),
            "--env-file",
            str(env),
            "--description",
            "Authorized local onboarding test.",
        ]
    )

    assert brief.is_file()
    assert env.is_file()
    output = capsys.readouterr().out
    assert "--probe surface_map --report" in output
    assert "source .env" not in output


def test_unknown_command_has_suggestion() -> None:
    with pytest.raises(SystemExit, match="Did you mean `ravage doctor`"):
        cli.main(["doctro"])


def test_scan_lists_probes_without_a_brief(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(["scan", "--list-probes"])

    output = capsys.readouterr().out
    assert "RAVAGE // SCAN PROBES" in output
    assert "surface_map · default" in output
    assert "sqli" in output


def test_attack_auto_loads_generated_env_and_selects_hosted_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief = tmp_path / "brief.yaml"
    env = tmp_path / ".env.ravage"
    run_dir = tmp_path / "run"
    brief.write_text(BRIEF_YAML, encoding="utf-8")
    env.write_text("OPENAI_API_KEY=onboarding-key\n", encoding="utf-8")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli,
        "_run_subprocess_tee_stdout",
        lambda argv, _stdout: calls.append(argv) or 0,
    )

    cli.main(
        [
            "attack",
            str(brief),
            "--run-dir",
            str(run_dir),
            "--allow-paid-models",
            "--no-tool-recon",
        ]
    )

    [command] = calls
    assert command[command.index("--model-profile") + 1] == "hosted-openai"
    assert command[command.index("--model-tier") + 1] == "low"
    assert os.environ["OPENAI_API_KEY"] == "onboarding-key"


def test_attack_without_a_brief_has_first_run_guidance(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured:
        cli.main(["attack"])

    assert captured.value.code == _ARGPARSE_ERROR
    assert "ravage init URL" in capsys.readouterr().err


def test_doctor_core_is_useful_without_project_files(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "docker_compose_diagnostic",
        lambda *, required: SetupDiagnostic(
            "docker",
            "warn",
            "required" if required else "optional",
            "install Docker",
        ),
    )
    monkeypatch.setattr(
        cli,
        "labs_diagnostic",
        lambda *, required: SetupDiagnostic(
            "labs",
            "ok",
            "included labs ready" if required else "included labs optional",
        ),
    )
    monkeypatch.setattr(
        cli,
        "playwright_diagnostic",
        lambda *, required: SetupDiagnostic(
            "browser",
            "warn",
            "required" if required else "optional",
            "scripts/bootstrap.sh --install-browser",
        ),
    )

    cli.main(["doctor", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "ravage.setup_check.v2"
    assert payload["workflow"] == "core"
    assert payload["ok"] is True
    assert {item["name"] for item in payload["checks"]} >= {
        "python",
        "package",
        "run_location",
        "docker",
        "browser",
    }


def test_doctor_traffic_requires_an_explicit_target(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "playwright_diagnostic",
        lambda *, required: SetupDiagnostic(
            "browser",
            "ok" if required else "warn",
            "Chromium ready",
        ),
    )

    with pytest.raises(SystemExit) as captured:
        cli.main(["doctor", "--workflow", "traffic", "--json"])

    assert captured.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    target = next(item for item in payload["checks"] if item["name"] == "target")
    assert target["status"] == "fail"
    assert "--target-url" in target["fix"]


def test_doctor_redacts_target_urls_from_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sensitive_value = "onboarding-secret"
    target_url = (
        f"http://operator:password@127.0.0.1:8765/private?token={sensitive_value}"
    )
    brief = tmp_path / "brief.yaml"
    brief.write_text(
        BRIEF_YAML.replace("http://127.0.0.1:8765", target_url),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cli,
        "target_reachability_diagnostic",
        lambda *_args, **_kwargs: SetupDiagnostic(
            "target",
            "ok",
            "HTTP 200 from http://127.0.0.1:8765",
        ),
    )

    cli.main(["doctor", "--workflow", "scan", "--brief", str(brief), "--json"])

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert sensitive_value not in output
    assert "password" not in output
    assert payload["target_url"] == "http://127.0.0.1:8765"
    brief_check = next(item for item in payload["checks"] if item["name"] == "brief")
    assert brief_check["detail"].endswith("target=http://127.0.0.1:8765")


def test_traffic_doctor_next_command_drops_secrets_and_shell_syntax(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli._write_setup_next_command(  # noqa: SLF001
        workflow="traffic",
        brief_path=None,
        env_file=None,
        target_url=(
            "http://operator:password@127.0.0.1:3000/private;echo-pwned?token=secret"
        ),
        model_profile="local-ollama",
        model_tier="mid",
    )

    output = capsys.readouterr().out
    assert "ravage traffic capture http://127.0.0.1:3000" in output
    assert "password" not in output
    assert "token" not in output
    assert ";" not in output


def test_doctor_scan_fails_with_actionable_unreachable_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    brief.write_text(BRIEF_YAML, encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "target_reachability_diagnostic",
        lambda *_args, **_kwargs: SetupDiagnostic(
            "target",
            "fail",
            "connection refused",
            "Start the application and retry.",
        ),
    )

    with pytest.raises(SystemExit) as captured:
        cli.main(["doctor", "--workflow", "scan", "--brief", str(brief)])

    assert captured.value.code == 1
    output = capsys.readouterr().out
    assert "[fail] target" in output
    assert "[fix] Start the application and retry." in output


def test_scan_transport_failure_does_not_write_completed_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    brief.write_text(BRIEF_YAML, encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "run_builtin_probe",
        lambda *_args, **_kwargs: ProbeRunResult(
            ok=False,
            probe="surface_map",
            summary="received 0/1 HTTP response(s)",
            requests=[
                {
                    "method": "GET",
                    "url": "http://127.0.0.1:8765/",
                    "status": None,
                    "error": "[Errno 61] Connection refused",
                }
            ],
            errors=["[Errno 61] Connection refused"],
        ),
    )

    with pytest.raises(SystemExit, match="target unreachable"):
        cli.main(
            [
                "scan",
                str(brief),
                "--probe",
                "surface_map",
                "--run-dir",
                str(run_dir),
                "--report",
            ]
        )

    assert not (run_dir / "report.md").exists()
    assert not (run_dir / "scan-summary.json").exists()
    manifest = read_manifest(run_dir)
    assert manifest is not None
    assert manifest.result_label == "failed"


def test_scan_missing_http_status_fails_even_without_a_transport_error_string(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    brief.write_text(BRIEF_YAML, encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "run_builtin_probe",
        lambda *_args, **_kwargs: ProbeRunResult(
            ok=False,
            probe="surface_map",
            summary="no HTTP response",
            requests=[
                {
                    "method": "GET",
                    "url": "http://127.0.0.1:8765/",
                    "status": None,
                    "error": "",
                }
            ],
        ),
    )

    with pytest.raises(SystemExit, match="transport returned no HTTP status"):
        cli.main(
            [
                "scan",
                str(brief),
                "--probe",
                "surface_map",
                "--run-dir",
                str(run_dir),
            ]
        )

    manifest = read_manifest(run_dir)
    assert manifest is not None
    assert manifest.result_label == "failed"


def test_scan_http_error_status_still_counts_as_reachable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    brief.write_text(BRIEF_YAML, encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "run_builtin_probe",
        lambda *_args, **_kwargs: ProbeRunResult(
            ok=True,
            probe="surface_map",
            summary="fetched 1 URL(s), notable=0",
            requests=[
                {
                    "method": "GET",
                    "url": "http://127.0.0.1:8765/",
                    "status": 401,
                    "error": "",
                }
            ],
        ),
    )

    cli.main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--run-dir",
            str(run_dir),
        ]
    )

    assert (run_dir / "scan-summary.json").is_file()
    manifest = read_manifest(run_dir)
    assert manifest is not None
    assert manifest.result_label == "completed"


def test_scan_persists_confirmed_native_finding_without_a_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    brief.write_text(BRIEF_YAML, encoding="utf-8")
    monkeypatch.setattr(cli, "run_builtin_probe", lambda *_args, **_kwargs: _file_read_result())

    cli.main(
        [
            "scan",
            str(brief),
            "--probe",
            "file_read_extract",
            "--run-dir",
            str(run_dir),
            "--report",
            "--json",
        ]
    )
    capsys.readouterr()

    summary = json.loads((run_dir / "scan-summary.json").read_text(encoding="utf-8"))
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in (run_dir / "workspace" / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]

    assert "findings_count" not in summary
    assert summary["probe_observations_count"] == 1
    assert summary["confirmed_findings_count"] == 1
    assert summary["flags"] == []
    assert report["executive_summary"]["finding_count"] == 1
    assert report["captured_proofs"]["count"] == 0
    assert report["outcome"]["confirmed_finding_count"] == 1
    assert report["outcome"]["stage"] == "exploit_primitive"
    assert [finding["vuln_class"] for finding in report["findings"]] == [
        "path_traversal"
    ]
    assert {event["kind"] for event in events} >= {
        "scan_probe",
        "tool_run_probe",
        "outcome_evidence_observed",
        "finding_confirmed",
    }


def test_scan_separates_candidates_and_exhausted_records_from_confirmed_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "scan-run"
    brief.write_text(BRIEF_YAML, encoding="utf-8")
    results = iter((_surface_candidate_result(), _exhausted_result()))
    monkeypatch.setattr(cli, "run_builtin_probe", lambda *_args, **_kwargs: next(results))

    cli.main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--probe",
            "sqli_auth_transition",
            "--run-dir",
            str(run_dir),
            "--report",
            "--json",
        ]
    )
    capsys.readouterr()

    summary = json.loads((run_dir / "scan-summary.json").read_text(encoding="utf-8"))
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in (run_dir / "workspace" / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]

    assert summary["probe_observations_count"] == 2
    assert summary["confirmed_findings_count"] == 0
    assert report["findings"] == []
    assert report["outcome"]["stage"] == "suspected_vulnerability"
    assert report["outcome"]["suspected_vulnerability_count"] == 1
    scan_findings = [
        finding["type"]
        for event in events
        if event["kind"] == "scan_probe"
        for finding in event["payload"]["findings"]
    ]
    assert scan_findings == ["notable_response", "sqli_auth_transition_exhausted"]
    assert not any(event["kind"] == "finding_confirmed" for event in events)


def _file_read_result() -> ProbeRunResult:
    url = "http://127.0.0.1:8765/view?file=../../../../etc/passwd"
    return ProbeRunResult(
        ok=True,
        probe="file_read_extract",
        summary="confirmed local file read without a captured proof",
        findings=[
            {
                "type": "file_read_primitive",
                "payload": "../../../../etc/passwd",
                "signal": {"kind": "local_file_read", "matches": ["root:x:0:0"]},
                "delta": {"body_changed": True},
                "response": {
                    "method": "GET",
                    "url": url,
                    "final_url": "http://127.0.0.1:8765/view",
                    "status": 200,
                    "elapsed_ms": 1,
                    "body_len": 32,
                    "body_sha_hint": "0123456789abcdef",
                    "body_snippet": "root:x:0:0:root:/root:/bin/sh",
                    "error": "",
                },
                "replay": {
                    "method": "GET",
                    "url": url,
                    "payload_field": "file",
                },
            }
        ],
        requests=[
            {
                "method": "GET",
                "url": url,
                "status": 200,
                "error": "",
            }
        ],
    )


def _surface_candidate_result() -> ProbeRunResult:
    url = "http://127.0.0.1:8765/"
    return ProbeRunResult(
        ok=True,
        probe="surface_map",
        summary="fetched 1 URL, notable=1",
        findings=[
            {
                "type": "notable_response",
                "url": url,
                "status": 200,
                "body_markers": ["login"],
            }
        ],
        requests=[{"method": "GET", "url": url, "status": 200, "error": ""}],
    )


def _exhausted_result() -> ProbeRunResult:
    url = "http://127.0.0.1:8765/login"
    return ProbeRunResult(
        ok=False,
        probe="sqli_auth_transition",
        summary="terminal_reason=matrix_exhausted, authenticated=false",
        findings=[
            {
                "type": "sqli_auth_transition_exhausted",
                "attempts": [{"input": "password", "verified": False}],
            }
        ],
        requests=[{"method": "POST", "url": url, "status": 401, "error": ""}],
    )
