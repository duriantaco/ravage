# ruff: noqa: PLR2004,SLF001
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tools.xben_head_to_head import strix_runner

API_KEY = "sk-test-key-that-must-never-be-persisted"
TARGET_URL = "http://target.internal:8080"
INSTRUCTION = "Recover every target-origin flag through black-box testing."
SANDBOX_IMAGE = "ghcr.io/usestrix/strix-sandbox@sha256:" + "a" * 64


def _docker_receipt(returncode: int = 0) -> dict[str, object]:
    return {
        "operation": "mocked_docker",
        "returncode": returncode,
        "stdout_bytes": 0,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_bytes": 0,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "elapsed_seconds": 0.0,
        "error": None,
        "valid_output": True,
    }


@pytest.fixture(autouse=True)
def _mock_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_ids",
        lambda _image, *, environment, sandbox_run_id=None: (set(), _docker_receipt()),
    )
    monkeypatch.setattr(
        strix_runner,
        "_docker_remove_containers",
        lambda _ids, *, environment: _docker_receipt(),
    )


def _executable(tmp_path: Path) -> tuple[Path, str]:
    executable = tmp_path / "strix"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    return executable, digest


def _request(
    tmp_path: Path,
    *,
    result_path: Path | None = None,
) -> strix_runner.StrixRunRequest:
    executable, digest = _executable(tmp_path)
    instruction_file = tmp_path / "instruction.md"
    instruction_file.write_text(INSTRUCTION + "\n", encoding="utf-8")
    return strix_runner.StrixRunRequest(
        executable=executable,
        executable_sha256=digest,
        target_url=TARGET_URL,
        instruction_file=instruction_file,
        working_directory=tmp_path / "work",
        model="openai/gpt-5.4",
        sandbox_image=SANDBOX_IMAGE,
        api_key=API_KEY,
        timeout_seconds=30,
        max_budget_usd=7.5,
        max_turns=42,
        result_path=result_path,
        environment={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(tmp_path),
            "TMPDIR": str(tmp_path / "tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "SSL_CERT_FILE": "/certs/ca.pem",
            "DOCKER_HOST": "unix:///mock/docker.sock",
            "DOCKER_CONTEXT": "mock-context",
            "DOCKER_CONFIG": str(tmp_path / "docker-config"),
            "OPENAI_API_KEY": "stale",
            "LLM_API_BASE": "https://proxy.invalid",
            "HTTPS_PROXY": "http://proxy.invalid",
            "GITHUB_TOKEN": "github-secret",
            "POSTMAN_API_KEY": "postman-secret",
            "PERPLEXITY_API_KEY": "perplexity-secret",
            "PYTHONPATH": "/untrusted/python/path",
            "STRIX_MCP_CONFIG": "/untrusted/mcp.json",
            "STRIX_RUN_ID": "inherited-owner-must-not-be-used",
            "STRIX_RUN_TYPE": "inherited-type-must-not-be-used",
        },
    )


def _write_run(
    working_directory: Path,
    *,
    name: str = "target_abcd",
    target_url: str = TARGET_URL,
    instruction: str = INSTRUCTION,
    status: str | None = "completed",
) -> Path:
    run_dir = working_directory / "strix_runs" / name
    (run_dir / "vulnerabilities").mkdir(parents=True)
    run_record = {
        "run_id": name,
        "run_name": name,
        "status": status,
        "targets_info": [
            {
                "type": "url",
                "original": target_url,
                "details": {"target_url": target_url},
            }
        ],
        "scan_mode": "deep",
        "non_interactive": True,
        "user_instruction": instruction,
        "scan_results": {"executive_summary": "flag{manifest-is-not-report-evidence}"},
        "llm_usage": {
            "requests": 9,
            "input_tokens": 1200,
            # The Strix SDK persists one token-detail mapping per model call.
            "input_tokens_details": [
                {"cached_tokens": 150},
                {"cached_tokens": 250},
            ],
            "output_tokens": 300,
            "total_tokens": 1500,
            "cost": 1.25,
        },
    }
    (run_dir / "run.json").write_text(json.dumps(run_record), encoding="utf-8")
    (run_dir / "penetration_test_report.md").write_text(
        "Found flag{from-executive-report}.\n",
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps([{"evidence": "XBEN{from-json-report}"}]),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities" / "vuln-0001.md").write_text(
        "Proof: ctf{from-vulnerability-markdown}\n",
        encoding="utf-8",
    )
    (run_dir / "agent-notes.txt").write_text(
        "flag{must-not-come-from-arbitrary-files}\n",
        encoding="utf-8",
    )
    return run_dir


@pytest.mark.parametrize(
    ("exit_code", "completion_kind"),
    [(0, "no_filed_findings"), (2, "findings_filed")],
)
def test_completed_run_uses_env_and_declared_reports_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    completion_kind: str,
) -> None:
    result_path = tmp_path / "receipt.json"
    request = _request(tmp_path, result_path=result_path)
    observed: dict[str, Any] = {}

    def fake_run_process(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: float,
        termination_grace_seconds: float,
    ) -> strix_runner._ProcessOutcome:
        observed.update(
            command=command,
            cwd=cwd,
            environment=environment,
            timeout=timeout_seconds,
            grace=termination_grace_seconds,
        )
        config_path = Path(command[command.index("--config") + 1])
        mcp_path = Path(command[command.index("--mcp-config") + 1])
        observed["config_path"] = config_path
        observed["mcp_path"] = mcp_path
        observed["config"] = config_path.read_text(encoding="utf-8")
        observed["mcp_config"] = mcp_path.read_text(encoding="utf-8")
        # Current Strix persists env-backed settings into its selected config
        # during bootstrap.  The runner must treat that file as ephemeral.
        config_path.write_text(json.dumps({"env": {"LLM_API_KEY": API_KEY}}), encoding="utf-8")
        _write_run(cwd)
        return strix_runner._ProcessOutcome(
            returncode=exit_code,
            timed_out=False,
            stdout=b"normal output",
            stderr=b"",
        )

    monkeypatch.setattr(strix_runner, "_run_process", fake_run_process)

    result = strix_runner.run_strix(request)

    assert result["status"] == "completed"
    assert result["valid"] is True
    assert result["exit_code"] == exit_code
    assert result["completion_kind"] == completion_kind
    assert result["flag_candidates"] == [
        "XBEN{from-json-report}",
        "ctf{from-vulnerability-markdown}",
        "flag{from-executive-report}",
    ]
    assert result["usage"] == {
        "requests": 9,
        "input_tokens": 1200,
        "cached_input_tokens": 400,
        "output_tokens": 300,
        "total_tokens": 1500,
        "cost_usd": 1.25,
    }
    assert observed["environment"]["LLM_API_KEY"] == API_KEY
    assert observed["environment"]["STRIX_LLM"] == "openai/gpt-5.4"
    assert observed["environment"]["STRIX_IMAGE"] == SANDBOX_IMAGE
    assert observed["environment"]["STRIX_RUNTIME_BACKEND"] == "docker"
    assert observed["environment"]["STRIX_RUN_ID"] == result["container_cleanup"]["sandbox_run_id"]
    assert observed["environment"]["STRIX_RUN_ID"] != "inherited-owner-must-not-be-used"
    assert observed["environment"]["STRIX_RUN_TYPE"] == "ravage-xben-head-to-head"
    assert observed["environment"]["STRIX_NO_UPDATE_CHECK"] == "1"
    assert observed["environment"]["STRIX_SANDBOX_LOG_MAX_SIZE"] == "10m"
    assert observed["environment"]["STRIX_SANDBOX_LOG_MAX_FILE"] == "2"
    assert observed["environment"]["HOME"] == str(tmp_path)
    assert observed["environment"]["DOCKER_HOST"] == "unix:///mock/docker.sock"
    for forbidden in (
        "OPENAI_API_KEY",
        "LLM_API_BASE",
        "HTTPS_PROXY",
        "GITHUB_TOKEN",
        "POSTMAN_API_KEY",
        "PERPLEXITY_API_KEY",
        "PYTHONPATH",
    ):
        assert forbidden not in observed["environment"]
    assert "--instruction-file" in observed["command"]
    assert "--instruction" not in observed["command"]
    assert "--non-interactive" in observed["command"]
    assert observed["command"][observed["command"].index("--scan-mode") + 1] == "deep"
    assert API_KEY not in json.dumps(result)
    assert "openai/gpt-5.4" not in observed["command"]
    assert API_KEY not in observed["command"]
    assert API_KEY not in observed["config"]
    assert json.loads(observed["config"]) == {"env": {}}
    assert json.loads(observed["mcp_config"]) == []
    assert not observed["config_path"].exists()
    assert not observed["mcp_path"].exists()
    assert result["sandbox_image"] == SANDBOX_IMAGE
    assert result["container_cleanup"]["verified"] is True
    persisted = result_path.read_text(encoding="utf-8")
    assert API_KEY not in persisted
    assert json.loads(persisted) == result


def test_stale_and_nonmatching_runs_are_not_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(tmp_path)
    _write_run(request.working_directory, name="stale_1111")

    def fake_run_process(*_args: object, cwd: Path, **_kwargs: object) -> Any:
        _write_run(cwd, name="unrelated_2222", target_url="http://other.internal")
        _write_run(cwd, name="current_3333")
        return strix_runner._ProcessOutcome(0, False, b"", b"")

    monkeypatch.setattr(strix_runner, "_run_process", fake_run_process)

    result = strix_runner.run_strix(request)

    assert result["status"] == "completed"
    assert Path(result["run_directory"]).name == "current_3333"


@pytest.mark.parametrize("run_status", ["stopped", "running", None])
@pytest.mark.parametrize("exit_code", [0, 2])
def test_accepted_exit_cannot_complete_unfinished_run_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_status: str | None,
    exit_code: int,
) -> None:
    request = _request(tmp_path)

    def budget_stopped(*_args: object, cwd: Path, **_kwargs: object) -> Any:
        _write_run(cwd, status=run_status)
        return strix_runner._ProcessOutcome(exit_code, False, b"", b"")

    monkeypatch.setattr(strix_runner, "_run_process", budget_stopped)

    result = strix_runner.run_strix(request)

    assert result["status"] == "error"
    assert result["valid"] is False
    assert result["error"] == "strix_run_status_not_completed"
    assert result["strix_run_status"] == run_status
    assert result["completion_kind"] is None
    assert result["exit_code"] == exit_code


def test_usage_supports_legacy_dict_details_without_partial_list_totals() -> None:
    assert (
        strix_runner._parse_usage(  # noqa: SLF001
            {"llm_usage": {"input_tokens_details": {"cached_tokens": 17}}}
        )["cached_input_tokens"]
        == 17
    )
    assert (
        strix_runner._parse_usage(  # noqa: SLF001
            {"llm_usage": {"input_tokens_details": [{"cached_tokens": 17}, {}]}}
        )["cached_input_tokens"]
        is None
    )


def test_fatal_exit_and_timeout_are_not_completed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(tmp_path)

    def fatal(*_args: object, cwd: Path, **_kwargs: object) -> Any:
        _write_run(cwd)
        return strix_runner._ProcessOutcome(1, False, b"", b"fatal")

    monkeypatch.setattr(strix_runner, "_run_process", fatal)
    fatal_result = strix_runner.run_strix(request)
    assert fatal_result["status"] == "error"
    assert fatal_result["error"] == "strix_exit_1"

    def timed_out(*_args: object, cwd: Path, **_kwargs: object) -> Any:
        _write_run(cwd, name="target_efgh")
        return strix_runner._ProcessOutcome(-9, True, b"", b"")

    monkeypatch.setattr(strix_runner, "_run_process", timed_out)
    timeout_result = strix_runner.run_strix(request)
    assert timeout_result["status"] == "timed_out"
    assert timeout_result["error"] == "strix_timeout"


def test_run_process_kills_the_whole_process_group_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 7312
        returncode = -signal.SIGKILL

        def __init__(self) -> None:
            self.calls = 0

        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            self.calls += 1
            if self.calls <= 2:
                raise subprocess.TimeoutExpired(["strix"], timeout)
            return b"out", b"err"

    fake = FakeProcess()
    popen_arguments: dict[str, Any] = {}
    signals: list[tuple[int, signal.Signals]] = []

    def fake_popen(*args: object, **kwargs: object) -> FakeProcess:
        popen_arguments.update(args=args, kwargs=kwargs)
        return fake

    monkeypatch.setattr(strix_runner.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        strix_runner.os,
        "killpg",
        lambda pid, requested_signal: signals.append((pid, requested_signal)),
    )

    outcome = strix_runner._run_process(
        ("/pinned/strix", "--non-interactive"),
        cwd=tmp_path,
        environment={"PATH": "/bin"},
        timeout_seconds=1,
        termination_grace_seconds=0.1,
    )

    assert outcome.timed_out is True
    assert outcome.stdout == b"out"
    assert popen_arguments["kwargs"]["start_new_session"] is True
    assert signals == [(7312, signal.SIGTERM), (7312, signal.SIGKILL)]


def test_run_process_sigterm_handler_kills_and_reaps_before_propagating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_handlers: dict[signal.Signals, Any] = {}
    restored: list[signal.Signals] = []
    previous_handler = object()

    class FakeProcess:
        pid = 8413
        returncode = -signal.SIGKILL

        def __init__(self) -> None:
            self.calls = 0

        def communicate(self, **_kwargs: object) -> tuple[bytes, bytes]:
            self.calls += 1
            if self.calls == 1:
                active_handlers[signal.SIGTERM](signal.SIGTERM, None)
            return b"reaped", b""

    fake = FakeProcess()
    signals: list[tuple[int, signal.Signals]] = []

    def fake_signal(requested: signal.Signals, handler: Any) -> object:
        if handler is previous_handler:
            restored.append(requested)
        else:
            active_handlers[requested] = handler
        return previous_handler

    monkeypatch.setattr(strix_runner.subprocess, "Popen", lambda *_args, **_kwargs: fake)
    monkeypatch.setattr(strix_runner.signal, "getsignal", lambda _requested: previous_handler)
    monkeypatch.setattr(strix_runner.signal, "signal", fake_signal)
    monkeypatch.setattr(
        strix_runner.os,
        "killpg",
        lambda pid, requested: signals.append((pid, requested)),
    )

    with pytest.raises(KeyboardInterrupt, match="received signal"):
        strix_runner._run_process(
            ("/pinned/strix", "--non-interactive"),
            cwd=tmp_path,
            environment={"PATH": "/bin"},
            timeout_seconds=10,
            termination_grace_seconds=1,
        )

    assert fake.calls == 2
    assert signals == [(8413, signal.SIGKILL)]
    assert signal.SIGTERM in restored


def test_pin_mismatch_fails_before_launch(tmp_path: Path) -> None:
    request = _request(tmp_path)
    changed = strix_runner.StrixRunRequest(
        **{
            **request.__dict__,
            "executable_sha256": "0" * 64,
        }
    )

    with pytest.raises(strix_runner.StrixRunnerError, match="SHA-256 pin"):
        strix_runner.run_strix(changed)


def test_mutable_sandbox_image_is_rejected_before_launch(tmp_path: Path) -> None:
    request = _request(tmp_path)
    changed = strix_runner.StrixRunRequest(
        **{
            **request.__dict__,
            "sandbox_image": "ghcr.io/usestrix/strix-sandbox:latest",
        }
    )

    with pytest.raises(strix_runner.StrixRunnerError, match="immutable sha256"):
        strix_runner.run_strix(changed)


def test_new_sandbox_container_is_force_removed_and_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(tmp_path)
    old_id = "1" * 64
    new_id = "2" * 64
    snapshots = iter(({old_id}, {old_id, new_id}))
    removed: list[set[str]] = []
    state: dict[str, Any] = {"run_id": None, "removed": False}

    monkeypatch.setattr(
        strix_runner,
        "_docker_container_ids",
        lambda _image, *, environment, sandbox_run_id=None: (
            set(next(snapshots))
            if sandbox_run_id is None
            else ({new_id} if state["run_id"] is not None and not state["removed"] else set()),
            _docker_receipt(),
        ),
    )
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_owners",
        lambda _ids, *, environment: ({new_id: state["run_id"]}, _docker_receipt()),
    )

    def remove(ids: set[str], *, environment: dict[str, str]) -> dict[str, object]:
        assert API_KEY not in environment.values()
        removed.append(set(ids))
        state["removed"] = True
        return _docker_receipt()

    monkeypatch.setattr(strix_runner, "_docker_remove_containers", remove)

    def completed(*_args: object, cwd: Path, environment: dict[str, str], **_kwargs: object) -> Any:
        state["run_id"] = environment["STRIX_RUN_ID"]
        _write_run(cwd)
        return strix_runner._ProcessOutcome(0, False, b"", b"")

    monkeypatch.setattr(strix_runner, "_run_process", completed)

    result = strix_runner.run_strix(request)

    assert result["status"] == "completed"
    assert result["valid"] is True
    assert removed == [{new_id}]
    cleanup = result["container_cleanup"]
    assert cleanup["new_leftover_container_ids"] == [new_id]
    assert cleanup["remaining_new_container_ids"] == []
    assert cleanup["verified"] is True


def test_unremoved_sandbox_container_invalidates_the_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(tmp_path)
    new_id = "3" * 64
    snapshots = iter((set(), {new_id}))
    state: dict[str, str | None] = {"run_id": None}
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_ids",
        lambda _image, *, environment, sandbox_run_id=None: (
            set(next(snapshots))
            if sandbox_run_id is None
            else ({new_id} if state["run_id"] is not None else set()),
            _docker_receipt(),
        ),
    )
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_owners",
        lambda _ids, *, environment: ({new_id: state["run_id"]}, _docker_receipt()),
    )
    monkeypatch.setattr(
        strix_runner,
        "_docker_remove_containers",
        lambda _ids, *, environment: _docker_receipt(returncode=1),
    )

    def completed(*_args: object, cwd: Path, environment: dict[str, str], **_kwargs: object) -> Any:
        state["run_id"] = environment["STRIX_RUN_ID"]
        _write_run(cwd)
        return strix_runner._ProcessOutcome(0, False, b"", b"")

    monkeypatch.setattr(strix_runner, "_run_process", completed)

    result = strix_runner.run_strix(request)

    assert result["status"] == "error"
    assert result["valid"] is False
    assert result["error"] == "sandbox_container_cleanup_failed"
    assert result["container_cleanup"]["remaining_new_container_ids"] == [new_id]


def test_failed_docker_inspection_blocks_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(tmp_path)
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_ids",
        lambda _image, *, environment, sandbox_run_id=None: (None, _docker_receipt(returncode=1)),
    )
    monkeypatch.setattr(
        strix_runner,
        "_run_process",
        lambda *_args, **_kwargs: pytest.fail("Strix launched after Docker inspection failure"),
    )

    result = strix_runner.run_strix(request)

    assert result["status"] == "error"
    assert result["valid"] is False
    assert result["error"] == "sandbox_container_inspection_failed_before_launch"
    assert result["container_cleanup"]["launch_attempted"] is False


def test_cleanup_preserves_concurrent_foreign_sandbox_containers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "a" * 32
    owned_id, foreign_id = "1" * 64, "2" * 64
    remaining = {owned_id, foreign_id}
    removed: list[set[str]] = []

    def container_ids(
        _image: str, *, environment: dict[str, str], sandbox_run_id: str | None = None
    ) -> tuple[set[str], dict[str, object]]:
        if sandbox_run_id is not None:
            assert sandbox_run_id == run_id
            return remaining & {owned_id}, _docker_receipt()
        return set(remaining), _docker_receipt()

    def remove(ids: set[str], *, environment: dict[str, str]) -> dict[str, object]:
        removed.append(set(ids))
        remaining.difference_update(ids)
        return _docker_receipt()

    monkeypatch.setattr(strix_runner, "_docker_container_ids", container_ids)
    monkeypatch.setattr(strix_runner, "_docker_remove_containers", remove)
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_owners",
        lambda _ids, *, environment: ({owned_id: run_id, foreign_id: "b" * 32}, _docker_receipt()),
    )

    receipt = strix_runner._cleanup_new_sandbox_containers(
        image=SANDBOX_IMAGE,
        before_ids=set(),
        sandbox_run_id=run_id,
        environment={},
        receipt=strix_runner._new_container_cleanup_receipt(SANDBOX_IMAGE, sandbox_run_id=run_id),
    )

    assert receipt["verified"] is True
    assert removed == [{owned_id}]
    assert remaining == {foreign_id}
    assert receipt["foreign_new_container_ids"] == [foreign_id]


def test_cleanup_preserves_unattributed_container_and_invalidates_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, unattributed_id = "a" * 32, "3" * 64
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_ids",
        lambda _image, *, environment, sandbox_run_id=None: (
            {unattributed_id} if sandbox_run_id is None else set(),
            _docker_receipt(),
        ),
    )
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_owners",
        lambda _ids, *, environment: ({unattributed_id: None}, _docker_receipt()),
    )
    monkeypatch.setattr(
        strix_runner,
        "_docker_remove_containers",
        lambda *_args, **_kwargs: pytest.fail("unattributed container must not be removed"),
    )
    receipt = strix_runner._cleanup_new_sandbox_containers(
        image=SANDBOX_IMAGE,
        before_ids=set(),
        sandbox_run_id=run_id,
        environment={},
        receipt=strix_runner._new_container_cleanup_receipt(SANDBOX_IMAGE, sandbox_run_id=run_id),
    )

    assert receipt["verified"] is False
    assert receipt["error"] == "sandbox_container_ownership_unverified"
    assert receipt["unattributed_new_container_ids"] == [unattributed_id]
    assert receipt["remove"] is None


def test_preexisting_ownership_namespace_blocks_strix_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        strix_runner,
        "_docker_container_ids",
        lambda _image, *, environment, sandbox_run_id=None: ({"4" * 64}, _docker_receipt()),
    )
    monkeypatch.setattr(
        strix_runner,
        "_run_process",
        lambda *_args, **_kwargs: pytest.fail("existing ownership namespace must block launch"),
    )

    result = strix_runner.run_strix(_request(tmp_path))

    assert result["status"] == "error"
    assert result["error"] == "sandbox_container_ownership_namespace_not_empty"
    assert result["container_cleanup"]["launch_attempted"] is False


def test_owned_container_enumeration_requires_exact_image_and_run_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []

    def run_docker(command: tuple[str, ...], **_kwargs: object) -> Any:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, b"", b""), _docker_receipt()

    monkeypatch.setattr(strix_runner, "_run_docker_command", run_docker)
    strix_runner._docker_container_ids(SANDBOX_IMAGE, environment={}, sandbox_run_id="a" * 32)
    assert commands == [
        (
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"ancestor={SANDBOX_IMAGE}",
            "--filter",
            "label=strix-run-id=" + "a" * 32,
        )
    ]


def test_container_inspection_reads_owned_foreign_and_unlabelled_containers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned_id, foreign_id, unlabelled_id = "1" * 64, "2" * 64, "3" * 64
    records = [
        {"Id": owned_id, "Config": {"Labels": {"strix-run-id": "a" * 32}}},
        {"Id": foreign_id, "Config": {"Labels": {"strix-run-id": "b" * 32}}},
        {"Id": unlabelled_id, "Config": {"Labels": None}},
    ]

    def run_docker(command: tuple[str, ...], **_kwargs: object) -> Any:
        assert command == (
            "docker",
            "inspect",
            "--type",
            "container",
            owned_id,
            foreign_id,
            unlabelled_id,
        )
        return (
            subprocess.CompletedProcess(command, 0, json.dumps(records).encode(), b""),
            _docker_receipt(),
        )

    monkeypatch.setattr(strix_runner, "_run_docker_command", run_docker)
    owners, _receipt = strix_runner._docker_container_owners(
        {owned_id, foreign_id, unlabelled_id}, environment={}
    )
    assert owners == {owned_id: "a" * 32, foreign_id: "b" * 32, unlabelled_id: None}


@pytest.mark.parametrize(
    "records",
    [
        [{"Id": [], "Config": {"Labels": {}}}],
        [{"Id": "f" * 64, "Config": {"Labels": {}}}],
        [{"Id": "1" * 64, "Config": {"Labels": "invalid"}}],
    ],
)
def test_malformed_ownership_inspection_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    records: list[dict[str, object]],
) -> None:
    monkeypatch.setattr(
        strix_runner,
        "_run_docker_command",
        lambda command, **_kwargs: (
            subprocess.CompletedProcess(command, 0, json.dumps(records).encode(), b""),
            _docker_receipt(),
        ),
    )
    owners, _receipt = strix_runner._docker_container_owners({"1" * 64}, environment={})
    assert owners is None
