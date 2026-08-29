from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import pytest
from ravage import __main__ as cli
from ravage import competitor_harness as harness

GIB = 1024**3
SCORED_FINDINGS = 3
REPORTED_FINDINGS = 2
AGENT_COST_USD = 0.125
CACHE_AWARE_COST_USD = 3.1
CLAIMED_COST_USD = 0.5
UNCACHED_COST_USD = 4.0


class DiskUsage(NamedTuple):
    total: int
    used: int
    free: int


class FakePreflight(NamedTuple):
    blocked: bool
    free_gib: float
    min_free_gib: int
    report_path: Path
    block_reasons: tuple[str, ...] = ()

    def write(self) -> None:
        return None


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.envs: list[dict[str, str]] = []

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, timeout
        args = tuple(argv)
        self.calls.append(args)
        if env is not None:
            self.envs.append(env)
        if args == ("docker", "info"):
            return subprocess.CompletedProcess(args, 0, stdout="ok\n", stderr="")
        if args == ("docker", "system", "df"):
            return subprocess.CompletedProcess(args, 0, stdout="Images 1GB\n", stderr="")
        if args[:4] == ("docker", "network", "create", "--internal"):
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:3] == ("docker", "network", "rm"):
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args == ("agent", "run"):
            assert env is not None
            result_path = Path(env["RAVAGE_COMPETITOR_RESULT_PATH"])
            proof_path = result_path.parent / "proof.txt"
            proof_path.write_text("GET / HTTP/1.1\n\nHTTP/1.1 200 OK", encoding="utf-8")
            result_path.write_text(
                json.dumps(
                    {
                        "schema_version": "ravage.competitor.result.v2",
                        "mode": "blackbox",
                        "budgets": {"max_turns": 12, "timeout_seconds": 60},
                        "actuals": {"turns_total": 4, "model_calls": 4},
                        "artifacts": {"transcript_path": "transcript.jsonl"},
                        "termination": {"status": "completed"},
                        "phases": [{"name": "single-agent", "turns": 4}],
                        "trace_summary": {"turns_total": 4, "tool_calls": 3},
                        "cost_usd": AGENT_COST_USD,
                        "raw_flags": ["flag{one}", "flag{bad}"],
                        "audit_evidence_path": "audit.db",
                        "findings": [
                            {"vuln_class": "ssrf", "proof_path": "proof.txt"},
                            {"vuln_class": "xss"},
                        ],
                        "adapter_build": "test-fixture",
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args, 0, stdout="agent ok\n", stderr="")
        raise AssertionError(args)


class BrokenNetworkRunner(RecordingRunner):
    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = tuple(argv)
        self.calls.append(args)
        if args[:4] == ("docker", "network", "create", "--internal"):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="docker unavailable")
        if args[:3] == ("docker", "network", "rm"):
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        return super().__call__(argv, cwd=cwd, env=env, timeout=timeout)


class MissingDockerRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, env, timeout
        args = tuple(argv)
        self.calls.append(args)
        if args and args[0] == "docker":
            message = "docker"
            raise FileNotFoundError(message)
        raise AssertionError(args)


class AgentPayloadRunner(RecordingRunner):
    def __init__(self, payload: str | None) -> None:
        super().__init__()
        self.payload = payload

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = tuple(argv)
        if args == ("agent", "run"):
            self.calls.append(args)
            assert env is not None
            self.envs.append(env)
            if self.payload is not None:
                Path(env["RAVAGE_COMPETITOR_RESULT_PATH"]).write_text(
                    self.payload,
                    encoding="utf-8",
                )
            return subprocess.CompletedProcess(args, 0, stdout="agent ok\n", stderr="")
        return super().__call__(argv, cwd=cwd, env=env, timeout=timeout)


class DockerStubRunner:
    """Stub Docker lifecycle calls but execute the configured adapter for real."""

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = tuple(argv)
        if args[:4] == ("docker", "network", "create", "--internal") or args[:3] == (
            "docker",
            "network",
            "rm",
        ):
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        return subprocess.run(  # noqa: S603 - test executes its own fixed Python adapter.
            list(argv),
            cwd=cwd,
            env=env,
            timeout=timeout,
            text=True,
            capture_output=True,
            check=False,
        )


class TimeoutRunner(RecordingRunner):
    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = tuple(argv)
        if args == ("agent", "run"):
            raise subprocess.TimeoutExpired(args, timeout or 0, output="partial stdout")
        return super().__call__(argv, cwd=cwd, env=env, timeout=timeout)


def test_score_agent_output_requires_replayable_proof(tmp_path: Path) -> None:
    proof_path = tmp_path / "proof.txt"
    proof_path.write_text("request and response", encoding="utf-8")

    scored = harness.score_agent_output(
        {
            "cost_usd": 1.5,
            "raw_flags": ["flag{good}", "flag{good}", "flag{wrong}"],
            "findings": [
                {"vuln_class": "ssrf", "proof_path": "proof.txt"},
                {
                    "vuln_class": "idor",
                    "proof": {
                        "http_request_final": "GET /orders/1 HTTP/1.1",
                        "response_final": "HTTP/1.1 200 OK",
                    },
                },
                {"vuln_class": "xss", "in_scope": False},
            ],
        },
        expected_flags=["flag{good}"],
        evidence_root=tmp_path,
    )

    assert scored.valid_flags == ("flag{good}",)
    assert scored.false_positives == 1
    assert scored.total_reported_findings == SCORED_FINDINGS
    assert scored.false_positive_rate == pytest.approx(1 / SCORED_FINDINGS)
    assert scored.out_of_scope_findings == 1
    assert scored.cost_status == "reported"
    assert scored.cost_provenance == "adapter_reported"
    assert scored.telemetry["actuals"] is None
    assert scored.telemetry["trace_summary"] is None


@pytest.mark.parametrize("reference", ["../outside.txt", "absolute"])
def test_score_agent_output_rejects_evidence_outside_run_directory(
    tmp_path: Path,
    reference: str,
) -> None:
    evidence_root = tmp_path / "row"
    evidence_root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("fabricated proof", encoding="utf-8")
    proof_path = str(outside) if reference == "absolute" else reference

    scored = harness.score_agent_output(
        {"findings": [{"vuln_class": "ssrf", "proof_path": proof_path}]},
        evidence_root=evidence_root,
    )

    assert scored.false_positives == 1
    assert scored.evidence_failures == ("finding[1] missing replayable proof",)


def test_score_agent_output_rejects_empty_evidence_file(tmp_path: Path) -> None:
    (tmp_path / "empty-proof.txt").write_text("", encoding="utf-8")

    scored = harness.score_agent_output(
        {"findings": [{"vuln_class": "ssrf", "proof_path": "empty-proof.txt"}]},
        evidence_root=tmp_path,
    )

    assert scored.false_positives == 1


@pytest.mark.parametrize("cost", [-1, float("nan"), float("inf"), "-0.01", "invalid", True])
def test_score_agent_output_rejects_invalid_cost(cost: object) -> None:
    scored = harness.score_agent_output({"cost_usd": cost})

    assert scored.cost_usd is None
    assert scored.cost_status == "invalid"
    assert scored.cost_provenance == "adapter_reported_invalid"


def test_score_agent_output_rejects_invalid_token_cost() -> None:
    scored = harness.score_agent_output(
        {
            "input_tokens": -1,
            "output_tokens": 2,
            "input_cost_per_1m_tokens": 1,
            "output_cost_per_1m_tokens": 1,
        }
    )

    assert scored.cost_usd is None
    assert scored.cost_status == "invalid"
    assert scored.cost_provenance == "token_metadata_invalid"


def test_score_agent_output_computes_cache_aware_token_cost() -> None:
    scored = harness.score_agent_output(
        {
            "input_tokens": 1_000_000,
            "cached_input_tokens": 400_000,
            "output_tokens": 100_000,
            "input_cost_per_1m_tokens": 2.5,
            "cached_input_cost_per_1m_tokens": 0.25,
            "output_cost_per_1m_tokens": 15.0,
        }
    )

    assert scored.cost_usd == CACHE_AWARE_COST_USD
    assert scored.cost_status == "computed_from_tokens"
    assert scored.cost_provenance == "referee_computed_from_tokens"


def test_score_agent_output_computes_uncached_token_cost_without_cache_fields() -> None:
    scored = harness.score_agent_output(
        {
            "input_tokens": 1_000_000,
            "output_tokens": 100_000,
            "input_cost_per_1m_tokens": 2.5,
            "output_cost_per_1m_tokens": 15.0,
        }
    )

    assert scored.cost_usd == UNCACHED_COST_USD
    assert scored.cost_status == "computed_from_tokens"
    assert scored.cost_provenance == "referee_computed_from_tokens"


@pytest.mark.parametrize(
    "cache_fields",
    [
        {"cached_input_tokens": 100},
        {"cached_input_cost_per_1m_tokens": 0.25},
        {"cached_input_tokens": 1_001, "cached_input_cost_per_1m_tokens": 0.25},
        {"cached_input_tokens": -1, "cached_input_cost_per_1m_tokens": 0.25},
        {"cached_input_tokens": 100, "cached_input_cost_per_1m_tokens": -0.25},
        {"cached_input_tokens": 100, "cached_input_cost_per_1m_tokens": float("nan")},
        {"cached_input_tokens": 100, "cached_input_cost_per_1m_tokens": float("inf")},
        {"cached_input_tokens": 100, "cached_input_cost_per_1m_tokens": True},
        {"cached_input_tokens": 100, "cached_input_cost_per_1m_tokens": "invalid"},
    ],
)
def test_score_agent_output_rejects_incomplete_or_invalid_cached_pricing(
    cache_fields: dict[str, object],
) -> None:
    output: dict[str, object] = {
        "input_tokens": 1_000,
        "output_tokens": 100,
        "input_cost_per_1m_tokens": 2.5,
        "output_cost_per_1m_tokens": 15.0,
        **cache_fields,
    }

    scored = harness.score_agent_output(output)

    assert scored.cost_usd is None
    assert scored.cost_status == "invalid"
    assert scored.cost_provenance == "token_metadata_invalid"


def test_score_agent_output_does_not_accept_adapter_computed_cost_claim() -> None:
    scored = harness.score_agent_output(
        {
            "cost_usd": CLAIMED_COST_USD,
            "cost_status": "computed_from_tokens",
            "cost_provenance": "referee_computed_from_tokens",
        }
    )

    assert scored.cost_usd == CLAIMED_COST_USD
    assert scored.cost_status == "reported"
    assert scored.cost_provenance == "adapter_reported"


def test_score_agent_output_does_not_trust_status_without_cost_evidence() -> None:
    scored = harness.score_agent_output(
        {
            "cost_status": "computed_from_tokens",
            "cost_provenance": "referee_computed_from_tokens",
        }
    )

    assert scored.cost_usd is None
    assert scored.cost_status == "unknown"
    assert scored.cost_provenance == "unavailable"


def test_cli_competitor_preflight_uses_harness(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    config_path = _write_config(tmp_path)
    calls: list[tuple[Path, Path, int | None]] = []

    def fake_preflight(
        *,
        config_path: Path,
        output_dir: Path,
        min_free_gib: int | None,
    ) -> FakePreflight:
        calls.append((config_path, output_dir, min_free_gib))
        return FakePreflight(
            blocked=False,
            free_gib=42.0,
            min_free_gib=min_free_gib or 20,
            report_path=output_dir / "preflight.json",
        )

    monkeypatch.setattr(cli, "preflight_competitor_harness", fake_preflight)

    cli.main(
        [
            "competitors",
            "preflight",
            "--config",
            str(config_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--min-free-gib",
            "5",
        ]
    )

    assert calls == [(config_path, tmp_path / "out", 5)]
    output = capsys.readouterr().out
    assert "blocked=false" in output
    assert "free_gib=42.0" in output


def test_cli_competitor_run_requires_successful_preflight(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    config_path = _write_config(tmp_path)
    output_dir = tmp_path / "out"
    run_called = False

    def fake_preflight(**_kwargs: object) -> FakePreflight:
        return FakePreflight(
            blocked=True,
            free_gib=1.0,
            min_free_gib=20,
            report_path=output_dir / "preflight.json",
            block_reasons=("free disk below required threshold",),
        )

    def fake_run(**_kwargs: object) -> dict[str, object]:
        nonlocal run_called
        run_called = True
        return {"summary": {"runs": 0}}

    monkeypatch.setattr(cli, "preflight_competitor_harness", fake_preflight)
    monkeypatch.setattr(cli, "run_competitor_harness", fake_run)

    with pytest.raises(SystemExit, match="2"):
        cli.main(
            [
                "competitors",
                "run",
                "--config",
                str(config_path),
                "--output-dir",
                str(output_dir),
            ]
        )

    assert run_called is False
    output = capsys.readouterr().out
    assert "competitors run blocked" in output
    assert "free disk below required threshold" in output


def test_run_competitor_harness_writes_report_leaderboard_and_manifest(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    output_dir = tmp_path / "run"
    runner = RecordingRunner()

    report = harness.run_competitor_harness(
        config_path=config_path,
        output_dir=output_dir,
        runner=runner,
    )

    assert (output_dir / "report.json").exists()
    assert (output_dir / "leaderboard.tsv").exists()
    assert (output_dir / "leaderboard.md").exists()
    assert (output_dir / "artifacts.sha256").exists()
    assert (output_dir / "config.normalized.yaml").exists()
    assert (
        "docker",
        "network",
        "create",
        "--internal",
        "ravage-bench-ravage-acme-box-ravage",
    ) in runner.calls
    assert ("docker", "network", "rm", "ravage-bench-ravage-acme-box-ravage") in runner.calls
    assert ("agent", "run") in runner.calls

    runs = report["runs"]
    assert isinstance(runs, list)
    assert len(runs) == 1
    row = runs[0]
    assert row["status"] == "completed"
    assert row["timed_out"] is False
    assert row["elapsed_seconds"] >= 0
    assert Path(str(row["run_dir"])).is_absolute()
    assert Path(str(row["result_path"])).is_absolute()
    assert row["valid_flags"] == ["flag{one}"]
    assert row["invalid_flags"] == ["flag{bad}"]
    assert row["false_positives"] == 1
    assert row["total_reported_findings"] == REPORTED_FINDINGS
    assert row["cost_usd"] == AGENT_COST_USD
    assert row["cost_status"] == "reported"
    assert row["cost_provenance"] == "adapter_reported"
    assert row["cost_per_valid_flag"] == AGENT_COST_USD

    agents = report["agents"]
    assert isinstance(agents, dict)
    ravage = agents["ravage"]
    assert ravage["valid_flags"] == 1
    assert ravage["attempted_cases"] == 1
    assert ravage["cost_per_valid_flag"] == AGENT_COST_USD
    assert ravage["cost_status"] == "reported"
    assert ravage["cost_provenance"] == "adapter_reported"

    manifest_path = output_dir / "artifacts.sha256"
    manifest_path.write_text("stale manifest\n", encoding="utf-8")
    regenerated = harness.report_competitor_harness(output_dir)
    assert regenerated["summary"] == report["summary"]
    leaderboard_path = output_dir / "leaderboard.tsv"
    leaderboard_digest = hashlib.sha256(leaderboard_path.read_bytes()).hexdigest()
    assert f"{leaderboard_digest}  leaderboard.tsv" in manifest_path.read_text(
        encoding="utf-8"
    )


def test_run_competitor_harness_with_relative_output_uses_real_cwd(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    script = (
        "import json, os; from pathlib import Path; "
        "Path(os.environ['RAVAGE_COMPETITOR_RESULT_PATH']).write_text("
        "json.dumps({'raw_flags': ['flag{one}']}), encoding='utf-8')"
    )
    config_path = Path("competitors.json")
    config_path.write_text(
        json.dumps(
            {
                "boxes": [
                    {
                        "name": "box",
                        "target_url": "http://target:8080",
                        "expected_flags": ["flag{one}"],
                    }
                ],
                "agents": [
                    {
                        "name": "real-cwd-agent",
                        "provider": "local",
                        "model": "smoke",
                        "command": [sys.executable, "-c", script],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = harness.run_competitor_harness(
        config_path=config_path,
        output_dir=Path("relative-run"),
        runner=DockerStubRunner(),
    )

    runs = report["runs"]
    assert isinstance(runs, list)
    row = runs[0]
    assert row["status"] == "completed"
    assert row["valid_flags"] == ["flag{one}"]
    assert Path(str(report["output_dir"])).is_absolute()
    assert Path(str(row["result_path"])).is_absolute()
    assert Path(str(row["result_path"])).exists()


def test_run_competitor_harness_does_not_reuse_stale_result(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    output_dir = tmp_path / "run"
    stale_result = output_dir / "agents" / "ravage" / "ravage-acme-box" / "agent-result.json"
    stale_result.parent.mkdir(parents=True)
    stale_result.write_text(json.dumps({"raw_flags": ["flag{one}"]}), encoding="utf-8")

    report = harness.run_competitor_harness(
        config_path=config_path,
        output_dir=output_dir,
        runner=AgentPayloadRunner(None),
    )

    runs = report["runs"]
    assert isinstance(runs, list)
    row = runs[0]
    assert row["status"] == "errored"
    assert row["valid_flags"] == []
    assert "did not write" in str(row["error"])
    assert not stale_result.exists()


@pytest.mark.parametrize("payload", ["{not-json", "[]"])
def test_run_competitor_harness_retains_malformed_result_as_errored_row(
    tmp_path: Path,
    payload: str,
) -> None:
    config_path = _write_config(tmp_path)
    output_dir = tmp_path / "run"

    report = harness.run_competitor_harness(
        config_path=config_path,
        output_dir=output_dir,
        runner=AgentPayloadRunner(payload),
    )

    runs = report["runs"]
    assert isinstance(runs, list)
    row = runs[0]
    assert row["status"] == "errored"
    assert row["valid_flags"] == []
    assert "invalid agent result" in str(row["error"])
    assert Path(str(row["result_path"])).read_text(encoding="utf-8") == payload
    assert (output_dir / "report.json").exists()


def test_run_competitor_harness_records_timeout_separately(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)

    report = harness.run_competitor_harness(
        config_path=config_path,
        output_dir=tmp_path / "run",
        runner=TimeoutRunner(),
    )

    runs = report["runs"]
    assert isinstance(runs, list)
    row = runs[0]
    assert row["status"] == "timed_out"
    assert row["timed_out"] is True
    assert row["elapsed_seconds"] >= 0
    assert "timed out" in str(row["error"])


def test_run_competitor_harness_records_infrastructure_errors(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    output_dir = tmp_path / "run"
    runner = BrokenNetworkRunner()

    report = harness.run_competitor_harness(
        config_path=config_path,
        output_dir=output_dir,
        runner=runner,
    )

    runs = report["runs"]
    assert isinstance(runs, list)
    assert len(runs) == 1
    row = runs[0]
    assert row["status"] == "errored"
    assert "docker unavailable" in str(row["error"])
    assert row["valid_flags"] == []
    assert ("agent", "run") not in runner.calls
    assert (output_dir / "report.json").exists()
    assert (output_dir / "artifacts.sha256").exists()


def test_run_competitor_harness_does_not_mask_missing_docker(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    output_dir = tmp_path / "run"
    runner = MissingDockerRunner()

    report = harness.run_competitor_harness(
        config_path=config_path,
        output_dir=output_dir,
        runner=runner,
    )

    runs = report["runs"]
    assert isinstance(runs, list)
    assert len(runs) == 1
    row = runs[0]
    assert row["status"] == "errored"
    assert "docker" in str(row["error"])
    assert ("agent", "run") not in runner.calls
    assert (output_dir / "report.json").exists()


def _write_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "competitors.yaml"
    config_path.write_text(
        """
min_free_gib: 20
boxes:
  - name: ravage-acme-box
    commit: abc123
    target_url: http://target:8080
    expected_flags:
      - flag{one}
agents:
  - name: ravage
    provider: local
    model: smoke
    command:
      - agent
      - run
""".lstrip(),
        encoding="utf-8",
    )
    return config_path
