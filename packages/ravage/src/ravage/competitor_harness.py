from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

RESULT_SCHEMA_VERSION = "ravage.competitor.result.v2"
REPORT_SCHEMA_VERSION = "ravage.competitor.report.v1"
DEFAULT_MIN_FREE_GIB = 20
DEFAULT_AGENT_TIMEOUT_SECONDS = 1800
GIB = 1024**3


@dataclass(frozen=True)
class ScoredAgentOutput:
    valid_flags: tuple[str, ...] = ()
    invalid_flags: tuple[str, ...] = ()
    false_positives: int = 0
    total_reported_findings: int = 0
    out_of_scope_findings: int = 0
    cost_usd: float | None = None
    cost_status: str = "unknown"
    cost_provenance: str = "unavailable"
    evidence_failures: tuple[str, ...] = ()
    telemetry: dict[str, object] = field(default_factory=dict)

    @property
    def false_positive_rate(self) -> float:
        if not self.total_reported_findings:
            return 0.0
        return self.false_positives / self.total_reported_findings

    @property
    def cost_per_valid_flag(self) -> float | None:
        if self.cost_usd is None or not self.valid_flags:
            return None
        return round(self.cost_usd / len(self.valid_flags), 6)


@dataclass(frozen=True)
class BoxConfig:
    name: str
    target_url: str
    expected_flags: tuple[str, ...] = ()
    commit: str = ""


@dataclass(frozen=True)
class AgentConfig:
    name: str
    provider: str
    model: str
    command: tuple[str, ...]
    timeout_seconds: int = DEFAULT_AGENT_TIMEOUT_SECONDS


@dataclass(frozen=True)
class HarnessConfig:
    min_free_gib: int
    boxes: tuple[BoxConfig, ...]
    agents: tuple[AgentConfig, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "min_free_gib": self.min_free_gib,
            "boxes": [
                {
                    "name": box.name,
                    "commit": box.commit,
                    "target_url": box.target_url,
                    "expected_flags": list(box.expected_flags),
                }
                for box in self.boxes
            ],
            "agents": [
                {
                    "name": agent.name,
                    "provider": agent.provider,
                    "model": agent.model,
                    "command": list(agent.command),
                    "timeout_seconds": agent.timeout_seconds,
                }
                for agent in self.agents
            ],
        }


@dataclass(frozen=True)
class PreflightResult:
    blocked: bool
    free_gib: float
    min_free_gib: int
    report_path: Path
    docker_available: bool
    block_reasons: tuple[str, ...]
    config: dict[str, object]

    def write(self) -> None:
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": "ravage.competitor.preflight.v1",
            "generated_at": _now(),
            "blocked": self.blocked,
            "block_reasons": list(self.block_reasons),
            "free_gib": self.free_gib,
            "min_free_gib": self.min_free_gib,
            "docker_available": self.docker_available,
            "config": self.config,
        }


Runner = Any


class ProcessRunError(RuntimeError):
    def __init__(self, argv: Sequence[str], message: str) -> None:
        self.argv = tuple(argv)
        self.process_message = message
        super().__init__(f"{' '.join(argv)} failed: {message}")


def load_competitor_config(config_path: Path) -> HarnessConfig:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        message = f"competitor config must be a mapping: {config_path}"
        raise TypeError(message)
    boxes = tuple(_box_config(item) for item in _list_value(raw.get("boxes")))
    agents = tuple(_agent_config(item) for item in _list_value(raw.get("agents")))
    if not boxes:
        message = "competitor config must define at least one box"
        raise ValueError(message)
    if not agents:
        message = "competitor config must define at least one agent"
        raise ValueError(message)
    return HarnessConfig(
        min_free_gib=_int_value(raw.get("min_free_gib"), DEFAULT_MIN_FREE_GIB),
        boxes=boxes,
        agents=agents,
    )


def preflight_competitor_harness(
    *,
    config_path: Path,
    output_dir: Path,
    min_free_gib: int | None = None,
    runner: Runner | None = None,
) -> PreflightResult:
    config_path = config_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    config = load_competitor_config(config_path)
    threshold = min_free_gib if min_free_gib is not None else config.min_free_gib
    output_dir.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(output_dir)
    free_gib = round(usage.free / GIB, 3)
    block_reasons: list[str] = []
    if free_gib < threshold:
        block_reasons.append(f"free disk {free_gib} GiB below required {threshold} GiB")

    docker_available = _docker_available(runner=runner)
    if not docker_available:
        block_reasons.append("docker is unavailable")

    result = PreflightResult(
        blocked=bool(block_reasons),
        free_gib=free_gib,
        min_free_gib=threshold,
        report_path=output_dir / "preflight.json",
        docker_available=docker_available,
        block_reasons=tuple(block_reasons),
        config=_config_summary(config),
    )
    result.write()
    return result


def run_competitor_harness(
    *,
    config_path: Path,
    output_dir: Path,
    runner: Runner | None = None,
) -> dict[str, object]:
    config_path = config_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    config = load_competitor_config(config_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_normalized_config(output_dir / "config.normalized.yaml", config)
    rows = [
        _run_agent_box(
            output_dir=output_dir,
            agent=agent,
            box=box,
            runner=runner,
        )
        for box in config.boxes
        for agent in config.agents
    ]

    report = _aggregate_report(
        config_path=config_path,
        output_dir=output_dir,
        config=config,
        rows=rows,
    )
    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    _write_leaderboard_tsv(output_dir / "leaderboard.tsv", report)
    _write_leaderboard_md(output_dir / "leaderboard.md", report)
    write_artifact_manifest(output_dir)
    return report


def report_competitor_harness(run_dir: Path) -> dict[str, object]:
    run_dir = run_dir.expanduser().resolve()
    report_path = run_dir / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    _write_leaderboard_tsv(run_dir / "leaderboard.tsv", report)
    _write_leaderboard_md(run_dir / "leaderboard.md", report)
    write_artifact_manifest(run_dir)
    return report


def score_agent_output(
    output: dict[str, object],
    *,
    expected_flags: Sequence[str] = (),
    evidence_root: Path | None = None,
) -> ScoredAgentOutput:
    raw_flags = _string_tuple(output.get("raw_flags") or output.get("flags") or [])
    expected = {str(flag) for flag in expected_flags}
    valid_flags = _dedupe(flag for flag in raw_flags if flag in expected)
    invalid_flags = _dedupe(flag for flag in raw_flags if flag not in expected)
    findings = output.get("findings") or []
    finding_items = findings if isinstance(findings, list) else []
    false_positives = 0
    out_of_scope = 0
    evidence_failures: list[str] = []
    root = evidence_root or Path.cwd()
    for index, finding in enumerate(finding_items, start=1):
        if not isinstance(finding, dict):
            false_positives += 1
            evidence_failures.append(f"finding[{index}] is not an object")
            continue
        if finding.get("in_scope") is False:
            out_of_scope += 1
            false_positives += 1
            evidence_failures.append(f"finding[{index}] is out of scope")
            continue
        if _finding_has_replayable_evidence(finding, root):
            continue
        false_positives += 1
        evidence_failures.append(f"finding[{index}] missing replayable proof")

    cost, cost_status, cost_provenance = _cost(output)
    telemetry = dict(output)
    telemetry.setdefault("actuals", None)
    telemetry.setdefault("trace_summary", None)
    return ScoredAgentOutput(
        valid_flags=valid_flags,
        invalid_flags=invalid_flags,
        false_positives=false_positives,
        total_reported_findings=len(finding_items),
        out_of_scope_findings=out_of_scope,
        cost_usd=cost,
        cost_status=cost_status,
        cost_provenance=cost_provenance,
        evidence_failures=tuple(evidence_failures),
        telemetry=telemetry,
    )


def write_artifact_manifest(output_dir: Path) -> Path:
    manifest_path = output_dir / "artifacts.sha256"
    rows: list[str] = []
    for path in sorted(item for item in output_dir.rglob("*") if item.is_file()):
        if path == manifest_path:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.relative_to(output_dir)}")
    manifest_path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return manifest_path


def _run_agent_box(  # noqa: PLR0915 - keeps one row's lifecycle and retained errors together.
    *,
    output_dir: Path,
    agent: AgentConfig,
    box: BoxConfig,
    runner: Runner | None,
) -> dict[str, object]:
    run_dir = (output_dir / "agents" / _slug(agent.name) / _slug(box.name)).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    result_path = run_dir / "agent-result.json"
    stdout_path = run_dir / "stdout.log"
    stderr_path = run_dir / "stderr.log"
    network = f"ravage-bench-{_slug(box.name)}-{_slug(agent.name)}"
    env = {
        **os.environ,
        "RAVAGE_COMPETITOR_DOCKER_NETWORK": network,
        "RAVAGE_COMPETITOR_TARGET_URL": box.target_url,
        "RAVAGE_COMPETITOR_OUTPUT_DIR": str(run_dir),
        "RAVAGE_COMPETITOR_RESULT_PATH": str(result_path),
        "RAVAGE_COMPETITOR_AGENT": agent.name,
        "RAVAGE_COMPETITOR_BOX": box.name,
        "RAVAGE_COMPETITOR_MODEL": agent.model,
        "RAVAGE_COMPETITOR_PROVIDER": agent.provider,
        "RAVAGE_COMPETITOR_BOX_COMMIT": box.commit,
    }
    status = "completed"
    exit_code: int | None = None
    error = ""
    timed_out = False
    result_slot_prepared = False
    started = time.monotonic()
    try:
        # A row must only consume output produced by this invocation. In particular,
        # a failed adapter must not inherit a valid result from an earlier run that
        # used the same output directory.
        result_path.unlink(missing_ok=True)
        result_slot_prepared = True
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        _run_process(["docker", "network", "create", "--internal", network], runner=runner)
        completed = _run_process(
            agent.command,
            runner=runner,
            cwd=run_dir,
            env=env,
            timeout=agent.timeout_seconds,
        )
        exit_code = int(completed.returncode)
        stdout_path.write_text(completed.stdout or "", encoding="utf-8")
        stderr_path.write_text(completed.stderr or "", encoding="utf-8")
        if completed.returncode != 0:
            status = "errored"
            error = completed.stderr.strip() or completed.stdout.strip()
    except subprocess.TimeoutExpired as exc:
        status = "timed_out"
        timed_out = True
        error = f"agent timed out after {agent.timeout_seconds} seconds"
        stdout_path.write_text(_stream_text(exc.stdout), encoding="utf-8")
        stderr = _stream_text(exc.stderr)
        stderr_path.write_text(stderr or error, encoding="utf-8")
    except TimeoutError as exc:
        status = "timed_out"
        timed_out = True
        error = str(exc) or f"agent timed out after {agent.timeout_seconds} seconds"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(error, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 - harness rows record adapter failures.
        status = "errored"
        error = str(exc)
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(error, encoding="utf-8")
    finally:
        with suppress(Exception):
            _run_process(["docker", "network", "rm", network], runner=runner, check=False)
    elapsed_seconds = round(time.monotonic() - started, 3)

    output: dict[str, object] = {}
    if result_slot_prepared:
        try:
            output = _read_agent_output(result_path)
        except Exception as exc:  # noqa: BLE001 - malformed rows must not abort the matrix.
            status = "errored"
            error = _combine_errors(error, f"invalid agent result: {exc}")
    if not output and status == "completed":
        status = "errored"
        error = f"agent did not write {result_path.name}"
    scored = score_agent_output(
        output,
        expected_flags=box.expected_flags,
        evidence_root=run_dir,
    )
    return {
        "agent": agent.name,
        "provider": agent.provider,
        "model": agent.model,
        "box": box.name,
        "box_commit": box.commit,
        "target_url": box.target_url,
        "status": status,
        "timed_out": timed_out,
        "elapsed_seconds": elapsed_seconds,
        "exit_code": exit_code,
        "error": error,
        "run_dir": str(run_dir),
        "result_path": str(result_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "raw_flags": list(_string_tuple(output.get("raw_flags") or output.get("flags") or [])),
        "valid_flags": list(scored.valid_flags),
        "invalid_flags": list(scored.invalid_flags),
        "expected_flags": list(box.expected_flags),
        "false_positives": scored.false_positives,
        "false_positive_rate": scored.false_positive_rate,
        "total_reported_findings": scored.total_reported_findings,
        "out_of_scope_findings": scored.out_of_scope_findings,
        "cost_usd": scored.cost_usd,
        "cost_status": scored.cost_status,
        "cost_provenance": scored.cost_provenance,
        "cost_per_valid_flag": scored.cost_per_valid_flag,
        "evidence_failures": list(scored.evidence_failures),
    }


def _aggregate_report(
    *,
    config_path: Path,
    output_dir: Path,
    config: HarnessConfig,
    rows: list[dict[str, object]],
) -> dict[str, object]:
    agents: dict[str, dict[str, object]] = {}
    for agent in config.agents:
        agent_rows = [row for row in rows if row["agent"] == agent.name]
        valid_flags = sum(len(row.get("valid_flags", [])) for row in agent_rows)
        expected_flags = sum(len(row.get("expected_flags", [])) for row in agent_rows)
        solved_cases = sum(1 for row in agent_rows if row.get("valid_flags"))
        attempted = len(agent_rows)
        cost_values = [row.get("cost_usd") for row in agent_rows]
        known_costs = [float(value) for value in cost_values if isinstance(value, int | float)]
        total_cost = round(sum(known_costs), 6) if len(known_costs) == len(agent_rows) else None
        cost_statuses = {str(row.get("cost_status") or "unknown") for row in agent_rows}
        cost_provenances = {
            str(row.get("cost_provenance") or "unavailable") for row in agent_rows
        }
        aggregate_cost_status = _aggregate_cost_label(
            total_cost=total_cost,
            labels=cost_statuses,
            missing_label="unknown",
        )
        aggregate_cost_provenance = _aggregate_cost_provenance(cost_provenances)
        agents[agent.name] = {
            "agent": agent.name,
            "provider": agent.provider,
            "model": agent.model,
            "attempted_cases": attempted,
            "solved_cases": solved_cases,
            "expected_flags": expected_flags,
            "valid_flags": valid_flags,
            "solve_rate": round(valid_flags / expected_flags, 6) if expected_flags else 0.0,
            "false_positives": sum(_int_value(row.get("false_positives")) for row in agent_rows),
            "out_of_scope_findings": sum(
                _int_value(row.get("out_of_scope_findings")) for row in agent_rows
            ),
            "total_reported_findings": sum(
                _int_value(row.get("total_reported_findings")) for row in agent_rows
            ),
            "cost_usd": total_cost,
            "cost_status": aggregate_cost_status,
            "cost_provenance": aggregate_cost_provenance,
            "cost_per_valid_flag": (
                round(total_cost / valid_flags, 6)
                if total_cost is not None and valid_flags
                else None
            ),
        }
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": _now(),
        "config_path": str(config_path),
        "output_dir": str(output_dir),
        "summary": {
            "agents": len(config.agents),
            "boxes": len(config.boxes),
            "runs": len(rows),
        },
        "agents": agents,
        "runs": rows,
    }


def _write_leaderboard_tsv(path: Path, report: Mapping[str, object]) -> None:
    rows = _leaderboard_rows(report)
    header = [
        "agent",
        "provider",
        "model",
        "valid_flags",
        "attempted_cases",
        "solve_rate",
        "false_positives",
        "out_of_scope_findings",
        "cost_usd",
        "cost_per_valid_flag",
        "cost_status",
        "cost_provenance",
    ]
    lines = ["\t".join(header)]
    lines.extend("\t".join(str(row.get(key, "")) for key in header) for row in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_leaderboard_md(path: Path, report: Mapping[str, object]) -> None:
    rows = _leaderboard_rows(report)
    lines = [
        (
            "| Agent | Model | Valid Flags | Cases | Solve Rate | "
            "False Positives | Cost | Cost / Flag | Cost Status | Cost Provenance |"
        ),
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    lines.extend(
        "| {agent} | {provider}/{model} | {valid_flags} | {attempted_cases} | "
        "{solve_rate} | {false_positives} | {cost_usd} | {cost_per_valid_flag} | "
        "{cost_status} | {cost_provenance} |".format(
            **row
        )
        for row in rows
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _leaderboard_rows(report: Mapping[str, object]) -> list[dict[str, object]]:
    agents = report.get("agents", {})
    if not isinstance(agents, dict):
        return []
    rows = [dict(value) for value in agents.values() if isinstance(value, dict)]
    for row in rows:
        row.setdefault("cost_status", "unknown")
        row.setdefault("cost_provenance", "unavailable")
    return sorted(
        rows,
        key=lambda row: (
            -_int_value(row.get("valid_flags")),
            _float_or_large(row.get("cost_per_valid_flag")),
            str(row.get("agent") or ""),
        ),
    )


def _write_normalized_config(path: Path, config: HarnessConfig) -> None:
    path.write_text(yaml.safe_dump(config.to_json(), sort_keys=False), encoding="utf-8")


def _read_agent_output(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        message = f"agent result must be a JSON object: {path}"
        raise TypeError(message)
    return raw


def _finding_has_replayable_evidence(finding: Mapping[str, object], root: Path) -> bool:
    for key in ("proof_path", "evidence_path"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            path = Path(value)
            if path.is_absolute():
                continue
            evidence_root = root.resolve()
            path = (evidence_root / path).resolve()
            try:
                path.relative_to(evidence_root)
            except ValueError:
                continue
            if path.is_file() and path.stat().st_size > 0:
                return True
    proof = finding.get("proof")
    if isinstance(proof, dict):
        request = (
            proof.get("http_request_final")
            or proof.get("http_request")
            or proof.get("request")
        )
        response = (
            proof.get("response_final")
            or proof.get("http_response")
            or proof.get("response")
        )
        return bool(str(request or "").strip() and str(response or "").strip())
    return False


def _cost(output: Mapping[str, object]) -> tuple[float | None, str, str]:
    value = output.get("cost_usd")
    if value is not None and (not isinstance(value, str) or value.strip()):
        parsed = _optional_float(value)
        if parsed is None or not _valid_cost_component(parsed):
            return (None, "invalid", "adapter_reported_invalid")
        return (round(parsed, 6), "reported", "adapter_reported")

    token_keys = (
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "input_cost_per_1m_tokens",
        "cached_input_cost_per_1m_tokens",
        "output_cost_per_1m_tokens",
    )
    has_token_cost = any(output.get(key) is not None for key in token_keys)
    token_cost = _cost_from_tokens(output)
    if token_cost is not None:
        return (token_cost, "computed_from_tokens", "referee_computed_from_tokens")
    if has_token_cost:
        return (None, "invalid", "token_metadata_invalid")
    return (None, "unknown", "unavailable")


def _cost_from_tokens(  # noqa: PLR0911 - each incomplete/invalid price shape fails closed.
    output: Mapping[str, object],
) -> float | None:
    input_tokens = _optional_float(output.get("input_tokens"))
    output_tokens = _optional_float(output.get("output_tokens"))
    input_price = _optional_float(output.get("input_cost_per_1m_tokens"))
    output_price = _optional_float(output.get("output_cost_per_1m_tokens"))
    if None in (input_tokens, output_tokens, input_price, output_price):
        return None
    values = (input_tokens, output_tokens, input_price, output_price)
    if not all(_valid_cost_component(value) for value in values if value is not None):
        return None

    cached_token_value = output.get("cached_input_tokens")
    cached_price_value = output.get("cached_input_cost_per_1m_tokens")
    has_cached_tokens = cached_token_value is not None
    has_cached_price = cached_price_value is not None
    if has_cached_tokens != has_cached_price:
        return None
    cached_input_tokens = 0.0
    cached_input_price = input_price or 0.0
    if has_cached_tokens:
        parsed_cached_input_tokens = _optional_float(cached_token_value)
        parsed_cached_input_price = _optional_float(cached_price_value)
        if parsed_cached_input_tokens is None or parsed_cached_input_price is None:
            return None
        cached_input_tokens = parsed_cached_input_tokens
        cached_input_price = parsed_cached_input_price
        if not _valid_cost_component(cached_input_tokens) or not _valid_cost_component(
            cached_input_price
        ):
            return None
        if cached_input_tokens > (input_tokens or 0.0):
            return None

    uncached_input_tokens = (input_tokens or 0.0) - cached_input_tokens
    return round(
        uncached_input_tokens / 1_000_000 * (input_price or 0.0)
        + cached_input_tokens / 1_000_000 * cached_input_price
        + (output_tokens or 0.0) / 1_000_000 * (output_price or 0.0),
        6,
    )


def _aggregate_cost_label(
    *,
    total_cost: float | None,
    labels: set[str],
    missing_label: str,
) -> str:
    if total_cost is None:
        return "invalid" if any("invalid" in label for label in labels) else missing_label
    if len(labels) == 1:
        return next(iter(labels))
    return "mixed"


def _aggregate_cost_provenance(labels: set[str]) -> str:
    if len(labels) == 1:
        return next(iter(labels))
    if not labels:
        return "unavailable"
    return "mixed"


def _docker_available(*, runner: Runner | None) -> bool:
    try:
        result = _run_process(["docker", "info"], runner=runner, check=False)
    except Exception:  # noqa: BLE001 - preflight reports docker as unavailable.
        return False
    return result.returncode == 0


def _run_process(  # noqa: PLR0913 - thin subprocess wrapper mirrors subprocess.run knobs.
    argv: Sequence[str],
    *,
    runner: Runner | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    if runner is None:
        result = subprocess.run(  # noqa: S603
            list(argv),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    else:
        result = runner(
            list(argv),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            timeout=timeout,
        )
    if check and result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise ProcessRunError(argv, message)
    return result


def _box_config(item: object) -> BoxConfig:
    if not isinstance(item, dict):
        message = "box config entries must be mappings"
        raise TypeError(message)
    return BoxConfig(
        name=str(item.get("name") or ""),
        target_url=str(item.get("target_url") or ""),
        expected_flags=_string_tuple(item.get("expected_flags") or []),
        commit=str(item.get("commit") or ""),
    )


def _agent_config(item: object) -> AgentConfig:
    if not isinstance(item, dict):
        message = "agent config entries must be mappings"
        raise TypeError(message)
    command = _string_tuple(item.get("command") or [])
    if not command:
        message = f"agent {item.get('name') or '<unnamed>'} must define command"
        raise ValueError(message)
    return AgentConfig(
        name=str(item.get("name") or ""),
        provider=str(item.get("provider") or ""),
        model=str(item.get("model") or ""),
        command=command,
        timeout_seconds=_int_value(item.get("timeout_seconds"), DEFAULT_AGENT_TIMEOUT_SECONDS),
    )


def _config_summary(config: HarnessConfig) -> dict[str, object]:
    return {
        "boxes": len(config.boxes),
        "agents": len(config.agents),
        "box_names": [box.name for box in config.boxes],
        "agent_names": [agent.name for agent in config.agents],
    }


def _list_value(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    message = "expected list value"
    raise TypeError(message)


def _string_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    return ()


def _dedupe(values: object) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        item = str(value)
        if item not in seen:
            seen.add(item)
            result.append(item)
    return tuple(result)


def _int_value(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return default


def _optional_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except (OverflowError, ValueError):
            return None
    return None


def _valid_cost_component(value: float) -> bool:
    return math.isfinite(value) and value >= 0.0


def _float_or_large(value: object) -> float:
    maybe = _optional_float(value)
    if maybe is None:
        return 1_000_000_000.0
    return maybe


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-").lower()
    return slug or "unnamed"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stream_text(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _combine_errors(current: str, addition: str) -> str:
    if not current:
        return addition
    return f"{current}; {addition}"
