from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, ClassVar, cast

import pytest
from ravage import __main__ as cli
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyController,
)
from ravage.web_core.http_probe import ProbeSession

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path


_CLI_USAGE_ERROR = 2
_LEDGER_FAILURE_MESSAGE = "private ledger failure"


class _CountingHandler(BaseHTTPRequestHandler):
    paths: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).paths.append(self.path)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        del args


@pytest.fixture
def counting_server() -> Iterator[tuple[str, list[str]]]:
    _CountingHandler.paths = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}/", _CountingHandler.paths
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _write_brief(path: Path, target_url: str) -> None:
    path.write_text(
        f"""engagement_id: 11111111-1111-4111-8111-111111111111
scope:
  in_scope:
    - {target_url}
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
objectives:
  - web_application_assessment
budget:
  max_cost_usd: 1.0
  max_runtime_min: 5
context:
  description: scan traffic policy integration fixture
""",
        encoding="utf-8",
    )


def _metered_probe(probe: str, **kwargs: object) -> ProbeRunResult:
    target_url = str(kwargs["target_url"])
    policy = cast("TrafficPolicyController", kwargs["traffic_policy"])
    observer = cast("Callable[[dict[str, object]], None] | None", kwargs["traffic_observer"])
    session = ProbeSession(
        target_url,
        in_scope=cast("tuple[str, ...]", kwargs["in_scope"]),
        out_of_scope=cast("tuple[str, ...]", kwargs["out_of_scope"]),
        traffic_observer=observer,
        traffic_policy=policy,
    )
    response = session.get(f"{target_url.rstrip('/')}/{probe}")
    return ProbeRunResult(
        ok=response.ok,
        probe=probe,
        summary="request completed" if response.ok else response.error,
        requests=[response.summary()],
        errors=[response.error] if response.error else [],
        http_request_count=session.physical_request_count,
    )


def test_scan_low_noise_cap_matches_real_physical_dispatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    counting_server: tuple[str, list[str]],
) -> None:
    target_url, dispatched_paths = counting_server
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_brief(brief, target_url)
    monkeypatch.setattr(cli, "run_builtin_probe", _metered_probe)

    cli.main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--probe",
            "secret_sweep",
            "--traffic-policy",
            "low-noise",
            "--max-physical-requests",
            "1",
            "--traffic-max-rps",
            "0.9",
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )

    summary = json.loads(capsys.readouterr().out)
    accounting = summary["traffic_accounting"]
    coverage = json.loads((run_dir / "scan-coverage.json").read_text(encoding="utf-8"))
    assert dispatched_paths == ["/surface_map"]
    assert accounting["physical_request_count"] == len(dispatched_paths) == 1
    assert accounting["completed_request_count"] == 1
    assert accounting["blocked_count"] == 1
    assert accounting["remaining_physical_requests"] == 0
    assert accounting["accounting_status"] == "exact"
    assert accounting["provenance"] == "workspace_traffic_policy_ledger"
    assert coverage["status"] == "partial"
    assert "budget_blocked" in coverage["limitations"]
    assert "traffic_policy_blocked" in coverage["limitations"]
    assert [record["disposition"] for record in coverage["probes"]] == [
        "completed_no_finding",
        "blocked_budget",
    ]


def test_scan_opaque_transport_is_accounted_or_blocked(tmp_path: Path) -> None:
    observe = TrafficPolicyController.open(
        tmp_path / "observe.json",
        target_url="http://127.0.0.1:4321/",
        config=TrafficPolicyConfig(),
    )
    enforce = TrafficPolicyController.open(
        tmp_path / "enforce.json",
        target_url="http://127.0.0.1:4321/",
        config=TrafficPolicyConfig.low_noise(max_physical_requests=3, max_rps=0.9),
    )

    assert (
        cli._guard_scan_probe_traffic(  # noqa: SLF001
            "surface_map", traffic_policy=observe
        )
        == ""
    )
    assert (
        cli._guard_scan_probe_traffic(  # noqa: SLF001
            "dom_execution", traffic_policy=observe
        )
        == ""
    )
    observed = cli._scan_traffic_accounting(observe)  # noqa: SLF001
    assert observed["unmetered_action_count"] == 1
    assert observed["accounting_status"] == "lower_bound"

    reason = cli._guard_scan_probe_traffic(  # noqa: SLF001
        "dom_execution", traffic_policy=enforce
    )
    assert "unmetered network-capable actions" in reason
    blocked = cli._scan_traffic_accounting(enforce)  # noqa: SLF001
    assert blocked["unmetered_action_count"] == 0
    assert blocked["blocked_count"] == 1
    assert blocked["accounting_status"] == "exact"


def test_scan_requires_a_fresh_run_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_brief(brief, "http://127.0.0.1:4321/")
    monkeypatch.setattr(
        cli,
        "run_builtin_probe",
        lambda probe, **_kwargs: ProbeRunResult(ok=True, probe=probe, summary="done"),
    )
    command = [
        "scan",
        str(brief),
        "--probe",
        "surface_map",
        "--run-dir",
        str(run_dir),
        "--json",
    ]

    cli.main(command)
    capsys.readouterr()
    with pytest.raises(SystemExit, match="scan run directory already contains prior state"):
        cli.main(command)


def test_scan_aborts_when_mandatory_traffic_ledger_cannot_initialize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    _write_brief(brief, "http://127.0.0.1:4321/")
    probe_called = False

    def fail_open(*_args: object, **_kwargs: object) -> TrafficPolicyController:
        raise OSError(_LEDGER_FAILURE_MESSAGE)

    def run_probe(probe: str, **_kwargs: object) -> ProbeRunResult:
        nonlocal probe_called
        probe_called = True
        return ProbeRunResult(ok=True, probe=probe, summary="unexpected")

    monkeypatch.setattr(cli.TrafficPolicyController, "open", fail_open)
    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)

    with pytest.raises(SystemExit) as stopped:
        cli.main(
            [
                "scan",
                str(brief),
                "--probe",
                "surface_map",
                "--run-dir",
                str(tmp_path / "run"),
            ]
        )

    assert stopped.value.code == _CLI_USAGE_ERROR
    assert not probe_called
    stderr = capsys.readouterr().err
    assert "cannot initialize scan traffic policy" in stderr
    assert _LEDGER_FAILURE_MESSAGE in stderr
