from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ravage import __main__ as cli
from ravage.probe_suite_parts.result import ProbeRunResult

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _write_brief(path: Path) -> None:
    path.write_text(
        """engagement_id: 11111111-1111-4111-8111-111111111111
scope:
  in_scope:
    - http://127.0.0.1:4321/
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
  description: adaptive scan CLI fixture
""",
        encoding="utf-8",
    )


class _ReconResult:
    def to_json(self) -> dict[str, object]:
        return {
            "target_url": "http://127.0.0.1:4321/",
            "origin": "http://127.0.0.1:4321",
            "pages": [
                {
                    "url": "http://127.0.0.1:4321/",
                    "status": 200,
                    "final_url": "http://127.0.0.1:4321/",
                    "headers": {"Content-Type": "text/html"},
                    "links": ["/fetch"],
                    "scripts": [],
                    "forms": [
                        {
                            "method": "POST",
                            "action": "http://127.0.0.1:4321/fetch",
                            "enctype": "application/x-www-form-urlencoded",
                            "inputs": [
                                {
                                    "name": "callback",
                                    "type": "url",
                                    "value": "",
                                    "required": False,
                                    "disabled": False,
                                }
                            ],
                        }
                    ],
                    "request_templates": [],
                    "query_parameter_names": [],
                    "interesting_markers": [],
                    "reflected_parameters": [],
                    "error": "",
                }
            ],
            "query_parameter_names": [],
            "interesting_markers": [],
            "errors": [],
            "http_request_count": 1,
        }


def test_default_scan_replans_breadth_then_trusted_depth_and_writes_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_brief(brief)
    executed: list[str] = []

    def run_probe(probe: str, **_kwargs: object) -> ProbeRunResult:
        executed.append(probe)
        findings = [{"type": "sql_injection_error_signal"}] if probe == "sqli_differential" else []
        return ProbeRunResult(
            ok=bool(findings),
            probe=probe,
            summary="typed finding" if findings else "completed without a finding",
            findings=findings,
        )

    monkeypatch.setattr(cli, "run_recon", lambda *_args, **_kwargs: _ReconResult())
    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)

    cli.main(
        [
            "scan",
            str(brief),
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )

    summary = json.loads(capsys.readouterr().out)
    coverage = json.loads((run_dir / "scan-coverage.json").read_text(encoding="utf-8"))
    assert summary["planner_mode"] == "adaptive"
    assert summary["probes_executed"] == executed
    assert len(executed) == len(set(executed))
    assert "ssrf_boundary" in executed
    assert "data_query" in executed
    assert "sqli_differential" in executed
    assert "sqli_exploit" in executed
    assert "filtered_query_bypass" in executed
    assert executed.index("data_query") < executed.index("sqli_exploit")
    assert executed.index("sqli_differential") < executed.index("sqli_exploit")
    assert executed.index("sqli_differential") < executed.index("filtered_query_bypass")
    assert coverage["status"] == "complete"
    assert coverage["completion_basis"] == "planner_frontier_exhausted"
    assert coverage["limitations"] == []
    encoded_coverage = json.dumps(coverage).lower()
    assert "no vulnerabilities" not in encoded_coverage
    assert "application_exhausted" not in encoded_coverage
    assert "family_exhausted" not in encoded_coverage


def test_explicit_probe_order_and_duplicates_do_not_invoke_adaptive_recon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_brief(brief)
    executed: list[str] = []

    def reject_recon(*_args: object, **_kwargs: object) -> object:
        message = "explicit scans must not invoke adaptive recon"
        raise AssertionError(message)

    def run_probe(probe: str, **_kwargs: object) -> ProbeRunResult:
        executed.append(probe)
        return ProbeRunResult(ok=True, probe=probe, summary="completed")

    monkeypatch.setattr(cli, "run_recon", reject_recon)
    monkeypatch.setattr(cli, "run_builtin_probe", run_probe)

    cli.main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--probe",
            "secret_sweep",
            "--probe",
            "surface_map",
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )

    summary = json.loads(capsys.readouterr().out)
    coverage = json.loads((run_dir / "scan-coverage.json").read_text(encoding="utf-8"))
    assert executed == ["surface_map", "secret_sweep", "surface_map"]
    assert summary["planner_mode"] == "explicit"
    assert [record["probe_id"] for record in coverage["probes"]] == [
        "surface_map",
        "secret_sweep",
        "surface_map.2",
    ]


def test_opaque_explicit_probe_produces_an_honest_partial_certificate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = tmp_path / "brief.yaml"
    run_dir = tmp_path / "run"
    _write_brief(brief)
    monkeypatch.setattr(
        cli,
        "run_builtin_probe",
        lambda probe, **_kwargs: ProbeRunResult(ok=True, probe=probe, summary="rendered"),
    )

    cli.main(
        [
            "scan",
            str(brief),
            "--probe",
            "dom_execution",
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )

    capsys.readouterr()
    coverage = json.loads((run_dir / "scan-coverage.json").read_text(encoding="utf-8"))
    assert coverage["status"] == "partial"
    assert coverage["traffic"]["accounting_status"] == "lower_bound"
    assert "traffic_accounting_lower_bound" in coverage["limitations"]
    assert "unmetered_actions" in coverage["limitations"]
    assert coverage["probes"][0]["request_accounting_status"] == "lower_bound"
