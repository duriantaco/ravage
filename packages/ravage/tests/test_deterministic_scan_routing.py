from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ravage import __main__ as cli
from ravage.agent_core.agent_state import AgentState, load_agent_state
from ravage.probe_suite import available_probes
from ravage.probe_suite_parts.result import ProbeRunResult

if TYPE_CHECKING:
    from pathlib import Path


_BRIEF = """
engagement_id: "99999999-9999-4999-8999-999999999999"
scope:
  in_scope:
    - "http://127.0.0.1:8765/app"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "web_application_assessment"
budget:
  max_cost_usd: 1
  max_runtime_min: 5
context:
  description: "Local deterministic scan routing test."
  win_condition: "Record observed target surface."
""".lstrip()


def test_scan_help_warns_that_all_probes_is_high_traffic(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["scan", "--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "broad catalog" in output
    assert "thousands of bounded requests" in output
    assert "authorized remote targets" in output


def test_all_scan_probes_follow_dependencies_but_explicit_order_is_preserved() -> None:
    requested = ["dom_execution", "surface_map", "api_behavior"]

    assert cli._selected_scan_probes(requested, all_probes=False) == requested  # noqa: SLF001

    selected = cli._selected_scan_probes([], all_probes=True)  # noqa: SLF001
    assert set(selected) == {item["name"] for item in available_probes()}
    assert selected[: len(cli._SCAN_DISCOVERY_PROBES)] == list(  # noqa: SLF001
        cli._SCAN_DISCOVERY_PROBES  # noqa: SLF001
    )
    for probe, dependencies in cli._SCAN_PROBE_DEPENDENCIES.items():  # noqa: SLF001
        if probe not in selected:
            continue
        for dependency in dependencies:
            if dependency in selected:
                assert selected.index(dependency) < selected.index(probe)


def test_scan_seeds_target_bound_state_and_ingests_structured_probe_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brief = tmp_path / "brief.yaml"
    brief.write_text(_BRIEF, encoding="utf-8")
    run_dir = tmp_path / "scan-run"
    observed: dict[str, object] = {}

    def fake_probe(
        probe: str,
        *,
        target_url: str,
        state: AgentState,
        **_kwargs: object,
    ) -> ProbeRunResult:
        observed["target_url"] = state.surface.get("target_url")
        observed["origin"] = state.surface.get("origin")
        observed["graph_origin"] = state.surface_graph.target_origin
        return ProbeRunResult(
            ok=True,
            probe=probe,
            summary="observed one route",
            requests=[
                {
                    "method": "GET",
                    "url": f"{target_url.rstrip('/')}/discovered",
                    "status": 200,
                    "headers": {"Server": "nginx/1.27.5"},
                    "body_snippet": '<a href="/app/next">Next</a>',
                }
            ],
        )

    monkeypatch.setattr(cli, "run_builtin_probe", fake_probe)

    cli.main(
        [
            "scan",
            str(brief),
            "--probe",
            "surface_map",
            "--run-dir",
            str(run_dir),
            "--json",
        ]
    )

    assert observed == {
        "target_url": "http://127.0.0.1:8765/app",
        "origin": "http://127.0.0.1:8765",
        "graph_origin": "http://127.0.0.1:8765",
    }
    saved = load_agent_state(run_dir / "workspace" / "working_state.json")
    assert saved is not None
    assert any(
        operation.structural_url == "http://127.0.0.1:8765/app/discovered"
        for operation in (saved.surface_graph.operations or {}).values()
    )
    assert "/1.27.5" not in saved.signals.get("endpoints", [])
