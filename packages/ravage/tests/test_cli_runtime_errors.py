from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from ravage import __main__ as cli

if TYPE_CHECKING:
    from pathlib import Path

_BRIEF_YAML = """
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


def test_cli_docker_runtime_setup_error_is_actionable_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(_BRIEF_YAML, encoding="utf-8")
    runtime_error = "Docker daemon is not reachable. Start Docker Desktop and retry."

    def fail_runtime_setup(**_: object) -> None:
        raise cli.ScopedNetworkError(runtime_error)

    monkeypatch.setattr(cli, "run_ai_web_agent", fail_runtime_setup)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "--brief",
                str(brief_path),
                "--target-url",
                "http://127.0.0.1:8765",
                "--tool-runtime",
                "docker",
                "--display",
                "plain",
            ]
        )

    assert exc_info.value.code == 1
    error = capsys.readouterr().err
    assert "[fail] Docker daemon is not reachable" in error
    assert "Start Docker Desktop" in error
    assert "Traceback" not in error
