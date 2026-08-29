from __future__ import annotations

import json

import pytest
from ravage import __main__ as cli
from ravage import authbench
from ravage.authbench import (
    MANIFEST_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    AuthBenchCaseResult,
    AuthBenchCheck,
    AuthBenchObservation,
    AuthBenchResult,
    default_manifest,
)


def test_top_level_help_lists_authbench_as_optional(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    assert exc_info.value.code == 0
    assert "ravage authbench" in capsys.readouterr().out


def test_authbench_defaults_to_concise_per_case_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(["authbench"])

    output = capsys.readouterr().out
    assert "RAVAGE // AUTHBENCH" in output
    for case in default_manifest().cases:
        assert f"[pass] {case.case_id}" in output
    assert "[pass] 7/7 cases" in output
    assert '"schema_version"' not in output


def test_authbench_json_emits_stable_result_contract(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(["authbench", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == RESULT_SCHEMA_VERSION
    assert payload["manifest_schema_version"] == MANIFEST_SCHEMA_VERSION
    assert payload["passed"] is True
    assert payload["score"] == {"passed": 7, "total": 7}
    assert len(payload["cases"]) == 7


def test_authbench_failure_is_concise_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    failed = AuthBenchResult(
        benchmark_id="ravage-authbench-cli-test",
        manifest_schema_version=MANIFEST_SCHEMA_VERSION,
        manifest_revision=1,
        cases=(
            AuthBenchCaseResult(
                case_id="forced_expiry",
                passed=False,
                checks=(
                    AuthBenchCheck(
                        name="reauthenticated",
                        passed=False,
                        detail="session was not restored",
                    ),
                ),
                observation=AuthBenchObservation(authenticated=False),
            ),
        ),
    )
    monkeypatch.setattr(authbench, "run_authbench", lambda strategy: failed)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["authbench"])

    assert exc_info.value.code == 1
    output = capsys.readouterr().out
    assert "[fail] forced_expiry — reauthenticated" in output
    assert "[fail] 0/1 cases" in output
