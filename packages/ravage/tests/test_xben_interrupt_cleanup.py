from __future__ import annotations

import json
from io import StringIO
from pathlib import Path  # noqa: TC003 - pytest evaluates tmp_path annotations at runtime.

import pytest
from ravage.run_data.run_manifest import (
    STATUS_FINISHED,
    STATUS_TORN_DOWN,
    read_manifest,
)
from ravage.xben_parts.models import XbenPreflight, XbenSettings
from ravage.xben_parts.runner import run_xben


def _write_case(root: Path) -> None:
    case_dir = root / "XBEN-001-24"
    case_dir.mkdir(parents=True)
    case_dir.joinpath("benchmark.yaml").write_text(
        """
name: Interrupt lifecycle test
level: 1
tags:
  - web
content:
  - kind: description
    content_type: text/markdown
    content: Test challenge description.
main-service: web
main-service-port: 80
""".lstrip(),
        encoding="utf-8",
    )
    case_dir.joinpath("docker-compose.yml").write_text(
        """
services:
  web:
    image: nginx
    ports:
      - "8080:80"
""".lstrip(),
        encoding="utf-8",
    )


def _allow_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def unblocked_preflight(
        settings: XbenSettings,
        *,
        selected_cases: object = None,
    ) -> XbenPreflight:
        del selected_cases
        return XbenPreflight(
            report_path=settings.output_dir / "preflight.json",
            blocked=False,
            block_reasons=(),
            payload={"blocked": False},
        )

    monkeypatch.setattr("ravage.xben_parts.runner.preflight_xben", unblocked_preflight)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._disk_preflight_payload",
        lambda _settings: {"free_gib": 100.0},
    )


@pytest.mark.parametrize("interrupt_stage", ["build", "up"])
def test_keyboard_interrupt_during_target_startup_finalizes_case_and_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interrupt_stage: str,
) -> None:
    benchmarks_root = tmp_path / "benchmarks"
    output_dir = tmp_path / "run"
    _write_case(benchmarks_root)
    _allow_run(monkeypatch)
    calls: list[str] = []

    def build_case(**_kwargs: object) -> None:
        calls.append("build")
        if interrupt_stage == "build":
            raise KeyboardInterrupt

    def up_case(**_kwargs: object) -> None:
        calls.append("up")
        if interrupt_stage == "up":
            raise KeyboardInterrupt

    monkeypatch.setattr("ravage.xben_parts.runner._build_case", build_case)
    monkeypatch.setattr("ravage.xben_parts.runner._up_case", up_case)
    monkeypatch.setattr(
        "ravage.xben_parts.runner._collect_docker_logs",
        lambda **_kwargs: calls.append("logs"),
    )
    monkeypatch.setattr(
        "ravage.xben_parts.runner._down_case",
        lambda **_kwargs: calls.append("down"),
    )
    stdout = StringIO()

    with pytest.raises(KeyboardInterrupt):
        run_xben(
            XbenSettings(
                benchmarks_root=benchmarks_root,
                output_dir=output_dir,
                all_cases=True,
                keep_target=True,
            ),
            stdout=stdout,
        )

    expected_prefix = ["build"] if interrupt_stage == "build" else ["build", "up"]
    assert calls == [*expected_prefix, "logs", "down"]
    manifest = read_manifest(output_dir / "XBEN-001-24")
    assert manifest is not None
    assert manifest.status == STATUS_TORN_DOWN
    assert manifest.phase == "interrupted"
    assert manifest.result_label == "interrupted"
    assert manifest.target_alive is False
    assert manifest.is_active is False
    assert manifest.finished_at
    assert manifest.teardown_at
    manifest_payload = json.loads(
        (output_dir / "XBEN-001-24" / "run.json").read_text(encoding="utf-8")
    )
    assert manifest_payload["is_active"] is False

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == "incomplete"
    assert report["termination_reason"] == "keyboard_interrupt"
    assert report["summary"]["completed"] == 0
    assert "[xben:interrupted] id=XBEN-001-24 cleanup=attempted" in stdout.getvalue()


def test_keyboard_interrupt_preserves_interrupt_when_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    benchmarks_root = tmp_path / "benchmarks"
    output_dir = tmp_path / "run"
    _write_case(benchmarks_root)
    _allow_run(monkeypatch)
    calls: list[str] = []
    log_error = "log capture failed"
    teardown_error = "teardown failed"

    monkeypatch.setattr("ravage.xben_parts.runner._build_case", lambda **_kwargs: None)

    def interrupt_up(**_kwargs: object) -> None:
        raise KeyboardInterrupt

    def fail_logs(**_kwargs: object) -> None:
        calls.append("logs")
        raise RuntimeError(log_error)

    def fail_down(**_kwargs: object) -> None:
        calls.append("down")
        raise RuntimeError(teardown_error)

    monkeypatch.setattr("ravage.xben_parts.runner._up_case", interrupt_up)
    monkeypatch.setattr("ravage.xben_parts.runner._collect_docker_logs", fail_logs)
    monkeypatch.setattr("ravage.xben_parts.runner._down_case", fail_down)

    with pytest.raises(KeyboardInterrupt) as captured:
        run_xben(
            XbenSettings(
                benchmarks_root=benchmarks_root,
                output_dir=output_dir,
                all_cases=True,
            ),
            stdout=StringIO(),
        )

    assert calls == ["logs", "down"]
    notes = getattr(captured.value, "__notes__", ())
    assert any("log capture failed" in note for note in notes)
    assert any("teardown failed" in note for note in notes)

    manifest = read_manifest(output_dir / "XBEN-001-24")
    assert manifest is not None
    assert manifest.status == STATUS_FINISHED
    assert manifest.phase == "interrupted"
    assert manifest.result_label == "interrupted"
    assert manifest.target_alive is True
    assert manifest.is_active is False
    assert manifest.finished_at
    assert manifest.teardown_at == ""
    manifest_payload = json.loads(
        (output_dir / "XBEN-001-24" / "run.json").read_text(encoding="utf-8")
    )
    assert manifest_payload["is_active"] is False

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert report["run_status"] == "incomplete"
    assert report["termination_reason"] == "keyboard_interrupt"
