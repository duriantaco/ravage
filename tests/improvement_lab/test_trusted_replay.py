from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from tools.improvement_lab.trusted_replay import TrustedReplayError, replay_previous_run

if TYPE_CHECKING:
    from pathlib import Path

_KEY = b"historical-replay-test-key-32bytes!"


def _run_root(tmp_path: Path, *case_names: str) -> Path:
    root = tmp_path / "prior-run"
    covered: list[Path] = []
    for case_name in case_names:
        workspace = root / case_name / "workspace"
        workspace.mkdir(parents=True)
        state = workspace / "working_state.json"
        events = workspace / "events.jsonl"
        state.write_text('{"target_url":"http://sensitive.invalid"}\n', encoding="utf-8")
        events.write_text("{}\n", encoding="utf-8")
        covered.extend((state, events))
    lines = []
    for path in covered:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(root).as_posix()}")
    (root / "artifacts.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return root


def _report(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "observations": 3,
        "trusted_observations": 3,
        "unique_raw_records": 2,
        "duplicate_raw_records": 1,
        "material_records": 2,
        "proof_records": 1,
        "source_counts": {"tool_run_probe": 3},
        "progress_counts": {"evidence": 2},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_previous_run_replay_is_opaque_and_never_promotable(tmp_path: Path) -> None:
    root = _run_root(tmp_path, "XBEN-secret-case")
    seen: list[str] = []

    def replay(**kwargs: object) -> SimpleNamespace:
        seen.append(str(kwargs["case_id"]))
        return _report()

    receipt = replay_previous_run(root, hmac_key=_KEY, replay=replay)
    payload = receipt.to_json()
    serialized = json.dumps(payload, sort_keys=True)

    assert seen == ["XBEN-secret-case"]
    assert payload["execution_kind"] == "historical_replay"
    assert payload["promotable"] is False
    assert payload["totals"]["completed_cases"] == 1
    assert payload["totals"]["proof_records"] == 1
    assert "XBEN-secret-case" not in serialized
    assert "sensitive.invalid" not in serialized
    assert receipt.cases[0].case_id.startswith("case_")


def test_replay_errors_do_not_expose_exception_text(tmp_path: Path) -> None:
    root = _run_root(tmp_path, "private-case")

    def replay(**_kwargs: object) -> SimpleNamespace:
        message = "proof-value and /private/route"
        raise ValueError(message)

    receipt = replay_previous_run(root, hmac_key=_KEY, replay=replay)
    serialized = json.dumps(receipt.to_json(), sort_keys=True)

    assert receipt.cases[0].status == "errored"
    assert receipt.cases[0].error_code == "unreadable_replay_artifact"
    assert "proof-value" not in serialized
    assert "/private/route" not in serialized


def test_replay_fails_closed_on_bad_checksum_and_short_key(tmp_path: Path) -> None:
    root = _run_root(tmp_path, "case")
    events = root / "case" / "workspace" / "events.jsonl"
    events.write_text('{"tampered":true}\n', encoding="utf-8")

    with pytest.raises(TrustedReplayError, match="checksum"):
        replay_previous_run(root, hmac_key=_KEY)
    with pytest.raises(TrustedReplayError, match="at least 32 bytes"):
        replay_previous_run(root, hmac_key=b"short")
