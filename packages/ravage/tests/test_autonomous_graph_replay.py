from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.autonomous_graph.replay import (
    GraphReplayError,
    load_recorded_observations,
    replay_case_artifacts,
    verify_checksum_manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

CASE_ID = "XBEN-029-24"
TARGET_URL = "http://127.0.0.1:8765"
EXPECTED_REPLAY_OBSERVATIONS = 2
EXPECTED_MATERIAL_RECORDS = 3


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_events(path: Path, events: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{json.dumps(event, sort_keys=True)}\n" for event in events),
        encoding="utf-8",
    )


def _write_manifest(run_root: Path, paths: Iterable[Path]) -> None:
    entries = []
    for path in sorted(paths):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        relative = path.relative_to(run_root).as_posix()
        entries.append(f"{digest}  {relative}\n")
    (run_root / "artifacts.sha256").write_text(
        "".join(entries),
        encoding="utf-8",
    )


def _sql_probe_payload() -> dict[str, object]:
    return {
        "ok": True,
        "probe": "sqli_differential",
        "findings": [
            {
                "type": "sql_literal_comment_exposed_secret",
                "input": {"name": "lookup"},
                "replay": {
                    "method": "POST",
                    "url": "http://target/search",
                    "payload_field": "lookup",
                    "form": {"lookup": "redacted"},
                },
                "response": {
                    "status": 200,
                    "body_snippet": "redacted",
                },
            }
        ],
    }


def _build_run(  # noqa: PLR0913 - test fixture exposes each corruption axis.
    tmp_path: Path,
    *,
    artifact_reference: str | None = None,
    include_probe_artifact: bool = True,
    base_action_id: str = "base-action",
    tool_action_id: str = "base-action",
    include_tool_action_id: bool = True,
) -> tuple[Path, Path]:
    run_root = tmp_path / "run"
    workspace = run_root / CASE_ID / "workspace"
    route_workspace = workspace / "autonomous-route"
    probe_artifact = workspace / "artifacts" / "probe.json"
    _write_json(workspace / "working_state.json", {"target_url": TARGET_URL})
    _write_json(probe_artifact, _sql_probe_payload())

    probe_result: object = {
        "artifact_path": artifact_reference or str(probe_artifact),
        "snippet": "truncated",
        "truncated": True,
    }
    probe_payload: dict[str, object] = {
        "observation_id": "base-observation",
        "ok": True,
        "recognized_proofs": [],
        "repeat_count": 0,
        "result": probe_result,
        "timed_out": False,
    }
    if include_tool_action_id:
        probe_payload["action_id"] = tool_action_id
    base_action = {
        "action": "run_probe",
        "probe": "sqli_differential",
        "strategy": "bounded-differential",
    }
    _write_events(
        workspace / "events.jsonl",
        (
            {
                "kind": "agent_action_selected",
                "payload": {"action": base_action, "turn": 1},
            },
            {
                "kind": "action_started",
                "payload": {
                    "action_id": base_action_id,
                    "action_kind": "run_probe",
                    "params": {"probe": "sqli_differential"},
                    "turn": 1,
                },
            },
            {"kind": "tool_run_probe", "payload": probe_payload},
            {
                "kind": "agent_attempt_recorded",
                "payload": {
                    "action_id": base_action_id,
                    "outcome": {
                        "classification": "confirmed_signal",
                        "ok": True,
                        "repeat_count": 0,
                        "stop": False,
                    },
                    "selected_action": base_action,
                },
            },
        ),
    )

    python_action = {
        "action": "run_python",
        "code": "print(fake_finding)",
    }
    _write_events(
        route_workspace / "events.jsonl",
        (
            {
                "kind": "tool_run_python",
                "payload": {
                    "action_id": "route-action",
                    "exit_code": 0,
                    "observation_id": "route-observation",
                    "ok": True,
                    "recognized_proofs": [],
                    "repeat_count": 0,
                    "stderr": "",
                    "stdout": json.dumps(_sql_probe_payload()),
                    "timed_out": False,
                },
            },
            {
                "kind": "frontier_action_completed",
                "payload": {
                    "action": python_action,
                    "action_id": "route-action",
                    "outcome": {
                        "classification": "observed",
                        "exit_code": 0,
                        "ok": True,
                    },
                    "worker_id": "sql-closure",
                },
            },
        ),
    )
    covered = [
        workspace / "working_state.json",
        workspace / "events.jsonl",
        route_workspace / "events.jsonl",
    ]
    if include_probe_artifact:
        covered.append(probe_artifact)
    _write_manifest(run_root, covered)
    return run_root, probe_artifact


def test_replay_is_deterministic_and_only_promotes_typed_probe(
    tmp_path: Path,
) -> None:
    run_root, _ = _build_run(tmp_path)

    first = replay_case_artifacts(
        run_root=run_root,
        case_id=CASE_ID,
        blackboard_path=tmp_path / "blackboard-one.json",
    )
    second = replay_case_artifacts(
        run_root=run_root,
        case_id=CASE_ID,
        blackboard_path=tmp_path / "blackboard-two.json",
    )

    assert first == second
    assert first.observations == EXPECTED_REPLAY_OBSERVATIONS
    assert first.trusted_observations == EXPECTED_REPLAY_OBSERVATIONS
    assert first.unique_raw_records == EXPECTED_REPLAY_OBSERVATIONS
    assert first.duplicate_raw_records == 0
    assert first.material_records == EXPECTED_MATERIAL_RECORDS
    assert first.proof_records == 0
    assert first.source_counts == {
        "tool_run_probe": 1,
        "tool_run_python": 1,
    }
    assert first.progress_counts == {
        "request_template_validated": 1,
        "response_differential_validated": 1,
    }
    assert first.producer_counts == {
        "replay-base": 1,
        "replay-frontier:sql-closure": 1,
    }

    checksum = verify_checksum_manifest(run_root / "artifacts.sha256")
    observations = load_recorded_observations(
        run_root / CASE_ID,
        checksum_root=run_root,
        checksum=checksum,
    )
    assert observations[0].action["strategy"] == "bounded-differential"
    assert observations[1].result.exit_code == 0


def test_replay_rejects_tampered_checksum_artifact(tmp_path: Path) -> None:
    run_root, probe_artifact = _build_run(tmp_path)
    probe_artifact.write_text("tampered\n", encoding="utf-8")

    with pytest.raises(GraphReplayError, match="checksum artifact mismatch"):
        replay_case_artifacts(
            run_root=run_root,
            case_id=CASE_ID,
            blackboard_path=tmp_path / "blackboard.json",
        )


def test_replay_rejects_uncovered_artifact(tmp_path: Path) -> None:
    run_root, _ = _build_run(
        tmp_path,
        include_probe_artifact=False,
    )

    with pytest.raises(GraphReplayError, match="not checksum-covered"):
        replay_case_artifacts(
            run_root=run_root,
            case_id=CASE_ID,
            blackboard_path=tmp_path / "blackboard.json",
        )


def test_replay_resolves_relocatable_suffix_of_launch_relative_artifact(
    tmp_path: Path,
) -> None:
    artifact_reference = f"archived/launch/path/{CASE_ID}/workspace/artifacts/probe.json"
    run_root, _ = _build_run(
        tmp_path,
        artifact_reference=artifact_reference,
    )

    replay = replay_case_artifacts(
        run_root=run_root,
        case_id=CASE_ID,
        blackboard_path=tmp_path / "blackboard.json",
    )

    assert replay.observations == EXPECTED_REPLAY_OBSERVATIONS
    assert replay.trusted_observations == EXPECTED_REPLAY_OBSERVATIONS


def test_replay_rejects_artifact_path_escape(tmp_path: Path) -> None:
    escaped_artifact = tmp_path / "run" / "escaped.json"
    _write_json(escaped_artifact, _sql_probe_payload())
    run_root, probe_artifact = _build_run(
        tmp_path,
        artifact_reference=str(escaped_artifact),
    )
    _write_manifest(
        run_root,
        (
            run_root / CASE_ID / "workspace" / "working_state.json",
            run_root / CASE_ID / "workspace" / "events.jsonl",
            run_root / CASE_ID / "workspace" / "autonomous-route" / "events.jsonl",
            probe_artifact,
            escaped_artifact,
        ),
    )

    with pytest.raises(GraphReplayError, match="escapes its allowed root"):
        replay_case_artifacts(
            run_root=run_root,
            case_id=CASE_ID,
            blackboard_path=tmp_path / "blackboard.json",
        )


@pytest.mark.parametrize(
    ("include_tool_action_id", "tool_action_id", "message"),
    [
        (False, "base-action", "lacks action or observation provenance"),
        (True, "unknown-action", "recorded tool action is missing"),
    ],
)
def test_replay_rejects_missing_action_provenance(
    tmp_path: Path,
    *,
    include_tool_action_id: bool,
    tool_action_id: str,
    message: str,
) -> None:
    run_root, _ = _build_run(
        tmp_path,
        include_tool_action_id=include_tool_action_id,
        tool_action_id=tool_action_id,
    )

    with pytest.raises(GraphReplayError, match=message):
        replay_case_artifacts(
            run_root=run_root,
            case_id=CASE_ID,
            blackboard_path=tmp_path / "blackboard.json",
        )
