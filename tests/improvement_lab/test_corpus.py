from __future__ import annotations

import base64
import json
import os
from typing import TYPE_CHECKING
from urllib.parse import quote

import pytest

from tools.improvement_lab.corpus import (
    CAPSULE_SCHEMA_VERSION,
    DEVELOPMENT,
    SEALED_HOLDOUT,
    CorpusFormatError,
    CorpusLeakError,
    CorpusSplit,
    HoldoutAccessError,
    candidate_visible_export,
    find_leaks,
    ingest_events_jsonl,
    ingest_run_dir,
    scan_for_leaks,
    serialize_candidate_corpus,
    serialize_capsule,
    write_candidate_corpus,
    write_capsule,
)

if TYPE_CHECKING:
    from pathlib import Path

HMAC_KEY = b"development-only-test-key-material-0001"
SECOND_HMAC_KEY = b"development-only-test-key-material-0002"
EXPECTED_FACTS_DELTA = 2
EXPECTED_IGNORED_EVENTS = 2
EXPECTED_PHYSICAL_REQUESTS = 7


def _write_events(path: Path, events: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def _traffic_snapshot() -> dict[str, object]:
    return {
        "physical_request_count": 7,
        "completed_request_count": 6,
        "incomplete_request_count": 1,
        "pending_dispatch_count": 0,
        "reservation_count": 7,
        "cache_hit_count": 2,
        "deduplicated_count": 3,
        "retry_count": 1,
        "blocked_count": 4,
        "circuit_open_count": 1,
        "unmetered_action_count": 0,
        "accounting_status": "exact",
        "target_origin": "http://private.invalid:8765",
        "cache": {"response_body": "must-not-survive"},
    }


def _double_percent_encode(value: str) -> str:
    return quote(quote(value, safe=""), safe="")


def _double_base64(value: str) -> str:
    once = base64.b64encode(value.encode()).decode()
    return base64.b64encode(once.encode()).decode()


def _representative_events(secret: str) -> list[dict[str, object]]:
    endpoint = "http://private.invalid:8765/admin/42?access=" + secret
    proposed = {
        "action": "run_probe",
        "method": "GET",
        "params": {
            "url": endpoint,
            "input_name": "account_id",
            "payload": {"body": secret},
        },
        "authorization": secret,
    }
    selected = {
        "action": "validate_sqli",
        "method": "POST",
        "params": {
            "endpoint": endpoint,
            "parameter": "account_id",
            "body": secret,
        },
    }
    return [
        {
            "kind": "harness_selection",
            "timestamp": "2040-01-01T00:00:00Z",
            "payload": {
                "turn": 1,
                "action_id": "raw-action-1",
                "proposed_action": proposed,
                "selected_action": selected,
                "selected_differs_from_model": True,
                "selection_reason": "repeat_guard_with_literal_detail_" + secret,
                "proposed_route": {"path": "/admin/42", "input": "account_id"},
                "selected_route": {"path": "/admin/42", "input": "account_id"},
                "repeat_context": secret,
            },
        },
        {
            "kind": "agent_attempt_recorded",
            "payload": {
                "turn": 1,
                "action_id": "raw-action-1",
                "proposed_action": proposed,
                "selected_action": selected,
                "selected_differs_from_model": True,
                "selection_reason": "repeat_guard",
                "proposed_route": endpoint,
                "selected_route": endpoint,
                "proposed_fingerprint": secret,
                "selected_fingerprint": secret,
                "exact_selected_fingerprint": secret,
                "evidence_epoch_before": "raw-epoch-before",
                "evidence_epoch_after": "raw-epoch-after",
                "outcome": {
                    "ok": True,
                    "stop": False,
                    "classification": "finding_confirmed",
                    "repeat_count": 2,
                    "raw_output": secret,
                },
                "novel": True,
                "status": "progressed",
                "state_delta": {
                    "phase_changed": True,
                    "phase_before": "recon",
                    "phase_after": "validation",
                    "flags_delta": 1,
                    "facts_delta": 2,
                    "hypotheses_delta": -1,
                    "actions_delta": 1,
                    "attempts_delta": 1,
                    "new_primitives": ["file_read", secret],
                    "signal_count_delta": {"sqli_signal": 2, secret: 99},
                    "task_status_delta": {"completed": 1},
                },
            },
        },
        {
            "kind": "harness_turn_trace",
            "payload": {
                "turn": 1,
                "action_id": "raw-action-1",
                "proposed_action": proposed,
                "selected_action": selected,
                "outcome": {
                    "ok": True,
                    "stop": False,
                    "exit_code": 0,
                    "timed_out": False,
                    "flag_captured": True,
                    "observation_digest": {"text": secret},
                },
                "pre_state": {
                    "phase": "recon",
                    "flags_count": 0,
                    "last_observation": {"body": secret},
                },
                "post_state": {
                    "phase": "validation",
                    "flags_count": 1,
                    "last_observation": {"body": secret},
                },
                "state_delta": {"flags_delta": 1, "facts_delta": 2},
            },
        },
        {
            "kind": "outcome_evidence_observed",
            "payload": {
                "turn": 1,
                "action_id": "raw-action-1",
                "evidence_id": "raw-evidence-1",
                "finding_id": "raw-finding-1",
                "stage": "verified_vulnerability",
                "contract_status": "confirmed",
                "confirmed_finding": True,
                "vuln_class": "sql_injection",
                "endpoint": endpoint,
                "input": "account_id",
                "proof": {"response_final": secret},
                "request": {"body": secret},
                "response": {"body": secret},
                "provenance": {"literal_path": "/admin/42"},
            },
        },
        {
            "kind": "finding_confirmed",
            "payload": {
                "turn": 1,
                "action_id": "raw-action-1",
                "finding_id": "raw-finding-1",
                "endpoint": endpoint,
                "proof": secret,
                "exploit_steps": [secret],
            },
        },
        {
            "kind": "model_request_started",
            "payload": {
                "turn": 1,
                "model_request_id": "raw-model-request-1",
                "provider": secret,
                "model": secret,
                "prompt": secret,
            },
        },
        {
            "kind": "model_reply_received",
            "payload": {
                "turn": 1,
                "model_request_id": "raw-model-request-1",
                "content": secret,
                "input_tokens": 100,
                "output_tokens": 50,
                "cost_usd": 0.25,
                "cost_known": True,
                "response_id": secret,
            },
        },
        {
            "kind": "traffic_policy_finished",
            "payload": {
                "state_path": "/private/run/traffic-policy.json",
                "snapshot": _traffic_snapshot(),
            },
        },
        {
            "kind": "agent_finished",
            "payload": {
                "cost_usd": 0.25,
                "finding_count": 1,
                "flag_count": 1,
                "flags": [secret],
                "report_path": "/private/report.json",
                "traffic_policy_snapshot": _traffic_snapshot(),
            },
        },
        {
            "kind": "tool_run_command",
            "payload": {"command": "read " + endpoint, "stdout": secret, "stderr": secret},
        },
        {
            "kind": "benchmark_case_loaded",
            "payload": {"benchmark_id": "case-026", "solution": endpoint, "expected": secret},
        },
    ]


def test_ingestion_projects_only_structural_trajectory(tmp_path: Path) -> None:  # noqa: PLR0915
    sensitive_marker = "sensitive-marker-9Zq7-never-export"
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, _representative_events(sensitive_marker))

    capsule = ingest_events_jsonl(
        events_path,
        hmac_key=HMAC_KEY,
        partition=CorpusSplit.DEVELOPMENT,
        case_identifier="literal-case-name-026",
        run_identifier="literal-run-name-202",
        taints=(
            sensitive_marker,
            "literal-case-name-026",
            "literal-run-name-202",
            "account_id",
        ),
    )

    encoded = serialize_capsule(capsule, taints=(sensitive_marker, "account_id"))
    folded = encoded.casefold()
    assert sensitive_marker.casefold() not in folded
    assert "literal-case-name" not in folded
    assert "literal-run-name" not in folded
    assert "private.invalid" not in folded
    assert "/admin" not in folded
    assert '"proof"' not in folded
    assert '"flag' not in folded
    assert '"input_tokens"' not in folded
    assert '"output_tokens"' not in folded
    assert '"payload"' not in folded
    assert '"body"' not in folded

    assert capsule["schema_version"] == CAPSULE_SCHEMA_VERSION
    assert capsule["metadata"] == {
        "partition": DEVELOPMENT,
        "candidate_visible": True,
    }
    assert str(capsule["case_id"]).startswith("case_")
    assert str(capsule["run_id"]).startswith("run_")

    turns = capsule["turns"]
    assert isinstance(turns, list)
    assert len(turns) == 1
    turn = turns[0]
    assert isinstance(turn, dict)
    selection = turn["selection"]
    assert selection["reason"] == "repeat_guard"
    assert selection["changed"] is True
    assert selection["selected"]["category"] == "validate"
    assert selection["selected"]["family"] == "sqli"
    assert selection["selected"]["method"] == "POST"
    assert str(selection["selected"]["route_id"]).startswith("route_")
    assert selection["selected"]["input_ids"][0].startswith("input_")

    attempt = turn["attempt"]
    assert attempt["status"] == "progressed"
    assert attempt["novel"] is True
    assert attempt["evidence_advanced"] is True
    assert str(attempt["evidence_epoch_before"]).startswith("epoch_")
    assert str(attempt["evidence_epoch_after"]).startswith("epoch_")
    assert attempt["outcome"] == {
        "ok": True,
        "stop": False,
        "timed_out": False,
        "process_status": "success",
        "classification": "finding_gain",
        "repeat_count": 2,
    }
    assert attempt["state_delta"]["facts_delta"] == EXPECTED_FACTS_DELTA
    assert attempt["state_delta"]["hypotheses_delta"] == -1
    assert "flags_delta" not in attempt["state_delta"]

    evidence = turn["evidence"]
    assert evidence["observations"] == 1
    assert evidence["confirmed"] == 1
    assert evidence["stage_counts"] == [{"category": "verified", "count": 1}]
    assert evidence["family_counts"] == [{"category": "sqli", "count": 1}]
    assert evidence["route_ids"][0].startswith("route_")
    assert evidence["input_ids"][0].startswith("input_")

    aggregate = capsule["aggregate"]
    assert aggregate["turn_count"] == 1
    assert aggregate["selection_count"] == 1
    assert aggregate["attempt_count"] == 1
    assert aggregate["evidence_observation_count"] == 1
    assert aggregate["confirmed_finding_count"] == 1
    assert aggregate["model_call_count"] == 1
    assert aggregate["cost_usd"] == pytest.approx(0.25)
    assert aggregate["cost_accounting"] == "exact"
    assert aggregate["ignored_event_count"] == EXPECTED_IGNORED_EVENTS
    assert aggregate["termination"] == "completed"
    assert aggregate["traffic"]["physical_request_count"] == EXPECTED_PHYSICAL_REQUESTS
    assert aggregate["traffic"]["accounting_status"] == "exact"


def test_hmac_ids_are_stable_within_case_and_separated_by_key_and_case(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    events = [
        {
            "kind": "harness_selection",
            "payload": {
                "turn": 1,
                "proposed_action": {"action": "probe", "path": "/same", "input": "item"},
                "selected_action": {"action": "probe", "path": "/same", "input": "item"},
                "proposed_route": "/same",
                "selected_route": "/same",
                "selected_differs_from_model": False,
                "selection_reason": "model_proposal",
            },
        }
    ]
    _write_events(events_path, events)

    first = ingest_events_jsonl(
        events_path,
        hmac_key=HMAC_KEY,
        case_identifier="case-A",
        run_identifier="run-1",
    )
    repeated = ingest_events_jsonl(
        events_path,
        hmac_key=HMAC_KEY,
        case_identifier="case-A",
        run_identifier="run-2",
    )
    different_case = ingest_events_jsonl(
        events_path,
        hmac_key=HMAC_KEY,
        case_identifier="case-B",
        run_identifier="run-3",
    )
    different_key = ingest_events_jsonl(
        events_path,
        hmac_key=SECOND_HMAC_KEY,
        case_identifier="case-A",
        run_identifier="run-1",
    )

    assert first["case_id"] == repeated["case_id"]
    assert first["run_id"] != repeated["run_id"]
    first_selected = first["turns"][0]["selection"]["selected"]
    repeated_selected = repeated["turns"][0]["selection"]["selected"]
    different_case_selected = different_case["turns"][0]["selection"]["selected"]
    assert first_selected["route_id"] == repeated_selected["route_id"]
    assert first_selected["input_ids"] == repeated_selected["input_ids"]
    assert first_selected["route_id"] != different_case_selected["route_id"]
    assert first["case_id"] != different_case["case_id"]
    assert first["case_id"] != different_key["case_id"]
    different_key_selected = different_key["turns"][0]["selection"]["selected"]
    assert first_selected["route_id"] != different_key_selected["route_id"]


def test_run_directory_reads_only_the_events_stream(tmp_path: Path) -> None:
    sensitive_marker = "sealed-raw-replay-marker-X19"
    run_dir = tmp_path / "run"
    _write_events(
        run_dir / "workspace" / "events.jsonl",
        [
            {
                "kind": "agent_finished",
                "payload": {"cost_usd": 0.0, "flags": [sensitive_marker]},
            }
        ],
    )
    (run_dir / "workspace" / "transcript.jsonl").write_text(
        sensitive_marker,
        encoding="utf-8",
    )
    (run_dir / "workspace" / "working_state.json").write_text(
        sensitive_marker,
        encoding="utf-8",
    )
    (run_dir / "workspace" / "graph-replay.json").write_text(
        sensitive_marker,
        encoding="utf-8",
    )
    (run_dir / "benchmark-source.json").write_text(sensitive_marker, encoding="utf-8")

    capsule = ingest_run_dir(
        run_dir,
        hmac_key=HMAC_KEY,
        case_identifier="case",
        run_identifier="run",
        taints=(sensitive_marker,),
    )

    assert sensitive_marker not in serialize_capsule(capsule, taints=(sensitive_marker,))
    assert capsule["aggregate"]["termination"] == "completed"


def test_run_directory_rejects_ambiguous_event_streams(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_events(run_dir / "events.jsonl", [])
    _write_events(run_dir / "workspace" / "events.jsonl", [])

    with pytest.raises(CorpusFormatError, match="ambiguous"):
        ingest_run_dir(run_dir, hmac_key=HMAC_KEY)


def test_sealed_holdout_can_be_archived_but_never_candidate_exported(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [{"kind": "agent_finished", "payload": {"cost_usd": 0.0}}])
    capsule = ingest_events_jsonl(
        events_path,
        hmac_key=HMAC_KEY,
        partition=CorpusSplit.SEALED_HOLDOUT,
        case_identifier="hidden-case",
        run_identifier="hidden-run",
    )

    assert capsule["metadata"] == {
        "partition": SEALED_HOLDOUT,
        "candidate_visible": False,
    }
    assert serialize_capsule(capsule)
    archive_path = write_capsule(tmp_path / "sealed.json", capsule)
    assert archive_path.is_file()

    with pytest.raises(HoldoutAccessError):
        candidate_visible_export([capsule])
    with pytest.raises(HoldoutAccessError):
        serialize_candidate_corpus([capsule])
    with pytest.raises(HoldoutAccessError):
        write_candidate_corpus(tmp_path / "must-not-exist.json", [capsule])
    assert not (tmp_path / "must-not-exist.json").exists()


def test_development_candidate_export_is_detached_and_canonical(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [{"kind": "agent_finished", "payload": {"cost_usd": 0.0}}])
    capsule = ingest_events_jsonl(
        events_path,
        hmac_key=HMAC_KEY,
        partition=DEVELOPMENT,
        case_identifier="dev-case",
        run_identifier="dev-run",
    )

    document = candidate_visible_export([capsule])
    assert document["capsules"][0] == capsule
    assert document["capsules"][0] is not capsule
    destination = write_candidate_corpus(tmp_path / "candidate.json", [capsule])
    assert destination.read_text(encoding="utf-8").strip() == serialize_candidate_corpus([capsule])


@pytest.mark.parametrize(
    "transform",
    [
        lambda value: value,
        lambda value: quote(value, safe=""),
        _double_percent_encode,
        lambda value: base64.b64encode(value.encode()).decode(),
        _double_base64,
        lambda value: base64.urlsafe_b64encode(value.encode()).decode().rstrip("="),
        lambda value: value.encode().hex(),
    ],
)
def test_recursive_leak_scanner_rejects_taint_derivatives(transform: object) -> None:
    taint = "taint-marker-Qx91/with spaces"
    encoded = transform(taint)

    findings = find_leaks({"capsules": [{"route_id": encoded}]}, taints=(taint,))

    assert findings
    assert any(finding.reason == "tainted_value" for finding in findings)
    with pytest.raises(CorpusLeakError):
        scan_for_leaks({"capsules": [{"route_id": encoded}]}, taints=(taint,))


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "http://private.invalid/internal",
        "/private/tmp/raw-output.txt",
        "Bearer opaque-credential-material",
        "password=do-not-copy",
        "free form model response text",
    ],
)
def test_recursive_leak_scanner_rejects_raw_string_classes(unsafe_value: str) -> None:
    with pytest.raises(CorpusLeakError):
        scan_for_leaks({"route_id": unsafe_value})


def test_recursive_leak_scanner_accepts_only_opaque_ids_and_categories() -> None:
    scan_for_leaks(
        {
            "route_id": "route_0123456789abcdef0123456789abcdef",
            "category": "probe",
            "candidate_visible": True,
            "physical_request_count": 3,
        }
    )


def test_allowed_event_with_non_mapping_payload_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps({"kind": "harness_selection", "payload": "raw data"}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(CorpusFormatError, match="non-object payload"):
        ingest_events_jsonl(path, hmac_key=HMAC_KEY)


@pytest.mark.parametrize(
    "raw_line",
    [
        '{"kind":"agent_finished","payload":{},"payload":{}}',
        '{"kind":"agent_finished","payload":{"cost_usd":NaN}}',
    ],
)
def test_non_strict_json_fails_without_retaining_the_raw_error(
    tmp_path: Path,
    raw_line: str,
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(raw_line + "\n", encoding="utf-8")

    with pytest.raises(CorpusFormatError) as raised:
        ingest_events_jsonl(path, hmac_key=HMAC_KEY)

    assert raised.value.__cause__ is None


def test_short_hmac_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_events(path, [])

    with pytest.raises(ValueError, match="at least 32 bytes"):
        ingest_events_jsonl(path, hmac_key=b"too-short")


def test_ingest_rejects_symlink_hardlink_and_non_regular_event_inputs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-events.jsonl"
    _write_events(source, [])

    symlink = tmp_path / "symlink-events.jsonl"
    symlink.symlink_to(source)
    with pytest.raises(CorpusFormatError, match="regular single-link"):
        ingest_events_jsonl(symlink, hmac_key=HMAC_KEY)

    hardlink = tmp_path / "hardlink-events.jsonl"
    os.link(source, hardlink)
    with pytest.raises(CorpusFormatError, match="regular single-link"):
        ingest_events_jsonl(hardlink, hmac_key=HMAC_KEY)

    fifo = tmp_path / "fifo-events.jsonl"
    os.mkfifo(fifo)
    with pytest.raises(CorpusFormatError, match="regular single-link"):
        ingest_events_jsonl(fifo, hmac_key=HMAC_KEY)


def test_run_directory_rejects_a_symlinked_workspace(tmp_path: Path) -> None:
    external = tmp_path / "external"
    _write_events(external / "events.jsonl", [])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "workspace").symlink_to(external, target_is_directory=True)

    with pytest.raises(CorpusFormatError, match="symlinked workspace"):
        ingest_run_dir(run_dir, hmac_key=HMAC_KEY)


def test_default_identities_are_content_bound_and_location_independent(tmp_path: Path) -> None:
    first_path = tmp_path / "first" / "events.jsonl"
    second_path = tmp_path / "second" / "events.jsonl"
    changed_path = tmp_path / "third" / "events.jsonl"
    event = {"kind": "agent_finished", "payload": {"cost_usd": 0.0}}
    _write_events(first_path, [event])
    _write_events(second_path, [event])
    _write_events(
        changed_path,
        [{"kind": "agent_finished", "payload": {"cost_usd": 0.5}}],
    )

    first = ingest_events_jsonl(first_path, hmac_key=HMAC_KEY)
    relocated = ingest_events_jsonl(second_path, hmac_key=HMAC_KEY)
    changed = ingest_events_jsonl(changed_path, hmac_key=HMAC_KEY)

    assert (first["case_id"], first["run_id"]) == (
        relocated["case_id"],
        relocated["run_id"],
    )
    assert first["case_id"] != changed["case_id"]
    assert first["run_id"] != changed["run_id"]


def test_corpus_writers_refuse_to_replace_existing_destinations(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    _write_events(events_path, [{"kind": "agent_finished", "payload": {}}])
    capsule = ingest_events_jsonl(events_path, hmac_key=HMAC_KEY)
    candidate_path = write_candidate_corpus(tmp_path / "candidate.json", [capsule])
    sealed_path = write_capsule(tmp_path / "sealed.json", capsule)
    candidate_before = candidate_path.read_bytes()
    sealed_before = sealed_path.read_bytes()

    with pytest.raises(CorpusFormatError, match="refusing to overwrite"):
        write_candidate_corpus(candidate_path, [capsule])
    with pytest.raises(CorpusFormatError, match="refusing to overwrite"):
        write_capsule(sealed_path, capsule)

    assert candidate_path.read_bytes() == candidate_before
    assert sealed_path.read_bytes() == sealed_before
