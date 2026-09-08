from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from ravage.outcome_evidence import (
    native_confirmed_finding_payload,
    outcome_evidence_payload,
    qualify_probe_findings,
    summarize_run_outcome,
)
from ravage.probe_suite_parts.sqli.sqli_transport import _sqli_replay

_ENGAGEMENT_ID = UUID("77777777-7777-4777-8777-777777777777")


def test_source_sql_replay_preserves_post_query_location_and_bounded_ids() -> None:
    candidate_ids = [
        _candidate_id(0),
        _candidate_id(0),
        "not/a/source-id",
        *(_candidate_id(index) for index in range(1, 40)),
    ]
    target = {
        "kind": "replay",
        "method": "POST",
        "url": "http://127.0.0.1:8765/search?page=1",
        "input": "term",
        "input_location": "query",
        "source_candidate_ids": candidate_ids,
    }

    replay = _sqli_replay(target, "quoted'value")

    assert replay["method"] == "POST"
    assert replay["input_location"] == "query"
    assert "form" not in replay
    assert parse_qs(urlsplit(str(replay["url"])).query) == {
        "page": ["1"],
        "term": ["quoted'value"],
    }
    assert replay["source_candidate_ids"] == [_candidate_id(index) for index in range(32)]


def test_source_sql_qualification_keeps_query_location_and_confirmed_provenance() -> None:
    source_candidate_ids = [_candidate_id(1), _candidate_id(2)]
    target = {
        "kind": "replay",
        "method": "POST",
        "url": "http://127.0.0.1:8765/search?page=1",
        "input": "term",
        "input_location": "query",
        "source_candidate_ids": source_candidate_ids,
    }
    raw_finding = {
        "type": "sql_injection_error_signal",
        "markers": ["database syntax error"],
        "delta": {"new_error_markers": ["database"]},
        "replay": _sqli_replay(target, "'"),
        "baseline_replay": _sqli_replay(target, "plain"),
        "response": {
            "method": "POST",
            "url": "http://127.0.0.1:8765/search?page=1&term=%27",
            "status": 500,
            "body_sha_hint": "database-error",
        },
    }

    [qualified] = qualify_probe_findings(
        probe="sqli_differential",
        probe_text=json.dumps(
            {
                "probe": "sqli_differential",
                "ok": True,
                "findings": [raw_finding],
                "requests": [],
                "errors": [],
            }
        ),
        target_url="http://127.0.0.1:8765/",
    )

    assert raw_finding["replay"]["source_candidate_ids"] == source_candidate_ids
    assert qualified.promotable is True
    assert qualified.request["input_location"] == "query"
    assert qualified.request["source_candidate_ids"] == source_candidate_ids
    assert qualified.request["affected_parameter"] == {
        "name": "term",
        "location": "query",
    }
    assert qualified.request["params"] == [
        {"name": "page", "location": "query"},
        {"name": "term", "location": "query"},
    ]

    confirmed = native_confirmed_finding_payload(
        qualified,
        engagement_id=_ENGAGEMENT_ID,
        source_observation_id="observation-source-sql",
        action_id="action-source-sql",
        finding_record_path="events.jsonl",
    )
    assert confirmed["input"]["affected_parameters"] == [{"name": "term", "location": "query"}]
    assert confirmed["provenance"]["source_candidate_ids"] == source_candidate_ids
    assert confirmed["provenance"]["source_map_artifact"] == ("artifacts/source-map.json")

    observed = outcome_evidence_payload(
        qualified,
        engagement_id=_ENGAGEMENT_ID,
        source_observation_id="observation-source-sql",
        action_id="action-source-sql",
        confirmed=True,
    )
    assert observed["provenance"]["source_candidate_ids"] == source_candidate_ids
    assert observed["provenance"]["source_map_artifact"] == ("artifacts/source-map.json")
    summary = summarize_run_outcome(
        [
            (
                "tool_run_probe",
                {
                    "observation_id": "observation-source-sql",
                    "action_id": "action-source-sql",
                    "display_summary": {
                        "probe": "sqli_differential",
                        "findings": 1,
                    },
                },
            ),
            ("outcome_evidence_observed", observed),
        ]
    )
    assert summary.evidence[0]["provenance"]["source_candidate_ids"] == (
        source_candidate_ids
    )
    assert summary.evidence[0]["provenance"]["source_map_artifact"] == (
        "artifacts/source-map.json"
    )


def test_non_source_sql_finding_does_not_claim_source_map_provenance() -> None:
    [qualified] = qualify_probe_findings(
        probe="sqli_differential",
        probe_text=json.dumps(
            {
                "probe": "sqli_differential",
                "ok": True,
                "findings": [
                    {
                        "type": "sql_injection_error_signal",
                        "markers": ["database syntax error"],
                        "delta": {"new_error_markers": ["database"]},
                        "replay": {
                            "method": "GET",
                            "url": "http://127.0.0.1:8765/search?term=%27",
                            "payload_field": "term",
                        },
                        "baseline_replay": {
                            "method": "GET",
                            "url": "http://127.0.0.1:8765/search?term=plain",
                            "payload_field": "term",
                        },
                        "response": {
                            "method": "GET",
                            "url": "http://127.0.0.1:8765/search?term=%27",
                            "status": 500,
                            "body_sha_hint": "database-error",
                        },
                    }
                ],
                "requests": [],
                "errors": [],
            }
        ),
        target_url="http://127.0.0.1:8765/",
    )

    confirmed = native_confirmed_finding_payload(
        qualified,
        engagement_id=_ENGAGEMENT_ID,
        source_observation_id="observation-sql",
        action_id="action-sql",
        finding_record_path="events.jsonl",
    )

    assert "source_candidate_ids" not in confirmed["provenance"]
    assert "source_map_artifact" not in confirmed["provenance"]


def _candidate_id(index: int) -> str:
    return f"src-{index:024x}"
