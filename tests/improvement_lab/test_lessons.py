from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tools.improvement_lab.corpus import ingest_events_jsonl
from tools.improvement_lab.lessons import ImprovementBriefError, build_improvement_brief

if TYPE_CHECKING:
    from pathlib import Path


def test_brief_prioritizes_generic_gaps_without_raw_identifiers(
    tmp_path: Path,
) -> None:
    events = tmp_path / "events.jsonl"
    raw_events = []
    for turn in range(1, 5):
        raw_events.extend(
            (
                {
                    "kind": "harness_selection",
                    "payload": {
                        "turn": turn,
                        "proposed_action": {
                            "action": "run_probe",
                            "probe": "mystery_probe",
                            "url": "http://secret.invalid/private",
                        },
                        "selected_action": {
                            "action": "run_probe",
                            "probe": "mystery_probe",
                            "url": "http://secret.invalid/private",
                        },
                        "selected_differs_from_model": turn % 2 == 0,
                        "selection_reason": "harness_override",
                    },
                },
                {
                    "kind": "agent_attempt_recorded",
                    "payload": {
                        "turn": turn,
                        "proposed_action": {"action": "run_probe", "probe": "mystery_probe"},
                        "selected_action": {"action": "run_probe", "probe": "mystery_probe"},
                        "selection_reason": "harness_override",
                        "novel": False,
                        "status": "low_value",
                        "outcome": {
                            "classification": "same_as_before",
                            "ok": True,
                            "repeat_count": turn,
                            "stop": False,
                        },
                        "state_delta": {},
                    },
                },
            )
        )
    events.write_text(
        "".join(json.dumps(event) + "\n" for event in raw_events),
        encoding="utf-8",
    )
    capsule = ingest_events_jsonl(
        events,
        hmac_key=b"k" * 32,
        case_identifier="secret-case",
        run_identifier="secret-run",
    )

    brief = build_improvement_brief(
        {
            "schema_version": "ravage.improvement.corpus.v1",
            "capsules": [capsule],
        }
    )
    serialized = json.dumps(brief, sort_keys=True)
    gap_kinds = {str(gap["kind"]) for gap in brief["capability_gaps"]}

    assert brief["decision"] == "propose_candidates"
    assert "novelty_and_dedup" in gap_kinds
    assert "family_classification_and_surface_graph" in gap_kinds
    assert "secret.invalid" not in serialized
    assert "secret-case" not in serialized
    assert "secret-run" not in serialized
    assert "private" not in serialized


def test_brief_rejects_sealed_capsule(
    tmp_path: Path,
) -> None:
    events = tmp_path / "events.jsonl"
    events.write_text("", encoding="utf-8")
    capsule = ingest_events_jsonl(
        events,
        hmac_key=b"k" * 32,
        partition="sealed_holdout",
        case_identifier="case",
        run_identifier="run",
    )

    with pytest.raises(ImprovementBriefError, match="sealed"):
        build_improvement_brief(
            {
                "schema_version": "ravage.improvement.corpus.v1",
                "capsules": [capsule],
            }
        )
