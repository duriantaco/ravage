from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest
from pentest_schemas import Scope
from ravage.agent_core.action_executor import (
    _record_probe_result,
    _tool_text,
    execute_action,
)
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.outcome_evidence import (
    OutcomeStage,
    ProbeFindingContract,
    _build_contract_registry,
    load_run_outcome,
    native_confirmed_finding_payload,
    outcome_evidence_payload,
    qualify_probe_findings,
    summarize_run_outcome,
    validated_captured_flags,
)
from ravage.report import build_pentest_report, render_markdown_report
from ravage.run_data.audit import AuditStore
from ravage.run_data.workspace import AgentWorkspace
from ravage.runtime import ToolResult
from ravage.xben_parts.logs import _existing_to_result, _write_report
from ravage.xben_parts.models import XbenCase, XbenSettings

if TYPE_CHECKING:
    from pathlib import Path


_ENGAGEMENT_ID = UUID("77777777-7777-4777-8777-777777777777")
_UNKNOWN_FINDING_COUNT = 2
_COMBINED_EVIDENCE_COUNT = 2


def test_native_contract_registry_rejects_duplicate_finding_types() -> None:
    contract = ProbeFindingContract(
        finding_type="future_boundary_signal",
        probes=("future_boundary",),
        vuln_class="future_boundary",
        stage=OutcomeStage.VERIFIED_VULNERABILITY,
        severity="High",
        hypothesis="A generic boundary changed.",
        impact="The affected boundary may expose protected behavior.",
    )

    with pytest.raises(ValueError, match="duplicate native finding contract type"):
        _build_contract_registry((contract, contract))


def test_native_probe_contract_is_explicit_and_secret_safe() -> None:
    secret = "private-native-probe-value"  # noqa: S105 - redaction fixture.
    probe_text = _file_read_probe_text(secret=secret)

    qualified = qualify_probe_findings(
        probe="file_read_extract",
        probe_text=probe_text,
        target_url="http://127.0.0.1:8765/",
    )

    assert len(qualified) == 1
    item = qualified[0]
    assert item.promotable is True
    assert item.stage is OutcomeStage.EXPLOIT_PRIMITIVE
    assert item.contract.vuln_class == "path_traversal"
    assert item.endpoint == {
        "method": "GET",
        "url": "http://127.0.0.1:8765/view",
        "params": [
            {"name": "file", "location": "query"},
            {"name": "token", "location": "query"},
        ],
    }

    finding = native_confirmed_finding_payload(
        item,
        engagement_id=_ENGAGEMENT_ID,
        source_observation_id="observation-1",
        action_id="action-1",
        finding_record_path="events.jsonl",
    )
    assert secret not in json.dumps(finding, sort_keys=True)
    assert finding["outcome_stage"] == "exploit_primitive"


def test_native_outcome_replaces_secret_bearing_path_segments() -> None:
    secret = "private-native-probe-value"  # noqa: S105 - redaction fixture.
    probe_text = json.dumps(
        {
            "probe": "idor_boundary",
            "ok": True,
            "findings": [
                {
                    "type": "idor_boundary_followup_exposed_secret",
                    "signal": {"kind": "reset_link_exposed"},
                    "matches": ["reset link"],
                    "replay": {
                        "method": "GET",
                        "url": f"http://127.0.0.1/reset/{secret}",
                    },
                    "source_response": {
                        "method": "GET",
                        "url": "http://127.0.0.1/users/2",
                        "status": 200,
                    },
                    "response": {
                        "method": "GET",
                        "url": f"http://127.0.0.1/reset/{secret}",
                        "status": 200,
                    },
                }
            ],
        }
    )

    [qualified] = qualify_probe_findings(
        probe="idor_boundary",
        probe_text=probe_text,
        target_url="http://127.0.0.1/",
    )
    finding = native_confirmed_finding_payload(
        qualified,
        engagement_id=_ENGAGEMENT_ID,
        source_observation_id="observation-path-secret",
        action_id="action-path-secret",
        finding_record_path="events.jsonl",
    )

    serialized = json.dumps(finding, sort_keys=True)
    assert secret not in serialized
    assert "http://127.0.0.1/reset/{segment}" in serialized


def test_distinct_affected_parameters_survive_outcome_and_report_deduplication(
    tmp_path: Path,
) -> None:
    probe = "sqli_differential"
    expected_count = 2
    findings: list[dict[str, object]] = [
        {
            "type": "sql_injection_error_signal",
            "markers": ["database syntax error"],
            "delta": {"new_error_markers": ["database"]},
            "replay": {
                "method": "GET",
                "url": "http://127.0.0.1:8765/lookup?alpha=test&beta=test",
                "payload_field": affected_parameter,
            },
            "baseline_replay": {
                "method": "GET",
                "url": "http://127.0.0.1:8765/lookup?alpha=plain&beta=plain",
                "payload_field": affected_parameter,
            },
            "response": {
                "method": "GET",
                "url": "http://127.0.0.1:8765/lookup",
                "status": 500,
                "body_sha_hint": f"error-{affected_parameter}",
            },
        }
        for affected_parameter in ("alpha", "beta")
    ]
    qualified = qualify_probe_findings(
        probe=probe,
        probe_text=json.dumps(
            {
                "probe": probe,
                "ok": True,
                "findings": findings,
                "requests": [],
                "errors": [],
            }
        ),
        target_url="http://127.0.0.1:8765/",
    )

    assert len(qualified) == expected_count
    first, second = qualified
    assert first.endpoint == second.endpoint
    assert first.finding_id(_ENGAGEMENT_ID) != second.finding_id(_ENGAGEMENT_ID)
    assert first.evidence_id(_ENGAGEMENT_ID) != second.evidence_id(_ENGAGEMENT_ID)
    assert first.finding_id(_ENGAGEMENT_ID) == first.finding_id(_ENGAGEMENT_ID)
    assert first.evidence_id(_ENGAGEMENT_ID) == first.evidence_id(_ENGAGEMENT_ID)

    observation = (
        "tool_run_probe",
        {
            "observation_id": "observation-multi-input",
            "action_id": "action-multi-input",
            "display_summary": {"probe": probe, "findings": 2},
            "recognized_proofs": [],
        },
    )
    evidence = [
        outcome_evidence_payload(
            item,
            engagement_id=_ENGAGEMENT_ID,
            source_observation_id="observation-multi-input",
            action_id="action-multi-input",
            confirmed=True,
        )
        for item in qualified
    ]
    summary = summarize_run_outcome(
        [
            observation,
            ("outcome_evidence_observed", evidence[0]),
            ("outcome_evidence_observed", evidence[1]),
            ("outcome_evidence_observed", evidence[0]),
        ]
    )

    assert summary.evidence_count == expected_count
    assert {
        json.dumps(item["input"]["affected_parameters"], sort_keys=True)
        for item in summary.evidence
    } == {
        json.dumps([{"name": "alpha", "location": "query"}], sort_keys=True),
        json.dumps([{"name": "beta", "location": "query"}], sort_keys=True),
    }

    brief_path = _write_no_flag_brief(tmp_path)
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = tmp_path / "run" / "audit.db"
    audit = AuditStore(audit_path)
    try:
        for item in (first, second, first):
            payload = native_confirmed_finding_payload(
                item,
                engagement_id=_ENGAGEMENT_ID,
                source_observation_id="observation-multi-input",
                action_id="action-multi-input",
                finding_record_path=str(workspace.events_path),
            )
            audit.record_finding_payload(
                finding_id=str(payload["finding_id"]),
                engagement_id=_ENGAGEMENT_ID,
                vuln_class=str(payload["vuln_class"]),
                status="confirmed",
                validator_vote="confirm",
                payload=payload,
            )
    finally:
        audit.close()

    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765/",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert report["executive_summary"]["finding_count"] == expected_count
    assert {
        finding["input"]["affected_parameters"][0]["name"] for finding in report["findings"]
    } == {"alpha", "beta"}


def test_affected_parameter_identity_ignores_unrelated_endpoint_parameters() -> None:
    probe = "sqli_differential"
    expected_count = 2
    findings = [
        {
            "type": "sql_injection_error_signal",
            "markers": ["database syntax error"],
            "delta": {"new_error_markers": ["database"]},
            "replay": {
                "method": "GET",
                "url": url,
                "payload_field": "q",
            },
            "baseline_replay": {
                "method": "GET",
                "url": "http://127.0.0.1:8765/lookup?q=plain",
                "payload_field": "q",
            },
            "response": {
                "method": "GET",
                "url": "http://127.0.0.1:8765/lookup",
                "status": 500,
                "body_sha_hint": "database-error",
            },
        }
        for url in (
            "http://127.0.0.1:8765/lookup?q=test",
            "http://127.0.0.1:8765/lookup?q=test&submit=Search",
        )
    ]
    qualified = qualify_probe_findings(
        probe=probe,
        probe_text=json.dumps(
            {
                "probe": probe,
                "ok": True,
                "findings": findings,
                "requests": [],
                "errors": [],
            }
        ),
        target_url="http://127.0.0.1:8765/",
    )

    assert len(qualified) == expected_count
    first, second = qualified
    assert first.endpoint != second.endpoint
    assert first.finding_id(_ENGAGEMENT_ID) == second.finding_id(_ENGAGEMENT_ID)
    assert first.evidence_id(_ENGAGEMENT_ID) == second.evidence_id(_ENGAGEMENT_ID)
    assert first.evidence_id(_ENGAGEMENT_ID) == replace(
        second,
        probe="alternate_detector",
    ).evidence_id(_ENGAGEMENT_ID)

    first_without_affected = replace(
        first,
        request={key: value for key, value in first.request.items() if key != "affected_parameter"},
    )
    second_without_affected = replace(
        second,
        request={
            key: value
            for key, value in second.request.items()
            if key != "affected_parameter"
        },
    )
    assert first_without_affected.finding_id(
        _ENGAGEMENT_ID
    ) != second_without_affected.finding_id(_ENGAGEMENT_ID)
    assert first_without_affected.evidence_id(
        _ENGAGEMENT_ID
    ) != second_without_affected.evidence_id(_ENGAGEMENT_ID)


def test_unknown_signals_are_retained_but_cannot_self_promote() -> None:
    unknown = json.dumps(
        {
            "probe": "surface_map",
            "ok": True,
            "findings": [{"type": "server_banner", "value": "Apache/2.4"}],
            "requests": [],
            "errors": [],
        }
    )
    [unknown_candidate] = qualify_probe_findings(
        probe="surface_map",
        probe_text=unknown,
        target_url="http://127.0.0.1/",
    )
    assert unknown_candidate.contract_status == "contract_missing"
    assert unknown_candidate.contract.vuln_class == "surface_map"
    assert unknown_candidate.finding_type == "server_banner"
    assert unknown_candidate.stage is OutcomeStage.SUSPECTED_VULNERABILITY
    assert unknown_candidate.promotable is False
    assert "finding_contract" in unknown_candidate.missing_evidence

    template_error = json.dumps(
        {
            "probe": "ssti_fingerprint",
            "ok": True,
            "findings": [
                {
                    "type": "ssti_fingerprint_signal",
                    "signal": {"kind": "template_error", "markers": ["jinja2"]},
                    "replay": {
                        "method": "GET",
                        "url": "http://127.0.0.1/render?name=%7B%7B7%2A7%7D%7D",
                        "payload_field": "name",
                    },
                    "baseline_replay": {
                        "method": "GET",
                        "url": "http://127.0.0.1/render?name=hello",
                        "payload_field": "name",
                    },
                    "response": {
                        "method": "GET",
                        "url": "http://127.0.0.1/render",
                        "status": 500,
                        "body_sha_hint": "abc123",
                    },
                    "delta": {"status_changed": True},
                }
            ],
            "requests": [],
            "errors": [],
        }
    )
    [candidate] = qualify_probe_findings(
        probe="ssti_fingerprint",
        probe_text=template_error,
        target_url="http://127.0.0.1/",
    )
    assert candidate.promotable is False
    assert candidate.stage is OutcomeStage.SUSPECTED_VULNERABILITY
    assert "evaluated_expression" in candidate.missing_evidence


def test_missing_contract_evidence_is_value_free_and_fail_closed() -> None:
    secret = "private-future-observation-value"  # noqa: S105 - redaction fixture.
    probe = "future_access_boundary"
    [candidate] = qualify_probe_findings(
        probe=probe,
        probe_text=json.dumps(
            {
                "probe": probe,
                "ok": True,
                "findings": [
                    {
                        "type": "future_authorization_boundary",
                        "vuln_class": "authorization",
                        "input": {"name": "account", "value": secret},
                        "signal": {"kind": "access_changed", "value": secret},
                        "replay": {
                            "method": "GET",
                            "url": f"http://127.0.0.1/account?account={secret}",
                            "payload_field": "account",
                        },
                        "response": {
                            "method": "GET",
                            "url": f"http://127.0.0.1/account?account={secret}",
                            "status": 200,
                            "body_snippet": secret,
                        },
                    }
                ],
            }
        ),
        target_url="http://127.0.0.1/",
    )

    payload = outcome_evidence_payload(
        candidate,
        engagement_id=_ENGAGEMENT_ID,
        source_observation_id="observation-future",
        action_id="action-future",
        confirmed=True,
        forced_stage=OutcomeStage.EXPLOIT_PRIMITIVE,
    )

    assert candidate.contract_status == "contract_missing"
    assert candidate.promotable is False
    assert payload["stage"] == "suspected_vulnerability"
    assert payload["confirmed_finding"] is False
    assert payload["contract_status"] == "contract_missing"
    assert payload["missing_evidence"] == ["finding_contract"]
    assert payload["endpoint"] == {
        "method": "GET",
        "url": "http://127.0.0.1/account",
        "params": [{"name": "account", "location": "query"}],
    }
    assert payload["input"] == {
        "method": "GET",
        "parameters": [{"name": "account", "location": "query"}],
        "affected_parameters": [{"name": "account", "location": "query"}],
    }
    assert secret not in json.dumps(payload, sort_keys=True)

    with pytest.raises(ValueError, match="cannot be promoted"):
        native_confirmed_finding_payload(
            candidate,
            engagement_id=_ENGAGEMENT_ID,
            source_observation_id="observation-future",
            action_id="action-future",
            finding_record_path="events.jsonl",
        )

    summary = summarize_run_outcome(
        [
            (
                "tool_run_probe",
                {
                    "observation_id": "observation-future",
                    "action_id": "action-future",
                    "display_summary": {"probe": probe, "findings": 1},
                    "recognized_proofs": [],
                },
            ),
            ("outcome_evidence_observed", payload),
        ]
    )
    assert summary.stage is OutcomeStage.SUSPECTED_VULNERABILITY
    assert summary.suspected_vulnerability_count == 1
    assert summary.confirmed_finding_count == 0
    assert summary.evidence[0]["contract_status"] == "contract_missing"
    assert summary.evidence[0]["vuln_class"] == "authorization"
    assert summary.evidence[0]["input"] == payload["input"]
    assert secret not in json.dumps(summary.to_json(), sort_keys=True)

    forged = dict(payload)
    forged["stage"] = "verified_vulnerability"
    forged["confirmed_finding"] = True
    rejected = summarize_run_outcome(
        [
            (
                "tool_run_probe",
                {
                    "observation_id": "observation-future",
                    "action_id": "action-future",
                    "display_summary": {"probe": probe, "findings": 1},
                },
            ),
            ("outcome_evidence_observed", forged),
        ]
    )
    assert rejected.stage is OutcomeStage.NONE
    assert rejected.evidence_count == 0


@pytest.mark.parametrize(
    ("probe", "finding", "vuln_class", "stage"),
    [
        (
            "sqli_differential",
            {
                "type": "sql_injection_error_signal",
                "markers": ["sqlite syntax error"],
                "delta": {"new_error_markers": ["sqlite"]},
                "replay": {"method": "GET", "url": "http://127.0.0.1/search?q=%27"},
                "baseline_replay": {
                    "method": "GET",
                    "url": "http://127.0.0.1/search?q=hello",
                },
                "response": {
                    "method": "GET",
                    "url": "http://127.0.0.1/search?q=%27",
                    "status": 500,
                    "body_sha_hint": "sqlhash",
                },
            },
            "sql_injection",
            OutcomeStage.VERIFIED_VULNERABILITY,
        ),
        (
            "command_boundary",
            {
                "type": "apache_traversal_file_read_signal",
                "input": {"vector": "apache_path_traversal_file_read"},
                "url": "http://127.0.0.1/cgi-bin/.%2e/.%2e/etc/passwd",
                "expected": "new local-file content",
                "control_response": {
                    "method": "GET",
                    "url": "http://127.0.0.1/",
                    "status": 200,
                    "body_sha_hint": "controlhash",
                },
                "response": {
                    "method": "GET",
                    "url": "http://127.0.0.1/cgi-bin/.%2e/.%2e/etc/passwd",
                    "status": 200,
                    "body_sha_hint": "passwdhash",
                },
            },
            "path_traversal",
            OutcomeStage.EXPLOIT_PRIMITIVE,
        ),
        (
            "command_boundary",
            {
                "type": "command_boundary_signal",
                "input": {"name": "host"},
                "url": "http://127.0.0.1/ping?host=PAYLOAD",
                "expected": "executor marker",
                "delta": {"body_changed": True},
                "response": {
                    "method": "GET",
                    "url": "http://127.0.0.1/ping?host=marker",
                    "status": 200,
                    "body_sha_hint": "cmdhash",
                },
            },
            "command_injection",
            OutcomeStage.EXPLOIT_PRIMITIVE,
        ),
        (
            "ssrf_boundary",
            {
                "type": "ssrf_boundary_signal",
                "signal": {"kind": "internal_response", "matches": ["metadata"]},
                "replay": {
                    "method": "GET",
                    "url": "http://127.0.0.1/fetch?url=http://127.0.0.1/admin",
                },
                "baseline_replay": {
                    "method": "GET",
                    "url": "http://127.0.0.1/fetch?url=http://example.com",
                },
                "response": {
                    "method": "GET",
                    "url": "http://127.0.0.1/fetch",
                    "status": 200,
                    "body_sha_hint": "ssrfhash",
                },
            },
            "ssrf",
            OutcomeStage.VERIFIED_VULNERABILITY,
        ),
        (
            "idor_boundary",
            {
                "type": "idor_boundary_exposed_secret",
                "signal": {"kind": "object_changed"},
                "matches": ["private field"],
                "replay": {"method": "GET", "url": "http://127.0.0.1/users/2"},
                "baseline_replay": {
                    "method": "GET",
                    "url": "http://127.0.0.1/users/1",
                },
                "baseline": {
                    "method": "GET",
                    "url": "http://127.0.0.1/users/1",
                    "status": 200,
                },
                "response": {
                    "method": "GET",
                    "url": "http://127.0.0.1/users/2",
                    "status": 200,
                    "body_sha_hint": "idorhash",
                },
            },
            "idor",
            OutcomeStage.EXPLOIT_PRIMITIVE,
        ),
        (
            "xxe_boundary",
            {
                "type": "xxe_file_read_signal",
                "markers": ["root:x:0:0"],
                "response": {
                    "method": "POST",
                    "url": "http://127.0.0.1/xml",
                    "status": 200,
                    "body_sha_hint": "xxehash",
                },
            },
            "xxe",
            OutcomeStage.EXPLOIT_PRIMITIVE,
        ),
    ],
)
def test_typed_native_contracts_cover_major_exploit_families(
    probe: str,
    finding: dict[str, object],
    vuln_class: str,
    stage: OutcomeStage,
) -> None:
    [qualified] = qualify_probe_findings(
        probe=probe,
        probe_text=json.dumps(
            {
                "probe": probe,
                "ok": True,
                "findings": [finding],
                "requests": [],
                "errors": [],
            }
        ),
        target_url="http://127.0.0.1/",
    )

    assert qualified.promotable is True
    assert qualified.contract.vuln_class == vuln_class
    assert qualified.stage is stage


@pytest.mark.parametrize(
    ("probe", "finding_type", "vuln_class", "severity"),
    [
        ("file_read_extract", "file_read_extracted_proof", "path_traversal", "High"),
        (
            "file_fetch_parser",
            "php_include_extracted_proof",
            "path_traversal",
            "Critical",
        ),
        ("ssti_fingerprint", "ssti_extracted_proof", "ssti", "High"),
        ("xxe_boundary", "xxe_extracted_proof", "xxe", "High"),
    ],
)
def test_extracted_proof_contract_aliases_qualify(
    probe: str,
    finding_type: str,
    vuln_class: str,
    severity: str,
) -> None:
    [qualified] = qualify_probe_findings(
        probe=probe,
        probe_text=_extracted_proof_probe_text(probe=probe, finding_type=finding_type),
        target_url="http://127.0.0.1/",
    )

    assert qualified.contract_status == "registered"
    assert qualified.promotable is True
    assert qualified.missing_evidence == ()
    assert qualified.contract.vuln_class == vuln_class
    assert qualified.contract.severity == severity
    assert qualified.stage is OutcomeStage.EXPLOIT_PRIMITIVE


@pytest.mark.parametrize(
    ("registered_probe", "finding_type"),
    [
        ("file_read_extract", "file_read_extracted_proof"),
        ("file_fetch_parser", "php_include_extracted_proof"),
        ("ssti_fingerprint", "ssti_extracted_proof"),
        ("xxe_boundary", "xxe_extracted_proof"),
    ],
)
def test_extracted_proof_contract_aliases_reject_wrong_probe(
    registered_probe: str,
    finding_type: str,
) -> None:
    wrong_probe = "surface_map"
    probe_text = _extracted_proof_probe_text(
        probe=wrong_probe,
        finding_type=finding_type,
    )

    [qualified] = qualify_probe_findings(
        probe=wrong_probe,
        probe_text=probe_text,
        target_url="http://127.0.0.1/",
    )

    assert wrong_probe != registered_probe
    assert qualified.contract_status == "contract_missing"
    assert qualified.promotable is False
    assert qualified.stage is OutcomeStage.SUSPECTED_VULNERABILITY
    assert "finding_contract" in qualified.missing_evidence


@pytest.mark.parametrize(
    ("probe", "finding_type"),
    [
        ("file_read_extract", "file_read_extracted_proof"),
        ("file_fetch_parser", "php_include_extracted_proof"),
        ("ssti_fingerprint", "ssti_extracted_proof"),
        ("xxe_boundary", "xxe_extracted_proof"),
    ],
)
@pytest.mark.parametrize(
    ("missing_key", "expected_missing"),
    [
        ("replay", "request_template"),
        ("response", "response_summary"),
        ("proofs", "class_specific_indicator"),
    ],
)
def test_extracted_proof_contract_aliases_fail_closed_without_required_evidence(
    probe: str,
    finding_type: str,
    missing_key: str,
    expected_missing: str,
) -> None:
    payload = json.loads(_extracted_proof_probe_text(probe=probe, finding_type=finding_type))
    del payload["findings"][0][missing_key]

    [qualified] = qualify_probe_findings(
        probe=probe,
        probe_text=json.dumps(payload),
        target_url="http://127.0.0.1/",
    )

    assert qualified.contract_status == "registered"
    assert qualified.promotable is False
    assert qualified.stage is OutcomeStage.SUSPECTED_VULNERABILITY
    assert expected_missing in qualified.missing_evidence


def test_outcome_summary_is_monotonic_and_provenance_checked() -> None:
    [qualified] = qualify_probe_findings(
        probe="file_read_extract",
        probe_text=_file_read_probe_text(secret="not-stored"),  # noqa: S106
        target_url="http://127.0.0.1:8765/",
    )
    tool = (
        "tool_run_probe",
        {
            "observation_id": "observation-1",
            "action_id": "action-1",
            "display_summary": {"probe": "file_read_extract"},
            "recognized_proofs": [],
        },
    )
    suspected = outcome_evidence_payload(
        qualified,
        engagement_id=_ENGAGEMENT_ID,
        source_observation_id="observation-1",
        action_id="action-1",
        confirmed=False,
        forced_stage=OutcomeStage.SUSPECTED_VULNERABILITY,
    )
    verified = outcome_evidence_payload(
        qualified,
        engagement_id=_ENGAGEMENT_ID,
        source_observation_id="observation-1",
        action_id="action-1",
        confirmed=True,
    )
    forged = dict(verified)
    forged["evidence_id"] = "forged"
    forged["source_observation_id"] = "model-authored-observation"

    summary = summarize_run_outcome(
        [
            tool,
            ("outcome_evidence_observed", suspected),
            ("outcome_evidence_observed", verified),
            ("outcome_evidence_observed", forged),
        ]
    )

    assert summary.stage is OutcomeStage.EXPLOIT_PRIMITIVE
    assert summary.evidence_count == 1
    assert summary.exploit_primitive_count == 1
    assert summary.vulnerability_classes == ("path_traversal",)


def test_workspace_outcome_is_scoped_to_current_engagement(tmp_path: Path) -> None:
    [qualified] = qualify_probe_findings(
        probe="file_read_extract",
        probe_text=_file_read_probe_text(secret="scoped-secret"),  # noqa: S106
        target_url="http://127.0.0.1:8765/",
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    workspace.record_event(
        kind="tool_run_probe",
        payload={
            "observation_id": "stale-observation",
            "action_id": "stale-action",
            "display_summary": {"probe": "file_read_extract"},
            "recognized_proofs": [],
        },
    )
    workspace.record_event(
        kind="outcome_evidence_observed",
        payload=outcome_evidence_payload(
            qualified,
            engagement_id=UUID("99999999-9999-4999-8999-999999999999"),
            source_observation_id="stale-observation",
            action_id="stale-action",
            confirmed=True,
        ),
    )

    summary = load_run_outcome(
        db_path=None,
        workspace_path=workspace.root,
        engagement_id=_ENGAGEMENT_ID,
    )

    assert summary.stage is OutcomeStage.NONE
    assert summary.evidence_count == 0


def test_workspace_outcome_loads_nested_graph_stream_without_audit_db(
    tmp_path: Path,
) -> None:
    [qualified] = qualify_probe_findings(
        probe="file_read_extract",
        probe_text=_file_read_probe_text(secret="nested-secret"),  # noqa: S106
        target_url="http://127.0.0.1:8765/",
    )
    root = tmp_path / "workspace"
    graph_workspace = AgentWorkspace.open(root / "autonomous-route" / "agent-graph")
    graph_workspace.record_event(
        kind="tool_run_probe",
        payload={
            "observation_id": "nested-observation",
            "action_id": "nested-action",
            "display_summary": {"probe": "file_read_extract"},
            "recognized_proofs": [],
        },
    )
    graph_workspace.record_event(
        kind="outcome_evidence_observed",
        payload=outcome_evidence_payload(
            qualified,
            engagement_id=_ENGAGEMENT_ID,
            source_observation_id="nested-observation",
            action_id="nested-action",
            confirmed=True,
        ),
    )

    summary = load_run_outcome(
        db_path=None,
        workspace_path=root,
        engagement_id=_ENGAGEMENT_ID,
    )

    assert summary.stage is OutcomeStage.EXPLOIT_PRIMITIVE
    assert summary.evidence_count == 1
    assert summary.vulnerability_classes == ("path_traversal",)

    resumed = _existing_to_result(
        {
            "benchmark_id": "XBEN-001-24",
            "status": "failed",
            "solved": False,
            "workspace_path": str(root),
            "outcome_stage": "none",
        }
    )
    assert resumed.outcome_stage == "exploit_primitive"
    assert resumed.outcome_evidence_count == 1
    assert resumed.outcome_vulnerability_classes == ("path_traversal",)


def test_exact_executor_flag_evidence_outranks_vulnerability() -> None:
    proof = "flag{outcome-evidence-exact-proof}"
    records = [
        (
            "tool_run_probe",
            {
                "observation_id": "observation-flag",
                "action_id": "action-flag",
                "display_summary": {"probe": "file_read_extract"},
                "recognized_proofs": [proof],
            },
        ),
        (
            "flag_captured",
            {
                "flag": proof,
                "source_observation_id": "observation-flag",
                "action_id": "action-flag",
            },
        ),
    ]

    exact = summarize_run_outcome(records, expected_flag=proof)
    wrong_expected = summarize_run_outcome(
        records,
        expected_flag="flag{different-target-proof}",
    )

    assert exact.stage is OutcomeStage.FLAG_CAPTURED
    assert wrong_expected.stage is OutcomeStage.NONE


def test_captured_proof_validation_rejects_wrong_engagement_and_stale_links() -> None:
    proof = "flag{provenance-unit-proof}"
    observation = (
        "tool_run_probe",
        {
            "observation_id": "observation-current",
            "action_id": "action-current",
            "recognized_proofs": [proof],
        },
    )
    valid = (
        "flag_captured",
        {
            "flag": proof,
            "engagement_id": str(_ENGAGEMENT_ID),
            "source_observation_id": "observation-current",
            "source_kind": "tool_run_probe",
            "action_id": "action-current",
        },
    )
    invalid = [
        (
            "flag_captured",
            {
                **valid[1],
                "engagement_id": str(uuid4()),
            },
        ),
        (
            "flag_captured",
            {
                **valid[1],
                "action_id": "action-stale",
            },
        ),
        (
            "flag_captured",
            {
                **valid[1],
                "source_observation_id": "observation-missing",
            },
        ),
    ]

    assert validated_captured_flags(
        [observation, *invalid, valid],
        engagement_id=_ENGAGEMENT_ID,
    ) == [proof]
    assert (
        validated_captured_flags(
            [observation, *invalid],
            engagement_id=_ENGAGEMENT_ID,
        )
        == []
    )


def test_native_finding_survives_no_flag_run_and_is_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "native-response-secret"  # noqa: S105 - redaction fixture.
    monkeypatch.setattr(
        "ravage.agent_core.action_executor.subprocess.run",
        _probe_runner(_file_read_probe_text(secret=secret)),
    )
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = tmp_path / "run" / "audit.db"
    audit = AuditStore(
        audit_path,
        scope=Scope(in_scope=["http://127.0.0.1:8765/"], out_of_scope=[]),
    )
    try:
        result = execute_action(
            {"action": "run_probe", "probe": "file_read_extract"},
            target_url="http://127.0.0.1:8765/",
            runtime=object(),  # type: ignore[arg-type]
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=_ENGAGEMENT_ID,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            proof_recognition_enabled=True,
            action_id="native-no-flag",
        )
        assert audit.count_findings(status="confirmed", engagement_id=_ENGAGEMENT_ID) == 1
    finally:
        audit.close()

    assert result.stop is False
    assert result.flag == ""
    assert result.outcome == "finding_confirmed"
    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    confirmed = [event for event in events if event["kind"] == "finding_confirmed"]
    outcomes = [event for event in events if event["kind"] == "outcome_evidence_observed"]
    assert len(confirmed) == 1
    assert len(outcomes) == 1
    assert outcomes[0]["payload"]["stage"] == "exploit_primitive"
    assert secret not in json.dumps(confirmed[0], sort_keys=True)
    assert secret not in json.dumps(outcomes[0], sort_keys=True)

    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        """
engagement_id: "77777777-7777-4777-8777-777777777777"
scope:
  in_scope: ["http://127.0.0.1:8765/"]
  out_of_scope: []
roe:
  max_rps: 1
  no_destructive_actions: true
  data_handling: redacted
objectives: ["web_application_assessment"]
budget:
  max_cost_usd: 1
  max_runtime_min: 5
context:
  description: outcome evidence test
""".lstrip(),
        encoding="utf-8",
    )
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765/",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )

    assert report["executive_summary"]["captured_proof_count"] == 0
    assert report["executive_summary"]["finding_count"] == 1
    assert report["executive_summary"]["outcome_stage"] == "exploit_primitive"
    assert report["outcome"]["confirmed_finding_count"] == 1
    assert "Highest evidence-backed outcome: exploit_primitive" in render_markdown_report(report)


def test_multiple_unknown_native_findings_survive_no_flag_run_as_suspected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "private-unknown-probe-value"  # noqa: S105 - redaction fixture.
    probe = "future_access_boundary"
    monkeypatch.setattr(
        "ravage.agent_core.action_executor.subprocess.run",
        _probe_runner(_unknown_contract_probe_text(probe=probe, secret=secret)),
    )
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = tmp_path / "run" / "audit.db"
    audit = AuditStore(
        audit_path,
        scope=Scope(in_scope=["http://127.0.0.1:8765/"], out_of_scope=[]),
    )
    try:
        result = execute_action(
            {"action": "run_probe", "probe": probe},
            target_url="http://127.0.0.1:8765/",
            runtime=object(),  # type: ignore[arg-type]
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=_ENGAGEMENT_ID,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            proof_recognition_enabled=False,
            action_id="unknown-no-flag",
        )
        assert audit.count_findings(status="confirmed", engagement_id=_ENGAGEMENT_ID) == 0
    finally:
        audit.close()

    assert result.stop is False
    assert result.flag == ""
    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    assert not any(event["kind"] == "finding_confirmed" for event in events)
    assert not any(event["kind"] == "flag_captured" for event in events)
    outcome_events = [
        event["payload"] for event in events if event["kind"] == "outcome_evidence_observed"
    ]
    assert len(outcome_events) == _UNKNOWN_FINDING_COUNT
    assert all(event["stage"] == "suspected_vulnerability" for event in outcome_events)
    assert all(event["confirmed_finding"] is False for event in outcome_events)
    assert all(event["contract_status"] == "contract_missing" for event in outcome_events)
    assert secret not in json.dumps(outcome_events, sort_keys=True)

    summary = load_run_outcome(
        db_path=audit_path,
        workspace_path=workspace.root,
        engagement_id=_ENGAGEMENT_ID,
    )
    assert summary.stage is OutcomeStage.SUSPECTED_VULNERABILITY
    assert summary.evidence_count == _UNKNOWN_FINDING_COUNT
    assert summary.suspected_vulnerability_count == _UNKNOWN_FINDING_COUNT
    assert summary.confirmed_finding_count == 0
    assert {item["finding_type"] for item in summary.evidence} == {
        "future_authorization_boundary",
        "future_session_boundary",
    }
    assert secret not in json.dumps(summary.to_json(), sort_keys=True)

    brief_path = _write_no_flag_brief(tmp_path)
    report = build_pentest_report(
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765/",
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )
    markdown = render_markdown_report(report)
    assert report["executive_summary"]["captured_proof_count"] == 0
    assert report["executive_summary"]["finding_count"] == 0
    assert report["executive_summary"]["outcome_stage"] == "suspected_vulnerability"
    assert report["outcome"]["suspected_vulnerability_count"] == _UNKNOWN_FINDING_COUNT
    assert "## Suspected Vulnerabilities" in markdown
    assert "future_authorization_boundary" in markdown
    assert "future_session_boundary" in markdown
    assert secret not in json.dumps(report, sort_keys=True)
    assert secret not in markdown


def test_no_flag_report_keeps_confirmed_and_contract_missing_findings_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_url = "http://127.0.0.1:8765/"
    confirmed_secret = "combined-confirmed-secret"  # noqa: S105 - redaction fixture.
    suspected_secret = "combined-suspected-secret"  # noqa: S105 - redaction fixture.
    workspace = AgentWorkspace.open(tmp_path / "run" / "workspace")
    audit_path = tmp_path / "run" / "audit.db"
    audit = AuditStore(
        audit_path,
        scope=Scope(in_scope=[target_url], out_of_scope=[]),
    )
    try:
        monkeypatch.setattr(
            "ravage.agent_core.action_executor.subprocess.run",
            _probe_runner(_file_read_probe_text(secret=confirmed_secret)),
        )
        confirmed = execute_action(
            {"action": "run_probe", "probe": "file_read_extract"},
            target_url=target_url,
            runtime=object(),  # type: ignore[arg-type]
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=_ENGAGEMENT_ID,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            proof_recognition_enabled=False,
            action_id="combined-confirmed",
        )

        unknown_payload = json.loads(
            _unknown_contract_probe_text(
                probe="future_access_boundary",
                secret=suspected_secret,
            )
        )
        unknown_payload["findings"] = unknown_payload["findings"][:1]
        monkeypatch.setattr(
            "ravage.agent_core.action_executor.subprocess.run",
            _probe_runner(json.dumps(unknown_payload)),
        )
        suspected = execute_action(
            {"action": "run_probe", "probe": "future_access_boundary"},
            target_url=target_url,
            runtime=object(),  # type: ignore[arg-type]
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=_ENGAGEMENT_ID,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            proof_recognition_enabled=False,
            action_id="combined-suspected",
        )
        assert audit.count_findings(status="confirmed", engagement_id=_ENGAGEMENT_ID) == 1
    finally:
        audit.close()

    assert confirmed.flag == suspected.flag == ""
    summary = load_run_outcome(
        db_path=audit_path,
        workspace_path=workspace.root,
        engagement_id=_ENGAGEMENT_ID,
    )
    assert summary.stage is OutcomeStage.EXPLOIT_PRIMITIVE
    assert summary.evidence_count == _COMBINED_EVIDENCE_COUNT
    assert summary.confirmed_finding_count == 1
    assert summary.suspected_vulnerability_count == 1
    assert {item["contract_status"] for item in summary.evidence} == {
        "registered",
        "contract_missing",
    }

    report = build_pentest_report(
        brief_path=_write_no_flag_brief(tmp_path),
        target_url=target_url,
        workspace_dir=workspace.root,
        status="completed",
        completed=True,
        audit_db_path=audit_path,
    )
    markdown = render_markdown_report(report)
    assert report["executive_summary"]["captured_proof_count"] == 0
    assert report["executive_summary"]["finding_count"] == 1
    assert report["outcome"]["confirmed_finding_count"] == 1
    assert report["outcome"]["suspected_vulnerability_count"] == 1
    assert "## Findings" in markdown
    assert "## Suspected Vulnerabilities" in markdown
    assert "future_authorization_boundary" in markdown


def test_outcome_events_are_idempotent_for_same_native_primitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.agent_core.action_executor.subprocess.run",
        _probe_runner(_file_read_probe_text(secret="repeat-secret")),  # noqa: S106
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    engagement_id = uuid4()
    try:
        for action_id in ("native-first", "native-replay"):
            execute_action(
                {"action": "run_probe", "probe": "file_read_extract"},
                target_url="http://127.0.0.1:8765/",
                runtime=object(),  # type: ignore[arg-type]
                state=AgentState(),
                workspace=workspace,
                audit=audit,
                engagement_id=engagement_id,
                repeat_count=1,
                max_observation_chars=2_000,
                max_transcript_chars=20_000,
                action_id=action_id,
            )
        assert audit.count_findings(status="confirmed", engagement_id=engagement_id) == 1
    finally:
        audit.close()

    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    assert sum(event["kind"] == "finding_confirmed" for event in events) == 1
    assert sum(event["kind"] == "outcome_evidence_observed" for event in events) == 1


def test_incomplete_native_evidence_is_reported_as_suspected_not_confirmed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.agent_core.action_executor.subprocess.run",
        _probe_runner(_ssti_template_error_probe_text()),
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        result = execute_action(
            {"action": "run_probe", "probe": "ssti_fingerprint"},
            target_url="http://127.0.0.1:8765/",
            runtime=object(),  # type: ignore[arg-type]
            state=AgentState(),
            workspace=workspace,
            audit=audit,
            engagement_id=_ENGAGEMENT_ID,
            repeat_count=1,
            max_observation_chars=2_000,
            max_transcript_chars=20_000,
            action_id="ssti-candidate",
        )
        assert audit.count_findings(status="confirmed") == 0
    finally:
        audit.close()

    assert result.outcome != "finding_confirmed"
    events = [json.loads(line) for line in workspace.events_path.read_text().splitlines()]
    evidence = next(
        event["payload"] for event in events if event["kind"] == "outcome_evidence_observed"
    )
    assert evidence["stage"] == "suspected_vulnerability"
    assert evidence["missing_evidence"] == ["evaluated_expression"]

    summary = summarize_run_outcome(
        [
            (str(event["kind"]), event["payload"])
            for event in events
            if isinstance(event.get("payload"), dict)
        ]
    )
    rendered = render_markdown_report(
        {
            "engagement": {"scope": {}, "rules_of_engagement": {}},
            "executive_summary": {
                "summary": "Partial assessment.",
                "finding_count": 0,
                "captured_proof_count": 0,
                "outcome_stage": summary.stage.value,
            },
            "captured_proofs": {"count": 0, "masked": []},
            "outcome": summary.to_json(),
            "findings": [],
            "methodology": [],
            "recommendations": [],
            "limitations": [],
            "evidence_handling": [],
        }
    )
    assert "## Suspected Vulnerabilities" in rendered
    assert "ssti_fingerprint_signal" in rendered


def test_xben_legacy_result_defaults_outcome_without_changing_solved() -> None:
    legacy_http_count = 14
    result = _existing_to_result(
        {
            "benchmark_id": "XBEN-001-24",
            "name": "legacy",
            "status": "solved",
            "solved": True,
            "found_flag": "flag{legacy-exact-proof}",
            "http_request_count": legacy_http_count,
            "http_request_count_status": "exact",
        }
    )

    assert result.solved is True
    assert result.status == "skipped"
    assert result.outcome_stage == "none"
    assert result.outcome_evidence_count == 0
    assert result.http_request_count_status == "unavailable"
    assert result.http_request_count_provenance == "legacy_report_numeric_count"
    assert result.http_request_count == legacy_http_count
    assert result.tool_action_count == legacy_http_count
    assert result.to_json()["outcome_stage"] == "none"


def test_xben_legacy_result_rejects_invalid_outcome_metrics() -> None:
    result = _existing_to_result(
        {
            "benchmark_id": "XBEN-001-24",
            "status": "failed",
            "solved": False,
            "outcome_stage": "invented_super_flag",
            "outcome_evidence_count": -10,
            "confirmed_finding_count": -20,
            "outcome_vulnerability_classes": ["command_injection"],
        }
    )

    assert result.outcome_stage == "none"
    assert result.outcome_evidence_count == 0
    assert result.confirmed_finding_count == 0
    assert result.outcome_vulnerability_classes == ()


def test_scan_captured_flag_survives_legacy_audit_without_findings_table(
    tmp_path: Path,
) -> None:
    proof = "flag{trusted_scan_capture}"
    db_path = tmp_path / "legacy-audit.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE audit_log "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, payload_json TEXT)"
        )
        connection.execute(
            "INSERT INTO audit_log (action, payload_json) VALUES (?, ?)",
            (
                "flag_captured",
                json.dumps(
                    {
                        "flag": proof,
                        "evidence": "scan result",
                        "recognizer": "scan_probe_output",
                    }
                ),
            ),
        )

    summary = load_run_outcome(
        db_path=db_path,
        workspace_path=tmp_path / "missing-workspace",
        expected_flag=proof,
    )

    assert summary.stage is OutcomeStage.FLAG_CAPTURED


def test_xben_report_adds_outcome_metrics_without_inflating_solved(tmp_path: Path) -> None:
    confirmed_findings = 2
    output_dir = tmp_path / "xben"
    output_dir.mkdir()
    result = replace(
        _existing_to_result(
            {
                "benchmark_id": "XBEN-002-24",
                "name": "evidence-only",
                "status": "failed",
                "solved": False,
            }
        ),
        outcome_stage="exploit_primitive",
        outcome_evidence_count=3,
        confirmed_finding_count=confirmed_findings,
        outcome_vulnerability_classes=("command_injection",),
    )
    case = XbenCase(
        benchmark_id="XBEN-002-24",
        path=tmp_path / "case",
        name="evidence-only",
        level=2,
        description="No proof captured, but an exploit primitive was retained.",
        main_service="web",
        main_service_port=80,
    )

    report = _write_report(
        settings=XbenSettings(output_dir=output_dir),
        results=[result],
        selected_cases=[case],
    )
    summary = report["summary"]

    assert isinstance(summary, dict)
    assert summary["solved"] == 0
    assert summary["failed"] == 1
    assert summary["cases_with_verified_vulnerability"] == 1
    assert summary["cases_with_exploit_primitive"] == 1
    assert summary["confirmed_findings"] == confirmed_findings
    assert summary["outcome_stages"] == {"exploit_primitive": 1}


def test_full_probe_payload_feeds_identity_aware_graph_before_clipping(
    tmp_path: Path,
) -> None:
    target_url = "http://127.0.0.1:8765/"
    expected_status = 200
    observed_value = "private-value"
    request_url = f"{target_url}api/users/42?expand={observed_value}"
    probe_text = json.dumps(
        {
            "probe": "api_behavior",
            "ok": True,
            "summary": "A" * 5_000,
            "requests": [
                {
                    "method": "GET",
                    "url": request_url,
                    "status": expected_status,
                    "request_header_names": ["Accept"],
                }
            ],
            "findings": [],
            "errors": ["B" * 5_000],
        }
    )
    state = AgentState(
        surface={"target_url": target_url},
        surface_graph=SurfaceGraphState.for_target(target_url),
    )
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    audit = AuditStore(tmp_path / "audit.db")
    try:
        result = _record_probe_result(
            probe_text,
            ok=True,
            kind="tool_run_probe",
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=_ENGAGEMENT_ID,
            proof_recognition_enabled=False,
            action_id="graph-before-clipping",
            repeat_count=1,
            timed_out=False,
            max_observation_chars=320,
            max_transcript_chars=320,
            session_mode="identity:alice",
        )
    finally:
        audit.close()

    assert result.ok is True
    assert request_url not in result.observation
    assert "truncated from middle" in result.observation
    [operation] = list((state.surface_graph.operations or {}).values())
    assert operation.method == "GET"
    assert operation.route_shape == "/api/users/{int}"
    assert operation.provenance == ("probe",)
    assert operation.actionable is False
    assert operation.parameters == ()
    [observation] = list((state.surface_graph.observations or {}).values())
    assert observation.identity_alias == "alice"
    assert observation.source_kind == "probe"
    assert observation.response_status == expected_status
    assert {
        str(state.last_observation["observation_id"]),
        "api_behavior",
    } <= set(observation.evidence_refs)

    projected = json.dumps(state.surface, sort_keys=True)
    serialized_graph = json.dumps(state.surface_graph.to_json(), sort_keys=True)
    assert "http://127.0.0.1:8765/api/users/{int}" not in projected
    assert observed_value not in projected
    assert observed_value not in serialized_graph


def test_tool_text_keeps_evidence_head_and_tail_before_bounded_wrapper() -> None:
    max_chars = 600
    result = ToolResult(
        ok=True,
        tool="command",
        command=(
            "sh",
            "-lc",
            "wrapper-start " + ("C" * 2_000) + " wrapper-tail",
        ),
        exit_code=0,
        stdout="HEAD_SIGNAL\n" + ("A" * 4_000) + "\nTAIL_SIGNAL",
        stderr="",
    )

    compacted = _tool_text(result, max_chars=max_chars)
    payload = json.loads(compacted)

    assert len(compacted) <= max_chars
    assert compacted.index('"stdout"') < compacted.index('"command"')
    assert payload["stdout"].startswith("HEAD_SIGNAL")
    assert payload["stdout"].endswith("TAIL_SIGNAL")
    assert "truncated from middle" in payload["stdout"]
    assert payload["command"][0].startswith("sh\n-lc\nwrapper-start")
    assert payload["command"][0].endswith("wrapper-tail")


def _file_read_probe_text(*, secret: str) -> str:
    return json.dumps(
        {
            "probe": "file_read_extract",
            "ok": True,
            "summary": "local file content observed without a target proof",
            "findings": [
                {
                    "type": "file_read_primitive",
                    "payload": "../../../../etc/passwd",
                    "signal": {
                        "kind": "local_file_read",
                        "matches": ["root:x:0:0", secret],
                    },
                    "delta": {"body_changed": True},
                    "response": {
                        "method": "GET",
                        "url": (
                            f"http://127.0.0.1:8765/view?file=../../../../etc/passwd&token={secret}"
                        ),
                        "final_url": "http://127.0.0.1:8765/view",
                        "status": 200,
                        "elapsed_ms": 12,
                        "body_len": 250,
                        "body_sha_hint": "0123456789abcdef",
                        "body_snippet": f"root:x:0:0:{secret}",
                        "error": "",
                    },
                    "replay": {
                        "method": "GET",
                        "url": (
                            f"http://127.0.0.1:8765/view?file=../../../../etc/passwd&token={secret}"
                        ),
                        "payload_field": "file",
                    },
                }
            ],
            "requests": [],
            "errors": [],
        }
    )


def _extracted_proof_probe_text(*, probe: str, finding_type: str) -> str:
    return json.dumps(
        {
            "probe": probe,
            "ok": True,
            "findings": [
                {
                    "type": finding_type,
                    "proofs": ["flag{contract-alias-fixture}"],
                    "replay": {
                        "method": "GET",
                        "url": "http://127.0.0.1/proof?input=payload",
                        "payload_field": "input",
                    },
                    "response": {
                        "method": "GET",
                        "url": "http://127.0.0.1/proof",
                        "status": 200,
                        "body_sha_hint": "proofhash",
                    },
                }
            ],
            "requests": [],
            "errors": [],
        }
    )


def _ssti_template_error_probe_text() -> str:
    return json.dumps(
        {
            "probe": "ssti_fingerprint",
            "ok": True,
            "summary": "template error observed without expression evaluation",
            "findings": [
                {
                    "type": "ssti_fingerprint_signal",
                    "signal": {"kind": "template_error", "markers": ["jinja2"]},
                    "replay": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8765/render?name=%7B%7B",
                        "payload_field": "name",
                    },
                    "baseline_replay": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8765/render?name=hello",
                        "payload_field": "name",
                    },
                    "response": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8765/render",
                        "status": 500,
                        "body_sha_hint": "abc123",
                    },
                    "delta": {"status_changed": True},
                }
            ],
            "requests": [],
            "errors": [],
        }
    )


def _unknown_contract_probe_text(*, probe: str, secret: str) -> str:
    first_url = f"http://127.0.0.1:8765/accounts?account={secret}"
    second_url = f"http://127.0.0.1:8765/session?token={secret}"
    return json.dumps(
        {
            "probe": probe,
            "ok": True,
            "summary": "two structured observations require finding contracts",
            "findings": [
                {
                    "type": "future_authorization_boundary",
                    "vuln_class": "authorization",
                    "input": {"name": "account", "value": secret},
                    "signal": {"kind": "access_changed", "value": secret},
                    "replay": {
                        "method": "GET",
                        "url": first_url,
                        "payload_field": "account",
                    },
                    "response": {
                        "method": "GET",
                        "url": first_url,
                        "status": 200,
                        "body_snippet": secret,
                    },
                },
                {
                    "type": "future_session_boundary",
                    "input": {"name": "role", "value": secret},
                    "detail": "a session boundary changed",
                    "replay": {
                        "method": "POST",
                        "url": second_url,
                        "form": {"role": secret},
                        "payload_field": "role",
                    },
                    "response": {
                        "method": "POST",
                        "url": second_url,
                        "status": 200,
                        "body_snippet": secret,
                    },
                },
            ],
            "requests": [],
            "errors": [],
        }
    )


def _write_no_flag_brief(tmp_path: Path) -> Path:
    path = tmp_path / "brief.yaml"
    path.write_text(
        """
engagement_id: "77777777-7777-4777-8777-777777777777"
scope:
  in_scope: ["http://127.0.0.1:8765/"]
  out_of_scope: []
roe:
  max_rps: 1
  no_destructive_actions: true
  data_handling: redacted
objectives: ["web_application_assessment"]
budget:
  max_cost_usd: 1
  max_runtime_min: 5
context:
  description: no-flag outcome evidence test
""".lstrip(),
        encoding="utf-8",
    )
    return path


class _CompletedProbeRunner:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def _probe_runner(probe_text: str) -> object:
    def runner(*args: object, **kwargs: object) -> _CompletedProbeRunner:
        del args, kwargs
        return _CompletedProbeRunner(json.dumps({"status": "ok", "ok": True, "text": probe_text}))

    return runner
