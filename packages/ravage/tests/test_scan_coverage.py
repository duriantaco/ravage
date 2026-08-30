from __future__ import annotations

import json
import stat
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from ravage.scan_coverage import (
    MAX_CERTIFICATE_BYTES,
    PlannerProbeDecision,
    ProbeCoverageOutcome,
    ProbeDisposition,
    RequestAccountingStatus,
    ScanCoverageError,
    ScanCoverageRecorder,
    ScanCoverageStatus,
    write_scan_coverage_certificate,
)
from ravage.traffic.policy import (
    TrafficPolicyConfig,
    TrafficPolicyMode,
    TrafficPolicySnapshot,
)

if TYPE_CHECKING:
    from pathlib import Path

_PRIVATE_FILE_MODE = 0o600


def _snapshot(**changes: int | str) -> TrafficPolicySnapshot:
    snapshot = TrafficPolicySnapshot(
        physical_request_count=3,
        completed_request_count=3,
        incomplete_request_count=0,
        pending_dispatch_count=0,
        reservation_count=0,
        cache_hit_count=0,
        deduplicated_count=0,
        retry_count=0,
        blocked_count=0,
        circuit_open_count=0,
        unmetered_action_count=0,
        accounting_status="exact",
    )
    return replace(snapshot, **changes)


def _config() -> TrafficPolicyConfig:
    return TrafficPolicyConfig(
        mode=TrafficPolicyMode.ENFORCE,
        max_rps=0.5,
        max_physical_requests=20,
        cache_enabled=True,
        deduplicate=True,
    )


def _complete_recorder() -> ScanCoverageRecorder:
    recorder = ScanCoverageRecorder()
    recorder.record_planner_decision(
        PlannerProbeDecision(
            probe_id="surface_map",
            family="recon",
            rank=0,
            surface_key="http://127.0.0.1/private/path?q=secret",
            reason_codes=("broad_first",),
        )
    )
    recorder.record_probe_outcome(
        ProbeCoverageOutcome(
            probe_id="surface_map",
            disposition=ProbeDisposition.COMPLETED_NO_FINDING,
            physical_request_count=3,
        )
    )
    return recorder


def test_exact_finite_plan_produces_versioned_complete_certificate() -> None:
    recorder = _complete_recorder()
    recorder.record_planner_decision(
        PlannerProbeDecision(
            probe_id="sqli_differential",
            family="injection",
            rank=1,
            reason_codes=("observed_query_input",),
        )
    )
    recorder.record_probe_outcome(
        ProbeCoverageOutcome(
            probe_id="sqli_differential",
            disposition=ProbeDisposition.COMPLETED_FINDING,
            finding_count=2,
        )
    )
    recorder.record_planner_decision(
        PlannerProbeDecision(
            probe_id="graphql_schema",
            family="graphql",
            rank=2,
            terminal_disposition=ProbeDisposition.NOT_APPLICABLE,
            reason_codes=("surface_absent",),
        )
    )

    certificate = recorder.finalize(
        planner_frontier_exhausted=True,
        traffic_snapshot=_snapshot(),
        traffic_config=_config(),
    )
    payload = certificate.to_json()

    assert certificate.status is ScanCoverageStatus.COMPLETE
    assert payload["schema"] == "ravage.scan-coverage"
    assert payload["version"] == 1
    assert payload["completion_basis"] == "planner_frontier_exhausted"
    assert payload["limitations"] == []
    assert payload["summary"] == {
        "completed_probe_count": 2,
        "disposition_counts": {
            "blocked_budget": 0,
            "completed_finding": 1,
            "completed_no_finding": 1,
            "not_applicable": 1,
            "transport_incomplete": 0,
            "unsupported": 0,
        },
        "finding_count": 2,
        "planner_decision_count": 3,
    }
    graphql = certificate.probes[2].to_json()
    assert graphql["request_accounting_status"] == "exact"
    assert graphql["physical_request_count"] == 0


@pytest.mark.parametrize(
    ("disposition", "expected_limitation"),
    [
        (ProbeDisposition.UNSUPPORTED, "unsupported_probe"),
        (ProbeDisposition.BLOCKED_BUDGET, "budget_blocked"),
        (ProbeDisposition.TRANSPORT_INCOMPLETE, "transport_incomplete"),
    ],
)
def test_incomplete_dispositions_force_partial_status(
    disposition: ProbeDisposition,
    expected_limitation: str,
) -> None:
    recorder = _complete_recorder()
    recorder.record_planner_decision(
        PlannerProbeDecision(probe_id="candidate_probe", family="candidate", rank=1)
    )
    recorder.record_probe_outcome(
        ProbeCoverageOutcome(probe_id="candidate_probe", disposition=disposition)
    )

    certificate = recorder.finalize(
        planner_frontier_exhausted=True,
        traffic_snapshot=_snapshot(),
        traffic_config=_config(),
    )

    assert certificate.status is ScanCoverageStatus.PARTIAL
    assert expected_limitation in certificate.limitations


@pytest.mark.parametrize("accounting_status", ["lower_bound", "unavailable"])
def test_non_exact_whole_run_accounting_forces_partial(accounting_status: str) -> None:
    certificate = _complete_recorder().finalize(
        planner_frontier_exhausted=True,
        traffic_snapshot=_snapshot(accounting_status=accounting_status),
        traffic_config=_config(),
    )

    assert certificate.status is ScanCoverageStatus.PARTIAL
    assert f"traffic_accounting_{accounting_status}" in certificate.limitations


@pytest.mark.parametrize(
    ("changes", "expected_limitation"),
    [
        ({"incomplete_request_count": 1}, "traffic_incomplete"),
        ({"pending_dispatch_count": 1}, "traffic_incomplete"),
        ({"blocked_count": 1}, "traffic_policy_blocked"),
        ({"circuit_open_count": 1}, "traffic_circuit_open"),
        ({"unmetered_action_count": 1}, "unmetered_actions"),
    ],
)
def test_whole_run_transport_and_policy_gaps_force_partial(
    changes: dict[str, int],
    expected_limitation: str,
) -> None:
    certificate = _complete_recorder().finalize(
        planner_frontier_exhausted=True,
        traffic_snapshot=_snapshot(**changes),
        traffic_config=_config(),
    )

    assert certificate.status is ScanCoverageStatus.PARTIAL
    assert expected_limitation in certificate.limitations


def test_missing_traffic_accounting_is_explicitly_partial() -> None:
    certificate = _complete_recorder().finalize(
        planner_frontier_exhausted=True,
        traffic_snapshot=None,
        traffic_config=_config(),
    )

    assert certificate.status is ScanCoverageStatus.PARTIAL
    assert certificate.traffic.accounting_status is RequestAccountingStatus.UNAVAILABLE
    assert certificate.traffic.physical_request_count is None
    assert "traffic_accounting_unavailable" in certificate.limitations


def test_per_probe_lower_bound_accounting_forces_partial() -> None:
    recorder = ScanCoverageRecorder()
    recorder.record_planner_decision(
        PlannerProbeDecision(probe_id="dom_execution", family="browser", rank=0)
    )
    recorder.record_probe_outcome(
        ProbeCoverageOutcome(
            probe_id="dom_execution",
            disposition=ProbeDisposition.COMPLETED_NO_FINDING,
            physical_request_count=1,
            request_accounting_status=RequestAccountingStatus.LOWER_BOUND,
        )
    )

    certificate = recorder.finalize(
        planner_frontier_exhausted=True,
        traffic_snapshot=_snapshot(accounting_status="lower_bound"),
        traffic_config=_config(),
    )

    assert certificate.status is ScanCoverageStatus.PARTIAL
    assert "probe_request_accounting_lower_bound" in certificate.limitations


def test_missing_probe_outcome_is_materialized_without_claiming_completion() -> None:
    recorder = ScanCoverageRecorder()
    recorder.record_planner_decision(
        PlannerProbeDecision(probe_id="secret_sweep", family="exposure", rank=0)
    )

    certificate = recorder.finalize(
        planner_frontier_exhausted=True,
        traffic_snapshot=_snapshot(),
        traffic_config=_config(),
    )

    assert certificate.status is ScanCoverageStatus.PARTIAL
    assert certificate.probes[0].disposition is ProbeDisposition.TRANSPORT_INCOMPLETE
    assert certificate.probes[0].reason_codes == ("probe_outcome_missing",)
    assert "probe_outcome_missing" in certificate.limitations


def test_json_is_deterministic_path_free_and_uses_narrow_completion_wording() -> None:
    private_surface = "/Users/operator/customer/admin?token=private"

    def build(*, reverse: bool) -> str:
        recorder = ScanCoverageRecorder()
        decisions = [
            PlannerProbeDecision(
                probe_id="second",
                family="injection",
                rank=1,
                surface_key=private_surface,
                reason_codes=("signal_b", "signal_a"),
            ),
            PlannerProbeDecision(
                probe_id="first",
                family="recon",
                rank=0,
                surface_key="https://example.invalid/private",
            ),
        ]
        for decision in reversed(decisions) if reverse else decisions:
            recorder.record_planner_decision(decision)
        outcomes = [
            ProbeCoverageOutcome(
                probe_id="second",
                disposition=ProbeDisposition.COMPLETED_NO_FINDING,
            ),
            ProbeCoverageOutcome(
                probe_id="first",
                disposition=ProbeDisposition.COMPLETED_NO_FINDING,
            ),
        ]
        for outcome in reversed(outcomes) if reverse else outcomes:
            recorder.record_probe_outcome(outcome)
        return recorder.finalize(
            planner_frontier_exhausted=True,
            traffic_snapshot=_snapshot(),
            traffic_config=_config(),
        ).to_json_text()

    forward = build(reverse=False)
    reverse = build(reverse=True)

    assert forward == reverse
    assert private_surface not in forward
    assert "/Users/operator" not in forward
    assert "example.invalid/private" not in forward
    assert forward.count("planner_frontier_exhausted") == 1
    assert "application_exhausted" not in forward
    assert "family_exhausted" not in forward
    assert "no_vulnerability" not in forward
    assert "no vulnerabilities" not in forward.lower()
    assert len(forward.encode()) < MAX_CERTIFICATE_BYTES
    assert json.loads(forward)["probes"][0]["probe_id"] == "first"


def test_open_planner_frontier_is_partial() -> None:
    certificate = _complete_recorder().finalize(
        planner_frontier_exhausted=False,
        traffic_snapshot=_snapshot(),
        traffic_config=_config(),
    )

    assert certificate.status is ScanCoverageStatus.PARTIAL
    assert certificate.completion_basis == "planner_frontier_open"
    assert "planner_frontier_open" in certificate.limitations


def test_inputs_are_bounded_and_do_not_accept_path_identifiers() -> None:
    with pytest.raises(ScanCoverageError, match="lowercase identifier"):
        PlannerProbeDecision(probe_id="/admin", family="recon", rank=0)

    recorder = ScanCoverageRecorder(max_probe_records=1)
    recorder.record_planner_decision(PlannerProbeDecision(probe_id="first", family="recon", rank=0))
    with pytest.raises(ScanCoverageError, match="decision limit"):
        recorder.record_planner_decision(
            PlannerProbeDecision(probe_id="second", family="recon", rank=1)
        )


def test_finding_dispositions_enforce_consistent_counts() -> None:
    with pytest.raises(ScanCoverageError, match="at least one finding"):
        ProbeCoverageOutcome(
            probe_id="sqli",
            disposition=ProbeDisposition.COMPLETED_FINDING,
        )
    with pytest.raises(ScanCoverageError, match="only completed_finding"):
        ProbeCoverageOutcome(
            probe_id="sqli",
            disposition=ProbeDisposition.COMPLETED_NO_FINDING,
            finding_count=1,
        )


def test_certificate_writer_is_atomic_private_and_reproducible(tmp_path: Path) -> None:
    certificate = _complete_recorder().finalize(
        planner_frontier_exhausted=True,
        traffic_snapshot=_snapshot(),
        traffic_config=_config(),
    )
    output_path = tmp_path / "nested" / "scan-coverage.json"

    written = write_scan_coverage_certificate(output_path, certificate)
    first = output_path.read_bytes()
    write_scan_coverage_certificate(output_path, certificate)

    assert written == output_path.absolute()
    assert output_path.read_bytes() == first == certificate.to_json_text().encode()
    assert stat.S_IMODE(output_path.stat().st_mode) == _PRIVATE_FILE_MODE
    assert list(output_path.parent.glob(f".{output_path.name}.*.tmp")) == []
