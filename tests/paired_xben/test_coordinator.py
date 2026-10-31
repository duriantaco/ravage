# ruff: noqa: ANN001,ANN201,ANN202,ARG002,EM101,PLR0913,PLR2004,PLW0108,TC003,TRY003
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, NoReturn, cast

import pytest
from ravage.xben_parts.external_comparison import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    OUTER_PROCESS_GROUP_ENV,
    OUTER_PROCESS_GROUP_VALUE,
    ExternalAgentCommand,
    ExternalExecutionLimits,
)
from ravage.xben_parts.models import XbenCase

from tools.paired_xben import cli as paired_cli
from tools.paired_xben import coordinator
from tools.paired_xben import report as paired_report
from tools.paired_xben.coordinator import (
    AgentNetworkLease,
    CampaignAlreadyStartedError,
    CampaignCoordinatorError,
    DockerAgentNetworkManager,
    ResolvedCampaignPlan,
    RowExecutionContext,
    ScheduledRow,
)
from tools.paired_xben.coordinator import (
    _execute_loaded_campaign as execute_loaded_campaign,
)
from tools.paired_xben.coordinator import (
    _external_limits as external_limits,
)


def _contract() -> dict[str, object]:
    policy = {
        "model": "gpt-test-2026-09-01",
        "reasoning_effort": "high",
        "pricing_usd_per_million_tokens": {
            "input_per_million": "1",
            "cached_input_per_million": "0.1",
            "output_per_million": "4",
        },
        "max_completion_tokens_per_request": 100,
    }
    return {
        "model_gateway": {
            "policy": policy,
            "policy_sha256": "sha256:" + "a" * 64,
        },
        "budgets": {
            "per_row": {
                "wall_seconds": 10,
                "max_model_requests": 2,
                "max_target_requests": 3,
                "max_cost_usd": "0.5",
            },
            "campaign": {
                "wall_seconds": 400,
                "max_model_requests": 80,
                "max_target_requests": 120,
                "max_cost_usd": "20",
            },
        },
        "execution_policy": {
            "evaluator_host": {
                "systems": {
                    system: {"evidence_class": "paired_local"} for system in ("ravage", "strix")
                }
            }
        },
    }


def _plan(tmp_path: Path) -> tuple[ResolvedCampaignPlan, dict[str, XbenCase]]:
    schedule: list[ScheduledRow] = []
    cases: dict[str, XbenCase] = {}
    for pair_index in range(1, 21):
        case_id = f"XBEN-{pair_index:03d}-24"
        case_path = tmp_path / "source" / case_id
        case_path.mkdir(parents=True)
        cases[case_id] = XbenCase(
            benchmark_id=case_id,
            path=case_path,
            name=case_id,
            level=1,
            description="Find the proof through the HTTP application.",
            main_service="app",
            main_service_port=80,
        )
        order = ("ravage", "strix") if pair_index % 2 else ("strix", "ravage")
        for position, system in enumerate(order, start=1):
            system_id = cast("Literal['ravage', 'strix']", system)
            slot = (pair_index - 1) * 2 + position
            artifact_root = tmp_path / "attempts" / "primary" / f"primary-{slot:03d}" / "artifacts"
            artifact_root.mkdir(parents=True)
            schedule.append(
                ScheduledRow(
                    slot_id=f"primary-{slot:03d}",
                    case_id=case_id,
                    system=system_id,
                    pair_index=pair_index,
                    position_within_pair=position,
                    artifact_root=artifact_root,
                )
            )
    return (
        ResolvedCampaignPlan(
            campaign_root=tmp_path,
            campaign_id="campaign-test",
            commitment_digest="sha256:" + "1" * 64,
            selection_digest="sha256:" + "2" * 64,
            primary_matrix_digest="sha256:" + "3" * 64,
            run_contract=_contract(),
            schedule=tuple(schedule),
        ),
        cases,
    )


def test_row_limits_preserve_the_committed_decimal_cost() -> None:
    contract = _contract()
    text = "0.5000000000000000000000000000000000001"
    contract["budgets"]["per_row"]["max_cost_usd"] = text

    limits = external_limits(contract)

    assert limits.max_cost_usd == Decimal(text)
    assert limits.to_json()["max_cost_usd"] == text


def test_row_limits_reject_float_cost_caps() -> None:
    contract = _contract()
    contract["budgets"]["per_row"]["max_cost_usd"] = 0.5

    with pytest.raises(CampaignCoordinatorError, match="row cost cap"):
        external_limits(contract)


class FakeGateway:
    def __init__(
        self,
        events: list[tuple[object, ...]],
        *,
        close_failure: bool = False,
        base_url_failure: bool = False,
        duplicate_tokens: bool = False,
    ) -> None:
        self.events = events
        self.close_failure = close_failure
        self.base_url_failure = base_url_failure
        self.duplicate_tokens = duplicate_tokens
        self.policy_digest = "sha256:" + "a" * 64
        self._base_url = "http://127.0.0.1:32123/v1"
        self.registered: list[str] = []
        self.sealed: set[str] = set()

    @property
    def base_url(self) -> str:
        if self.base_url_failure:
            message = "injected gateway URL failure"
            raise RuntimeError(message)
        return self._base_url

    def register_row(self, row_id, *, max_requests, max_cost_usd):
        self.events.append(("register", row_id, max_requests, str(max_cost_usd)))
        self.registered.append(row_id)
        if self.duplicate_tokens:
            return "duplicate-token-abcdefghijklmnopqrstuvwxyz0123456789"
        return f"token-{row_id}-abcdefghijklmnopqrstuvwxyz0123456789"

    def start(self) -> None:
        assert len(self.registered) == 40
        self.events.append(("gateway_start",))

    def close(self) -> None:
        self.events.append(("gateway_close",))
        if self.close_failure:
            message = "injected gateway close failure"
            raise RuntimeError(message)

    def seal_primary_campaign(self, output_path: Path) -> dict[str, object]:
        assert self.sealed == set(self.registered)
        assert self.events[-1] == ("gateway_close",)
        payload: dict[str, object] = {
            "schema_version": "fake-model-campaign",
            "rows": sorted(self.sealed),
        }
        payload["document_sha256"] = _json_digest(payload)
        output_path.write_text(json.dumps(payload, sort_keys=True) + "\n")
        self.events.append(("gateway_seal", str(output_path)))
        return payload


@dataclass
class FakePrepared:
    pair_id: str
    benchmark_id: str
    evidence_dir: Path


class FakeRuntime:
    def __init__(
        self,
        *,
        setup_failure_slots: set[str] | None = None,
        preparation_failure_pairs: set[int] | None = None,
        prelaunch_failure_slots: set[str] | None = None,
        gateway_close_failure: bool = False,
        gateway_base_url_failure: bool = False,
        duplicate_gateway_tokens: bool = False,
        unstarted_failure_slots: set[str] | None = None,
        postterminal_unstarted_failure_slots: set[str] | None = None,
        context_failure_slots: set[str] | None = None,
        unstarted_context_failure_slots: set[str] | None = None,
        invalid_context_slots: set[str] | None = None,
        postterminal_failure_slots: set[str] | None = None,
        provisioning_failure_slots: set[str] | None = None,
        network_remove_failure_slots: set[str] | None = None,
        release_failure_pairs: set[int] | None = None,
    ) -> None:
        self.events: list[tuple[object, ...]] = []
        self.gateway = FakeGateway(
            self.events,
            close_failure=gateway_close_failure,
            base_url_failure=gateway_base_url_failure,
            duplicate_tokens=duplicate_gateway_tokens,
        )
        self.setup_failure_slots = setup_failure_slots or set()
        self.preparation_failure_pairs = preparation_failure_pairs or set()
        self.prelaunch_failure_slots = prelaunch_failure_slots or set()
        self.unstarted_failure_slots = unstarted_failure_slots or set()
        self.postterminal_unstarted_failure_slots = postterminal_unstarted_failure_slots or set()
        self.context_failure_slots = context_failure_slots or set()
        self.unstarted_context_failure_slots = unstarted_context_failure_slots or set()
        self.invalid_context_slots = invalid_context_slots or set()
        self.postterminal_failure_slots = postterminal_failure_slots or set()
        self.provisioning_failure_slots = provisioning_failure_slots or set()
        self.network_remove_failure_slots = network_remove_failure_slots or set()
        self.release_failure_pairs = release_failure_pairs or set()
        self.flags_by_slot: dict[str, str] = {}
        self.prepared_identity_by_slot: dict[str, int] = {}
        self.prepared_by_slot: dict[str, FakePrepared] = {}
        self.abandoned_slots: set[str] = set()
        self.terminal_counts: dict[str, int] = {}
        self.slot_by_instance: dict[str, str] = {}

    def validate_plan(self, plan) -> None:
        self.events.append(("validate",))

    def load_selected_cases(self, plan):
        raise AssertionError("execute_loaded_campaign receives cases directly")

    def create_gateway(self, plan):
        self.events.append(("gateway_create",))
        return self.gateway

    def build_row_context(
        self,
        *,
        plan,
        row,
        gateway,
        row_token,
        gateway_base_url,
        instance_id,
        network_name,
    ):
        if row.slot_id in self.context_failure_slots:
            raise RuntimeError("injected row context failure")
        context = self._row_context(
            row=row,
            row_token=row_token,
            gateway_base_url=gateway_base_url,
            instance_id=instance_id,
            network_name=network_name,
            setup_error=(
                "injected setup failure" if row.slot_id in self.setup_failure_slots else None
            ),
        )
        if row.slot_id in self.invalid_context_slots:
            return RowExecutionContext(
                row=context.row,
                instance_id="xben-row-" + "0" * 32,
                network_name=context.network_name,
                agent=context.agent,
                process_backend=context.process_backend,
            )
        return context

    def build_unstarted_row_context(
        self,
        *,
        plan,
        row,
        gateway,
        row_token,
        gateway_base_url,
        instance_id,
        network_name,
    ):
        self.events.append(("context_fallback", row.slot_id))
        if row.slot_id in self.unstarted_context_failure_slots:
            raise RuntimeError("injected unstarted context failure")
        return self._row_context(
            row=row,
            row_token=row_token,
            gateway_base_url=gateway_base_url,
            instance_id=instance_id,
            network_name=network_name,
            setup_error="registered row context failed before target preparation",
        )

    @staticmethod
    def _row_context(
        *,
        row,
        row_token,
        gateway_base_url,
        instance_id,
        network_name,
        setup_error,
    ) -> RowExecutionContext:
        limits = ExternalExecutionLimits(10, 2, 3, "0.5")
        agent = ExternalAgentCommand(
            name="Ravage" if row.system == "ravage" else "Strix",
            system_id=row.system,
            command=("/fake/adapter", row.slot_id),
            artifact_path="flag-candidates.bin",
            limits=limits,
            reasoning_effort="high",
            provider="paired-row-gateway",
            model="gpt-test-2026-09-01",
            adapter_version="paired-description-only-black-box-v4",
            environment={
                COMPARISON_GATEWAY_TOKEN_ENV: row_token,
                "RAVAGE_COMPARISON_GATEWAY_BASE_URL": gateway_base_url,
                OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
            },
            environment_allowlist=(
                COMPARISON_GATEWAY_TOKEN_ENV,
                "RAVAGE_COMPARISON_GATEWAY_BASE_URL",
                OUTER_PROCESS_GROUP_ENV,
            ),
        )
        process = SimpleNamespace(receipt_contract=SimpleNamespace(row_id=row.slot_id))
        return RowExecutionContext(
            row=row,
            instance_id=instance_id,
            network_name=network_name,
            agent=agent,
            process_backend=process,
            setup_error=setup_error,
        )

    def create_agent_network(self, context):
        self.events.append(("network_create", context.row.slot_id))
        if context.row.slot_id in self.provisioning_failure_slots:
            raise RuntimeError("injected network provisioning failure")
        self.slot_by_instance[context.instance_id] = context.row.slot_id
        return AgentNetworkLease(
            instance_id=context.instance_id,
            name=context.network_name,
            network_id=hashlib.sha256(context.instance_id.encode()).hexdigest(),
        )

    def create_target_backend(self, *, plan, context, lease):
        return cast(
            "coordinator.DockerComparisonTargetBackend", SimpleNamespace(slot=context.row.slot_id)
        )

    def prepare_pair(self, *, case, expected_flag, pair_id, backend):
        pair_index = int(pair_id[-3:])
        self.events.append(("prepare", pair_index, case.benchmark_id, expected_flag))
        if pair_index in self.preparation_failure_pairs:
            raise RuntimeError("injected preparation failure")
        evidence = case.path.parents[1] / "execution" / "targets" / f"{pair_id}.prepared"
        evidence.mkdir(parents=True)
        (evidence / "prepared.json").write_text("prepared\n")
        return FakePrepared(pair_id, case.benchmark_id, evidence)

    def arm_target_backend(self, *, prepared, context, backend):
        self.prepared_by_slot[context.row.slot_id] = prepared
        return SimpleNamespace(prepared=prepared, system=context.row.system)

    def run_row(self, *, plan, context, case, expected_flag, target_backend):
        self.events.append(("run", context.row.slot_id, expected_flag, id(target_backend.prepared)))
        if context.row.slot_id in self.prelaunch_failure_slots:
            raise RuntimeError("injected prelaunch failure")
        self.flags_by_slot[context.row.slot_id] = expected_flag
        self.prepared_identity_by_slot[context.row.slot_id] = id(target_backend.prepared)
        result = self._terminal(
            plan,
            context,
            case,
            status="failed",
            target_succeeded=True,
        )
        if context.row.slot_id in self.postterminal_failure_slots:
            raise RuntimeError("injected exception after terminal row evidence")
        return result

    def record_unstarted(self, *, plan, context, case, expected_flag, reason):
        self.events.append(("unstarted", context.row.slot_id, expected_flag, reason))
        self.flags_by_slot[context.row.slot_id] = expected_flag
        if context.row.slot_id in self.unstarted_failure_slots:
            message = "injected unstarted evidence failure"
            raise RuntimeError(message)
        result = self._terminal(
            plan,
            context,
            case,
            status="infrastructure_error",
            target_succeeded=False,
        )
        if context.row.slot_id in self.postterminal_unstarted_failure_slots:
            raise RuntimeError("injected exception after unstarted terminal evidence")
        return result

    def release_pair(self, *, prepared, backend):
        pair_index = int(prepared.pair_id[-3:])
        pair_slots = {
            f"primary-{pair_index * 2 - 1:03d}",
            f"primary-{pair_index * 2:03d}",
        }
        attempted = set(self.prepared_identity_by_slot) | self.abandoned_slots
        assert pair_slots <= attempted
        self.events.append(("release", prepared.pair_id))
        (prepared.evidence_dir / "release.json").write_text("released\n")
        if pair_index in self.release_failure_pairs:
            raise RuntimeError("injected pair release failure")
        return {"valid": True}

    def terminalize_prepared_arm(self, *, prepared, context, backend):
        slot = context.row.slot_id
        if slot in self.prepared_identity_by_slot:
            self.events.append(("target_already_terminal", slot, prepared.pair_id))
            status = "already_terminal_via_target_lifecycle"
        else:
            assert slot not in self.abandoned_slots
            self.abandoned_slots.add(slot)
            self.events.append(("abandon", slot, prepared.pair_id))
            status = "abandoned_before_target_start"
        expected_flag = self.flags_by_slot[slot]
        return {
            "status": status,
            "pair_id": prepared.pair_id,
            "benchmark_id": prepared.benchmark_id,
            "arm": context.row.system,
            "instance_id": context.instance_id,
            "pair_flag_sha256": hashlib.sha256(expected_flag.encode()).hexdigest(),
            "row_terminal": True,
            "valid": True,
        }

    def remove_agent_network(self, lease):
        self.events.append(("network_remove", lease.instance_id))
        slot = self.slot_by_instance[lease.instance_id]
        if slot in self.network_remove_failure_slots:
            raise RuntimeError("injected network removal failure")

    def _terminal(self, plan, context, case, *, status, target_succeeded):
        slot = context.row.slot_id
        self.terminal_counts[slot] = self.terminal_counts.get(slot, 0) + 1
        assert self.terminal_counts[slot] == 1
        root = context.row.artifact_root / "row"
        root.mkdir()
        (root / "native-output").mkdir()
        for name in (
            "process-receipt.json",
            "model-gateway-receipt.json",
            "sandbox-profile.sb",
        ):
            (root / name).write_text(f"{slot}:{name}\n")
        if target_succeeded:
            prepared = self.prepared_by_slot[slot]
            build = {
                "status": "succeeded",
                "provenance": {
                    "pair_id": prepared.pair_id,
                    "prepared_provenance_path": str(prepared.evidence_dir / "prepared.json"),
                },
            }
            teardown = {"status": "succeeded"}
        else:
            build = {"status": "errored"}
            teardown = {"status": "not_started"}
        (root / "target-build.json").write_text(json.dumps(build, sort_keys=True) + "\n")
        (root / "target-teardown.json").write_text(json.dumps(teardown, sort_keys=True) + "\n")
        result = {
            "status": status,
            "schedule_binding": {"primary_slot_id": slot},
            "case": {"benchmark_id": case.benchmark_id},
            "agent": {"system_id": context.row.system},
        }
        (root / "row-result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
        (root / "artifacts.sha256").write_text("fake manifest\n")
        self.gateway.sealed.add(slot)
        self.events.append(("terminal", slot))
        return result


def _json_digest(payload: dict[str, object]) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _verify_with_report_oracle(plan: ResolvedCampaignPlan) -> dict[str, object]:
    schedule = [{"slot_id": row.slot_id, "case_id": row.case_id} for row in plan.schedule]
    rows = [{"completed_at": "2000-01-01T00:00:00+00:00"} for _ in plan.schedule]
    row_roots = {row.slot_id: row.artifact_root / "row" for row in plan.schedule}
    independent_rows: list[dict[str, object]] = []
    for row in plan.schedule:
        row_root = row_roots[row.slot_id]
        build = json.loads((row_root / "target-build.json").read_text())
        teardown = json.loads((row_root / "target-teardown.json").read_text())
        provenance = build.get("provenance")
        prepared_target = None
        if (
            build.get("status") == "succeeded"
            and teardown.get("status") == "succeeded"
            and isinstance(provenance, dict)
        ):
            prepared_target = {
                "pair_id": provenance["pair_id"],
                "prepared_path": provenance["prepared_provenance_path"],
            }
        independent_rows.append({"prepared_target": prepared_target})
    return paired_report._verify_primary_results_seal(  # noqa: SLF001
        plan.campaign_root,
        schedule=schedule,
        rows=rows,
        row_roots=row_roots,
        independent_rows=independent_rows,
        campaign_id=plan.campaign_id,
        commitment_digest=plan.commitment_digest,
        selection_digest=plan.selection_digest,
    )


def _entropy(size: int) -> str:
    _entropy.counter += 1
    return f"{_entropy.counter:0{size * 2}x}"[-size * 2 :]


_entropy.counter = 0


@pytest.fixture(autouse=True)
def _accept_test_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(coordinator, "validate_run_contract", lambda value: dict(value))
    _entropy.counter = 0


def test_full_matrix_is_preregistered_and_runs_once_in_exact_pair_order(tmp_path: Path) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime()

    result = execute_loaded_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        flag_hex=_entropy,
        instance_hex=_entropy,
    )

    register_events = [event for event in runtime.events if event[0] == "register"]
    assert [event[1] for event in register_events] == [f"primary-{i:03d}" for i in range(1, 41)]
    assert runtime.events.index(("gateway_start",)) > max(
        runtime.events.index(event) for event in register_events
    )
    first_row_event = next(
        index
        for index, event in enumerate(runtime.events)
        if event[0] in {"network_create", "prepare", "run", "unstarted"}
    )
    assert first_row_event > max(runtime.events.index(event) for event in register_events)
    terminal_order = [event[1] for event in runtime.events if event[0] == "terminal"]
    assert terminal_order == [f"primary-{i:03d}" for i in range(1, 41)]
    assert runtime.terminal_counts == {f"primary-{i:03d}": 1 for i in range(1, 41)}
    for offset in range(0, 40, 2):
        first = f"primary-{offset + 1:03d}"
        second = f"primary-{offset + 2:03d}"
        assert runtime.flags_by_slot[first] == runtime.flags_by_slot[second]
        assert runtime.prepared_identity_by_slot[first] == runtime.prepared_identity_by_slot[second]
    assert len(set(runtime.flags_by_slot.values())) == 20
    assert [event[1] for event in runtime.events if event[0] == "prepare"] == list(range(1, 21))
    assert len([event for event in runtime.events if event[0] == "network_create"]) == 40
    assert len([event for event in runtime.events if event[0] == "network_remove"]) == 40
    assert [event[1] for event in runtime.events if event[0] == "release"] == [
        f"pair-{index:03d}" for index in range(1, 21)
    ]
    for offset in range(0, 40, 2):
        first = f"primary-{offset + 1:03d}"
        second = f"primary-{offset + 2:03d}"
        first_terminal = runtime.events.index(("terminal", first))
        second_run = next(
            index
            for index, event in enumerate(runtime.events)
            if event[0] == "run" and event[1] == second
        )
        assert first_terminal < second_run
    assert result["mode"] == "paired_local"
    assert result["official_attestation_eligible"] is False

    seal = json.loads((tmp_path / "primary-results.json").read_text())
    assert seal["row_count"] == 40
    assert seal["all_terminal"] is True
    body = {key: value for key, value in seal.items() if key != "document_sha256"}
    assert seal["document_sha256"] == _json_digest(body)
    first_result = tmp_path / "attempts/primary/primary-001/artifacts/row/row-result.json"
    assert seal["rows"][0]["row_result_sha256"] == (
        "sha256:" + hashlib.sha256(first_result.read_bytes()).hexdigest()
    )
    first_prepared = tmp_path / "execution/targets/pair-001.prepared/prepared.json"
    first_release = tmp_path / "execution/targets/pair-001.prepared/release.json"
    assert seal["paired_targets"][0] == {
        "pair_index": 1,
        "case_id": "XBEN-001-24",
        "pair_id": "pair-001",
        "prepared_target_sha256": (
            "sha256:" + hashlib.sha256(first_prepared.read_bytes()).hexdigest()
        ),
        "release_sha256": ("sha256:" + hashlib.sha256(first_release.read_bytes()).hexdigest()),
    }
    assert (tmp_path / "campaign-model-gateway.json").is_file()
    gateway_path = tmp_path / "campaign-model-gateway.json"
    gateway_seal = json.loads(gateway_path.read_text())
    execution_terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert execution_terminal["model_gateway_document_sha256"] == gateway_seal["document_sha256"]
    assert execution_terminal["model_gateway_receipt_sha256"] == (
        "sha256:" + hashlib.sha256(gateway_path.read_bytes()).hexdigest()
    )
    assert execution_terminal["primary_results_sha256"] == (
        "sha256:" + hashlib.sha256((tmp_path / "primary-results.json").read_bytes()).hexdigest()
    )
    retained_evidence = b"".join(
        path.read_bytes() for path in sorted(tmp_path.rglob("*")) if path.is_file()
    )
    assert all(
        flag.encode() not in retained_evidence for flag in set(runtime.flags_by_slot.values())
    )
    assert _verify_with_report_oracle(plan)["verified"] is True

    with pytest.raises(CampaignAlreadyStartedError, match="resume is forbidden"):
        execute_loaded_campaign(
            plan,
            runtime=FakeRuntime(),
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )


def test_failures_terminalize_affected_rows_and_later_pairs_continue(tmp_path: Path) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(
        setup_failure_slots={"primary-011"},
        preparation_failure_pairs={2},
        prelaunch_failure_slots={"primary-007"},
    )

    execute_loaded_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        flag_hex=_entropy,
        instance_hex=_entropy,
    )

    assert runtime.terminal_counts == {f"primary-{i:03d}": 1 for i in range(1, 41)}
    unstarted = [event[1] for event in runtime.events if event[0] == "unstarted"]
    assert unstarted == [
        "primary-003",
        "primary-004",
        "primary-007",
        "primary-011",
        "primary-012",
    ]
    runs = [event[1] for event in runtime.events if event[0] == "run"]
    assert runs.count("primary-007") == 1
    assert runtime.abandoned_slots == {"primary-007"}
    assert "primary-040" in runs
    assert runtime.events.index(("gateway_close",)) < next(
        index for index, event in enumerate(runtime.events) if event[0] == "gateway_seal"
    )
    seal = json.loads((tmp_path / "primary-results.json").read_text())
    assert seal["paired_targets"][1] == {
        "pair_index": 2,
        "case_id": "XBEN-002-24",
        "pair_id": None,
        "prepared_target_sha256": None,
        "release_sha256": None,
    }
    assert seal["paired_targets"][3] == {
        "pair_index": 4,
        "case_id": "XBEN-004-24",
        "pair_id": None,
        "prepared_target_sha256": None,
        "release_sha256": None,
    }
    assert len(seal["rows"]) == 40
    assert _verify_with_report_oracle(plan)["verified"] is True


def test_thrown_or_invalid_row_context_uses_prevalidated_zero_launch_fallback(
    tmp_path: Path,
) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(
        context_failure_slots={"primary-001"},
        invalid_context_slots={"primary-003"},
    )

    result = execute_loaded_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        flag_hex=_entropy,
        instance_hex=_entropy,
    )

    assert result["rows_terminal"] == 40
    assert runtime.terminal_counts == {f"primary-{index:03d}": 1 for index in range(1, 41)}
    fallback_events = [event for event in runtime.events if event[0] == "context_fallback"]
    assert [event[1] for event in fallback_events] == [
        f"primary-{index:03d}" for index in range(1, 41)
    ]
    assert max(runtime.events.index(event) for event in fallback_events) < runtime.events.index(
        ("gateway_start",)
    )
    assert [event[1] for event in runtime.events if event[0] == "unstarted"][:4] == [
        "primary-001",
        "primary-002",
        "primary-003",
        "primary-004",
    ]
    runs = [event[1] for event in runtime.events if event[0] == "run"]
    assert not {"primary-001", "primary-002", "primary-003", "primary-004"} & set(runs)
    assert "primary-040" in runs
    assert _verify_with_report_oracle(plan)["verified"] is True


def test_unstarted_context_failure_permanently_poisoned_after_one_shot_claim(
    tmp_path: Path,
) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(
        unstarted_context_failure_slots={"primary-040"},
    )

    with pytest.raises(RuntimeError, match="injected unstarted context failure"):
        execute_loaded_campaign(
            plan,
            runtime=runtime,
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )

    assert [event[1] for event in runtime.events if event[0] == "register"] == [
        f"primary-{index:03d}" for index in range(1, 41)
    ]
    assert [event[1] for event in runtime.events if event[0] == "context_fallback"] == [
        f"primary-{index:03d}" for index in range(1, 41)
    ]
    assert ("gateway_start",) not in runtime.events
    assert runtime.events[-1] == ("gateway_close",)
    assert runtime.gateway.sealed == set()
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 0
    assert terminal["scheduler_pairs_reached"] == 0
    assert [error["stage"] for error in terminal["errors"]] == ["campaign_setup"]

    with pytest.raises(CampaignAlreadyStartedError, match="resume is forbidden"):
        execute_loaded_campaign(
            plan,
            runtime=FakeRuntime(),
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )


def test_exceptions_after_terminal_writes_are_recovered_without_second_receipt(
    tmp_path: Path,
) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(
        preparation_failure_pairs={2},
        postterminal_failure_slots={"primary-001"},
        postterminal_unstarted_failure_slots={"primary-003"},
    )

    result = execute_loaded_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        flag_hex=_entropy,
        instance_hex=_entropy,
    )

    assert result["rows_terminal"] == 40
    assert result["recorded_errors"] == 3
    assert runtime.terminal_counts == {f"primary-{index:03d}": 1 for index in range(1, 41)}
    assert runtime.gateway.sealed == {f"primary-{index:03d}" for index in range(1, 41)}
    assert [event for event in runtime.events if event[:2] == ("unstarted", "primary-001")] == []
    assert (
        len([event for event in runtime.events if event[:2] == ("unstarted", "primary-003")]) == 1
    )
    assert _verify_with_report_oracle(plan)["verified"] is True


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(RuntimeError("injected failure after claim"), id="exception"),
        pytest.param(KeyboardInterrupt(), id="interrupt"),
    ],
)
def test_postclaim_scheduler_failure_seals_every_registered_row_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime()

    def fail_start_document(
        _plan: object,
        *,
        execution_root: object,
        row_instances: object,
    ) -> None:
        del execution_root, row_instances
        raise failure

    monkeypatch.setattr(coordinator, "_write_execution_start", fail_start_document)
    with pytest.raises(CampaignCoordinatorError, match="did not close cleanly"):
        execute_loaded_campaign(
            plan,
            runtime=runtime,
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )

    assert runtime.terminal_counts == {f"primary-{index:03d}": 1 for index in range(1, 41)}
    assert runtime.gateway.sealed == {f"primary-{index:03d}" for index in range(1, 41)}
    assert [event[1] for event in runtime.events if event[0] == "terminal"] == [
        f"primary-{index:03d}" for index in range(1, 41)
    ]
    assert ("gateway_start",) not in runtime.events
    assert runtime.events[-1] == ("gateway_close",)
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["rows_terminal"] == 40
    assert terminal["complete"] is False
    assert terminal["scheduler_pairs_reached"] == 0
    assert not (tmp_path / "primary-results.json").exists()


def test_second_arm_provision_failure_terminalizes_pair_and_cleans_first_network(
    tmp_path: Path,
) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(provisioning_failure_slots={"primary-002"})

    result = execute_loaded_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        flag_hex=_entropy,
        instance_hex=_entropy,
    )

    assert result["rows_terminal"] == 40
    assert [event[1] for event in runtime.events if event[0] == "unstarted"][:2] == [
        "primary-001",
        "primary-002",
    ]
    removed_slots = [
        runtime.slot_by_instance[cast("str", event[1])]
        for event in runtime.events
        if event[0] == "network_remove"
    ]
    assert removed_slots.count("primary-001") == 1
    assert "primary-002" not in removed_slots
    assert "primary-040" in [event[1] for event in runtime.events if event[0] == "run"]
    assert _verify_with_report_oracle(plan)["verified"] is True


@pytest.mark.parametrize(
    ("failure_kind", "expected_stage"),
    [
        ("network", "agent_network_remove"),
        ("release", "pair_release"),
    ],
)
def test_cleanup_failure_is_terminal_but_cannot_produce_success_seals(
    tmp_path: Path,
    failure_kind: Literal["network", "release"],
    expected_stage: str,
) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(
        network_remove_failure_slots=({"primary-001"} if failure_kind == "network" else None),
        release_failure_pairs=({1} if failure_kind == "release" else None),
    )

    with pytest.raises(CampaignCoordinatorError, match="did not close cleanly"):
        execute_loaded_campaign(
            plan,
            runtime=runtime,
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )

    assert runtime.terminal_counts == {f"primary-{index:03d}": 1 for index in range(1, 41)}
    assert runtime.gateway.sealed == {f"primary-{index:03d}" for index in range(1, 41)}
    assert any(event[0] == "run" and event[1] == "primary-040" for event in runtime.events)
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 40
    assert any(error["stage"] == expected_stage for error in terminal["errors"])
    assert not (tmp_path / "campaign-model-gateway.json").exists()
    assert not (tmp_path / "primary-results.json").exists()

    with pytest.raises(CampaignAlreadyStartedError, match="resume is forbidden"):
        execute_loaded_campaign(
            plan,
            runtime=FakeRuntime(),
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )


def test_repeated_pair_entropy_permanently_poisoned_after_execution_is_claimed(
    tmp_path: Path,
) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime()

    def repeated_entropy(size: int) -> str:
        assert (tmp_path / "execution").is_dir()
        return "0" * (size * 2)

    with pytest.raises(CampaignCoordinatorError, match="repeated a pair nonce"):
        execute_loaded_campaign(
            plan,
            runtime=runtime,
            cases=cases,
            flag_hex=repeated_entropy,
            instance_hex=_entropy,
        )

    assert runtime.events == []
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 0
    assert [error["stage"] for error in terminal["errors"]] == ["campaign_setup"]

    with pytest.raises(CampaignAlreadyStartedError, match="resume is forbidden"):
        execute_loaded_campaign(
            plan,
            runtime=FakeRuntime(),
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )


def test_instance_entropy_and_gateway_hooks_cannot_run_before_admission(tmp_path: Path) -> None:
    plan, cases = _plan(tmp_path)

    def failing_instance_entropy(size: int) -> str:
        del size
        assert (tmp_path / "execution").is_dir()
        raise RuntimeError("injected instance entropy failure")

    with pytest.raises(RuntimeError, match="injected instance entropy failure"):
        execute_loaded_campaign(
            plan,
            runtime=FakeRuntime(),
            cases=cases,
            flag_hex=_entropy,
            instance_hex=failing_instance_entropy,
        )

    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 0
    assert [error["stage"] for error in terminal["errors"]] == ["campaign_setup"]

    second_plan, second_cases = _plan(tmp_path / "gateway")

    class FailingGatewayRuntime(FakeRuntime):
        def create_gateway(self, plan: ResolvedCampaignPlan) -> NoReturn:
            del plan
            assert (tmp_path / "gateway/execution").is_dir()
            self.events.append(("gateway_create",))
            raise RuntimeError("injected gateway creation failure")

    gateway_runtime = FailingGatewayRuntime()
    with pytest.raises(RuntimeError, match="injected gateway creation failure"):
        execute_loaded_campaign(
            second_plan,
            runtime=gateway_runtime,
            cases=second_cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )

    assert gateway_runtime.events == [("gateway_create",)]
    gateway_terminal = json.loads((tmp_path / "gateway/execution/terminal.json").read_text())
    assert gateway_terminal["complete"] is False
    assert gateway_terminal["rows_terminal"] == 0
    assert [error["stage"] for error in gateway_terminal["errors"]] == ["campaign_setup"]


def test_public_runtime_preflight_runs_only_after_irrevocable_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _cases = _plan(tmp_path)

    class FailingPreflightRuntime(FakeRuntime):
        def validate_plan(self, plan: ResolvedCampaignPlan) -> NoReturn:
            del plan
            assert (tmp_path / "execution").is_dir()
            self.events.append(("validate",))
            raise RuntimeError("injected runtime preflight failure")

    runtime = FailingPreflightRuntime()
    monkeypatch.setattr(coordinator, "load_verified_execution_plan", lambda _path: plan)

    with pytest.raises(RuntimeError, match="injected runtime preflight failure"):
        coordinator.execute_paired_campaign(tmp_path, runtime=runtime)

    assert runtime.events == [("validate",)]
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 0
    assert [error["stage"] for error in terminal["errors"]] == ["runtime_preflight"]

    with pytest.raises(CampaignAlreadyStartedError, match="resume is forbidden"):
        coordinator.execute_paired_campaign(tmp_path, runtime=FakeRuntime())


def test_config_and_provider_credential_lookup_follow_irrevocable_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _cases = _plan(tmp_path)
    observed: list[str] = []

    def load_configuration(_path: Path) -> SimpleNamespace:
        assert (tmp_path / "execution").is_dir()
        observed.append("config")
        return SimpleNamespace(upstream_api_key_environment="PAIRED_TEST_API_KEY")

    original_environment_get = os.environ.get

    def credential_get(name: str, default: str = "") -> str | None:
        if name == "PAIRED_TEST_API_KEY":
            assert (tmp_path / "execution").is_dir()
            observed.append("credential")
            return ""
        return original_environment_get(name, default)

    monkeypatch.setattr(coordinator, "load_verified_execution_plan", lambda _path: plan)
    monkeypatch.setattr(coordinator, "load_executor_configuration", load_configuration)
    monkeypatch.setattr(os.environ, "get", credential_get)

    with pytest.raises(CampaignCoordinatorError, match="credential environment"):
        coordinator.execute_paired_campaign_from_config(
            tmp_path,
            executor_config_path=tmp_path / "executor.json",
        )

    assert observed == ["config", "credential"]
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 0
    assert [error["stage"] for error in terminal["errors"]] == ["runtime_preflight"]


def test_internal_error_messages_cannot_retain_the_pair_flag(tmp_path: Path) -> None:
    plan, cases = _plan(tmp_path)

    class LeakyFailureRuntime(FakeRuntime):
        def prepare_pair(self, *, case, expected_flag, pair_id, backend):
            if pair_id == "pair-001":
                message = f"injected leak: {expected_flag}"
                raise RuntimeError(message)
            return super().prepare_pair(
                case=case,
                expected_flag=expected_flag,
                pair_id=pair_id,
                backend=backend,
            )

    runtime = LeakyFailureRuntime()
    execute_loaded_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        flag_hex=_entropy,
        instance_hex=_entropy,
    )

    terminal_text = (tmp_path / "execution/terminal.json").read_text()
    first_pair_flag = next(
        event[2]
        for event in runtime.events
        if event[0] == "unstarted" and event[1] == "primary-001"
    )
    assert first_pair_flag not in terminal_text
    assert "injected leak: [REDACTED]" in terminal_text


def test_gateway_close_failure_blocks_primary_seals_and_success_claim(tmp_path: Path) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(gateway_close_failure=True)

    with pytest.raises(CampaignCoordinatorError, match="did not close cleanly"):
        execute_loaded_campaign(
            plan,
            runtime=runtime,
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )

    assert not (tmp_path / "campaign-model-gateway.json").exists()
    assert not (tmp_path / "primary-results.json").exists()
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 40
    assert terminal["pairs_terminal"] == 20
    assert all(event[0] != "gateway_seal" for event in runtime.events)


def test_gateway_url_failure_terminalizes_all_rows_without_target_work(tmp_path: Path) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(gateway_base_url_failure=True)

    result = execute_loaded_campaign(
        plan,
        runtime=runtime,
        cases=cases,
        flag_hex=_entropy,
        instance_hex=_entropy,
    )

    assert result["rows_terminal"] == 40
    assert runtime.terminal_counts == {f"primary-{index:03d}": 1 for index in range(1, 41)}
    assert not any(event[0] == "network_create" for event in runtime.events)
    assert not any(event[0] == "run" for event in runtime.events)
    assert [event[1] for event in runtime.events if event[0] == "unstarted"] == [
        f"primary-{index:03d}" for index in range(1, 41)
    ]
    assert _verify_with_report_oracle(plan)["verified"] is True


def test_duplicate_gateway_tokens_permanently_poison_after_one_shot_claim(tmp_path: Path) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(duplicate_gateway_tokens=True)

    with pytest.raises(CampaignCoordinatorError, match="repeated a row token"):
        execute_loaded_campaign(
            plan,
            runtime=runtime,
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )

    assert runtime.events[-1] == ("gateway_close",)
    assert [event[1] for event in runtime.events if event[0] == "register"] == [
        "primary-001",
        "primary-002",
    ]
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 0
    assert [error["stage"] for error in terminal["errors"]] == ["campaign_setup"]

    with pytest.raises(CampaignAlreadyStartedError, match="resume is forbidden"):
        execute_loaded_campaign(
            plan,
            runtime=FakeRuntime(),
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )


def test_unstarted_receipt_failure_still_releases_pair_and_runs_later_slots(
    tmp_path: Path,
) -> None:
    plan, cases = _plan(tmp_path)
    runtime = FakeRuntime(
        prelaunch_failure_slots={"primary-001"},
        unstarted_failure_slots={"primary-001"},
    )

    with pytest.raises(CampaignCoordinatorError, match="did not close cleanly"):
        execute_loaded_campaign(
            plan,
            runtime=runtime,
            cases=cases,
            flag_hex=_entropy,
            instance_hex=_entropy,
        )

    assert "primary-001" in runtime.abandoned_slots
    assert ("release", "pair-001") in runtime.events
    assert any(event[0] == "run" and event[1] == "primary-040" for event in runtime.events)
    terminal = json.loads((tmp_path / "execution/terminal.json").read_text())
    assert terminal["complete"] is False
    assert terminal["rows_terminal"] == 39
    assert not (tmp_path / "campaign-model-gateway.json").exists()
    assert not (tmp_path / "primary-results.json").exists()


def test_agent_network_uses_exact_labels_id_and_verified_removal(tmp_path: Path) -> None:
    network_id = "a" * 64
    instance_id = "xben-row-" + "b" * 32
    name = "ravage-agent-" + "b" * 32
    payload = json.dumps(
        [
            {
                "Id": network_id,
                "Name": name,
                "Internal": True,
                "Labels": {
                    "com.ravage.evaluator.agent-network": "true",
                    "com.ravage.evaluator.instance": instance_id,
                },
                "Containers": {},
            }
        ]
    ).encode()

    class QueueRunner:
        def __init__(self) -> None:
            self.responses = [
                coordinator.CommandResult(("docker",), 0, stdout=f"{network_id}\n".encode()),
                coordinator.CommandResult(("docker",), 0, stdout=payload),
                coordinator.CommandResult(("docker",), 0, stdout=payload),
                coordinator.CommandResult(("docker",), 0),
                coordinator.CommandResult(("docker",), 0),
            ]
            self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def run(self, command, *, cwd, environment, timeout_seconds):
            self.calls.append((tuple(command), dict(environment)))
            return self.responses.pop(0)

    docker = tmp_path / "docker"
    docker.touch()
    socket_path = tmp_path / "docker.sock"
    socket_path.touch()
    runner = QueueRunner()
    manager = DockerAgentNetworkManager(
        docker_executable=docker,
        docker_socket=socket_path,
        trusted_path="/usr/bin:/bin",
        timeout_seconds=5,
        runner=runner,
    )

    lease = manager.create(instance_id=instance_id, name=name)
    manager.remove(lease)

    create = runner.calls[0][0]
    assert create[-5:] == (
        "--label",
        "com.ravage.evaluator.agent-network=true",
        "--label",
        f"com.ravage.evaluator.instance={instance_id}",
        name,
    )
    assert runner.calls[1][0][-1] == network_id
    assert runner.calls[3][0][-1] == network_id
    assert runner.calls[4][0][-1] == f"id={network_id}"
    assert all(
        environment["DOCKER_HOST"] == f"unix://{socket_path}" for _, environment in runner.calls
    )


def test_agent_network_daemon_error_is_not_treated_as_verified_absence(tmp_path: Path) -> None:
    network_id = "c" * 64
    instance_id = "xben-row-" + "d" * 32
    name = "ravage-agent-" + "d" * 32

    class QueueRunner:
        def __init__(self) -> None:
            self.responses = [
                coordinator.CommandResult(("docker",), 0, stdout=f"{network_id}\n".encode()),
                coordinator.CommandResult(("docker",), 1, stderr=b"daemon unavailable"),
                coordinator.CommandResult(("docker",), 0),
                coordinator.CommandResult(("docker",), 1, stderr=b"daemon unavailable"),
            ]
            self.calls: list[tuple[str, ...]] = []

        def run(self, command, *, cwd, environment, timeout_seconds):
            self.calls.append(tuple(command))
            return self.responses.pop(0)

    docker = tmp_path / "docker"
    docker.touch()
    socket_path = tmp_path / "docker.sock"
    socket_path.touch()
    runner = QueueRunner()
    manager = DockerAgentNetworkManager(
        docker_executable=docker,
        docker_socket=socket_path,
        trusted_path="/usr/bin:/bin",
        timeout_seconds=5,
        runner=runner,
    )

    with pytest.raises(CampaignCoordinatorError, match="absence was not verified"):
        manager.create(instance_id=instance_id, name=name)

    assert runner.calls[2][-1] == network_id
    assert runner.calls[3][-1] == f"id={network_id}"


def test_shared_target_agent_docker_authority_is_rejected(tmp_path: Path) -> None:
    docker_socket = tmp_path / "docker.sock"
    docker_socket.touch()
    socket_alias = tmp_path / "docker-alias.sock"
    socket_alias.symlink_to(docker_socket)

    with pytest.raises(CampaignCoordinatorError, match="share Docker authority"):
        coordinator._require_distinct_docker_authorities(
            target_socket=docker_socket,
            agent_socket=socket_alias,
        )


def test_distinct_target_agent_docker_authorities_are_accepted(tmp_path: Path) -> None:
    target_socket = tmp_path / "target.sock"
    target_socket.touch()
    agent_socket = tmp_path / "agent.sock"
    agent_socket.touch()

    coordinator._require_distinct_docker_authorities(
        target_socket=target_socket,
        agent_socket=agent_socket,
    )


def test_execute_cli_routes_only_campaign_and_nonsecret_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    campaign = tmp_path / "campaign"
    configuration = tmp_path / "executor.json"
    captured: dict[str, Path] = {}

    def fake_execute(campaign_dir: Path, *, executor_config_path: Path) -> dict[str, object]:
        captured["campaign"] = campaign_dir
        captured["configuration"] = executor_config_path
        return {
            "mode": "paired_local",
            "official_attestation_eligible": False,
            "rows_terminal": 40,
        }

    monkeypatch.setattr(paired_cli, "execute_paired_campaign_from_config", fake_execute)
    result = paired_cli.main(
        [
            "execute",
            "--campaign-dir",
            str(campaign),
            "--executor-config",
            str(configuration),
        ]
    )

    assert result == 0
    assert captured == {"campaign": campaign, "configuration": configuration}
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "paired_local"
    assert output["official_attestation_eligible"] is False
