# ruff: noqa: PLR2004
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import localcontext
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from ravage.xben_parts.comparison_contracts import ExternalExecutionLimits

from tools.paired_xben import report

if TYPE_CHECKING:
    from collections.abc import Mapping

CAMPAIGN = "paired-campaign"
COMMITMENT = "sha256:" + "a" * 64
SELECTION = "sha256:" + "b" * 64


def test_report_limits_preserve_exact_money_under_low_decimal_precision() -> None:
    amount = "1.123456789012345678901234567890123456789"
    limits = ExternalExecutionLimits(600, 40, 500, amount)
    with localcontext() as context:
        context.prec = 6
        assert report._row_limits_json(limits.to_json()) == limits.to_json()
        assert report._money(amount, "row cost cap") == amount
    with pytest.raises(report.EvidenceIntegrityError, match="canonical"):
        report._money(1.0, "row cost cap")


def _run_contract() -> dict[str, object]:
    adapter_source = "sha256:" + "6" * 64
    policy = {
        "schema_version": "ravage.xben.model-gateway-policy.v1",
        "upstream": "https://api.openai.com/v1/chat/completions",
        "model": "gpt-test-2026-09-01",
        "reasoning_effort": "high",
        "pricing_usd_per_million_tokens": {
            "input_per_million": "2",
            "cached_input_per_million": "0.5",
            "output_per_million": "8",
        },
        "campaign_max_cost_usd": "200",
        "max_completion_tokens_per_request": 8192,
        "max_request_body_bytes": 1048576,
        "max_upstream_response_bytes": 8388608,
        "upstream_timeout_seconds": 120,
        "max_parallel_requests": 1,
        "input_token_reservation": {
            "algorithm": "utf8_body_bytes_plus_fixed_overhead",
            "fixed_overhead_tokens": 4096,
            "cached_discount_assumed": False,
        },
        "retry_policy": "gateway_never_retries",
        "unknown_usage_policy": "charge_full_reservation_and_invalidate_row",
    }
    policy_bytes = json.dumps(
        policy,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    evaluator_paths = (
        "tools/paired_xben/protocol.py",
        "tools/paired_xben/report.py",
        "tools/paired_xben/authenticity.py",
        "tools/paired_xben/preflight.py",
        "tools/paired_xben/cli.py",
        "tools/paired_xben/coordinator.py",
        "tools/paired_xben/public_ledger.py",
        "tools/paired_xben/github_runner.py",
        "tools/paired_xben/github_execution_gate.py",
        "tools/paired_xben/github_execution_start.py",
        "tools/paired_xben/images/target-gateway.Dockerfile",
        ".github/workflows/paired-xben-intake.yml",
        ".github/workflows/paired-xben.yml",
        ".github/workflows/paired-xben-execution.yml",
        ".github/workflows/paired-xben-helper-image.yml",
        "scripts/eval/run_paired_xben_protocol.py",
        "packages/ravage/src/ravage/xben_parts/external_comparison.py",
        "packages/ravage/src/ravage/xben_parts/comparison_adapters.py",
        "packages/ravage/src/ravage/xben_parts/comparison_agent_vm.py",
        "packages/ravage/src/ravage/xben_parts/comparison_model_gateway.py",
        "packages/ravage/src/ravage/xben_parts/comparison_target.py",
        "packages/ravage/src/ravage/xben_parts/comparison_process_backend.py",
        "packages/ravage/src/ravage/xben_parts/http_meter_gateway.py",
    )
    return {
        "schema_version": "ravage.paired-xben.run-contract.v2",
        "mode": "description-only-black-box",
        "objective": "capture_flag",
        "sources": {
            "ravage": {
                "commit_sha": "a" * 40,
                "tree_object": "4" * 40,
                "tree_path": ".",
                "origin_url": "https://github.com/example/ravage.git",
                "dirty": False,
            },
            "strix": {
                "commit_sha": "b" * 40,
                "tree_object": "7" * 40,
                "tree_path": ".",
                "origin_url": "https://github.com/usestrix/strix.git",
                "dirty": False,
            },
            "xben": {
                "commit_sha": "c" * 40,
                "tree_object": "7" * 40,
                "tree_path": "benchmarks",
                "origin_url": ("https://github.com/xbow-engineering/validation-benchmarks.git"),
                "dirty": False,
            },
        },
        "compatibility_catalog": {
            "schema_version": "ravage.paired-xben.compatibility-catalog.v1",
            "sha256": "sha256:" + "1" * 64,
        },
        "adapter": {
            "schema_version": "ravage.xben.comparison-adapter.v4",
            "adapter_version": "paired-description-only-black-box-v4",
            "source_sha256": adapter_source,
        },
        "runtime_manifests": {
            system: {
                "schema_version": "ravage.xben.runtime-environment.v1",
                "sha256": "sha256:" + digit * 64,
                "executable_sha256": "sha256:" + "5" * 64,
                "interpreter_sha256": "sha256:" + "6" * 64,
                "lockfile_sha256": "sha256:" + "7" * 64,
                "distribution_inventory_sha256": "sha256:" + "8" * 64,
                "site_packages_tree_sha256": "sha256:" + "9" * 64,
            }
            for system, digit in (("ravage", "2"), ("strix", "3"))
        },
        "model_gateway": {
            "row_receipt_schema_version": "ravage.xben.model-gateway-receipt.v1",
            "campaign_receipt_schema_version": ("ravage.xben.model-gateway-campaign-receipt.v1"),
            "provider": "openai",
            "agent_provider": "paired-row-gateway",
            "service_tier": "default",
            "store": False,
            "policy": policy,
            "policy_sha256": "sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
            "pricing_source": {
                "kind": "openai_model_page_markdown",
                "url": "https://developers.openai.com/api/docs/models/gpt-test.md",
                "published_on": None,
                "retrieved_at": "2026-09-01T00:00:00+00:00",
                "artifact_sha256": "sha256:" + "0" * 64,
            },
        },
        "budgets": {
            "campaign": {
                "wall_seconds": 24000,
                "max_model_requests": 1600,
                "max_target_requests": 20000,
                "max_cost_usd": "200",
            },
            "per_row": {
                "wall_seconds": 600,
                "max_model_requests": 40,
                "max_target_requests": 500,
                "max_cost_usd": "5",
            },
        },
        "evaluator_components": {
            path: (
                adapter_source if path.endswith("comparison_adapters.py") else "sha256:" + "4" * 64
            )
            for path in evaluator_paths
        },
        "execution_policy": {
            "platform": "linux/amd64",
            "model_gateway_endpoint_mode": "host_loopback_row_token",
            "process_group_policy": "joined_evaluator_outer_group",
            "outer_process_group_environment": "joined_evaluator_group_v1",
            "evaluator_host": {
                "platform": "darwin",
                "containment_backend": "sandbox-exec",
                "sandbox_executable_path": "/usr/bin/sandbox-exec",
                "sandbox_executable_sha256": "sha256:" + "a" * 64,
                "systems": {
                    system: {
                        "evidence_class": "strict_official",
                        "runtime_read_roots_sha256": "sha256:" + digit * 64,
                        "runtime_read_root_count": 2,
                        "docker_socket_access": False,
                        "docker_socket_path_sha256": None,
                        "docker_host_sha256": None,
                    }
                    for system, digit in (("ravage", "b"), ("strix", "c"))
                },
            },
            "target_endpoint_modes": {
                "ravage": "host_loopback",
                "strix": "docker_alias",
            },
            "flag_scope": "fresh_random_256bit_flag_per_case_pair",
            "flag_disclosure": "withheld_until_both_arms_terminal",
            "build_once_per_case_pair": True,
            "same_prepared_image_ids_for_both_arms": True,
            "fresh_project_per_arm": True,
            "fresh_containers_per_arm": True,
            "fresh_volumes_per_arm": True,
            "runtime_build_allowed": False,
            "runtime_pull_allowed": False,
            "target_build_input_boundary": {
                "pinned_source_and_compatibility_catalog": True,
                "explicit_privileged_or_remote_compose_build_features_forbidden": True,
                "preparation_registry_and_default_build_network_available": True,
                "external_base_references_may_be_mutable": True,
                "post_resolution_local_image_ids_frozen": True,
                "hermetic_rebuild_claimed": False,
            },
        },
        "oci_images": {
            role: f"registry.example.invalid/{role}@sha256:{digit * 64}"
            for role, digit in (
                ("ravage_tool", "a"),
                ("strix_sandbox", "b"),
                ("target_gateway", "c"),
                ("target_probe", "d"),
            )
        },
        "target_helper_image_ids": {
            "target_gateway": "sha256:" + "e" * 64,
            "target_probe": "sha256:" + "f" * 64,
        },
        "preflight_digest": "sha256:" + "e" * 64,
    }


def _campaign(tmp_path: Path, outcomes: list[tuple[bool, bool]]) -> Path:
    root = tmp_path / "campaign"
    primary = root / "attempts" / "primary"
    (root / "resolution").mkdir(parents=True)
    schedule: list[dict[str, object]] = []
    slot = 0
    for pair_index in range(1, 21):
        case_id = f"XBEN-{pair_index:03d}-24"
        for within_pair, system in enumerate(("ravage", "strix"), start=1):
            slot += 1
            slot_id = f"primary-{slot:03d}"
            scheduled = {
                "slot": slot,
                "slot_id": slot_id,
                "pair_index": pair_index,
                "position_within_pair": within_pair,
                "case_id": case_id,
                "system": system,
                "purpose": "primary",
                "score_eligible": True,
            }
            schedule.append(scheduled)
            attempt_root = primary / slot_id
            row_root = attempt_root / "artifacts" / "row"
            row_root.mkdir(parents=True)
            attempt = {
                "campaign_id": CAMPAIGN,
                "commitment_digest": COMMITMENT,
                "selection_digest": SELECTION,
                "attempt_id": slot_id,
                "purpose": "primary",
                "score_eligible": True,
                "primary_slot_id": slot_id,
                "case_id": case_id,
                "system": system,
                "pair_index": pair_index,
                "position_within_pair": within_pair,
                "parent_primary_slot_id": None,
                "artifact_directory": "artifacts",
            }
            (attempt_root / "attempt.json").write_text(json.dumps(attempt), encoding="utf-8")
            solved = outcomes[pair_index - 1][0 if system == "ravage" else 1]
            expected_flag = f"flag{{ravage_cmp_{pair_index:064x}}}"
            expected_flag_sha256 = hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
            description = f"Assess the exposed web application for pair {pair_index}."
            description_sha256 = hashlib.sha256(description.encode()).hexdigest()
            created_at = datetime(2026, 9, 11, 1, tzinfo=UTC) + timedelta(seconds=(slot - 1) * 2)
            completed_at = created_at + timedelta(seconds=1)
            flag_commitment = {
                "schema_version": report.FLAG_COMMITMENT_SCHEMA,
                "created_at": (created_at - timedelta(seconds=1)).isoformat(),
                "schedule_binding": {
                    "campaign_id": CAMPAIGN,
                    "commitment_digest": COMMITMENT,
                    "selection_digest": SELECTION,
                    "primary_slot_id": slot_id,
                },
                "instance_id": f"xben-row-{slot:032x}",
                "algorithm": "sha256-utf8",
                "expected_flag_sha256": expected_flag_sha256,
                "scope": "pair",
            }
            (row_root / report.FLAG_COMMITMENT_FILE).write_text(
                json.dumps(flag_commitment), encoding="utf-8"
            )
            row = {
                "schema_version": report.ROW_RESULT_SCHEMA,
                "created_at": created_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "elapsed_seconds": 1.0,
                "status": "solved" if solved else "failed",
                "valid_for_comparison": True,
                "valid_for_paired_local_comparison": False,
                "official_attestation_eligible": True,
                "case": {
                    "benchmark_id": case_id,
                    "description_sha256": description_sha256,
                },
                "agent": {
                    "name": system.title(),
                    "system_id": system,
                    "provider": "paired-row-gateway",
                    "model": "gpt-test-2026-09-01",
                    "reasoning_effort": "high",
                    "adapter_version": "paired-description-only-black-box-v4",
                    "command_sha256": "d" * 64,
                    "environment_names": [
                        "RAVAGE_COMPARISON_GATEWAY_BASE_URL",
                        "RAVAGE_COMPARISON_GATEWAY_TOKEN",
                        "RAVAGE_COMPARISON_OUTER_PROCESS_GROUP",
                    ],
                },
                "schedule_binding": {
                    "campaign_id": CAMPAIGN,
                    "commitment_digest": COMMITMENT,
                    "selection_digest": SELECTION,
                    "primary_slot_id": slot_id,
                },
                "isolation": {
                    "kind": "docker-network-isolated",
                    "filesystem_isolated": True,
                    "target_network_only": True,
                    "inherits_parent_environment": False,
                    "black_box_safe": True,
                    "budget_enforcement": {
                        "wall_timeout": True,
                        "model_requests": True,
                        "target_requests": True,
                        "cost": True,
                        "all_required": True,
                    },
                    "comparison_safe": True,
                },
                "target": {
                    "instance_id": f"xben-row-{slot:032x}",
                    "target_url": "http://target.internal:8080",
                    "build_provenance_path": "target-build.json",
                    "teardown_provenance_path": "target-teardown.json",
                },
                "limits": {
                    "wall_seconds": 600,
                    "max_model_requests": 40,
                    "max_target_requests": 500,
                    "max_cost_usd": "5",
                },
                "policy": {
                    "attempt": 1,
                    "retry_allowed": False,
                    "replacement_allowed": False,
                    "fresh_target_per_row": True,
                    "pair_scoped_flag": True,
                },
                "execution": {
                    "status": "completed",
                    "returncode": 0,
                    "timeout_seconds": 600,
                    "started_at": created_at.isoformat(),
                    "completed_at": completed_at.isoformat(),
                    "error": None,
                    "stdout_path": "stdout.log",
                    "stderr_path": "stderr.log",
                    "stdout_capture": _empty_capture(),
                    "stderr_capture": _empty_capture(),
                    "receipts": {
                        "valid": True,
                        "official_attestation_eligible": True,
                        "evidence_class": "strict_official",
                    },
                },
                "score": {
                    "mode": "committed_flag_candidate_sha256",
                    "max_artifact_bytes": 64 * 1024 * 1024,
                    "expected_flag_sha256": expected_flag_sha256,
                    "exact_match": solved,
                    "solved": solved,
                    "artifact": {
                        "path": "answer.txt",
                        "status": "scored",
                        "sha256": None,
                        "size_bytes": None,
                        "exact_match": solved,
                    },
                },
            }
            native_output = row_root / "native-output"
            native_output.mkdir()
            artifact_bytes = expected_flag.encode("utf-8") if solved else b"no matching proof\n"
            (native_output / "answer.txt").write_bytes(artifact_bytes)
            row["score"]["artifact"]["sha256"] = hashlib.sha256(artifact_bytes).hexdigest()
            row["score"]["artifact"]["size_bytes"] = len(artifact_bytes)
            row_bytes = (json.dumps(row, sort_keys=True) + "\n").encode()
            (row_root / "row-result.json").write_bytes(row_bytes)
            (row_root / "stdout.log").write_bytes(b"")
            (row_root / "stderr.log").write_bytes(b"")
            (row_root / "target-build.json").write_text(
                json.dumps(
                    {
                        "status": "succeeded",
                        "instance_id": f"xben-row-{slot:032x}",
                        "provenance": {"fresh": True},
                    }
                ),
                encoding="utf-8",
            )
            (row_root / "target-teardown.json").write_text(
                json.dumps(
                    {
                        "status": "succeeded",
                        "instance_id": f"xben-row-{slot:032x}",
                        "provenance": {"removed": True},
                    }
                ),
                encoding="utf-8",
            )
            _rewrite_manifest(row_root)
    selection = {
        "campaign_id": CAMPAIGN,
        "commitment_digest": COMMITMENT,
        "document_digest": SELECTION,
        "selected_case_ids": [f"XBEN-{index:03d}-24" for index in range(1, 21)],
        "schedule": schedule,
    }
    (root / "resolution" / "selection.json").write_text(json.dumps(selection), encoding="utf-8")
    commitment = {
        "campaign_id": CAMPAIGN,
        "document_digest": COMMITMENT,
        "run_contract": _run_contract(),
    }
    (root / "commitment.json").write_text(json.dumps(commitment), encoding="utf-8")
    return root


def _verified(_root: Path, *, require_all_primary_attempts: bool) -> dict[str, object]:
    assert require_all_primary_attempts is True
    return {
        "phase": "resolved",
        "structurally_valid": True,
        "selection_digest": SELECTION,
        "beacon_authenticity_verified": False,
        "publication_anchor_verified": False,
        "canonical_namespace_first_entry_verified": False,
        "diagnostic_reruns": 0,
    }


def _unverified_independent_row(
    _result: Mapping[str, object],
    *,
    scheduled: Mapping[str, object],
    row_root: Path,
    campaign_root: Path,
    run_contract: Mapping[str, object],
) -> dict[str, object]:
    assert row_root.is_dir()
    assert campaign_root.is_dir()
    assert run_contract["schema_version"] == "ravage.paired-xben.run-contract.v2"
    return {
        "slot_id": scheduled["slot_id"],
        "adapter_verified": False,
        "model_gateway_verified": False,
        "process_verified": False,
        "target_verified": False,
        "official_attestation_eligible": False,
        "prepared_target": None,
    }


def _verified_independent_row(
    result: Mapping[str, object],
    *,
    scheduled: Mapping[str, object],
    row_root: Path,
    campaign_root: Path,
    run_contract: Mapping[str, object],
) -> dict[str, object]:
    evidence = _unverified_independent_row(
        result,
        scheduled=scheduled,
        row_root=row_root,
        campaign_root=campaign_root,
        run_contract=run_contract,
    )
    evidence.update(
        {
            "adapter_verified": True,
            "model_gateway_verified": True,
            "process_verified": True,
            "target_verified": True,
            "official_attestation_eligible": (result.get("official_attestation_eligible") is True),
        }
    )
    return evidence


def _stub_report_verifiers(
    monkeypatch: pytest.MonkeyPatch,
    *,
    independent_rows_verified: bool = False,
) -> None:
    monkeypatch.setattr(report, "verify_campaign", _verified)
    monkeypatch.setattr(
        report,
        "_verify_independent_row_evidence",
        _verified_independent_row if independent_rows_verified else _unverified_independent_row,
    )


def _rewrite_result(path: Path, payload: Mapping[str, object]) -> None:
    changed = (json.dumps(payload, sort_keys=True) + "\n").encode()
    path.write_bytes(changed)
    _rewrite_manifest(path.parent)


def _empty_capture() -> dict[str, object]:
    return {
        "raw_sha256": hashlib.sha256(b"").hexdigest(),
        "raw_size_bytes": 0,
        "retained_size_bytes": 0,
        "redacted": False,
        "truncated": False,
        "max_retained_bytes": 1024 * 1024,
    }


def _rewrite_manifest(row_root: Path) -> None:
    manifest = row_root / "artifacts.sha256"
    rows = []
    for path in sorted(candidate for candidate in row_root.rglob("*") if candidate.is_file()):
        if path == manifest:
            continue
        rows.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(row_root)}"
        )
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_complete_report_has_paired_statistics_and_honest_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes = [(True, True)] * 8 + [(True, False)] * 4 + [(False, True)] * 2
    outcomes += [(False, False)] * 6
    root = _campaign(tmp_path, outcomes)
    _stub_report_verifiers(monkeypatch, independent_rows_verified=True)

    result = report.aggregate_campaign(root, generated_at="2026-09-11T02:00:00+00:00")

    assert result["evidence_classification"]["sota_claim_supported"] is False
    assert result["evidence_classification"]["raw_agent_output_publication_safe"] is False
    assert result["claim_ready"] is False
    assert result["results"] == {
        "available": False,
        "withheld": True,
        "reasons": [
            "drand_bls_authenticity_unverified",
            "predraw_publication_timestamp_unverified",
            "canonical_public_namespace_unverified",
            "public_execution_attestation_unverified",
            "primary_results_seal_unverified",
            "campaign_model_seal_unverified",
            "paired_target_reuse_unverified",
            "evaluator_component_sources_unverified",
            "execution_receipts_unverified",
            "raw_agent_output_publication_safety_unverified",
        ],
    }
    paired = result["diagnostics"]["unverified_paired_results"]
    assert result["diagnostics"]["not_for_comparison_claims"] is True
    assert paired["systems"]["ravage"]["solved"] == 12
    assert paired["systems"]["strix"]["solved"] == 10
    assert paired["paired_contingency"] == {
        "both_solved": 8,
        "ravage_only": 4,
        "strix_only": 2,
        "neither_solved": 6,
    }
    assert paired["solve_rate_delta_ravage_minus_strix"] == pytest.approx(0.1)
    assert paired["exact_two_sided_sign_mcnemar_p_value"] == pytest.approx(0.6875)
    assert result["elapsed_seconds"]["total"] == 40.0
    assert result["cost_usd"]["available"] is False


def test_missing_duplicate_and_unbound_evidence_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)

    missing = _campaign(tmp_path / "missing", [(False, False)] * 20)
    (missing / "attempts/primary/primary-001/artifacts/row/row-result.json").unlink()
    with pytest.raises(report.IncompleteCampaignError, match="no terminal"):
        report.aggregate_campaign(missing)

    duplicate = _campaign(tmp_path / "duplicate", [(False, False)] * 20)
    source = duplicate / "attempts/primary/primary-001/artifacts/row/row-result.json"
    other = duplicate / "attempts/primary/primary-001/artifacts/other"
    other.mkdir()
    (other / "row-result.json").write_bytes(source.read_bytes())
    with pytest.raises(report.EvidenceIntegrityError, match="duplicate row results"):
        report.aggregate_campaign(duplicate)

    unbound = _campaign(tmp_path / "unbound", [(False, False)] * 20)
    result_path = unbound / "attempts/primary/primary-001/artifacts/row/row-result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    del payload["schedule_binding"]
    changed = (json.dumps(payload, sort_keys=True) + "\n").encode()
    result_path.write_bytes(changed)
    _rewrite_manifest(result_path.parent)
    with pytest.raises(report.EvidenceIntegrityError, match="unsupported result schema"):
        report.aggregate_campaign(unbound)


def test_verified_reruns_are_reported_but_never_scored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _campaign(tmp_path, [(False, False)] * 20)
    _stub_report_verifiers(monkeypatch)

    def verified_with_rerun(path: Path, *, require_all_primary_attempts: bool) -> dict[str, object]:
        payload = _verified(path, require_all_primary_attempts=require_all_primary_attempts)
        payload["diagnostic_reruns"] = 2
        return payload

    monkeypatch.setattr(report, "verify_campaign", verified_with_rerun)
    result = report.aggregate_campaign(root)

    assert result["integrity"]["diagnostic_reruns"] == 2
    assert result["integrity"]["diagnostic_reruns_present"] is True
    assert result["integrity"]["diagnostic_reruns_scored"] is False


def test_row_binding_and_manifest_tampering_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)
    root = _campaign(tmp_path, [(False, False)] * 20)
    result_path = root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["schedule_binding"]["primary_slot_id"] = "primary-040"
    changed = (json.dumps(payload, sort_keys=True) + "\n").encode()
    result_path.write_bytes(changed)
    manifest = result_path.parent / "artifacts.sha256"
    _rewrite_manifest(result_path.parent)
    with pytest.raises(report.EvidenceIntegrityError, match="schedule_binding"):
        report.aggregate_campaign(root)

    _rewrite_manifest(result_path.parent)
    lines = manifest.read_text(encoding="utf-8").splitlines()
    manifest.write_text(
        "\n".join(
            f"{'0' * 64}  row-result.json" if line.endswith("  row-result.json") else line
            for line in lines
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(report.EvidenceIntegrityError, match="digest mismatch"):
        report.aggregate_campaign(root)


def test_report_rescores_retained_native_artifact_after_result_and_manifest_forgery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)
    root = _campaign(tmp_path, [(False, False)] * 20)
    result_path = root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["status"] = "solved"
    payload["score"]["exact_match"] = True
    payload["score"]["solved"] = True
    payload["score"]["artifact"]["exact_match"] = True
    _rewrite_result(result_path, payload)

    with pytest.raises(report.EvidenceIntegrityError, match="flag match does not reproduce"):
        report.aggregate_campaign(root)


def test_report_retains_non_scoring_changed_artifact_without_inviting_a_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)
    root = _campaign(tmp_path, [(False, False)] * 20)
    result_path = root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    artifact = payload["score"]["artifact"]
    artifact["status"] = "invalid_changed_or_unreadable"
    artifact["sha256"] = None
    # The producer samples this before its bounded read. A hostile writer can
    # change the length before the later manifest closes over stable bytes.
    artifact["size_bytes"] += 1
    _rewrite_result(result_path, payload)

    result = report.aggregate_campaign(root)

    assert result["integrity"]["complete"] is True
    assert result["results"]["withheld"] is True


def test_report_reproduces_too_many_candidates_as_a_terminal_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)
    root = _campaign(tmp_path, [(False, False)] * 20)
    result_path = root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    answer_path = result_path.parent / "native-output/answer.txt"
    count = report._external_module.DEFAULT_MAX_FLAG_CANDIDATES + 1
    content = b"\n".join(f"flag{{candidate-{index:04d}}}".encode() for index in range(count))
    answer_path.write_bytes(content)
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    artifact = payload["score"]["artifact"]
    artifact.update(
        {
            "status": "invalid_too_many_candidates",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "candidate_count": count,
            "exact_match": False,
        }
    )
    _rewrite_result(result_path, payload)

    result = report.aggregate_campaign(root)

    assert result["integrity"]["complete"] is True
    assert result["results"]["withheld"] is True


def test_report_recomputes_isolation_attestation_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)
    root = _campaign(tmp_path, [(False, False)] * 20)
    result_path = root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["isolation"]["filesystem_isolated"] = False
    _rewrite_result(result_path, payload)

    with pytest.raises(report.EvidenceIntegrityError, match="isolation verdicts"):
        report.aggregate_campaign(root)


def test_report_recomputes_lifecycle_receipts_and_schedule_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)
    receipt_root = _campaign(tmp_path / "receipt", [(False, False)] * 20)
    result_path = receipt_root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    build_path = result_path.parent / "target-build.json"
    build = json.loads(build_path.read_text(encoding="utf-8"))
    build["status"] = "errored"
    build["error"] = "synthetic failure"
    del build["provenance"]
    build_path.write_text(json.dumps(build), encoding="utf-8")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["target"]["target_url"] = None
    _rewrite_result(result_path, result)
    with pytest.raises(report.EvidenceIntegrityError, match="comparison validity"):
        report.aggregate_campaign(receipt_root)

    order_root = _campaign(tmp_path / "order", [(False, False)] * 20)
    second_path = order_root / "attempts/primary/primary-002/artifacts/row/row-result.json"
    second = json.loads(second_path.read_text(encoding="utf-8"))
    second["created_at"] = "2026-09-11T01:00:00.500000+00:00"
    second["execution"]["started_at"] = second["created_at"]
    second["execution"]["completed_at"] = "2026-09-11T01:00:00.750000+00:00"
    second["completed_at"] = second["execution"]["completed_at"]
    flag_path = second_path.parent / report.FLAG_COMMITMENT_FILE
    flag = json.loads(flag_path.read_text(encoding="utf-8"))
    flag["created_at"] = "2026-09-11T01:00:00.250000+00:00"
    flag_path.write_text(json.dumps(flag), encoding="utf-8")
    _rewrite_result(second_path, second)
    with pytest.raises(report.EvidenceIntegrityError, match="committed order"):
        report.aggregate_campaign(order_root)


@pytest.mark.parametrize(
    ("execution_status", "returncode"),
    (("timed_out", 124), ("errored", 125)),
)
def test_timed_out_or_nonzero_primary_is_a_valid_unsuccessful_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    execution_status: str,
    returncode: int,
) -> None:
    _stub_report_verifiers(monkeypatch, independent_rows_verified=True)
    root = _campaign(tmp_path, [(True, False), *([(False, False)] * 19)])
    result_path = root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["execution"]["status"] = execution_status
    result["execution"]["returncode"] = returncode
    result["status"] = execution_status
    result["score"]["solved"] = False
    _rewrite_result(result_path, result)

    aggregated = report.aggregate_campaign(root)

    assert aggregated["integrity"]["invalid_for_comparison_rows"] == 0
    assert aggregated["integrity"]["all_rows_valid_for_comparison"] is True
    assert aggregated["status_counts"]["overall"][execution_status] == 1
    paired = aggregated["diagnostics"]["unverified_paired_results"]
    assert paired["systems"]["ravage"]["solved"] == 0
    assert paired["paired_contingency"]["neither_solved"] == 20


def test_asymmetric_unstarted_setup_failure_withholds_numeric_paired_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_report_verifiers(monkeypatch, independent_rows_verified=True)
    root = _campaign(tmp_path, [(False, True), *([(False, False)] * 19)])
    result_path = root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    instance_id = result["target"]["instance_id"]
    (result_path.parent / "target-build.json").write_text(
        json.dumps(
            {
                "status": "errored",
                "instance_id": instance_id,
                "error": "synthetic setup failure",
            }
        ),
        encoding="utf-8",
    )
    (result_path.parent / "target-teardown.json").write_text(
        json.dumps({"status": "not_started", "instance_id": instance_id}),
        encoding="utf-8",
    )
    result["status"] = "infrastructure_error"
    result["valid_for_comparison"] = False
    result["valid_for_paired_local_comparison"] = False
    result["official_attestation_eligible"] = False
    result["target"]["target_url"] = None
    result["execution"].update(
        {
            "status": "not_started",
            "returncode": -1,
            "started_at": None,
            "completed_at": None,
            "error": "target setup failed before agent launch",
            "receipts": {
                "valid": False,
                "official_attestation_eligible": False,
                "evidence_class": None,
                "error": "target setup failed before agent launch",
            },
        }
    )
    _rewrite_result(result_path, result)

    aggregated = report.aggregate_campaign(root)

    assert aggregated["integrity"]["invalid_for_comparison_rows"] == 1
    withheld = aggregated["diagnostics"]["unverified_paired_results"]
    assert withheld == {
        "available": False,
        "withheld": True,
        "reasons": ["invalid_primary_rows"],
    }
    assert not any(
        key in withheld
        for key in (
            "systems",
            "paired_contingency",
            "solve_rate_delta_ravage_minus_strix",
            "exact_two_sided_sign_mcnemar_p_value",
        )
    )


def test_invalid_independent_row_evidence_withholds_numeric_paired_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _campaign(tmp_path, [(False, True), *([(False, False)] * 19)])
    monkeypatch.setattr(report, "verify_campaign", _verified)

    def independently_verify(
        result: Mapping[str, object],
        *,
        scheduled: Mapping[str, object],
        row_root: Path,
        campaign_root: Path,
        run_contract: Mapping[str, object],
    ) -> dict[str, object]:
        evidence = _verified_independent_row(
            result,
            scheduled=scheduled,
            row_root=row_root,
            campaign_root=campaign_root,
            run_contract=run_contract,
        )
        if scheduled["slot_id"] == "primary-001":
            evidence["model_gateway_verified"] = False
        return evidence

    monkeypatch.setattr(report, "_verify_independent_row_evidence", independently_verify)

    aggregated = report.aggregate_campaign(root)

    assert aggregated["integrity"]["invalid_for_comparison_rows"] == 0
    assert aggregated["diagnostics"]["unverified_paired_results"] == {
        "available": False,
        "withheld": True,
        "reasons": ["independent_row_evidence_unverified"],
    }


@pytest.mark.parametrize(
    ("execution_status", "returncode"),
    (("timed_out", 124), ("errored", 125)),
)
def test_flag_shaped_artifact_cannot_rescue_a_terminal_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    execution_status: str,
    returncode: int,
) -> None:
    _stub_report_verifiers(monkeypatch)
    root = _campaign(tmp_path, [(True, False), *([(False, False)] * 19)])
    result_path = root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["execution"].update({"status": execution_status, "returncode": returncode})
    result["status"] = "solved"
    _rewrite_result(result_path, result)

    with pytest.raises(report.EvidenceIntegrityError, match="solved value is inconsistent"):
        report.aggregate_campaign(root)


def test_frozen_contract_and_per_row_uniqueness_are_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)
    contract_root = _campaign(tmp_path / "contract", [(False, False)] * 20)
    result_path = contract_root / "attempts/primary/primary-001/artifacts/row/row-result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["agent"]["reasoning_effort"] = "low"
    _rewrite_result(result_path, payload)
    with pytest.raises(report.EvidenceIntegrityError, match="frozen run contract"):
        report.aggregate_campaign(contract_root)

    duplicate_flag = _campaign(tmp_path / "flag", [(False, False)] * 20)
    first_path = duplicate_flag / "attempts/primary/primary-001/artifacts/row/row-result.json"
    first = json.loads(first_path.read_text(encoding="utf-8"))
    for slot in (3, 4):
        duplicate_path = (
            duplicate_flag / f"attempts/primary/primary-{slot:03d}/artifacts/row/row-result.json"
        )
        duplicate = json.loads(duplicate_path.read_text(encoding="utf-8"))
        duplicate["score"]["expected_flag_sha256"] = first["score"]["expected_flag_sha256"]
        flag_commitment_path = duplicate_path.parent / report.FLAG_COMMITMENT_FILE
        flag_commitment = json.loads(flag_commitment_path.read_text(encoding="utf-8"))
        flag_commitment["expected_flag_sha256"] = first["score"]["expected_flag_sha256"]
        flag_commitment_path.write_text(json.dumps(flag_commitment), encoding="utf-8")
        _rewrite_result(duplicate_path, duplicate)
    with pytest.raises(report.EvidenceIntegrityError, match="pair flag .* uniqueness"):
        report.aggregate_campaign(duplicate_flag)

    duplicate_target = _campaign(tmp_path / "target", [(False, False)] * 20)
    first_path = duplicate_target / "attempts/primary/primary-001/artifacts/row/row-result.json"
    second_path = duplicate_target / "attempts/primary/primary-002/artifacts/row/row-result.json"
    first = json.loads(first_path.read_text(encoding="utf-8"))
    second = json.loads(second_path.read_text(encoding="utf-8"))
    second["target"]["instance_id"] = first["target"]["instance_id"]
    flag_commitment_path = second_path.parent / report.FLAG_COMMITMENT_FILE
    flag_commitment = json.loads(flag_commitment_path.read_text(encoding="utf-8"))
    flag_commitment["instance_id"] = first["target"]["instance_id"]
    flag_commitment_path.write_text(json.dumps(flag_commitment), encoding="utf-8")
    for receipt_name in ("target-build.json", "target-teardown.json"):
        receipt_path = second_path.parent / receipt_name
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["instance_id"] = first["target"]["instance_id"]
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _rewrite_result(second_path, second)
    with pytest.raises(report.EvidenceIntegrityError, match="instance IDs are not unique"):
        report.aggregate_campaign(duplicate_target)


def test_independent_receipts_cross_bind_adapter_runtime_and_process_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _run_contract()
    row_root = tmp_path / "row"
    native = row_root / "native-output"
    native.mkdir(parents=True)
    for child_writable_root in (
        "agent-run",
        "adapter-home",
        "adapter-work",
        "adapter-tmp",
    ):
        (native / child_writable_root).mkdir()
    (native / "adapter-stdout.log").write_bytes(b"")
    (native / "adapter-stderr.log").write_bytes(b"")
    (native / "flag-candidates.txt").write_bytes(b"")
    target_url = "http://127.0.0.1:55000"
    gateway_url = "http://127.0.0.1:56000"
    description = "Inspect the exposed web application."
    prompt = "Shared generic objective and rules.\n" + description
    description_digest = "sha256:" + hashlib.sha256(description.encode()).hexdigest()
    prompt_digest = "sha256:" + hashlib.sha256(prompt.encode()).hexdigest()
    runtime_contract = contract["runtime_manifests"]["ravage"]
    source_contract = contract["sources"]["ravage"]
    gateway_policy = contract["model_gateway"]["policy"]
    docker_socket = "/var/run/docker.sock"
    docker_host = f"unix://{docker_socket}"
    system_host_policy = contract["execution_policy"]["evaluator_host"]["systems"]["ravage"]
    system_host_policy.update(
        {
            "evidence_class": "paired_local",
            "docker_socket_access": True,
            "docker_socket_path_sha256": (
                "sha256:" + hashlib.sha256(docker_socket.encode()).hexdigest()
            ),
            "docker_host_sha256": ("sha256:" + hashlib.sha256(docker_host.encode()).hexdigest()),
        }
    )
    row_token_digest = "sha256:" + "c" * 64
    empty_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
    adapter = {
        "schema_version": "ravage.xben.comparison-adapter.v4",
        "adapter_version": "paired-description-only-black-box-v4",
        "system_id": "ravage",
        "status": "completed",
        "returncode": 0,
        "wrapper_returncode": 0,
        "timed_out": False,
        "command_sha256": "sha256:" + "a" * 64,
        "target_url_sha256": "sha256:" + hashlib.sha256(target_url.encode()).hexdigest(),
        "gateway_base_url_sha256": ("sha256:" + hashlib.sha256(gateway_url.encode()).hexdigest()),
        "docker_host_sha256": system_host_policy["docker_host_sha256"],
        "gateway": {
            "base_url_sha256": ("sha256:" + hashlib.sha256(gateway_url.encode()).hexdigest()),
            "token_sha256": row_token_digest,
            "model": gateway_policy["model"],
            "reasoning_effort": gateway_policy["reasoning_effort"],
            "pricing": gateway_policy["pricing_usd_per_million_tokens"],
            "max_output_tokens": gateway_policy["max_completion_tokens_per_request"],
        },
        "limits": report._row_limits_json(contract["budgets"]["per_row"]),
        "tool_image": contract["oci_images"]["ravage_tool"],
        "process_group_policy": "joined_evaluator_outer_group",
        "input_contract": {
            "mode": "description-only-black-box",
            "description_sha256": description_digest,
            "description_bytes": len(description.encode()),
            "semantic_prompt_sha256": prompt_digest,
            "semantic_prompt_bytes": len(prompt.encode()),
            "target_url_in_semantic_prompt": False,
            "case_id_included": False,
            "source_path_included": False,
            "expected_flag_used": False,
        },
        "runtime": {
            "executable_sha256": runtime_contract["executable_sha256"],
            "source_commit": source_contract["commit_sha"],
            "source_tree": source_contract["tree_object"],
            "source_origin_url": source_contract["origin_url"],
            "environment_manifest_sha256": runtime_contract["sha256"],
            "interpreter_sha256": runtime_contract["interpreter_sha256"],
            "lockfile_sha256": runtime_contract["lockfile_sha256"],
            "distribution_inventory_sha256": runtime_contract["distribution_inventory_sha256"],
            "site_packages_tree_sha256": runtime_contract["site_packages_tree_sha256"],
        },
        "capture": {
            stream: {
                "sha256": empty_digest,
                "total_bytes": 0,
                "retained_bytes": 0,
                "truncated": False,
                "complete": True,
            }
            for stream in ("stdout", "stderr")
        },
        "candidate_extraction": {
            "complete": True,
            "candidate_count": 0,
            "artifact_path": "flag-candidates.txt",
            "scanned_artifact_files": 0,
            "scanned_artifact_bytes": 0,
            "scanned_roots": [
                "agent-run",
                "adapter-home",
                "adapter-work",
                "adapter-tmp",
            ],
            "expected_flag_used": False,
        },
        "environment_policy": {
            "inherits_parent": False,
            "row_gateway_only": True,
            "ambient_proxy_or_provider_credentials": False,
            "fresh_home_work_run": True,
            "persisted_row_credentials_redacted": 0,
        },
    }
    (native / "adapter-result.json").write_text(json.dumps(adapter), encoding="utf-8")
    model_path = row_root / "model-gateway-receipt.json"
    model_path.write_text("{}", encoding="utf-8")
    model_file_digest = "sha256:" + hashlib.sha256(model_path.read_bytes()).hexdigest()
    model_document_digest = "sha256:" + "b" * 64
    process_body = {"schema_version": "synthetic-process-receipt"}
    process_document_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                process_body,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )
    process_payload = {**process_body, "document_sha256": process_document_digest}
    process_path = row_root / "process-receipt.json"
    process_path.write_text(json.dumps(process_payload), encoding="utf-8")
    process_file_digest = "sha256:" + hashlib.sha256(process_path.read_bytes()).hexdigest()
    profile = b"(version 1)\n"
    (row_root / "sandbox-profile.sb").write_bytes(profile)
    profile_digest = "sha256:" + hashlib.sha256(profile).hexdigest()
    policy_digest = contract["model_gateway"]["policy_sha256"]
    command_digest = "d" * 64
    environment_hashes = {
        "RAVAGE_COMPARISON_GATEWAY_BASE_URL": adapter["gateway_base_url_sha256"],
        "RAVAGE_COMPARISON_GATEWAY_TOKEN": row_token_digest,
        "RAVAGE_COMPARISON_OUTER_PROCESS_GROUP": (
            "sha256:" + hashlib.sha256(b"joined_evaluator_group_v1").hexdigest()
        ),
        "RAVAGE_XBEN_DESCRIPTION": description_digest,
        "RAVAGE_XBEN_TARGET_URL": adapter["target_url_sha256"],
    }
    public_contract = {
        "command": {"argv_sha256": "sha256:" + command_digest},
        "environment": {
            "names": sorted(environment_hashes),
            "value_sha256": environment_hashes,
        },
        "limits": report._row_limits_json(contract["budgets"]["per_row"]),
        "model_gateway_policy_sha256": policy_digest,
        "sandbox_executable_sha256": contract["execution_policy"]["evaluator_host"][
            "sandbox_executable_sha256"
        ],
        "sandbox": {
            "platform": "darwin",
            "backend": "sandbox-exec",
            "executable_path": "/usr/bin/sandbox-exec",
            "executable_sha256": contract["execution_policy"]["evaluator_host"][
                "sandbox_executable_sha256"
            ],
            "runtime_read_roots_sha256": contract["execution_policy"]["evaluator_host"]["systems"][
                "ravage"
            ]["runtime_read_roots_sha256"],
            "runtime_read_root_count": 2,
            "docker_socket_access": True,
            "docker_socket_path": docker_socket,
        },
    }
    receipts = {
        "valid": True,
        "official_attestation_eligible": False,
        "evidence_class": "paired_local",
        "process_receipt_path": "process-receipt.json",
        "process_receipt_document_sha256": process_document_digest,
        "process_receipt_file_sha256": process_file_digest,
        "model_gateway_receipt_path": "model-gateway-receipt.json",
        "model_gateway_receipt_document_sha256": model_document_digest,
        "model_gateway_receipt_file_sha256": model_file_digest,
        "model_gateway_policy_sha256": policy_digest,
        "sandbox_profile_path": "sandbox-profile.sb",
        "sandbox_profile_sha256": profile_digest,
        "public_validation_contract": public_contract,
        "error": None,
    }
    result = {
        "elapsed_seconds": 3.0,
        "case": {
            "benchmark_id": "XBEN-001-24",
            "description_sha256": description_digest.removeprefix("sha256:"),
        },
        "agent": {"command_sha256": command_digest},
        "target": {"target_url": target_url},
        "execution": {
            "returncode": 0,
            "status": "completed",
            "started_at": "2026-09-11T00:00:00+00:00",
            "completed_at": "2026-09-11T00:00:02+00:00",
            "stdout_capture": _empty_capture(),
            "stderr_capture": _empty_capture(),
            "receipts": receipts,
        },
        "score": {"artifact": {"path": "flag-candidates.txt"}},
        "policy": {"pair_scoped_flag": True},
        "official_attestation_eligible": False,
    }
    scheduled = {
        "slot_id": "primary-001",
        "case_id": "XBEN-001-24",
        "system": "ravage",
    }

    monkeypatch.setattr(
        report,
        "validate_model_gateway_receipt",
        lambda *_args, **_kwargs: {
            "document_sha256": model_document_digest,
            "policy": contract["model_gateway"]["policy"],
            "row_token_sha256": row_token_digest,
            "valid": True,
        },
    )

    def validate_process_receipt(
        *_args: object,
        expected_output_directory: Path,
        **_kwargs: object,
    ) -> dict[str, object]:
        assert expected_output_directory == native
        return {
            "evidence_class": "paired_local",
            "execution": {
                "started_at": "2026-09-11T00:00:00.1+00:00",
                "completed_at": "2026-09-11T00:00:01.9+00:00",
                "elapsed_seconds": 1.8,
                "returncode": result["execution"]["returncode"],
                "timed_out": False,
                "stdout": {
                    "raw_sha256": empty_digest,
                    "raw_size_bytes": 0,
                    "retained_size_bytes": 0,
                    "truncated": False,
                    "complete": True,
                },
                "stderr": {
                    "raw_sha256": empty_digest,
                    "raw_size_bytes": 0,
                    "retained_size_bytes": 0,
                    "truncated": False,
                    "complete": True,
                },
            },
            "official_attestation_eligible": False,
        }

    monkeypatch.setattr(
        report,
        "validate_comparison_process_receipt_public",
        validate_process_receipt,
    )
    monkeypatch.setattr(
        report,
        "_verify_target_evidence",
        lambda *_args, **_kwargs: {
            "target_verified": True,
            "prepared_target": None,
            "target_request_attempts": None,
        },
    )

    verified = report._verify_independent_row_evidence(
        result,
        scheduled=scheduled,
        row_root=row_root,
        campaign_root=tmp_path,
        run_contract=contract,
    )
    assert verified["adapter_verified"] is True
    assert verified["model_gateway_verified"] is True
    assert verified["process_verified"] is True

    public_contract["sandbox"]["runtime_read_roots_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(report.EvidenceIntegrityError, match="host containment differs"):
        report._verify_independent_row_evidence(
            result,
            scheduled=scheduled,
            row_root=row_root,
            campaign_root=tmp_path,
            run_contract=contract,
        )
    public_contract["sandbox"]["runtime_read_roots_sha256"] = contract["execution_policy"][
        "evaluator_host"
    ]["systems"]["ravage"]["runtime_read_roots_sha256"]

    (native / "flag-candidates.txt").unlink()
    adapter["candidate_extraction"].update({"complete": False, "artifact_path": None})
    adapter["wrapper_returncode"] = 125
    result["execution"]["returncode"] = 125
    assert (
        report._validate_adapter_result(
            adapter,
            result=result,
            scheduled=scheduled,
            row_root=row_root,
            run_contract=contract,
        )
        is False
    )
    adapter.update(
        {
            "status": "timed_out",
            "timed_out": True,
            "returncode": -15,
            "wrapper_returncode": 124,
        }
    )
    result["execution"].update({"status": "errored", "returncode": 124})
    assert (
        report._validate_adapter_result(
            adapter,
            result=result,
            scheduled=scheduled,
            row_root=row_root,
            run_contract=contract,
        )
        is True
    )
    (native / "adapter-result.json").write_text(json.dumps(adapter), encoding="utf-8")
    terminal = report._verify_independent_row_evidence(
        result,
        scheduled=scheduled,
        row_root=row_root,
        campaign_root=tmp_path,
        run_contract=contract,
    )
    assert terminal["adapter_verified"] is True
    assert terminal["process_verified"] is True
    adapter["capture"]["stdout"]["complete"] = False
    assert (
        report._validate_adapter_result(
            adapter,
            result=result,
            scheduled=scheduled,
            row_root=row_root,
            run_contract=contract,
        )
        is False
    )
    adapter["capture"]["stdout"]["complete"] = True
    (native / "flag-candidates.txt").write_bytes(b"")
    adapter.update({"status": "completed", "timed_out": False, "returncode": 0})
    adapter["candidate_extraction"].update(
        {"complete": True, "artifact_path": "flag-candidates.txt"}
    )
    adapter["wrapper_returncode"] = 0
    result["execution"].update({"status": "completed", "returncode": 0})

    adapter["capture"]["stdout"].update({"total_bytes": 1, "truncated": True})
    (native / "adapter-result.json").write_text(json.dumps(adapter), encoding="utf-8")
    truncated = report._verify_independent_row_evidence(
        result,
        scheduled=scheduled,
        row_root=row_root,
        campaign_root=tmp_path,
        run_contract=contract,
    )
    assert truncated["adapter_verified"] is False
    adapter["capture"]["stdout"].update({"total_bytes": 0, "truncated": False})
    injected = b"flag{post_hoc_injection}"
    (native / "flag-candidates.txt").write_bytes(injected + b"\n")
    adapter["candidate_extraction"]["candidate_count"] = 1
    (native / "adapter-result.json").write_text(json.dumps(adapter), encoding="utf-8")
    with pytest.raises(report.EvidenceIntegrityError, match="extraction does not reproduce"):
        report._verify_independent_row_evidence(
            result,
            scheduled=scheduled,
            row_root=row_root,
            campaign_root=tmp_path,
            run_contract=contract,
        )
    (native / "flag-candidates.txt").write_bytes(b"")
    adapter["candidate_extraction"]["candidate_count"] = 0

    adapter["process_group_policy"] = "independent_inner_group"
    (native / "adapter-result.json").write_text(json.dumps(adapter), encoding="utf-8")
    with pytest.raises(report.EvidenceIntegrityError, match="process-group policy differs"):
        report._verify_independent_row_evidence(
            result,
            scheduled=scheduled,
            row_root=row_root,
            campaign_root=tmp_path,
            run_contract=contract,
        )
    adapter["process_group_policy"] = "joined_evaluator_outer_group"

    adapter["tool_image"] = contract["oci_images"]["strix_sandbox"]
    (native / "adapter-result.json").write_text(json.dumps(adapter), encoding="utf-8")
    with pytest.raises(report.EvidenceIntegrityError, match="tool image differs"):
        report._verify_independent_row_evidence(
            result,
            scheduled=scheduled,
            row_root=row_root,
            campaign_root=tmp_path,
            run_contract=contract,
        )
    adapter["tool_image"] = contract["oci_images"]["ravage_tool"]
    (native / "adapter-result.json").write_text(json.dumps(adapter), encoding="utf-8")

    environment_hashes["RAVAGE_COMPARISON_OUTER_PROCESS_GROUP"] = "sha256:" + "0" * 64
    with pytest.raises(report.EvidenceIntegrityError, match="environment is not cross-bound"):
        report._verify_independent_row_evidence(
            result,
            scheduled=scheduled,
            row_root=row_root,
            campaign_root=tmp_path,
            run_contract=contract,
        )
    environment_hashes["RAVAGE_COMPARISON_OUTER_PROCESS_GROUP"] = (
        "sha256:" + hashlib.sha256(b"joined_evaluator_group_v1").hexdigest()
    )

    environment_hashes["RAVAGE_XBEN_DESCRIPTION"] = "sha256:" + "f" * 64
    with pytest.raises(report.EvidenceIntegrityError, match="environment is not cross-bound"):
        report._verify_independent_row_evidence(
            result,
            scheduled=scheduled,
            row_root=row_root,
            campaign_root=tmp_path,
            run_contract=contract,
        )

    environment_hashes["RAVAGE_XBEN_DESCRIPTION"] = description_digest
    adapter["runtime"]["lockfile_sha256"] = "sha256:" + "0" * 64
    (native / "adapter-result.json").write_text(json.dumps(adapter), encoding="utf-8")
    with pytest.raises(report.EvidenceIntegrityError, match="runtime differs"):
        report._verify_independent_row_evidence(
            result,
            scheduled=scheduled,
            row_root=row_root,
            campaign_root=tmp_path,
            run_contract=contract,
        )


def test_duplicate_adapter_receipt_path_is_rejected(tmp_path: Path) -> None:
    row_root = tmp_path / "row"
    expected = row_root / "native-output" / "adapter-result.json"
    expected.parent.mkdir(parents=True)
    expected.write_text("{}", encoding="utf-8")
    duplicate = row_root / "ignored" / "adapter-result.json"
    duplicate.parent.mkdir()
    duplicate.write_text("{}", encoding="utf-8")

    with pytest.raises(report.EvidenceIntegrityError, match="duplicated, or substituted"):
        report._require_unique_file_location(
            row_root,
            expected=expected,
            basename="adapter-result.json",
            label="adapter result",
        )


def test_target_helper_images_are_cross_bound_to_frozen_oci_refs() -> None:
    contract = _run_contract()
    images = contract["oci_images"]
    image_ids = contract["target_helper_image_ids"]
    build = {
        "readiness": {
            "probe_image": images["target_probe"],
            "probe_image_id": image_ids["target_probe"],
        },
        "gateway": {
            "image": images["target_gateway"],
            "image_id": image_ids["target_gateway"],
        },
    }
    report._verify_target_infrastructure_images(
        build,
        oci_images=images,
        target_helper_image_ids=image_ids,
        slot_id="primary-001",
    )

    build["gateway"] = {"image": "registry.example.invalid/gateway@sha256:" + "f" * 64}
    with pytest.raises(report.EvidenceIntegrityError, match="infrastructure images differ"):
        report._verify_target_infrastructure_images(
            build,
            oci_images=images,
            target_helper_image_ids=image_ids,
            slot_id="primary-001",
        )


def test_evaluator_sources_include_the_exact_compatibility_catalog() -> None:
    contract = _run_contract()
    repository = Path(report.__file__).resolve().parents[2]
    contract["evaluator_components"] = {
        relative: "sha256:" + hashlib.sha256((repository / relative).read_bytes()).hexdigest()
        for relative in contract["evaluator_components"]
    }
    catalog = repository / "tools/paired_xben/compatibility/catalog.json"
    contract["compatibility_catalog"]["sha256"] = (
        "sha256:" + hashlib.sha256(catalog.read_bytes()).hexdigest()
    )
    assert report._verify_evaluator_component_sources(contract) is True

    contract["compatibility_catalog"]["sha256"] = "sha256:" + "0" * 64
    assert report._verify_evaluator_component_sources(contract) is False


def test_paired_target_rejects_reused_runtime_resource_identities() -> None:
    schedule = [
        {"case_id": "XBEN-001-24", "system": "ravage"},
        {"case_id": "XBEN-001-24", "system": "strix"},
    ]
    shared = {
        "pair_id": "pair-001",
        "benchmark_id": "XBEN-001-24",
        "pair_flag_sha256": "a" * 64,
        "prepared_path": "/unused/prepared.json",
        "prepared_sha256": "b" * 64,
        "image_ids_by_service": {"app": "sha256:" + "c" * 64},
        "project": "reused-project",
    }
    evidence = [
        {
            "prepared_target": {
                **shared,
                "arm": "ravage",
                "instance_id": "xben-row-" + "1" * 32,
                "target_network_name": "network-ravage",
                "target_network_id": "d" * 64,
                "container_ids": ["e" * 64],
                "volume_names": [],
            }
        },
        {
            "prepared_target": {
                **shared,
                "arm": "strix",
                "instance_id": "xben-row-" + "2" * 32,
                "target_network_name": "network-strix",
                "target_network_id": "f" * 64,
                "container_ids": ["1" * 64],
                "volume_names": [],
            }
        },
    ]
    with pytest.raises(report.EvidenceIntegrityError, match="reuses Docker project"):
        report._verify_paired_target_reuse(schedule, [{}, {}], evidence)


def test_report_write_is_create_only_and_manifest_has_no_self_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_report_verifiers(monkeypatch)
    root = _campaign(tmp_path, [(False, False)] * 20)
    output = tmp_path / "report-output"

    report_path, manifest_path = report.write_report(
        root, output, generated_at="2026-09-11T02:00:00+00:00"
    )

    line = manifest_path.read_text(encoding="ascii")
    assert line == f"{hashlib.sha256(report_path.read_bytes()).hexdigest()}  report.json\n"
    assert "artifacts.sha256" not in line
    with pytest.raises(report.ReportAlreadyExistsError):
        report.write_report(root, output)


def test_exact_mcnemar_edge_cases() -> None:
    assert report.exact_two_sided_mcnemar_p_value(0, 0) == 1.0
    assert report.exact_two_sided_mcnemar_p_value(6, 0) == pytest.approx(0.03125)
    assert report.exact_two_sided_mcnemar_p_value(3, 3) == 1.0
