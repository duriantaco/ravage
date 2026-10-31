# ruff: noqa: PLR2004
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from tools.paired_xben import authenticity as authenticity_module
from tools.paired_xben.authenticity import drand_source_bundle_digest
from tools.paired_xben.cli import main
from tools.paired_xben.preflight import STRIX_CANONICAL_ORIGIN_URL, XBEN_CANONICAL_ORIGIN_URL
from tools.paired_xben.protocol import RUN_CONTRACT_SCHEMA, canonical_json

if TYPE_CHECKING:
    from pathlib import Path

CHAIN_HASH = "12" * 32
DRAW_ROUND = 4_000_000


def _source_binding(*, head: str, origin: str, tree_path: str) -> dict[str, object]:
    return {
        "ready": True,
        "status": "ready",
        "repository_root_verified": True,
        "expected_head": head,
        "expected_origin_url": origin,
        "origin_url": origin,
        "origin_matches_expected": True,
        "origin_observed_sha256": "sha256:" + "8" * 64,
        "tree_path": tree_path,
        "tree_object": "7" * 40,
        "tree_object_algorithm": "sha1",
        "tree_matches_worktree": True,
        "location_is_canonical": True,
    }


def _contract_payload(preflight_digest: str) -> dict[str, object]:
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
        "schema_version": RUN_CONTRACT_SCHEMA,
        "mode": "description-only-black-box",
        "objective": "capture_flag",
        "sources": {
            "ravage": {
                "commit_sha": "1" * 40,
                "tree_object": "4" * 40,
                "tree_path": ".",
                "origin_url": "https://github.com/example/ravage.git",
                "dirty": False,
            },
            "strix": {
                "commit_sha": "2" * 40,
                "tree_object": "7" * 40,
                "tree_path": ".",
                "origin_url": STRIX_CANONICAL_ORIGIN_URL,
                "dirty": False,
            },
            "xben": {
                "commit_sha": "3" * 40,
                "tree_object": "7" * 40,
                "tree_path": "benchmarks",
                "origin_url": XBEN_CANONICAL_ORIGIN_URL,
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
            "policy_sha256": (
                "sha256:" + hashlib.sha256(canonical_json(policy).encode()).hexdigest()
            ),
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
                "max_target_requests": 3840,
                "max_cost_usd": "200",
            },
            "per_row": {
                "wall_seconds": 600,
                "max_model_requests": 40,
                "max_target_requests": 96,
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
            "target_endpoint_modes": {"ravage": "host_loopback", "strix": "docker_alias"},
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
        "preflight_digest": preflight_digest,
    }


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    case_ids = [f"XBEN-{index:03d}-24" for index in range(1, 105)]
    ids_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(case_ids, ensure_ascii=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    preflight = tmp_path / "preflight.json"
    preflight_bytes = (
        json.dumps(
            {
                "schema_version": "ravage.paired-xben.preflight.v1",
                "captured_at": "2026-01-01T00:00:00+00:00",
                "blocked": False,
                "block_reasons": [],
                "policy": {
                    "require_clean_sources": True,
                    "require_source_pins": True,
                    "require_website_target": True,
                },
                "disk": {"ready": True, "status": "ready"},
                "docker": {
                    "ready": True,
                    "executable_present": True,
                    "daemon_responsive": True,
                    "status": "ready",
                },
                "git": {
                    name: {
                        "available": True,
                        "head": head,
                        "dirty": False,
                        "pin_status": "match",
                        "expected_head": head,
                    }
                    for name, head in {
                        "ravage": "1" * 40,
                        "strix": "2" * 40,
                        "xben": "3" * 40,
                    }.items()
                },
                "xben": {
                    "ready": True,
                    "status": "ready",
                    "case_count": 104,
                    "eligible_case_count": 104,
                    "expected_case_count": 104,
                    "exact_case_set": True,
                    "eligible_case_ids": case_ids,
                    "eligible_case_ids_sha256": ids_digest,
                    "source_binding": _source_binding(
                        head="3" * 40,
                        origin=XBEN_CANONICAL_ORIGIN_URL,
                        tree_path="benchmarks",
                    ),
                },
                "strix": {
                    "ready": True,
                    "source_present": True,
                    "executable_present": True,
                    "dependency_probe_ok": True,
                    "executable_source": "explicit",
                    "executable_sha256": "sha256:" + "6" * 64,
                    "expected_executable_sha256": None,
                    "identity_mode": "pinned_source_blob",
                    "identity_verified": True,
                    "source_relative_executable": "bin/strix",
                    "source_blob_object": "5" * 40,
                    "source_blob_algorithm": "sha1",
                    "source_binding": _source_binding(
                        head="2" * 40,
                        origin=STRIX_CANONICAL_ORIGIN_URL,
                        tree_path=".",
                    ),
                    "status": "ready",
                },
                "provider_environment": {
                    "ready": True,
                    "required": [{"name": "OPENAI_API_KEY", "present": True}],
                    "missing": [],
                    "source": "process_environment_only",
                    "dotenv_loaded": False,
                },
                "website": {
                    "required": True,
                    "configured": True,
                    "resolved": True,
                    "classification": "known_site",
                    "reference_sha256": "sha256:" + "7" * 64,
                    "raw_reference_emitted": False,
                },
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    preflight.write_bytes(preflight_bytes)
    preflight_digest = "sha256:" + hashlib.sha256(preflight_bytes).hexdigest()
    contract = tmp_path / "contract.json"
    contract.write_text(
        json.dumps(_contract_payload(preflight_digest)),
        encoding="utf-8",
    )
    drand = tmp_path / "test-drandverify"
    drand.write_text(
        f"""#!{sys.executable}
import hashlib, json, pathlib, sys
if "--self-info" in sys.argv:
    print(json.dumps({{"schema_version":"ravage.paired-xben.drand-verifier-self.v1","library_module":"github.com/drand/drand/v2","library_version":"v2.1.6","source_bundle_sha256":"{drand_source_bundle_digest()}"}}))
    raise SystemExit(0)
def value(flag): return sys.argv[sys.argv.index(flag) + 1]
chain = pathlib.Path(value("--chain-info")).read_bytes()
beacon_bytes = pathlib.Path(value("--beacon")).read_bytes()
beacon = json.loads(beacon_bytes)
print(json.dumps({{"schema_version":"ravage.paired-xben.drand-verification.v1","verified":True,"library_module":"github.com/drand/drand/v2","library_version":"v2.1.6","chain_hash":value("--expected-chain-hash"),"round":int(value("--expected-round")),"scheme":"pedersen-bls-chained","randomness":beacon["randomness"],"chain_info_sha256":"sha256:"+hashlib.sha256(chain).hexdigest(),"beacon_sha256":"sha256:"+hashlib.sha256(beacon_bytes).hexdigest(),"public_key_sha256":"sha256:"+"6"*64}}))
""",
        encoding="utf-8",
    )
    os.chmod(drand, 0o700)
    cosign = tmp_path / "test-cosign"
    cosign.write_text(
        f"""#!{sys.executable}
import sys
if len(sys.argv) > 1 and sys.argv[1] == "version": print("GitVersion: v3.1.3"); raise SystemExit(0)
if len(sys.argv) > 1 and sys.argv[1] == "verify-blob": print("Verified OK"); raise SystemExit(0)
raise SystemExit(2)
""",
        encoding="utf-8",
    )
    os.chmod(cosign, 0o700)
    trusted_root = tmp_path / "trusted-root.json"
    trusted_root.write_text("{}\n", encoding="utf-8")
    return preflight, contract, drand, cosign, trusted_root


def _fake_rfc3161_timestamp() -> str:
    def der(tag: int, value: bytes) -> bytes:
        if len(value) < 128:
            encoded_length = bytes([len(value)])
        else:
            raw = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
            encoded_length = bytes([0x80 | len(raw)]) + raw
        return bytes([tag]) + encoded_length + value

    integer = der(0x02, b"\x01")
    oid = der(0x06, b"\x2a\x03")
    tst_info = der(
        0x30,
        integer + oid + der(0x30, b"") + integer + der(0x18, b"20270101000000Z"),
    )
    encapsulated = der(0x30, oid + der(0xA0, der(0x04, tst_info)))
    signed_data = der(0x30, integer + der(0x31, b"") + encapsulated)
    content_info = der(0x30, oid + der(0xA0, signed_data))
    return base64.b64encode(der(0x30, der(0x30, integer) + content_info)).decode("ascii")


def test_cli_commit_resolve_verify_and_attempt_separation(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preflight, contract, drand, cosign, trusted_root = _write_inputs(tmp_path)
    campaign = tmp_path / "campaign"
    assert (
        main(
            [
                "commit",
                "--output-dir",
                str(campaign),
                "--campaign-id",
                "paired-xben-cli",
                "--preflight",
                str(preflight),
                "--run-contract",
                str(contract),
                "--chain-hash",
                CHAIN_HASH,
                "--chain-genesis-time",
                "1700000000",
                "--chain-period-seconds",
                "30",
                "--observed-latest-round",
                "3999990",
                "--draw-round",
                str(DRAW_ROUND),
                "--drand-verifier-binary",
                str(drand),
                "--cosign-binary",
                str(cosign),
                "--sigstore-trusted-root",
                str(trusted_root),
                "--publication-certificate-identity",
                "https://github.com/example/ravage/.github/workflows/benchmark.yml@refs/heads/main",
                "--publication-certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    commitment = json.loads(captured.out)
    assert (campaign / "preflight-source.json").read_bytes() == preflight.read_bytes()

    signature = bytes.fromhex("ef" * 96)
    beacon_body = json.dumps(
        {
            "round": DRAW_ROUND,
            "signature": signature.hex(),
            "previous_signature": "cd" * 96,
            "randomness": hashlib.sha256(signature).hexdigest(),
        }
    ).encode()
    monkeypatch.setattr(
        authenticity_module,
        "_download_drand_response",
        lambda _url: beacon_body,
    )
    chain_info = tmp_path / "chain-info.json"
    chain_info.write_text("{}\n", encoding="utf-8")
    anchor = tmp_path / "anchor.json"
    anchor.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "tlogEntries": [
                        {
                            "integratedTime": "1798761600",
                            "logIndex": "9",
                            "inclusionProof": {"checkpoint": {"envelope": "proof"}},
                        }
                    ],
                    "timestampVerificationData": {
                        "rfc3161Timestamps": [{"signedTimestamp": _fake_rfc3161_timestamp()}]
                    },
                },
                "messageSignature": {"messageDigest": {}, "signature": "test"},
            }
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "resolve",
                "--campaign-dir",
                str(campaign),
                "--drand-chain-info",
                str(chain_info),
                "--publication-anchor",
                str(anchor),
                "--commitment-digest",
                commitment["document_digest"],
            ]
        )
        == 0
    )
    capsys.readouterr()  # type: ignore[attr-defined]

    assert main(["start-primary", "--campaign-dir", str(campaign), "--slot", "primary-001"]) == 2
    blocked = capsys.readouterr()  # type: ignore[attr-defined]
    assert "individual primary reservation is disabled" in blocked.err
    assert main(["reserve-primary-matrix", "--campaign-dir", str(campaign)]) == 0
    matrix = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert matrix["matrix_reserved"] is True
    assert matrix["score_eligible_slots"] == 40
    assert (
        main(
            [
                "start-rerun",
                "--campaign-dir",
                str(campaign),
                "--rerun-id",
                "diagnostic-001",
                "--primary-slot",
                "primary-001",
                "--reason",
                "diagnostic only",
            ]
        )
        == 0
    )
    rerun = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert rerun["score_eligible"] is False

    assert main(["verify", "--campaign-dir", str(campaign)]) == 0
    verified = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert verified["structurally_valid"] is True
    assert verified["claim_ready"] is False
    assert verified["recorded_primary_attempts"] == 40
    assert verified["primary_matrix_reserved"] is True
    assert verified["diagnostic_reruns"] == 1


def test_cli_refuses_to_reuse_commitment_directory(
    tmp_path: Path,
    capsys: object,
) -> None:
    preflight, contract, drand, cosign, trusted_root = _write_inputs(tmp_path)
    campaign = tmp_path / "campaign"
    argv = [
        "commit",
        "--output-dir",
        str(campaign),
        "--campaign-id",
        "paired-xben-cli",
        "--preflight",
        str(preflight),
        "--run-contract",
        str(contract),
        "--chain-hash",
        CHAIN_HASH,
        "--chain-genesis-time",
        "1700000000",
        "--chain-period-seconds",
        "30",
        "--observed-latest-round",
        "3999990",
        "--draw-round",
        str(DRAW_ROUND),
        "--drand-verifier-binary",
        str(drand),
        "--cosign-binary",
        str(cosign),
        "--sigstore-trusted-root",
        str(trusted_root),
        "--publication-certificate-identity",
        "https://github.com/example/ravage/.github/workflows/benchmark.yml@refs/heads/main",
        "--publication-certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
    ]
    assert main(argv) == 0
    capsys.readouterr()  # type: ignore[attr-defined]
    original = (campaign / "commitment.json").read_bytes()
    assert main(argv) == 2
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "refusing to reuse" in captured.err
    assert (campaign / "commitment.json").read_bytes() == original


def test_cli_rejects_operator_typed_preflight_digest(
    tmp_path: Path,
    capsys: object,
) -> None:
    preflight, contract, drand, cosign, trusted_root = _write_inputs(tmp_path)
    payload = json.loads(contract.read_text(encoding="utf-8"))
    payload["preflight_digest"] = "sha256:" + "0" * 64
    contract.write_text(json.dumps(payload), encoding="utf-8")
    campaign = tmp_path / "campaign"

    assert (
        main(
            [
                "commit",
                "--output-dir",
                str(campaign),
                "--campaign-id",
                "paired-xben-bad-digest",
                "--preflight",
                str(preflight),
                "--run-contract",
                str(contract),
                "--chain-hash",
                CHAIN_HASH,
                "--chain-genesis-time",
                "1700000000",
                "--chain-period-seconds",
                "30",
                "--observed-latest-round",
                "3999990",
                "--draw-round",
                str(DRAW_ROUND),
                "--drand-verifier-binary",
                str(drand),
                "--cosign-binary",
                str(cosign),
                "--sigstore-trusted-root",
                str(trusted_root),
                "--publication-certificate-identity",
                "https://github.com/example/ravage/.github/workflows/benchmark.yml@refs/heads/main",
                "--publication-certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
            ]
        )
        == 2
    )
    assert "preflight digest does not match" in capsys.readouterr().err  # type: ignore[attr-defined]
    assert not campaign.exists()


def test_standalone_wrapper_exposes_help() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/eval/run_paired_xben_protocol.py", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "non-cherry-picked paired XBEN-20" in completed.stdout
    assert "report" in completed.stdout
