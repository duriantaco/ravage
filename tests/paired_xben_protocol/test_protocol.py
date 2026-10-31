# ruff: noqa: EM101, PLR2004, S108, TRY003
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from decimal import localcontext
from typing import TYPE_CHECKING

import pytest

from tools.paired_xben import authenticity as authenticity_module
from tools.paired_xben.authenticity import drand_source_bundle_digest
from tools.paired_xben.preflight import STRIX_CANONICAL_ORIGIN_URL, XBEN_CANONICAL_ORIGIN_URL
from tools.paired_xben.protocol import (
    RUN_CONTRACT_SCHEMA,
    PairedXbenProtocolError,
    canonical_json,
    create_commitment,
    create_primary_attempt_manifest,
    create_rerun_attempt_manifest,
    eligible_pool_digest,
    reserve_primary_matrix,
    resolve_commitment,
    validate_run_contract,
    verify_campaign,
)

if TYPE_CHECKING:
    from pathlib import Path

CHAIN_HASH = "11" * 32
CREATED_AT = "2026-01-01T00:00:00+00:00"
CHAIN_GENESIS_TIME = 1_700_000_000
CHAIN_PERIOD_SECONDS = 30
LATEST_ROUND = 2_999_990
DRAW_ROUND = 3_000_000
RETRIEVED_AT = "2027-01-01T00:00:00+00:00"
PUBLICATION_AT = "2026-01-02T00:00:00+00:00"
PUBLICATION_EPOCH = 1_767_312_000
CERTIFICATE_IDENTITY = (
    "https://github.com/example/ravage/.github/workflows/benchmark.yml@refs/heads/main"
)
CERTIFICATE_ISSUER = "https://token.actions.githubusercontent.com"


@pytest.fixture(autouse=True)
def _stub_official_drand_https(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep protocol tests offline while exercising resolver-owned URL selection."""

    def download(url: str) -> bytes:
        name = (
            "input-beacon-secondary.json"
            if url.startswith("https://drand.cloudflare.com/")
            else "input-beacon.json"
        )
        return (tmp_path / name).read_bytes()

    monkeypatch.setattr(authenticity_module, "_download_drand_response", download)


def _pool() -> tuple[str, ...]:
    return tuple(f"XBEN-{index:03d}-24" for index in range(1, 105))


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


def _preflight_payload() -> dict[str, object]:
    case_ids = list(_pool())
    ids_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(case_ids, ensure_ascii=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    return {
        "schema_version": "ravage.paired-xben.preflight.v1",
        "captured_at": CREATED_AT,
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
            "ravage": {
                "available": True,
                "head": "a" * 40,
                "dirty": False,
                "pin_status": "match",
                "expected_head": "a" * 40,
            },
            "strix": {
                "available": True,
                "head": "b" * 40,
                "dirty": False,
                "pin_status": "match",
                "expected_head": "b" * 40,
            },
            "xben": {
                "available": True,
                "head": "c" * 40,
                "dirty": False,
                "pin_status": "match",
                "expected_head": "c" * 40,
            },
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
                head="c" * 40,
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
                head="b" * 40,
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
            "reference_sha256": "sha256:" + "9" * 64,
            "raw_reference_emitted": False,
        },
    }


def _write_preflight(path: Path, payload: dict[str, object] | None = None) -> tuple[Path, str]:
    content = (
        json.dumps(
            _preflight_payload() if payload is None else payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    path.write_bytes(content)
    return path, "sha256:" + hashlib.sha256(content).hexdigest()


def _contract(preflight_digest: str) -> dict[str, object]:
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
                "origin_url": STRIX_CANONICAL_ORIGIN_URL,
                "dirty": False,
            },
            "xben": {
                "commit_sha": "c" * 40,
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
        "preflight_digest": preflight_digest,
    }


@pytest.mark.parametrize("precision", [6, 28, 80])
def test_run_contract_preserves_exact_campaign_money_and_rejects_rounded_substitution(
    precision: int,
) -> None:
    row_cost = "1." + "0" * 35 + "1"
    campaign_cost = "40." + "0" * 34 + "4"
    contract = _contract("sha256:" + "e" * 64)
    contract["budgets"]["per_row"]["max_cost_usd"] = row_cost
    contract["budgets"]["campaign"]["max_cost_usd"] = campaign_cost
    policy = contract["model_gateway"]["policy"]
    policy["campaign_max_cost_usd"] = campaign_cost
    contract["model_gateway"]["policy_sha256"] = (
        "sha256:" + hashlib.sha256(canonical_json(policy).encode()).hexdigest()
    )

    with localcontext() as context:
        context.prec = precision
        round_trip = json.loads(canonical_json(contract))
        assert validate_run_contract(round_trip) == contract
        round_trip["budgets"]["campaign"]["max_cost_usd"] = "40"
        with pytest.raises(PairedXbenProtocolError, match="forty times"):
            validate_run_contract(round_trip)


def test_v2_run_contract_rejects_mutable_or_substituted_execution_inputs() -> None:
    digest = "sha256:" + "e" * 64
    assert validate_run_contract(_contract(digest))["schema_version"] == RUN_CONTRACT_SCHEMA

    mutable_model = _contract(digest)
    mutable_model["model_gateway"]["policy"]["model"] = "gpt-latest"  # type: ignore[index]
    with pytest.raises(PairedXbenProtocolError, match="immutable date-suffixed"):
        validate_run_contract(mutable_model)

    runtime_tamper = _contract(digest)
    runtime_tamper["runtime_manifests"]["strix"]["lockfile_sha256"] = "0" * 64  # type: ignore[index]
    with pytest.raises(PairedXbenProtocolError, match="sha256 digest"):
        validate_run_contract(runtime_tamper)

    source_substitution = _contract(digest)
    source_substitution["sources"]["xben"]["origin_url"] = (  # type: ignore[index]
        "https://example.invalid/substitute.git"
    )
    with pytest.raises(PairedXbenProtocolError, match="origin is not canonical"):
        validate_run_contract(source_substitution)

    private_origin = _contract(digest)
    private_origin["sources"]["ravage"]["origin_url"] = (  # type: ignore[index]
        "https://127.0.0.1/ravage.git"
    )
    with pytest.raises(PairedXbenProtocolError, match="external HTTPS"):
        validate_run_contract(private_origin)

    build_policy_tamper = _contract(digest)
    build_policy_tamper["execution_policy"]["target_build_input_boundary"][  # type: ignore[index]
        "hermetic_rebuild_claimed"
    ] = True
    with pytest.raises(PairedXbenProtocolError, match="paired-image policy"):
        validate_run_contract(build_policy_tamper)

    process_group_tamper = _contract(digest)
    process_group_tamper["execution_policy"]["process_group_policy"] = (  # type: ignore[index]
        "independent_inner_group"
    )
    with pytest.raises(PairedXbenProtocolError, match="paired-image policy"):
        validate_run_contract(process_group_tamper)

    sandbox_tamper = _contract(digest)
    sandbox_tamper["execution_policy"]["evaluator_host"][  # type: ignore[index]
        "sandbox_executable_path"
    ] = "/tmp/operator-supplied-sandbox"
    with pytest.raises(PairedXbenProtocolError, match="host containment policy"):
        validate_run_contract(sandbox_tamper)

    runtime_roots_tamper = _contract(digest)
    runtime_roots_tamper["execution_policy"]["evaluator_host"]["systems"]["strix"][  # type: ignore[index]
        "runtime_read_roots_sha256"
    ] = "sha256:" + "z" * 64
    with pytest.raises(PairedXbenProtocolError, match="runtime read-root digest"):
        validate_run_contract(runtime_roots_tamper)

    mutable_image = _contract(digest)
    mutable_image["oci_images"]["strix_sandbox"] = "registry.invalid/strix:latest"  # type: ignore[index]
    with pytest.raises(PairedXbenProtocolError, match="digest-pinned OCI"):
        validate_run_contract(mutable_image)

    helper_image_id_tamper = _contract(digest)
    helper_image_id_tamper["target_helper_image_ids"]["target_probe"] = "f" * 64  # type: ignore[index]
    with pytest.raises(PairedXbenProtocolError, match="local sha256 image ID"):
        validate_run_contract(helper_image_id_tamper)

    pricing_origin_tamper = _contract(digest)
    pricing_origin_tamper["model_gateway"]["pricing_source"]["url"] = (  # type: ignore[index]
        "https://example.invalid/gpt-test.md"
    )
    with pytest.raises(PairedXbenProtocolError, match="canonical official"):
        validate_run_contract(pricing_origin_tamper)

    pricing_time_tamper = _contract(digest)
    pricing_time_tamper["model_gateway"]["pricing_source"][  # type: ignore[index]
        "retrieved_at"
    ] = "2026-09-01T08:00:00+08:00"
    with pytest.raises(PairedXbenProtocolError, match="must be UTC"):
        validate_run_contract(pricing_time_tamper)


def _write_test_verifiers(tmp_path: Path) -> tuple[Path, Path, Path]:
    drand = tmp_path / "test-drandverify"
    drand.write_text(
        f"""#!{sys.executable}
import hashlib
import json
import pathlib
import sys

if "--self-info" in sys.argv:
    print(json.dumps({{
        "schema_version": "ravage.paired-xben.drand-verifier-self.v1",
        "library_module": "github.com/drand/drand/v2",
        "library_version": "v2.1.6",
        "source_bundle_sha256": "{drand_source_bundle_digest()}",
    }}))
    raise SystemExit(0)

def value(flag):
    return sys.argv[sys.argv.index(flag) + 1]

chain_path = pathlib.Path(value("--chain-info"))
beacon_path = pathlib.Path(value("--beacon"))
chain = chain_path.read_bytes()
beacon_bytes = beacon_path.read_bytes()
beacon = json.loads(beacon_bytes)
print(json.dumps({{
    "schema_version": "ravage.paired-xben.drand-verification.v1",
    "verified": True,
    "library_module": "github.com/drand/drand/v2",
    "library_version": "v2.1.6",
    "chain_hash": value("--expected-chain-hash"),
    "round": int(value("--expected-round")),
    "scheme": "pedersen-bls-chained",
    "randomness": beacon["randomness"],
    "chain_info_sha256": "sha256:" + hashlib.sha256(chain).hexdigest(),
    "beacon_sha256": "sha256:" + hashlib.sha256(beacon_bytes).hexdigest(),
    "public_key_sha256": "sha256:" + "6" * 64,
}}))
""",
        encoding="utf-8",
    )
    os.chmod(drand, 0o700)
    cosign = tmp_path / "test-cosign"
    cosign.write_text(
        f"""#!{sys.executable}
import sys
if len(sys.argv) > 1 and sys.argv[1] == "version":
    print("GitVersion: v3.1.3")
    raise SystemExit(0)
if len(sys.argv) > 1 and sys.argv[1] == "verify-blob":
    print("Verified OK")
    raise SystemExit(0)
raise SystemExit(2)
""",
        encoding="utf-8",
    )
    os.chmod(cosign, 0o700)
    trusted_root = tmp_path / "trusted-root.json"
    trusted_root.write_text("{}\n", encoding="utf-8")
    return drand, cosign, trusted_root


def _commit(
    root: Path,
    *,
    campaign_id: str = "paired-xben-test",
    created_at: str = CREATED_AT,
) -> dict[str, object]:
    preflight, digest = _write_preflight(root.parent / f"{root.name}-preflight.json")
    drand, cosign, trusted_root = _write_test_verifiers(root.parent)
    return create_commitment(
        root,
        campaign_id=campaign_id,
        preflight_json_path=preflight,
        eligible_case_ids=_pool(),
        chain_hash=CHAIN_HASH,
        chain_genesis_time=CHAIN_GENESIS_TIME,
        chain_period_seconds=CHAIN_PERIOD_SECONDS,
        observed_latest_round=LATEST_ROUND,
        draw_round=DRAW_ROUND,
        run_contract=_contract(digest),
        drand_verifier_binary_path=drand,
        cosign_binary_path=cosign,
        sigstore_trusted_root_path=trusted_root,
        publication_certificate_identity=CERTIFICATE_IDENTITY,
        publication_certificate_oidc_issuer=CERTIFICATE_ISSUER,
        created_at=created_at,
    )


def _write_resolution_inputs(
    tmp_path: Path,
    commitment: dict[str, object],
) -> tuple[Path, Path, Path, Path]:
    signature = bytes.fromhex("ab" * 96)
    beacon_path = tmp_path / "input-beacon.json"
    beacon_path.write_text(
        json.dumps(
            {
                "round": DRAW_ROUND,
                "signature": signature.hex(),
                "previous_signature": "cd" * 96,
                "randomness": hashlib.sha256(signature).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    secondary_beacon_path = tmp_path / "input-beacon-secondary.json"
    secondary_payload = json.loads(beacon_path.read_text(encoding="utf-8"))
    secondary_beacon_path.write_text(json.dumps(secondary_payload), encoding="utf-8")
    chain_info_path = tmp_path / "chain-info.json"
    chain_info_path.write_text("{}\n", encoding="utf-8")
    anchor_path = tmp_path / "publication-anchor.json"
    anchor_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "tlogEntries": [
                        {
                            "integratedTime": str(PUBLICATION_EPOCH),
                            "logIndex": "7",
                            "inclusionProof": {"checkpoint": {"envelope": "test-proof"}},
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
    return beacon_path, secondary_beacon_path, chain_info_path, anchor_path


def _fake_rfc3161_timestamp(time_text: bytes = b"20260102000000Z") -> str:
    def der(tag: int, value: bytes) -> bytes:
        if len(value) < 128:
            length = bytes([len(value)])
        else:
            raw = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
            length = bytes([0x80 | len(raw)]) + raw
        return bytes([tag]) + length + value

    integer = der(0x02, b"\x01")
    oid = der(0x06, b"\x2a\x03")
    tst_info = der(
        0x30,
        integer + oid + der(0x30, b"") + integer + der(0x18, time_text),
    )
    encapsulated = der(0x30, oid + der(0xA0, der(0x04, tst_info)))
    signed_data = der(0x30, integer + der(0x31, b"") + encapsulated)
    content_info = der(0x30, oid + der(0xA0, signed_data))
    response = der(0x30, der(0x30, integer) + content_info)
    return base64.b64encode(response).decode("ascii")


def _resolve(root: Path, tmp_path: Path) -> dict[str, object]:
    commitment = json.loads((root / "commitment.json").read_text(encoding="utf-8"))
    _beacon, _secondary, chain_info, anchor = _write_resolution_inputs(tmp_path, commitment)
    return resolve_commitment(
        root,
        drand_chain_info_json_path=chain_info,
        publication_anchor_json_path=anchor,
        eligible_case_ids=_pool(),
        expected_commitment_digest=str(commitment["document_digest"]),
    )


def test_commitment_is_create_only_and_binds_exact_canonical_pool(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    commitment = _commit(root)

    assert commitment["sample_size"] == 20
    assert commitment["systems"] == ["ravage", "strix"]
    pool = commitment["eligible_pool"]
    assert isinstance(pool, dict)
    assert pool["count"] == 104
    assert pool["case_ids"] == list(_pool())
    assert pool["digest"] == eligible_pool_digest(_pool())
    preflight_bytes = (root / "preflight-source.json").read_bytes()
    preflight_digest = "sha256:" + hashlib.sha256(preflight_bytes).hexdigest()
    assert commitment["run_contract"] == _contract(preflight_digest)
    assert commitment["preflight_source"] == {
        "file": "preflight-source.json",
        "sha256": preflight_digest,
    }
    assert verify_campaign(root)["phase"] == "committed"
    assert verify_campaign(root)["claim_ready"] is False

    with pytest.raises(PairedXbenProtocolError, match="reuse protocol directory"):
        _commit(root)


def test_commitment_requires_actual_ready_preflight_and_matching_sources(tmp_path: Path) -> None:
    preflight, digest = _write_preflight(tmp_path / "preflight.json")
    common = {
        "eligible_case_ids": _pool(),
        "chain_hash": CHAIN_HASH,
        "chain_genesis_time": CHAIN_GENESIS_TIME,
        "chain_period_seconds": CHAIN_PERIOD_SECONDS,
        "observed_latest_round": LATEST_ROUND,
        "draw_round": DRAW_ROUND,
        "created_at": CREATED_AT,
    }
    with pytest.raises(PairedXbenProtocolError, match="digest does not match"):
        create_commitment(
            tmp_path / "wrong-digest",
            campaign_id="paired-xben-wrong-digest",
            preflight_json_path=preflight,
            run_contract=_contract("sha256:" + "0" * 64),
            **common,
        )

    blocked_payload = _preflight_payload()
    blocked_payload["blocked"] = True
    blocked_payload["block_reasons"] = ["docker_daemon_unhealthy"]
    blocked, blocked_digest = _write_preflight(tmp_path / "blocked.json", blocked_payload)
    with pytest.raises(PairedXbenProtocolError, match="preflight is blocked"):
        create_commitment(
            tmp_path / "blocked",
            campaign_id="paired-xben-blocked",
            preflight_json_path=blocked,
            run_contract=_contract(blocked_digest),
            **common,
        )

    unready_payload = _preflight_payload()
    unready_payload["docker"]["daemon_responsive"] = False  # type: ignore[index]
    unready, unready_digest = _write_preflight(tmp_path / "unready.json", unready_payload)
    with pytest.raises(PairedXbenProtocolError, match="docker gate is not ready"):
        create_commitment(
            tmp_path / "unready",
            campaign_id="paired-xben-unready",
            preflight_json_path=unready,
            run_contract=_contract(unready_digest),
            **common,
        )

    mismatch_payload = _preflight_payload()
    mismatch_payload["git"]["ravage"]["head"] = "8" * 40  # type: ignore[index]
    mismatch, mismatch_digest = _write_preflight(tmp_path / "mismatch.json", mismatch_payload)
    with pytest.raises(PairedXbenProtocolError, match="ravage source binding"):
        create_commitment(
            tmp_path / "mismatch",
            campaign_id="paired-xben-mismatch",
            preflight_json_path=mismatch,
            run_contract=_contract(mismatch_digest),
            **common,
        )


def test_offline_verifier_rechecks_retained_preflight_bytes(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    _commit(root)
    retained = root / "preflight-source.json"
    retained.write_bytes(retained.read_bytes() + b" ")

    with pytest.raises(PairedXbenProtocolError, match="preflight digest mismatch"):
        verify_campaign(root)


def test_commitment_rejects_subset_dirty_source_and_unresolved_budget(tmp_path: Path) -> None:
    preflight, digest = _write_preflight(tmp_path / "preflight.json")
    with pytest.raises(PairedXbenProtocolError, match="exactly canonical"):
        create_commitment(
            tmp_path / "subset",
            campaign_id="paired-xben-subset",
            preflight_json_path=preflight,
            eligible_case_ids=_pool()[:-1],
            chain_hash=CHAIN_HASH,
            chain_genesis_time=CHAIN_GENESIS_TIME,
            chain_period_seconds=CHAIN_PERIOD_SECONDS,
            observed_latest_round=LATEST_ROUND,
            draw_round=DRAW_ROUND,
            run_contract=_contract(digest),
            created_at=CREATED_AT,
        )

    dirty = _contract(digest)
    dirty["sources"]["ravage"]["dirty"] = True  # type: ignore[index]
    with pytest.raises(PairedXbenProtocolError, match="dirty=false"):
        create_commitment(
            tmp_path / "dirty",
            campaign_id="paired-xben-dirty",
            preflight_json_path=preflight,
            eligible_case_ids=_pool(),
            chain_hash=CHAIN_HASH,
            chain_genesis_time=CHAIN_GENESIS_TIME,
            chain_period_seconds=CHAIN_PERIOD_SECONDS,
            observed_latest_round=LATEST_ROUND,
            draw_round=DRAW_ROUND,
            run_contract=dirty,
            created_at=CREATED_AT,
        )

    unresolved = _contract(digest)
    unresolved["budgets"]["per_row"]["max_cost_usd"] = None  # type: ignore[index]
    with pytest.raises(PairedXbenProtocolError, match="canonical decimal"):
        create_commitment(
            tmp_path / "unresolved",
            campaign_id="paired-xben-unresolved",
            preflight_json_path=preflight,
            eligible_case_ids=_pool(),
            chain_hash=CHAIN_HASH,
            chain_genesis_time=CHAIN_GENESIS_TIME,
            chain_period_seconds=CHAIN_PERIOD_SECONDS,
            observed_latest_round=LATEST_ROUND,
            draw_round=DRAW_ROUND,
            run_contract=unresolved,
            created_at=CREATED_AT,
        )


def test_commitment_requires_round_future_by_index_and_precommit_time(tmp_path: Path) -> None:
    preflight, digest = _write_preflight(tmp_path / "preflight.json")
    common = {
        "campaign_id": "paired-xben-round",
        "preflight_json_path": preflight,
        "eligible_case_ids": _pool(),
        "chain_hash": CHAIN_HASH,
        "chain_genesis_time": CHAIN_GENESIS_TIME,
        "chain_period_seconds": CHAIN_PERIOD_SECONDS,
        "run_contract": _contract(digest),
        "created_at": CREATED_AT,
    }
    with pytest.raises(PairedXbenProtocolError, match="later than the observed"):
        create_commitment(
            tmp_path / "past-index",
            observed_latest_round=DRAW_ROUND,
            draw_round=DRAW_ROUND,
            **common,
        )
    with pytest.raises(PairedXbenProtocolError, match="after the recorded commitment time"):
        create_commitment(
            tmp_path / "past-time",
            observed_latest_round=1,
            draw_round=2,
            **common,
        )


def test_resolution_reproduces_uniform_rank_and_counterbalanced_schedule(
    tmp_path: Path,
) -> None:
    root = tmp_path / "campaign"
    _commit(root)
    selection = _resolve(root, tmp_path)

    selected = selection["selected_case_ids"]
    ranking = selection["case_ranking"]
    schedule = selection["schedule"]
    assert isinstance(selected, list) and len(selected) == 20 and len(set(selected)) == 20
    assert isinstance(ranking, list) and len(ranking) == 104
    assert selected == [row["case_id"] for row in ranking[:20]]
    assert isinstance(schedule, list) and len(schedule) == 40
    assert [row["slot"] for row in schedule] == list(range(1, 41))

    first_systems: list[str] = []
    for offset in range(0, 40, 2):
        first, second = schedule[offset : offset + 2]
        assert first["case_id"] == second["case_id"]
        assert {first["system"], second["system"]} == {"ravage", "strix"}
        assert first["pair_index"] == second["pair_index"] == offset // 2 + 1
        first_systems.append(first["system"])
    assert first_systems.count("ravage") == first_systems.count("strix") == 10

    verification = verify_campaign(root)
    assert verification["structurally_valid"] is True
    assert verification["claim_ready"] is False
    assert verification["beacon_authenticity_verified"] is True
    assert verification["publication_anchor_verified"] is True
    assert verification["scheduled_primary_attempts"] == 40


def test_selection_has_a_cross_implementation_known_answer(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    commitment = _commit(root)
    selection = _resolve(root, tmp_path)

    assert commitment["eligible_pool"]["digest"] == (
        "sha256:f964032619ecd580874896f58b42cfc1ef0c7d24adbc99563dc5b1a0e38dea88"
    )
    assert selection["draw_key_sha256"] == (
        "sha256:aeab88bf92b6b623e4da3cd50ce55f8a078deed1a9ebb97672f6385263450e88"
    )
    assert selection["selected_case_ids"] == [
        "XBEN-021-24",
        "XBEN-051-24",
        "XBEN-067-24",
        "XBEN-092-24",
        "XBEN-030-24",
        "XBEN-081-24",
        "XBEN-100-24",
        "XBEN-078-24",
        "XBEN-013-24",
        "XBEN-024-24",
        "XBEN-102-24",
        "XBEN-083-24",
        "XBEN-103-24",
        "XBEN-035-24",
        "XBEN-084-24",
        "XBEN-028-24",
        "XBEN-059-24",
        "XBEN-061-24",
        "XBEN-090-24",
        "XBEN-010-24",
    ]


def test_resolution_refuses_commitment_or_population_drift_before_writing(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    commitment = _commit(root)
    _beacon, _secondary, chain_info, anchor = _write_resolution_inputs(tmp_path, commitment)

    with pytest.raises(PairedXbenProtocolError, match="expected digest"):
        resolve_commitment(
            root,
            drand_chain_info_json_path=chain_info,
            publication_anchor_json_path=anchor,
            eligible_case_ids=_pool(),
            expected_commitment_digest="sha256:" + "0" * 64,
        )
    assert not (root / "resolution").exists()

    changed = list(_pool())
    changed[-1] = "XBEN-103-24"
    with pytest.raises(PairedXbenProtocolError, match="duplicate eligible"):
        resolve_commitment(
            root,
            drand_chain_info_json_path=chain_info,
            publication_anchor_json_path=anchor,
            eligible_case_ids=changed,
            expected_commitment_digest=str(commitment["document_digest"]),
        )
    assert not (root / "resolution").exists()


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("chain_hash", "22" * 32, "required schema"),
        ("round", DRAW_ROUND + 1, "committed round"),
        ("randomness", "00" * 32, "SHA-256"),
        ("source_url", "https://example.org/beacon", "required schema"),
    ],
)
def test_resolution_rejects_invalid_beacon_evidence(
    tmp_path: Path,
    field: str,
    replacement: object,
    message: str,
) -> None:
    root = tmp_path / "campaign"
    commitment = _commit(root)
    beacon, _secondary, chain_info, anchor = _write_resolution_inputs(tmp_path, commitment)
    payload = json.loads(beacon.read_text(encoding="utf-8"))
    payload[field] = replacement
    beacon.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PairedXbenProtocolError, match=message):
        resolve_commitment(
            root,
            drand_chain_info_json_path=chain_info,
            publication_anchor_json_path=anchor,
            eligible_case_ids=_pool(),
            expected_commitment_digest=str(commitment["document_digest"]),
        )


def test_resolution_is_create_only_and_offline_verifier_detects_tampering(
    tmp_path: Path,
) -> None:
    root = tmp_path / "campaign"
    commitment = _commit(root)
    _beacon, _secondary, chain_info, anchor = _write_resolution_inputs(tmp_path, commitment)
    resolve_commitment(
        root,
        drand_chain_info_json_path=chain_info,
        publication_anchor_json_path=anchor,
        eligible_case_ids=_pool(),
        expected_commitment_digest=str(commitment["document_digest"]),
    )
    with pytest.raises(PairedXbenProtocolError, match="reuse protocol directory"):
        resolve_commitment(
            root,
            drand_chain_info_json_path=chain_info,
            publication_anchor_json_path=anchor,
            eligible_case_ids=_pool(),
            expected_commitment_digest=str(commitment["document_digest"]),
        )

    selection_path = root / "resolution" / "selection.json"
    payload = json.loads(selection_path.read_text(encoding="utf-8"))
    payload["schedule"][0]["system"] = "forged"
    selection_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PairedXbenProtocolError, match="digest mismatch"):
        verify_campaign(root)


def test_ground_truth_cannot_enter_commitment(tmp_path: Path) -> None:
    preflight, digest = _write_preflight(tmp_path / "preflight.json")
    contract = _contract(digest)
    contract["expected_flags"] = ["flag{do-not-store-this}"]
    with pytest.raises(PairedXbenProtocolError, match="frozen schema|ground truth"):
        create_commitment(
            tmp_path / "campaign",
            campaign_id="paired-xben-secrets",
            preflight_json_path=preflight,
            eligible_case_ids=_pool(),
            chain_hash=CHAIN_HASH,
            chain_genesis_time=CHAIN_GENESIS_TIME,
            chain_period_seconds=CHAIN_PERIOD_SECONDS,
            observed_latest_round=LATEST_ROUND,
            draw_round=DRAW_ROUND,
            run_contract=contract,
            created_at=CREATED_AT,
        )


def test_primary_matrix_is_all_at_once_single_use_and_reruns_are_unscored(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    _commit(root)
    _resolve(root, tmp_path)

    with pytest.raises(PairedXbenProtocolError, match="individual primary reservation is disabled"):
        create_primary_attempt_manifest(root, slot_id="primary-001")
    assert not (root / "attempts").exists()

    marker = reserve_primary_matrix(root, created_at=RETRIEVED_AT)
    marker_payload = json.loads(marker.read_text(encoding="utf-8"))
    assert marker_payload["scheduled_primary_attempts"] == 40
    assert len(marker_payload["attempts"]) == 40
    assert len({entry["attempt_document_digest"] for entry in marker_payload["attempts"]}) == 40
    primary_root = root / "attempts" / "primary"
    slots = sorted(path.name for path in primary_root.iterdir())
    assert slots == [f"primary-{index:03d}" for index in range(1, 41)]
    assert all((primary_root / slot / "attempt.json").is_file() for slot in slots)
    assert all((primary_root / slot / "artifacts").is_dir() for slot in slots)

    with pytest.raises(PairedXbenProtocolError, match="already been reserved"):
        reserve_primary_matrix(root)
    with pytest.raises(PairedXbenProtocolError, match="individual primary reservation is disabled"):
        create_primary_attempt_manifest(root, slot_id="primary-002")

    rerun = create_rerun_attempt_manifest(
        root,
        rerun_id="diagnostic-001",
        primary_slot_id="primary-001",
        reason="inspect a provider transport failure; never replace the primary score",
        created_at=RETRIEVED_AT,
    )
    rerun_payload = json.loads(rerun.read_text(encoding="utf-8"))
    assert rerun_payload["purpose"] == "diagnostic_rerun"
    assert rerun_payload["score_eligible"] is False
    assert "/attempts/reruns/" in str(rerun)

    verification = verify_campaign(root)
    assert verification["recorded_primary_attempts"] == 40
    assert verification["missing_primary_attempts"] == 0
    assert verification["primary_matrix_reserved"] is True
    assert verification["primary_matrix_digest"] == marker_payload["document_digest"]
    assert verification["diagnostic_reruns"] == 1
    complete = verify_campaign(root, require_all_primary_attempts=True)
    assert complete["recorded_primary_attempts"] == 40


def test_rerun_requires_retained_primary_parent(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    _commit(root)
    _resolve(root, tmp_path)

    with pytest.raises(PairedXbenProtocolError, match="has not been reserved"):
        create_rerun_attempt_manifest(
            root,
            rerun_id="diagnostic-001",
            primary_slot_id="primary-001",
            reason="diagnostic only",
        )


def test_attempt_creation_refuses_planted_symlink_parent(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    _commit(root)
    _resolve(root, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "attempts").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PairedXbenProtocolError, match="real directory"):
        reserve_primary_matrix(root)
    assert list(outside.iterdir()) == []


def test_incomplete_primary_matrix_is_permanently_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    _commit(root)
    _resolve(root, tmp_path)
    partial = root / "attempts" / "primary" / "primary-001"
    (partial / "artifacts").mkdir(parents=True)

    with pytest.raises(PairedXbenProtocolError, match="reuse protocol directory"):
        reserve_primary_matrix(root)
    with pytest.raises(PairedXbenProtocolError, match="incomplete and cannot be resumed"):
        verify_campaign(root)
    assert not (root / "attempts" / "primary-reservation.json").exists()


def test_resolution_rejects_unusable_rfc3161_time_and_legacy_bundle(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    commitment = _commit(root)
    _beacon, _secondary, chain_info, anchor = _write_resolution_inputs(tmp_path, commitment)
    payload = json.loads(anchor.read_text(encoding="utf-8"))
    payload["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0][
        "signedTimestamp"
    ] = _fake_rfc3161_timestamp(b"20260101000000Z")
    anchor.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PairedXbenProtocolError, match="RFC3161 time must be after"):
        resolve_commitment(
            root,
            drand_chain_info_json_path=chain_info,
            publication_anchor_json_path=anchor,
            eligible_case_ids=_pool(),
            expected_commitment_digest=str(commitment["document_digest"]),
        )

    payload["mediaType"] = "application/vnd.dev.cosign.simplesigning.v1+json"
    anchor.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PairedXbenProtocolError, match="standardized Sigstore v0.3"):
        resolve_commitment(
            root,
            drand_chain_info_json_path=chain_info,
            publication_anchor_json_path=anchor,
            eligible_case_ids=_pool(),
            expected_commitment_digest=str(commitment["document_digest"]),
        )


def test_resolution_requires_two_distinct_matching_official_relays(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    commitment = _commit(root)
    beacon, secondary, chain_info, anchor = _write_resolution_inputs(tmp_path, commitment)
    resolve_commitment(
        root,
        drand_chain_info_json_path=chain_info,
        publication_anchor_json_path=anchor,
        expected_commitment_digest=str(commitment["document_digest"]),
    )
    fetch = json.loads((root / "resolution" / "drand-fetch.json").read_text(encoding="utf-8"))
    assert [source["source_url"] for source in fetch["relay_sources"]] == [
        f"https://api.drand.sh/{CHAIN_HASH}/public/{DRAW_ROUND}",
        f"https://drand.cloudflare.com/{CHAIN_HASH}/public/{DRAW_ROUND}",
    ]
    assert (root / "resolution" / "beacon-source.json").read_bytes() == beacon.read_bytes()
    assert (
        root / "resolution" / "beacon-source-secondary.json"
    ).read_bytes() == secondary.read_bytes()

    root = tmp_path / "campaign-disagreement"
    commitment = _commit(root, campaign_id="paired-xben-disagreement")
    _beacon, secondary, chain_info, anchor = _write_resolution_inputs(tmp_path, commitment)
    payload = json.loads(secondary.read_text(encoding="utf-8"))
    signature = bytes.fromhex("ac" * 96)
    payload["signature"] = signature.hex()
    payload["randomness"] = hashlib.sha256(signature).hexdigest()
    secondary.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PairedXbenProtocolError, match="relay responses disagree"):
        resolve_commitment(
            root,
            drand_chain_info_json_path=chain_info,
            publication_anchor_json_path=anchor,
            expected_commitment_digest=str(commitment["document_digest"]),
        )


def test_attempt_reservation_reverifies_retained_binary_hashes(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    _commit(root)
    _resolve(root, tmp_path)
    cosign = root / "verifiers" / "cosign"
    cosign.write_bytes(cosign.read_bytes() + b"\n# tampered\n")
    os.chmod(cosign, 0o700)

    with pytest.raises(PairedXbenProtocolError, match="cosign verifier differs"):
        reserve_primary_matrix(root)
    assert not (root / "attempts").exists()


def test_attempt_reservation_reverifies_both_raw_relays_and_fixed_provenance(
    tmp_path: Path,
) -> None:
    raw_root = tmp_path / "raw-campaign"
    _commit(raw_root, campaign_id="paired-xben-raw-tamper")
    _resolve(raw_root, tmp_path)
    secondary_path = raw_root / "resolution" / "beacon-source-secondary.json"
    secondary = json.loads(secondary_path.read_text(encoding="utf-8"))
    forged_signature = bytes.fromhex("ee" * 96)
    secondary["signature"] = forged_signature.hex()
    secondary["randomness"] = hashlib.sha256(forged_signature).hexdigest()
    secondary_path.write_text(json.dumps(secondary), encoding="utf-8")

    with pytest.raises(PairedXbenProtocolError, match="raw response|relay responses disagree"):
        reserve_primary_matrix(raw_root)
    assert not (raw_root / "attempts").exists()

    provenance_root = tmp_path / "provenance-campaign"
    _commit(provenance_root, campaign_id="paired-xben-provenance-tamper")
    _resolve(provenance_root, tmp_path)
    fetch_path = provenance_root / "resolution" / "drand-fetch.json"
    fetch = json.loads(fetch_path.read_text(encoding="utf-8"))
    fetch["relay_sources"][0]["source_url"] = (
        f"https://api2.drand.sh/{CHAIN_HASH}/public/{DRAW_ROUND}"
    )
    body = {key: value for key, value in fetch.items() if key != "document_digest"}
    fetch["document_digest"] = "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()
    fetch_path.write_text(canonical_json(fetch) + "\n", encoding="utf-8")

    with pytest.raises(PairedXbenProtocolError, match="provenance is not resolver-fixed"):
        reserve_primary_matrix(provenance_root)
    assert not (provenance_root / "attempts").exists()


def test_draw_seed_excludes_operator_campaign_label_and_timestamp(tmp_path: Path) -> None:
    first_root = tmp_path / "campaign-a"
    second_root = tmp_path / "campaign-b"
    first_commitment = _commit(
        first_root,
        campaign_id="paired-xben-campaign-a",
        created_at="2026-01-01T00:00:00+00:00",
    )
    second_commitment = _commit(
        second_root,
        campaign_id="paired-xben-campaign-b",
        created_at="2026-01-01T12:00:00+00:00",
    )
    first = _resolve(first_root, tmp_path)
    second = _resolve(second_root, tmp_path)

    assert first_commitment["document_digest"] != second_commitment["document_digest"]
    assert first["draw_key_sha256"] == second["draw_key_sha256"]
    assert first["selected_case_ids"] == second["selected_case_ids"]
    assert first["pair_order"] == second["pair_order"]


def test_commitment_rejects_unbound_runtime_source_identities(tmp_path: Path) -> None:
    xben_payload = _preflight_payload()
    xben_payload["xben"]["source_binding"]["origin_matches_expected"] = False  # type: ignore[index]
    xben, xben_digest = _write_preflight(tmp_path / "xben-unbound.json", xben_payload)
    with pytest.raises(PairedXbenProtocolError, match="XBEN source is not canonically bound"):
        create_commitment(
            tmp_path / "xben-unbound",
            campaign_id="paired-xben-xben-unbound",
            preflight_json_path=xben,
            eligible_case_ids=_pool(),
            chain_hash=CHAIN_HASH,
            chain_genesis_time=CHAIN_GENESIS_TIME,
            chain_period_seconds=CHAIN_PERIOD_SECONDS,
            observed_latest_round=LATEST_ROUND,
            draw_round=DRAW_ROUND,
            run_contract=_contract(xben_digest),
            created_at=CREATED_AT,
        )

    strix_payload = _preflight_payload()
    strix_payload["strix"]["identity_verified"] = False  # type: ignore[index]
    strix, strix_digest = _write_preflight(tmp_path / "strix-unbound.json", strix_payload)
    with pytest.raises(PairedXbenProtocolError, match="Strix executable is unverified"):
        create_commitment(
            tmp_path / "strix-unbound",
            campaign_id="paired-xben-strix-unbound",
            preflight_json_path=strix,
            eligible_case_ids=_pool(),
            chain_hash=CHAIN_HASH,
            chain_genesis_time=CHAIN_GENESIS_TIME,
            chain_period_seconds=CHAIN_PERIOD_SECONDS,
            observed_latest_round=LATEST_ROUND,
            draw_round=DRAW_ROUND,
            run_contract=_contract(strix_digest),
            created_at=CREATED_AT,
        )


def test_commitment_rejects_cosign_with_known_identity_bypass(tmp_path: Path) -> None:
    preflight, digest = _write_preflight(tmp_path / "preflight.json")
    drand, cosign, trusted_root = _write_test_verifiers(tmp_path)
    cosign.write_text(
        cosign.read_text(encoding="utf-8").replace("v3.1.3", "v3.1.2"),
        encoding="utf-8",
    )
    os.chmod(cosign, 0o700)
    campaign = tmp_path / "old-cosign"

    with pytest.raises(PairedXbenProtocolError, match="known verification bypass"):
        create_commitment(
            campaign,
            campaign_id="paired-xben-old-cosign",
            preflight_json_path=preflight,
            eligible_case_ids=_pool(),
            chain_hash=CHAIN_HASH,
            chain_genesis_time=CHAIN_GENESIS_TIME,
            chain_period_seconds=CHAIN_PERIOD_SECONDS,
            observed_latest_round=LATEST_ROUND,
            draw_round=DRAW_ROUND,
            run_contract=_contract(digest),
            drand_verifier_binary_path=drand,
            cosign_binary_path=cosign,
            sigstore_trusted_root_path=trusted_root,
            publication_certificate_identity=CERTIFICATE_IDENTITY,
            publication_certificate_oidc_issuer=CERTIFICATE_ISSUER,
            created_at=CREATED_AT,
        )
    assert not campaign.exists()


def test_commitment_kills_verifier_output_beyond_the_bound(tmp_path: Path) -> None:
    preflight, digest = _write_preflight(tmp_path / "preflight.json")
    drand, cosign, trusted_root = _write_test_verifiers(tmp_path)
    cosign.write_text(
        f"#!{sys.executable}\nprint('x' * 70000)\n",
        encoding="utf-8",
    )
    os.chmod(cosign, 0o700)

    with pytest.raises(PairedXbenProtocolError, match="output exceeds the byte limit"):
        create_commitment(
            tmp_path / "oversized-output",
            campaign_id="paired-xben-oversized-output",
            preflight_json_path=preflight,
            eligible_case_ids=_pool(),
            chain_hash=CHAIN_HASH,
            chain_genesis_time=CHAIN_GENESIS_TIME,
            chain_period_seconds=CHAIN_PERIOD_SECONDS,
            observed_latest_round=LATEST_ROUND,
            draw_round=DRAW_ROUND,
            run_contract=_contract(digest),
            drand_verifier_binary_path=drand,
            cosign_binary_path=cosign,
            sigstore_trusted_root_path=trusted_root,
            publication_certificate_identity=CERTIFICATE_IDENTITY,
            publication_certificate_oidc_issuer=CERTIFICATE_ISSUER,
            created_at=CREATED_AT,
        )
