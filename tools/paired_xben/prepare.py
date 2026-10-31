"""Create-only production preparation for a paired XBEN campaign.

This command is deliberately before the randomness commitment boundary.  It
does not fetch a beacon, select cases, pull or build OCI images, or contact a
model provider.  It turns an exact, secret-free local request into a retained
preflight, a validated run contract, and the machine-local executor config.
When an input is absent or mutable it retains a blocked preparation report and
does not emit artifacts that could be mistaken for a runnable contract.
"""

# ruff: noqa: C901,D202,D213,EM101,EM102,PLR0912,PLR0913,PLR0915,PLR2004,TRY003,TRY301

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Final, cast
from urllib.parse import urlsplit

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[2]
PACKAGE_SOURCE: Final = REPOSITORY_ROOT / "packages" / "ravage" / "src"
if str(PACKAGE_SOURCE) not in sys.path:
    sys.path.insert(0, str(PACKAGE_SOURCE))

from ravage.xben_parts.comparison_adapters import (  # noqa: E402
    ADAPTER_SCHEMA_VERSION,
    ADAPTER_VERSION,
    RUNTIME_ENVIRONMENT_SCHEMA_VERSION,
    AdapterConfigurationError,
    PinnedAgentRuntime,
    verify_pinned_runtime,
)
from ravage.xben_parts.comparison_model_gateway import (  # noqa: E402
    MODEL_GATEWAY_CAMPAIGN_SCHEMA,
    MODEL_GATEWAY_SCHEMA,
    ModelGatewayPolicy,
    ModelPricing,
)
from ravage.xben_parts.comparison_target import (  # noqa: E402
    CompatibilityPatchCatalog,
    SourceMaterializationError,
    _resolve_compatibility_patch_catalog,
)

from tools.paired_xben.authenticity import (  # noqa: E402
    AuthenticityError,
    prepare_authenticity_policy,
)
from tools.paired_xben.preflight import (  # noqa: E402
    DEFAULT_GIT_EXECUTABLE,
    STRIX_CANONICAL_ORIGIN_URL,
    XBEN_CANONICAL_ORIGIN_URL,
    PreflightConfigurationError,
    canonical_json_bytes,
    collect_preflight,
    write_preflight,
)
from tools.paired_xben.protocol import (  # noqa: E402
    RUN_CONTRACT_SCHEMA,
    PairedXbenProtocolError,
    canonical_json,
    validate_run_contract,
)

PREPARE_REQUEST_SCHEMA: Final = "ravage.paired-xben.prepare-request.v1"
PREPARATION_SCHEMA: Final = "ravage.paired-xben.production-preparation.v1"
EXECUTOR_CONFIG_SCHEMA: Final = "ravage.paired-xben.executor-config.v1"
PREPARATION_FILE: Final = "preparation.json"
RUN_CONTRACT_FILE: Final = "run-contract.json"
EXECUTOR_CONFIG_FILE: Final = "executor-config.json"
STATUS_FILE: Final = "STATUS.md"
HASH_MANIFEST_FILE: Final = "ARTIFACTS.sha256"
PRICING_SOURCE_FILE: Final = "inputs/model-pricing-source.md"
PRICING_SOURCE_METADATA_FILE: Final = "inputs/model-pricing-source.json"
WEBSITE_REFERENCE_FILE: Final = "inputs/website-reference.json"
AUTHENTICITY_POLICY_FILE: Final = "inputs/authenticity-policy.json"
COSIGN_RELEASE_BUNDLE_FILE: Final = "inputs/cosign-release.sigstore.json"
SIGSTORE_TRUSTED_ROOT_FILE: Final = "inputs/sigstore-trusted-root.json"
PREPARE_REQUEST_FILE: Final = "prepare-request.json"
COSIGN_RELEASE_IDENTITY: Final = "keyless@projectsigstore.iam.gserviceaccount.com"
COSIGN_RELEASE_OIDC_ISSUER: Final = "https://accounts.google.com"
GITHUB_ACTIONS_OIDC_ISSUER: Final = "https://token.actions.githubusercontent.com"

SYSTEMS: Final = ("ravage", "strix")
OCI_ROLES: Final = ("ravage_tool", "strix_sandbox", "target_gateway", "target_probe")
EVALUATOR_COMPONENTS: Final = (
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

_SHA256_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_RE: Final = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_OCI_RE: Final = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_ENV_RE: Final = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_MONEY_RE: Final = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
_PRICE_RE: Final = re.compile(r"\$\s*([0-9]+(?:\.[0-9]+)?)")
_SECRET_KEYS: Final = frozenset(
    {"apikey", "authorization", "credential", "password", "secret", "token", "value"}
)
_MAX_CONFIG_BYTES: Final = 256 * 1024
_MAX_INPUT_FILE_BYTES: Final = 16 * 1024 * 1024
_MAX_WEBSITE_FILES: Final = 100_000
_MAX_WEBSITE_BYTES: Final = 4 * 1024 * 1024 * 1024
_MAX_SUBPROCESS_OUTPUT: Final = 64 * 1024
_EXPECTED_TOP_LEVEL: Final = {
    "schema_version",
    "sources",
    "runtimes",
    "compatibility_catalog",
    "website",
    "model_gateway",
    "budgets",
    "execution",
    "authenticity",
}


class ProductionPreparationError(ValueError):
    """The preparation request or output boundary is unsafe."""


def prepare_from_config(
    config_path: Path,
    output_dir: Path,
    *,
    environment: Mapping[str, str] | None = None,
    captured_at: str | None = None,
) -> tuple[dict[str, object], Path]:
    """Inspect exact local inputs and retain one create-only preparation."""

    config_bytes = _read_regular(config_path, "preparation request", _MAX_CONFIG_BYTES)
    config = _request(_decode_json(config_bytes, "preparation request"))
    timestamp = _utc_timestamp(captured_at)
    blockers: list[str] = []
    checks: dict[str, object] = {}

    execution = _mapping(config["execution"], "execution request")
    trusted_path = _trusted_path(execution.get("trusted_path"))
    provider_environment = _environment_name(execution.get("upstream_api_key_environment"))

    source_snapshots: dict[str, dict[str, object]] = {}
    source_requests = _mapping(config["sources"], "source requests")
    for system in (*SYSTEMS, "xben"):
        try:
            source_snapshots[system] = _source_snapshot(
                _mapping(source_requests[system], f"{system} source"),
                system=system,
                trusted_path=trusted_path,
            )
        except ProductionPreparationError as exc:
            blockers.append(f"{system}_source_unready")
            source_snapshots[system] = {"ready": False, "error": str(exc)}
    checks["sources"] = source_snapshots

    website_request = _mapping(config["website"], "website request")
    website_result: dict[str, object]
    website_token: str | None = None
    try:
        website_result = _website_reference(website_request)
        website_token = "content-addressed-website:" + cast("str", website_result["sha256"])
    except ProductionPreparationError as exc:
        blockers.append("website_reference_unready")
        website_result = {"ready": False, "error": str(exc), "raw_reference_emitted": False}
    checks["website"] = website_result

    runtime_requests = _mapping(config["runtimes"], "runtime requests")
    runtime_bindings: dict[str, dict[str, object]] = {}
    for system in SYSTEMS:
        snapshot = source_snapshots[system]
        try:
            if snapshot.get("ready") is not True:
                raise ProductionPreparationError("source identity is not ready")
            runtime_bindings[system] = _runtime_binding(
                _mapping(runtime_requests[system], f"{system} runtime"),
                source=snapshot,
                trusted_path=trusted_path,
            )
        except (AdapterConfigurationError, OSError, ProductionPreparationError) as exc:
            blockers.append(f"{system}_runtime_manifest_unready")
            runtime_bindings[system] = {"ready": False, "error": str(exc)}
    checks["runtime_manifests"] = runtime_bindings

    catalog_result: dict[str, object]
    try:
        xben_commit = _ready_text(source_snapshots["xben"], "commit_sha", "XBEN source")
        catalog_result = _catalog_binding(
            _mapping(config["compatibility_catalog"], "compatibility catalog"),
            expected_commit=xben_commit,
        )
    except (ProductionPreparationError, SourceMaterializationError) as exc:
        blockers.append("compatibility_catalog_unready")
        catalog_result = {"ready": False, "error": str(exc)}
    checks["compatibility_catalog"] = catalog_result

    model_result: dict[str, object]
    pricing_bytes: bytes | None = None
    try:
        model_result, pricing_bytes = _model_gateway_binding(
            _mapping(config["model_gateway"], "model gateway request")
        )
    except (ProductionPreparationError, ValueError) as exc:
        blockers.append("model_gateway_contract_unready")
        model_result = {"ready": False, "error": str(exc)}
    checks["model_gateway"] = _public_model_result(model_result)

    host_result: dict[str, object]
    executor_config: dict[str, object] | None = None
    try:
        host_result, executor_config = _execution_binding(
            execution,
            runtime_requests=runtime_requests,
            xben_repository=_source_repository(source_requests, "xben"),
            compatibility_catalog=_canonical_file(
                _mapping(config["compatibility_catalog"], "compatibility catalog")["path"],
                "compatibility catalog",
            ),
            output_dir=output_dir,
        )
        if host_result.get("ready") is not True:
            blockers.append("execution_isolation_unsupported")
            executor_config = None
    except ProductionPreparationError as exc:
        blockers.append("execution_environment_unready")
        host_result = {"ready": False, "error": str(exc)}
    checks["execution"] = host_result

    images_result: dict[str, object]
    try:
        images_result = _image_bindings(
            _mapping(execution.get("oci_images"), "OCI image requests"),
            docker_executable=_canonical_file(
                execution.get("docker_executable"), "Docker executable"
            ),
            docker_socket=_canonical_socket(execution.get("docker_socket")),
            trusted_path=trusted_path,
        )
    except ProductionPreparationError as exc:
        blockers.append("oci_images_unready")
        images_result = {"ready": False, "error": str(exc), "pull_or_build_performed": False}
    checks["oci_images"] = images_result

    authenticity_result: dict[str, object]
    authenticity_copies: dict[str, bytes] = {}
    try:
        authenticity_result, authenticity_copies = _authenticity_binding(
            _mapping(config["authenticity"], "authenticity request"),
            ravage_repository=_configured_source_repository(source_requests, "ravage"),
            ravage_origin=_mapping(source_requests["ravage"], "Ravage source")["origin_url"],
        )
        if authenticity_result.get("ready") is not True:
            blockers.append("authenticity_verifiers_unready")
    except (AuthenticityError, ProductionPreparationError) as exc:
        blockers.append("authenticity_verifiers_unready")
        authenticity_result = {"ready": False, "error": str(exc)}
    checks["authenticity"] = authenticity_result

    component_bindings: dict[str, str] = {}
    try:
        component_bindings = _component_bindings()
        checks["evaluator_components"] = {
            "ready": True,
            "count": len(component_bindings),
            "components": component_bindings,
        }
    except ProductionPreparationError as exc:
        blockers.append("evaluator_components_unready")
        checks["evaluator_components"] = {"ready": False, "error": str(exc)}

    preflight_report = collect_preflight(
        evidence_dir=output_dir,
        benchmarks_root=_configured_source_repository(source_requests, "xben") / "benchmarks",
        xben_repo_root=_configured_source_repository(source_requests, "xben"),
        strix_repo_root=_configured_source_repository(source_requests, "strix"),
        ravage_repo_root=_configured_source_repository(source_requests, "ravage"),
        trusted_path=trusted_path,
        git_executable=DEFAULT_GIT_EXECUTABLE,
        docker_executable=(
            cast("str", execution.get("docker_executable"))
            if isinstance(execution.get("docker_executable"), str)
            else None
        ),
        docker_socket=(
            cast("str", execution.get("docker_socket"))
            if isinstance(execution.get("docker_socket"), str)
            else None
        ),
        strix_executable=_configured_runtime_executable(runtime_requests, "strix"),
        expected_strix_executable_sha256=_optional_runtime_executable_digest(
            runtime_bindings.get("strix")
        ),
        required_free_gib=_positive_int(execution.get("required_free_gib"), "required free GiB"),
        required_provider_env=(provider_environment,),
        environment=os.environ if environment is None else environment,
        expected_ravage_head=_source_expected_commit(source_requests, "ravage"),
        expected_strix_head=_source_expected_commit(source_requests, "strix"),
        expected_xben_head=_source_expected_commit(source_requests, "xben"),
        require_clean_sources=True,
        require_website_target=True,
        website_target=website_token,
        website_classification=_website_classification(website_request.get("classification")),
        captured_at=timestamp,
    )
    for reason in cast("list[str]", preflight_report["block_reasons"]):
        _append_unique(blockers, f"preflight:{reason}")

    preflight_digest = _sha256(canonical_json_bytes(preflight_report))
    contract: dict[str, object] | None = None
    if not blockers:
        try:
            contract = _run_contract(
                preflight_digest=preflight_digest,
                sources=source_snapshots,
                runtime_bindings=runtime_bindings,
                catalog=catalog_result,
                model=model_result,
                budgets=_mapping(config["budgets"], "budget request"),
                host=host_result,
                images=images_result,
                components=component_bindings,
            )
            validate_run_contract(contract)
        except (KeyError, PairedXbenProtocolError, ProductionPreparationError) as exc:
            blockers.append("run_contract_invalid")
            checks["run_contract"] = {"ready": False, "error": str(exc)}
            contract = None
    if contract is not None:
        checks["run_contract"] = {
            "ready": True,
            "sha256": _sha256((canonical_json(contract) + "\n").encode()),
        }

    ready = not blockers and contract is not None and executor_config is not None
    preparation = {
        "schema_version": PREPARATION_SCHEMA,
        "captured_at": timestamp,
        "ready": ready,
        "block_reasons": blockers,
        "no_live_actions": {
            "case_draw_performed": False,
            "randomness_or_entropy_request_performed": False,
            "model_call_performed": False,
            "paid_api_call_performed": False,
            "docker_pull_performed": False,
            "docker_build_performed": False,
        },
        "request_sha256": _sha256(config_bytes),
        "preflight_sha256": preflight_digest,
        "checks": checks,
        "emitted": {
            "preflight": True,
            "run_contract": ready,
            "executor_config": ready,
        },
    }

    output = _claim_output_directory(output_dir)
    preflight_path = write_preflight(output, preflight_report)
    _write_exclusive(output / PREPARE_REQUEST_FILE, config_bytes)
    inputs = output / "inputs"
    inputs.mkdir(mode=0o700, exist_ok=False)
    if pricing_bytes is not None and model_result.get("ready") is True:
        _write_exclusive(output / PRICING_SOURCE_FILE, pricing_bytes)
        _write_exclusive(
            output / PRICING_SOURCE_METADATA_FILE,
            canonical_json_bytes(cast("Mapping[str, object]", model_result["pricing_source"])),
        )
    _write_exclusive(output / WEBSITE_REFERENCE_FILE, canonical_json_bytes(website_result))
    if authenticity_copies:
        _write_exclusive(
            output / COSIGN_RELEASE_BUNDLE_FILE,
            authenticity_copies["cosign_release_bundle"],
        )
        _write_exclusive(
            output / SIGSTORE_TRUSTED_ROOT_FILE,
            authenticity_copies["sigstore_trusted_root"],
        )
    if authenticity_result.get("ready") is True:
        policy = _mapping(authenticity_result["policy"], "authenticity policy")
        _write_exclusive(output / AUTHENTICITY_POLICY_FILE, canonical_json_bytes(policy))
    if ready:
        assert contract is not None
        assert executor_config is not None
        _write_exclusive(output / RUN_CONTRACT_FILE, (canonical_json(contract) + "\n").encode())
        _write_exclusive(output / EXECUTOR_CONFIG_FILE, canonical_json_bytes(executor_config))
    _write_exclusive(output / PREPARATION_FILE, canonical_json_bytes(preparation))
    _write_exclusive(output / STATUS_FILE, _status_markdown(preparation).encode())
    _write_hash_manifest(output)
    return preparation, preflight_path


def _request(value: object) -> dict[str, object]:
    request = _mapping(value, "preparation request")
    if (
        set(request) != _EXPECTED_TOP_LEVEL
        or request.get("schema_version") != PREPARE_REQUEST_SCHEMA
    ):
        raise ProductionPreparationError("preparation request fields or schema are invalid")
    _reject_secret_fields(request)
    for key in _EXPECTED_TOP_LEVEL - {"schema_version"}:
        _mapping(request[key], f"preparation request {key}")
    if set(_mapping(request["sources"], "sources")) != {"ravage", "strix", "xben"}:
        raise ProductionPreparationError("source request must contain Ravage, Strix, and XBEN")
    if set(_mapping(request["runtimes"], "runtimes")) != set(SYSTEMS):
        raise ProductionPreparationError("runtime request must contain Ravage and Strix")
    source_fields = {"repository", "expected_commit", "origin_url"}
    for system, source in _mapping(request["sources"], "sources").items():
        if set(_mapping(source, f"{system} source")) != source_fields:
            raise ProductionPreparationError(f"{system} source fields are invalid")
    runtime_fields = {"executable", "runtime_environment_manifest", "runtime_read_roots"}
    for system, runtime in _mapping(request["runtimes"], "runtimes").items():
        if set(_mapping(runtime, f"{system} runtime")) != runtime_fields:
            raise ProductionPreparationError(f"{system} runtime fields are invalid")
    if set(_mapping(request["compatibility_catalog"], "compatibility catalog")) != {
        "path",
        "sha256",
    }:
        raise ProductionPreparationError("compatibility catalog request fields are invalid")
    if set(_mapping(request["website"], "website")) != {
        "classification",
        "reference_artifact",
        "sha256",
    }:
        raise ProductionPreparationError("website request fields are invalid")
    return request


def _source_snapshot(
    request: Mapping[str, object], *, system: str, trusted_path: str
) -> dict[str, object]:
    if set(request) != {"repository", "expected_commit", "origin_url"}:
        raise ProductionPreparationError(f"{system} source fields are invalid")
    repository = _canonical_directory(request["repository"], f"{system} repository")
    expected = _git_object(request["expected_commit"], f"{system} expected commit")
    configured_origin = _public_https_url(request["origin_url"], f"{system} origin")
    if system == "strix" and configured_origin != STRIX_CANONICAL_ORIGIN_URL:
        raise ProductionPreparationError("Strix origin is not canonical")
    if system == "xben" and configured_origin != XBEN_CANONICAL_ORIGIN_URL:
        raise ProductionPreparationError("XBEN origin is not canonical")
    environment = _command_environment(trusted_path)
    top = _git(repository, ("rev-parse", "--show-toplevel"), environment)
    if Path(top).resolve(strict=True) != repository:
        raise ProductionPreparationError(f"{system} repository is not the Git toplevel")
    head = _git(repository, ("rev-parse", "--verify", "HEAD"), environment).lower()
    if head != expected:
        raise ProductionPreparationError(f"{system} HEAD differs from its explicit pin")
    tree_path = "benchmarks" if system == "xben" else "."
    tree_spec = f"{head}:benchmarks" if system == "xben" else f"{head}^{{tree}}"
    tree = _git(repository, ("rev-parse", "--verify", tree_spec), environment).lower()
    _git_object(tree, f"{system} tree")
    origin = _git(repository, ("remote", "get-url", "origin"), environment)
    if _origin_identity(origin) != _origin_identity(configured_origin):
        raise ProductionPreparationError(f"{system} origin differs from its public pin")
    status_output = _git(
        repository,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        environment,
        allow_empty=True,
    )
    if status_output:
        raise ProductionPreparationError(f"{system} source worktree is dirty")
    return {
        "ready": True,
        "repository": str(repository),
        "commit_sha": head,
        "tree_object": tree,
        "tree_path": tree_path,
        "origin_url": configured_origin,
        "dirty": False,
    }


def _runtime_binding(
    request: Mapping[str, object], *, source: Mapping[str, object], trusted_path: str
) -> dict[str, object]:
    if set(request) != {"executable", "runtime_environment_manifest", "runtime_read_roots"}:
        raise ProductionPreparationError("runtime request fields are invalid")
    executable = _canonical_file(request["executable"], "runtime executable")
    manifest_path = _canonical_file(
        request["runtime_environment_manifest"], "runtime environment manifest"
    )
    manifest_bytes = _read_regular(
        manifest_path, "runtime environment manifest", _MAX_INPUT_FILE_BYTES
    )
    manifest = _mapping(_decode_json(manifest_bytes, "runtime environment manifest"), "manifest")
    executable_digest = _sha256_file(executable)
    runtime = PinnedAgentRuntime(
        executable=executable,
        executable_sha256=executable_digest,
        source_root=Path(_ready_text(source, "repository", "source"))
        if "repository" in source
        else Path(_manifest_text(manifest, "source_root")),
        source_commit=_ready_text(source, "commit_sha", "source"),
        source_tree=_ready_text(source, "tree_object", "source"),
        source_origin_url=_ready_text(source, "origin_url", "source"),
        runtime_environment_manifest=manifest_path,
        runtime_environment_manifest_sha256=_sha256(manifest_bytes),
    )
    verified = verify_pinned_runtime(runtime, trusted_path=trusted_path)
    if verified != manifest:
        raise ProductionPreparationError("runtime manifest did not reproduce")
    interpreter = _mapping(manifest.get("interpreter"), "runtime interpreter")
    lockfile = _mapping(manifest.get("lockfile"), "runtime lockfile")
    if manifest.get("schema_version") != RUNTIME_ENVIRONMENT_SCHEMA_VERSION:
        raise ProductionPreparationError("runtime manifest schema is unsupported")
    return {
        "ready": True,
        "schema_version": RUNTIME_ENVIRONMENT_SCHEMA_VERSION,
        "sha256": _sha256(manifest_bytes),
        "executable_sha256": executable_digest,
        "interpreter_sha256": _digest(interpreter.get("sha256"), "runtime interpreter"),
        "lockfile_sha256": _digest(lockfile.get("sha256"), "runtime lockfile"),
        "distribution_inventory_sha256": _digest(
            manifest.get("distribution_inventory_sha256"), "runtime distribution inventory"
        ),
        "site_packages_tree_sha256": _digest(
            manifest.get("site_packages_tree_sha256"), "runtime site-packages tree"
        ),
        "manifest_path": str(manifest_path),
    }


def _catalog_binding(request: Mapping[str, object], *, expected_commit: str) -> dict[str, object]:
    if set(request) != {"path", "sha256"}:
        raise ProductionPreparationError("compatibility catalog request fields are invalid")
    path = _canonical_file(request["path"], "compatibility catalog")
    digest = _digest(request["sha256"], "compatibility catalog")
    resolved = _resolve_compatibility_patch_catalog(
        CompatibilityPatchCatalog(path=path, sha256=digest.removeprefix("sha256:")),
        expected_commit=expected_commit,
    )
    return {
        "ready": True,
        "schema_version": "ravage.paired-xben.compatibility-catalog.v1",
        "sha256": "sha256:" + resolved.raw_sha256,
        "patch_count": len(resolved.entries),
        "all_patch_file_digests_verified": True,
    }


def _model_gateway_binding(
    request: Mapping[str, object],
) -> tuple[dict[str, object], bytes]:
    if set(request) != {"policy", "pricing_source"}:
        raise ProductionPreparationError("model gateway request fields are invalid")
    raw_policy = _mapping(request["policy"], "model gateway policy")
    configurable = {
        "model",
        "reasoning_effort",
        "pricing_usd_per_million_tokens",
        "campaign_max_cost_usd",
        "max_completion_tokens_per_request",
        "max_request_body_bytes",
        "max_upstream_response_bytes",
        "upstream_timeout_seconds",
        "max_parallel_requests",
    }
    if set(raw_policy) != configurable:
        raise ProductionPreparationError("model gateway configurable policy fields are invalid")
    prices = _mapping(raw_policy["pricing_usd_per_million_tokens"], "model prices")
    if set(prices) != {"input_per_million", "cached_input_per_million", "output_per_million"}:
        raise ProductionPreparationError("model price fields are invalid")
    policy = ModelGatewayPolicy.build(
        model=_normalized_text(raw_policy["model"], "model snapshot", 200),
        reasoning_effort=_normalized_text(raw_policy["reasoning_effort"], "reasoning effort", 50),
        pricing=ModelPricing.from_numbers(
            input_per_million=_money(prices["input_per_million"], "input price", positive=True),
            cached_input_per_million=_money(
                prices["cached_input_per_million"], "cached-input price", positive=False
            ),
            output_per_million=_money(prices["output_per_million"], "output price", positive=True),
        ),
        campaign_max_cost_usd=_money(
            raw_policy["campaign_max_cost_usd"], "campaign cost cap", positive=True
        ),
        max_completion_tokens_per_request=_positive_int(
            raw_policy["max_completion_tokens_per_request"], "completion token cap"
        ),
        max_request_body_bytes=_positive_int(raw_policy["max_request_body_bytes"], "request cap"),
        max_upstream_response_bytes=_positive_int(
            raw_policy["max_upstream_response_bytes"], "response cap"
        ),
        upstream_timeout_seconds=_positive_int(
            raw_policy["upstream_timeout_seconds"], "upstream timeout"
        ),
        max_parallel_requests=_positive_int(raw_policy["max_parallel_requests"], "parallel cap"),
    ).to_json()
    pricing_request = _mapping(request["pricing_source"], "pricing source")
    expected_pricing_fields = {
        "kind",
        "url",
        "published_on",
        "retrieved_at",
        "artifact_path",
        "artifact_sha256",
    }
    if set(pricing_request) != expected_pricing_fields:
        raise ProductionPreparationError("pricing source request fields are invalid")
    model = cast("str", policy["model"])
    if pricing_request.get("kind") != "openai_model_page_markdown":
        raise ProductionPreparationError("pricing source kind is unsupported")
    expected_url = f"https://developers.openai.com/api/docs/models/{model[:-11]}.md"
    if pricing_request.get("url") != expected_url:
        raise ProductionPreparationError("pricing source URL is not the official model Markdown")
    published_on = pricing_request.get("published_on")
    if published_on is not None and (
        not isinstance(published_on, str) or _canonical_date(published_on) != published_on
    ):
        raise ProductionPreparationError("pricing source publication date is invalid")
    retrieved_at = _utc_timestamp(cast("str", pricing_request.get("retrieved_at")))
    artifact_path = _canonical_file(pricing_request["artifact_path"], "pricing source artifact")
    artifact = _read_regular(artifact_path, "pricing source artifact", _MAX_INPUT_FILE_BYTES)
    artifact_digest = _digest(pricing_request["artifact_sha256"], "pricing source artifact")
    if _sha256(artifact) != artifact_digest:
        raise ProductionPreparationError("pricing source artifact differs from its explicit pin")
    _verify_pricing_page(artifact, model=model, prices=cast("Mapping[str, object]", prices))
    source = {
        "kind": "openai_model_page_markdown",
        "url": expected_url,
        "published_on": published_on,
        "retrieved_at": retrieved_at,
        "artifact_sha256": artifact_digest,
    }
    return {
        "ready": True,
        "policy": policy,
        "policy_sha256": _sha256(canonical_json(policy).encode()),
        "pricing_source": source,
        "pricing_values_present_in_artifact": True,
    }, artifact


def _verify_pricing_page(artifact: bytes, *, model: str, prices: Mapping[str, object]) -> None:
    try:
        text = artifact.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductionPreparationError("pricing source artifact is not UTF-8") from exc
    lowered = text.casefold()
    if model.casefold() not in lowered:
        raise ProductionPreparationError("pricing source artifact omits the frozen model snapshot")
    observed = {Decimal(match.group(1)) for match in _PRICE_RE.finditer(text)}
    required = {
        Decimal(_money(prices[name], f"{name} price", positive=name != "cached_input_per_million"))
        for name in ("input_per_million", "cached_input_per_million", "output_per_million")
    }
    if not required <= observed:
        raise ProductionPreparationError("pricing source artifact omits a frozen USD token price")
    for marker in ("input", "cached input", "output"):
        if marker not in lowered:
            raise ProductionPreparationError("pricing source artifact omits token price labels")


def _execution_binding(
    request: Mapping[str, object],
    *,
    runtime_requests: Mapping[str, object],
    xben_repository: Path,
    compatibility_catalog: Path,
    output_dir: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    expected = {
        "required_free_gib",
        "upstream_api_key_environment",
        "trusted_path",
        "docker_executable",
        "docker_socket",
        "private_target_root",
        "ravage_target_listen_port",
        "timeouts",
        "oci_images",
    }
    if set(request) != expected:
        raise ProductionPreparationError("execution request fields are invalid")
    _positive_int(request["required_free_gib"], "required free GiB")
    provider = _environment_name(request["upstream_api_key_environment"])
    trusted_path = _trusted_path(request["trusted_path"])
    docker_executable = _canonical_file(request["docker_executable"], "Docker executable")
    if not os.access(docker_executable, os.X_OK):
        raise ProductionPreparationError("Docker executable is not executable")
    resolved_docker = shutil.which("docker", path=trusted_path)
    if resolved_docker is None or Path(resolved_docker).resolve(strict=True) != docker_executable:
        raise ProductionPreparationError(
            "trusted PATH does not resolve the frozen Docker executable"
        )
    docker_socket = _canonical_socket(request["docker_socket"])
    private_root = _canonical_directory(request["private_target_root"], "private target root")
    metadata = private_root.stat()
    if (
        metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or any(private_root.iterdir())
    ):
        raise ProductionPreparationError(
            "private target root must be evaluator-owned, empty, and mode 0700"
        )
    for protected in (REPOSITORY_ROOT, output_dir.expanduser().resolve(strict=False)):
        if _paths_overlap(private_root, protected):
            raise ProductionPreparationError(
                "private target root overlaps retained evidence or source"
            )
    port = _positive_int(request["ravage_target_listen_port"], "Ravage target port")
    if not 1024 <= port <= 65535:
        raise ProductionPreparationError("Ravage target port is outside 1024..65535")
    _require_loopback_port_free(port)
    timeouts = _mapping(request["timeouts"], "executor timeouts")
    timeout_names = {"build_seconds", "startup_seconds", "inspect_seconds", "teardown_seconds"}
    if set(timeouts) != timeout_names:
        raise ProductionPreparationError("executor timeout fields are invalid")
    normalized_timeouts = {
        name: _positive_int(timeouts[name], f"executor {name}") for name in sorted(timeout_names)
    }
    if normalized_timeouts["teardown_seconds"] <= 35:
        raise ProductionPreparationError("executor teardown timeout must exceed 35 seconds")

    system_configs: dict[str, object] = {}
    system_policies: dict[str, object] = {}
    for system in SYSTEMS:
        runtime = _mapping(runtime_requests[system], f"{system} runtime")
        roots = _runtime_roots(runtime.get("runtime_read_roots"), system=system)
        outer_python_root = Path(sys.executable).resolve(strict=True).parent
        if outer_python_root not in roots:
            raise ProductionPreparationError(
                f"{system} runtime roots omit the outer evaluator interpreter directory"
            )
        roots_text = [str(path) for path in roots]
        system_configs[system] = {
            "executable": str(_canonical_file(runtime["executable"], f"{system} executable")),
            "runtime_environment_manifest": str(
                _canonical_file(
                    runtime["runtime_environment_manifest"], f"{system} runtime manifest"
                )
            ),
            "runtime_read_roots": roots_text,
        }
        system_policies[system] = {
            "evidence_class": "paired_local",
            "runtime_read_roots_sha256": _sha256(
                json.dumps(
                    roots_text, allow_nan=False, separators=(",", ":"), sort_keys=True
                ).encode()
            ),
            "runtime_read_root_count": len(roots),
            "docker_socket_access": True,
            "docker_socket_path_sha256": _sha256(str(docker_socket).encode()),
            "docker_host_sha256": _sha256(f"unix://{docker_socket}".encode()),
        }
    sandbox = Path("/usr/bin/sandbox-exec")
    if not sandbox.is_file() or not os.access(sandbox, os.X_OK):
        raise ProductionPreparationError("required /usr/bin/sandbox-exec is unavailable")
    policy = {
        "platform": "linux/amd64",
        "model_gateway_endpoint_mode": "host_loopback_row_token",
        "process_group_policy": "joined_evaluator_outer_group",
        "outer_process_group_environment": "joined_evaluator_group_v1",
        "evaluator_host": {
            "platform": "darwin",
            "containment_backend": "sandbox-exec",
            "sandbox_executable_path": "/usr/bin/sandbox-exec",
            "sandbox_executable_sha256": _sha256_file(sandbox),
            "systems": system_policies,
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
    }
    executor = {
        "schema_version": EXECUTOR_CONFIG_SCHEMA,
        "mode": "paired_local",
        "upstream_api_key_environment": provider,
        "xben_repository": str(xben_repository),
        "compatibility_catalog": str(compatibility_catalog),
        "private_target_root": str(private_root),
        "trusted_path": trusted_path,
        "docker_executable": str(docker_executable),
        "docker_socket": str(docker_socket),
        "ravage_target_listen_port": port,
        "systems": system_configs,
        "timeouts": normalized_timeouts,
    }
    return {
        "ready": False,
        "error": (
            "target and agent share one Docker daemon; an agent with that socket can inspect "
            "target containers, mounted source, and flags"
        ),
        "environment_verified": True,
        "policy": policy,
        "docker_executable_sha256": _sha256_file(docker_executable),
        "docker_socket_verified": True,
        "loopback_port_available": True,
    }, executor


def _image_bindings(
    request: Mapping[str, object],
    *,
    docker_executable: Path,
    docker_socket: Path,
    trusted_path: str,
) -> dict[str, object]:
    if set(request) != set(OCI_ROLES):
        missing = sorted(set(OCI_ROLES) - set(request))
        unexpected = sorted(set(request) - set(OCI_ROLES))
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if unexpected:
            detail.append("unexpected " + ", ".join(unexpected))
        raise ProductionPreparationError("OCI image roles are incomplete: " + "; ".join(detail))
    images: dict[str, str] = {}
    inspections: dict[str, object] = {}
    helper_ids: dict[str, str] = {}
    for role in OCI_ROLES:
        reference = request[role]
        if not isinstance(reference, str) or _OCI_RE.fullmatch(reference) is None:
            raise ProductionPreparationError(f"{role} is not a digest-pinned OCI reference")
        inspection = _inspect_image(
            docker_executable,
            docker_socket=docker_socket,
            trusted_path=trusted_path,
            reference=reference,
        )
        if inspection["os"] != "linux" or inspection["architecture"] != "amd64":
            raise ProductionPreparationError(f"{role} local image is not linux/amd64")
        images[role] = reference
        inspections[role] = inspection
        if role in {"target_gateway", "target_probe"}:
            helper_ids[role] = cast("str", inspection["image_id"])
    return {
        "ready": True,
        "references": images,
        "local_inspections": inspections,
        "target_helper_image_ids": helper_ids,
        "pull_or_build_performed": False,
    }


def _inspect_image(
    docker_executable: Path, *, docker_socket: Path, trusted_path: str, reference: str
) -> dict[str, object]:
    environment = _command_environment(trusted_path)
    environment["DOCKER_HOST"] = f"unix://{docker_socket}"
    try:
        completed = subprocess.run(  # noqa: S603
            (
                str(docker_executable),
                "image",
                "inspect",
                "--format",
                "{{.Id}}|{{.Os}}|{{.Architecture}}",
                reference,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=20,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProductionPreparationError("Docker image inspection failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > _MAX_SUBPROCESS_OUTPUT:
        raise ProductionPreparationError("digest-pinned OCI image is not locally inspectable")
    try:
        image_id, operating_system, architecture = (
            completed.stdout.decode("ascii").strip().split("|")
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProductionPreparationError("Docker image inspection output is invalid") from exc
    if _SHA256_RE.fullmatch(image_id) is None:
        raise ProductionPreparationError("Docker returned an invalid local image ID")
    return {
        "image_id": image_id,
        "os": operating_system,
        "architecture": architecture,
        "reference": reference,
    }


def _authenticity_binding(
    request: Mapping[str, object],
    *,
    ravage_repository: Path,
    ravage_origin: object,
) -> tuple[dict[str, object], dict[str, bytes]]:
    expected = {
        "drand_verifier",
        "cosign_binary",
        "sigstore_trusted_root",
        "cosign_release_bundle",
        "cosign_release_bundle_sha256",
        "cosign_release_identity",
        "cosign_release_oidc_issuer",
        "publication_certificate_identity",
        "publication_certificate_oidc_issuer",
    }
    if set(request) != expected:
        raise ProductionPreparationError("authenticity request fields are invalid")
    drand = _canonical_file(request["drand_verifier"], "drand verifier")
    cosign = _canonical_file(request["cosign_binary"], "cosign verifier")
    trusted_root = _canonical_file(request["sigstore_trusted_root"], "Sigstore trusted root")
    release_bundle = _canonical_file(request["cosign_release_bundle"], "Cosign release bundle")
    bundle_bytes = _read_regular(release_bundle, "Cosign release bundle", _MAX_INPUT_FILE_BYTES)
    if _sha256(bundle_bytes) != _digest(
        request["cosign_release_bundle_sha256"], "Cosign release bundle"
    ):
        raise ProductionPreparationError("Cosign release bundle differs from its explicit pin")
    root_bytes = _read_regular(trusted_root, "Sigstore trusted root", _MAX_INPUT_FILE_BYTES)
    _decode_json(bundle_bytes, "Cosign release bundle")
    _decode_json(root_bytes, "Sigstore trusted root")
    release_identity = _normalized_text(
        request["cosign_release_identity"], "Cosign release identity", 1000
    )
    release_issuer = _public_https_url(
        request["cosign_release_oidc_issuer"], "Cosign release OIDC issuer"
    )
    if release_identity != COSIGN_RELEASE_IDENTITY or release_issuer != COSIGN_RELEASE_OIDC_ISSUER:
        raise ProductionPreparationError(
            "Cosign release signer is not the pinned official identity"
        )
    _verify_cosign_release(
        cosign=cosign,
        binary=cosign,
        bundle=release_bundle,
        trusted_root=trusted_root,
        identity=release_identity,
        issuer=release_issuer,
    )
    publication_identity = _publication_identity(request["publication_certificate_identity"])
    release_result: dict[str, object] = {
        "cosign_official_release_bundle_verified": True,
        "cosign_release_bundle_sha256": _sha256(bundle_bytes),
        "cosign_release_identity": release_identity,
        "cosign_release_oidc_issuer": release_issuer,
    }
    copies = {
        "cosign_release_bundle": bundle_bytes,
        "sigstore_trusted_root": root_bytes,
    }
    try:
        _verify_publication_workflow(
            publication_identity,
            ravage_repository=ravage_repository,
            ravage_origin=_public_https_url(ravage_origin, "Ravage origin"),
        )
        policy = prepare_authenticity_policy(
            drand_verifier_binary_path=drand,
            cosign_binary_path=cosign,
            sigstore_trusted_root_path=trusted_root,
            publication_certificate_identity=publication_identity,
            publication_certificate_oidc_issuer=_publication_issuer(
                request["publication_certificate_oidc_issuer"]
            ),
        )
    except (AuthenticityError, ProductionPreparationError) as exc:
        return {"ready": False, "error": str(exc), **release_result}, copies
    return {"ready": True, **release_result, "policy": policy}, copies


def _verify_cosign_release(
    *,
    cosign: Path,
    binary: Path,
    bundle: Path,
    trusted_root: Path,
    identity: str,
    issuer: str,
) -> None:
    try:
        completed = subprocess.run(  # noqa: S603
            (
                str(cosign),
                "verify-blob",
                "--bundle",
                str(bundle),
                "--trusted-root",
                str(trusted_root),
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                issuer,
                "--use-signed-timestamps",
                str(binary),
            ),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=90,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent-paired-xben-home"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProductionPreparationError("Cosign release verification failed") from exc
    if (
        completed.returncode != 0
        or len(completed.stdout) > _MAX_SUBPROCESS_OUTPUT
        or len(completed.stderr) > _MAX_SUBPROCESS_OUTPUT
    ):
        raise ProductionPreparationError("Cosign release bundle did not verify")


def _component_bindings() -> dict[str, str]:
    bindings: dict[str, str] = {}
    for relative in EVALUATOR_COMPONENTS:
        path = REPOSITORY_ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ProductionPreparationError(f"evaluator component is unavailable: {relative}")
        bindings[relative] = _sha256_file(path)
    return bindings


def _run_contract(
    *,
    preflight_digest: str,
    sources: Mapping[str, Mapping[str, object]],
    runtime_bindings: Mapping[str, Mapping[str, object]],
    catalog: Mapping[str, object],
    model: Mapping[str, object],
    budgets: Mapping[str, object],
    host: Mapping[str, object],
    images: Mapping[str, object],
    components: Mapping[str, str],
) -> dict[str, object]:
    adapter_path = "packages/ravage/src/ravage/xben_parts/comparison_adapters.py"
    per_row, campaign = _budgets(budgets)
    frozen_runtimes = {
        system: {
            key: runtime_bindings[system][key]
            for key in (
                "schema_version",
                "sha256",
                "executable_sha256",
                "interpreter_sha256",
                "lockfile_sha256",
                "distribution_inventory_sha256",
                "site_packages_tree_sha256",
            )
        }
        for system in SYSTEMS
    }
    policy = _mapping(model["policy"], "model policy")
    if campaign["max_cost_usd"] != policy["campaign_max_cost_usd"]:
        raise ProductionPreparationError("campaign budget and gateway cost caps differ")
    return {
        "schema_version": RUN_CONTRACT_SCHEMA,
        "mode": "description-only-black-box",
        "objective": "capture_flag",
        "sources": {
            system: {
                key: sources[system][key]
                for key in ("commit_sha", "tree_object", "tree_path", "origin_url", "dirty")
            }
            for system in (*SYSTEMS, "xben")
        },
        "compatibility_catalog": {
            "schema_version": catalog["schema_version"],
            "sha256": catalog["sha256"],
        },
        "adapter": {
            "schema_version": ADAPTER_SCHEMA_VERSION,
            "adapter_version": ADAPTER_VERSION,
            "source_sha256": components[adapter_path],
        },
        "runtime_manifests": frozen_runtimes,
        "model_gateway": {
            "row_receipt_schema_version": MODEL_GATEWAY_SCHEMA,
            "campaign_receipt_schema_version": MODEL_GATEWAY_CAMPAIGN_SCHEMA,
            "provider": "openai",
            "agent_provider": "paired-row-gateway",
            "service_tier": "default",
            "store": False,
            "policy": policy,
            "policy_sha256": model["policy_sha256"],
            "pricing_source": model["pricing_source"],
        },
        "budgets": {"campaign": campaign, "per_row": per_row},
        "evaluator_components": dict(components),
        "execution_policy": host["policy"],
        "oci_images": images["references"],
        "target_helper_image_ids": images["target_helper_image_ids"],
        "preflight_digest": preflight_digest,
    }


def _budgets(request: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    if set(request) != {"per_row"}:
        raise ProductionPreparationError("budget request must contain only per_row")
    raw = _mapping(request["per_row"], "per-row budget")
    if set(raw) != {"wall_seconds", "max_model_requests", "max_target_requests", "max_cost_usd"}:
        raise ProductionPreparationError("per-row budget fields are invalid")
    per_row: dict[str, object] = {
        "wall_seconds": _positive_int(raw["wall_seconds"], "row wall cap"),
        "max_model_requests": _positive_int(raw["max_model_requests"], "row model cap"),
        "max_target_requests": _positive_int(raw["max_target_requests"], "row target cap"),
        "max_cost_usd": _money(raw["max_cost_usd"], "row cost cap", positive=True),
    }
    row_cost = Decimal(cast("str", per_row["max_cost_usd"]))
    with localcontext() as context:
        context.prec = max(context.prec, len(row_cost.as_tuple().digits) + 2)
        campaign_cost = row_cost * 40
    campaign = {
        "wall_seconds": cast("int", per_row["wall_seconds"]) * 40,
        "max_model_requests": cast("int", per_row["max_model_requests"]) * 40,
        "max_target_requests": cast("int", per_row["max_target_requests"]) * 40,
        "max_cost_usd": _decimal_text(campaign_cost),
    }
    return per_row, campaign


def _website_reference(request: Mapping[str, object]) -> dict[str, object]:
    if set(request) != {"classification", "reference_artifact", "sha256"}:
        raise ProductionPreparationError("website reference fields are invalid")
    classification = _website_classification(request["classification"])
    path = _canonical_path(request["reference_artifact"], "website reference artifact")
    if path.is_file():
        body = _read_regular(path, "website reference artifact", _MAX_INPUT_FILE_BYTES)
        digest, count, total, kind = _sha256(body), 1, len(body), "file"
    elif path.is_dir():
        digest, count, total = _tree_digest(path)
        kind = "directory_tree"
    else:
        raise ProductionPreparationError("website reference artifact has unsupported type")
    expected = _digest(request["sha256"], "website reference artifact")
    if digest != expected:
        raise ProductionPreparationError("website reference differs from its explicit pin")
    return {
        "ready": True,
        "classification": classification,
        "kind": kind,
        "sha256": digest,
        "file_count": count,
        "total_bytes": total,
        "raw_reference_emitted": False,
    }


def _tree_digest(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ProductionPreparationError("website reference tree contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file() or path.name.startswith(".env"):
            raise ProductionPreparationError("website reference tree contains an unsafe entry")
        file_count += 1
        if file_count > _MAX_WEBSITE_FILES:
            raise ProductionPreparationError("website reference tree contains too many files")
        size = path.stat().st_size
        total_bytes += size
        if total_bytes > _MAX_WEBSITE_BYTES:
            raise ProductionPreparationError("website reference tree exceeds the byte limit")
        item = {
            "path": relative,
            "mode": stat.S_IMODE(path.stat().st_mode),
            "size": size,
            "sha256": _sha256_file(path),
        }
        digest.update(canonical_json(item).encode())
    if not file_count:
        raise ProductionPreparationError("website reference tree is empty")
    return "sha256:" + digest.hexdigest(), file_count, total_bytes


def _public_model_result(value: Mapping[str, object]) -> dict[str, object]:
    if value.get("ready") is not True:
        return dict(value)
    return {
        "ready": True,
        "policy": value["policy"],
        "policy_sha256": value["policy_sha256"],
        "pricing_source": value["pricing_source"],
        "pricing_values_present_in_artifact": True,
    }


def _source_repository(sources: Mapping[str, object], system: str) -> Path:
    return _canonical_directory(
        _mapping(sources[system], f"{system} source")["repository"], f"{system} repository"
    )


def _configured_source_repository(sources: Mapping[str, object], system: str) -> Path:
    return _configured_absolute_path(
        _mapping(sources[system], f"{system} source")["repository"], f"{system} repository"
    )


def _source_expected_commit(sources: Mapping[str, object], system: str) -> str:
    return _git_object(
        _mapping(sources[system], f"{system} source")["expected_commit"],
        f"{system} expected commit",
    )


def _configured_runtime_executable(runtimes: Mapping[str, object], system: str) -> Path:
    return _configured_absolute_path(
        _mapping(runtimes[system], f"{system} runtime")["executable"],
        f"{system} executable",
    )


def _optional_runtime_executable_digest(binding: object) -> str | None:
    if isinstance(binding, Mapping):
        value = binding.get("executable_sha256")
        if isinstance(value, str) and _SHA256_RE.fullmatch(value):
            return value
    return None


def _status_markdown(preparation: Mapping[str, object]) -> str:
    ready = preparation.get("ready") is True
    blockers = preparation.get("block_reasons")
    lines = [
        "# Paired XBEN production preparation",
        "",
        f"State: **{'READY' if ready else 'BLOCKED'}**",
        "",
        (
            "No case draw, randomness or entropy request, model request, paid API call, "
            "Docker pull, or Docker build was performed."
        ),
        "",
    ]
    if ready:
        lines.extend(
            [
                "The create-only `preflight.json`, `run-contract.json`, and "
                "`executor-config.json` were emitted from exact local inputs.",
                "",
                "This is preparation only; no randomness commitment exists yet.",
            ]
        )
    else:
        lines.extend(["Remaining blocker codes:", ""])
        if isinstance(blockers, list):
            lines.extend(f"- `{reason}`" for reason in blockers)
        checks = preparation.get("checks")
        details: list[tuple[str, str]] = []
        if isinstance(checks, Mapping):
            for name, raw_check in checks.items():
                if isinstance(raw_check, Mapping) and isinstance(raw_check.get("error"), str):
                    details.append((str(name), cast("str", raw_check["error"])))
                elif isinstance(raw_check, Mapping):
                    for nested_name, nested in raw_check.items():
                        if isinstance(nested, Mapping) and isinstance(nested.get("error"), str):
                            details.append((f"{name}.{nested_name}", cast("str", nested["error"])))
        if details:
            lines.extend(["", "Concrete readiness failures:", ""])
            lines.extend(f"- `{name}`: {error}" for name, error in details)
        lines.extend(
            [
                "",
                "`run-contract.json` and `executor-config.json` were not emitted.",
            ]
        )
    return "\n".join(lines) + "\n"


def _write_hash_manifest(root: Path) -> None:
    paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    entries = [
        f"{_sha256_file(path).removeprefix('sha256:')}  {path.relative_to(root)}"
        for path in paths
        if path.is_file() and path.name != HASH_MANIFEST_FILE
    ]
    _write_exclusive(root / HASH_MANIFEST_FILE, ("\n".join(entries) + "\n").encode())


def _claim_output_directory(path: Path) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise ProductionPreparationError("output directory must not be a symlink")
    output = requested.resolve(strict=False)
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        if not output.is_dir() or any(output.iterdir()):
            raise ProductionPreparationError("output directory must be new or empty") from None
    return output


def _write_exclusive(path: Path, body: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("exclusive artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ProductionPreparationError(f"{label} must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        with resolved.open("rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ProductionPreparationError(f"{label} is not a regular file")
            body = handle.read(maximum + 1)
    except ProductionPreparationError:
        raise
    except OSError as exc:
        raise ProductionPreparationError(f"{label} is unavailable") from exc
    if len(body) > maximum:
        raise ProductionPreparationError(f"{label} exceeds the byte limit")
    return body


def _decode_json(body: bytes, label: str) -> object:
    try:
        return json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_raise_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionPreparationError(f"{label} is not valid JSON") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProductionPreparationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _raise_nonfinite(value: str) -> object:
    raise ProductionPreparationError(f"non-finite JSON value is forbidden: {value}")


def _reject_secret_fields(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized in _SECRET_KEYS:
                raise ProductionPreparationError("preparation request must not contain secrets")
            _reject_secret_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_secret_fields(nested)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ProductionPreparationError(f"{label} must be an object")
    return dict(value)


def _normalized_text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ProductionPreparationError(f"{label} is invalid")
    if any(ord(character) < 32 for character in value):
        raise ProductionPreparationError(f"{label} contains control characters")
    return value


def _public_https_url(value: object, label: str) -> str:
    text = _normalized_text(value, label, 1000)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ProductionPreparationError(f"{label} must be a public HTTPS URL")
    return text


def _publication_identity(value: object) -> str:
    identity = _public_https_url(value, "publication certificate identity")
    parsed = urlsplit(identity)
    if (
        parsed.hostname != "github.com"
        or "/.github/workflows/" not in parsed.path
        or "@" not in identity
    ):
        raise ProductionPreparationError("publication identity is not a GitHub Actions workflow")
    return identity


def _publication_issuer(value: object) -> str:
    issuer = _public_https_url(value, "publication certificate OIDC issuer")
    if issuer != GITHUB_ACTIONS_OIDC_ISSUER:
        raise ProductionPreparationError("publication OIDC issuer is not GitHub Actions")
    return issuer


def _verify_publication_workflow(
    identity: str, *, ravage_repository: Path, ravage_origin: str
) -> None:
    parsed = urlsplit(identity)
    origin = urlsplit(ravage_origin)
    origin_path = origin.path.strip("/").removesuffix(".git")
    if not identity.startswith(f"https://github.com/{origin_path}/.github/workflows/"):
        raise ProductionPreparationError("publication workflow differs from the Ravage origin")
    workflow_with_ref = parsed.path.partition("/.github/workflows/")[2]
    workflow_name, separator, reference = workflow_with_ref.partition("@")
    if (
        separator != "@"
        or not workflow_name
        or "/" in workflow_name
        or reference != "refs/heads/main"
    ):
        raise ProductionPreparationError(
            "publication workflow identity is not main-branch canonical"
        )
    repository = _canonical_directory(str(ravage_repository), "Ravage publication repository")
    workflow = repository / ".github" / "workflows" / workflow_name
    if workflow.is_symlink() or not workflow.is_file():
        raise ProductionPreparationError("publication workflow is absent from the Ravage source")


def _origin_identity(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProductionPreparationError("Git origin is not a public HTTPS URL")
    path = parsed.path.strip("/").removesuffix(".git").casefold()
    return f"{parsed.hostname.casefold()}/{path}"


def _canonical_path(value: object, label: str) -> Path:
    text = _normalized_text(value, label, 4096)
    path = Path(text)
    if not path.is_absolute() or path.is_symlink():
        raise ProductionPreparationError(f"{label} must be a canonical absolute path")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProductionPreparationError(f"{label} is unavailable") from exc
    if resolved != path:
        raise ProductionPreparationError(f"{label} must not traverse a symlink")
    return resolved


def _configured_absolute_path(value: object, label: str) -> Path:
    text = _normalized_text(value, label, 4096)
    path = Path(text)
    if not path.is_absolute() or "\x00" in text or any(part in {".", ".."} for part in path.parts):
        raise ProductionPreparationError(f"{label} must be a canonical absolute path")
    return path


def _canonical_file(value: object, label: str) -> Path:
    path = _canonical_path(value, label)
    if not path.is_file():
        raise ProductionPreparationError(f"{label} is not a regular file")
    return path


def _canonical_directory(value: object, label: str) -> Path:
    path = _canonical_path(value, label)
    if not path.is_dir():
        raise ProductionPreparationError(f"{label} is not a directory")
    return path


def _canonical_socket(value: object) -> Path:
    path = _canonical_path(value, "Docker socket")
    if not stat.S_ISSOCK(path.stat().st_mode):
        raise ProductionPreparationError("Docker socket path is not a Unix socket")
    return path


def _runtime_roots(value: object, *, system: str) -> tuple[Path, ...]:
    if not isinstance(value, list) or not value or len(value) > 128:
        raise ProductionPreparationError(f"{system} runtime read roots are invalid")
    roots: set[Path] = set()
    for item in value:
        path = _canonical_path(item, f"{system} runtime read root")
        root = path if path.is_dir() else path.parent
        if root == Path("/"):
            raise ProductionPreparationError("runtime read root cannot be filesystem root")
        roots.add(root)
    return tuple(sorted(roots))


def _trusted_path(value: object) -> str:
    text = _normalized_text(value, "trusted PATH", 8192)
    entries = text.split(os.pathsep)
    if not entries or len(entries) > 32:
        raise ProductionPreparationError("trusted PATH has an invalid entry count")
    normalized: list[str] = []
    for entry in entries:
        path = _canonical_directory(entry, "trusted PATH entry")
        normalized.append(str(path))
    return os.pathsep.join(normalized)


def _git(
    repository: Path,
    arguments: Sequence[str],
    environment: Mapping[str, str],
    *,
    allow_empty: bool = False,
) -> str:
    try:
        completed = subprocess.run(  # noqa: S603
            ("/usr/bin/git", "-C", str(repository), *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
            env=dict(environment),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProductionPreparationError("Git source inspection failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > _MAX_SUBPROCESS_OUTPUT:
        raise ProductionPreparationError("Git source inspection did not complete")
    try:
        output = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ProductionPreparationError("Git source inspection output is invalid") from exc
    if not output and not allow_empty:
        raise ProductionPreparationError("Git source inspection returned no identity")
    return output


def _command_environment(trusted_path: str) -> dict[str, str]:
    return {
        "PATH": trusted_path,
        "HOME": "/nonexistent-paired-xben-home",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _manifest_text(manifest: Mapping[str, object], key: str) -> str:
    return _normalized_text(manifest.get(key), f"runtime manifest {key}", 4096)


def _ready_text(value: Mapping[str, object], key: str, label: str) -> str:
    return _normalized_text(value.get(key), f"{label} {key}", 4096)


def _git_object(value: object, label: str) -> str:
    text = _normalized_text(value, label, 64).lower()
    if _GIT_RE.fullmatch(text) is None:
        raise ProductionPreparationError(f"{label} is not a full Git object ID")
    return text


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ProductionPreparationError(f"{label} is not a canonical SHA-256 digest")
    return value


def _sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProductionPreparationError(f"{label} must be a positive integer")
    return value


def _money(value: object, label: str, *, positive: bool) -> str:
    if not isinstance(value, str) or _MONEY_RE.fullmatch(value) is None:
        raise ProductionPreparationError(f"{label} must be a canonical decimal string")
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise ProductionPreparationError(f"{label} is invalid") from exc
    normalized = _decimal_text(amount)
    if normalized != value or (positive and amount <= 0):
        raise ProductionPreparationError(f"{label} is not canonical and positive")
    return normalized


def _decimal_text(value: Decimal) -> str:
    normalized = format(value, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return "0" if normalized in {"", "-0"} else normalized


def _environment_name(value: object) -> str:
    text = _normalized_text(value, "provider environment name", 128)
    if _ENV_RE.fullmatch(text) is None:
        raise ProductionPreparationError("provider environment name is invalid")
    return text


def _website_classification(value: object) -> str:
    if value not in {"known_site", "sealed_holdout"}:
        raise ProductionPreparationError(
            "website classification must be known_site or sealed_holdout"
        )
    return value


def _canonical_date(value: str) -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise ProductionPreparationError("date is invalid") from exc


def _utc_timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    if not isinstance(value, str) or len(value) > 128:
        raise ProductionPreparationError("timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ProductionPreparationError("timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ProductionPreparationError("timestamp must be UTC")
    return parsed.isoformat()


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        first.relative_to(second)
    except ValueError:
        pass
    else:
        return True
    try:
        second.relative_to(first)
    except ValueError:
        return False
    return True


def _require_loopback_port_free(port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise ProductionPreparationError("Ravage target loopback port is unavailable") from exc
    finally:
        probe.close()


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a no-live-action production preflight and paired-XBEN run contract."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result, _preflight = prepare_from_config(args.config, args.output_dir)
    except (OSError, PreflightConfigurationError, ProductionPreparationError) as exc:
        sys.stderr.write(f"[paired-xben:prepare:blocked] {exc}\n")
        return 2
    state = "ready" if result["ready"] else "blocked"
    reasons = cast("list[str]", result["block_reasons"])
    sys.stdout.write(
        f"[paired-xben:prepare] {state} output={args.output_dir} blockers={len(reasons)}\n"
    )
    for reason in reasons:
        sys.stdout.write(f"  - {reason}\n")
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXECUTOR_CONFIG_FILE",
    "PREPARATION_FILE",
    "PREPARATION_SCHEMA",
    "PREPARE_REQUEST_SCHEMA",
    "RUN_CONTRACT_FILE",
    "ProductionPreparationError",
    "main",
    "prepare_from_config",
]
