# ruff: noqa: ARG005,C420,PLR2004,SLF001
from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping
from decimal import localcontext
from pathlib import Path

import pytest

from tools.paired_xben import cli as paired_cli
from tools.paired_xben import prepare, protocol
from tools.paired_xben.preflight import STRIX_CANONICAL_ORIGIN_URL, XBEN_CANONICAL_ORIGIN_URL


def _digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def test_public_execution_code_and_workflows_are_explicitly_source_bound() -> None:
    required = {
        "tools/paired_xben/github_runner.py",
        "tools/paired_xben/github_execution_gate.py",
        "tools/paired_xben/github_execution_start.py",
        "tools/paired_xben/public_ledger.py",
        "tools/paired_xben/images/target-gateway.Dockerfile",
        "packages/ravage/src/ravage/xben_parts/comparison_agent_vm.py",
        ".github/workflows/paired-xben-intake.yml",
        ".github/workflows/paired-xben.yml",
        ".github/workflows/paired-xben-execution.yml",
        ".github/workflows/paired-xben-helper-image.yml",
    }

    assert set(prepare.EVALUATOR_COMPONENTS) == set(protocol._EVALUATOR_COMPONENTS)
    assert required <= set(prepare.EVALUATOR_COMPONENTS)
    bindings = prepare._component_bindings()
    assert set(bindings) == set(prepare.EVALUATOR_COMPONENTS)
    for relative in required:
        body = (prepare.REPOSITORY_ROOT / relative).read_bytes()
        assert bindings[relative] == _digest(body)


def _policy() -> dict[str, object]:
    return {
        "model": "gpt-test-2026-09-01",
        "reasoning_effort": "high",
        "pricing_usd_per_million_tokens": {
            "input_per_million": "0.75",
            "cached_input_per_million": "0.075",
            "output_per_million": "4.5",
        },
        "campaign_max_cost_usd": "20",
        "max_completion_tokens_per_request": 8192,
        "max_request_body_bytes": 1048576,
        "max_upstream_response_bytes": 8388608,
        "upstream_timeout_seconds": 120,
        "max_parallel_requests": 1,
    }


def _request(tmp_path: Path) -> tuple[dict[str, object], bytes]:
    repositories: dict[str, Path] = {}
    for name in ("ravage", "strix", "xben"):
        repository = tmp_path / name
        repository.mkdir()
        repositories[name] = repository
    executable = tmp_path / "agent"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    runtime_manifest = tmp_path / "runtime.json"
    runtime_manifest.write_text("{}\n", encoding="utf-8")
    catalog = tmp_path / "catalog.json"
    catalog.write_text("{}\n", encoding="utf-8")
    website = tmp_path / "website.txt"
    website.write_text("known website revision\n", encoding="utf-8")
    pricing = b"gpt-test-2026-09-01\nInput $0.75\nCached input $0.075\nOutput $4.50\n"
    pricing_path = tmp_path / "pricing.md"
    pricing_path.write_bytes(pricing)
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\n", encoding="utf-8")
    docker.chmod(0o700)
    docker_socket_path = tmp_path / "docker.sock"
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    drand = tmp_path / "drand"
    drand.write_text("#!/bin/sh\n", encoding="utf-8")
    drand.chmod(0o700)
    cosign = tmp_path / "cosign"
    cosign.write_text("#!/bin/sh\n", encoding="utf-8")
    cosign.chmod(0o700)
    root = tmp_path / "trusted-root.json"
    root.write_text("{}\n", encoding="utf-8")
    bundle = tmp_path / "cosign.sigstore.json"
    bundle.write_text("{}\n", encoding="utf-8")
    source_origins = {
        "ravage": "https://github.com/example/ravage.git",
        "strix": STRIX_CANONICAL_ORIGIN_URL,
        "xben": XBEN_CANONICAL_ORIGIN_URL,
    }
    return {
        "schema_version": prepare.PREPARE_REQUEST_SCHEMA,
        "sources": {
            name: {
                "repository": str(repository),
                "expected_commit": digit * 40,
                "origin_url": source_origins[name],
            }
            for name, repository, digit in (
                ("ravage", repositories["ravage"], "1"),
                ("strix", repositories["strix"], "2"),
                ("xben", repositories["xben"], "3"),
            )
        },
        "runtimes": {
            system: {
                "executable": str(executable),
                "runtime_environment_manifest": str(runtime_manifest),
                "runtime_read_roots": [str(tmp_path)],
            }
            for system in ("ravage", "strix")
        },
        "compatibility_catalog": {
            "path": str(catalog),
            "sha256": _digest(catalog.read_bytes()),
        },
        "website": {
            "classification": "known_site",
            "reference_artifact": str(website),
            "sha256": _digest(website.read_bytes()),
        },
        "model_gateway": {
            "policy": _policy(),
            "pricing_source": {
                "kind": "openai_model_page_markdown",
                "url": "https://developers.openai.com/api/docs/models/gpt-test.md",
                "published_on": None,
                "retrieved_at": "2026-09-01T00:00:00+00:00",
                "artifact_path": str(pricing_path),
                "artifact_sha256": _digest(pricing),
            },
        },
        "budgets": {
            "per_row": {
                "wall_seconds": 600,
                "max_model_requests": 40,
                "max_target_requests": 96,
                "max_cost_usd": "0.5",
            }
        },
        "execution": {
            "required_free_gib": 20,
            "upstream_api_key_environment": "OPENAI_API_KEY",
            "trusted_path": "/usr/bin:/bin",
            "docker_executable": str(docker),
            "docker_socket": str(docker_socket_path),
            "private_target_root": str(private),
            "ravage_target_listen_port": 32123,
            "timeouts": {
                "build_seconds": 900,
                "startup_seconds": 180,
                "inspect_seconds": 30,
                "teardown_seconds": 90,
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
        },
        "authenticity": {
            "drand_verifier": str(drand),
            "cosign_binary": str(cosign),
            "sigstore_trusted_root": str(root),
            "cosign_release_bundle": str(bundle),
            "cosign_release_bundle_sha256": _digest(bundle.read_bytes()),
            "cosign_release_identity": "release@example.invalid",
            "cosign_release_oidc_issuer": "https://accounts.example.invalid",
            "publication_certificate_identity": "https://github.com/example/repo/workflow",
            "publication_certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
        },
    }, pricing


def _source_snapshots(request: Mapping[str, object]) -> dict[str, dict[str, object]]:
    sources = request["sources"]
    assert isinstance(sources, Mapping)
    return {
        name: {
            "ready": True,
            "repository": source["repository"],
            "commit_sha": source["expected_commit"],
            "tree_object": digit * 40,
            "tree_path": "benchmarks" if name == "xben" else ".",
            "origin_url": source["origin_url"],
            "dirty": False,
        }
        for name, source, digit in (
            ("ravage", sources["ravage"], "4"),
            ("strix", sources["strix"], "5"),
            ("xben", sources["xben"], "6"),
        )
    }


def _runtime_binding(digit: str) -> dict[str, object]:
    return {
        "ready": True,
        "schema_version": "ravage.xben.runtime-environment.v1",
        "sha256": "sha256:" + digit * 64,
        "executable_sha256": "sha256:" + "7" * 64,
        "interpreter_sha256": "sha256:" + "8" * 64,
        "lockfile_sha256": "sha256:" + "9" * 64,
        "distribution_inventory_sha256": "sha256:" + "a" * 64,
        "site_packages_tree_sha256": "sha256:" + "b" * 64,
        "manifest_path": "/unused",
    }


def _execution_policy() -> dict[str, object]:
    systems = {
        system: {
            "evidence_class": "paired_local",
            "runtime_read_roots_sha256": "sha256:" + digit * 64,
            "runtime_read_root_count": 1,
            "docker_socket_access": True,
            "docker_socket_path_sha256": "sha256:" + "d" * 64,
            "docker_host_sha256": "sha256:" + "e" * 64,
        }
        for system, digit in (("ravage", "b"), ("strix", "c"))
    }
    return {
        "platform": "linux/amd64",
        "model_gateway_endpoint_mode": "host_loopback_row_token",
        "process_group_policy": "joined_evaluator_outer_group",
        "outer_process_group_environment": "joined_evaluator_group_v1",
        "evaluator_host": {
            "platform": "darwin",
            "containment_backend": "sandbox-exec",
            "sandbox_executable_path": "/usr/bin/sandbox-exec",
            "sandbox_executable_sha256": "sha256:" + "f" * 64,
            "systems": systems,
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


def _patch_ready_dependencies(
    monkeypatch: pytest.MonkeyPatch, request: Mapping[str, object]
) -> None:
    snapshots = _source_snapshots(request)
    monkeypatch.setattr(prepare, "_canonical_socket", lambda value: Path(str(value)))
    monkeypatch.setattr(
        prepare,
        "_source_snapshot",
        lambda _request, *, system, trusted_path: snapshots[system],
    )
    bindings = {"ravage": _runtime_binding("1"), "strix": _runtime_binding("2")}
    monkeypatch.setattr(
        prepare,
        "_runtime_binding",
        lambda _request, *, source, trusted_path: (
            bindings["strix"] if source["commit_sha"] == "2" * 40 else bindings["ravage"]
        ),
    )
    monkeypatch.setattr(
        prepare,
        "_catalog_binding",
        lambda _request, *, expected_commit: {
            "ready": True,
            "schema_version": "ravage.paired-xben.compatibility-catalog.v1",
            "sha256": "sha256:" + "3" * 64,
            "patch_count": 0,
            "all_patch_file_digests_verified": True,
        },
    )
    monkeypatch.setattr(
        prepare,
        "_execution_binding",
        lambda *_args, **_kwargs: (
            {"ready": True, "policy": _execution_policy()},
            {"schema_version": prepare.EXECUTOR_CONFIG_SCHEMA, "mode": "paired_local"},
        ),
    )
    execution = request["execution"]
    assert isinstance(execution, Mapping)
    images = execution["oci_images"]
    monkeypatch.setattr(
        prepare,
        "_image_bindings",
        lambda *_args, **_kwargs: {
            "ready": True,
            "references": images,
            "target_helper_image_ids": {
                "target_gateway": "sha256:" + "4" * 64,
                "target_probe": "sha256:" + "5" * 64,
            },
            "pull_or_build_performed": False,
        },
    )
    monkeypatch.setattr(
        prepare,
        "_authenticity_binding",
        lambda _request, **_kwargs: (
            {"ready": True, "policy": {"schema_version": "test"}},
            {"cosign_release_bundle": b"{}\n", "sigstore_trusted_root": b"{}\n"},
        ),
    )
    component_digest = "sha256:" + "6" * 64
    monkeypatch.setattr(
        prepare,
        "_component_bindings",
        lambda: {path: component_digest for path in prepare.EVALUATOR_COMPONENTS},
    )
    monkeypatch.setattr(
        prepare,
        "collect_preflight",
        lambda **_kwargs: {
            "schema_version": "ravage.paired-xben.preflight.v1",
            "captured_at": "2026-09-01T00:00:00+00:00",
            "blocked": False,
            "block_reasons": [],
        },
    )


def test_prepare_emits_valid_contract_and_create_only_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, pricing = _request(tmp_path)
    _patch_ready_dependencies(monkeypatch, request)
    preflight_arguments: dict[str, object] = {}

    def collect_preflight(**kwargs: object) -> dict[str, object]:
        preflight_arguments.update(kwargs)
        return {
            "schema_version": "ravage.paired-xben.preflight.v1",
            "captured_at": "2026-09-01T00:00:00+00:00",
            "blocked": False,
            "block_reasons": [],
        }

    monkeypatch.setattr(prepare, "collect_preflight", collect_preflight)
    config = tmp_path / "prepare.json"
    config.write_text(json.dumps(request), encoding="utf-8")
    output = tmp_path / "evidence"

    result, preflight_path = prepare.prepare_from_config(
        config,
        output,
        environment={"OPENAI_API_KEY": "presence-only-canary"},
        captured_at="2026-09-01T00:00:00+00:00",
    )

    assert result["ready"] is True
    assert result["block_reasons"] == []
    assert preflight_path == output / "preflight.json"
    assert (output / prepare.RUN_CONTRACT_FILE).is_file()
    assert (output / prepare.EXECUTOR_CONFIG_FILE).is_file()
    assert (output / prepare.PRICING_SOURCE_FILE).read_bytes() == pricing
    assert (output / prepare.PREPARE_REQUEST_FILE).read_bytes() == config.read_bytes()
    assert result["request_sha256"] == _digest((output / prepare.PREPARE_REQUEST_FILE).read_bytes())
    execution = request["execution"]
    assert isinstance(execution, Mapping)
    assert preflight_arguments["trusted_path"] == execution["trusted_path"]
    assert preflight_arguments["git_executable"] == prepare.DEFAULT_GIT_EXECUTABLE
    assert preflight_arguments["docker_executable"] == execution["docker_executable"]
    assert preflight_arguments["docker_socket"] == execution["docker_socket"]
    assert "READY" in (output / prepare.STATUS_FILE).read_text(encoding="utf-8")
    retained = b"".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
    assert b"presence-only-canary" not in retained
    with pytest.raises(prepare.ProductionPreparationError, match="new or empty"):
        prepare.prepare_from_config(config, output, environment={"OPENAI_API_KEY": "x"})


def test_prepare_retains_exact_money_under_low_decimal_precision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row_cost = "1." + "0" * 35 + "1"
    campaign_cost = "40." + "0" * 34 + "4"
    request, _pricing = _request(tmp_path)
    request["budgets"]["per_row"]["max_cost_usd"] = row_cost
    request["model_gateway"]["policy"]["campaign_max_cost_usd"] = campaign_cost
    _patch_ready_dependencies(monkeypatch, request)
    config = tmp_path / "prepare.json"
    config.write_text(json.dumps(request), encoding="utf-8")
    output = tmp_path / "evidence"

    with localcontext() as context:
        context.prec = 6
        result, _ = prepare.prepare_from_config(
            config,
            output,
            environment={"OPENAI_API_KEY": "presence-only-canary"},
            captured_at="2026-09-01T00:00:00+00:00",
        )
        retained = json.loads((output / prepare.RUN_CONTRACT_FILE).read_text(encoding="utf-8"))
        validated = protocol.validate_run_contract(retained)

    assert result["ready"] is True
    assert validated["budgets"]["per_row"]["max_cost_usd"] == row_cost
    assert validated["budgets"]["campaign"]["max_cost_usd"] == campaign_cost
    assert validated["model_gateway"]["policy"]["campaign_max_cost_usd"] == campaign_cost


def test_prepare_retains_blockers_without_emitting_runnable_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, _pricing = _request(tmp_path)
    _patch_ready_dependencies(monkeypatch, request)
    monkeypatch.setattr(
        prepare,
        "_image_bindings",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            prepare.ProductionPreparationError("image absent")
        ),
    )
    config = tmp_path / "prepare.json"
    config.write_text(json.dumps(request), encoding="utf-8")
    output = tmp_path / "evidence"

    result, _path = prepare.prepare_from_config(config, output)

    assert result["ready"] is False
    reasons = result["block_reasons"]
    assert isinstance(reasons, list)
    assert "oci_images_unready" in reasons
    assert (output / "preflight.json").is_file()
    assert not (output / prepare.RUN_CONTRACT_FILE).exists()
    assert not (output / prepare.EXECUTOR_CONFIG_FILE).exists()
    assert "BLOCKED" in (output / prepare.STATUS_FILE).read_text(encoding="utf-8")


def test_pricing_source_must_contain_model_and_all_frozen_prices(tmp_path: Path) -> None:
    request, _pricing = _request(tmp_path)
    gateway = request["model_gateway"]
    assert isinstance(gateway, dict)
    source = gateway["pricing_source"]
    assert isinstance(source, dict)
    bad = tmp_path / "bad-pricing.md"
    bad.write_text("gpt-test-2026-09-01\nInput $0.75\nOutput $4.50\n", encoding="utf-8")
    source["artifact_path"] = str(bad)
    source["artifact_sha256"] = _digest(bad.read_bytes())

    with pytest.raises(prepare.ProductionPreparationError, match="omits a frozen USD"):
        prepare._model_gateway_binding(gateway)


def test_request_rejects_secret_value_fields(tmp_path: Path) -> None:
    request, _pricing = _request(tmp_path)
    gateway = request["model_gateway"]
    assert isinstance(gateway, dict)
    gateway["api_key"] = "must-not-be-accepted"

    with pytest.raises(prepare.ProductionPreparationError, match="must not contain secrets"):
        prepare._request(request)


def test_image_inspection_is_read_only_and_requires_linux_amd64(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\n", encoding="utf-8")
    docker.chmod(0o700)
    observed: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=("sha256:" + "a" * 64 + "|linux|amd64\n").encode(),
            stderr=b"",
        )

    monkeypatch.setattr("tools.paired_xben.prepare.subprocess.run", run)
    result = prepare._inspect_image(
        docker,
        docker_socket=tmp_path / "docker.sock",
        trusted_path="/usr/bin:/bin",
        reference="registry.invalid/tool@sha256:" + "b" * 64,
    )

    assert result["image_id"] == "sha256:" + "a" * 64
    assert len(observed) == 1
    assert observed[0][1:3] == ("image", "inspect")
    assert "pull" not in observed[0]
    assert "build" not in observed[0]


def test_website_tree_rejects_dotenv_without_reading_it(tmp_path: Path) -> None:
    website = tmp_path / "website"
    website.mkdir()
    (website / "index.html").write_text("ok", encoding="utf-8")
    (website / ".env").write_text("SECRET=canary", encoding="utf-8")

    with pytest.raises(prepare.ProductionPreparationError, match="unsafe entry"):
        prepare._tree_digest(website)


def test_publication_workflow_is_bound_to_ravage_origin_and_main(tmp_path: Path) -> None:
    repository = tmp_path / "ravage"
    workflows = repository / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "paired-xben.yml").write_text("name: paired-xben\n", encoding="utf-8")
    identity = "https://github.com/example/ravage/.github/workflows/paired-xben.yml@refs/heads/main"

    prepare._verify_publication_workflow(
        identity,
        ravage_repository=repository,
        ravage_origin="https://github.com/example/ravage.git",
    )
    with pytest.raises(prepare.ProductionPreparationError, match="differs from the Ravage origin"):
        prepare._verify_publication_workflow(
            identity,
            ravage_repository=repository,
            ravage_origin="https://github.com/another/ravage.git",
        )
    (workflows / "paired-xben.yml").unlink()
    with pytest.raises(prepare.ProductionPreparationError, match="absent"):
        prepare._verify_publication_workflow(
            identity,
            ravage_repository=repository,
            ravage_origin="https://github.com/example/ravage.git",
        )


def test_blocked_authenticity_retains_verified_release_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, _pricing = _request(tmp_path)
    _patch_ready_dependencies(monkeypatch, request)
    monkeypatch.setattr(
        prepare,
        "_authenticity_binding",
        lambda _request, **_kwargs: (
            {
                "ready": False,
                "error": "publication workflow is absent",
                "cosign_official_release_bundle_verified": True,
            },
            {"cosign_release_bundle": b"bundle\n", "sigstore_trusted_root": b"root\n"},
        ),
    )
    config = tmp_path / "prepare.json"
    config.write_text(json.dumps(request), encoding="utf-8")
    output = tmp_path / "evidence"

    result, _path = prepare.prepare_from_config(config, output)

    assert result["ready"] is False
    block_reasons = result["block_reasons"]
    assert isinstance(block_reasons, list)
    assert "authenticity_verifiers_unready" in block_reasons
    assert (output / prepare.COSIGN_RELEASE_BUNDLE_FILE).read_bytes() == b"bundle\n"
    assert (output / prepare.SIGSTORE_TRUSTED_ROOT_FILE).read_bytes() == b"root\n"
    status = (output / prepare.STATUS_FILE).read_text(encoding="utf-8")
    assert "publication workflow is absent" in status


def test_shared_target_agent_daemon_is_a_hard_preparation_blocker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, _pricing = _request(tmp_path)
    _patch_ready_dependencies(monkeypatch, request)
    monkeypatch.setattr(
        prepare,
        "_execution_binding",
        lambda *_args, **_kwargs: (
            {
                "ready": False,
                "error": (
                    "target and agent share one Docker daemon; an agent with that socket can "
                    "inspect target containers, mounted source, and flags"
                ),
                "environment_verified": True,
                "policy": _execution_policy(),
            },
            {"schema_version": prepare.EXECUTOR_CONFIG_SCHEMA, "mode": "paired_local"},
        ),
    )
    config = tmp_path / "prepare.json"
    config.write_text(json.dumps(request), encoding="utf-8")
    output = tmp_path / "evidence"

    result, _path = prepare.prepare_from_config(config, output)

    reasons = result["block_reasons"]
    assert isinstance(reasons, list)
    assert "execution_isolation_unsupported" in reasons
    assert not (output / prepare.RUN_CONTRACT_FILE).exists()
    assert not (output / prepare.EXECUTOR_CONFIG_FILE).exists()
    status = (output / prepare.STATUS_FILE).read_text(encoding="utf-8")
    assert "inspect target containers, mounted source, and flags" in status
    assert "randomness or entropy request" in status
    no_live_actions = result["no_live_actions"]
    assert isinstance(no_live_actions, Mapping)
    assert no_live_actions["paid_api_call_performed"] is False


def test_protocol_cli_prepare_reports_retained_blockers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        paired_cli,
        "prepare_from_config",
        lambda _config, _output: (
            {
                "ready": False,
                "block_reasons": ["oci_images_unready"],
                "no_live_actions": {
                    "case_draw_performed": False,
                    "model_call_performed": False,
                    "docker_pull_performed": False,
                    "docker_build_performed": False,
                },
            },
            tmp_path / "preflight.json",
        ),
    )

    exit_code = paired_cli.main(
        [
            "prepare",
            "--config",
            str(tmp_path / "request.json"),
            "--output-dir",
            str(tmp_path / "evidence"),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert output["ready"] is False
    assert output["block_reasons"] == ["oci_images_unready"]
    assert output["no_live_actions"]["model_call_performed"] is False
