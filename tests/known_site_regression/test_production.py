# ruff: noqa: ANN001,ANN003,ANN202,ARG002,EM101,SLF001,TRY003
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from ravage.xben_parts.comparison_model_gateway import (
    ModelGatewayPolicy,
    ModelPricing,
)

from tools.known_site_regression import harness, production
from tools.known_site_regression.production import (
    KnownSiteProductionError,
    build_production_configuration,
    execute_from_config,
    prepare_from_config,
)

_REAL_ORDER_SOURCE_VALIDATOR = production._validate_authenticated_order_source


@pytest.fixture(autouse=True)
def _no_live_paired_xben_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid executing retained verifier binaries or touching a real draw."""
    monkeypatch.setattr(
        production,
        "_validate_authenticated_order_source",
        lambda configuration: {
            "authenticated_order_source": {
                "ready": True,
                "derived_arm_order": list(configuration.contract.arm_order),
            }
        },
    )


def _digest(value: str | bytes) -> str:
    body = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _request(
    *,
    provider_path: Path | None = None,
    campaign_dir: Path | None = None,
    order_source_dir: Path | None = None,
) -> dict[str, object]:
    implementation = provider_path or Path("/opt/ravage/comparison_dual_daemon.py")
    policy = ModelGatewayPolicy.build(
        model="gpt-test-snapshot-2026-09-01",
        reasoning_effort="high",
        pricing=ModelPricing.from_numbers(
            input_per_million="0.75",
            cached_input_per_million="0.075",
            output_per_million="4.5",
        ),
        campaign_max_cost_usd="2",
        max_completion_tokens_per_request=100,
        max_request_body_bytes=1024,
        max_upstream_response_bytes=4096,
        upstream_timeout_seconds=10,
        max_parallel_requests=2,
    ).to_json()
    system = {
        "origin_url": "https://github.com/duriantaco/ravage.git",
        "repository": "/opt/ravage-source",
        "commit": "a" * 40,
        "tree": "b" * 40,
        "executable": "/opt/ravage-runtime/bin/ravage",
        "executable_sha256": "sha256:" + "1" * 64,
        "runtime_environment_manifest": "/opt/pins/ravage-runtime.json",
        "runtime_environment_manifest_sha256": "sha256:" + "2" * 64,
        "runtime_read_roots": ["/opt/ravage-runtime"],
        "tool_image_reference": "registry.example/ravage@sha256:" + "3" * 64,
        "tool_image_id": "sha256:" + "4" * 64,
        "tool_image_archive": "/opt/images/ravage-tool.tar",
        "tool_image_archive_sha256": "sha256:" + "0" * 64,
        "platform": "linux/amd64",
    }
    strix = {
        **system,
        "origin_url": "https://github.com/usestrix/strix.git",
        "repository": "/opt/strix-source",
        "commit": "c" * 40,
        "tree": "d" * 40,
        "executable": "/opt/strix-runtime/bin/strix",
        "executable_sha256": "sha256:" + "5" * 64,
        "runtime_environment_manifest": "/opt/pins/strix-runtime.json",
        "runtime_environment_manifest_sha256": "sha256:" + "6" * 64,
        "runtime_read_roots": ["/opt/strix-runtime"],
        "tool_image_reference": "registry.example/strix@sha256:" + "7" * 64,
        "tool_image_id": "sha256:" + "8" * 64,
        "tool_image_archive": "/opt/images/strix-tool.tar",
        "tool_image_archive_sha256": "sha256:" + "1" * 64,
    }
    return {
        "schema_version": production.PRODUCTION_REQUEST_SCHEMA,
        "campaign_id": "known-site-production-test",
        "canonical_campaign_directory": str(
            campaign_dir or Path("/opt/evidence/comparison/known-site-production-test")
        ),
        "authenticated_order_source": {
            "paired_campaign_directory": str(
                order_source_dir or Path("/opt/evidence/comparison/paired-xben-test")
            ),
            "paired_campaign_id": "paired-xben-test",
            "commitment_document_sha256": "sha256:" + "0" * 64,
            "preflight_document_sha256": "sha256:" + "1" * 64,
            "beacon_document_sha256": "sha256:" + "2" * 64,
            "selection_document_sha256": "sha256:" + "3" * 64,
            "draw_key_sha256": "sha256:" + "4" * 64,
            "website_content_sha256": "sha256:" + "5" * 64,
            "website_reference_sha256": "sha256:" + "6" * 64,
        },
        "site_source": {
            "origin_url": "https://github.com/duriantaco/ravage.git",
            "repository": "/opt/ravage-source",
            "commit": "a" * 40,
            "tree": "e" * 40,
            "relative_path": harness.KNOWN_SITE_SOURCE_PATH,
        },
        "systems": {"ravage": system, "strix": strix},
        "target_runtime": {
            "platform": "linux/amd64",
            "images": {
                name: {
                    "reference": f"registry.example/{name}@sha256:{index * 64}",
                    "expected_image_id": f"sha256:{index * 64}",
                }
                for index, name in zip(
                    ("1", "2", "3", "4"),
                    ("node_base", "proxy", "http_meter", "readiness_probe"),
                    strict=True,
                )
            },
            "http_meter": {
                "program_sha256": "5" * 64,
                "protocol": harness.HTTP_METER_PROTOCOL,
            },
            "dependency_lock": {
                "required": True,
                "relative_path": "web/package-lock.json",
                "sha256": "sha256:" + "6" * 64,
                "package_json_sha256": "sha256:" + "7" * 64,
                "installer": "npm-ci-omit-dev",
            },
            "proxy_configuration": {
                "relative_path": "proxy/nginx.conf",
                "sha256": "sha256:" + "8" * 64,
            },
        },
        "model_gateway_policy": policy,
        "limits": {
            "per_arm": {
                "wall_seconds": 60,
                "max_model_requests": 4,
                "max_target_requests": 30,
                "max_cost_usd": "1",
            },
            "campaign": {
                "wall_seconds": 130,
                "max_model_requests": 8,
                "max_target_requests": 60,
                "max_cost_usd": "2",
            },
        },
        "docker_separation": {
            "target": {
                "docker_executable": "/usr/local/bin/docker-target",
                "docker_executable_sha256": "sha256:" + "9" * 64,
                "docker_socket_path": "/private/tmp/target-docker.sock",
                "docker_socket_path_sha256": _digest("/private/tmp/target-docker.sock"),
                "docker_host": "unix:///private/tmp/target-docker.sock",
                "docker_host_sha256": _digest("unix:///private/tmp/target-docker.sock"),
                "daemon_identity_sha256": "sha256:" + "a" * 64,
            },
            "agent_vm": {
                "docker_executable": "/usr/local/bin/docker-target",
                "docker_executable_sha256": "sha256:" + "b" * 64,
                "controller_kind": "colima-lima-ephemeral-v1",
                "controller_implementation": "/opt/ravage/agent-vm-controller.py",
                "controller_implementation_sha256": "sha256:" + "c" * 64,
                "controller_policy": "/opt/pins/agent-vm-controller-policy.json",
                "controller_policy_sha256": "sha256:" + "d" * 64,
                "supervisor_executable": "/usr/local/bin/colima",
                "supervisor_executable_sha256": "sha256:" + "e" * 64,
                "supervisor_runtime_manifest": "/opt/pins/colima-runtime.json",
                "supervisor_runtime_manifest_sha256": "sha256:" + "0" * 64,
                "vm_template": "/opt/pins/agent-vm-template.yaml",
                "vm_template_sha256": "sha256:" + "1" * 64,
                "base_image": "/opt/images/agent-vm-base.qcow2",
                "base_image_sha256": "sha256:" + "2" * 64,
                "relay_implementation": "/opt/ravage/host-relay.py",
                "relay_implementation_sha256": "sha256:" + "3" * 64,
                "relay_policy": "/opt/pins/host-relay-policy.json",
                "relay_policy_sha256": "sha256:" + "4" * 64,
                "relay_enforcement_kind": "qemu-slirp-restrict-on-guestfwd-v1",
                "plans": {
                    row_id: {
                        "docker_socket_path": f"/private/tmp/agent-{index}.sock",
                        "docker_socket_path_sha256": _digest(f"/private/tmp/agent-{index}.sock"),
                        "docker_host": f"unix:///private/tmp/agent-{index}.sock",
                        "docker_host_sha256": _digest(f"unix:///private/tmp/agent-{index}.sock"),
                    }
                    for index, row_id in enumerate(harness.ROW_IDS, start=1)
                },
            },
        },
        "execution": {
            "trusted_path": "/usr/local/bin:/usr/bin:/bin",
            "sandbox_executable": "/usr/bin/sandbox-exec",
            "sandbox_executable_sha256": "sha256:" + "d" * 64,
            "upstream_api_key_environment": "OPENAI_API_KEY",
        },
        "isolation_provider": {
            "name": "reviewed-dual-daemon-metered-relay-v1",
            "implementation_path": str(implementation),
            "implementation_sha256": (
                _digest(implementation.read_bytes())
                if implementation.is_file()
                else "sha256:" + "f" * 64
            ),
            "target_meter_exposure": "target-host-loopback-only",
            "agent_visible_target_path": "independently-enforced-metered-relay",
        },
    }


def _write_executor(path: Path, request: dict[str, object]) -> None:
    configuration = build_production_configuration(request)
    contract = configuration.contract.to_document()
    body = {
        "schema_version": production.EXECUTOR_CONFIGURATION_SCHEMA,
        "classification": harness.KNOWN_SITE_CLASSIFICATION,
        "claim_boundary": harness.KNOWN_SITE_CLAIM_BOUNDARY,
        "eligible_for_sota_claim": False,
        "eligible_for_unseen_claim": False,
        "contract_sha256": contract["document_sha256"],
        "request_sha256": production._json_digest(request),
        "contract": contract,
        "request": request,
    }
    body["document_sha256"] = production._json_digest(body)
    path.write_text(
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def test_contract_builder_freezes_public_claim_boundary_and_all_systems() -> None:
    configuration = build_production_configuration(_request())
    contract = configuration.contract.to_document()

    assert contract["classification"]["eligible_for_sota_claim"] is False
    assert contract["classification"]["eligible_for_unseen_claim"] is False
    assert tuple(row["system"] for row in contract["schedule"]) == (
        configuration.contract.arm_order
    )
    assert (
        contract["execution_policy"]["arm_order_assignment"][
            "authenticated_future_randomness_required"
        ]
        is True
    )
    assert set(contract["systems"]) == {"ravage", "strix"}
    assert contract["docker_separation"]["shared_daemon_allowed"] is False
    agent_vm = contract["docker_separation"]["agent_vm"]
    assert "daemon_identity_sha256" not in json.dumps(agent_vm)
    assert set(agent_vm["plans"]) == set(harness.ROW_IDS)
    assert agent_vm["controller"]["policy_sha256"] == "sha256:" + "d" * 64
    assert agent_vm["controller"]["supervisor_runtime_manifest_sha256"] == ("sha256:" + "0" * 64)
    assert agent_vm["template"]["sha256"] == "sha256:" + "1" * 64
    assert agent_vm["base_image"] == {
        "sha256": "sha256:" + "2" * 64,
        "platform": "linux/amd64",
        "offline_required": True,
    }
    assert len({plan["generation_id"] for plan in agent_vm["plans"].values()}) == len(
        harness.ROW_IDS
    )


def test_checked_in_request_template_has_frozen_affordable_model_policy() -> None:
    template = Path(production.__file__).resolve().parent / "production-request.template.json"
    configuration = build_production_configuration(json.loads(template.read_text()))

    assert configuration.contract.model_gateway_policy["model"] == ("gpt-5.4-mini-2026-03-17")
    assert configuration.contract.model_gateway_policy["reasoning_effort"] == "high"
    assert str(configuration.contract.limits.max_cost_usd_per_arm) == "0.55"
    assert str(configuration.contract.limits.campaign_max_cost_usd) == "1.1"
    assert str(configuration.canonical_campaign_directory).startswith(
        "/Users/oha/ravage/runs/comparisons/20260911-strix-ravage-xben20/"
    )


def test_contract_builder_rejects_endpoint_text_not_bound_to_hash() -> None:
    request = _request()
    request["docker_separation"]["agent_vm"]["plans"]["primary-001"]["docker_host_sha256"] = (
        "sha256:" + "0" * 64
    )

    with pytest.raises(KnownSiteProductionError, match="endpoint text differs"):
        build_production_configuration(request)


def test_authenticated_order_source_is_required_before_production_can_arm() -> None:
    configuration = build_production_configuration(_request())

    with pytest.raises(KnownSiteProductionError, match="real resolved directory"):
        _REAL_ORDER_SOURCE_VALIDATOR(configuration)


def test_prepare_is_create_only_and_retains_no_live_action_block(
    tmp_path: Path,
    monkeypatch,
) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(_request()), encoding="utf-8")
    output = tmp_path / "preparation"
    monkeypatch.setattr(
        production,
        "_validate_configuration_pre_draw",
        lambda _configuration: {"local_pre_draw": {"ready": True}},
    )

    result, result_path = prepare_from_config(
        request_path,
        output,
        captured_at="2026-09-11T00:00:00Z",
    )

    assert result_path == output / production.PREPARATION_FILE
    assert result["ready"] is False
    assert result["block_reasons"] == [
        "authenticated_external_order_source_unready",
        "authenticated_order_source_retention_bridge_unavailable",
        "dual_daemon_metered_relay_provider_unavailable",
    ]
    assert result["eligible_for_sota_claim"] is False
    assert all(value is False for value in result["no_live_actions"].values())
    assert (output / production.DRAFT_CONTRACT_FILE).is_file()
    assert not (output / production.RUN_CONTRACT_FILE).exists()
    assert not (output / production.EXECUTOR_CONFIGURATION_FILE).exists()
    with pytest.raises(KnownSiteProductionError, match="overwrite/resume is forbidden"):
        prepare_from_config(request_path, output)


class _ExplodingEnvironment(dict[str, str]):
    def get(self, key, default=None):
        raise AssertionError("credential must not be read before isolation validation")


def test_execute_without_injected_bridge_fails_before_credential_and_campaign(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executor = tmp_path / "executor.json"
    campaign = tmp_path / "campaign"
    _write_executor(executor, _request(campaign_dir=campaign))
    monkeypatch.setattr(production, "_validate_configuration_pre_draw", lambda _value: {})

    with pytest.raises(KnownSiteProductionError, match="independently trusted"):
        execute_from_config(
            campaign,
            executor_config_path=executor,
            environment=_ExplodingEnvironment(),
        )

    assert not campaign.exists()


def test_executor_rejects_alternate_campaign_directory_before_preflight(
    tmp_path: Path,
    monkeypatch,
) -> None:
    canonical = tmp_path / "canonical"
    alternate = tmp_path / "alternate"
    executor = tmp_path / "executor.json"
    _write_executor(executor, _request(campaign_dir=canonical))
    monkeypatch.setattr(
        production,
        "_validate_configuration_pre_draw",
        lambda _value: pytest.fail("path aliases must fail before live preflight"),
    )

    with pytest.raises(KnownSiteProductionError, match="canonical path"):
        execute_from_config(
            alternate,
            executor_config_path=executor,
            environment=_ExplodingEnvironment(),
        )

    assert not canonical.exists()
    assert not alternate.exists()


def test_executor_cannot_upgrade_the_known_site_claim_boundary(tmp_path: Path) -> None:
    executor = tmp_path / "executor.json"
    campaign = tmp_path / "campaign"
    _write_executor(executor, _request(campaign_dir=campaign))
    payload = json.loads(executor.read_text(encoding="utf-8"))
    payload["eligible_for_sota_claim"] = True
    payload["document_sha256"] = production._json_digest(
        {key: value for key, value in payload.items() if key != "document_sha256"}
    )
    executor.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(KnownSiteProductionError, match="executor configuration is invalid"):
        execute_from_config(
            campaign,
            executor_config_path=executor,
            environment=_ExplodingEnvironment(),
        )


def test_execute_refuses_existing_campaign_before_live_preflight_or_credential(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executor = tmp_path / "executor.json"
    campaign = tmp_path / "claimed"
    _write_executor(executor, _request(campaign_dir=campaign))
    campaign.mkdir()
    monkeypatch.setattr(
        production,
        "_validate_configuration_pre_draw",
        lambda _value: pytest.fail("claimed campaigns must not be revalidated"),
    )

    with pytest.raises(KnownSiteProductionError, match="already claimed"):
        execute_from_config(
            campaign,
            executor_config_path=executor,
            environment=_ExplodingEnvironment(),
        )


class _RejectedProvider:
    def __init__(self, implementation_path: Path) -> None:
        self.implementation_path = implementation_path

    def validate_pre_draw(self, **kwargs) -> None:
        raise KnownSiteProductionError("relay attestation is absent")


class _PreparedProvider:
    def __init__(self, implementation_path: Path) -> None:
        self.implementation_path = implementation_path
        self.validation_calls = 0
        self.configuration = None

    def validate_pre_draw(self, **kwargs) -> None:
        self.validation_calls += 1
        self.configuration = kwargs["configuration"]

    def planned_agent_vm(self, *, row_id, generation_id):
        assert self.configuration is not None
        plan = self.configuration.agent_vm.plans[row_id]
        assert plan.generation_id == generation_id
        return plan

    def build_target_backend(self, **kwargs):
        raise AssertionError("prepare must not construct or start a target")

    def agent_tool_boundary(self, **kwargs):
        raise AssertionError("prepare must not provision an agent daemon")


class _DriftedPlanProvider(_PreparedProvider):
    def planned_agent_vm(self, *, row_id, generation_id):
        plan = super().planned_agent_vm(row_id=row_id, generation_id=generation_id)
        if row_id != "primary-001":
            return plan
        return type(plan)(
            row_id=plan.row_id,
            profile_name=plan.profile_name,
            generation_id=plan.generation_id,
            docker_host="unix:///private/tmp/uncommitted.sock",
            docker_socket=Path("/private/tmp/uncommitted.sock"),
            agent_network=plan.agent_network,
        )


def test_prepare_remains_blocked_without_authenticated_order_retention_bridge(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = Path(production.__file__).resolve()
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(_request(provider_path=implementation)), encoding="utf-8")
    output = tmp_path / "ready-preparation"
    provider = _PreparedProvider(implementation)
    monkeypatch.setattr(
        production,
        "_validate_configuration_pre_draw",
        lambda _configuration: {"local_pre_draw": {"ready": True}},
    )

    result, _result_path = prepare_from_config(
        request_path,
        output,
        isolation_provider=provider,  # type: ignore[arg-type]
        captured_at="2026-09-11T00:00:00Z",
    )

    assert result["ready"] is False
    assert result["block_reasons"] == [
        "authenticated_external_order_source_unready",
        "authenticated_order_source_retention_bridge_unavailable",
    ]
    assert provider.validation_calls == 1
    assert not (output / production.RUN_CONTRACT_FILE).exists()
    assert not (output / production.EXECUTOR_CONFIGURATION_FILE).exists()


def test_prepare_rejects_provider_plan_drift_without_executor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = Path(production.__file__).resolve()
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(_request(provider_path=implementation)), encoding="utf-8")
    output = tmp_path / "drifted-plan"
    provider = _DriftedPlanProvider(implementation)
    monkeypatch.setattr(
        production,
        "_validate_configuration_pre_draw",
        lambda _configuration: {"local_pre_draw": {"ready": True}},
    )

    result, _ = prepare_from_config(
        request_path,
        output,
        isolation_provider=provider,  # type: ignore[arg-type]
        captured_at="2026-09-11T00:00:00Z",
    )

    assert result["ready"] is False
    assert result["block_reasons"] == [
        "authenticated_external_order_source_unready",
        "authenticated_order_source_retention_bridge_unavailable",
        "dual_daemon_metered_relay_provider_unready",
    ]
    assert not (output / production.EXECUTOR_CONFIGURATION_FILE).exists()


def test_rejected_injected_bridge_fails_before_credential_and_campaign(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = Path(production.__file__).resolve()
    executor = tmp_path / "executor.json"
    campaign = tmp_path / "campaign"
    request = _request(provider_path=implementation, campaign_dir=campaign)
    _write_executor(executor, request)
    monkeypatch.setattr(production, "_validate_configuration_pre_draw", lambda _value: {})

    with pytest.raises(KnownSiteProductionError, match="independently trusted"):
        execute_from_config(
            campaign,
            executor_config_path=executor,
            isolation_provider=_RejectedProvider(implementation),  # type: ignore[arg-type]
            environment=_ExplodingEnvironment(),
        )

    assert not campaign.exists()


def test_production_defaults_never_invoke_campaign_retained_verifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_path = tmp_path / "request.json"
    preparation = tmp_path / "preparation"
    campaign = tmp_path / "campaign"
    executor = tmp_path / "executor.json"
    request = _request(campaign_dir=campaign)
    request_path.write_text(json.dumps(request), encoding="utf-8")
    _write_executor(executor, request)

    def forbidden_verification(_configuration: object) -> dict[str, object]:
        pytest.fail("campaign-retained verifier binaries must never be reached")

    monkeypatch.setattr(
        production,
        "_validate_authenticated_order_source",
        forbidden_verification,
    )
    monkeypatch.setattr(production, "_validate_configuration_pre_draw", lambda _value: {})

    prepared, _ = prepare_from_config(request_path, preparation)
    assert "authenticated_external_order_source_unready" in prepared["block_reasons"]
    assert "were not executed" in prepared["checks"]["authenticated_order_source"]["error"]

    with pytest.raises(KnownSiteProductionError, match="were not executed"):
        execute_from_config(
            campaign,
            executor_config_path=executor,
            environment=_ExplodingEnvironment(),
        )
    assert not campaign.exists()
