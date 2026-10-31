# ruff: noqa: ANN001,ANN002,ANN003,ANN201,ANN202,ARG001,ARG002,ARG005,EM101,FBT001,PLR0913,PLR2004,SLF001,TRY003
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path

import pytest
from ravage.xben_parts.comparison_adapters import ADAPTER_VERSION
from ravage.xben_parts.comparison_model_gateway import (
    MODEL_GATEWAY_SCHEMA,
    ModelGatewayPolicy,
    ModelPricing,
)

from tools.known_site_regression import harness
from tools.known_site_regression.cli import main as known_site_cli_main
from tools.known_site_regression.harness import (
    AgentArmContext,
    AgentArmTerminal,
    AgentVmPlanPin,
    AgentVmPolicyPin,
    AgentVmTeardownEvidence,
    CampaignAlreadyExistsError,
    DockerDaemonPin,
    DockerSeparationPolicy,
    FrozenKnownSiteContract,
    KnownSiteLimits,
    KnownSiteRegressionError,
    KnownSiteSystemPin,
    LiveAgentVmEvidence,
    LiveKnownSiteArm,
    PreparedKnownSiteTarget,
    SiteArmTeardown,
    SiteSourcePin,
    score_candidate_artifact,
    verify_known_site_regression,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _digest(value: bytes | str) -> str:
    body = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _document(body: dict[str, object]) -> dict[str, object]:
    result = dict(body)
    result["document_sha256"] = _digest(_canonical(result))
    return result


@pytest.fixture(autouse=True)
def _portable_agent_vm_lifecycle_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep coordinator tests independent of the generic receipt grammar."""

    def validate(*, provision_path: Path, teardown_path: Path, expectation) -> dict[str, object]:
        expected_row_id = expectation.row_id
        provision = json.loads(provision_path.read_text(encoding="utf-8"))
        teardown = json.loads(teardown_path.read_text(encoding="utf-8"))
        assert provision["row_id"] == expected_row_id
        assert teardown["row_id"] == expected_row_id
        return {
            "row_id": expected_row_id,
            "provision_file_sha256": _digest(provision_path.read_bytes()),
            "teardown_file_sha256": _digest(teardown_path.read_bytes()),
            "valid": True,
        }

    monkeypatch.setattr(harness, "validate_agent_daemon_lifecycle", validate)

    def validate_order(_snapshot: Path, *, contract_document) -> dict[str, object]:
        order = contract_document["authenticated_arm_order"]
        return {
            "schema_version": "ravage.paired-xben.verification.v1",
            "phase": "resolved",
            "structurally_valid": True,
            "claim_ready": False,
            "beacon_authenticity_verified": True,
            "publication_anchor_verified": True,
            "claim_ready_scope": "structural-protocol-integrity-only",
            "campaign_id": order["paired_campaign_id"],
            "commitment_digest": order["commitment_document_sha256"],
            "preflight_digest": order["preflight_document_sha256"],
            "beacon_digest": order["beacon_document_sha256"],
            "publication_anchor_digest": "sha256:" + "f" * 64,
            "selection_digest": order["selection_document_sha256"],
            "eligible_pool_digest": "sha256:" + "e" * 64,
            "selected_cases": 20,
        }

    monkeypatch.setattr(harness, "_validate_authenticated_order_snapshot", validate_order)


class FakeAuthenticatedOrderBackend:
    def validate_pre_draw(self, *, contract: FrozenKnownSiteContract) -> None:
        contract.to_document()

    def retain_snapshot(
        self,
        destination: Path,
        *,
        contract: FrozenKnownSiteContract,
    ) -> None:
        contract.to_document()
        destination.mkdir(parents=True, exist_ok=False)
        for relative in harness.AUTHENTICATED_ORDER_SNAPSHOT_FILES:
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((relative + "\n").encode())
            executable = relative in {"verifiers/drandverify", "verifiers/cosign"}
            path.chmod(0o700 if executable else 0o600)


def _policy() -> tuple[dict[str, object], str]:
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
    return policy, _digest(_canonical(policy))


def _agent_vm_policy(campaign_id: str) -> AgentVmPolicyPin:
    controller = "sha256:" + "a" * 64
    template = "sha256:" + "b" * 64
    base = "sha256:" + "c" * 64
    relay = "sha256:" + "d" * 64
    plans: dict[str, AgentVmPlanPin] = {}
    for index, row_id in enumerate(harness.ROW_IDS, start=1):
        generation = harness.derive_agent_vm_generation_id(
            campaign_id=campaign_id,
            row_id=row_id,
            controller_policy_sha256=controller,
            vm_template_sha256=template,
            base_image_sha256=base,
            relay_policy_sha256=relay,
        )
        socket = f"/private/tmp/known-site-agent-{index}.sock"
        plans[row_id] = AgentVmPlanPin(
            generation_id=generation,
            profile_name=f"ravage-agent-{row_id}-{generation[:16]}",
            docker_socket_path_sha256=_digest(socket),
            docker_host_sha256=_digest(f"unix://{socket}"),
            agent_network=f"ravage-agent-net-{row_id}-{generation[:16]}",
        )
    return AgentVmPolicyPin(
        docker_executable_sha256="sha256:" + "e" * 64,
        controller_kind="colima-lima-ephemeral-v1",
        controller_implementation_sha256="sha256:" + "f" * 64,
        controller_policy_sha256=controller,
        supervisor_executable_sha256="sha256:" + "0" * 64,
        supervisor_runtime_manifest_sha256="sha256:" + "2" * 64,
        vm_template_sha256=template,
        base_image_sha256=base,
        relay_implementation_sha256="sha256:" + "1" * 64,
        relay_policy_sha256=relay,
        relay_enforcement_kind="qemu-slirp-restrict-on-guestfwd-v1",
        plans=plans,
    )


def _contract(campaign_dir: Path | None = None) -> FrozenKnownSiteContract:
    policy, policy_digest = _policy()
    return FrozenKnownSiteContract(
        campaign_id="known-site-test",
        campaign_directory_sha256=_digest(
            (campaign_dir or Path("/private/tmp/known-site-test-evidence"))
            .resolve(strict=False)
            .as_posix()
        ),
        source=SiteSourcePin(
            origin_url="https://github.com/duriantaco/ravage.git",
            commit="a" * 40,
            tree="b" * 40,
        ),
        model_gateway_policy=policy,
        model_gateway_policy_sha256=policy_digest,
        limits=KnownSiteLimits.build(
            wall_seconds_per_arm=60,
            max_model_requests_per_arm=4,
            max_target_requests_per_arm=30,
            max_cost_usd_per_arm="1",
            campaign_wall_seconds=130,
            campaign_max_model_requests=8,
            campaign_max_target_requests=60,
            campaign_max_cost_usd="2",
        ),
        target_runtime={
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
        system_pins={
            "ravage": KnownSiteSystemPin(
                origin_url="https://github.com/duriantaco/ravage.git",
                commit="a" * 40,
                tree="b" * 40,
                runtime_manifest_sha256="sha256:" + "1" * 64,
                executable_sha256="sha256:" + "2" * 64,
                tool_image_reference="registry.example/ravage@sha256:" + "3" * 64,
                tool_image_id="sha256:" + "4" * 64,
                tool_image_archive_sha256="sha256:" + "0" * 64,
            ),
            "strix": KnownSiteSystemPin(
                origin_url="https://github.com/usestrix/strix.git",
                commit="c" * 40,
                tree="d" * 40,
                runtime_manifest_sha256="sha256:" + "5" * 64,
                executable_sha256="sha256:" + "6" * 64,
                tool_image_reference="registry.example/strix@sha256:" + "7" * 64,
                tool_image_id="sha256:" + "8" * 64,
                tool_image_archive_sha256="sha256:" + "1" * 64,
            ),
        },
        adapter_source_sha256="sha256:" + "9" * 64,
        authenticated_arm_order=harness.AuthenticatedArmOrderPin(
            paired_campaign_id="paired-xben-test",
            commitment_document_sha256="sha256:" + "8" * 64,
            preflight_document_sha256="sha256:" + "9" * 64,
            beacon_document_sha256="sha256:" + "a" * 64,
            selection_document_sha256="sha256:" + "b" * 64,
            draw_key_sha256="sha256:" + "c" * 64,
            website_content_sha256="sha256:" + "e" * 64,
            website_reference_sha256=_digest("content-addressed-website:" + "sha256:" + "e" * 64),
        ),
        docker_separation=DockerSeparationPolicy(
            target=DockerDaemonPin(
                docker_executable_sha256="sha256:" + "a" * 64,
                docker_socket_path_sha256="sha256:" + "b" * 64,
                docker_host_sha256="sha256:" + "c" * 64,
                daemon_identity_sha256="sha256:" + "d" * 64,
            ),
            agent_vm=_agent_vm_policy("known-site-test"),
        ),
    )


def _paired_order_inputs(
    contract: FrozenKnownSiteContract,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    known = contract.to_document()
    systems = known["systems"]
    assert isinstance(systems, dict)
    sources: dict[str, object] = {}
    runtimes: dict[str, object] = {}
    images = {
        "target_gateway": "registry.example/gateway@sha256:" + "a" * 64,
        "target_probe": "registry.example/probe@sha256:" + "b" * 64,
    }
    roles = {"ravage": "ravage_tool", "strix": "strix_sandbox"}
    for system in harness.SYSTEMS:
        pin = systems[system]
        assert isinstance(pin, dict)
        source = pin["source"]
        runtime = pin["runtime"]
        tool = pin["tool_image"]
        assert isinstance(source, dict)
        assert isinstance(runtime, dict)
        assert isinstance(tool, dict)
        sources[system] = {
            "origin_url": source["origin_url"],
            "commit_sha": source["commit"],
            "tree_object": source["tree"],
            "tree_path": source["tree_path"],
            "dirty": False,
        }
        runtimes[system] = {
            "schema_version": runtime["schema_version"],
            "sha256": runtime["manifest_sha256"],
            "executable_sha256": runtime["executable_sha256"],
        }
        images[roles[system]] = tool["reference"]
    paired = {
        "sources": sources,
        "runtime_manifests": runtimes,
        "oci_images": images,
        "execution_policy": {"platform": "linux/amd64"},
        "model_gateway": {"policy": known["model_gateway"]["policy"]},
        "budgets": {"per_row": known["budgets"]["per_arm"]},
    }
    order = known["authenticated_arm_order"]
    assert isinstance(order, dict)
    preflight = {"website": {"reference_sha256": order["website_reference_sha256"]}}
    return paired, preflight, known


class FakeGateway:
    def __init__(self, contract: FrozenKnownSiteContract) -> None:
        self.policy_digest = contract.model_gateway_policy_sha256
        self.events: list[tuple[object, ...]] = []
        self.tokens: dict[str, str] = {}

    def register_row(self, row_id, *, max_requests, max_cost_usd):
        token = f"token-{row_id}-" + "z" * 48
        self.tokens[row_id] = token
        self.events.append(("register", row_id, max_requests, str(max_cost_usd)))
        return token

    def start(self):
        assert tuple(self.tokens) == harness.ROW_IDS
        self.events.append(("start",))

    def close(self):
        self.events.append(("close",))


@dataclass
class _PreparedState:
    flags: dict[str, str]


class FakeTarget:
    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []
        self.prepared: PreparedKnownSiteTarget | None = None
        self.flags_by_arm: dict[str, dict[str, str]] = {}
        self._arm_roots: dict[str, Path] = {}
        self.contract: FrozenKnownSiteContract | None = None

    def validate_pre_draw(self, *, contract):
        contract.docker_separation.to_json(campaign_id=contract.campaign_id)
        self.contract = contract

    def prepare(
        self,
        *,
        contract,
        flags_by_environment,
        flag_commitments_sha256,
        private_root,
    ):
        root = private_root.parent
        assert (root / harness.FLAG_COMMITMENTS_FILE).is_file()
        assert not (root / harness.TARGET_PREPARATION_FILE).exists()
        self.events.append(("prepare", flag_commitments_sha256))
        self.prepared = PreparedKnownSiteTarget(
            source_archive_sha256=_digest(b"archive"),
            source_tree_sha256=_digest(b"tree"),
            image_ids_by_service={
                "proxy": "sha256:" + "1" * 64,
                "web": "sha256:" + "2" * 64,
                "internal": "sha256:" + "3" * 64,
            },
            build_count_by_service={"proxy": 0, "web": 1, "internal": 1},
            clean_pinned_archive_verified=True,
            flags_used_during_build=False,
            runtime_flag_injection_only=True,
            source_mounted_into_agent=False,
            operator_material_mounted_into_agent=False,
            credential_material_mounted_into_agent=False,
            backend_handle=_PreparedState(dict(flags_by_environment)),
        )
        return self.prepared

    def start_arm(
        self,
        *,
        prepared,
        row_id,
        system,
        instance_id,
        flags_by_environment,
        private_arm_root,
        max_target_requests,
    ):
        assert prepared is self.prepared
        state = prepared.backend_handle
        assert isinstance(state, _PreparedState)
        assert flags_by_environment == state.flags
        assert not (private_arm_root / "arm-score.json").exists()
        if row_id == "primary-002":
            # Arm one may have terminated, but the evaluator has not inspected
            # or published its score before arm two starts.
            first = private_arm_root.parent / "primary-001"
            assert (first / "arm-terminal.json").is_file()
            assert not (first / "arm-score.json").exists()
        self.flags_by_arm[row_id] = dict(flags_by_environment)
        self.events.append(("start", row_id, id(prepared)))
        logical_hashes = {
            logical: _digest(flags_by_environment[environment])
            for logical, environment in harness.FLAG_ENVIRONMENT
        }
        suffix = row_id[-3:]
        assert self.contract is not None
        policy = self.contract.docker_separation.agent_vm.to_json(
            campaign_id=self.contract.campaign_id
        )
        plan = policy["plans"][row_id]
        assert isinstance(plan, dict)
        agent_identity = "sha256:" + ("e" if row_id == "primary-001" else "f") * 64
        canary_value = harness.derive_target_canary_value(
            campaign_id=self.contract.campaign_id,
            row_id=row_id,
            instance_id=instance_id,
            generation_id=str(plan["generation_id"]),
        )
        canary_selector_sha256 = _digest(f"{harness.TARGET_CANARY_LABEL}={canary_value}")
        target_meter_url = f"http://127.0.0.1:{7000 + int(suffix)}"
        source_model_url = "http://127.0.0.1:7999/v1"
        agent_target_url = f"http://127.0.0.1:{9000 + int(suffix)}"
        agent_model_url = f"http://127.0.0.1:{8000 + int(suffix)}/v1"
        agent_root = private_arm_root / "agent-daemon"
        agent_root.mkdir(mode=0o700)
        self._arm_roots[row_id] = private_arm_root
        controller = policy["controller"]
        relay_policy = policy["relay"]
        assert isinstance(controller, dict)
        assert isinstance(relay_policy, dict)
        tool = self.contract.system_pins[system].to_json(system=system)["tool_image"]
        assert isinstance(tool, dict)
        provision = {
            "row_id": row_id,
            "controller_kind": controller["kind"],
            "controller_policy_sha256": controller["policy_sha256"],
            "relay_policy_sha256": relay_policy["policy_sha256"],
            **plan,
            "target_daemon_identity_sha256": (
                self.contract.docker_separation.target.daemon_identity_sha256
            ),
            "agent_daemon_identity_sha256": agent_identity,
            "target_canary_selector_sha256": canary_selector_sha256,
            "tool_image": {
                "reference": tool["reference"],
                "image_id": tool["expected_image_id"],
                "archive_sha256": tool["archive_sha256"],
                "platform": tool["platform"],
                "pull_performed": False,
            },
            "relay_receipt": {
                "enforcement_kind": relay_policy["enforcement_kind"],
                "target_meter_url_sha256": _digest(target_meter_url),
                "model_gateway_url_sha256": _digest(source_model_url),
            },
        }
        (agent_root / harness.AGENT_DAEMON_PROVISION_FILE).write_text(
            json.dumps(provision, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        (agent_root / harness.HOST_RELAY_PROBE_FILE).write_text("{}", encoding="utf-8")
        return LiveKnownSiteArm(
            row_id=row_id,
            system=system,
            instance_id=instance_id,
            target_url=agent_target_url,
            project_id=f"project-{suffix}",
            network_id=f"network-{suffix}",
            container_ids_by_service={
                service: f"container-{suffix}-{service}" for service in harness.SERVICE_NAMES
            },
            volume_ids=(f"volume-{suffix}-web", f"volume-{suffix}-internal"),
            image_ids_by_service=prepared.image_ids_by_service,
            runtime_flag_sha256_by_name=logical_hashes,
            build_invocations=0,
            pull_invocations=0,
            source_mounts=(),
            operator_material_mounts=(),
            credential_material_mounts=(),
            request_limit=max_target_requests,
            fresh=True,
            backend_handle={"row_id": row_id},
            agent_vm=LiveAgentVmEvidence(
                row_id=row_id,
                generation_id=str(plan["generation_id"]),
                profile_name=str(plan["profile_name"]),
                docker_socket_path_sha256=str(plan["docker_socket_path_sha256"]),
                docker_host_sha256=str(plan["docker_host_sha256"]),
                agent_network=str(plan["agent_network"]),
                agent_daemon_identity_sha256=agent_identity,
                target_canary_selector_sha256=canary_selector_sha256,
                target_meter_url_sha256=_digest(target_meter_url),
                model_gateway_url_sha256=_digest(source_model_url),
                agent_visible_target_url_sha256=_digest(agent_target_url),
                agent_visible_model_gateway_url_sha256=_digest(agent_model_url),
                frozen_policy_sha256=_digest(_canonical(policy)),
            ),
        )

    def stop_arm(self, *, live):
        self.events.append(("stop", live.row_id))
        assert live.agent_vm is not None
        teardown = {
            "row_id": live.row_id,
            "generation_id": live.agent_vm.generation_id,
        }
        # The provider retains teardown in the same row-owned lifecycle directory.
        # Recover it from the provision path saved on the live evidence root.
        agent_root = self._arm_roots[live.row_id] / "agent-daemon"
        (agent_root / harness.AGENT_DAEMON_TEARDOWN_FILE).write_text(
            json.dumps(teardown, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        return SiteArmTeardown(
            row_id=live.row_id,
            instance_id=live.instance_id,
            observed_target_requests=7,
            request_limit=live.request_limit,
            request_meter_sealed=True,
            request_meter_complete=True,
            containers_remaining=(),
            volumes_remaining=(),
            networks_remaining=(),
            removed_container_ids=tuple(live.container_ids_by_service.values()),
            removed_volume_ids=live.volume_ids,
            removed_network_ids=(live.network_id,),
            agent_vm=AgentVmTeardownEvidence(
                row_id=live.row_id,
                generation_id=live.agent_vm.generation_id,
            ),
        )

    def release(self, *, prepared):
        assert prepared is self.prepared
        self.events.append(("release", id(prepared)))
        return {"released": True, "prepared_images_retained": True}


class FakeAgent:
    def __init__(self, contract: FrozenKnownSiteContract, target: FakeTarget) -> None:
        self.contract = contract
        self.target = target
        self.events: list[tuple[object, ...]] = []

    def validate_pre_draw(self, *, contract: FrozenKnownSiteContract) -> None:
        assert contract is self.contract

    def run_arm(self, context: AgentArmContext) -> AgentArmTerminal:
        assert context.description == harness.KNOWN_SITE_PUBLIC_DESCRIPTION
        assert context.gateway_policy_sha256 == self.contract.model_gateway_policy_sha256
        if context.row_id == "primary-002":
            assert context.first_arm_evidence_forbidden == (
                context.evidence_dir.parent / "primary-001"
            )
        flags = sorted(self.target.flags_by_arm[context.row_id].values())
        candidates = flags[:3] if context.system == "ravage" else flags[-2:]
        socket_index = harness.ROW_IDS.index(context.row_id) + 1
        (context.native_output_dir / harness.CANDIDATE_ARTIFACT_PATH).write_text(
            "".join(f"{candidate}\n" for candidate in sorted(candidates)),
            encoding="utf-8",
        )
        candidate_sha256 = _digest(
            (context.native_output_dir / harness.CANDIDATE_ARTIFACT_PATH).read_bytes()
        )
        self._write_model_receipt(context)
        self.events.append(("run", context.row_id))
        return AgentArmTerminal(
            status="completed",
            returncode=0,
            timed_out=False,
            elapsed_seconds=5.0,
            description_sha256=_digest(context.description),
            semantic_prompt_sha256=_digest("same-semantic-prompt"),
            model_gateway_policy_sha256=context.gateway_policy_sha256,
            adapter_version=ADAPTER_VERSION,
            artifact_path=harness.CANDIDATE_ARTIFACT_PATH,
            artifact_sha256=candidate_sha256,
            adapter_receipt_path=None,
            process_receipt_path=None,
            model_receipt_path=harness.MODEL_RECEIPT_FILE,
            sandbox_profile_path=None,
            process_public_contract={
                "environment": {
                    "value_sha256": {
                        "RAVAGE_XBEN_TARGET_URL": _digest(str(context.target_url)),
                        "RAVAGE_XBEN_DESCRIPTION": _digest(context.description),
                        "RAVAGE_COMPARISON_GATEWAY_BASE_URL": _digest(
                            f"http://127.0.0.1:{8000 + int(context.row_id[-3:])}/v1"
                        ),
                    }
                },
                "sandbox": {
                    "docker_socket_access": True,
                    "docker_socket_path": f"/private/tmp/known-site-agent-{socket_index}.sock",
                },
            },
            evidence_class="paired_local",
        )

    def seal_unstarted(self, context: AgentArmContext, *, reason: str) -> AgentArmTerminal:
        self._write_model_receipt(context)
        return AgentArmTerminal(
            status="unstarted",
            returncode=-1,
            timed_out=False,
            elapsed_seconds=0,
            description_sha256=_digest(context.description),
            semantic_prompt_sha256=None,
            model_gateway_policy_sha256=context.gateway_policy_sha256,
            adapter_version=ADAPTER_VERSION,
            artifact_path=None,
            artifact_sha256=None,
            adapter_receipt_path=None,
            process_receipt_path=None,
            model_receipt_path=harness.MODEL_RECEIPT_FILE,
            sandbox_profile_path=None,
            process_public_contract=None,
            evidence_class="paired_local",
        )

    def _write_model_receipt(self, context: AgentArmContext) -> None:
        policy = dict(self.contract.model_gateway_policy)
        body: dict[str, object] = {
            "schema_version": MODEL_GATEWAY_SCHEMA,
            "created_at": "2026-09-11T00:00:00Z",
            "row_id": context.row_id,
            "row_token_sha256": _digest(context.gateway_token),
            "policy": policy,
            "policy_sha256": context.gateway_policy_sha256,
            "limits": {
                "max_requests": context.limits.max_model_requests,
                "max_cost_usd": str(Decimal(str(context.limits.max_cost_usd)).normalize()),
            },
            "totals": {
                "requests_started": 0,
                "requests_recorded": 0,
                "charged_cost_usd": "0",
                "known_actual_cost_usd": "0",
                "within_request_limit": True,
                "within_cost_limit": True,
            },
            "records": [],
            "valid": True,
        }
        receipt = _document(body)
        (context.evidence_dir / harness.MODEL_RECEIPT_FILE).write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )


class InvalidFirstTerminalAgent(FakeAgent):
    def run_arm(self, context: AgentArmContext) -> AgentArmTerminal:
        terminal = super().run_arm(context)
        if context.row_id == "primary-001":
            return AgentArmTerminal(
                **{
                    **terminal.__dict__,
                    "elapsed_seconds": context.limits.wall_seconds + 1.0,
                }
            )
        return terminal


class IncompleteReleaseTarget(FakeTarget):
    def release(self, *, prepared):
        assert prepared is self.prepared
        self.events.append(("release-incomplete", id(prepared)))
        return {"released": False, "prepared_images_retained": True}


class FirstStartFailsAndPoisonsTarget(FakeTarget):
    def start_arm(self, *, row_id, **kwargs):
        self.events.append(("start-failed", row_id))
        message = "target start failed" if row_id == "primary-001" else "target manager poisoned"
        raise KnownSiteRegressionError(message)


class FirstStopFailsAndPoisonsTarget(FakeTarget):
    poisoned = False

    def start_arm(self, *, row_id, **kwargs):
        if self.poisoned:
            self.events.append(("start-suppressed", row_id))
            raise KnownSiteRegressionError("target manager poisoned by prior stop failure")
        return super().start_arm(row_id=row_id, **kwargs)

    def stop_arm(self, *, live):
        self.events.append(("stop-failed", live.row_id))
        self.poisoned = True
        raise KnownSiteRegressionError("target stop failed and manager was poisoned")


class FirstArmOutcomeAgent(FakeAgent):
    def __init__(self, *args, first_status: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.first_status = first_status

    def run_arm(self, context: AgentArmContext) -> AgentArmTerminal:
        terminal = super().run_arm(context)
        if context.row_id != "primary-001":
            return terminal
        (context.native_output_dir / harness.ADAPTER_RECEIPT_FILE).write_text(
            "{}\n",
            encoding="utf-8",
        )
        (context.evidence_dir / harness.PROCESS_RECEIPT_FILE).write_text(
            "{}\n",
            encoding="utf-8",
        )
        (context.evidence_dir / harness.SANDBOX_PROFILE_FILE).write_text(
            "(version 1)\n",
            encoding="utf-8",
        )
        receipt_paths = {
            "adapter_receipt_path": (
                f"{harness.NATIVE_OUTPUT_DIRECTORY}/{harness.ADAPTER_RECEIPT_FILE}"
            ),
            "process_receipt_path": harness.PROCESS_RECEIPT_FILE,
            "sandbox_profile_path": harness.SANDBOX_PROFILE_FILE,
        }
        if self.first_status == "failed":
            return replace(
                terminal,
                status="failed",
                returncode=7,
                **receipt_paths,
                error="canonical agent exited nonzero",
            )
        if self.first_status == "timed_out":
            (context.native_output_dir / harness.CANDIDATE_ARTIFACT_PATH).unlink()
            return replace(
                terminal,
                status="timed_out",
                returncode=124,
                timed_out=True,
                artifact_path=None,
                artifact_sha256=None,
                **receipt_paths,
                error="canonical adapter reached its first-attempt timeout",
            )
        raise AssertionError("unsupported first-arm test outcome")


class FirstArmRaisesAgent(FakeAgent):
    def run_arm(self, context: AgentArmContext) -> AgentArmTerminal:
        if context.row_id == "primary-001":
            raise KnownSiteRegressionError("agent launch failed")
        return super().run_arm(context)


class MissingBridgeTarget(FakeTarget):
    def validate_pre_draw(self, *, contract):
        message = "dual-daemon metered bridge is unavailable"
        raise KnownSiteRegressionError(message)


class MissingRuntimeAgent(FakeAgent):
    def validate_pre_draw(self, *, contract: FrozenKnownSiteContract) -> None:
        assert contract is self.contract
        message = "package-only runtime is unavailable"
        raise KnownSiteRegressionError(message)


class MustNotValidateTarget(FakeTarget):
    def validate_pre_draw(self, *, contract):
        message = "target validation must follow agent runtime validation"
        raise AssertionError(message)


def test_known_site_limits_preserve_exact_cost_through_execution_contract() -> None:
    text = "1.0000000000000000000000000000000000001"
    limits = replace(
        _contract().limits,
        max_cost_usd_per_arm=Decimal(text),
        campaign_max_cost_usd=Decimal("2.0000000000000000000000000000000000002"),
    )

    external_limits = limits.external_limits()

    assert external_limits.max_cost_usd == Decimal(text)
    assert external_limits.to_json()["max_cost_usd"] == text


def test_known_site_limits_reject_float_cost_caps() -> None:
    with pytest.raises(ValueError, match="per-arm cost limit"):
        KnownSiteLimits.build(
            wall_seconds_per_arm=60,
            max_model_requests_per_arm=4,
            max_target_requests_per_arm=30,
            max_cost_usd_per_arm=1.0,  # type: ignore[arg-type]
            campaign_wall_seconds=130,
            campaign_max_model_requests=8,
            campaign_max_target_requests=60,
            campaign_max_cost_usd="2",
        )


def test_contract_is_explicitly_known_public_and_never_sota() -> None:
    contract = _contract()
    document = contract.to_document()

    assert document["classification"] == {
        "kind": "known_site_regression",
        "claim_boundary": "not_sota_not_unseen_not_holdout",
        "target_source_is_public": True,
        "vulnerability_classes_are_public": True,
        "eligible_for_sota_claim": False,
        "eligible_for_unseen_claim": False,
        "eligible_for_holdout_claim": False,
        "purpose": "paired-known-site-end-to-end-regression-only",
    }
    encoded = json.dumps(document)
    assert "OPERATOR_NOTES" in encoded  # exclusion is declared, never its contents
    assert "market-dev-secret" not in encoded
    assert "seeded" not in encoded.lower()
    assert [row["system"] for row in document["schedule"]] == list(contract.arm_order)
    assert set(document["systems"]) == {"ravage", "strix"}
    assert document["comparison_adapter"]["adapter_version"] == ADAPTER_VERSION
    assert document["docker_separation"]["shared_daemon_allowed"] is False
    agent_vm = document["docker_separation"]["agent_vm"]
    assert "daemon_identity_sha256" not in json.dumps(agent_vm)
    assert set(agent_vm["plans"]) == set(harness.ROW_IDS)


def test_arm_order_is_derived_from_authenticated_future_beacon() -> None:
    document = _contract().to_document()
    source = document["authenticated_arm_order"]
    assert tuple(row["system"] for row in document["schedule"]) == harness.derive_arm_order(
        source["draw_key_sha256"],
        source["website_identity_sha256"],
    )
    assignment = document["execution_policy"]["arm_order_assignment"]
    assert assignment["method"] == harness.ARM_ORDER_DOMAIN
    assert assignment["source_protocol"] == harness.AUTHENTICATED_ARM_ORDER_PROTOCOL
    assert assignment["authenticated_future_randomness_required"] is True
    assert "campaign_id_sha256" not in assignment


def test_campaign_id_cannot_change_authenticated_arm_order() -> None:
    contract = _contract()
    renamed = FrozenKnownSiteContract(**{**contract.__dict__, "campaign_id": "renamed-test"})
    assert renamed.arm_order == contract.arm_order


def test_every_post_beacon_execution_category_is_excluded_from_arm_order() -> None:
    contract = _contract()
    baseline_identity = contract.website_order_identity_sha256
    baseline_order = contract.arm_order
    variants: list[FrozenKnownSiteContract] = []

    renamed_campaign = "renamed-valid-campaign"
    variants.append(
        replace(
            contract,
            campaign_id=renamed_campaign,
            docker_separation=replace(
                contract.docker_separation,
                agent_vm=_agent_vm_policy(renamed_campaign),
            ),
        )
    )
    variants.append(replace(contract, campaign_directory_sha256="sha256:" + "0" * 64))
    variants.append(
        replace(
            contract,
            limits=KnownSiteLimits.build(
                wall_seconds_per_arm=contract.limits.wall_seconds_per_arm,
                max_model_requests_per_arm=contract.limits.max_model_requests_per_arm,
                max_target_requests_per_arm=contract.limits.max_target_requests_per_arm,
                max_cost_usd_per_arm=contract.limits.max_cost_usd_per_arm,
                campaign_wall_seconds=contract.limits.campaign_wall_seconds + 1,
                campaign_max_model_requests=contract.limits.campaign_max_model_requests,
                campaign_max_target_requests=contract.limits.campaign_max_target_requests,
                campaign_max_cost_usd=contract.limits.campaign_max_cost_usd,
            ),
        )
    )
    target_runtime = deepcopy(contract.target_runtime)
    target_runtime["images"]["node_base"]["expected_image_id"] = "sha256:" + "f" * 64
    variants.append(replace(contract, target_runtime=target_runtime))
    variants.append(replace(contract, adapter_source_sha256="sha256:" + "0" * 64))
    variants.append(
        replace(
            contract,
            docker_separation=replace(
                contract.docker_separation,
                target=DockerDaemonPin(
                    docker_executable_sha256="sha256:" + "0" * 64,
                    docker_socket_path_sha256="sha256:" + "1" * 64,
                    docker_host_sha256="sha256:" + "2" * 64,
                    daemon_identity_sha256="sha256:" + "3" * 64,
                ),
                agent_vm=replace(
                    contract.docker_separation.agent_vm,
                    docker_executable_sha256="sha256:" + "4" * 64,
                    controller_implementation_sha256="sha256:" + "5" * 64,
                    supervisor_executable_sha256="sha256:" + "6" * 64,
                    supervisor_runtime_manifest_sha256="sha256:" + "7" * 64,
                    relay_implementation_sha256="sha256:" + "8" * 64,
                ),
            ),
        )
    )
    for system in harness.SYSTEMS:
        for field_name, digest in (
            ("tool_image_id", "sha256:" + "9" * 64),
            ("tool_image_archive_sha256", "sha256:" + "a" * 64),
        ):
            systems = dict(contract.system_pins)
            systems[system] = replace(systems[system], **{field_name: digest})
            variants.append(replace(contract, system_pins=systems))

    for variant in variants:
        variant.to_document()
        assert variant.website_order_identity_sha256 == baseline_identity
        assert variant.arm_order == baseline_order


def test_every_precommitted_order_category_is_cross_bound() -> None:
    paired, preflight, known = _paired_order_inputs(_contract())
    harness._validate_precommitted_order_identity_inputs(
        paired_contract=paired,
        paired_preflight=preflight,
        known_contract=known,
    )

    mutations: list[tuple[str, dict[str, object], dict[str, object]]] = []
    changed = deepcopy(paired)
    changed["sources"]["ravage"]["commit_sha"] = "f" * 40
    mutations.append(("source", changed, deepcopy(preflight)))
    changed = deepcopy(paired)
    changed["runtime_manifests"]["strix"]["sha256"] = "sha256:" + "f" * 64
    mutations.append(("runtime", changed, deepcopy(preflight)))
    changed = deepcopy(paired)
    changed["oci_images"]["ravage_tool"] = "registry.example/other@sha256:" + "f" * 64
    mutations.append(("tool image", changed, deepcopy(preflight)))
    changed = deepcopy(paired)
    changed["execution_policy"]["platform"] = "linux/arm64"
    mutations.append(("tool image", changed, deepcopy(preflight)))
    changed = deepcopy(paired)
    changed["model_gateway"]["policy"]["model"] = "different-model"
    mutations.append(("model policies", changed, deepcopy(preflight)))
    changed = deepcopy(paired)
    changed["budgets"]["per_row"]["wall_seconds"] += 1
    mutations.append(("per-arm budgets", changed, deepcopy(preflight)))
    changed_preflight = deepcopy(preflight)
    changed_preflight["website"]["reference_sha256"] = "sha256:" + "f" * 64
    mutations.append(("website reference", deepcopy(paired), changed_preflight))

    for expected_error, changed_contract, changed_preflight in mutations:
        with pytest.raises(harness.EvidenceValidationError, match=expected_error):
            harness._validate_precommitted_order_identity_inputs(
                paired_contract=changed_contract,
                paired_preflight=changed_preflight,
                known_contract=known,
            )


def test_campaign_path_alias_fails_before_preflight_or_entropy(tmp_path: Path) -> None:
    canonical = tmp_path / "canonical"
    alternate = tmp_path / "alternate"
    contract = _contract(canonical)

    with pytest.raises(KnownSiteRegressionError, match="canonical destination"):
        harness._execute_with_entropy(
            alternate,
            contract=contract,
            gateway=FakeGateway(contract),
            target_backend=MustNotValidateTarget(),
            agent_backend=MissingRuntimeAgent(contract, MustNotValidateTarget()),
            authenticated_order_backend=FakeAuthenticatedOrderBackend(),
            entropy=lambda _size: pytest.fail("path mismatch must precede entropy"),
            clock=lambda: 0.0,
        )

    assert not canonical.exists()
    assert not alternate.exists()


def test_contract_rejects_shared_target_and_agent_docker_authority() -> None:
    contract = _contract()
    target = contract.docker_separation.target
    policy = contract.docker_separation.agent_vm
    first = policy.plans["primary-001"]
    bad_policy = AgentVmPolicyPin(
        **{
            **policy.__dict__,
            "plans": {
                **policy.plans,
                "primary-001": AgentVmPlanPin(
                    **{
                        **first.__dict__,
                        "docker_socket_path_sha256": target.docker_socket_path_sha256,
                        "docker_host_sha256": target.docker_host_sha256,
                    }
                ),
            },
        }
    )
    invalid = FrozenKnownSiteContract(
        **{
            **contract.__dict__,
            "docker_separation": DockerSeparationPolicy(
                target=target,
                agent_vm=bad_policy,
            ),
        }
    )

    with pytest.raises(ValueError, match="independently distinct"):
        invalid.to_document()


def test_missing_dual_daemon_bridge_fails_before_claim_or_entropy(tmp_path: Path) -> None:
    campaign = tmp_path / "must-not-be-claimed"
    contract = _contract(campaign)
    target = MissingBridgeTarget()

    with pytest.raises(KnownSiteRegressionError, match="dual-daemon metered bridge"):
        harness._execute_with_entropy(
            campaign,
            contract=contract,
            gateway=FakeGateway(contract),
            target_backend=target,
            agent_backend=FakeAgent(contract, target),
            authenticated_order_backend=FakeAuthenticatedOrderBackend(),
            entropy=lambda _size: pytest.fail("preflight failure must precede entropy"),
            clock=lambda: 0.0,
        )

    assert not campaign.exists()


def test_missing_package_runtime_fails_before_target_validation_or_entropy(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "must-not-be-claimed"
    contract = _contract(campaign)
    target = MustNotValidateTarget()

    with pytest.raises(KnownSiteRegressionError, match="package-only runtime"):
        harness._execute_with_entropy(
            campaign,
            contract=contract,
            gateway=FakeGateway(contract),
            target_backend=target,
            agent_backend=MissingRuntimeAgent(contract, target),
            authenticated_order_backend=FakeAuthenticatedOrderBackend(),
            entropy=lambda _size: pytest.fail("entropy must remain untouched"),
            clock=lambda: 0.0,
        )

    assert not campaign.exists()


def test_missing_authenticated_order_evidence_fails_before_claim_or_entropy(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "must-not-be-claimed"
    contract = _contract(campaign)
    target = FakeTarget()

    with pytest.raises(KnownSiteRegressionError, match="order-evidence backend"):
        harness._execute_with_entropy(
            campaign,
            contract=contract,
            gateway=FakeGateway(contract),
            target_backend=target,
            agent_backend=FakeAgent(contract, target),
            entropy=lambda _size: pytest.fail("entropy must remain untouched"),
            clock=lambda: 0.0,
        )

    assert not campaign.exists()


def test_complete_contract_validator_rejects_rehashed_policy_weakening() -> None:
    document = _contract().to_document()
    document["flags"]["redraw_allowed"] = True
    document["document_sha256"] = _digest(
        _canonical({name: value for name, value in document.items() if name != "document_sha256"})
    )

    with pytest.raises(harness.EvidenceValidationError, match="complete frozen schema"):
        harness._validate_contract_document(document)


def test_score_reads_only_strict_normalized_allowlisted_candidate_file(
    tmp_path: Path,
) -> None:
    expected = [f"flag{{ravage_site_{index:064x}}}" for index in range(5)]
    expected_hashes = [_digest(value) for value in expected]
    output = tmp_path / "native-output"
    output.mkdir()
    candidates = sorted((expected[0], expected[3], "flag{unrelated-proof}"))
    (output / harness.CANDIDATE_ARTIFACT_PATH).write_text(
        "".join(f"{value}\n" for value in candidates), encoding="utf-8"
    )
    (output / "stdout.log").write_text(expected[4], encoding="utf-8")

    scored = score_candidate_artifact(output, expected_flag_sha256=expected_hashes)

    assert scored["status"] == "scored"
    assert scored["score"] == 2
    assert scored["matched_flag_sha256"] == sorted((expected_hashes[0], expected_hashes[3]))

    (output / harness.CANDIDATE_ARTIFACT_PATH).write_text(
        f"{expected[0]}\n{expected[0]}\n", encoding="utf-8"
    )
    invalid = score_candidate_artifact(output, expected_flag_sha256=expected_hashes)
    assert invalid["status"] == "invalid_not_sorted_unique"
    assert invalid["score"] == 0


def test_one_shot_coordinator_commits_once_builds_once_and_scores_after_both(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = tmp_path / "site-campaign"
    contract = _contract(campaign)
    gateway = FakeGateway(contract)
    target = FakeTarget()
    agent = FakeAgent(contract, target)
    entropy_calls: list[int] = []

    def entropy(size: int) -> str:
        entropy_calls.append(size)
        return f"{len(entropy_calls):064x}"

    # Canonical process receipt validation is covered by its owning module.
    # This coordinator test isolates sequencing and target/score invariants.
    monkeypatch.setattr(harness, "_verify_agent_receipts", lambda *args, **kwargs: True)
    report = harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=gateway,
        target_backend=target,
        agent_backend=agent,
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=entropy,
        clock=lambda: 100.0,
    )

    assert entropy_calls == [32] * 5
    assert [event[0] for event in target.events].count("prepare") == 1
    assert [event[0] for event in target.events].count("start") == 2
    assert target.flags_by_arm["primary-001"] == target.flags_by_arm["primary-002"]
    starts = [event for event in target.events if event[0] == "start"]
    assert starts[0][2] == starts[1][2]
    assert gateway.events[:2] == [
        ("register", "primary-001", 4, "1"),
        ("register", "primary-002", 4, "1"),
    ]
    assert gateway.events[-1] == ("close",)
    assert report["scores_out_of_five"] == {"ravage": 3, "strix": 2}
    assert report["eligible_for_sota_claim"] is False
    assert report["eligible_for_unseen_claim"] is False
    assert report["valid_for_paired_known_site_regression"] is True
    assert report["agent_vm_lifecycle_valid"] is True
    assert verify_known_site_regression(campaign)["structurally_valid"] is True
    first_terminal = json.loads(
        (campaign / "private" / "primary-001" / "arm-terminal.json").read_text(encoding="utf-8")
    )
    assert all(
        first_terminal["receipts"][name] is not None
        for name in (
            "agent_vm_provision",
            "agent_vm_relay_probes",
            "agent_vm_teardown",
        )
    )
    assert (
        first_terminal["artifact_sha256"]
        == first_terminal["receipts"]["candidate_artifact"]["file_sha256"]
    )

    raw_entropy = tuple(f"{index:064x}" for index in range(1, 6))
    rendered_flags = tuple(f"flag{{ravage_site_{value}}}" for value in raw_entropy)
    for evidence_path in campaign.rglob("*.json"):
        evidence_body = evidence_path.read_text(encoding="utf-8")
        assert not any(value in evidence_body for value in raw_entropy)
        assert not any(value in evidence_body for value in rendered_flags)
    for row_id in harness.ROW_IDS:
        target_start = json.loads(
            (campaign / "private" / row_id / "target-start.json").read_text(encoding="utf-8")
        )
        assert not any(target_start["instance_id"].endswith(value[:24]) for value in raw_entropy)

    first_candidates = (
        campaign / "private" / "primary-001" / "native-output" / harness.CANDIDATE_ARTIFACT_PATH
    )
    first_candidates.write_text("flag{tampered-after-seal}\n", encoding="utf-8")
    tampered = verify_known_site_regression(campaign)
    assert tampered["structurally_valid"] is False
    assert tampered["eligible_for_sota_claim"] is False

    with pytest.raises(CampaignAlreadyExistsError):
        harness._execute_with_entropy(
            campaign,
            contract=contract,
            gateway=FakeGateway(contract),
            target_backend=FakeTarget(),
            agent_backend=FakeAgent(contract, FakeTarget()),
            authenticated_order_backend=FakeAuthenticatedOrderBackend(),
            entropy=lambda _size: pytest.fail("existing campaign must fail before entropy"),
            clock=lambda: 100.0,
        )


def test_offline_vm_join_rejects_self_consistent_receipt_from_wrong_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = tmp_path / "vm-policy-join"
    contract = _contract(campaign)
    target = FakeTarget()
    monkeypatch.setattr(harness, "_verify_agent_receipts", lambda *args, **kwargs: True)
    counter = 0

    def entropy(_size: int) -> str:
        nonlocal counter
        counter += 1
        return f"{counter:064x}"

    harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=FakeGateway(contract),
        target_backend=target,
        agent_backend=FakeAgent(contract, target),
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=entropy,
        clock=lambda: 100.0,
    )
    arm_root = campaign / "private" / "primary-001"
    start = json.loads((arm_root / "target-start.json").read_text(encoding="utf-8"))
    stop = json.loads((arm_root / "target-stop.json").read_text(encoding="utf-8"))
    provision_path = arm_root / "agent-daemon" / harness.AGENT_DAEMON_PROVISION_FILE
    provision = json.loads(provision_path.read_text(encoding="utf-8"))
    provision["controller_policy_sha256"] = "sha256:" + "9" * 64
    provision_path.write_text(
        json.dumps(provision, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    start["agent_vm"]["provision_receipt"]["file_sha256"] = _digest(provision_path.read_bytes())

    with pytest.raises(harness.EvidenceValidationError, match="frozen campaign"):
        harness._validate_agent_vm_terminal_pair(
            start,
            stop,
            arm_root=arm_root,
            contract_document=contract.to_document(),
            expected_row_id="primary-001",
            expected_system="ravage",
        )


def test_duplicate_entropy_claims_visible_incomplete_attempt_without_redraw(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "collision"
    contract = _contract(campaign)
    calls = 0

    def duplicate(_size: int) -> str:
        nonlocal calls
        calls += 1
        return "f" * 64

    with pytest.raises(KnownSiteRegressionError, match="duplicate flag entropy"):
        harness._execute_with_entropy(
            campaign,
            contract=contract,
            gateway=FakeGateway(contract),
            target_backend=FakeTarget(),
            agent_backend=FakeAgent(contract, FakeTarget()),
            authenticated_order_backend=FakeAuthenticatedOrderBackend(),
            entropy=duplicate,
            clock=lambda: 0.0,
        )

    assert calls == 5
    assert (campaign / harness.CONTRACT_FILE).is_file()
    assert not (campaign / harness.FLAG_COMMITMENTS_FILE).exists()
    with pytest.raises(CampaignAlreadyExistsError):
        harness._execute_with_entropy(
            campaign,
            contract=contract,
            gateway=FakeGateway(contract),
            target_backend=FakeTarget(),
            agent_backend=FakeAgent(contract, FakeTarget()),
            authenticated_order_backend=FakeAuthenticatedOrderBackend(),
            entropy=lambda _size: pytest.fail("collision attempt cannot be redrawn"),
            clock=lambda: 0.0,
        )


def test_gateway_policy_mismatch_fails_before_claim(tmp_path: Path) -> None:
    campaign = tmp_path / "not-claimed"
    contract = _contract(campaign)
    gateway = FakeGateway(contract)
    gateway.policy_digest = "sha256:" + "0" * 64

    with pytest.raises(KnownSiteRegressionError, match="gateway policy differs"):
        harness._execute_with_entropy(
            campaign,
            contract=contract,
            gateway=gateway,
            target_backend=FakeTarget(),
            agent_backend=FakeAgent(contract, FakeTarget()),
            authenticated_order_backend=FakeAuthenticatedOrderBackend(),
            entropy=lambda _size: "1" * 64,
            clock=lambda: 0.0,
        )

    assert not campaign.exists()


def test_invalid_first_terminal_is_retained_and_does_not_cancel_second_arm(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "terminal-failure"
    contract = _contract(campaign)
    target = FakeTarget()
    gateway = FakeGateway(contract)
    agent = InvalidFirstTerminalAgent(contract, target)
    draws = iter(f"{index:064x}" for index in range(10, 15))

    report = harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=gateway,
        target_backend=target,
        agent_backend=agent,
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=lambda _size: next(draws),
        clock=lambda: 1.0,
    )

    assert agent.events == [("run", "primary-001"), ("run", "primary-002")]
    assert [event[:2] for event in target.events if event[0] in {"start", "stop"}] == [
        ("start", "primary-001"),
        ("stop", "primary-001"),
        ("start", "primary-002"),
        ("stop", "primary-002"),
    ]
    first_terminal = json.loads(
        (campaign / "private" / "primary-001" / "arm-terminal.json").read_text(encoding="utf-8")
    )
    assert first_terminal["status"] == "unstarted"
    assert "process timing is invalid" in first_terminal["error"]
    assert report["valid_for_paired_known_site_regression"] is False


def _terminal_state_document(
    contract: FrozenKnownSiteContract,
    *,
    status: str,
    returncode: int,
    timed_out: bool,
    target_started: bool,
    target_stopped: bool,
    error: str | None,
) -> dict[str, object]:
    launched = status != "unstarted"
    artifact = status in {"completed", "failed"}
    launched_receipt = {
        "path": "placeholder",
        "file_sha256": _digest("placeholder"),
        "size_bytes": 1,
    }
    return harness._document(
        {
            "schema_version": harness.ARM_TERMINAL_SCHEMA,
            "created_at": "2026-09-12T00:00:00Z",
            "row_id": "primary-001",
            "system": contract.arm_order[0],
            "status": status,
            "returncode": returncode,
            "timed_out": timed_out,
            "elapsed_seconds": 5.0 if launched else 0.0,
            "description_sha256": _digest(harness.KNOWN_SITE_PUBLIC_DESCRIPTION),
            "semantic_prompt_sha256": _digest("same-semantic-prompt") if launched else None,
            "model_gateway_policy_sha256": contract.model_gateway_policy_sha256,
            "adapter_version": ADAPTER_VERSION,
            "artifact_path": harness.CANDIDATE_ARTIFACT_PATH if artifact else None,
            "artifact_sha256": _digest("candidate") if artifact else None,
            "evidence_class": "paired_local",
            "process_public_contract": {"bound": True} if launched else None,
            "target_started": target_started,
            "target_start_sha256": _digest("start") if target_started else None,
            "target_stopped": target_stopped,
            "target_stop_sha256": _digest("stop") if target_stopped else None,
            "receipts": {
                "candidate_artifact": None,
                "adapter": launched_receipt if launched else None,
                "process": launched_receipt if launched else None,
                "model": launched_receipt if launched else None,
                "sandbox_profile": launched_receipt if launched else None,
                "agent_vm_provision": None,
                "agent_vm_relay_probes": None,
                "agent_vm_teardown": None,
            },
            "error": error,
            "attempt": 1,
            "retry_allowed": False,
            "resume_allowed": False,
            "replacement_allowed": False,
        }
    )


@pytest.mark.parametrize(
    (
        "status",
        "returncode",
        "timed_out",
        "started",
        "stopped",
        "error",
        "successful",
        "reportable",
    ),
    [
        ("completed", 0, False, True, True, None, True, True),
        ("failed", 7, False, True, True, "agent exited nonzero", False, True),
        ("failed", 0, False, True, False, "target stop failed", False, False),
        ("timed_out", 124, True, True, True, "first attempt timed out", False, True),
        ("unstarted", -1, False, False, False, "target start failed", False, False),
        ("unstarted", -1, False, True, True, "agent launch failed", False, False),
    ],
)
def test_terminal_state_table_accepts_truthful_first_attempt_outcomes(
    status: str,
    returncode: int,
    timed_out: bool,
    started: bool,
    stopped: bool,
    error: str | None,
    successful: bool,
    reportable: bool,
) -> None:
    contract = _contract()
    terminal = _terminal_state_document(
        contract,
        status=status,
        returncode=returncode,
        timed_out=timed_out,
        target_started=started,
        target_stopped=stopped,
        error=error,
    )

    assert (
        harness._validate_terminal_contract(
            terminal,
            contract=contract.to_document(),
        )
        is successful
    )
    assert harness._terminal_is_reportable_observation(terminal) is reportable


@pytest.mark.parametrize(
    ("status", "returncode", "timed_out", "artifact"),
    [
        ("failed", 7, False, True),
        ("timed_out", 124, True, False),
    ],
)
def test_started_loss_without_public_process_contract_is_not_reportable(
    status: str,
    returncode: int,
    timed_out: bool,
    artifact: bool,
) -> None:
    contract = _contract()
    terminal = _terminal_state_document(
        contract,
        status=status,
        returncode=returncode,
        timed_out=timed_out,
        target_started=True,
        target_stopped=True,
        error="forged started loss",
    )
    terminal = {key: value for key, value in terminal.items() if key != "document_sha256"}
    terminal["process_public_contract"] = None
    if not artifact:
        terminal["artifact_path"] = None
        terminal["artifact_sha256"] = None
    terminal = harness._document(terminal)

    assert harness._validate_terminal_contract(terminal, contract=contract.to_document()) is False
    assert harness._terminal_is_reportable_observation(terminal) is False


def test_non_mapping_public_process_contract_is_rejected() -> None:
    contract = _contract()
    terminal = _terminal_state_document(
        contract,
        status="failed",
        returncode=7,
        timed_out=False,
        target_started=True,
        target_stopped=True,
        error="forged started loss",
    )
    terminal = {key: value for key, value in terminal.items() if key != "document_sha256"}
    terminal["process_public_contract"] = "claimed-valid"
    terminal = harness._document(terminal)

    with pytest.raises(harness.EvidenceValidationError, match="process public contract"):
        harness._validate_terminal_contract(terminal, contract=contract.to_document())
    assert harness._terminal_is_reportable_observation(terminal) is False


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"target_stopped": False, "target_stop_sha256": None}, "completed arm"),
        ({"status": "failed", "error": "claimed failure"}, "failed arm"),
        ({"status": "timed_out", "timed_out": True}, "timed-out arm"),
        ({"status": "unstarted", "error": "not started"}, "unstarted arm"),
        ({"target_started": False, "target_start_sha256": None}, "one-shot contract"),
    ],
)
def test_terminal_state_table_rejects_contradictory_outcomes(
    changes: dict[str, object],
    message: str,
) -> None:
    contract = _contract()
    terminal = _terminal_state_document(
        contract,
        status="completed",
        returncode=0,
        timed_out=False,
        target_started=True,
        target_stopped=True,
        error=None,
    )
    body = {name: value for name, value in terminal.items() if name != "document_sha256"}
    body.update(changes)
    mutated = harness._document(body)

    with pytest.raises(harness.EvidenceValidationError, match=message):
        harness._validate_terminal_contract(mutated, contract=contract.to_document())


def _minimal_adapter_receipt(
    *,
    status: str,
    returncode: int,
    wrapper_returncode: int,
    timed_out: bool,
    extraction_complete: bool,
) -> dict[str, object]:
    return {
        "schema_version": harness.ADAPTER_SCHEMA_VERSION,
        "adapter_version": harness.ADAPTER_VERSION,
        "system_id": "ravage",
        "status": status,
        "returncode": returncode,
        "wrapper_returncode": wrapper_returncode,
        "process_group_policy": "joined_evaluator_outer_group",
        "timed_out": timed_out,
        "command_sha256": _digest("command"),
        "target_url_sha256": _digest("target"),
        "gateway_base_url_sha256": _digest("gateway"),
        "docker_host_sha256": _digest("docker"),
        "gateway": {},
        "limits": {},
        "tool_image": "unused",
        "input_contract": {},
        "runtime": {},
        "capture": {},
        "candidate_extraction": {
            "complete": extraction_complete,
            "candidate_count": 0,
            "artifact_path": None,
            "expected_flag_used": False,
        },
        "environment_policy": {},
    }


@pytest.mark.parametrize(
    ("receipt", "terminal", "message"),
    [
        (
            _minimal_adapter_receipt(
                status="completed",
                returncode=0,
                wrapper_returncode=125,
                timed_out=False,
                extraction_complete=False,
            ),
            {"system": "ravage", "status": "failed", "returncode": 125},
            "non-timeout adapter candidate extraction is incomplete",
        ),
        (
            _minimal_adapter_receipt(
                status="timed_out",
                returncode=0,
                wrapper_returncode=124,
                timed_out=True,
                extraction_complete=False,
            ),
            {"system": "ravage", "status": "timed_out", "returncode": 124},
            "canonical adapter outcome is internally inconsistent",
        ),
    ],
)
def test_offline_adapter_rejects_unreportable_terminal_outcomes(
    tmp_path: Path,
    receipt: dict[str, object],
    terminal: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(harness.EvidenceValidationError, match=message):
        harness._validate_adapter_receipt(
            receipt,
            terminal=terminal,
            contract={},
            candidate_path=None,
            native_output_dir=tmp_path,
        )


def test_offline_adapter_capture_requires_complete_reproducible_files(
    tmp_path: Path,
) -> None:
    body = b"retained output\n"
    capture: dict[str, dict[str, object]] = {}
    for stream, filename in (
        ("stdout", harness.ADAPTER_STDOUT_PATH),
        ("stderr", harness.ADAPTER_STDERR_PATH),
    ):
        (tmp_path / filename).write_bytes(body)
        capture[stream] = {
            "sha256": _digest(body.decode()),
            "total_bytes": len(body),
            "retained_bytes": len(body),
            "truncated": False,
            "complete": True,
        }
    harness._validate_adapter_capture(capture, native_output_dir=tmp_path)
    capture["stderr"]["complete"] = False

    with pytest.raises(harness.EvidenceValidationError, match="capture is incomplete"):
        harness._validate_adapter_capture(capture, native_output_dir=tmp_path)


def _structural_receipt_only(
    _arm_root: Path,
    *,
    terminal: dict[str, object],
    contract: dict[str, object],
) -> bool:
    del terminal, contract
    return True


@pytest.mark.parametrize("first_status", ["failed", "timed_out"])
def test_started_non_success_is_retained_as_reportable_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    first_status: str,
) -> None:
    campaign = tmp_path / f"process-{first_status}"
    contract = _contract(campaign)
    target = FakeTarget()
    agent = FirstArmOutcomeAgent(contract, target, first_status=first_status)
    monkeypatch.setattr(harness, "_verify_agent_receipts", _structural_receipt_only)
    draws = iter(f"{index:064x}" for index in range(30, 35))

    report = harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=FakeGateway(contract),
        target_backend=target,
        agent_backend=agent,
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=lambda _size: next(draws),
        clock=lambda: 1.0,
    )
    verification = verify_known_site_regression(campaign)

    assert report["arms_terminal"] == report["expected_arms"] == 2
    assert report["all_precommitted_rows_terminal"] is True
    assert report["complete"] is True
    assert report["scoreable"] is True
    assert report["valid_for_paired_known_site_regression"] is True
    failed_system = contract.arm_order[0]
    assert report["scores_out_of_five"][failed_system] == 0
    assert report["score_artifact_status"][failed_system] == "retained_unsuccessful_zero"
    assert report["arm_reportable_observation"][failed_system] is True
    assert report["arm_attempt_succeeded"][failed_system] is False
    assert report["arm_solved"][failed_system] is False
    score = json.loads(
        (campaign / "private/primary-001/arm-score.json").read_text(encoding="utf-8")
    )
    if first_status == "failed":
        assert score["candidate_observation"]["score"] > 0
    assert score["score"]["score"] == 0
    assert verification["structurally_valid"] is True
    assert verification["valid_for_paired_known_site_regression"] is True


def test_agent_launch_error_is_retained_as_unstarted_non_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    campaign = tmp_path / "agent-error"
    contract = _contract(campaign)
    target = FakeTarget()
    monkeypatch.setattr(harness, "_verify_agent_receipts", _structural_receipt_only)
    draws = iter(f"{index:064x}" for index in range(35, 40))

    report = harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=FakeGateway(contract),
        target_backend=target,
        agent_backend=FirstArmRaisesAgent(contract, target),
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=lambda _size: next(draws),
        clock=lambda: 1.0,
    )
    verification = verify_known_site_regression(campaign)
    first = json.loads(
        (campaign / "private/primary-001/arm-terminal.json").read_text(encoding="utf-8")
    )

    assert first["status"] == "unstarted"
    assert first["target_started"] is True
    assert first["target_stopped"] is True
    assert "agent launch failed" in first["error"]
    assert report["arms_terminal"] == 2
    assert report["all_precommitted_rows_terminal"] is True
    assert report["complete"] is False
    assert report["scoreable"] is False
    assert report["arm_reportable_observation"][contract.arm_order[0]] is False
    assert report["valid_for_paired_known_site_regression"] is False
    withheld = report["scores_out_of_five"]
    assert withheld["available"] is False
    assert withheld["withheld"] is True
    assert "campaign_not_scoreable" in withheld["reasons"]
    assert not set(harness.SYSTEMS).intersection(withheld)
    assert verification["structurally_valid"] is True
    assert verification["valid_for_paired_known_site_regression"] is False
    assert known_site_cli_main(["verify", "--campaign-dir", str(campaign)]) == 2
    cli_payload = json.loads(capsys.readouterr().out)
    assert cli_payload["structurally_valid"] is True
    assert cli_payload["valid_for_paired_known_site_regression"] is False


def test_target_start_failure_and_poisoned_counterpart_are_two_valid_observations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = tmp_path / "start-failure"
    contract = _contract(campaign)
    target = FirstStartFailsAndPoisonsTarget()
    monkeypatch.setattr(harness, "_verify_agent_receipts", _structural_receipt_only)
    draws = iter(f"{index:064x}" for index in range(40, 45))

    report = harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=FakeGateway(contract),
        target_backend=target,
        agent_backend=FakeAgent(contract, target),
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=lambda _size: next(draws),
        clock=lambda: 1.0,
    )
    verification = verify_known_site_regression(campaign)

    terminals = [
        json.loads((campaign / "private" / row / "arm-terminal.json").read_text(encoding="utf-8"))
        for row in harness.ROW_IDS
    ]
    assert [terminal["status"] for terminal in terminals] == ["unstarted", "unstarted"]
    assert all(terminal["target_started"] is False for terminal in terminals)
    assert report["all_precommitted_rows_terminal"] is True
    assert report["complete"] is False
    assert report["scoreable"] is False
    assert verification["structurally_valid"] is True


def test_failed_target_stop_poisoning_is_structurally_valid_not_successful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = tmp_path / "stop-failure"
    contract = _contract(campaign)
    target = FirstStopFailsAndPoisonsTarget()
    monkeypatch.setattr(harness, "_verify_agent_receipts", _structural_receipt_only)
    draws = iter(f"{index:064x}" for index in range(50, 55))

    report = harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=FakeGateway(contract),
        target_backend=target,
        agent_backend=FakeAgent(contract, target),
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=lambda _size: next(draws),
        clock=lambda: 1.0,
    )
    verification = verify_known_site_regression(campaign)

    first = json.loads(
        (campaign / "private/primary-001/arm-terminal.json").read_text(encoding="utf-8")
    )
    second = json.loads(
        (campaign / "private/primary-002/arm-terminal.json").read_text(encoding="utf-8")
    )
    assert (first["status"], first["target_started"], first["target_stopped"]) == (
        "failed",
        True,
        False,
    )
    assert "target stop failed" in first["error"]
    assert second["status"] == "unstarted"
    assert report["all_precommitted_rows_terminal"] is True
    assert report["complete"] is False
    assert report["valid_for_paired_known_site_regression"] is False
    assert verification["structurally_valid"] is True


def test_unstarted_receipts_use_shared_validator_and_require_all_seals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract().to_document()
    arm_root = tmp_path / "primary-001"
    (arm_root / harness.NATIVE_OUTPUT_DIRECTORY).mkdir(parents=True)
    model_path = arm_root / harness.MODEL_RECEIPT_FILE
    process_path = arm_root / harness.PROCESS_RECEIPT_FILE
    sandbox_path = arm_root / harness.SANDBOX_PROFILE_FILE
    model_path.write_text("{}", encoding="utf-8")
    process_path.write_text("{}", encoding="utf-8")
    sandbox_path.write_bytes(b"")

    def receipt(path: Path, relative: str) -> dict[str, object]:
        return {
            "path": relative,
            "file_sha256": _digest(path.read_bytes()),
            "size_bytes": path.stat().st_size,
        }

    terminal = _terminal_state_document(
        _contract(),
        status="unstarted",
        returncode=-1,
        timed_out=False,
        target_started=False,
        target_stopped=False,
        error="target start failed",
    )
    terminal["receipts"] = {
        "candidate_artifact": None,
        "adapter": None,
        "model": receipt(model_path, harness.MODEL_RECEIPT_FILE),
        "process": receipt(process_path, harness.PROCESS_RECEIPT_FILE),
        "sandbox_profile": receipt(sandbox_path, harness.SANDBOX_PROFILE_FILE),
        "agent_vm_provision": None,
        "agent_vm_relay_probes": None,
        "agent_vm_teardown": None,
    }
    model_document_sha256 = "sha256:" + "9" * 64
    monkeypatch.setattr(
        harness,
        "validate_model_gateway_receipt",
        lambda *args, **kwargs: {"document_sha256": model_document_sha256},
    )
    observed: list[str] = []

    def validate_unstarted(payload, **kwargs):
        observed.append(str(kwargs["expected_row_id"]))
        assert kwargs["model_receipt_document_sha256"] == model_document_sha256
        assert kwargs["sandbox_profile"] == b""
        return {"valid": False}

    monkeypatch.setattr(
        harness,
        "validate_unstarted_comparison_process_receipt",
        validate_unstarted,
    )

    assert (
        harness._verify_agent_receipts(
            arm_root,
            terminal=terminal,
            contract=contract,
        )
        is True
    )
    assert observed == ["primary-001"]

    terminal["receipts"] = {**terminal["receipts"], "process": None}
    with pytest.raises(harness.EvidenceValidationError, match="process receipt record"):
        harness._verify_agent_receipts(arm_root, terminal=terminal, contract=contract)


def test_failed_fallback_process_receipt_is_retained_but_not_reportable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract().to_document()
    arm_root = tmp_path / "primary-001"
    native = arm_root / harness.NATIVE_OUTPUT_DIRECTORY
    daemon = arm_root / "agent-daemon"
    native.mkdir(parents=True)
    daemon.mkdir()
    model_path = arm_root / harness.MODEL_RECEIPT_FILE
    process_path = arm_root / harness.PROCESS_RECEIPT_FILE
    sandbox_path = arm_root / harness.SANDBOX_PROFILE_FILE
    model_path.write_text("{}\n", encoding="utf-8")
    sandbox_path.write_bytes(b"")
    model_document_sha256 = "sha256:" + "9" * 64
    monkeypatch.setattr(
        harness,
        "validate_model_gateway_receipt",
        lambda *args, **kwargs: {"document_sha256": model_document_sha256},
    )
    per_arm = contract["budgets"]["per_arm"]
    empty_capture = {
        "raw_sha256": _digest(b""),
        "raw_size_bytes": 0,
        "retained_size_bytes": 0,
        "max_retained_bytes": 1024,
        "truncated": False,
        "complete": True,
    }
    process = _document(
        {
            "schema_version": harness.PROCESS_RECEIPT_SCHEMA_VERSION,
            "created_at": "2026-09-12T00:00:00Z",
            "row_id": "primary-001",
            "evidence_class": "paired_local",
            "command": {"unbound": True},
            "environment": {"unbound": True},
            "cwd": {
                "mode": "row_native_output",
                "relative_path": harness.NATIVE_OUTPUT_DIRECTORY,
            },
            "limits": {
                "wall_seconds": per_arm["wall_seconds"],
                "max_model_requests": per_arm["max_model_requests"],
                "max_target_requests": per_arm["max_target_requests"],
                "max_cost_usd": per_arm["max_cost_usd"],
            },
            "sandbox": {
                "profile_path": harness.SANDBOX_PROFILE_FILE,
                "profile_sha256": _digest(b""),
            },
            "execution": {
                "started_at": "2026-09-12T00:00:00Z",
                "completed_at": "2026-09-12T00:00:01Z",
                "elapsed_seconds": 5.0,
                "returncode": 7,
                "timed_out": False,
                "spawn_succeeded": False,
                "wall_timeout_enforced": True,
                "process_group_created": False,
                "process_group_teardown_complete": True,
                "stdout": empty_capture,
                "stderr": empty_capture,
                "error": "spawn evidence unavailable",
            },
            "model_gateway": {
                "receipt_path": harness.MODEL_RECEIPT_FILE,
                "receipt_file_sha256": _digest(model_path.read_bytes()),
                "receipt_document_sha256": model_document_sha256,
                "policy_sha256": contract["model_gateway"]["policy_sha256"],
                "sealed_in_finally": True,
                "validator_passed": True,
                "error": None,
            },
            "official_attestation_eligible": False,
            "valid": False,
        }
    )
    process_path.write_text(
        json.dumps(process, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    terminal = _terminal_state_document(
        _contract(),
        status="failed",
        returncode=7,
        timed_out=False,
        target_started=True,
        target_stopped=True,
        error="started process evidence is incomplete",
    )
    terminal["process_public_contract"] = None

    def receipt(path: Path, relative: str) -> dict[str, object]:
        return {
            "path": relative,
            "file_sha256": _digest(path.read_bytes()),
            "size_bytes": path.stat().st_size,
        }

    daemon_receipts: dict[str, dict[str, object]] = {}
    for name, filename in (
        ("agent_vm_provision", harness.AGENT_DAEMON_PROVISION_FILE),
        ("agent_vm_relay_probes", harness.HOST_RELAY_PROBE_FILE),
        ("agent_vm_teardown", harness.AGENT_DAEMON_TEARDOWN_FILE),
    ):
        path = daemon / filename
        path.write_text("{}\n", encoding="utf-8")
        daemon_receipts[name] = receipt(path, f"agent-daemon/{filename}")
    terminal["receipts"] = {
        "candidate_artifact": None,
        "adapter": None,
        "model": receipt(model_path, harness.MODEL_RECEIPT_FILE),
        "process": receipt(process_path, harness.PROCESS_RECEIPT_FILE),
        "sandbox_profile": receipt(sandbox_path, harness.SANDBOX_PROFILE_FILE),
        **daemon_receipts,
    }

    assert harness._terminal_is_reportable_observation(terminal) is False
    assert harness._verify_agent_receipts(arm_root, terminal=terminal, contract=contract) is False


def test_terminal_target_digest_binding_rejects_missing_or_orphan_documents() -> None:
    contract = _contract()
    terminal = _terminal_state_document(
        contract,
        status="completed",
        returncode=0,
        timed_out=False,
        target_started=True,
        target_stopped=True,
        error=None,
    )
    start = {"document_sha256": terminal["target_start_sha256"]}
    stop = {"document_sha256": terminal["target_stop_sha256"]}
    harness._validate_terminal_target_bindings(
        terminal,
        target_start=start,
        target_stop=stop,
    )

    with pytest.raises(harness.EvidenceValidationError, match="lifecycle binding"):
        harness._validate_terminal_target_bindings(
            terminal,
            target_start=None,
            target_stop=stop,
        )
    with pytest.raises(harness.EvidenceValidationError, match="lifecycle binding"):
        harness._validate_terminal_target_bindings(
            terminal,
            target_start={"document_sha256": _digest("wrong")},
            target_stop=stop,
        )


def test_incomplete_target_release_invalidates_report_and_offline_verification(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "release-failure"
    contract = _contract(campaign)
    target = IncompleteReleaseTarget()
    gateway = FakeGateway(contract)
    agent = FakeAgent(contract, target)
    draws = iter(f"{index:064x}" for index in range(20, 25))
    report = harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=gateway,
        target_backend=target,
        agent_backend=agent,
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=lambda _size: next(draws),
        clock=lambda: 1.0,
    )

    assert report["canonical_process_target_evidence_valid"] is False
    assert report["valid_for_paired_known_site_regression"] is False
    assert report["scoreable"] is True
    assert report["scores_out_of_five"] == {
        "available": False,
        "withheld": True,
        "reasons": ["operational_evidence_invalid"],
    }
    verification = verify_known_site_regression(campaign)
    assert verification["structurally_valid"] is False
    assert any("target release is incomplete" in error for error in verification["errors"])


def test_receipt_validation_exception_cannot_make_report_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = tmp_path / "malformed-receipt"
    contract = _contract(campaign)
    target = FakeTarget()
    draws = iter(f"{index:064x}" for index in range(60, 65))

    def reject_receipt(*_args: object, **_kwargs: object) -> bool:
        raise harness.EvidenceValidationError("malformed process receipt")

    monkeypatch.setattr(harness, "_verify_agent_receipts", reject_receipt)
    report = harness._execute_with_entropy(
        campaign,
        contract=contract,
        gateway=FakeGateway(contract),
        target_backend=target,
        agent_backend=FakeAgent(contract, target),
        authenticated_order_backend=FakeAuthenticatedOrderBackend(),
        entropy=lambda _size: next(draws),
        clock=lambda: 1.0,
    )

    assert report["all_precommitted_rows_terminal"] is True
    assert report["canonical_process_target_evidence_valid"] is False
    assert report["valid_for_paired_known_site_regression"] is False
    verification = verify_known_site_regression(campaign)
    assert verification["structurally_valid"] is False
    assert any("malformed process receipt" in error for error in verification["errors"])
