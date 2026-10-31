# ruff: noqa: FBT003,PLR2004,PT018,TC003
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.paired_xben import github_runner
from tools.paired_xben.protocol import SELECTION_SCHEMA, canonical_json

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64
WORKFLOW_SHA = "1" * 40
REPOSITORY = "duriantaco/ravage"
IMAGES = {
    "ravage": (
        "ghcr.io/duriantaco/ravage-kali@sha256:" + "4" * 64,
        SHA_D,
        SHA_A,
    ),
    "strix": (
        "ghcr.io/usestrix/strix-sandbox@sha256:" + "5" * 64,
        SHA_E,
        SHA_B,
    ),
}


def _document(body: dict[str, object]) -> dict[str, object]:
    digest = "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()
    return {**body, "document_digest": digest}


def _selection() -> dict[str, object]:
    cases = [f"XBEN-{number:03d}-24" for number in range(1, 21)]
    schedule: list[dict[str, object]] = []
    slot = 0
    for pair_index, case_id in enumerate(cases, start=1):
        systems = ("ravage", "strix") if pair_index % 2 else ("strix", "ravage")
        for position, system in enumerate(systems, start=1):
            slot += 1
            schedule.append(
                {
                    "slot": slot,
                    "slot_id": f"primary-{slot:03d}",
                    "pair_index": pair_index,
                    "position_within_pair": position,
                    "case_id": case_id,
                    "system": system,
                    "purpose": "primary",
                    "score_eligible": True,
                }
            )
    return _document(
        {
            "schema_version": SELECTION_SCHEMA,
            "campaign_id": "paired-xben-public-20260912",
            "commitment_digest": SHA_A,
            "beacon_digest": SHA_B,
            "eligible_pool_digest": SHA_C,
            "draw_key_sha256": SHA_D,
            "algorithms": {},
            "case_ranking": [],
            "selected_case_ids": cases,
            "pair_order": cases,
            "schedule": schedule,
            "attempt_policy": {},
        }
    )


def _network_probes() -> dict[str, object]:
    return {
        name: {"origin": origin, "outcome": outcome, "attempts": 1}
        for name, (origin, outcome) in github_runner.REQUIRED_NETWORK_PROBES.items()
    }


def _arm(system: str, *, uid: int, daemon_digest: str) -> dict[str, object]:
    reference, image_id, archive_sha = IMAGES[system]
    tool = {
        "probe_kind": (
            "pinned-strix-default-manifest-startup-v1"
            if system == "strix"
            else "pinned-ravage-scoped-tool-runtime-startup-v1"
        ),
        "container_created": True,
        "container_started": True,
        "entrypoint_preserved": True,
        "sandbox_network_attached": True,
        "host_gateway_present": True,
        "requested_capabilities": ["NET_ADMIN", "NET_RAW"] if system == "strix" else [],
        "effective_capabilities": ["NET_ADMIN", "NET_RAW"] if system == "strix" else [],
        "net_admin_functional_probe": "succeeded" if system == "strix" else "not_requested",
        "net_raw_functional_probe": "succeeded" if system == "strix" else "not_requested",
        "sys_admin_requested": False,
        "fuse_device_requested": False,
        "local_service_ready": True,
        "container_removed": True,
    }
    return {
        "system": system,
        "agent_uid": uid,
        "agent_name_sha256": SHA_C,
        "supplementary_groups": [],
        "daemon_kind": github_runner.ROOTLESS_DAEMON_KIND,
        "daemon_identity_sha256": daemon_digest,
        "docker_executable_sha256": SHA_A,
        "docker_host_sha256": SHA_B,
        "socket_owner_uid": uid,
        "socket_group_access_absent": True,
        "socket_other_access_absent": True,
        "security_options": ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"],
        "cgroup_driver": "systemd",
        "initial_inventory": {
            "images": [],
            "containers": [],
            "volumes": [],
            "networks": [
                {"name": "bridge", "id": SHA_A, "driver": "bridge"},
                {"name": "host", "id": SHA_B, "driver": "host"},
                {"name": "none", "id": SHA_C, "driver": "null"},
            ],
        },
        "offline_image_admission": {
            "archive_sha256": archive_sha,
            "image_reference": reference,
            "image_id": image_id,
            "platform": "linux/amd64",
            "loaded_after_network_lockdown": True,
            "registry_requests": 0,
            "pull_events": 0,
            "build_events": 0,
            "post_load_images": [{"reference": reference, "id": image_id}],
        },
        "authority_probes": {
            "agent_has_sudo": False,
            "root_campaign_readable": False,
            "root_target_material_readable": False,
            "rootful_docker_socket_usable": False,
            "provider_secret_proc_readable": False,
            "target_canary_visible_on_agent_daemon": False,
            "agent_socket_usable_by_evaluator_only_uid": True,
        },
        "network_policy": {
            "kind": github_runner.NETWORK_ENFORCEMENT_KIND,
            "owner_uid": uid,
            "policy_sha256": SHA_D,
            "ruleset_sha256": SHA_E,
            "installed_by_uid": 0,
            "mutable_by_agent_uid": False,
            "rootlesskit_process_uid": uid,
            "dockerd_process_uid": uid,
            "all_agent_processes_same_uid": True,
            "rootlesskit_ipv6_enabled": False,
            "default_reject_after_allowlist": True,
        },
        "network_probes": _network_probes(),
        "cross_daemon_target_route": {
            "kind": "rootful-loopback-via-rootless-host-gateway-v1",
            "rootful_gateway_daemon_identity_sha256": SHA_A,
            "rootful_gateway_network_count": 1,
            "rootful_gateway_target_network_only": True,
            "rootful_gateway_agent_network_attached": False,
            "rootful_gateway_agent_socket_mounted": False,
            "rootful_gateway_rootful_socket_mounted": False,
            "rootful_gateway_evaluator_source_mounted": False,
            "rootful_publish_host": "127.0.0.1",
            "rootful_publish_port": 50_001 if system == "ravage" else 50_002,
            "agent_host_gateway_ipv4": "10.0.2.2",
            "agent_url_uses_host_gateway": True,
            "root_owned_uid_firewall_active": True,
            "agent_process_http_probe": "succeeded",
            "tool_container_http_probe": "succeeded",
            "meter_observed_request_delta": 2,
            "direct_target_canary_denied": True,
            "tool_image_reference": reference,
            "tool_image_id": image_id,
        },
        "tool_compatibility": tool,
        "teardown": {
            "daemon_stopped": True,
            "all_containers_absent": True,
            "all_images_absent": True,
            "all_volumes_absent": True,
            "nondefault_networks_absent": True,
            "socket_absent": True,
            "runtime_directory_absent": True,
            "data_directory_absent": True,
            "agent_processes_absent": True,
            "firewall_policy_absent": True,
            "user_removed": True,
        },
    }


def _qualification() -> dict[str, object]:
    return _document(
        {
            "schema_version": github_runner.QUALIFICATION_SCHEMA,
            "github": {
                "repository": REPOSITORY,
                "repository_visibility": "public",
                "event_name": "workflow_dispatch",
                "ref": "refs/heads/main",
                "workflow_sha": WORKFLOW_SHA,
                "run_id": 123456,
                "run_attempt": 1,
            },
            "runner": {
                "environment": "github-hosted",
                "label": github_runner.RUNNER_LABEL,
                "os": "Linux",
                "arch": "X64",
                "image_os": "ubuntu24",
                "image_version": "20260907.1.0",
                "name_sha256": SHA_A,
                "host_free_bytes_before": 13 * 1024**3,
            },
            "boundary": {
                "kind": github_runner.BOUNDARY_KIND,
                "network_enforcement_kind": github_runner.NETWORK_ENFORCEMENT_KIND,
                "privileged_dind_used": False,
                "nested_virtualization_used": False,
                "vm_grade_isolation_claimed": False,
                "target_material_owner_uid": 0,
                "target_material_mode": "0700",
                "campaign_material_owner_uid": 0,
                "campaign_material_mode": "0700",
            },
            "rootful_target_daemon": {
                "daemon_identity_sha256": SHA_A,
                "docker_executable_sha256": SHA_A,
                "security_options": ["name=seccomp,profile=builtin", "name=apparmor"],
                "target_canary_sha256": SHA_B,
            },
            "arms": [
                _arm("ravage", uid=20001, daemon_digest=SHA_D),
                _arm("strix", uid=20002, daemon_digest=SHA_E),
            ],
        }
    )


def _reservation(matrix: dict[str, object]) -> dict[str, object]:
    return _document(
        {
            "schema_version": github_runner.EXECUTION_RESERVATION_SCHEMA,
            "campaign_id": "paired-xben-public-20260912",
            "commitment_digest": SHA_A,
            "selection_digest": SHA_B,
            "primary_matrix_digest": SHA_C,
            "pair_matrix_digest": matrix["document_digest"],
            "repository": REPOSITORY,
            "workflow_path": ".github/workflows/paired-xben-execution.yml",
            "workflow_sha": WORKFLOW_SHA,
            "workflow_run_id": 987654,
            "workflow_run_attempt": 1,
            "github_event": "workflow_dispatch",
            "github_ref": "refs/heads/main",
            "pair_jobs": 20,
            "primary_rows": 40,
            "retry_resume_or_replacement_allowed": False,
        }
    )


def _validate(receipt: dict[str, object]) -> dict[str, object]:
    return github_runner.validate_qualification_receipt(
        receipt,
        repository=REPOSITORY,
        workflow_sha=WORKFLOW_SHA,
        expected_images=IMAGES,
        expected_docker_executable_sha256=SHA_A,
    )


def _redigest(value: dict[str, object]) -> dict[str, object]:
    value.pop("document_digest", None)
    return _document(value)


def test_assessment_keeps_paid_execution_and_draw_mechanically_blocked() -> None:
    assessment = github_runner.implementation_assessment()

    assert assessment["runnable"] is False
    assert assessment["paid_execution_permitted"] is False
    assert assessment["draw_permitted_by_this_module"] is False
    assert assessment["block_reasons"] == list(github_runner.IMPLEMENTATION_BLOCKERS)
    assert assessment["isolation_policy"]["privileged_dind"] is False  # type: ignore[index]
    assert assessment["isolation_policy"]["vm_grade_isolation_claim"] is False  # type: ignore[index]


def test_matrix_is_all_twenty_adjacent_pairs_with_no_subset_or_retry_knob() -> None:
    selection = _selection()
    matrix = github_runner.build_pair_job_matrix(selection)

    assert matrix["schema_version"] == github_runner.PAIR_MATRIX_SCHEMA
    assert matrix["selection_digest"] == selection["document_digest"]
    include = matrix["include"]
    assert isinstance(include, list) and len(include) == 20
    assert [job["pair_index"] for job in include] == list(range(1, 21))
    assert include[0] == {
        "pair_index": 1,
        "pair_id": "pair-001",
        "case_id": "XBEN-001-24",
        "first_slot_id": "primary-001",
        "first_system": "ravage",
        "second_slot_id": "primary-002",
        "second_system": "strix",
    }
    assert matrix["job_policy"]["retry_or_resume_allowed"] is False  # type: ignore[index]
    assert matrix["job_policy"]["replacement_allowed"] is False  # type: ignore[index]
    assert github_runner.validate_pair_job_matrix(matrix, selection=selection) == matrix


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["schedule"].pop(), "20-case/40-row"),
        (
            lambda value: value["schedule"][1].__setitem__("system", "ravage"),
            "paired and counterbalanced",
        ),
        (lambda value: value["schedule"].reverse(), "schedule row binding"),
    ],
)
def test_matrix_rejects_truncation_replacement_and_reordering(
    mutation: object, message: str
) -> None:
    selection = _selection()
    cast_mutation = mutation
    assert callable(cast_mutation)
    cast_mutation(selection)  # type: ignore[operator]
    selection = _redigest(selection)

    with pytest.raises(github_runner.GithubRunnerContractError, match=message):
        github_runner.build_pair_job_matrix(selection)


def test_matrix_rejects_a_forged_document_digest() -> None:
    selection = _selection()
    selection["schedule"][0]["system"] = "strix"  # type: ignore[index]

    with pytest.raises(github_runner.GithubRunnerContractError, match="digest does not verify"):
        github_runner.build_pair_job_matrix(selection)


def test_public_start_reservation_authorizes_only_one_exact_first_attempt_run() -> None:
    matrix = github_runner.build_pair_job_matrix(_selection())
    reservation = _reservation(matrix)

    assert (
        github_runner.validate_execution_reservation(
            reservation,
            campaign_id="paired-xben-public-20260912",
            commitment_digest=SHA_A,
            selection_digest=SHA_B,
            primary_matrix_digest=SHA_C,
            pair_matrix_digest=matrix["document_digest"],
            repository=REPOSITORY,
            workflow_sha=WORKFLOW_SHA,
            workflow_run_id=987654,
        )
        == reservation
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_run_id", 987655),
        ("workflow_run_attempt", 2),
        ("workflow_sha", "2" * 40),
        ("pair_jobs", 19),
        ("retry_resume_or_replacement_allowed", True),
    ],
)
def test_public_start_reservation_rejects_copy_rerun_or_subset(field: str, value: object) -> None:
    matrix = github_runner.build_pair_job_matrix(_selection())
    reservation = _reservation(matrix)
    reservation[field] = value
    reservation = _redigest(reservation)

    with pytest.raises(github_runner.GithubRunnerContractError, match="does not authorize"):
        github_runner.validate_execution_reservation(
            reservation,
            campaign_id="paired-xben-public-20260912",
            commitment_digest=SHA_A,
            selection_digest=SHA_B,
            primary_matrix_digest=SHA_C,
            pair_matrix_digest=matrix["document_digest"],
            repository=REPOSITORY,
            workflow_sha=WORKFLOW_SHA,
            workflow_run_id=987654,
        )


def test_qualification_accepts_exact_non_vm_grade_rootless_boundary() -> None:
    receipt = _qualification()

    assert _validate(receipt) == receipt


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["boundary"].__setitem__("privileged_dind_used", True),
            "boundary declaration",
        ),
        (
            lambda value: value["boundary"].__setitem__("vm_grade_isolation_claimed", True),
            "boundary declaration",
        ),
        (
            lambda value: value["github"].__setitem__("run_attempt", 2),
            "GitHub binding",
        ),
        (
            lambda value: value["arms"][1]["security_options"].remove("name=rootless"),
            "rootless Docker binding",
        ),
        (
            lambda value: value["arms"][1]["tool_compatibility"].__setitem__(
                "effective_capabilities", ["NET_RAW"]
            ),
            "Strix rootless Docker capability",
        ),
        (
            lambda value: value["arms"][0]["authority_probes"].__setitem__(
                "target_canary_visible_on_agent_daemon", True
            ),
            "authority separation",
        ),
        (
            lambda value: value["arms"][0]["network_probes"][
                "direct_provider_agent_process"
            ].__setitem__("outcome", "allowed"),
            "network probe direct_provider_agent_process",
        ),
        (
            lambda value: value["arms"][1]["teardown"].__setitem__("data_directory_absent", False),
            "teardown was not fully proven",
        ),
        (
            lambda value: value["arms"][1].__setitem__(
                "daemon_identity_sha256", value["arms"][0]["daemon_identity_sha256"]
            ),
            "reused an arm UID or Docker authority",
        ),
    ],
)
def test_qualification_fails_closed_on_boundary_regressions(mutate: object, message: str) -> None:
    receipt = _qualification()
    assert callable(mutate)
    mutate(receipt)  # type: ignore[operator]
    receipt = _redigest(receipt)

    with pytest.raises(github_runner.GithubRunnerContractError, match=message):
        _validate(receipt)


def test_qualification_rejects_nonempty_initial_inventory() -> None:
    receipt = _qualification()
    receipt["arms"][0]["initial_inventory"]["images"] = [SHA_C]  # type: ignore[index]
    receipt = _redigest(receipt)

    with pytest.raises(github_runner.GithubRunnerContractError, match="was not pristine"):
        _validate(receipt)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rootful_gateway_network_count", 2),
        ("rootful_gateway_agent_network_attached", True),
        ("rootful_publish_host", "192.0.2.1"),
        ("tool_container_http_probe", "not_run"),
        ("meter_observed_request_delta", 1),
        ("direct_target_canary_denied", False),
    ],
)
def test_qualification_rejects_unproven_cross_daemon_route(
    field: str,
    value: object,
) -> None:
    receipt = _qualification()
    receipt["arms"][0]["cross_daemon_target_route"][field] = value  # type: ignore[index]
    receipt = _redigest(receipt)

    with pytest.raises(github_runner.GithubRunnerContractError, match="cross-daemon"):
        _validate(receipt)


def test_assessment_cli_writes_create_only_blocked_evidence(tmp_path: Path) -> None:
    output = tmp_path / "assessment.json"

    assert github_runner.main(["assessment", "--output", str(output)]) == 2
    assert json.loads(output.read_text()) == github_runner.implementation_assessment()
    original = output.read_bytes()
    assert github_runner.main(["assessment", "--output", str(output)]) == 2
    assert output.read_bytes() == original


def test_json_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"one","schema_version":"two"}\n')

    with pytest.raises(github_runner.GithubRunnerContractError, match="duplicate"):
        github_runner.load_json(path, label="test document")
