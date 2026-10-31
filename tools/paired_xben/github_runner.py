# ruff: noqa: C901,D202,D213,EM101,EM102,PLR2004,TRY003
"""Fail-closed planning and qualification for public GitHub XBEN workers.

This module intentionally does not execute a benchmark row.  It provides the
parts that are safe to use before the Linux execution boundary is complete:

* reproduce the one-and-only 20-pair GitHub job matrix from a resolved
  ``selection.json``;
* publish a machine-readable implementation assessment; and
* validate a no-model, no-target live qualification receipt for the exact
  rootless-Docker boundary proposed for a scored worker.

The qualification is deliberately stronger than a successful ``docker run``.
It requires a dedicated non-sudo UID, a pristine rootless daemon, exact offline
image admission, root-owned egress enforcement, negative target/secret/socket
canaries, Strix's real capability and entrypoint requirements, and verified
teardown.  A receipt passing this validator still does *not* establish VM-grade
isolation: the agent and evaluator remain different Linux UIDs in one
GitHub-hosted runner VM.

No command here reads a provider credential, obtains randomness, pulls or
builds an image, contacts GitHub, or starts an agent.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

from tools.paired_xben.protocol import SELECTION_SCHEMA, canonical_json

ASSESSMENT_SCHEMA: Final = "ravage.paired-xben.github-runner-assessment.v1"
PAIR_MATRIX_SCHEMA: Final = "ravage.paired-xben.github-pair-matrix.v1"
QUALIFICATION_SCHEMA: Final = "ravage.paired-xben.github-runner-qualification.v1"
EXECUTION_RESERVATION_SCHEMA: Final = "ravage.paired-xben.github-execution-reservation.v1"
GITHUB_EXECUTION_START_SCHEMA: Final = "ravage.paired-xben.github-execution-start.v1"

EXPECTED_PAIRS: Final = 20
EXPECTED_ROWS: Final = 40
SYSTEMS: Final = ("ravage", "strix")
RUNNER_LABEL: Final = "ubuntu-24.04"
BOUNDARY_KIND: Final = "linux-uid-rootless-docker-root-owned-egress-v1"
NETWORK_ENFORCEMENT_KIND: Final = "root-owned-nftables-output-uid-v1"
ROOTLESS_DAEMON_KIND: Final = "direct-rootless-dockerd-dedicated-uid-v1"

# These are implementation facts, not operator-configurable warnings.  Paid
# execution must stay unavailable until code and tests replace every item.
IMPLEMENTATION_BLOCKERS: Final = (
    "trusted_external_postcommitment_verifier_wiring_missing",
    "same_run_atomic_public_start_publisher_missing",
    "public_ledger_start_schema_does_not_admit_github_reservation",
    "cross_daemon_target_meter_not_integrated_or_live_qualified",
    "linux_dedicated_uid_process_backend_missing",
    "linux_runtime_contract_not_emitted_by_preparation",
    "rootless_strix_live_qualification_missing",
    "github_runner_pair_worker_missing",
    "full_row_result_artifact_aggregator_missing",
)

REQUIRED_NETWORK_PROBES: Final = {
    "model_gateway_agent_process": ("agent-process", "allowed"),
    "model_gateway_tool_container": ("tool-container", "allowed"),
    "target_meter_agent_process": ("agent-process", "allowed"),
    "target_meter_tool_container": ("tool-container", "allowed"),
    "direct_target_agent_process": ("agent-process", "denied"),
    "direct_target_tool_container": ("tool-container", "denied"),
    "direct_provider_agent_process": ("agent-process", "denied"),
    "direct_provider_tool_container": ("tool-container", "denied"),
    "default_ipv4_agent_process": ("agent-process", "denied"),
    "default_ipv4_tool_container": ("tool-container", "denied"),
    "default_ipv6_agent_process": ("agent-process", "denied"),
    "default_ipv6_tool_container": ("tool-container", "denied"),
    "dns_udp_agent_process": ("agent-process", "denied"),
    "dns_udp_tool_container": ("tool-container", "denied"),
    "dns_tcp_agent_process": ("agent-process", "denied"),
    "dns_tcp_tool_container": ("tool-container", "denied"),
    "rootful_docker_tcp_agent_process": ("agent-process", "denied"),
    "rootful_docker_tcp_tool_container": ("tool-container", "denied"),
    "other_host_loopback_agent_process": ("agent-process", "denied"),
    "other_host_loopback_tool_container": ("tool-container", "denied"),
}

_SELECTION_FIELDS: Final = frozenset(
    {
        "schema_version",
        "campaign_id",
        "commitment_digest",
        "beacon_digest",
        "eligible_pool_digest",
        "draw_key_sha256",
        "algorithms",
        "case_ranking",
        "selected_case_ids",
        "pair_order",
        "schedule",
        "attempt_policy",
        "document_digest",
    }
)
_MATRIX_FIELDS: Final = frozenset(
    {
        "schema_version",
        "campaign_id",
        "selection_digest",
        "job_policy",
        "include",
        "document_digest",
    }
)
_QUALIFICATION_FIELDS: Final = frozenset(
    {
        "schema_version",
        "github",
        "runner",
        "boundary",
        "rootful_target_daemon",
        "arms",
        "document_digest",
    }
)
_EXECUTION_RESERVATION_FIELDS: Final = frozenset(
    {
        "schema_version",
        "campaign_id",
        "commitment_digest",
        "selection_digest",
        "primary_matrix_digest",
        "pair_matrix_digest",
        "repository",
        "workflow_path",
        "workflow_sha",
        "workflow_run_id",
        "workflow_run_attempt",
        "github_event",
        "github_ref",
        "pair_jobs",
        "primary_rows",
        "retry_resume_or_replacement_allowed",
        "document_digest",
    }
)
_EXECUTION_START_FIELDS: Final = frozenset(
    {
        "schema_version",
        "campaign_id",
        "commitment_digest",
        "selection_digest",
        "primary_matrix_digest",
        "pair_matrix_digest",
        "execution_reservation_digest",
        "evidence_class",
        "official_attestation_eligible",
        "registered_row_count",
        "registered_row_ids",
        "registered_pair_job_count",
        "registered_pair_job_ids",
        "github",
        "policy",
        "document_digest",
    }
)
_EXECUTION_START_GITHUB_FIELDS: Final = frozenset(
    {
        "repository",
        "workflow_path",
        "workflow_ref",
        "workflow_sha",
        "workflow_run_id",
        "workflow_run_attempt",
    }
)
_EXECUTION_START_POLICY: Final = {
    "public_start_immutable_before_model_or_target": True,
    "authorization_job_provider_secret_present": False,
    "pair_job_revalidates_same_run_admission_before_secret": True,
    "resume_allowed": False,
    "row_retry_allowed": False,
    "row_replacement_allowed": False,
    "adjacent_pair_schedule": True,
    "failed_or_missing_row_is_terminal_not_replaced": True,
}
_GITHUB_FIELDS: Final = frozenset(
    {
        "repository",
        "repository_visibility",
        "event_name",
        "ref",
        "workflow_sha",
        "run_id",
        "run_attempt",
    }
)
_RUNNER_FIELDS: Final = frozenset(
    {
        "environment",
        "label",
        "os",
        "arch",
        "image_os",
        "image_version",
        "name_sha256",
        "host_free_bytes_before",
    }
)
_BOUNDARY_FIELDS: Final = frozenset(
    {
        "kind",
        "network_enforcement_kind",
        "privileged_dind_used",
        "nested_virtualization_used",
        "vm_grade_isolation_claimed",
        "target_material_owner_uid",
        "target_material_mode",
        "campaign_material_owner_uid",
        "campaign_material_mode",
    }
)
_TARGET_DAEMON_FIELDS: Final = frozenset(
    {
        "daemon_identity_sha256",
        "docker_executable_sha256",
        "security_options",
        "target_canary_sha256",
    }
)
_ARM_FIELDS: Final = frozenset(
    {
        "system",
        "agent_uid",
        "agent_name_sha256",
        "supplementary_groups",
        "daemon_kind",
        "daemon_identity_sha256",
        "docker_executable_sha256",
        "docker_host_sha256",
        "socket_owner_uid",
        "socket_group_access_absent",
        "socket_other_access_absent",
        "security_options",
        "cgroup_driver",
        "initial_inventory",
        "offline_image_admission",
        "authority_probes",
        "network_policy",
        "network_probes",
        "cross_daemon_target_route",
        "tool_compatibility",
        "teardown",
    }
)
_INVENTORY_FIELDS: Final = frozenset({"images", "containers", "volumes", "networks"})
_IMAGE_ADMISSION_FIELDS: Final = frozenset(
    {
        "archive_sha256",
        "image_reference",
        "image_id",
        "platform",
        "loaded_after_network_lockdown",
        "registry_requests",
        "pull_events",
        "build_events",
        "post_load_images",
    }
)
_AUTHORITY_PROBE_FIELDS: Final = frozenset(
    {
        "agent_has_sudo",
        "root_campaign_readable",
        "root_target_material_readable",
        "rootful_docker_socket_usable",
        "provider_secret_proc_readable",
        "target_canary_visible_on_agent_daemon",
        "agent_socket_usable_by_evaluator_only_uid",
    }
)
_NETWORK_POLICY_FIELDS: Final = frozenset(
    {
        "kind",
        "owner_uid",
        "policy_sha256",
        "ruleset_sha256",
        "installed_by_uid",
        "mutable_by_agent_uid",
        "rootlesskit_process_uid",
        "dockerd_process_uid",
        "all_agent_processes_same_uid",
        "rootlesskit_ipv6_enabled",
        "default_reject_after_allowlist",
    }
)
_CROSS_DAEMON_ROUTE_FIELDS: Final = frozenset(
    {
        "kind",
        "rootful_gateway_daemon_identity_sha256",
        "rootful_gateway_network_count",
        "rootful_gateway_target_network_only",
        "rootful_gateway_agent_network_attached",
        "rootful_gateway_agent_socket_mounted",
        "rootful_gateway_rootful_socket_mounted",
        "rootful_gateway_evaluator_source_mounted",
        "rootful_publish_host",
        "rootful_publish_port",
        "agent_host_gateway_ipv4",
        "agent_url_uses_host_gateway",
        "root_owned_uid_firewall_active",
        "agent_process_http_probe",
        "tool_container_http_probe",
        "meter_observed_request_delta",
        "direct_target_canary_denied",
        "tool_image_reference",
        "tool_image_id",
    }
)
_TOOL_FIELDS: Final = frozenset(
    {
        "probe_kind",
        "container_created",
        "container_started",
        "entrypoint_preserved",
        "sandbox_network_attached",
        "host_gateway_present",
        "requested_capabilities",
        "effective_capabilities",
        "net_admin_functional_probe",
        "net_raw_functional_probe",
        "sys_admin_requested",
        "fuse_device_requested",
        "local_service_ready",
        "container_removed",
    }
)
_TEARDOWN_FIELDS: Final = frozenset(
    {
        "daemon_stopped",
        "all_containers_absent",
        "all_images_absent",
        "all_volumes_absent",
        "nondefault_networks_absent",
        "socket_absent",
        "runtime_directory_absent",
        "data_directory_absent",
        "agent_processes_absent",
        "firewall_policy_absent",
        "user_removed",
    }
)

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_CAMPAIGN_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}")
_CASE_RE = re.compile(r"XBEN-(?:00[1-9]|0[1-9][0-9]|10[0-4])-24")
_SLOT_RE = re.compile(r"primary-(?:00[1-9]|0[1-3][0-9]|040)")
_OCI_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_IMAGE_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{2,127}")
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MIN_RUNNER_FREE_BYTES = 12 * 1024**3


class GithubRunnerContractError(ValueError):
    """A public-runner artifact does not prove the required contract."""


def implementation_assessment() -> dict[str, object]:
    """Return the current non-secret, deterministic execution readiness state."""

    body: dict[str, object] = {
        "schema_version": ASSESSMENT_SCHEMA,
        "runnable": False,
        "paid_execution_permitted": False,
        "draw_permitted_by_this_module": False,
        "runner_policy": {
            "repository_visibility": "public",
            "runner_label": RUNNER_LABEL,
            "fresh_standard_runner_vm_per_pair_job": True,
            "pair_jobs": EXPECTED_PAIRS,
            "primary_rows": EXPECTED_ROWS,
            "run_attempt": 1,
            "matrix_fail_fast": False,
        },
        "isolation_policy": {
            "kind": BOUNDARY_KIND,
            "rootful_target_daemon": True,
            "fresh_rootless_daemon_per_row": True,
            "fresh_non_sudo_uid_per_row": True,
            "root_owned_network_policy": True,
            "privileged_dind": False,
            "nested_virtualization": False,
            "vm_grade_isolation_claim": False,
        },
        "block_reasons": list(IMPLEMENTATION_BLOCKERS),
        "qualification_is_non_scored": True,
        "qualification_uses_provider_credentials": False,
    }
    return _with_digest(body)


def build_pair_job_matrix(selection: Mapping[str, object]) -> dict[str, object]:
    """Reproduce all twenty adjacent jobs from one authentic selection.

    There is intentionally no ``pair_indexes`` argument.  A caller cannot ask
    for a subset, choose an order, replace a case, or create a retry matrix.
    """

    _require_fields(selection, _SELECTION_FIELDS, "selection")
    if selection.get("schema_version") != SELECTION_SCHEMA:
        raise GithubRunnerContractError("selection schema is unsupported")
    selection_digest = _verified_document_digest(selection, "selection")
    campaign_id = _campaign_id(selection.get("campaign_id"))
    raw_schedule = selection.get("schedule")
    raw_selected = selection.get("selected_case_ids")
    raw_pair_order = selection.get("pair_order")
    if (
        not isinstance(raw_schedule, list)
        or len(raw_schedule) != EXPECTED_ROWS
        or not isinstance(raw_selected, list)
        or len(raw_selected) != EXPECTED_PAIRS
        or not isinstance(raw_pair_order, list)
        or len(raw_pair_order) != EXPECTED_PAIRS
    ):
        raise GithubRunnerContractError("selection is not an exact 20-case/40-row matrix")

    selected = tuple(_case_id(value) for value in raw_selected)
    pair_order = tuple(_case_id(value) for value in raw_pair_order)
    if len(set(selected)) != EXPECTED_PAIRS or set(selected) != set(pair_order):
        raise GithubRunnerContractError("selection case and pair-order sets disagree")

    jobs: list[dict[str, object]] = []
    for offset in range(0, EXPECTED_ROWS, 2):
        expected_pair = offset // 2 + 1
        raw_pair = raw_schedule[offset : offset + 2]
        if any(not isinstance(row, Mapping) for row in raw_pair):
            raise GithubRunnerContractError("selection schedule row is malformed")
        first, second = cast("list[Mapping[str, object]]", raw_pair)
        rows = tuple(
            _validated_schedule_row(row, slot=offset + position, pair_index=expected_pair)
            for position, row in enumerate((first, second), start=1)
        )
        if (
            rows[0]["case_id"] != rows[1]["case_id"]
            or rows[0]["case_id"] != pair_order[expected_pair - 1]
            or {rows[0]["system"], rows[1]["system"]} != set(SYSTEMS)
        ):
            raise GithubRunnerContractError("schedule is not exactly paired and counterbalanced")
        jobs.append(
            {
                "pair_index": expected_pair,
                "pair_id": f"pair-{expected_pair:03d}",
                "case_id": rows[0]["case_id"],
                "first_slot_id": rows[0]["slot_id"],
                "first_system": rows[0]["system"],
                "second_slot_id": rows[1]["slot_id"],
                "second_system": rows[1]["system"],
            }
        )

    body = {
        "schema_version": PAIR_MATRIX_SCHEMA,
        "campaign_id": campaign_id,
        "selection_digest": selection_digest,
        "job_policy": {
            "runner_label": RUNNER_LABEL,
            "jobs": EXPECTED_PAIRS,
            "rows_per_job": 2,
            "fresh_runner_job_per_pair": True,
            "fresh_agent_uid_per_row": True,
            "fresh_rootless_daemon_per_row": True,
            "retry_or_resume_allowed": False,
            "replacement_allowed": False,
            "matrix_fail_fast": False,
            "privileged_dind_allowed": False,
            "vm_grade_isolation_claimed": False,
        },
        "include": jobs,
    }
    return _with_digest(body)


def validate_pair_job_matrix(
    matrix: Mapping[str, object], *, selection: Mapping[str, object]
) -> dict[str, object]:
    """Require byte-semantic equality with the deterministic complete matrix."""

    _require_fields(matrix, _MATRIX_FIELDS, "pair-job matrix")
    _verified_document_digest(matrix, "pair-job matrix")
    expected = build_pair_job_matrix(selection)
    if dict(matrix) != expected:
        raise GithubRunnerContractError("pair-job matrix differs from the frozen selection")
    return expected


def validate_execution_reservation(  # noqa: PLR0913
    reservation: Mapping[str, object],
    *,
    campaign_id: str,
    commitment_digest: str,
    selection_digest: str,
    primary_matrix_digest: str,
    pair_matrix_digest: str,
    repository: str,
    workflow_sha: str,
    workflow_run_id: int,
) -> dict[str, object]:
    """Require a public start document to name this one execution run.

    The caller must obtain ``reservation`` from the cryptographically verified,
    immutable ``03-start`` release.  Validating an untrusted local copy is not a
    substitute for that public-ledger verification.
    """

    _require_fields(
        reservation,
        _EXECUTION_RESERVATION_FIELDS,
        "GitHub execution reservation",
    )
    if reservation.get("schema_version") != EXECUTION_RESERVATION_SCHEMA:
        raise GithubRunnerContractError("GitHub execution reservation schema is unsupported")
    _verified_document_digest(reservation, "GitHub execution reservation")
    expected = {
        "campaign_id": _campaign_id(campaign_id),
        "commitment_digest": _digest(commitment_digest, "commitment digest"),
        "selection_digest": _digest(selection_digest, "selection digest"),
        "primary_matrix_digest": _digest(primary_matrix_digest, "primary matrix digest"),
        "pair_matrix_digest": _digest(pair_matrix_digest, "pair matrix digest"),
        "repository": _repository(repository),
        "workflow_path": ".github/workflows/paired-xben-execution.yml",
        "workflow_sha": _git_sha(workflow_sha, "execution workflow SHA"),
        "workflow_run_id": _positive_int(workflow_run_id, "execution workflow run ID"),
        "workflow_run_attempt": 1,
        "github_event": "workflow_dispatch",
        "github_ref": "refs/heads/main",
        "pair_jobs": EXPECTED_PAIRS,
        "primary_rows": EXPECTED_ROWS,
        "retry_resume_or_replacement_allowed": False,
    }
    for name, value in expected.items():
        if reservation.get(name) != value:
            raise GithubRunnerContractError(
                f"GitHub execution reservation field {name!r} does not authorize this run"
            )
    return dict(reservation)


def validate_github_execution_start(  # noqa: PLR0913
    start: Mapping[str, object],
    *,
    reservation: Mapping[str, object],
    pair_matrix: Mapping[str, object],
    selection: Mapping[str, object],
    campaign_id: str,
    commitment_digest: str,
    selection_digest: str,
    primary_matrix_digest: str,
    repository: str,
    workflow_sha: str,
) -> dict[str, object]:
    """Bind the GitHub start, reservation, and complete pair matrix exactly."""

    _require_fields(start, _EXECUTION_START_FIELDS, "GitHub execution start")
    if start.get("schema_version") != GITHUB_EXECUTION_START_SCHEMA:
        raise GithubRunnerContractError("GitHub execution start schema is unsupported")
    _verified_document_digest(start, "GitHub execution start")
    expected_pair_matrix = validate_pair_job_matrix(pair_matrix, selection=selection)
    pair_matrix_digest = _digest(expected_pair_matrix.get("document_digest"), "pair matrix digest")
    expected_campaign = {
        "campaign_id": _campaign_id(campaign_id),
        "commitment_digest": _digest(commitment_digest, "commitment digest"),
        "selection_digest": _digest(selection_digest, "selection digest"),
        "primary_matrix_digest": _digest(primary_matrix_digest, "primary matrix digest"),
        "pair_matrix_digest": pair_matrix_digest,
    }
    for name, value in expected_campaign.items():
        if start.get(name) != value:
            raise GithubRunnerContractError(
                f"GitHub execution start field {name!r} differs from the signed matrix"
            )
    github = _mapping(start.get("github"), "GitHub execution start run binding")
    _require_fields(github, _EXECUTION_START_GITHUB_FIELDS, "GitHub execution start run binding")
    repository_name = _repository(repository)
    source_sha = _git_sha(workflow_sha, "execution workflow SHA")
    run_id = _positive_int(github.get("workflow_run_id"), "execution workflow run ID")
    expected_github = {
        "repository": repository_name,
        "workflow_path": ".github/workflows/paired-xben-execution.yml",
        "workflow_ref": (
            f"{repository_name}/.github/workflows/paired-xben-execution.yml@refs/heads/main"
        ),
        "workflow_sha": source_sha,
        "workflow_run_id": run_id,
        "workflow_run_attempt": 1,
    }
    if dict(github) != expected_github:
        raise GithubRunnerContractError("GitHub execution start run binding is invalid")
    validated_reservation = validate_execution_reservation(
        reservation,
        campaign_id=expected_campaign["campaign_id"],
        commitment_digest=expected_campaign["commitment_digest"],
        selection_digest=expected_campaign["selection_digest"],
        primary_matrix_digest=expected_campaign["primary_matrix_digest"],
        pair_matrix_digest=pair_matrix_digest,
        repository=repository_name,
        workflow_sha=source_sha,
        workflow_run_id=run_id,
    )
    reservation_digest = _digest(
        validated_reservation.get("document_digest"), "execution reservation digest"
    )
    jobs = cast("list[Mapping[str, object]]", expected_pair_matrix["include"])
    expected_rows = [
        cast("str", job[field]) for job in jobs for field in ("first_slot_id", "second_slot_id")
    ]
    expected_pairs = [cast("str", job["pair_id"]) for job in jobs]
    if (
        start.get("execution_reservation_digest") != reservation_digest
        or start.get("evidence_class") != BOUNDARY_KIND
        or start.get("official_attestation_eligible") is not False
        or start.get("registered_row_count") != EXPECTED_ROWS
        or start.get("registered_row_ids") != expected_rows
        or start.get("registered_pair_job_count") != EXPECTED_PAIRS
        or start.get("registered_pair_job_ids") != expected_pairs
        or start.get("policy") != _EXECUTION_START_POLICY
    ):
        raise GithubRunnerContractError(
            "GitHub execution start does not seal the complete no-replacement run"
        )
    return dict(start)


def validate_qualification_receipt(
    receipt: Mapping[str, object],
    *,
    repository: str,
    workflow_sha: str,
    expected_images: Mapping[str, tuple[str, str, str]],
    expected_docker_executable_sha256: str,
) -> dict[str, object]:
    """Validate an exact no-model qualification for both system arm types.

    ``expected_images`` maps each system to ``(digest reference, image ID,
    archive SHA-256)``.  These expectations must come from the frozen campaign,
    never from fields selected by the live receipt.
    """

    _require_fields(receipt, _QUALIFICATION_FIELDS, "qualification receipt")
    if receipt.get("schema_version") != QUALIFICATION_SCHEMA:
        raise GithubRunnerContractError("qualification receipt schema is unsupported")
    _verified_document_digest(receipt, "qualification receipt")
    expected_workflow_sha = _git_sha(workflow_sha, "workflow SHA")
    docker_digest = _digest(expected_docker_executable_sha256, "Docker executable digest")
    if set(expected_images) != set(SYSTEMS):
        raise GithubRunnerContractError("qualification image expectations must cover both systems")

    github = _mapping(receipt.get("github"), "qualification GitHub binding")
    _require_fields(github, _GITHUB_FIELDS, "qualification GitHub binding")
    if (
        github.get("repository") != _repository(repository)
        or github.get("repository_visibility") != "public"
        or github.get("event_name") != "workflow_dispatch"
        or github.get("ref") != "refs/heads/main"
        or github.get("workflow_sha") != expected_workflow_sha
        or github.get("run_attempt") != 1
        or _positive_int(github.get("run_id"), "GitHub run ID") <= 0
    ):
        raise GithubRunnerContractError("qualification GitHub binding is invalid")

    runner = _mapping(receipt.get("runner"), "qualification runner")
    _require_fields(runner, _RUNNER_FIELDS, "qualification runner")
    image_version = runner.get("image_version")
    if (
        runner.get("environment") != "github-hosted"
        or runner.get("label") != RUNNER_LABEL
        or runner.get("os") != "Linux"
        or runner.get("arch") != "X64"
        or runner.get("image_os") != "ubuntu24"
        or not isinstance(image_version, str)
        or _IMAGE_VERSION_RE.fullmatch(image_version) is None
        or _digest(runner.get("name_sha256"), "runner-name digest") != runner.get("name_sha256")
        or _positive_int(runner.get("host_free_bytes_before"), "runner free bytes")
        < _MIN_RUNNER_FREE_BYTES
    ):
        raise GithubRunnerContractError("qualification did not use the required standard runner")

    boundary = _mapping(receipt.get("boundary"), "qualification boundary")
    _require_fields(boundary, _BOUNDARY_FIELDS, "qualification boundary")
    if boundary != {
        "kind": BOUNDARY_KIND,
        "network_enforcement_kind": NETWORK_ENFORCEMENT_KIND,
        "privileged_dind_used": False,
        "nested_virtualization_used": False,
        "vm_grade_isolation_claimed": False,
        "target_material_owner_uid": 0,
        "target_material_mode": "0700",
        "campaign_material_owner_uid": 0,
        "campaign_material_mode": "0700",
    }:
        raise GithubRunnerContractError("qualification boundary declaration is invalid")

    target = _mapping(receipt.get("rootful_target_daemon"), "rootful target daemon")
    _require_fields(target, _TARGET_DAEMON_FIELDS, "rootful target daemon")
    target_identity = _digest(target.get("daemon_identity_sha256"), "target daemon identity")
    if (
        target.get("docker_executable_sha256") != docker_digest
        or not _security_options(target.get("security_options"), require_rootless=False)
        or _digest(target.get("target_canary_sha256"), "target canary digest")
        != target.get("target_canary_sha256")
    ):
        raise GithubRunnerContractError("rootful target daemon binding is invalid")

    raw_arms = receipt.get("arms")
    if not isinstance(raw_arms, list) or len(raw_arms) != len(SYSTEMS):
        raise GithubRunnerContractError("qualification must contain two exact arm probes")
    arms_by_system: dict[str, Mapping[str, object]] = {}
    seen_uids: set[int] = set()
    seen_daemons: set[str] = {target_identity}
    for raw_arm in raw_arms:
        arm = _mapping(raw_arm, "qualification arm")
        system = arm.get("system")
        if not isinstance(system, str) or system not in SYSTEMS or system in arms_by_system:
            raise GithubRunnerContractError("qualification arm system is invalid or duplicated")
        expected_reference, expected_image_id, expected_archive = expected_images[system]
        _validate_qualification_arm(
            arm,
            system=system,
            target_identity=target_identity,
            expected_reference=_oci_reference(expected_reference),
            expected_image_id=_digest(expected_image_id, f"{system} image ID"),
            expected_archive_sha256=_digest(expected_archive, f"{system} archive digest"),
            expected_docker_sha256=docker_digest,
        )
        uid = cast("int", arm["agent_uid"])
        daemon = cast("str", arm["daemon_identity_sha256"])
        if uid in seen_uids or daemon in seen_daemons:
            raise GithubRunnerContractError("qualification reused an arm UID or Docker authority")
        seen_uids.add(uid)
        seen_daemons.add(daemon)
        arms_by_system[system] = arm
    if set(arms_by_system) != set(SYSTEMS):
        raise GithubRunnerContractError("qualification did not cover both systems")
    return dict(receipt)


def write_json_exclusive(path: Path, payload: Mapping[str, object]) -> Path:
    """Write one canonical evidence document without replacement or symlinks."""

    target = path.expanduser().absolute()
    parent = target.parent.resolve(strict=True)
    if target.parent.absolute() != parent or target.is_symlink():
        raise GithubRunnerContractError("output path or parent is not canonical")
    body = _canonical_bytes(payload)
    if len(body) > _MAX_JSON_BYTES:
        raise GithubRunnerContractError("output document exceeds its fixed byte limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        raise GithubRunnerContractError("refusing to replace an evidence document") from exc
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(target.stat().st_mode) != 0o600:
        raise GithubRunnerContractError("evidence document permissions are invalid")
    return target


def load_json(path: Path, *, label: str) -> dict[str, object]:
    """Load one bounded JSON object while rejecting duplicate member names."""

    source = path.expanduser()
    if source.is_symlink():
        raise GithubRunnerContractError(f"{label} must not be a symlink")
    try:
        source = source.resolve(strict=True)
        raw = source.read_bytes()
    except OSError as exc:
        raise GithubRunnerContractError(f"{label} is unavailable") from exc
    if not source.is_file() or len(raw) > _MAX_JSON_BYTES:
        raise GithubRunnerContractError(f"{label} is not a bounded regular file")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GithubRunnerContractError(f"{label} is malformed JSON") from exc
    if not isinstance(value, dict):
        raise GithubRunnerContractError(f"{label} must be a JSON object")
    return cast("dict[str, object]", value)


def _validate_qualification_arm(  # noqa: PLR0913
    arm: Mapping[str, object],
    *,
    system: str,
    target_identity: str,
    expected_reference: str,
    expected_image_id: str,
    expected_archive_sha256: str,
    expected_docker_sha256: str,
) -> None:
    _require_fields(arm, _ARM_FIELDS, f"{system} qualification arm")
    uid = _positive_int(arm.get("agent_uid"), f"{system} agent UID")
    if uid < 1000 or uid == 65534:
        raise GithubRunnerContractError(f"{system} agent UID is not a dedicated login UID")
    groups = arm.get("supplementary_groups")
    if (
        not isinstance(groups, list)
        or any(not isinstance(group, str) or not group for group in groups)
        or set(groups) & {"adm", "docker", "root", "sudo", "systemd-journal"}
    ):
        raise GithubRunnerContractError(f"{system} agent has a privileged supplementary group")
    daemon_identity = _digest(arm.get("daemon_identity_sha256"), f"{system} daemon identity")
    if (
        arm.get("daemon_kind") != ROOTLESS_DAEMON_KIND
        or daemon_identity == target_identity
        or arm.get("docker_executable_sha256") != expected_docker_sha256
        or _digest(arm.get("docker_host_sha256"), f"{system} Docker-host digest")
        != arm.get("docker_host_sha256")
        or arm.get("socket_owner_uid") != uid
        or arm.get("socket_group_access_absent") is not True
        or arm.get("socket_other_access_absent") is not True
        or not _security_options(arm.get("security_options"), require_rootless=True)
        or arm.get("cgroup_driver") != "systemd"
    ):
        raise GithubRunnerContractError(f"{system} rootless Docker binding is invalid")

    inventory = _mapping(arm.get("initial_inventory"), f"{system} initial inventory")
    _require_fields(inventory, _INVENTORY_FIELDS, f"{system} initial inventory")
    if (
        inventory.get("images") != []
        or inventory.get("containers") != []
        or inventory.get("volumes") != []
    ):
        raise GithubRunnerContractError(f"{system} rootless daemon was not pristine")
    networks = inventory.get("networks")
    if (
        not isinstance(networks, list)
        or len(networks) != 3
        or {network.get("name") for network in networks if isinstance(network, Mapping)}
        != {"bridge", "host", "none"}
        or any(
            not isinstance(network, Mapping)
            or set(network) != {"name", "id", "driver"}
            or _digest(network.get("id"), f"{system} default network ID") != network.get("id")
            or network.get("driver") != _default_network_driver(network.get("name"))
            for network in networks
        )
    ):
        raise GithubRunnerContractError(f"{system} default Docker network inventory is invalid")

    admission = _mapping(arm.get("offline_image_admission"), f"{system} image admission")
    _require_fields(admission, _IMAGE_ADMISSION_FIELDS, f"{system} image admission")
    if (
        admission.get("archive_sha256") != expected_archive_sha256
        or admission.get("image_reference") != expected_reference
        or admission.get("image_id") != expected_image_id
        or admission.get("platform") != "linux/amd64"
        or admission.get("loaded_after_network_lockdown") is not True
        or admission.get("registry_requests") != 0
        or admission.get("pull_events") != 0
        or admission.get("build_events") != 0
        or admission.get("post_load_images")
        != [{"reference": expected_reference, "id": expected_image_id}]
    ):
        raise GithubRunnerContractError(f"{system} image was not admitted offline exactly once")

    authority = _mapping(arm.get("authority_probes"), f"{system} authority probes")
    _require_fields(authority, _AUTHORITY_PROBE_FIELDS, f"{system} authority probes")
    if authority != {
        "agent_has_sudo": False,
        "root_campaign_readable": False,
        "root_target_material_readable": False,
        "rootful_docker_socket_usable": False,
        "provider_secret_proc_readable": False,
        "target_canary_visible_on_agent_daemon": False,
        "agent_socket_usable_by_evaluator_only_uid": True,
    }:
        raise GithubRunnerContractError(f"{system} authority separation probe failed")

    network_policy = _mapping(arm.get("network_policy"), f"{system} network policy")
    _require_fields(network_policy, _NETWORK_POLICY_FIELDS, f"{system} network policy")
    if (
        network_policy.get("kind") != NETWORK_ENFORCEMENT_KIND
        or network_policy.get("owner_uid") != uid
        or network_policy.get("installed_by_uid") != 0
        or network_policy.get("mutable_by_agent_uid") is not False
        or network_policy.get("rootlesskit_process_uid") != uid
        or network_policy.get("dockerd_process_uid") != uid
        or network_policy.get("all_agent_processes_same_uid") is not True
        or network_policy.get("rootlesskit_ipv6_enabled") is not False
        or network_policy.get("default_reject_after_allowlist") is not True
        or _digest(network_policy.get("policy_sha256"), f"{system} network policy digest")
        != network_policy.get("policy_sha256")
        or _digest(network_policy.get("ruleset_sha256"), f"{system} ruleset digest")
        != network_policy.get("ruleset_sha256")
    ):
        raise GithubRunnerContractError(f"{system} root-owned egress policy is invalid")
    _validate_network_probes(
        _mapping(arm.get("network_probes"), f"{system} network probes"),
        system=system,
    )
    _validate_cross_daemon_target_route(
        _mapping(
            arm.get("cross_daemon_target_route"),
            f"{system} cross-daemon target route",
        ),
        system=system,
        target_identity=target_identity,
        expected_reference=expected_reference,
        expected_image_id=expected_image_id,
    )
    _validate_tool_compatibility(
        _mapping(arm.get("tool_compatibility"), f"{system} tool compatibility"),
        system=system,
    )
    teardown = _mapping(arm.get("teardown"), f"{system} teardown")
    _require_fields(teardown, _TEARDOWN_FIELDS, f"{system} teardown")
    if any(value is not True for value in teardown.values()):
        raise GithubRunnerContractError(f"{system} teardown was not fully proven")


def _validate_network_probes(probes: Mapping[str, object], *, system: str) -> None:
    if set(probes) != set(REQUIRED_NETWORK_PROBES):
        raise GithubRunnerContractError(f"{system} network probe set is incomplete")
    for name, (origin, outcome) in REQUIRED_NETWORK_PROBES.items():
        value = _mapping(probes.get(name), f"{system} network probe {name}")
        if set(value) != {"origin", "outcome", "attempts"} or value != {
            "origin": origin,
            "outcome": outcome,
            "attempts": 1,
        }:
            raise GithubRunnerContractError(f"{system} network probe {name} failed")


def _validate_cross_daemon_target_route(
    route: Mapping[str, object],
    *,
    system: str,
    target_identity: str,
    expected_reference: str,
    expected_image_id: str,
) -> None:
    _require_fields(route, _CROSS_DAEMON_ROUTE_FIELDS, f"{system} cross-daemon target route")
    try:
        host_gateway = ipaddress.ip_address(str(route.get("agent_host_gateway_ipv4") or ""))
    except ValueError as exc:
        raise GithubRunnerContractError(
            f"{system} cross-daemon host-gateway address is invalid"
        ) from exc
    if (
        host_gateway.version != 4
        or host_gateway.is_unspecified
        or host_gateway.is_loopback
        or host_gateway.is_multicast
        or host_gateway.is_link_local
    ):
        raise GithubRunnerContractError(f"{system} cross-daemon host-gateway address is unsafe")
    publish_port = _positive_int(
        route.get("rootful_publish_port"), f"{system} rootful gateway port"
    )
    expected = {
        "kind": "rootful-loopback-via-rootless-host-gateway-v1",
        "rootful_gateway_daemon_identity_sha256": target_identity,
        "rootful_gateway_network_count": 1,
        "rootful_gateway_target_network_only": True,
        "rootful_gateway_agent_network_attached": False,
        "rootful_gateway_agent_socket_mounted": False,
        "rootful_gateway_rootful_socket_mounted": False,
        "rootful_gateway_evaluator_source_mounted": False,
        "rootful_publish_host": "127.0.0.1",
        "rootful_publish_port": publish_port,
        "agent_host_gateway_ipv4": str(host_gateway),
        "agent_url_uses_host_gateway": True,
        "root_owned_uid_firewall_active": True,
        "agent_process_http_probe": "succeeded",
        "tool_container_http_probe": "succeeded",
        "meter_observed_request_delta": 2,
        "direct_target_canary_denied": True,
        "tool_image_reference": expected_reference,
        "tool_image_id": expected_image_id,
    }
    if not 49_152 <= publish_port <= 65_535 or dict(route) != expected:
        raise GithubRunnerContractError(
            f"{system} cross-daemon target route was not functionally qualified"
        )


def _validate_tool_compatibility(tool: Mapping[str, object], *, system: str) -> None:
    _require_fields(tool, _TOOL_FIELDS, f"{system} compatibility probe")
    requested = tool.get("requested_capabilities")
    effective = tool.get("effective_capabilities")
    if not isinstance(requested, list) or not isinstance(effective, list):
        raise GithubRunnerContractError(f"{system} capability evidence is malformed")
    common = {
        "container_created": True,
        "container_started": True,
        "entrypoint_preserved": True,
        "sandbox_network_attached": True,
        "host_gateway_present": True,
        "sys_admin_requested": False,
        "fuse_device_requested": False,
        "local_service_ready": True,
        "container_removed": True,
    }
    if any(tool.get(name) != expected for name, expected in common.items()):
        raise GithubRunnerContractError(f"{system} tool compatibility probe failed")
    if system == "strix":
        if (
            tool.get("probe_kind") != "pinned-strix-default-manifest-startup-v1"
            or requested != ["NET_ADMIN", "NET_RAW"]
            or not {"NET_ADMIN", "NET_RAW"} <= set(effective)
            or "SYS_ADMIN" in effective
            or tool.get("net_admin_functional_probe") != "succeeded"
            or tool.get("net_raw_functional_probe") != "succeeded"
        ):
            raise GithubRunnerContractError(
                "Strix rootless Docker capability/startup qualification failed"
            )
    elif (
        tool.get("probe_kind") != "pinned-ravage-scoped-tool-runtime-startup-v1"
        or requested != []
        or effective != []
        or tool.get("net_admin_functional_probe") != "not_requested"
        or tool.get("net_raw_functional_probe") != "not_requested"
    ):
        raise GithubRunnerContractError("Ravage rootless Docker startup qualification failed")


def _validated_schedule_row(
    row: Mapping[str, object], *, slot: int, pair_index: int
) -> dict[str, object]:
    expected_keys = {
        "slot",
        "slot_id",
        "pair_index",
        "position_within_pair",
        "case_id",
        "system",
        "purpose",
        "score_eligible",
    }
    _require_fields(row, expected_keys, "selection schedule row")
    position = 1 if slot % 2 else 2
    slot_id = row.get("slot_id")
    system = row.get("system")
    if (
        row.get("slot") != slot
        or slot_id != f"primary-{slot:03d}"
        or not isinstance(slot_id, str)
        or _SLOT_RE.fullmatch(slot_id) is None
        or row.get("pair_index") != pair_index
        or row.get("position_within_pair") != position
        or not isinstance(system, str)
        or system not in SYSTEMS
        or row.get("purpose") != "primary"
        or row.get("score_eligible") is not True
    ):
        raise GithubRunnerContractError("selection schedule row binding is invalid")
    return {"slot_id": slot_id, "case_id": _case_id(row.get("case_id")), "system": system}


def _security_options(value: object, *, require_rootless: bool) -> bool:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return False
    normalized = {item.lower() for item in value}
    has_rootless = bool(normalized & {"rootless", "name=rootless"})
    return has_rootless is require_rootless and any("seccomp" in item for item in normalized)


def _default_network_driver(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return {"bridge": "bridge", "host": "host", "none": "null"}.get(value)


def _with_digest(body: Mapping[str, object]) -> dict[str, object]:
    if "document_digest" in body:
        raise GithubRunnerContractError("document body already contains a digest")
    normalized = dict(body)
    return {**normalized, "document_digest": _digest_value(normalized)}


def _verified_document_digest(value: Mapping[str, object], label: str) -> str:
    digest = _digest(value.get("document_digest"), f"{label} document digest")
    body = {key: member for key, member in value.items() if key != "document_digest"}
    if _digest_value(body) != digest:
        raise GithubRunnerContractError(f"{label} document digest does not verify")
    return digest


def _digest_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GithubRunnerContractError("JSON document contains a duplicate member name")
        result[key] = value
    return result


def _require_fields(value: Mapping[str, object], expected: object, label: str) -> None:
    if set(value) != set(cast("Sequence[str]", expected)):
        raise GithubRunnerContractError(f"{label} fields are invalid")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise GithubRunnerContractError(f"{label} must be an object")
    return cast("Mapping[str, object]", value)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise GithubRunnerContractError(f"{label} is invalid")
    return value


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA_RE.fullmatch(value) is None:
        raise GithubRunnerContractError(f"{label} is invalid")
    return value


def _campaign_id(value: object) -> str:
    if not isinstance(value, str) or _CAMPAIGN_RE.fullmatch(value) is None:
        raise GithubRunnerContractError("campaign ID is invalid")
    return value


def _case_id(value: object) -> str:
    if not isinstance(value, str) or _CASE_RE.fullmatch(value) is None:
        raise GithubRunnerContractError("XBEN case ID is invalid")
    return value


def _oci_reference(value: object) -> str:
    if not isinstance(value, str) or _OCI_RE.fullmatch(value) is None:
        raise GithubRunnerContractError("OCI image reference is not digest-pinned")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GithubRunnerContractError(f"{label} must be a positive integer")
    return value


def _repository(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 200
        or value.count("/") != 1
        or any(not part or part in {".", ".."} for part in value.split("/"))
    ):
        raise GithubRunnerContractError("GitHub repository name is invalid")
    return value


def _parse_expected_image(values: Sequence[str]) -> dict[str, tuple[str, str, str]]:
    parsed: dict[str, tuple[str, str, str]] = {}
    for value in values:
        parts = value.split("=", 1)
        fields = parts[1].split(",") if len(parts) == 2 else []
        if parts[0] not in SYSTEMS or parts[0] in parsed or len(fields) != 3:
            raise GithubRunnerContractError(
                "--expected-image must be SYSTEM=REFERENCE,IMAGE_ID,ARCHIVE_SHA256"
            )
        parsed[parts[0]] = (fields[0], fields[1], fields[2])
    if set(parsed) != set(SYSTEMS):
        raise GithubRunnerContractError("--expected-image must cover Ravage and Strix")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    assessment = subparsers.add_parser("assessment")
    assessment.add_argument("--output", type=Path, required=True)
    matrix = subparsers.add_parser("matrix")
    matrix.add_argument("--selection", type=Path, required=True)
    matrix.add_argument("--output", type=Path, required=True)
    qualify = subparsers.add_parser("validate-qualification")
    qualify.add_argument("--receipt", type=Path, required=True)
    qualify.add_argument("--repository", required=True)
    qualify.add_argument("--workflow-sha", required=True)
    qualify.add_argument("--docker-executable-sha256", required=True)
    qualify.add_argument("--expected-image", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "assessment":
            write_json_exclusive(args.output, implementation_assessment())
            return 2
        if args.command == "matrix":
            selection = load_json(args.selection, label="selection")
            write_json_exclusive(args.output, build_pair_job_matrix(selection))
            return 0
        if args.command == "validate-qualification":
            receipt = load_json(args.receipt, label="qualification receipt")
            validate_qualification_receipt(
                receipt,
                repository=args.repository,
                workflow_sha=args.workflow_sha,
                expected_images=_parse_expected_image(args.expected_image),
                expected_docker_executable_sha256=args.docker_executable_sha256,
            )
            return 0
    except GithubRunnerContractError as exc:
        sys.stderr.write(f"blocked: {exc}\n")
        return 2
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
