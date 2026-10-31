# ruff: noqa: BLE001,C901,D202,D213,EM101,EM102,PLR2004,TRY003,TRY004,TRY301
"""Canonical adapter/process bridge for the paired known-site harness.

The website coordinator never receives an agent command directly.  This bridge
accepts factories for the two already pinned canonical adapters and for the
row-scoped comparison process backend, verifies their cross-bindings, supplies
only the target URL and normalized public description, and turns the generic
comparison receipts into the website-specific terminal contract.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

import ravage.xben_parts.comparison_adapters as comparison_adapters_module
from ravage.xben_parts.comparison_adapters import (
    ADAPTER_SCHEMA_VERSION,
    ADAPTER_STDERR_PATH,
    ADAPTER_STDOUT_PATH,
    ADAPTER_VERSION,
    CANDIDATE_ARTIFACT_PATH,
    GATEWAY_BASE_URL_ENV,
    AdapterConfigurationError,
    validate_pinned_adapter_agent,
)
from ravage.xben_parts.comparison_model_gateway import (
    ModelGatewayError,
    validate_model_gateway_receipt,
)
from ravage.xben_parts.comparison_process_backend import (
    MODEL_GATEWAY_RECEIPT_FILE,
    PAIRED_LOCAL,
    PROCESS_RECEIPT_FILE,
    SANDBOX_PROFILE_FILE,
    ComparisonProcessError,
    read_bounded_json_receipt,
    validate_comparison_process_receipt,
)
from ravage.xben_parts.external_comparison import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    DESCRIPTION_ENV,
    OUTER_PROCESS_GROUP_ENV,
    OUTER_PROCESS_GROUP_VALUE,
    TARGET_URL_ENV,
    ExternalAgentCommand,
    ExternalProcessBackend,
)

from tools.known_site_regression.harness import (
    ADAPTER_RECEIPT_FILE,
    KNOWN_SITE_SOURCE_PATH,
    NATIVE_OUTPUT_DIRECTORY,
    AgentArmContext,
    AgentArmTerminal,
)

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_SITE_FLAG_RE = re.compile(r"flag\{ravage_site_[0-9a-f]{64}\}")
_MAX_ADAPTER_RECEIPT_BYTES = 16 * 1024 * 1024
_MAX_CANDIDATE_BYTES = 1024 * 1024
_MAX_PROFILE_BYTES = 1024 * 1024
_MAX_GIT_MARKER_BYTES = 4096


class CanonicalAgentFactory(Protocol):
    """Build one exact Ravage or Strix adapter for a row context."""

    def __call__(self, context: AgentArmContext) -> ExternalAgentCommand: ...


class ComparisonProcessFactory(Protocol):
    """Build the registered row's evaluator-owned process boundary."""

    def __call__(
        self,
        context: AgentArmContext,
        agent: ExternalAgentCommand,
    ) -> ExternalProcessBackend: ...


@dataclass(frozen=True)
class CanonicalKnownSiteAgentBackend:
    """Run canonical comparison adapters without invoking an XBEN row schema."""

    agent_factories: Mapping[str, CanonicalAgentFactory]
    process_factory: ComparisonProcessFactory
    forbidden_target_source_paths: tuple[Path, ...]
    pre_draw_validator: Callable[[object], None] | None = None

    def __post_init__(self) -> None:
        if set(self.agent_factories) != {"ravage", "strix"}:
            raise ValueError("known-site backend requires exactly Ravage and Strix factories")
        if not self.forbidden_target_source_paths:
            raise ValueError("known-site backend requires a forbidden target-source path")
        _resolved_forbidden_paths(self.forbidden_target_source_paths)

    def validate_pre_draw(self, *, contract: object) -> None:
        """Validate source exclusion and production runtime pins before entropy.

        The concrete production assembler supplies ``pre_draw_validator``.  It
        revalidates both frozen runtime manifests, clean source identities,
        readable roots, and the agent Docker boundary without constructing a
        gateway row or launching an adapter.  The local checks here also bind
        the exact adapter source and forbidden target path even for injected
        backends used by tests.
        """

        adapter_source = Path(str(comparison_adapters_module.__file__)).resolve(strict=True)
        expected = getattr(contract, "adapter_source_sha256", None)
        if (
            not isinstance(expected, str)
            or _sha256_bytes(_read_bounded(adapter_source, _MAX_ADAPTER_RECEIPT_BYTES)) != expected
        ):
            raise AdapterConfigurationError(
                "comparison adapter source differs from its pre-draw digest"
            )
        _resolved_forbidden_paths(self.forbidden_target_source_paths)
        if self.pre_draw_validator is None:
            raise AdapterConfigurationError(
                "production runtime pre-draw validator is not configured"
            )
        self.pre_draw_validator(contract)

    def run_arm(self, context: AgentArmContext) -> AgentArmTerminal:
        """Launch once and return a terminal receipt even when validation fails."""

        if context.target_url is None:
            return self.seal_unstarted(context, reason="target URL is unavailable")
        agent, process, environment = self._prepare(context, include_target=True)
        try:
            result = process.run(
                agent.command,
                cwd=context.native_output_dir,
                environment=environment,
                limits=context.limits,
            )
        except Exception as exc:
            return self._seal_after_launch_failure(
                context,
                agent=agent,
                process=process,
                reason=_safe_error(exc, sensitive=(context.gateway_token,)),
            )

        receipt_paths_match = (
            result.process_receipt_path == PROCESS_RECEIPT_FILE
            and result.model_gateway_receipt_path == MODEL_GATEWAY_RECEIPT_FILE
            and result.sandbox_profile_path == SANDBOX_PROFILE_FILE
        )
        validation_error: str | None = None
        public_contract: Mapping[str, object] | None = None
        semantic_prompt_sha256: str | None = None
        elapsed_seconds = 0.0
        adapter_path = context.native_output_dir / ADAPTER_RECEIPT_FILE
        artifact_path: str | None = None
        artifact_sha256: str | None = None
        adapter_timed_out = False
        try:
            if not receipt_paths_match:
                raise ComparisonProcessError("process backend returned unexpected receipt paths")
            evidence = self._validate_started_evidence(
                context,
                agent=agent,
                process=process,
                environment=environment,
                wrapper_returncode=result.returncode,
                wrapper_timed_out=result.timed_out,
            )
            public_contract = evidence["public_contract"]  # type: ignore[assignment]
            semantic_prompt_sha256 = str(evidence["semantic_prompt_sha256"])
            elapsed_value = evidence["elapsed_seconds"]
            if isinstance(elapsed_value, bool) or not isinstance(elapsed_value, (int, float)):
                raise ComparisonProcessError("validated process elapsed time is not numeric")
            elapsed_seconds = float(elapsed_value)
            if evidence["artifact_sha256"] is not None:
                artifact_path = CANDIDATE_ARTIFACT_PATH
                artifact_sha256 = str(evidence["artifact_sha256"])
            adapter_timed_out = evidence.get("adapter_timed_out") is True
        except (
            AdapterConfigurationError,
            ComparisonProcessError,
            ModelGatewayError,
            OSError,
            ValueError,
        ) as exc:
            validation_error = _safe_error(exc, sensitive=(context.gateway_token,))
            observed_elapsed = _observed_process_elapsed(context)
            if observed_elapsed is not None:
                elapsed_seconds = observed_elapsed
        status: Literal["completed", "failed", "timed_out", "unstarted"] = (
            "timed_out"
            if result.timed_out or adapter_timed_out
            else ("completed" if result.returncode == 0 and validation_error is None else "failed")
        )
        if validation_error is None and status == "timed_out":
            validation_error = "canonical adapter reached its first-attempt timeout"
        elif validation_error is None and status == "failed":
            validation_error = "canonical agent or adapter exited nonzero"
        if elapsed_seconds == 0.0 and validation_error is None:
            elapsed_seconds = min(float(context.limits.wall_seconds), 0.000001)
        return AgentArmTerminal(
            status=status,
            returncode=result.returncode,
            timed_out=status == "timed_out",
            elapsed_seconds=elapsed_seconds,
            description_sha256=_sha256_text(context.description),
            semantic_prompt_sha256=semantic_prompt_sha256,
            model_gateway_policy_sha256=context.gateway_policy_sha256,
            adapter_version=ADAPTER_VERSION,
            artifact_path=artifact_path,
            artifact_sha256=artifact_sha256,
            adapter_receipt_path=(
                f"{NATIVE_OUTPUT_DIRECTORY}/{ADAPTER_RECEIPT_FILE}"
                if adapter_path.is_file() and not adapter_path.is_symlink()
                else None
            ),
            process_receipt_path=(PROCESS_RECEIPT_FILE if receipt_paths_match else None),
            model_receipt_path=(MODEL_GATEWAY_RECEIPT_FILE if receipt_paths_match else None),
            sandbox_profile_path=(SANDBOX_PROFILE_FILE if receipt_paths_match else None),
            process_public_contract=public_contract,
            evidence_class=PAIRED_LOCAL,
            error=validation_error,
        )

    def seal_unstarted(self, context: AgentArmContext, *, reason: str) -> AgentArmTerminal:
        """Seal the registered model row without pretending an agent launched."""

        try:
            agent, process, environment = self._prepare(context, include_target=False)
            result = process.seal_unstarted(
                agent.command,
                cwd=context.native_output_dir,
                environment=environment,
                limits=context.limits,
                reason=_safe_error(RuntimeError(reason), sensitive=(context.gateway_token,)),
            )
            receipt_paths_match = (
                result.process_receipt_path == PROCESS_RECEIPT_FILE
                and result.model_gateway_receipt_path == MODEL_GATEWAY_RECEIPT_FILE
                and result.sandbox_profile_path == SANDBOX_PROFILE_FILE
            )
            error = None if receipt_paths_match else "unstarted receipt paths are incomplete"
        except Exception as exc:
            receipt_paths_match = False
            error = _safe_error(exc, sensitive=(context.gateway_token,))
        return AgentArmTerminal(
            status="unstarted",
            returncode=-1,
            timed_out=False,
            elapsed_seconds=0.0,
            description_sha256=_sha256_text(context.description),
            semantic_prompt_sha256=None,
            model_gateway_policy_sha256=context.gateway_policy_sha256,
            adapter_version=ADAPTER_VERSION,
            artifact_path=None,
            artifact_sha256=None,
            adapter_receipt_path=None,
            process_receipt_path=(PROCESS_RECEIPT_FILE if receipt_paths_match else None),
            model_receipt_path=(MODEL_GATEWAY_RECEIPT_FILE if receipt_paths_match else None),
            sandbox_profile_path=(SANDBOX_PROFILE_FILE if receipt_paths_match else None),
            process_public_contract=None,
            evidence_class=PAIRED_LOCAL,
            error=error,
        )

    def _seal_after_launch_failure(
        self,
        context: AgentArmContext,
        *,
        agent: ExternalAgentCommand,
        process: ExternalProcessBackend,
        reason: str,
    ) -> AgentArmTerminal:
        try:
            result = process.seal_unstarted(
                agent.command,
                cwd=context.native_output_dir,
                environment=dict(agent.environment),
                limits=context.limits,
                reason=reason,
            )
            paths_match = (
                result.process_receipt_path == PROCESS_RECEIPT_FILE
                and result.model_gateway_receipt_path == MODEL_GATEWAY_RECEIPT_FILE
                and result.sandbox_profile_path == SANDBOX_PROFILE_FILE
            )
        except Exception as exc:
            paths_match = False
            reason = _safe_error(exc, sensitive=(context.gateway_token,))
        return AgentArmTerminal(
            status="unstarted",
            returncode=-1,
            timed_out=False,
            elapsed_seconds=0.0,
            description_sha256=_sha256_text(context.description),
            semantic_prompt_sha256=None,
            model_gateway_policy_sha256=context.gateway_policy_sha256,
            adapter_version=ADAPTER_VERSION,
            artifact_path=None,
            artifact_sha256=None,
            adapter_receipt_path=None,
            process_receipt_path=(PROCESS_RECEIPT_FILE if paths_match else None),
            model_receipt_path=(MODEL_GATEWAY_RECEIPT_FILE if paths_match else None),
            sandbox_profile_path=(SANDBOX_PROFILE_FILE if paths_match else None),
            process_public_contract=None,
            evidence_class=PAIRED_LOCAL,
            error=reason,
        )

    def _prepare(
        self,
        context: AgentArmContext,
        *,
        include_target: bool,
    ) -> tuple[ExternalAgentCommand, ExternalProcessBackend, dict[str, str]]:
        if context.system not in self.agent_factories:
            raise AdapterConfigurationError("known-site system has no canonical adapter factory")
        adapter_source = Path(str(comparison_adapters_module.__file__)).resolve(strict=True)
        if _sha256_bytes(_read_bounded(adapter_source, _MAX_ADAPTER_RECEIPT_BYTES)) != (
            context.adapter_source_sha256
        ):
            raise AdapterConfigurationError(
                "comparison adapter source differs from its pre-draw digest"
            )
        agent = self.agent_factories[context.system](context)
        launch = validate_pinned_adapter_agent(agent)
        if (
            agent.system_id != context.system
            or launch.system_id != context.system
            or agent.limits != context.limits
            or agent.artifact_path != CANDIDATE_ARTIFACT_PATH
            or agent.adapter_version != ADAPTER_VERSION
            or agent.environment.get(COMPARISON_GATEWAY_TOKEN_ENV) != context.gateway_token
        ):
            raise AdapterConfigurationError("canonical adapter differs from the website row")
        system_pin = context.system_pin.to_json(system=context.system)
        source_pin = _mapping(system_pin.get("source"), "frozen system source")
        runtime_pin = _mapping(system_pin.get("runtime"), "frozen system runtime")
        tool_pin = _mapping(system_pin.get("tool_image"), "frozen system tool image")
        runtime_identity = launch.runtime.to_json()
        if (
            runtime_identity.get("source_origin_url") != source_pin.get("origin_url")
            or runtime_identity.get("source_commit") != source_pin.get("commit")
            or runtime_identity.get("source_tree") != source_pin.get("tree")
            or runtime_identity.get("runtime_environment_manifest_sha256")
            != runtime_pin.get("manifest_sha256")
            or runtime_identity.get("executable_sha256") != runtime_pin.get("executable_sha256")
            or launch.tool_image != tool_pin.get("reference")
        ):
            raise AdapterConfigurationError(
                "canonical adapter runtime differs from its pre-draw system pin"
            )
        process = self.process_factory(context, agent)
        receipt = process.receipt_contract
        agent_plan = context.docker_separation.agent_vm.plan_for(context.row_id)
        socket_path = receipt.docker_socket_path
        if (
            receipt.row_id != context.row_id
            or receipt.model_gateway_policy_sha256 != context.gateway_policy_sha256
            or receipt.model_gateway_row_token_sha256 != _sha256_text(context.gateway_token)
            or receipt.evidence_class != PAIRED_LOCAL
            or socket_path is None
            or launch.docker_host != f"unix://{socket_path.as_posix()}"
            or _sha256_text(socket_path.as_posix()) != agent_plan.docker_socket_path_sha256
            or _sha256_text(launch.docker_host) != agent_plan.docker_host_sha256
        ):
            raise ComparisonProcessError("process receipt contract differs from website row")
        _validate_forbidden_source_separation(
            receipt.runtime_read_roots,
            forbidden_paths=self.forbidden_target_source_paths,
        )
        _validate_evidence_root_separation(
            receipt.runtime_read_roots,
            private_campaign_root=context.evidence_dir.parent,
        )
        environment = dict(agent.environment)
        if include_target:
            if context.target_url is None:
                raise AdapterConfigurationError("started arm requires a target URL")
            environment[TARGET_URL_ENV] = context.target_url
            environment[DESCRIPTION_ENV] = context.description
        return agent, process, environment

    def _validate_started_evidence(  # noqa: PLR0913
        self,
        context: AgentArmContext,
        *,
        agent: ExternalAgentCommand,
        process: ExternalProcessBackend,
        environment: Mapping[str, str],
        wrapper_returncode: int,
        wrapper_timed_out: bool,
    ) -> dict[str, object]:
        receipt_contract = process.receipt_contract
        model_path = context.evidence_dir / MODEL_GATEWAY_RECEIPT_FILE
        process_path = context.evidence_dir / PROCESS_RECEIPT_FILE
        profile_path = context.evidence_dir / SANDBOX_PROFILE_FILE
        adapter_path = context.native_output_dir / ADAPTER_RECEIPT_FILE
        model_payload = read_bounded_json_receipt(model_path)
        process_payload = read_bounded_json_receipt(process_path)
        profile = _read_bounded(profile_path, _MAX_PROFILE_BYTES)
        adapter = _read_json(adapter_path, _MAX_ADAPTER_RECEIPT_BYTES)
        model = validate_model_gateway_receipt(
            model_payload,
            expected_row_id=context.row_id,
            expected_policy_sha256=context.gateway_policy_sha256,
            expected_max_requests=context.limits.max_model_requests,
            expected_max_cost_usd=context.limits.max_cost_usd,
        )
        if model.get("row_token_sha256") != _sha256_text(context.gateway_token):
            raise ModelGatewayError("model receipt row token differs from the context")
        model_file_sha256 = _sha256_bytes(_read_bounded(model_path, _MAX_ADAPTER_RECEIPT_BYTES))
        process_receipt = validate_comparison_process_receipt(
            process_payload,
            expected_row_id=context.row_id,
            expected_command=agent.command,
            expected_environment=environment,
            expected_limits=context.limits,
            expected_policy_sha256=context.gateway_policy_sha256,
            expected_sandbox_exec_sha256=receipt_contract.sandbox_executable_sha256,
            expected_runtime_read_roots=receipt_contract.runtime_read_roots,
            expected_output_directory=context.native_output_dir,
            expected_docker_socket_path=receipt_contract.docker_socket_path,
            model_receipt_file_sha256=model_file_sha256,
            model_receipt_document_sha256=str(model["document_sha256"]),
            sandbox_profile=profile,
            require_official_safety=False,
        )
        candidate_path = context.native_output_dir / CANDIDATE_ARTIFACT_PATH
        candidate_body = (
            _read_bounded(candidate_path, _MAX_CANDIDATE_BYTES)
            if candidate_path.is_file() and not candidate_path.is_symlink()
            else None
        )
        adapter_evidence = _validate_adapter_receipt(
            adapter,
            context=context,
            agent=agent,
            candidate_body=candidate_body,
            wrapper_returncode=wrapper_returncode,
            wrapper_timed_out=wrapper_timed_out,
        )
        execution = _mapping(process_receipt.get("execution"), "process execution")
        elapsed = execution.get("elapsed_seconds")
        if (
            isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or not math.isfinite(elapsed)
            or elapsed < 0
            or elapsed > context.limits.wall_seconds
        ):
            raise ComparisonProcessError("process elapsed time exceeds the arm cap")
        public_contract: dict[str, object] = {
            "row_id": context.row_id,
            "command": process_receipt["command"],
            "environment": process_receipt["environment"],
            "limits": context.limits.to_json(),
            "model_gateway_policy_sha256": context.gateway_policy_sha256,
            "model_gateway_row_token_sha256": receipt_contract.model_gateway_row_token_sha256,
            "sandbox_executable_sha256": receipt_contract.sandbox_executable_sha256,
            "sandbox": process_receipt["sandbox"],
        }
        return {
            "public_contract": public_contract,
            "semantic_prompt_sha256": adapter_evidence["semantic_prompt_sha256"],
            "elapsed_seconds": float(elapsed),
            "artifact_sha256": (
                _sha256_bytes(candidate_body) if candidate_body is not None else None
            ),
            "adapter_timed_out": adapter_evidence["timed_out"],
        }


def _validate_adapter_receipt(  # noqa: PLR0912,PLR0913
    value: object,
    *,
    context: AgentArmContext,
    agent: ExternalAgentCommand,
    candidate_body: bytes | None,
    wrapper_returncode: int,
    wrapper_timed_out: bool,
) -> dict[str, object]:
    receipt = _mapping(value, "adapter receipt")
    expected_fields = {
        "schema_version",
        "adapter_version",
        "system_id",
        "status",
        "returncode",
        "wrapper_returncode",
        "process_group_policy",
        "timed_out",
        "command_sha256",
        "target_url_sha256",
        "gateway_base_url_sha256",
        "docker_host_sha256",
        "gateway",
        "limits",
        "tool_image",
        "input_contract",
        "runtime",
        "capture",
        "candidate_extraction",
        "environment_policy",
    }
    status = receipt.get("status")
    returncode = receipt.get("returncode")
    timed_out = receipt.get("timed_out")
    if (
        set(receipt) != expected_fields
        or receipt.get("schema_version") != ADAPTER_SCHEMA_VERSION
        or receipt.get("adapter_version") != ADAPTER_VERSION
        or receipt.get("system_id") != context.system
        or status not in {"completed", "agent_nonzero", "timed_out"}
        or isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or receipt.get("wrapper_returncode") != wrapper_returncode
        or not isinstance(wrapper_timed_out, bool)
        or not isinstance(timed_out, bool)
        or receipt.get("process_group_policy") != "joined_evaluator_outer_group"
        or receipt.get("target_url_sha256") != _sha256_text(str(context.target_url))
        or receipt.get("gateway_base_url_sha256")
        != _sha256_text(agent.environment[GATEWAY_BASE_URL_ENV])
    ):
        raise AdapterConfigurationError("adapter receipt identity is invalid")
    if (
        wrapper_timed_out
        or (status == "completed" and (returncode != 0 or timed_out))
        or (
            status == "agent_nonzero"
            and (
                returncode == 0
                or timed_out
                or wrapper_returncode != _portable_adapter_returncode(returncode)
            )
        )
        or (
            status == "timed_out"
            and (timed_out is not True or returncode == 0 or wrapper_returncode != 124)
        )
    ):
        raise AdapterConfigurationError("adapter receipt outcome is internally inconsistent")
    extraction = _mapping(receipt.get("candidate_extraction"), "candidate extraction")
    candidate_count = extraction.get("candidate_count")
    extraction_complete = extraction.get("complete")
    if (
        not isinstance(extraction_complete, bool)
        or extraction.get("expected_flag_used") is not False
        or isinstance(candidate_count, bool)
        or not isinstance(candidate_count, int)
        or candidate_count < 0
    ):
        raise AdapterConfigurationError("adapter candidate extraction is invalid")
    if status != "timed_out" and extraction_complete is not True:
        raise AdapterConfigurationError("non-timeout adapter candidate extraction is incomplete")
    if status == "timed_out" and extraction_complete is not False:
        raise AdapterConfigurationError("timed-out adapter invented candidate extraction")
    if extraction_complete:
        if candidate_body is None or extraction.get("artifact_path") != CANDIDATE_ARTIFACT_PATH:
            raise AdapterConfigurationError("adapter candidate artifact is missing")
        candidate_lines = candidate_body.splitlines()
        if candidate_count != len(candidate_lines) or candidate_body != b"".join(
            line + b"\n" for line in candidate_lines
        ):
            raise AdapterConfigurationError("adapter candidate extraction is incomplete")
    elif (
        candidate_body is not None
        or extraction.get("artifact_path") is not None
        or candidate_count != 0
    ):
        raise AdapterConfigurationError("incomplete adapter extraction invented candidates")
    _validate_adapter_capture(
        receipt.get("capture"),
        output_directory=context.native_output_dir,
    )
    launch = validate_pinned_adapter_agent(agent)
    if (
        receipt.get("docker_host_sha256") != _sha256_text(launch.docker_host)
        or receipt.get("gateway") != launch.gateway_public
        or receipt.get("limits") != context.limits.to_json()
        or receipt.get("tool_image") != launch.tool_image
        or agent.environment.get(OUTER_PROCESS_GROUP_ENV) != OUTER_PROCESS_GROUP_VALUE
    ):
        raise AdapterConfigurationError("adapter receipt runtime binding is invalid")
    runtime = _mapping(receipt.get("runtime"), "adapter runtime")
    frozen = context.system_pin.to_json(system=context.system)
    source_pin = _mapping(frozen.get("source"), "frozen source")
    runtime_pin = _mapping(frozen.get("runtime"), "frozen runtime")
    if (
        runtime.get("source_origin_url") != source_pin.get("origin_url")
        or runtime.get("source_commit") != source_pin.get("commit")
        or runtime.get("source_tree") != source_pin.get("tree")
        or runtime.get("environment_manifest_sha256") != runtime_pin.get("manifest_sha256")
        or runtime.get("executable_sha256") != runtime_pin.get("executable_sha256")
    ):
        raise AdapterConfigurationError("adapter receipt source/runtime pin is invalid")
    input_contract = _mapping(receipt.get("input_contract"), "adapter input contract")
    semantic = input_contract.get("semantic_prompt_sha256")
    if (
        input_contract.get("mode") != "description-only-black-box"
        or input_contract.get("description_sha256") != _sha256_text(context.description)
        or not isinstance(semantic, str)
        or _SHA256_RE.fullmatch(semantic) is None
        or input_contract.get("target_url_in_semantic_prompt") is not False
        or input_contract.get("case_id_included") is not False
        or input_contract.get("source_path_included") is not False
        or input_contract.get("expected_flag_used") is not False
    ):
        raise AdapterConfigurationError("adapter receipt black-box contract is invalid")
    gateway = _mapping(receipt.get("gateway"), "adapter gateway")
    if gateway.get("model") != agent.model or gateway.get("reasoning_effort") != (
        agent.reasoning_effort
    ):
        raise AdapterConfigurationError("adapter receipt model identity is invalid")
    environment = _mapping(receipt.get("environment_policy"), "adapter environment")
    redacted_credentials = environment.get("persisted_row_credentials_redacted")
    if (
        environment.get("inherits_parent") is not False
        or environment.get("row_gateway_only") is not True
        or environment.get("ambient_proxy_or_provider_credentials") is not False
        or environment.get("fresh_home_work_run") is not True
        or isinstance(redacted_credentials, bool)
        or not isinstance(redacted_credentials, int)
        or redacted_credentials < 0
    ):
        raise AdapterConfigurationError("adapter environment isolation is invalid")
    return {"semantic_prompt_sha256": semantic, "timed_out": timed_out}


def _validate_adapter_capture(value: object, *, output_directory: Path) -> None:
    capture = _mapping(value, "adapter capture")
    if set(capture) != {"stdout", "stderr"}:
        raise AdapterConfigurationError("adapter capture streams are invalid")
    for stream, filename in (
        ("stdout", ADAPTER_STDOUT_PATH),
        ("stderr", ADAPTER_STDERR_PATH),
    ):
        observed = _mapping(capture.get(stream), f"adapter {stream} capture")
        if set(observed) != {
            "sha256",
            "total_bytes",
            "retained_bytes",
            "truncated",
            "complete",
        }:
            raise AdapterConfigurationError(f"adapter {stream} capture is invalid")
        total = observed.get("total_bytes")
        retained = observed.get("retained_bytes")
        if (
            isinstance(total, bool)
            or not isinstance(total, int)
            or total < 0
            or isinstance(retained, bool)
            or not isinstance(retained, int)
            or retained < 0
            or observed.get("truncated") is not False
            or observed.get("complete") is not True
        ):
            raise AdapterConfigurationError(f"adapter {stream} capture is incomplete")
        body = _read_bounded(output_directory / filename, _MAX_ADAPTER_RECEIPT_BYTES)
        if (
            total != retained
            or retained != len(body)
            or observed.get("sha256") != (_sha256_bytes(body))
        ):
            raise AdapterConfigurationError(
                f"adapter {stream} capture does not reproduce retained bytes"
            )


def _portable_adapter_returncode(value: int) -> int:
    """Recompute the canonical adapter wrapper's portable exit status."""

    if value < 0:
        return 128 + min(127, abs(value))
    return min(value, 125)


def _read_json(path: Path, maximum_bytes: int) -> dict[str, object]:
    body = _read_bounded(path, maximum_bytes)
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AdapterConfigurationError(f"receipt is invalid JSON: {path.name}") from exc
    return _mapping(value, path.name)


def _observed_process_elapsed(context: AgentArmContext) -> float | None:
    """Recover retained timing after an expected non-success validation path."""

    try:
        receipt = _read_json(
            context.evidence_dir / PROCESS_RECEIPT_FILE,
            _MAX_ADAPTER_RECEIPT_BYTES,
        )
        execution = _mapping(receipt.get("execution"), "process execution")
        value = execution.get("elapsed_seconds")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
            or value > context.limits.wall_seconds
        ):
            return None
        return float(value)
    except (AdapterConfigurationError, OSError, ValueError):
        return None


def _read_bounded(path: Path, maximum_bytes: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise OSError(f"receipt is missing or unsafe: {path.name}")
    body = path.read_bytes()
    if len(body) > maximum_bytes:
        raise OSError(f"receipt exceeds its byte limit: {path.name}")
    return body


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return {str(name): item for name, item in value.items()}


def _resolved_forbidden_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    resolved: set[Path] = set()
    expected_suffix = Path(KNOWN_SITE_SOURCE_PATH).parts
    for raw in paths:
        if raw.is_symlink():
            raise ValueError("forbidden target-source path cannot be a symlink")
        try:
            path = raw.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError("forbidden target-source path is missing") from exc
        if not path.is_dir():
            raise ValueError("forbidden target-source path must be a directory")
        if path.parts[-len(expected_suffix) :] != expected_suffix:
            raise ValueError("forbidden path must identify the known-site lab directory")
        resolved.add(path)
    return tuple(sorted(resolved))


def _validate_forbidden_source_separation(
    read_roots: Sequence[Path],
    *,
    forbidden_paths: Sequence[Path],
) -> None:
    forbidden_material = _forbidden_material_paths(forbidden_paths)
    for raw_root in read_roots:
        try:
            root = raw_root.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ComparisonProcessError("runtime read root is missing") from exc
        if not root.is_dir():
            root = root.parent
        for target_material in forbidden_material:
            if _paths_overlap(root, target_material):
                raise ComparisonProcessError(
                    "runtime read roots expose known-site source or Git objects"
                )


def _forbidden_material_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    sources = _resolved_forbidden_paths(paths)
    material: set[Path] = set(sources)
    for source in sources:
        repository = source.parents[len(Path(KNOWN_SITE_SOURCE_PATH).parts) - 1]
        material.update(_resolved_git_material(repository / ".git"))
    return tuple(sorted(material))


def _resolved_git_material(git_metadata: Path) -> tuple[Path, ...]:
    if not git_metadata.exists() and not git_metadata.is_symlink():
        return ()
    try:
        resolved = git_metadata.resolve(strict=True)
    except OSError as exc:
        raise ValueError("known-site Git metadata cannot be resolved") from exc
    if resolved.is_dir():
        return (resolved,)
    try:
        marker = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("known-site Git worktree marker is unreadable") from exc
    prefix = "gitdir: "
    if not marker.startswith(prefix) or "\x00" in marker or len(marker) > _MAX_GIT_MARKER_BYTES:
        raise ValueError("known-site Git worktree marker is malformed")
    git_directory = Path(marker[len(prefix) :].strip())
    if not git_directory.is_absolute():
        git_directory = resolved.parent / git_directory
    try:
        return (resolved, git_directory.resolve(strict=True))
    except OSError as exc:
        raise ValueError("known-site Git worktree directory is missing") from exc


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


def _validate_evidence_root_separation(
    read_roots: Sequence[Path],
    *,
    private_campaign_root: Path,
) -> None:
    try:
        campaign = private_campaign_root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ComparisonProcessError("private campaign evidence root is missing") from exc
    if not campaign.is_dir():
        raise ComparisonProcessError("private campaign evidence root is invalid")
    for raw_root in read_roots:
        try:
            root = raw_root.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ComparisonProcessError("runtime read root is missing") from exc
        if not root.is_dir():
            root = root.parent
        if _paths_overlap(root, campaign):
            raise ComparisonProcessError(
                "runtime read roots expose current or sibling campaign evidence"
            )


def _safe_error(exc: BaseException, *, sensitive: Sequence[str]) -> str:
    value = str(exc).strip() or type(exc).__name__
    for secret in sensitive:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = _SITE_FLAG_RE.sub("[REDACTED]", value)
    return value[:1000]


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


__all__ = [
    "CanonicalAgentFactory",
    "CanonicalKnownSiteAgentBackend",
    "ComparisonProcessFactory",
]
