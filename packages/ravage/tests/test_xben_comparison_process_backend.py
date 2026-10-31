# ruff: noqa: SLF001

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
from ravage.xben_parts import comparison_adapters as adapter_module
from ravage.xben_parts import comparison_process_backend as backend_module
from ravage.xben_parts import external_comparison as external_module
from ravage.xben_parts.comparison_model_gateway import (
    ComparisonModelGateway,
    ModelGatewayPolicy,
    ModelPricing,
    RowSealError,
    validate_model_gateway_receipt,
)
from ravage.xben_parts.comparison_process_backend import (
    MODEL_GATEWAY_RECEIPT_FILE,
    PAIRED_LOCAL,
    PROCESS_RECEIPT_FILE,
    SANDBOX_PROFILE_FILE,
    STRICT_OFFICIAL,
    ComparisonProcessBackend,
    ComparisonProcessError,
    read_bounded_json_receipt,
    validate_comparison_process_receipt,
    validate_comparison_process_receipt_public,
)
from ravage.xben_parts.external_comparison import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    DESCRIPTION_ENV,
    OUTER_PROCESS_GROUP_ENV,
    OUTER_PROCESS_GROUP_VALUE,
    TARGET_URL_ENV,
    ComparisonRowBinding,
    ExternalAgentCommand,
    ExternalExecutionLimits,
    ExternalTarget,
    record_unstarted_external_xben_row,
    run_external_xben_row,
)
from ravage.xben_parts.models import XbenCase

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")


def test_command_preserves_only_the_active_interpreter_symlink(tmp_path: Path) -> None:
    validated = backend_module._validated_command((sys.executable, "-c", "pass"))

    assert validated[0] == sys.executable
    assert backend_module._command_executable_sha256(Path(validated[0])) == _sha256(
        Path(sys.executable).resolve()
    )
    runtime_paths = backend_module._command_runtime_paths(Path(validated[0]))
    if Path(sys.executable).is_symlink():
        assert Path(sys.executable).parent.parent in runtime_paths

    foreign = tmp_path / "foreign-python"
    foreign.symlink_to(Path(sys.executable).resolve())
    with pytest.raises(ComparisonProcessError, match="path is unsafe"):
        backend_module._validated_command((str(foreign), "-c", "pass"))


def _policy() -> ModelGatewayPolicy:
    return ModelGatewayPolicy.build(
        model="gpt-test-fixed",
        reasoning_effort="high",
        pricing=ModelPricing.from_numbers(
            input_per_million="1",
            cached_input_per_million="0.1",
            output_per_million="5",
        ),
        campaign_max_cost_usd="20",
        max_completion_tokens_per_request=128,
    )


def _limits() -> ExternalExecutionLimits:
    return ExternalExecutionLimits(
        wall_seconds=10,
        max_model_requests=2,
        max_target_requests=10,
        max_cost_usd="1",
    )


def test_process_receipt_limits_preserve_exact_decimal_text() -> None:
    amount = "1.0000000000000000000000000000000000001"
    limits = ExternalExecutionLimits(10, 2, 10, amount)

    assert backend_module._validated_limits_payload(limits.to_json()) == {
        "wall_seconds": 10,
        "max_model_requests": 2,
        "max_target_requests": 10,
        "max_cost_usd": amount,
    }


@pytest.mark.parametrize("amount", [1.0, 1, True, "1.0", "01", "1e0", "0", "NaN"])
def test_process_receipt_limits_reject_inexact_or_noncanonical_money(amount: object) -> None:
    payload = _limits().to_json()
    payload["max_cost_usd"] = amount

    with pytest.raises(ComparisonProcessError, match=r"(?:cost limit|limits)"):
        backend_module._validated_limits_payload(payload)


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _token_sha256(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _environment(token: str) -> dict[str, str]:
    return {
        TARGET_URL_ENV: "http://127.0.0.1:18080",
        backend_module.GATEWAY_BASE_URL_ENV: "http://127.0.0.1:18081/v1",
        COMPARISON_GATEWAY_TOKEN_ENV: token,
        DESCRIPTION_ENV: "Opaque black-box task.",
        OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
    }


def _backend(gateway: ComparisonModelGateway, token: str) -> ComparisonProcessBackend:
    return ComparisonProcessBackend(
        gateway=gateway,
        row_id="primary-001",
        expected_policy_sha256=gateway.policy_digest,
        expected_row_token_sha256=_token_sha256(token),
        sandbox_exec_sha256=_sha256(SANDBOX_EXEC),
        runtime_read_roots=(Path(sys.executable).resolve().parent,),
    )


def test_backend_seals_model_receipt_in_finally_when_sandbox_probe_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = _backend(gateway, token)
    row_dir = tmp_path / "row"
    output = row_dir / "native-output"
    output.mkdir(parents=True)
    monkeypatch.setattr(backend_module, "_probe_sandbox_profile", lambda *_args, **_kwargs: False)

    result = process_backend.run(
        (str(Path(sys.executable).resolve()), "-c", "raise SystemExit(0)"),
        cwd=output,
        environment=_environment(token),
        limits=_limits(),
    )

    assert result.returncode == -1
    assert (row_dir / MODEL_GATEWAY_RECEIPT_FILE).is_file()
    assert (row_dir / PROCESS_RECEIPT_FILE).is_file()
    process_receipt = read_bounded_json_receipt(row_dir / PROCESS_RECEIPT_FILE)
    assert isinstance(process_receipt, dict)
    assert process_receipt["valid"] is False
    assert process_receipt["sandbox"]["profile_probe_succeeded"] is False
    assert process_receipt["model_gateway"]["validator_passed"] is True
    with pytest.raises(RowSealError, match="already sealed"):
        gateway.seal_row("primary-001", tmp_path / "second-model-receipt.json")


def test_sandbox_probe_fails_if_profile_can_read_evaluator_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / SANDBOX_PROFILE_FILE
    profile.write_text("(version 1)\n(allow default)\n", encoding="utf-8")
    results = iter(
        (
            subprocess.CompletedProcess(args=(), returncode=0),
            subprocess.CompletedProcess(args=(), returncode=0),
        )
    )
    monkeypatch.setattr(
        backend_module,
        "_run_sandbox_probe",
        lambda *_args, **_kwargs: next(results),
    )

    assert (
        backend_module._probe_sandbox_profile(
            SANDBOX_EXEC,
            profile,
            timeout_seconds=1,
        )
        is False
    )


def test_backend_seals_terminal_evidence_when_sandbox_binary_pin_mismatches(
    tmp_path: Path,
) -> None:
    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = ComparisonProcessBackend(
        gateway=gateway,
        row_id="primary-001",
        expected_policy_sha256=gateway.policy_digest,
        expected_row_token_sha256=_token_sha256(token),
        sandbox_exec_sha256="sha256:" + "0" * 64,
        runtime_read_roots=(Path(sys.executable).resolve().parent,),
    )
    row_dir = tmp_path / "row"
    output = row_dir / "native-output"
    output.mkdir(parents=True)

    result = process_backend.run(
        (str(Path(sys.executable).resolve()), "-c", "raise SystemExit(0)"),
        cwd=output,
        environment=_environment(token),
        limits=_limits(),
    )

    assert result.returncode == -1
    assert (row_dir / MODEL_GATEWAY_RECEIPT_FILE).is_file()
    assert (row_dir / PROCESS_RECEIPT_FILE).is_file()
    assert (row_dir / SANDBOX_PROFILE_FILE).read_bytes() == b""
    process = read_bounded_json_receipt(row_dir / PROCESS_RECEIPT_FILE)
    assert isinstance(process, dict)
    assert process["valid"] is False
    assert "frozen digest" in str(process["execution"]["error"])


def test_backend_receipts_recompute_and_public_validator_rejects_profile_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = _backend(gateway, token)
    row_dir = tmp_path / "row"
    output = row_dir / "native-output"
    output.mkdir(parents=True)
    real_popen = subprocess.Popen

    def launch_without_nested_sandbox(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        assert command[:3] == (
            str(SANDBOX_EXEC),
            "-f",
            str(row_dir / SANDBOX_PROFILE_FILE),
        )
        return real_popen(command[3:], **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(backend_module, "_probe_sandbox_profile", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(backend_module.subprocess, "Popen", launch_without_nested_sandbox)
    command = (
        sys.executable,
        "-c",
        "import ravage, sys; print('bounded-out'); print('bounded-err', file=sys.stderr)",
    )
    environment = _environment(token)

    result = process_backend.run(
        command,
        cwd=output,
        environment=environment,
        limits=_limits(),
    )

    assert result.returncode == 0
    assert result.timed_out is False
    model_path = row_dir / MODEL_GATEWAY_RECEIPT_FILE
    process_path = row_dir / PROCESS_RECEIPT_FILE
    profile_path = row_dir / SANDBOX_PROFILE_FILE
    model = read_bounded_json_receipt(model_path)
    process = read_bounded_json_receipt(process_path)
    profile = profile_path.read_bytes()
    assert isinstance(model, dict)
    assert isinstance(process, dict)
    assert b"(allow process*)" not in profile
    assert b"(allow signal)" not in profile
    assert b"(allow sysctl-read)" not in profile
    assert b"(allow process-info* (target self))" in profile
    assert b"(allow signal (target children))" in profile
    validated_model = validate_model_gateway_receipt(
        model,
        expected_row_id="primary-001",
        expected_policy_sha256=gateway.policy_digest,
        expected_max_requests=2,
        expected_max_cost_usd="1",
    )
    validated = validate_comparison_process_receipt(
        process,
        expected_row_id="primary-001",
        expected_command=command,
        expected_environment=environment,
        expected_limits=_limits(),
        expected_policy_sha256=gateway.policy_digest,
        expected_sandbox_exec_sha256=_sha256(SANDBOX_EXEC),
        expected_runtime_read_roots=process_backend.runtime_read_roots,
        expected_output_directory=output,
        expected_docker_socket_path=None,
        model_receipt_file_sha256=_sha256(model_path),
        model_receipt_document_sha256=str(validated_model["document_sha256"]),
        sandbox_profile=profile,
        require_official_safety=True,
    )
    assert validated["valid"] is True
    assert validated["official_attestation_eligible"] is True
    public_contract = {
        "row_id": "primary-001",
        "command": process["command"],
        "environment": process["environment"],
        "limits": _limits().to_json(),
        "model_gateway_policy_sha256": gateway.policy_digest,
        "model_gateway_row_token_sha256": _token_sha256(token),
        "sandbox_executable_sha256": _sha256(SANDBOX_EXEC),
        "sandbox": process["sandbox"],
    }
    assert (
        validate_comparison_process_receipt_public(
            process,
            expected_row_id="primary-001",
            public_contract=public_contract,
            model_receipt_file_sha256=_sha256(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=profile,
            expected_output_directory=output,
            require_official_safety=True,
        )
        == process
    )
    wrong_token_contract = json.loads(json.dumps(public_contract))
    wrong_token_contract["model_gateway_row_token_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ComparisonProcessError, match="row-token binding"):
        validate_comparison_process_receipt_public(
            process,
            expected_row_id="primary-001",
            public_contract=wrong_token_contract,
            model_receipt_file_sha256=_sha256(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=profile,
            expected_output_directory=output,
            require_official_safety=True,
        )

    relocated_output = tmp_path / "other-row" / "native-output"
    relocated_output.mkdir(parents=True)
    relocated_profile = profile.replace(
        str(output).encode("utf-8"),
        str(relocated_output).encode("utf-8"),
    )
    relocated = json.loads(json.dumps(process))
    relocated_contract = json.loads(json.dumps(public_contract))
    relocated_digest = backend_module._sha256_bytes(relocated_profile)
    relocated["sandbox"]["profile_sha256"] = relocated_digest
    relocated_contract["sandbox"]["profile_sha256"] = relocated_digest
    relocated_body = {key: value for key, value in relocated.items() if key != "document_sha256"}
    relocated["document_sha256"] = backend_module._sha256_bytes(
        backend_module._canonical_json(relocated_body)
    )
    with pytest.raises(ComparisonProcessError, match="writable root is invalid"):
        validate_comparison_process_receipt_public(
            relocated,
            expected_row_id="primary-001",
            public_contract=relocated_contract,
            model_receipt_file_sha256=_sha256(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=relocated_profile,
            expected_output_directory=output,
            require_official_safety=True,
        )

    forged_roots = json.loads(json.dumps(process))
    forged_roots_contract = json.loads(json.dumps(public_contract))
    roots = forged_roots["sandbox"]["runtime_read_roots"]
    roots.append("/zzzz-unexpected-runtime-root")
    forged_roots["sandbox"]["runtime_read_root_count"] = len(roots)
    forged_roots["sandbox"]["runtime_read_roots_sha256"] = backend_module._sha256_bytes(
        backend_module._canonical_json(roots)
    )
    forged_roots_contract["sandbox"] = json.loads(json.dumps(forged_roots["sandbox"]))
    forged_roots_body = {
        key: value for key, value in forged_roots.items() if key != "document_sha256"
    }
    forged_roots["document_sha256"] = backend_module._sha256_bytes(
        backend_module._canonical_json(forged_roots_body)
    )
    with pytest.raises(ComparisonProcessError, match="readable roots differ"):
        validate_comparison_process_receipt_public(
            forged_roots,
            expected_row_id="primary-001",
            public_contract=forged_roots_contract,
            model_receipt_file_sha256=_sha256(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=profile,
            expected_output_directory=output,
            require_official_safety=True,
        )

    expanded_profile = profile + b"(allow network-outbound)\n"
    forged = json.loads(json.dumps(process))
    forged_contract = json.loads(json.dumps(public_contract))
    expanded_digest = "sha256:" + hashlib.sha256(expanded_profile).hexdigest()
    forged["sandbox"]["profile_sha256"] = expanded_digest
    forged_contract["sandbox"]["profile_sha256"] = expanded_digest
    forged_body = {key: value for key, value in forged.items() if key != "document_sha256"}
    forged["document_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                forged_body,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )
    with pytest.raises(ComparisonProcessError, match="broader than declared"):
        validate_comparison_process_receipt_public(
            forged,
            expected_row_id="primary-001",
            public_contract=forged_contract,
            model_receipt_file_sha256=_sha256(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=expanded_profile,
            expected_output_directory=output,
            require_official_safety=True,
        )


@pytest.mark.parametrize("terminal_outcome", ("nonzero", "timed_out"))
def test_started_terminal_loss_has_independently_valid_process_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_outcome: str,
) -> None:
    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = _backend(gateway, token)
    row_dir = tmp_path / terminal_outcome
    output = row_dir / "native-output"
    output.mkdir(parents=True)
    real_popen = subprocess.Popen

    def launch_without_nested_sandbox(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        return real_popen(command[3:], **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(backend_module, "_probe_sandbox_profile", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(backend_module.subprocess, "Popen", launch_without_nested_sandbox)
    if terminal_outcome == "timed_out":

        def terminal_timeout(
            process: subprocess.Popen[bytes],
            **_kwargs: object,
        ) -> tuple[backend_module._Capture, backend_module._Capture, bool]:
            process.terminate()
            process.wait(timeout=1)
            assert process.stdout is not None
            assert process.stderr is not None
            process.stdout.close()
            process.stderr.close()
            empty = backend_module._Capture(
                retained=b"",
                total_bytes=0,
                sha256=backend_module._sha256_bytes(b""),
                complete=True,
            )
            return empty, empty, True

        monkeypatch.setattr(backend_module, "_wait_bounded_process", terminal_timeout)
        command = (sys.executable, "-c", "import time; time.sleep(30)")
    else:
        command = (sys.executable, "-c", "raise SystemExit(7)")
    environment = _environment(token)

    result = process_backend.run(
        command,
        cwd=output,
        environment=environment,
        limits=_limits(),
    )

    model_path = row_dir / MODEL_GATEWAY_RECEIPT_FILE
    process_path = row_dir / PROCESS_RECEIPT_FILE
    profile_path = row_dir / SANDBOX_PROFILE_FILE
    model = read_bounded_json_receipt(model_path)
    process = read_bounded_json_receipt(process_path)
    assert isinstance(model, dict)
    assert isinstance(process, dict)
    assert result.returncode != 0
    assert result.timed_out is (terminal_outcome == "timed_out")
    assert process["valid"] is True
    assert process["official_attestation_eligible"] is True
    validated_model = validate_model_gateway_receipt(
        model,
        expected_row_id="primary-001",
        expected_policy_sha256=gateway.policy_digest,
        expected_max_requests=2,
        expected_max_cost_usd="1",
    )
    validated = validate_comparison_process_receipt(
        process,
        expected_row_id="primary-001",
        expected_command=command,
        expected_environment=environment,
        expected_limits=_limits(),
        expected_policy_sha256=gateway.policy_digest,
        expected_sandbox_exec_sha256=_sha256(SANDBOX_EXEC),
        expected_runtime_read_roots=process_backend.runtime_read_roots,
        expected_output_directory=output,
        expected_docker_socket_path=None,
        model_receipt_file_sha256=_sha256(model_path),
        model_receipt_document_sha256=str(validated_model["document_sha256"]),
        sandbox_profile=profile_path.read_bytes(),
        require_official_safety=True,
    )
    public_contract = {
        "row_id": "primary-001",
        "command": process["command"],
        "environment": process["environment"],
        "limits": _limits().to_json(),
        "model_gateway_policy_sha256": gateway.policy_digest,
        "model_gateway_row_token_sha256": _token_sha256(token),
        "sandbox_executable_sha256": _sha256(SANDBOX_EXEC),
        "sandbox": process["sandbox"],
    }
    assert validated["valid"] is True
    assert (
        validate_comparison_process_receipt_public(
            process,
            expected_row_id="primary-001",
            public_contract=public_contract,
            model_receipt_file_sha256=_sha256(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=profile_path.read_bytes(),
            expected_output_directory=output,
            require_official_safety=True,
        )
        == process
    )


def test_timed_out_process_receipt_cannot_claim_zero_returncode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forged timeout/success hybrid is evidence corruption, not a loss."""

    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = _backend(gateway, token)
    row_dir = tmp_path / "forged-timeout"
    output = row_dir / "native-output"
    output.mkdir(parents=True)
    real_popen = subprocess.Popen

    def launch_without_nested_sandbox(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        return real_popen(command[3:], **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(backend_module, "_probe_sandbox_profile", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(backend_module.subprocess, "Popen", launch_without_nested_sandbox)
    command = (sys.executable, "-c", "raise SystemExit(7)")
    environment = _environment(token)
    process_backend.run(command, cwd=output, environment=environment, limits=_limits())
    model_path = row_dir / MODEL_GATEWAY_RECEIPT_FILE
    process_path = row_dir / PROCESS_RECEIPT_FILE
    process = read_bounded_json_receipt(process_path)
    model = read_bounded_json_receipt(model_path)
    assert isinstance(process, dict)
    assert isinstance(model, dict)
    process["execution"].update({"timed_out": True, "returncode": 0})
    body = {key: value for key, value in process.items() if key != "document_sha256"}
    process["document_sha256"] = backend_module._sha256_bytes(backend_module._canonical_json(body))
    validated_model = validate_model_gateway_receipt(
        model,
        expected_row_id="primary-001",
        expected_policy_sha256=gateway.policy_digest,
        expected_max_requests=2,
        expected_max_cost_usd="1",
    )

    with pytest.raises(ComparisonProcessError, match="successful exit"):
        validate_comparison_process_receipt(
            process,
            expected_row_id="primary-001",
            expected_command=command,
            expected_environment=environment,
            expected_limits=_limits(),
            expected_policy_sha256=gateway.policy_digest,
            expected_sandbox_exec_sha256=_sha256(SANDBOX_EXEC),
            expected_runtime_read_roots=process_backend.runtime_read_roots,
            expected_output_directory=output,
            expected_docker_socket_path=None,
            model_receipt_file_sha256=_sha256(model_path),
            model_receipt_document_sha256=str(validated_model["document_sha256"]),
            sandbox_profile=(row_dir / SANDBOX_PROFILE_FILE).read_bytes(),
            require_official_safety=True,
        )


def test_paired_local_contract_is_never_official_eligible(tmp_path: Path) -> None:
    socket_path = tmp_path / "docker.sock"
    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = ComparisonProcessBackend(
        gateway=gateway,
        row_id="primary-001",
        expected_policy_sha256=gateway.policy_digest,
        expected_row_token_sha256=_token_sha256(token),
        sandbox_exec_sha256=_sha256(SANDBOX_EXEC),
        runtime_read_roots=(Path(sys.executable).resolve().parent,),
        evidence_class=PAIRED_LOCAL,
        allow_docker_socket=True,
        docker_socket_path=socket_path,
    )
    assert process_backend.isolation.comparison_safe is False
    assert process_backend.receipt_contract.evidence_class == PAIRED_LOCAL
    assert process_backend.receipt_contract.docker_socket_path == socket_path
    assert process_backend.evidence_class != STRICT_OFFICIAL


def test_paired_local_nonloopback_target_is_port_scoped_and_never_official(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = tmp_path / "docker.sock"
    socket_path.touch()
    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = ComparisonProcessBackend(
        gateway=gateway,
        row_id="primary-001",
        expected_policy_sha256=gateway.policy_digest,
        expected_row_token_sha256=_token_sha256(token),
        sandbox_exec_sha256=_sha256(SANDBOX_EXEC),
        runtime_read_roots=(Path(sys.executable).resolve().parent,),
        evidence_class=PAIRED_LOCAL,
        allow_docker_socket=True,
        docker_socket_path=socket_path,
    )
    real_popen = subprocess.Popen

    def launch_without_nested_sandbox(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        return real_popen(command[3:], **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(
        backend_module,
        "_probe_sandbox_profile",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        backend_module,
        "_resolved_docker_socket",
        lambda _path, *, required: socket_path.resolve() if required else None,
    )
    monkeypatch.setattr(
        backend_module.subprocess,
        "Popen",
        launch_without_nested_sandbox,
    )
    row_dir = tmp_path / "paired-local-row"
    output = row_dir / "native-output"
    output.mkdir(parents=True)
    environment = _environment(token)
    environment[TARGET_URL_ENV] = "http://ravage-target:18080"

    result = process_backend.run(
        (str(Path(sys.executable).resolve()), "-c", "raise SystemExit(0)"),
        cwd=output,
        environment=environment,
        limits=_limits(),
    )

    assert result.returncode == 0
    process = read_bounded_json_receipt(row_dir / PROCESS_RECEIPT_FILE)
    assert isinstance(process, dict)
    assert process["valid"] is True
    assert process["official_attestation_eligible"] is False
    sandbox = process["sandbox"]
    assert sandbox["network_scope_verified"] is False
    assert sandbox["outbound_tcp"] == [
        {"host_scope": "any", "port": 18080},
        {"host_scope": "loopback", "port": 18081},
    ]
    assert '(remote tcp "*:18080")' in (row_dir / SANDBOX_PROFILE_FILE).read_text(encoding="utf-8")


def test_outer_timeout_kills_the_entire_process_group() -> None:
    process = subprocess.Popen(  # noqa: S603
        (
            str(Path(sys.executable).resolve()),
            "-c",
            (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "time.sleep(30)"
            ),
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )

    _stdout, _stderr, timed_out = backend_module._wait_bounded_process(
        process,
        timeout_seconds=0.1,
        maximum_capture_bytes=1024,
        termination_grace_seconds=0.5,
    )

    assert timed_out is True
    assert process.returncode is not None
    assert backend_module._process_group_absent(process.pid)


def test_public_sandbox_paths_reject_lexical_parent_traversal() -> None:
    with pytest.raises(ComparisonProcessError, match="runtime root is unsafe"):
        backend_module._validated_public_read_roots(["/tmp/campaign/notrows/../rows"])
    with pytest.raises(ComparisonProcessError, match="path rule is not canonical"):
        backend_module._profile_path(
            '(allow file-write* (subpath "/tmp/campaign/notrows/../rows/native-output"))',
            prefix="(allow file-write* (subpath ",
        )


def test_external_row_independently_validates_concrete_backend_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Target:
        def start(
            self,
            *,
            case: XbenCase,
            expected_flag: str,
            instance_id: str,
        ) -> ExternalTarget:
            del case, expected_flag
            return ExternalTarget(
                instance_id=instance_id,
                target_url="http://127.0.0.1:18080",
                build_provenance={"fresh": True},
            )

        def stop(self, *, target: ExternalTarget) -> Mapping[str, object]:
            del target
            return {"removed": True}

    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = _backend(gateway, token)
    real_popen = subprocess.Popen

    def launch_without_nested_sandbox(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        return real_popen(command[3:], **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(backend_module, "_probe_sandbox_profile", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(backend_module.subprocess, "Popen", launch_without_nested_sandbox)
    case_path = tmp_path / "benchmarks" / "XBEN-001-24"
    case_path.mkdir(parents=True)
    case = XbenCase(
        benchmark_id="XBEN-001-24",
        path=case_path,
        name="withheld",
        level=1,
        description="XBEN-001-24 Opaque black-box task.",
        main_service="web",
        main_service_port=8080,
    )
    agent = ExternalAgentCommand(
        name="Pinned agent",
        system_id="agent",
        command=(str(Path(sys.executable).resolve()), "-c", "raise SystemExit(0)"),
        artifact_path="agent-report.md",
        limits=_limits(),
        reasoning_effort="high",
        provider="paired-row-gateway",
        model="gpt-test-fixed",
        adapter_version="test-v1",
        environment={
            COMPARISON_GATEWAY_TOKEN_ENV: token,
            backend_module.GATEWAY_BASE_URL_ENV: "http://127.0.0.1:18081/v1",
            OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
        },
        environment_allowlist=(
            COMPARISON_GATEWAY_TOKEN_ENV,
            backend_module.GATEWAY_BASE_URL_ENV,
            OUTER_PROCESS_GROUP_ENV,
        ),
    )
    flag = "flag{ravage_cmp_" + "a" * 64 + "}"
    row_dir = tmp_path / "official-row"

    with pytest.raises(
        adapter_module.AdapterConfigurationError,
        match="canonical adapter command",
    ):
        run_external_xben_row(
            case=case,
            agent=agent,
            binding=ComparisonRowBinding(
                campaign_id="campaign-001",
                commitment_digest="sha256:" + "b" * 64,
                selection_digest="sha256:" + "c" * 64,
                primary_slot_id="primary-001",
            ),
            row_dir=tmp_path / "noncanonical-row",
            process_backend=process_backend,
            target_backend=Target(),
            expected_flag=flag,
        )
    assert not (tmp_path / "noncanonical-row").exists()

    # This test's remaining scope is the process/model receipt handoff. The
    # real canonical-adapter verifier has dedicated identity tests; replacing
    # it here avoids constructing and executing a full pinned agent runtime.
    monkeypatch.setattr(adapter_module, "validate_pinned_adapter_agent", lambda _agent: None)

    result = run_external_xben_row(
        case=case,
        agent=agent,
        binding=ComparisonRowBinding(
            campaign_id="campaign-001",
            commitment_digest="sha256:" + "b" * 64,
            selection_digest="sha256:" + "c" * 64,
            primary_slot_id="primary-001",
        ),
        row_dir=row_dir,
        process_backend=process_backend,
        target_backend=Target(),
        expected_flag=flag,
    )

    assert result["valid_for_comparison"] is False
    assert result["official_attestation_eligible"] is False
    assert result["status"] == "infrastructure_error"
    receipts = result["execution"]["receipts"]
    assert receipts["valid"] is True
    assert receipts["evidence_class"] == STRICT_OFFICIAL
    serialized = (row_dir / "row-result.json").read_text(encoding="utf-8")
    assert flag not in serialized
    assert '"expected_flag"' not in serialized
    manifest = (row_dir / "artifacts.sha256").read_text(encoding="utf-8")
    assert PROCESS_RECEIPT_FILE in manifest
    assert MODEL_GATEWAY_RECEIPT_FILE in manifest
    assert SANDBOX_PROFILE_FILE in manifest


def test_external_target_start_failure_terminally_seals_gateway_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenTarget:
        def start(
            self,
            *,
            case: XbenCase,
            expected_flag: str,
            instance_id: str,
        ) -> ExternalTarget:
            del case, expected_flag, instance_id
            raise RuntimeError("target preparation failed")

        def stop(self, *, target: ExternalTarget) -> Mapping[str, object]:
            raise AssertionError(f"unexpected stop: {target.instance_id}")

    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = _backend(gateway, token)
    monkeypatch.setattr(adapter_module, "validate_pinned_adapter_agent", lambda _agent: None)
    case_path = tmp_path / "benchmarks" / "XBEN-001-24"
    case_path.mkdir(parents=True)
    row_dir = tmp_path / "infra-failure"
    result = run_external_xben_row(
        case=XbenCase(
            benchmark_id="XBEN-001-24",
            path=case_path,
            name="withheld",
            level=1,
            description="XBEN-001-24 Opaque black-box task.",
            main_service="web",
            main_service_port=8080,
        ),
        agent=ExternalAgentCommand(
            name="Pinned agent",
            system_id="agent",
            command=(str(Path(sys.executable).resolve()), "-c", "raise SystemExit(0)"),
            artifact_path="agent-report.md",
            limits=_limits(),
            reasoning_effort="high",
            environment={
                COMPARISON_GATEWAY_TOKEN_ENV: token,
                backend_module.GATEWAY_BASE_URL_ENV: "http://127.0.0.1:18081/v1",
                OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
            },
            environment_allowlist=(
                COMPARISON_GATEWAY_TOKEN_ENV,
                backend_module.GATEWAY_BASE_URL_ENV,
                OUTER_PROCESS_GROUP_ENV,
            ),
        ),
        binding=ComparisonRowBinding(
            campaign_id="campaign-001",
            commitment_digest="sha256:" + "b" * 64,
            selection_digest="sha256:" + "c" * 64,
            primary_slot_id="primary-001",
        ),
        row_dir=row_dir,
        process_backend=process_backend,
        target_backend=BrokenTarget(),
        expected_flag="flag{ravage_cmp_" + "a" * 64 + "}",
    )

    assert result["status"] == "infrastructure_error"
    assert result["valid_for_comparison"] is False
    assert (row_dir / MODEL_GATEWAY_RECEIPT_FILE).is_file()
    assert (row_dir / PROCESS_RECEIPT_FILE).is_file()
    process = read_bounded_json_receipt(row_dir / PROCESS_RECEIPT_FILE)
    assert isinstance(process, dict)
    assert process["execution"]["spawn_succeeded"] is False
    assert process["model_gateway"]["validator_passed"] is True
    receipts = result["execution"]["receipts"]
    assert receipts["valid"] is False
    assert receipts["process_receipt_document_sha256"].startswith("sha256:")
    assert receipts["process_receipt_file_sha256"].startswith("sha256:")
    assert receipts["model_gateway_receipt_document_sha256"].startswith("sha256:")
    assert receipts["model_gateway_receipt_file_sha256"].startswith("sha256:")
    assert receipts["sandbox_profile_sha256"].startswith("sha256:")
    with pytest.raises(RowSealError, match="already sealed"):
        gateway.seal_row("primary-001", tmp_path / "duplicate.json")


def test_public_unstarted_row_helper_terminalizes_preparation_failure(
    tmp_path: Path,
) -> None:
    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = _backend(gateway, token)
    case_path = tmp_path / "benchmarks" / "XBEN-001-24"
    case_path.mkdir(parents=True)
    row_dir = tmp_path / "preparation-failure"

    result = record_unstarted_external_xben_row(
        case=XbenCase(
            benchmark_id="XBEN-001-24",
            path=case_path,
            name="withheld",
            level=1,
            description="XBEN-001-24 Opaque black-box task.",
            main_service="web",
            main_service_port=8080,
        ),
        agent=ExternalAgentCommand(
            name="Pinned agent",
            system_id="agent",
            command=(str(Path(sys.executable).resolve()), "-c", "raise SystemExit(0)"),
            artifact_path="agent-report.md",
            limits=_limits(),
            reasoning_effort="high",
            environment={
                COMPARISON_GATEWAY_TOKEN_ENV: token,
                backend_module.GATEWAY_BASE_URL_ENV: "http://127.0.0.1:18081/v1",
                OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
            },
            environment_allowlist=(
                COMPARISON_GATEWAY_TOKEN_ENV,
                backend_module.GATEWAY_BASE_URL_ENV,
                OUTER_PROCESS_GROUP_ENV,
            ),
        ),
        binding=ComparisonRowBinding(
            campaign_id="campaign-001",
            commitment_digest="sha256:" + "b" * 64,
            selection_digest="sha256:" + "c" * 64,
            primary_slot_id="primary-001",
        ),
        row_dir=row_dir,
        process_backend=process_backend,
        expected_flag="flag{ravage_cmp_" + "a" * 64 + "}",
        reason="pair preparation failed before either arm started",
    )

    assert result["status"] == "infrastructure_error"
    receipts = result["execution"]["receipts"]
    assert receipts["valid"] is False
    assert receipts["process_receipt_document_sha256"].startswith("sha256:")
    model = validate_model_gateway_receipt(
        read_bounded_json_receipt(row_dir / MODEL_GATEWAY_RECEIPT_FILE),
        expected_row_id="primary-001",
        expected_policy_sha256=gateway.policy_digest,
        expected_max_requests=2,
        expected_max_cost_usd="1",
    )
    assert model["valid"] is True
    assert model["totals"]["requests_started"] == 0
    with pytest.raises(RowSealError, match="already sealed"):
        gateway.seal_row("primary-001", tmp_path / "duplicate-helper.json")


def test_unstarted_row_redacts_receipt_validation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = ComparisonModelGateway(policy=_policy(), upstream_api_key="not-used")
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="1")
    process_backend = _backend(gateway, token)
    case_path = tmp_path / "benchmarks" / "XBEN-001-24"
    case_path.mkdir(parents=True)
    row_dir = tmp_path / "redacted-preparation-failure"
    monkeypatch.setattr(
        external_module,
        "_validate_execution_receipts",
        lambda **_kwargs: {"valid": False, "error": f"malformed receipt contained {token}"},
    )

    result = record_unstarted_external_xben_row(
        case=XbenCase(
            benchmark_id="XBEN-001-24",
            path=case_path,
            name="withheld",
            level=1,
            description="XBEN-001-24 Opaque black-box task.",
            main_service="web",
            main_service_port=8080,
        ),
        agent=ExternalAgentCommand(
            name="Pinned agent",
            system_id="agent",
            command=(str(Path(sys.executable).resolve()), "-c", "raise SystemExit(0)"),
            artifact_path="agent-report.md",
            limits=_limits(),
            reasoning_effort="high",
            environment={
                COMPARISON_GATEWAY_TOKEN_ENV: token,
                backend_module.GATEWAY_BASE_URL_ENV: "http://127.0.0.1:18081/v1",
                OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
            },
            environment_allowlist=(
                COMPARISON_GATEWAY_TOKEN_ENV,
                backend_module.GATEWAY_BASE_URL_ENV,
                OUTER_PROCESS_GROUP_ENV,
            ),
        ),
        binding=ComparisonRowBinding(
            campaign_id="campaign-001",
            commitment_digest="sha256:" + "b" * 64,
            selection_digest="sha256:" + "c" * 64,
            primary_slot_id="primary-001",
        ),
        row_dir=row_dir,
        process_backend=process_backend,
        expected_flag="flag{ravage_cmp_" + "a" * 64 + "}",
        reason=f"pair preparation failed with credential {token}",
    )

    receipts = result["execution"]["receipts"]
    assert receipts["error"] == "malformed receipt contained [REDACTED]"
    for path in row_dir.rglob("*"):
        if path.is_file():
            assert token.encode() not in path.read_bytes()
