from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import pytest
from ravage.xben_parts import comparison_contracts as contracts
from ravage.xben_parts import external_comparison as external_module
from ravage.xben_parts.comparison_contracts import ComparisonContractError
from ravage.xben_parts.external_comparison import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    DESCRIPTION_ENV,
    FLAG_COMMITMENT_FILE,
    FLAG_COMMITMENT_SCHEMA_VERSION,
    TARGET_URL_ENV,
    AgentEnvironmentError,
    ComparisonBindingError,
    ComparisonRowBinding,
    ExternalAgentCommand,
    ExternalComparisonError,
    ExternalExecutionLimits,
    ExternalProcessReceiptContract,
    ExternalProcessResult,
    ExternalTarget,
    ProcessIsolation,
    RowAlreadyExistsError,
    SubprocessBackend,
    UnsafeProcessBackendError,
    run_external_xben_row,
)
from ravage.xben_parts.models import XbenCase

SAFE_ISOLATION = ProcessIsolation(
    kind="test-container",
    filesystem_isolated=True,
    target_network_only=True,
    wall_timeout_enforced=True,
    model_request_limit_enforced=True,
    target_request_limit_enforced=True,
    cost_limit_enforced=True,
)


def test_external_comparison_reexports_the_shared_row_contracts() -> None:
    assert ExternalExecutionLimits is contracts.ExternalExecutionLimits
    assert ExternalAgentCommand is contracts.ExternalAgentCommand
    assert ExternalTarget is contracts.ExternalTarget


class FakeTargetBackend:
    def __init__(
        self,
        *,
        build_error: bool = False,
        teardown_error: bool = False,
    ) -> None:
        self.starts: list[tuple[str, str, str]] = []
        self.stops: list[str] = []
        self.build_error = build_error
        self.teardown_error = teardown_error

    @property
    def latest_flag(self) -> str:
        return self.starts[-1][1]

    def start(
        self,
        *,
        case: XbenCase,
        expected_flag: str,
        instance_id: str,
    ) -> ExternalTarget:
        self.starts.append((case.benchmark_id, expected_flag, instance_id))
        if self.build_error:
            raise RuntimeError("target build failed")
        return ExternalTarget(
            instance_id=instance_id,
            target_url="http://target.internal:8080",
            build_provenance={"image_digest": "sha256:target", "fresh": True},
            backend_handle={"project": instance_id},
        )

    def stop(self, *, target: ExternalTarget) -> Mapping[str, object]:
        self.stops.append(target.instance_id)
        if self.teardown_error:
            raise RuntimeError("target teardown failed")
        return {"removed": True, "project": target.instance_id}


class FakeProcessBackend:
    isolation = SAFE_ISOLATION

    def __init__(
        self,
        target_backend: FakeTargetBackend,
        *,
        artifact_text: str | None = "expected",
        stdout_text: str = "adapter stdout",
        returncode: int = 0,
        timeout: bool = False,
        timed_out_result: bool = False,
    ) -> None:
        self.target_backend = target_backend
        self.artifact_text = artifact_text
        self.stdout_text = stdout_text
        self.returncode = returncode
        self.timeout = timeout
        self.timed_out_result = timed_out_result
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: ExternalExecutionLimits,
    ) -> ExternalProcessResult:
        row_dir = cwd.parent
        # Evaluator evidence, including the expected flag, is not materialized
        # until this invocation has become terminal.
        assert not any(
            (row_dir / name).exists() for name in _evidence_names() if name != FLAG_COMMITMENT_FILE
        )
        expected_flag = self.target_backend.latest_flag
        flag_commitment = json.loads((row_dir / FLAG_COMMITMENT_FILE).read_text(encoding="utf-8"))
        assert flag_commitment["schema_version"] == FLAG_COMMITMENT_SCHEMA_VERSION
        assert expected_flag not in json.dumps(flag_commitment)
        assert (
            flag_commitment["expected_flag_sha256"]
            == hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
        )
        assert expected_flag not in environment.values()
        self.calls.append(
            {
                "command": tuple(command),
                "cwd": cwd,
                "environment": dict(environment),
                "limits": limits,
            }
        )
        if self.artifact_text is not None:
            content = self.artifact_text.replace("expected", expected_flag)
            (cwd / "agent-report.md").write_text(content, encoding="utf-8")
        stdout = self.stdout_text.replace("expected", expected_flag)
        if self.timeout:
            raise subprocess.TimeoutExpired(command, limits.wall_seconds, output=stdout)
        return ExternalProcessResult(
            returncode=self.returncode,
            stdout=stdout,
            stderr="adapter stderr",
            timed_out=self.timed_out_result,
        )


def test_external_row_exact_scores_only_declared_artifact_and_retains_evidence(
    tmp_path: Path,
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target, stdout_text="token=test-row-token")
    row_dir = tmp_path / "row-001"
    agent = _agent(
        environment={COMPARISON_GATEWAY_TOKEN_ENV: "test-row-token"},
        environment_allowlist=(COMPARISON_GATEWAY_TOKEN_ENV,),
    )

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=agent,
        binding=_binding(),
        row_dir=row_dir,
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
    )

    assert result["status"] == "failed"
    assert result["valid_for_comparison"] is False
    assert result["limits"] == {
        "wall_seconds": 600,
        "max_model_requests": 40,
        "max_target_requests": 300,
        "max_cost_usd": "20",
    }
    isolation = result["isolation"]
    assert isinstance(isolation, dict)
    assert isolation["comparison_safe"] is True
    budget_enforcement = isolation["budget_enforcement"]
    assert isinstance(budget_enforcement, dict)
    assert budget_enforcement["all_required"] is True
    assert result["schedule_binding"] == _binding().to_json()
    result_agent = result["agent"]
    assert isinstance(result_agent, dict)
    assert result_agent["system_id"] == "agent"
    assert result_agent["reasoning_effort"] == "high"
    score = result["score"]
    assert isinstance(score, dict)
    assert score["solved"] is False
    assert score["exact_match"] is True
    assert (
        score["expected_flag_sha256"]
        == hashlib.sha256(target.latest_flag.encode("utf-8")).hexdigest()
    )
    artifact = score["artifact"]
    assert isinstance(artifact, dict)
    content = (row_dir / "native-output" / "agent-report.md").read_bytes()
    assert artifact["sha256"] == hashlib.sha256(content).hexdigest()
    assert artifact["size_bytes"] == len(content)

    call = process.calls[0]
    environment = call["environment"]
    assert isinstance(environment, dict)
    assert environment == {
        COMPARISON_GATEWAY_TOKEN_ENV: "test-row-token",
        TARGET_URL_ENV: "http://target.internal:8080",
        DESCRIPTION_ENV: "Find the proof through the application.",
    }
    assert str(_case(tmp_path).path) not in json.dumps(environment)
    assert target.starts[0][1] not in json.dumps(environment)
    for evaluator_only_value in _binding().to_json().values():
        assert evaluator_only_value not in json.dumps(environment)
    assert target.stops == [target.starts[0][2]]

    for name in _evidence_names():
        assert (row_dir / name).is_file()
    build = json.loads((row_dir / "target-build.json").read_text(encoding="utf-8"))
    teardown = json.loads((row_dir / "target-teardown.json").read_text(encoding="utf-8"))
    assert build["provenance"]["fresh"] is True
    assert teardown["provenance"]["removed"] is True
    stdout = (row_dir / "stdout.log").read_text(encoding="utf-8")
    assert "test-row-token" not in stdout
    assert "[REDACTED]" in stdout
    execution = result["execution"]
    assert isinstance(execution, dict)
    assert execution["stdout_capture"]["redacted"] is True
    manifest = (row_dir / "artifacts.sha256").read_text(encoding="utf-8")
    assert "native-output/agent-report.md" in manifest
    assert "row-result.json" in manifest


def test_external_row_purges_native_tree_that_persists_gateway_credential(
    tmp_path: Path,
) -> None:
    token = "row-secret-token-" + "x" * 64
    target = FakeTargetBackend()
    process = FakeProcessBackend(target, artifact_text=f"copied credential: {token}")
    row_dir = tmp_path / "credential-contamination"

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(
            environment={COMPARISON_GATEWAY_TOKEN_ENV: token},
            environment_allowlist=(COMPARISON_GATEWAY_TOKEN_ENV,),
        ),
        binding=_binding(),
        row_dir=row_dir,
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
    )

    assert result["status"] == "errored"
    assert result["valid_for_comparison"] is False
    execution = result["execution"]
    assert isinstance(execution, dict)
    receipts = execution["receipts"]
    assert isinstance(receipts, dict)
    assert receipts["valid"] is False
    assert list((row_dir / "native-output").iterdir()) == []
    for path in row_dir.rglob("*"):
        assert token not in path.as_posix()
        if path.is_file():
            assert token.encode() not in path.read_bytes()


def test_external_log_redaction_covers_common_reversible_token_encodings() -> None:
    token = "row-secret-token-" + "x" * 64
    encoded = base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")

    retained, record = external_module._sanitized_bounded_log(
        f"credential={encoded}",
        sensitive_values=(token,),
        maximum_bytes=1024,
    )

    assert token not in retained
    assert encoded not in retained
    assert "[REDACTED]" in retained
    assert record["redacted"] is True


def test_external_row_never_scores_stdout_or_stderr(tmp_path: Path) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(
        target,
        artifact_text="no proof in declared artifact",
        stdout_text="expected",
    )

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(),
        binding=_binding(),
        row_dir=tmp_path / "row-stdout-only",
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
    )

    score = result["score"]
    assert isinstance(score, dict)
    assert score["exact_match"] is False
    assert score["solved"] is False
    assert result["status"] == "failed"
    stdout = (tmp_path / "row-stdout-only" / "stdout.log").read_text(encoding="utf-8")
    assert target.latest_flag not in stdout
    assert "[REDACTED]" in stdout


def test_external_pair_reuses_committed_flag_but_starts_fresh_arm_instances(
    tmp_path: Path,
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target)
    pair_flag = "flag{ravage_cmp_" + "d" * 64 + "}"

    first = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(name="ravage"),
        binding=_binding(primary_slot_id="primary-001"),
        row_dir=tmp_path / "row-ravage",
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
        expected_flag=pair_flag,
        row_instance_id="xben-row-" + "1" * 32,
    )
    second = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(name="external"),
        binding=_binding(primary_slot_id="primary-002"),
        row_dir=tmp_path / "row-external",
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
        expected_flag=pair_flag,
        row_instance_id="xben-row-" + "2" * 32,
    )

    first_score = first["score"]
    second_score = second["score"]
    first_target = first["target"]
    second_target = second["target"]
    assert isinstance(first_score, dict)
    assert isinstance(second_score, dict)
    assert isinstance(first_target, dict)
    assert isinstance(second_target, dict)
    expected_digest = hashlib.sha256(pair_flag.encode("utf-8")).hexdigest()
    assert first_score["expected_flag_sha256"] == expected_digest
    assert second_score["expected_flag_sha256"] == expected_digest
    assert "expected_flag" not in first_score
    assert "found_flag" not in first_score
    for row_name in ("row-ravage", "row-external"):
        row_dir = tmp_path / row_name
        commitment = json.loads((row_dir / FLAG_COMMITMENT_FILE).read_text(encoding="utf-8"))
        assert commitment["scope"] == "pair"
        assert pair_flag not in (row_dir / "row-result.json").read_text(encoding="utf-8")
    assert first_target["instance_id"] == "xben-row-" + "1" * 32
    assert second_target["instance_id"] == "xben-row-" + "2" * 32
    assert target.starts[0][1] == target.starts[1][1] == pair_flag
    assert len(target.starts) == 2
    assert len(target.stops) == 2


def test_invalid_coordinator_instance_id_is_rejected_before_row_claim(tmp_path: Path) -> None:
    row_dir = tmp_path / "invalid-instance"
    with pytest.raises(ComparisonBindingError, match="row_instance_id"):
        run_external_xben_row(
            case=_case(tmp_path),
            agent=_agent(),
            binding=_binding(),
            row_dir=row_dir,
            process_backend=FakeProcessBackend(FakeTargetBackend()),
            target_backend=FakeTargetBackend(),
            require_comparison_safety=False,
            row_instance_id="not-a-bound-instance",
        )
    assert not row_dir.exists()


def test_manifest_rejects_filename_injection_and_unbounded_evidence(tmp_path: Path) -> None:
    unsafe_row = tmp_path / "unsafe-manifest"
    unsafe_output = unsafe_row / "native-output"
    unsafe_output.mkdir(parents=True)
    (unsafe_output / "line\nbreak").write_bytes(b"x")
    with pytest.raises(ExternalComparisonError, match="manifest-safe"):
        external_module._write_manifest_exclusive(unsafe_row)
    assert not (unsafe_row / "artifacts.sha256").exists()

    oversized_row = tmp_path / "oversized-manifest"
    oversized_output = oversized_row / "native-output"
    oversized_output.mkdir(parents=True)
    oversized = oversized_output / "oversized.bin"
    oversized.write_bytes(b"12345")
    original_bound = external_module.DEFAULT_MAX_EVIDENCE_FILE_BYTES
    external_module.DEFAULT_MAX_EVIDENCE_FILE_BYTES = 4
    try:
        with pytest.raises(ExternalComparisonError, match="file exceeds"):
            external_module._write_manifest_exclusive(oversized_row)
    finally:
        external_module.DEFAULT_MAX_EVIDENCE_FILE_BYTES = original_bound
    assert not (oversized_row / "artifacts.sha256").exists()

    hardlinked_row = tmp_path / "hardlinked-manifest"
    hardlinked_output = hardlinked_row / "native-output"
    hardlinked_output.mkdir(parents=True)
    first = hardlinked_output / "first.txt"
    second = hardlinked_output / "second.txt"
    first.write_bytes(b"shared inode")
    second.hardlink_to(first)
    with pytest.raises(ExternalComparisonError, match="multiply-linked"):
        external_module._write_manifest_exclusive(hardlinked_row)
    assert not (hardlinked_row / "artifacts.sha256").exists()


def test_external_row_directory_is_create_only_and_never_retries(tmp_path: Path) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target)
    row_dir = tmp_path / "immutable-row"
    kwargs = {
        "case": _case(tmp_path),
        "agent": _agent(),
        "binding": _binding(),
        "row_dir": row_dir,
        "process_backend": process,
        "target_backend": target,
        "require_comparison_safety": False,
    }
    first = run_external_xben_row(**kwargs)
    original = (row_dir / "row-result.json").read_bytes()

    with pytest.raises(RowAlreadyExistsError, match="already exists"):
        run_external_xben_row(**kwargs)

    assert first["status"] == "failed"
    assert len(target.starts) == 1
    assert len(process.calls) == 1
    assert (row_dir / "row-result.json").read_bytes() == original
    assert first["policy"] == {
        "attempt": 1,
        "retry_allowed": False,
        "replacement_allowed": False,
        "fresh_target_per_row": True,
        "pair_scoped_flag": False,
    }


def test_external_row_timeout_is_terminal_and_stdout_proof_does_not_count(
    tmp_path: Path,
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(
        target,
        artifact_text="no proof",
        stdout_text="expected",
        timeout=True,
    )
    row_dir = tmp_path / "timed-out-row"

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(),
        binding=_binding(),
        row_dir=row_dir,
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
    )

    assert result["status"] == "timed_out"
    execution = result["execution"]
    score = result["score"]
    assert isinstance(execution, dict)
    assert isinstance(score, dict)
    assert execution["status"] == "timed_out"
    assert score["solved"] is False
    stdout = (row_dir / "stdout.log").read_text(encoding="utf-8")
    assert target.latest_flag not in stdout
    assert "[REDACTED]" in stdout
    assert len(process.calls) == 1
    assert len(target.stops) == 1


@pytest.mark.parametrize(
    ("returncode", "timed_out", "expected_status"),
    ((7, False, "errored"), (-15, True, "timed_out")),
)
def test_terminal_agent_loss_is_valid_but_exact_artifact_cannot_make_it_solved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    timed_out: bool,
    expected_status: str,
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(
        target,
        artifact_text="expected",
        returncode=returncode,
        timed_out_result=timed_out,
    )
    process.isolation = ProcessIsolation(
        kind="macos-sandbox-exec-trusted-host-docker",
        filesystem_isolated=False,
        target_network_only=False,
        inherits_parent_environment=False,
        wall_timeout_enforced=True,
        model_request_limit_enforced=True,
        target_request_limit_enforced=False,
        cost_limit_enforced=True,
    )
    process.receipt_contract = ExternalProcessReceiptContract(
        row_id="primary-001",
        model_gateway_policy_sha256="sha256:" + "1" * 64,
        model_gateway_row_token_sha256="sha256:" + "2" * 64,
        sandbox_executable_sha256="sha256:" + "3" * 64,
        runtime_read_roots=(),
        evidence_class="paired_local",
        docker_socket_path=Path("/var/run/docker.sock"),
    )
    monkeypatch.setattr(
        external_module,
        "_validate_execution_receipts",
        lambda **_kwargs: {
            "valid": True,
            "official_attestation_eligible": False,
            "evidence_class": "paired_local",
        },
    )
    monkeypatch.setattr(
        external_module,
        "_validate_comparison_target_evidence",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        "ravage.xben_parts.comparison_adapters.validate_pinned_adapter_agent",
        lambda _agent: None,
    )

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(),
        binding=_binding(),
        row_dir=tmp_path / "nonzero-exact",
        process_backend=process,
        target_backend=target,
        require_comparison_safety=True,
        expected_flag="flag{ravage_cmp_" + "a" * 64 + "}",
    )

    execution = result["execution"]
    score = result["score"]
    assert isinstance(execution, dict)
    assert isinstance(score, dict)
    assert execution["status"] == expected_status
    assert score["exact_match"] is True
    assert result["valid_for_paired_local_comparison"] is True
    assert result["official_attestation_eligible"] is False
    assert score["solved"] is False
    assert result["status"] == expected_status


def test_external_row_missing_artifact_is_a_counted_failure_not_an_exclusion(
    tmp_path: Path,
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target, artifact_text=None)

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(),
        binding=_binding(),
        row_dir=tmp_path / "missing-artifact",
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
    )

    assert result["status"] == "failed"
    assert result["valid_for_comparison"] is False
    score = result["score"]
    assert isinstance(score, dict)
    assert score["solved"] is False
    artifact = score["artifact"]
    assert isinstance(artifact, dict)
    assert artifact["status"] == "missing"


def test_external_row_teardown_failure_invalidates_an_exact_match(tmp_path: Path) -> None:
    target = FakeTargetBackend(teardown_error=True)
    process = FakeProcessBackend(target)

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(),
        binding=_binding(),
        row_dir=tmp_path / "teardown-error",
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
    )

    assert result["status"] == "infrastructure_error"
    assert result["valid_for_comparison"] is False
    score = result["score"]
    assert isinstance(score, dict)
    assert score["exact_match"] is True
    assert score["solved"] is False
    teardown = json.loads(
        (tmp_path / "teardown-error" / "target-teardown.json").read_text(encoding="utf-8")
    )
    assert teardown["status"] == "errored"


def test_external_row_setup_failure_retains_schedule_binding(tmp_path: Path) -> None:
    target = FakeTargetBackend(build_error=True)
    process = FakeProcessBackend(target)
    binding = _binding(primary_slot_id="primary-017")
    row_dir = tmp_path / "setup-error"

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(),
        binding=binding,
        row_dir=row_dir,
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
    )

    assert result["status"] == "infrastructure_error"
    assert result["valid_for_comparison"] is False
    assert result["schedule_binding"] == binding.to_json()
    result_agent = result["agent"]
    assert isinstance(result_agent, dict)
    assert result_agent["reasoning_effort"] == "high"
    assert process.calls == []
    retained = json.loads((row_dir / "row-result.json").read_text(encoding="utf-8"))
    assert retained["schedule_binding"] == binding.to_json()


def test_external_row_redacts_secret_before_bounding_setup_error(tmp_path: Path) -> None:
    token = "tok_" + "S" * 60

    class LeakyTarget(FakeTargetBackend):
        def start(
            self,
            *,
            case: XbenCase,
            expected_flag: str,
            instance_id: str,
        ) -> ExternalTarget:
            del case, expected_flag, instance_id
            raise RuntimeError("A" * 1_985 + token)

    target = LeakyTarget()
    process = FakeProcessBackend(target)
    row_dir = tmp_path / "redacted-setup-error"

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(
            environment={COMPARISON_GATEWAY_TOKEN_ENV: token},
            environment_allowlist=(COMPARISON_GATEWAY_TOKEN_ENV,),
        ),
        binding=_binding(),
        row_dir=row_dir,
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
    )

    assert result["status"] == "infrastructure_error"
    build = json.loads((row_dir / "target-build.json").read_text(encoding="utf-8"))
    assert build["error"].endswith("[REDACTED]")
    for path in row_dir.rglob("*"):
        if path.is_file():
            retained = path.read_bytes()
            assert token.encode() not in retained
            assert b"tok_" not in retained


def test_external_row_rejects_unsafe_backend_before_target_or_row_creation(
    tmp_path: Path,
) -> None:
    target = FakeTargetBackend()
    row_dir = tmp_path / "unsafe-row"

    with pytest.raises(UnsafeProcessBackendError, match="comparison isolation and budget controls"):
        run_external_xben_row(
            case=_case(tmp_path),
            agent=_agent(),
            binding=_binding(),
            row_dir=row_dir,
            process_backend=SubprocessBackend(),
            target_backend=target,
        )

    assert not row_dir.exists()
    assert target.starts == []


def test_external_row_rejects_backend_missing_any_budget_enforcement(
    tmp_path: Path,
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target)
    process.isolation = replace(SAFE_ISOLATION, cost_limit_enforced=False)
    row_dir = tmp_path / "unmetered-row"

    with pytest.raises(UnsafeProcessBackendError, match="comparison isolation and budget controls"):
        run_external_xben_row(
            case=_case(tmp_path),
            agent=_agent(),
            binding=_binding(),
            row_dir=row_dir,
            process_backend=process,
            target_backend=target,
        )

    assert not row_dir.exists()
    assert target.starts == []


def test_process_runtime_roots_cannot_overlap_withheld_benchmark_source(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    contract = ExternalProcessReceiptContract(
        row_id="primary-001",
        model_gateway_policy_sha256="sha256:" + "a" * 64,
        model_gateway_row_token_sha256="sha256:" + "b" * 64,
        sandbox_executable_sha256="sha256:" + "c" * 64,
        runtime_read_roots=(case.path.parent,),
        evidence_class="strict_official",
    )

    with pytest.raises(UnsafeProcessBackendError, match="withheld benchmark source"):
        external_module._validate_process_read_roots_for_case(contract, case=case)


@pytest.mark.parametrize(
    "binding_overrides",
    [
        {"campaign_id": "Bad Campaign"},
        {"commitment_digest": "a" * 64},
        {"selection_digest": "sha256:" + "A" * 64},
        {"primary_slot_id": "primary-041"},
        {"primary_slot_id": "rerun-001"},
    ],
)
def test_external_row_rejects_invalid_schedule_binding_before_row_creation(
    tmp_path: Path,
    binding_overrides: dict[str, str],
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target)
    row_dir = tmp_path / "invalid-binding"

    with pytest.raises(ComparisonBindingError):
        run_external_xben_row(
            case=_case(tmp_path),
            agent=_agent(),
            binding=_binding(**binding_overrides),
            row_dir=row_dir,
            process_backend=process,
            target_backend=target,
        )

    assert not row_dir.exists()
    assert target.starts == []


@pytest.mark.parametrize("reasoning_effort", ["", " high "])
def test_external_row_rejects_noncanonical_reasoning_effort_before_row_creation(
    tmp_path: Path,
    reasoning_effort: str,
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target)
    row_dir = tmp_path / "invalid-reasoning-effort"

    with pytest.raises(ComparisonContractError, match="reasoning effort"):
        run_external_xben_row(
            case=_case(tmp_path),
            agent=_agent(reasoning_effort=reasoning_effort),
            binding=_binding(),
            row_dir=row_dir,
            process_backend=process,
            target_backend=target,
        )

    assert not row_dir.exists()
    assert target.starts == []


@pytest.mark.parametrize(
    ("environment", "allowlist", "expected_error"),
    [
        ({"OPENAI_API_KEY": "deliberate"}, (), ComparisonContractError),
        ({"XBEN_ROOT": "/private/benchmark"}, ("XBEN_ROOT",), AgentEnvironmentError),
        ({"EXPECTED_FLAG": "guess"}, ("EXPECTED_FLAG",), AgentEnvironmentError),
    ],
)
def test_external_row_rejects_undeclared_or_benchmark_sensitive_environment(
    tmp_path: Path,
    environment: dict[str, str],
    allowlist: tuple[str, ...],
    expected_error: type[Exception],
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target)
    row_dir = tmp_path / "bad-environment"

    with pytest.raises(expected_error):
        run_external_xben_row(
            case=_case(tmp_path),
            agent=_agent(environment=environment, environment_allowlist=allowlist),
            binding=_binding(),
            row_dir=row_dir,
            process_backend=process,
            target_backend=target,
        )

    assert not row_dir.exists()
    assert target.starts == []


def test_external_row_rejects_account_provider_key_even_when_allowlisted(
    tmp_path: Path,
) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target)
    row_dir = tmp_path / "account-key-environment"

    with pytest.raises(AgentEnvironmentError, match="benchmark-sensitive name"):
        run_external_xben_row(
            case=_case(tmp_path),
            agent=_agent(
                environment={"OPENAI_API_KEY": "must-stay-in-evaluator-gateway"},
                environment_allowlist=("OPENAI_API_KEY",),
            ),
            binding=_binding(),
            row_dir=row_dir,
            process_backend=process,
            target_backend=target,
        )

    assert not row_dir.exists()
    assert target.starts == []


def test_external_row_truncates_retained_logs_and_records_raw_digest(tmp_path: Path) -> None:
    target = FakeTargetBackend()
    process = FakeProcessBackend(target, stdout_text="x" * 100)
    row_dir = tmp_path / "bounded-log"

    result = run_external_xben_row(
        case=_case(tmp_path),
        agent=_agent(),
        binding=_binding(),
        row_dir=row_dir,
        process_backend=process,
        target_backend=target,
        require_comparison_safety=False,
        max_log_bytes=32,
    )

    retained = (row_dir / "stdout.log").read_bytes()
    assert len(retained) <= 32
    assert b"TRUNCATED" in retained
    execution = result["execution"]
    assert isinstance(execution, dict)
    capture = execution["stdout_capture"]
    assert isinstance(capture, dict)
    assert capture["truncated"] is True
    assert capture["raw_size_bytes"] == 100
    assert capture["raw_sha256"] == hashlib.sha256(b"x" * 100).hexdigest()


def test_external_row_rejects_benchmark_source_path_hidden_under_allowed_name(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    target = FakeTargetBackend()
    process = FakeProcessBackend(target)
    row_dir = tmp_path / "source-environment"

    with pytest.raises(AgentEnvironmentError, match="evaluator-only benchmark state"):
        run_external_xben_row(
            case=case,
            agent=_agent(
                environment={"ADAPTER_CONFIG": str(case.path)},
                environment_allowlist=("ADAPTER_CONFIG",),
            ),
            binding=_binding(),
            row_dir=row_dir,
            process_backend=process,
            target_backend=target,
        )

    assert not row_dir.exists()
    assert target.starts == []


def _case(tmp_path: Path) -> XbenCase:
    path = tmp_path / "benchmarks" / "XBEN-001-24"
    path.mkdir(parents=True, exist_ok=True)
    return XbenCase(
        benchmark_id="XBEN-001-24",
        path=path,
        name="withheld name",
        level=4,
        description="XBEN-001-24 Find the proof through the application.",
        main_service="web",
        main_service_port=8080,
    )


def _agent(
    *,
    name: str = "agent",
    reasoning_effort: str = "high",
    environment: Mapping[str, str] | None = None,
    environment_allowlist: tuple[str, ...] = (),
) -> ExternalAgentCommand:
    return ExternalAgentCommand(
        name=name,
        system_id=name,
        command=("/fake/agent-adapter", "run"),
        artifact_path="agent-report.md",
        limits=ExternalExecutionLimits(
            wall_seconds=600,
            max_model_requests=40,
            max_target_requests=300,
            max_cost_usd="20",
        ),
        reasoning_effort=reasoning_effort,
        provider="provider",
        model="model",
        adapter_version="test-v1",
        environment=environment or {},
        environment_allowlist=environment_allowlist,
    )


def _binding(
    *,
    campaign_id: str = "campaign-001",
    commitment_digest: str = "sha256:" + "a" * 64,
    selection_digest: str = "sha256:" + "b" * 64,
    primary_slot_id: str = "primary-001",
) -> ComparisonRowBinding:
    return ComparisonRowBinding(
        campaign_id=campaign_id,
        commitment_digest=commitment_digest,
        selection_digest=selection_digest,
        primary_slot_id=primary_slot_id,
    )


def _evidence_names() -> tuple[str, ...]:
    return (
        "row-result.json",
        "stdout.log",
        "stderr.log",
        "target-build.json",
        "target-teardown.json",
        FLAG_COMMITMENT_FILE,
        "artifacts.sha256",
    )
