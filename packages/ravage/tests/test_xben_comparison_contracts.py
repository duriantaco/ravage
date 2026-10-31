from __future__ import annotations

from decimal import Decimal

import pytest
from ravage.xben_parts import comparison_contracts as contracts
from ravage.xben_parts.comparison_contracts import (
    ComparisonContractError,
    ExternalAgentCommand,
    ExternalExecutionLimits,
    ExternalTarget,
    decimal_text,
)


def test_execution_limits_use_exact_canonical_decimal_text() -> None:
    limits = ExternalExecutionLimits(
        wall_seconds=600,
        max_model_requests=24,
        max_target_requests=300,
        max_cost_usd="2.5000",
    )

    assert limits.max_cost_usd == Decimal("2.5000")
    assert limits.to_json() == {
        "wall_seconds": 600,
        "max_model_requests": 24,
        "max_target_requests": 300,
        "max_cost_usd": "2.5",
    }


def test_execution_limits_preserve_positional_callers_and_long_decimal_values() -> None:
    text = "1.0000000000000000000000000000000000001"
    limits = ExternalExecutionLimits(60, 2, 10, text)

    assert limits.max_cost_usd == Decimal(text)
    assert limits.to_json()["max_cost_usd"] == text


@pytest.mark.parametrize("value", [0.1, 0.1 + 0.2, float("inf")])
def test_execution_limits_reject_inexact_float_money(value: float) -> None:
    with pytest.raises(ComparisonContractError, match="exact Decimal"):
        ExternalExecutionLimits(
            wall_seconds=1,
            max_model_requests=1,
            max_target_requests=1,
            max_cost_usd=value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("field", ["wall_seconds", "max_model_requests", "max_target_requests"])
@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "1", pytest.param(10**5000, id="huge-int")])
def test_execution_limits_reject_invalid_integer_ceiling(field: str, value: object) -> None:
    values: dict[str, object] = {
        "wall_seconds": 1,
        "max_model_requests": 1,
        "max_target_requests": 1,
        "max_cost_usd": "1",
    }
    values[field] = value

    with pytest.raises(ComparisonContractError, match="positive integer"):
        ExternalExecutionLimits(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    [
        True,
        0,
        -1,
        "",
        " 1",
        "1 ",
        "NaN",
        "Infinity",
        float("inf"),
        "1e999",
        pytest.param(10**5000, id="huge-int"),
    ],
)
def test_execution_limits_reject_invalid_cost_ceiling(value: object) -> None:
    with pytest.raises(ComparisonContractError):
        ExternalExecutionLimits(
            wall_seconds=1,
            max_model_requests=1,
            max_target_requests=1,
            max_cost_usd=value,  # type: ignore[arg-type]
        )


def test_decimal_text_never_uses_exponent_notation() -> None:
    assert decimal_text(Decimal("1E+3")) == "1000"
    assert decimal_text(Decimal("0.0001000")) == "0.0001"
    assert decimal_text(Decimal("-0.00")) == "0"


def test_agent_command_snapshots_only_its_explicit_environment() -> None:
    environment = {"ROW_TOKEN": "secret"}
    agent = ExternalAgentCommand(
        name="Ravage",
        system_id="ravage",
        command=("/opt/ravage/bin/python", "-m", "ravage.adapter"),
        artifact_path="flag-candidates.txt",
        limits=ExternalExecutionLimits(
            wall_seconds=60,
            max_model_requests=2,
            max_target_requests=10,
            max_cost_usd="1.25",
        ),
        reasoning_effort="high",
        environment=environment,
        environment_allowlist=("ROW_TOKEN",),
    )

    environment["LATE_MUTATION"] = "not captured"
    assert dict(agent.environment) == {"ROW_TOKEN": "secret"}
    assert "secret" not in repr(agent)


@pytest.mark.parametrize(
    "override",
    [
        {"command": ("python", "-m", "adapter")},
        {"command": ("/bin/python", "")},
        {"command": ("/bin/python", "bad\nargument")},
        {"command": ("/bin/python", *("x" * 16_000 for _ in range(17)))},
        {"artifact_path": "../score.txt"},
        {"artifact_path": "/tmp/score.txt"},
        {"artifact_path": "score\x00.txt"},
        {"environment_allowlist": ()},
        {"environment_allowlist": ("ROW_TOKEN", "ROW_TOKEN")},
        {"reasoning_effort": ""},
    ],
)
def test_agent_command_rejects_ambient_or_ambiguous_authority(
    override: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "name": "Ravage",
        "system_id": "ravage",
        "command": ("/bin/python",),
        "artifact_path": "score.txt",
        "limits": ExternalExecutionLimits(
            wall_seconds=1,
            max_model_requests=1,
            max_target_requests=1,
            max_cost_usd="1",
        ),
        "reasoning_effort": "high",
        "environment": {"ROW_TOKEN": "secret"},
        "environment_allowlist": ("ROW_TOKEN",),
    }
    values.update(override)

    with pytest.raises(ComparisonContractError):
        ExternalAgentCommand(**values)  # type: ignore[arg-type]


def test_agent_environment_type_errors_are_normalized() -> None:
    with pytest.raises(ComparisonContractError):
        ExternalAgentCommand(
            name="Ravage",
            system_id="ravage",
            command=("/bin/python",),
            artifact_path="score.txt",
            limits=ExternalExecutionLimits(
                wall_seconds=1,
                max_model_requests=1,
                max_target_requests=1,
                max_cost_usd="1",
            ),
            reasoning_effort="high",
            environment={1: "invalid"},  # type: ignore[dict-item]
            environment_allowlist=("ROW_TOKEN",),
        )


def test_target_provenance_is_snapshotted_and_handle_is_not_disclosed() -> None:
    provenance: dict[str, object] = {
        "source": {"commit": "a" * 40},
        "images": ["sha256:one"],
    }
    handle = object()
    target = ExternalTarget(
        instance_id="row-target",
        target_url="http://127.0.0.1:8080",
        build_provenance=provenance,
        backend_handle=handle,
    )

    provenance["late_mutation"] = True
    provenance["source"]["commit"] = "b" * 40  # type: ignore[index]
    provenance["images"].append("sha256:two")  # type: ignore[union-attr]
    assert "late_mutation" not in target.build_provenance
    assert target.build_provenance["source"] == {"commit": "a" * 40}
    assert target.build_provenance["images"] == ["sha256:one"]
    returned = target.build_provenance
    returned["source"]["commit"] = "c" * 40  # type: ignore[index]
    assert target.build_provenance["source"] == {"commit": "a" * 40}
    assert repr(handle) not in repr(target)


def test_target_provenance_rejects_recursive_non_json_and_oversized_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recursive: list[object] = []
    recursive.append(recursive)
    for provenance in ({"recursive": recursive}, {"opaque": object()}):
        with pytest.raises(ComparisonContractError, match="provenance"):
            ExternalTarget(
                instance_id="row-target",
                target_url="http://127.0.0.1:8080",
                build_provenance=provenance,
            )

    monkeypatch.setattr(contracts, "_MAX_TARGET_PROVENANCE_BYTES", 32)
    with pytest.raises(ComparisonContractError, match="provenance"):
        ExternalTarget(
            instance_id="row-target",
            target_url="http://127.0.0.1:8080",
            build_provenance={"oversized": "x" * 64},
        )
