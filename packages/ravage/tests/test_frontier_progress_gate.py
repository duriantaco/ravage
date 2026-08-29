from __future__ import annotations

from dataclasses import dataclass

from ravage.agent_core.frontier_progress_gate import (
    trusted_material_progress_tokens,
)
from ravage.agent_core.recovery_policy import (
    MaterialProgressKind,
    ProgressSnapshot,
)


@dataclass(frozen=True)
class _Assessment:
    material_progress: tuple[MaterialProgressKind, ...]
    snapshot: ProgressSnapshot


def test_executor_classification_without_typed_delta_cannot_buy_a_lease() -> None:
    assessment = _Assessment(
        material_progress=(),
        snapshot=ProgressSnapshot(),
    )

    assert trusted_material_progress_tokens(assessment) == ()


def test_typed_target_evidence_and_validated_coordinator_work_are_preserved() -> None:
    assessment = _Assessment(
        material_progress=(MaterialProgressKind.REQUEST_TEMPLATE_VALIDATED,),
        snapshot=ProgressSnapshot(validated_request_templates=frozenset({"template-fingerprint"})),
    )

    tokens = trusted_material_progress_tokens(
        assessment,
        coordinator_progress=("checkpoint:admin",),
    )

    assert "checkpoint:admin" in tokens
    assert any(item.startswith("validated_request_templates:") for item in tokens)
