"""Exercise the real read-only evaluator with synthetic model replies."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import TYPE_CHECKING

import pytest
from ravage.repository_review import ReviewReply
from ravage.repository_review_eval_runner import run_repository_review_ab_evaluation

from tools.review_quality_gate.client import ExactReviewClient
from tools.review_quality_gate.gate import (
    MANIFEST,
    POLICY_PATH,
    ROOT,
    Policy,
    extract_samples,
    read_json,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import Any

    from ravage.model_core.providers import ResolvedModelRoute
    from ravage.repository_review import ReviewMessage


class EmptyReviewClient:
    def complete(
        self, *, messages: Sequence[ReviewMessage], route: ResolvedModelRoute
    ) -> ReviewReply:
        del route
        if len(messages) == 2:  # noqa: PLR2004 - initial system and user messages.
            content = '{"action":"list_files","args":{}}'
        elif json.loads(messages[-1].content).get("type") == "file_list":
            path = json.loads(messages[-1].content)["files"][0]["path"]
            content = json.dumps(
                {
                    "action": "excerpt",
                    "args": {"path": path, "start_line": 1, "end_line": 40},
                }
            )
        else:
            content = '{"action":"final","args":{"summary":"Synthetic test","findings":[]}}'
        return ReviewReply(
            content=content,
            input_tokens=1,
            output_tokens=1,
            cost_usd=0.001,
            usage_reported=True,
            cost_known=True,
        )


@pytest.fixture
def report(monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], Policy]:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-test-key")
    policy = Policy.model_validate(read_json(ROOT / POLICY_PATH))
    route = ExactReviewClient(policy, allow_paid_models=True).route
    report: dict[str, Any] = run_repository_review_ab_evaluation(
        manifest_path=ROOT / MANIFEST,
        repository_root=ROOT,
        route=route,
        client=EmptyReviewClient(),
        repeats=policy.repeats,
        max_turns=policy.max_turns,
        max_cost_usd_per_run=policy.max_cost_per_run_usd,
        aggregate_cost_ceiling_usd=policy.max_cost_usd,
        allow_paid_models=True,
    )
    assert not report["failures"], report["failures"][:1]
    return report, policy


def test_all_completed_reviews_are_scored_again(report: tuple[dict[str, Any], Policy]) -> None:
    data, policy = report
    rows = extract_samples(data, policy, ROOT)
    assert len(rows) == data["completion"]["planned_runs"]
    assert all(row.hits == [] for row in rows)


@pytest.mark.parametrize("mutation", ["score", "snapshot", "failure", "model", "accounting"])
def test_invalid_evaluator_report_is_rejected(
    report: tuple[dict[str, Any], Policy], mutation: str
) -> None:
    data, policy = deepcopy(report)
    if mutation == "score":
        data["runs"][0]["score"]["true_positives"] += 1
    elif mutation == "snapshot":
        data["runs"][0]["review"]["snapshot_id"] = "sha256:" + "f" * 64
    elif mutation == "failure":
        data["runs"][0]["completed"] = False
    elif mutation == "model":
        data["route"]["model"] = "another-model"
    else:
        data["runs"][0]["model"]["cost_known"] = False
    with pytest.raises(ValueError, match=r"counts|snapshot|finish|settings|accounting"):
        extract_samples(data, policy, ROOT)
