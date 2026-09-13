from __future__ import annotations

import hashlib
import json
from uuid import UUID

import pytest
from pentest_schemas.brief import DataHandling, EngagementBrief
from ravage.xben_parts.comparison_semantics import (
    FIXED_OBJECTIVE,
    FIXED_RULES,
    FORBIDDEN_LITERAL_SCANNER_VERSION,
    SEMANTIC_DOCUMENT_SCHEMA,
    ComparisonSemanticDocument,
    semantic_prompt_policy,
)


def test_semantic_document_projects_through_native_inputs() -> None:
    document = ComparisonSemanticDocument.build(
        description="  Public café challenge.\r\nTest the exposed application.  "
    )

    assert document.description == "Public café challenge.\nTest the exposed application."
    assert json.loads(document.canonical_text) == document.to_json()
    assert document.to_json()["schema_version"] == SEMANTIC_DOCUMENT_SCHEMA

    ravage = document.for_system("ravage")
    brief = EngagementBrief.model_validate(
        {
            "engagement_id": UUID("6a9e8d5a-a179-5e3f-b04e-a10cfbeb7383"),
            "scope": {"in_scope": ["http://target.invalid"], "out_of_scope": []},
            "roe": {
                "max_rps": 10,
                "no_destructive_actions": True,
                "data_handling": DataHandling.PLACEHOLDERS_ONLY,
            },
            "budget": {"max_cost_usd": 1.0, "max_runtime_min": 10},
            **ravage,
        }
    )
    assert brief.objectives == ["capture_flag"]
    assert brief.context == {
        "description": document.description,
        "win_condition": FIXED_OBJECTIVE,
        "rules": list(FIXED_RULES),
    }

    reference = document.for_system("reference")
    assert reference == {"instruction": document.canonical_text}
    expected_digests = {
        system: _digest(document.for_system(system)) for system in ("ravage", "reference")
    }
    assert document.projection_digests == expected_digests
    assert document.projection_digests["ravage"] != document.projection_digests["reference"]


@pytest.mark.parametrize(
    "description",
    [
        "Check whether /etc/passwd can be read.",
        "Review /admin?id=1 for authorization issues.",
        "Assess /api/users using black-box behavior.",
        "Look for an IDOR vulnerability.",
    ],
)
def test_public_security_language_is_not_overfiltered(description: str) -> None:
    assert ComparisonSemanticDocument.build(description=description).description == description


@pytest.mark.parametrize(
    "description",
    [
        "Use XBEN-026-24 as the case.",
        "The answer is flag{do-not-leak}.",
        "Read file:///tmp/solution.txt.",
        "Open /Users/operator/repo/solution.py.",
        "Open /home/runner/work/solution.py.",
        "Open /private/tmp/solution.py.",
        r"Open C:\Users\operator\solution.py.",
        "Open benchmarks/XBEN/app.py.",
        "Open /repo/benchmarks/XBEN/app.py.",
        "Use XBEN-\n026-24 as the case.",
        "Open benchmarks/\nXBEN/app.py.",
        "The answer is flag{proof-\ntoken}.",
        "\tPublic challenge.",
        "Public challenge.\f",
        "Hidden\x00control.",
        "Hidden\u200bseparator.",
        "Invalid \ud800 text.",
    ],
)
def test_evaluator_or_benchmark_material_is_rejected(description: str) -> None:
    with pytest.raises(ValueError, match=r"hidden or unsupported|evaluator-only"):
        ComparisonSemanticDocument.build(description=description)


@pytest.mark.parametrize(
    "forbidden_literal",
    ['quote"secret', r"slash\secret", "line\nsecret"],
)
def test_forbidden_literal_scan_handles_json_escaping_without_echoing_secret(
    forbidden_literal: str,
) -> None:
    document = ComparisonSemanticDocument.build(
        description=f"Public details containing {forbidden_literal} for scanner testing."
    )

    with pytest.raises(ValueError, match="failed evaluator-only") as exc_info:
        document.scan_forbidden_literals([forbidden_literal])

    assert forbidden_literal not in str(exc_info.value)


def test_forbidden_literal_scan_emits_only_a_verdict_and_bindings() -> None:
    document = ComparisonSemanticDocument.build(description="Public black-box challenge.")

    assert document.scan_forbidden_literals(["evaluator-only-secret"]) == {
        "scanner_version": FORBIDDEN_LITERAL_SCANNER_VERSION,
        "semantic_document_sha256": document.digest,
        "zero_matches": True,
    }
    with pytest.raises(ValueError, match="duplicates after normalization"):
        document.scan_forbidden_literals(["cafe\u0301", "café"])


@pytest.mark.parametrize("projection_only_literal", ["capture_flag", SEMANTIC_DOCUMENT_SCHEMA])
def test_forbidden_literal_scan_checks_each_native_projection(
    projection_only_literal: str,
) -> None:
    document = ComparisonSemanticDocument.build(description="Public black-box challenge.")

    with pytest.raises(ValueError, match="failed evaluator-only"):
        document.scan_forbidden_literals([projection_only_literal])


def test_forbidden_literal_scan_rejects_line_split_literals() -> None:
    document = ComparisonSemanticDocument.build(
        description="Public details contain evaluator-\nsecret material."
    )

    with pytest.raises(ValueError, match="failed evaluator-only"):
        document.scan_forbidden_literals(["evaluator-secret"])


def test_prompt_policy_limits_the_claim_to_shared_authored_semantics() -> None:
    policy = semantic_prompt_policy()

    assert policy["runtime_forbidden_literal_check_required"] is True
    assert policy["claim"] == (
        "both_arms_receive_projections_of_one_evaluator_authored_semantic_document"
    )
    assert policy["fixed_objective"] == FIXED_OBJECTIVE
    assert policy["fixed_rules"] == list(FIXED_RULES)


def _digest(value: object) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
