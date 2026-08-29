from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from pentest_schemas import ProofVerifierVerdict
from ravage.proof_bundle_eval import (
    ProofBundleEvalCase,
    evaluate_proof_bundle_cases,
    load_proof_bundle_eval_cases,
)

if TYPE_CHECKING:
    from pathlib import Path

EVAL_CASE_COUNT = 2


def _bundle(
    *,
    verdict: str = "accepted",
    impact: str | None = "Cross-account read",
) -> dict[str, Any]:
    return {
        "bundle_id": "bundle-1",
        "title": "Unauthorized record access",
        "hypothesis": "Changing an object identifier exposes another account record.",
        "scope": {"in_scope": ["http://127.0.0.1:8765"], "out_of_scope": []},
        "target_origin": "http://127.0.0.1:8765",
        "vuln_class": "idor",
        "steps": [
            {
                "step_id": "baseline",
                "kind": "baseline",
                "description": "Read the attacker's own profile.",
                "actor": "attacker",
                "http": {
                    "method": "GET",
                    "url": "http://127.0.0.1:8765/profile/10",
                    "request": "GET /profile/10 HTTP/1.1",
                    "response_status": 200,
                    "response_snippet": "name=Alice account_id=10",
                },
                "observation": "The baseline response shows the attacker's own account.",
            },
            {
                "step_id": "mutation",
                "kind": "mutation",
                "description": "Replay the same session with a different profile identifier.",
                "actor": "attacker",
                "http": {
                    "method": "GET",
                    "url": "http://127.0.0.1:8765/profile/11",
                    "request": "GET /profile/11 HTTP/1.1",
                    "response_status": 200,
                    "response_snippet": "name=Bob account_id=11",
                },
                "observation": "The mutated response exposes a different account.",
            },
        ],
        "provenance": [
            {
                "source_step_id": "mutation",
                "source_value": "11",
                "observed_step_id": "mutation",
                "observed_value": "account_id=11",
                "relation": "mutated path identifier selected the observed account",
            }
        ],
        "controls": [
            {
                "control_id": "baseline-control",
                "kind": "baseline",
                "step_ids": ["baseline"],
                "expected_result": "Baseline shows only attacker-owned data.",
                "observed_result": "Baseline showed account_id=10.",
                "passed": True,
            }
        ],
        "replay": {
            "summary": "Authenticate as the attacker and replay both profile requests.",
            "steps": [
                "Request the attacker's own profile.",
                "Change only the profile identifier and replay the request.",
            ],
            "required_state": ["attacker session cookie"],
        },
        "verifier": {
            "verdict": verdict,
            "confidence": "high",
            "rationale": "The same session saw data for a different account after one mutation.",
            "impact": impact,
        },
    }


def test_evaluate_proof_bundle_cases_counts_passes() -> None:
    cases = [
        ProofBundleEvalCase(
            case_id="positive",
            expected_verdict="accepted",
            proof_bundle=_bundle(),
        ),
        ProofBundleEvalCase(
            case_id="negative",
            expected_verdict="rejected",
            proof_bundle=_bundle(verdict="rejected", impact=None),
        ),
    ]

    report = evaluate_proof_bundle_cases(cases)

    assert report.total == EVAL_CASE_COUNT
    assert report.passed == EVAL_CASE_COUNT
    assert report.failed == 0
    assert report.false_positive == 0
    assert report.false_negative == 0


def test_evaluate_proof_bundle_cases_counts_false_positive() -> None:
    report = evaluate_proof_bundle_cases(
        [
            ProofBundleEvalCase(
                case_id="negative-control",
                expected_verdict="rejected",
                proof_bundle=_bundle(),
            )
        ]
    )

    assert report.passed == 0
    assert report.failed == 1
    assert report.false_positive == 1
    assert report.results[0].actual_verdict == "accepted"


def test_evaluate_proof_bundle_cases_uses_semantic_verifier() -> None:
    def verifier(_bundle: object) -> ProofVerifierVerdict:
        return ProofVerifierVerdict(
            verdict="rejected",
            confidence="high",
            rationale="The mutation returns no protected object.",
            impact=None,
        )

    report = evaluate_proof_bundle_cases(
        [
            ProofBundleEvalCase(
                case_id="negative-control",
                expected_verdict="rejected",
                proof_bundle=_bundle(),
            )
        ],
        semantic_verifier=verifier,
    )

    assert report.passed == 1
    assert report.false_positive == 0
    assert report.results[0].actual_verdict == "rejected"


def test_evaluate_proof_bundle_cases_fails_accepted_bundle_with_gate_failures() -> None:
    report = evaluate_proof_bundle_cases(
        [
            ProofBundleEvalCase(
                case_id="thin-positive",
                expected_verdict="accepted",
                proof_bundle=_bundle(impact=None),
            )
        ]
    )

    assert report.passed == 0
    assert report.failed == 1
    assert "missing proof_bundle.verifier.impact" in report.results[0].gate_failures


def test_evaluate_proof_bundle_cases_gates_semantic_verifier_acceptance() -> None:
    def verifier(_bundle: object) -> ProofVerifierVerdict:
        return ProofVerifierVerdict(
            verdict="accepted",
            confidence="high",
            rationale="Looks exploitable.",
            impact=None,
        )

    report = evaluate_proof_bundle_cases(
        [
            ProofBundleEvalCase(
                case_id="thin-positive",
                expected_verdict="accepted",
                proof_bundle=_bundle(verdict="rejected", impact=None),
            )
        ],
        semantic_verifier=verifier,
    )

    assert report.passed == 0
    assert report.failed == 1
    assert "missing proof_bundle.verifier.impact" in report.results[0].gate_failures


def test_load_proof_bundle_eval_cases_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "cases.jsonl"
    path.write_text(
        "\n".join(
            [
                "# comment",
                json.dumps(
                    {
                        "case_id": "positive",
                        "expected_verdict": "accepted",
                        "proof_bundle": _bundle(),
                    }
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )

    cases = load_proof_bundle_eval_cases(path)

    assert len(cases) == 1
    assert cases[0].case_id == "positive"
    assert cases[0].expected_verdict == "accepted"
