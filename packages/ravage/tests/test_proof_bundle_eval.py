from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pentest_schemas import ProofVerifierVerdict
from ravage.proof_bundle_eval import (
    ProofBundleEvalCase,
    evaluate_proof_bundle_cases,
    load_proof_bundle_eval_cases,
    write_proof_bundle_eval_report,
)

EVAL_CASE_COUNT = 2
_REPO_ROOT = Path(__file__).resolve().parents[3]
_INVALID_INPUT_EXIT_CODE = 2


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
    assert report.successful
    assert report.to_json()["evaluation_mode"] == "recorded_verdicts"


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


def test_empty_proof_bundle_evaluation_is_not_successful(tmp_path: Path) -> None:
    report = evaluate_proof_bundle_cases([])
    output_path = tmp_path / "reports" / "empty.json"

    write_proof_bundle_eval_report(report, output_path)

    assert report.total == 0
    assert not report.successful
    assert report.status == "empty"
    assert json.loads(output_path.read_text(encoding="utf-8"))["successful"] is False


@pytest.mark.parametrize("expected_verdict", ["", "accept", "Accepted", "anything"])
def test_evaluation_rejects_unknown_labels(expected_verdict: str) -> None:
    with pytest.raises(ValueError, match="invalid expected_verdict"):
        evaluate_proof_bundle_cases([ProofBundleEvalCase("case", expected_verdict, _bundle())])


def test_evaluation_rejects_duplicate_case_ids() -> None:
    case = ProofBundleEvalCase("duplicate", "accepted", _bundle())
    with pytest.raises(ValueError, match="nonempty and unique"):
        evaluate_proof_bundle_cases([case, case])


def test_invalid_bundle_cannot_be_counted_as_correct_rejection() -> None:
    with pytest.raises(ValueError, match="invalid proof_bundle"):
        evaluate_proof_bundle_cases([ProofBundleEvalCase("missing", "rejected", {})])


def test_verifier_gate_uses_actual_verdict_impact() -> None:
    def verifier(_bundle: object) -> ProofVerifierVerdict:
        return ProofVerifierVerdict(
            verdict="accepted",
            confidence="high",
            rationale="The supplied evidence crosses the account boundary.",
            impact="Another account's protected record is disclosed.",
        )

    report = evaluate_proof_bundle_cases(
        [ProofBundleEvalCase("new-verdict", "accepted", _bundle(verdict="rejected", impact=None))],
        verifier=verifier,
    )

    assert report.successful
    assert report.to_json()["evaluation_mode"] == "provided_verifier"


def test_stored_impact_does_not_mask_a_missing_verifier_impact() -> None:
    def verifier(_bundle: object) -> ProofVerifierVerdict:
        return ProofVerifierVerdict(
            verdict="accepted",
            confidence="high",
            rationale="No impact has been supplied by this verifier.",
            impact=None,
        )

    report = evaluate_proof_bundle_cases(
        [ProofBundleEvalCase("missing-impact", "accepted", _bundle())],
        verifier=verifier,
    )

    assert not report.successful
    assert report.failed == 1
    assert "missing proof_bundle.verifier.impact" in report.results[0].gate_failures


def test_acceptance_with_a_failed_control_cannot_pass_evaluation() -> None:
    bundle = _bundle()
    bundle["controls"][0]["passed"] = False

    report = evaluate_proof_bundle_cases(
        [ProofBundleEvalCase("failed-control", "accepted", bundle)]
    )

    assert not report.successful
    assert "proof control 'baseline-control' did not pass" in report.results[0].gate_failures


def test_callback_cannot_override_a_failed_fixture_control() -> None:
    bundle = _bundle(verdict="rejected", impact=None)
    bundle["controls"][0]["passed"] = False

    def verifier(_bundle: object) -> ProofVerifierVerdict:
        return ProofVerifierVerdict(
            verdict="accepted",
            confidence="high",
            rationale="Accepted by an independent callback.",
            impact="An impact statement does not establish a passing control.",
        )

    report = evaluate_proof_bundle_cases(
        [ProofBundleEvalCase("failed-control", "accepted", bundle)], verifier=verifier
    )

    assert not report.successful
    assert "proof control 'baseline-control' did not pass" in report.results[0].gate_failures


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("duplicate-step", "proof step IDs must be nonempty and unique"),
        ("duplicate-control", "proof control IDs must be nonempty and unique"),
        ("missing-control-step", "control 'baseline-control' refers to an unknown proof step"),
        ("missing-source-step", "provenance refers to an unknown proof step"),
        ("missing-observed-step", "provenance refers to an unknown proof step"),
    ],
)
def test_evaluation_rejects_inconsistent_proof_references(mutation: str, error: str) -> None:
    bundle = _bundle()
    if mutation == "duplicate-step":
        bundle["steps"][1]["step_id"] = bundle["steps"][0]["step_id"]
    elif mutation == "duplicate-control":
        bundle["controls"].append(dict(bundle["controls"][0]))
    elif mutation == "missing-control-step":
        bundle["controls"][0]["step_ids"] = ["absent"]
    elif mutation == "missing-source-step":
        bundle["provenance"][0]["source_step_id"] = "absent"
    else:
        bundle["provenance"][0]["observed_step_id"] = "absent"

    with pytest.raises(ValueError, match=error):
        evaluate_proof_bundle_cases([ProofBundleEvalCase(mutation, "accepted", bundle)])


@pytest.mark.parametrize(
    "raw",
    [
        "[1, 2]",
        "{bad-json",
        '{"case_id": "missing-bundle", "expected_verdict": "rejected"}',
        '{"case_id": 1, "expected_verdict": "rejected", "proof_bundle": {}}',
    ],
)
def test_loader_rejects_malformed_cases(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "cases.jsonl"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match=r"cases\.jsonl:1"):
        load_proof_bundle_eval_cases(path)


@pytest.mark.parametrize("script", ["eval_proof_bundles.py", "eval/eval_proof_bundles.py"])
def test_proof_bundle_eval_cli_help(script: str) -> None:
    result = subprocess.run(  # noqa: S603 - fixed local script, no shell.
        [sys.executable, str(_REPO_ROOT / "scripts" / script), "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0
    assert "recorded" in result.stdout
    assert "does not independently verify" in result.stdout


@pytest.mark.parametrize(
    ("expected_verdict", "actual_verdict", "expected_exit", "successful"),
    [("accepted", "accepted", 0, True), ("rejected", "accepted", 1, False)],
)
def test_proof_bundle_eval_cli_scores_offline_cases(
    tmp_path: Path,
    expected_verdict: str,
    actual_verdict: str,
    expected_exit: int,
    *,
    successful: bool,
) -> None:
    cases_path = tmp_path / "cases.jsonl"
    output_path = tmp_path / "results" / "report.json"
    cases_path.write_text(
        json.dumps(
            {
                "case_id": "recorded",
                "expected_verdict": expected_verdict,
                "proof_bundle": _bundle(verdict=actual_verdict),
            }
        ),
        encoding="utf-8",
    )

    result = _run_cli(str(cases_path), "--output", str(output_path))

    assert result.returncode == expected_exit
    payload = json.loads(result.stdout)
    assert payload["total"] == 1
    assert payload["successful"] is successful
    assert payload["evaluation_mode"] == "recorded_verdicts"
    assert json.loads(output_path.read_text(encoding="utf-8")) == payload


def test_proof_bundle_eval_cli_empty_input_is_not_successful(tmp_path: Path) -> None:
    cases_path = tmp_path / "empty.jsonl"
    cases_path.write_text("# No observations\n", encoding="utf-8")
    result = _run_cli(str(cases_path))
    assert result.returncode == _INVALID_INPUT_EXIT_CODE
    assert json.loads(result.stdout)["status"] == "empty"
    assert json.loads(result.stdout)["successful"] is False


def test_proof_bundle_eval_cli_invalid_input_is_not_successful(tmp_path: Path) -> None:
    cases_path = tmp_path / "invalid.jsonl"
    cases_path.write_text("[]\n", encoding="utf-8")
    result = _run_cli(str(cases_path))
    assert result.returncode == _INVALID_INPUT_EXIT_CODE
    assert "[proof-bundle-eval:invalid]" in result.stderr
    assert "Traceback" not in result.stderr


def test_proof_bundle_eval_cli_live_verifier_is_explicitly_unavailable(tmp_path: Path) -> None:
    result = _run_cli(str(tmp_path / "missing.jsonl"), "--live-verifier")
    assert result.returncode == _INVALID_INPUT_EXIT_CODE
    assert "live model verification is unavailable" in result.stderr
    assert "Traceback" not in result.stderr


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed local script, no shell.
        [sys.executable, str(_REPO_ROOT / "scripts" / "eval" / "eval_proof_bundles.py"), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
