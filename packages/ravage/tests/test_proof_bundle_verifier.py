from __future__ import annotations

import pytest
from pentest_schemas import ProofBundle
from ravage.proof_bundle_verifier import proof_bundle_verifier_payload


def _bundle(*, response: str = "name=Bob account_id=11") -> ProofBundle:
    return ProofBundle.model_validate(
        {
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
                        "response_snippet": response,
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
                "verdict": "accepted",
                "confidence": "high",
                "rationale": "The same session saw data for a different account.",
                "impact": "Unauthorized cross-account data exposure.",
            },
        }
    )


def test_proof_bundle_verifier_payload_excludes_existing_verdict() -> None:
    payload = proof_bundle_verifier_payload(_bundle())

    assert "verifier" not in payload


def test_proof_bundle_verifier_payload_rejects_benchmark_flags() -> None:
    with pytest.raises(ValueError, match="must not contain benchmark flags"):
        proof_bundle_verifier_payload(_bundle(response="flag{benchmark-answer}"))
