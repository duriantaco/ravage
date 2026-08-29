from __future__ import annotations

from ravage.proof_bundle import accepted_proof_bundle_failures


def _http(
    *,
    method: str = "GET",
    path: str,
    request: str,
    status: int = 200,
    response: str,
) -> dict[str, object]:
    return {
        "method": method,
        "url": f"http://127.0.0.1:8765{path}",
        "request": request,
        "response_status": status,
        "response_snippet": response,
    }


def _base_bundle() -> dict[str, object]:
    return {
        "bundle_id": "bundle-1",
        "title": "Unauthorized record access",
        "hypothesis": "Changing an object identifier exposes another account record.",
        "scope": {"in_scope": ["http://127.0.0.1:8765"], "out_of_scope": []},
        "target_origin": "http://127.0.0.1:8765",
        "vuln_class": "idor",
        "identities": [
            {
                "label": "attacker",
                "actor_kind": "attacker",
                "role": "customer",
                "stable_identifiers": {"account_id": "10"},
            }
        ],
        "steps": [
            {
                "step_id": "baseline",
                "kind": "baseline",
                "description": "Read the attacker's own profile.",
                "actor": "attacker",
                "http": _http(
                    path="/profile/10",
                    request="GET /profile/10 HTTP/1.1",
                    response="name=Alice account_id=10",
                ),
                "observation": "The baseline response shows the attacker's own account.",
            },
            {
                "step_id": "mutation",
                "kind": "mutation",
                "description": "Replay the same session with a different profile identifier.",
                "actor": "attacker",
                "http": _http(
                    path="/profile/11",
                    request="GET /profile/11 HTTP/1.1",
                    response="name=Bob account_id=11",
                ),
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
            "rationale": "The same session saw data for a different account after one mutation.",
            "impact": "Unauthorized cross-account data exposure.",
        },
    }


def test_accepted_proof_bundle_accepts_idor_pair_shape() -> None:
    assert accepted_proof_bundle_failures(_base_bundle()) == ()


def test_accepted_proof_bundle_accepts_multi_step_provenance_shape() -> None:
    bundle = _base_bundle()
    bundle["title"] = "Stored workflow input is rendered later"
    bundle["vuln_class"] = "ssti"
    bundle["steps"] = [
        {
            "step_id": "write-input",
            "kind": "setup",
            "description": "Submit a marker through a workflow form.",
            "actor": "attacker",
            "http": _http(
                method="POST",
                path="/wizard/start",
                request="POST /wizard/start HTTP/1.1\n\nmarker=rv-proof-123",
                response="next step",
            ),
            "observation": "The application accepted the marker and advanced the workflow.",
        },
        {
            "step_id": "continue-workflow",
            "kind": "trigger",
            "description": "Complete the intermediate workflow step.",
            "actor": "attacker",
            "http": _http(
                method="POST",
                path="/wizard/continue",
                request="POST /wizard/continue HTTP/1.1",
                response="review ready",
            ),
            "observation": "The session advanced to the review step.",
        },
        {
            "step_id": "observe-output",
            "kind": "observation",
            "description": "Read the later workflow page that renders stored state.",
            "actor": "attacker",
            "http": _http(
                path="/wizard/review",
                request="GET /wizard/review HTTP/1.1",
                response="rendered greeting rv-proof-123",
            ),
            "observation": "The marker submitted earlier was rendered later.",
        },
    ]
    bundle["provenance"] = [
        {
            "source_step_id": "write-input",
            "source_value": "rv-proof-123",
            "observed_step_id": "observe-output",
            "observed_value": "rv-proof-123",
            "relation": "stored workflow input was rendered on the later page",
        }
    ]
    bundle["controls"] = [
        {
            "control_id": "marker-control",
            "kind": "negative",
            "step_ids": ["observe-output"],
            "expected_result": "A fresh session without the marker does not show it.",
            "observed_result": "The marker appeared only after the write-input step.",
            "passed": True,
        }
    ]

    assert accepted_proof_bundle_failures(bundle) == ()


def test_accepted_proof_bundle_rejects_nonaccepted_verdict() -> None:
    bundle = _base_bundle()
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    verifier["verdict"] = "inconclusive"

    failures = accepted_proof_bundle_failures(bundle)

    assert "proof_bundle.verifier.verdict must be accepted" in failures


def test_accepted_proof_bundle_rejects_unknown_provenance_step() -> None:
    bundle = _base_bundle()
    provenance = bundle["provenance"]
    assert isinstance(provenance, list)
    link = provenance[0]
    assert isinstance(link, dict)
    link["observed_step_id"] = "missing"

    failures = accepted_proof_bundle_failures(bundle)

    assert "proof_bundle.provenance[0].observed_step_id references unknown step" in failures


def test_accepted_proof_bundle_rejects_unpassed_controls() -> None:
    bundle = _base_bundle()
    controls = bundle["controls"]
    assert isinstance(controls, list)
    control = controls[0]
    assert isinstance(control, dict)
    control["passed"] = False

    failures = accepted_proof_bundle_failures(bundle)

    assert "proof_bundle.controls must include at least one passed control" in failures
