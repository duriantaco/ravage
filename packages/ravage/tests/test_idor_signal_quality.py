from __future__ import annotations

import pytest
from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists.idor_signals import _idor_access_signal
from ravage.probes.specialists.idor_targets import _idor_targets
from ravage.web_core.http_probe import ProbeResponse


def _response(
    body: str,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url="http://127.0.0.1/resource",
        status=status,
        final_url="http://127.0.0.1/resource",
        elapsed_ms=5,
        body=body,
        headers=headers or {},
    )


@pytest.mark.parametrize(
    ("baseline_body", "response_body"),
    [
        ('{"results":["apple"]}', '{"results":["admin"]}'),
        ("<p>Search: apple</p>", "<p>Search: admin</p>"),
    ],
)
def test_idor_signal_rejects_pure_identifier_reflection(
    baseline_body: str,
    response_body: str,
) -> None:
    signal = _idor_access_signal(
        baseline=_response(baseline_body),
        response=_response(response_body),
        original_id="apple",
        candidate_id="admin",
    )

    assert signal == {}


def test_idor_signal_keeps_meaningful_object_delta() -> None:
    signal = _idor_access_signal(
        baseline=_response('{"id":"10","owner":"alice","data":"mine"}'),
        response=_response('{"id":"9","owner":"bob","data":"private"}'),
        original_id="10",
        candidate_id="9",
    )

    assert signal["kind"] == "object_access_delta"


def test_idor_signal_keeps_proof_from_other_object() -> None:
    signal = _idor_access_signal(
        baseline=_response('{"id":"10"}'),
        response=_response('{"id":"9","proof":"flag{other_object}"}'),
        original_id="10",
        candidate_id="9",
    )

    assert signal["kind"] == "proof_or_secret"


def test_idor_signal_keeps_cookie_identity_delta() -> None:
    signal = _idor_access_signal(
        baseline=_response(
            '{"id":"10"}',
            status=302,
            headers={"Set-Cookie": "session=owner-10; Path=/"},
        ),
        response=_response(
            '{"id":"9"}',
            status=302,
            headers={"Set-Cookie": "session=owner-9; Path=/"},
        ),
        original_id="10",
        candidate_id="9",
    )

    assert signal["kind"] == "auth_cookie_identity_delta"


def test_idor_targets_require_context_for_username_like_values() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/search?q=apple",
        "origin": "http://127.0.0.1",
        "parameters": [
            {
                "name": "q",
                "locations": ["http://127.0.0.1/search?q=apple"],
                "value": "apple",
            },
            {
                "name": "q",
                "locations": ["http://127.0.0.1/search?q=42"],
                "value": "42",
            },
            {
                "name": "user_id",
                "locations": ["http://127.0.0.1/profile?user_id=alice"],
                "value": "alice",
            },
            {
                "name": "account",
                "locations": ["http://127.0.0.1/settings?account=primary"],
                "value": "primary",
            },
        ],
        "forms": [
            {
                "action": "http://127.0.0.1/search",
                "method": "GET",
                "inputs": [{"name": "q", "type": "text", "value": "apple"}],
            }
        ],
        "endpoints": [
            {"url": "http://127.0.0.1/search?q=apple"},
            {"url": "http://127.0.0.1/search?q=42"},
            {"url": "http://127.0.0.1/profile?user_id=alice"},
            {"url": "http://127.0.0.1/settings?account=primary"},
        ],
    }

    targets = _idor_targets(state)
    target_keys = {
        (str(target.get("input")), str(target.get("baseline_id"))) for target in targets
    }

    assert ("q", "apple") not in target_keys
    assert ("q", "42") in target_keys
    assert ("user_id", "alice") in target_keys
    assert ("account", "primary") in target_keys
