"""Provider identity, accounting, and budget failures must stop paid requests."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from ravage.repository_review import ReviewMessage

from tools.review_quality_gate.client import ExactReviewClient
from tools.review_quality_gate.gate import POLICY_PATH, ROOT, Policy, read_json


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> ExactReviewClient:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-test-key")
    policy = Policy.model_validate(read_json(ROOT / POLICY_PATH))
    return ExactReviewClient(policy, allow_paid_models=True)


def _reply() -> SimpleNamespace:
    return SimpleNamespace(
        response_model="gpt-5.4-2026-03-05",
        content="{}",
        input_tokens=100,
        output_tokens=50,
        cached_input_tokens=0,
        cost_usd=0.001,
        usage_reported=True,
        cost_known=True,
    )


def _complete(client: ExactReviewClient) -> None:
    client.complete(messages=[ReviewMessage(role="user", content="fixture")], route=client.route)


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("response_model", "different-model"),
        ("usage_reported", False),
        ("cost_known", False),
        ("cost_usd", float("nan")),
        ("cost_usd", -1.0),
    ],
)
def test_bad_response_stops_further_calls(
    client: ExactReviewClient, monkeypatch: pytest.MonkeyPatch, attribute: str, value: object
) -> None:
    reply = _reply()
    setattr(reply, attribute, value)
    transport = Mock(return_value=reply)
    monkeypatch.setattr(client.transport, "chat", transport)
    with pytest.raises(RuntimeError):
        _complete(client)
    with pytest.raises(RuntimeError, match="stopped"):
        _complete(client)
    assert transport.call_count == 1
    assert client.verified_calls == 0


def test_transport_error_stops_further_spending(
    client: ExactReviewClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = Mock(side_effect=OSError("provider unavailable"))
    monkeypatch.setattr(client.transport, "chat", transport)
    with pytest.raises(OSError, match="provider unavailable"):
        _complete(client)
    with pytest.raises(RuntimeError, match="stopped"):
        _complete(client)
    assert transport.call_count == 1


def test_insufficient_budget_rejects_before_network(
    client: ExactReviewClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = Mock()
    monkeypatch.setattr(client.transport, "chat", transport)
    client.cost_usd = client.policy.max_cost_usd - 0.0001
    with pytest.raises(RuntimeError, match="budget"):
        _complete(client)
    transport.assert_not_called()


def test_production_messages_are_unchanged_and_usage_is_verified(
    client: ExactReviewClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = Mock(return_value=_reply())
    monkeypatch.setattr(client.transport, "chat", transport)
    _complete(client)
    transport.assert_called_once_with([{"role": "user", "content": "fixture"}])
    assert client.calls == client.verified_calls == 1
    assert client.route.max_retries == 0


def test_wrong_route_is_rejected_before_network(
    client: ExactReviewClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = Mock()
    monkeypatch.setattr(client.transport, "chat", transport)
    with pytest.raises(ValueError, match="route changed"):
        client.complete(messages=[], route=replace(client.route, model="another-model"))
    transport.assert_not_called()


def test_paid_opt_in_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    policy = Policy.model_validate(read_json(ROOT / POLICY_PATH))
    with pytest.raises(ValueError, match="allow-paid-models"):
        ExactReviewClient(policy, allow_paid_models=False)


def test_missing_credentials_never_select_a_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    policy = Policy.model_validate(read_json(ROOT / POLICY_PATH))
    with pytest.raises(ValueError, match="pinned native"):
        ExactReviewClient(policy, allow_paid_models=True)
