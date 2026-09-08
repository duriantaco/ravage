from __future__ import annotations

from dataclasses import replace

import pytest
from ravage.agent_core.ai_agent import ModelReply

from tools.source_navigation_eval import provider

REPLY_COST_USD = 0.01


def test_paid_driver_requires_explicit_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="allow-paid-models"):
        provider.GPT54Driver(allow_paid_models=False, budget=provider.ModelBudget(1.0))


@pytest.mark.parametrize(
    "changes",
    [
        {"model": "gpt-5.4"},
        {"reasoning_effort": "low"},
        {"base_url": "http://localhost:11434/v1"},
        {"output_token_limit_parameter": "none"},
    ],
)
def test_paid_driver_rejects_a_changed_model_contract(
    monkeypatch: pytest.MonkeyPatch, changes: dict[str, object]
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    route = provider.resolve_model_routes(
        provider.load_model_registry(), profile_name="hosted-openai-gpt-5.4-high", tier="high"
    )[0]
    monkeypatch.setattr(
        provider, "resolve_model_routes", lambda _registry, **_kwargs: [replace(route, **changes)]
    )
    with pytest.raises(ValueError, match=r"exact GPT-5\.4 high"):
        provider.GPT54Driver(allow_paid_models=True, budget=provider.ModelBudget(1.0))


@pytest.mark.parametrize("ceiling", [float("nan"), float("inf"), 0.0, -1.0, 11.0])
def test_model_budget_rejects_invalid_limits(ceiling: float) -> None:
    with pytest.raises(ValueError, match="budget"):
        provider.ModelBudget(ceiling)


@pytest.mark.parametrize("model", [provider.EXACT_MODEL, "different-model"])
def test_paid_adapter_attests_exact_response_and_accounts_calls(
    monkeypatch: pytest.MonkeyPatch, model: str
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class StubClient:
        def __init__(self, route: object) -> None:
            self.route = route

        def chat(self, _messages: list[dict[str, str]]) -> ModelReply:
            return ModelReply(
                content='{"action":"finish"}',
                input_tokens=100,
                output_tokens=10,
                cost_usd=REPLY_COST_USD,
                cost_known=True,
                usage_reported=True,
                response_model=model,
            )

    monkeypatch.setattr(provider, "ChatClient", StubClient)
    driver = provider.GPT54Driver(allow_paid_models=True, budget=provider.ModelBudget(1.0))
    if model == provider.EXACT_MODEL:
        assert driver.action({}) == {"action": "finish"}
    else:
        with pytest.raises(RuntimeError, match="identity"):
            driver.action({})
    assert driver.usage()["model_calls"] == 1
    assert driver.usage()["cost_usd"] == REPLY_COST_USD


def test_paid_budget_stops_before_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    driver = provider.GPT54Driver(allow_paid_models=True, budget=provider.ModelBudget(0.000001))

    def unexpected_call(_messages: list[dict[str, str]]) -> ModelReply:
        pytest.fail("a request was sent before the budget gate")

    monkeypatch.setattr(driver.client, "chat", unexpected_call)
    with pytest.raises(RuntimeError, match="remaining budget"):
        driver.action({})
    assert driver.usage()["model_calls"] == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"usage_reported": False},
        {"cost_known": False},
        {"cost_usd": float("nan")},
    ],
)
def test_incomplete_accounting_is_a_failure(
    monkeypatch: pytest.MonkeyPatch, changes: dict[str, object]
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    driver = provider.GPT54Driver(allow_paid_models=True, budget=provider.ModelBudget(1.0))
    reply = ModelReply(
        content='{"action":"finish"}',
        input_tokens=100,
        output_tokens=10,
        cost_usd=REPLY_COST_USD,
        cost_known=True,
        usage_reported=True,
        response_model=provider.EXACT_MODEL,
    )
    monkeypatch.setattr(driver.client, "chat", lambda _messages: replace(reply, **changes))
    with pytest.raises(RuntimeError, match="incomplete usage"):
        driver.action({})
    assert driver.usage()["model_calls"] == 1
    assert not driver.usage()["accounting_complete"]


def test_budget_is_shared_between_arms(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    budget = provider.ModelBudget(1.0)
    first = provider.GPT54Driver(allow_paid_models=True, budget=budget)
    second = provider.GPT54Driver(allow_paid_models=True, budget=budget)
    reply = ModelReply(
        content='{"action":"finish"}',
        input_tokens=100,
        output_tokens=10,
        cost_usd=1.0,
        cost_known=True,
        usage_reported=True,
        response_model=provider.EXACT_MODEL,
    )
    monkeypatch.setattr(first.client, "chat", lambda _messages: reply)

    def unexpected_call(_messages: list[dict[str, str]]) -> ModelReply:
        pytest.fail("a second arm ignored the aggregate budget")

    monkeypatch.setattr(second.client, "chat", unexpected_call)
    first.action({})
    with pytest.raises(RuntimeError, match="remaining budget"):
        second.action({})
    assert second.usage()["model_calls"] == 0
