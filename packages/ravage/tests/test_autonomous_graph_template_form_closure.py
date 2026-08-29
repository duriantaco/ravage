# ruff: noqa: CPY001, PLR2004

from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.autonomous_graph.adapter import graph_objective_from_frontier
from ravage.agent_core.autonomous_graph.bounded_probe import (
    _graph_probe_handlers,
)
from ravage.agent_core.autonomous_graph.campaigns import (
    campaigns_for_objective,
    initial_stage_for_objective,
)
from ravage.agent_core.autonomous_graph.seed_portfolio import (
    build_seed_portfolio,
)
from ravage.agent_core.autonomous_graph.template_form_closure import (
    PROBE_NAME,
    probe_template_form_closure,
    template_form_contract,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    BaseRouteTermination,
)
from ravage.probe_suite import _probe_handlers
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

TARGET_URL = "http://127.0.0.1:8765/"
FORM_URL = TARGET_URL + "generate"
EXPECTED_PROOF = "flag{graph_template_form_closure}"


def _state(*, attempted_ssti: bool = True) -> AgentState:
    actions: list[dict[str, object]] = []
    if attempted_ssti:
        actions.append(
            {
                "action": "run_probe",
                "probe": "ssti_fingerprint",
                "task_id": "server-rendering",
            }
        )
    return AgentState(
        turn=40,
        actions=actions,
        surface={
            "target_url": TARGET_URL,
            "visible_description": (
                "Generate a preview that repeats submitted text several times."
            ),
            "forms": [
                {
                    "action": FORM_URL,
                    "method": "POST",
                    "inputs": [
                        {
                            "name": "sentence",
                            "type": "text",
                            "required": True,
                            "value": "",
                        },
                        {
                            "name": "number",
                            "type": "number",
                            "required": True,
                            "value": "",
                        },
                    ],
                }
            ],
        },
        tasks=[
            {
                "id": "server-rendering",
                "status": "blocked",
                "priority": 96,
                "attempts": 1,
            }
        ],
    )


def _base() -> BaseRouteOutcome:
    return BaseRouteOutcome(
        target_url=TARGET_URL,
        termination=BaseRouteTermination.REQUEST_BUDGET_EXHAUSTED,
        model_requests=40,
        state_digest="a" * 64,
        state_ref="frozen-state.json",
    )


class _ErbFormSession(ProbeSession):
    def __init__(self) -> None:
        super().__init__(TARGET_URL, timeout_seconds=5)
        self.payloads: list[str] = []

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        payload = fields["sentence"]
        self.payloads.append(payload)
        status = 200
        if payload == "<%= 67*11 %>":
            body = "<p>737</p>"
        elif payload.startswith("<%= process.env"):
            status = 500
            body = "undefined local variable process"
        elif payload.startswith("<%= `"):
            body = f"<p>{EXPECTED_PROOF}</p>"
        else:
            body = f"<p>{payload}</p>"
        return ProbeResponse(
            method="POST",
            url=url,
            status=status,
            final_url=url,
            elapsed_ms=1,
            body=body,
        )


def test_contract_uses_observed_post_form_without_source_or_answer_channel() -> None:
    contract = template_form_contract(_state())

    assert contract is not None
    assert contract.endpoint == FORM_URL
    assert contract.method == "POST"
    assert contract.payload_field == "sentence"
    assert contract.required_fields == ("sentence", "number")
    assert "prior_ssti_attempt" in contract.evidence
    assert EXPECTED_PROOF not in str(contract.to_json())


def test_graph_only_probe_fingerprints_erb_then_extracts_exact_proof() -> None:
    session = _ErbFormSession()

    result = probe_template_form_closure(session, _state())

    assert result.ok is True
    assert result.findings[0]["type"] == "ssti_extracted_proof"
    assert result.findings[0]["proof"] == EXPECTED_PROOF
    assert session.payloads[:2] == [
        "ravagebaseline",
        "<%= 67*11 %>",
    ]
    assert len(session.payloads) <= 4


def test_probe_is_registered_only_for_the_additive_graph_route() -> None:
    assert PROBE_NAME not in _probe_handlers()
    assert PROBE_NAME in _graph_probe_handlers()


def test_seed_portfolio_replaces_broad_ssti_retry_with_bounded_form_closure() -> None:
    portfolio = build_seed_portfolio(_state(), base=_base(), limit=4)

    objective = portfolio.objectives[0]
    assert objective.family == "template_injection"
    assert objective.probe == PROBE_NAME
    assert objective.endpoint == FORM_URL
    assert "sentence" in objective.inputs
    assert all(item.probe != "ssti_fingerprint" for item in portfolio.objectives)
    assert any(
        item.objective.probe == "ssti_fingerprint"
        and item.reason.startswith("bounded_template_closure_supersedes_generic_fingerprint")
        for item in portfolio.suppressed
    )

    graph_objective = graph_objective_from_frontier(
        family=objective.family,
        probe=objective.probe,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=objective.expected_signal,
    )
    campaigns = campaigns_for_objective(
        graph_objective,
        stage=initial_stage_for_objective(graph_objective),
    )
    assert campaigns[0].probe == PROBE_NAME
    assert campaigns[0].dimension == ("preserved_form_template_dialect_and_engine_proof")


def test_unrelated_post_form_is_not_promoted_without_template_evidence() -> None:
    state = _state(attempted_ssti=False)
    state.surface["visible_description"] = "Update an account profile."

    assert template_form_contract(state) is None
