from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import parse_qs, urlencode, urlsplit

from ravage import probe_suite
from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite import available_probes, run_builtin_probe
from ravage.web_core.http_probe import ProbeResponse

if TYPE_CHECKING:
    import pytest
    from ravage.probe_suite_parts.result import ProbeRunResult

_PROOF = "flag{bounded_filter_constraint_probe}"
_BOUNDARY_SAMPLE_COUNT = 3


class _TagBoundarySession:
    seen: ClassVar[list[tuple[str, dict[str, str]]]] = []

    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.timeout_seconds = timeout_seconds
        type(self).seen = []

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        fields = {key: values[-1] for key, values in parse_qs(urlsplit(url).query).items()}
        return self._response("GET", url, fields)

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        encoded_url = f"{url}?{urlencode(fields)}"
        return self._response("POST", encoded_url, fields)

    def _response(
        self,
        method: str,
        url: str,
        fields: dict[str, str],
    ) -> ProbeResponse:
        type(self).seen.append((method, dict(fields)))
        value = fields.get("name") or fields.get("solution") or ""
        if value.startswith("<z ") and 'alert("XSS")' in value:
            body = f"Congratulations. Here is the flag: {_PROOF}"
        elif value.startswith("<"):
            body = "Sorry, you can't use that tag"
        else:
            body = "Try a reflected value"
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=5,
            body=body,
        )


class _AlwaysBlockedSession(_TagBoundarySession):
    def _response(
        self,
        method: str,
        url: str,
        fields: dict[str, str],
    ) -> ProbeResponse:
        type(self).seen.append((method, dict(fields)))
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=5,
            body="Sorry, you can't use that tag",
        )


def _state_with_context(*, post: bool = False) -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/page",
        "origin": "http://127.0.0.1",
        "visible_description": (
            "Execute XSS with the exact string 'XSS', for example alert('XSS')."
        ),
        "parameters": [],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/page"}],
        "reflections": [],
    }
    if post:
        form = {
            "id": "proof-form",
            "action": "http://127.0.0.1/page",
            "method": "POST",
            "inputs": [
                {"name": "csrf", "type": "hidden", "value": "preserve-me"},
                {"name": "solution", "type": "text", "value": ""},
            ],
        }
        state.surface["forms"] = [form]
        context = {
            "url": "http://127.0.0.1/page",
            "input": "solution",
            "context": "html_body",
            "kind": "form",
            "method": "POST",
            "form": form,
        }
    else:
        context = {
            "url": "http://127.0.0.1/page",
            "input": "name",
            "context": "html_body",
            "kind": "query_param",
        }
    state.signals["xss_contexts"] = [json.dumps(context, sort_keys=True)]
    return state


def _run(state: AgentState) -> ProbeRunResult:
    return run_builtin_probe(
        "xss_filter_constraint",
        target_url="http://127.0.0.1/page",
        state=state,
    )


def _variant_values(result: ProbeRunResult) -> list[str]:
    requests = result.requests
    return [
        str(request["value"])
        for request in requests
        if request.get("probe_kind") == "xss_filter_constraint_variant"
    ]


def test_xss_filter_constraint_is_an_available_probe() -> None:
    assert "xss_filter_constraint" in {item["name"] for item in available_probes()}


def test_probe_mutates_only_tag_boundary_and_stops_on_target_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _TagBoundarySession)

    result = _run(_state_with_context())

    assert result.ok
    assert _variant_values(result) == [
        '<x autofocus tabindex=1 onfocus=alert("XSS")>',
        '<y autofocus tabindex=1 onfocus=alert("XSS")>',
        '<z autofocus tabindex=1 onfocus=alert("XSS")>',
    ]
    assert result.findings[0]["type"] == "xss_filter_constraint_proof"
    assert _PROOF in result.findings[0]["proofs"]
    assert len(_TagBoundarySession.seen) == _BOUNDARY_SAMPLE_COUNT


def test_probe_preserves_post_method_and_companion_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _TagBoundarySession)

    result = _run(_state_with_context(post=True))

    assert result.ok
    assert [method for method, _ in _TagBoundarySession.seen] == ["POST"] * 3
    assert all(fields.get("csrf") == "preserve-me" for _, fields in _TagBoundarySession.seen)


def test_probe_is_bounded_when_every_boundary_sample_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _AlwaysBlockedSession)

    result = _run(_state_with_context())

    assert not result.ok
    assert len(_variant_values(result)) == _BOUNDARY_SAMPLE_COUNT
    assert len(_AlwaysBlockedSession.seen) == _BOUNDARY_SAMPLE_COUNT
    assert "exhausted" in result.summary
    assert result.findings == []


def test_probe_accepts_exact_recon_confirmed_reflection_when_context_probe_timed_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _TagBoundarySession)
    state = _state_with_context()
    state.signals["xss_contexts"] = []
    state.surface["reflections"] = [
        {
            "name": "name",
            "page": "http://127.0.0.1/page",
            "source": "form",
            "url": "http://127.0.0.1/page?name=<recon-marker>",
        }
    ]
    state.surface["forms"] = [
        {
            "action": "http://127.0.0.1/page",
            "method": "GET",
            "inputs": [{"name": "name", "type": "text", "value": ""}],
        }
    ]

    result = _run(state)

    assert result.ok
    assert len(_TagBoundarySession.seen) == _BOUNDARY_SAMPLE_COUNT
    assert _PROOF in result.findings[0]["proofs"]


def test_probe_requires_target_observed_context_and_exact_dialog_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _TagBoundarySession)
    without_context = _state_with_context()
    without_context.signals["xss_contexts"] = []

    context_result = _run(without_context)

    assert not context_result.ok
    assert context_result.requests == []
    assert _TagBoundarySession.seen == []

    without_value = _state_with_context()
    without_value.surface["visible_description"] = "Test the reflected HTML input."

    value_result = _run(without_value)

    assert not value_result.ok
    assert value_result.requests == []
    assert _TagBoundarySession.seen == []
