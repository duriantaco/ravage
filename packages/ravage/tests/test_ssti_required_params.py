from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlsplit

from ravage import probe_suite
from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists.ssti import _ssti_expression_targets
from ravage.web_core.http_probe import ProbeResponse
from ravage.probe_suite import run_builtin_probe

_FLAG = "flag{ssti_loan_calc_required_params_7c2a}"


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
        del fields, headers
        return self.request("POST", url)

    def request(self, method: str, url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None) -> ProbeResponse:
        del data, headers
        return self._response(method, url)

    def _response(self, method: str, url: str) -> ProbeResponse:
        raise NotImplementedError


class _LoanCalcRequiredParamsSession(_BaseFakeSession):
    """Calculator endpoint: rejects a single-parameter probe, renders Jinja once
    the sibling parameters are supplied, and is therefore SSTI-injectable."""

    def _response(self, method: str, url: str) -> ProbeResponse:
        query = parse_qs(urlsplit(url).query)
        principal = query.get("principal", [""])[0]
        if "payment" not in query or "term" not in query:
            return ProbeResponse(
                method=method,
                url=url,
                status=400,
                final_url=url,
                elapsed_ms=5,
                body="Missing principal, payment or term parameters",
            )
        rendered = principal.replace("{{7*7}}", "49")
        if any(gadget in principal for gadget in ("config", "globals", "popen", "cycler", "lipsum")):
            rendered = _FLAG
        body = '{ "loan_principal": "%s", "monthly_payment": "1", "loan_term_amount": "1" }' % rendered
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)


class _FilteredNumericJinjaLoanSession(_BaseFakeSession):
    """Benchmark-style filtered JSON template sink with numeric-only output."""

    def _response(self, method: str, url: str) -> ProbeResponse:
        query = parse_qs(urlsplit(url).query)
        principal = query.get("principal", [""])[0]
        payment = query.get("payment", [""])[0]
        term = query.get("term", [""])[0]
        if not principal or not payment or not term:
            return ProbeResponse(
                method=method,
                url=url,
                status=400,
                final_url=url,
                elapsed_ms=5,
                body="Missing principal, payment or term parameters",
            )
        if any(marker in principal for marker in ("{{", "}}", "[", "]", "_", ".")):
            return ProbeResponse(
                method=method,
                url=url,
                status=400,
                final_url=url,
                elapsed_ms=5,
                body="GET parameter `principal` contains forbidden characters.",
            )
        if not _looks_number(payment) or not _looks_number(term):
            return ProbeResponse(
                method=method,
                url=url,
                status=400,
                final_url=url,
                elapsed_ms=5,
                body="Missing principal, payment or term parameters",
            )

        rendered = self._render_principal(principal)
        if re.match(r"^[0-9.]*$", rendered) is None:
            return ProbeResponse(
                method=method,
                url=url,
                status=400,
                final_url=url,
                elapsed_ms=5,
                body="Computed `loan_principal` value is not a number.",
            )
        body = (
            '{ "loan_principal": "%s", '
            '"monthly_payment": "%s", '
            '"loan_term_amount": "%s", '
            '"total_loan_payments": "%s" }'
        ) % (rendered, payment, term, int(float(payment)) * int(term))
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)

    def _render_principal(self, principal: str) -> str:
        if principal == "{% print 7*7 %}":
            return "49"
        if principal == "{% if 7*7 == 49 %}49{% endif %}":
            return "49"
        if principal == "{% print 6*7 %}":
            return "42"
        if principal == "{% if 6*7 == 42 %}42{% endif %}":
            return "42"
        if principal.startswith("{% print ") and "head -c" in principal:
            return str(_filtered_numeric_flag_ordinal(principal))
        return principal


class _UsernameJinjaSession(_BaseFakeSession):
    """FastAPI/Jinja-style root handler with a username query sink.

    The route mirrors a bare ``jinja2.Environment().from_string(...)`` context:
    harmless arithmetic evaluates, Flask-only globals are absent, and pure Jinja
    globals such as ``cycler``/``joiner``/``namespace`` can reach command output.
    """

    def _response(self, method: str, url: str) -> ProbeResponse:
        query = parse_qs(urlsplit(url).query)
        username = query.get("username", [""])[0]
        if not username:
            body = (
                "<h2>You can call this URL with a username querystring parameter, "
                "anything you put there will be shown on the page.</h2>"
                "<pre>app/\n    main.py\n    flag.txt\n    templates/</pre>"
            )
            return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)
        if username == "{{7*7}}":
            rendered = "49"
        elif any(marker in username for marker in ("cycler", "joiner", "namespace", "lipsum")) and "popen" in username:
            rendered = _USERNAME_FLAG
        else:
            rendered = username
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=5,
            body=f"Welcome {rendered}!",
        )


class _AuthenticatedReminderJinjaSession(_BaseFakeSession):
    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        if urlsplit(url).path == "/remind" and (headers or {}).get("Cookie") != "session=valid":
            return ProbeResponse(
                method="GET",
                url=url,
                status=302,
                final_url=url,
                elapsed_ms=5,
                body="Redirecting to /login",
            )
        return self.request("GET", url, headers=headers)

    def _response(self, method: str, url: str) -> ProbeResponse:
        query = parse_qs(urlsplit(url).query)
        date = query.get("date", [""])[0]
        if date in {"{{7*7}}", "{% print 7*7 %}", "{% if 7*7 == 49 %}49{% endif %}"}:
            rendered = "49"
        elif date in {"{% print 6*7 %}", "{% if 6*7 == 42 %}42{% endif %}"}:
            rendered = "42"
        elif any(marker in date for marker in ("cycler", "joiner", "namespace", "lipsum")) and "popen" in date:
            rendered = _REMINDER_FLAG
        else:
            rendered = date
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=5,
            body=f"Reminder will be sent on {rendered}",
        )


def _filtered_numeric_flag_ordinal(payload: str) -> int:
    match = re.search(r"head -c (\d+)", payload)
    if match is None:
        return 0
    position = int(match.group(1)) - 1
    if position < 0 or position >= len(_FLAG):
        return 0
    return ord(_FLAG[position])


def _looks_number(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


_USERNAME_FLAG = "flag{ssti_username_openapi_signal_9c6d}"
_REMINDER_FLAG = "flag{ssti_reminder_date_signal_3c58}"


def _state_with_calculator_param() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/total_loan_payments",
        "origin": "http://127.0.0.1",
        "parameters": [
            {
                "name": "principal",
                "locations": ["http://127.0.0.1/total_loan_payments?principal=ravage"],
                "hints": ["reflected", "structured"],
                "priority": 80,
            }
        ],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/total_loan_payments?principal=ravage"}],
    }
    return state


def _state_with_ajax_calculator_signal() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [],
    }
    state.signals["auth_headers"] = ["Cookie: session=valid"]
    state.signals["endpoints"] = [
        "/total_loan_payments?principal=1&payment=1&term=1",
    ]
    return state


def _state_with_authenticated_reminder_signal() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [],
    }
    state.signals["auth_headers"] = ["Cookie: session=valid"]
    state.signals["endpoints"] = ["/transactions", "/add_transaction", "/remind?date=2026-07-10"]
    state.signals["parameters"] = ["date"]
    state.signals["markers"] = ["authenticated session", "reminder", "template"]
    return state


def _state_with_noisy_username_signal() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/"}],
    }
    state.signals["parameters"] = ["page", "name", "q", "query", "username"]
    state.signals["endpoints"] = [
        "http://127.0.0.1/?page=XSS0d8dd0d1",
        "http://127.0.0.1/?name=XSSeb35ebc9&page=%22%3E%3Csvg+onload%3Dprompt%28%27XSS%27%29%3E",
        "http://127.0.0.1/",
    ]
    state.signals["forms"] = [
        json.dumps(
            {
                "action": "http://127.0.0.1/?username=ravage",
                "categories": ["api", "openapi"],
                "enctype": "application/x-www-form-urlencoded",
                "id": "openapi:GET:http://127.0.0.1/",
                "inputs": [{"name": "username", "type": "string"}],
                "method": "GET",
            }
        )
    ]
    state.signals["markers"] = ["template", "jinja"]
    return state


def _state_with_generated_username_endpoint_only() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/"}],
    }
    state.signals["parameters"] = ["name", "username"]
    state.signals["endpoints"] = [
        "http://127.0.0.1/?username=%3Cdetails+open+ontoggle%3Dconfirm%28%27XSS%27%29%3E",
        "http://127.0.0.1/",
    ]
    state.signals["markers"] = ["template", "jinja"]
    return state


def test_ssti_missing_param_recovery_skips_when_no_validation_error(monkeypatch) -> None:
    class _PlainReflectionSession(_BaseFakeSession):
        def _response(self, method: str, url: str) -> ProbeResponse:
            principal = parse_qs(urlsplit(url).query).get("principal", [""])[0]
            return ProbeResponse(
                method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=f"value={principal}"
            )

    monkeypatch.setattr(probe_suite, "ProbeSession", _PlainReflectionSession)

    result = run_builtin_probe(
        "ssti_fingerprint", target_url="http://127.0.0.1/total_loan_payments", state=_state_with_calculator_param()
    )

    assert not any(r.get("probe_kind") == "baseline_supplemented" for r in result.requests)


def test_ssti_prioritizes_openapi_username_over_generated_probe_urls(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _UsernameJinjaSession)

    result = run_builtin_probe(
        "ssti_fingerprint",
        target_url="http://127.0.0.1/",
        state=_state_with_noisy_username_signal(),
    )

    assert result.ok
    assert result.findings[0]["type"] == "ssti_extracted_proof"
    proofs = result.findings[0]["proofs"]
    assert isinstance(proofs, list)
    assert _USERNAME_FLAG in proofs
    first_baseline = next(r for r in result.requests if r.get("probe_kind") == "baseline")
    target = first_baseline["target"]
    assert isinstance(target, dict)
    assert target["input"] == "username"


def test_ssti_does_not_post_generated_username_query_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _UsernameJinjaSession)

    result = run_builtin_probe(
        "ssti_fingerprint",
        target_url="http://127.0.0.1/",
        state=_state_with_generated_username_endpoint_only(),
    )

    assert result.ok
    proofs = result.findings[0]["proofs"]
    assert isinstance(proofs, list)
    assert _USERNAME_FLAG in proofs
    assert not any(
        _is_generated_username_post(request)
        for request in result.requests
    )


def test_ssti_uses_auth_cookie_for_reminder_date_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _AuthenticatedReminderJinjaSession)

    result = run_builtin_probe(
        "ssti_fingerprint",
        target_url="http://127.0.0.1/",
        state=_state_with_authenticated_reminder_signal(),
    )

    assert result.ok
    assert result.findings[0]["type"] == "ssti_extracted_proof"
    proofs = result.findings[0]["proofs"]
    assert isinstance(proofs, list)
    assert _REMINDER_FLAG in proofs
    first_baseline = next(
        r for r in result.requests if r.get("probe_kind") == "ssti_expression_baseline"
    )
    target = first_baseline["target"]
    assert isinstance(target, dict)
    assert target["input"] == "date"
    assert target["authenticated"] is True


def test_visible_reminder_description_seeds_authenticated_date_target() -> None:
    state = AgentState()
    state.surface["visible_description"] = (
        "Users log in to view transactions and set reminders for debts."
    )
    state.signals = {"cookies": ["session=valid"]}

    targets = _ssti_expression_targets(state, [])

    reminder = next(
        target
        for target in targets
        if str(target.get("url", "")).startswith("/remind?")
        and target.get("input") == "date"
    )
    assert reminder["auth_headers"] == {"Cookie": "session=valid"}
    url = reminder["url"]
    assert isinstance(url, str)
    assert "date=2" in url


def _is_generated_username_post(request: dict[str, object]) -> bool:
    target = request.get("target")
    return (
        isinstance(target, dict)
        and target.get("kind") == "heuristic_post"
        and target.get("input") == "username"
    )
