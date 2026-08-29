from __future__ import annotations

from ravage.probes.specialists.specialists import _jinja_ssti_payloads, _ssti_extraction_payloads
from ravage.probes.specialists.ssti import _filtered_numeric_prefix_is_meaningful


def test_jinja_payloads_dump_flask_config_before_rce() -> None:
    payloads = _jinja_ssti_payloads()
    assert "{{config}}" in payloads
    assert "{{config.items()}}" in payloads
    config_index = payloads.index("{{config}}")
    first_rce = next(i for i, p in enumerate(payloads) if "popen(" in p)
    assert config_index < first_rce


def test_jinja_payloads_include_no_shell_env_dump() -> None:
    payloads = _jinja_ssti_payloads()
    assert any("environ" in p and "popen(" not in p for p in payloads)
    assert "{{url_for.__globals__.os.environ}}" in payloads


def test_extraction_payloads_surface_config_for_jinja_engines() -> None:
    payloads = _ssti_extraction_payloads(["jinja2"])
    assert "{{config}}" in payloads
    assert any("request.application.__globals__.__builtins__.__import__" in p for p in payloads)


def test_filtered_numeric_ssti_rejects_static_html_number_fill() -> None:
    assert not _filtered_numeric_prefix_is_meaningful("dddddddddddddddd")
    assert _filtered_numeric_prefix_is_meaningful("flag{partial")
    assert _filtered_numeric_prefix_is_meaningful("abc123_token")
