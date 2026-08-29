from __future__ import annotations

import json
from email.message import Message
from typing import Any

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.attack_surface import merge_surface_state, surface_from_recon
from ravage.probe_suite_parts.sqli.sqli_targets import _sqli_targets
from ravage.web_core.recon import _parse_recon_document


def test_recon_extracts_inline_fetch_json_request_template() -> None:
    html = b"""
    <!doctype html>
    <script>
      const jobType = document.querySelector('#job-type').value;
      fetch('/jobs', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ job_type: jobType })
      });
    </script>
    """

    document = _parse_recon_document("http://localhost:64221/", _HeaderAdapter(_headers()), html)

    assert document.request_templates == [
        {
            "source": "fetch",
            "method": "POST",
            "url": "/jobs",
            "fields": {"job_type": "ravage"},
            "headers": {"Content-Type": "application/json"},
        }
    ]


def test_attack_surface_seeds_request_templates_into_agent_state() -> None:
    surface = surface_from_recon(
        target_url="http://localhost:64221/",
        description="Find the premium job listing",
        recon_payload={
            "origin": "http://localhost:64221",
            "pages": [
                {
                    "url": "http://localhost:64221/",
                    "final_url": "http://localhost:64221/",
                    "forms": [],
                    "links": [],
                    "scripts": [],
                    "cookies": [],
                    "headers": {},
                    "query_parameter_names": [],
                    "interesting_markers": [],
                    "reflected_parameters": [],
                    "request_templates": [
                        {
                            "source": "fetch",
                            "method": "POST",
                            "url": "/jobs",
                            "fields": {"job_type": "ravage"},
                            "headers": {"Content-Type": "application/json"},
                        }
                    ],
                }
            ],
        },
    )

    state = AgentState()
    merge_surface_state(state, surface)

    templates = [json.loads(value) for value in state.signals["request_templates"]]
    targets = _sqli_targets(state)

    counts = surface["counts"]
    assert isinstance(counts, dict)
    assert counts["request_templates"] == 1
    request_templates = surface["request_templates"]
    assert isinstance(request_templates, list)
    assert request_templates
    first_template = request_templates[0]
    assert isinstance(first_template, dict)
    assert first_template["url"] == "http://localhost:64221/jobs"
    assert "job_type" in state.signals["parameters"]
    assert templates[0]["fields"] == {"job_type": "ravage"}
    assert targets[0]["kind"] == "replay"
    assert targets[0]["url"] == "http://localhost:64221/jobs"
    assert targets[0]["input"] == "job_type"


def _headers() -> Message:
    headers = Message()
    headers["Content-Type"] = "text/html; charset=utf-8"
    return headers


class _HeaderAdapter:
    def __init__(self, headers: Message) -> None:
        self._headers = headers

    def get_content_charset(self, failobj: Any = None) -> Any:
        return self._headers.get_content_charset(failobj)

    def get_all(self, name: str, failobj: Any = None) -> Any:
        return self._headers.get_all(name, failobj)

    def items(self) -> Any:
        return self._headers.items()
