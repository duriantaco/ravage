from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from ravage.agent_core.agent_state import AgentState, save_agent_state
from ravage.probes.api_authorization import inventory_api_authorization

_ARGPARSE_ERROR = 2
_EXPECTED_DISTINCT_ROUTES = 2


def test_inventory_finds_api_write_shape_without_values_or_network() -> None:
    state = AgentState(
        surface={
            "request_templates": [
                {
                    "source": "fetch",
                    "method": "PATCH",
                    "url": "http://127.0.0.1:8000/api/profile?token=do-not-record",
                    "fields": {
                        "displayName": "Alice",
                        "isAdmin": "true",
                        "tenantId": "tenant-secret",
                        "price": "0",
                    },
                    "headers": {"Authorization": "Bearer do-not-record"},
                }
            ]
        }
    )

    inventory = inventory_api_authorization(state)

    assert inventory["schema"] == "ravage.api_authorization_inventory.v1"
    assert inventory["candidate_only"] is True
    assert inventory["network_requests"] == 0
    assert inventory["mutation_attempts"] == 0
    assert inventory["confirmed_vulnerabilities"] == 0
    candidate = _candidates(inventory)[0]
    assert candidate["kind"] == "mass_assignment_review"
    assert candidate["verification_status"] == "unverified_candidate"
    assert candidate["authorization_fields"] == ["is_admin", "tenant_id"]
    assert candidate["business_control_fields"] == ["price"]
    route = _mapping(candidate["route"])
    assert route["path_shape"] == "/api/profile"
    assert route["query_keys"] == ["token"]
    assert route["route_ref"] == "route-0001"
    assert "_route_identity" not in json.dumps(inventory)
    serialized = json.dumps(inventory)
    assert "do-not-record" not in serialized
    assert "tenant-secret" not in serialized
    assert "Bearer" not in serialized


def test_inventory_requires_api_shape_and_exact_control_field_names() -> None:
    state = AgentState(
        surface={
            "request_templates": [
                {
                    "source": "fetch",
                    "method": "POST",
                    "url": "/contact",
                    "fields": {"status": "new"},
                },
                {
                    "source": "fetch",
                    "method": "POST",
                    "url": "/api/profile",
                    "fields": {
                        "role_description": "operator",
                        "admin_note": "reviewed",
                        "price_label": "retail",
                    },
                },
            ]
        }
    )

    inventory = inventory_api_authorization(state)

    assert _candidates(inventory) == []
    assert _summary(inventory)["candidate_count"] == 0


def test_inventory_normalizes_acronyms_nested_fields_and_deduplicates() -> None:
    first = {
        "source": "fetch",
        "method": "PATCH",
        "url": "/api/users/17",
        "fields": {
            "ROLE": "member",
            "userID": "17",
            "payload.tenantID": "1",
            "user[role]": "member",
            "isADMIN": False,
        },
    }
    second = {
        "source": "xhr",
        "method": "PATCH",
        "url": "/api/users/17",
        "fields": {
            "isADMIN": False,
            "user[role]": "member",
            "payload.tenantID": "1",
            "userID": "17",
            "ROLE": "member",
        },
    }
    state = AgentState(surface={"request_templates": [first, second]})

    inventory = inventory_api_authorization(state)

    candidates = _candidates(inventory)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["authorization_fields"] == [
        "is_admin",
        "role",
        "tenant_id",
        "user_id",
    ]
    assert candidate["sources"] == ["fetch", "xhr"]
    route = _mapping(candidate["route"])
    assert route["path_shape"] == "/api/users/{dynamic}"
    assert route["query_keys"] == []


def test_inventory_reads_nested_json_keys_without_emitting_nested_values() -> None:
    proof_value = "flag{nested-value-must-not-escape}"
    state = AgentState(
        surface={
            "request_templates": [
                {
                    "source": "fetch",
                    "method": "PATCH",
                    "url": "/api/profile",
                    "headers": {"Content-Type": "application/json"},
                    "fields": {
                        "profile": {"permissions": [proof_value], "plan": proof_value},
                        "members": [{"ownerID": proof_value}],
                    },
                }
            ]
        }
    )

    inventory = inventory_api_authorization(state)

    candidate = _candidates(inventory)[0]
    assert candidate["authorization_fields"] == ["owner_id", "permissions"]
    assert candidate["business_control_fields"] == ["plan"]
    assert proof_value not in json.dumps(inventory)


def test_inventory_reads_openapi_derived_forms_passively() -> None:
    state = AgentState(
        surface={
            "forms": [
                {
                    "method": "PUT",
                    "action": "http://127.0.0.1:8000/api/accounts/1",
                    "enctype": "application/json",
                    "categories": ["api", "openapi"],
                    "inputs": [
                        {"name": "display_name", "type": "string"},
                        {"name": "permissions", "type": "array"},
                        {"name": "accountId", "type": "integer"},
                        {"name": "plan", "type": "string"},
                    ],
                }
            ]
        }
    )

    inventory = inventory_api_authorization(state)

    candidates = _candidates(inventory)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["authorization_fields"] == ["account_id", "permissions"]
    assert candidate["business_control_fields"] == ["plan"]
    assert candidate["sources"] == ["openapi"]


def test_inventory_marks_only_api_shaped_observed_privileged_gets() -> None:
    state = AgentState(
        surface={
            "endpoints": [
                {
                    "url": "http://127.0.0.1:8000/api/admin/export?format=csv&token=secret",
                    "sources": ["link"],
                    "hints": ["api"],
                },
                {
                    "url": "http://127.0.0.1:8000/admin/export",
                    "sources": ["link"],
                },
                {
                    "url": "http://127.0.0.1:8000/api/system",
                    "sources": ["form"],
                    "hints": ["api"],
                },
                {
                    "url": "http://127.0.0.1:8000/api/audit",
                    "sources": ["request_template"],
                    "hints": ["api"],
                },
            ],
            "request_templates": [
                {
                    "source": "fetch",
                    "method": "GET",
                    "url": "/api/audit",
                    "fields": {},
                }
            ],
        }
    )

    inventory = inventory_api_authorization(state)

    candidates = [
        candidate
        for candidate in _candidates(inventory)
        if candidate["kind"] == "function_authorization_review"
    ]
    assert {_mapping(candidate["route"])["path_shape"] for candidate in candidates} == {
        "/api/admin/export",
        "/api/audit",
    }
    admin = next(
        candidate
        for candidate in candidates
        if "admin" in _string_list(candidate["privileged_path_segments"])
    )
    assert admin["privileged_path_segments"] == ["admin", "export"]
    assert _mapping(admin["route"])["query_keys"] == ["format", "token"]
    assert "secret" not in json.dumps(admin)


def test_inventory_redacts_untrusted_paths_query_keys_sources_and_values() -> None:
    proof = "flag{metadata-must-not-escape}"
    state = AgentState(
        surface={
            "request_templates": [
                {
                    "source": proof,
                    "method": "PATCH",
                    "url": f"/api/invites/{proof}/admin?{proof}=yes&token={proof}",
                    "fields": {"role": proof},
                    "headers": {"Authorization": proof},
                }
            ],
            "endpoints": [
                {
                    "url": f"/api/invites/{proof}/admin?token={proof}",
                    "sources": ["link", proof],
                    "hints": ["api"],
                }
            ],
        }
    )

    inventory = inventory_api_authorization(state)
    serialized = json.dumps(inventory)

    assert proof not in serialized
    assert "metadata-must-not-escape" not in serialized
    mass_assignment = next(
        candidate
        for candidate in _candidates(inventory)
        if candidate["kind"] == "mass_assignment_review"
    )
    assert mass_assignment["sources"] == ["observed"]
    route = _mapping(mass_assignment["route"])
    assert route["path_shape"] == "/api/invites/{dynamic}/admin"
    assert route["query_keys"] == ["token", "{key}"]


def test_inventory_excludes_cross_origin_candidates_when_target_is_known() -> None:
    state = AgentState(
        surface={
            "request_templates": [
                {
                    "source": "fetch",
                    "method": "PATCH",
                    "url": "https://target.example/api/profile",
                    "fields": {"role": "member"},
                },
                {
                    "source": "fetch",
                    "method": "PATCH",
                    "url": "https://third-party.example/api/external-profile",
                    "fields": {"role": "member"},
                },
            ]
        }
    )

    inventory = inventory_api_authorization(state, target_url="https://target.example/")

    candidates = _candidates(inventory)
    assert len(candidates) == 1
    assert candidates[0]["scope_status"] == "same_origin"
    assert _mapping(candidates[0]["route"])["path_shape"] == "/api/profile"
    assert _mapping(inventory["scope"])["excluded_candidate_count"] == 1


def test_inventory_keeps_distinct_routes_after_value_redaction() -> None:
    state = AgentState(
        surface={
            "request_templates": [
                {
                    "source": "fetch",
                    "method": "PATCH",
                    "url": "/api/orders/123",
                    "fields": {"role": "member"},
                },
                {
                    "source": "fetch",
                    "method": "PATCH",
                    "url": "/api/invoices/456",
                    "fields": {"role": "member"},
                },
            ]
        }
    )

    candidates = _candidates(inventory_api_authorization(state))

    assert {_mapping(candidate["route"])["path_shape"] for candidate in candidates} == {
        "/api/invoices/{dynamic}",
        "/api/orders/{dynamic}",
    }
    assert (
        len({_mapping(candidate["route"])["route_ref"] for candidate in candidates})
        == _EXPECTED_DISTINCT_ROUTES
    )
    serialized = json.dumps(candidates)
    assert "123" not in serialized
    assert "456" not in serialized
    assert "route_fingerprint" not in serialized


def test_inventory_includes_non_get_function_routes_and_override_names() -> None:
    state = AgentState(
        surface={
            "request_templates": [
                {
                    "source": "fetch",
                    "method": "DELETE",
                    "url": "/api/users/7",
                    "fields": {},
                },
                {
                    "source": "fetch",
                    "method": "POST",
                    "url": "/api/users/8",
                    "fields": {"_method": "DELETE"},
                },
                {
                    "source": "xhr",
                    "method": "PATCH",
                    "url": "/api/system/settings",
                    "fields": {},
                    "headers": {"X-HTTP-Method-Override": "PUT"},
                },
                {
                    "source": "fetch",
                    "method": "PUT",
                    "url": "/api/admin/users/9",
                    "fields": {},
                },
            ]
        }
    )

    candidates = [
        candidate
        for candidate in _candidates(inventory_api_authorization(state))
        if candidate["kind"] == "function_authorization_review"
    ]

    assert {candidate["method"] for candidate in candidates} == {
        "DELETE",
        "PATCH",
        "POST",
        "PUT",
    }
    signals = {
        candidate["method"]: candidate["method_override_signals"] for candidate in candidates
    }
    assert signals == {
        "DELETE": [],
        "PATCH": ["header_name_present"],
        "POST": ["field_name_present"],
        "PUT": [],
    }


def test_inventory_has_no_silent_candidate_cap() -> None:
    mass_assignment_count = 45
    templates = [
        {
            "source": "fetch",
            "method": "PATCH",
            "url": f"/api/accounts/{index}",
            "fields": {"role": "member"},
        }
        for index in range(mass_assignment_count)
    ]
    templates.append(
        {
            "source": "fetch",
            "method": "GET",
            "url": "/api/admin/export",
            "fields": {},
        }
    )

    inventory = inventory_api_authorization(AgentState(surface={"request_templates": templates}))

    assert _summary(inventory)["candidate_count"] == mass_assignment_count + 1
    assert _summary(inventory)["mass_assignment_review_count"] == mass_assignment_count
    assert _summary(inventory)["function_authorization_review_count"] == 1


def test_inventory_output_is_independent_of_template_order() -> None:
    templates = [
        {
            "source": "fetch",
            "method": "PATCH",
            "url": "/api/users/1",
            "fields": {"role": "member"},
        },
        {
            "source": "fetch",
            "method": "PATCH",
            "url": "/api/users/1",
            "fields": {"tenantId": "1"},
        },
    ]

    forward = inventory_api_authorization(AgentState(surface={"request_templates": templates}))
    reverse = inventory_api_authorization(
        AgentState(surface={"request_templates": list(reversed(templates))})
    )

    assert json.dumps(forward, sort_keys=True) == json.dumps(reverse, sort_keys=True)


def test_standalone_script_reads_saved_state_and_emits_inventory(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    state_path = tmp_path / "agent-state.json"
    save_agent_state(
        state_path,
        target_url="http://127.0.0.1:8000/",
        state=AgentState(
            surface={
                "request_templates": [
                    {
                        "source": "fetch",
                        "method": "PATCH",
                        "url": "/api/profile",
                        "fields": {"role": "member"},
                    }
                ]
            }
        ),
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(repo_root / "packages" / "ravage" / "src"),
            str(repo_root / "packages" / "schemas" / "src"),
        ]
    )

    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "ravage.api_authorization_inventory",
            str(state_path),
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    inventory = json.loads(completed.stdout)
    assert inventory["confirmed_vulnerabilities"] == 0
    assert inventory["summary"]["candidate_count"] == 1
    assert inventory["candidates"][0]["authorization_fields"] == ["role"]

    original_state = state_path.read_text(encoding="utf-8")
    overwrite = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "ravage.api_authorization_inventory",
            str(state_path),
            "--output",
            str(state_path),
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert overwrite.returncode == _ARGPARSE_ERROR
    assert "must not replace the input" in overwrite.stderr
    assert state_path.read_text(encoding="utf-8") == original_state

    hardlink_path = tmp_path / "state-hardlink.json"
    os.link(state_path, hardlink_path)
    hardlink_overwrite = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "ravage.api_authorization_inventory",
            str(state_path),
            "--output",
            str(hardlink_path),
            "--force",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert hardlink_overwrite.returncode == _ARGPARSE_ERROR
    assert "must not replace the input" in hardlink_overwrite.stderr
    assert state_path.read_text(encoding="utf-8") == original_state


def _candidates(inventory: dict[str, object]) -> list[dict[str, object]]:
    candidates = inventory["candidates"]
    assert isinstance(candidates, list)
    typed_candidates: list[dict[str, object]] = []
    for candidate in candidates:
        typed_candidates.append(  # noqa: PERF401 - explicit narrowing keeps Pylance precise.
            _mapping(candidate)
        )
    return typed_candidates


def _summary(inventory: dict[str, object]) -> dict[str, object]:
    return _mapping(inventory["summary"])


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {str(key): item for key, item in value.items()}


def _string_list(value: object) -> list[str]:
    assert isinstance(value, list)
    items: list[str] = []
    for item in value:
        assert isinstance(item, str)
        items.append(item)
    return items
