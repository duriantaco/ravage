# ruff: noqa: PLR2004
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

import pytest
from ravage.auth.authorization_matrix import (
    ANONYMOUS_ACTOR,
    AUTHORIZATION_MATRIX_PLAN_SCHEMA,
    AuthorizationExpectation,
    AuthorizationMatrixCase,
    AuthorizationMatrixPlan,
    AuthorizationMatrixPlanError,
    AuthorizationMatrixResult,
    AuthorizationMatrixRunner,
    AuthorizationObservationOutcome,
    AuthorizationVerdict,
    load_authorization_matrix_plan,
    parse_authorization_matrix_plan,
)
from ravage.auth.secrets import EnvironmentSecretResolver
from ravage.traffic.policy import TrafficPolicySnapshot

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path


_MARKER = "owner-object-marker-7f98c2"
_URL = "https://app.example.test/accounts/123456?view=private"


@dataclass(frozen=True, slots=True)
class _Response:
    status: int | None
    body: str = ""
    error: str = ""
    truncated: bool = False

    @property
    def body_bytes(self) -> bytes:
        return self.body.encode()


class _FakeRuntime:
    def __init__(
        self,
        responses: Mapping[tuple[str, str], Sequence[_Response]],
        *,
        identities: Sequence[str] = ("alice", "bob"),
        blocked_on_call: int | None = None,
        final_counter_changes: Mapping[str, int | str] | None = None,
    ) -> None:
        self.identities = tuple(identities)
        self.initial_traffic_snapshot = _snapshot()
        self._snapshot = self.initial_traffic_snapshot
        self._responses = {key: list(value) for key, value in responses.items()}
        self._blocked_on_call = blocked_on_call
        self._final_counter_changes = dict(final_counter_changes or {})
        self.calls: list[tuple[str, str, str]] = []

    def roles(self, identity_alias: str) -> tuple[str, ...]:
        return ("customer",) if identity_alias in {"alice", "bob"} else ("administrator",)

    def request(self, identity_alias: str | None, method: str, url: str) -> _Response:
        actor = ANONYMOUS_ACTOR if identity_alias is None else identity_alias
        self.calls.append((actor, method, url))
        if self._blocked_on_call == len(self.calls):
            self._snapshot = replace(
                self._snapshot,
                blocked_count=self._snapshot.blocked_count + 1,
            )
            return _Response(status=None, error="sensitive policy detail")
        self._snapshot = replace(
            self._snapshot,
            physical_request_count=self._snapshot.physical_request_count + 1,
            completed_request_count=self._snapshot.completed_request_count + 1,
        )
        queue = self._responses.get((actor, url), [])
        if not queue:
            return _Response(status=None, error="missing fake response")
        return queue.pop(0)

    def traffic_snapshot(self) -> TrafficPolicySnapshot:
        if not self._final_counter_changes:
            return self._snapshot
        changed = replace(self._snapshot, **self._final_counter_changes)
        self._final_counter_changes.clear()
        self._snapshot = changed
        return changed


def _snapshot(**changes: int | str) -> TrafficPolicySnapshot:
    return replace(
        TrafficPolicySnapshot(
            physical_request_count=0,
            completed_request_count=0,
            incomplete_request_count=0,
            pending_dispatch_count=0,
            reservation_count=0,
            cache_hit_count=0,
            deduplicated_count=0,
            retry_count=0,
            blocked_count=0,
            circuit_open_count=0,
            unmetered_action_count=0,
            accounting_status="exact",
        ),
        **changes,
    )


def _case(
    expect: Mapping[str, str | AuthorizationExpectation],
    *,
    case_id: str = "private-account",
    url: str = _URL,
) -> AuthorizationMatrixCase:
    return AuthorizationMatrixCase(
        case_id=case_id,
        url=url,
        owner="alice",
        marker_env="OWNER_MARKER",
        expect=expect,
    )


def _run(
    case: AuthorizationMatrixCase,
    responses: Mapping[tuple[str, str], Sequence[_Response]],
    **runtime_options: object,
) -> tuple[AuthorizationMatrixResult, _FakeRuntime]:
    runtime = _FakeRuntime(responses, **runtime_options)
    result = AuthorizationMatrixRunner(
        EnvironmentSecretResolver({"OWNER_MARKER": _MARKER})
    ).run(AuthorizationMatrixPlan(cases=(case,)), runtime)
    return result, runtime


def _owner_responses(marker: str = _MARKER) -> list[_Response]:
    return [_Response(200, marker), _Response(200, marker)]


def test_safe_horizontal_denial_is_not_a_vulnerability() -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    result, runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [_Response(403, "not permitted")],
        },
    )

    assert result.verdict is AuthorizationVerdict.NO_VIOLATION
    assert result.cases[0].verdict is AuthorizationVerdict.NO_VIOLATION
    assert [item.outcome for item in result.cases[0].observations] == [
        AuthorizationObservationOutcome.EXPECTED_ALLOW,
        AuthorizationObservationOutcome.EXPECTED_ALLOW,
        AuthorizationObservationOutcome.SAFE_DENIAL,
    ]
    assert runtime.calls == [
        ("alice", "GET", _URL),
        ("alice", "GET", _URL),
        ("bob", "GET", _URL),
    ]
    assert result.traffic_delta.physical_request_count == 3
    assert result.traffic_delta.completed_request_count == 3


def test_horizontal_exposure_is_confirmed_without_a_ctf_flag() -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    result, _runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [_Response(200, _MARKER), _Response(200, _MARKER)],
        },
    )

    assert result.verdict is AuthorizationVerdict.CONFIRMED_VIOLATION
    assert result.cases[0].violation_actors == ("bob",)
    assert len(result.cases[0].observations) == 4
    assert "flag{" not in _MARKER.casefold()


def test_anonymous_exposure_uses_an_isolated_anonymous_actor() -> None:
    case = _case({"alice": "allow", ANONYMOUS_ACTOR: "deny"})
    result, runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            (ANONYMOUS_ACTOR, _URL): [
                _Response(200, _MARKER),
                _Response(200, _MARKER),
            ],
        },
    )

    assert result.verdict is AuthorizationVerdict.CONFIRMED_VIOLATION
    assert result.cases[0].violation_actors == (ANONYMOUS_ACTOR,)
    anonymous = result.cases[0].observations[-1]
    assert anonymous.roles == ()
    assert runtime.calls[-1][0] == ANONYMOUS_ACTOR


def test_public_and_allowed_actors_are_positive_controls() -> None:
    case = _case(
        {
            ANONYMOUS_ACTOR: "allow",
            "bob": "allow",
            "alice": "allow",
        }
    )
    result, runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [_Response(200, _MARKER)],
            (ANONYMOUS_ACTOR, _URL): [_Response(200, _MARKER)],
        },
    )

    assert result.verdict is AuthorizationVerdict.NO_VIOLATION
    assert all(
        item.outcome is AuthorizationObservationOutcome.EXPECTED_ALLOW
        for item in result.cases[0].observations
    )
    assert [actor for actor, _method, _url in runtime.calls] == [
        "alice",
        "alice",
        "bob",
        ANONYMOUS_ACTOR,
    ]


def test_allowed_actor_without_marker_is_inconclusive() -> None:
    case = _case({"alice": "allow", "bob": "allow"})
    result, _runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [_Response(200, "generic response")],
        },
    )

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE


def test_deceptive_200_without_marker_is_inconclusive() -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    result, runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [_Response(200, "please sign in")],
        },
    )

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert len(runtime.calls) == 3
    assert result.cases[0].observations[-1].marker_observed is False


def test_unstable_unexpected_marker_is_never_confirmed() -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    result, _runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [_Response(200, _MARKER), _Response(403, "denied")],
        },
    )

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert result.cases[0].violation_actors == ()


@pytest.mark.parametrize(
    "response",
    [
        _Response(200, _MARKER, truncated=True),
        _Response(200, _MARKER, error="private transport failure"),
        _Response(429, _MARKER),
        _Response(503, _MARKER),
    ],
)
def test_truncated_error_rate_limited_or_server_error_is_inconclusive(
    response: _Response,
) -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    result, runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [response],
        },
    )

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert len(runtime.calls) == 3


def test_owner_baseline_failure_stops_actor_comparisons() -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    result, runtime = _run(
        case,
        {
            ("alice", _URL): [_Response(200, "generic"), _Response(200, _MARKER)],
            ("bob", _URL): [_Response(200, _MARKER), _Response(200, _MARKER)],
        },
    )

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert [actor for actor, _method, _url in runtime.calls] == ["alice", "alice"]


@pytest.mark.parametrize(
    ("environment", "reason"),
    [
        ({}, "marker_unavailable"),
        ({"OWNER_MARKER": "too-short"}, "marker_not_distinctive"),
        ({"OWNER_MARKER": " marker-with-padding "}, "marker_not_distinctive"),
        ({"OWNER_MARKER": "marker-with\nnewline"}, "marker_not_distinctive"),
    ],
)
def test_missing_or_weak_markers_never_dispatch(
    environment: Mapping[str, str],
    reason: str,
) -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    runtime = _FakeRuntime({})

    result = AuthorizationMatrixRunner(EnvironmentSecretResolver(environment)).run(
        AuthorizationMatrixPlan(cases=(case,)),
        runtime,
    )

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert result.cases[0].reason_codes == (reason,)
    assert runtime.calls == []


def test_marker_present_in_request_url_never_dispatches_or_confirms() -> None:
    marker = "owner-object-marker-7f98c2"
    raw_url = f"https://app.example.test/accounts/123456?proof={marker}"
    case = _case({"alice": "allow", "bob": "deny"}, url=raw_url)
    runtime = _FakeRuntime({})

    result = AuthorizationMatrixRunner(
        EnvironmentSecretResolver({"OWNER_MARKER": marker})
    ).run(AuthorizationMatrixPlan(cases=(case,)), runtime)

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert result.cases[0].reason_codes == ("marker_present_in_request_url",)
    assert runtime.calls == []
    assert marker not in json.dumps(result.to_json())


def test_form_encoded_marker_present_in_request_url_never_dispatches() -> None:
    marker = "owner marker 1234"
    raw_url = "https://app.example.test/accounts/123456?proof=owner+marker+1234"
    case = _case({"alice": "allow", "bob": "deny"}, url=raw_url)
    runtime = _FakeRuntime({})

    result = AuthorizationMatrixRunner(
        EnvironmentSecretResolver({"OWNER_MARKER": marker})
    ).run(AuthorizationMatrixPlan(cases=(case,)), runtime)

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert result.cases[0].reason_codes == ("marker_present_in_request_url",)
    assert runtime.calls == []
    assert marker not in json.dumps(result.to_json())


def test_policy_reuse_invalidates_otherwise_confirmed_evidence() -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    result, _runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [_Response(200, _MARKER), _Response(200, _MARKER)],
        },
        final_counter_changes={"cache_hit_count": 1},
    )

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert result.cases[0].violation_actors == ()
    assert "reused_traffic_response" in result.reason_codes


def test_policy_block_halts_matrix_and_cannot_confirm() -> None:
    case = _case({"alice": "allow", "bob": "deny"})
    result, runtime = _run(
        case,
        {
            ("alice", _URL): _owner_responses(),
            ("bob", _URL): [_Response(200, _MARKER), _Response(200, _MARKER)],
        },
        blocked_on_call=3,
    )

    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert len(runtime.calls) == 3
    assert result.traffic_delta.blocked_count == 1
    assert "traffic_policy_blocked" in result.reason_codes


def test_policy_halt_redacts_later_case_marker_before_skipping() -> None:
    later_marker = "later-owner-marker-secret"
    later_url = f"https://app.example.test/accounts/{later_marker}"
    first = _case(
        {"alice": "allow", "bob": "deny"},
        case_id="a-first",
    )
    later = AuthorizationMatrixCase(
        case_id="b-later",
        url=later_url,
        owner="alice",
        marker_env="LATER_MARKER",
        expect={"alice": "allow", "bob": "deny"},
    )
    runtime = _FakeRuntime({}, blocked_on_call=1)
    result = AuthorizationMatrixRunner(
        EnvironmentSecretResolver(
            {"OWNER_MARKER": _MARKER, "LATER_MARKER": later_marker}
        )
    ).run(AuthorizationMatrixPlan(cases=(first, later)), runtime)

    serialized = json.dumps(result.to_json(), sort_keys=True)
    assert result.verdict is AuthorizationVerdict.INCONCLUSIVE
    assert result.cases[1].reason_codes == (
        "traffic_policy_blocked",
        "traffic_policy_halted",
    )
    assert later_marker not in serialized
    assert result.cases[1].sanitized_url.endswith("/accounts/:redacted")


def test_result_never_persists_marker_body_url_values_or_transport_detail() -> None:
    raw_url = (
        "https://app.example.test/accounts/123456"
        "?token=query-value-secret&view=private-value"
    )
    case = _case({"alice": "allow", "bob": "deny"}, url=raw_url)
    body = f'{{"private":"{_MARKER}","cookie":"session-cookie-value"}}'
    result, _runtime = _run(
        case,
        {
            ("alice", raw_url): [_Response(200, body), _Response(200, body)],
            ("bob", raw_url): [_Response(403, "private transport detail")],
        },
    )

    serialized = json.dumps(result.to_json(), sort_keys=True)
    assert _MARKER not in serialized
    assert body not in serialized
    assert "query-value-secret" not in serialized
    assert "private-value" not in serialized
    assert "session-cookie-value" not in serialized
    assert "private transport detail" not in serialized
    assert "OWNER_MARKER" not in serialized
    assert "headers" not in serialized
    assert "cookies" not in serialized
    assert result.cases[0].sanitized_url == (
        "https://app.example.test/accounts/:id"
        "?token=%5BREDACTED%5D&view=%5BREDACTED%5D"
    )
    assert "body_sha256" not in serialized


def test_case_and_actor_order_and_accounting_are_deterministic() -> None:
    first_url = "https://app.example.test/items/1001"
    second_url = "https://app.example.test/items/1002"
    case_z = _case(
        {ANONYMOUS_ACTOR: "deny", "bob": "deny", "alice": "allow"},
        case_id="z-case",
        url=second_url,
    )
    case_a = _case(
        {"alice": "allow", "bob": "deny", ANONYMOUS_ACTOR: "deny"},
        case_id="a-case",
        url=first_url,
    )

    def responses() -> dict[tuple[str, str], list[_Response]]:
        return {
            ("alice", first_url): _owner_responses(),
            ("bob", first_url): [_Response(403)],
            (ANONYMOUS_ACTOR, first_url): [_Response(404)],
            ("alice", second_url): _owner_responses(),
            ("bob", second_url): [_Response(403)],
            (ANONYMOUS_ACTOR, second_url): [_Response(404)],
        }

    runner = AuthorizationMatrixRunner(
        EnvironmentSecretResolver({"OWNER_MARKER": _MARKER})
    )
    first_runtime = _FakeRuntime(responses())
    second_runtime = _FakeRuntime(responses())
    first = runner.run(AuthorizationMatrixPlan(cases=(case_z, case_a)), first_runtime)
    second = runner.run(AuthorizationMatrixPlan(cases=(case_a, case_z)), second_runtime)

    assert first.to_json() == second.to_json()
    assert [case.case_id for case in first.cases] == ["a-case", "z-case"]
    assert first.traffic_delta.physical_request_count == 8
    assert first.traffic_delta.completed_request_count == 8


def _valid_payload() -> dict[str, object]:
    return {
        "schema": AUTHORIZATION_MATRIX_PLAN_SCHEMA,
        "cases": [
            {
                "id": "private-account",
                "method": "GET",
                "url": _URL,
                "owner": "alice",
                "marker_env": "OWNER_MARKER",
                "expect": {"alice": "allow", "bob": "deny"},
            }
        ],
    }


def test_yaml_loader_accepts_only_the_versioned_schema(tmp_path: Path) -> None:
    path = tmp_path / "authorization-matrix.yaml"
    path.write_text(
        "\n".join(
            (
                f"schema: {AUTHORIZATION_MATRIX_PLAN_SCHEMA}",
                "cases:",
                "  - id: private-account",
                "    method: GET",
                f"    url: {_URL}",
                "    owner: alice",
                "    marker_env: OWNER_MARKER",
                "    expect:",
                "      bob: deny",
                "      alice: allow",
            )
        ),
        encoding="utf-8",
    )

    plan = load_authorization_matrix_plan(path, known_identities=("alice", "bob"))

    assert plan.schema == AUTHORIZATION_MATRIX_PLAN_SCHEMA
    assert tuple(plan.cases[0].expect) == ("alice", "bob")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update({"extra": True}),
        lambda payload: payload["cases"][0].update({"extra": True}),
        lambda payload: payload["cases"][0].update({"method": "POST"}),
        lambda payload: payload["cases"][0].update({"marker_env": ""}),
        lambda payload: payload["cases"][0].pop("marker_env"),
        lambda payload: payload["cases"][0].update({"url": "file:///etc/passwd"}),
        lambda payload: payload["cases"][0].update(
            {"url": "https://app.example.test/accounts/{id}"}
        ),
        lambda payload: payload["cases"][0].update(
            {"expect": {"alice": "allow", "mallory": "deny"}}
        ),
        lambda payload: payload["cases"][0].update(
            {"expect": {"alice": "allow", "anon": "deny"}}
        ),
        lambda payload: payload["cases"][0].update(
            {"expect": {"alice": "deny", "bob": "deny"}}
        ),
    ],
)
def test_loader_rejects_unknown_reserved_or_unsafe_input(mutation: object) -> None:
    payload = _valid_payload()
    assert callable(mutation)
    mutation(payload)

    with pytest.raises(AuthorizationMatrixPlanError):
        parse_authorization_matrix_plan(payload, known_identities=("alice", "bob"))


def test_loader_rejects_duplicate_case_ids() -> None:
    payload = _valid_payload()
    cases = payload["cases"]
    assert isinstance(cases, list)
    cases.append(dict(cases[0]))

    with pytest.raises(AuthorizationMatrixPlanError, match="duplicate case ids"):
        parse_authorization_matrix_plan(payload, known_identities=("alice", "bob"))
