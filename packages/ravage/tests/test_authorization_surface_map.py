# ruff: noqa: PLR2004, S105
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

import pytest
from ravage.auth.authorization_matrix import ANONYMOUS_ACTOR
from ravage.auth.authorization_surface_map import run_authorization_surface_map
from ravage.traffic.policy import TrafficPolicySnapshot
from ravage.web_core.scope_policy import same_origin

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


_TARGET = "https://app.example.test/"
_ALICE = "alice"
_BOB = "bob"


@dataclass(frozen=True, slots=True)
class _Response:
    status: int | None
    final_url: str
    headers: Mapping[str, str]
    body: str
    body_bytes: bytes
    error: str = ""
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Plan:
    response: _Response
    generation_after: int | None = None


class _Runtime:
    def __init__(
        self,
        *,
        identities: Sequence[str] = (_ALICE, _BOB),
        responses: Mapping[tuple[str | None, str], Sequence[_Plan]] | None = None,
        roles: Mapping[str, Sequence[str]] | None = None,
        final_snapshot_changes: Mapping[str, int | str] | None = None,
    ) -> None:
        self._identities = tuple(identities)
        self._responses = {key: tuple(plans) for key, plans in (responses or {}).items()}
        self._roles = {
            alias: tuple(values)
            for alias, values in (
                roles
                or {
                    _ALICE: ("admin",),
                    _BOB: ("member",),
                }
            ).items()
        }
        self._generations: dict[str | None, int] = dict.fromkeys(self._identities, 1)
        self._generations[None] = 0
        self._call_counts: dict[tuple[str | None, str], int] = {}
        self._final_snapshot_changes = dict(final_snapshot_changes or {})
        self.requests: list[tuple[str | None, str, str]] = []
        self._physical_requests = 0
        self._completed_requests = 0
        self._initial = _snapshot()

    @property
    def identities(self) -> Sequence[str]:
        return self._identities

    @property
    def initial_traffic_snapshot(self) -> TrafficPolicySnapshot:
        return self._initial

    def roles(self, identity_alias: str) -> Sequence[str]:
        return self._roles[identity_alias]

    def identity_generation(self, identity_alias: str | None) -> int:
        return self._generations[identity_alias]

    def in_scope(self, url: str) -> bool:
        return same_origin(_TARGET, url)

    def request(self, identity_alias: str | None, method: str, url: str) -> _Response:
        self.requests.append((identity_alias, method, url))
        self._physical_requests += 1
        key = (identity_alias, url)
        index = self._call_counts.get(key, 0)
        self._call_counts[key] = index + 1
        plans = self._responses.get(key)
        plan = plans[min(index, len(plans) - 1)] if plans else _Plan(_response(url))
        if plan.generation_after is not None:
            self._generations[identity_alias] = plan.generation_after
        self._completed_requests += 1
        return plan.response

    def traffic_snapshot(self) -> TrafficPolicySnapshot:
        snapshot = _snapshot(
            physical=self._physical_requests,
            completed=self._completed_requests,
        )
        if self._physical_requests and self._final_snapshot_changes:
            return replace(snapshot, **self._final_snapshot_changes)
        return snapshot


def test_stable_shared_surface_has_no_candidates() -> None:
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_response(_TARGET)),
            (_BOB, _TARGET): _stable(_response(_TARGET)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is True
    assert result.coverage_limited is False
    assert result.reason_codes == ()
    assert result.candidates == ()
    assert runtime.requests == [
        (_ALICE, "GET", _TARGET),
        (_BOB, "GET", _TARGET),
    ]


def test_empty_missing_and_fragment_links_do_not_force_repeats() -> None:
    inert_links = '<a>Missing</a><a href="">Empty</a><a href="#local">Fragment</a>'
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_html(_TARGET, inert_links)),
            (_BOB, _TARGET): _stable(_html(_TARGET, "")),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is True
    assert result.candidates == ()
    assert len(runtime.requests) == 2


def test_identity_only_visibility_creates_review_candidate() -> None:
    admin_url = f"{_TARGET}admin"
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_html(_TARGET, '<a href="/admin">Admin</a>')),
            (_BOB, _TARGET): _stable(_html(_TARGET, "")),
            (_ALICE, admin_url): _stable(_response(admin_url)),
            (_BOB, admin_url): _stable(_response(admin_url)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is True
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.route_shape == "/admin"
    assert candidate.reason_codes == ("identity_visibility_difference",)
    assert candidate.discovered_by == (_ALICE,)
    assert candidate.not_discovered_by == (_BOB,)
    evidence = {item.actor: item for item in candidate.actor_evidence}
    assert evidence[_ALICE].declaration_observed is True
    assert evidence[_BOB].declaration_observed is False
    assert all(item.stable for item in candidate.actor_evidence)
    assert candidate.review_ready is True


def test_link_candidate_is_not_suppressed_when_route_is_also_a_script_source() -> None:
    admin_url = f"{_TARGET}admin"
    body = '<a href="/admin">Admin</a><script src="/admin"></script>'
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_html(_TARGET, body)),
            (_BOB, _TARGET): _stable(_html(_TARGET, "")),
            (_ALICE, admin_url): _stable(_response(admin_url)),
            (_BOB, admin_url): _stable(_response(admin_url)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    candidates = {candidate.route_shape: candidate for candidate in result.candidates}
    assert candidates["/admin"].reason_codes == ("identity_visibility_difference",)
    assert candidates["/admin"].review_ready is True


def test_stable_success_vs_denied_creates_review_candidate() -> None:
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_response(_TARGET, status=200)),
            (_BOB, _TARGET): _stable(_response(_TARGET, status=403)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is True
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.route_shape == "/"
    assert candidate.reason_codes == ("response_access_class_difference",)
    assert candidate.review_ready is True
    evidence = {item.actor: item for item in candidate.actor_evidence}
    assert evidence[_ALICE].access_classes == ("success",)
    assert evidence[_ALICE].statuses == (200,)
    assert evidence[_BOB].access_classes == ("denied",)
    assert evidence[_BOB].statuses == (403,)
    assert all(item.stable for item in candidate.actor_evidence)


def test_success_status_variants_do_not_create_status_noise() -> None:
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_response(_TARGET, status=200)),
            (_BOB, _TARGET): _stable(_response(_TARGET, status=204)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is True
    assert result.candidates == ()
    assert len(runtime.requests) == 2


def test_rotating_query_values_do_not_make_a_stable_shape_incomplete() -> None:
    first = _html(_TARGET, '<a href="/download?signature=first-secret">Download</a>')
    second = _html(_TARGET, '<a href="/download?signature=second-secret">Download</a>')
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _sequence(first, second),
            (_BOB, _TARGET): _sequence(first, second),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)
    rendered = json.dumps(result.to_json(), sort_keys=True)

    assert result.complete is True
    assert "unstable_surface_observation" not in result.reason_codes
    assert result.candidates == ()
    assert "first-secret" not in rendered
    assert "second-secret" not in rendered


def test_query_action_form_script_and_javascript_operations_are_never_dispatched() -> None:
    body = """
    <a href="/search?q=private-value">Search</a>
    <a href="/logout">Log out</a>
    <a href="/account/%256c%256f%2567%256f%2575%2574">Encoded log out</a>
    <a href="/account/deleteAccount">Delete account</a>
    <form method="GET" action="/reports">
      <input name="account" value="private-value">
    </form>
    <form method="POST" action="/orders/update">
      <input name="csrf" value="private-value">
    </form>
    <script src="/assets/app.js"></script>
    <script>fetch('/api/diagnostics')</script>
    """
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_html(_TARGET, body)),
            (_BOB, _TARGET): _stable(_html(_TARGET, body)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is True
    assert {url for _actor, _method, url in runtime.requests} == {_TARGET}
    assert len(runtime.requests) == 4
    assert {
        "action_route_not_dispatched",
        "declared_operation_not_dispatched",
        "non_get_operation_not_dispatched",
        "query_route_not_dispatched",
        "static_asset_not_dispatched",
    } <= set(result.coverage_reason_codes)


def test_deeply_encoded_paths_and_common_action_routes_are_never_dispatched() -> None:
    encoded_logout = "".join(f"%{ord(character):02x}" for character in "logout")
    for _round in range(5):
        encoded_logout = encoded_logout.replace("%", "%25")
    body = f"""
    <a href="/safe/%25252e%25252e/admin">Traversal</a>
    <a href="/account/{encoded_logout}">Deep logout</a>
    <a href="/billing/cancelSubscription">Cancel</a>
    <a href="/admin/impersonate">Impersonate</a>
    <a href="/jobs/restart">Restart</a>
    <a href="/payments/transfer">Transfer</a>
    <a href="/newsletter/unsubscribe">Unsubscribe</a>
    <a href="/tasks/execute">Execute</a>
    <a href="/billing/purchase">Purchase</a>
    <a href="/admin/deploy">Deploy</a>
    <a href="/system/shutdown">Shutdown</a>
    <a href="/jobs/run">Run</a>
    <a href="/orders/refund">Refund</a>
    <a href="/account/changePassword">Change password</a>
    <a href="/account/enable2FA">Enable 2FA</a>
    <a href="/account/disable2fa">Disable 2FA</a>
    <a href="/account/reset2FA">Reset 2FA</a>
    <a href="/keys/rotate2fa">Rotate 2FA</a>
    <a href="/admin/delete2FA">Delete 2FA</a>
    """
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_html(_TARGET, body)),
            (_BOB, _TARGET): _stable(_html(_TARGET, body)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is True
    assert {url for _actor, _method, url in runtime.requests} == {_TARGET}
    assert len(runtime.requests) == 4
    assert "action_route_not_dispatched" in result.coverage_reason_codes
    assert "unsafe_surface_declaration_skipped" in result.coverage_reason_codes


def test_short_action_prefixes_do_not_hide_safe_navigation_routes() -> None:
    safe_paths = (
        "address",
        "banner",
        "buyer-guide",
        "runtime",
        "changelog",
        "movement",
        "payments",
    )
    body = "".join(f'<a href="/{path}">{path}</a>' for path in safe_paths)
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_html(_TARGET, body)),
            (_BOB, _TARGET): _stable(_html(_TARGET, body)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    requested_urls = {url for _actor, _method, url in runtime.requests}
    assert result.complete is True
    assert requested_urls == {_TARGET} | {f"{_TARGET}{path}" for path in safe_paths}


def test_redirect_query_names_are_preserved_without_dispatching_values() -> None:
    location = "/callback?code=private-code&state=private-state"
    redirect = _response(_TARGET, status=302, headers={"Location": location})
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(redirect),
            (_BOB, _TARGET): _stable(redirect),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)
    callback = next(
        operation
        for operation in (result.surface_graph.operations or {}).values()
        if operation.route_shape == "/callback"
    )
    rendered = json.dumps(result.to_json(), sort_keys=True)

    assert {(parameter.name, parameter.location) for parameter in callback.parameters} == {
        ("code", "query"),
        ("state", "query"),
    }
    assert {url for _actor, _method, url in runtime.requests} == {_TARGET}
    assert "private-code" not in rendered
    assert "private-state" not in rendered


def test_unstable_surface_is_incomplete_and_never_review_ready() -> None:
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _sequence(
                _html(_TARGET, '<a href="/first">First</a>'),
                _html(_TARGET, '<a href="/second">Second</a>'),
            ),
            (_BOB, _TARGET): _stable(_html(_TARGET, "")),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is False
    assert "unstable_surface_observation" in result.reason_codes
    assert not any(candidate.review_ready for candidate in result.candidates)
    assert len(runtime.requests) == 4


@pytest.mark.parametrize("status", [429, 500, 503])
def test_rate_limit_and_server_errors_are_incomplete(status: int) -> None:
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_response(_TARGET, status=status)),
            (_BOB, _TARGET): _stable(_response(_TARGET, status=200)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is False
    assert "inconclusive_response_status" in result.reason_codes
    assert not any(candidate.review_ready for candidate in result.candidates)
    assert result.actors[0].inconclusive_count == 1


def test_identity_generation_change_is_incomplete_and_never_review_ready() -> None:
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): (_Plan(_response(_TARGET), generation_after=2),),
            (_BOB, _TARGET): _stable(_response(_TARGET)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is False
    assert "identity_generation_changed" in result.reason_codes
    assert not any(candidate.review_ready for candidate in result.candidates)
    alice_probe_observations = tuple(
        observation
        for observation in (result.surface_graph.observations or {}).values()
        if observation.identity_alias == _ALICE and observation.source_kind == "probe"
    )
    assert alice_probe_observations
    assert all(observation.response_status is None for observation in alice_probe_observations)


def test_output_is_deterministic_across_identity_input_order() -> None:
    alice_body = '<a href="/zeta">Zeta</a><a href="/alpha">Alpha</a>'
    bob_body = '<a href="/alpha">Alpha</a>'
    responses = {
        (_ALICE, _TARGET): _stable(_html(_TARGET, alice_body)),
        (_BOB, _TARGET): _stable(_html(_TARGET, bob_body)),
    }
    first = _Runtime(identities=(_BOB, _ALICE), responses=responses)
    second = _Runtime(identities=(_ALICE, _BOB), responses=responses)

    first_result = run_authorization_surface_map(_TARGET, runtime=first)
    second_result = run_authorization_surface_map(_TARGET, runtime=second)

    assert first_result.to_json() == second_result.to_json()
    assert first.requests == second.requests


def test_receipt_never_persists_response_or_concrete_secret_values() -> None:
    resource_id = "f84a91b4-45d1-4e70-8b34-2f3215a9e773"
    query_secret = "query-secret-must-not-persist"
    cookie_secret = "cookie-secret-must-not-persist"
    body_secret = "body-secret-must-not-persist"
    form_secret = "form-secret-must-not-persist"
    javascript_secret = "javascript-secret-must-not-persist"
    body = f"""
    <p>{body_secret}</p>
    <a href="/users/{resource_id}?access={query_secret}">Account</a>
    <form method="POST" action="/orders/{resource_id}/update">
      <input name="csrf" value="{form_secret}">
    </form>
    <script>
      fetch('/orders/{resource_id}/details?auth={query_secret}', {{
        headers: {{Authorization: 'Bearer {javascript_secret}'}},
        body: JSON.stringify({{password: '{javascript_secret}'}})
      }})
    </script>
    """
    alice_response = _html(
        _TARGET,
        body,
        headers={"Set-Cookie": f"session={cookie_secret}; HttpOnly"},
    )
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(alice_response),
            (_BOB, _TARGET): _stable(_html(_TARGET, "")),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)
    rendered = json.dumps(result.to_json(), sort_keys=True)

    assert result.complete is True
    assert result.candidates
    for secret in (
        resource_id,
        query_secret,
        cookie_secret,
        body_secret,
        form_secret,
        javascript_secret,
    ):
        assert secret not in rendered
    assert "/users/{id}" in rendered
    assert "/orders/{id}/update" in rendered


def test_receipt_conservatively_shapes_short_ids_slugs_and_target_path_secrets() -> None:
    secret_segments = (
        "customer-acme",
        "a1b2",
        "abc123",
        "ABCDEFGHIJKLMNOP",
        "tokenonlysecret",
    )
    body = (
        '<a href="/widgets/customer-acme">Customer</a>'
        '<a href="/widgets/a1b2">Short ID</a>'
        '<a href="/objects/abc123">Object</a>'
        '<a href="/foo/ABCDEFGHIJKLMNOP">Opaque label</a>'
        '<a href="/download/tokenonlysecret">Download</a>'
    )
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_html(_TARGET, body)),
            (_BOB, _TARGET): _stable(_html(_TARGET, "")),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)
    rendered = json.dumps(result.to_json(), sort_keys=True)

    assert all(secret not in rendered for secret in secret_segments)
    assert "/widgets/{segment}" in rendered
    assert "/objects/{id}" in rendered
    assert "/download/{id}" in rendered

    target_with_secret = f"{_TARGET}download/tokenonlysecret"
    target_result = run_authorization_surface_map(target_with_secret, runtime=_Runtime())
    target_rendered = json.dumps(target_result.to_json(), sort_keys=True)
    assert "tokenonlysecret" not in target_rendered
    assert "/download/{id}" in target_rendered


def test_frontier_limit_bounds_dispatch_without_marking_run_incomplete() -> None:
    links = "".join(f'<a href="/page/{index}">Page {index}</a>' for index in range(1, 7))
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_html(_TARGET, links)),
            (_BOB, _TARGET): _stable(_html(_TARGET, links)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime, max_urls=3)

    assert result.complete is True
    assert result.coverage_limited is True
    assert "frontier_limit_reached" in result.coverage_reason_codes
    assert {url for _actor, _method, url in runtime.requests} == {
        _TARGET,
        f"{_TARGET}page/1",
        f"{_TARGET}page/2",
    }
    assert len(runtime.requests) == 8
    assert all(actor.mapped_url_count == 3 for actor in result.actors)


def test_optional_anonymous_actor_is_last_then_repeated_first() -> None:
    runtime = _Runtime(
        identities=(_BOB, _ALICE),
        responses={
            (_ALICE, _TARGET): _stable(_response(_TARGET, status=200)),
            (_BOB, _TARGET): _stable(_response(_TARGET, status=403)),
            (None, _TARGET): _stable(_response(_TARGET, status=403)),
        },
    )

    result = run_authorization_surface_map(
        _TARGET,
        runtime=runtime,
        include_anonymous=True,
    )

    assert tuple(actor.actor for actor in result.actors) == (
        _ALICE,
        _BOB,
        ANONYMOUS_ACTOR,
    )
    assert runtime.requests == [
        (_ALICE, "GET", _TARGET),
        (_BOB, "GET", _TARGET),
        (None, "GET", _TARGET),
        (None, "GET", _TARGET),
        (_BOB, "GET", _TARGET),
        (_ALICE, "GET", _TARGET),
    ]


def test_result_reports_exact_whole_run_traffic_accounting() -> None:
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_response(_TARGET, status=200)),
            (_BOB, _TARGET): _stable(_response(_TARGET, status=403)),
        }
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    delta = result.traffic_delta
    assert delta.physical_request_count == len(runtime.requests) == 4
    assert delta.completed_request_count == 4
    assert delta.incomplete_request_count == 0
    assert delta.pending_dispatch_count == 0
    assert delta.reservation_count == 0
    assert delta.cache_hit_count == 0
    assert delta.deduplicated_count == 0
    assert delta.retry_count == 0
    assert delta.blocked_count == 0
    assert delta.circuit_open_count == 0
    assert delta.unmetered_action_count == 0
    assert delta.initial_accounting_status == "exact"
    assert delta.current_accounting_status == "exact"
    assert sum(actor.observation_count for actor in result.actors) == 4


@pytest.mark.parametrize(
    ("snapshot_changes", "reason"),
    [
        ({"cache_hit_count": 1}, "reused_traffic_response"),
        ({"retry_count": 1}, "traffic_policy_retry"),
        ({"unmetered_action_count": 1}, "unmetered_traffic"),
        ({"accounting_status": "inexact"}, "traffic_accounting_not_exact"),
    ],
)
def test_policy_anomalies_make_every_candidate_not_review_ready(
    snapshot_changes: Mapping[str, int | str],
    reason: str,
) -> None:
    runtime = _Runtime(
        responses={
            (_ALICE, _TARGET): _stable(_response(_TARGET, status=200)),
            (_BOB, _TARGET): _stable(_response(_TARGET, status=403)),
        },
        final_snapshot_changes=snapshot_changes,
    )

    result = run_authorization_surface_map(_TARGET, runtime=runtime)

    assert result.complete is False
    assert reason in result.reason_codes
    assert result.candidates
    assert not any(candidate.review_ready for candidate in result.candidates)


def _stable(response: _Response) -> tuple[_Plan, ...]:
    return (_Plan(response),)


def _sequence(*responses: _Response) -> tuple[_Plan, ...]:
    return tuple(_Plan(response) for response in responses)


def _html(
    url: str,
    body: str,
    *,
    headers: Mapping[str, str] | None = None,
) -> _Response:
    return _response(
        url,
        body=f"<html><body>{body}</body></html>",
        headers={"Content-Type": "text/html; charset=utf-8", **dict(headers or {})},
    )


def _response(
    url: str,
    *,
    status: int | None = 200,
    body: str = "",
    headers: Mapping[str, str] | None = None,
) -> _Response:
    return _Response(
        status=status,
        final_url=url,
        headers=dict(headers or {}),
        body=body,
        body_bytes=body.encode("utf-8"),
    )


def _snapshot(
    *,
    physical: int = 0,
    completed: int = 0,
) -> TrafficPolicySnapshot:
    return TrafficPolicySnapshot(
        physical_request_count=physical,
        completed_request_count=completed,
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
    )
