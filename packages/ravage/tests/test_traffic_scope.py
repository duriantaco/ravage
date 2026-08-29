from __future__ import annotations

import pytest
from ravage.traffic.scope import TrafficScope


def test_direct_capture_scope_allows_only_the_target_origin() -> None:
    scope = TrafficScope("http://127.0.0.1:3000/app")

    assert scope.decide("http://127.0.0.1:3000/api/me").allowed
    assert not scope.decide("http://127.0.0.1:3001/api/me").allowed
    assert not scope.decide("https://example.test/analytics").allowed


def test_brief_scope_respects_path_exclusions() -> None:
    scope = TrafficScope(
        "http://127.0.0.1:3000/app",
        in_scope=("http://127.0.0.1:3000/app",),
        out_of_scope=("http://127.0.0.1:3000/app/admin",),
    )

    assert scope.decide("http://127.0.0.1:3000/app/profile").allowed
    assert not scope.decide("http://127.0.0.1:3000/app/admin/users").allowed


def test_remote_scope_requires_acknowledgement_and_pins_dns() -> None:
    with pytest.raises(ValueError, match="authorized-remote-target"):
        TrafficScope("https://staging.example.test/")

    answers = iter((("203.0.113.8",), ("203.0.113.9",)))
    scope = TrafficScope(
        "https://staging.example.test/",
        allow_remote_target=True,
        resolver=lambda _host, _port: next(answers),
    )

    assert scope.decide("https://staging.example.test/api/me").allowed
    changed = scope.decide("https://staging.example.test/api/orders")
    assert not changed.allowed
    assert changed.reason == "target DNS changed after pinning"


def test_browser_route_can_reuse_a_frozen_pin_without_dns_reresolution() -> None:
    answers = iter((("203.0.113.8",), ("203.0.113.9",)))
    scope = TrafficScope(
        "https://staging.example.test/",
        allow_remote_target=True,
        resolver=lambda _host, _port: next(answers),
    )

    assert scope.decide("https://staging.example.test/").allowed
    assert scope.decide_using_pins("https://staging.example.test/api/me").allowed
    changed = scope.decide("https://staging.example.test/api/me")
    assert not changed.allowed
    assert changed.reason == "target DNS changed after pinning"


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "::ffff:0.0.0.0"])
def test_remote_scope_rejects_unspecified_dns_addresses(address: str) -> None:
    scope = TrafficScope(
        "https://staging.example.test/",
        allow_remote_target=True,
        resolver=lambda _host, _port: (address,),
    )

    decision = scope.decide("https://staging.example.test/")

    assert not decision.allowed
    assert decision.reason == "target DNS resolution returned an unspecified address"
