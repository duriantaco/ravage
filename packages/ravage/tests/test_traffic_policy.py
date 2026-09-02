from __future__ import annotations

import json
import multiprocessing
import os
import time
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread
from urllib.parse import urlencode

import pytest
from ravage.traffic import policy as traffic_policy_module
from ravage.traffic.policy import (
    RequestIntent,
    TrafficCacheRecord,
    TrafficDecisionKind,
    TrafficOutcome,
    TrafficPolicyBlocked,
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyError,
    TrafficPolicyMode,
    load_traffic_policy_snapshot,
)


class _Clock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_cache_record_preserves_non_utf8_response_bytes() -> None:
    raw = b"PK\x03\x04\xff\x00archive"
    record = TrafficCacheRecord(
        status=200,
        final_url="http://127.0.0.1/archive.zip",
        headers={"content-type": "application/zip"},
        body=raw.decode("utf-8", errors="replace"),
        body_bytes=raw,
    )

    restored = TrafficCacheRecord.from_json(record.to_json())

    assert restored.body_bytes == raw


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_config_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        TrafficPolicyConfig(max_rps=value)

    payload = TrafficPolicyConfig().to_json()
    payload["cache_ttl_seconds"] = value
    with pytest.raises(TrafficPolicyError, match="number"):
        TrafficPolicyConfig.from_json(payload)


def test_config_rejects_rate_with_infinite_interval() -> None:
    with pytest.raises(ValueError, match="finite pacing interval"):
        TrafficPolicyConfig(max_rps=5e-324)


def _portswigger_request_config() -> TrafficPolicyConfig:
    return TrafficPolicyConfig(
        mode=TrafficPolicyMode.ENFORCE,
        max_rps=0.5,
        max_physical_requests=24,
        allowed_request_routes=("GET /catalog", "HEAD /catalog"),
        allowed_query_fields=("category", "searchterm"),
        allowed_explicit_headers=(
            "accept",
            "accept-encoding",
            "user-agent",
        ),
        allowed_form_fields=(),
        max_request_body_bytes=1_024,
        request_value_profile="portswigger-scanme-demo",
        require_public_addresses=True,
    )


def test_portswigger_profile_rejects_partial_policy_configuration() -> None:
    with pytest.raises(ValueError, match="requires its enforced routes"):
        TrafficPolicyConfig(request_value_profile="portswigger-scanme-demo")


def test_portswigger_profile_is_locked_to_the_published_test_origin(tmp_path: Path) -> None:
    with pytest.raises(TrafficPolicyError, match="locked to"):
        TrafficPolicyController.open(
            tmp_path / "traffic.json",
            target_url="https://example.com/catalog?category=Accessories",
            config=_portswigger_request_config(),
        )


def test_request_restrictions_round_trip_through_durable_reference(tmp_path: Path) -> None:
    config = _portswigger_request_config()
    controller = _controller(tmp_path, config)

    restored = TrafficPolicyController.from_reference(controller.to_reference())

    assert restored.config == config


def test_request_restrictions_allow_only_curated_catalog_traffic(tmp_path: Path) -> None:
    controller = _controller(tmp_path, _portswigger_request_config())
    baseline = RequestIntent(
        "GET",
        "https://vulnerable-website.com/catalog?searchTerm=&category=Accessories",
        headers={
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "application/json;q=0.8,text/plain;q=0.7,*/*;q=0.1"
            ),
            "Accept-Encoding": "identity",
            "User-Agent": "ravage-probe/1.0",
        },
    )
    boolean_true = RequestIntent(
        "GET",
        "https://vulnerable-website.com/catalog?category=Accessories%27+OR+%271%27%3D%271",
    )
    boolean_false = RequestIntent(
        "GET",
        "https://vulnerable-website.com/catalog?category=Accessories%27+AND+%271%27%3D%272",
    )

    for intent in (baseline, boolean_true, boolean_false):
        decision = controller.acquire(intent)
        assert decision.kind is TrafficDecisionKind.DISPATCH
        assert decision.lease is not None
        controller.cancel(decision.lease)


@pytest.mark.parametrize(
    "category",
    sorted(traffic_policy_module._PORTSWIGGER_SAFE_QUERY_VALUES["category"]),  # noqa: SLF001
)
def test_portswigger_profile_admits_every_code_owned_category_value(
    tmp_path: Path,
    category: str,
) -> None:
    controller = _controller(tmp_path, _portswigger_request_config())
    decision = controller.acquire(
        RequestIntent(
            "GET",
            f"https://vulnerable-website.com/catalog?{urlencode({'category': category})}",
        )
    )

    assert decision.kind is TrafficDecisionKind.DISPATCH
    assert decision.lease is not None
    controller.cancel(decision.lease)


def test_portswigger_profile_preserves_only_the_observed_blank_search_term(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path, _portswigger_request_config())

    allowed = controller.acquire(
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?searchTerm=&category=Accessories",
        )
    )
    assert allowed.kind is TrafficDecisionKind.DISPATCH
    assert allowed.lease is not None
    controller.cancel(allowed.lease)

    blocked = controller.acquire(
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?searchTerm=admin&category=Accessories",
        )
    )
    assert blocked.kind is TrafficDecisionKind.BLOCKED
    assert "value" in blocked.reason


def test_portswigger_profile_blocks_duplicate_query_fields(tmp_path: Path) -> None:
    controller = _controller(tmp_path, _portswigger_request_config())

    decision = controller.acquire(
        RequestIntent(
            "GET",
            (
                "https://vulnerable-website.com/catalog?category=Accessories&"
                "category=Accessories%27+OR+%271%27%3D%271%27+--+"
            ),
        )
    )

    assert decision.kind is TrafficDecisionKind.BLOCKED
    assert "repeats" in decision.reason


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    ("name", "value"),
    [
        (name, value)
        for name, values in sorted(
            traffic_policy_module._PORTSWIGGER_SAFE_HEADER_VALUES.items()  # noqa: SLF001
        )
        for value in sorted(values)
    ],
)
def test_portswigger_profile_admits_every_code_owned_header_value(
    tmp_path: Path,
    name: str,
    value: str,
) -> None:
    controller = _controller(tmp_path, _portswigger_request_config())

    decision = controller.acquire(
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories",
            headers={name: value},
        )
    )

    assert decision.kind is TrafficDecisionKind.DISPATCH
    assert decision.lease is not None
    controller.cancel(decision.lease)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "headers",
    [
        {"User-Agent": "ravage'; DROP TABLE products;--"},
        {"Accept": "text/html OR SLEEP(10)"},
        {"User-Agent": "UNION SELECT username, password FROM users"},
        {"Accept-Encoding": "gzip"},
    ],
    ids=["destructive", "timing", "data-extraction", "unapproved-encoding"],
)
def test_portswigger_profile_blocks_unapproved_header_values_before_dispatch(
    tmp_path: Path,
    headers: dict[str, str],
) -> None:
    controller = _controller(tmp_path, _portswigger_request_config())

    decision = controller.acquire(
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories",
            headers=headers,
        )
    )

    assert decision.kind is TrafficDecisionKind.BLOCKED
    assert "header" in decision.reason
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == 0
    assert snapshot.reservation_count == 0
    assert snapshot.blocked_count == 1


@pytest.mark.parametrize(
    "intent",
    [
        RequestIntent("GET", "https://vulnerable-website.com/admin/admin.jsp"),
        RequestIntent("GET", "https://vulnerable-website.com/ignored/../catalog"),
        RequestIntent("GET", "https://vulnerable-website.com/cat%61log"),
        RequestIntent("DELETE", "https://vulnerable-website.com/catalog"),
        RequestIntent("GET", "https://vulnerable-website.com/catalog?role=admin"),
        RequestIntent("GET", "https://vulnerable-website.com/catalog?category=Gifts"),
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories",
            headers={"Host": "normal.example"},
        ),
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories",
            headers={"Cookie": "session=attacker-controlled"},
        ),
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories&role=admin",
        ),
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories%27%3B+DROP+TABLE+products%3B--",
        ),
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories%27+OR+SLEEP%2810%29--",
        ),
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories",
            headers={"Content-Type": "application/json"},
            body=b'{"category":"Accessories"}',
        ),
        RequestIntent(
            "GET",
            "https://vulnerable-website.com/catalog?category=Accessories",
            body=b"x" * 1_025,
        ),
    ],
    ids=[
        "off-route",
        "dot-segment-path",
        "encoded-path",
        "method",
        "query-field",
        "query-value",
        "host-header",
        "explicit-cookie",
        "form-field",
        "destructive-form-value",
        "timing-form-value",
        "body-encoding",
        "body-size",
    ],
)
def test_request_restrictions_block_before_dispatch(
    tmp_path: Path,
    intent: RequestIntent,
) -> None:
    controller = _controller(tmp_path, _portswigger_request_config())

    decision = controller.acquire(intent)

    assert decision.kind is TrafficDecisionKind.BLOCKED
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == 0
    assert snapshot.reservation_count == 0
    assert snapshot.blocked_count == 1


def _intent(path: str = "/", *, cacheable: bool = False) -> RequestIntent:
    return RequestIntent(
        "GET",
        f"http://127.0.0.1{path}",
        lane="recon",
        cacheable=cacheable,
        retryable=True,
    )


def _controller(
    tmp_path: Path,
    config: TrafficPolicyConfig,
    *,
    clock: _Clock | None = None,
) -> TrafficPolicyController:
    target_url = "http://127.0.0.1/"
    if config.request_value_profile == "portswigger-scanme-demo":
        target_url = "https://vulnerable-website.com/catalog?category=Accessories"
    return TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url=target_url,
        config=config,
        clock=clock or __import__("time").time,
        sleep=(clock.sleep if clock is not None else __import__("time").sleep),
    )


def test_reservation_is_not_counted_until_physical_dispatch(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_physical_requests=1,
        ),
    )

    decision = controller.acquire(_intent())

    assert decision.kind is TrafficDecisionKind.DISPATCH
    assert controller.snapshot().physical_request_count == 0
    assert decision.lease is not None
    controller.begin_dispatch(decision.lease)
    controller.complete(decision.lease, TrafficOutcome(status=None, transport_error=True))

    blocked = controller.acquire(_intent("/other"))
    assert blocked.kind is TrafficDecisionKind.BLOCKED
    assert controller.snapshot().physical_request_count == 1


def test_sub_one_rps_uses_exact_global_interval(tmp_path: Path) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_rps=0.5,
            max_physical_requests=3,
        ),
        clock=clock,
    )
    first = controller.acquire(_intent("/one"))
    assert first.lease is not None
    controller.begin_dispatch(first.lease)
    controller.complete(first.lease, TrafficOutcome(status=200))

    second = controller.acquire(_intent("/two"))
    assert second.lease is not None
    controller.begin_dispatch(second.lease)

    assert sum(clock.sleeps) == pytest.approx(2.0)
    assert controller.snapshot().physical_request_count == 2


def test_budget_snapshot_reports_live_remaining_cap_without_paths(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig.low_noise(max_physical_requests=3, max_rps=0.5),
    )
    decision = controller.acquire(_intent())
    assert decision.lease is not None
    controller.begin_dispatch(decision.lease)
    controller.complete(decision.lease, TrafficOutcome(status=200))

    budget = controller.budget_snapshot()

    assert budget["physical_request_count"] == 1
    assert budget["max_physical_requests"] == 3
    assert budget["remaining_physical_requests"] == 2
    assert budget["circuit_state"] == "closed"
    assert all("path" not in key for key in budget)

    reserved = controller.acquire(_intent("/reserved"))
    assert reserved.lease is not None
    assert controller.budget_snapshot()["remaining_physical_requests"] == 1
    controller.cancel(reserved.lease)


def test_safe_anonymous_get_cache_avoids_second_dispatch(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            cache_enabled=True,
            max_physical_requests=3,
        ),
    )
    intent = _intent(cacheable=True)
    first = controller.acquire(intent)
    assert first.lease is not None
    controller.begin_dispatch(first.lease)
    controller.complete(
        first.lease,
        TrafficOutcome(
            status=200,
            cache_record=TrafficCacheRecord(
                status=200,
                final_url="http://127.0.0.1/",
                headers={"content-type": "text/plain"},
                body="cached body",
            ),
        ),
    )

    second = controller.acquire(intent)

    assert second.kind is TrafficDecisionKind.CACHE_HIT
    assert second.cached is not None
    assert second.cached.body == "cached body"
    assert controller.snapshot().physical_request_count == 1


def test_authenticated_aliases_and_generations_never_share_cache_or_dedup(
    tmp_path: Path,
) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            cache_enabled=True,
            deduplicate=True,
        ),
    )
    base = _intent("/resource", cacheable=True)
    intents = (
        replace(base, identity_alias="alice", identity_generation=1),
        replace(base, identity_alias="bob", identity_generation=1),
        replace(base, identity_alias="alice", identity_generation=2),
    )

    first_decisions = [controller.acquire(intent) for intent in intents]

    assert all(decision.kind is TrafficDecisionKind.DISPATCH for decision in first_decisions)
    assert len({intent.fingerprint for intent in intents}) == len(intents)
    for decision in first_decisions:
        assert decision.lease is not None
        controller.begin_dispatch(decision.lease)
        controller.complete(
            decision.lease,
            TrafficOutcome(
                status=200,
                cache_record=TrafficCacheRecord(
                    status=200,
                    final_url="http://127.0.0.1/resource",
                    headers={"content-type": "text/plain"},
                    body="identity-bound",
                ),
            ),
        )

    second_decisions = [controller.acquire(intent) for intent in intents]

    assert all(decision.kind is TrafficDecisionKind.DISPATCH for decision in second_decisions)
    for decision in second_decisions:
        assert decision.lease is not None
        controller.cancel(decision.lease)
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == len(intents)
    assert snapshot.cache_hit_count == 0
    assert snapshot.deduplicated_count == 0


def test_cache_body_limit_uses_authoritative_raw_bytes(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            cache_enabled=True,
            cache_max_body_bytes=4,
        ),
    )
    intent = _intent(cacheable=True)
    first = controller.acquire(intent)
    assert first.lease is not None
    controller.begin_dispatch(first.lease)
    controller.complete(
        first.lease,
        TrafficOutcome(
            status=200,
            cache_record=TrafficCacheRecord(
                status=200,
                final_url="http://127.0.0.1/",
                headers={},
                body="x",
                body_bytes=b"12345",
            ),
        ),
    )

    assert controller.acquire(intent).kind is TrafficDecisionKind.DISPATCH


def test_ledger_rejects_non_finite_timestamps(tmp_path: Path) -> None:
    controller = _controller(tmp_path, TrafficPolicyConfig())
    payload = json.loads(controller.state_path.read_text(encoding="utf-8"))
    payload["next_physical_dispatch_at"] = float("nan")
    controller.state_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(TrafficPolicyError, match="timestamp"):
        controller.snapshot()


def test_controller_rejects_non_finite_clock(tmp_path: Path) -> None:
    with pytest.raises(TrafficPolicyError, match="clock timestamp"):
        TrafficPolicyController.open(
            tmp_path / "traffic.json",
            target_url="http://127.0.0.1/",
            config=TrafficPolicyConfig(),
            clock=lambda: float("nan"),
        )


@pytest.mark.parametrize(
    ("intent", "headers"),
    [
        (
            RequestIntent(
                "GET",
                "http://127.0.0.1/",
                headers={"Authorization": "Bearer private"},
                lane="recon",
                cacheable=True,
            ),
            {},
        ),
        (_intent(cacheable=True), {"set-cookie": "session=private"}),
        (_intent(cacheable=True), {"cache-control": "private"}),
    ],
)
def test_sensitive_or_private_traffic_is_not_cached(
    tmp_path: Path,
    intent: RequestIntent,
    headers: dict[str, str],
) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(mode=TrafficPolicyMode.ENFORCE, cache_enabled=True),
    )
    first = controller.acquire(intent)
    assert first.lease is not None
    controller.begin_dispatch(first.lease)
    controller.complete(
        first.lease,
        TrafficOutcome(
            status=200,
            cache_record=TrafficCacheRecord(
                status=200,
                final_url="http://127.0.0.1/",
                headers=headers,
                body="private",
            ),
        ),
    )

    second = controller.acquire(intent)

    assert second.kind is TrafficDecisionKind.DISPATCH


def test_inflight_deduplication_reuses_first_response(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            cache_enabled=True,
            deduplicate=True,
        ),
    )
    intent = _intent(cacheable=True)
    first = controller.acquire(intent)
    assert first.lease is not None
    controller.begin_dispatch(first.lease)
    started = Event()
    decisions: list[TrafficDecisionKind] = []

    def acquire_duplicate() -> None:
        started.set()
        decisions.append(controller.acquire(intent).kind)

    thread = Thread(target=acquire_duplicate)
    thread.start()
    assert started.wait(timeout=2)
    deadline = time.monotonic() + 2
    while controller.snapshot().deduplicated_count == 0:
        if time.monotonic() >= deadline:
            pytest.fail("duplicate request did not observe the in-flight request")
        time.sleep(0.001)
    controller.complete(
        first.lease,
        TrafficOutcome(
            status=200,
            cache_record=TrafficCacheRecord(
                status=200,
                final_url="http://127.0.0.1/",
                headers={},
                body="once",
            ),
        ),
    )
    thread.join(timeout=5)

    assert decisions == [TrafficDecisionKind.CACHE_HIT]
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == 1
    assert snapshot.deduplicated_count == 1


def test_retry_after_backoff_and_circuit_half_open(tmp_path: Path) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_retries=1,
            circuit_failure_threshold=1,
            circuit_open_seconds=10,
            backoff_max_seconds=10,
        ),
        clock=clock,
    )
    intent = _intent()
    first = controller.acquire(intent)
    assert first.lease is not None
    controller.begin_dispatch(first.lease)
    outcome = TrafficOutcome(status=429, headers={"Retry-After": "5"})
    controller.complete(first.lease, outcome)
    assert controller.should_retry(intent, outcome, 0)
    assert controller.acquire(intent, retry=True).kind is TrafficDecisionKind.BLOCKED

    clock.now += 10
    half_open = controller.acquire(intent, retry=True)
    assert half_open.lease is not None
    controller.begin_dispatch(half_open.lease)
    controller.complete(half_open.lease, TrafficOutcome(status=200))

    allowed = controller.acquire(_intent("/healthy"))
    assert allowed.kind is TrafficDecisionKind.DISPATCH
    assert controller.snapshot().circuit_open_count == 1


def test_backoff_respacing_prevents_reserved_leases_from_bursting(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_rps=2,
            backoff_max_seconds=10,
        ),
        clock=clock,
    )
    first = controller.acquire(_intent("/one"))
    second = controller.acquire(_intent("/two"))
    third = controller.acquire(_intent("/three"))
    assert first.lease is not None
    assert second.lease is not None
    assert third.lease is not None

    controller.begin_dispatch(first.lease)
    controller.complete(
        first.lease,
        TrafficOutcome(status=429, headers={"Retry-After": "5"}),
    )

    controller.begin_dispatch(second.lease)
    second_dispatched_at = clock.now
    controller.complete(second.lease, TrafficOutcome(status=200))
    controller.begin_dispatch(third.lease)

    assert second_dispatched_at == 1_005.0
    assert clock.now == 1_005.5
    assert clock.sleeps == [5.0, 0.5]


def test_cancelled_reservations_do_not_consume_pacing_slots(tmp_path: Path) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_rps=0.5,
        ),
        clock=clock,
    )
    cancelled = [controller.acquire(_intent(f"/{index}")) for index in range(3)]
    for decision in cancelled:
        assert decision.lease is not None
        controller.cancel(decision.lease)

    fresh = controller.acquire(_intent("/fresh"))
    assert fresh.lease is not None
    controller.begin_dispatch(fresh.lease)

    assert clock.now == 1_000.0
    assert clock.sleeps == []
    assert controller.snapshot().physical_request_count == 1


def test_active_paced_queue_outlives_initial_lease_timeout(tmp_path: Path) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_rps=0.5,
            lease_timeout_seconds=1,
        ),
        clock=clock,
    )
    decisions = [controller.acquire(_intent(f"/{index}")) for index in range(3)]

    for decision in decisions:
        assert decision.lease is not None
        controller.begin_dispatch(decision.lease)
        controller.complete(decision.lease, TrafficOutcome(status=200))

    assert clock.now == 1_004.0
    assert controller.snapshot().physical_request_count == 3
    assert controller.snapshot().reservation_count == 0


def test_active_wait_renews_lease_across_later_backoff(tmp_path: Path) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            lease_timeout_seconds=1,
            backoff_initial_seconds=5,
            backoff_max_seconds=5,
        ),
        clock=clock,
    )
    first = controller.acquire(_intent("/one"))
    second = controller.acquire(_intent("/two"))
    assert first.lease is not None
    assert second.lease is not None
    controller.begin_dispatch(first.lease)
    controller.complete(first.lease, TrafficOutcome(status=429))

    controller.begin_dispatch(second.lease)

    assert clock.now == 1_005.0
    assert controller.snapshot().physical_request_count == 2


def test_circuit_cancelled_queue_does_not_delay_recovery(tmp_path: Path) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_rps=0.5,
            circuit_failure_threshold=1,
            circuit_open_seconds=10,
        ),
        clock=clock,
    )
    first = controller.acquire(_intent("/one"))
    second = controller.acquire(_intent("/two"))
    third = controller.acquire(_intent("/three"))
    assert first.lease is not None
    assert second.lease is not None
    assert third.lease is not None
    controller.begin_dispatch(first.lease)
    controller.complete(first.lease, TrafficOutcome(status=429))
    with pytest.raises(TrafficPolicyBlocked, match="circuit is open"):
        controller.begin_dispatch(second.lease)
    with pytest.raises(TrafficPolicyBlocked, match="circuit is open"):
        controller.begin_dispatch(third.lease)

    clock.now += 10
    recovered = controller.acquire(_intent("/recovered"))
    assert recovered.lease is not None
    controller.begin_dispatch(recovered.lease)

    assert clock.now == 1_010.0
    assert clock.sleeps == []
    assert controller.snapshot().physical_request_count == 2


def test_queued_leases_allow_only_one_half_open_trial(tmp_path: Path) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            circuit_failure_threshold=1,
            circuit_open_seconds=10,
        ),
        clock=clock,
    )
    first = controller.acquire(_intent("/one"))
    second = controller.acquire(_intent("/two"))
    third = controller.acquire(_intent("/three"))
    assert first.lease is not None
    assert second.lease is not None
    assert third.lease is not None

    controller.begin_dispatch(first.lease)
    controller.complete(first.lease, TrafficOutcome(status=429))
    clock.now += 10

    controller.begin_dispatch(second.lease)
    with pytest.raises(TrafficPolicyBlocked, match="half-open trial"):
        controller.begin_dispatch(third.lease)

    assert controller.snapshot().physical_request_count == 2
    controller.complete(second.lease, TrafficOutcome(status=200))
    assert controller.acquire(_intent("/healthy")).kind is TrafficDecisionKind.DISPATCH


def test_forged_cache_key_cannot_escape_cache_directory(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            cache_enabled=True,
        ),
    )
    decision = controller.acquire(_intent(cacheable=True))
    assert decision.lease is not None
    controller.begin_dispatch(decision.lease)
    outside = tmp_path / "outside"
    forged = replace(decision.lease, cache_key=str(outside))
    outcome = TrafficOutcome(
        status=200,
        cache_record=TrafficCacheRecord(
            status=200,
            final_url="http://127.0.0.1/",
            headers={},
            body="safe",
        ),
    )

    with pytest.raises(TrafficPolicyError, match="cache key mismatch"):
        controller.complete(forged, outcome)

    assert not outside.with_suffix(".json").exists()
    controller.complete(decision.lease, outcome)
    assert controller.snapshot().completed_request_count == 1


def test_crashed_dispatched_lease_is_reclaimed_but_remains_charged(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            cache_enabled=True,
            lease_timeout_seconds=5,
        ),
        clock=clock,
    )
    intent = _intent(cacheable=True)
    crashed = controller.acquire(intent)
    assert crashed.lease is not None
    controller.begin_dispatch(crashed.lease)
    assert controller.snapshot().pending_dispatch_count == 1

    clock.now += 6
    recovered = controller.acquire(intent)

    assert recovered.kind is TrafficDecisionKind.DISPATCH
    snapshot = controller.snapshot()
    assert snapshot.physical_request_count == 1
    assert snapshot.pending_dispatch_count == 0
    assert snapshot.incomplete_request_count == 1


def test_unmetered_actions_lower_bound_observe_and_fail_closed_in_enforce(
    tmp_path: Path,
) -> None:
    observed = _controller(tmp_path, TrafficPolicyConfig())

    observed.record_unmetered_action()

    inspection = load_traffic_policy_snapshot(observed.state_path)
    assert inspection.target_origin == "http://127.0.0.1"
    assert inspection.snapshot.unmetered_action_count == 1
    assert inspection.snapshot.accounting_status == "lower_bound"

    enforced = TrafficPolicyController.open(
        tmp_path / "enforced.json",
        target_url="http://127.0.0.1/",
        config=TrafficPolicyConfig(mode=TrafficPolicyMode.ENFORCE),
    )
    with pytest.raises(TrafficPolicyBlocked, match="unmetered"):
        enforced.record_unmetered_action()
    snapshot = enforced.snapshot()
    assert snapshot.unmetered_action_count == 0
    assert snapshot.blocked_count == 1
    assert snapshot.accounting_status == "exact"


def test_inspection_accepts_legacy_ledger_without_unmetered_counter(tmp_path: Path) -> None:
    controller = _controller(tmp_path, TrafficPolicyConfig())
    payload = json.loads(controller.state_path.read_text(encoding="utf-8"))
    payload.pop("unmetered_action_count")
    controller.state_path.write_text(json.dumps(payload), encoding="utf-8")

    inspection = load_traffic_policy_snapshot(controller.state_path)

    assert inspection.snapshot.unmetered_action_count == 0
    assert inspection.snapshot.accounting_status == "exact"


def test_rejects_changed_config_and_symlink_ledger(tmp_path: Path) -> None:
    path = tmp_path / "traffic.json"
    config = TrafficPolicyConfig()
    TrafficPolicyController.open(path, target_url="http://127.0.0.1/", config=config)

    reference = TrafficPolicyController.open(
        path,
        target_url="http://127.0.0.1/",
        config=config,
    ).to_reference()
    reference["version"] = 999
    with pytest.raises(TrafficPolicyError, match="version"):
        TrafficPolicyController.from_reference(reference)

    with pytest.raises(TrafficPolicyError, match="configuration changed"):
        TrafficPolicyController.open(
            path,
            target_url="http://127.0.0.1/",
            config=TrafficPolicyConfig(max_rps=1),
        )

    symlink = tmp_path / "linked.json"
    symlink.symlink_to(path)
    with pytest.raises(TrafficPolicyError, match="symlink"):
        TrafficPolicyController.open(
            symlink,
            target_url="http://127.0.0.1/",
            config=config,
        )


def test_inspection_validates_opened_ledger_fd_against_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = _controller(tmp_path, TrafficPolicyConfig())
    replacement = tmp_path / "replacement.json"
    replacement.write_text(controller.state_path.read_text(encoding="utf-8"), encoding="utf-8")
    replacement.chmod(0o644)
    real_open = os.open

    def swapped_open(path: str | os.PathLike[str], flags: int, mode: int = 0o777) -> int:
        if Path(path) == controller.state_path and not flags & os.O_CREAT:
            return real_open(replacement, flags, mode)
        return real_open(path, flags, mode)

    monkeypatch.setattr(traffic_policy_module.os, "open", swapped_open)

    with pytest.raises(TrafficPolicyError, match="private"):
        load_traffic_policy_snapshot(controller.state_path)


def _cap_worker(reference: dict[str, object], queue: object, index: int) -> None:
    controller = TrafficPolicyController.from_reference(reference)
    decision = controller.acquire(_intent(f"/{index}"))
    dispatched = decision.kind is TrafficDecisionKind.DISPATCH
    if dispatched and decision.lease is not None:
        controller.begin_dispatch(decision.lease)
        controller.complete(decision.lease, TrafficOutcome(status=200))
    queue.put(dispatched)  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name != "posix", reason="process locking uses POSIX flock")
def test_processes_cannot_oversubscribe_total_cap(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_physical_requests=2,
        ),
    )
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(target=_cap_worker, args=(controller.to_reference(), queue, index))
        for index in range(6)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=15)
        assert process.exitcode == 0

    assert sum(bool(queue.get(timeout=2)) for _process in processes) == 2
    assert controller.snapshot().physical_request_count == 2
