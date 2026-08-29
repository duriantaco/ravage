# ruff: noqa: PLR2004, S105
from __future__ import annotations

import json
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from typing import TYPE_CHECKING

import pytest
from ravage.traffic import (
    CapturedHttpExchange,
    ReplayReceipt,
    RequestContract,
    TrafficContractError,
    TrafficStore,
    TrafficStoreError,
    aggregate_request_contracts,
    body_metadata,
    build_captured_http_exchange,
    build_replay_receipt,
    redact_headers,
    sanitize_url,
)

if TYPE_CHECKING:
    from pathlib import Path

_SECRET_A = "-".join(("sk", "proj", "FAKESECRETVALUE123456789"))
_SECRET_B = "-".join(("sk", "proj", "OTHERSECRETVALUE987654321"))
_CAPTURED_AT = "2026-08-18T01:02:03Z"


def _capture(
    *,
    secret: str = _SECRET_A,
    source: str = "probe",
    status: int = 200,
    captured_at: str = _CAPTURED_AT,
    query_order: str = "token&q",
) -> CapturedHttpExchange:
    query = f"token={secret}&q=hello" if query_order == "token&q" else f"q=other&token={secret}"
    return build_captured_http_exchange(
        capture_session_id="capture-1",
        source=source,
        source_observation_id=f"observation-{secret}",
        identity_alias="admin",
        method="post",
        url=f"https://user:{secret}@example.test/reset/{secret}?{query}",
        resource_type="document",
        navigation=True,
        request_headers=[
            ("Authorization", f"Bearer {secret}"),
            ("Content-Type", "application/json; charset=utf-8"),
            ("X-Trace", secret),
        ],
        request_body={"password": secret, "name": "Ada"},
        request_sent=True,
        response_status=status,
        response_final_url=f"https://example.test/account?session={secret}",
        response_headers=[
            ("Set-Cookie", f"session={secret}; HttpOnly"),
            ("Content-Type", "text/html"),
            ("Location", f"/next?token={secret}"),
        ],
        response_body=f"flag{{{secret}}}",
        response_error=f"authorization: Bearer {secret}",
        response_elapsed_ms=17,
        scope_decision="allowed",
        scope_reason=f"token={secret}",
        captured_at=captured_at,
        unresolved_slots=("header:authorization", "body:password"),
        known_secrets=(secret,),
    )


def test_capture_builder_never_persists_raw_request_or_response_secrets() -> None:
    exchange = _capture()
    serialized = json.dumps(exchange.to_json(), sort_keys=True)

    assert _SECRET_A not in serialized
    assert "flag{" not in serialized
    assert "user:" not in exchange.request_url
    assert exchange.request_url == (
        "https://example.test/reset/:redacted?token=%5BREDACTED%5D&q=%5BREDACTED%5D"
    )
    assert exchange.request_headers == (
        ("authorization", "[REDACTED]"),
        ("content-type", "application/json"),
        ("x-trace", "[REDACTED]"),
    )
    assert exchange.response_headers[0] == ("set-cookie", "[REDACTED]")
    assert exchange.response_headers[2] == (
        "location",
        "/next?token=%5BREDACTED%5D",
    )
    assert exchange.request_body_field_names == ("name", "password")
    assert exchange.request_body_bytes > 0
    assert exchange.request_body_sha256 == "unavailable"
    assert exchange.response_body_bytes > 0
    assert exchange.response_body_sha256 == "unavailable"
    assert exchange.response_error == "authorization: [REDACTED]"
    assert exchange.scope_reason == "token=[REDACTED]"


def test_schemas_are_frozen_and_round_trip_with_tamper_detection() -> None:
    exchange = _capture()
    with pytest.raises(FrozenInstanceError):
        exchange.request_method = "GET"  # type: ignore[misc]

    restored = CapturedHttpExchange.from_json(exchange.to_json())
    assert restored == exchange

    tampered = exchange.to_json()
    tampered["semantic_fingerprint"] = "sha256:" + "0" * 64
    with pytest.raises(TrafficContractError, match="fingerprint mismatch"):
        CapturedHttpExchange.from_json(tampered)

    with pytest.raises(TrafficContractError, match="persisted-safe canonical form"):
        replace(exchange, response_error="password=raw-secret")


def test_configured_arbitrary_secret_is_removed_from_all_structural_metadata() -> None:
    secret = "correct-horse-battery-staple"
    exchange = build_captured_http_exchange(
        capture_session_id="capture-1",
        source="browser",
        source_observation_id=secret,
        identity_alias=secret,
        method="POST",
        url=f"https://{secret}.example.test/{secret}?{secret}=value",
        request_headers=[(secret, "value"), ("Content-Type", "application/json")],
        request_body={secret: "value"},
        request_sent=True,
        response_error=secret,
        scope_decision="allowed",
        scope_reason=secret,
        unresolved_slots=(secret,),
        known_secrets=(secret,),
        captured_at=_CAPTURED_AT,
    )

    assert secret not in json.dumps(exchange.to_json(), sort_keys=True)


def test_semantic_fingerprint_ignores_values_order_time_and_response() -> None:
    first = _capture(secret=_SECRET_A, status=200, query_order="token&q")
    second = _capture(
        secret=_SECRET_B,
        status=503,
        query_order="q&token",
        captured_at="2026-08-18T02:03:04Z",
    )

    assert first.semantic_fingerprint == second.semantic_fingerprint

    different_method = build_captured_http_exchange(
        capture_session_id="capture-1",
        source="probe",
        method="GET",
        url="https://example.test/reset/value?q=one&token=two",
        request_sent=True,
        scope_decision="allowed",
        captured_at=_CAPTURED_AT,
    )
    assert different_method.semantic_fingerprint != first.semantic_fingerprint


def test_contract_aggregation_is_deterministic_and_preserves_observation_facts() -> None:
    first = _capture(source="probe", status=200)
    second = _capture(
        secret=_SECRET_B,
        source="browser",
        status=503,
        captured_at="2026-08-18T02:03:04Z",
        query_order="q&token",
    )

    contracts = aggregate_request_contracts((second, first))

    assert len(contracts) == 1
    contract = contracts[0]
    assert isinstance(contract, RequestContract)
    assert contract.semantic_fingerprint == first.semantic_fingerprint
    assert contract.observation_count == 2
    assert contract.sources == ("browser", "probe")
    assert contract.status_codes == (200, 503)
    assert contract.resource_types == ("document",)
    assert contract.navigation_observed is True
    assert contract.first_seen_at == "2026-08-18T01:02:03.000Z"
    assert contract.last_seen_at == "2026-08-18T02:03:04.000Z"
    assert RequestContract.from_json(contract.to_json()) == contract


def test_body_metadata_extracts_only_field_names() -> None:
    form = body_metadata(
        f"username=ada&password={_SECRET_A}",
        media_type="application/x-www-form-urlencoded",
    )
    multipart = body_metadata(
        (
            b'--x\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n'
            + _SECRET_A.encode()
            + b"\r\n--x--\r\n"
        ),
        media_type="multipart/form-data; boundary=x",
    )

    assert form.field_names == ("password", "username")
    assert multipart.field_names == ("csrf_token",)
    assert _SECRET_A not in repr(form)
    assert _SECRET_A not in repr(multipart)


def test_body_metadata_rejects_excessively_nested_json_without_crashing() -> None:
    nested_json = (b"[" * 10_000) + b"0" + (b"]" * 10_000)

    metadata = body_metadata(nested_json, media_type="application/json")

    assert metadata.byte_length == len(nested_json)
    assert metadata.field_names == ()


def test_body_digests_are_never_persisted_even_when_an_adapter_supplies_one() -> None:
    metadata = body_metadata(
        b"123456",
        media_type="text/plain",
        sha256="a" * 64,
    )

    assert metadata.sha256 == "unavailable"


def test_query_name_case_and_multiplicity_are_part_of_request_identity() -> None:
    upper = build_captured_http_exchange(
        capture_session_id="capture-1",
        source="probe",
        method="GET",
        url="https://example.test/search?UserID=one&UserID=two",
        request_sent=True,
        scope_decision="allowed",
        captured_at=_CAPTURED_AT,
    )
    lower = build_captured_http_exchange(
        capture_session_id="capture-1",
        source="probe",
        method="GET",
        url="https://example.test/search?userid=one",
        request_sent=True,
        scope_decision="allowed",
        captured_at=_CAPTURED_AT,
    )

    assert upper.semantic_fingerprint != lower.semantic_fingerprint


def test_binary_and_multipart_request_bodies_are_not_marked_replayable() -> None:
    exchange = build_captured_http_exchange(
        capture_session_id="capture-1",
        source="browser",
        method="POST",
        url="https://example.test/upload",
        request_headers={"Content-Type": "multipart/form-data; boundary=secret-boundary"},
        request_body=b"\x00\xffbinary",
        request_sent=True,
        scope_decision="allowed",
        captured_at=_CAPTURED_AT,
    )

    assert exchange.replayability == "not_replayable"
    assert exchange.unresolved_slots == ()


def test_identity_bound_capture_is_never_replayed_as_anonymous() -> None:
    exchange = build_captured_http_exchange(
        capture_session_id="capture-1",
        source="managed-auth",
        identity_alias="administrator",
        method="GET",
        url="https://example.test/account",
        request_sent=True,
        scope_decision="allowed",
        captured_at=_CAPTURED_AT,
    )

    assert exchange.replayability == "not_replayable"
    assert exchange.unresolved_slots == ()
    with pytest.raises(TrafficContractError, match="managed authentication"):
        replace(exchange, replayability="safe")


@pytest.mark.parametrize("content_encoding", ["gzip", "br"])
def test_content_encoded_request_bodies_are_not_marked_replayable(
    content_encoding: str,
) -> None:
    exchange = build_captured_http_exchange(
        capture_session_id="capture-1",
        source="browser",
        method="POST",
        url="https://example.test/encoded",
        request_headers={
            "Content-Type": "application/json",
            "Content-Encoding": content_encoding,
        },
        request_body=b"encoded-body",
        request_sent=True,
        scope_decision="allowed",
        captured_at=_CAPTURED_AT,
    )

    assert exchange.replayability == "not_replayable"
    assert exchange.unresolved_slots == ()
    with pytest.raises(TrafficContractError, match="content-encoded bodies"):
        replace(
            exchange,
            replayability="requires_authorization",
            unresolved_slots=("body",),
        )


def test_url_and_header_redaction_is_idempotent_and_preserves_duplicates() -> None:
    raw_url = f"https://user:{_SECRET_A}@example.test/token/{_SECRET_A}?x=1&x=2"
    safe_url = sanitize_url(raw_url, known_secrets=(_SECRET_A,))
    headers = redact_headers(
        [("Set-Cookie", f"a={_SECRET_A}"), ("Set-Cookie", f"b={_SECRET_A}")],
        response=True,
    )

    assert sanitize_url(safe_url) == safe_url
    assert headers == (
        ("set-cookie", "[REDACTED]"),
        ("set-cookie", "[REDACTED]"),
    )
    assert safe_url.endswith("?x=%5BREDACTED%5D&x=%5BREDACTED%5D")


def test_url_path_decoding_preserves_literal_plus_semantics() -> None:
    safe_url = sanitize_url(
        "https://example.test/literal+plus/encoded%2Bplus/encoded%20space/"
        "double%252Bplus/double%252Fslash"
    )

    assert safe_url == (
        "https://example.test/literal+plus/encoded+plus/encoded%20space/"
        "double%252Bplus/double%252Fslash"
    )
    assert sanitize_url(safe_url) == safe_url


def test_store_assigns_ids_round_trips_and_uses_private_files(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    store = TrafficStore.create(workspace)
    first = store.append_exchange(_capture())
    second = store.append_exchange(_capture(secret=_SECRET_B, captured_at="2026-08-18T02:03:04Z"))

    assert store.root == workspace / "traffic"
    assert first.exchange_id == "rq_0001"
    assert second.exchange_id == "rq_0002"
    assert store.exchanges() == (first, second)
    assert store.exchange("rq_0002") == second
    assert store.contract(first.semantic_fingerprint) == store.contracts()[0]
    assert store.contracts()[0].observation_count == 2
    assert stat.S_IMODE(store.exchanges_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.replays_path.stat().st_mode) == 0o600
    assert _SECRET_A not in store.exchanges_path.read_text(encoding="utf-8")
    assert _SECRET_B not in store.exchanges_path.read_text(encoding="utf-8")
    assert TrafficStore.open(workspace).exchanges() == (first, second)


def test_store_appends_atomically_across_threads(tmp_path: Path) -> None:
    store = TrafficStore.create(tmp_path / "workspace")

    def append(index: int) -> str:
        exchange = build_captured_http_exchange(
            capture_session_id="threaded",
            source="probe",
            source_observation_id=f"observation-{index}",
            method="GET",
            url=f"https://example.test/items/{index}?token={_SECRET_A}",
            request_sent=True,
            response_status=200,
            response_body=f"result-{index}",
            scope_decision="allowed",
            captured_at=_CAPTURED_AT,
            known_secrets=(_SECRET_A,),
        )
        return store.append_exchange(exchange).exchange_id

    with ThreadPoolExecutor(max_workers=8) as executor:
        ids = tuple(executor.map(append, range(32)))

    assert len(set(ids)) == 32
    assert [exchange.sequence for exchange in store.exchanges()] == list(range(1, 33))
    for line in store.exchanges_path.read_text(encoding="utf-8").splitlines():
        assert isinstance(json.loads(line), dict)


def test_replay_receipt_is_safe_and_must_reference_a_stored_exchange(tmp_path: Path) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    source = store.append_exchange(_capture())
    receipt = build_replay_receipt(
        source_exchange=source,
        mutation_slots=("query:q", "header:authorization"),
        side_effect_authorized=True,
        request_sent=True,
        response_status=201,
        response_final_url=f"https://example.test/done?token={_SECRET_A}",
        response_body=f"flag{{{_SECRET_A}}}",
        response_error=f"password={_SECRET_A}",
        response_elapsed_ms=9,
        scope_decision="allowed",
        outcome="changed",
        replayed_at=_CAPTURED_AT,
        known_secrets=(_SECRET_A,),
    )
    stored = store.append_replay(receipt)

    assert stored.replay_id == "rp_0001"
    assert stored.source_exchange_id == "rq_0001"
    assert ReplayReceipt.from_json(stored.to_json()) == stored
    assert _SECRET_A not in store.replays_path.read_text(encoding="utf-8")

    other_store = TrafficStore.create(tmp_path / "other-workspace")
    with pytest.raises(TrafficStoreError, match="source exchange"):
        other_store.append_replay(receipt)


def test_store_rejects_corrupt_or_tampered_jsonl(tmp_path: Path) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    stored = store.append_exchange(_capture())
    payload = stored.to_json()
    payload["semantic_fingerprint"] = "sha256:" + "f" * 64
    store.exchanges_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    with pytest.raises(TrafficStoreError, match="fingerprint mismatch"):
        store.exchanges()


def test_store_rejects_a_symlinked_traffic_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "traffic").symlink_to(outside, target_is_directory=True)

    with pytest.raises(TrafficStoreError, match="cannot be a symlink"):
        TrafficStore.create(workspace)

    assert not list(outside.iterdir())


def test_read_only_store_does_not_create_or_repair_artifacts(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(TrafficStoreError, match="could not inspect"):
        TrafficStore.open(missing)
    assert not missing.exists()

    workspace = tmp_path / "workspace"
    writer = TrafficStore.create(workspace)
    writer.exchanges_path.chmod(0o644)
    with pytest.raises(TrafficStoreError, match="permissions must be owner-only"):
        TrafficStore.open(workspace)
    assert stat.S_IMODE(writer.exchanges_path.stat().st_mode) == 0o644


def test_append_sequence_does_not_reload_the_full_exchange_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    store.append_exchange(_capture())

    def fail_reload() -> tuple[CapturedHttpExchange, ...]:
        raise AssertionError("append must not parse all prior exchanges")

    monkeypatch.setattr(store, "_load_exchanges_unlocked", fail_reload)
    second = store.append_exchange(_capture(secret=_SECRET_B))

    assert second.exchange_id == "rq_0002"
