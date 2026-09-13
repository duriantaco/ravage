from __future__ import annotations

import hashlib
import http.client
import json
import socket
import threading
from dataclasses import dataclass, field
from decimal import Decimal, localcontext
from pathlib import Path
from urllib.parse import urlparse

import pytest
from ravage.xben_parts.comparison_model_gateway import (
    ComparisonModelGateway,
    ModelGatewayError,
    ModelGatewayPolicy,
    ModelPricing,
    RowRegistrationError,
    RowSealError,
    UpstreamResponse,
    _safe_content_type,
    validate_model_gateway_receipt,
)

MODEL = "gpt-5.4-mini-2026-03-17"
REASONING = "high"


@dataclass
class FakeTransport:
    responses: list[UpstreamResponse]
    requests: list[dict[str, object]] = field(default_factory=list)

    def send(
        self,
        body: bytes,
        *,
        api_key: str,
        timeout_seconds: int,
        maximum_response_bytes: int,
    ) -> UpstreamResponse:
        self.requests.append(
            {
                "body": body,
                "api_key": api_key,
                "timeout_seconds": timeout_seconds,
                "maximum_response_bytes": maximum_response_bytes,
            }
        )
        return self.responses.pop(0)


@dataclass
class BlockingTransport:
    response: UpstreamResponse
    entered: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)
    requests: list[bytes] = field(default_factory=list)

    def send(
        self,
        body: bytes,
        *,
        api_key: str,
        timeout_seconds: int,
        maximum_response_bytes: int,
    ) -> UpstreamResponse:
        del api_key, timeout_seconds, maximum_response_bytes
        self.requests.append(body)
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise TimeoutError("test did not release blocked upstream request")
        return self.response


@dataclass
class FailingTransport:
    calls: int = 0

    def send(
        self,
        body: bytes,
        *,
        api_key: str,
        timeout_seconds: int,
        maximum_response_bytes: int,
    ) -> UpstreamResponse:
        del body, api_key, timeout_seconds, maximum_response_bytes
        self.calls += 1
        raise TimeoutError("synthetic upstream timeout")


class PausingAdmissionGateway(ComparisonModelGateway):
    """Expose the old ordinal-to-reservation race window deterministically."""

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.ordinal_entered = threading.Event()
        self.ordinal_release = threading.Event()

    def _begin_ordinal(self, row: object, request_hash: str) -> int:
        ordinal = super()._begin_ordinal(row, request_hash)  # type: ignore[arg-type]
        self.ordinal_entered.set()
        if not self.ordinal_release.wait(timeout=5):
            raise TimeoutError("test did not release admitted request")
        return ordinal


def test_gateway_enforces_contract_accounts_usage_and_retains_hashes_only(
    tmp_path: Path,
) -> None:
    prompt_marker = "prompt-must-not-enter-receipt"
    upstream_key = "upstream-secret-must-not-enter-receipt"
    response = _json_response(prompt_tokens=120, cached_tokens=20, completion_tokens=30)
    transport = FakeTransport([response])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key=upstream_key, transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-001", max_requests=2, max_cost_usd="0.05")
    try:
        status, body = _post(gateway, token, _request(prompt_marker))
    finally:
        gateway.close()

    assert status == 200
    assert json.loads(body)["model"] == MODEL
    sent = json.loads(transport.requests[0]["body"])
    assert sent["model"] == MODEL
    assert sent["reasoning_effort"] == REASONING
    assert sent["max_completion_tokens"] == 100
    assert sent["n"] == 1
    assert sent["service_tier"] == "default"
    assert sent["store"] is False
    assert transport.requests[0]["api_key"] == upstream_key

    receipt_path = tmp_path / "model-gateway.json"
    receipt = gateway.seal_row("primary-001", receipt_path)
    serialized = receipt_path.read_text(encoding="utf-8")
    assert prompt_marker not in serialized
    assert upstream_key not in serialized
    assert token not in serialized
    assert receipt["valid"] is True
    assert receipt["totals"] == {
        "requests_started": 1,
        "requests_recorded": 1,
        "charged_cost_usd": "0.0002115",
        "known_actual_cost_usd": "0.0002115",
        "within_request_limit": True,
        "within_cost_limit": True,
    }
    record = receipt["records"][0]
    assert record["accounting_status"] == "verified"
    assert record["usage"] == {
        "input_tokens": 120,
        "cached_input_tokens": 20,
        "output_tokens": 30,
    }
    assert str(record["raw_request_sha256"]).startswith("sha256:")
    assert (
        validate_model_gateway_receipt(
            receipt,
            expected_row_id="primary-001",
            expected_policy_sha256=gateway.policy_digest,
            expected_max_requests=2,
            expected_max_cost_usd="0.05",
        )
        == receipt
    )


def test_gateway_normalizes_pinned_client_compaction_request(tmp_path: Path) -> None:
    transport = FakeTransport([_json_response(completion_tokens=20)])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-025", max_requests=1, max_cost_usd="0.05")
    request = {
        "model": MODEL,
        "messages": [{"role": "user", "content": "compact this conversation"}],
        "max_tokens": 64,
    }
    try:
        status, _ = _post(gateway, token, request)
    finally:
        gateway.close()

    assert status == 200
    assert len(transport.requests) == 1
    forwarded_bytes = transport.requests[0]["body"]
    assert isinstance(forwarded_bytes, bytes)
    forwarded = json.loads(forwarded_bytes)
    assert forwarded["reasoning_effort"] == REASONING
    assert forwarded["max_completion_tokens"] == 64
    assert "max_tokens" not in forwarded
    receipt = gateway.seal_row("primary-025", tmp_path / "client-compaction.json")
    assert receipt["records"][0]["input_token_upper_bound"] == len(forwarded_bytes) + 4096
    assert (
        validate_model_gateway_receipt(
            receipt,
            expected_row_id="primary-025",
            expected_policy_sha256=gateway.policy_digest,
            expected_max_requests=1,
            expected_max_cost_usd="0.05",
        )
        == receipt
    )


@pytest.mark.parametrize(
    ("cap_fields", "expected_cap"),
    [({}, 100), ({"max_completion_tokens": 64}, 64)],
)
def test_gateway_accepts_omitted_or_smaller_canonical_output_cap(
    cap_fields: dict[str, object],
    expected_cap: int,
    tmp_path: Path,
) -> None:
    transport = FakeTransport([_json_response(completion_tokens=10)])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-026", max_requests=1, max_cost_usd="0.05")
    request: dict[str, object] = {
        "model": MODEL,
        "reasoning_effort": REASONING,
        "messages": [{"role": "user", "content": "bounded"}],
        **cap_fields,
    }
    try:
        status, _ = _post(gateway, token, request)
    finally:
        gateway.close()

    assert status == 200
    forwarded = json.loads(transport.requests[0]["body"])
    assert forwarded["max_completion_tokens"] == expected_cap
    assert "max_tokens" not in forwarded
    assert gateway.seal_row("primary-026", tmp_path / "accepted-cap.json")["valid"] is True


def test_receipt_verifier_rejects_recomputed_but_false_cost_accounting(
    tmp_path: Path,
) -> None:
    gateway = ComparisonModelGateway(
        policy=_policy(),
        upstream_api_key="secret",
        transport=FakeTransport([_json_response()]),
    )
    gateway.start()
    token = gateway.register_row("primary-010", max_requests=1, max_cost_usd="0.05")
    try:
        assert _post(gateway, token, _request("tamper"))[0] == 200
    finally:
        gateway.close()
    receipt = gateway.seal_row("primary-010", tmp_path / "tamper.json")
    receipt["records"][0]["actual_cost_usd"] = "0"
    body = {key: value for key, value in receipt.items() if key != "document_sha256"}
    canonical = json.dumps(
        body,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    receipt["document_sha256"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    with pytest.raises(Exception, match="actual cost is inconsistent"):
        validate_model_gateway_receipt(
            receipt,
            expected_row_id="primary-010",
            expected_policy_sha256=gateway.policy_digest,
            expected_max_requests=1,
            expected_max_cost_usd="0.05",
        )


def test_gateway_validates_stream_terminal_usage(tmp_path: Path) -> None:
    chunks = [
        {"id": "one", "model": MODEL, "choices": [{"delta": {"content": "ok"}}]},
        {
            "id": "one",
            "model": MODEL,
            "choices": [],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "prompt_tokens_details": {"cached_tokens": 0},
            },
        },
    ]
    body = (
        b"".join(b"data: " + json.dumps(chunk).encode() + b"\n\n" for chunk in chunks)
        + b"data: [DONE]\n\n"
    )
    transport = FakeTransport([UpstreamResponse(200, body, "text/event-stream")])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-002", max_requests=1, max_cost_usd="0.05")
    try:
        status, returned = _post(gateway, token, _request("stream", stream=True))
    finally:
        gateway.close()

    assert status == 200
    assert returned == body
    forwarded = json.loads(transport.requests[0]["body"])
    assert forwarded["stream_options"] == {"include_usage": True}
    receipt = gateway.seal_row("primary-002", tmp_path / "stream.json")
    assert receipt["valid"] is True


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"model": "gpt-5.4-mini"}, "model_mismatch"),
        ({"reasoning_effort": "low"}, "reasoning_effort_mismatch"),
        ({"reasoning_effort": None}, "reasoning_effort_mismatch"),
        ({"max_tokens": 100}, "completion_token_field_conflict"),
        ({"service_tier": "priority"}, "service_tier_mismatch"),
        ({"store": True}, "stored_completion_forbidden"),
        ({"n": True}, "single_choice_required"),
        ({"n": 1.0}, "single_choice_required"),
    ],
)
def test_gateway_rejects_contract_drift_and_invalidates_row(
    tmp_path: Path, override: dict[str, object], code: str
) -> None:
    transport = FakeTransport([_json_response()])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-003", max_requests=1, max_cost_usd="0.05")
    request = _request("test")
    request.update(override)
    try:
        status, body = _post(gateway, token, request)
    finally:
        gateway.close()

    assert status == 400
    assert json.loads(body)["error"]["code"] == code
    assert transport.requests == []
    receipt = gateway.seal_row("primary-003", tmp_path / f"{code}.json")
    assert receipt["valid"] is False
    assert receipt["records"][0]["failure_code"] == code


@pytest.mark.parametrize("field", ["max_completion_tokens", "max_tokens"])
@pytest.mark.parametrize("value", [0, -1, 101, True, 1.5])
def test_gateway_rejects_invalid_output_caps_before_upstream(
    field: str,
    value: object,
    tmp_path: Path,
) -> None:
    transport = FakeTransport([_json_response()])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-027", max_requests=1, max_cost_usd="0.05")
    request = {
        "model": MODEL,
        "reasoning_effort": REASONING,
        "messages": [{"role": "user", "content": "invalid cap"}],
        field: value,
    }
    try:
        status, body = _post(gateway, token, request)
    finally:
        gateway.close()

    assert status == 400
    assert json.loads(body)["error"]["code"] == "completion_token_contract_mismatch"
    assert transport.requests == []
    receipt = gateway.seal_row("primary-027", tmp_path / "invalid-cap.json")
    assert receipt["valid"] is False


def test_gateway_request_limit_is_atomic_and_does_not_forward_extra_call(
    tmp_path: Path,
) -> None:
    transport = FakeTransport([_json_response()])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-004", max_requests=1, max_cost_usd="0.05")
    try:
        first, _ = _post(gateway, token, _request("one"))
        second, body = _post(gateway, token, _request("two"))
    finally:
        gateway.close()

    assert first == 200
    assert second == 429
    assert json.loads(body)["error"]["code"] == "model_request_limit_reached"
    assert len(transport.requests) == 1
    receipt = gateway.seal_row("primary-004", tmp_path / "limit.json")
    assert receipt["totals"]["requests_started"] == 1
    assert receipt["valid"] is True


def test_gateway_reduces_output_reservation_before_forwarding_at_cost_ceiling(
    tmp_path: Path,
) -> None:
    transport = FakeTransport([_json_response(completion_tokens=1)])
    gateway = ComparisonModelGateway(
        policy=_policy(campaign_cost="0.0035"),
        upstream_api_key="secret",
        transport=transport,
    )
    gateway.start()
    token = gateway.register_row("primary-005", max_requests=1, max_cost_usd="0.0035")
    try:
        status, _ = _post(gateway, token, _request("bounded"))
    finally:
        gateway.close()

    assert status == 200
    forwarded = json.loads(transport.requests[0]["body"])
    assert 0 < forwarded["max_completion_tokens"] < 100
    receipt = gateway.seal_row("primary-005", tmp_path / "cost.json")
    normalized_before_dynamic_cap = {
        **_request("bounded"),
        "n": 1,
        "service_tier": "default",
        "store": False,
    }
    normalized_bytes = json.dumps(
        normalized_before_dynamic_cap,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    forwarded_bytes = transport.requests[0]["body"]
    record = receipt["records"][0]
    assert record["input_token_upper_bound"] == len(normalized_bytes) + 4096
    assert record["forwarded_request_sha256"] == (
        "sha256:" + hashlib.sha256(forwarded_bytes).hexdigest()
    )
    assert float(receipt["totals"]["charged_cost_usd"]) <= 0.0035


@pytest.mark.parametrize(
    "field",
    [
        "audio",
        "frequency_penalty",
        "logit_bias",
        "logprobs",
        "modalities",
        "prediction",
        "presence_penalty",
        "seed",
        "stop",
        "temperature",
        "top_logprobs",
        "top_p",
        "verbosity",
        "web_search_options",
    ],
)
def test_gateway_rejects_generation_controls_before_upstream(tmp_path: Path, field: str) -> None:
    transport = FakeTransport([_json_response()])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-022", max_requests=1, max_cost_usd="0.05")
    request = _request("defaults")
    request[field] = 0
    try:
        status, body = _post(gateway, token, request)
    finally:
        gateway.close()

    assert status == 400
    assert json.loads(body)["error"]["code"] == "generation_control_forbidden"
    assert transport.requests == []
    receipt = gateway.seal_row("primary-022", tmp_path / f"{field}.json")
    assert receipt["valid"] is False
    assert receipt["records"][0]["failure_code"] == "generation_control_forbidden"


@pytest.mark.parametrize("field", ["prompt_cache_key", "safety_identifier", "user"])
def test_gateway_rejects_evaluator_reserved_fields_before_upstream(
    field: str,
    tmp_path: Path,
) -> None:
    transport = FakeTransport([_json_response()])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-028", max_requests=1, max_cost_usd="0.05")
    request = _request("reserved")
    request[field] = "arm-controlled"
    try:
        status, body = _post(gateway, token, request)
    finally:
        gateway.close()

    assert status == 400
    assert json.loads(body)["error"]["code"] == "evaluator_reserved_field"
    assert transport.requests == []
    receipt = gateway.seal_row("primary-028", tmp_path / f"{field}.json")
    assert receipt["valid"] is False


def test_gateway_rejects_unknown_request_fields_fail_closed(tmp_path: Path) -> None:
    transport = FakeTransport([_json_response()])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-023", max_requests=1, max_cost_usd="0.05")
    request = _request("unknown")
    request["future_sampling_knob"] = 1
    try:
        status, body = _post(gateway, token, request)
    finally:
        gateway.close()

    assert status == 400
    assert json.loads(body)["error"]["code"] == "unsupported_request_field"
    assert transport.requests == []
    receipt = gateway.seal_row("primary-023", tmp_path / "unknown.json")
    assert receipt["valid"] is False


def test_gateway_transport_is_attempted_exactly_once(tmp_path: Path) -> None:
    transport = FailingTransport()
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-024", max_requests=1, max_cost_usd="0.05")
    try:
        status, body = _post(gateway, token, _request("one attempt"))
    finally:
        gateway.close()

    assert status == 502
    assert json.loads(body)["error"]["code"] == "upstream_transport_failed"
    assert transport.calls == 1
    receipt = gateway.seal_row("primary-024", tmp_path / "transport.json")
    assert receipt["valid"] is False
    assert receipt["records"][0]["failure_code"] == "upstream_transport:TimeoutError"


def test_policy_digest_commits_request_and_reservation_rules() -> None:
    policy = _policy()
    serialized = json.dumps(
        policy.to_json(),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    assert policy.digest == "sha256:" + hashlib.sha256(serialized).hexdigest()
    policy_json = policy.to_json()
    assert policy_json["schema_version"] == "ravage.xben.model-gateway-policy.v3"
    request_policy = policy_json["request_field_policy"]
    assert isinstance(request_policy, dict)
    assert request_policy["output_token_cap"] == {
        "accepted_fields": ["max_completion_tokens", "max_tokens"],
        "conflict": "reject",
        "missing": "insert_policy_maximum",
        "validation": "positive_integer_no_greater_than_policy_maximum",
        "forwarded_field": "max_completion_tokens",
    }
    assert request_policy["reasoning_effort"] == {
        "missing": "insert_frozen_policy_value",
        "provided": "require_exact_frozen_policy_value",
        "explicit_null": "reject",
    }
    assert request_policy["evaluator_reserved_fields"] == {
        "enforcement": "reject_if_present",
        "fields": ["prompt_cache_key", "safety_identifier", "user"],
    }
    generation_fields = request_policy["provider_default_generation_fields"]
    assert isinstance(generation_fields, dict)
    assert "max_tokens" not in generation_fields["fields"]


def test_receipt_verifier_rejects_rehashed_request_policy_tampering(tmp_path: Path) -> None:
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=FakeTransport([])
    )
    gateway.register_row("primary-029", max_requests=1, max_cost_usd="0.05")
    receipt = gateway.seal_row("primary-029", tmp_path / "policy-tamper.json")
    request_policy = receipt["policy"]["request_field_policy"]
    request_policy["output_token_cap"]["conflict"] = "allow"
    policy_bytes = json.dumps(
        receipt["policy"],
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    receipt["policy_sha256"] = "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
    body = {key: value for key, value in receipt.items() if key != "document_sha256"}
    document_bytes = json.dumps(
        body,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    receipt["document_sha256"] = "sha256:" + hashlib.sha256(document_bytes).hexdigest()

    with pytest.raises(ModelGatewayError, match="request-field policy is invalid"):
        validate_model_gateway_receipt(
            receipt,
            expected_row_id="primary-029",
            expected_policy_sha256=receipt["policy_sha256"],
            expected_max_requests=1,
            expected_max_cost_usd="0.05",
        )


def test_campaign_reservations_are_atomic_across_concurrent_rows(tmp_path: Path) -> None:
    transport = BlockingTransport(_json_response(completion_tokens=1))
    gateway = ComparisonModelGateway(
        policy=_policy(campaign_cost="0.0037"),
        upstream_api_key="secret",
        transport=transport,
    )
    gateway.start()
    first_token = gateway.register_row("primary-008", max_requests=1, max_cost_usd="0.0037")
    second_token = gateway.register_row("primary-009", max_requests=1, max_cost_usd="0.0037")
    first_result: list[tuple[int, bytes]] = []
    worker = threading.Thread(
        target=lambda: first_result.append(_post(gateway, first_token, _request("first")))
    )
    worker.start()
    assert transport.entered.wait(timeout=5)
    try:
        second_status, second_body = _post(gateway, second_token, _request("second"))
    finally:
        transport.release.set()
        worker.join(timeout=5)
        gateway.close()

    assert not worker.is_alive()
    assert first_result[0][0] == 200
    assert second_status == 429
    assert json.loads(second_body)["error"]["code"] == "model_cost_limit_reached"
    assert len(transport.requests) == 1
    first = gateway.seal_row("primary-008", tmp_path / "first.json")
    second = gateway.seal_row("primary-009", tmp_path / "second.json")
    assert first["valid"] is True
    assert second["valid"] is False


def test_seal_closes_the_admission_to_reservation_race(tmp_path: Path) -> None:
    gateway = PausingAdmissionGateway(
        policy=_policy(),
        upstream_api_key="secret",
        transport=FakeTransport([_json_response()]),
    )
    gateway.start()
    token = gateway.register_row("primary-011", max_requests=1, max_cost_usd="0.05")
    response: list[tuple[int, bytes]] = []
    worker = threading.Thread(
        target=lambda: response.append(_post(gateway, token, _request("paused")))
    )
    worker.start()
    assert gateway.ordinal_entered.wait(timeout=5)

    receipt_path = tmp_path / "admission-race.json"
    receipt = gateway.close_row_and_seal(
        "primary-011",
        receipt_path,
        drain_timeout_seconds=0,
    )
    sealed_bytes = receipt_path.read_bytes()
    gateway.ordinal_release.set()
    worker.join(timeout=5)
    gateway.close()

    assert not worker.is_alive()
    assert response[0][0] == 409
    assert receipt_path.read_bytes() == sealed_bytes
    assert receipt["valid"] is False
    assert receipt["records"][0]["failure_code"] == ("row_seal_drain_timeout_before_forward")
    assert receipt["totals"]["charged_cost_usd"] == "0"


def test_bounded_seal_charges_reservation_and_ignores_late_upstream_result(
    tmp_path: Path,
) -> None:
    transport = BlockingTransport(_json_response(completion_tokens=1))
    gateway = ComparisonModelGateway(
        policy=_policy(),
        upstream_api_key="secret",
        transport=transport,
    )
    gateway.start()
    token = gateway.register_row("primary-012", max_requests=1, max_cost_usd="0.05")
    response: list[tuple[int, bytes]] = []
    worker = threading.Thread(
        target=lambda: response.append(_post(gateway, token, _request("blocked")))
    )
    worker.start()
    assert transport.entered.wait(timeout=5)

    receipt_path = tmp_path / "drain-timeout.json"
    receipt = gateway.close_row_and_seal(
        "primary-012",
        receipt_path,
        drain_timeout_seconds=0.01,
    )
    sealed_bytes = receipt_path.read_bytes()
    transport.release.set()
    worker.join(timeout=5)
    gateway.close()

    assert not worker.is_alive()
    assert response[0][0] == 502
    assert receipt_path.read_bytes() == sealed_bytes
    assert receipt["valid"] is False
    record = receipt["records"][0]
    assert record["failure_code"] == "row_seal_drain_timeout"
    assert record["accounting_status"] == "unknown"
    assert receipt["totals"]["charged_cost_usd"] == record["reserved_cost_usd"]


def test_upstream_content_type_cannot_inject_evaluator_response_headers() -> None:
    assert _safe_content_type("application/json\r\nX-Leak: injected") == (
        "application/octet-stream"
    )
    assert _safe_content_type("text/event-stream") == "text/event-stream"


def test_missing_usage_charges_full_reservation_and_withholds_validity(
    tmp_path: Path,
) -> None:
    response = UpstreamResponse(
        200,
        json.dumps({"id": "response", "model": MODEL, "choices": []}).encode(),
    )
    transport = FakeTransport([response])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-006", max_requests=1, max_cost_usd="0.05")
    try:
        status, body = _post(gateway, token, _request("missing usage"))
    finally:
        gateway.close()

    assert status == 502
    assert json.loads(body)["error"]["code"] == "upstream_accounting_invalid"
    receipt = gateway.seal_row("primary-006", tmp_path / "unknown.json")
    assert receipt["valid"] is False
    assert float(receipt["totals"]["charged_cost_usd"]) > 0
    assert receipt["totals"]["known_actual_cost_usd"] == "0"
    assert receipt["records"][0]["accounting_status"] == "unknown"


def test_out_of_bounds_provider_usage_charges_the_greater_observed_cost(
    tmp_path: Path,
) -> None:
    transport = FakeTransport([_json_response(prompt_tokens=10_000, completion_tokens=10)])
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=transport
    )
    gateway.start()
    token = gateway.register_row("primary-014", max_requests=1, max_cost_usd="0.05")
    try:
        status, body = _post(gateway, token, _request("usage exceeded reservation"))
    finally:
        gateway.close()

    assert status == 502
    assert json.loads(body)["error"]["code"] == "upstream_accounting_invalid"
    receipt = gateway.seal_row("primary-014", tmp_path / "over-reservation.json")
    record = receipt["records"][0]
    assert receipt["valid"] is False
    assert receipt["totals"]["known_actual_cost_usd"] == "0"
    assert record["failure_code"] == "provider_usage_out_of_bounds"
    assert record["accounting_status"] == "provider_usage_out_of_bounds"
    assert record["usage"] == {
        "input_tokens": 10_000,
        "cached_input_tokens": 0,
        "output_tokens": 10,
    }
    assert float(record["charged_cost_usd"]) == max(
        float(record["reserved_cost_usd"]),
        float(record["observed_usage_cost_usd"]),
    )
    assert float(record["charged_cost_usd"]) > float(record["reserved_cost_usd"])
    assert (
        validate_model_gateway_receipt(
            receipt,
            expected_row_id="primary-014",
            expected_policy_sha256=gateway.policy_digest,
            expected_max_requests=1,
            expected_max_cost_usd="0.05",
        )
        == receipt
    )


def test_largest_bounded_provider_usage_still_seals_terminal_cost_evidence(
    tmp_path: Path,
) -> None:
    maximum_usage = (1 << 63) - 1
    policy = ModelGatewayPolicy.build(
        model=MODEL,
        reasoning_effort=REASONING,
        pricing=ModelPricing.from_numbers(
            input_per_million="1e28",
            cached_input_per_million="0",
            output_per_million="1e28",
        ),
        campaign_max_cost_usd="1e28",
        max_completion_tokens_per_request=100,
        upstream_timeout_seconds=10,
    )
    gateway = ComparisonModelGateway(
        policy=policy,
        upstream_api_key="secret",
        transport=FakeTransport(
            [
                _json_response(
                    prompt_tokens=maximum_usage,
                    completion_tokens=maximum_usage,
                )
            ]
        ),
    )
    gateway.start()
    token = gateway.register_row("primary-017", max_requests=1, max_cost_usd="1e28")
    try:
        status, body = _post(gateway, token, _request("maximum bounded usage"))
    finally:
        gateway.close()

    assert status == 502
    assert json.loads(body)["error"]["code"] == "upstream_accounting_invalid"
    receipt = gateway.seal_row("primary-017", tmp_path / "maximum-usage.json")
    record = receipt["records"][0]
    assert record["status"] == "failed"
    assert record["failure_code"] == "provider_usage_out_of_bounds"
    assert Decimal(record["charged_cost_usd"]) > Decimal(receipt["limits"]["max_cost_usd"])
    assert (
        validate_model_gateway_receipt(
            receipt,
            expected_row_id="primary-017",
            expected_policy_sha256=gateway.policy_digest,
            expected_max_requests=1,
            expected_max_cost_usd="1e28",
        )
        == receipt
    )


@pytest.mark.parametrize(
    ("framing_headers", "failure_code"),
    [
        (("Transfer-Encoding: chunked", "Content-Length: 2"), "transfer_encoding_forbidden"),
        (("Content-Length: 2", "Content-Length: 2"), "content_length_ambiguous"),
    ],
)
def test_gateway_rejects_ambiguous_request_framing(
    tmp_path: Path,
    framing_headers: tuple[str, ...],
    failure_code: str,
) -> None:
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=FakeTransport([])
    )
    gateway.start()
    token = gateway.register_row("primary-015", max_requests=1, max_cost_usd="0.05")
    request = (
        "POST /v1/chat/completions HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        f"Authorization: Bearer {token}\r\n"
        + "\r\n".join(framing_headers)
        + "\r\nConnection: close\r\n\r\n{}"
    ).encode("ascii")
    try:
        status, body = _raw_http(gateway, request)
    finally:
        gateway.close()

    assert status == 400
    assert json.loads(body)["error"]["code"] == failure_code
    receipt = gateway.seal_row("primary-015", tmp_path / f"{failure_code}.json")
    assert receipt["valid"] is False
    assert receipt["records"][0]["failure_code"] == failure_code


def test_gateway_times_out_an_incomplete_inbound_body(tmp_path: Path) -> None:
    gateway = ComparisonModelGateway(
        policy=_policy(upstream_timeout_seconds=1),
        upstream_api_key="secret",
        transport=FakeTransport([]),
    )
    gateway.start()
    token = gateway.register_row("primary-016", max_requests=1, max_cost_usd="0.05")
    request = (
        "POST /v1/chat/completions HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        f"Authorization: Bearer {token}\r\n"
        "Content-Length: 10\r\n"
        "Connection: close\r\n\r\n"
        "{"
    ).encode("ascii")
    try:
        status, body = _raw_http(gateway, request, close_write=False, timeout_seconds=3)
    finally:
        gateway.close()

    assert status == 408
    assert json.loads(body)["error"]["code"] == "request_body_read_timeout"
    receipt = gateway.seal_row("primary-016", tmp_path / "inbound-timeout.json")
    assert receipt["valid"] is False
    assert receipt["records"][0]["failure_code"] == "request_body_read_timeout"


def test_malformed_json_closes_admission_and_retains_invalid_receipt(tmp_path: Path) -> None:
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=FakeTransport([])
    )
    gateway.start()
    token = gateway.register_row("primary-013", max_requests=1, max_cost_usd="0.05")
    try:
        status, body = _post_raw(gateway, token, b"{")
    finally:
        gateway.close()

    assert status == 400
    assert json.loads(body)["error"]["code"] == "malformed_request"
    receipt = gateway.seal_row("primary-013", tmp_path / "malformed.json")
    assert receipt["valid"] is False
    assert receipt["totals"]["requests_started"] == 1
    assert receipt["records"][0]["failure_code"] == "malformed_request:ModelGatewayError"


def test_receipt_is_create_only_and_row_cannot_be_registered_or_sealed_twice(
    tmp_path: Path,
) -> None:
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=FakeTransport([])
    )
    gateway.register_row("primary-007", max_requests=1, max_cost_usd="0.05")
    with pytest.raises(Exception, match="already registered"):
        gateway.register_row("primary-007", max_requests=1, max_cost_usd="0.05")
    receipt_path = tmp_path / "sealed.json"
    gateway.seal_row("primary-007", receipt_path)
    with pytest.raises(RowSealError, match="already sealed"):
        gateway.seal_row("primary-007", tmp_path / "other.json")
    assert receipt_path.is_file()


def test_row_can_retry_sealing_to_a_fresh_path_after_output_collision(tmp_path: Path) -> None:
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=FakeTransport([])
    )
    gateway.register_row("primary-018", max_requests=1, max_cost_usd="0.05")
    occupied_path = tmp_path / "occupied.json"
    occupied_path.write_text("keep me", encoding="utf-8")

    with pytest.raises(RowSealError, match="refusing to replace"):
        gateway.seal_row("primary-018", occupied_path)

    receipt = gateway.seal_row("primary-018", tmp_path / "retry.json")
    assert receipt["valid"] is True
    assert occupied_path.read_text(encoding="utf-8") == "keep me"


@pytest.mark.parametrize(
    ("row_id", "max_requests"),
    [
        ("primary-000", 1),
        ("primary-001", 4097),
    ],
)
def test_gateway_rejects_invalid_row_or_unbounded_receipt_population(
    row_id: str,
    max_requests: int,
) -> None:
    gateway = ComparisonModelGateway(
        policy=_policy(), upstream_api_key="secret", transport=FakeTransport([])
    )
    with pytest.raises(RowRegistrationError, match="row (ID|request limit) is invalid"):
        gateway.register_row(row_id, max_requests=max_requests, max_cost_usd="0.05")


def test_gateway_rejects_zero_input_or_output_prices() -> None:
    with pytest.raises(ValueError, match="input and output prices"):
        ModelGatewayPolicy.build(
            model=MODEL,
            reasoning_effort=REASONING,
            pricing=ModelPricing.from_numbers(
                input_per_million="0",
                cached_input_per_million="0",
                output_per_million="4.5",
            ),
            campaign_max_cost_usd="1",
        )


def test_gateway_rejects_overlong_reasoning_effort() -> None:
    with pytest.raises(ValueError, match="reasoning effort"):
        ModelGatewayPolicy.build(
            model=MODEL,
            reasoning_effort="r" * 51,
            pricing=ModelPricing.from_numbers(
                input_per_million="0.75",
                cached_input_per_million="0.075",
                output_per_million="4.5",
            ),
            campaign_max_cost_usd="1",
        )


def test_gateway_rejects_inexact_float_money_inputs() -> None:
    with pytest.raises(ValueError, match="invalid"):
        ModelPricing.from_numbers(
            input_per_million=0.1,  # type: ignore[arg-type]
            cached_input_per_million="0.01",
            output_per_million="1",
        )
    with pytest.raises(ValueError, match="invalid"):
        ModelGatewayPolicy.build(
            model=MODEL,
            reasoning_effort=REASONING,
            pricing=ModelPricing.from_numbers(
                input_per_million="0.1",
                cached_input_per_million="0.01",
                output_per_million="1",
            ),
            campaign_max_cost_usd=0.1,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("pricing", "campaign_cost"),
    [
        (
            ModelPricing(
                input_per_million=Decimal("1e64"),
                cached_input_per_million=Decimal("0"),
                output_per_million=Decimal("1"),
            ),
            Decimal("10"),
        ),
        (
            ModelPricing(
                input_per_million=Decimal("1"),
                cached_input_per_million=Decimal("0"),
                output_per_million=Decimal("1"),
            ),
            Decimal("1e64"),
        ),
    ],
)
def test_gateway_rejects_direct_policy_money_outside_supported_bounds(
    pricing: ModelPricing,
    campaign_cost: Decimal,
) -> None:
    policy = ModelGatewayPolicy(
        model=MODEL,
        reasoning_effort=REASONING,
        pricing=pricing,
        campaign_max_cost_usd=campaign_cost,
    )

    with pytest.raises(ValueError, match="invalid"):
        ComparisonModelGateway(
            policy=policy,
            upstream_api_key="secret",
            transport=FakeTransport([]),
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("max_completion_tokens_per_request", 1_000_001),
        ("max_request_body_bytes", 64 * 1024 * 1024 + 1),
        ("max_upstream_response_bytes", 256 * 1024 * 1024 + 1),
        ("upstream_timeout_seconds", 3601),
        ("max_parallel_requests", 257),
    ],
)
def test_gateway_policy_rejects_unbounded_integer_controls(name: str, value: int) -> None:
    values = {
        "max_completion_tokens_per_request": 100,
        "max_request_body_bytes": 1024,
        "max_upstream_response_bytes": 1024,
        "upstream_timeout_seconds": 10,
        "max_parallel_requests": 2,
    }
    values[name] = value
    with pytest.raises(ValueError, match="no greater than"):
        ModelGatewayPolicy.build(
            model=MODEL,
            reasoning_effort=REASONING,
            pricing=ModelPricing.from_numbers(
                input_per_million="0.1",
                cached_input_per_million="0.01",
                output_per_million="1",
            ),
            campaign_max_cost_usd="10",
            **values,
        )


def test_gateway_money_evidence_is_independent_of_ambient_decimal_precision(
    tmp_path: Path,
) -> None:
    def run(precision: int, row_id: str) -> tuple[object, ...]:
        with localcontext() as context:
            context.prec = precision
            policy = ModelGatewayPolicy.build(
                model=MODEL,
                reasoning_effort=REASONING,
                pricing=ModelPricing.from_numbers(
                    input_per_million=Decimal("0.123456789012345678901234567890123456789"),
                    cached_input_per_million=Decimal("0.0123456789012345678901234567890123456789"),
                    output_per_million=Decimal("1.23456789012345678901234567890123456789"),
                ),
                campaign_max_cost_usd=Decimal("10.0000000000000000000000000000000000001"),
                max_completion_tokens_per_request=100,
                upstream_timeout_seconds=10,
            )
            gateway = ComparisonModelGateway(
                policy=policy,
                upstream_api_key="secret",
                transport=FakeTransport(
                    [_json_response(prompt_tokens=120, cached_tokens=20, completion_tokens=30)]
                ),
            )
            gateway.start()
            token = gateway.register_row(
                row_id,
                max_requests=1,
                max_cost_usd=Decimal("1.00000000000000000000000000000000000001"),
            )
            try:
                assert _post(gateway, token, _request("precision"))[0] == 200
            finally:
                gateway.close()
            receipt = gateway.seal_row(row_id, tmp_path / f"{row_id}.json")
            record = receipt["records"][0]
            return (
                policy.to_json(),
                gateway.policy_digest,
                receipt["limits"]["max_cost_usd"],
                receipt["totals"]["charged_cost_usd"],
                receipt["totals"]["known_actual_cost_usd"],
                record["reserved_cost_usd"],
                record["actual_cost_usd"],
            )

    low_precision = run(6, "primary-020")
    high_precision = run(80, "primary-021")

    assert low_precision == high_precision


def _policy(
    *,
    campaign_cost: str = "1",
    upstream_timeout_seconds: int = 10,
) -> ModelGatewayPolicy:
    return ModelGatewayPolicy.build(
        model=MODEL,
        reasoning_effort=REASONING,
        pricing=ModelPricing.from_numbers(
            input_per_million="0.75",
            cached_input_per_million="0.075",
            output_per_million="4.50",
        ),
        campaign_max_cost_usd=campaign_cost,
        max_completion_tokens_per_request=100,
        upstream_timeout_seconds=upstream_timeout_seconds,
    )


def _request(marker: str, *, stream: bool = False) -> dict[str, object]:
    return {
        "model": MODEL,
        "reasoning_effort": REASONING,
        "messages": [{"role": "user", "content": marker}],
        "max_completion_tokens": 100,
        "stream": stream,
    }


def _json_response(
    *,
    prompt_tokens: int = 20,
    cached_tokens: int = 0,
    completion_tokens: int = 10,
) -> UpstreamResponse:
    return UpstreamResponse(
        200,
        json.dumps(
            {
                "id": "response",
                "model": MODEL,
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "prompt_tokens_details": {"cached_tokens": cached_tokens},
                },
            }
        ).encode(),
    )


def _post(
    gateway: ComparisonModelGateway,
    token: str,
    payload: dict[str, object],
) -> tuple[int, bytes]:
    return _post_raw(gateway, token, json.dumps(payload).encode())


def _post_raw(
    gateway: ComparisonModelGateway,
    token: str,
    body: bytes,
) -> tuple[int, bytes]:
    parsed = urlparse(gateway.base_url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _raw_http(
    gateway: ComparisonModelGateway,
    request: bytes,
    *,
    close_write: bool = True,
    timeout_seconds: float = 5,
) -> tuple[int, bytes]:
    parsed = urlparse(gateway.base_url)
    if parsed.hostname is None or parsed.port is None:
        raise AssertionError("gateway URL lacks a host or port")
    chunks: list[bytes] = []
    with socket.create_connection(
        (parsed.hostname, parsed.port), timeout=timeout_seconds
    ) as client:
        client.settimeout(timeout_seconds)
        client.sendall(request)
        if close_write:
            client.shutdown(socket.SHUT_WR)
        while True:
            chunk = client.recv(64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    head, body = b"".join(chunks).split(b"\r\n\r\n", 1)
    status_line = head.splitlines()[0]
    return int(status_line.split()[1]), body
