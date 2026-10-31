from __future__ import annotations

import copy
import hashlib
import json
from decimal import Decimal
from pathlib import Path

import pytest
from ravage.xben_parts.comparison_model_gateway import (
    MODEL_GATEWAY_CAMPAIGN_SCHEMA,
    ComparisonModelGateway,
    ModelGatewayError,
    ModelGatewayPolicy,
    ModelPricing,
    RowRegistrationError,
    RowSealError,
    UpstreamResponse,
    validate_model_gateway_campaign_receipt,
)

MODEL = "campaign-test-model"
ROW_IDS = tuple(f"primary-{index:03d}" for index in range(1, 41))


def _gateway() -> ComparisonModelGateway:
    return ComparisonModelGateway(
        policy=ModelGatewayPolicy.build(
            model=MODEL,
            reasoning_effort="high",
            pricing=ModelPricing.from_numbers(
                input_per_million="0.75",
                cached_input_per_million="0.075",
                output_per_million="4.5",
            ),
            campaign_max_cost_usd="1",
            max_completion_tokens_per_request=100,
        ),
        upstream_api_key="campaign-upstream-credential",
    )


def _register(gateway: ComparisonModelGateway) -> None:
    for row_id in ROW_IDS:
        gateway.register_row(row_id, max_requests=2, max_cost_usd="0.05")


def _record_request(
    gateway: ComparisonModelGateway,
    *,
    unknown_usage: bool = False,
    prompt_tokens: int = 120,
) -> None:
    # Exercise the real accounting path with an in-memory provider response;
    # no gateway listener or provider connection is needed for these tests.
    reservation, _ = gateway._prepare_request(
        gateway._rows[ROW_IDS[0]],
        json.dumps(
            {
                "model": MODEL,
                "reasoning_effort": "high",
                "messages": [{"role": "user", "content": "campaign prompt"}],
            }
        ).encode(),
    )
    if unknown_usage:
        gateway._finalize_failure(reservation, "upstream_unavailable", charge_reservation=True)
        return
    valid, _ = gateway._validate_upstream(
        reservation,
        UpstreamResponse(
            200,
            json.dumps(
                {
                    "model": MODEL,
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": 30,
                        "prompt_tokens_details": {"cached_tokens": 20},
                    },
                }
            ).encode(),
        ),
    )
    assert valid is (prompt_tokens <= reservation.input_token_upper_bound)


def _seal_rows(
    gateway: ComparisonModelGateway, root: Path
) -> tuple[dict[str, object], dict[str, str]]:
    receipts: dict[str, object] = {}
    digests: dict[str, str] = {}
    for row_id in ROW_IDS:
        path = root / f"{row_id}.json"
        receipts[row_id] = gateway.seal_row(row_id, path)
        digests[row_id] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return receipts, digests


def _validate(
    payload: object,
    gateway: ComparisonModelGateway,
    receipts: dict[str, object],
    digests: dict[str, str],
    **overrides: object,
) -> dict[str, object]:
    expected: dict[str, object] = {
        "expected_policy_sha256": gateway.policy_digest,
        "expected_campaign_max_cost_usd": "1",
        "expected_max_requests_per_row": 2,
        "expected_max_cost_usd_per_row": "0.05",
        "row_receipts": receipts,
        "row_receipt_file_sha256": digests,
    }
    expected.update(overrides)
    return validate_model_gateway_campaign_receipt(payload, **expected)


def _rehash(payload: dict[str, object]) -> None:
    body = {key: value for key, value in payload.items() if key != "document_sha256"}
    encoded = json.dumps(
        body, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    payload["document_sha256"] = "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


def test_campaign_seal_binds_every_row_and_recomputes_exact_cost(tmp_path: Path) -> None:
    gateway = _gateway()
    _register(gateway)
    _record_request(gateway)
    receipts, digests = _seal_rows(gateway, tmp_path)
    campaign_path = tmp_path / "campaign.json"
    campaign = gateway.seal_primary_campaign(campaign_path)

    assert campaign["schema_version"] == MODEL_GATEWAY_CAMPAIGN_SCHEMA
    assert campaign["row_count"] == len(ROW_IDS)
    assert [row["row_id"] for row in campaign["rows"]] == list(ROW_IDS)
    assert campaign["totals"] == {
        "requests_started": 1,
        "requests_recorded": 1,
        "charged_cost_usd": "0.0002115",
        "known_actual_cost_usd": "0.0002115",
        "campaign_max_cost_usd": "1",
        "within_cost_limit": True,
    }
    assert campaign["valid"] is True
    assert json.loads(campaign_path.read_bytes()) == campaign
    assert _validate(campaign, gateway, receipts, digests) == campaign
    serialized = campaign_path.read_text()
    assert "campaign-upstream-credential" not in serialized
    assert "campaign prompt" not in serialized


@pytest.mark.parametrize("mode", ["missing", "extra", "unsealed", "different_budget"])
def test_campaign_requires_the_complete_closed_primary_matrix(tmp_path: Path, mode: str) -> None:
    gateway = _gateway()
    for row_id in ROW_IDS:
        if mode == "missing" and row_id == ROW_IDS[-1]:
            continue
        gateway.register_row(
            row_id,
            max_requests=1 if mode == "different_budget" and row_id == ROW_IDS[-1] else 2,
            max_cost_usd="0.05",
        )
        if mode != "unsealed" or row_id != ROW_IDS[-1]:
            gateway.seal_row(row_id, tmp_path / f"{row_id}.json")
    if mode == "extra":
        gateway.register_row("primary-041", max_requests=2, max_cost_usd="0.05")
        gateway.seal_row("primary-041", tmp_path / "primary-041.json")
    output = tmp_path / "campaign.json"
    with pytest.raises(RowSealError, match=r"forty primary|unsealed or active|budgets differ"):
        gateway.seal_primary_campaign(output)
    assert not output.exists()


def test_campaign_evidence_is_create_only_and_prevents_reopening(tmp_path: Path) -> None:
    gateway = _gateway()
    _register(gateway)
    _seal_rows(gateway, tmp_path)
    occupied = tmp_path / "occupied.json"
    occupied.write_text("retain original")
    with pytest.raises(RowSealError, match="refusing to replace"):
        gateway.seal_primary_campaign(occupied)
    assert occupied.read_text() == "retain original"
    gateway.seal_primary_campaign(tmp_path / "campaign.json")
    with pytest.raises(RowSealError, match="already sealed"):
        gateway.seal_primary_campaign(tmp_path / "second.json")
    with pytest.raises(ModelGatewayError, match="already sealed"):
        gateway.start()
    with pytest.raises(RowRegistrationError, match="already sealed"):
        gateway.register_row("primary-041", max_requests=2, max_cost_usd="0.05")


def test_campaign_seal_rejects_rewritten_retained_row_bytes(tmp_path: Path) -> None:
    gateway = _gateway()
    _register(gateway)
    _seal_rows(gateway, tmp_path)
    path = tmp_path / "primary-001.json"
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(RowSealError, match="evidence changed"):
        gateway.seal_primary_campaign(tmp_path / "campaign.json")


def test_campaign_uses_immutable_row_snapshots(tmp_path: Path) -> None:
    gateway = _gateway()
    _register(gateway)
    receipts, _ = _seal_rows(gateway, tmp_path)
    receipts[ROW_IDS[0]]["totals"]["charged_cost_usd"] = "999"
    campaign = gateway.seal_primary_campaign(tmp_path / "campaign.json")
    assert campaign["totals"]["charged_cost_usd"] == "0"


@pytest.mark.parametrize(
    "change", ["cost", "request_total", "file_binding", "duplicate_row", "row_count", "valid"]
)
def test_campaign_validator_rejects_rehashed_tampering(tmp_path: Path, change: str) -> None:
    gateway = _gateway()
    _register(gateway)
    receipts, digests = _seal_rows(gateway, tmp_path)
    campaign = copy.deepcopy(gateway.seal_primary_campaign(tmp_path / "campaign.json"))
    if change == "cost":
        campaign["totals"]["charged_cost_usd"] = "0.01"
    elif change == "request_total":
        campaign["totals"]["requests_started"] = 1
    elif change == "file_binding":
        campaign["rows"][0]["row_receipt_file_sha256"] = "sha256:" + "a" * 64
    elif change == "duplicate_row":
        campaign["rows"][1] = copy.deepcopy(campaign["rows"][0])
    elif change == "row_count":
        campaign["row_count"] = 39
    else:
        campaign["valid"] = False
    _rehash(campaign)
    with pytest.raises(ModelGatewayError):
        _validate(campaign, gateway, receipts, digests)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_policy_sha256", "sha256:" + "b" * 64),
        ("expected_campaign_max_cost_usd", "2"),
        ("expected_max_requests_per_row", 3),
        ("expected_max_requests_per_row", True),
        ("expected_max_cost_usd_per_row", "0.06"),
    ],
)
def test_campaign_validator_binds_the_frozen_policy_and_budgets(
    tmp_path: Path, field: str, value: object
) -> None:
    gateway = _gateway()
    _register(gateway)
    receipts, digests = _seal_rows(gateway, tmp_path)
    campaign = gateway.seal_primary_campaign(tmp_path / "campaign.json")
    with pytest.raises(ModelGatewayError):
        _validate(campaign, gateway, receipts, digests, **{field: value})


@pytest.mark.parametrize("change", ["missing", "duplicate_token", "false_row_cost"])
def test_campaign_validator_independently_checks_every_row(tmp_path: Path, change: str) -> None:
    gateway = _gateway()
    _register(gateway)
    receipts, digests = _seal_rows(gateway, tmp_path)
    campaign = gateway.seal_primary_campaign(tmp_path / "campaign.json")
    if change == "missing":
        receipts.pop(ROW_IDS[-1])
    else:
        row = receipts[ROW_IDS[1]]
        if change == "duplicate_token":
            row["row_token_sha256"] = receipts[ROW_IDS[0]]["row_token_sha256"]
        else:
            row["totals"]["charged_cost_usd"] = "0.01"
        _rehash(row)
    with pytest.raises(
        ModelGatewayError, match=r"forty primary|tokens are not unique|charged total"
    ):
        _validate(campaign, gateway, receipts, digests)


def test_campaign_preserves_unknown_usage_cost_and_invalidity(tmp_path: Path) -> None:
    gateway = _gateway()
    _register(gateway)
    _record_request(gateway, unknown_usage=True)
    receipts, digests = _seal_rows(gateway, tmp_path)
    campaign = gateway.seal_primary_campaign(tmp_path / "campaign.json")
    assert campaign["valid"] is False
    assert campaign["all_rows_terminal"] is True
    assert Decimal(campaign["totals"]["charged_cost_usd"]) > 0
    assert campaign["totals"]["known_actual_cost_usd"] == "0"
    assert _validate(campaign, gateway, receipts, digests) == campaign


def test_campaign_preserves_observed_provider_cost_above_the_campaign_cap(tmp_path: Path) -> None:
    gateway = _gateway()
    _register(gateway)
    _record_request(gateway, prompt_tokens=1_000_000_000)
    receipts, digests = _seal_rows(gateway, tmp_path)
    campaign = gateway.seal_primary_campaign(tmp_path / "campaign.json")
    assert campaign["valid"] is False
    assert campaign["totals"]["within_cost_limit"] is False
    assert Decimal(campaign["totals"]["charged_cost_usd"]) > Decimal("1")
    assert _validate(campaign, gateway, receipts, digests) == campaign
