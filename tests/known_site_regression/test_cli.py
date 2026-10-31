# ruff: noqa: ANN001,PLR2004,TC003
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.known_site_regression import cli


def test_offline_verify_cli_never_upgrades_an_incomplete_directory(
    tmp_path: Path,
    capsys,
) -> None:
    campaign = tmp_path / "incomplete"
    campaign.mkdir()

    assert cli.main(["verify", "--campaign-dir", str(campaign)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["structurally_valid"] is False
    assert payload["eligible_for_sota_claim"] is False
    assert payload["eligible_for_unseen_claim"] is False


def test_offline_verify_cli_rejects_structural_but_unscoreable_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    campaign = tmp_path / "sealed-unscoreable"
    campaign.mkdir()
    monkeypatch.setattr(
        cli,
        "verify_known_site_regression",
        lambda _path: {
            "schema_version": "ravage.known-site.verification.v2",
            "structurally_valid": True,
            "valid_for_paired_known_site_regression": False,
            "errors": [],
        },
    )

    assert cli.main(["verify", "--campaign-dir", str(campaign)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["structurally_valid"] is True
    assert payload["valid_for_paired_known_site_regression"] is False
