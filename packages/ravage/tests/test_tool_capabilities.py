from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ravage.run_data.brief import load_engagement_brief
from ravage.tool_capabilities import (
    build_tool_capability_report,
    replacement_action_for_capability,
    unavailable_tool_observation_fields,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    import pytest


def test_capability_report_uses_any_available_provider_for_grouped_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_which(binary: str) -> str | None:
        return f"/usr/bin/{binary}" if binary == "gobuster" else None

    monkeypatch.setattr("ravage.tool_capabilities.shutil.which", fake_which)
    monkeypatch.chdir(tmp_path)

    report = build_tool_capability_report(
        context={
            "required_capabilities": ["dir_bruteforce"],
            "optional_capabilities": ["crawl"],
        },
        tool_recon=False,
        runtime_mode="host",
    )

    assert report["missing_required"] == []
    assert report["missing_optional"] == ["crawl"]
    dir_status = _capability_status(report, "dir_bruteforce")
    assert dir_status["available"] is True
    selected_provider = dir_status["selected_provider"]
    assert isinstance(selected_provider, dict)
    assert selected_provider["action"] == "gobuster_dir"
    assert replacement_action_for_capability(report, "ffuf_dir") == "gobuster_dir"
    assert replacement_action_for_capability(report, "katana_crawl") is None


def test_capability_report_treats_tool_recon_actions_as_optional(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("ravage.tool_capabilities.shutil.which", lambda _binary: None)
    monkeypatch.chdir(tmp_path)

    report = build_tool_capability_report(
        context={"tool_recon_tools": ["nmap_scan", "ffuf_dir"]},
        tool_recon=True,
        runtime_mode="host",
    )

    assert report["required_capabilities"] == []
    assert report["optional_capabilities"] == ["dir_bruteforce", "port_scan"]
    assert report["missing_required"] == []
    assert report["missing_optional"] == ["dir_bruteforce", "port_scan"]
    assert report["blocking"] is False
    assert report["degraded"] is True


def test_perimeter_lab_required_recon_capabilities_block_when_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("ravage.tool_capabilities.shutil.which", lambda _binary: None)
    monkeypatch.chdir(tmp_path)
    repo_root = Path(__file__).resolve().parents[3]
    brief = load_engagement_brief(
        repo_root / "examples" / "labs" / "ravage-perimeter-box" / "brief.yaml"
    )

    report = build_tool_capability_report(
        context=brief.context,
        tool_recon=False,
        runtime_mode="host",
    )

    assert report["required_capabilities"] == ["port_scan", "dir_bruteforce"]
    assert report["missing_required"] == ["port_scan", "dir_bruteforce"]
    assert report["blocking"] is True
    assert report["degraded"] is True


def test_unavailable_tool_observation_includes_capability_and_fallbacks() -> None:
    fields = unavailable_tool_observation_fields(
        action="ffuf_dir",
        args={},
        capability_report={
            "capabilities": {
                "dir_bruteforce": {
                    "available": False,
                    "providers": [],
                }
            }
        },
    )

    assert fields["error_type"] == "tool_unavailable"
    assert fields["capability"] == "dir_bruteforce"
    fallbacks_available = fields["fallbacks_available"]
    assert isinstance(fallbacks_available, list)
    assert "katana_crawl" in fallbacks_available
    install_hint = fields["install_hint"]
    assert isinstance(install_hint, str)
    assert "ravage tools install" in install_hint


def _capability_status(
    report: Mapping[str, object],
    capability_id: str,
) -> Mapping[str, object]:
    capabilities = report["capabilities"]
    assert isinstance(capabilities, dict)
    status = capabilities[capability_id]
    assert isinstance(status, dict)
    return status
