from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from scripts.qa import check_pypi_version

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch

EXPECTED_PACKAGE_COUNT = 2


def _package(tmp_path: Path, *, name: str, version: str) -> Path:
    path = tmp_path / f"{name}.toml"
    path.write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    return path


def test_both_unused_versions_pass(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    packages = (
        _package(tmp_path, name="ravage-schemas", version="0.6.0"),
        _package(tmp_path, name="ravage", version="0.6.0"),
    )
    checked_urls: list[str] = []

    def unused(url: str) -> int:
        checked_urls.append(url)
        return 404

    monkeypatch.setattr(check_pypi_version, "PACKAGES", packages)
    monkeypatch.setattr(check_pypi_version, "_release_status", unused)

    assert check_pypi_version.main([]) == 0
    assert len(checked_urls) == EXPECTED_PACKAGE_COUNT
    output = capsys.readouterr().out
    assert "ravage-schemas==0.6.0" in output
    assert "ravage==0.6.0" in output


def test_occupied_version_fails(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    packages = (_package(tmp_path, name="ravage", version="0.5.0"),)
    monkeypatch.setattr(check_pypi_version, "PACKAGES", packages)
    monkeypatch.setattr(check_pypi_version, "_release_status", lambda _url: 200)

    assert check_pypi_version.main([]) == 1
    assert "already exists" in capsys.readouterr().err


def test_registry_failure_fails_closed(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    packages = (_package(tmp_path, name="ravage", version="0.6.0"),)
    monkeypatch.setattr(check_pypi_version, "PACKAGES", packages)

    def fail(_url: str) -> int:
        message = "offline"
        raise check_pypi_version.RegistryCheckError(message)

    monkeypatch.setattr(check_pypi_version, "_release_status", fail)

    assert check_pypi_version.main([]) == 1
    assert "offline" in capsys.readouterr().err


def test_unexpected_registry_status_fails_closed(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    packages = (_package(tmp_path, name="ravage", version="0.6.0"),)
    monkeypatch.setattr(check_pypi_version, "PACKAGES", packages)
    monkeypatch.setattr(check_pypi_version, "_release_status", lambda _url: 503)

    assert check_pypi_version.main([]) == 1
    assert "HTTP 503" in capsys.readouterr().err


def test_release_url_requires_absolute_https_and_quotes_components() -> None:
    assert check_pypi_version._release_url(  # noqa: SLF001
        "https://example.test/pypi/", "ravage schemas", "0.6.0+local"
    ) == "https://example.test/pypi/ravage%20schemas/0.6.0%2Blocal/json"

    for invalid in ("http://example.test/pypi", "https:///pypi"):
        with pytest.raises(check_pypi_version.RegistryCheckError):
            check_pypi_version._release_url(invalid, "ravage", "0.6.0")  # noqa: SLF001
