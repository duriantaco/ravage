from __future__ import annotations

from typing import TYPE_CHECKING

from scripts.qa import check_pypi_version

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch


def _package(tmp_path: Path, *, name: str, version: str) -> Path:
    path = tmp_path / f"{name}.toml"
    path.write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    return path


def test_unused_versions_pass(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    packages = (
        _package(tmp_path, name="ravage-schemas", version="0.6.0"),
        _package(tmp_path, name="ravage", version="0.6.0"),
    )
    monkeypatch.setattr(check_pypi_version, "PACKAGES", packages)
    monkeypatch.setattr(check_pypi_version, "_release_status", lambda _url: 404)

    assert check_pypi_version.main([]) == 0
    assert "ravage==0.6.0" in capsys.readouterr().out


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


def test_release_url_quotes_components() -> None:
    assert check_pypi_version._release_url(  # noqa: SLF001
        "https://example.test/pypi/", "ravage schemas", "0.6.0+local"
    ) == "https://example.test/pypi/ravage%20schemas/0.6.0%2Blocal/json"
