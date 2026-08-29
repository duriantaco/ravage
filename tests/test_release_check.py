import json
import tomllib
from pathlib import Path

import pytest

from scripts.qa import check_release

GITHUB_ENVIRONMENT_KEYS = (
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
)


@pytest.fixture(autouse=True)
def _clear_github_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in GITHUB_ENVIRONMENT_KEYS:
        monkeypatch.delenv(key, raising=False)


def _expected_tag() -> str:
    pyproject_path = check_release.PACKAGES[0][1]
    version = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]["version"]
    return f"v{version}"


def _write_release_event(path: Path, tag: str) -> None:
    path.write_text(
        json.dumps({"action": "published", "release": {"tag_name": tag}}),
        encoding="utf-8",
    )


def test_local_release_check_does_not_require_a_github_tag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert check_release.main() == 0
    assert "release check passed" in capsys.readouterr().out


def test_published_release_accepts_exact_package_tag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    event_path = tmp_path / "event.json"
    _write_release_event(event_path, _expected_tag())
    monkeypatch.setenv("GITHUB_EVENT_NAME", "release")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    assert check_release.main() == 0


def test_published_release_rejects_non_v_tag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tag = _expected_tag().removeprefix("v")
    event_path = tmp_path / "event.json"
    _write_release_event(event_path, tag)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "release")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    assert check_release.main() == 1
    assert f"release tag {tag!r} does not match package version {_expected_tag()}" in (
        capsys.readouterr().err
    )


def test_published_release_rejects_mismatched_v_tag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tag = "v999.999.999"
    event_path = tmp_path / "event.json"
    _write_release_event(event_path, tag)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "release")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    assert check_release.main() == 1
    assert f"release tag {tag!r} does not match package version {_expected_tag()}" in (
        capsys.readouterr().err
    )


def test_release_event_without_a_tag_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "release")

    assert check_release.main() == 1
    assert f"release context is missing its tag; expected {_expected_tag()!r}" in (
        capsys.readouterr().err
    )


def test_v_prefixed_branch_is_not_treated_as_a_release_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "v999.999.999"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
    monkeypatch.setenv("GITHUB_REF", f"refs/heads/{branch}")
    monkeypatch.setenv("GITHUB_REF_NAME", branch)

    assert check_release.main() == 0


def test_tag_push_rejects_non_release_tag(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tag = "release-candidate"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    monkeypatch.setenv("GITHUB_REF", f"refs/tags/{tag}")
    monkeypatch.setenv("GITHUB_REF_NAME", tag)

    assert check_release.main() == 1
    assert f"release tag {tag!r} does not match package version {_expected_tag()}" in (
        capsys.readouterr().err
    )
