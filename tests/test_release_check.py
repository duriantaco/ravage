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
    version = _expected_tag().removeprefix("v")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(f"# Changelog\n\n## {version} - 2026-08-30\n", encoding="utf-8")
    monkeypatch.setattr(check_release, "CHANGELOG_FILE", changelog)
    event_path = tmp_path / "event.json"
    _write_release_event(event_path, _expected_tag())
    monkeypatch.setenv("GITHUB_EVENT_NAME", "release")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    assert check_release.main() == 0


def test_published_release_rejects_unreleased_changelog(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## Unreleased\n\n- Pending.\n", encoding="utf-8")
    monkeypatch.setattr(check_release, "CHANGELOG_FILE", changelog)
    event_path = tmp_path / "event.json"
    _write_release_event(event_path, _expected_tag())
    monkeypatch.setenv("GITHUB_EVENT_NAME", "release")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    assert check_release.main() == 1
    assert "missing a dated" in capsys.readouterr().err


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


def test_workspace_version_check_rejects_stale_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    citation = tmp_path / "CITATION.cff"
    citation.write_text("version: 0.6.0\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{".": "0.5.0"}\n', encoding="utf-8")
    lock = tmp_path / "uv.lock"
    lock.write_text(
        """
[[package]]
name = "ravage"
version = "0.6.0"
[[package]]
name = "ravage-schemas"
version = "0.6.0"
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(check_release, "CITATION_FILE", citation)
    monkeypatch.setattr(check_release, "RELEASE_MANIFEST", manifest)
    monkeypatch.setattr(check_release, "LOCK_FILE", lock)

    assert check_release._workspace_version_errors("0.6.0") == [  # noqa: SLF001
        "release-please manifest version '0.5.0' does not match package version '0.6.0'"
    ]


def test_workspace_configuration_rejects_a_duplicate_root_distribution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root_pyproject = tmp_path / "pyproject.toml"
    root_pyproject.write_text(
        check_release.ROOT_PYPROJECT.read_text(encoding="utf-8")
        + '\n[project]\nname = "pentest-agent"\nversion = "0.5.0"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(check_release, "ROOT_PYPROJECT", root_pyproject)

    assert check_release._workspace_configuration_errors() == [  # noqa: SLF001
        "root pyproject.toml must remain a virtual, non-distributable workspace"
    ]


def test_workspace_configuration_rejects_active_mcp_scaffolds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root_pyproject = tmp_path / "pyproject.toml"
    root_pyproject.write_text(
        check_release.ROOT_PYPROJECT.read_text(encoding="utf-8").replace(
            'exclude = ["packages/mcp_servers/*"]', "exclude = []"
        ),
        encoding="utf-8",
    )
    lock = tmp_path / "uv.lock"
    lock.write_text(
        check_release.LOCK_FILE.read_text(encoding="utf-8")
        + '\n[[package]]\nname = "ffuf-mcp"\nversion = "0.1.0"\n'
        'source = { editable = "packages/mcp_servers/ffuf_mcp" }\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(check_release, "ROOT_PYPROJECT", root_pyproject)
    monkeypatch.setattr(check_release, "LOCK_FILE", lock)

    assert check_release._workspace_configuration_errors() == [  # noqa: SLF001
        "unimplemented MCP scaffolds must be excluded from the UV workspace",
        "uv.lock must install only the two real workspace packages",
    ]
