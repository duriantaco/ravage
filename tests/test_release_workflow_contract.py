from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
ACTION_USE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
RELEASE_WORKFLOWS = (
    "publish-kali-image.yml",
    "publish-pypi.yml",
    "publish-testpypi.yml",
    "release-please.yml",
)
PRODUCTION_PYPI_PUBLISH_JOB_COUNT = 2
TEST_PYPI_PUBLISH_JOB_COUNT = 2
RAVAGE_VERSION_MARKER_COUNT = 2
PYPI_PUBLISH_ACTION = (
    "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
)


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _job(workflow: str, name: str, *, next_name: str | None = None) -> str:
    section = workflow.split(f"  {name}:\n", maxsplit=1)[1]
    if next_name is not None:
        section = section.split(f"  {next_name}:\n", maxsplit=1)[0]
    return section


def test_release_workflow_actions_are_pinned_to_full_commit_shas() -> None:
    failures: list[str] = []
    for name in RELEASE_WORKFLOWS:
        for action in ACTION_USE.findall(_workflow(name)):
            if action.startswith("./"):
                continue
            _, separator, ref = action.rpartition("@")
            if not separator or FULL_COMMIT_SHA.fullmatch(ref) is None:
                failures.append(f"{name}: {action}")

    assert failures == []


def test_production_publish_is_serialized_and_requires_exact_current_main() -> None:
    workflow = _workflow("publish-pypi.yml")

    assert "group: publish-pypi-${{ github.event.release.tag_name || github.ref }}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert 'git rev-parse --verify "refs/tags/${RELEASE_TAG}^{commit}"' in workflow
    assert 'git rev-parse --verify "refs/remotes/origin/main^{commit}"' in workflow
    assert 'git rev-parse --verify "${GITHUB_SHA}^{commit}"' in workflow
    assert "git merge-base --is-ancestor" not in workflow
    assert "python scripts/check_pypi_version.py" in workflow
    preflight_position = workflow.index("python scripts/check_pypi_version.py")
    assert preflight_position < workflow.index("  build-schemas:")
    assert workflow.count(PYPI_PUBLISH_ACTION) == PRODUCTION_PYPI_PUBLISH_JOB_COUNT
    assert workflow.count("environment: pypi") == PRODUCTION_PYPI_PUBLISH_JOB_COUNT
    assert workflow.count("id-token: write") == PRODUCTION_PYPI_PUBLISH_JOB_COUNT

    test_job = _job(workflow, "test", next_name="build-schemas")
    assert "github.event.release.prerelease == false" in test_job
    assert "github.event_name == 'workflow_dispatch'" in test_job
    for build_name, next_name in (
        ("build-schemas", "build-ravage"),
        ("build-ravage", "publish-schemas"),
    ):
        assert "needs: test" in _job(workflow, build_name, next_name=next_name)

    publish_schemas = _job(workflow, "publish-schemas", next_name="publish-ravage")
    publish_ravage = _job(workflow, "publish-ravage")
    for publish_job in (publish_schemas, publish_ravage):
        assert "github.event_name == 'release'" in publish_job
        assert "github.event.release.prerelease == false" in publish_job
        assert publish_job.count(PYPI_PUBLISH_ACTION) == 1
        assert "actions/checkout@" not in publish_job
        assert "\n        run:" not in publish_job


def test_testpypi_rehearsal_cannot_target_production() -> None:
    workflow = _workflow("publish-testpypi.yml")

    assert "workflow_dispatch:" in workflow
    assert workflow.count("environment: testpypi") == TEST_PYPI_PUBLISH_JOB_COUNT
    assert "environment: pypi" not in workflow
    assert (
        workflow.count("repository-url: https://test.pypi.org/legacy/")
        == TEST_PYPI_PUBLISH_JOB_COUNT
    )
    assert (
        "python scripts/check_pypi_version.py --index-base https://test.pypi.org/pypi"
        in workflow
    )
    assert "--index-url https://test.pypi.org/simple/" in workflow
    assert "--probe surface_map" in workflow
    assert "--timeout-seconds 10" in workflow
    assert workflow.count(PYPI_PUBLISH_ACTION) == TEST_PYPI_PUBLISH_JOB_COUNT

    publish_schemas = _job(workflow, "publish-schemas", next_name="publish-ravage")
    publish_ravage = _job(workflow, "publish-ravage", next_name="verify")
    for publish_job in (publish_schemas, publish_ravage):
        assert publish_job.count(PYPI_PUBLISH_ACTION) == 1
        assert "actions/checkout@" not in publish_job
        assert "\n        run:" not in publish_job


def test_kali_publish_requires_exact_current_main_and_skips_prereleases() -> None:
    workflow = _workflow("publish-kali-image.yml")
    preflight = _job(workflow, "preflight", next_name="publish-platform")
    publish_platform = _job(workflow, "publish-platform", next_name="publish-manifest")
    publish_manifest = _job(workflow, "publish-manifest")

    prerelease_guard = (
        "github.event_name != 'release' || github.event.release.prerelease == false"
    )
    assert prerelease_guard in publish_platform
    assert prerelease_guard in publish_manifest
    assert "needs: preflight" in publish_platform
    assert '"${GITHUB_REF}" != "refs/heads/main"' in preflight
    assert 'git rev-parse --verify "refs/tags/${RELEASE_TAG}^{commit}"' in preflight
    assert 'git rev-parse --verify "refs/remotes/origin/main^{commit}"' in preflight
    assert 'git rev-parse --verify "${GITHUB_SHA}^{commit}"' in preflight
    assert "python scripts/check_release.py" in preflight
    assert (
        "type=semver,pattern={{version}},value=${{ github.event.release.tag_name }},"
        "enable=${{ github.event_name == 'release' && !github.event.release.prerelease }}"
        in publish_manifest
    )
    assert (
        "type=semver,pattern={{major}}.{{minor}},value=${{ github.event.release.tag_name }},"
        "enable=${{ github.event_name == 'release' && !github.event.release.prerelease }}"
        in publish_manifest
    )


def test_release_please_is_main_only_and_has_no_token_fallback() -> None:
    workflow = _workflow("release-please.yml")

    assert "group: release-please" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert "RELEASE_PLEASE_TOKEN is required" in workflow
    assert "secrets.GITHUB_TOKEN" not in workflow
    assert "token: ${{ secrets.RELEASE_PLEASE_TOKEN }}" in workflow
    assert "python -m pip install uv==0.12.5" in workflow
    assert "uv lock" in workflow
    assert "python scripts/check_release.py" in workflow
    assert "git add uv.lock" in workflow
    assert 'git push origin "HEAD:${RELEASE_PR_BRANCH}"' in workflow


def test_release_please_updates_the_ravage_version_and_schema_pin_together() -> None:
    config_path = ROOT / "tools/release/release-please-config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert re.fullmatch(r"[0-9a-f]{40}", config["bootstrap-sha"])
    extra_files = config["packages"]["."]["extra-files"]
    assert "pyproject.toml" not in {item["path"] for item in extra_files}
    generic_paths = {
        item["path"] for item in extra_files if item.get("type") == "generic"
    }

    assert "packages/ravage/pyproject.toml" in generic_paths
    assert "packages/ravage/src/ravage/_version.py" in generic_paths
    assert "packages/schemas/src/pentest_schemas/_version.py" in generic_paths
    assert "CITATION.cff" in generic_paths
    ravage_pyproject = (ROOT / "packages/ravage/pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert (
        ravage_pyproject.count("# x-release-please-version")
        == RAVAGE_VERSION_MARKER_COUNT
    )
    project_version = re.search(
        r'^version = "([0-9]+\.[0-9]+\.[0-9]+)" # x-release-please-version$',
        ravage_pyproject,
        re.MULTILINE,
    )
    schema_pin = re.search(
        r'^\s+"ravage-schemas==([0-9]+\.[0-9]+\.[0-9]+)", '
        r'# x-release-please-version$',
        ravage_pyproject,
        re.MULTILINE,
    )
    assert project_version is not None
    assert schema_pin is not None
    assert project_version.group(1) == schema_pin.group(1)
