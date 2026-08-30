from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
ACTION_USE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
MINIMUM_PRODUCTION_RELEASE_GUARDS = 2
PRODUCTION_PYPI_PUBLISH_JOB_COUNT = 2
TEST_PYPI_PUBLISH_JOB_COUNT = 2
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


def test_every_external_action_is_pinned_to_a_full_commit_sha() -> None:
    failures: list[str] = []
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for action in ACTION_USE.findall(text):
            if action.startswith("./"):
                continue
            _, separator, ref = action.rpartition("@")
            if not separator or FULL_COMMIT_SHA.fullmatch(ref) is None:
                failures.append(f"{path.name}: {action}")

    assert failures == []


def test_production_publish_is_serialized_and_requires_current_main() -> None:
    workflow = _workflow("publish-pypi.yml")

    assert "group: publish-pypi-${{ github.event.release.tag_name || github.ref }}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "package-manager-cache: false" in workflow
    assert 'git rev-parse "${GITHUB_SHA}^{commit}"' in workflow
    assert 'git rev-parse "origin/main^{commit}"' in workflow
    assert "git merge-base --is-ancestor" not in workflow
    assert (
        workflow.count("if: github.event_name == 'release'")
        >= MINIMUM_PRODUCTION_RELEASE_GUARDS
    )
    assert workflow.count(PYPI_PUBLISH_ACTION) == PRODUCTION_PYPI_PUBLISH_JOB_COUNT
    assert workflow.count("environment: pypi") == PRODUCTION_PYPI_PUBLISH_JOB_COUNT
    assert workflow.count("id-token: write") == PRODUCTION_PYPI_PUBLISH_JOB_COUNT

    publish_schemas = _job(workflow, "publish-schemas", next_name="publish-ravage")
    publish_ravage = _job(workflow, "publish-ravage")
    for publish_job in (publish_schemas, publish_ravage):
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


def test_pages_write_permissions_are_limited_to_the_deploy_job() -> None:
    workflow = _workflow("docs-pages.yml")
    workflow_permissions = workflow.split("jobs:", maxsplit=1)[0]
    deploy_job = workflow.split("  deploy:", maxsplit=1)[1]

    assert "pages: write" not in workflow_permissions
    assert "id-token: write" not in workflow_permissions
    assert "pages: write" in deploy_job
    assert "id-token: write" in deploy_job
    assert "if: github.ref == 'refs/heads/main'" in deploy_job


def test_release_build_backends_are_exactly_pinned() -> None:
    for relative_path in ("packages/ravage/pyproject.toml", "packages/schemas/pyproject.toml"):
        project = tomllib.loads((ROOT / relative_path).read_text(encoding="utf-8"))
        assert project["build-system"]["requires"] == ["hatchling==1.32.0"]


def test_release_please_synchronizes_and_validates_the_lockfile() -> None:
    workflow = _workflow("release-please.yml")

    assert "group: release-please" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert "RELEASE_PLEASE_TOKEN is required" in workflow
    assert "secrets.GITHUB_TOKEN" not in workflow
    assert "python -m pip install uv==0.12.5" in workflow
    assert "uv lock" in workflow
    assert "python scripts/check_release.py" in workflow
    assert "git add uv.lock" in workflow
    assert 'git push origin "HEAD:${RELEASE_PR_BRANCH}"' in workflow
