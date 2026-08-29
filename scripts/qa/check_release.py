from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

ROOT = Path(__file__).resolve().parents[2]
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
PACKAGES = (
    (
        "ravage-schemas",
        ROOT / "packages/schemas/pyproject.toml",
        ROOT / "packages/schemas/src/pentest_schemas/_version.py",
    ),
    (
        "ravage",
        ROOT / "packages/ravage/pyproject.toml",
        ROOT / "packages/ravage/src/ravage/_version.py",
    ),
)


def main() -> int:
    errors: list[str] = []
    versions: dict[str, str] = {}

    for name, pyproject_path, version_path in PACKAGES:
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        package_name = pyproject["project"]["name"]
        pyproject_version = pyproject["project"]["version"]
        source_version = _source_version(version_path)
        versions[name] = pyproject_version

        if package_name != name:
            errors.append(f"{pyproject_path}: expected project.name {name!r}, got {package_name!r}")
        if pyproject_version != source_version:
            errors.append(
                f"{name}: pyproject version {pyproject_version!r} does not match "
                f"SOURCE_VERSION {source_version!r}"
            )
        if SEMVER_RE.fullmatch(pyproject_version) is None:
            errors.append(f"{name}: version {pyproject_version!r} is not MAJOR.MINOR.PATCH")

    if len(set(versions.values())) != 1:
        errors.append(f"package versions must match for a release: {versions}")

    ravage_project = tomllib.loads(
        (ROOT / "packages/ravage/pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    schema_requirement = f"ravage-schemas=={versions['ravage-schemas']}"
    if schema_requirement not in ravage_project.get("dependencies", []):
        errors.append(
            "ravage must pin its release-matched schema dependency: "
            f"expected {schema_requirement!r}"
        )

    expected = next(iter(versions.values()))
    errors.extend(_release_ref_errors(expected, os.environ))

    if errors:
        for error in errors:
            sys.stderr.write(f"release check failed: {error}\n")
        return 1

    sys.stdout.write(f"release check passed: {next(iter(versions.values()))}\n")
    return 0


def _release_ref_errors(expected_version: str, environ: Mapping[str, str]) -> list[str]:
    is_tag_context, tag = _github_tag_context(environ)
    if not is_tag_context:
        return []

    expected_tag = f"v{expected_version}"
    if tag is None:
        return [f"release context is missing its tag; expected {expected_tag!r}"]
    if tag != expected_tag:
        return [f"release tag {tag!r} does not match package version {expected_tag}"]
    return []


def _github_tag_context(environ: Mapping[str, str]) -> tuple[bool, str | None]:
    """Return whether this is a release/tag run and its unqualified tag name."""
    if environ.get("GITHUB_EVENT_NAME") == "release":
        tag = _release_event_tag(environ) or _tag_from_ref(environ)
        # A release event makes REF_NAME unambiguously a tag even when the
        # runner did not provide REF_TYPE/REF (for example in a minimal test
        # harness or a manually forwarded release environment).
        return True, tag or environ.get("GITHUB_REF_NAME")

    ref_type = environ.get("GITHUB_REF_TYPE")
    if ref_type is not None:
        if ref_type != "tag":
            return False, None
        return True, _tag_from_ref(environ)

    ref = environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        return True, ref.removeprefix("refs/tags/") or None
    return False, None


def _tag_from_ref(environ: Mapping[str, str]) -> str | None:
    ref = environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        return ref.removeprefix("refs/tags/") or None
    if environ.get("GITHUB_REF_TYPE") == "tag":
        return environ.get("GITHUB_REF_NAME") or None
    return None


def _release_event_tag(environ: Mapping[str, str]) -> str | None:
    event_path = environ.get("GITHUB_EVENT_PATH")
    if event_path is None:
        return None

    try:
        payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(payload, dict):
        return None
    release = payload.get("release")
    if not isinstance(release, dict):
        return None
    tag = release.get("tag_name")
    return tag if isinstance(tag, str) and tag else None


def _source_version(path: Path) -> str:
    match = re.search(
        r'^SOURCE_VERSION\s*=\s*["\']([^"\']+)["\']',
        path.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match is None:
        message = f"missing SOURCE_VERSION in {path}"
        raise ValueError(message)
    return match.group(1)


if __name__ == "__main__":
    raise SystemExit(main())
