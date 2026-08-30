from __future__ import annotations

import argparse
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INDEX_BASE = "https://pypi.org/pypi"
HTTP_OK = 200
HTTP_NOT_FOUND = 404
PACKAGES = (
    ROOT / "packages/schemas/pyproject.toml",
    ROOT / "packages/ravage/pyproject.toml",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when a local package version is already occupied on PyPI."
    )
    parser.add_argument(
        "--index-base",
        default=DEFAULT_INDEX_BASE,
        help="JSON API base URL (default: %(default)s)",
    )
    parsed = parser.parse_args(argv)

    errors: list[str] = []
    checked: list[str] = []
    for pyproject_path in PACKAGES:
        project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]
        name = str(project["name"])
        version = str(project["version"])
        checked.append(f"{name}=={version}")
        try:
            url = _release_url(parsed.index_base, name, version)
            status = _release_status(url)
        except RegistryCheckError as exc:
            errors.append(f"{name}=={version}: {exc}")
            continue
        if status == HTTP_OK:
            errors.append(
                f"{name}=={version} already exists at {url}; "
                "published versions are immutable"
            )
        elif status != HTTP_NOT_FOUND:
            errors.append(f"{name}=={version}: registry returned HTTP {status} for {url}")

    if errors:
        for error in errors:
            sys.stderr.write(f"PyPI version check failed: {error}\n")
        return 1

    sys.stdout.write(f"PyPI version check passed: {', '.join(checked)} are unused\n")
    return 0


def _release_url(index_base: str, name: str, version: str) -> str:
    base = index_base.rstrip("/")
    if urllib.parse.urlparse(base).scheme != "https":
        message = "registry JSON API must use HTTPS"
        raise RegistryCheckError(message)
    quoted_name = urllib.parse.quote(name, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    return f"{base}/{quoted_name}/{quoted_version}/json"


def _release_status(url: str) -> int:
    request = urllib.request.Request(  # noqa: S310 - HTTPS is validated above.
        url,
        headers={"User-Agent": "ravage-release-check/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (OSError, urllib.error.URLError) as exc:
        message = f"could not verify registry state: {exc}"
        raise RegistryCheckError(message) from exc


class RegistryCheckError(RuntimeError):
    """Raised when registry occupancy cannot be verified safely."""


if __name__ == "__main__":
    raise SystemExit(main())
