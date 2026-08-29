from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

SOURCE_VERSION = "0.5.0"  # x-release-please-version


def package_version() -> str:
    try:
        return version("ravage")
    except PackageNotFoundError:
        return SOURCE_VERSION


__version__ = package_version()
