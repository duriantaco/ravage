from __future__ import annotations

# This standalone check reports concise, actionable contract failures.
# ruff: noqa: EM101, EM102, TRY003
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_COMMAND_TIMEOUT_SECONDS = 300


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build and smoke-test Ravage's base wheels in a clean virtualenv."
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="retain artifacts in this empty directory instead of a temporary directory",
    )
    parsed = parser.parse_args(argv)

    if parsed.work_dir is not None:
        work_dir = parsed.work_dir.resolve(strict=False)
        _require_empty_directory(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        return _run_smoke(work_dir)

    with tempfile.TemporaryDirectory(prefix="ravage-clean-install-") as temporary:
        return _run_smoke(Path(temporary))


def _run_smoke(work_dir: Path) -> int:
    wheel_dir = work_dir / "wheels"
    wheel_dir.mkdir()
    _run(
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--disable-pip-version-check",
        "--no-deps",
        "--wheel-dir",
        str(wheel_dir),
        str(ROOT / "packages" / "schemas"),
    )
    _run(
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--disable-pip-version-check",
        "--no-deps",
        "--wheel-dir",
        str(wheel_dir),
        str(ROOT / "packages" / "ravage"),
    )
    schemas_wheel = _one_wheel(wheel_dir, "ravage_schemas-*.whl")
    ravage_wheel = _one_wheel(wheel_dir, "ravage-[0-9]*.whl")

    clean_venv = work_dir / "venv"
    _run(sys.executable, "-m", "venv", str(clean_venv))
    clean_python = _venv_command(clean_venv, "python")
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["PATH"] = f"{clean_python.parent}{os.pathsep}{environment.get('PATH', '')}"
    environment["PYTHONNOUSERSITE"] = "1"
    environment["VIRTUAL_ENV"] = str(clean_venv)
    _run(
        clean_python,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        str(schemas_wheel),
        str(ravage_wheel),
        env=environment,
    )
    clean_ravage = _venv_command(clean_venv, "ravage")

    _run(
        clean_python,
        "-c",
        _BASE_INSTALL_ASSERTIONS,
        env=environment,
    )
    help_result = _run(clean_ravage, "--help", env=environment, capture=True)
    if "doctor" not in help_result.stdout:
        raise SmokeCheckError("clean `ravage --help` output does not expose `doctor`")

    run_root = work_dir / "runs"
    doctor_result = _run(
        clean_ravage,
        "doctor",
        "--json",
        "--run-root",
        str(run_root),
        cwd=work_dir,
        env=environment,
        capture=True,
    )
    try:
        doctor = json.loads(doctor_result.stdout)
    except json.JSONDecodeError as exc:
        raise SmokeCheckError("clean `ravage doctor --json` did not return JSON") from exc
    _assert_doctor_payload(doctor)

    sys.stdout.write(
        "clean install check passed: base wheels, no Playwright, CLI help, and doctor\n"
    )
    return 0


def _assert_doctor_payload(payload: object) -> None:
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise SmokeCheckError("clean core doctor did not report ok=true")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise SmokeCheckError("clean core doctor omitted checks")
    by_name = {
        str(item.get("name")): item
        for item in checks
        if isinstance(item, dict) and item.get("name")
    }
    for required in ("python", "entrypoint", "package", "run_location"):
        if by_name.get(required, {}).get("status") != "ok":
            raise SmokeCheckError(f"clean core doctor did not pass {required}")
    browser = by_name.get("browser", {})
    if (
        browser.get("status") != "warn"
        or "not installed" not in str(browser.get("detail", "")).lower()
    ):
        raise SmokeCheckError("clean base doctor did not report Playwright as optional")


def _require_empty_directory(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise SmokeCheckError("--work-dir must be a regular directory")
    if path.exists() and any(path.iterdir()):
        raise SmokeCheckError("--work-dir must be empty")


def _one_wheel(directory: Path, pattern: str) -> Path:
    matches = tuple(directory.glob(pattern))
    if len(matches) != 1:
        raise SmokeCheckError(f"expected one wheel matching {pattern}, found {len(matches)}")
    return matches[0]


def _venv_command(venv: Path, name: str) -> Path:
    scripts = venv / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""
    command = scripts / f"{name}{suffix}"
    if not command.is_file():
        raise SmokeCheckError(f"clean virtualenv did not create {command}")
    return command


def _run(
    executable: str | Path,
    *args: str,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = [str(executable), *args]
    try:
        result = subprocess.run(  # noqa: S603 - fixed local build/test tools.
            command,
            cwd=cwd,
            env=env,
            capture_output=capture,
            text=True,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SmokeCheckError(
            f"command timed out after {_COMMAND_TIMEOUT_SECONDS}s: {' '.join(command)}"
        ) from exc
    if result.returncode != 0:
        detail = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        message = f"command failed ({result.returncode}): {' '.join(command)}"
        if detail:
            message += f"\n{detail}"
        raise SmokeCheckError(message)
    return result


class SmokeCheckError(RuntimeError):
    """Raised when the built-wheel consumer contract is broken."""


_BASE_INSTALL_ASSERTIONS = """
from importlib.metadata import requires
from importlib.util import find_spec
from pathlib import Path

import ravage

assert find_spec("playwright") is None, "base install unexpectedly includes Playwright"
playwright_requirements = [
    item for item in (requires("ravage") or []) if item.lower().startswith("playwright")
]
assert playwright_requirements, "ravage wheel omitted its browser extra metadata"
assert all("extra == 'browser'" in item for item in playwright_requirements)
assert "site-packages" in str(Path(ravage.__file__).resolve())
"""


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SmokeCheckError as exc:
        sys.stderr.write(f"clean install check failed: {exc}\n")
        raise SystemExit(1) from None
