from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path
from typing import Any

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BOOTSTRAP_SCRIPT = REPOSITORY_ROOT / "scripts" / "ops" / "bootstrap.sh"
INVALID_OPTION_EXIT_CODE = 2


def test_checkout_metadata_keeps_browser_support_optional() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert not any(
        dependency.partition(">=")[0] == "playwright"
        for dependency in metadata["project"]["dependencies"]
    )
    assert metadata["project"]["optional-dependencies"]["browser"] == ["playwright>=1.48"]


def test_help_and_unknown_options_do_not_create_an_environment(tmp_path: Path) -> None:
    checkout, _, _ = _bootstrap_checkout(tmp_path)

    help_result = _run(checkout, "--help", env={"PATH": "/usr/bin:/bin"})
    invalid_result = _run(checkout, "--browesr", env={"PATH": "/usr/bin:/bin"})

    assert help_result.returncode == 0
    assert "--install-browser" in help_result.stdout
    assert "deliberately lean" in help_result.stdout
    assert invalid_result.returncode == INVALID_OPTION_EXIT_CODE
    assert "unknown bootstrap option" in invalid_result.stderr
    assert not (checkout / ".venv").exists()


def test_base_bootstrap_is_lean_editable_and_runs_core_self_check(
    tmp_path: Path,
) -> None:
    checkout, fake_python, log_path = _bootstrap_checkout(tmp_path)

    result = _run(
        checkout,
        env=_bootstrap_env(tmp_path, fake_python=fake_python, log_path=log_path),
    )

    assert result.returncode == 0, result.stderr
    calls = _calls(log_path)
    install = _pip_install(calls, editable=True)
    assert str(checkout / "packages" / "schemas") in install
    assert str(checkout / "packages" / "ravage") in install
    assert not any("playwright" in argument for call in calls for argument in call["args"])
    assert any(call["args"] == ["-m", "ravage", "--version"] for call in calls)
    assert "[bootstrap] running core self-check" in result.stdout
    assert "Next: source" in result.stdout
    assert "ravage init http://127.0.0.1:3000" in result.stdout


def test_dev_and_browser_layers_are_explicit_and_do_not_download_chromium(
    tmp_path: Path,
) -> None:
    checkout, fake_python, log_path = _bootstrap_checkout(tmp_path)

    result = _run(
        checkout,
        "--dev",
        "--browser",
        env=_bootstrap_env(tmp_path, fake_python=fake_python, log_path=log_path),
    )

    assert result.returncode == 0, result.stderr
    calls = _calls(log_path)
    editable_install = _pip_install(calls, editable=True)
    assert f"{checkout / 'packages' / 'ravage'}[browser]" in editable_install
    dev_install = next(
        call["args"]
        for call in calls
        if call["args"][:3] == ["-m", "pip", "install"] and "pytest>=8.2" in call["args"]
    )
    assert "ruff>=0.5" in dev_install
    assert not any(call["args"][:2] == ["-m", "playwright"] for call in calls)
    assert "Chromium was not downloaded" in result.stdout


def test_install_browser_implies_extra_and_explicit_chromium_download(
    tmp_path: Path,
) -> None:
    checkout, fake_python, log_path = _bootstrap_checkout(tmp_path)

    result = _run(
        checkout,
        "--install-browser",
        env=_bootstrap_env(tmp_path, fake_python=fake_python, log_path=log_path),
    )

    assert result.returncode == 0, result.stderr
    calls = _calls(log_path)
    assert f"{checkout / 'packages' / 'ravage'}[browser]" in _pip_install(
        calls,
        editable=True,
    )
    assert any(call["args"] == ["-m", "playwright", "install", "chromium"] for call in calls)
    assert "explicit --install-browser request" in result.stdout


@pytest.mark.parametrize("target_kind", ["checkout", "non_venv", "symlink"])
def test_bootstrap_refuses_unsafe_virtualenv_targets_without_removing_them(
    tmp_path: Path,
    target_kind: str,
) -> None:
    checkout, fake_python, log_path = _bootstrap_checkout(tmp_path)
    if target_kind == "checkout":
        target = checkout
    elif target_kind == "non_venv":
        target = tmp_path / "important-data"
        target.mkdir()
    else:
        real_target = tmp_path / "real-venv-location"
        real_target.mkdir()
        target = tmp_path / "linked-venv"
        target.symlink_to(real_target, target_is_directory=True)
    sentinel = target.resolve() / "keep-me.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    environment = _bootstrap_env(
        tmp_path,
        fake_python=fake_python,
        log_path=log_path,
    )
    environment["RAVAGE_VENV"] = str(target)

    result = _run(checkout, env=environment)

    assert result.returncode == 1
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert "refusing" in result.stderr or "cannot be a symlink" in result.stderr
    assert not any(call["args"][:2] == ["-m", "venv"] for call in _calls(log_path))


def test_stale_marked_virtualenv_can_be_safely_recreated(tmp_path: Path) -> None:
    checkout, fake_python, log_path = _bootstrap_checkout(tmp_path)
    target = tmp_path / "stale-venv"
    (target / "bin").mkdir(parents=True)
    (target / "pyvenv.cfg").write_text("home = old\n", encoding="utf-8")
    shutil.copy2(fake_python, target / "bin" / "python")
    (target / "bin" / "activate").write_text(
        "export VIRTUAL_ENV=/old/location\n",
        encoding="utf-8",
    )
    sentinel = target / "old-state.txt"
    sentinel.write_text("stale", encoding="utf-8")
    environment = _bootstrap_env(
        tmp_path,
        fake_python=fake_python,
        log_path=log_path,
    )
    environment["RAVAGE_VENV"] = str(target)

    result = _run(checkout, env=environment)

    assert result.returncode == 0, result.stderr
    assert not sentinel.exists()
    assert any(call["args"][:2] == ["-m", "venv"] for call in _calls(log_path))
    assert "stale or damaged virtualenv" in result.stdout


def test_bootstrap_discovers_an_existing_uv_managed_python(tmp_path: Path) -> None:
    checkout, fake_python, log_path = _bootstrap_checkout(tmp_path)
    discovery_bin = tmp_path / "discovery-bin"
    discovery_bin.mkdir()
    managed_python = tmp_path / "uv-managed" / "python3.12"
    managed_python.parent.mkdir()
    shutil.copy2(fake_python, managed_python)
    _write_executable(
        discovery_bin / "python3",
        "#!/bin/sh\nexit 1\n",
    )
    uv_log = tmp_path / "uv.log"
    _write_executable(
        discovery_bin / "uv",
        textwrap.dedent(
            f"""\
            #!/bin/sh
            printf '%s\\n' "$*" > {uv_log!s}
            printf '%s\\n' {managed_python!s}
            """
        ),
    )
    environment = _bootstrap_env(tmp_path, fake_python=fake_python, log_path=log_path)
    environment.pop("RAVAGE_PYTHON")
    environment["PATH"] = f"{discovery_bin}:/usr/bin:/bin"

    result = _run(checkout, env=environment)

    assert result.returncode == 0, result.stderr
    assert "using uv-managed Python 3.12" in result.stdout
    discovery = uv_log.read_text(encoding="utf-8")
    assert "python find 3.12" in discovery
    assert "--managed-python" in discovery
    assert "--no-python-downloads" in discovery


def test_missing_python_prints_non_mutating_uv_guidance(tmp_path: Path) -> None:
    checkout, _, _ = _bootstrap_checkout(tmp_path)
    discovery_bin = tmp_path / "unsupported-bin"
    discovery_bin.mkdir()
    _write_executable(discovery_bin / "python3", "#!/bin/sh\nexit 1\n")
    environment = os.environ.copy()
    environment.pop("RAVAGE_PYTHON", None)
    environment["PATH"] = f"{discovery_bin}:/usr/bin:/bin"

    result = _run(checkout, env=environment)

    assert result.returncode == 1
    assert "uv python install 3.12" in result.stderr
    assert "RAVAGE_PYTHON" in result.stderr
    assert not (checkout / ".venv").exists()


def _bootstrap_checkout(tmp_path: Path) -> tuple[Path, Path, Path]:
    checkout = tmp_path / "checkout"
    script = checkout / "scripts" / "ops" / "bootstrap.sh"
    script.parent.mkdir(parents=True)
    shutil.copy2(BOOTSTRAP_SCRIPT, script)
    (checkout / "packages" / "schemas").mkdir(parents=True)
    (checkout / "packages" / "ravage").mkdir(parents=True)
    (checkout / "pyproject.toml").write_text(
        textwrap.dedent(
            """\
            [dependency-groups]
            dev = [
                "pytest>=8.2",
                "ruff>=0.5",
            ]
            """
        ),
        encoding="utf-8",
    )
    log_path = tmp_path / "python-calls.jsonl"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python3.12"
    _write_fake_python(fake_python)
    return checkout, fake_python, log_path


def _write_fake_python(path: Path) -> None:
    source = r"""#!@@REAL_SHEBANG@@
from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys

REAL_PYTHON = @@REAL_LITERAL@@
args = sys.argv[1:]
program = pathlib.Path(sys.argv[0])
log_path = pathlib.Path(os.environ["RAVAGE_BOOTSTRAP_TEST_LOG"])
log_path.parent.mkdir(parents=True, exist_ok=True)
with log_path.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"program": str(program), "args": args}) + "\n")

is_fake_venv = program.parent.name == "bin" and (program.parent.parent / "pyvenv.cfg").is_file()
if is_fake_venv:
    if args[:2] in (["-m", "ensurepip"], ["-m", "pip"]):
        raise SystemExit(0)
    if args[:2] == ["-m", "ravage"]:
        if "--version" in args:
            print("ravage 0.5.0")
        raise SystemExit(0)
    if args[:2] == ["-m", "playwright"]:
        raise SystemExit(0)
    os.execv(REAL_PYTHON, [REAL_PYTHON, *args])

if args[:2] == ["-m", "venv"] and len(args) == 3:
    target = pathlib.Path(args[2])
    (target / "bin").mkdir(parents=True, exist_ok=True)
    (target / "pyvenv.cfg").write_text("home = fake\n", encoding="utf-8")
    shutil.copy2(__file__, target / "bin" / "python")
    shutil.copy2(__file__, target / "bin" / "ravage")
    (target / "bin" / "activate").write_text(
        f'export VIRTUAL_ENV="{target}"\n',
        encoding="utf-8",
    )
    raise SystemExit(0)

os.execv(REAL_PYTHON, [REAL_PYTHON, *args])
"""
    rendered = source.replace("@@REAL_SHEBANG@@", sys.executable).replace(
        "@@REAL_LITERAL@@",
        repr(sys.executable),
    )
    _write_executable(path, rendered)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _bootstrap_env(
    tmp_path: Path,
    *,
    fake_python: Path,
    log_path: Path,
) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_python.parent}:/usr/bin:/bin"
    environment["RAVAGE_PYTHON"] = str(fake_python)
    environment["RAVAGE_BOOTSTRAP_TEST_LOG"] = str(log_path)
    environment["PIP_CACHE_DIR"] = str(tmp_path / "pip-cache")
    return environment


def _run(
    checkout: Path,
    *args: str,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - executes a copied local fixture script.
        ["/bin/bash", str(checkout / "scripts" / "ops" / "bootstrap.sh"), *args],
        cwd=checkout,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def _calls(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _pip_install(
    calls: list[dict[str, Any]],
    *,
    editable: bool,
) -> list[str]:
    return next(
        call["args"]
        for call in calls
        if call["args"][:3] == ["-m", "pip", "install"] and ("-e" in call["args"]) is editable
    )
