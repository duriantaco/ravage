from __future__ import annotations

# ruff: noqa: EM102,I001,PERF401,T201,TRY003,TRY004

import argparse
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, build_opener

import yaml  # type: ignore[import-untyped]

from ravage.cli_ui import banner, tone

_HTTP_OK_MIN = 200
_HTTP_OK_MAX = 300


@dataclass(frozen=True)
class LabManifest:
    id: str
    name: str
    difficulty: str
    category: str
    warning: str
    manifest_path: Path
    compose_path: Path
    default_url: str
    brief_path: Path
    flags: list[dict[str, object]]
    vulnerabilities: list[dict[str, object]]
    attack_chain: list[str]
    healthcheck: str = ""

    @property
    def flag_count(self) -> int:
        return len(self.flags)


class LabCommandError(RuntimeError):
    """An actionable lab setup or lifecycle failure."""


def _default_labs_dir() -> Path:
    override = os.environ.get("RAVAGE_LABS_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    checkout_labs = Path(__file__).resolve().parents[4] / "examples" / "labs"
    if checkout_labs.is_dir():
        return checkout_labs
    return Path("examples/labs")


DEFAULT_LABS_DIR = _default_labs_dir()


def load_lab(lab_id: str, *, labs_dir: Path | str = DEFAULT_LABS_DIR) -> LabManifest:
    labs_path = Path(labs_dir)
    manifest_path = labs_path / lab_id / "ravage-lab.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"lab manifest not found: {manifest_path}")
    payload = _load_yaml(manifest_path)
    compose_file = str(payload.get("compose_file") or "docker-compose.yml")
    brief_file = str(payload.get("brief") or "brief.yaml")
    return LabManifest(
        id=str(payload.get("id") or lab_id),
        name=str(payload.get("name") or lab_id),
        difficulty=str(payload.get("difficulty") or ""),
        category=str(payload.get("category") or ""),
        warning=str(payload.get("warning") or ""),
        manifest_path=manifest_path,
        compose_path=manifest_path.parent / compose_file,
        default_url=str(payload.get("default_url") or ""),
        brief_path=manifest_path.parent / brief_file,
        flags=_dict_list(payload.get("flags")),
        vulnerabilities=_dict_list(payload.get("vulnerabilities")),
        attack_chain=[str(item) for item in _list(payload.get("attack_chain"))],
        healthcheck=str(payload.get("healthcheck") or ""),
    )


def list_labs(*, labs_dir: Path | str = DEFAULT_LABS_DIR) -> list[LabManifest]:
    labs_path = Path(labs_dir)
    labs: list[LabManifest] = []
    if not labs_path.exists():
        return labs
    for manifest_path in sorted(labs_path.glob("*/ravage-lab.yaml")):
        labs.append(load_lab(manifest_path.parent.name, labs_dir=labs_path))
    return labs


def handle_lab_command(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="ravage lab",
        description="Run the included, deliberately vulnerable local practice labs.",
    )
    parser.add_argument("--labs-dir", type=Path, default=DEFAULT_LABS_DIR)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--labs-dir", type=Path, default=argparse.SUPPRESS)
    show_parser = subparsers.add_parser("show")
    show_parser.add_argument("lab_id")
    show_parser.add_argument("--labs-dir", type=Path, default=argparse.SUPPRESS)
    up_parser = subparsers.add_parser("up")
    up_parser.add_argument("lab_id")
    up_parser.add_argument("--labs-dir", type=Path, default=argparse.SUPPRESS)
    up_parser.add_argument(
        "--wait-seconds",
        type=_positive_wait_seconds,
        default=60,
        help="wait for the lab health endpoint; defaults to 60 seconds",
    )
    up_parser.add_argument(
        "--no-wait",
        action="store_true",
        help="return after Docker Compose starts without waiting for health",
    )
    down_parser = subparsers.add_parser("down")
    down_parser.add_argument("lab_id")
    down_parser.add_argument("--labs-dir", type=Path, default=argparse.SUPPRESS)
    parsed = parser.parse_args(args)

    try:
        if parsed.command == "list":
            _print_lab_list(parsed.labs_dir)
            return
        lab = load_lab(str(parsed.lab_id), labs_dir=parsed.labs_dir)
        if parsed.command == "show":
            _print_lab(lab)
            return
        if parsed.command == "up":
            _compose(lab, "up", "--build", "-d")
            if not parsed.no_wait and lab.healthcheck:
                _wait_for_health(lab, timeout_seconds=parsed.wait_seconds)
            _print_lab_ready(lab, waited=not parsed.no_wait and bool(lab.healthcheck))
            return
        if parsed.command == "down":
            _compose(lab, "down")
            print(f"{tone('[done]', 'ok')} stopped {lab.id}")
            return
    except FileNotFoundError as exc:
        parser.error(
            f"{exc}. Run `ravage lab list` to see available labs; "
            "set RAVAGE_LABS_DIR when using a custom checkout."
        )
    except (LabCommandError, OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))


def _print_lab_list(labs_dir: Path) -> None:
    labs = list_labs(labs_dir=labs_dir)
    if not labs:
        raise LabCommandError(
            f"no Ravage labs found in {labs_dir}; run from a source checkout or set "
            "RAVAGE_LABS_DIR to its examples/labs directory"
        )
    print(banner("LABS"))
    print(tone("lab  flags  url  difficulty", "muted"))
    for lab in labs:
        print(
            f"{tone(lab.id, 'info')}  "
            f"flags={tone(lab.flag_count, 'accent')}  "
            f"url={lab.default_url}  "
            f"difficulty={tone(lab.difficulty, 'accent')}"
        )


def _print_lab(lab: LabManifest) -> None:
    print(banner("LAB"))
    for label, value in (
        ("id", lab.id),
        ("name", lab.name),
        ("difficulty", lab.difficulty),
        ("category", lab.category),
        ("url", lab.default_url),
        ("flags", lab.flag_count),
        ("compose", lab.compose_path),
        ("brief", lab.brief_path),
        ("health", lab.healthcheck),
    ):
        print(f"{tone(f'{label:<12}', 'info')}{value}")
    if lab.warning:
        print(f"{tone('warning    ', 'warn')}{lab.warning}")


def _compose(lab: LabManifest, *compose_args: str) -> None:
    if not lab.compose_path.exists():
        raise LabCommandError(f"compose file not found: {lab.compose_path}")
    docker = shutil.which("docker")
    if not docker:
        message = (
            "Docker is required for local labs but was not found. Install/start Docker, "
            "then run `ravage doctor --workflow lab`."
        )
        raise LabCommandError(message)
    command = [docker, "compose", "-f", str(lab.compose_path), *compose_args]
    try:
        subprocess.run(command, check=True)  # noqa: S603
    except subprocess.CalledProcessError as exc:
        raise LabCommandError(
            f"Docker Compose failed for {lab.id} (exit {exc.returncode}). "
            "Run `docker compose version` and `ravage doctor --workflow lab`."
        ) from None
    except OSError as exc:
        raise LabCommandError(f"could not run Docker Compose for {lab.id}: {exc}") from None


def _wait_for_health(lab: LabManifest, *, timeout_seconds: int) -> None:
    if timeout_seconds < 1:
        message = "--wait-seconds must be at least 1; use --no-wait to skip"
        raise LabCommandError(message)
    deadline = time.monotonic() + timeout_seconds
    opener = build_opener(ProxyHandler({}))
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            with opener.open(lab.healthcheck, timeout=min(2, timeout_seconds)) as response:
                if _HTTP_OK_MIN <= response.status < _HTTP_OK_MAX:
                    return
                last_error = f"HTTP {response.status}"
        except HTTPError as exc:
            last_error = f"HTTP {exc.code}"
        except (TimeoutError, URLError, OSError) as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise LabCommandError(
        f"{lab.id} did not become healthy at {lab.healthcheck} within "
        f"{timeout_seconds}s ({last_error}). Inspect with "
        f"`docker compose -f {shlex.quote(str(lab.compose_path))} logs`."
    )


def _print_lab_ready(lab: LabManifest, *, waited: bool) -> None:
    state = "ready" if waited else "started"
    print(banner("LAB", f"{lab.id} · {state}"))
    print(f"{tone(f'{state:<12}', 'ok')}{lab.default_url}")
    quoted_brief = shlex.quote(str(lab.brief_path))
    print(f"{tone('[next]', 'info')} ravage scan {quoted_brief} --probe surface_map --report")
    print(f"{tone('[browser]', 'info')} ravage traffic capture {lab.default_url}")
    print(f"{tone('[stop]', 'warn')} ravage lab down {shlex.quote(lab.id)}")


def _positive_wait_seconds(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError as exc:
        message = "must be an integer"
        raise argparse.ArgumentTypeError(message) from exc
    if seconds < 1:
        message = "must be at least 1; use --no-wait to skip"
        raise argparse.ArgumentTypeError(message)
    return seconds


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"lab manifest must be a YAML object: {path}")
    return payload


def _dict_list(value: object) -> list[dict[str, object]]:
    return [dict(item) for item in _list(value) if isinstance(item, dict)]


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


__all__ = [
    "DEFAULT_LABS_DIR",
    "LabCommandError",
    "LabManifest",
    "handle_lab_command",
    "list_labs",
    "load_lab",
]
