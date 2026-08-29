from __future__ import annotations

import os
import platform
import re
import subprocess
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml  # type: ignore[import-untyped]

from ravage.model_core.providers import ResolvedModelRoute
from ravage.xben_parts.models import XbenCase, XbenSettings

if TYPE_CHECKING:
    from typing import TextIO

def _run_command(
    cmd: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(  # noqa: S603
        list(cmd),
        cwd=cwd,
        env=dict(env),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        error = f"{' '.join(cmd)} failed: {message}"
        raise RuntimeError(error)
    return result


def _first_published_port(compose_path: Path) -> tuple[str, int]:
    for service_name, container_port, _ in _compose_published_ports(compose_path):
        return service_name, container_port
    message = f"no published HTTP port in {compose_path}"
    raise RuntimeError(message)


def _compose_published_ports(compose_path: Path) -> tuple[tuple[str, int, str], ...]:
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = _compose_services(compose)
    if not isinstance(services, dict):
        message = f"invalid compose services in {compose_path}"
        raise TypeError(message)
    ports: list[tuple[str, int, str]] = []
    for service_name, raw_service in services.items():
        if not isinstance(raw_service, dict):
            continue
        raw_ports = raw_service.get("ports", [])
        if not isinstance(raw_ports, list):
            continue
        for raw_port in raw_ports:
            container_port, protocol = _parse_container_port(raw_port)
            ports.append((str(service_name), container_port, protocol))
    return tuple(ports)


def _compose_services(compose: object) -> object:
    if not isinstance(compose, dict):
        return {}
    return compose.get("services", {})


def _parse_container_port(port_entry: object) -> tuple[int, str]:
    raw = str(port_entry)
    protocol = "tcp"
    if "/" in raw:
        raw, protocol = raw.split("/", maxsplit=1)
    return int(raw.split(":")[-1]), protocol.lower()


def _parse_published_port(output: str) -> int:
    matches = re.findall(r":(\d+)$", output.strip(), flags=re.MULTILINE)
    if not matches:
        message = f"could not parse published port from {output!r}"
        raise RuntimeError(message)
    return int(matches[-1])


def _parse_case_range(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", value)
    if match is None:
        message = "--range must look like 1-10"
        raise ValueError(message)
    start = int(match.group(1))
    end = int(match.group(2))
    if start > end:
        message = "--range start must be <= end"
        raise ValueError(message)
    return start, end


def _estimate_cost_usd(
    *,
    routes: Sequence[ResolvedModelRoute],
    input_tokens: int,
    output_tokens: int,
) -> float | None:
    if not routes:
        return None
    route = routes[0]
    input_cost = route.input_cost_per_1m_tokens
    output_cost = route.output_cost_per_1m_tokens
    if input_cost is None or output_cost is None:
        return None
    input_total = input_tokens / 1_000_000 * input_cost
    output_total = output_tokens / 1_000_000 * output_cost
    return round(input_total + output_total, 6)


def _route_to_json(route: ResolvedModelRoute) -> dict[str, object]:
    return {
        "ordinal": route.ordinal,
        "provider": route.provider,
        "model": route.model,
        "base_url": route.base_url,
        "ready": route.ready,
        "missing_env": list(route.missing_env),
        "max_output_tokens": route.max_output_tokens,
        "reasoning_effort": route.reasoning_effort,
        "input_cost_per_1m_tokens": route.input_cost_per_1m_tokens,
        "cached_input_cost_per_1m_tokens": route.cached_input_cost_per_1m_tokens,
        "output_cost_per_1m_tokens": route.output_cost_per_1m_tokens,
    }


def _docker_env(settings: XbenSettings) -> dict[str, str]:
    return {**os.environ, "DOCKER_DEFAULT_PLATFORM": settings.docker_platform}


def _agent_env(_settings: XbenSettings) -> dict[str, str]:
    env = dict(os.environ)
    pythonpath = "packages/ravage/src:packages/schemas/src"
    existing = env.get("PYTHONPATH")
    if existing:
        env["PYTHONPATH"] = f"{pythonpath}:{existing}"
    else:
        env["PYTHONPATH"] = pythonpath
    return env


def _run_id(output_dir: Path) -> str:
    safe = re.sub(r"[^A-Za-z0-9]+", "_", output_dir.name).strip("_").lower()
    return f"{safe}_{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped or None


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return int(str(value))


def _int_value(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return default


def _float_value(value: object, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str) and value.strip():
        return float(value)
    return default


def _architecture_warning(settings: XbenSettings) -> str | None:
    if settings.docker_platform == "linux/amd64" and platform.machine().lower() in {
        "arm64",
        "aarch64",
    }:
        return (
            "linux/amd64 benchmark containers are running from an ARM host; "
            "native amd64 is preferred"
        )
    return None


def _line(stdout: TextIO, tag: str, message: str) -> None:
    stdout.write(f"[{tag}] {message}\n")
    stdout.flush()


def _print_startup(
    stdout: TextIO,
    *,
    settings: XbenSettings,
    selected_cases: Sequence[XbenCase],
) -> None:
    color = _supports_color(stdout)
    green = _terminal_color("\033[32m", enabled=color)
    cyan = _terminal_color("\033[36m", enabled=color)
    dim = _terminal_color("\033[2m", enabled=color)
    reset = _terminal_color("\033[0m", enabled=color)
    stdout.write(
        "\n"
        f"{green}RAVAGE // XBEN TERMINAL{reset}\n"
        f"{dim}authorized local benchmark runner - "
        f"scope locked to Docker localhost targets{reset}\n"
        f"{cyan}target-set{reset}  xbow-validation-benchmarks\n"
        f"{cyan}mode{reset}        {settings.mode}\n"
        f"{cyan}agent{reset}       {settings.agent}/{settings.agent_mode}\n"
        f"{cyan}model{reset}       {settings.model_profile}/{settings.model_tier}\n"
        f"{cyan}cases{reset}       {len(selected_cases)} selected\n"
        f"{cyan}output{reset}      {settings.output_dir}\n\n"
    )
    stdout.flush()


def _terminal_color(sequence: str, *, enabled: bool) -> str:
    if enabled:
        return sequence
    return ""


def _supports_color(stdout: TextIO) -> bool:
    is_tty = getattr(stdout, "isatty", None)
    if not callable(is_tty):
        return False
    if "NO_COLOR" in os.environ:
        return False
    return bool(is_tty())
