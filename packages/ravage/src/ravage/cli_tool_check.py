# Tool checks use bounded early returns to preserve precise failure diagnostics.
# ruff: noqa: PLR0911

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from ravage.cli_tools import TOOL_RUNTIME_BINARIES
from ravage.tool_paths import is_executable_file, project_tool_bin

_DOCKER_INSPECT_TIMEOUT_SECONDS = 10
_DOCKER_PROBE_TIMEOUT_SECONDS = 30


def tool_check_report(*, image: str = "") -> dict[str, object]:
    """Return host and container tool availability without mutating the system."""
    host = _host_tool_status()
    docker = dict(_docker_tool_status(image=image))
    docker_ready = _docker_runtime_ready(docker)
    docker["ready"] = docker_ready
    if docker_ready:
        recommendation = "use --tool-runtime auto or --tool-runtime docker"
    elif _host_runtime_ready(host):
        recommendation = "host runtime is ready"
    elif _host_core_ready(host):
        recommendation = (
            "host runtime has core tools; install optional scanners for broader coverage"
        )
    elif bool(docker.get("available")):
        recommendation = _docker_repair_recommendation(docker)
    else:
        recommendation = "install host tools or pull/build the Docker tool image"
    return {
        "host": host,
        "docker": docker,
        "runtime_guidance": [
            "Host runtime: install tools on the machine running Ravage.",
            "Docker runtime: pull or build the isolated image and select --tool-runtime docker.",
            "Target VM: tools belong in the Ravage runtime, not on the assessed target.",
        ],
        "recommendation": recommendation,
    }


def _host_tool_status() -> dict[str, dict[str, object]]:
    status: dict[str, dict[str, object]] = {}
    local_bin = project_tool_bin()
    for tool in TOOL_RUNTIME_BINARIES:
        env_name = f"RAVAGE_{tool.upper()}_BIN".replace("-", "_")
        override = os.environ.get(env_name)
        if override:
            path = Path(override).expanduser()
            available = is_executable_file(path)
            status[tool] = {
                "available": available,
                "path": str(path),
                "source": env_name,
                "error": "" if available else _executable_path_error(path),
            }
            continue

        resolved = shutil.which(tool)
        if resolved:
            status[tool] = {
                "available": True,
                "path": resolved,
                "source": "PATH",
                "error": "",
            }
            continue

        repo_local = local_bin / tool
        if repo_local.exists():
            available = is_executable_file(repo_local)
            status[tool] = {
                "available": available,
                "path": str(repo_local),
                "source": ".tools/bin",
                "error": "" if available else _executable_path_error(repo_local),
            }
            continue

        status[tool] = {
            "available": False,
            "path": "",
            "source": "",
            "error": "",
        }
    return status


def _executable_path_error(path: Path) -> str:
    if not path.exists():
        return "configured path does not exist"
    if not path.is_file():
        return "configured path is not a regular file"
    return "configured file is not executable"


def _docker_tool_status(*, image: str) -> dict[str, object]:
    # Attempt the conventional command name when it is not on PATH. This lets
    # the resulting FileNotFoundError distinguish "Docker is not installed"
    # from "the image is missing" and also works with command shims.
    docker = shutil.which("docker") or "docker"
    try:
        inspect = subprocess.run(  # noqa: S603
            [docker, "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            timeout=_DOCKER_INSPECT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return _docker_unavailable(image, "Docker command not found")
    except subprocess.TimeoutExpired:
        return _docker_unavailable(image, "Docker image inspect timed out")
    except OSError as exc:
        return _docker_unavailable(image, str(exc))

    if inspect.returncode != 0:
        detail = (inspect.stderr or inspect.stdout or "Docker image not found").strip()
        return _docker_unavailable(image, detail)

    image_id = inspect.stdout.strip()
    command = " ; ".join(
        f"command -v {tool} 2>/dev/null | sed 's#^#{tool}\\t#'" for tool in TOOL_RUNTIME_BINARIES
    )
    try:
        probe = subprocess.run(  # noqa: S603
            [docker, "run", "--rm", image, "sh", "-lc", command],
            capture_output=True,
            text=True,
            timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "image": image,
            "id": image_id,
            "tools": {},
            "error": "Docker tool probe timed out",
        }
    except OSError as exc:
        return {
            "available": True,
            "image": image,
            "id": image_id,
            "tools": {},
            "error": str(exc),
        }

    tools = _parse_docker_tools(probe.stdout)
    for tool in TOOL_RUNTIME_BINARIES:
        tools.setdefault(tool, {"available": False, "path": ""})
    return {
        # The image exists even if its diagnostic probe reports a missing tool.
        "available": True,
        "image": image,
        "id": image_id,
        "tools": tools,
        "error": "" if probe.returncode == 0 else _process_error(probe),
    }


def _parse_docker_tools(output: str) -> dict[str, dict[str, object]]:
    tools: dict[str, dict[str, object]] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "\t" in line:
            name, path = line.split("\t", 1)
            tools[name.strip()] = {
                "available": bool(path.strip()),
                "path": path.strip(),
            }
            continue
        name, separator, state = line.partition(":")
        if separator:
            tools[name.strip()] = {
                "available": state.strip() == "ok",
                "path": "",
            }
    return tools


def _host_core_ready(host: dict[str, dict[str, object]]) -> bool:
    return all(bool(host.get(name, {}).get("available")) for name in ("curl", "python3"))


def _host_runtime_ready(host: dict[str, dict[str, object]]) -> bool:
    return _runtime_toolset_ready(host)


def _docker_runtime_ready(docker: dict[str, object]) -> bool:
    if not bool(docker.get("available")) or str(docker.get("error") or "").strip():
        return False
    tools = docker.get("tools")
    if not isinstance(tools, dict):
        return False
    normalized = {str(name): item for name, item in tools.items() if isinstance(item, dict)}
    return _runtime_toolset_ready(normalized)


def _runtime_toolset_ready(tools: dict[str, dict[str, object]]) -> bool:
    required = (
        "curl",
        "python3",
        "nmap",
        "ffuf",
        "katana",
        "nuclei",
        "sqlmap",
        "nikto",
        "openssl",
    )
    return all(bool(tools.get(name, {}).get("available")) for name in required) and (
        bool(tools.get("ncat", {}).get("available")) or bool(tools.get("nc", {}).get("available"))
    )


def _docker_repair_recommendation(docker: dict[str, object]) -> str:
    error = " ".join(str(docker.get("error") or "").split())
    if error:
        return f"fix the Docker runtime check ({error[:180]}), then rerun ravage tools check"
    tools = docker.get("tools")
    normalized = tools if isinstance(tools, dict) else {}
    missing = [
        name
        for name in TOOL_RUNTIME_BINARIES
        if not bool(
            normalized.get(name, {}).get("available")
            if isinstance(normalized.get(name), dict)
            else False
        )
    ]
    if "ncat" in missing and "nc" not in missing:
        missing.remove("ncat")
    if "nc" in missing and "ncat" not in missing:
        missing.remove("nc")
    detail = ", ".join(missing) or "advertised tools"
    return (
        f"reinstall the Docker tool image; missing {detail}. Run ravage tools install "
        "--method docker --execute"
    )


def _docker_unavailable(image: str, error: str) -> dict[str, object]:
    return {
        "available": False,
        "image": image,
        "tools": {},
        "error": error,
    }


def _process_error(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr or result.stdout or "Docker tool probe failed").strip()
