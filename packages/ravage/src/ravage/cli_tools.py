# This CLI-facing module deliberately writes its installation plan to stdout.
# ruff: noqa: T201

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ravage.runtime.image import ToolImageError, verify_published_tool_image
from ravage.runtime.types import DEFAULT_PUBLISHED_TOOL_IMAGE, DEFAULT_TOOL_IMAGE

TOOL_RUNTIME_BINARIES = (
    "curl",
    "python3",
    "nmap",
    "ffuf",
    "katana",
    "nuclei",
    "sqlmap",
    "nikto",
    "openssl",
    "ncat",
    "nc",
)

InstallMethod = Literal["auto", "docker", "apt", "brew", "manual"]

_GO_VERSION = "1.23.6"
_GO_TOOLS = (
    "github.com/ffuf/ffuf/v2@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
)
_BUNDLED_KALI_DOCKERFILE = """\
FROM kalilinux/kali-rolling
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl ffuf git golang-go katana ncat nikto nmap nuclei \
    openssl python3 sqlmap \
    && rm -rf /var/lib/apt/lists/* \
    && for binary in curl python3 nmap ffuf katana nuclei sqlmap nikto openssl ncat; do \
        command -v "$binary" >/dev/null; \
    done
"""


@dataclass(frozen=True)
class InstallCommand:
    argv: tuple[str, ...]
    display: str = ""
    env: dict[str, str] = field(default_factory=dict)
    input_text: str | None = None

    @property
    def rendered(self) -> str:
        return self.display or " ".join(self.argv)


@dataclass(frozen=True)
class InstallPlan:
    requested_method: InstallMethod
    method: InstallMethod
    image: str
    execute: bool
    commands: tuple[InstallCommand, ...]
    fallback_commands: tuple[InstallCommand, ...] = ()
    notes: tuple[str, ...] = ()


def install_tools(
    *,
    method: InstallMethod = "auto",
    execute: bool = False,
    image: str = DEFAULT_TOOL_IMAGE,
    no_cache: bool = False,
) -> int:
    """
    Print an installation plan and optionally execute it.

    The default is deliberately a dry run. Downloads, package installation,
    and image builds happen only after the caller supplies ``--execute``.
    """
    selected = _select_method(method)
    plan = _build_plan(
        requested=method,
        selected=selected,
        image=image,
        execute=execute,
        no_cache=no_cache,
    )
    _print_plan(plan)
    if not execute:
        print("DRY RUN — no commands were executed")
        return 0
    if not plan.commands:
        print("No automatic install commands are available for the manual method.")
        return 2
    if selected == "docker":
        preflight = _preflight_docker(plan.commands[0].argv[0])
        if preflight != 0:
            return preflight
        return _execute_docker_plan(plan)
    return _execute_plan(plan)


def _select_method(requested: InstallMethod) -> InstallMethod:
    if requested != "auto":
        return requested
    if shutil.which("docker"):
        return "docker"
    if sys.platform == "darwin" and shutil.which("brew"):
        return "brew"
    if sys.platform.startswith("linux") and shutil.which("apt-get"):
        return "apt"
    return "manual"


def _build_plan(
    *,
    requested: InstallMethod,
    selected: InstallMethod,
    image: str,
    execute: bool,
    no_cache: bool,
) -> InstallPlan:
    if selected == "docker":
        commands, fallback_commands, notes = _docker_commands(
            image=image,
            no_cache=no_cache,
        )
    elif selected == "apt":
        commands, notes = _apt_commands()
        fallback_commands = ()
    elif selected == "brew":
        commands, notes = _brew_commands()
        fallback_commands = ()
    else:
        commands = ()
        fallback_commands = ()
        notes = (
            "Install the listed runtime tools with your system package manager,",
            "or choose --method docker, apt, or brew.",
        )
    return InstallPlan(
        requested_method=requested,
        method=selected,
        image=image,
        execute=execute,
        commands=commands,
        fallback_commands=fallback_commands,
        notes=notes,
    )


def _docker_commands(
    *,
    image: str,
    no_cache: bool,
) -> tuple[
    tuple[InstallCommand, ...],
    tuple[InstallCommand, ...],
    tuple[str, ...],
]:
    docker = shutil.which("docker") or "docker"
    build_command = _docker_build_command(
        docker=docker,
        image=image,
        no_cache=no_cache,
    )
    if image != DEFAULT_TOOL_IMAGE or no_cache:
        return (
            (build_command,),
            (),
            (f"After installation: ravage tools check --image {image}",),
        )

    commands = (
        InstallCommand((docker, "pull", DEFAULT_PUBLISHED_TOOL_IMAGE)),
        InstallCommand((docker, "tag", DEFAULT_PUBLISHED_TOOL_IMAGE, image)),
    )
    return (
        commands,
        (build_command,),
        (
            "Ravage verifies the published image by digest before tagging it locally.",
            "If the pull fails, rerun with --no-cache for the unsigned local fallback.",
            f"After installation: ravage tools check --image {image}",
        ),
    )


def _docker_build_command(
    *,
    docker: str,
    image: str,
    no_cache: bool,
) -> InstallCommand:
    local_dockerfile = Path("sandbox") / "kali.Dockerfile"
    if local_dockerfile.is_file():
        argv = [docker, "build", "-t", image, "-f", str(local_dockerfile)]
        if no_cache:
            argv.append("--no-cache")
        argv.append("sandbox")
        return InstallCommand(tuple(argv))
    argv = [docker, "build", "-t", image]
    if no_cache:
        argv.append("--no-cache")
    argv.append("-")
    return InstallCommand(
        tuple(argv),
        display=" ".join(argv) + "  < bundled kali.Dockerfile",
        input_text=_BUNDLED_KALI_DOCKERFILE,
    )


def _apt_commands() -> tuple[tuple[InstallCommand, ...], tuple[str, ...]]:
    commands: list[InstallCommand] = [
        InstallCommand(("sudo", "apt-get", "update")),
        InstallCommand(
            (
                "sudo",
                "apt-get",
                "install",
                "-y",
                "ca-certificates",
                "curl",
                "git",
                "nikto",
                "nmap",
                "ncat",
                "openssl",
                "python3",
                "sqlmap",
                "tar",
            )
        ),
    ]
    commands.extend(_go_tool_commands())
    return (
        tuple(commands),
        (
            "Go-based scanners are installed in .tools/bin.",
            "Ravage automatically discovers .tools/bin with --tool-runtime host.",
        ),
    )


def _brew_commands() -> tuple[tuple[InstallCommand, ...], tuple[str, ...]]:
    brew = shutil.which("brew") or "brew"
    commands: list[InstallCommand] = [
        InstallCommand(
            (
                brew,
                "install",
                "curl",
                "ffuf",
                "go",
                "nikto",
                "nmap",
                "openssl",
                "sqlmap",
            )
        ),
    ]
    commands.extend(_go_tool_commands())
    return (
        tuple(commands),
        (
            "Go-based scanners are installed in .tools/bin.",
            "Ravage automatically discovers .tools/bin with --tool-runtime host.",
        ),
    )


def _go_tool_commands() -> tuple[InstallCommand, ...]:
    tools_dir = Path(".tools")
    local_go = tools_dir / "go-root" / "bin" / "go"
    system_go = shutil.which("go")
    commands: list[InstallCommand] = []
    if local_go.is_file():
        go = str(local_go)
    elif system_go:
        go = system_go
    else:
        archive = tools_dir / "downloads" / "go.tar.gz"
        go_root = tools_dir / "go-root"
        go = str(local_go)
        commands.extend(
            (
                InstallCommand(
                    (
                        "mkdir",
                        "-p",
                        str(archive.parent),
                        str(go_root),
                        str(tools_dir / "bin"),
                    )
                ),
                InstallCommand(
                    (
                        "curl",
                        "-L",
                        "-o",
                        str(archive),
                        _go_download_url(),
                    )
                ),
                InstallCommand(
                    (
                        "tar",
                        "-xzf",
                        str(archive),
                        "-C",
                        str(go_root),
                        "--strip-components=1",
                    ),
                    display=(
                        f"mkdir -p {go_root} && tar -xzf {archive} "
                        f"-C {go_root} --strip-components=1"
                    ),
                ),
            )
        )
    commands.append(InstallCommand(("mkdir", "-p", str(tools_dir / "bin"))))
    commands.extend(
        InstallCommand(
            (go, "install", package),
            display=f"GOBIN=.tools/bin {go} install {package}",
            env={"GOBIN": str((Path.cwd() / tools_dir / "bin").resolve())},
        )
        for package in _GO_TOOLS
    )
    return tuple(commands)


def _go_download_url() -> str:
    os_name = "darwin" if sys.platform == "darwin" else "linux"
    machine = platform.machine().lower()
    architecture = "arm64" if machine in {"arm64", "aarch64"} else "amd64"
    return f"https://go.dev/dl/go{_GO_VERSION}.{os_name}-{architecture}.tar.gz"


def _print_plan(plan: InstallPlan) -> None:
    print("RAVAGE // INSTALL PLAN")
    print(f"requested  {plan.requested_method}")
    print(f"method     {plan.method}")
    print(f"execute    {str(plan.execute).lower()}")
    if plan.method == "docker":
        print(f"image      {plan.image}")
    print("commands")
    if plan.commands:
        for command in plan.commands:
            print(f"  $ {command.rendered}")
    else:
        print("  (manual installation)")
    if plan.fallback_commands:
        print("local fallback (rerun with --no-cache if the pull fails)")
        for command in plan.fallback_commands:
            print(f"  $ {command.rendered}")
    for note in plan.notes:
        print(f"  {note}")


def _preflight_docker(docker: str) -> int:
    argv = [docker, "info", "--format", "{{.ServerVersion}}"]
    try:
        result = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        print("docker command not found", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("docker preflight timed out after 30 seconds", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"docker preflight failed: {exc}", file=sys.stderr)
        return 1
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    lowered = output.lower()
    failed = result.returncode != 0 or any(
        marker in lowered
        for marker in (
            "cannot connect",
            "permission denied",
            "daemon is not running",
            "error during connect",
        )
    )
    if not failed:
        return 0

    print("docker daemon is not reachable.", file=sys.stderr)
    if output:
        print(output, file=sys.stderr)
    if _running_under_wsl():
        print(
            "Detected WSL. Start Docker Desktop, enable WSL Integration for this "
            "distribution, then run `wsl --shutdown` before retrying.",
            file=sys.stderr,
        )
    else:
        print("Start the Docker daemon and retry the command.", file=sys.stderr)
    return 1


def _execute_plan(plan: InstallPlan) -> int:
    return _execute_commands(plan.commands)


def _execute_docker_plan(plan: InstallPlan) -> int:
    if not plan.fallback_commands:
        return _execute_plan(plan)
    pull_result = _execute_commands(plan.commands[:1])
    if pull_result != 0:
        print(
            "Published image pull failed; no local build was started. "
            "Rerun with --no-cache to use the unsigned local build fallback.",
            file=sys.stderr,
        )
        return pull_result
    try:
        verify_published_tool_image(docker=plan.commands[0].argv[0])
    except ToolImageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return _execute_commands(plan.commands[1:])


def _execute_commands(commands: tuple[InstallCommand, ...]) -> int:
    for command in commands:
        env = None
        if command.env:
            env = os.environ.copy()
            env.update(command.env)
        try:
            result = subprocess.run(  # noqa: S603
                list(command.argv),
                check=False,
                env=env,
                input=command.input_text,
                text=command.input_text is not None,
            )
        except OSError as exc:
            print(f"command failed to start: {command.rendered}: {exc}", file=sys.stderr)
            return 1
        if result.returncode != 0:
            return int(result.returncode)
    return 0


def _running_under_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        version = Path("/proc/version").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return "microsoft" in version.lower()
