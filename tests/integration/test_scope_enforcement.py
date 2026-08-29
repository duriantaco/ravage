import os
import shutil
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Never
from uuid import uuid4

import pytest
from pentest_schemas import Scope
from ravage.runtime import ScopeFirewall

COMPOSE_FILE = Path(__file__).resolve().parent / "fixtures" / "scope-compose.yml"
REQUIRE_DOCKER_ENV = "RAVAGE_REQUIRE_DOCKER_INTEGRATION"

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
BinaryResolver = Callable[[str], str | None]


def run_command(
    args: list[str],
    *,
    check: bool = True,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        args,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def compose_command_prefix(project_name: str | None = None) -> list[str]:
    name = project_name or f"ravage-scope-{uuid4().hex}"
    return [
        "docker",
        "compose",
        "--project-name",
        name,
        "--file",
        str(COMPOSE_FILE),
    ]


def _docker_unavailable(reason: str) -> Never:
    if os.environ.get(REQUIRE_DOCKER_ENV) == "1":
        pytest.fail(reason)
    pytest.skip(reason)


def ensure_docker_available(
    *,
    binary_resolver: BinaryResolver = shutil.which,
    runner: CommandRunner = run_command,
) -> None:
    if binary_resolver("docker") is None:
        _docker_unavailable("docker is required for scope-enforcement integration test")

    try:
        daemon = runner(["docker", "info"], check=False, timeout=15)
    except subprocess.TimeoutExpired:
        _docker_unavailable("docker daemon availability check timed out")
    except OSError as exc:
        _docker_unavailable(f"docker is not executable: {exc}")
    if daemon.returncode != 0:
        reason = daemon.stderr.strip() or daemon.stdout.strip() or "unknown error"
        _docker_unavailable(f"docker daemon is not available: {reason}")


@contextmanager
def running_compose_project(
    *,
    project_name: str | None = None,
    runner: CommandRunner = run_command,
) -> Iterator[list[str]]:
    command_prefix = compose_command_prefix(project_name)
    primary_error: BaseException | None = None
    try:
        runner([*command_prefix, "up", "--build", "-d"], timeout=300)
        yield command_prefix
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            cleanup = runner(
                [
                    *command_prefix,
                    "down",
                    "--volumes",
                    "--remove-orphans",
                    "--rmi",
                    "local",
                ],
                check=False,
                timeout=120,
            )
            if cleanup.returncode != 0:
                raise subprocess.CalledProcessError(
                    cleanup.returncode,
                    cleanup.args,
                    output=cleanup.stdout,
                    stderr=cleanup.stderr,
                )
        except (OSError, subprocess.SubprocessError) as cleanup_error:
            if primary_error is None:
                raise
            primary_error.add_note(f"Compose cleanup also failed: {cleanup_error}")


def test_running_compose_project_cleans_up_after_failed_start() -> None:
    calls: list[tuple[list[str], bool, int]] = []

    def failing_runner(
        args: list[str],
        *,
        check: bool = True,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((args, check, timeout))
        if "up" in args:
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, "", "")

    with (
        pytest.raises(subprocess.CalledProcessError),
        running_compose_project(
            project_name="ravage-scope-lifecycle-test",
            runner=failing_runner,
        ),
    ):
        pytest.fail("a failed Compose start must not enter the test body")

    expected_prefix = compose_command_prefix("ravage-scope-lifecycle-test")
    assert calls == [
        ([*expected_prefix, "up", "--build", "-d"], True, 300),
        (
            [
                *expected_prefix,
                "down",
                "--volumes",
                "--remove-orphans",
                "--rmi",
                "local",
            ],
            False,
            120,
        ),
    ]


def test_compose_project_names_are_unique() -> None:
    first = compose_command_prefix()
    second = compose_command_prefix()

    assert first != second
    assert first[:3] == ["docker", "compose", "--project-name"]
    assert first[3].startswith("ravage-scope-")


def test_cleanup_failure_does_not_mask_startup_failure() -> None:
    startup_error = subprocess.CalledProcessError(17, ["docker", "compose", "up"])

    def doubly_failing_runner(
        args: list[str],
        *,
        check: bool = True,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        del check
        if "up" in args:
            raise startup_error
        raise subprocess.TimeoutExpired(args, timeout)

    with (
        pytest.raises(subprocess.CalledProcessError) as caught,
        running_compose_project(
            project_name="ravage-scope-cleanup-failure-test",
            runner=doubly_failing_runner,
        ),
    ):
        pytest.fail("a failed Compose start must not enter the test body")

    assert caught.value is startup_error
    assert any("Compose cleanup also failed" in note for note in startup_error.__notes__)


def test_docker_preflight_skips_missing_binary_outside_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(REQUIRE_DOCKER_ENV, raising=False)

    with pytest.raises(pytest.skip.Exception, match="docker is required"):
        ensure_docker_available(binary_resolver=lambda _name: None)


def test_docker_preflight_fails_missing_binary_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(REQUIRE_DOCKER_ENV, "1")

    with pytest.raises(pytest.fail.Exception, match="docker is required"):
        ensure_docker_available(binary_resolver=lambda _name: None)


def test_docker_preflight_fails_unavailable_daemon_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(REQUIRE_DOCKER_ENV, "1")

    def unavailable_daemon(
        args: list[str],
        *,
        check: bool = True,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        del check, timeout
        return subprocess.CompletedProcess(args, 1, "", "daemon unavailable")

    with pytest.raises(pytest.fail.Exception, match="daemon unavailable"):
        ensure_docker_available(
            binary_resolver=lambda _name: "/usr/bin/docker",
            runner=unavailable_daemon,
        )


def test_docker_preflight_fails_daemon_timeout_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(REQUIRE_DOCKER_ENV, "1")

    def timed_out_daemon(
        args: list[str],
        *,
        check: bool = True,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        del check
        raise subprocess.TimeoutExpired(args, timeout)

    with pytest.raises(pytest.fail.Exception, match="availability check timed out"):
        ensure_docker_available(
            binary_resolver=lambda _name: "/usr/bin/docker",
            runner=timed_out_daemon,
        )


@pytest.mark.integration
def test_scope_firewall_blocks_explicitly_excluded_destination() -> None:
    ensure_docker_available()

    with running_compose_project() as compose:
        resolved = run_command(
            [
                *compose,
                "exec",
                "-T",
                "kali",
                "getent",
                "hosts",
                "target",
            ]
        ).stdout.split()
        target_ip = resolved[0]
        decoy_ip = run_command(
            [*compose, "exec", "-T", "kali", "getent", "hosts", "decoy"]
        ).stdout.split()[0]
        unspecified_ip = run_command(
            [*compose, "exec", "-T", "kali", "getent", "hosts", "unspecified"]
        ).stdout.split()[0]

        target_before_firewall = run_command(
            [
                *compose,
                "exec",
                "-T",
                "kali",
                "curl",
                "-fsS",
                "--max-time",
                "5",
                f"http://{target_ip}/",
            ],
            check=False,
        )
        decoy_before_firewall = run_command(
            [
                *compose,
                "exec",
                "-T",
                "kali",
                "curl",
                "-fsS",
                "--max-time",
                "5",
                f"http://{decoy_ip}/",
            ],
            check=False,
        )
        unspecified_before_firewall = run_command(
            [
                *compose,
                "exec",
                "-T",
                "kali",
                "curl",
                "-fsS",
                "--max-time",
                "5",
                f"http://{unspecified_ip}/",
            ],
            check=False,
        )

        assert target_before_firewall.returncode == 0, target_before_firewall.stderr
        assert decoy_before_firewall.returncode == 0, decoy_before_firewall.stderr
        assert unspecified_before_firewall.returncode == 0, unspecified_before_firewall.stderr

        firewall = ScopeFirewall.from_scope(
            Scope(
                in_scope=[f"http://{target_ip}:80", f"http://{decoy_ip}:80"],
                out_of_scope=[f"http://{decoy_ip}:80"],
            )
        )
        assert firewall.allows(f"http://{target_ip}/")
        assert not firewall.allows(f"http://{decoy_ip}/")
        assert not firewall.allows(f"http://{unspecified_ip}/")

        rules = "\n".join(firewall.script_lines) + "\n"
        run_command([*compose, "exec", "-T", "kali", "sh", "-lc", rules])

        in_scope = run_command(
            [
                *compose,
                "exec",
                "-T",
                "kali",
                "curl",
                "-fsS",
                "--max-time",
                "5",
                f"http://{target_ip}/",
            ],
            check=False,
        )
        out_of_scope = run_command(
            [
                *compose,
                "exec",
                "-T",
                "kali",
                "curl",
                "-fsS",
                "--max-time",
                "5",
                f"http://{decoy_ip}/",
            ],
            check=False,
        )
        unspecified = run_command(
            [
                *compose,
                "exec",
                "-T",
                "kali",
                "curl",
                "-fsS",
                "--max-time",
                "5",
                f"http://{unspecified_ip}/",
            ],
            check=False,
        )

        assert in_scope.returncode == 0, in_scope.stderr
        assert out_of_scope.returncode != 0
        assert unspecified.returncode != 0
