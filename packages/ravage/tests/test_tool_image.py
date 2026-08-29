from __future__ import annotations

import subprocess

import pytest
from ravage.runtime import image as tool_image

EXPECTED_INSPECTIONS = 2


def test_existing_local_default_image_is_allowed_as_explicit_unsigned_fallback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        stdout = "sha256:existing\n" if argv[-1] == "{{.Id}}" else "[]\n"
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(tool_image.subprocess, "run", fake_run)

    tool_image.ensure_default_tool_image(docker="docker")

    assert len(calls) == EXPECTED_INSPECTIONS + 1
    assert calls[0][:2] == ("docker", "info")
    assert all(call[:3] == ("docker", "image", "inspect") for call in calls[1:])
    assert "local unsigned build fallback" in capsys.readouterr().out


def test_existing_published_default_image_is_verified_by_digest(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []
    call_options: list[dict[str, object]] = []
    digest = "a" * 64

    def fake_run(
        argv: tuple[str, ...],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        call_options.append(options)
        if argv[:3] == ("docker", "image", "inspect"):
            stdout = (
                "sha256:existing\n"
                if argv[-1] == "{{.Id}}"
                else f'["ghcr.io/duriantaco/ravage-kali@sha256:{digest}"]\n'
            )
            return subprocess.CompletedProcess(argv, 0, stdout, "")
        return subprocess.CompletedProcess(
            argv,
            0,
            '[{"critical":{"identity":{"docker-reference":"raw-cosign-json"}}}]',
            "Verification for raw-cosign-diagnostic",
        )

    monkeypatch.setattr(tool_image.subprocess, "run", fake_run)

    tool_image.ensure_default_tool_image(docker="docker")

    verify = next(call for call in calls if call[:2] == ("docker", "run"))
    assert "--pull=missing" in verify
    assert "ghcr.io/sigstore/cosign/cosign@sha256:" in " ".join(verify)
    assert verify[-1] == f"ghcr.io/duriantaco/ravage-kali@sha256:{digest}"
    assert "--certificate-identity-regexp" in verify
    verify_options = call_options[calls.index(verify)]
    assert verify_options["capture_output"] is True
    output = capsys.readouterr().out
    assert "raw-cosign-json" not in output
    assert "raw-cosign-diagnostic" not in output
    assert "verified  GitHub Actions publisher identity" in output


def test_missing_default_tool_image_is_pulled_and_aliased(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []
    alias_inspections = 0
    digest = "b" * 64

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal alias_inspections
        calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            if argv[-1] == "{{json .RepoDigests}}":
                stdout = f'["ghcr.io/duriantaco/ravage-kali@sha256:{digest}"]\n'
                return subprocess.CompletedProcess(argv, 0, stdout, "")
            if argv[3] == "ravage-kali:latest":
                alias_inspections += 1
                if alias_inspections == 1:
                    return subprocess.CompletedProcess(argv, 1, "", "not found")
            return subprocess.CompletedProcess(argv, 0, "sha256:published\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(tool_image.subprocess, "run", fake_run)

    tool_image.ensure_default_tool_image(docker="docker")

    assert ("docker", "pull", "ghcr.io/duriantaco/ravage-kali:latest") in calls
    assert (
        "docker",
        "tag",
        "ghcr.io/duriantaco/ravage-kali:latest",
        "ravage-kali:latest",
    ) in calls
    verify = next(call for call in calls if call[:2] == ("docker", "run"))
    assert verify[-1] == f"ghcr.io/duriantaco/ravage-kali@sha256:{digest}"
    output = capsys.readouterr().out
    assert "RAVAGE // TOOL IMAGE" in output
    assert "verified  GitHub Actions publisher identity" in output
    assert "ready     ravage-kali:latest" in output


def test_failed_first_run_pull_points_to_local_build_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        returncode = 1 if argv[1] in {"image", "pull"} else 0
        return subprocess.CompletedProcess(argv, returncode, "", "")

    monkeypatch.setattr(tool_image.subprocess, "run", fake_run)

    with pytest.raises(tool_image.ToolImageError, match="--no-cache"):
        tool_image.ensure_default_tool_image(docker="docker")


def test_unavailable_docker_daemon_is_not_reported_as_an_image_pull_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            return subprocess.CompletedProcess(
                argv,
                1,
                "",
                "Cannot connect to the Docker daemon",
            )
        if argv[:2] == ("docker", "info"):
            return subprocess.CompletedProcess(
                argv,
                1,
                "",
                "Cannot connect to the Docker daemon",
            )
        raise AssertionError(argv)

    monkeypatch.setattr(tool_image.subprocess, "run", fake_run)

    with pytest.raises(tool_image.ToolImageError) as exc_info:
        tool_image.ensure_default_tool_image(docker="docker")

    message = str(exc_info.value)
    assert "Docker daemon is not reachable" in message
    assert "docker version" in message
    assert "--no-cache" not in message
    assert not any(call[:2] == ("docker", "pull") for call in calls)
    assert calls == [("docker", "info", "--format", "{{.ServerVersion}}")]


def test_docker_daemon_preflight_timeout_is_actionable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ("docker", "info"):
            raise subprocess.TimeoutExpired(argv, 30)
        raise AssertionError(argv)

    monkeypatch.setattr(tool_image.subprocess, "run", fake_run)

    with pytest.raises(tool_image.ToolImageError) as exc_info:
        tool_image.ensure_default_tool_image(docker="docker")

    message = str(exc_info.value)
    assert "preflight timed out" in message
    assert "docker version" in message
    assert "--no-cache" not in message


def test_signature_failure_never_creates_default_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    digest = "c" * 64

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            if argv[-1] == "{{json .RepoDigests}}":
                stdout = f'["ghcr.io/duriantaco/ravage-kali@sha256:{digest}"]\n'
                return subprocess.CompletedProcess(argv, 0, stdout, "")
            if argv[3] == "ravage-kali:latest":
                return subprocess.CompletedProcess(argv, 1, "", "not found")
            return subprocess.CompletedProcess(argv, 0, "sha256:published\n", "")
        if argv[:2] == ("docker", "run"):
            return subprocess.CompletedProcess(argv, 1, "", "invalid signature")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(tool_image.subprocess, "run", fake_run)

    with pytest.raises(tool_image.ToolImageError, match="signature verification failed"):
        tool_image.ensure_default_tool_image(docker="docker")

    assert not any(call[:2] == ("docker", "tag") for call in calls)


def test_missing_custom_tool_image_is_pulled_explicitly_before_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    inspections = 0

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal inspections
        calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            inspections += 1
            return subprocess.CompletedProcess(
                argv,
                0 if inspections == EXPECTED_INSPECTIONS else 1,
                "sha256:custom\n" if inspections == EXPECTED_INSPECTIONS else "",
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(tool_image.subprocess, "run", fake_run)

    tool_image.ensure_tool_image("ghcr.io/example/custom-tools:1", docker="docker")

    assert ("docker", "pull", "ghcr.io/example/custom-tools:1") in calls
