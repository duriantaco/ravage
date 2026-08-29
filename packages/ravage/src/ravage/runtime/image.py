# First-run image provisioning is intentionally visible in the operator terminal.
# ruff: noqa: T201

from __future__ import annotations

import json
import shutil
import subprocess

from .types import DEFAULT_PUBLISHED_TOOL_IMAGE, DEFAULT_TOOL_IMAGE

_IMAGE_ID_FORMAT = "{{.Id}}"
_REPO_DIGESTS_FORMAT = "{{json .RepoDigests}}"
_PUBLISHED_TOOL_IMAGE_REPOSITORY = DEFAULT_PUBLISHED_TOOL_IMAGE.rsplit(":", 1)[0]
# Cosign v3.0.6 multi-architecture index; keep the verifier content-addressed.
_COSIGN_VERIFIER_IMAGE = (
    "ghcr.io/sigstore/cosign/cosign@"
    "sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"
)
_CERTIFICATE_IDENTITY_REGEXP = (
    r"^https://github\.com/duriantaco/ravage/\.github/workflows/"
    r"publish-kali-image\.yml@refs/(heads/main|tags/v[^/]+)$"
)
_CERTIFICATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_DOCKER_PREFLIGHT_TIMEOUT_SECONDS = 30


class ToolImageError(RuntimeError):
    """Raised when Ravage cannot provision or verify a Docker tool image."""


def ensure_tool_image(image: str, *, docker: str | None = None) -> None:
    """Ensure a requested tool image is local before scoped Docker startup."""
    if image == DEFAULT_TOOL_IMAGE:
        ensure_default_tool_image(docker=docker)
        return
    if image.startswith("sha256:"):
        return

    docker_command = docker or shutil.which("docker") or "docker"
    _require_docker_daemon(docker_command)
    if _image_id(docker_command, image):
        return
    print("RAVAGE // TOOL IMAGE", flush=True)
    print(f"pull      {image}", flush=True)
    pull = _run_visible((docker_command, "pull", image))
    if pull.returncode != 0 or not _image_id(docker_command, image):
        _require_docker_daemon(docker_command)
        message = f"could not pull requested Docker tool image {image}"
        raise ToolImageError(message)
    print(f"ready     {image}", flush=True)


def ensure_default_tool_image(*, docker: str | None = None) -> None:
    """Verify the default alias, pulling and tagging the published image if absent."""
    docker_command = docker or shutil.which("docker") or "docker"
    _require_docker_daemon(docker_command)
    if _image_id(docker_command, DEFAULT_TOOL_IMAGE):
        digest_reference = _published_digest_reference(
            docker_command,
            DEFAULT_TOOL_IMAGE,
        )
        if digest_reference:
            verify_published_tool_image(
                docker=docker_command,
                reference=digest_reference,
            )
        else:
            print(
                f"tool image {DEFAULT_TOOL_IMAGE} is a local unsigned build fallback",
                flush=True,
            )
        return

    print("RAVAGE // TOOL IMAGE", flush=True)
    print(f"pull      {DEFAULT_PUBLISHED_TOOL_IMAGE}", flush=True)
    pull = _run_visible((docker_command, "pull", DEFAULT_PUBLISHED_TOOL_IMAGE))
    if pull.returncode != 0:
        _require_docker_daemon(docker_command)
        message = (
            f"could not pull {DEFAULT_PUBLISHED_TOOL_IMAGE}. Run "
            "`ravage tools install --method docker --execute --no-cache` "
            "to explicitly use the local unsigned build fallback."
        )
        raise ToolImageError(message)

    source_id = _image_id(docker_command, DEFAULT_PUBLISHED_TOOL_IMAGE)
    if not source_id:
        _require_docker_daemon(docker_command)
        message = (
            f"Docker pulled {DEFAULT_PUBLISHED_TOOL_IMAGE} but it could not be inspected"
        )
        raise ToolImageError(message)
    digest_reference = _published_digest_reference(
        docker_command,
        DEFAULT_PUBLISHED_TOOL_IMAGE,
    )
    if not digest_reference:
        message = "Docker did not report an immutable digest for the published tool image"
        raise ToolImageError(message)
    verify_published_tool_image(
        docker=docker_command,
        reference=digest_reference,
    )

    tag = _run_visible(
        (docker_command, "tag", DEFAULT_PUBLISHED_TOOL_IMAGE, DEFAULT_TOOL_IMAGE)
    )
    if tag.returncode != 0:
        message = (
            f"could not tag {DEFAULT_PUBLISHED_TOOL_IMAGE} as {DEFAULT_TOOL_IMAGE}"
        )
        raise ToolImageError(message)
    if _image_id(docker_command, DEFAULT_TOOL_IMAGE) != source_id:
        message = "Docker tool image alias does not match the pulled image"
        raise ToolImageError(message)
    print(f"ready     {DEFAULT_TOOL_IMAGE}", flush=True)


def verify_published_tool_image(
    *,
    docker: str,
    reference: str | None = None,
) -> str:
    """Verify the published image digest against Ravage's GitHub Actions identity."""
    digest_reference = reference or _published_digest_reference(
        docker,
        DEFAULT_PUBLISHED_TOOL_IMAGE,
    )
    if not digest_reference:
        message = "Docker did not report an immutable digest for signature verification"
        raise ToolImageError(message)

    print(f"verify    {digest_reference}", flush=True)
    verification = _run_captured(
        (
            docker,
            "run",
            "--rm",
            "--pull=missing",
            _COSIGN_VERIFIER_IMAGE,
            "verify",
            "--certificate-identity-regexp",
            _CERTIFICATE_IDENTITY_REGEXP,
            "--certificate-oidc-issuer",
            _CERTIFICATE_OIDC_ISSUER,
            digest_reference,
        )
    )
    if verification.returncode != 0:
        message = f"signature verification failed for {digest_reference}"
        raise ToolImageError(message)
    print("verified  GitHub Actions publisher identity", flush=True)
    return digest_reference


def _image_id(docker: str, image: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603
            (docker, "image", "inspect", image, "--format", _IMAGE_ID_FORMAT),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def _published_digest_reference(docker: str, image: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603
            (docker, "image", "inspect", image, "--format", _REPO_DIGESTS_FORMAT),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    try:
        repo_digests = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        return ""
    prefix = f"{_PUBLISHED_TOOL_IMAGE_REPOSITORY}@sha256:"
    if not isinstance(repo_digests, list):
        return ""
    return next(
        (
            str(reference)
            for reference in repo_digests
            if str(reference).startswith(prefix)
        ),
        "",
    )


def _require_docker_daemon(docker: str) -> None:
    argv = (docker, "info", "--format", "{{.ServerVersion}}")
    try:
        completed = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=_DOCKER_PREFLIGHT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        message = "Docker command was not found. Install Docker, then retry."
        raise ToolImageError(message) from exc
    except subprocess.TimeoutExpired as exc:
        message = (
            "Docker daemon preflight timed out after 30 seconds. Restart Docker, "
            "wait for `docker version` to show a Server section, then retry."
        )
        raise ToolImageError(message) from exc
    except OSError as exc:
        message = f"Docker daemon preflight failed: {exc}"
        raise ToolImageError(message) from exc
    output = "\n".join(
        part for part in (completed.stdout, completed.stderr) if part
    ).lower()
    unavailable = completed.returncode != 0 or any(
        marker in output
        for marker in (
            "cannot connect",
            "permission denied",
            "daemon is not running",
            "error during connect",
        )
    )
    if not unavailable:
        return
    message = (
        "Docker daemon is not reachable. Start Docker Desktop or the Docker daemon, "
        "wait for `docker version` to show a Server section, then retry. A local "
        "image build cannot run until Docker is available."
    )
    raise ToolImageError(message)


def _run_visible(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, check=False, text=True)  # noqa: S603
    except OSError as exc:
        message = f"could not run {' '.join(argv)}: {exc}"
        raise ToolImageError(message) from exc


def _run_captured(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603
            argv,
            check=False,
            text=True,
            capture_output=True,
        )
    except OSError as exc:
        message = f"could not run {' '.join(argv)}: {exc}"
        raise ToolImageError(message) from exc
