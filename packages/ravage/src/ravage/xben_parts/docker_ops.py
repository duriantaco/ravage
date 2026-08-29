from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request

from ravage.xben_parts.models import (
    COMPOSE_SERVICE_INDENT,
    COMPOSE_SERVICE_KEY_INDENT,
    DOCKER,
    FLAG_PATTERN,
    HTTP_SERVER_ERROR_MIN,
    LEGACY_APT_BASE_MARKERS,
    LEGACY_APT_COMPAT_MARKER,
    LEGACY_APT_COMPAT_SNIPPET,
    MYSQL_ARM_COMPAT_IMAGE,
    MYSQL_ARM_COMPAT_MARKER,
    MYSQL_ARM_COMPAT_PLATFORM_LINE,
    XbenCase,
    XbenSettings,
    urlopen,
)
from ravage.xben_parts.util import (
    _compose_published_ports,
    _docker_env,
    _first_published_port,
    _parse_published_port,
    _run_command,
)

COMPOSE_FILENAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)


class XbenEvidenceCaptureError(RuntimeError):
    """Raised when required referee evidence cannot be captured."""


def _compose_file_for_case(case_path: Path) -> Path | None:
    for name in COMPOSE_FILENAMES:
        candidate = case_path / name
        if candidate.exists():
            return candidate
    nested = _nested_compose_files(case_path)
    if nested:
        return nested[0]
    return None


def _nested_compose_files(case_path: Path) -> list[Path]:
    nested: list[Path] = []
    for name in COMPOSE_FILENAMES:
        for path in case_path.glob(f"*/{name}"):
            nested.append(path)
    nested.sort()
    return nested


def _required_compose_file_for_case(case_path: Path) -> Path:
    compose_file = _compose_file_for_case(case_path)
    if compose_file is None:
        message = f"no docker compose file found for benchmark case: {case_path}"
        raise RuntimeError(message)
    return compose_file


def _compose_cwd_for_case(case_path: Path) -> Path:
    return _required_compose_file_for_case(case_path).parent


def _build_case(
    *,
    settings: XbenSettings,
    case: XbenCase,
    project: str,
    flag: str,
) -> None:
    pre_patch_tree_sha256 = _source_tree_sha256(case.path)
    before_files = _source_file_hashes(case.path)
    patched_files = _patch_legacy_xben_dockerfiles(
        case.path,
        docker_platform=settings.docker_platform,
    )
    after_files = _source_file_hashes(case.path)
    _write_build_source_provenance(
        settings=settings,
        case=case,
        patched_files=patched_files,
        pre_patch_tree_sha256=pre_patch_tree_sha256,
        before_files=before_files,
        after_files=after_files,
    )
    compose_cwd = _compose_cwd_for_case(case.path)
    _run_command(
        [
            DOCKER,
            "compose",
            "-p",
            project,
            "build",
            "--build-arg",
            f"flag={flag}",
            "--build-arg",
            f"FLAG={flag}",
        ],
        cwd=compose_cwd,
        env=_docker_env(settings),
        timeout=settings.case_timeout_seconds,
    )


def _write_build_source_provenance(
    *,
    settings: XbenSettings,
    case: XbenCase,
    patched_files: int,
    pre_patch_tree_sha256: str,
    before_files: Mapping[str, str],
    after_files: Mapping[str, str],
) -> Path:
    path = settings.output_dir / case.benchmark_id / "benchmark-source.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "benchmark_id": case.benchmark_id,
        "source_path": str(case.path.resolve()),
        "docker_platform": settings.docker_platform,
        "compatibility_files_changed": patched_files,
        "pre_patch_tree_sha256": pre_patch_tree_sha256,
        "post_patch_tree_sha256": _source_tree_sha256(case.path),
        "changed_files": _changed_source_files(before_files, after_files),
        "compose_images": None,
    }
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


def _source_file_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts or not (path.is_file() or path.is_symlink()):
            continue
        hashes[relative.as_posix()] = _source_entry_sha256(path)
    return hashes


def _source_entry_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_symlink():
        digest.update(b"symlink\0")
        digest.update(path.readlink().as_posix().encode("utf-8"))
    else:
        digest.update(b"file\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _changed_source_files(
    before: Mapping[str, str],
    after: Mapping[str, str],
) -> list[dict[str, object]]:
    changes: list[dict[str, object]] = []
    for relative in sorted(set(before) | set(after)):
        before_sha = before.get(relative)
        after_sha = after.get(relative)
        if before_sha == after_sha:
            continue
        changes.append(
            {
                "path": relative,
                "change": (
                    "added" if before_sha is None else "deleted" if after_sha is None else "modified"
                ),
                "before_sha256": before_sha,
                "after_sha256": after_sha,
            }
        )
    return changes


def _record_compose_image_provenance(
    *,
    path: Path,
    settings: XbenSettings,
    compose_cwd: Path,
    project: str,
) -> None:
    completed = subprocess.run(  # noqa: S603 - fixed Docker inspection command.
        [
            DOCKER,
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.ID}}",
        ],
        cwd=compose_cwd,
        env=_docker_env(settings),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        _write_compose_image_error(path, completed.stderr or completed.stdout)
        msg = f"could not enumerate Docker project containers: {project}"
        raise XbenEvidenceCaptureError(msg)
    container_ids = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not container_ids:
        _write_compose_image_error(path, "no project containers found after compose up")
        msg = f"no Docker project containers found after compose up: {project}"
        raise XbenEvidenceCaptureError(msg)
    inspected = subprocess.run(  # noqa: S603 - fixed Docker inspection command.
        [DOCKER, "inspect", *container_ids],
        cwd=compose_cwd,
        env=_docker_env(settings),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if inspected.returncode != 0:
        _write_compose_image_error(path, inspected.stderr or inspected.stdout)
        msg = f"could not inspect Docker project containers: {project}"
        raise XbenEvidenceCaptureError(msg)
    try:
        raw_containers = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        _write_compose_image_error(path, str(exc))
        raise XbenEvidenceCaptureError("invalid Docker container inspect payload") from exc
    if not isinstance(raw_containers, list) or not raw_containers:
        _write_compose_image_error(path, "empty Docker container inspect payload")
        msg = f"empty Docker container inspect payload: {project}"
        raise XbenEvidenceCaptureError(msg)
    containers = [_container_image_record(item) for item in raw_containers if isinstance(item, dict)]
    if len(containers) != len(container_ids) or any(not item["image_id"] for item in containers):
        _write_compose_image_error(path, "incomplete Docker container image identity")
        msg = f"incomplete Docker container image identity: {project}"
        raise XbenEvidenceCaptureError(msg)
    image_ids = sorted({str(item["image_id"]) for item in containers})
    image_inspect = subprocess.run(  # noqa: S603 - fixed Docker inspection command.
        [DOCKER, "image", "inspect", *image_ids],
        cwd=compose_cwd,
        env=_docker_env(settings),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if image_inspect.returncode != 0:
        _write_compose_image_error(path, image_inspect.stderr or image_inspect.stdout)
        msg = f"could not inspect Docker project images: {project}"
        raise XbenEvidenceCaptureError(msg)
    try:
        raw_images = json.loads(image_inspect.stdout)
    except json.JSONDecodeError as exc:
        _write_compose_image_error(path, str(exc))
        raise XbenEvidenceCaptureError("invalid Docker image inspect payload") from exc
    if not isinstance(raw_images, list) or len(raw_images) != len(image_ids):
        _write_compose_image_error(path, "incomplete Docker image inspect payload")
        msg = f"incomplete Docker image inspect payload: {project}"
        raise XbenEvidenceCaptureError(msg)
    images = [_image_identity_record(item) for item in raw_images if isinstance(item, dict)]
    if len(images) != len(image_ids):
        _write_compose_image_error(path, "malformed Docker image inspect payload")
        msg = f"malformed Docker image inspect payload: {project}"
        raise XbenEvidenceCaptureError(msg)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["compose_images"] = {
        "status": "captured",
        "project": project,
        "containers": containers,
        "images": images,
    }
    _write_json_atomic(path, payload)


def _container_image_record(raw: Mapping[str, object]) -> dict[str, object]:
    config = raw.get("Config")
    config_payload = config if isinstance(config, dict) else {}
    labels = config_payload.get("Labels")
    label_payload = labels if isinstance(labels, dict) else {}
    state = raw.get("State")
    state_payload = state if isinstance(state, dict) else {}
    return {
        "container_id": raw.get("Id"),
        "name": str(raw.get("Name") or "").lstrip("/"),
        "service": label_payload.get("com.docker.compose.service"),
        "configured_image": config_payload.get("Image"),
        "image_id": raw.get("Image"),
        "state": state_payload.get("Status"),
    }


def _image_identity_record(raw: Mapping[str, object]) -> dict[str, object]:
    root_fs = raw.get("RootFS")
    root_payload = root_fs if isinstance(root_fs, dict) else {}
    layers = root_payload.get("Layers")
    return {
        "id": raw.get("Id"),
        "repo_digests": raw.get("RepoDigests") or [],
        "created": raw.get("Created"),
        "architecture": raw.get("Architecture"),
        "os": raw.get("Os"),
        "size": raw.get("Size"),
        "rootfs_layers": layers if isinstance(layers, list) else [],
    }


def _write_compose_image_error(path: Path, error: object) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["compose_images"] = {"status": "error", "error": str(error).strip()}
    _write_json_atomic(path, payload)


def _write_json_atomic(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _source_tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts or not (path.is_file() or path.is_symlink()):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(path.readlink().as_posix().encode("utf-8"))
        else:
            digest.update(b"file\0")
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _patch_legacy_xben_dockerfiles(
    case_path: Path,
    *,
    docker_platform: str | None = None,
    force_mysql_arm_compat: bool = False,
) -> int:
    mysql_arm_compat = force_mysql_arm_compat or _needs_mysql_arm_compat(docker_platform)
    patched = 0
    for dockerfile in case_path.rglob("Dockerfile"):
        original = dockerfile.read_text(encoding="utf-8")
        updated = _legacy_xben_dockerfile_text(
            original,
            mysql_arm_compat=mysql_arm_compat,
        )
        if updated == original:
            continue
        dockerfile.write_text(updated, encoding="utf-8")
        patched += 1
    for compose_file in case_path.glob("docker-compose*.yml"):
        original = compose_file.read_text(encoding="utf-8")
        updated = _legacy_xben_compose_text(
            original,
            mysql_arm_compat=mysql_arm_compat,
        )
        if updated == original:
            continue
        compose_file.write_text(updated, encoding="utf-8")
        patched += 1
    patched += _patch_pymysql_cryptography_requirements(case_path)
    return patched


def _legacy_xben_dockerfile_text(text: str, *, mysql_arm_compat: bool = False) -> str:
    updated = (
        text.replace("FROM --platform=linux/amd64 mysql:5.7.15", "FROM mysql:5.7")
        .replace("FROM --platform=linux/amd64 mysql:5.7", "FROM mysql:5.7")
        .replace("FROM mysql:5.7.15", "FROM mysql:5.7")
        .replace("FROM node:14-alpine", "FROM node:18-alpine")
        .replace("FROM node:12-alpine", "FROM node:18-alpine")
    )
    updated = _declare_flag_args_before_use(updated)
    updated = _normalize_hardcoded_flag_env(updated)
    updated = _declare_flag_args_before_use(updated)
    if mysql_arm_compat:
        updated = updated.replace("FROM mysql:5.7", f"FROM {MYSQL_ARM_COMPAT_IMAGE}")
    if _needs_legacy_apt_patch(updated):
        updated = updated.replace(
            "\nRUN apt-get update",
            f"\n{LEGACY_APT_COMPAT_SNIPPET}\nRUN apt-get update",
            1,
        )
    return updated


def _declare_flag_args_before_use(text: str) -> str:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    seen_args: set[str] = set()
    changed = False
    for line in lines:
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            seen_args = set()
        arg_match = re.match(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)", line, flags=re.IGNORECASE)
        if arg_match is not None:
            seen_args.add(arg_match.group(1))
            output.append(line)
            continue
        missing: list[str] = []
        for name in ("FLAG", "flag"):
            if name in seen_args:
                continue
            if re.search(rf"\$(?:\{{{re.escape(name)}\}}|{re.escape(name)}\b)", line):
                missing.append(name)
        for name in missing:
            output.append(f"ARG {name}\n")
            seen_args.add(name)
            changed = True
        output.append(line)
    if changed:
        return "".join(output)
    return text


def _normalize_hardcoded_flag_env(text: str) -> str:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    changed = False
    flag_env_names = "FLAG|flag|CTF_FLAG|CHALLENGE_FLAG|APP_FLAG|SECRET_FLAG"
    for line in lines:
        match = re.match(
            rf"^(\s*ENV\s+)({flag_env_names})(\s*=\s*|\s+)([\"']?)([^\"'\s]+)([\"']?)([ \t]*)$",
            line.rstrip("\n"),
        )
        if match is None:
            output.append(line)
            continue
        value = match.group(5)
        if FLAG_PATTERN.fullmatch(value) is None:
            output.append(line)
            continue
        env_name = match.group(2)
        build_arg = _flag_build_arg_for_env(env_name)
        output.append(_dynamic_flag_env_line(match, build_arg))
        changed = True
    if changed:
        return "".join(output)
    return text


def _flag_build_arg_for_env(env_name: str) -> str:
    if env_name == "flag":
        return "flag"
    return "FLAG"


def _dynamic_flag_env_line(match: re.Match[str], build_arg: str) -> str:
    prefix = match.group(1)
    env_name = match.group(2)
    separator = match.group(3)
    suffix = match.group(7)
    return f"{prefix}{env_name}{separator}${build_arg}{suffix}\n"


def _needs_legacy_apt_patch(text: str) -> bool:
    if LEGACY_APT_COMPAT_MARKER in text:
        return False
    if "RUN apt-get update" not in text:
        return False
    return _has_legacy_apt_base_marker(text)


def _has_legacy_apt_base_marker(text: str) -> bool:
    for marker in LEGACY_APT_BASE_MARKERS:
        if marker in text:
            return True
    return False


def _patch_pymysql_cryptography_requirements(case_path: Path) -> int:
    patched = 0
    for requirements_path in case_path.rglob("requirements*.txt"):
        original = requirements_path.read_text(encoding="utf-8")
        lowered = original.lower()
        if "pymysql" not in lowered or "cryptography" in lowered:
            continue
        suffix = "\n"
        if original.endswith("\n"):
            suffix = ""
        requirements_path.write_text(f"{original}{suffix}cryptography\n", encoding="utf-8")
        patched += 1
    return patched


def _legacy_xben_compose_text(text: str, *, mysql_arm_compat: bool = False) -> str:
    updated = text.replace(f"    {MYSQL_ARM_COMPAT_MARKER}\n", "").replace(
        MYSQL_ARM_COMPAT_PLATFORM_LINE,
        "",
    )
    updated = _dedupe_duplicate_service_mapping_keys(updated)
    updated = _use_dynamic_host_ports(updated)
    if mysql_arm_compat:
        updated = updated.replace("image: mysql:5.7.15", f"image: {MYSQL_ARM_COMPAT_IMAGE}")
        updated = updated.replace("image: mysql:5.7", f"image: {MYSQL_ARM_COMPAT_IMAGE}")
    return updated


def _dedupe_duplicate_service_mapping_keys(text: str) -> str:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    in_services = False
    seen_service_keys: set[str] = set()
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        content = stripped.strip()
        if indent == 0:
            in_services = content.startswith("services:")
        elif (
            in_services
            and indent == COMPOSE_SERVICE_INDENT
            and _compose_mapping_key(stripped) is not None
        ):
            seen_service_keys = set()
        elif in_services and indent == COMPOSE_SERVICE_KEY_INDENT:
            key = _compose_mapping_key(stripped)
            if key is not None:
                if key in seen_service_keys:
                    index = _skip_yaml_block(lines, index, indent)
                    continue
                seen_service_keys.add(key)
        output.append(line)
        index += 1
    return "".join(output)


def _use_dynamic_host_ports(text: str) -> str:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    ports_indent: int | None = None
    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        content = stripped.strip()
        if ports_indent is not None and content and indent <= ports_indent:
            ports_indent = None
        if _compose_mapping_key(stripped) == "ports":
            ports_indent = indent
        output_line = line
        if ports_indent is not None and indent > ports_indent:
            output_line = _dynamic_host_port_line(line)
        output.append(output_line)
    return "".join(output)


def _dynamic_host_port_line(line: str) -> str:
    match = re.match(
        r"^(?P<prefix>\s*-\s*)(?P<quote>[\"']?)"
        r"(?:(?:127\.0\.0\.1|0\.0\.0\.0):)?\d+:"
        r"(?P<container>\d+(?:/(?:tcp|udp))?)(?P=quote)"
        r"(?P<suffix>\s*(?:#.*)?\n?)$",
        line,
        flags=re.IGNORECASE,
    )
    if match is None:
        return line
    quote = match.group("quote")
    return f"{match.group('prefix')}{quote}{match.group('container')}{quote}{match.group('suffix')}"


def _compose_mapping_key(stripped_line: str) -> str | None:
    if stripped_line.startswith("#"):
        return None
    match = re.match(r"^([A-Za-z0-9_.-]+):(?:\s|$)", stripped_line)
    if match is None:
        return None
    return match.group(1)


def _skip_yaml_block(lines: Sequence[str], start: int, indent: int) -> int:
    index = start + 1
    while index < len(lines):
        stripped = lines[index].lstrip()
        if stripped.strip():
            next_indent = len(lines[index]) - len(stripped)
            if next_indent <= indent:
                break
        index += 1
    return index


def _needs_mysql_arm_compat(docker_platform: str | None) -> bool:
    return docker_platform in {
        "linux/amd64",
        "linux/arm64",
        "linux/arm64/v8",
    } and platform.machine().lower() in {
        "arm64",
        "aarch64",
    }


def _up_case(*, settings: XbenSettings, case: XbenCase, project: str) -> None:
    compose_cwd = _compose_cwd_for_case(case.path)
    _run_command(
        [DOCKER, "compose", "-p", project, "up", "-d"],
        cwd=compose_cwd,
        env=_docker_env(settings),
        timeout=settings.case_timeout_seconds,
    )
    try:
        _record_compose_image_provenance(
            path=settings.output_dir / case.benchmark_id / "benchmark-source.json",
            settings=settings,
            compose_cwd=compose_cwd,
            project=project,
        )
    except XbenEvidenceCaptureError:
        raise
    except Exception as exc:  # noqa: BLE001 - all missing provenance is fatal.
        msg = f"could not capture Docker image provenance for {project}: {exc}"
        raise XbenEvidenceCaptureError(msg) from exc


def _restart_case_web_service(*, settings: XbenSettings, case: XbenCase, project: str) -> None:
    service = _published_web_service_for_case(case)
    compose_cwd = _compose_cwd_for_case(case.path)
    _run_command(
        [DOCKER, "compose", "-p", project, "restart", service],
        cwd=compose_cwd,
        env=_docker_env(settings),
        timeout=min(settings.case_timeout_seconds, 120),
    )


def _down_case(*, settings: XbenSettings, case: XbenCase, project: str) -> None:
    command = [DOCKER, "compose", "-p", project, "down", "--remove-orphans", "-v"]
    if settings.prune_case_images:
        command.extend(["--rmi", "local"])
    evidence_path = settings.output_dir / case.benchmark_id / "teardown.json"
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            cwd=_compose_cwd_for_case(case.path),
            env=_docker_env(settings),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        _write_json_atomic(
            evidence_path,
            {
                "status": "error",
                "project": project,
                "command": command,
                "prune_case_images": settings.prune_case_images,
                "error": str(exc),
            },
        )
        raise RuntimeError(f"Docker teardown failed for {project}: {exc}") from exc
    teardown_payload = {
        "status": "succeeded" if completed.returncode == 0 else "error",
        "project": project,
        "command": command,
        "prune_case_images": settings.prune_case_images,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
    _write_json_atomic(evidence_path, teardown_payload)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"Docker teardown failed for {project}: {detail}")


def _collect_docker_logs(
    *,
    settings: XbenSettings,
    case: XbenCase,
    project: str,
    path: Path,
) -> None:
    try:
        result = subprocess.run(  # noqa: S603
            [DOCKER, "compose", "-p", project, "logs", "--no-color"],
            cwd=_compose_cwd_for_case(case.path),
            env=_docker_env(settings),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        text = (result.stdout or "") + (result.stderr or "")
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        text = f"docker log collection failed: {exc}\n"
    path.write_text(text, encoding="utf-8")


def _wait_for_target(*, settings: XbenSettings, target_url: str) -> None:
    deadline = time.monotonic() + min(settings.case_timeout_seconds, 120)
    last_error = "target did not respond"
    request = Request(target_url, method="GET")  # noqa: S310
    while time.monotonic() < deadline:
        try:
            with urlopen(request, timeout=3) as response:
                response.read(1)
        except HTTPError as exc:
            if exc.code < HTTP_SERVER_ERROR_MIN:
                return
            last_error = f"HTTP {exc.code}"
            time.sleep(1)
        except (OSError, URLError) as exc:
            last_error = str(exc)
            time.sleep(1)
        else:
            return
    message = f"target did not become reachable at {target_url}: {last_error}"
    raise RuntimeError(message)


def _target_readiness_error_is_restartable(exc: Exception) -> bool:
    text = str(exc)
    return "target did not become reachable" in text and bool(re.search(r"HTTP 5\d\d\b", text))


def _target_url_for(*, settings: XbenSettings, case: XbenCase, project: str) -> str:
    if case.main_service and case.main_service_port:
        compose_cwd = _compose_cwd_for_case(case.path)
        result = _run_command(
            [
                DOCKER,
                "compose",
                "-p",
                project,
                "port",
                case.main_service,
                str(case.main_service_port),
            ],
            cwd=compose_cwd,
            env=_docker_env(settings),
            timeout=30,
        )
    else:
        compose_file = _required_compose_file_for_case(case.path)
        service, port = _first_published_port(compose_file)
        compose_cwd = compose_file.parent
        result = _run_command(
            [DOCKER, "compose", "-p", project, "port", service, str(port)],
            cwd=compose_cwd,
            env=_docker_env(settings),
            timeout=30,
        )
    published_port = _parse_published_port(result.stdout)
    return f"http://localhost:{published_port}"


def _published_web_service_for_case(case: XbenCase) -> str:
    if case.main_service:
        return case.main_service
    compose_file = _required_compose_file_for_case(case.path)
    service, _ = _first_published_port(compose_file)
    return service


def _published_ports_for_case(
    *,
    settings: XbenSettings,
    case: XbenCase,
    project: str,
) -> tuple[dict[str, object], ...]:
    published: list[dict[str, object]] = []
    compose_file = _required_compose_file_for_case(case.path)
    compose_ports = _compose_published_ports(compose_file)
    compose_cwd = compose_file.parent
    for service, container_port, protocol in compose_ports:
        result = _run_command(
            [DOCKER, "compose", "-p", project, "port", service, str(container_port)],
            cwd=compose_cwd,
            env=_docker_env(settings),
            timeout=30,
        )
        published.append(
            {
                "service": service,
                "container_port": container_port,
                "host": "localhost",
                "host_port": _parse_published_port(result.stdout),
                "protocol": protocol,
            }
        )
    return tuple(published)
