from __future__ import annotations

import json
import shlex
from collections.abc import Sequence
from pathlib import Path

from ravage.xben_setup_parts.paths import relative_path

DOCKER_COPY_INSTRUCTION_PREFIXES = ("COPY ", "ADD ")
DOCKER_COPY_INSTRUCTION_PARTS_MIN = 3
DOCKER_COPY_SOURCE_PARTS_MIN = 2
DOCKER_INSTRUCTION_SPLIT_PARTS = 2
REMOTE_DOCKER_COPY_SOURCE_PREFIXES = ("http://", "https://", "git://")


def dockerfile_copy_source_issues(
    context_path: Path,
    dockerfile_path: Path,
) -> tuple[str, ...]:
    issues: list[str] = []
    for instruction in dockerfile_copy_instructions(dockerfile_path):
        for source in dockerfile_local_copy_sources(instruction):
            if docker_copy_source_exists(context_path, source):
                continue
            context_name = relative_path(context_path.parent, context_path)
            issues.append(f"missing COPY source in {context_name}: {source}")
    return tuple(issues)


def dockerfile_copy_instructions(dockerfile_path: Path) -> tuple[str, ...]:
    instructions: list[str] = []
    pending = ""
    lines = dockerfile_path.read_text(encoding="utf-8").splitlines()

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        pending = append_dockerfile_instruction_line(pending, line)
        if pending.endswith("\\"):
            pending = pending[:-1].strip()
            continue

        if is_copy_instruction(pending):
            instructions.append(pending)
        pending = ""

    return tuple(instructions)


def append_dockerfile_instruction_line(pending: str, line: str) -> str:
    if pending:
        return f"{pending} {line}"
    return line


def is_copy_instruction(instruction: str) -> bool:
    upper = instruction.upper()
    for prefix in DOCKER_COPY_INSTRUCTION_PREFIXES:
        if upper.startswith(prefix):
            return True
    return False


def dockerfile_local_copy_sources(instruction: str) -> tuple[str, ...]:
    parts = dockerfile_copy_parts(instruction)
    if len(parts) < DOCKER_COPY_INSTRUCTION_PARTS_MIN:
        return ()

    args = parts[1:]
    if dockerfile_copy_uses_stage(args):
        return ()

    sources = dockerfile_copy_positional_args(args)
    if len(sources) < DOCKER_COPY_SOURCE_PARTS_MIN:
        return ()

    return local_copy_sources_before_destination(sources)


def dockerfile_copy_parts(instruction: str) -> list[str]:
    keyword, raw_args = dockerfile_instruction_args(instruction)
    if raw_args.startswith("["):
        return dockerfile_json_copy_parts(keyword=keyword, raw_args=raw_args)
    return shell_copy_parts(instruction)


def dockerfile_instruction_args(instruction: str) -> tuple[str, str]:
    pieces = instruction.strip().split(maxsplit=1)
    if len(pieces) != DOCKER_INSTRUCTION_SPLIT_PARTS:
        return instruction.strip(), ""
    return pieces[0], pieces[1].strip()


def dockerfile_json_copy_parts(*, keyword: str, raw_args: str) -> list[str]:
    json_args = dockerfile_json_copy_args(raw_args)
    parts = [keyword]
    parts.extend(json_args)
    return parts


def dockerfile_json_copy_args(raw_args: str) -> list[str]:
    try:
        parsed = json.loads(raw_args)
    except json.JSONDecodeError:
        return []

    if not isinstance(parsed, list):
        return []

    args: list[str] = []
    for item in parsed:
        args.append(str(item))
    return args


def shell_copy_parts(instruction: str) -> list[str]:
    try:
        return shlex.split(instruction)
    except ValueError:
        return instruction.split()


def dockerfile_copy_uses_stage(args: Sequence[str]) -> bool:
    for arg in args:
        if arg == "--from":
            return True
        if arg.startswith("--from="):
            return True
    return False


def dockerfile_copy_positional_args(args: Sequence[str]) -> tuple[str, ...]:
    positional: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("--"):
            skip_next = "=" not in arg
            continue
        positional.append(arg)
    return tuple(positional)


def local_copy_sources_before_destination(sources: Sequence[str]) -> tuple[str, ...]:
    local_sources: list[str] = []
    for source in sources[:-1]:
        if is_local_docker_copy_source(source):
            local_sources.append(source)
    return tuple(local_sources)


def is_local_docker_copy_source(source: str) -> bool:
    lowered = source.lower()
    for prefix in REMOTE_DOCKER_COPY_SOURCE_PREFIXES:
        if lowered.startswith(prefix):
            return False
    return True


def docker_copy_source_exists(context_path: Path, source: str) -> bool:
    normalized = source.lstrip("/")
    if has_glob_pattern(normalized):
        return glob_source_exists(context_path, normalized)
    return (context_path / normalized).exists()


def has_glob_pattern(value: str) -> bool:
    for char in "*?[":
        if char in value:
            return True
    return False


def glob_source_exists(context_path: Path, pattern: str) -> bool:
    for _path in context_path.glob(pattern):
        return True
    return False
