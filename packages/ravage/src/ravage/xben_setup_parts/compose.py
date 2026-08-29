from __future__ import annotations

from pathlib import Path

import yaml  # type: ignore[import-untyped]


def compose_build_contexts(compose_path: Path) -> tuple[tuple[Path, Path], ...]:
    raw = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = _compose_services(raw)
    if not isinstance(services, dict):
        return ()

    contexts: list[tuple[Path, Path]] = []
    for service in services.values():
        context = compose_service_build_context(service, compose_path.parent)
        if context is not None:
            contexts.append(context)
    return tuple(contexts)


def _compose_services(raw: object) -> object:
    if not isinstance(raw, dict):
        return {}
    return raw.get("services", {})


def compose_service_build_context(
    service: object,
    compose_root: Path,
) -> tuple[Path, Path] | None:
    if not isinstance(service, dict):
        return None

    build = service.get("build")
    if isinstance(build, str):
        return _string_build_context(build, compose_root)
    if isinstance(build, dict):
        return _mapping_build_context(build, compose_root)
    return None


def _string_build_context(build: str, compose_root: Path) -> tuple[Path, Path]:
    context_path = (compose_root / build).resolve()
    return context_path, context_path / "Dockerfile"


def _mapping_build_context(
    build: dict[object, object],
    compose_root: Path,
) -> tuple[Path, Path]:
    raw_context = build.get("context", ".")
    context_path = (compose_root / str(raw_context)).resolve()
    dockerfile_path = _dockerfile_path(build, context_path)
    return context_path, dockerfile_path.resolve()


def _dockerfile_path(build: dict[object, object], context_path: Path) -> Path:
    dockerfile_name = str(build.get("dockerfile", "Dockerfile"))
    dockerfile_path = Path(dockerfile_name)
    if dockerfile_path.is_absolute():
        return dockerfile_path
    return context_path / dockerfile_path
