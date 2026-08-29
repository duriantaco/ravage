from __future__ import annotations

from pathlib import Path

from ravage.xben_setup_parts.compose import compose_build_contexts
from ravage.xben_setup_parts.dockerfile import dockerfile_copy_source_issues
from ravage.xben_setup_parts.paths import relative_path


def docker_build_context_issues(case_path: Path) -> tuple[str, ...]:
    compose_path = case_path / "docker-compose.yml"
    if not compose_path.is_file():
        return (f"missing compose file: {compose_path.name}",)

    issues: list[str] = []
    contexts = compose_build_contexts(compose_path)
    for context_path, dockerfile_path in contexts:
        context_issue = _build_context_issue(
            case_path=case_path,
            context_path=context_path,
            dockerfile_path=dockerfile_path,
        )
        if context_issue:
            issues.append(context_issue)
            continue
        issues.extend(dockerfile_copy_source_issues(context_path, dockerfile_path))
    return tuple(issues)


def _build_context_issue(
    *,
    case_path: Path,
    context_path: Path,
    dockerfile_path: Path,
) -> str:
    if not context_path.is_dir():
        path = relative_path(case_path, context_path)
        return f"missing build context: {path}"
    if not dockerfile_path.is_file():
        path = relative_path(case_path, dockerfile_path)
        return f"missing Dockerfile: {path}"
    return ""
