from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
TOP_LEVEL_DOCS = (
    ROOT / "README.md",
    ROOT / "BENCHMARKS.md",
    ROOT / "CHANGELOG.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "RELEASING.md",
    ROOT / "SECURITY.md",
)
PUBLIC_INSTALL_DOCS = (
    ROOT / "README.md",
    ROOT / "docs" / "how-to-use.md",
    ROOT / "docs" / "index.md",
    ROOT / "docs" / "setup.md",
    ROOT / "packages" / "ravage" / "README.md",
)
MAINTAINED_TREES = (
    ROOT / "docs",
    ROOT / "examples",
    ROOT / "packages" / "ravage",
    ROOT / "packages" / "schemas",
)
IGNORED_PARTS = {
    ("docs", "archive"),
    ("docs", "xben-run-evidence"),
}
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REPO_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"((?:packages|tests|scripts|docs|examples)/[A-Za-z0-9_./-]+\.(?:py|md|sh|ya?ml|toml|json))"
    r"(?![A-Za-z0-9_./-])"
)
STALE_PATTERNS = (
    (re.compile(r"--observe(?:-port)?\b"), "removed inline observer flag"),
    (re.compile(r"--tool-recon\b"), "removed tool-recon flag"),
    (re.compile(r"(?<!examples/)labs/ravage-[a-z0-9-]+"), "stale lab path"),
    (re.compile(r"/Users/[^/]+/ravage"), "machine-specific checkout path"),
)
RAVAGE_INSTALL_SPEC_RE = re.compile(
    r"ravage(?:\[browser\])?(?:[<>=!~]{1,2}[A-Za-z0-9.*+!<>=~,-]+)?"
)


def main() -> int:
    errors = _missing_required_docs()
    expected_version = _ravage_version()
    for path in _maintained_markdown_files():
        text = path.read_text(encoding="utf-8")
        relative_path = path.relative_to(ROOT)
        for pattern, label in STALE_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"{relative_path}:{line}: {label}: {match.group(0)}")
        errors.extend(_broken_links(path, text))
        errors.extend(_missing_repo_paths(path, text))
        if path in PUBLIC_INSTALL_DOCS:
            errors.extend(_public_install_errors(path, text, expected_version))

    if errors:
        for error in errors:
            sys.stderr.write(f"docs check failed: {error}\n")
        return 1

    count = len(tuple(_maintained_markdown_files()))
    sys.stdout.write(f"docs check passed: {count} maintained Markdown files\n")
    return 0


def _ravage_version() -> str:
    project = tomllib.loads(
        (ROOT / "packages" / "ravage" / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    return str(project["version"])


def _missing_required_docs(
    paths: tuple[Path, ...] = TOP_LEVEL_DOCS,
    *,
    root: Path = ROOT,
) -> list[str]:
    errors: list[str] = []
    for path in paths:
        if path.is_file():
            continue
        try:
            display = path.relative_to(root)
        except ValueError:
            display = path
        errors.append(f"missing required document: {display}")
    return errors


def _public_install_errors(
    path: Path,
    text: str,
    expected_version: str,
    *,
    root: Path = ROOT,
) -> list[str]:
    errors: list[str] = []
    try:
        display = path.relative_to(root)
    except ValueError:
        display = path
    command_count = 0
    expected_specs = {
        f"ravage=={expected_version}",
        f"ravage[browser]=={expected_version}",
    }
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "python -m pip install" not in line or "ravage" not in line:
            continue
        if "packages/ravage" in line:
            continue
        command_count += 1
        command = line.split("python -m pip install", maxsplit=1)[1]
        command = command.split("</code>", maxsplit=1)[0]
        specs = RAVAGE_INSTALL_SPEC_RE.findall(command)
        errors.extend(
            f"{display}:{line_number}: public install spec "
            f"{spec!r} must use exact version {expected_version}"
            for spec in specs
            if spec not in expected_specs
        )
        if "x-release-please-version" not in line:
            errors.append(
                f"{display}:{line_number}: public install pin is missing the "
                "Release Please version marker"
            )
    if command_count == 0:
        errors.append(f"{display}: missing version-pinned public install command")
    return errors


def _maintained_markdown_files() -> tuple[Path, ...]:
    paths = {path for path in TOP_LEVEL_DOCS if path.exists()}
    for tree in MAINTAINED_TREES:
        for path in tree.rglob("*.md"):
            relative_parts = path.relative_to(ROOT).parts
            if any(relative_parts[: len(prefix)] == prefix for prefix in IGNORED_PARTS):
                continue
            paths.add(path)
    return tuple(sorted(paths))


def _broken_links(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    for match in LINK_RE.finditer(text):
        raw_target = match.group(1).strip().split(maxsplit=1)[0]
        target = raw_target.strip("<>")
        if not target or target.startswith(("#", "/", "mailto:")):
            continue
        if "://" in target or "{{" in target or "}}" in target:
            continue
        target = unquote(target.split("#", 1)[0].split("?", 1)[0])
        if not target:
            continue
        candidate = (path.parent / target).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError:
            line = text.count("\n", 0, match.start()) + 1
            errors.append(f"{path.relative_to(ROOT)}:{line}: link leaves repository: {raw_target}")
            continue
        if not candidate.exists():
            line = text.count("\n", 0, match.start()) + 1
            errors.append(f"{path.relative_to(ROOT)}:{line}: missing link target: {raw_target}")
    return errors


def _missing_repo_paths(path: Path, text: str, *, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    resolved_root = root.resolve()
    try:
        display_path = path.resolve().relative_to(resolved_root)
    except ValueError:
        display_path = path
    for match in REPO_PATH_RE.finditer(text):
        raw_target = match.group(1)
        candidate = (resolved_root / raw_target).resolve()
        try:
            candidate.relative_to(resolved_root)
        except ValueError:
            line = text.count("\n", 0, match.start()) + 1
            errors.append(
                f"{display_path}:{line}: repository path leaves root: {raw_target}"
            )
            continue
        if candidate.exists():
            continue
        line = text.count("\n", 0, match.start()) + 1
        errors.append(f"{display_path}:{line}: missing repository path: {raw_target}")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
