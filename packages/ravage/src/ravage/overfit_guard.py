from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

_TEXT_SUFFIXES = {
    ".cfg",
    ".csv",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".py",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
_BENCHMARK_ID_RE = re.compile(r"\bXBEN-\d+(?:-\d+)?\b")
_FLAG_RE = re.compile(r"\b[A-Za-z0-9_-]*flag\{[^}\n]{3,256}\}", re.IGNORECASE)
_GENERATED_FLAG_RE = re.compile(
    r"\b[A-Za-z0-9_-]*flag\{\{[A-Za-z0-9_-]*\{secrets\.token_hex\([1-9]\d*\)\}\}\}",
    re.IGNORECASE,
)
_BENCHMARK_REPO_RE = re.compile(r"\bxbow-validation(?:-benchmarks)?\b", re.IGNORECASE)
_CHALLENGE_FILE_RE = re.compile(r"(?<![A-Za-z0-9_.-])secret\.txt(?![A-Za-z0-9_.-])")

_ALLOWED_FLAG_BODIES = {
    "...",
    "redacted",
    "probe",
    "test",
}

_FORBIDDEN_LITERALS = (
    "/starttime",
    "10032",
    "not_that_easy",
    "/amortization",
    "image_profile",
    "not_implemented.html",
    "register/step",
    "/password/test",
    "/api/change_password.php",
    "/orders_archive",
)

_COMPETITOR_NAMES = (
    "KeygraphHQ/shannon",
    "Keygraph",
)

_RAVAGE_PACKAGE_MARKER = ("packages", "ravage", "src", "ravage")

# These trees legitimately describe benchmark provenance and identity.  Only
# metadata rules are relaxed here: proof material and execution-boundary
# shortcuts remain guarded even when they appear in benchmark orchestration.
_BENCHMARK_METADATA_SUBTREES: set[tuple[str, ...]] = {
    ("authbench",),
    ("xben_parts",),
    ("xben_setup_parts",),
}

_BENCHMARK_METADATA_RULES = {
    "benchmark_id",
    "benchmark_repo",
    "competitor_name",
}

_EXEMPT_PACKAGE_FILES: set[tuple[str, ...]] = {
    ("overfit_guard.py",),
}

_RULE_EXEMPT_PACKAGE_FILES: dict[tuple[str, ...], frozenset[str]] = {
    ("probes", "file_read", "payloads.py"): frozenset({"challenge_file"}),
}

_NON_PRODUCTION_DIRECTORY_NAMES = {
    "__pycache__",
    "fixtures",
    "tests",
}


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    rule: str
    match: str
    source: str

    def render(self, *, repo_root: Path | None = None) -> str:
        display = self.path
        if repo_root is not None:
            try:
                display = self.path.relative_to(repo_root)
            except ValueError:
                display = self.path
        return f"{display}:{self.line}: [{self.rule}] {self.match} -- {self.source.strip()}"


def default_scan_roots(repo_root: Path) -> tuple[Path, ...]:
    return (repo_root.joinpath(*_RAVAGE_PACKAGE_MARKER),)


def scan_paths(paths: Sequence[Path]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        if not path.exists():
            violations.append(
                Violation(
                    path=path,
                    line=0,
                    rule="missing_scan_path",
                    match="missing",
                    source="configured scan path does not exist",
                )
            )
            continue
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if is_scannable(child):
                    violations.extend(_scan_file(child))
        elif is_scannable(path):
            violations.extend(_scan_file(path))
    return violations


def scan_text(path: Path, text: str) -> list[Violation]:
    violations: list[Violation] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        violations.extend(_scan_line(path, line_no, line))
    return violations


def is_scannable(path: Path) -> bool:
    package_relative = _package_relative_parts(path)
    if package_relative is not None:
        if package_relative in _EXEMPT_PACKAGE_FILES:
            return False
    elif _NON_PRODUCTION_DIRECTORY_NAMES.intersection(path.parts):
        return False
    return path.suffix.lower() in _TEXT_SUFFIXES


def _package_relative_parts(path: Path) -> tuple[str, ...] | None:
    parts = path.parts
    marker_length = len(_RAVAGE_PACKAGE_MARKER)
    for index in range(len(parts) - marker_length, -1, -1):
        if tuple(parts[index : index + marker_length]) == _RAVAGE_PACKAGE_MARKER:
            return tuple(parts[index + marker_length :])
    return None


def _scan_file(path: Path) -> list[Violation]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="replace")
    return scan_text(path, text)


def _scan_line(path: Path, line_no: int, line: str) -> list[Violation]:
    violations: list[Violation] = []
    violations.extend(_regex_violations(path, line_no, line, "benchmark_id", _BENCHMARK_ID_RE))
    violations.extend(_flag_violations(path, line_no, line))
    violations.extend(
        _literal_violations(path, line_no, line, "forbidden_literal", _FORBIDDEN_LITERALS)
    )
    violations.extend(
        _literal_violations(path, line_no, line, "competitor_name", _COMPETITOR_NAMES)
    )
    violations.extend(_regex_violations(path, line_no, line, "benchmark_repo", _BENCHMARK_REPO_RE))
    violations.extend(_regex_violations(path, line_no, line, "challenge_file", _CHALLENGE_FILE_RE))
    return [violation for violation in violations if not _is_rule_exempt(path, violation.rule)]


def _is_rule_exempt(path: Path, rule: str) -> bool:
    package_relative = _package_relative_parts(path)
    if package_relative is not None and rule in _RULE_EXEMPT_PACKAGE_FILES.get(
        package_relative, set()
    ):
        return True
    if rule not in _BENCHMARK_METADATA_RULES:
        return False
    if package_relative is None:
        return False
    return any(
        package_relative[: len(subtree)] == subtree
        for subtree in _BENCHMARK_METADATA_SUBTREES
    )


def _regex_violations(
    path: Path,
    line_no: int,
    line: str,
    rule: str,
    pattern: re.Pattern[str],
) -> list[Violation]:
    return [
        Violation(path, line_no, rule, match.group(0), line) for match in pattern.finditer(line)
    ]


def _literal_violations(
    path: Path,
    line_no: int,
    line: str,
    rule: str,
    literals: Iterable[str],
) -> list[Violation]:
    alternatives = sorted({literal for literal in literals if literal}, key=len, reverse=True)
    if not alternatives:
        return []
    pattern = re.compile("|".join(re.escape(item) for item in alternatives), re.IGNORECASE)
    return [
        Violation(path, line_no, rule, match.group(0), line) for match in pattern.finditer(line)
    ]


def _flag_violations(path: Path, line_no: int, line: str) -> list[Violation]:
    violations: list[Violation] = []
    generated_spans = [match.span() for match in _GENERATED_FLAG_RE.finditer(line)]
    for match in _FLAG_RE.finditer(line):
        if any(start <= match.start() and match.end() <= end for start, end in generated_spans):
            continue
        candidate = match.group(0)
        body = candidate[candidate.find("{") + 1 : -1].strip().lower()
        if body in _ALLOWED_FLAG_BODIES or "redacted" in body:
            continue
        violations.append(Violation(path, line_no, "hardcoded_flag", candidate, line))
    return violations
