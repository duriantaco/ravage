from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ravage.agent_knowledge import describe_knowledge_pack
from ravage.cli_ui import banner

CODE_BUG_SKILLS_ENV = "RAVAGE_CODE_BUG_SKILLS"
DEFAULT_CODE_BUG_CARD_LIMIT = 4
DEFAULT_CODE_BUG_MAX_CHARS = 6_000

CodeBugCommand = Literal["help", "attack", "xben"]


@dataclass(frozen=True)
class CodeBugInvocation:
    command: CodeBugCommand
    args: tuple[str, ...] = ()
    help_text: str = ""


def build_code_bug_invocation(args: list[str]) -> CodeBugInvocation:
    if not args or any(arg in {"-h", "--help"} for arg in args):
        return CodeBugInvocation(command="help", help_text=code_bug_help_text())
    command = args[0]
    if command == "attack":
        return CodeBugInvocation(
            command="attack", args=_forwarded_args("ravage code-bug", args[1:])
        )
    if command in {"xben", "benchmark"}:
        return CodeBugInvocation(
            command="xben",
            args=_forwarded_args("ravage code-bug xben", args[1:]),
        )
    return CodeBugInvocation(command="attack", args=_forwarded_args("ravage code-bug", args))


def code_bug_help_text() -> str:
    return "\n".join(
        [
            banner("CODE-BUG", "Agent Skills-guided web bug workflow"),
            "",
            "Usage:",
            "  ravage code-bug BRIEF.yaml --skills /path/to/skills [attack options]",
            "  ravage code-bug BRIEF.yaml --skills builtin [attack options]",
            "  ravage code-bug BRIEF.yaml --skills PATH --skills-sha256 DIGEST",
            "  ravage code-bug attack BRIEF.yaml --skills /path/to/skills [attack options]",
            "  ravage code-bug xben --skills /path/to/skills [selection/options]",
            "",
            "The skills path may be a SKILL.md file, one skill directory, or a",
            "skills/ directory containing */SKILL.md. You can also set",
            f"{CODE_BUG_SKILLS_ENV}=/path/to/skills.",
            "Use --card-limit N and --max-card-chars N to bound complete selected cards;",
            "use --skills-sha256 DIGEST to pin an archived pack exactly.",
            "",
            "Benchmark A/B:",
            "  ravage xben ...",
            "  ravage code-bug xben --skills /path/to/skills ...",
        ]
    )


def _forwarded_args(prog: str, args: list[str]) -> tuple[str, ...]:
    parsed, remaining = _parse_code_bug_options(prog, args)
    return (
        *remaining,
        "--knowledge-pack",
        str(parsed.skills),
        "--knowledge-pack-sha256",
        str(parsed.skills_sha256),
        "--knowledge-pack-limit",
        str(parsed.card_limit),
        "--knowledge-pack-max-chars",
        str(parsed.max_card_chars),
    )


def _parse_code_bug_options(
    prog: str,
    args: list[str],
) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(prog=prog, add_help=False)
    parser.add_argument("--skills", "--skill-pack", "--pack", dest="skills", type=Path)
    parser.add_argument("--skills-sha256")
    parser.add_argument(
        "--card-limit",
        type=int,
        default=DEFAULT_CODE_BUG_CARD_LIMIT,
    )
    parser.add_argument(
        "--max-card-chars",
        type=int,
        default=DEFAULT_CODE_BUG_MAX_CHARS,
    )
    parsed, remaining = parser.parse_known_args(args)
    parsed.skills, parsed.skills_sha256 = _resolve_code_bug_skills(
        parser,
        parsed.skills,
        expected_sha256=parsed.skills_sha256,
    )
    if parsed.card_limit < 1:
        parser.error("--card-limit must be >= 1")
    if parsed.max_card_chars < 1:
        parser.error("--max-card-chars must be >= 1")
    return parsed, remaining


def _resolve_code_bug_skills(
    parser: argparse.ArgumentParser,
    skills_path: Path | None,
    *,
    expected_sha256: str | None,
) -> tuple[Path, str]:
    raw_path = skills_path or os.environ.get(CODE_BUG_SKILLS_ENV)
    if raw_path is None:
        parser.error(f"ravage code-bug requires --skills PATH or {CODE_BUG_SKILLS_ENV}=PATH")
    path = Path(raw_path).expanduser()
    try:
        metadata = describe_knowledge_pack(path, expected_sha256=expected_sha256)
    except (FileNotFoundError, OSError, ValueError) as exc:
        parser.error(str(exc))
    if metadata is None:
        parser.error("knowledge pack metadata is unavailable")
    return path, metadata.sha256
