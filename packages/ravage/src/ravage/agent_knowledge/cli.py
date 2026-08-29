from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ravage.agent_knowledge.mappings import mapped_probes
from ravage.agent_knowledge.skill_pack import load_skill_pack


def handle_skills_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="ravage skills",
        description="Inspect and validate opt-in Ravage knowledge skill packs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("list", "validate"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "path",
            type=Path,
            nargs="?",
            default=Path("builtin"),
            help="SKILL.md, skill directory, pack directory, or builtin",
        )
    parsed = parser.parse_args(argv)
    try:
        pack = load_skill_pack(parsed.path)
    except (FileNotFoundError, OSError, ValueError) as exc:
        parser.error(str(exc))
    payload = {
        "valid": True,
        "metadata": pack.metadata.to_json(),
        "skills": [
            {
                "name": skill.name,
                "description": skill.description,
                "sha256": skill.sha256,
                "authority": "advisory",
                "mapped_probes": list(mapped_probes(skill.name)),
            }
            for skill in pack.skills
        ],
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


__all__ = ["handle_skills_command"]
