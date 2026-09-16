from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
AGENT_DIR = ROOT / ".claude" / "agents"
SKILL_DIR = ROOT / ".claude" / "skills"
ALLOWED_TOOLS = {"Read", "Glob", "Grep"}
FRONTMATTER_OPEN = "---\n"
MAX_AGENT_TURNS = 24
SOURCE_SKILL_PREFIX = "ravage-source-"
ALLOWED_KEYS = {
    "name",
    "description",
    "tools",
    "model",
    "permissionMode",
    "maxTurns",
    "skills",
}


def _frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith(FRONTMATTER_OPEN)
    closing = text.find("\n---\n", len(FRONTMATTER_OPEN))
    assert closing > len(FRONTMATTER_OPEN)
    payload = yaml.safe_load(text[len(FRONTMATTER_OPEN) : closing])
    assert isinstance(payload, dict)
    return payload


def test_claude_agents_are_read_only_and_bounded() -> None:
    paths = sorted(AGENT_DIR.glob("*.md"))
    assert {path.name for path in paths} == {
        "ravage-source-adjudicator.md",
        "ravage-source-auditor.md",
    }

    names: set[str] = set()
    for path in paths:
        metadata = _frontmatter(path)
        assert set(metadata) <= ALLOWED_KEYS
        name = metadata.get("name")
        assert isinstance(name, str)
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
        assert name == path.stem
        assert name not in names
        names.add(name)
        assert isinstance(metadata.get("description"), str)
        assert str(metadata["description"]).strip()
        tools = {item.strip() for item in str(metadata.get("tools") or "").split(",")}
        assert tools == ALLOWED_TOOLS
        assert metadata.get("model") == "inherit"
        assert metadata.get("permissionMode") == "plan"
        max_turns = metadata.get("maxTurns")
        assert isinstance(max_turns, int)
        assert 1 <= max_turns <= MAX_AGENT_TURNS
        skills = metadata.get("skills")
        assert isinstance(skills, list)
        assert len(skills) == 1
        assert all(
            isinstance(skill, str) and (SKILL_DIR / skill / "SKILL.md").is_file()
            for skill in skills
        )


def test_claude_skill_adapters_point_to_canonical_workflows() -> None:
    expected = {
        path.name
        for path in (ROOT / "skills").iterdir()
        if path.name.startswith(SOURCE_SKILL_PREFIX)
        and path.is_dir()
        and (path / "SKILL.md").is_file()
    }
    assert {path.name for path in SKILL_DIR.iterdir()} == expected
    for name in expected:
        adapter = SKILL_DIR / name
        assert adapter.is_symlink()
        assert adapter.resolve() == (ROOT / "skills" / name).resolve()
        assert (adapter / "SKILL.md").is_file()


def test_claude_guidance_references_source_only_workflows() -> None:
    guidance = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    assert "ravage-source-audit" in guidance
    assert "source-audit work is read-only" in guidance.casefold()
    assert (ROOT / "skills" / "ravage-source-audit" / "SKILL.md").is_file()
