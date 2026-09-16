from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
AGENT_DIR = ROOT / ".codex" / "agents"
SKILL_DIR = ROOT / ".agents" / "skills"
CANONICAL_SKILL_DIR = ROOT / "skills"
SOURCE_SKILL_PREFIX = "ravage-source-"
EXPECTED_AGENT_SKILLS = {
    "ravage_source_adjudicator": "ravage-source-adjudication",
    "ravage_source_auditor": "ravage-source-audit",
}
ALLOWED_AGENT_KEYS = {
    "name",
    "description",
    "sandbox_mode",
    "developer_instructions",
}


def _agent_config(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        config = tomllib.load(stream)
    assert isinstance(config, dict)
    return config


def test_codex_agents_are_read_only_and_reference_expected_skills() -> None:
    paths = sorted(AGENT_DIR.glob("*.toml"))
    assert {path.stem for path in paths} == set(EXPECTED_AGENT_SKILLS)

    names: set[str] = set()
    for path in paths:
        config = _agent_config(path)
        assert set(config) == ALLOWED_AGENT_KEYS
        name = config.get("name")
        assert isinstance(name, str)
        assert name == path.stem
        assert name not in names
        names.add(name)
        assert isinstance(config.get("description"), str)
        assert str(config["description"]).strip()
        assert config.get("sandbox_mode") == "read-only"
        instructions = config.get("developer_instructions")
        assert isinstance(instructions, str)
        assert instructions.strip()
        assert f"${EXPECTED_AGENT_SKILLS[name]}" in instructions


def test_codex_skill_adapters_point_to_canonical_workflows() -> None:
    expected = {
        path.name
        for path in CANONICAL_SKILL_DIR.iterdir()
        if path.name.startswith(SOURCE_SKILL_PREFIX)
        and path.is_dir()
        and (path / "SKILL.md").is_file()
    }
    assert {path.name for path in SKILL_DIR.iterdir()} == expected
    for name in expected:
        adapter = SKILL_DIR / name
        assert adapter.is_symlink()
        assert adapter.resolve() == (CANONICAL_SKILL_DIR / name).resolve()
        assert (adapter / "SKILL.md").is_file()


def test_codex_project_guidance_names_agents_and_pattern_catalog() -> None:
    guidance = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for path in AGENT_DIR.glob("*.toml"):
        name = _agent_config(path)["name"]
        assert isinstance(name, str)
        assert name in guidance
    assert "skills/ravage-source-audit/references/code-patterns.json" in guidance
    assert "source snapshot only" in guidance
