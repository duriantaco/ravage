from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
SKILLS = ROOT / "skills"
EXPECTED_SKILLS = {
    "ravage-source-access-control",
    "ravage-source-adjudication",
    "ravage-source-advisory-applicability",
    "ravage-source-advisory-discovery",
    "ravage-source-audit",
    "ravage-source-business-logic",
    "ravage-source-concurrency",
    "ravage-source-files-and-parsers",
    "ravage-source-identity-tokens",
    "ravage-source-injection",
    "ravage-source-outbound-requests",
    "ravage-source-security-config",
    "ravage-source-supply-chain",
}
REQUIRED_PATTERN_KEYS = {
    "id",
    "family",
    "skill",
    "signals",
    "trace",
    "counterevidence",
}
FRONTMATTER_PREFIX_CHARS = 4
MIN_PATTERN_RULES = 20
MAX_PATTERN_RULES = 60


def _frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    end = text.find("\n---\n", FRONTMATTER_PREFIX_CHARS)
    assert end > FRONTMATTER_PREFIX_CHARS
    payload = yaml.safe_load(text[FRONTMATTER_PREFIX_CHARS:end])
    assert isinstance(payload, dict)
    return payload


def test_source_skill_pack_has_only_expected_code_review_workflows() -> None:
    actual = {
        path.name
        for path in SKILLS.iterdir()
        if path.name.startswith("ravage-source-")
        and path.is_dir()
        and (path / "SKILL.md").is_file()
    }

    assert actual == EXPECTED_SKILLS


def test_source_skills_have_discriminating_metadata_and_no_runtime_commands() -> None:
    prohibited_commands = (
        "ravage attack",
        "ravage code-bug",
        "ravage scan",
        "ravage demo",
    )

    for name in EXPECTED_SKILLS:
        path = SKILLS / name / "SKILL.md"
        metadata = _frontmatter(path)
        assert metadata.get("name") == name
        description = metadata.get("description")
        assert isinstance(description, str)
        assert "source" in description.casefold() or "repository" in description.casefold()
        text = path.read_text(encoding="utf-8").casefold()
        assert not any(command in text for command in prohibited_commands)
        assert re.search(r"\b(?:do not|never)\b", text)


def test_structural_pattern_dictionary_is_bounded_and_routes_to_existing_skills() -> None:
    path = SKILLS / "ravage-source-audit" / "references" / "code-patterns.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "ravage.source-pattern-catalog.v1"
    rules = payload["rules"]
    assert isinstance(rules, list)
    assert MIN_PATTERN_RULES <= len(rules) <= MAX_PATTERN_RULES
    ids: set[str] = set()
    for rule in rules:
        assert isinstance(rule, dict)
        assert set(rule) == REQUIRED_PATTERN_KEYS
        identifier = rule["id"]
        assert isinstance(identifier, str)
        assert identifier not in ids
        ids.add(identifier)
        assert rule["skill"] in EXPECTED_SKILLS
        assert isinstance(rule["signals"], list)
        assert rule["signals"]
        assert isinstance(rule["counterevidence"], list)
        assert rule["counterevidence"]
        assert isinstance(rule["trace"], str)
        assert rule["trace"].strip()
    assert re.search(r"CVE-\d{4}-\d+", path.read_text(encoding="utf-8")) is None


def test_routing_reference_covers_every_source_skill() -> None:
    routing = (
        SKILLS / "ravage-source-audit" / "references" / "routing.md"
    ).read_text(encoding="utf-8")

    for name in EXPECTED_SKILLS:
        assert name in routing
