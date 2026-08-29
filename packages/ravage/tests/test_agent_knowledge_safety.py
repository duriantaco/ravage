# ruff: noqa: PLR2004
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Self

import pytest
from ravage.agent_core.agent_state import AgentState
from ravage.agent_knowledge import (
    clear_knowledge_pack_cache,
    load_skill_pack,
    select_knowledge_cards,
)
from ravage.agent_knowledge import skill_pack as skill_pack_module


def test_loader_rejects_hardlinks_and_writable_pack_roots(tmp_path: Path) -> None:
    hardlinked = tmp_path / "hardlinked"
    skill = hardlinked / "hunt-idor"
    skill.mkdir(parents=True)
    source = tmp_path / "source-skill.md"
    source.write_text(_skill_text("hunt-idor"), encoding="utf-8")
    os.link(source, skill / "SKILL.md")

    with pytest.raises(ValueError, match="unsafe"):
        load_skill_pack(hardlinked)

    writable = tmp_path / "writable"
    _write_skill(writable, "hunt-idor")
    writable.chmod(0o777)
    with pytest.raises(ValueError, match="group- or world-writable"):
        load_skill_pack(writable)


@pytest.mark.parametrize(
    ("frontmatter", "message"),
    [
        (
            "name: hunt-idor\ndescription: Safe.\nversion: 1",
            "unsupported frontmatter fields",
        ),
        (
            "name: another-name\ndescription: Safe.",
            "name must match its directory",
        ),
        (
            "name: Hunt_IDOR\ndescription: Safe.",
            "invalid name",
        ),
    ],
)
def test_loader_rejects_unbound_or_ambiguous_metadata(
    tmp_path: Path,
    frontmatter: str,
    message: str,
) -> None:
    root = tmp_path / message.replace(" ", "-")
    directory = root / "hunt-idor"
    directory.mkdir(parents=True)
    directory.joinpath("SKILL.md").write_text(
        f"---\n{frontmatter}\n---\nBounded guidance.\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        load_skill_pack(root)


def test_pack_is_snapshotted_once_per_process(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    skill_path = _write_skill(root, "hunt-idor", body="Original guidance.")

    first = load_skill_pack(root)
    skill_path.write_text(
        _skill_text("hunt-idor", body="Changed after the run snapshot."),
        encoding="utf-8",
    )
    second = load_skill_pack(root)

    assert second is first
    assert second.skills[0].body == "Original guidance."
    assert second.metadata.sha256 == first.metadata.sha256


def test_loader_enforces_optional_expected_digest(tmp_path: Path) -> None:
    root = tmp_path / "digest"
    _write_skill(root, "hunt-idor")
    digest = load_skill_pack(root).metadata.sha256

    assert load_skill_pack(root, expected_sha256=digest).metadata.sha256 == digest
    assert load_skill_pack(root, expected_sha256=f"sha256:{digest}").metadata.sha256 == digest
    with pytest.raises(ValueError, match="expected SHA-256"):
        load_skill_pack(root, expected_sha256="0" * 64)
    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        load_skill_pack(root, expected_sha256="not-a-digest")


@pytest.mark.parametrize(
    "body",
    [
        "Only run this for XBEN-123-45.",
        "The expected secret is flag{benchmark_specific_value}.",
        "Always request /starttime first.",
    ],
)
def test_loader_rejects_benchmark_specific_skill_guidance(
    tmp_path: Path,
    body: str,
) -> None:
    root = tmp_path / "overfit"
    _write_skill(root, "hunt-idor", body=body)

    with pytest.raises(ValueError, match="anti-overfit policy"):
        load_skill_pack(root)


def test_selector_rechecks_digest_after_pack_cache_eviction(tmp_path: Path) -> None:
    clear_knowledge_pack_cache()
    try:
        original = tmp_path / "original"
        skill_path = _write_skill(original, "hunt-idor", body="Original guidance.")
        digest = load_skill_pack(original).metadata.sha256
        skill_path.write_text(
            _skill_text("hunt-idor", body="Changed after digest verification."),
            encoding="utf-8",
        )
        for index in range(9):
            other = tmp_path / f"eviction-{index}"
            _write_skill(other, f"hunt-other-{index}")
            load_skill_pack(other)

        with pytest.raises(ValueError, match="expected SHA-256"):
            select_knowledge_cards(
                pack_path=original,
                expected_sha256=digest,
                state=AgentState(),
                description="Assess authorization and IDOR boundaries.",
            )
    finally:
        clear_knowledge_pack_cache()


def test_loader_rejects_skill_changed_during_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "read-race"
    skill_path = _write_skill(root, "hunt-idor", body="Original guidance.")
    real_fdopen = skill_pack_module.os.fdopen

    class RacingStream:
        def __init__(self, stream: object) -> None:
            self.stream = stream

        def __enter__(self) -> Self:
            self.stream.__enter__()  # type: ignore[attr-defined]
            return self

        def __exit__(self, *args: object) -> object:
            return self.stream.__exit__(*args)  # type: ignore[attr-defined,no-any-return]

        def read(self, size: int) -> bytes:
            content = self.stream.read(size)  # type: ignore[attr-defined,no-any-return]
            skill_path.write_text(
                _skill_text("hunt-idor", body="Changed during descriptor read."),
                encoding="utf-8",
            )
            return content

        def fileno(self) -> int:
            return self.stream.fileno()  # type: ignore[attr-defined,no-any-return]

    def racing_fdopen(*args: object, **kwargs: object) -> RacingStream:
        return RacingStream(real_fdopen(*args, **kwargs))  # type: ignore[arg-type]

    monkeypatch.setattr(skill_pack_module.os, "fdopen", racing_fdopen)

    with pytest.raises(ValueError, match="changed while it was being read"):
        load_skill_pack(root)


def test_serialized_card_budget_includes_metadata(tmp_path: Path) -> None:
    root = tmp_path / "budget"
    _write_skill(root, "hunt-idor", body="Investigate carefully. " * 100)

    too_small = select_knowledge_cards(
        pack_path=root,
        state=AgentState(),
        description="Assess authorization and IDOR boundaries.",
        max_chars=40,
    )
    cards = select_knowledge_cards(
        pack_path=root,
        state=AgentState(),
        description="Assess authorization and IDOR boundaries.",
        max_chars=5_000,
    )
    rendered = json.dumps(
        [card.to_json() for card in cards],
        ensure_ascii=True,
        separators=(",", ":"),
    )

    assert too_small == []
    assert cards
    assert "Investigate carefully." in cards[0].guidance
    assert "[truncated]" not in cards[0].guidance
    assert len(rendered) <= 5_000


def test_selector_never_truncates_invariant_skill_sections() -> None:
    state = AgentState()
    too_small = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=state,
        description="Inspect GraphQL, IDOR authorization, and CCSDS telemetry.",
        limit=3,
        max_chars=800,
    )
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=state,
        description="Inspect GraphQL, IDOR authorization, and CCSDS telemetry.",
        limit=3,
        max_chars=3_000,
    )
    rendered = json.dumps(
        [card.to_json() for card in cards],
        ensure_ascii=True,
        separators=(",", ":"),
    )

    assert too_small == []
    assert cards
    assert len(rendered) <= 3_000
    assert all("## Evidence Gate" in card.guidance for card in cards)
    assert all("## Stop Conditions" in card.guidance for card in cards)
    assert all("[truncated]" not in card.guidance for card in cards)


def _write_skill(root: Path, name: str, *, body: str = "Bounded guidance.") -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    path = directory / "SKILL.md"
    path.write_text(_skill_text(name, body=body), encoding="utf-8")
    return path


def _skill_text(name: str, *, body: str = "Bounded guidance.") -> str:
    return (
        "---\n"
        f"name: {name}\n"
        "description: Investigate authorized object-level access control.\n"
        "---\n"
        f"{body}\n"
    )
