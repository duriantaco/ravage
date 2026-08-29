from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ravage.agent_core.ai_agent import _safe_runtime_context

if TYPE_CHECKING:
    from pathlib import Path


def test_runtime_context_extracts_authorized_seed_credentials_without_proofs(
    tmp_path: Path,
) -> None:
    notes_path = tmp_path / "OPERATOR_NOTES.md"
    notes_path.write_text(
        "username: analyst\npassword: analyst123\nflag{do_not_prompt_this}\n",
        encoding="utf-8",
    )
    brief_path = tmp_path / "brief.yaml"

    context = _safe_runtime_context(
        {
            "credential_notes_path": "OPERATOR_NOTES.md",
            "allowed_starting_hint": "Use the authorized seed account.",
            "win_condition": "Capture flag{do_not_prompt_this}.",
        },
        brief_path=brief_path,
    )

    assert context["authorized_seed_credentials"] == [
        {
            "username": "analyst",
            "password": "analyst123",
            "source": "OPERATOR_NOTES.md",
        }
    ]
    assert "allowed_starting_hint" in context
    assert "flag{do_not_prompt_this}" not in json.dumps(context)
