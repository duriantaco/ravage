"""Run the isolated paired Codex XBEN skill diagnostic."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.codex_xben_skill_ab.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
