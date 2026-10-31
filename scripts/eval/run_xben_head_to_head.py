"""Run the local Codex + Ravage skill versus Strix XBEN diagnostic."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.xben_head_to_head.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
