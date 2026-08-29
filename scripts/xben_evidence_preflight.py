from __future__ import annotations

import runpy
from pathlib import Path

if __name__ == "__main__":
    script = Path(__file__).resolve().parent / "xben" / "evidence_preflight.py"
    runpy.run_path(str(script), run_name="__main__")
