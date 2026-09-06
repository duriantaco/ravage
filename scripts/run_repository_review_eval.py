from __future__ import annotations

import runpy
from pathlib import Path

if __name__ == "__main__":
    runpy.run_path(
        str(Path(__file__).resolve().parent / "eval" / "run_repository_review_eval.py"),
        run_name="__main__",
    )
