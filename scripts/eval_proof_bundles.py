from __future__ import annotations

import runpy
from pathlib import Path


if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parent / "eval" / "eval_proof_bundles.py"), run_name="__main__")
