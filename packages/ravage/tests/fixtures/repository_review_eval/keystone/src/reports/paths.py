from pathlib import Path

REPORT_ROOT = Path("/srv/reports")


def resolve_report_path(requested_name: str) -> Path:
    root = REPORT_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError
    return candidate
