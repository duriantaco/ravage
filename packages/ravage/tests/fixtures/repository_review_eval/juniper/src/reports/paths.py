from pathlib import Path

REPORT_ROOT = Path("/srv/reports")


def resolve_report_path(requested_name: str) -> Path:
    return REPORT_ROOT / requested_name
