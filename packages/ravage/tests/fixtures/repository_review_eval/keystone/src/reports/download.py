from flask import Blueprint, abort, request, send_file

from .paths import resolve_report_path

reports = Blueprint("reports", __name__, url_prefix="/reports")


@reports.get("/download")
def download_report() -> object:
    requested_name = request.args.get("name", "")
    try:
        candidate = resolve_report_path(requested_name)
    except ValueError:
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
