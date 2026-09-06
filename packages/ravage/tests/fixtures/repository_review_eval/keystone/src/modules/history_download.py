from pathlib import Path

from flask import Blueprint, abort, request, send_file

history_files = Blueprint("history_files", __name__, url_prefix="/history")
HISTORY_ROOT = Path("/srv/history")


@history_files.get("/download")
def download_history_file() -> object:
    requested_name = request.args.get("name", "")
    root = HISTORY_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
