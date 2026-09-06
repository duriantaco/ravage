from pathlib import Path

from flask import Blueprint, abort, request, send_file

archive_files = Blueprint("archive_files", __name__, url_prefix="/archive")
ARCHIVE_ROOT = Path("/srv/archive")


@archive_files.get("/download")
def download_archive_file() -> object:
    requested_name = request.args.get("name", "")
    root = ARCHIVE_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
