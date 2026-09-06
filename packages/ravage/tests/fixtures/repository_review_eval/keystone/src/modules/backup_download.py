from pathlib import Path

from flask import Blueprint, abort, request, send_file

backup_files = Blueprint("backup_files", __name__, url_prefix="/backup")
BACKUP_ROOT = Path("/srv/backup")


@backup_files.get("/download")
def download_backup_file() -> object:
    requested_name = request.args.get("name", "")
    root = BACKUP_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
