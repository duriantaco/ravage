from pathlib import Path

from flask import Blueprint, abort, request, send_file

guide_files = Blueprint("guide_files", __name__, url_prefix="/guide")
GUIDE_ROOT = Path("/srv/guide")


@guide_files.get("/download")
def download_guide_file() -> object:
    requested_name = request.args.get("name", "")
    root = GUIDE_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
