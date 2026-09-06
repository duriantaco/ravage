from pathlib import Path

from flask import Blueprint, abort, request, send_file

form_files = Blueprint("form_files", __name__, url_prefix="/form")
FORM_ROOT = Path("/srv/form")


@form_files.get("/download")
def download_form_file() -> object:
    requested_name = request.args.get("name", "")
    root = FORM_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
