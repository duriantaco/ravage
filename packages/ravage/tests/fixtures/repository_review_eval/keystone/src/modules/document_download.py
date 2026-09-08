from pathlib import Path

from flask import Blueprint, abort, request, send_file

document_files = Blueprint("document_files", __name__, url_prefix="/document")
DOCUMENT_ROOT = Path("/srv/document")


@document_files.get("/download")
def download_document_file() -> object:
    requested_name = request.args.get("name", "")
    root = DOCUMENT_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
