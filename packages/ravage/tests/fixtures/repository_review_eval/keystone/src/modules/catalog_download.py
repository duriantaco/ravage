from pathlib import Path

from flask import Blueprint, abort, request, send_file

catalog_files = Blueprint("catalog_files", __name__, url_prefix="/catalog")
CATALOG_ROOT = Path("/srv/catalog")


@catalog_files.get("/download")
def download_catalog_file() -> object:
    requested_name = request.args.get("name", "")
    root = CATALOG_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
