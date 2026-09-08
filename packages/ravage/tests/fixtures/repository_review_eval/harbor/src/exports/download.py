from flask import Blueprint, abort, request, send_file

from .settings import EXPORT_ROOT

exports = Blueprint("exports", __name__, url_prefix="/exports")


@exports.get("/download")
def download_export() -> object:
    requested_name = request.args.get("name", "")
    root = EXPORT_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
