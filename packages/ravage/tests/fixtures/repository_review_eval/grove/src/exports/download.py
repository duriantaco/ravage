from flask import Blueprint, abort, request, send_file

from .settings import EXPORT_ROOT

exports = Blueprint("exports", __name__, url_prefix="/exports")


@exports.get("/download")
def download_export() -> object:
    requested_name = request.args.get("name", "")
    candidate = EXPORT_ROOT / requested_name
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
