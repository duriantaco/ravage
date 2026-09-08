from pathlib import Path

from flask import Blueprint, abort, request, send_file

evidence_files = Blueprint("evidence_files", __name__, url_prefix="/evidence")
EVIDENCE_ROOT = Path("/srv/evidence")


@evidence_files.get("/download")
def download_evidence_file() -> object:
    requested_name = request.args.get("name", "")
    root = EVIDENCE_ROOT.resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        abort(400)
    if not candidate.is_file():
        abort(404)
    return send_file(candidate)
