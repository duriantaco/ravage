import subprocess
from pathlib import Path
from uuid import uuid4

from flask import Blueprint, abort, request, send_file

from .settings import PREVIEW_ROOT, UPLOAD_ROOT

media = Blueprint("media", __name__, url_prefix="/media")


@media.post("/preview")
def create_preview() -> object:
    source_name = request.form["source"]
    if Path(source_name).name != source_name:
        abort(400)
    source_path = UPLOAD_ROOT / source_name
    output_path = PREVIEW_ROOT / f"{uuid4().hex}.png"
    subprocess.run(
        f"/usr/bin/magick {source_path} {output_path}", shell=True, check=True
    )
    return send_file(output_path)
