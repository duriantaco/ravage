from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "tools/paired_xben/images/target-gateway.Dockerfile"
WORKFLOW = ROOT / ".github/workflows/paired-xben-helper-image.yml"


def test_target_gateway_image_has_no_mutable_or_networked_build_inputs() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")

    assert text.startswith(
        "# syntax=docker/dockerfile:1.18.0@sha256:"
        "dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf\n"
    )
    assert re.findall(r"(?m)^FROM\s+(.+)$", text) == [
        "docker.io/library/python@sha256:"
        "c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49"
    ]
    assert "packages/ravage/src/ravage/xben_parts/http_meter_gateway.py" in text
    assert "ravage/xben_parts/http_meter_gateway.py" in text
    assert not re.search(r"(?m)^RUN\s", text)
    assert not re.search(r"(?m)^ADD\s", text)


def test_helper_image_workflow_is_manual_first_attempt_and_digest_publishing() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "github.ref_protected == true" in text
    assert "github.run_attempt == 1" in text
    assert "runs-on: ubuntu-24.04" in text
    assert "--platform linux/amd64" in text
    assert "--provenance=mode=max" in text
    assert "--sbom=true" in text
    assert 'cosign sign --yes "${IMAGE_REFERENCE}"' in text
    assert "Use the digest, never the source tag" in text
    assert "OPENAI_API_KEY" not in text
