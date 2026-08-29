from __future__ import annotations

from ravage.probes.sqli_auth_upload_closure import (
    evidence_directed_upload_readback_urls,
    prioritize_observed_upload_attempts,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession


def test_live_pdf_contract_overrides_ambient_attempt_order() -> None:
    attempts = [
        {"filename": "probe.jpg.php"},
        {"filename": "probe.php.jpg"},
        {"filename": "probe.pdf.php"},
        {"filename": "probe.php"},
    ]

    ranked = prioritize_observed_upload_attempts(
        attempts,
        form={
            "action": "https://target.test/upload.php",
            "page_context": "pdf invoice upload",
            "inputs": [{"name": "invoice", "type": "file"}],
        },
    )

    assert ranked[0]["filename"] == "probe.pdf.php"
    assert attempts[0]["filename"] == "probe.jpg.php"


def test_server_reported_directory_precedes_generic_path_guessing() -> None:
    session = ProbeSession("http://127.0.0.1:8765/")
    response = ProbeResponse(
        method="POST",
        url="http://127.0.0.1:8765/upload.php",
        status=200,
        final_url="http://127.0.0.1:8765/upload.php",
        elapsed_ms=1,
        headers={},
        body="File is successfully uploaded to /uploaded_invoices/",
        error="",
    )

    urls = evidence_directed_upload_readback_urls(
        session,
        upload_response=response,
        filename="probe.pdf.php",
    )

    assert urls == ("http://127.0.0.1:8765/uploaded_invoices/probe.pdf.php",)
