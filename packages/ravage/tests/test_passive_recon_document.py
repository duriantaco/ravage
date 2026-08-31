from __future__ import annotations

from ravage.web_core.recon import parse_passive_recon_document


def test_passive_document_is_transient_and_hides_exact_urls_from_repr() -> None:
    secret = "query-secret-sentinel"  # noqa: S105 - leak sentinel.
    document = parse_passive_recon_document(
        "https://app.example.test/account/123",
        {
            "Content-Type": "text/html",
            "Set-Cookie": "session=cookie-secret-sentinel; Secure",
        },
        (
            f"<a href='/orders/987?token={secret}'>order</a>"
            "<form method='POST' action='/save?flow=private'>"
            "<input name='title' value='form-secret-sentinel'>"
            "</form>"
        ),
    )

    assert secret in document.links[0]
    assert secret not in repr(document)
    assert all(secret not in repr(operation) for operation in document.operations)
    assert "cookie-secret-sentinel" not in repr(document)
    assert "form-secret-sentinel" not in repr(document)


def test_passive_document_filters_inert_self_links_and_empty_script_sources() -> None:
    page = "https://app.example.test/dashboard"
    document = parse_passive_recon_document(
        page,
        {"Content-Type": "text/html"},
        (
            "<html><a>missing</a><a href=''>empty</a><a href='#fragment'>fragment</a>"
            "<script>window.ready = true;</script></html>"
        ),
    )

    assert document.links == ()
    assert all(not (item.url == page and "script" in item.hints) for item in document.operations)


def test_passive_document_preserves_mixed_parameter_locations_without_values() -> None:
    document = parse_passive_recon_document(
        "https://app.example.test/",
        {"Content-Type": "text/html"},
        """
        <form method="POST" action="/save?flow=private-value">
          <input name="title" value="form-value-secret">
        </form>
        <script>
          fetch('/api/jobs?view=private-value', {
            method: 'POST',
            headers: {'X-Trace': 'header-value-secret'},
            body: JSON.stringify({job_id: 'body-value-secret'})
          });
        </script>
        """,
    )

    form = next(item for item in document.operations if item.hints == ("form",))
    javascript = next(item for item in document.operations if item.hints == ("javascript",))

    assert {(item.name, item.location) for item in form.parameters} == {
        ("flow", "query"),
        ("title", "form"),
    }
    assert {(item.name, item.location) for item in javascript.parameters} == {
        ("job_id", "body"),
        ("view", "query"),
    }
    serialized_metadata = repr(
        (
            tuple((item.name, item.location) for item in form.parameters),
            tuple((item.name, item.location) for item in javascript.parameters),
            javascript.header_names,
        )
    )
    assert "private-value" not in serialized_metadata
    assert "form-value-secret" not in serialized_metadata
    assert "body-value-secret" not in serialized_metadata
    assert "header-value-secret" not in serialized_metadata
