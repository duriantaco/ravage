from __future__ import annotations

import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from typing import cast
from urllib.parse import urljoin
from urllib.parse import parse_qs, urlparse

import pytest

from ravage.agent_core.agent_state import AgentState
from ravage.probes.cms.cms_exposure import _interesting_artifact, probe_cms_exposure
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

SECRET = "FLAG{cms_backup_leak}"


def test_cms_artifact_classifier_ignores_plain_login_page() -> None:
    login_body = """
    <html>
      <title>Springfield Login</title>
      <style>body { background-image: url('./static/springfield_background.jpg'); }</style>
      <form action="index.php" method="POST">
        <input name="username"><input type="password" name="password">
      </form>
    </html>
    """

    assert not _interesting_artifact(_resp("http://127.0.0.1/?backup-migration=PROGRESS_LOGS", login_body))
    assert _interesting_artifact(
        _resp("http://127.0.0.1/wp-content/backup-migration-abcd1234/complete_logs.log", "created site-backup.zip")
    )


class _CmsApp:
    target_url = "http://127.0.0.1/"

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.target_url)

    def get(self, url: str, *, headers=None) -> ProbeResponse:
        del headers
        if url.endswith("/wp-content/backup-migration-config.php"):
            return _resp(url, "STORAGE::LOCAL::PATH=/var/www/html/wp-content/backup-migration-abcd1234")
        if url.endswith("/wp-content/backup-migration-abcd1234/complete_logs.log"):
            return _resp(url, f"backup completed; exported secret {SECRET}")
        return _resp(url, "not found", status=404)


def _resp(url: str, body: str, *, status: int = 200) -> ProbeResponse:
    return ProbeResponse(method="GET", url=url, status=status, final_url=url, elapsed_ms=2, headers={}, body=body)


def test_cms_exposure_follows_backup_plugin_breadcrumbs() -> None:
    session = cast(ProbeSession, _CmsApp())
    result = probe_cms_exposure(session, AgentState())

    proofs = [f["proof"] for f in result.findings if f.get("type") == "cms_exposure_extracted_proof"]
    assert proofs == [SECRET]


class _PluginMetadataApp:
    target_url = "http://127.0.0.1/"

    def __init__(self) -> None:
        self.requested: list[str] = []

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.target_url)

    def get(self, url: str, *, headers=None) -> ProbeResponse:
        del headers
        self.requested.append(url)
        if url.endswith("/wp-content/plugins/backup-backup/readme.txt"):
            return _resp(url, "=== Backup Migration Staging ===\nStable tag: 1.3.5\nBackupBliss")
        if url.endswith("/wp-content/plugins/backup-backup/background-errors.log"):
            return _resp(url, "backup-heart.php Content-ConfigDir warning")
        return _resp(url, "not found", status=404)


class _HostSensitiveCmsApp:
    target_url = "http://127.0.0.1:5000/"

    def __init__(self) -> None:
        self.requested: list[tuple[str, dict[str, str] | None]] = []

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def in_scope(self, url: str) -> bool:
        return url.startswith("http://127.0.0.1:5000/")

    def get(self, url: str, *, headers=None) -> ProbeResponse:
        self.requested.append((url, headers))
        if (headers or {}).get("Host") != "localhost":
            return _resp(url, "", status=404)
        if url.endswith("/wp-content/backup-migration-config.php"):
            return _resp(url, "STORAGE::LOCAL::PATH=/var/www/html/wp-content/backup-migration-hosted")
        if url.endswith("/wp-content/backup-migration-hosted/complete_logs.log"):
            return _resp(url, f"backup log {SECRET}")
        return _resp(url, "not found", status=404)




class _ProgressLogApp:
    target_url = "http://127.0.0.1/"

    def absolute(self, path: str) -> str:
        return urljoin(self.target_url, path)

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.target_url)

    def get(self, url: str, *, headers=None) -> ProbeResponse:
        del headers
        if "backup-migration=PROGRESS_LOGS" in url and "latest_migration.log" in url:
            return _resp(url, "Checking this path: /var/www/html/wp-content/backup-migration-abcd1234/backups")
        if url.endswith("/wp-content/backup-migration-abcd1234/complete_logs.log"):
            return _resp(url, f"restore logs exposed proof {SECRET}")
        return _resp(url, "not found", status=404)


def test_cms_exposure_uses_backup_migration_progress_log_breadcrumb() -> None:
    session = cast(ProbeSession, _ProgressLogApp())
    result = probe_cms_exposure(session, AgentState())

    proofs = [f["proof"] for f in result.findings if f.get("type") == "cms_exposure_extracted_proof"]
    assert proofs == [SECRET]


class _ArchiveHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/wp-content/backup-migration-config.php":
            self._send_text("backup-migration-zzzz1234")
            return
        if self.path == "/wp-content/backup-migration-zzzz1234/backups/latest.log":
            self._send_text("created site-backup.zip")
            return
        if self.path == "/wp-content/backup-migration-zzzz1234/backups/site-backup.zip":
            data = BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                archive.writestr("wp-config.php", f"<?php // {SECRET}")
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.end_headers()
            self.wfile.write(data.getvalue())
            return
        self._send_text("not found", status=404)

    def _send_text(self, body: str, *, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def archive_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ArchiveHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_cms_exposure_inspects_public_backup_archive(archive_server: str) -> None:
    result = probe_cms_exposure(ProbeSession(archive_server, timeout_seconds=5), AgentState())

    proofs = [f["proof"] for f in result.findings if f.get("type") == "cms_exposure_extracted_proof"]
    assert SECRET in proofs


class _BackupMigrationUnlockHandler(BaseHTTPRequestHandler):
    archive_name = "BM_Backup_2026-06-27_00_35_03_xwypEJusGamCiMUc.zip"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.headers.get("Host") != "localhost":
            self._send_text("not found", status=404)
            return
        parsed = urlparse(self.path)
        if parsed.path == "/wp-content/plugins/backup-backup/readme.txt":
            self._send_text("=== Backup Migration Staging ===\nStable tag: 1.3.5\nBackupBliss")
            return
        if parsed.path == "/" and parse_qs(parsed.query).get("backup-migration") == ["BMI_BACKUP"]:
            backup_id = parse_qs(parsed.query).get("backup-id", [""])[0]
            location = f"http://localhost/wp-content/backup-migration-unlocked/backups/{backup_id}"
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        if parsed.path == "/wp-content/backup-migration-unlocked/complete_logs.log":
            self._send_text(f"New backup created and its name is: {self.archive_name}")
            return
        if parsed.path == f"/wp-content/backup-migration-unlocked/backups/{self.archive_name}":
            data = BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                archive.writestr(
                    "bmi_backup_manifest.json",
                    '{"version":"1.3.5","config":{"NONCE_KEY":"k","NONCE_SALT":"s","table_prefix":"wp_"}}',
                )
                archive.writestr("db_tables/wp_users.sql", "INSERT INTO `wp_users` VALUES (1,'admin','$P$hash','admin','a@b','','','','','admin');")
                archive.writestr("wordpress/wp-content/uploads/proof.txt", SECRET)
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.end_headers()
            self.wfile.write(data.getvalue())
            return
        self._send_text("not found", status=404)

    def _send_text(self, body: str, *, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def backup_migration_unlock_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BackupMigrationUnlockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_cms_exposure_drives_backup_migration_unlock_and_rewrites_canonical_location(
    backup_migration_unlock_server: str,
) -> None:
    state = AgentState()
    state.signals["canonical_hosts"] = ["localhost"]

    result = probe_cms_exposure(ProbeSession(backup_migration_unlock_server, timeout_seconds=5), state)

    proofs = [f["proof"] for f in result.findings if f.get("type") == "cms_exposure_extracted_proof"]
    assert SECRET in proofs
    requested = [str(request.get("url") or "") for request in result.requests]
    assert any("backup-migration=BMI_BACKUP&backup-id=probe.zip" in url for url in requested)
    assert any(_BackupMigrationUnlockHandler.archive_name in url for url in requested)


class _PublicPluginArchiveHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/wp-content/uploads/":
            self._send_text('<html><title>Index of /wp-content/uploads</title><a href="2024/">2024/</a></html>')
            return
        if parsed.path == "/wp-content/uploads/2024/":
            self._send_text('<html><title>Index of /wp-content/uploads/2024</title><a href="06/">06/</a></html>')
            return
        if parsed.path == "/wp-content/uploads/2024/06/":
            self._send_text(
                '<html><title>Index of /wp-content/uploads/2024/06</title>'
                '<a href="sample.1.2.3.zip">sample.1.2.3.zip</a></html>'
            )
            return
        if parsed.path == "/wp-content/uploads/2024/06/sample.1.2.3.zip":
            data = BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                archive.writestr(
                    "sample/includes/lib/detail.php",
                    "<?php require_once($_REQUEST['wp_abspath'] . '/wp-admin/admin.php'); echo $_REQUEST['id'];",
                )
                archive.writestr("sample/readme.txt", "=== Sample ===\nStable tag: 1.2.3\n")
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.end_headers()
            self.wfile.write(data.getvalue())
            return
        if parsed.path == "/wp-content/plugins/sample/includes/lib/detail.php":
            params = parse_qs(parsed.query)
            if params.get("wp_abspath", [""])[0].startswith("data://text/plain,"):
                self._send_text(f"loaded include\n{SECRET}")
                return
        self._send_text("not found", status=404)

    def _send_text(self, body: str, *, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))
