# ruff: noqa: E501,I001,PLR0911,S104,S105,S108,S608
from __future__ import annotations

import html
import json
import os
import sqlite3
import urllib.parse
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROLE = os.environ.get("PERIMETER_ROLE", "edge")
PORT = int(os.environ.get("PERIMETER_PORT", "8000"))
OPS_URL = os.environ.get("PERIMETER_OPS_URL", "http://127.0.0.1:8095")
FLAG_BACKUP = os.environ.get("PERIMETER_FLAG_BACKUP", "flag{perimeter_backup_disclosure}")
FLAG_DEBUG = os.environ.get("PERIMETER_FLAG_DEBUG", "flag{perimeter_debug_trace}")
FLAG_ADMIN = os.environ.get("PERIMETER_FLAG_ADMIN", "flag{perimeter_ops_admin_panel}")
FLAG_AUDIT = os.environ.get("PERIMETER_FLAG_AUDIT", "flag{perimeter_audit_union_sqli}")
FLAG_TRAVERSAL = os.environ.get("PERIMETER_FLAG_TRAVERSAL", "flag{perimeter_export_path_traversal}")
DB_PATH = Path(f"/tmp/perimeter-{ROLE}.db")
COOKIE_NAME = "perimeter_ops"


def init_db() -> None:
    if ROLE != "ops":
        return
    if DB_PATH.exists():
        DB_PATH.unlink()
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE audit_events (
              id INTEGER PRIMARY KEY,
              summary TEXT NOT NULL,
              severity TEXT NOT NULL
            );
            CREATE TABLE secrets (
              id INTEGER PRIMARY KEY,
              label TEXT NOT NULL,
              value TEXT NOT NULL
            );
            """
        )
        conn.executemany(
            "INSERT INTO audit_events (id, summary, severity) VALUES (?, ?, ?)",
            [
                (1, "normal health probe", "low"),
                (2, "operator export opened", "medium"),
                (3, "breakglass console review", "high"),
            ],
        )
        conn.execute(
            "INSERT INTO secrets (id, label, value) VALUES (?, ?, ?)",
            (1, "audit_pipeline_marker", FLAG_AUDIT),
        )


class PerimeterHandler(BaseHTTPRequestHandler):
    def version_string(self) -> str:
        return "VertexEdge/0.4" if ROLE == "edge" else "VertexOpsConsole/1.8"

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/health":
            self._json({"ok": True, "role": ROLE})
            return
        if ROLE == "edge":
            self._edge_get(parsed.path, query)
            return
        self._ops_get(parsed.path, query)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if ROLE != "ops" or parsed.path != "/login":
            self.send_error(HTTPStatus.NOT_FOUND, "unknown path")
            return
        form = urllib.parse.parse_qs(self.rfile.read(_content_length(self)).decode())
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        if username == "admin" and password == "admin":
            self._redirect("/console", cookie="admin")
            return
        self._html(_ops_login("Invalid username or password."), status=401)

    def _edge_get(self, path: str, query: dict[str, list[str]]) -> None:
        if path == "/":
            self._html(_edge_home())
            return
        if path == "/robots.txt":
            self._text(
                "User-agent: *\nDisallow: /backup/\nDisallow: /debug/\nSitemap: /sitemap.xml\n"
            )
            return
        if path == "/sitemap.xml":
            self._xml(
                """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:8094/status</loc></url>
</urlset>
"""
            )
            return
        if path == "/status":
            self._html("<h1>Gateway Status</h1><p>edge online</p>")
            return
        if path in {"/backup", "/backup/"}:
            self._html(
                '<h1>Backup Index</h1><a href="/backup/gateway.conf">gateway.conf</a>'
            )
            return
        if path == "/backup/gateway.conf":
            self._text(
                "\n".join(
                    [
                        "# Vertex gateway backup",
                        f"ops_console={OPS_URL}",
                        "ops_login=/login",
                        "ops_audit=/api/audit?q=health",
                        "ops_export=/exports?file=reports/summary.txt",
                        f"backup_marker={FLAG_BACKUP}",
                    ]
                )
                + "\n"
            )
            return
        if path in {"/debug", "/debug/"}:
            self._html('<h1>Debug Index</h1><a href="/debug/trace">trace</a>')
            return
        if path == "/debug/trace":
            self._json(
                {
                    "ok": True,
                    "mode": "staging",
                    "ops_console": OPS_URL,
                    "trace_flag": FLAG_DEBUG,
                    "operator_note": "debug trace is not linked from the landing page",
                }
            )
            return
        if path == "/fetch":
            target = query.get("url", [""])[0]
            self._json({"ok": False, "error": "fetch disabled", "target": target}, status=403)
            return
        self.send_error(HTTPStatus.NOT_FOUND, "unknown path")

    def _ops_get(self, path: str, query: dict[str, list[str]]) -> None:
        user = self._current_ops_user()
        if path == "/":
            self._html("<h1>Vertex Ops</h1><p>Private console. Use /login.</p>")
            return
        if path == "/login":
            self._html(_ops_login())
            return
        if path == "/logout":
            self._redirect("/", clear_cookie=True)
            return
        if path == "/console":
            if user is None:
                self._redirect("/login")
                return
            self._html(_ops_console())
            return
        if path == "/api/audit":
            self._audit_search(query)
            return
        if path == "/exports":
            if user is None:
                self._json({"ok": False, "error": "authentication required"}, status=401)
                return
            self._export_file(query)
            return
        self.send_error(HTTPStatus.NOT_FOUND, "unknown path")

    def _audit_search(self, query: dict[str, list[str]]) -> None:
        q = query.get("q", [""])[0]
        with sqlite3.connect(DB_PATH) as conn:
            try:
                rows = conn.execute(
                    f"SELECT summary, severity FROM audit_events WHERE summary LIKE '%{q}%'"
                ).fetchall()
            except sqlite3.Error as exc:
                self._text(f"sqlite3.OperationalError: {exc}", status=500)
                return
        self._json({"ok": True, "q": q, "rows": rows})

    def _export_file(self, query: dict[str, list[str]]) -> None:
        file_name = query.get("file", ["reports/summary.txt"])[0]
        files = {
            "reports/summary.txt": "daily export completed\n",
            "../secrets/export-token.txt": f"{FLAG_TRAVERSAL}\n",
            "../../secrets/export-token.txt": f"{FLAG_TRAVERSAL}\n",
        }
        body = files.get(file_name)
        if body is None:
            self._text("missing export", status=404)
            return
        self._text(body)

    def _current_ops_user(self) -> str | None:
        raw_cookie = self.headers.get("Cookie", "")
        cookie = SimpleCookie(raw_cookie)
        morsel = cookie.get(COOKIE_NAME)
        return "admin" if morsel is not None and morsel.value == "admin" else None

    def _redirect(
        self,
        location: str,
        *,
        cookie: str | None = None,
        clear_cookie: bool = False,
    ) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        if cookie is not None:
            self.send_header("Set-Cookie", f"{COOKIE_NAME}={cookie}; Path=/; HttpOnly; SameSite=Lax")
        if clear_cookie:
            self.send_header("Set-Cookie", f"{COOKIE_NAME}=; Path=/; Max-Age=0")
        self.end_headers()

    def _html(self, body: str, *, status: int = 200) -> None:
        self._send("text/html; charset=utf-8", body, status=status)

    def _json(self, body: dict[str, object], *, status: int = 200) -> None:
        self._send("application/json", json.dumps(body, sort_keys=True), status=status)

    def _text(self, body: str, *, status: int = 200) -> None:
        self._send("text/plain; charset=utf-8", body, status=status)

    def _xml(self, body: str, *, status: int = 200) -> None:
        self._send("application/xml; charset=utf-8", body, status=status)

    def _send(self, content_type: str, body: str, *, status: int = 200) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _edge_home() -> str:
    return """
<!doctype html>
<title>Vertex Perimeter Gateway</title>
<h1>Vertex Perimeter Gateway</h1>
<p>Public edge is online. Operational consoles are not linked here.</p>
"""


def _ops_login(error: str = "") -> str:
    error_html = f"<p>{html.escape(error)}</p>" if error else ""
    return f"""
<!doctype html>
<title>Vertex Ops Login</title>
<h1>Vertex Ops Login</h1>
{error_html}
<form method="post" action="/login">
  <label>Username <input name="username"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Sign in</button>
</form>
"""


def _ops_console() -> str:
    return f"""
<!doctype html>
<title>Vertex Ops Console</title>
<h1>Welcome admin</h1>
<p>Ops console flag: {html.escape(FLAG_ADMIN)}</p>
<ul>
  <li><a href="/api/audit?q=health">Audit search</a></li>
  <li><a href="/exports?file=reports/summary.txt">Export summary</a></li>
</ul>
"""


def _content_length(handler: BaseHTTPRequestHandler) -> int:
    raw = handler.headers.get("Content-Length", "0")
    try:
        return max(0, min(int(raw), 8192))
    except ValueError:
        return 0


if __name__ == "__main__":
    init_db()
    ThreadingHTTPServer(("0.0.0.0", PORT), PerimeterHandler).serve_forever()
