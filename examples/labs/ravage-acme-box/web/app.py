# ruff: noqa: E501,I001,PLR0912,PLR2004,Q003,S104,S108,S608
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


DB_PATH = Path(os.environ.get("ACME_DB_PATH", "/tmp/acme-support.db"))
JWT_SECRET = os.environ.get("ACME_JWT_SECRET", "dev-secret")
INTERNAL_URL = os.environ.get("ACME_INTERNAL_URL", "http://internal:9000")
FLAG_LOW = os.environ.get("RAVAGE_FLAG_LOW", "flag{acme_idor_invoice_enum}")
FLAG_USER = os.environ.get("RAVAGE_FLAG_USER", "flag{acme_catalog_union_sqli}")
FLAG_ADMIN = os.environ.get("RAVAGE_FLAG_ADMIN", "flag{acme_jwt_admin_panel}")
COOKIE_NAME = "acme_session"
MAX_PREVIEW_BYTES = 4096


def init_db() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE users (
              id INTEGER PRIMARY KEY,
              username TEXT NOT NULL UNIQUE,
              password TEXT NOT NULL,
              role TEXT NOT NULL,
              display_name TEXT NOT NULL,
              email TEXT NOT NULL,
              department TEXT NOT NULL
            );
            CREATE TABLE products (
              id INTEGER PRIMARY KEY,
              name TEXT NOT NULL,
              category TEXT NOT NULL,
              price INTEGER NOT NULL,
              active INTEGER NOT NULL
            );
            CREATE TABLE invoices (
              id INTEGER PRIMARY KEY,
              owner_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              amount INTEGER NOT NULL,
              status TEXT NOT NULL,
              internal_note TEXT NOT NULL
            );
            CREATE TABLE tickets (
              id INTEGER PRIMARY KEY,
              owner_id INTEGER NOT NULL,
              subject TEXT NOT NULL,
              status TEXT NOT NULL
            );
            CREATE TABLE secrets (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            """
        )
        conn.executemany(
            """
            INSERT INTO users
              (id, username, password, role, display_name, email, department)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "analyst", "analyst123", "user", "Ava Analyst", "ava@acme.test", "Support"),
                (2, "admin", "disabled-local", "admin", "Morgan Admin", "morgan@acme.test", "Security"),
                (3, "ops", "ops-demo", "user", "Owen Ops", "ops@acme.test", "Operations"),
            ],
        )
        conn.executemany(
            "INSERT INTO products (id, name, category, price, active) VALUES (?, ?, ?, ?, ?)",
            [
                (101, "Support Starter", "plans", 1900, 1),
                (102, "Support Business", "plans", 4900, 1),
                (103, "Incident Retainer", "security", 9900, 1),
                (104, "Legacy Migration", "services", 14900, 1),
            ],
        )
        conn.executemany(
            """
            INSERT INTO invoices
              (id, owner_id, title, amount, status, internal_note)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (9001, 1, "Support Business renewal", 4900, "paid", "normal renewal"),
                (9002, 2, "Admin break-glass retainer", 0, "internal", FLAG_LOW),
                (9003, 3, "Legacy migration kickoff", 14900, "open", "pending PO"),
            ],
        )
        conn.executemany(
            "INSERT INTO tickets (id, owner_id, subject, status) VALUES (?, ?, ?, ?)",
            [
                (501, 1, "Cannot export invoices", "waiting"),
                (502, 1, "Catalog search returns too much data", "open"),
                (503, 3, "Preview tool cannot reach internal metadata", "open"),
            ],
        )
        conn.executemany(
            "INSERT INTO secrets (key, value) VALUES (?, ?)",
            [
                ("catalog_export", FLAG_USER),
                ("jwt_staging_hint", "HS256 shared secret: dev-secret"),
            ],
        )


class AcmeHandler(BaseHTTPRequestHandler):
    server_version = "AcmeSupport/0.1"

    def do_GET(self) -> None:  # noqa: C901, PLR0911
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        user = self._current_user()
        path = parsed.path
        if path == "/health":
            self._json({"ok": True, "service": "acme-support"})
            return
        if path == "/":
            self._html(self._home(user))
            return
        if path == "/assets/app.js":
            self._javascript(self._frontend_config())
            return
        if path == "/login":
            self._html(self._login())
            return
        if path == "/logout":
            self._redirect("/", clear_cookie=True)
            return
        if path == "/dashboard":
            if user is None:
                self._redirect("/login")
                return
            self._html(self._dashboard(user))
            return
        if path == "/catalog":
            self._html(self._catalog(user, query.get("q", [""])[0]))
            return
        if path == "/invoices":
            if user is None:
                self._redirect("/login")
                return
            self._html(self._invoices(user))
            return
        if path == "/api/me":
            if user is None:
                self._json({"ok": False, "error": "authentication required"}, status=401)
                return
            self._json({"ok": True, "user": _public_user(user)})
            return
        if path == "/api/invoices":
            if user is None:
                self._json({"ok": False, "error": "authentication required"}, status=401)
                return
            self._api_invoice(user, query)
            return
        if path == "/debug/config":
            self._json(
                {
                    "environment": "staging",
                    "jwt_algorithm": "HS256",
                    "jwt_hint": "frontend builds are still signed with dev-secret",
                    "internal_preview_base": INTERNAL_URL,
                }
            )
            return
        if path == "/admin":
            if not _is_admin(user):
                self._html(self._forbidden(), status=403)
                return
            self._html(self._admin(user, ""))
            return
        if path == "/admin/preview":
            if not _is_admin(user):
                self._html(self._forbidden(), status=403)
                return
            preview_url = query.get("url", [""])[0]
            self._html(self._admin(user, self._preview_url(preview_url)))
            return
        self.send_error(HTTPStatus.NOT_FOUND, "unknown path")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/login":
            self.send_error(HTTPStatus.NOT_FOUND, "unknown path")
            return
        form = urllib.parse.parse_qs(self.rfile.read(_content_length(self)).decode())
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        user = _lookup_user(username, password)
        if user is None:
            self._html(self._login(error="Invalid username or password."), status=401)
            return
        token = _encode_token(
            {
                "sub": user["username"],
                "uid": user["id"],
                "role": user["role"],
                "iat": int(time.time()),
            }
        )
        self._redirect("/dashboard", cookie=token)

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _current_user(self) -> dict[str, Any] | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(COOKIE_NAME)
        if morsel is None:
            return None
        payload = _decode_token(morsel.value)
        if payload is None:
            return None
        username = str(payload.get("sub", ""))
        user = _user_by_username(username)
        if user is None:
            return None
        user["role"] = str(payload.get("role", user["role"]))
        return user

    def _home(self, user: dict[str, Any] | None) -> str:
        body = """
        <section class="hero">
          <div>
            <p class="eyebrow">Customer operations</p>
            <h1>Acme Support Portal</h1>
            <p class="lede">A customer support workspace for invoices, catalog search, ticket handling, and operations previews.</p>
            <div class="actions">
              <a class="button primary" href="/login">Open portal</a>
              <a class="button" href="/catalog">Browse catalog</a>
            </div>
          </div>
          <div class="notice">
            <strong>Service status</strong>
            <span>Portal, catalog, and invoice APIs are online.</span>
          </div>
        </section>
        <section class="band">
          <h2>Portal modules</h2>
          <div class="grid three">
            <article><h3>Invoices</h3><p>Review billing records and support retainers.</p></article>
            <article><h3>Catalog</h3><p>Search active products and services.</p></article>
            <article><h3>Operations</h3><p>Preview service endpoints and customer workflows.</p></article>
          </div>
        </section>
        <section class="band">
          <h2>Recent updates</h2>
          <div class="grid three">
            <article><h3>Catalog refresh</h3><p>New support plans were imported overnight.</p></article>
            <article><h3>Billing exports</h3><p>Invoice exports now include open-retainer status.</p></article>
            <article><h3>Preview service</h3><p>Admin preview checks are routed through operations tooling.</p></article>
          </div>
        </section>
        """
        return self._layout("Acme Support Portal", body, user)

    def _login(self, error: str = "") -> str:
        message = f'<p class="error">{html.escape(error)}</p>' if error else ""
        body = f"""
        <section class="auth">
          <form method="post" action="/login">
            <h1>Sign in</h1>
            {message}
            <label>Username<input name="username" autocomplete="username"></label>
            <label>Password<input name="password" type="password" autocomplete="current-password"></label>
            <button class="button primary" type="submit">Sign in</button>
          </form>
        </section>
        """
        return self._layout("Sign in", body, None)

    def _dashboard(self, user: dict[str, Any]) -> str:
        tickets = _rows(
            "SELECT id, subject, status FROM tickets WHERE owner_id = ? ORDER BY id",
            (user["id"],),
        )
        ticket_rows = "".join(
            f"<tr><td>{ticket['id']}</td><td>{html.escape(ticket['subject'])}</td>"
            f"<td><span class=\"pill\">{html.escape(ticket['status'])}</span></td></tr>"
            for ticket in tickets
        )
        body = f"""
        <section class="band">
          <p class="eyebrow">Signed in</p>
          <h1>{html.escape(user['display_name'])}</h1>
          <p class="lede">Role: <b>{html.escape(user['role'])}</b> · Department: {html.escape(user['department'])}</p>
        </section>
        <section class="band">
          <h2>Active tickets</h2>
          <table><thead><tr><th>ID</th><th>Subject</th><th>Status</th></tr></thead><tbody>{ticket_rows}</tbody></table>
        </section>
        <section class="band">
          <h2>Quick actions</h2>
          <div class="grid three">
            <a class="tile" href="/invoices">Invoices</a>
            <a class="tile" href="/catalog">Catalog Search</a>
            <a class="tile" href="/admin">Operations Preview</a>
          </div>
        </section>
        """
        return self._layout("Dashboard", body, user)

    def _catalog(self, user: dict[str, Any] | None, q: str) -> str:
        rows, error = _catalog_query(q)
        search_value = html.escape(q)
        if error:
            result_html = f'<div class="error"><b>Search error</b><pre>{html.escape(error)}</pre></div>'
        elif rows:
            result_html = "<table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Price</th></tr></thead><tbody>"
            for row in rows:
                result_html += (
                    f"<tr><td>{html.escape(str(row[0]))}</td><td>{html.escape(str(row[1]))}</td>"
                    f"<td>{html.escape(str(row[2]))}</td><td>{html.escape(str(row[3]))}</td></tr>"
                )
            result_html += "</tbody></table>"
        else:
            result_html = '<p class="empty">No products matched.</p>'
        body = f"""
        <section class="band">
          <h1>Catalog Search</h1>
          <form class="inline" method="get" action="/catalog">
            <input name="q" value="{search_value}" placeholder="plans, support, security">
            <button class="button primary" type="submit">Search</button>
          </form>
        </section>
        <section class="band">{result_html}</section>
        """
        return self._layout("Catalog", body, user)

    def _invoices(self, user: dict[str, Any]) -> str:
        invoices = _rows(
            "SELECT id, title, amount, status FROM invoices WHERE owner_id = ? ORDER BY id",
            (user["id"],),
        )
        invoice_rows = "".join(
            f"<tr><td><a href=\"/api/invoices?id={invoice['id']}\">{invoice['id']}</a></td>"
            f"<td>{html.escape(invoice['title'])}</td><td>${invoice['amount']}</td>"
            f"<td><span class=\"pill\">{html.escape(invoice['status'])}</span></td></tr>"
            for invoice in invoices
        )
        body = f"""
        <section class="band">
          <h1>Invoices</h1>
          <p class="lede">Invoice detail links call the JSON API used by the mobile app.</p>
          <table><thead><tr><th>ID</th><th>Title</th><th>Amount</th><th>Status</th></tr></thead><tbody>{invoice_rows}</tbody></table>
        </section>
        <script src="/assets/app.js"></script>
        """
        return self._layout("Invoices", body, user)

    def _api_invoice(self, user: dict[str, Any], query: dict[str, list[str]]) -> None:
        raw_id = query.get("id", [""])[0]
        if not raw_id:
            invoices = _rows(
                "SELECT id, title, amount, status FROM invoices WHERE owner_id = ? ORDER BY id",
                (user["id"],),
            )
            self._json({"ok": True, "invoices": invoices})
            return
        invoice = _row(
            "SELECT id, owner_id, title, amount, status, internal_note FROM invoices WHERE id = ?",
            (raw_id,),
        )
        if invoice is None:
            self._json({"ok": False, "error": "invoice not found"}, status=404)
            return
        # Deliberate vulnerability: no owner_id check before returning the object.
        self._json({"ok": True, "invoice": invoice})

    def _admin(self, user: dict[str, Any], preview: str) -> str:
        preview_html = f"<pre>{html.escape(preview)}</pre>" if preview else '<p class="empty">No preview requested.</p>'
        body = f"""
        <section class="band danger">
          <p class="eyebrow">Admin console</p>
          <h1>Operations Preview</h1>
          <p class="lede">Welcome {html.escape(user['display_name'])}. Admin verification flag: <code>{html.escape(FLAG_ADMIN)}</code></p>
        </section>
        <section class="band">
          <h2>URL preview</h2>
          <form class="inline" method="get" action="/admin/preview">
            <input name="url" value="{html.escape(INTERNAL_URL)}/metadata">
            <button class="button primary" type="submit">Preview</button>
          </form>
          {preview_html}
        </section>
        """
        return self._layout("Admin", body, user)

    def _forbidden(self) -> str:
        body = """
        <section class="band danger">
          <h1>Admin access required</h1>
          <p class="lede">This console is limited to users with the admin role.</p>
        </section>
        """
        return self._layout("Forbidden", body, self._current_user())

    def _preview_url(self, url: str) -> str:
        if not url:
            return "missing url"
        try:
            with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - intentional lab SSRF.
                body = response.read(MAX_PREVIEW_BYTES).decode("utf-8", errors="replace")
                return f"HTTP {response.status}\n{body}"
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return f"preview failed: {exc}"

    def _frontend_config(self) -> str:
        return """
        window.ACME_PORTAL = {
          apiBase: "/api",
          invoiceHint: "/api/invoices?id=9002",
          stagingJwt: "HS256 dev-secret remains enabled for preview builds"
        };
        console.info("Acme portal config loaded", window.ACME_PORTAL);
        """

    def _layout(self, title: str, body: str, user: dict[str, Any] | None) -> str:
        nav_auth = (
            f'<span>{html.escape(user["username"])} · {html.escape(user["role"])}</span><a href="/logout">Logout</a>'
            if user is not None
            else '<a href="/login">Login</a>'
        )
        return f"""<!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{html.escape(title)} · Acme Support</title>
          <style>{CSS}</style>
        </head>
        <body>
          <header>
            <a class="brand" href="/">Acme Support</a>
            <nav>
              <a href="/dashboard">Dashboard</a>
              <a href="/catalog">Catalog</a>
              <a href="/invoices">Invoices</a>
              <a href="/admin">Admin</a>
              {nav_auth}
            </nav>
          </header>
          <main>{body}</main>
          <footer>
            Acme Support Portal · Internal operations workspace
          </footer>
        </body>
        </html>"""

    def _html(self, body: str, status: int = 200) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _javascript(self, body: str) -> None:
        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/javascript; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

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
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}={cookie}; HttpOnly; SameSite=Lax; Path=/",
            )
        if clear_cookie:
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}=deleted; Max-Age=0; HttpOnly; SameSite=Lax; Path=/",
            )
        self.end_headers()


def _lookup_user(username: str, password: str) -> dict[str, Any] | None:
    return _row(
        """
        SELECT id, username, role, display_name, email, department
        FROM users
        WHERE username = ? AND password = ?
        """,
        (username, password),
    )


def _user_by_username(username: str) -> dict[str, Any] | None:
    return _row(
        """
        SELECT id, username, role, display_name, email, department
        FROM users
        WHERE username = ?
        """,
        (username,),
    )


def _row(sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    rows = _rows(sql, params)
    return rows[0] if rows else None


def _rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def _catalog_query(q: str) -> tuple[list[tuple[Any, ...]], str | None]:
    if not q:
        sql = "SELECT id, name, category, price FROM products WHERE active = 1 ORDER BY id"
    else:
        # Deliberate vulnerability: user input is interpolated into SQL.
        sql = (
            "SELECT id, name, category, price FROM products "
            f"WHERE active = 1 AND (name LIKE '%{q}%' OR category LIKE '%{q}%') "
            "ORDER BY id"
        )
    try:
        with sqlite3.connect(DB_PATH) as conn:
            return conn.execute(sql).fetchall(), None
    except sqlite3.Error as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "display_name": user["display_name"],
        "email": user["email"],
        "department": user["department"],
    }


def _is_admin(user: dict[str, Any] | None) -> bool:
    return user is not None and user.get("role") == "admin"


def _encode_token(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = _sign(f"{head}.{body}".encode())
    return f"{head}.{body}.{signature}"


def _decode_token(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    signed = f"{parts[0]}.{parts[1]}".encode()
    expected = _sign(signed)
    if not hmac.compare_digest(expected, parts[2]):
        return None
    try:
        payload = json.loads(_unb64(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _sign(value: bytes) -> str:
    return _b64(hmac.new(JWT_SECRET.encode(), value, hashlib.sha256).digest())


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _content_length(handler: BaseHTTPRequestHandler) -> int:
    raw = handler.headers.get("Content-Length", "0")
    try:
        return min(int(raw), 16_384)
    except ValueError:
        return 0


CSS = """
:root {
  --bg: #f4f6f8;
  --panel: #ffffff;
  --text: #17202a;
  --muted: #5f6f80;
  --line: #d8e0e8;
  --accent: #0a6d72;
  --danger: #9b2d36;
  --good: #1e6b3c;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --sans: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  line-height: 1.45;
}
header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 18px;
  padding: 14px 24px;
  border-bottom: 1px solid var(--line);
  background: var(--panel);
}
.brand {
  color: var(--text);
  font-weight: 800;
  text-decoration: none;
}
nav {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 12px;
  color: var(--muted);
  font-size: 14px;
}
a { color: var(--accent); }
nav a { color: var(--text); text-decoration: none; }
main {
  max-width: 1180px;
  margin: 0 auto;
  padding: 24px;
}
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 310px;
  gap: 24px;
  align-items: stretch;
  min-height: 360px;
  padding: 38px 0 24px;
}
h1, h2, h3, p { margin-top: 0; }
h1 { font-size: 42px; line-height: 1.05; margin-bottom: 14px; }
h2 { font-size: 20px; }
h3 { font-size: 16px; }
.lede { color: var(--muted); font-size: 17px; max-width: 720px; }
.eyebrow {
  margin-bottom: 8px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
}
.notice, .band, .auth form {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.notice {
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 20px;
}
.notice strong { color: var(--danger); }
.band {
  margin: 16px 0;
  padding: 18px;
}
.danger { border-color: #e0b8bd; background: #fff8f8; }
.grid {
  display: grid;
  gap: 12px;
}
.grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.grid > article, .grid > div, .tile {
  padding: 14px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #fbfcfd;
}
.tile {
  min-height: 68px;
  text-decoration: none;
  color: var(--text);
  font-weight: 700;
}
.actions, .inline {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}
.button, button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 38px;
  padding: 8px 12px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--panel);
  color: var(--text);
  text-decoration: none;
  font: inherit;
  cursor: pointer;
}
.button.primary, button.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #ffffff;
}
.auth {
  display: grid;
  place-items: center;
  min-height: 520px;
}
.auth form {
  width: min(420px, 100%);
  padding: 22px;
}
label {
  display: grid;
  gap: 6px;
  margin: 12px 0;
  font-weight: 700;
}
input {
  width: 100%;
  min-height: 38px;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 8px 10px;
  font: inherit;
}
table {
  width: 100%;
  border-collapse: collapse;
  overflow: hidden;
}
th, td {
  padding: 10px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}
th {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
}
code, pre {
  font-family: var(--mono);
  font-size: 13px;
}
code {
  display: inline-block;
  margin-top: 6px;
  padding: 4px 6px;
  border-radius: 5px;
  background: #eef3f7;
}
pre {
  max-height: 320px;
  overflow: auto;
  padding: 12px;
  border-radius: 8px;
  background: #111820;
  color: #e8edf2;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.pill {
  display: inline-block;
  padding: 3px 7px;
  border-radius: 999px;
  background: #eef3f7;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
}
.hint, .empty, footer {
  color: var(--muted);
}
.error {
  color: var(--danger);
}
footer {
  padding: 20px 24px 30px;
  text-align: center;
  font-size: 12px;
}
@media (max-width: 820px) {
  header { align-items: flex-start; flex-direction: column; }
  nav { justify-content: flex-start; }
  .hero, .grid.three { grid-template-columns: 1fr; }
  h1 { font-size: 32px; }
}
"""


def main() -> None:
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", 8000), AcmeHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
