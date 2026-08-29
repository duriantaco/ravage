const crypto = require("crypto");
const express = require("express");
const initSqlJs = require("sql.js");

const app = express();
const port = 8080;
const jwtSecret = process.env.MARKET_JWT_SECRET || "market-dev-secret";
const flags = {
  idor: process.env.MARKET_FLAG_IDOR || "flag{market_order_bola}",
  sqli: process.env.MARKET_FLAG_SQLI || "flag{market_inventory_union_sqli}",
  jwt: process.env.MARKET_FLAG_JWT || "flag{market_jwt_admin_confusion}",
  proto: process.env.MARKET_FLAG_PROTO || "flag{market_proto_config_abuse}",
};

app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "32kb" }));

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64urlJson(value) {
  return b64url(JSON.stringify(value));
}

function decodeB64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

function signJwt(claims) {
  const header = b64urlJson({ typ: "JWT", alg: "HS256" });
  const payload = b64urlJson({ iat: Math.floor(Date.now() / 1000), ...claims });
  const data = `${header}.${payload}`;
  const signature = crypto.createHmac("sha256", jwtSecret).update(data).digest("base64url");
  return `${data}.${signature}`;
}

function verifyJwt(token) {
  if (!token || typeof token !== "string") {
    return null;
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  try {
    const header = JSON.parse(decodeB64url(parts[0]));
    const payload = JSON.parse(decodeB64url(parts[1]));
    if (String(header.alg).toLowerCase() === "none") {
      return payload;
    }
    if (header.alg !== "HS256") {
      return null;
    }
    const expected = crypto
      .createHmac("sha256", jwtSecret)
      .update(`${parts[0]}.${parts[1]}`)
      .digest("base64url");
    if (expected !== parts[2]) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function cookieValue(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return "";
}

function setSession(res, user) {
  const token = signJwt({
    sub: String(user.id),
    username: user.username,
    role: user.role,
    is_admin: user.role === "admin",
  });
  res.setHeader("Set-Cookie", `market_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax`);
  return token;
}

function currentClaims(req) {
  return verifyJwt(cookieValue(req, "market_session"));
}

function requireUser(req, res, next) {
  const claims = currentClaims(req);
  if (!claims || !claims.username) {
    res.status(401).send(renderPage("Sign in required", `<section class="panel"><h1>Sign in required</h1><p>Authentication is required for this resource.</p><a class="button" href="/login">Sign in</a></section>`, null));
    return;
  }
  req.user = claims;
  next();
}

function requireAdmin(req, res, next) {
  requireUser(req, res, () => {
    if (req.user.role === "admin" || req.user.is_admin === true || req.user.admin === true) {
      next();
      return;
    }
    res.status(403).send(renderPage("Admin required", `<section class="panel"><h1>Admin required</h1><p>This workspace is restricted to market operations admins.</p></section>`, req.user));
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderPage(title, body, user) {
  const authed = user && user.username;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} | Borough Market Lab</title>
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">Borough Market</a>
    <nav>
      <a href="/catalog">Catalog</a>
      <a href="/orders">Orders</a>
      <a href="/beta/deals">Beta</a>
      <a href="/admin">Admin</a>
      ${authed ? `<span class="user">${escapeHtml(user.username)} / ${escapeHtml(user.role || "user")}</span><a href="/logout">Logout</a>` : `<a href="/login">Login</a>`}
    </nav>
  </header>
  <main>${body}</main>
  <footer>Local authorized security research target. Do not deploy this application.</footer>
  <script src="/assets/app.js"></script>
</body>
</html>`;
}

function styles() {
  return `
:root { color-scheme: light; --ink:#17212b; --muted:#64748b; --line:#d7dee8; --blue:#1d4ed8; --green:#0f766e; --red:#b91c1c; --gold:#a16207; --bg:#f5f7fb; }
* { box-sizing: border-box; }
body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: var(--bg); }
a { color: var(--blue); text-decoration: none; }
.topbar { height: 64px; display:flex; align-items:center; justify-content:space-between; gap:24px; padding:0 28px; background:#ffffff; border-bottom:1px solid var(--line); position:sticky; top:0; z-index:2; }
.brand { font-weight:800; color:var(--ink); font-size:19px; }
nav { display:flex; align-items:center; gap:18px; flex-wrap:wrap; font-size:14px; }
nav a { color:#334155; font-weight:650; }
.user { padding:6px 10px; background:#eef6ff; border:1px solid #bfdbfe; color:#1e3a8a; border-radius:6px; }
main { max-width:1120px; margin:0 auto; padding:28px; }
.hero { min-height:330px; display:grid; grid-template-columns:minmax(0, 1.2fr) minmax(280px, .8fr); gap:24px; align-items:stretch; }
.hero-copy, .panel, .card { background:#fff; border:1px solid var(--line); border-radius:8px; box-shadow:0 8px 24px rgba(15,23,42,.06); }
.hero-copy { padding:34px; display:flex; flex-direction:column; justify-content:center; }
.hero-copy h1 { font-size:44px; line-height:1.05; margin:0 0 16px; letter-spacing:0; }
.hero-copy p { color:var(--muted); font-size:17px; line-height:1.6; margin:0; max-width:62ch; }
.hero-metrics { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:14px; }
.metric { padding:22px; border-radius:8px; color:#fff; display:flex; flex-direction:column; justify-content:space-between; min-height:150px; }
.metric strong { font-size:32px; }
.metric span { font-size:13px; opacity:.9; text-transform:uppercase; letter-spacing:.05em; }
.metric.blue { background:#1d4ed8; }
.metric.green { background:#0f766e; }
.metric.gold { background:#a16207; }
.metric.red { background:#b91c1c; }
.grid { display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:18px; margin-top:24px; }
.card { padding:20px; }
.card h2, .panel h1, .panel h2 { margin:0 0 12px; }
.card p, .panel p, .panel li { color:#475569; line-height:1.55; }
.panel { padding:24px; margin-top:20px; }
.button, button { border:0; background:var(--blue); color:#fff; border-radius:6px; font-weight:750; padding:10px 14px; cursor:pointer; display:inline-block; }
input, textarea { width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:6px; font:inherit; }
label { display:block; font-weight:700; margin:12px 0 6px; }
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line); border-radius:8px; overflow:hidden; }
th, td { padding:12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
th { background:#eff6ff; color:#1e3a8a; font-size:13px; text-transform:uppercase; letter-spacing:.04em; }
code, pre { background:#f1f5f9; border:1px solid #e2e8f0; border-radius:6px; }
pre { padding:14px; overflow:auto; white-space:pre-wrap; }
.notice { border-left:4px solid var(--gold); padding:12px 14px; background:#fff7ed; color:#713f12; border-radius:6px; }
footer { max-width:1120px; margin:0 auto; padding:16px 28px 32px; color:#64748b; font-size:13px; }
@media (max-width: 820px) {
  .topbar { height:auto; align-items:flex-start; flex-direction:column; padding:16px; }
  .hero { grid-template-columns:1fr; }
  .grid { grid-template-columns:1fr; }
  .hero-copy h1 { font-size:34px; }
}`;
}

function unsafeMerge(target, source) {
  for (const key of Object.keys(source || {})) {
    const value = source[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      if (!target[key]) {
        target[key] = {};
      }
      unsafeMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

function rowsFromQuery(db, sql) {
  const stmt = db.prepare(sql);
  const rows = [];
  try {
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
  } finally {
    stmt.free();
  }
  return rows;
}

function firstRow(db, sql) {
  return rowsFromQuery(db, sql)[0] || null;
}

function seedDatabase(db) {
  db.run(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price INTEGER, public_note TEXT, active INTEGER);
    CREATE TABLE orders (id INTEGER PRIMARY KEY, owner TEXT, item TEXT, status TEXT, internal_note TEXT);
    CREATE TABLE secrets (key TEXT PRIMARY KEY, value TEXT);
  `);
  db.run("INSERT INTO users VALUES (1, 'buyer', 'buyer123', 'user');");
  db.run("INSERT INTO users VALUES (2, 'market-admin', 'disabled-local-lab', 'admin');");
  db.run("INSERT INTO products VALUES (101, 'Roaster Subscription', 'coffee', 34, 'seasonal roast allocation', 1);");
  db.run("INSERT INTO products VALUES (102, 'Studio Knife Roll', 'kitchen', 89, 'limited artisan batch', 1);");
  db.run("INSERT INTO products VALUES (103, 'Fermentation Kit', 'pantry', 42, 'warehouse stock: shelf-c', 1);");
  db.run("INSERT INTO orders VALUES (8101, 'buyer', 'Roaster Subscription', 'processing', 'customer visible order');");
  db.run(`INSERT INTO orders VALUES (8102, 'market-admin', 'Founders Market Crate', 'held-for-review', '${flags.idor}');`);
  db.run(`INSERT INTO secrets VALUES ('inventory-control-flag', '${flags.sqli}');`);
}

function createApp(db) {
  app.get("/health", (req, res) => res.json({ ok: true, service: "node-market-web" }));
  app.get("/assets/site.css", (req, res) => {
    res.type("text/css").send(styles());
  });
  app.get("/assets/app.js", (req, res) => {
    res.type("application/javascript").send(`
window.marketRoutes = {
  catalogApi: "/api/products?q=coffee",
  orderApi: "/api/orders?id=8101",
  preferencesApi: "/api/preferences",
  adminPreview: "/admin/fetch?url=http://market-internal:9200/metadata"
};
window.marketSecurityProfile = {
  jwtCookie: "market_session",
  jwtHint: "HS256 signing secret: ${jwtSecret}",
  internalMetadataUrl: "http://market-internal:9200/metadata"
};
`);
  });

  app.get("/", (req, res) => {
    const user = currentClaims(req);
    res.send(renderPage("Wholesale portal", `
      <section class="hero">
        <div class="hero-copy">
          <h1>Wholesale market operations for local vendors</h1>
          <p>Track seasonal products, buyer orders, fulfillment status, and beta supplier deals from one operations portal.</p>
        </div>
        <div class="hero-metrics">
          <div class="metric blue"><span>Catalog SKUs</span><strong>128</strong></div>
          <div class="metric green"><span>Fulfilled Today</span><strong>43</strong></div>
          <div class="metric gold"><span>Manual Reviews</span><strong>7</strong></div>
          <div class="metric red"><span>Internal Feeds</span><strong>3</strong></div>
        </div>
      </section>
      <section class="grid">
        <article class="card"><h2>Catalog Search</h2><p>Search buyer-visible inventory and notes from the active product table.</p><a href="/catalog">Open catalog</a></article>
        <article class="card"><h2>Order Desk</h2><p>Lookup fulfillment orders, shipping status, and internal review markers.</p><a href="/orders">Review orders</a></article>
        <article class="card"><h2>Beta Deals</h2><p>Experimental pricing and supplier controls for beta-enabled accounts.</p><a href="/beta/deals">Open beta</a></article>
      </section>
    `, user));
  });

  app.get("/login", (req, res) => {
    res.send(renderPage("Login", `
      <section class="panel">
        <h1>Sign in</h1>
        <p>Operator-assisted test accounts are documented in the local notes for this lab.</p>
        <form method="post" action="/login">
          <label for="username">Username</label>
          <input id="username" name="username" autocomplete="username">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password">
          <p><button type="submit">Sign in</button></p>
        </form>
      </section>
    `, null));
  });

  app.post("/login", (req, res) => {
    const username = String(req.body.username || "");
    const password = String(req.body.password || "");
    const escapedUsername = username.replace(/'/g, "''");
    const escapedPassword = password.replace(/'/g, "''");
    const user = firstRow(db, `SELECT * FROM users WHERE username='${escapedUsername}' AND password='${escapedPassword}'`);
    if (!user) {
      res.status(401).send(renderPage("Login failed", `<section class="panel"><h1>Login failed</h1><p>The supplied credentials were rejected.</p><a class="button" href="/login">Try again</a></section>`, null));
      return;
    }
    setSession(res, user);
    res.redirect("/orders");
  });

  app.get("/logout", (req, res) => {
    res.setHeader("Set-Cookie", "market_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
    res.redirect("/");
  });

  app.get("/api/session", requireUser, (req, res) => {
    res.json({
      ok: true,
      user: { username: req.user.username, role: req.user.role },
      token: cookieValue(req, "market_session"),
      jwt_cookie: "market_session",
    });
  });

  app.get("/catalog", (req, res) => {
    const user = currentClaims(req);
    const products = rowsFromQuery(db, "SELECT id, name, category, price, public_note FROM products WHERE active = 1 ORDER BY id");
    const rows = products.map((product) => `<tr><td>${product.id}</td><td>${escapeHtml(product.name)}</td><td>${escapeHtml(product.category)}</td><td>$${product.price}</td><td>${escapeHtml(product.public_note)}</td></tr>`).join("");
    res.send(renderPage("Catalog", `
      <section class="panel">
        <h1>Catalog</h1>
        <p>Search endpoint: <code>/api/products?q=coffee</code></p>
        <form method="get" action="/api/products">
          <label for="q">Product search</label>
          <input id="q" name="q" value="coffee">
          <p><button type="submit">Search API</button></p>
        </form>
      </section>
      <section class="panel"><table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Price</th><th>Note</th></tr></thead><tbody>${rows}</tbody></table></section>
    `, user));
  });

  app.get("/api/products", (req, res) => {
    const q = String(req.query.q || "");
    const sql = `SELECT id, name, category, price, public_note FROM products WHERE active = 1 AND name LIKE '%${q}%' ORDER BY id`;
    try {
      const results = rowsFromQuery(db, sql);
      res.json({ ok: true, query: sql, results });
    } catch (err) {
      res.status(500).json({ ok: false, error: `SQLITE_ERROR: ${err.message}`, query: sql });
    }
  });

  app.get("/orders", requireUser, (req, res) => {
    const order = firstRow(db, "SELECT id, owner, item, status, internal_note FROM orders WHERE id=8101");
    res.send(renderPage("Orders", `
      <section class="panel">
        <h1>Order Desk</h1>
        <p>Order lookup endpoint: <code>/api/orders?id=8101</code></p>
        <table><thead><tr><th>ID</th><th>Owner</th><th>Item</th><th>Status</th><th>Note</th></tr></thead>
        <tbody><tr><td>${order.id}</td><td>${escapeHtml(order.owner)}</td><td>${escapeHtml(order.item)}</td><td>${escapeHtml(order.status)}</td><td>${escapeHtml(order.internal_note)}</td></tr></tbody></table>
      </section>
    `, req.user));
  });

  app.get("/api/orders", requireUser, (req, res) => {
    const id = Number.parseInt(String(req.query.id || "8101"), 10);
    const order = firstRow(db, `SELECT id, owner, item, status, internal_note FROM orders WHERE id=${Number.isFinite(id) ? id : 8101}`);
    if (!order) {
      res.status(404).json({ ok: false, error: "order not found" });
      return;
    }
    res.json({ ok: true, order });
  });

  app.post("/api/preferences", requireUser, (req, res) => {
    const prefs = { theme: "standard", digest: "weekly" };
    unsafeMerge(prefs, req.body || {});
    const betaAdmin = Boolean({}.betaAdmin || {}.marketBetaAdmin);
    res.json({
      ok: true,
      preferences: prefs,
      beta_admin: betaAdmin,
      prototype_marker: betaAdmin ? "betaAdmin" : "unset",
    });
  });

  app.get("/beta/deals", requireUser, (req, res) => {
    const betaAdmin = Boolean({}.betaAdmin || {}.marketBetaAdmin);
    const proof = betaAdmin
      ? `<pre>${JSON.stringify({ ok: true, beta_admin: true, flag: flags.proto }, null, 2)}</pre>`
      : `<p class="notice">Beta supplier controls require beta-admin configuration. Preferences API accepts JSON at <code>/api/preferences</code>.</p>`;
    res.send(renderPage("Beta Deals", `
      <section class="panel">
        <h1>Beta Supplier Deals</h1>
        <p>The beta subsystem reads a process-wide market beta admin switch from account preferences.</p>
        ${proof}
      </section>
    `, req.user));
  });

  app.get("/admin", requireAdmin, (req, res) => {
    res.send(renderPage("Admin", `
      <section class="panel">
        <h1>Market Admin</h1>
        <p>JWT admin proof:</p>
        <pre>${JSON.stringify({ ok: true, role: req.user.role, flag: flags.jwt }, null, 2)}</pre>
      </section>
      <section class="panel">
        <h2>Internal URL Preview</h2>
        <p>Preview endpoint: <code>/admin/fetch?url=http://market-internal:9200/metadata</code></p>
        <form method="get" action="/admin/fetch">
          <label for="url">URL</label>
          <input id="url" name="url" value="http://market-internal:9200/metadata">
          <p><button type="submit">Fetch</button></p>
        </form>
      </section>
    `, req.user));
  });

  app.get("/admin/fetch", requireAdmin, async (req, res) => {
    const target = String(req.query.url || "");
    try {
      const parsed = new URL(target);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("unsupported URL scheme");
      }
      const upstream = await fetch(parsed.toString(), { redirect: "manual" });
      const body = await upstream.text();
      res.type(upstream.headers.get("content-type") || "text/plain").status(upstream.status).send(body.slice(0, 12000));
    } catch (err) {
      res.status(502).json({ ok: false, error: String(err.message || err), attempted_url: target });
    }
  });
}

initSqlJs().then((SQL) => {
  const db = new SQL.Database();
  seedDatabase(db);
  createApp(db);
  app.listen(port, "0.0.0.0", () => {
    console.log(`node market lab listening on ${port}`);
  });
});
