const http = require("http");

const port = 9200;
const rootFlag = process.env.MARKET_FLAG_ROOT || "flag{market_internal_admin_pivot}";

function json(res, status, body) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(body, null, 2));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "market-internal"}`);
  if (url.pathname === "/health") {
    json(res, 200, { ok: true, service: "market-internal" });
    return;
  }
  if (url.pathname === "/metadata") {
    json(res, 200, {
      ok: true,
      service: "warehouse-metadata",
      environment: "local-lab",
      next_url: "http://market-internal:9200/flag",
      flag_endpoint: "/flag",
    });
    return;
  }
  if (url.pathname === "/flag") {
    json(res, 200, {
      ok: true,
      proof_category: "internal-admin-pivot",
      flag: rootFlag,
    });
    return;
  }
  json(res, 404, { ok: false, error: "not found" });
});

server.listen(port, "0.0.0.0", () => {
  console.log(`market-internal listening on ${port}`);
});
