package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type user struct {
	ID          string
	Username    string
	DisplayName string
	Password    string
	Role        string
	Team        string
}

type app struct {
	jwtSecret     string
	flagIDOR      string
	flagQuery     string
	flagJWT       string
	flagTraversal string
	flagCommand   string
	artifactDir   string
	users         map[string]user
}

func main() {
	a := &app{
		jwtSecret:     env("FORGEOPS_JWT_SECRET", "local-secret"),
		flagIDOR:      env("FORGEOPS_FLAG_IDOR", "flag{forgeops_project_bola}"),
		flagQuery:     env("FORGEOPS_FLAG_QUERY", "flag{forgeops_audit_query_injection}"),
		flagJWT:       env("FORGEOPS_FLAG_JWT", "flag{forgeops_forged_release_admin}"),
		flagTraversal: env("FORGEOPS_FLAG_TRAVERSAL", "flag{forgeops_artifact_path_traversal}"),
		flagCommand:   env("FORGEOPS_FLAG_CMD", "flag{forgeops_diag_command_injection}"),
		artifactDir:   "/tmp/forgeops/artifacts",
		users: map[string]user{
			"auditor": {
				ID:          "501",
				Username:    "auditor",
				DisplayName: "Mira Auditor",
				Password:    "spring2026!",
				Role:        "auditor",
				Team:        "assurance",
			},
			"release": {
				ID:          "502",
				Username:    "release",
				DisplayName: "Release Bot",
				Password:    "not-used",
				Role:        "release_manager",
				Team:        "platform",
			},
		},
	}
	if err := a.prepareFiles(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/", a.home)
	mux.HandleFunc("/assets/app.js", a.assets)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/logout", a.logout)
	mux.HandleFunc("/dashboard", a.dashboard)
	mux.HandleFunc("/projects", a.projects)
	mux.HandleFunc("/api/projects", a.apiProjects)
	mux.HandleFunc("/audit/search", a.auditSearch)
	mux.HandleFunc("/artifacts", a.artifacts)
	mux.HandleFunc("/artifacts/download", a.downloadArtifact)
	mux.HandleFunc("/ops/diagnostics", a.diagnostics)
	mux.HandleFunc("/admin", a.admin)
	mux.HandleFunc("/admin/fetch", a.adminFetch)
	mux.HandleFunc("/api/profile", a.profileAPI)

	log.Fatal(http.ListenAndServe(":8080", securityHeaders(mux)))
}

func (a *app) prepareFiles() error {
	if err := os.MkdirAll(a.artifactDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(
		filepath.Join(a.artifactDir, "release-notes.txt"),
		[]byte("ForgeOps 2026.05 release notes\n- deployment automation\n- audit filters\n"),
		0o644,
	); err != nil {
		return err
	}
	if err := os.WriteFile(
		"/tmp/forgeops/forgeops-artifact-secret.txt",
		[]byte("artifact recovery note: "+a.flagTraversal+"\n"),
		0o644,
	); err != nil {
		return err
	}
	return os.WriteFile(
		"/tmp/forgeops/cmd-flag.txt",
		[]byte(a.flagCommand+"\n"),
		0o644,
	)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-ForgeOps-Lab", "local-research-only")
		next.ServeHTTP(w, r)
	})
}

func (a *app) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	current, _, ok := a.currentUser(r)
	action := `<a class="button primary" href="/login">Sign in</a>`
	if ok {
		action = `<a class="button primary" href="/dashboard">Open dashboard</a>`
	}
	body := `
<section class="hero">
  <p class="eyebrow">Local research lab</p>
  <h1>ForgeOps Release Console</h1>
  <p class="lede">A deliberately vulnerable deployment operations portal for authorized local Ravage testing.</p>
  ` + action + `
</section>
<section class="band">
  <h2>Operator Surfaces</h2>
  <div class="grid">
    <a class="tile" href="/projects">Projects</a>
    <a class="tile" href="/audit/search?q=release">Audit Search</a>
    <a class="tile" href="/artifacts">Build Artifacts</a>
    <a class="tile" href="/ops/diagnostics?host=127.0.0.1">Diagnostics</a>
  </div>
</section>`
	a.writeHTML(w, "ForgeOps", body, current)
}

func (a *app) assets(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte(`
window.FORGEOPS_ROUTES = [
  "/api/projects?id=1001",
  "/api/projects?id=1002",
  "/audit/search?q=release",
  "/artifacts/download?path=release-notes.txt",
  "/artifacts/download?path=../forgeops-artifact-secret.txt",
  "/ops/diagnostics?host=127.0.0.1",
  "/admin/fetch?url=http://forgeops-internal:9100/metadata"
];
window.FORGEOPS_PUBLIC_CONFIG = {
  issuer: "forgeops-dev",
  tokenCookie: "forge_session",
  jwtHint: "local-secret",
  internalMetadataURL: "http://forgeops-internal:9100/metadata"
};
`))
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.writeHTML(w, "Sign in", `
<section class="band narrow">
  <h1>Sign in</h1>
  <form method="post" action="/login">
    <label>Username<input name="username" autocomplete="username"></label>
    <label>Password<input name="password" type="password" autocomplete="current-password"></label>
    <button class="button primary" type="submit">Sign in</button>
  </form>
</section>`, user{})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	current, ok := a.users[username]
	if !ok || current.Password != password {
		w.WriteHeader(http.StatusUnauthorized)
		a.writeHTML(w, "Sign in failed", `<section class="band narrow"><h1>Sign in failed</h1><p class="error">Invalid credentials.</p><a href="/login">Try again</a></section>`, user{})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "forge_session",
		Value:    a.signToken(current, current.Role),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	a.writeHTML(w, "Dashboard", a.dashboardBody(current), current)
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "forge_session", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) dashboard(w http.ResponseWriter, r *http.Request) {
	current, _, ok := a.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	a.writeHTML(w, "Dashboard", a.dashboardBody(current), current)
}

func (a *app) dashboardBody(current user) string {
	return fmt.Sprintf(`
<section class="band">
  <p class="eyebrow">Signed in</p>
  <h1>%s</h1>
  <p class="lede">Role: <b>%s</b> · Team: %s</p>
</section>
<section class="band">
  <h2>Release Workbench</h2>
  <div class="grid">
    <a class="tile" href="/projects">Project Ledger</a>
    <a class="tile" href="/audit/search?q=release">Audit Search</a>
    <a class="tile" href="/artifacts">Build Artifacts</a>
    <a class="tile" href="/ops/diagnostics?host=127.0.0.1">Diagnostics</a>
    <a class="tile" href="/admin">Admin Console</a>
  </div>
</section>
<script src="/assets/app.js"></script>`, html.EscapeString(current.DisplayName), html.EscapeString(current.Role), html.EscapeString(current.Team))
}

func (a *app) projects(w http.ResponseWriter, r *http.Request) {
	current, _, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	body := `
<section class="band">
  <h1>Project Ledger</h1>
  <p class="lede">Project details are loaded by the mobile API.</p>
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>
      <tr><td>1001</td><td>Checkout hardening</td><td><span class="pill">active</span></td><td><a href="/api/projects?id=1001">JSON</a></td></tr>
      <tr><td>1003</td><td>Edge image rollout</td><td><span class="pill">queued</span></td><td><a href="/api/projects?id=1003">JSON</a></td></tr>
    </tbody>
  </table>
</section>
<script src="/assets/app.js"></script>`
	a.writeHTML(w, "Projects", body, current)
}

func (a *app) apiProjects(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireUser(w, r); !ok {
		return
	}
	id := r.URL.Query().Get("id")
	switch id {
	case "", "1001":
		writeJSON(w, map[string]any{
			"ok": true,
			"project": map[string]any{
				"id":     "1001",
				"owner":  "auditor",
				"name":   "Checkout hardening",
				"status": "active",
			},
		})
	case "1002":
		writeJSON(w, map[string]any{
			"ok": true,
			"project": map[string]any{
				"id":              "1002",
				"owner":           "release-admin",
				"name":            "Crown deployment pipeline",
				"status":          "internal",
				"restricted_note": a.flagIDOR,
			},
		})
	default:
		writeJSON(w, map[string]any{"ok": false, "error": "project not found"})
	}
}

func (a *app) auditSearch(w http.ResponseWriter, r *http.Request) {
	current, _, _ := a.currentUser(r)
	q := r.URL.Query().Get("q")
	lower := strings.ToLower(q)
	var body string
	switch {
	case strings.Contains(lower, "union select"):
		body = `<table><tr><th>source</th><th>message</th></tr><tr><td>vault</td><td>` + html.EscapeString(a.flagQuery) + `</td></tr></table>`
	case strings.Contains(q, "'"):
		w.WriteHeader(http.StatusInternalServerError)
		body = `<div class="error"><b>query engine error</b><pre>syntax error near token ''' in audit filter</pre></div>`
	case q == "":
		body = `<p class="empty">Enter a search term.</p>`
	default:
		body = `<p>Results for <b>` + q + `</b></p><ul><li>release approved</li><li>artifact signed</li></ul>`
	}
	a.writeHTML(w, "Audit Search", `
<section class="band">
  <h1>Audit Search</h1>
  <form class="inline" method="get" action="/audit/search">
    <input name="q" value="`+html.EscapeString(q)+`" placeholder="release, actor, project">
    <button class="button primary" type="submit">Search</button>
  </form>
</section>
<section class="band">`+body+`</section>
<script src="/assets/app.js"></script>`, current)
}

func (a *app) artifacts(w http.ResponseWriter, r *http.Request) {
	current, _, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	a.writeHTML(w, "Artifacts", `
<section class="band">
  <h1>Build Artifacts</h1>
  <form class="inline" method="get" action="/artifacts/download">
    <input name="path" value="release-notes.txt" placeholder="release-notes.txt">
    <button class="button primary" type="submit">Download</button>
  </form>
  <p class="lede">Artifacts are resolved by the legacy worker.</p>
</section>
<script src="/assets/app.js"></script>`, current)
}

func (a *app) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireUser(w, r); !ok {
		return
	}
	rawPath := r.URL.Query().Get("path")
	if rawPath == "" {
		http.Error(w, "missing path", http.StatusBadRequest)
		return
	}
	resolved := filepath.Clean(filepath.Join(a.artifactDir, rawPath))
	if strings.HasPrefix(rawPath, "/") {
		resolved = filepath.Clean(rawPath)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(data)
}

func (a *app) diagnostics(w http.ResponseWriter, r *http.Request) {
	current, _, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}
	cmd := exec.Command("sh", "-c", "echo probing "+host)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run()
	a.writeHTML(w, "Diagnostics", `
<section class="band">
  <h1>Diagnostics</h1>
  <form class="inline" method="get" action="/ops/diagnostics">
    <input name="host" value="`+html.EscapeString(host)+`" placeholder="127.0.0.1">
    <button class="button primary" type="submit">Probe</button>
  </form>
  <pre>`+html.EscapeString(out.String())+`</pre>
</section>`, current)
}

func (a *app) admin(w http.ResponseWriter, r *http.Request) {
	current, claims, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	if claims["role"] != "admin" {
		w.WriteHeader(http.StatusForbidden)
		a.writeHTML(w, "Forbidden", `<section class="band"><h1>Forbidden</h1><p class="error">Admin role required.</p></section><script src="/assets/app.js"></script>`, current)
		return
	}
	a.writeHTML(w, "Admin", `
<section class="band">
  <p class="eyebrow">Admin console</p>
  <h1>Release Admin</h1>
  <p class="lede">Admin verification flag: <code>`+html.EscapeString(a.flagJWT)+`</code></p>
</section>
<section class="band">
  <h2>Internal URL Preview</h2>
  <form class="inline" method="get" action="/admin/fetch">
    <input name="url" value="http://forgeops-internal:9100/metadata">
    <button class="button primary" type="submit">Preview</button>
  </form>
</section>
<script src="/assets/app.js"></script>`, current)
}

func (a *app) adminFetch(w http.ResponseWriter, r *http.Request) {
	current, claims, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	if claims["role"] != "admin" {
		w.WriteHeader(http.StatusForbidden)
		a.writeHTML(w, "Forbidden", `<section class="band"><h1>Forbidden</h1><p class="error">Admin role required.</p></section>`, current)
		return
	}
	rawURL := r.URL.Query().Get("url")
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(rawURL) // intentional lab SSRF
	if err != nil {
		a.writeHTML(w, "Preview", `<section class="band"><h1>Preview failed</h1><pre>`+html.EscapeString(err.Error())+`</pre></section>`, current)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 20_000))
	a.writeHTML(w, "Preview", `
<section class="band">
  <h1>Preview</h1>
  <p class="lede">Fetched `+html.EscapeString(rawURL)+`</p>
  <pre>`+html.EscapeString(string(body))+`</pre>
</section>`, current)
}

func (a *app) profileAPI(w http.ResponseWriter, r *http.Request) {
	current, _, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]any{"ok": true, "user": current.Username, "role": current.Role})
		return
	}
	var payload map[string]string
	_ = json.NewDecoder(r.Body).Decode(&payload)
	role := payload["role"]
	if role == "" {
		role = current.Role
	}
	writeJSON(w, map[string]any{
		"ok":      true,
		"user":    current.Username,
		"role":    role,
		"warning": "legacy mass-assignment path accepted client role field",
	})
}

func (a *app) currentUser(r *http.Request) (user, map[string]string, bool) {
	cookie, err := r.Cookie("forge_session")
	if err != nil {
		return user{}, nil, false
	}
	claims, ok := a.verifyToken(cookie.Value)
	if !ok {
		return user{}, nil, false
	}
	current, ok := a.users[claims["username"]]
	if !ok {
		return user{}, nil, false
	}
	return current, claims, true
}

func (a *app) requireUser(w http.ResponseWriter, r *http.Request) (user, map[string]string, bool) {
	current, claims, ok := a.currentUser(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		a.writeHTML(w, "Sign in required", `<section class="band narrow"><h1>Sign in required</h1><a href="/login">Sign in</a></section>`, user{})
		return user{}, nil, false
	}
	return current, claims, true
}

func (a *app) signToken(current user, role string) string {
	header := b64JSON(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload := b64JSON(map[string]any{
		"sub":      current.ID,
		"username": current.Username,
		"role":     role,
		"iat":      time.Now().Unix(),
	})
	signed := header + "." + payload
	return signed + "." + b64(a.hmac([]byte(signed)))
}

func (a *app) verifyToken(token string) (map[string]string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	signed := parts[0] + "." + parts[1]
	expected := b64(a.hmac([]byte(signed)))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, false
	}
	normalized := map[string]string{}
	for key, value := range claims {
		normalized[key] = fmt.Sprint(value)
	}
	return normalized, true
}

func (a *app) hmac(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(a.jwtSecret))
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func b64JSON(value any) string {
	raw, _ := json.Marshal(value)
	return b64(raw)
}

func b64(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (a *app) writeHTML(w http.ResponseWriter, title string, body string, current user) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	name := "Guest"
	if current.Username != "" {
		name = current.DisplayName
	}
	nav := `<a href="/">Home</a><a href="/login">Sign in</a>`
	if current.Username != "" {
		nav = `<a href="/dashboard">Dashboard</a><a href="/projects">Projects</a><a href="/audit/search?q=release">Audit</a><a href="/artifacts">Artifacts</a><a href="/logout">Logout</a>`
	}
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>` + html.EscapeString(title) + ` · ForgeOps</title>
  <style>` + stylesheet + `</style>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">ForgeOps</a>
    <nav>` + nav + `</nav>
    <span class="identity">` + html.EscapeString(name) + `</span>
  </header>
  <main>` + body + `</main>
  <footer>Deliberately vulnerable local lab. Do not deploy.</footer>
</body>
</html>`))
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func env(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

const stylesheet = `
:root {
  --bg: #eef2f5;
  --panel: #ffffff;
  --text: #17202a;
  --muted: #667789;
  --line: #d3dde7;
  --accent: #126b5d;
  --warn: #975a16;
  --danger: #9b2d36;
  --good: #1e6b3c;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --sans: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: var(--sans); }
.topbar { min-height: 64px; display: flex; align-items: center; gap: 24px; padding: 0 28px; background: #111820; color: white; }
.brand { color: white; font-size: 20px; font-weight: 800; text-decoration: none; }
nav { display: flex; gap: 16px; flex: 1; flex-wrap: wrap; }
nav a { color: #d8e7f0; text-decoration: none; font-weight: 650; }
.identity { color: #9fb3c8; }
main { max-width: 1120px; margin: 0 auto; padding: 28px; }
.hero { min-height: 390px; padding: 54px; background: linear-gradient(135deg, #14313b, #166b5d 55%, #8c6d1f); color: white; display: flex; flex-direction: column; justify-content: center; border-radius: 8px; }
.hero h1 { max-width: 760px; font-size: 56px; line-height: 1.02; margin: 0 0 16px; }
.lede { color: var(--muted); font-size: 17px; line-height: 1.6; }
.hero .lede { color: #dcebef; max-width: 680px; }
.eyebrow { color: var(--accent); text-transform: uppercase; font-size: 12px; font-weight: 800; letter-spacing: .08em; }
.hero .eyebrow { color: #d7c46a; }
.band { margin-top: 24px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 28px; }
.narrow { max-width: 560px; margin-left: auto; margin-right: auto; }
h1, h2 { margin: 0 0 16px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; }
.tile { display: block; padding: 18px; border: 1px solid var(--line); border-radius: 8px; text-decoration: none; color: var(--text); background: #f9fbfc; font-weight: 750; }
.tile:hover { border-color: var(--accent); }
.button { display: inline-flex; align-items: center; justify-content: center; min-height: 42px; padding: 0 16px; border: 1px solid var(--line); border-radius: 6px; text-decoration: none; font-weight: 750; cursor: pointer; }
.primary { background: var(--accent); color: white; border-color: var(--accent); }
.inline { display: flex; gap: 10px; flex-wrap: wrap; align-items: end; }
label { display: grid; gap: 8px; font-weight: 700; margin: 12px 0; }
input { min-height: 42px; min-width: 280px; border: 1px solid var(--line); border-radius: 6px; padding: 0 12px; font: inherit; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 12px; border-bottom: 1px solid var(--line); }
pre, code { font-family: var(--mono); }
pre { overflow: auto; background: #111820; color: #d8e7f0; padding: 16px; border-radius: 8px; }
.pill { display: inline-block; border-radius: 999px; padding: 4px 8px; background: #e5f3ef; color: var(--good); font-weight: 750; }
.error { color: var(--danger); }
footer { padding: 24px 28px 40px; color: var(--muted); text-align: center; }
@media (max-width: 700px) {
  .topbar { align-items: flex-start; flex-direction: column; padding: 18px; }
  main { padding: 16px; }
  .hero { min-height: 300px; padding: 28px; }
  .hero h1 { font-size: 38px; }
  input { min-width: 100%; }
}
`
