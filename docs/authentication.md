---
title: Authentication
---

# Authentication

Ravage can log in as a test user before a deterministic scan or model-driven
attack. You do not need to hand-write the authentication YAML or export secrets
in your shell.

## New project: configure and test login

For a form login on a localhost development app:

```bash
ravage init http://127.0.0.1:3000 \
  --brief ravage-brief.yaml \
  --env-file .env.ravage \
  --description "Authorized assessment of my local app." \
  --auth form \
  --auth-identity user \
  --auth-login /login \
  --auth-health /account \
  --auth-marker Logout
```

Use a health URL that is protected by login. `--auth-marker` is text that only
appears when the user is signed in, such as `Logout`, `Account settings`, or a
known username. If the login form uses `email` instead of `username`, add
`--auth-username-field email`.

The command creates both files and prints the next commands. Open
`.env.ravage`, fill in `RAVAGE_USER_USERNAME` and `RAVAGE_USER_PASSWORD`, then
run:

```bash
ravage auth check ravage-brief.yaml \
  --identity user

ravage scan ravage-brief.yaml \
  --identity user \
  --probe surface_map \
  --report

ravage attack ravage-brief.yaml \
  --identity user \
  --allow-paid-models \
  --report
```

All three commands find `.env.ravage` beside the brief automatically; do not
shell-source it. Start with `surface_map`, then use `--all-probes` when you want
every deterministic probe that can preserve the selected identity. Ravage lists
and skips unavailable probes during the default or `--all-probes` selection. If
you explicitly name an incompatible probe with `--probe`, Ravage fails closed
before dispatch instead of silently changing its identity policy. The attack
example assumes a paid model route; omit `--allow-paid-models` when using a
local model. The full catalog can generate thousands of bounded requests, so
use focused probes unless the target and rules of engagement allow that breadth.

Use `--identity user` explicitly in saved commands and automation. The public
`ravage attack` wrapper selects the identity automatically when the brief has
exactly one, but a brief with multiple identities requires `--identity`. Ravage
fails before starting the agent if the selected identity is unknown, its
secrets are missing, or its login and health check do not establish an
authenticated session.

`auth check` verifies the configuration, secrets, login, and protected health
page without creating a scan run. If the brief has only one identity, you can
omit `--identity` from `auth check`.

For an authorized remote URL, use the same commands and add
`--authorized-remote-target` to `auth check`, `scan`, and `attack`; the attack
uses the same scoped managed HTTP lane and does not require Docker. Command,
Python, process, and scanner lanes are absent while an identity is active.
Ravage refuses to send configured credentials over plain HTTP to a non-local target.

## Existing brief: add login

Add an identity to an existing brief without editing YAML:

```bash
ravage auth add ravage-brief.yaml \
  --identity user \
  --type form \
  --login /login \
  --health /account \
  --marker Logout \
  --env-file .env.ravage
```

Then fill in the empty credential values and run the commands printed by
Ravage. Existing values in the env file are preserved. The env file is written
with mode `0600` and must not be committed.

To see the identities already configured:

```bash
ravage auth list ravage-brief.yaml
```

If an alias already exists, `auth add` refuses to overwrite it. Use `--replace`
only when you intentionally want to replace that identity.

Relative paths such as `/login` and `/account` are resolved against the first
HTTP(S) target in `scope.in_scope`. You can also pass complete URLs, but login
and health endpoints must remain within the authorized scope.

## Bearer token or API key

For a bearer token:

```bash
ravage auth add ravage-brief.yaml \
  --identity service-api \
  --type bearer \
  --health /api/me \
  --marker '"subject"' \
  --env-file .env.ravage
```

Set the generated `RAVAGE_SERVICE_API_TOKEN` value in `.env.ravage`.

For a fixed static header such as an API key:

```bash
ravage auth add ravage-brief.yaml \
  --identity partner \
  --type header \
  --header X-API-Key \
  --health /api/whoami \
  --marker partner \
  --env-file .env.ravage
```

Set the generated `RAVAGE_PARTNER_API_KEY` value in `.env.ravage`.

## What happens during an authenticated run

Each identity gets an isolated cookie jar and set of headers. Ravage logs in,
checks the protected health endpoint, and hands only the managed session owner
to eligible request executors. If the session expires, Ravage creates a fresh
session generation. A safe `GET`, `HEAD`, or `OPTIONS` may be retried once after
a `401`; state-changing requests are never replayed automatically.

Authentication values in `.env.ravage` form a private overlay: file values win
over inherited values, but Ravage does not copy those authentication secrets
into the process environment. They are not put on the command line or exported
to child processes, and raw authentication values never enter model action
arguments. The managed owner applies headers and cookies at the HTTP request
boundary and redacts recognized configured and runtime credentials from
auth-backed response bodies, headers, URLs, errors, and observations before
they reach the model or evidence stores.

During `ravage scan`, eligible deterministic probes receive the managed
session. During `ravage attack`, the base agent can use it for eligible
in-process built-in probes and structured `validate_poc` HTTP replays. The
bounded `agent-graph` route can use it through its scope-checked structured
`http_request` lane; its captured traffic is labeled with the selected
identity, and an action cannot replace the managed `Authorization` or `Cookie`
header. Authenticated graph runs do not construct a process executor. They
expose only managed `http_request`, plus `capture_flag` when the brief has a
flag objective.

Managed in-process specialists health-check the selected identity before each
ordinary request and safely refresh read requests after a `401`. Trusted
specialists may still send explicit Cookie or Authorization variants for paired
security controls; those responses do not invalidate or refresh the owner
identity, and probe artifacts label this request policy. Model-authored PoC and
graph requests cannot use the control-only override.

Authentication-bypass probes—currently `stateful_session`,
`default_credentials`, and `sqli_auth_transition`—deliberately run anonymously
even when an identity is selected. They must establish and verify their own
authentication boundary; inheriting a valid login could create a false
positive. Run artifacts label whether a probe used the selected identity or
the deliberate anonymous lane.

The initial crawl is also an explicit `anonymous:baseline`. Ravage records that
label, then runs a managed protected `surface_map` before the first model turn;
this preserves a reviewable public-versus-protected surface comparison instead
of silently treating baseline requests as authenticated.

Authenticated mode does not make credentials available to arbitrary code.
Base-agent command and Python actions are blocked, and the authenticated
`agent-graph` capability set excludes command, Python, persistent-process,
external probe-runner, and graph-level PoC replay lanes. Ravage does not silently
run those actions anonymously. When those lanes are appropriate, use a reviewed
authentication-free copy of the brief; merely omitting `--identity` is not
enough because the public attack wrapper auto-selects a sole configured
identity. Otherwise, use the managed in-process and structured-HTTP paths for
authenticated testing. The `captcha_form_state` and `dom_execution` built-in
probes are also unavailable while an identity is active because their browser
or OCR helpers launch external processes; the agent prompt omits them and the
executor rejects a forged request before dispatch. `browser_boundary` is
likewise withheld because its raw WebSocket handshake lane cannot yet carry,
refresh, pace, and record the managed HTTP identity safely. `cms_exposure` is
withheld because its binary archive download path does not yet pass through the
managed refresh, pacing, and request-accounting hook.

Because `dom_execution` is unavailable in managed mode, authenticated XSS
observations remain candidate signals in the current release; reflection or a
reported sink cannot be promoted to a confirmed XSS finding without that
trusted browser validator.

Resume keeps the principal bound to the saved state. Supply the same
`--identity` used by the original run; Ravage rejects a missing or different
identity binding instead of upgrading an anonymous workspace or changing roles.
`--resume-from` accepts each operator-facing artifact boundary:

```bash
ravage attack ravage-brief.yaml --identity user --resume-from RUN_DIR
ravage attack ravage-brief.yaml --identity user --resume-from RUN_DIR/workspace
ravage attack ravage-brief.yaml --identity user --resume-from RUN_DIR/workspace/working_state.json
ravage attack ravage-brief.yaml --identity user --resume-from RUN_DIR/report.json
```

Keep the original remote authorization acknowledgement, model options, and
report options on these commands when they applied to the interrupted run.

## Supported login flows and limits

The ready-to-use `auth check`, `scan`, and `attack` paths support:

- HTML form login using a URL-encoded POST, including hidden fields such as a
  rotating CSRF token;
- bearer tokens;
- a fixed static header.

The form adapter is for server-rendered HTML forms. JSON login APIs, complex
SPA flows, browser-driven login, OAuth/OIDC, SAML, WebAuthn, CAPTCHA, push MFA,
and external identity providers are not wired into the operator CLI. These
flows fail explicitly instead of guessing. Cross-origin login through an
`auth_dependency` has the same limitation. Configured browser and OIDC flow
kinds in the typed schema are therefore not executable attack identities yet.

The typed brief also supports an advanced TOTP configuration for form flows,
but `ravage auth add` does not scaffold it yet. Add that block manually only if
you are already using the typed brief schema.

Use dedicated, least-privilege test accounts. A health marker is stronger than
status alone because many applications return `200` for both the account page
and a deceptive login page. You can add `--unauthenticated-marker "Sign in"`
for a second check.

## Validate Ravage's session machinery

`auth check` tests your target-specific login. `authbench` is a separate,
network-free acceptance suite for Ravage's underlying session machinery:

```bash
ravage authbench
```

It covers form/cookie login, rotating CSRF, bearer refresh, forced expiry and
re-login, identity isolation, a false-authentication negative control, and no
replay of an unsafe POST. Acceptance is `7/7`; the command exits nonzero if a
case fails. For automation:

```bash
ravage authbench --json
```

AuthBench does not scan a target or prove that a real login flow is configured
correctly; use `ravage auth check` for that.
