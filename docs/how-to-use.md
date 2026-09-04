---
title: How To Use
---

# How To Use

Use this guide to run Ravage against a web application that you own or are
explicitly authorized to assess.

Choose one path:

| Your target | Use this path | Required tool runtime |
| --- | --- | --- |
| A development app on `localhost` or `127.0.0.1` | [Path 1: localhost](#path-1-test-a-localhost-development-app) | Docker by default; managed HTTP when authenticated; explicit `host` opt-in available |
| An authorized staging or remote URL | [Path 2: authorized URL](#path-2-test-an-authorized-url) | Native metered HTTP by default; Docker only for an approved process lane |

If the app requires login, use the [Authentication guide](authentication.md).
The shortest path is `ravage init --auth ...`, followed by `ravage auth check`
and `ravage scan --identity ...`. A model-driven authenticated run is
`ravage attack BRIEF --identity user ...`. These commands auto-detect
`.env.ravage`; Ravage resolves authentication values from that private file
without exporting them into the process environment.

The public attack wrapper auto-selects an identity only when exactly one is
configured. Use explicit `--identity` in repeatable commands; it is required
when a brief has multiple identities. Configured form, bearer, and static-header
flows are supported. Browser/OIDC and other interactive identity-provider
flows are not.

The no-model `surface_map` scan is the recommended first check. An included
lab, observer, agent graph, full probe set, and benchmarks remain
[optional](#optional-workflows).

Ravage's structured HTTP follow-up is request-aware gray-box testing, not
white-box testing. It replays and mutates request templates observed from the
running application and typed Ravage evidence. It does not assume source-code,
server, database, or deployment access.

## Install Once

Ravage currently runs from a source checkout. Install Python 3.12, then run:

```bash
git clone https://github.com/duriantaco/ravage.git
cd ravage
scripts/bootstrap.sh
source .venv/bin/activate
ravage doctor
```

Bootstrap installs a lean core CLI. It does not install Chromium, Docker
images, or external scanners. The first deterministic scan below needs none of
them.

The primary examples below use OpenAI's hosted route and therefore spend model
credits. The generated `.env.ravage` file is ignored by the normal `.env*`
gitignore rule; still treat it as a secret and never commit it.

Hosted routes send the engagement brief, selected discovered state, prior
findings, and tool observations to the provider. Tool observations may contain
target response data. Confirm that the engagement permits this data transfer
and review the provider's retention terms before testing sensitive customer or
production systems. Use a local provider when evidence must remain local;
managed-secret redaction is not a general data-loss-prevention boundary.

To use Anthropic, Ollama, or another configured route, keep the same target
steps and change only the model setup described in
[Model Providers](model-providers.md).

## Path 1: Test A Localhost Development App

Use this path when the application is running on the same computer as Ravage.
No remote-authorization flag is needed.

### 1. Start your app

Start the development server normally and confirm its URL. This example uses
`http://127.0.0.1:3000`:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/
```

Any HTTP status, including `401` or `403`, proves the server is reachable. A
connection error does not. If your app uses another port, replace `3000`
everywhere below.

### 2. Create the Ravage files

From the Ravage repository root, run:

```bash
ravage init http://127.0.0.1:3000 \
  --brief ravage-brief.yaml \
  --env-file .env.ravage \
  --description "Authorized assessment of my local development app."
```

This creates:

- `ravage-brief.yaml`: target scope, safety rules, objective, budget, and target
  context;
- `.env.ravage`: empty provider-key fields and model defaults.

`ravage init` will not overwrite either file unless you deliberately pass
`--force`.

### 3. Review the brief and add the model key

Open `ravage-brief.yaml` and verify all of these before the run:

- `scope.in_scope` contains only your app's URL and port;
- `scope.out_of_scope` excludes anything Ravage must not touch;
- `context.description` tells the agent what the application does;
- `context.win_condition` says what a useful result means;
- `roe` and `budget` match the activity you permit.

For a normal assessment, a clear win condition is:

```yaml
context:
  description: "Development build of my account-management web app."
  win_condition: "Identify and evidence reproducible security vulnerabilities without destructive actions."
```

Then open `.env.ravage` and set:

```dotenv
OPENAI_API_KEY=your_key_here
```

Do not leave `context.description` as a `TODO`; the attack command rejects an
empty or placeholder description.

### 4. Check, map, then attack

Start with a deterministic surface map. It uses no model credits, Docker, or
external scanners:

```bash
ravage doctor --workflow scan --brief ravage-brief.yaml
ravage scan ravage-brief.yaml --probe surface_map --report
```

If the brief contains an identity, verify it and run the protected surface map
explicitly as that identity:

```bash
ravage auth check ravage-brief.yaml --identity user
ravage scan ravage-brief.yaml \
  --identity user \
  --probe surface_map \
  --report
```

To continue with the model-driven attack, check that workflow and run it:

```bash
ravage doctor --workflow attack --brief ravage-brief.yaml
ravage attack ravage-brief.yaml \
  --allow-paid-models \
  --report
```

If you also have the application checkout and the engagement permits source
review, add source-guided validation:

```bash
ravage attack ravage-brief.yaml \
  --source-root /path/to/application \
  --allow-paid-models \
  --report
```

`--source-root` is CLI-only opt-in; fields inside a brief cannot enable local
source access. Ravage scans local Python files for direct Flask and
FastAPI route-input flows into SQL, template, shell, file-read, and outbound-URL
sinks. Traversal is capped by file count, per-file and total bytes, directory
count, and directory-entry count; included source that exceeds any cap fails
closed. Hidden, temporary, version-control, virtual-environment, dependency,
cache, and build directories are excluded by policy. The private map stores
structural identifiers such as method, route and input names, input location,
framework, relative file, line, and sink; a bounded subset is sent to the configured
model. It does not store or send source snippets, function bodies, unrelated
constant values, defaults, or absolute source paths. Automatic replay is limited
to statically bound, non-mutating GET/query SQL candidates where Ravage knows
the complete supported scalar query shape and the tested field is a string.
POST, body, form, path, dynamic, relatively bound, and other sink-family
candidates remain prioritization hints in this version. A source-code graph
operation is therefore a route/input hypothesis, not necessarily a complete
request template. Only live differential evidence can produce a finding.

The source map is `RUN_DIR/workspace/artifacts/source-map.json` with private file
permissions. It reports traversal counts, including excluded directories;
exclusions are not live proof or coverage of the skipped code. Parse failures,
skipped symlinks, and dynamic or unsupported recognized route and direct-flow
patterns are recorded as incomplete coverage. `analysis_complete` means every
included file parsed and every recognized bounded pattern was handled; it does
not mean whole-program coverage. A resumed source-guided run must use the same
`--source-root` snapshot, analyzer contract, and candidate map; drift fails
before target traffic starts.

For the authenticated brief used above, add `--identity user` to the attack
command. A brief with one configured identity is auto-selected by the public
wrapper, but keeping the flag makes the intended role reviewable. A brief with
multiple identities requires it.

Ravage finds `.env.ravage` beside the brief, loads model settings directly, and
infers the configured hosted route. Do not shell-source the file. Authentication
secrets are resolved through a separate file-over-process overlay and remain in
the managed HTTP owner. An unauthenticated process-capable run defaults to
Docker and never silently falls back to the host. The explicit
`--tool-runtime host` option runs model-selected commands on your development
machine; it receives a minimal environment without provider keys but can still
read files available to your user account. Use that opt-in only in a disposable
localhost environment. Command and Python lanes are blocked when an identity
is active. Do not add `--authorized-remote-target`; that acknowledgement is for
non-local targets only.

Continue at [Read The Result](#read-the-result).

## Path 2: Test An Authorized URL

Use this path only when you own the remote application or have explicit written
authorization to assess it. Ravage can test an authorized remote URL; it is not
for indiscriminate public scanning.

The default low-noise lane can enforce the URL paths in `scope.in_scope`. When
authorization is path-limited, keep the run in this lane. Raw command and scanner
tools cannot enforce a URL-path boundary, so the optional process-capable lane
requires authorization for every complete origin and port it can reach.

### 1. Confirm the authorized scope

Before creating the brief, confirm:

- the exact host, scheme, ports, and paths you may test;
- whether authentication, scanners, and automated exploitation are allowed;
- the rate limit, time window, and forbidden actions;
- whether redirects or third-party subresources are in scope.

The command-line acknowledgement never expands the scope in the brief.

### 2. Optionally prepare Docker tools

Skip this step for the default native HTTP-only low-noise lane. If the written
ROE permits remote command, Python, persistent-process, or scanner actions for
the complete origin, those actions must use Ravage's target-scoped Docker
network. Start Docker Desktop or the Docker daemon, then run:

```bash
docker version
ravage tools install --method docker --execute
ravage tools check
```

The installer pulls and verifies the signed multi-architecture
`ghcr.io/duriantaco/ravage-kali` image. Docker selects the native `amd64` or
`arm64` image. A large local image build is not the normal path.

### 3. Create the Ravage files

Replace the example URL with the authorized target:

```bash
ravage init https://staging.example.test \
  --brief ravage-brief.yaml \
  --env-file .env.ravage \
  --description "Authorized assessment of my staging application."
```

### 4. Review the brief and add the model key

Open `ravage-brief.yaml` and verify:

- `scope.in_scope` contains every authorized origin and port, and nothing else;
- `scope.out_of_scope` captures prohibited systems or paths;
- `context.description` explains the application, authentication flow, and test
  account roles without embedding raw credentials;
- `context.win_condition` defines a useful completed assessment;
- `roe.max_rps`, forbidden actions, budget, and runtime match the agreement.

If the whole origin is authorized, use its root URL, for example
`https://staging.example.test/`. Raw TCP tools can enforce host and port but
cannot distinguish `/allowed` from `/forbidden`.

Set the provider key in `.env.ravage`:

```dotenv
OPENAI_API_KEY=your_key_here
```

### 5. Check, map, then attack

Run the same no-model surface map first, with the explicit remote-target
acknowledgement:

```bash
ravage doctor --workflow scan \
  --brief ravage-brief.yaml \
  --authorized-remote-target
ravage scan ravage-brief.yaml \
  --probe surface_map \
  --authorized-remote-target \
  --report
```

For a protected target, first configure a supported identity, then add
`--identity user` and `--authorized-remote-target` to both `auth check` and the
scan. Non-local authentication endpoints must use HTTPS.

Then check and start the isolated model-driven run:

```bash
ravage doctor --workflow attack \
  --brief ravage-brief.yaml \
  --authorized-remote-target
ravage attack ravage-brief.yaml \
  --authorized-remote-target \
  --allow-paid-models \
  --report
```

Add `--identity user` to that command when the remote brief configures the test
identity. In that authenticated mode, Ravage uses the scoped managed HTTP lane
and does not construct a process or Docker runtime.
Browser-driven login, OAuth/OIDC, SAML, and external SSO are not
executable configured flows; use a server-rendered form login, bearer token, or
fixed header identity.

Ravage loads `.env.ravage` directly; do not shell-source it.

Authorized remote attacks default to the whole-run low-noise policy. It shares
one durable physical-request ledger across authentication, recon, probes, PoC
replay, and structured base and graph HTTP; defaults to 300 physical requests
and 0.5 requests per second; and disables opaque command, Python,
browser-process, and external-process actions. Override the conservative limits
when the written ROE requires less traffic:

```bash
ravage attack ravage-brief.yaml \
  --authorized-remote-target \
  --traffic-policy low-noise \
  --max-physical-requests 120 \
  --traffic-max-rps 0.25 \
  --allow-paid-models \
  --report
```

If the complete origin is authorized and the written ROE explicitly permits the
broader unauthenticated process/scanner lane, use the Docker preparation above
and opt into it deliberately:

```bash
ravage attack ravage-brief.yaml \
  --authorized-remote-target \
  --traffic-policy observe \
  --tool-runtime docker \
  --allow-paid-models \
  --report
```

Local attacks default to `--traffic-policy observe`. Native requests remain
exactly counted, but running an opaque tool marks the total as a lower bound.
The ledger is `RUN_DIR/workspace/traffic-policy.json`; use the same policy,
ceiling, and rate when resuming because changed settings fail closed.

Ravage persists the base loop's canonical identity-aware surface graph in
`RUN_DIR/workspace/working_state.json`. If the optional agent graph starts, it
clones that snapshot and persists its current copy at
`RUN_DIR/workspace/autonomous-route/agent-graph/working_state.json`; the base
snapshot is not silently rewritten. Native recon and JavaScript discovery feed
the base graph. OpenAPI, GraphQL, built-in probes, and strict value-free external
observation batches contribute when those typed results pass through an
executor-owned native probe. The graph route also imports its own typed captured
HTTP exchanges, while base `http_request` exchanges update the base snapshot.
Standalone `ravage traffic capture` history is not automatically merged into
either attack snapshot. Query/body/header values and response bodies are omitted
from the graph.

For a remote target, `--authorized-remote-target` is mandatory. HTTP requests,
redirects, and routed HTTP(S) browser subresources are checked at URL scope.
When the observe-mode process lane is explicitly selected, raw command, Python,
process, and scanner traffic is bounded at origin and port by an internal Docker
network and fixed target forwarder.

An authenticated attack is intentionally narrower than that unauthenticated
tool set. Eligible in-process built-in probes and structured `validate_poc`
replays use the managed session. The bounded agent graph can use the identity
only through scope-checked structured HTTP. Its command, Python,
persistent-process, external probe-runner, and graph PoC-process capabilities
are withheld rather than run anonymously with missing credentials. The graph
does not attach a process executor in this mode, and model-supplied
`Authorization` or `Cookie` overrides are rejected. The external-process
`captcha_form_state` and `dom_execution` probes are likewise omitted from the
authenticated action catalog and blocked if requested directly. The
`browser_boundary` probe is also withheld: anonymous raw-WebSocket handshakes are
scope checked, paced, and accounted, but that transport cannot traverse the
managed identity owner or preserve its credentials and refresh semantics.
`cms_exposure` is withheld because managed binary downloads still require an
owner-controlled adapter; its anonymous binary lane is metered directly.

This means authenticated XSS observations remain candidate signals today:
`dom_execution` is the trusted XSS confirmation gate, and managed mode does not
yet have an eligible browser validator.

Three authentication-boundary probes—`stateful_session`,
`default_credentials`, and `sqli_auth_transition`—also run anonymously by
design. They must test the boundary they are meant to evaluate instead of
inheriting a known-good login, and their run records identify that deliberate
anonymous session mode.

## Read The Result

Near the start of the run, Ravage prints something like:

```text
RAVAGE // ATTACK
target    http://127.0.0.1:3000/
run       runs/ravage-brief-attack-20260815123000
workspace runs/ravage-brief-attack-20260815123000/workspace
audit     runs/ravage-brief-attack-20260815123000/audit.db
```

The final line repeats the important path:

```text
[done] run_dir=runs/ravage-brief-attack-20260815123000
```

Copy that value and use it in place of `RUN_DIR` below.

### Report and audit

Every attack writes these main outputs:

- `RUN_DIR/report.json`: canonical machine-readable report;
- `RUN_DIR/report.md`: optional redacted report for a person to read because
  these examples use `--report`;
- `RUN_DIR/stdout.log`: plain, ANSI-free progress output;
- `RUN_DIR/audit.db`: hash-chained audit records;
- `RUN_DIR/workspace/events.jsonl`: structured runtime events;
- `RUN_DIR/workspace/transcript.jsonl`: model and tool transcript;
- `RUN_DIR/workspace/traffic-policy.json`: durable physical-request ledger;
- `RUN_DIR/workspace/working_state.json`: base state and surface-graph snapshot;
- `RUN_DIR/workspace/agent-http-state.json`, `traffic/`, and
  `evidence-blackboard.json`: private base structured-HTTP artifacts, when used;
- `RUN_DIR/workspace/artifacts/`: larger captured artifacts.

If the bounded agent graph starts, its current state and events live below
`RUN_DIR/workspace/autonomous-route/agent-graph/`. The base and graph state files
use the same surface-graph schema, but the nested graph snapshot can advance
beyond the retained base snapshot. The graph's HTTP state, traffic store, and
evidence blackboard also live below that nested directory; Ravage keeps the two
lane stores separate on disk.

Verify the audit chain:

```bash
ravage audit verify RUN_DIR
```

The canonical JSON report is finalized even when a run is incomplete, fails
after starting, or has no flag-based objective. Evidence-backed findings remain
in the report independently of any captured flag. JSON-only finalization reads
saved artifacts and sends no model or target requests. It uses an atomic replace
and private file permissions so an interrupted write cannot leave a partially
written report.

If you did not pass `--report`, render the optional human-readable report later:

```bash
ravage report RUN_DIR --brief ravage-brief.yaml
```

### Inspect automatic agent HTTP evidence

Base `http_request` actions and bounded `agent-graph` structured HTTP actions
are captured automatically; do not start a separate browser capture for them.
Each lane has its own private traffic and evidence store. The histories include
every followed redirect as its own request and record transport-failure metadata
when no HTTP status is available. The normal traffic commands discover both
lanes from the printed attack run:

```bash
ravage traffic list RUN_DIR
ravage traffic show RUN_DIR base:rq_0001
ravage traffic replay RUN_DIR autonomous_graph:rq_0001
ravage traffic diff RUN_DIR \
  autonomous_graph:rq_0001 autonomous_graph:rp_0001
```

If only one lane exists, short IDs such as `rq_0001` keep working. When both
lanes exist, `list` emits `base:` and `autonomous_graph:` qualified IDs because
both stores can contain the same local ID. An unqualified ID is accepted only
when it is unique across the run. Replay stays in the selected lane, and `diff`
requires both records to come from that same lane/store. Pass the exact
manifested workspace path when you deliberately want to inspect only one lane
with its short local IDs.

Human output shows link status and counts. Add `--json` for stable fields such
as `observation_id`, `evidence_refs`, and `material_evidence_refs`. These are
identifier-only joins to the validated evidence blackboard: evidence payloads,
request values, and response bodies are not copied into CLI output. The
Markdown report has an **Agent HTTP Evidence** section, and `report.json` has
the corresponding `agent_http_evidence` object. Report links are also
lane-qualified so local request-ID collisions are unambiguous.

Report finalization binds every traffic lane and traffic-policy ledger to the
report target and the brief's exact scope, so a history copied from another
engagement is rejected. For an older run whose saved target contains redacted
query values or normalized path placeholders, omit `--target-url` and let
`ravage report` use that run's persisted-safe target; the original raw target
identity cannot be reconstructed from a legacy artifact.

Agent capture is part of the evidence boundary. If Ravage cannot durably save a
structured agent request, that action fails before its observation can be
promoted as evidence. Traffic from `curl`, Docker tools, scanners, and other
external processes is still outside this history.

### What the live CLI tells you

The live display shows:

- a compact status panel with target, model, phase, turn budget, elapsed time,
  cumulative token/cost usage, and result counts;
- up to three concurrent agent activities without using a full-screen or
  alternate-screen terminal interface;
- sanitized plan intent;
- which probe or action category was selected;
- what signal the agent expects;
- structured result counts and evidence changes;
- blocked or invalid actions;
- evidence-backed confirmed vulnerabilities;
- found-flag counts for flag-based lab objectives.

It intentionally does not print raw chain-of-thought, credentials, proof
values, raw commands, or complete target output. Full structured records remain
in the run directory.

Display controls:

- `--display auto` uses the live panel on an interactive terminal and plain
  lines in CI, pipes, and redirected output;
- `--display plain` produces a stable, non-animated stream suitable for screen
  readers and logs;
- `RAVAGE_SCREEN_READER=1` or `RAVAGE_NO_MOTION=1` forces plain output, even if
  `--display live` was selected;
- `NO_COLOR` keeps the live layout and disables color.

Interpret the live result literally:

| Live result | Meaning | Primary record |
| --- | --- | --- |
| `Candidate signals` | A probe observed something worth investigating. The count is not a confirmed vulnerability count. | `workspace/events.jsonl` and `workspace/artifacts/` |
| `Vulnerability confirmed` | A trusted, vulnerability-specific evidence gate passed and Ravage recorded a structured finding. | `report.json`, optional `report.md`, and event `finding_confirmed` |
| `Flag found` | `capture_flag` accepted an exact challenge proof observed in target evidence. | Event `flag_captured`, field `payload.flag` |

The report gives each confirmed finding concise remediation advice for a human
to review. `ravage attack` does not edit or deploy target code, reconfigure
infrastructure, change a WAF, or block inbound traffic.

The model cannot confirm a vulnerability merely by saying one exists. Probe
summaries and model claims stay candidate signals. The attack loop currently
promotes only these executor-owned evidence paths:

- **XSS:** `dom_execution` must observe actual client-side execution in a real
  browser. Reflection or a reported sink is not enough.
- **SQL injection, SSTI, path traversal, or LFI:** `validate_poc` must replay a
  control and an exploit labeled with `evidence_role`, using the same endpoint,
  method, and input shape. Both expectations must pass, and the executor must
  observe the response difference required for that vulnerability class.
- **Typed native specialists:** command injection, SQL injection, SSTI, path
  traversal/file read, SSRF, IDOR, and XXE can promote only through a registered
  contract with request and response summaries, a class-specific indicator,
  and control evidence where required. Apache traversal/CGI evidence uses the
  same executor gate.

Anything without a matching trusted contract remains a candidate signal. A
successful generic request, a model summary, or a plain response difference
cannot promote it. A confirmed vulnerability does not require a flag.

### Read the final RESULT block

After the live activity, Ravage prints a compact result such as:

```text
RAVAGE // RESULT
status    completed
traffic   34 physical requests · exact · cap 300
confirmed 1 vulnerability · High 1
finding 1 High · sql injection · GET /search · parameters=q
source 1  graph · RUN_DIR/workspace/autonomous-route/agent-graph/events.jsonl · event=EVENT_ID · finding=FINDING_ID
report    RUN_DIR/report.json
events    base · RUN_DIR/workspace/events.jsonl
events    route · RUN_DIR/workspace/autonomous-route/events.jsonl
events    graph · RUN_DIR/workspace/autonomous-route/agent-graph/events.jsonl
audit     RUN_DIR/audit.db
next      review the report for evidence, replay steps, and remediation
```

The `traffic` line is read from `workspace/traffic-policy.json`. `exact` means
every target dispatch used a metered lane; `lower bound` means an opaque action
may have emitted additional requests; and `unavailable` means the ledger is
missing or unreadable. `report.json` exposes the expanded
`traffic_accounting` object. When requested, `report.md` includes the physical
count and accounting status in its Executive Summary. The `finding` lines
identify what was confirmed without exposing secrets. The
matching `source` line identifies its exact events file, event ID, and finding
ID. The distinctly labeled `events` lines list every base, route, and graph
event stream that exists for this run. If canonical report finalization cannot
complete, `report cmd` prints the exact
`ravage report RUN_DIR --brief BRIEF` command to retry it; Ravage does not print
a nonexistent file as though it were a report.

Treat these status lines as materially different:

- `status completed`: the agent reached its terminal condition;
- `status warning · max turns reached`: the turn limit stopped the run;
- `status warning · cost budget exhausted`: the cost limit stopped the run.

The latter two mean **incomplete**, not "no vulnerabilities." Any confirmed
findings already recorded remain valid and available at the printed paths;
candidate signals may still need investigation.

Start with the redacted report. To inspect confirmed findings across every
printed event stream:

```bash
find RUN_DIR/workspace -type f -name events.jsonl -print0 \
  | xargs -0 jq 'select(.kind == "finding_confirmed") | .payload'
```

The event and larger artifacts may contain sensitive assessment evidence; store
and share the run directory accordingly.

### Flags are separate from vulnerability findings

Only expect a flag when the brief defines a flag-based lab or challenge
objective. When `capture_flag` accepts an evidence-backed flag, the live CLI
prints `Flag found` and points to:

```text
RUN_DIR/workspace/events.jsonl · event=flag_captured · field=payload.flag
```

Print unique raw values only when you intend to expose them in your terminal:

```bash
find RUN_DIR/workspace -type f -name events.jsonl -print0 \
  | xargs -0 jq -r 'select(.kind == "flag_captured") | .payload.flag // empty' \
  | sort -u
```

Treat this file as sensitive assessment data. Reports and the observer mask flag
values by default. An ordinary application should not produce a `Flag found`
message; look for `Vulnerability confirmed` and the report's Findings section
instead.

## Optional Workflows

None of the workflows in this section is required before the two primary attack
paths above.

### Optional: run a no-model baseline

`ravage scan` runs deterministic probes without model calls.

For localhost:

```bash
ravage scan ravage-brief.yaml \
  --probe surface_map \
  --report
```

For an authorized remote URL:

```bash
ravage scan ravage-brief.yaml \
  --authorized-remote-target \
  --probe surface_map \
  --report
```

Useful scan options include `--probe NAME`, `--all-probes`,
`--timeout-seconds N`, `--report`, and `--json`. Treat probe output as evidence
signals unless the resulting record has passed a formal confirmation gate; a
count alone is not proof of a vulnerability. `--all-probes` can generate
thousands of bounded requests across the catalog; reserve it for disposable
local or staging targets, and use focused probes for remote engagements.

### Optional: capture, inspect, and replay browser traffic

Use `ravage traffic` when you want a short, operator-driven request history
without starting an attack or spending model credits. For a local application:

This manual Playwright workflow is separate from the automatic structured-HTTP
history produced by base and `agent-graph` attack actions.

This workflow currently requires macOS, Linux, or WSL because its private
artifact permissions and cross-process locks rely on POSIX filesystem
semantics. On Windows, run it inside WSL rather than native Python.

```bash
scripts/bootstrap.sh --install-browser
source .venv/bin/activate
ravage doctor --workflow traffic --target-url http://127.0.0.1:3000
ravage traffic capture http://127.0.0.1:3000
```

The browser bootstrap is needed only once. Ravage then opens a
scope-restricted browser. Use the application normally, including logging in
with a dedicated test account if needed, then press Enter in the terminal. The
summary prints a run directory and short request IDs such as `rq_0002`.

The browser boundary is same-origin. Manual login works when the login pages
and requests stay on the captured origin. A redirect to an external SSO or
identity provider is blocked, as are cross-origin API and CDN requests. Use a
same-origin test login or configure the development application to keep the
whole test flow on one origin.

Capture defaults to `--max-requests 5000`. At that ceiling, Ravage fails closed
and blocks additional HTTP(S) and WebSocket requests. Set a lower value when
your rules of engagement require a smaller request budget.

List the captured application requests, inspect one redacted request template,
replay it once, and compare the replay result with the capture:

```bash
ravage traffic list RUN_DIR
ravage traffic show RUN_DIR REQUEST_ID
ravage traffic replay RUN_DIR REQUEST_ID
ravage traffic diff RUN_DIR REQUEST_ID REPLAY_ID
```

`list` hides static asset noise by default. `show` and `diff` do not send
network traffic. A replay result receives its own ID, which the replay command
prints for the final `diff` command.

One captured request ID can dispatch only once. Ravage durably reserves the
dispatch before touching the network. If the process stops after the server may
have received the request, a retry stays blocked; capture a fresh request when
you deliberately need another send.

If `show` prints unresolved slots, supply non-secret values with `--set`. Read
a secret from an environment variable with `--bind` so the value is not placed
in the command itself:

```bash
ravage traffic replay RUN_DIR REQUEST_ID --set query.page=2

export RAVAGE_REPLAY_AUTH='Bearer test-token'
ravage traffic replay RUN_DIR REQUEST_ID \
  --bind header.authorization=RAVAGE_REPLAY_AUTH
```

For an explicitly authorized remote application, acknowledge authorization on
both commands that can send traffic:

```bash
ravage traffic capture https://staging.example.test \
  --authorized-remote-target

ravage traffic replay RUN_DIR REQUEST_ID \
  --authorized-remote-target
```

The acknowledgement does not expand scope. The initial navigation, redirects,
browser subresources, and replay destination must all remain inside the
captured scope. Ravage blocks an out-of-scope request before it is sent.

Remote browser capture resolves the authorized origin before launch and forces
Chromium's routed TCP connections through a temporary loopback SOCKS5 proxy.
The proxy ignores ambient proxy settings, accepts only that origin and port,
and opens sockets only to the approved numeric DNS pins. QUIC and browser proxy
bypass are disabled so Chromium cannot independently resolve a different
address after Ravage's check.

Replay does not follow redirects automatically. A `3xx` response is recorded
as the result of that replay; inspect its redacted metadata, then capture or
replay the next request separately so its destination receives its own scope
check.

GET, HEAD, and OPTIONS requests can be replayed directly. POST, PUT, PATCH,
DELETE, and other requests that may alter the target fail closed unless the
operator deliberately arms that single replay:

```bash
ravage traffic replay RUN_DIR REQUEST_ID --allow-state-change
```

Add `--authorized-remote-target` to that command as well when `RUN_DIR` belongs
to a remote target.

Method-override headers also require `--allow-state-change`. Requests with a
custom `Host` or resource-routing headers such as `Forwarded`,
`X-Original-URL`, WebDAV `Destination`, or tagged WebDAV `If` are not replayed:
URL scope cannot safely authorize a different virtual host or resource hidden
inside a header.

Traffic capture is intentionally narrower than Burp or Caido. Ravage
scope-checks routed HTTP(S) requests and WebSocket connection handshakes and
pins remote TCP connections; the
stored history contains HTTP request records, not WebSocket frames. It is not a
system proxy or a complete host egress sandbox. It does not capture
WebRTC/STUN/TURN, other non-HTTP browser transports, or traffic emitted by
`curl`, Docker tools, scanners, and other external processes. Use Ravage's
Docker scoped network for attack-tool workflows that support it, and use a
separate isolated environment when the browser itself needs a hard outbound
boundary.

The persisted artifacts intentionally omit all query values, all request-body
values, and all raw response bodies. Authorization headers, cookies, passwords,
tokens, and recognized secret fields are omitted as well. Consequently, a
later replay must receive any needed values explicitly through `--set` or
`--bind`; Ravage never recovers or silently substitutes an omitted secret.
URL-path redaction remains conservative and heuristic, so handle the run
directory as sensitive data.

For textual JSON, form, XML, or text requests, replay accepts only a complete
operator-supplied opaque `body`; it does not reconstruct values from field
names. Multipart, binary, and content-encoded bodies are marked non-replayable.
Browser capture does not materialize a body declared above 1 MiB.

### Optional: use the included practice lab

The included labs are deliberately vulnerable test applications. Keep them on
localhost or an isolated private lab network.

```bash
ravage doctor --workflow lab
ravage lab up ravage-acme-box

ravage scan examples/labs/ravage-acme-box/brief.yaml \
  --probe surface_map \
  --run-dir runs/quickstart-acme-scan \
  --report

ravage audit verify runs/quickstart-acme-scan
ravage lab down ravage-acme-box
```

`lab up` finds the included lab directory automatically and waits for the
health endpoint before returning.

See the [lab index](../examples/labs/README.md). Operator notes, manifests,
expected flags, and lab source code are harness material; do not give them to a
strict black-box agent.

### Optional: preflight a localhost attack

Check a localhost brief and model route before spending calls. Ravage reads
`.env.ravage` directly:

```bash
ravage doctor --workflow attack --brief ravage-brief.yaml
```

Use `ravage tools list` and `ravage tools check` to inspect tool availability.

### Optional: change the progress display

`--display auto` is the default. It uses the scrollback-preserving live panel
in a terminal and stable plain lines when piped or running in CI.

- `--display live`: force the interactive terminal view;
- `--display plain`: stable line-oriented output;
- `--display quiet`: suppress convenience progress output.

`stdout.log` remains plain regardless of the terminal display.

### Optional: observe or resume an attack

Follow an existing run from another terminal:

```bash
ravage observe RUN_DIR
```

Resume the same attack workspace after an interrupted run:

```bash
ravage attack ravage-brief.yaml \
  --run-dir RUN_DIR \
  --resume \
  --model-profile hosted-openai \
  --model-tier low \
  --allow-paid-models \
  --report
```

This resumes with the safe Docker default. Add `--tool-runtime host` only when
the original localhost run explicitly used that host opt-in. When resuming an
authorized remote low-noise run, add `--authorized-remote-target`; the native
HTTP lane does not require an explicit runtime. A saved observe-mode process
lane uses `--tool-runtime docker`. An authenticated remote resume keeps the
same `--identity` and does not need Docker. Do not reuse an old
run directory for a fresh attack; leave `--run-dir` unset and let Ravage create
a timestamped one. Deterministic scans do not use this attack-resume flow.
For base and `agent-graph` structured HTTP, Ravage reopens each durable traffic
lane and reloads its request count and DNS pins, so interruption cannot reset
the request ceiling or silently resolve a different destination. Anonymous
cookie values are deliberately never written to disk: a resumed process starts
a new in-memory cookie jar and releases work tied to the old session so the
agent must authenticate again. Partial or inconsistent HTTP-state, traffic, and
evidence artifacts fail closed.
The base agent reopens the same `workspace/traffic-policy.json` ledger as well,
so authentication, recon, native probes, PoC replay, and graph HTTP retain one
physical-request total across the resume. An eligible opaque process action in
observe mode records a lower-bound marker rather than inventing a physical count.
Current ledgers remain mandatory and corruption or configuration mismatch fails
closed. A genuinely pre-ledger local/observe workspace with neither a ledger nor
its lock is migrated once to a new observe ledger marked `lower_bound` before
new target traffic. A legacy low-noise resume without its ledger is rejected.
For an authenticated resume, include the same `--identity` used by the original
run. Ravage rejects anonymous state or a different saved identity rather than
silently changing principals.

As a shorter alternative to `--run-dir RUN_DIR --resume`, `--resume-from`
accepts the run directory, its workspace, the saved state file, or its report:

```bash
ravage attack ravage-brief.yaml --identity user --resume-from RUN_DIR
ravage attack ravage-brief.yaml --identity user --resume-from RUN_DIR/workspace
ravage attack ravage-brief.yaml --identity user --resume-from RUN_DIR/workspace/working_state.json
ravage attack ravage-brief.yaml --identity user --resume-from RUN_DIR/report.json
```

### Optional: advanced routing and benchmarks

- [AI Web Operator Guide](ai-web-operator-guide.md): bounded autonomous routing,
  operational profiles, and advanced tool controls.
- [Benchmarking](benchmarking.md): XBEN runs and evidence contracts.
- [Competitor Harness](competitor-harness.md): configured external-agent
  comparisons.
- [Memory Design](memory.md): design context; active memory remains disabled in
  the current public attack entry point.

## Troubleshooting

### The attack rejects the brief description

Open `ravage-brief.yaml` and replace any `TODO` or empty
`context.description` with real target context. Review `context.win_condition`
at the same time.

### The model route or paid run is blocked

Confirm that `.env.ravage` is beside the brief and contains the provider key,
then run:

```bash
ravage doctor --workflow attack --brief ravage-brief.yaml
```

Ravage loads that file itself; do not shell-source it. If the file lives
elsewhere, pass `--env-file PATH`. Also verify the intentional
`--allow-paid-models` acknowledgement. See [Model Providers](model-providers.md).

### Docker times out or the image is missing

Check Docker itself first:

```bash
docker version
docker ps
```

If Docker is responsive, retry the normal signed-image path:

```bash
ravage tools install --method docker --execute
ravage tools check
```

Do not jump straight to `--no-cache`: that selects a large local build and can
use substantial temporary disk space. See [Setup](setup.md) for image
verification and fallback details.

### A remote target is rejected

Confirm that the URL is in `scope.in_scope` and the command includes
`--authorized-remote-target`. The default low-noise remote lane exposes only
native metered HTTP and does not construct a process runtime. If the written
ROE instead permits the broader observe-mode command/scanner lane, Docker must
be running and the command must include:

```text
--authorized-remote-target --traffic-policy observe --tool-runtime docker
```

Out-of-scope redirects and subresources are rejected even after authorization
is acknowledged.

### The report says there are no confirmed findings

This means no browser, paired-PoC, or registered native-specialist evidence
contract passed its gate. It does **not** prove the application is
vulnerability-free. Read `report.json` (and `report.md` when requested), then
inspect `stdout.log`, the printed base/route/graph event paths, and cited
artifacts for candidate signals, failed validation attempts, or an early model,
tool, budget, or scope failure. A candidate count or model statement alone is
not a confirmed vulnerability.

### The virtual environment imports old code

If the entry point imports `orchestrator` or another stale package, rerun:

```bash
scripts/bootstrap.sh
source .venv/bin/activate
```

## Short Glossary

- **brief**: YAML defining the target, authorized scope, rules, objective,
  context, win condition, and budgets.
- **attack**: the model-driven `ai-web` testing loop.
- **scan**: optional deterministic DAST without model calls.
- **signal**: a probe observation worth investigating; not automatically a
  confirmed vulnerability.
- **confirmed finding**: a structured record emitted only after a trusted typed
  evidence path passes: browser-observed XSS, a supported class-aware paired
  `validate_poc` replay, or a registered native-specialist contract.
- **flag**: an exact lab or challenge value accepted through `capture_flag`;
  ordinary vulnerability findings do not require one.
- **run directory**: the timestamped folder containing reports, events,
  transcripts, artifacts, and the audit database.
