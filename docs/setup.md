---
title: Setup
---

# Setup

Ravage is source-checkout-first. Install from this repository and run the
`ravage` CLI from the checkout virtual environment so the docs, examples, labs,
and benchmark evidence match the code you are running.

## Requirements

- Python 3.12 (`>=3.12,<3.13`; Python 3.14 is not supported)
- `pip`, normally through `python -m pip`
- Docker only for included labs or the Docker-backed tool runtime
- Chromium only for optional Playwright traffic capture or browser-backed probes
- External scanners only for recon-heavy attack workflows

Use Ravage only on systems you own or are explicitly authorized to test.
The active CLI is localhost-first. Any non-loopback target must be declared in
the brief and explicitly acknowledged with `--authorized-remote-target`;
remote command and external-scanner execution requires Docker.

## Checkout Install

The bootstrap script creates or refreshes `.venv`, installs the two editable
packages needed by the CLI, and verifies the entry point:

```bash
git clone https://github.com/duriantaco/ravage.git
cd ravage
scripts/bootstrap.sh
source .venv/bin/activate
ravage doctor
```

The default is a lean install. It does not download Chromium, Docker images, or
external scanners. Choose an optional bootstrap mode only when you need it:

```bash
scripts/bootstrap.sh --dev              # development/test dependencies
scripts/bootstrap.sh --browser          # Playwright Python package only
scripts/bootstrap.sh --install-browser  # Playwright plus Chromium
```

The script requires Python 3.12. If it cannot find one and `uv` is installed,
run `uv python install 3.12`, then rerun bootstrap. It does not silently
download a Python runtime.

For the shortest useful test, start your local app and run:

```bash
ravage init http://127.0.0.1:8080
ravage doctor --workflow scan --brief brief.yaml
ravage scan brief.yaml --probe surface_map --report
```

`ravage init` writes:

- `.env.ravage` for private provider variables;
- `brief.yaml` for scope, rules of engagement, objectives, and budget.

The scan is deliberately the first-run path: it calls no model and needs no
browser, Docker daemon, provider key, or external scanner. Review the brief
before running it. Keep `.env.ravage` private and do not commit it.

If you want to run the same steps manually, create a Python 3.12 virtualenv and
install the two package directories in editable mode:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install "setuptools>=68" wheel
python -m pip install --no-build-isolation -e packages/schemas -e packages/ravage
ravage --help
```

If an old virtualenv command still imports `orchestrator`, rerun bootstrap. It
repairs stale `.venv` activation paths and reinstalls the editable checkout:

```bash
scripts/bootstrap.sh
```

## Tool Runtime

Python package installation does not install scanners such as `nmap`, `ffuf`,
`katana`, `nuclei`, or `sqlmap`.

Check what is available:

```bash
ravage tools list
ravage tools check
```

Docker is optional for the default authorized-remote attack, which uses native
HTTP-only low-noise mode. It is required when an authorized remote run explicitly
selects the broader observe-mode command/scanner lane, and is also the repeatable
option for localhost runs that need tool isolation or the bundled scanner set:

```bash
ravage tools install --method docker --execute
ravage tools check
```

The Docker installer first pulls the signed multi-architecture image from
`ghcr.io/duriantaco/ravage-kali:latest` and keeps the local compatibility name
`ravage-kali:latest`. Docker selects the native `linux/amd64` or `linux/arm64`
variant automatically. Ravage verifies the pulled digest against the expected
GitHub Actions identity with a pinned multi-architecture Cosign verifier before
creating that alias.

If the pull fails, Ravage does not automatically start a large build. After
checking the error and available disk space, rerun with `--no-cache` to select
the local unsigned Dockerfile fallback explicitly. That flag skips the pull
and forces a clean local build.

An attack also pulls and verifies the published image when the default local
alias is missing, but it never starts the expensive build implicitly. Existing
published-image aliases are reverified before use. Existing local-build aliases
remain usable with an explicit unsigned-fallback warning. To prepare and check
the image before a run, use the command above.

To verify the published signature with Cosign:

```bash
cosign verify \
  --certificate-identity-regexp \
  '^https://github\.com/duriantaco/ravage/\.github/workflows/publish-kali-image\.yml@refs/(heads/main|tags/v[^/]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/duriantaco/ravage-kali:latest
```

The workflow also publishes SBOM and build-provenance attestations. A bare
`docker pull` validates registry content digests but does not enforce the
Cosign publisher identity; Ravage's default provisioning path does enforce it.
The command above is useful for independent manual verification.

On Linux, Kali, or WSL where host tools are preferred:

```bash
ravage tools install --method apt --execute
ravage tools check
```

On macOS with Homebrew:

```bash
ravage tools install --method brew --execute
ravage tools check
```

To preview the install plan without changing the machine, omit `--execute`.

Unauthenticated process-capable attacks default to Docker. `--tool-runtime
auto` is Docker-only and never falls back to host execution. The explicit
`--tool-runtime host` option avoids a Docker dependency for a trusted localhost
target but lets model-selected code read files available to your user account;
its child environment excludes provider keys and arbitrary parent variables.
Use that opt-in only in a disposable environment with narrow scope. For an
authorized remote run, omit the runtime in the default low-noise lane. Use
`--traffic-policy observe --tool-runtime docker` only when the complete origin
is authorized and the written ROE permits process/scanner execution.

## Doctor Workflows

Run `ravage doctor` immediately after installation. The default `core` check
verifies Python, the CLI entry point, and writable run storage. Docker,
Chromium, labs, and model routes are optional here, so missing optional pieces
are reported without making a lean install look broken.

Before a real command, ask doctor to require exactly that workflow's
dependencies:

```bash
ravage doctor --workflow scan --brief brief.yaml
ravage doctor --workflow attack --brief brief.yaml
ravage doctor --workflow traffic --target-url http://127.0.0.1:8080
ravage doctor --workflow lab
```

`scan` checks the brief and target without requiring a model or Docker.
`attack` also checks the selected model route, traffic policy, and any explicitly
selected tool runtime. `traffic`
requires Playwright and Chromium. `lab` requires Docker, Compose, and the
included lab definitions. Add `--authorized-remote-target` when asking doctor
to contact a non-loopback target; otherwise it stays fail-closed and does not
probe that URL.

Ravage prints a concrete `[fix]` for each failed check. For machine-readable
automation, add `--json`. `ravage setup check` remains an alias for existing
scripts, but `ravage doctor --workflow ...` is the clearest operator interface.

Human CLI output uses a green/cyan terminal theme by default in interactive
terminals. Set `RAVAGE_COLOR=never` to disable it or `RAVAGE_COLOR=always` to
force it in unusual terminal environments. JSON output stays plain.

## Optional Local Lab Smoke Test

This lab scan is useful for checking an installation, but it is not required
before testing your own application. For the normal localhost and authorized
URL paths, follow [How To Use](how-to-use.md).

Start a local lab:

```bash
ravage doctor --workflow lab
ravage lab up ravage-acme-box
```

`lab up` finds the checkout's `examples/labs` directory automatically, starts
Docker Compose, and waits up to 60 seconds for the health endpoint. Use
`--labs-dir` only for a custom lab collection.

Run a no-model deterministic scan:

```bash
ravage scan examples/labs/ravage-acme-box/brief.yaml \
  --run-dir runs/quickstart-acme-scan \
  --probe surface_map \
  --report
```

Verify outputs:

```bash
ravage audit verify runs/quickstart-acme-scan
python -m json.tool runs/quickstart-acme-scan/report.json | head -80
ravage lab down ravage-acme-box
```

A healthy setup has a run directory with `audit.db`, `report.json`, and
`workspace/`.

## Model Setup

The model-driven agent can test your application directly. Running the optional
deterministic scan above first is useful when diagnosing a new installation.

For a local OpenAI-compatible route such as Ollama:

```bash
ravage doctor --workflow attack \
  --brief examples/labs/ravage-acme-box/brief.yaml \
  --model-profile local-ollama \
  --model-tier mid

ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --model-profile local-ollama \
  --model-tier mid \
  --report
```

The built-in Ollama route defaults to `http://localhost:11434/v1`. Put
`OLLAMA_BASE_URL` or `RAVAGE_OLLAMA_MODEL` in `.env.ravage` when overriding
those defaults.

For hosted OpenAI-compatible routes, set the provider key and explicitly
acknowledge paid model use. If `brief.yaml` and `.env.ravage` are beside each
other, Ravage loads the file and infers the hosted route automatically:

```bash
ravage doctor --workflow attack --brief brief.yaml
ravage attack brief.yaml --allow-paid-models --report
```

There is no `source .env.ravage` step. Use `--env-file PATH` only when the file
has a custom name or location. Use explicit `--model-profile` and
`--model-tier` flags when you want to override the inferred route.

Provider-specific variables are documented in
[Model Providers](model-providers.md).

## Brief Setup

The wrapper commands infer `--target-url` from the first HTTP or HTTPS URL in
`scope.in_scope`. If the brief starts with CIDRs, hostnames, or multiple
allowed origins, either put the primary base URL first or pass `--target-url`
explicitly.

Choose one way to generate a starter brief. `ravage init` creates both the
brief and an environment template; `ravage brief template` prints only a brief
to standard output:

```bash
ravage init http://127.0.0.1:8080
```

Or:

```bash
ravage brief template --target-url http://127.0.0.1:8080 > brief.yaml
ravage brief template --help
```

Minimal brief:

```yaml
engagement_id: "99999999-9999-4999-8999-999999999999"
scope:
  in_scope:
    - "http://127.0.0.1:8080"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "web_application_assessment"
budget:
  max_cost_usd: 5.0
  max_runtime_min: 20
context:
  description: "Development build of my account-management web app."
  win_condition: "Identify and evidence reproducible vulnerabilities without destructive actions."
  rules:
    - "Stay within the in-scope target URL."
    - "Do not perform destructive actions."
```

For a user-owned or explicitly authorized staging app, follow the complete
[authorized URL path](how-to-use.md#path-2-test-an-authorized-url). The default
remote attack stays in native HTTP-only low-noise mode:

```bash
ravage init https://staging.example.test \
  --brief ravage-brief.yaml \
  --env-file .env.ravage \
  --description "Authorized assessment of my staging application."

ravage doctor --workflow attack \
  --brief ravage-brief.yaml \
  --authorized-remote-target

ravage attack ravage-brief.yaml \
  --authorized-remote-target \
  --allow-paid-models \
  --report
```

If the complete origin is authorized and the written ROE permits command or
scanner execution, first prepare Docker, then add
`--traffic-policy observe --tool-runtime docker` explicitly.

If a local engagement also needs a separate public hosting sanity check, keep
the active target as localhost and add the live website in brief context:

```yaml
context:
  description: "Local staging copy of the app."
  hosting_check:
    live_site: "https://example.com"
```

When a Markdown report is written, Ravage runs a separate `hosting-layer` report
agent after the localhost test and records `curl -I` results for HTTPS/HTTP apex
and `www` variants in `report.md`.

Use `web_application_assessment` for normal web tests and
`api_security_assessment` for API-heavy targets. Specific classes like `xss`,
`jwt`, or `sql_injection` are better for targeted retests only. Clean benchmark
or local CTF-style runs should keep broad objectives and let the agent derive
hypotheses from the challenge description and live target evidence.

## Troubleshooting

- Missing CLI: activate `.venv`, or use `.venv/bin/ravage`.
- Unsure what is wrong: run `ravage doctor`, then the matching
  `ravage doctor --workflow ...` command.
- Missing scanners: run `ravage tools check`, then install with
  `ravage tools install --method docker --execute`.
- Published tool image unavailable: check Docker disk space, then rerun the
  installer with `--no-cache` only if you intentionally want the much larger
  local unsigned build fallback.
- Docker unavailable in WSL: start Docker Desktop, enable WSL integration for
  the distro, then rerun `docker info`.
- Remote target rejected: confirm the URL is in `scope.in_scope` and rerun with
  `--authorized-remote-target`. Start Docker only for an explicitly selected
  observe-mode process/scanner lane.
- No ready model routes: set the provider environment variables and rerun
  `ravage doctor --workflow attack --brief brief.yaml`.
- No usable target URL in brief: pass `--target-url` or add an HTTP(S) URL to
  `scope.in_scope`.
