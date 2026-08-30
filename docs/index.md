---
title: Ravage Docs
description: Operator documentation for Ravage, an open-source security evaluation workspace and benchmark harness for controlled targets.
---

# Ravage Docs

Ravage tests a running web application that you own or are explicitly
authorized to assess. Most users need one of two paths: test a localhost
development app, or test an authorized URL through the native low-noise HTTP
lane.

Start with [How To Use]({{ '/how-to-use.html' | relative_url }}). Included labs,
deterministic scans, observers, autonomous routing, and benchmarks are optional.

<div class="quick-links" aria-label="Primary docs">
  <a href="{{ '/how-to-use.html' | relative_url }}">How To Use</a>
  <a href="{{ '/setup.html' | relative_url }}">Setup</a>
  <a href="{{ '/ai-web-operator-guide.html' | relative_url }}">AI Web Operator Guide</a>
  <a href="{{ '/benchmarking.html' | relative_url }}">Benchmarking</a>
  <a href="{{ '/xben-comparison-runbook.html' | relative_url }}">XBEN Runbook</a>
  <a href="{{ '/competitor-harness.html' | relative_url }}">Competitor Harness</a>
  <a href="{{ '/improvement-lab.html' | relative_url }}">Improvement Lab</a>
  <a href="{{ '/skills.html' | relative_url }}">Knowledge Skills</a>
  <a href="{{ '/satcom.html' | relative_url }}">Passive SATCOM</a>
  <a href="{{ '/architecture.html' | relative_url }}">Architecture</a>
</div>

## Start Here

Choose the target that matches your situation:

1. [Test a localhost development app]({{ '/how-to-use.html' | relative_url }}#path-1-test-a-localhost-development-app).
   Start the app, create a scoped brief, and begin with the no-model
   `surface_map` scan. Add a provider key only when continuing to `attack`.
2. [Test an authorized URL]({{ '/how-to-use.html' | relative_url }}#path-2-test-an-authorized-url).
   Confirm written authorization, create the remote brief, and run with
   `--authorized-remote-target`. Docker is an explicit opt-in only for the
   broader observe-mode process/scanner lane.

Both paths explain exactly how to read the report, verify the audit trail, and
locate a captured flag when the target defines one.

## Optional: Benchmarking

Private records from a pre-relaunch 2026-07-12 checkout report 85 / 104 exact
XBEN flags. The raw bundle is access-controlled and is not shipped in this
repository. The result has not been reproduced from the current checkout, so
it is historical context rather than a current reproducible or public
baseline. See [Benchmarking]({{ '/benchmarking.html' | relative_url }}) for
commands and evidence requirements.

[XBOW describes XBEN as outdated and saturated](https://github.com/xbow-engineering/validation-benchmarks).
Any new result should be treated as execution on a public regression suite; it
is not by itself a frontier, unseen-task, production-efficacy, or cross-agent
claim. The external-agent scoreboard remains a future stage.

## Optional Command Map

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Goal</th>
        <th>Command</th>
        <th>Read</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Test a localhost app</td>
        <td><code>ravage attack BRIEF.yaml</code></td>
        <td><a href="{{ '/how-to-use.html' | relative_url }}#path-1-test-a-localhost-development-app">Localhost path</a></td>
      </tr>
      <tr>
        <td>Test an authorized URL</td>
        <td><code>ravage attack BRIEF.yaml --authorized-remote-target</code></td>
        <td><a href="{{ '/how-to-use.html' | relative_url }}#path-2-test-an-authorized-url">Authorized-URL path</a></td>
      </tr>
      <tr>
        <td>Install from source</td>
        <td><code>scripts/bootstrap.sh</code><br><code>ravage doctor</code></td>
        <td><a href="{{ '/setup.html' | relative_url }}">Setup</a></td>
      </tr>
      <tr>
        <td>Run a localhost deterministic baseline</td>
        <td><code>ravage scan BRIEF.yaml --probe surface_map --report</code></td>
        <td><a href="{{ '/how-to-use.html' | relative_url }}">How To Use</a></td>
      </tr>
      <tr>
        <td>Check a workflow or external tools</td>
        <td><code>ravage doctor --workflow scan --brief BRIEF.yaml</code><br><code>ravage tools check</code></td>
        <td><a href="{{ '/how-to-use.html' | relative_url }}">How To Use</a></td>
      </tr>
      <tr>
        <td>Run XBEN-style benchmarks</td>
        <td><code>ravage xben ...</code></td>
        <td><a href="{{ '/benchmarking.html' | relative_url }}">Benchmarking</a></td>
      </tr>
      <tr>
        <td>Compare external agents</td>
        <td><code>ravage competitors ...</code></td>
        <td><a href="{{ '/competitor-harness.html' | relative_url }}">Competitor Harness</a></td>
      </tr>
    </tbody>
  </table>
</div>

## Documentation

<div class="doc-list">
  <section>
    <h3>Operate</h3>
    <ul>
      <li><a href="{{ '/how-to-use.html' | relative_url }}">How To Use</a>: copy-paste localhost and authorized-URL paths, outputs, and troubleshooting.</li>
      <li><a href="{{ '/setup.html' | relative_url }}">Setup</a>: source install, tool runtime, model routes, and brief setup.</li>
      <li><a href="{{ '/ai-web-operator-guide.html' | relative_url }}">AI Web Operator Guide</a>: model-driven runs, deterministic DAST, and scoped tools.</li>
      <li><a href="{{ '/model-providers.html' | relative_url }}">Model Providers</a>: Ollama, LM Studio, vLLM, LiteLLM, OpenAI-compatible routes, and Anthropic routes.</li>
      <li><a href="{{ '/authentication.html' | relative_url }}">Authentication</a>: optional test identities, secret references, health checks, and AuthBench.</li>
      <li><a href="{{ '/memory.html' | relative_url }}">Memory Design</a>: local memory model, redaction, retention, and replay-backed promotion design.</li>
      <li><a href="{{ '/skills.html' | relative_url }}">Knowledge Skills</a>: opt-in advisory cards, built-in workflows, and no-regression promotion rules.</li>
      <li><a href="{{ '/satcom.html' | relative_url }}">Passive SATCOM Analysis</a>: offline TLE and CCSDS Space Packet inventory with no network or transmit path.</li>
    </ul>
  </section>

  <section>
    <h3>Evaluate</h3>
    <ul>
      <li><a href="{{ '/benchmarking.html' | relative_url }}">Benchmarking</a>: XBEN modes, preflight, scoring, evidence, and report interpretation.</li>
      <li><a href="{{ '/xben-comparison-runbook.html' | relative_url }}">XBEN Comparison Runbook</a>: description-only inputs, canary execution, and acceptance checks.</li>
      <li><a href="{{ '/competitor-harness.html' | relative_url }}">Competitor Harness</a>: isolated external-agent comparison and adapter shape.</li>
      <li><a href="{{ '/improvement-lab.html' | relative_url }}">Improvement Lab</a>: secret-safe prior-run learning, immutable candidates, repeated gates, operator approval records, and normal reviewed promotion.</li>
      <li><a href="{{ '/benchmark-referee-launch.html' | relative_url }}">Referee Launch Plan</a>: current evidence-release copy and requirements for a future external-agent scoreboard.</li>
      <li><a href="https://github.com/duriantaco/ravage/blob/main/BENCHMARKS.md">Benchmarks And Local Test Boxes</a>: lab matrix, flag counts, and local scoring policy.</li>
    </ul>
  </section>

  <section>
    <h3>Build</h3>
    <ul>
      <li><a href="{{ '/architecture.html' | relative_url }}">Architecture</a>: system model, packages, loop, runtime, evidence, and safety.</li>
      <li><a href="{{ '/open-core.html' | relative_url }}">Open Core And Pro Reports</a>: Apache-2.0 core and proprietary report extension hook.</li>
      <li><a href="{{ '/technical-guide.html' | relative_url }}">Technical Guide</a>: code map, contracts, workflow rules, and test strategy.</li>
      <li><a href="{{ '/differentiation-roadmap.html' | relative_url }}">Differentiation Roadmap</a>: current differentiators, limits, and roadmap.</li>
    </ul>
  </section>
</div>

## Before You Run

- Use Ravage only on systems you own or have explicit written authorization to
  test.
- The active CLI is localhost-first. Any non-loopback target requires both brief
  scope and `--authorized-remote-target`. The default remote attack is native
  HTTP-only low-noise mode; an explicitly selected observe-mode command/scanner
  lane is forced into the scoped Docker runtime.
- Findings need live tool output. Memory and source context are hints, not
  proof.
- Local lab boxes are intentionally vulnerable and should stay local or
  isolated.
- The old top-level `ravage --benchmark` and `ravage memory ...` commands are
  not active public entry points. Use `ravage xben` for XBEN-style runs and
  treat the memory page as design documentation unless the CLI help shows a
  memory command in your checkout.
- Users are responsible for their own use; the project is provided without
  warranty or liability for misuse, unauthorized activity, or damages.

Read the [disclaimer](https://github.com/duriantaco/ravage/blob/main/DISCLAIMER.md)
and [license](https://github.com/duriantaco/ravage/blob/main/LICENSE) before
running it.
