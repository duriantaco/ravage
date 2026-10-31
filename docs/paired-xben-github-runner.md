---
title: Paired XBEN on public GitHub-hosted runners
---

# Paired XBEN on public GitHub-hosted runners

## Current status

This execution path is **fail-closed and not yet runnable**.  The safe planning
and receipt validator lives in `tools/paired_xben/github_runner.py`; it cannot
draw cases, read a provider key, pull or build an image, or launch a scored row.
Its `assessment` command exits 2 while any implementation blocker remains.

Do not add `OPENAI_API_KEY` to a workflow using this path yet.  Do not interpret
a rootless-Docker smoke test as benchmark readiness.

The intended compute has no GitHub Actions minute charge while the repository is
public and uses a standard runner.  This is not a promise of zero total cost:
model calls still cost money, Actions artifact storage is separately metered,
and larger runners are charged.  GitHub currently documents public standard
runners as free and says every standard runner other than `ubuntu-slim` is a
new VM:

- <https://docs.github.com/en/actions/reference/runners/github-hosted-runners>
- <https://docs.github.com/en/billing/concepts/product-billing/github-actions>

The fixed runner label is `ubuntu-24.04`, not `ubuntu-latest` and not
`ubuntu-slim`.  The live receipt must also capture `ImageOS`, `ImageVersion`,
the runner-name hash, Docker versions and binary hashes because GitHub updates
hosted images over time.

## Proposed authority layout

Each adjacent pair is one matrix job, so the exact 20-case selection produces
20 GitHub jobs and 40 primary rows.  GitHub supplies a fresh VM for each pair.
Within that VM, the two systems run sequentially against one target prepared
once for the pair.

```text
GitHub-hosted ubuntu-24.04 VM (one adjacent pair only)
|
|-- root evaluator
|   |-- root-only campaign + XBEN source (0700)
|   |-- rootful Docker daemon: target + fixed request meter
|   |-- model gateway: only holder of upstream provider key
|   `-- root-owned nftables policy for the active agent UID
|
|-- row 1: fresh non-sudo UID
|   |-- direct rootless dockerd, new empty data root/socket
|   `-- agent + digest-pinned tool image
|       `-- network may reach only model gateway and target meter
|
`-- row 2: different fresh non-sudo UID, daemon and data root
    `-- same frozen limits, model policy and prepared target
```

This does not use privileged Docker-in-Docker.  Docker documents that rootless
Docker-in-Docker still requires `--privileged`; that design is rejected here.
Instead, `dockerd-rootless.sh` runs directly as a dedicated host UID with an
XDG runtime directory under `/run/user/<uid>` and subordinate UID/GID ranges:
<https://docs.docker.com/engine/security/rootless/> and
<https://docs.docker.com/engine/security/rootless/tips/>.

This is also not VM-grade separation between an agent and its evaluator.  They
are separate Linux UIDs and Docker authorities in the same GitHub VM.  The
outer GitHub job has provider-managed VM isolation from other jobs, but that is
a different boundary.  Every report must use the evidence description
`linux-uid-rootless-docker-root-owned-egress-v1` and keep
`vm_grade_isolation_claimed=false`.

## Why the current executor cannot be reused

The current production coordinator is intentionally blocked because it gives
the agent and target the same Docker socket.  Merely pointing the adapter at a
second socket is not enough:

- `ProductionCampaignRuntime` only constructs the macOS `paired_local` process
  backend.
- `DockerComparisonTargetBackend` requires and inspects an agent Docker network
  on the target daemon, even for its host-loopback endpoint.  A network on a
  rootless agent daemon cannot be attached to or inspected by the rootful target
  daemon.
- the prepared runtime manifests are macOS-host artifacts and cannot bind a
  Linux hosted-runner runtime.
- the existing execution-start document is written locally and execution
  follows immediately.  The public `03-start` release therefore cannot prove
  it existed before calls began or authorize one specific GitHub workflow run.

A real Linux worker needs a cross-daemon meter mode.  The rootful target daemon
keeps the target and meter; the rootless worker receives only a precommitted
host-gateway URL for the meter's rootful loopback publication.  Root-owned
nftables must limit every process with the agent UID—including `dockerd`,
RootlessKit and tool containers—to the two gateway endpoints.  The agent can
control its rootless daemon, but it cannot change a root-owned host firewall.

The evaluator backend now contains an unqualified
`cross_daemon_host_gateway` mode.  It starts the meter directly on only the
rootful daemon's private target network, publishes exactly its precommitted
port on rootful `127.0.0.1`, returns the precommitted rootless host-gateway URL,
and rejects an agent-network attachment or any extra published binding.  This
is a fake-backed implementation result, not hosted-runner qualification.  It
is still blocked until both exact tool images demonstrate that their rootless
containers can route through that host gateway while the root-owned UID
firewall is active and cannot route directly to the target canary.

## Strix compatibility finding

The pinned Strix source at commit
`95e085eb6ce29c72ff84313b012cd2c9e9c1cfe5` always requests `NET_ADMIN` and
`NET_RAW` for its sandbox container and preserves the image entrypoint.  It can
also request `SYS_ADMIN`, `/dev/fuse`, and unconfined AppArmor when its OpenAI
Agents SDK manifest contains special remote mounts.  The benchmark adapter's
default manifest contains ordinary files and environment entries, not those
mount objects, so the expected scored path is:

- requested capabilities exactly `NET_ADMIN`, `NET_RAW`;
- no `SYS_ADMIN` request;
- no `/dev/fuse` device request;
- image entrypoint preserved;
- named sandbox network attached; and
- the in-container Caido service starts.

Rootless Docker places the daemon and containers in user namespaces.  That
makes the requested network capabilities plausible inside the container's
namespaces, but Docker's documentation does not guarantee this exact Strix
combination on GitHub's current image.  It must be demonstrated by the real
pinned image on the exact runner image before a commitment uses this backend.
Static source inspection is not sufficient.  A closed Moby rootless issue also
shows why checking only the requested/effective capability list is weak: a
container accepted `NET_ADMIN` and `NET_RAW` while a capability-dependent
socket operation still failed:
<https://github.com/moby/moby/issues/46501>.

`validate-qualification` therefore rejects a receipt unless Strix actually
starts, sees both effective capabilities, completes functional `NET_ADMIN` and
raw-socket probes against a local qualification canary, preserves its
entrypoint, joins its network, reaches its local Caido service, and is then
removed.  It also rejects any qualification that requests `SYS_ADMIN` or FUSE
because that would be a different runtime contract.

## Required pre-spend phases

The public sequence must be ordered as follows:

1. Publish the immutable `01-commitment` release before the drand round.
2. Resolve the round and publish the immutable `02-matrix` release containing
   all 40 reserved attempts and the deterministic 20-job matrix.
3. Dispatch the one execution workflow.  Its first authorization job has no
   model-provider environment, receives no provider secret, and derives the
   repository, protected `main` ref, workflow SHA, run ID and attempt directly
   from GitHub's live environment.  None of those values is a dispatch input.
4. That same job constructs the complete 20-job matrix from the signed
   `02-matrix` payload, creates a reservation for its own run with
   `run_attempt=1`, and atomically reserves the one fixed `03-start` tag.  The
   first successful tag creation is the campaign's permanent execution
   reservation; a failed publication leaves the campaign incomplete rather
   than making another run eligible.
5. The authorization job signs, publishes and re-downloads the immutable
   `03-start` release, then emits a create-only admission receipt.  Only
   downstream jobs in that same run may attach the protected environment that
   exposes `OPENAI_API_KEY`, and every pair job must revalidate the receipt
   against its live GitHub run values before target startup or gateway
   registration.  Any other run ID, a second dispatch, or any rerun
   (`GITHUB_RUN_ATTEMPT != 1`) terminates before the secret-bearing boundary.
6. Run all 20 fixed matrix jobs with `fail-fast: false`.  A failed row is a
   terminal primary observation.  A missing VM/job is a permanently incomplete
   campaign; it is not replaced.
7. An `always()` aggregation job downloads all 20 exact pair artifacts.  It
   validates all 40 full row directories, lifecycle receipts, target-meter and
   model-gateway receipts, candidates, terminal states and hashes.  It must not
   accept summaries in place of row evidence.
8. Publish that complete tree in the immutable `04-results` release.  If one
   pair artifact is absent or invalid, publish an incomplete terminal campaign,
   never a partial score.

`github_execution_gate.py` implements part of the verification and downstream
revalidation needed by steps 4 and 5.  The GitHub start path does not yet wire
independently trusted external drand, Cosign, and Sigstore-root inputs into
post-commitment verification; it must never execute verifier binaries supplied
by a downloaded campaign.  The same-run start publisher and the phase-specific
public-ledger schema are also not implemented, so paid execution remains
hard-blocked.  The generic `paired-xben.yml` operator-selected intake
must not be used for `03-start`: accepting an operator-supplied source run
would reintroduce the selection path this gate is intended to remove.  A
reusable publisher may retain that workflow's precommitted Sigstore identity,
but it must derive its source bytes and run binding from the calling execution
run and must not accept `source_run_id`, `source_artifact_name`, run ID, SHA, or
matrix JSON as inputs.

The admission command is deliberately usable only inside the fixed execution
workflow.  It rejects an unprotected ref, a workflow rerun, a different run or
SHA, a copied campaign binding, a mutable release observation, and an
authorization environment that already contains a provider key.  It does not
publish the release or grant a secret by itself:

```console
python -m tools.paired_xben.github_execution_gate \
  --start-release-dir "$RUNNER_TEMP/start-release" \
  --release-observation "$RUNNER_TEMP/start-release.json" \
  --cosign "$(command -v cosign)" \
  --trusted-root "$RUNNER_TEMP/matrix/verifiers/sigstore-trusted-root.json" \
  --campaign-id "$CAMPAIGN_ID" \
  --commitment-digest "$COMMITMENT_DIGEST" \
  --selection-digest "$SELECTION_DIGEST" \
  --primary-matrix-digest "$PRIMARY_MATRIX_DIGEST" \
  --pair-matrix-digest "$PAIR_MATRIX_DIGEST" \
  --output "$RUNNER_TEMP/execution-admission.json"
```

Those digest arguments must be outputs of cryptographic verification in the
same authorization job, not workflow-dispatch inputs.  A future workflow must
make that dataflow explicit and must attach the provider-secret environment
only to jobs that `need` the successful authorization job.

## Exact matrix and no-rerun enforcement

After `selection.json` exists, produce the only allowed matrix with:

```console
python -m tools.paired_xben.github_runner matrix \
  --selection /root/campaign/resolution/selection.json \
  --output /root/campaign/github-pair-matrix.json
```

The generator verifies the selection's own digest and exact field set.  It
requires 40 ordered primary slots, 20 distinct cases, adjacent equal-case pairs,
one Ravage and one Strix row per pair, and the frozen arm order.  It has no
subset, retry, resume, shuffle or replacement argument.  Its output fixes
`runner_label=ubuntu-24.04`, 20 jobs, two rows per job, `fail-fast=false`, fresh
UID/daemon per row, and no privileged DinD or VM-grade claim.

The workflow must compute this file from the downloaded, signed `02-matrix`
payload rather than accept JSON as a dispatch input.  It must compare the bytes
to the copy published in that payload before expanding `strategy.matrix`.

## Live qualification receipt

Qualification is a separate no-model, local-canary workflow.  It must not have
access to `OPENAI_API_KEY`, must not read the resolved XBEN selection, and must
not launch a real target.  Trusted setup may fetch the exact digest-pinned OCI
images before lockdown, but each arm daemon admits only an archive whose digest,
image reference and image ID are frozen outside the receipt.

The validator requires, for both Ravage and Strix:

- a different dedicated UID and daemon identity, neither equal to the target
  daemon;
- no `sudo`, `docker`, `adm`, `root`, or journal supplementary group;
- a rootless security option, systemd cgroup driver, UID-owned private socket,
  and exactly the three default networks in an otherwise empty daemon;
- offline admission of one exact `linux/amd64` tool image after host egress is
  locked, with zero pull/build/registry events;
- inability to read root-only campaign/target material, use the rootful Docker
  socket, inspect the evaluator provider secret via `/proc`, or see the live
  target-daemon label canary;
- root-owned nftables policy and live allowed/denied probes from both the host
  agent process and a tool container;
- actual tool startup requirements, not only Docker API acceptance; and
- for each exact tool image, successful agent-process and in-container HTTP
  requests through the cross-daemon host-gateway route, a two-request meter
  delta, one-network-only rootful gateway inspection, exact loopback port
  binding, and denial of the direct-target canary; and
- daemon, containers, images, volumes, nondefault networks, socket, data root,
  processes, firewall rules and user all absent after teardown.

Validation syntax (values must come from the frozen preparation, not from the
receipt being tested):

```console
python -m tools.paired_xben.github_runner validate-qualification \
  --receipt qualification.json \
  --repository duriantaco/ravage \
  --workflow-sha "$QUALIFICATION_WORKFLOW_GIT_SHA" \
  --docker-executable-sha256 "sha256:$DOCKER_SHA256" \
  --expected-image "ravage=$RAVAGE_REF,$RAVAGE_IMAGE_ID,$RAVAGE_ARCHIVE_SHA256" \
  --expected-image "strix=$STRIX_REF,$STRIX_IMAGE_ID,$STRIX_ARCHIVE_SHA256"
```

Even a valid qualification receipt is platform evidence, not permission to
spend.  The public start reservation and every scored row's own live lifecycle
receipt remain mandatory.

## Assurance limits

This design improves target-source and daemon separation and makes accidental
reruns visible.  It cannot prove that GitHub, the repository administrator, the
Linux kernel, Docker/RootlessKit, the model provider, or the benchmark operator
is honest.  GitHub-hosted runner freshness is a provider assertion corroborated
by job metadata, not a remotely attested machine identity.  UID/rootless
separation is weaker than a separately administered VM.  Public XBEN and the
known website regression are regression evidence, not an unseen holdout and not
by themselves support for a SOTA claim.
