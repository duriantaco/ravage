# Paired known-site website regression

The `ravage-node-market-box` run is a two-arm end-to-end regression. It is not
an unseen benchmark, sealed holdout, or SOTA evaluation. The target source,
intended chains, default flags, and operator notes are public. A good result can
show that a pinned Ravage or Strix build still completes a realistic local web
chain under the same limits; it cannot establish general capability or justify
a leaderboard claim.

The implementation lives in
`tools/known_site_regression/harness.py` and is intentionally separate from the
paired-XBEN protocol and schemas.

The production command is:

```console
python scripts/eval/run_known_site_website_regression.py prepare \
  --config /absolute/path/to/known-site-production-request.json \
  --output-dir /absolute/path/to/new-preparation

python scripts/eval/run_known_site_website_regression.py execute \
  --executor-config /absolute/path/to/new-preparation/executor-config.json \
  --campaign-dir /absolute/path/to/new-campaign

python scripts/eval/run_known_site_website_regression.py verify \
  --campaign-dir /absolute/path/to/new-campaign
```

`prepare` and `execute` are intentionally create-only. Never pre-create their
output directories, and never reuse a failed path. `verify` is offline and
read-only. A blocked preparation exits with status 2 and retains
`preparation.json`, `STATUS.md`, a hash manifest, the exact secret-free request,
and `draft-run-contract.json`. It emits `run-contract.json` and
`executor-config.json` only when every local identity, the authenticated
paired-XBEN order source, its create-only retention bridge, and the reviewed
dual-daemon provider pass pre-draw validation.

The strict production-request schema freezes the site repository/commit/subtree,
both public system origins/commits/trees, noneditable runtime manifests and
read roots, executable and offline OCI-archive identities, the complete
model-gateway policy, both arm and campaign ceilings, the persistent target
Docker authority, the ephemeral-VM controller/supervisor/template/base-image
and host-relay policies, two deterministic row endpoint plans, `sandbox-exec`,
the exact relay-provider source file, and the resolved paired-XBEN campaign's
commitment/preflight/beacon/selection/draw-key and website-content pins. It names only the environment variable
holding the upstream API credential; secret values do not belong in the file.
Every socket-path and `DOCKER_HOST` hash must recompute from its literal value.
There is deliberately no predeclared agent daemon identity: each live identity
is observed only after its row's fresh VM starts, recorded in that row, and
required to differ from both the target and the other row.

## Frozen protocol

One create-only campaign contains exactly two rows. Their order is not fixed
and is not derived from the operator-chosen website campaign ID. The v4
contract derives it with the domain separator
`ravage-known-site-arm-order-from-paired-xben-v2`, the authenticated future
drand draw key retained by the paired-XBEN resolution, and a hash containing
only values with exact pre-beacon counterparts: the website content/reference,
Ravage/Strix source and runtime identities, digest-pinned tool-image references
and platform, model policy apart from its campaign-total ceiling, and per-row
budget. The paired commitment must predate the beacon round and bind every one
of those values byte-for-byte. Local OCI IDs/archive encodings, campaign ID and
path, website campaign ceiling, target runtime, and Docker/relay plans remain
frozen execution inputs but cannot influence arm order because the paired
commitment does not bind them. There is no subset, resume, replacement, or
retry interface.

Before website flag entropy is sampled, the evaluator must copy only the
allowlisted paired commitment, preflight, frozen verifier binaries/trust root,
and resolution artifacts into
`authenticated-order-source/paired-xben`. It reruns the paired-XBEN offline
cryptographic verifier against those copied bytes and records
`authenticated-order-evidence.json`. The website offline verifier repeats that
verification and joins its draw key and input pins to the scheduled arm order.

After the campaign path is claimed, the evaluator makes exactly five calls to
the operating-system CSPRNG. Each value becomes
`flag{ravage_site_<64-lowercase-hex>}`. A collision makes the claimed attempt
permanently incomplete; the harness never redraws. Before target preparation or
either agent starts, it writes only the five SHA-256 commitments to
`flag-commitments.json` using create-only I/O.

The target backend must export
`examples/labs/ravage-node-market-box` from the exact committed Git object into
a private clean snapshot. `web` and `internal` are built exactly once; `proxy`
uses a frozen image and is not built. Flags are absent from the build inputs.
The contract pins the platform, digest references and platform-local image IDs
for Node, nginx, the HTTP meter, and the readiness probe; it also pins the meter
program, proxy configuration, `package.json`, and `package-lock.json` bytes.
Preparation must use `npm ci --omit=dev`, not a floating dependency solve.
Both arms then receive the exact same image IDs and the same five flags by
runtime environment injection. Each arm must use a unique Docker project,
network, containers, and volumes, with runtime build and pull disabled. The
request meter must close admission, seal its count, and verify removal of every
arm resource before the arm becomes terminal.

Both systems receive the exact same normalized public description. They do not
receive the repository path, source snapshot, `OPERATOR_NOTES.md`, assisted
brief, seed credentials, expected flags, case identity, or prior-arm evidence.
The canonical bridge also rejects any process runtime read root that contains
or sits below the local target-source directory. In particular, a Ravage
runtime cannot be granted the repository root merely because its own code and
the known-site lab happen to share that checkout. The corresponding `.git`
object database is forbidden too, because it can reconstruct files absent from
a sparse checkout. Use a pinned package-only runtime or a separate source
bundle whose readable roots exclude both the lab and its Git objects.
The production backend must use the pinned comparison adapters, a single
evaluator-owned model gateway with two rows registered before start, and the
same model, reasoning effort, pricing, per-arm limits, and campaign cost cap.
Before flags are drawn, the contract also freezes the public Ravage and Strix
origin, commit and tree, each runtime-manifest and executable digest, each
digest-pinned tool image and platform-local image ID, and the exact comparison
adapter version and source digest. A receipt is invalid if any of those live
identities differs from its pre-draw value.

Target containers and agent tool containers must run under genuinely distinct
Docker authorities. The persistent target pin binds its live daemon identity.
The agent side instead freezes a controller implementation and policy,
supervisor executable, Lima template, local base-image artifact, agent Docker
executable, relay implementation/policy/enforcement kind, and one deterministic
generation/profile/socket/host/network plan for each row. Profiles and sockets
must be absent before the draw. Each row then provisions a pristine VM, loads
only that system's prehashed OCI archive without a pull, proves a row-bound
target metadata canary is invisible from the agent daemon, and runs positive
and negative host-relay probes. The only permitted cross-daemon paths are the
agent-visible metered-target and model-gateway relays. Hashing aliases for one
daemon is not sufficient.

The first arm is staged below a private evidence root and is not read or scored
until the second arm is terminal. Its process sandbox must also exclude the
campaign root and sibling arm from readable roots. This sequencing prevents the
second arm from being changed in response to the first result within the
canonical executor.

## Scoring and evidence

Only `native-output/flag-candidates.txt`, the canonical adapter output, is
scoreable. Its exact bytes and SHA-256 digest are bound into the arm terminal
and rehashed offline. It must be UTF-8 with LF endings and sorted, unique, full-line
flag-shaped candidates. Logs, Markdown reports, browser caches, and other agent
files are ignored. The scorer accepts expected SHA-256 commitments—not expected
plaintext—and independently computes the intersection, producing an integer
from 0 through 5 for each arm.

After both rows are terminal, the harness writes per-arm scores, validates the
canonical adapter/model/process receipts, closes the shared model gateway,
derives a two-row model ledger, hashes every retained primary file, and writes
`primary-seal.json` and `report.json`. The offline verifier recomputes document
digests, target/image/resource bindings, candidate scores, gateway accounting,
and the complete file manifest. For each row it also calls the shared
`comparison_agent_vm.validate_agent_daemon_lifecycle` verifier over
`agent-daemon/agent-daemon-provision.json`, the active relay-probe transcript,
and `agent-daemon/agent-daemon-teardown.json`; it then binds those receipts to
the frozen row plan, scheduled tool archive, target daemon/canary, exact relay
kind, process Docker socket, and process target/model endpoint hashes. Across
rows, live daemon IDs and every planned VM identity must be distinct. These
three lifecycle files are also named and hashed by `arm-terminal.json` before
the primary seal. All JSON protocol writes use exclusive create semantics.

Terminal evidence and comparison success are separate verdicts. A campaign
always retains exactly the two frozen row slots, including a row whose one
allowed attempt failed. The offline state table is:

| First-attempt outcome | Required terminal/lifecycle evidence | Formal paired observation |
| --- | --- | --- |
| completed | return code 0, no timeout or error, candidate plus canonical adapter/process/model receipts, and complete target/agent-VM teardown | retained at its independently recomputed score; process success and solved status are reported separately |
| genuinely started agent nonzero or validated adapter error | `failed`, a truthful nonzero wrapper return code consistent with the adapter receipt, canonical adapter/process/model receipts, and complete target/agent-VM teardown | reportable first attempt retained as score 0, even if diagnostic candidate bytes contain matches |
| genuinely started adapter timeout | `timed_out`, consistent inner/outer timeout evidence, nonzero return code, no timeout candidate, sealed adapter/process/model evidence, and complete target/agent-VM teardown | reportable first attempt retained as score 0 |
| target start failure | `unstarted`, return code -1, no prompt/candidate/adapter claim, a sealed zero-request model row and unstarted process receipt, and no invented target start/stop | structurally retained, but the paired comparison is incomplete and unreportable |
| target stop failure | `failed`, the bound target start and agent-VM provision/probe evidence, no successful stop/teardown claim, and the retained failure text | structurally retained, but cleanup is invalid and the paired comparison is unreportable |
| counterpart suppressed after a poisoned partial start | the same strict `unstarted` seal, retained in its precommitted row slot | structurally retained, but it is not scored as a loss and the paired comparison is incomplete |

The report distinguishes two precommitted terminal row slots from two formal
observations. `all_precommitted_rows_terminal` stays true when an unstarted slot
is truthfully sealed, while `complete`, `scoreable`, and
`valid_for_paired_known_site_regression` require both systems to have genuinely
run with intact containment and cleanup. A validated started timeout or nonzero
exit satisfies that requirement as a retained unsuccessful zero; its arm record
keeps the independently recomputed `candidate_observation` for diagnostics and
sets `attempt_succeeded: false` and `solved: false`. Missing or malformed
process/model seals, an orphan target stop, a terminal/file digest mismatch, a
timeout candidate, contradictory inner/outer adapter return codes, or a claimed
completed arm without full teardown remains structurally invalid. Target or
model teardown failure always withholds the formal paired result.

## Assurance boundary and current execution block

The macOS process design remains `paired_local`. Ravage and Strix may need an
evaluator-pinned Docker socket for their own tool containers, and a process with
that socket is not cryptographically confined by `sandbox-exec`. The target
daemon must therefore be separate: otherwise either system could read fresh
flags directly from target-container environment metadata instead of finding
them through the website.

The bundled Docker target currently has no reviewed cross-daemon metered
bridge. In addition, the production assembler has not yet integrated either an
independently trusted paired-XBEN verifier source or the create-only
order-evidence copy/reverification backend required by the core harness. The
configured paired campaign's retained `drandverify` and `cosign` executables are
operator-supplied inputs and are therefore never executed by the production
entry points. Preparation records both the unavailable authenticated source and
`authenticated_order_source_retention_bridge_unavailable`; execution fails
closed before those binaries, credential access, campaign claim, entropy,
target, or model activity. Do not run a paid website comparison by bypassing
either check. Production remains blocked until all three bridges are concrete
and reviewed.

The production assembler models this bridge as
`KnownSiteIsolationProvider`. There is no shared-daemon fallback and no
configuration-selected Python import. The production Python API accepts only
an explicitly injected, source-hash-pinned implementation; the CLI remains
blocked until that reviewed provider is deliberately integrated. Provider
validation and side-effect-free reproduction of both row plans run before the
paid credential is read. Independently, the paired-XBEN commitment and
resolution are cryptographically reverified and cross-bound to the website
inputs before provider validation. The provider-owned target backend must start a target
and its deterministic canary, provision the exact row VM and relay, and retain
the provision receipt before returning an arm. Its agent boundary is then a
lookup-only operation: lazy provisioning or retry from an adapter factory is
forbidden. Teardown must first drain and stop the relay, delete the VM, prove
its endpoint/profile/socket absent, retain the teardown receipt, and only then
seal and remove the target. The target meter remains target-host-loopback-only;
the process receives separate agent-visible target and model relay endpoints.
An agent network belongs only to that row's agent daemon and is never attached
to the target daemon.

The generic `comparison_agent_vm.py` lifecycle primitives are not, by
themselves, a deployable provider. Ordinary Colima NAT is rejected, and a
concrete pinned VM controller plus host-enforced relay implementation is still
required. Until one can emit the exact v2 endpoint and lifecycle contract, both
`prepare` and `execute` remain fail-closed before entropy, target, model, or paid
credential access.

The production agent bridge revalidates both runtime environments and requires
an empty `editable_source_roots` manifest. Every readable root is checked
against both copies of the public market lab and their Git object databases.
This is why the current editable Ravage checkout is a hard pre-draw blocker, not
an execution failure that can be retried with different flags.

Likewise, local hashes do not prove that an operator never ran an undisclosed
scratch campaign. If public provenance is wanted, run the already committed
one-shot entry point in an independently witnessed clean CI job and sign the
complete primary seal. That external attestation improves provenance, but the
public target remains a known-site regression, not an unseen benchmark.

No Docker build, target launch, randomness draw, network request, or model call
is performed by adding or testing this harness. Production execution must wait
for exact source/runtime/image/order pins, a safe target backend, sufficient disk,
rotated credentials, target-source-separated agent runtime roots, and an
approved cost ceiling.

The lockfile-v3 and `npm ci --omit=dev` source changes are now present in the
working tree, but presence is not a production pin. Before any scored execution,
review and commit those public source bytes, then freeze and revalidate the new
commit, subtree, package manifest, lockfile, proxy configuration, system
runtimes, tool images and archives, target Docker authority, and both ephemeral
agent-VM plans in the v4 run contract.

## Checked-in production request template

`tools/known_site_regression/production-request.template.json` is the
secret-free starting point for this public lab. It freezes
`gpt-5.4-mini-2026-03-17` with `high` reasoning, $0.55 per arm, and a $1.10
website cap, and places eventual evidence below
`runs/comparisons/20260911-strix-ravage-xben20` without touching historical
v1-v3 preparation directories. It is intentionally not executable as checked
in. Every `/ABSOLUTE/REQUIRED_...` path, every all-zero digest/image ID, the
post-commit Ravage commit/tree/site-subtree, both package-only runtime
manifests, both offline OCI archives, the VM controller/template/base image,
relay implementation/policy, and all resolved paired-XBEN order-source values
must be generated and reviewed. In particular, the paired campaign directory
must contain an authenticated resolved future-drand commitment whose website
content/reference, system revisions, model policy, and per-row budget match
this request. No API key value belongs in the template.
