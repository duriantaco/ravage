# Paired-XBEN public release ledger

This ledger publishes the exact frozen artifacts for one paired-XBEN campaign as
four create-only GitHub releases:

1. `paired-xben-v1/<campaign>/01-commitment`
2. `paired-xben-v1/<campaign>/02-matrix`
3. `paired-xben-v1/<campaign>/03-start`
4. `paired-xben-v1/<campaign>/04-results`

Each release contains a canonical ZIP of the phase payload, a hash-chained ledger
entry, and a Sigstore v0.3 bundle. The commitment release also exposes and signs
`commitment.json` directly. Cosign uses the GitHub Actions OIDC identity, Sigstore's
public Rekor log, and Sigstore's official RFC3161 timestamp authority. The
publication workflow rejects GitHub rerun attempts and will not use upload
replacement. Every later phase must preserve every non-null binding from its
predecessor, so a campaign ID cannot be reused to swap the commitment, selection,
reservation matrix, or execution-start seal.

The releases are enumerable by their fixed tag prefix in the repository's Releases
page and API. Actions artifacts are only secondary, expiring copies; the immutable
release assets are the primary receipts.

## Exact phase payloads

The phases are cumulative so each downloaded payload can be checked without trusting
an earlier working directory.

- `commitment` contains the exact commitment, its frozen preflight, and the Sigstore
  trusted root needed to verify the preceding public release.
- `matrix` additionally contains both frozen verifier binaries and the complete
  resolution directory: exact bodies returned by both fixed official drand relays,
  the resolver-owned fetch manifest, chain-info source, original Sigstore commitment
  bundle, normalized publication anchor, normalized beacon, and deterministic
  selection. Validation calls the protocol's offline verifier. That verifier checks
  relay agreement, the exact round and chain, the BLS signature with the frozen
  drand helper, the pre-draw Rekor/RFC3161 commitment anchor with the frozen Cosign
  and trusted root, and byte-for-byte deterministic selection. It also requires all
  40 primary reservations and no diagnostic-rerun tree. Submission executables are
  never run in place: validation requires separately supplied, out-of-band-trusted
  drand and Cosign binaries, requires their exact bytes, sizes, and SHA-256 values to
  match both the commitment policy and retained payload, and runs only private
  snapshots made from those trusted inputs. Because ZIP manifests are
  file-only, each still-empty reserved `artifacts/` directory is represented by one
  fixed-content marker; validation reconstructs the directory and runs the same
  protocol verifier on the copied and extracted payload. A plausible `selection.json`
  by itself is rejected.
- `start` adds the sealed 40-row, no-resume/no-retry execution-start document.
- `results` accepts only `complete=true`, exactly 40 terminal rows and 20 terminal
  pairs. It includes every file enumerated by every row's `artifacts.sha256`—including
  the score-driving candidate bytes, logs, adapter/process/model/target receipts and
  sandbox profile—plus the entire retained target/pair evidence subtree, the campaign
  model-gateway seal, primary-results seal, and terminal document. The publisher
  cross-checks every row and pair digest and invokes the pinned report implementation
  to replay row validation, lifecycle status, exact flag-candidate scoring, execution
  order, uniqueness, and paired score calculation. A signed score summary without
  the 40 complete row trees is rejected. Evidence that changes an outcome is never
  silently omitted.

  This subset is not yet the report's full independent-evidence verification. In
  particular, publication does not yet rerun the commitment-common model/limits
  contract, independent adapter/process/model/target receipt validation, or paired
  target-reuse checks after relocation. A malformed or fabricated receipt set can
  therefore pass the ledger's raw-score replay while the full report rejects it.
  Results publication is a production blocker until a relocation-safe verifier runs
  checks equivalent to the report's complete independent-evidence path.

Submission manifests are sorted, exact path/size/SHA-256 allowlists. Symbolic links,
hard links, special files, unsafe or over-deep paths, more than 50,000 files, a row
file over 128 MiB, a frozen verifier over 300 MiB, or more than 1.5 GiB of raw payload
are rejected. ZIP entries use stored compression and fixed metadata and are checked
against the same limits before extraction.

Results also fail closed on recognizable provider credentials, private keys, access
tokens, bearer credentials, credential-bearing filenames, and unredacted sensitive
JSON fields. Each raw 64-character row gateway token is checked against all 40 sealed
token digests in its ordinary, hexadecimal, and base64 forms. This is a hygiene gate,
not a proof that arbitrary child-controlled bytes cannot encode a secret in an
unrecognized form. Consequently the ledger does not upgrade the report's raw-agent-
output publication-safety claim.

## Repository prerequisites

- Merge both workflows and `tools/paired_xben/public_ledger.py` to the protected
  default branch named `main` before creating the commitment.
- Enable GitHub immutable releases for the repository before the first publication.
- Configure Actions to allow the workflow's declared `contents: write`,
  `actions: read`, and `id-token: write` permissions.
- Add `PAIRED_XBEN_ADMIN_READ_TOKEN` as an Actions secret. It must be a narrowly
  scoped fine-grained PAT or GitHub App token for this repository with only
  **Administration: read** (and GitHub's implicit Metadata read). The token is used
  only to call `GET /repos/{owner}/{repo}/immutable-releases`. `GITHUB_TOKEN` cannot
  request repository Administration permission, so omitting this separate token
  makes publication fail closed. All repository writes still use `GITHUB_TOKEN`.
- Provision independently trusted Linux drand and Cosign verifiers before enabling
  publication. The checked-in workflow currently fails every phase before setting up
  tools or downloading a submission because those runner inputs do not exist. It must
  not publish even a commitment and leave a permanently dead campaign whose frozen
  workflow SHA cannot later acquire the verifier provisioning. This is an intentional
  safety block: intake-controlled verifier bytes must never execute in the
  credentialed publisher.
- Implement and review relocation-safe full independent-evidence verification before
  arming `results`. Exact score-byte replay alone does not establish the committed
  model/limits contract, valid component receipts, or paired target reuse.

GitHub documents that the immutable-release setting endpoint requires repository
Administration read permission, that publishing locks the release tag and assets,
and that the release REST representation contains an `immutable` field:

- <https://docs.github.com/en/rest/repos/repos#check-if-immutable-releases-are-enabled-for-a-repository>
- <https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases>
- <https://docs.github.com/en/rest/releases/releases#update-a-release>

Sigstore's official timestamp documentation lists the public RFC3161 service used
by the validated Cosign signing configuration:
<https://docs.sigstore.dev/cosign/verifying/timestamps/>.

## Create-only publication flow

`workflow_dispatch` cannot receive a local file. The separate intake workflow is
therefore the deliberately untrusted transport into Actions.

1. Build a new local directory without reusing an old one:

   ```console
   python -m tools.paired_xben.public_ledger create-submission \
     --campaign-dir evidence/paired-xben/<campaign> \
     --output-dir .paired-xben-submission \
     --phase commitment
   ```

   For `matrix`, `start`, and `results`, also pass `--previous-entry` pointing to
   the downloaded `ledger-entry.json` from the immediately preceding release, plus
   all three verifier inputs from an out-of-band trusted location (never paths inside
   the campaign or submission):

   ```console
   --drand-verifier /trusted/bin/drandverify \
   --cosign /trusted/bin/cosign \
   --trusted-root /trusted/sigstore-trusted-root.json
   ```

2. Record the exact `sha256:` digest of `.paired-xben-submission/submission.json`.
   Commit that directory on the exact one-use branch named
   `paired-xben-intake/<campaign>-<phase>` and push it. Do not add secrets to the
   submission branch.

3. The read-only `paired-xben-intake.yml` workflow uploads the directory as
   `paired-xben-submission-<run-id>`. Record that successful run ID. Intake does not
   endorse the bytes; the publisher revalidates the exact file set, hashes, phase
   schemas, cryptographic randomness resolution, 40 reserved primary attempts,
   complete result evidence, publication hygiene, and no-rerun policy.

4. Dispatch `paired-xben.yml` on `main` with the campaign, phase, intake run ID,
   canonical artifact name, and recorded `sha256:` digest. The publisher accepts
   only a successful, first-attempt, same-repository push run whose workflow path is
   `.github/workflows/paired-xben-intake.yml`. Its branch must exactly match the
   campaign and phase, and the publisher retrieves the intake workflow at the run's
   `head_sha` and requires its bytes to match the checked-out `main` workflow. The
   signed ledger entry records that intake head SHA and the enumerable run URL.
   At present this workflow deliberately blocks every phase until trusted runner
   verifier provisioning is implemented and reviewed. Do not publish the commitment
   separately: changing the workflow afterward would change the source SHA frozen by
   that commitment and strand the campaign.

5. Download the release assets and verify them offline. Supplying Cosign and the
   frozen trusted root upgrades structural bundle checks to cryptographic identity,
   transparency-log, and signed-timestamp verification. The verifier requires the
   supplied Cosign bytes and size to match the commitment's frozen binary binding,
   and requires the supplied trusted-root bytes to match both the commitment digest
   and the archived trusted-root member:

   ```console
   python -m tools.paired_xben.public_ledger verify-entry \
     --entry-dir downloaded-release \
     --repository owner/repository \
     --cosign /path/to/cosign \
     --trusted-root /path/to/sigstore-trusted-root.json
   ```

   For a `matrix`, `start`, or `results` entry, offline semantic verification also
   requires `--drand-verifier`, `--protocol-cosign`, and
   `--protocol-trusted-root`, all sourced independently of the downloaded release.

   Put downloaded phase directories under `01-commitment`, `02-matrix`,
   `03-start`, and `04-results`, then use `verify-ledger` to verify a gap-free
   hash chain.

   This exact-byte check preserves the campaign's frozen verification bootstrap; it
   does not independently establish that the commitment selected a trustworthy
   Cosign build or trust root. Verifiers must authenticate those expected bootstrap
   inputs from an out-of-band trusted source before accepting the cryptographic
   result.

Submission and publication outputs use exclusive creation and refuse existing
paths. Validation, the immutable-release setting check, and predecessor
verification happen before the fixed tag is reserved. Once reservation succeeds,
any later failure burns that campaign phase: do not delete the tag or try to fill
the path with replacement results; start a visibly new campaign instead.

## What this proves—and what it does not

A successfully verified published entry establishes that exact bytes were signed
by the pinned workflow identity, included in Rekor, accompanied by an RFC3161
timestamp, bound to the prior phase, and published under one fixed repository tag.
The workflow atomically creates that tag, and after publication GitHub reports the
release immutable. If GitHub does not return `immutable: true` in the synchronous
publish response, the workflow fails instead of claiming success.

This is not an independently administered benchmark registry. The repository
operator can create other campaign IDs, use another repository, keep commitments
private, or delete/recreate an un-published tag after an interrupted run. GitHub
repository control therefore cannot prove that no alternative commitment ever
existed. The current local coordinator writes `execution/start.json` and then
immediately proceeds; this publication workflow therefore cannot observe or enforce
that local execution began only after the immutable `start` release. A real public
execution gate must bind one first-attempt workflow run and withhold the model
credential until that run verifies the published start receipt. Signatures also do
not prove target isolation or a SOTA claim. For those reasons the signed entry and
offline verification output keep
`independently_administered_namespace`, `no_alternative_commitments_verified`,
`prepublication_repository_admin_override_excluded`, `public_execution_verified`,
`sota_claim_supported`, and `claim_ready` false.

There is also a current portability limit. Target receipts retain the execution
host's canonical absolute paths. The results payload carries the complete corresponding
campaign-relative target tree and authenticates every byte, and row scores are
recomputed after relocation, but the deeper `aggregate_campaign` target validator
cannot yet be run from an arbitrary extraction path without a path-preserving
reconstruction or a separately reviewed path-normalization layer. Do not describe an
offline ledger check as a full relocation-portable execution attestation until that
gap is closed. This is a production blocker for results publication, not merely a
reporting caveat.

An actual no-alternative-commitments claim requires a separately administered,
append-only namespace with a public first-entry-wins policy and independent
enumeration. GitHub/Sigstore can complement such a registry; a repository controlled
by the benchmark operator cannot substitute for it.
