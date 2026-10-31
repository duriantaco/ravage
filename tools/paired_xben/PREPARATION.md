# Paired-XBEN production preparation

`prepare` is the only supported bridge from machine-local inputs to an XBEN
campaign commitment. It is intentionally offline with respect to the model and
randomness beacon, and it never pulls or builds an image.

```console
python scripts/eval/run_paired_xben_protocol.py prepare \
  --config /absolute/path/to/prepare-request.json \
  --output-dir /absolute/new/empty/preparation-directory
```

The request must use schema `ravage.paired-xben.prepare-request.v1`; see
`prepare-request.example.json` for every required field. It contains paths,
digests, public identities, limits, and the *name* of the provider environment
variable. It cannot contain an API key, token, password, credential, or secret.
No dotenv file is opened.

The command checks all of the following before it emits runnable artifacts:

- clean, explicitly pinned Ravage, Strix, and canonical XBEN Git trees;
- exact executable and `uv sync --frozen` runtime-environment manifests;
- the complete pre-draw compatibility catalog and all patch hashes;
- a content-addressed known-site or sealed-holdout website reference;
- a retained official OpenAI model-page Markdown snapshot containing the
  frozen snapshot name and all three configured token prices;
- the evaluator source inventory, macOS `sandbox-exec`, normalized runtime
  read roots, the exact Docker socket, and an empty mode-0700 private target
  root;
- all four digest-pinned `linux/amd64` OCI references already present in the
  configured daemon, including the local IDs of the target helper images; and
- the drand verifier identity plus a Cosign binary verified from its official
  Sigstore release bundle, signed timestamp, and frozen trusted root.

The current paired-local executor deliberately remains hard-blocked even when
those checks pass: targets and agents use the same Docker daemon, so an agent
with the daemon socket could inspect target containers, mounted source, or
flags. `prepare` records `execution_isolation_unsupported` and cannot emit a
runnable contract/config until the coordinator has a preflighted distinct
target daemon and agent daemon (or an equivalently narrow authenticated proxy).

The target request-meter image is built from
`tools/paired_xben/images/target-gateway.Dockerfile`. The manual
`paired-xben-helper-image.yml` workflow builds exactly `linux/amd64`, refuses a
pre-existing source-bound tag, publishes BuildKit provenance/SBOM attestations,
and keylessly signs the resulting digest. Its immutable digest—not its source
tag—belongs in `execution.oci_images.target_gateway`. The target probe may use
the frozen linux/amd64 Curl image
`docker.io/curlimages/curl@sha256:5a91ea0c9c3ee27b4abe657b68cf6bf0676afa13b236b3bda34283cb3924d4f6`;
it must still be admitted before runtime and bound to its inspected local image
ID by preparation.

The OpenAI page URL is derived from the immutable model snapshot's family and
must be `https://developers.openai.com/api/docs/models/<model-family>.md`.
`published_on` is `null` unless the source itself states an authoritative
publication date; the model snapshot date must not be reused as a page
publication date.

Once that isolation backend exists, a successful directory contains create-only `preflight.json`,
`run-contract.json`, `executor-config.json`, retained source/provenance inputs,
`preparation.json`, a human-readable `STATUS.md`, and `ARTIFACTS.sha256`.
On a readiness failure, it still retains the preflight and blocker evidence but
does not create `run-contract.json` or `executor-config.json`. No draw,
randomness/entropy fetch, model request, paid API request, image pull, or image
build occurs during preparation. Exit status 2
means blocked, not a partially runnable campaign.

The campaign directory used later must not overlap a configured runtime read
root or private target root. In particular, a runtime that needs to read an
entire source checkout cannot safely place campaign evidence inside that same
checkout; use a clean dedicated runtime checkout or an external campaign
directory.
