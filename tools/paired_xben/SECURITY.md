# Paired-XBEN authenticity boundary

The protocol verifies one commitment end to end:

- the exact commitment bytes are verified from a standardized Sigstore v0.3
  bundle using a frozen cosign verifier and trusted root;
- a verified RFC3161 timestamp, not Rekor `integratedTime`, must place that
  commitment after creation and before the committed draw;
- resolution fetches the exact committed round itself from two fixed official
  drand HTTPS relays and retains both raw response bodies;
- the responses must match, and one is BLS-verified offline against chain info
  whose hash, genesis time, and period match the commitment;
- the selection seed excludes operator-controlled campaign labels and times;
  and
- every primary-matrix or rerun reservation repeats offline authenticity
  verification over the retained evidence and frozen binary hashes.

Relay retrieval wall-clock times are intentionally not used or recorded as
authenticity evidence. The BLS-verified exact round establishes the beacon;
the RFC3161 TSA establishes the independently signed pre-draw publication time.

## Canonical namespace still required

Offline evidence can prove that a particular commitment existed before its
draw. It cannot prove that the operator did not also publish commitments for
other future rounds and later choose the most favorable one.

Before making a public **no-alternative-commitments** claim, the benchmark must
have one independently administered, append-only campaign namespace with a
documented **first-entry-wins** rule. Reviewers must be able to enumerate that
namespace and reject every later commitment even if its result is preferred.
A Rekor entry or RFC3161 time for one artifact does not by itself provide this
global uniqueness property.

Until such a namespace receipt is implemented, `verify` reports
`canonical_namespace_first_entry_verified: false` and limits `claim_ready` to
`single-commitment-integrity-only`.

The repository-scoped [public release ledger](PUBLIC_LEDGER.md) makes one campaign's
fixed phase sequence signed, timestamped, immutable after publication, and publicly
enumerable. It intentionally does **not** clear this boundary: the same operator
controls the repository and campaign identifiers, so it is not the independently
administered namespace required for a no-alternative-commitments claim.

## Terminal losses stay in the denominator

Process-receipt `valid` and row `valid_for_comparison` describe evidence
integrity, not a successful solve. A started primary that reaches its enforced
timeout or exits nonzero is a valid unsuccessful observation when the frozen
process/model receipts verify, the evaluator process group is gone, captures
are complete, and target teardown verifies. It is retained once and may not be
replaced or rerun.

Solve credit has an additional clean-exit requirement: the outer adapter must
complete with return code zero and the committed flag candidate must match. A
flag-shaped artifact can therefore never rescue a timeout or nonzero exit.
Missing/corrupt receipts, failed process-group or target teardown, unsafe
retained output, incomplete non-timeout extraction, and unstarted rows remain
invalid infrastructure/evidence outcomes rather than benchmark losses.

## Bootstrap trust

The retained verifier binaries and Sigstore trusted root are hash-bound before
the future round so post-commit replacement fails closed. Their initial
provenance is still a reviewer/CI bootstrap responsibility: publish the helper
build logs, binary digests, cosign release provenance, and trusted-root source
alongside the campaign. The drand helper source pins
`github.com/drand/drand/v2` and its Go module graph; its known-answer test checks
a real mainnet beacon and rejects a forged signature.
