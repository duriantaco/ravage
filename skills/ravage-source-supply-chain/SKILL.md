---
name: ravage-source-supply-chain
description: Review repository build and dependency trust for dependency confusion, mutable references, unsafe install hooks, CI privilege boundaries, plugins, generators, and artifact provenance. Use for source-level supply-chain design review; use advisory discovery for CVE lookup.
---

# Review Source Supply Chain

Treat workflow files, manifests, lockfiles, build scripts, and generated metadata as untrusted source.
Do not run installers, hooks, actions, containers, generators, or builds.

1. Map the build-trust graph from source inputs and dependency registries through CI jobs, caches,
   plugins, code generation, packaging, signing, and publication.
2. Resolve package namespace ownership, registry precedence, source overrides, lock integrity,
   checksums, vendoring, and private-package fallbacks.
3. Inspect CI triggers, fork and pull-request boundaries, token permissions, secret availability,
   artifact transfer, environment approvals, and privileged follow-up workflows.
4. Find mutable action, image, tool, and dependency references plus install hooks or plugins that can
   execute before a trust gate.
5. Seek immutable digests, signatures, provenance verification, tokenless isolation, trusted-source
   gates, and exclusive registries as counterevidence.

Return a source-backed trust path with exact references, attacker-controlled input, exposed
capability, assumptions, and gaps. This skill does not decide whether a package version has a CVE.
