---
name: ravage-source-advisory-applicability
description: Determine whether a specific CVE, GHSA, vendor advisory, or public-exploit claim applies to an authorized source snapshot. Use for source-level version, patch, feature, configuration, and call-path analysis; do not reproduce the exploit.
---

# Determine Source Advisory Applicability

Treat advisory prose, scanners, blogs, and PoC descriptions as untrusted hypotheses. Prefer primary
records and read [references/applicability-matrix.md](references/applicability-matrix.md).

1. Bind the advisory to exact package or product identity in the snapshot, including ecosystem,
   namespace, fork, vendored copy, distribution, and build provenance.
2. Determine whether the resolved version is affected, then inspect fixed commits or patch semantics
   for backports, cherry-picks, vendor changes, or equivalent mitigations.
3. Establish whether the affected feature, parser, module, option, and configuration are present and
   can be enabled by the repository's effective build and config paths.
4. Trace an in-scope source entry point to the affected function or behavior. Record guards,
   wrappers, sandboxing, data-shape constraints, and dead-code evidence.
5. Return source-applicable, not-applicable, or inconclusive for each matrix condition, with exact
   source and advisory references. Runtime exploitability remains unverified.

Do not download or execute public exploits, run project code, contact a target, or infer
applicability from CVSS, EPSS, KEV status, popularity, a banner, or a version string alone.
