---
name: ravage-source-advisory-discovery
description: Inventory dependencies from an authorized repository, lockfile, or repository-contained SBOM and find current CVE, GHSA, and vendor advisory candidates. Use when known vulnerabilities or public exploit references are requested without a specific advisory ID.
---

# Discover Source Advisory Candidates

Read [references/advisory-sources.md](references/advisory-sources.md). The repository snapshot is the
only application evidence; external access is limited to current public advisory metadata.

1. Inventory exact ecosystem, package, version, package URL, source registry, dependency role, and
   provenance from lockfiles, manifests, vendored metadata, or repository-contained SBOMs.
2. Distinguish direct, transitive, optional, development, build, test, bundled, and runtime
   components. Do not run package-manager commands or fetch missing dependencies.
3. When current research is permitted, query primary vendor or project advisories and authoritative
   databases using the exact coordinates. Record URLs, aliases, publication and modification dates,
   retrieval time, affected ranges, fixed releases or commits, and stated prerequisites.
4. Record public-exploit availability only as provenance-bearing metadata. Do not open, copy,
   download, adapt, or execute exploit code.
5. Return deduplicated advisory candidates and route each viable one to
   ravage-source-advisory-applicability. An empty result is not evidence that the code is safe.

Do not query a live application, scan hosts, send private package names to an unapproved service, or
promote a version match to a source finding.
