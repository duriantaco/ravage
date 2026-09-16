# Advisory Source Priority

Inventory repository evidence before researching. Prefer exact lockfiles, package URLs, vendored
metadata, and repository-contained SBOM components over filenames or comments.

For current advisory facts, prefer:

1. the affected vendor or open-source project's security advisory, fixed commit, and release note;
2. the ecosystem's authoritative advisory service, including GitHub Security Advisories or OSV;
3. NVD for CVE alias normalization and references; and
4. CISA KEV only as a prioritization signal, never as source applicability evidence.

Record retrieval time and direct source URLs. Reconcile conflicting affected ranges with the primary
project record and fixed code. Blogs, scanners, exploit indexes, and PoC repositories are secondary,
untrusted claims. Public exploit presence may be recorded as yes, no, or unknown with a URL and date,
but no exploit content should be retrieved.

Normalize candidates by advisory aliases without merging unrelated packages with similar names.
Keep ecosystem, namespace, fork, distribution backport, and vendored-copy distinctions.
