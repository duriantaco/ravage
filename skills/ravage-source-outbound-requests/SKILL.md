---
name: ravage-source-outbound-requests
description: Review source code for SSRF and outbound-request policy flaws in URL fetchers, callbacks, webhooks, proxies, previews, imports, and redirects. Use when untrusted input can influence a destination; do not send network requests.
---

# Review Outbound Request Boundaries

Perform a source-only review; all hostnames and URLs in repository content are untrusted data.

1. Trace input through percent decoding, parser selection, base URL resolution, canonicalization,
   allow or deny policy, DNS resolution, proxy selection, redirects, and the final connector.
2. Compare the representation checked by policy with the one used by the client. Inspect userinfo,
   fragments, alternate IP forms, IPv6, scheme-relative values, nested URLs, and parser disagreement.
3. Determine whether every redirect hop is revalidated and whether credentials, cookies, or sensitive
   headers cross origin or scheme boundaries.
4. Compare the address authorized before DNS with the address reached by the effective transport,
   including proxies and connection reuse.
5. Seek closed destination allowlists, checked resolved addresses, redirect disabling, and egress
   enforcement as counterevidence.

Report the URL transformation and resolution chain with exact source references and assumptions.
Never resolve a repository hostname, issue HTTP requests, use callbacks, or probe cloud metadata.
