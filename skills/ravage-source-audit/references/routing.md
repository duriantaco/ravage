# Source Review Routing

Load only the specialist needed for the observed boundary.

| Code or request signal | Specialist |
| --- | --- |
| Broad audit, unknown class, mixed codebase | ravage-source-audit |
| Roles, ownership, tenancy, policy, IDOR/BOLA | ravage-source-access-control |
| Checkout, entitlement, approval, recovery, quota, workflow | ravage-source-business-logic |
| Transactions, locks, retries, duplicate jobs, TOCTOU | ravage-source-concurrency |
| SQL, commands, templates, expressions, query languages | ravage-source-injection |
| Paths, uploads, archives, XML/YAML, object decoding | ravage-source-files-and-parsers |
| URL fetches, callbacks, webhooks, proxies, redirects | ravage-source-outbound-requests |
| Sessions, JWT, OAuth/OIDC, API keys, reset tokens | ravage-source-identity-tokens |
| Middleware order, debug, CORS/CSRF, proxies, secrets, IaC | ravage-source-security-config |
| CI, build scripts, package sources, mutable refs, plugins | ravage-source-supply-chain |
| Dependency inventory plus current advisory search | ravage-source-advisory-discovery |
| Named CVE, GHSA, vendor advisory, or public-exploit claim | ravage-source-advisory-applicability |
| Independent review of one completed source candidate | ravage-source-adjudication |

Words alone do not route a finding. For example, a variable named token is not necessarily an
identity boundary, and a function named execute is not necessarily a command sink. Prefer the
semantic operation, reachable callers, and effective configuration.

For “find bugs” requests, start broad and select specialists after mapping entry points. For “known
CVEs” without an identifier, inventory first through advisory discovery. With a specific advisory,
go directly to applicability. Do not invoke live validation from this pack.
