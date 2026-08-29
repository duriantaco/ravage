---
name: hunt-ssrf
description: Investigate authorized server-side request forgery and URL-fetch boundaries. Use when typed discovery identifies server-side webhooks, callbacks, previews, proxying, imports, remote-resource fetches, URL parser differentials, or a suspected server-origin request primitive.
---

# Hunt Server-Side Request Boundaries

Treat this card as advisory prioritization. Scope, TrafficPolicy, replay contracts, and native
evidence remain authoritative.

## Workflow

1. Select a typed URL-fetch operation and preserve its method, identity, fields, and encoding.
2. Pair an ordinary baseline with a same-shape negative control; change one URL component.
3. Use `ssrf_boundary`; use `file_fetch_parser` only for a typed import or parser. The SSRF
   specialist includes fixed internal and metadata destinations, so run it only if all are authorized.
4. Separate server-origin requests from redirects, reflection, validation, and caching. Preserve
   redacted replays, deltas, and evidence references whether or not a challenge artifact exists.

## Evidence Gate

Confirm only a controlled target-origin request or protected-resource differential unexplained by
the paired control. Status, timing, DNS behavior, reflected URLs, and errors remain observations.
Keep any `contract_missing` result suspected rather than promoting it.

## Stop Conditions

Stop without a typed sink, replay, safe comparison, or remaining policy budget. Do not add range
scans or unapproved out-of-band destinations, and redact returned secrets.
