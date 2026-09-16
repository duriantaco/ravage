---
name: ravage-source-identity-tokens
description: Review source code for session, JWT, OAuth/OIDC, API-key, password-reset, invitation, and other credential-lifecycle flaws. Use when code mints, binds, verifies, rotates, revokes, or consumes identity-bearing tokens.
---

# Review Identity And Token Lifecycles

Keep raw credentials and secrets out of findings. Do not decode captured production tokens or attempt
forgery, cracking, login, or provider requests.

1. Build a lifecycle matrix for minting, entropy, storage, transport, subject and purpose binding,
   verification, authorization use, rotation, expiry, revocation, and one-time consumption.
2. For JWT or signed tokens, derive the effective verifier configuration: permitted algorithms,
   trusted key source, key identifier handling, issuer, audience, time claims, critical headers, and
   claim-to-principal mapping.
3. For OAuth/OIDC and recovery flows, trace state, nonce, PKCE, redirect selection, code exchange,
   account linking, and callback identity binding.
4. Check privilege changes, login, logout, password reset, account recovery, and role changes for
   session rotation and cache invalidation.
5. Seek library defaults, centralized verifier wrappers, atomic token consumption, and server-side
   revocation as counterevidence.

Return exact source paths, the lifecycle gap, affected identity property, required configuration,
counterevidence, and uncertainty. A weak-looking claim or algorithm name alone is not a vulnerability.
