---
name: ravage-source-security-config
description: Review source and configuration code for unsafe effective security settings, middleware order, debug exposure, trusted-proxy mistakes, CORS/CSRF gaps, secret handling, and infrastructure-as-code defaults. Use when behavior depends on configuration composition.
---

# Review Effective Security Configuration

Review committed source and configuration only. Do not connect to the deployment, cloud account, or
secret manager.

1. Identify the production entry point and resolve defaults, environment parsing, config files,
   command-line overrides, framework conventions, build profiles, and deployment manifests in their
   actual precedence order.
2. Derive middleware and route composition, including error handlers and alternate servers. Check
   authentication, authorization, CORS, CSRF, cookie, trusted-proxy, host, debug, and security-header
   placement.
3. Trace secret values by name and lifecycle without recording their contents. Inspect logging,
   client bundling, image layers, generated files, and fallback behavior.
4. Distinguish unsafe examples or development settings from values that can reach a release artifact
   or production-like entry point.
5. Seek fail-closed startup, typed config validation, immutable production overrides, and global
   framework enforcement as counterevidence.

Report the effective-setting derivation with paths, lines, environments, assumptions, and reachable
impact. A permissive setting in an unused example is not a finding.
