# Security Policy

Ravage is a pre-1.0 research project for controlled, authorized security
testing. Its lab applications are intentionally vulnerable; the security
policy covers Ravage itself, its packaging, and the boundaries it promises to
enforce.

## Supported Versions

Security fixes target the latest commit on `main` and the latest tagged
release, when one exists. Older releases, superseded snapshots, historical
benchmark archives, and intentionally vulnerable lab targets are not supported
release lines.

The untagged `0.0.1` and `0.5.0` PyPI previews are not supported release lines.
Use the latest tagged release when one exists; otherwise use the repository
checkout and identify the exact commit in reports.

## Report A Vulnerability Privately

Use [GitHub private vulnerability reporting](https://github.com/duriantaco/ravage/security/advisories/new).

Do not disclose security details in a public issue, pull request, discussion,
benchmark artifact, or log. Do not include provider keys, cookies, customer
data, real credentials, or unredacted target evidence.

Include only what is needed to reproduce the problem:

- affected version or commit;
- operating system, Python version, and tool runtime;
- the security boundary crossed and likely impact;
- minimal reproduction steps using synthetic data or a local fixture;
- redacted logs or a small proof of concept;
- any suggested mitigation.

Please coordinate disclosure until a fix or mutually agreed disclosure date is
available. Response and remediation timing is best effort; this is currently a
small research project without a paid security-response program.

## In Scope

Examples include:

- bypassing target authorization or explicit scope enforcement;
- causing Ravage tools to access an unapproved host or service;
- host or container escape from the scoped tool runtime;
- unintended command execution outside the documented execution boundary;
- leakage or failed redaction of credentials, tokens, provider secrets, or
  private evidence;
- tampering with audit integrity, proof validation, exact-flag scoring, or cost
  records;
- compromise of Ravage packages, release automation, or update paths.

## Out Of Scope

Use a normal issue or the benchmark-reproduction template for:

- vulnerabilities intentionally present in Ravage lab boxes or upstream
  benchmark targets;
- vulnerabilities in third-party targets, model providers, GitHub, or PyPI;
- benchmark misses, model hallucinations, false positives, or score disputes
  that do not cross a security boundary;
- documented limitations without a new exploit path.

## Testing Boundaries

Test Ravage only against local synthetic fixtures, isolated lab boxes, or
systems you own and are explicitly authorized to assess. This policy does not
authorize testing third-party infrastructure, maintainer accounts, package
registries, or model providers.

Do not perform denial-of-service testing, social engineering, credential
attacks, or destructive testing. There is currently no bug-bounty or payment
program.
