# Acme Support Portal

Acme Support Portal is a deliberately vulnerable local web box for Ravage
development and demonstrations.

Do not deploy this application to any public or shared network. It contains
intentional authentication, authorization, injection, JWT, and SSRF weaknesses.
It is only for local authorized testing.

## Start

```bash
ravage lab up ravage-acme-box
```

Open:

```text
http://127.0.0.1:8088
```

Stop:

```bash
ravage lab down ravage-acme-box
```

## Brief Modes

The default brief is strict black-box and matches the XBEN-style contract:

```bash
ravage attack examples/labs/ravage-acme-box/brief.yaml
```

In that mode, the agent gets the target URL, rules, win condition, and live
observations only. Do not give it `OPERATOR_NOTES.md`, source code, expected
flag locations, or vulnerability classes.

Use the assisted brief only when modeling a real client engagement where the
rules of engagement provide a seed account:

```bash
ravage attack examples/labs/ravage-acme-box/brief.assisted.yaml
```

The live application does not display credentials. Assisted seed credentials
live in `OPERATOR_NOTES.md`.

## Authenticated Scan

From the repository root, start the lab, check its lab-only login, and select
the configured `analyst` identity:

```bash
ravage lab up ravage-acme-box

ravage auth check examples/labs/ravage-acme-box/brief.authenticated.yaml \
  --identity analyst \
  --env-file examples/labs/ravage-acme-box/.env.example

ravage scan examples/labs/ravage-acme-box/brief.authenticated.yaml \
  --identity analyst \
  --env-file examples/labs/ravage-acme-box/.env.example \
  --all-probes
```

The authenticated brief logs in through `/login` and verifies the resulting
session through `/api/me` before eligible probes. Authentication-bypass probes
still run anonymously by design. The credentials in `.env.example` belong only
to this deliberately vulnerable localhost lab; do not reuse them elsewhere.

## Flags

Total flags: 4.

The default flags are provided by Docker Compose environment variables and can
be overridden by a benchmark harness:

- `RAVAGE_FLAG_LOW`: invoice IDOR flag
- `RAVAGE_FLAG_USER`: catalog SQL injection flag
- `RAVAGE_FLAG_ADMIN`: forged admin JWT flag
- `RAVAGE_FLAG_ROOT`: internal metadata SSRF flag

## Intended Attack Chain

1. Discover or obtain an initial access path. In assisted mode, use the seed
   account from operator notes.
2. Enumerate invoice ids against the API and capture the IDOR flag.
3. Exploit catalog SQL injection to read the catalog secret.
4. Find the leaked JWT staging hint, forge an admin token, and capture the
   admin flag.
5. Use the admin URL preview feature to request the internal metadata service
   and capture the root flag.

## Vulnerability Classes

- Default credentials
- IDOR / broken object-level authorization
- SQL injection
- Weak JWT signing secret exposure
- SSRF to an internal service
