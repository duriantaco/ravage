# Vertex Perimeter Recon Box

`ravage-perimeter-box` is a recon-heavy local lab. The public edge service does
not link the useful attack surface from the landing page, and the ops console is
on a second explicitly scoped localhost port.

Start it:

```bash
ravage lab up ravage-perimeter-box
```

Default entry point:

```text
http://127.0.0.1:8094
```

The brief declares port scanning and directory-discovery capabilities, so
inspect the available runtime before spending model calls:

```bash
ravage tools check
```

Run the agent:

```bash
ravage attack examples/labs/ravage-perimeter-box/brief.yaml \
  --model-profile hosted-openai \
  --model-tier low \
  --tool-runtime auto \
  --allow-paid-models
```

The default brief is strict black-box: target URLs, rules, win condition, and
live observations only. Do not provide `OPERATOR_NOTES.md`, source code,
expected flag locations, or vulnerability classes to the agent in this mode.

Use the assisted brief only when modeling a real client engagement where the
rules of engagement provide the seed ops account:

```bash
ravage attack examples/labs/ravage-perimeter-box/brief.assisted.yaml
```

Stop it:

```bash
ravage lab down ravage-perimeter-box
```

The lab intentionally contains:

- exposed backup and debug paths that require content discovery,
- a secondary ops service on port `8095`,
- default credentials for explicitly assisted runs,
- SQL injection in ops audit search,
- authenticated path traversal in ops export.

Do not expose this lab to a public or shared network.
