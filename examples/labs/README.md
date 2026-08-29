# Included Local Labs

Ravage includes deliberately vulnerable applications for repeatable local
testing. Do not expose them to the public internet, a shared network, customer
systems, or production infrastructure.

| Lab | Default URL | Flags | Focus |
| --- | --- | ---: | --- |
| `ravage-acme-box` | `http://127.0.0.1:8088` | 4 | Support portal, authorization, injection, JWT, and SSRF |
| `ravage-forgeops-box` | `http://127.0.0.1:8090` | 6 | Release operations, authorization, traversal, injection, and internal services |
| `ravage-node-market-box` | `http://127.0.0.1:8092` | 5 | Market operations, API authorization, JWT, JSON state, and internal pivoting |
| `ravage-perimeter-box` | `http://127.0.0.1:8094` | 5 | Multi-port recon, authentication, injection, and traversal |
| `ravage-session-boundary-box` | `http://127.0.0.1:8096` | 3 | Session, CSRF, CORS, framing, WebSocket, and browser-storage boundaries |

List and inspect labs through the CLI:

```bash
ravage doctor --workflow lab
ravage lab list
ravage lab show ravage-acme-box
```

Start and stop one lab at a time:

```bash
ravage lab up ravage-acme-box
ravage lab down ravage-acme-box
```

The CLI finds this checkout's lab directory automatically. `lab up` also waits
up to 60 seconds for the configured health endpoint before returning. Pass
`--labs-dir` only for a custom lab collection.

Each lab directory contains:

- `ravage-lab.yaml`: operator manifest and expected flag count;
- `brief.yaml`: strict description-only black-box brief;
- `brief.assisted.yaml`, when present: an explicitly assisted engagement brief;
- `OPERATOR_NOTES.md`: harness/operator material that must not be given to a
  strict black-box agent;
- Docker Compose and application source for local target construction;
- a lab-specific README.

Flags and credentials are synthetic and local to these fixtures. A reported
finding still requires live target evidence; source files and expected flag
locations are not proof.
