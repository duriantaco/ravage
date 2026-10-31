# Paired XBEN agent isolation

The paired XBEN executor must use two independent Docker authorities. The
persistent evaluator daemon owns the vulnerable target and the HTTP request
meter. A new Colima/Lima VM owns agent tool containers for exactly one primary
row and is deleted when that row becomes terminal.

```text
model provider
     ^
     | evaluator row-token gateway (host process only)
Ravage/Strix adapter on macOS
     |
     | dedicated agent Docker socket
     v
ephemeral Colima/Lima VM ---- host-enforced target relay ----> request meter
     |                                                       (target daemon)
     +-- one internal tool network                                  |
     +-- one digest-pinned tool image                               v
     +-- no target Docker socket                              target network
```

`ravage.xben_parts.comparison_agent_vm` implements the create-only lifecycle
and its independent receipt validator. Before an agent can start it requires:

1. different live daemon identity digests and different Unix sockets;
2. an empty agent inventory (no images, containers, volumes, or custom
   networks);
3. a live evaluator label on the target daemon that returns no matches through
   the agent daemon;
4. an offline OCI archive whose bytes, repository digest, image ID, OS, and
   architecture match the frozen contract;
5. a single internal row network; and
6. a host-enforced relay receipt with active positive and negative probes.

Each row gives this manager a new, empty evaluator-owned mode-0700 evidence
subdirectory. Lifecycle JSON is create-only mode 0600, and the relay transcript
must also be an evaluator-owned, single-link mode-0600 file in that directory.

The live VM start receipt must also attest a fresh writable disk, `linux/amd64`,
no host filesystem mounts, no host credential or target-Docker-socket
forwarding, and an outer-host/hypervisor-owned network policy. Default Colima
home-directory mounts are not accepted.

Both the VM controller policy and relay policy have precommitted SHA-256
identities. The controller-policy artifact must in turn bind the supervisor
binary, Lima template, golden/base disk, hypervisor executable, architecture,
and absence of host filesystem or credential forwarding. A live ephemeral
daemon ID is row evidence; it is never substituted with the template or base
disk digest.

After the row, the lifecycle is valid only if the relay is removed, the VM
controller reports the profile deleted, the planned socket is absent, and a
Docker identity query through the former endpoint fails. A failed or partial
generation is burned and can never be reused. A live agent-daemon identity may
appear in only one row. Any provisioning failure or teardown without a valid
terminal receipt poisons the manager, preventing later rows from starting in
the same campaign process.

## Why ordinary Colima networking is insufficient

Giving an agent a Docker socket is equivalent to giving it administrative
control of that VM. An `Internal=true` Docker network and firewall rules inside
the guest therefore do not enforce the boundary: the agent can create a
privileged container, change guest routing, or attach another network.

The accepted relay mechanisms are deliberately host-owned:

- QEMU user networking with `restrict=on` and only explicit guest forwards; or
- a macOS PF anchor bound to the unique VM source identity.

Both require active probes showing that the target meter is reachable, direct
target access is not, public/default and DNS egress are denied, and the model
provider cannot be reached from the VM. The six results and distinct gateway
challenge digests are retained as the row-bound, canonical
`host-relay-active-probes.json`; its file digest is joined into the relay and
provision receipts. A normal Colima NAT, a guest firewall, a malformed probe
set, or a controller-supplied boolean is rejected.

## Current integration boundary

The lifecycle manager is ready to be backed by a pinned Colima/Lima supervisor,
but the current campaign executor cannot yet make the relay real. Its target
gateway's Docker-alias mode joins a network on the target daemon, and its
production adapter receives the same daemon socket. Cross-daemon execution must
remain blocked until all of the following are wired together:

- target-side host-loopback meter mode that never joins an agent network;
- a pinned Colima/Lima controller implementing `EphemeralAgentVmController`;
- a host network supervisor implementing `HostEnforcedRelayController`;
- offline OCI archives prepared before commitment; and
- row evidence that joins `agent-daemon-provision.json` and
  `agent-daemon-teardown.json` to the process and request-meter receipts.

No score produced through the old shared-daemon path is eligible for the
no-cheating comparison. The preparation command must continue to report
`execution_isolation_unsupported` until this integration is complete and its
live canaries pass.
