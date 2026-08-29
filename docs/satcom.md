---
title: Passive SATCOM Analysis
---

# Passive SATCOM Analysis

Ravage phase-one SATCOM support inventories local, authorized artifacts without
opening a network connection, starting a subprocess, replaying a packet, or
transmitting RF. It is a separate typed surface graph, not an HTTP route forced
into the web graph.

## Inspect An Artifact

For a checksum-valid Two-Line Element catalog:

```bash
ravage satcom inspect orbit.tle \
  --format tle \
  --output orbit-report.json
```

For an exact concatenation of CCSDS Space Packets:

```bash
ravage satcom inspect capture.bin \
  --format ccsds-space-packets \
  --direction auto \
  --output packet-report.json
```

Use `--direction telemetry` or `--direction telecommand` to reject a stream
containing the other primary-header packet type. Ravage does not guess the
format, scan for a sync marker, or recover framing after malformed input.

Output files are private JSON, written atomically with mode `0600`. Existing
files are not replaced unless `--force` is explicit, and an output can never
replace its input. Omitting `--output` prints JSON to standard output.

## What The Report Means

The report uses `ravage.satcom-passive-report.v1` and embeds a deterministic
`ravage.satcom-surface.v1` graph.

TLE analysis retains spacecraft catalog identities, classifications, orbital
elements, per-line digests, and evidence references. It validates structure
and checksums but does not perform a network lookup, calculate a pass, or
propagate an orbit.

CCSDS analysis retains every complete packet's offset, length, version, packet
type, secondary-header-present bit, APID, sequence flags and count, and content
digests. It inventories telemetry and telecommand operations without copying
packet payload bytes into the report. Byte-identical repeated telecommands and
counter reuse with different packet bytes are retained as candidate or
informational signals.

Those signals are not vulnerabilities by themselves. Retransmission, reset,
counter wraparound, or capture composition can explain them. Phase one always
leaves `confirmed_findings` and `flags` empty because a passive primary header
cannot prove missing authentication, replay acceptance, command execution, or
mission impact. Malformed lengths, invalid checksums, unsupported versions, and
truncated records fail input validation rather than producing a partial report.

The reader accepts only a bounded regular file. It rejects final-component
symlinks, FIFOs, devices, mutation during the read, artifacts above 64 MiB,
more than 8,192 CCSDS packets, and more than 1,024 TLE records.

## How This Relates To HTB's Satellite Track

[Hack The Box's Satellite Exploitation Track](https://www.hackthebox.com/blog/hack-the-orbit-satellite-exploitation-track)
progresses across orbital calculations, CCSDS packet and CRC construction,
stateful telemetry/telecommand exchange, a mission-control web surface,
firmware and I²C analysis, AFSK demodulation, and a simulated raw ZMQ radio
link. Ravage phase one intentionally covers only the passive artifact foundation:
strict TLE inventory and CCSDS Space Packet primary-header decoding.

A safe capability sequence for Ravage is:

1. passive TLE and Space Packet inventory — implemented now;
2. TM/AOS/TC transfer frames, virtual channels, CRC, and mission dictionaries;
3. an isolated simulator-only stateful exchange with explicit command and
   replay evidence contracts;
4. mission-control web traffic joined through the existing identity-aware HTTP
   graph;
5. offline firmware, I²C, PCAP, WAV/AFSK, and IQ adapters; and
6. only then, an explicitly authorized ephemeral executor for a simulated radio
   or ZMQ link, with a separate transmit permission and complete accounting.

Each stage needs typed parsers and executor-owned validation before a knowledge
skill can usefully guide it. A prose card cannot create a modem, infer a
spacecraft identity, or turn a suspicious counter into a confirmed finding.

Per-agent VMs are not a training requirement. Isolation is an execution
control. The [Improvement Lab](improvement-lab.md) currently emits a hardened
networkless container job specification for candidate evaluation; a future
microVM backend is appropriate for adversarial firmware tools or simulator
transmit tests, not for ordinary passive parsing.
