# Aegis

**A lightweight, single-host Endpoint Detection and Response (EDR-lite) tool for Linux.**

Aegis monitors a Linux host for security-relevant behavior — process activity, network connections, file integrity, and privilege changes — and evaluates that activity against a configurable rule engine to detect signs of compromise. It's built as a two-layer system: a C daemon that senses OS-level activity, and a Python rule engine that interprets it.

---

## Status

> **This section reflects real, current progress — update it honestly as work happens, don't let it drift out of sync with the actual repo.**

- [ ] Week 0 — Skills foundation, SAM anomaly detection layer completed
- [ ] Week 1 — Daemon foundation, event schema locked
- [ ] Week 2 — File integrity watcher, floor-tier detection rules
- [ ] Week 3 — Privilege detection, sensing↔policy IPC integration
- [ ] Week 4 — Mid-tier detection rules, severity scoring
- [ ] Week 5 — Attack simulation, integration testing
- [ ] Week 6 — Documentation, demo, polish

See [`docs/03-aegis-scope.md`](docs/03-aegis-scope.md) for the full week-by-week plan.

---

## Why Aegis Exists

Most introductory security projects (login systems with brute-force detection, file hashers, basic packet sniffers) demonstrate application-layer security hygiene — they don't require understanding process internals, privilege models, or how attacker behavior actually surfaces as OS-level signals.

Aegis is scoped deliberately differently: the systems side requires real OS/process internals engineering (daemon design, `/proc` parsing, privilege tracking), and the security side requires real threat reasoning — understanding *why* a given signal indicates compromise, not just pattern-matching strings. It's a two-person project where both roles are substantive systems/security engineering work, not one person doing the engineering and the other doing setup.

This project also builds directly on [SAM (System Activity Monitor)](#), a prior C tool that established the foundational `/proc`-based process scanning, network connection scanning, and anomaly detection that Aegis's sensing layer extends.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         AEGIS HOST                            │
│                                                                 │
│  ┌──────────────────┐         ┌───────────────────────────┐  │
│  │   SENSING LAYER   │  JSON   │      POLICY LAYER          │  │
│  │   (aegisd, C)     │ events  │   (Python rule engine)     │  │
│  │                   │ ──────► │                             │  │
│  │  - Process scan   │  via    │  - Rule engine              │  │
│  │  - File watch     │  Unix   │  - Severity scoring         │  │
│  │  - Net connections│ socket  │  - Alert generation         │  │
│  │  - Privilege chk  │         │  - Log/alert output         │  │
│  └──────────────────┘         └───────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

The two layers communicate over a locked JSON event schema (see [`docs/06-aegis-schema-reference.md`](docs/06-aegis-schema-reference.md) and the formal schema at [`schema/aegis-event-schema-v1.json`](schema/aegis-event-schema-v1.json)). This schema is the contract between the two halves of the system — both sides are built and tested against it independently.

Full architectural detail, including IPC mechanism choice, polling strategy, and component breakdown, is in [`docs/02-aegis-architecture.md`](docs/02-aegis-architecture.md).

---

## What Aegis Detects

| Event type | What it watches | Example detection |
|---|---|---|
| `process_spawn` | New processes, parent-child lineage | A shell process spawned from a web server process — classic reverse shell pattern |
| `process_exit` | Process termination, exit codes | Very short-lived processes from unexpected parents |
| `net_connection` | Active TCP connections | Outbound connections to known reverse-shell-style ports |
| `file_modified` | SHA-256 integrity on sensitive paths | Modification of `/etc/shadow`, `/etc/passwd`, SSH config outside expected admin operations |
| `privilege_change` | UID/EUID transitions | A non-root process acquiring EUID 0 — privilege escalation |

Full field reference and worked examples for every event type: [`docs/06-aegis-schema-reference.md`](docs/06-aegis-schema-reference.md).

---

## Roles

**Systems Security Engineer — sensing layer**
Daemon design and lifecycle (fork/detach, signal handling, graceful shutdown), `/proc`-based process and network telemetry, file integrity hashing, privilege transition detection, and the event schema that defines the contract with the policy layer.

**Security / Detection Engineer — policy layer**
Detection rule design and implementation, severity scoring, and the reasoning behind what OS-level signals indicate compromise — starting from simple static rules and growing toward time-windowed correlation across multiple signal types.

Both roles are intentionally substantive — see [`docs/01-aegis-project-proposal.md`](docs/01-aegis-project-proposal.md) for why this split was deliberately designed this way, and what it was designed to avoid.

---

## Project Documents

| Document | Purpose |
|---|---|
| [`docs/01-aegis-project-proposal.md`](docs/01-aegis-project-proposal.md) | Why this project exists, problem statement, roles, risks |
| [`docs/02-aegis-architecture.md`](docs/02-aegis-architecture.md) | Full system architecture, component breakdown, technology choices |
| [`docs/03-aegis-scope.md`](docs/03-aegis-scope.md) | In/out of scope boundaries, week-by-week build plan, definition of done |
| [`docs/06-aegis-schema-reference.md`](docs/06-aegis-schema-reference.md) | Field-by-field event schema reference with worked examples |
| [`schema/aegis-event-schema-v1.json`](schema/aegis-event-schema-v1.json) | Formal JSON Schema, used for runtime validation in the policy layer |

---

## What's Explicitly Out of Scope

Aegis is scoped narrowly on purpose, to be completable in 6–7 weeks by two people without sacrificing depth. Explicitly excluded:

- eBPF / kernel modules (stays in userspace, `/proc`-based polling)
- IPv6 and UDP connection tracking
- Machine learning / statistical anomaly detection
- Multi-host or distributed agent architecture
- Web dashboard (terminal/CLI output only)
- Database backend (flat JSON logs)
- Offensive tooling / exploit development — Aegis is defensive only

Full reasoning for each exclusion: [`docs/03-aegis-scope.md`](docs/03-aegis-scope.md).

---

## Tech Stack

| Component | Technology |
|---|---|
| Sensing layer | C, `cJSON` |
| Policy layer | Python, `jsonschema` |
| IPC | Unix domain socket (newline-delimited JSON) |
| Storage | Flat JSON log files |
| Platform | Linux only |

---

## Running Aegis

> To be filled in once the daemon and rule engine reach a runnable state. Will include build instructions, configuration (watched paths, rule definitions), and how to start/stop `aegisd`.

---

## Demo

> A short demo (terminal recording) showing Aegis detecting a simulated attack scenario end-to-end will be added here once Week 5 integration testing is complete.

---

## Authors

Built by [Your name] (systems security engineer) and Faizan (security / detection engineer) as a portfolio project.