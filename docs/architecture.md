# Aegis — Architecture Document

## 1. System Overview

Aegis is a two-layer, single-host security monitoring system:

```
┌─────────────────────────────────────────────────────────────┐
│                         AEGIS HOST                           │
│                                                              │
│  ┌──────────────────┐         ┌───────────────────────────┐  │
│  │   SENSING LAYER   │  JSON   │      POLICY LAYER          │  │
│  │   (aegisd, C)     │ events  │   (Python, Faizan-owned)   │  │
│  │                   │ ──────► │                             │  │
│  │  - Process scan   │  via    │  - Rule engine              │  │
│  │  - File watch     │  pipe/  │  - Severity scoring         │  │
│  │  - Net connections│  socket │  - Alert generation         │  │
│  │  - Privilege chk  │         │  - Log/alert output         │  │
│  └──────────────────┘         └───────────────────────────┘  │
│         owned by: Furqan            owned by: Faizan         │
└─────────────────────────────────────────────────────────────┘
```

The boundary between these layers is the **event schema** — a JSON contract defined in Week 1 and frozen (changes require explicit renegotiation) for the rest of the project. This is the single most important architectural decision: it lets both halves be built in parallel without one blocking the other.

## 2. Sensing Layer (Systems Security Engineer)

### 2.1 Components

| Component | Function | Basis |
|---|---|---|
| Process Monitor | Polls `/proc/[pid]/` for new/exited processes, parent-child lineage, command line, UID/EUID | Extends SAM process scanning |
| Network Monitor | Reads `/proc/net/tcp` (and `tcp6` if time permits) for active connections, maps to owning PID | Extends SAM network scanning |
| File Integrity Watcher | Hashes (SHA-256) a configurable set of sensitive paths (e.g., `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`, project-defined "protected" dirs), detects modification | New for Aegis |
| Privilege Transition Detector | Flags processes where EUID changes during execution (UID 0 acquisition outside expected paths), and unexpected setuid binary execution | New for Aegis, builds on existing fd-symlink anomaly work |
| Event Emitter | Serializes all of the above into the agreed JSON schema, writes to a named pipe or local Unix domain socket consumed by the policy layer | New for Aegis |

### 2.2 Daemon Behavior

- Runs as a background daemon (`aegisd`), not a foreground script — this is a deliberate scope decision to make the systems half real (daemonization, signal handling, graceful shutdown via `SIGINT`/`SIGTERM`, PID file management).
- Polling-based (not eBPF/kernel-module-based) — consistent with SAM's existing `/proc`-based approach. This keeps the systems scope achievable in the timeline; eBPF is explicitly deferred (see Scope document).
- Configurable polling interval, with a documented tradeoff: faster polling catches more but costs CPU; this tradeoff should be measured and stated, not just assumed.

### 2.3 Event Schema (locked Week 1)

```json
{
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "event_type": "process_spawn | process_exit | net_connection | file_modified | privilege_change",
  "source": {
    "pid": 1234,
    "ppid": 1000,
    "uid": 0,
    "euid": 0,
    "cmdline": "string",
    "exe_path": "string"
  },
  "detail": {
    "_comment": "event_type-specific fields, e.g. for file_modified: path, old_hash, new_hash",
    "...": "..."
  }
}
```

This schema is the contract. **Both of you should review and agree on it explicitly before either layer is built further** — this is the single biggest interface-coupling risk named in the proposal, and it's solved by locking this early, not by hoping it stays stable by accident.

## 3. Policy Layer (Security / Detection Engineer)

### 3.1 Components

| Component | Function | Growth path |
|---|---|---|
| Rule Loader | Reads rule definitions (start: simple YAML/JSON static rules) | Floor: hardcoded conditions. Ceiling: composable rule chaining |
| Evaluation Engine | Applies rules to incoming events, tracks state where needed (e.g., "5 failed file-hash checks in 60s") | Floor: stateless per-event rules. Ceiling: time-windowed/stateful correlation |
| Severity Scorer | Assigns a severity (info/warning/critical) to matched rules | Floor: rule-defined static severity. Ceiling: weighted scoring across multiple correlated signals |
| Alert Output | Writes alerts to a log file and/or simple console/dashboard output | Floor: structured log lines. Ceiling: simple terminal dashboard (curses or similar) |

### 3.2 Example Rule Progression (Faizan's learning path, concrete)

**Week 2 (floor — no security background required):**
```yaml
rule: shadow_file_modified
match: event_type == "file_modified" AND path == "/etc/shadow"
severity: critical
```

**Week 4 (mid — requires understanding attacker behavior patterns, taught alongside the work):**
```yaml
rule: shell_from_web_process
match: event_type == "process_spawn" AND parent_cmdline contains ("nginx"|"apache") AND cmdline contains ("bash"|"sh"|"nc")
severity: critical
```

**Week 5–6 (ceiling — correlation, only if pace allows):**
```yaml
rule: privilege_escalation_chain
match: privilege_change event WITHIN 30s of a process_spawn event from a non-standard exe_path
severity: critical
```

This progression is the deliberate on-ramp: each tier is independently demoable, so the project has a real result even if Faizan only reaches the floor or mid tier.

## 4. Data Flow

1. Sensing layer detects a kernel/OS-visible event (new process, file hash mismatch, etc.)
2. Event serialized to the locked JSON schema
3. Emitted over a Unix domain socket (preferred) or named pipe (fallback if socket work overruns) to the policy layer
4. Policy layer evaluates against loaded rules
5. Matches produce alerts: written to a structured alert log, optionally surfaced in a simple terminal dashboard
6. All raw events are also persisted to a JSON log file regardless of rule matches, for later review/demo purposes

## 5. Technology Choices

| Decision | Choice | Reasoning |
|---|---|---|
| Sensing layer language | C | Direct continuation of SAM; genuine systems engineering work (memory management, `/proc` parsing, daemonization) |
| Policy layer language | Python | Lower barrier to entry for Faizan; fast iteration on rule logic without fighting a compiler while learning concepts |
| IPC mechanism | Unix domain socket | Standard, well-documented, teaches real IPC (consistent with prior JusticeFlow IPC experience: FIFO/shared memory/sockets) |
| Schema format | JSON | Human-readable for demo/debugging, trivial to parse in both C (cJSON, already used in SAM) and Python |
| Storage | Flat JSON log files | No database needed at this scope; avoids adding DB setup/management overhead that doesn't serve either learning goal |

## 6. Explicit Non-Goals (Architectural)

These are excluded **by design**, not by oversight — see the Scope document for full reasoning:

- No eBPF / kernel module — stays in userspace, `/proc`-based
- No multi-host / distributed agent architecture
- No machine learning / statistical anomaly detection
- No web UI (terminal/CLI output only)
- No IPv6, UDP tracking (same deferral as SAM)

## 7. Open Architectural Decision

One thing not yet decided and worth a short conversation before Week 1 ends: **Unix domain socket vs. named pipe** for the sensing→policy IPC. Socket is the more "correct" and resume-relevant choice; named pipe is simpler and faster to get working if time is tight in Week 1. Recommend defaulting to socket unless it's eating more than 1–2 days, in which case fall back to a named pipe without guilt — the architecture doesn't materially change either way.