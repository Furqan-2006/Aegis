# Aegis

Aegis is a lightweight Linux **EDR-lite** system that monitors host activity and raises security alerts.

It is built as two cooperating components:
- **Sensing layer (`aegisd`, C)**: collects process, network, file integrity, and privilege-change events.
- **Policy engine (`policy_engine/main.py`, Python)**: receives events over a Unix domain socket and applies detection rules.

---

## Description

Aegis continuously observes:
- Process lifecycle (`process_spawn`, `process_exit`)
- TCP network activity (`net_connection`)
- Integrity changes on sensitive files (`file_modified`)
- UID/EUID transitions (`privilege_change`)

Events are serialized as JSON and follow the schema in:
- `/home/runner/work/Aegis/Aegis/schema/schema.json`

---

## Design

### Architecture

```text
┌──────────────────────────── AEGIS HOST ────────────────────────────┐
│                                                                     │
│  ┌────────────────────────┐      Unix socket      ┌───────────────┐ │
│  │ Sensing Layer (C)      │  /tmp/aegis.sock      │ Policy Engine │ │
│  │ - process monitor      │  JSON event stream    │ (Python)      │ │
│  │ - network monitor      │  -------------------> │ - rule checks │ │
│  │ - file integrity check │                       │ - alerts log  │ │
│  │ - privilege monitor    │                       │               │ │
│  └────────────────────────┘                       └───────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Runtime behavior
- The daemon writes raw events to `/var/log/aegis_events.log`.
- The policy engine writes alert decisions to `/home/runner/work/Aegis/Aegis/aegis_alerts.log`.
- Event schema and reference docs:
  - `/home/runner/work/Aegis/Aegis/schema/schema.json`
  - `/home/runner/work/Aegis/Aegis/docs/json_schema_ref.md`

---

## Repository Structure

```text
/home/runner/work/Aegis/Aegis
├── run_aegis.sh                 # Supervisor script (build + start both layers)
├── sensor/
│   ├── src/                     # C implementation (daemon, monitors, emitter)
│   └── include/                 # C headers
├── policy_engine/
│   └── main.py                  # Python rule engine + Unix socket server
├── schema/
│   └── schema.json              # Locked event contract
├── docs/                        # Architecture, scope, schema reference, proposal
└── bin/
    └── aegisd                   # Compiled daemon binary
```

---

## Usage

### Prerequisites
- Linux host
- `gcc`
- OpenSSL development library (for `-lcrypto`)
- `python3`
- `sudo` privileges (daemon startup and log path usage)

### Compile and Run (Shell Script)

Use the provided supervisor script:

```bash
cd /home/runner/work/Aegis/Aegis
chmod +x run_aegis.sh
./run_aegis.sh
```

What this script does:
1. Compiles the sensing daemon (`bin/aegisd`) from `sensor/src/*.c`
2. Starts `aegisd` with `sudo`
3. Starts the policy engine (`python3 policy_engine/main.py`)

To stop both processes, press `Ctrl+C` in the same terminal.

### Logs
- Sensor events: `/var/log/aegis_events.log`
- Policy alerts: `/home/runner/work/Aegis/Aegis/aegis_alerts.log`

---

## Additional Technical Documents

- Architecture: `/home/runner/work/Aegis/Aegis/docs/architecture.md`
- Scope and milestones: `/home/runner/work/Aegis/Aegis/docs/scope.md`
- Proposal: `/home/runner/work/Aegis/Aegis/docs/proposal.md`
- Event schema reference: `/home/runner/work/Aegis/Aegis/docs/json_schema_ref.md`
