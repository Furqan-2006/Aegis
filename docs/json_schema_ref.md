# Aegis Event Schema v1 — Field Reference & Examples

**Status: LOCKED as of Week 1.**
This document is the contract between the sensing layer (C daemon, owned by Furqan) and the policy layer (Python rule engine, owned by Faizan). Neither side modifies this without explicit agreement from both. If a field is missing or named differently in the actual event stream, that is a bug in the sensing layer — not a reason to silently adapt the policy layer.

---

## How Every Event Is Structured

Every event Aegis emits has the same top-level shape, regardless of what happened:

```json
{
  "event_id":   "...",
  "timestamp":  "...",
  "event_type": "...",
  "source":     { ... },
  "detail":     { ... }
}
```

The `detail` object is the only part that changes shape between event types. Everything else is always present and always means the same thing.

---

## Top-Level Fields

| Field | Type | Always present? | What it means |
|---|---|---|---|
| `event_id` | string (UUID) | Yes | Unique ID for this event. Generated in C. Use this to correlate events in rules — e.g., "the same event_id shouldn't appear twice." |
| `timestamp` | string (ISO 8601) | Yes | When the sensing layer detected this event. UTC. Format: `2024-06-01T14:32:01.123Z` |
| `event_type` | string (enum) | Yes | **The first thing your rule engine should look at.** Determines what's in `detail`. One of: `process_spawn`, `process_exit`, `net_connection`, `file_modified`, `privilege_change` |
| `source` | object | Yes | The process responsible for or associated with this event. |
| `detail` | object | Yes | Event-specific fields. Shape depends entirely on `event_type`. |

---

## The `source` Object (Always Present)

The `source` block tells you *which process* caused the event. This is often more useful than the event itself — a `/etc/shadow` file modification is suspicious regardless of *what changed*, but a shell spawning is only suspicious depending on *which process spawned it*.

| Field | Type | Where it comes from | What to use it for |
|---|---|---|---|
| `pid` | integer | `/proc/[pid]/` directory name | Identify the specific process instance |
| `ppid` | integer | `/proc/[pid]/status` → `PPid:` | **Parent process ID — critical for lineage rules.** Who spawned this process? |
| `uid` | integer | `/proc/[pid]/status` → `Uid:` (1st value) | Real user who owns the process |
| `euid` | integer | `/proc/[pid]/status` → `Uid:` (2nd value) | **Effective user — what the process actually has permissions as.** `euid=0` with `uid!=0` is a privilege escalation signal |
| `cmdline` | string | `/proc/[pid]/cmdline` | Full command including arguments. Empty for some kernel threads |
| `exe_path` | string | `readlink /proc/[pid]/exe` | Absolute path of the binary. `(deleted)` means the binary was removed after launch — suspicious |
| `open_fds` | array of strings | `/proc/[pid]/fd/` symlinks | Optional. What files/sockets this process has open. Only included when relevant |

---

## Event Types — Detail Fields & Examples

### `process_spawn`

Emitted when a new process appears in `/proc` that wasn't there on the previous poll.

**Detail fields:**

| Field | Type | Required | What it means |
|---|---|---|---|
| `parent_exe_path` | string | Yes | Executable path of the parent process (the one that spawned this one) |
| `parent_cmdline` | string | Yes | Command line of the parent process |
| `is_setuid` | boolean | No | True if the new process's binary has the setuid bit set |

**Example event:**
```json
{
  "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2024-06-01T14:32:01.123Z",
  "event_type": "process_spawn",
  "source": {
    "pid": 4821,
    "ppid": 1203,
    "uid": 33,
    "euid": 33,
    "cmdline": "bash",
    "exe_path": "/bin/bash"
  },
  "detail": {
    "parent_exe_path": "/usr/sbin/nginx",
    "parent_cmdline": "nginx: worker process",
    "is_setuid": false
  }
}
```

**Why this example is suspicious:** a `bash` shell was spawned, and its parent is an nginx worker process. Web servers should not be spawning shells — this is the classic reverse shell pattern.

**Example floor-tier rule this enables:**
```python
if event["event_type"] == "process_spawn":
    if "nginx" in event["detail"]["parent_exe_path"]:
        if "bash" in event["source"]["cmdline"] or "sh" in event["source"]["cmdline"]:
            alert(event, severity="critical", reason="shell spawned from web server")
```

---

### `process_exit`

Emitted when a PID that was previously tracked disappears from `/proc`.

**Detail fields:**

| Field | Type | Required | What it means |
|---|---|---|---|
| `exit_code` | integer | Yes | Process exit code. Non-zero from a sensitive process is a potential signal |
| `duration_seconds` | float | No | How long the process ran, if spawn was also tracked. Very short-lived processes from unexpected parents are suspicious |

**Example event:**
```json
{
  "event_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "timestamp": "2024-06-01T14:32:03.456Z",
  "event_type": "process_exit",
  "source": {
    "pid": 4821,
    "ppid": 1203,
    "uid": 33,
    "euid": 33,
    "cmdline": "bash",
    "exe_path": "/bin/bash"
  },
  "detail": {
    "exit_code": 0,
    "duration_seconds": 2.3
  }
}
```

---

### `net_connection`

Emitted when a new TCP connection appears in `/proc/net/tcp` that wasn't present on the previous poll.

**Detail fields:**

| Field | Type | Required | What it means |
|---|---|---|---|
| `local_addr` | string | Yes | Local IP (e.g., `192.168.1.10`) |
| `local_port` | integer | Yes | Local port |
| `remote_addr` | string | Yes | Remote IP. `0.0.0.0` for listening sockets |
| `remote_port` | integer | Yes | Remote port. `0` for listening sockets |
| `state` | string | Yes | TCP state: `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, etc. |
| `protocol` | string | Yes | Always `"tcp"` in v1 |

**Example event:**
```json
{
  "event_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "timestamp": "2024-06-01T14:32:05.789Z",
  "event_type": "net_connection",
  "source": {
    "pid": 4821,
    "ppid": 1203,
    "uid": 33,
    "euid": 33,
    "cmdline": "bash",
    "exe_path": "/bin/bash"
  },
  "detail": {
    "local_addr": "192.168.1.10",
    "local_port": 54321,
    "remote_addr": "10.0.0.5",
    "remote_port": 4444,
    "state": "ESTABLISHED",
    "protocol": "tcp"
  }
}
```

**Why this example is suspicious:** a bash process (already suspicious from the process_spawn above) establishing an outbound TCP connection to port 4444 (a classic netcat/reverse shell default port).

---

### `file_modified`

Emitted when a watched file's SHA-256 hash differs from its previously recorded hash.

**Detail fields:**

| Field | Type | Required | What it means |
|---|---|---|---|
| `path` | string | Yes | Absolute path of the file that changed |
| `old_hash` | string | Yes | SHA-256 of the file before the change |
| `new_hash` | string | Yes | SHA-256 of the file after the change |
| `size_before` | integer | No | File size in bytes before modification |
| `size_after` | integer | No | File size in bytes after modification |

**Example event:**
```json
{
  "event_id": "d4e5f6a7-b8c9-0123-defa-234567890123",
  "timestamp": "2024-06-01T14:35:22.001Z",
  "event_type": "file_modified",
  "source": {
    "pid": 5012,
    "ppid": 4821,
    "uid": 0,
    "euid": 0,
    "cmdline": "passwd furqan",
    "exe_path": "/usr/bin/passwd"
  },
  "detail": {
    "path": "/etc/shadow",
    "old_hash": "a3f5b2c1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2",
    "new_hash": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
    "size_before": 1024,
    "size_after": 1056
  }
}
```

**Why this is a detection target:** `/etc/shadow` stores password hashes. Any modification outside of expected admin operations (password change, user creation) is suspicious. An attacker with root access may modify it to add a backdoor user.

**Example floor-tier rule:**
```python
WATCHED_CRITICAL_FILES = ["/etc/shadow", "/etc/passwd", "/etc/ssh/sshd_config"]

if event["event_type"] == "file_modified":
    if event["detail"]["path"] in WATCHED_CRITICAL_FILES:
        alert(event, severity="critical", reason=f"sensitive file modified: {event['detail']['path']}")
```

---

### `privilege_change`

Emitted when a tracked process's UID or EUID changes between polls.

**Detail fields:**

| Field | Type | Required | What it means |
|---|---|---|---|
| `old_uid` | integer | Yes | Real UID before the change |
| `new_uid` | integer | Yes | Real UID after the change |
| `old_euid` | integer | Yes | Effective UID before the change |
| `new_euid` | integer | Yes | Effective UID after the change |
| `trigger` | string | No | `setuid_exec`, `direct_change`, or `unknown` |

**Example event:**
```json
{
  "event_id": "e5f6a7b8-c9d0-1234-efab-345678901234",
  "timestamp": "2024-06-01T14:36:01.555Z",
  "event_type": "privilege_change",
  "source": {
    "pid": 4821,
    "ppid": 1203,
    "uid": 33,
    "euid": 0,
    "cmdline": "bash",
    "exe_path": "/bin/bash"
  },
  "detail": {
    "old_uid": 33,
    "new_uid": 33,
    "old_euid": 33,
    "new_euid": 0,
    "trigger": "setuid_exec"
  }
}
```

**Why this is suspicious:** the same bash process from before (uid=33, the nginx worker user) has acquired euid=0 (root). A non-root process should not become root — this is a textbook privilege escalation signal.

---

## What Changes This Schema (Version Policy)

This is v1 — locked at the start of Week 1. Things that would justify a v2:
- A new event type needed (e.g., UDP connections in a future sprint)
- A required field turns out to be unreadable from `/proc` on some configurations
- A field name is consistently causing confusion between the two layers

Things that do **not** justify a schema change mid-project:
- "It would be nicer if..."
- A rule is hard to write — that's a rule design problem, not a schema problem
- The sensing layer finds it hard to populate a field — solve it at the C level, not by removing the field from the contract