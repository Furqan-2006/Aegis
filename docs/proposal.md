# Aegis — Project Proposal

**A Linux Host-Level Security Monitoring & Behavioral Auditing Tool**

| | |
|---|---|
| **Team** | [Your name] — Systems Security Engineer · Faizan — Security Analyst / Detection Engineer |
| **Duration** | 6–7 weeks (Week 0: skills foundation, Weeks 1–6: build) |
| **Platform** | Linux (single-host) |
| **Type** | Portfolio project |
| **Status** | Proposed |

---

## 1. Why This Project Exists

This proposal replaces an earlier idea (a web login system with brute-force detection) that was scoped by AI-assisted conversation rather than by team capability and project goals. That idea had a structural flaw worth naming explicitly: it gave the "systems engineer" role almost no real systems work (install Linux, configure MySQL, start/stop a server) while giving the "security engineer" role nearly all the substantive engineering (hashing, detection logic, access control, logging design). For a project where one teammate's stated direction is **systems security engineering**, that split doesn't hold up — it produces a portfolio piece that doesn't actually demonstrate systems security engineering for the person who needs it to.

Aegis is designed to correct that: both roles are real engineering roles, scoped to each person's actual current level, with a deliberate growth path for the less experienced teammate rather than a role built around what they can already do.

## 2. What Aegis Is

Aegis is a lightweight **host intrusion detection and behavioral auditing agent** for Linux — conceptually a minimal, single-host EDR (Endpoint Detection and Response) tool. It runs as a background daemon, collects security-relevant telemetry from the OS (process creation, privilege transitions, file access on sensitive paths, network connections), and evaluates that telemetry against a policy/rules layer to flag suspicious behavior.

This is a direct extension of prior work: the System Activity Monitor (SAM) already built process scanning via `/proc`, network connection scanning via `/proc/net/tcp`, structured JSON logging, and anomaly detection via `/proc/pid/fd` inspection. Aegis formalizes and extends that foundation into a two-layer system with a defined interface between sensing and policy.

## 3. Problem Statement

Most student security projects (login systems, file hashers, basic packet sniffers) demonstrate *application security hygiene*, not *systems security engineering*. They don't require understanding of process internals, privilege models, or how real attackers' actions surface as OS-level signals. Aegis is scoped specifically to close that gap: the systems side requires real OS/process internals work, and the security side requires real threat-reasoning — not just rule-writing, but understanding *why* a given OS-level signal indicates compromise.

## 4. Roles

### Systems Security Engineer (You)
Owns the **sensing layer**: the daemon, OS-level telemetry collection, the data pipeline, and the interface contract the policy layer consumes. This is the direct continuation of SAM — daemonizing it, hardening it, extending its signal set, and defining a clean, documented event schema.

### Security / Detection Engineer (Faizan)
Owns the **policy layer**: deciding what telemetry matters, what "normal" vs "suspicious" looks like for a single-host system, encoding that as rules, and producing severity-scored alerts. Critically, Faizan does **not** just write rules in isolation — he co-designs the telemetry signal set with you, which is what makes this security *engineering* rather than scripting. This role has a genuine low floor (start with simple static rules against example logs) and a real ceiling (rule chaining, behavioral baselining, severity scoring) — both reachable without prior security coursework, but neither trivial.

## 5. Why This Scope (and Not Bigger)

**Benefit of this scope:** finishable in 5–6 weeks by two people, one of whom has unverified depth, without requiring a fallback branch.
**Cost accepted:** no network-wide detection, no distributed agents, no ML-based anomaly detection, no kernel module / eBPF (stays in `/proc`-based userspace collection, consistent with SAM). These are explicitly out of scope — see the Scope document for the full boundary.

**What would change this assessment:** if Faizan demonstrates (via an actual artifact — a completed TryHackMe room, a script, a writeup) meaningfully more depth than assumed, the policy layer ceiling can be raised (e.g., correlation across multiple signal types, basic MITRE ATT&CK technique mapping) without changing the architecture. If he demonstrates meaningfully less, the floor work (static rule-writing against provided examples) still produces a legitimate, explainable contribution — the project does not collapse if growth is slower than hoped.

## 6. High-Level Deliverables

1. A working Linux daemon (`aegisd`) collecting process, file, and network telemetry
2. A structured, documented event schema (JSON) connecting sensing and policy layers
3. A rules/policy engine consuming that schema and producing severity-scored alerts
4. A demonstration: a small set of simulated attack scenarios (e.g., reverse shell spawn, sensitive file access, privilege escalation attempt) that Aegis correctly flags
5. Two markdown companion documents: Architecture and Scope (see accompanying files)
6. A README suitable for a GitHub portfolio entry, explaining the system, both roles, and what each person actually built

## 7. Risks (Stated Plainly)

- **Confirmed teammate depth, now calibrated** [Observed, via depth assessment]: Faizan has no completed security labs/CTFs and no OS/networking-related coding experience, but does have self-study networking fundamentals (TCP/IP, OSI, subnetting), completed CS coursework including DSA, and showed real scenario-reasoning ability (correctly explained why a web-server process spawning a shell is suspicious, unprompted). He also rated himself "certain" on answers he'd just marked "I don't know," indicating self-reported confidence should not be trusted at face value going forward — actual output (code, working rules, demos) is the only reliable signal for the rest of the project.
- **Note — unresolved contradiction:** the depth assessment's Section B literally stated "never written code," which conflicts with his status as a 4th-semester CS student with completed programming coursework. This has not yet been clarified with Faizan directly (likely either an overly literal reading of "code" as "security/OS code," or a real gap between coursework completion and working confidence — both are useful to know, but neither should be assumed). Week 0 is scoped on the assumption that general programming literacy exists from coursework; if that assumption proves wrong once clarified, Week 0 will need to expand back toward fundamentals.
- **The actual binding constraint, pending that clarification, is domain literacy (OS/process concepts, JSON/YAML as config formats), not general programming ability.** This is why Week 0 exists: floor-tier rule-writing in Week 1–2 requires reading process trees and security-event reasoning that doesn't currently exist, even if the underlying code-writing ability does. If Week 0 isn't sufficient, the realistic fallback is you writing early rules with Faizan reviewing/explaining the security reasoning behind them, shifting to him writing independently once domain fluency catches up. This is a real possibility, not a worst case to wave away.
- **Timeline pressure**: now 6–7 weeks including Week 0. Scope remains deliberately narrow (single host, narrow signal set) to protect against overrun.
- **Interface coupling risk**: if the event schema between sensing and policy layers isn't locked early, both halves can stall waiting on each other. Addressed in the Architecture document (schema defined in Week 1).