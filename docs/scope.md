# Aegis — Scope Document

## 1. In Scope

- Single-host Linux monitoring (no distributed/multi-host architecture)
- Process lifecycle monitoring (spawn, exit, parent-child lineage, UID/EUID)
- TCP connection monitoring via `/proc/net/tcp` (IPv4 only)
- File integrity monitoring on a configurable, small set of sensitive paths
- Privilege transition detection (EUID changes, setuid execution)
- A locked JSON event schema connecting sensing and policy layers
- A rules-based policy/detection engine (static rules → time-windowed correlation, as pace allows)
- Severity-scored alerting to structured logs
- A simple terminal-based alert view (not a web dashboard)
- A small set of simulated attack scenarios for demonstration purposes
- Two-person clean role separation with a defined, locked interface

## 2. Explicitly Out of Scope

| Excluded | Why |
|---|---|
| eBPF / kernel modules | High systems complexity, steep learning curve, not necessary to demonstrate the target skills at this scope; `/proc`-based polling is sufficient and consistent with prior SAM work |
| IPv6 / UDP tracking | Deferred in SAM already; adding now expands sensing surface without adding to either person's core learning goal |
| Machine learning / statistical anomaly detection | Out of reach in 5–6 weeks alongside everything else; static + correlation rules already demonstrate real detection engineering |
| Multi-host / agent-server architecture | Major scope multiplier (networking, auth between agents, central aggregation); single-host is sufficient to demonstrate both roles fully |
| Web dashboard / UI | Pure scope cost with no proportional learning benefit for either of your stated goals; terminal output is sufficient for demo purposes |
| Database (MySQL/Postgres/etc.) | Flat JSON logs are sufficient at this scale and avoid burning time on DB setup/management that serves neither person's actual learning target |
| Full penetration testing / exploit development | Not part of either role as scoped; Aegis is a defensive/detection tool, not an offensive one |
| PID-to-inode socket matching, full network correlation | Same deferral as SAM Day 7 deferred items; can be a stated "future work" item, not a deliverable |

**If any of these get requested mid-project** (by an instructor, by ambition creep, by a "wouldn't it be cool if"), treat that as a scope change requiring explicit discussion of what gets cut to make room — not an automatic addition.

## 3. Week-by-Week Plan

### Week 0 — Skills Foundation (revised)

**Why this week exists, revised:** the original depth-assessment answer to Section B Q4 stated "no, never written code," which initially scoped Week 0 as from-zero programming instruction. That's inconsistent with Faizan being a 4th-semester CS student with completed programming coursework and DSA — **this contradiction has not yet been resolved and should be clarified directly with Faizan before Week 0 begins**, since the two readings imply different starting points: either he answered Q4 too literally (interpreting "code" as "security/OS-related code" specifically), or there's a real gap between coursework completion and working confidence that's itself worth knowing about.

Pending that clarification, Week 0 is now scoped narrower, assuming general programming literacy (variables, conditionals, functions, basic data structures) is solid from coursework. The actual gap is **domain literacy**, not programming fundamentals:

**Faizan:**
- Confirm which language(s) his coursework used; if not Python, a short syntax-translation pass (not concept-learning) — most CS coursework is C/C++/Java, and the gap from any of those to basic Python is small for someone who already has the underlying programming concepts
- JSON/YAML as configuration formats specifically (likely genuinely new — these aren't typically covered in intro CS coursework the way general syntax is)
- OS/process-domain literacy: what a process tree looks like, what an "event" means in this context, walking through the example rules in the Architecture document line by line until he can explain each one back unprompted
- Re-attempt Section C, Q8–9 from the depth assessment (process vs. thread, privilege escalation) after this pass — checkpoint for whether direct teaching closes the conceptual gap that self-study hadn't
- Optional, side-track: general Linux/terminal comfort (e.g., freeCodeCamp's Introduction to Linux course) — useful but does not replace the domain-literacy work above, since terminal navigation isn't the actual Week 1 bottleneck

**You:**
- Complete SAM's remaining anomaly detection layer (the deferred item from the original SAM sprint) — this directly feeds the sensing layer work in Week 1, so finishing it now removes a dependency rather than adding parallel work later
- Lightly review/refresh `/proc` internals and daemon-writing patterns (signal handling, fork/detach) ahead of Week 1, since it's been some time since the original SAM sprint
- Prepare 2–3 concrete worked examples of "event → rule → alert" to use as Faizan's Week 0 practice material — this is teaching prep, treat it as real project time, not overhead

**Joint:**
- End-of-week checkpoint: Faizan attempts Q7 from the depth assessment again (or an equivalent live exercise) — write and run one real, working rule against a sample event, with you watching but not doing it for him. Given confirmed prior programming experience, this should be a meaningfully easier bar to clear than originally scoped; if it's still a struggle, that's a stronger signal than before that something beyond syntax is the blocker (e.g., genuine unfamiliarity with the domain concepts, not the code itself).

---

### Week 1 — Foundations & Interface Lock
**You:**
- Refactor/extend SAM (now feature-complete, including anomaly detection, as of Week 0) into a daemonizable structure
- Implement basic daemon behavior: fork/detach, PID file, signal handling (SIGINT/SIGTERM for graceful shutdown)
- Draft the JSON event schema

**Faizan:**
- Study: what does process spawning normally look like vs. a compromise (read 2–3 real intrusion writeups/CVE postmortems, take notes — no coding yet)
- Review and give feedback on the draft event schema — what fields does he need to write meaningful rules?
- Set up his Python rule-engine project skeleton (just structure, no logic yet)

**Joint:** Lock the event schema together by end of week. This is the most important checkpoint in the whole project.

### Week 2 — Core Sensing + Floor-Level Rules
**You:**
- Implement file integrity watcher (SHA-256 hashing, configurable path list)
- Wire process/network monitors into the locked event schema, emit over chosen IPC mechanism

**Faizan:**
- Implement rule loader + evaluation engine for simple stateless rules (e.g., "alert if `/etc/shadow` modified")
- Write 5–8 floor-tier rules covering the sensitive-file and basic-process-spawn cases
- Test against synthetic events you provide (doesn't require the full pipeline working yet)

### Week 3 — Privilege Detection + IPC Integration
**You:**
- Implement privilege transition detection (EUID monitoring, setuid execution flagging)
- Connect sensing layer to policy layer over the real IPC channel (socket or pipe) — first end-to-end event flow

**Faizan:**
- Begin mid-tier rules: rules that reference process lineage (e.g., "shell spawned from web-server-like parent")
- Start learning what real attack chains look like (this is where you should plan to spend teaching time with him directly)

**Joint:** First full end-to-end test — a real event generated by the sensing layer reaches the policy layer and produces an alert.

### Week 4 — Mid-Tier Detection + Alerting Polish
**You:**
- Harden daemon (handle edge cases: process disappearing mid-scan, permission errors reading `/proc`, etc.)
- Build structured alert + raw event logging to disk

**Faizan:**
- Finish mid-tier rules
- Build severity scoring logic
- If pace allows: begin first time-windowed/stateful rule (e.g., "N failed integrity checks in T seconds")

### Week 5 — Integration, Attack Simulation, Stress Testing
**Joint:**
- Build 3–5 simulated attack scenarios (e.g., manually spawn a reverse-shell-like process tree, modify a watched file, simulate a privilege escalation pattern) and confirm Aegis flags them correctly
- Fix bugs surfaced by real end-to-end testing
- If ahead of schedule: attempt the ceiling-tier correlation rule from the architecture doc

### Week 6 — Documentation, README, Polish
**Joint:**
- Write the GitHub README: what the system does, architecture diagram, both roles explained honestly, what each person actually built
- Record a short demo (terminal recording or screen capture) showing an attack scenario being detected
- Final cleanup pass; cut anything broken or half-finished rather than leaving it in

## 4. Definition of Done (Minimum Viable Aegis)

The project is complete and presentable if, at minimum:
- The daemon runs continuously and emits real events from process/network/file monitoring
- At least 5 working detection rules exist, spanning at least 2 of the 4 event types
- At least 2 simulated attack scenarios are correctly detected end-to-end and demonstrable live
- Both roles are clearly visible and explainable by each person independently — if either of you can't explain the other's half at a basic level by the end, that's a signal worth addressing before presenting it
- **Realistic floor for Faizan's independent contribution, stated honestly:** given zero prior programming experience confirmed in the depth assessment, the floor-tier rules should be ones Faizan wrote or meaningfully co-wrote and can explain unaided — not rules you wrote that he can recite. If by Week 2 he's still primarily reviewing/explaining rather than writing, that's worth a direct conversation about adjusting the Week 0 ramp rather than quietly absorbing the imbalance for the rest of the project.

## 5. What Would Change This Scope

- **Week 0's end-of-week checkpoint is the real go/no-go signal**, not Week 1's schema lock. If Faizan can't write and run one basic rule unaided by end of Week 0, that's the point to have an honest conversation about extending the ramp slightly or rebalancing the floor-tier expectations — better to adjust here than discover it mid-Week-2.
- If Week 1's schema lock slips past end-of-week, that's a secondary early-warning signal worth addressing directly rather than absorbing silently.
- If Faizan reaches the floor tier but stalls there by Week 4, the project is still completable and presentable (floor-tier rules are real, demonstrable detection logic) — this is why the floor was designed to be genuinely sufficient on its own, not just a stepping stone.
- If either of you finishes core work early, the ceiling-tier correlation rule and IPv6/PID-socket-matching deferred items are the natural next additions — not new unscoped ideas.