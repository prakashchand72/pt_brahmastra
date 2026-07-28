# Autonomous Orchestration — The Brahmastra Loop

This reference defines **Autonomous Mode**: a self-driving, multi-agent orchestration
layer on top of the standard Phase 1–7 kill-chain. It reproduces the behavior of
autonomous pentest agents (Strix-style: autonomous loop + multi-agent fan-out +
validate-before-report) while running entirely inside Claude Code on the user's
subscription — no external tool, no separate API key.

**Mode setting for this deployment:**
- **Autonomy:** FULLY HANDS-OFF. After the authorization gate passes, run the entire
  chain end-to-end with no phase checkpoints. Do NOT stop to ask the user between
  phases or before exploitation. The user has explicitly opted into unattended runs.
- **Parallelism:** MODERATE. Fan out to **3–4 concurrent subagents** at a time — never
  more — to keep subscription token usage bounded. Queue remaining targets and refill
  as agents complete.

---

## Two hard boundaries that are NOT checkpoints

These are automated gates, not human check-ins. They stay ON even in fully-hands-off mode.

1. **Authorization gate (Phase 1).** Before any active work, confirm written
   authorization exists (see SKILL.md Phase 1). This is the one human confirmation.
   Once given, the run proceeds unattended.
2. **Scope-guard (automated).** Load the authorized scope into `pentest/scope.txt`.
   Before EVERY active request to a host, verify it matches the scope list
   (exact host or in-scope wildcard/CIDR). Any target not on the list is
   **auto-refused and logged** — the loop skips it and continues; it never asks
   the user for permission to go out of scope. This protects the engagement boundary.

---

## Run-state file

Maintain `pentest/run-state.json` as the loop's memory. Rewrite it at each phase
transition and after each subagent returns. Schema:

```json
{
  "engagement": "client-name",
  "scope": ["app.client.com", "*.api.client.com"],
  "phase": "5-exploitation",
  "targets_ranked": [
    {"host": "admin.client.com", "score": 9, "status": "in-progress", "agent": "agent-2"}
  ],
  "findings_pending_validation": [
    {"id": "F-tmp-1", "host": "...", "class": "sqli", "poc": "...", "evidence_path": "..."}
  ],
  "findings_confirmed": [
    {"id": "F-01", "severity": "high", "class": "sqli", "status": "TRUE_POSITIVE",
     "poc": "curl ...", "evidence_path": "pentest/evidence/F-01/"}
  ],
  "findings_rejected": [
    {"id": "F-tmp-2", "reason": "size matches baseline — false positive"}
  ]
}
```

The loop is **resumable**: on re-invocation, read `run-state.json` and continue from
`phase` rather than restarting.

---

## The loop

```
Phase 1  Authorization gate ──────── (human confirm, once)
   │
Phase 2  Passive recon ───────────── single agent, populate scope + live hosts
   │
Phase 3  Prioritization ──────────── score → targets_ranked, write interestingtarget.txt
   │
   ▼
┌─ AUTONOMOUS FAN-OUT (Phases 4–6 per target) ───────────────────────┐
│  While unworked targets remain:                                    │
│    • Take up to (4 − active_agents) top-ranked targets             │
│    • Spawn one subagent per target (see template below)            │
│    • Each subagent runs Phase 4 → 5 → 6 for its target             │
│    • On return: merge its findings into run-state                  │
│         - TRUE_POSITIVE + has PoC → findings_confirmed             │
│         - anything else           → findings_rejected (with reason)│
│    • Refill the agent pool from the queue                          │
└────────────────────────────────────────────────────────────────────┘
   │
Phase 6b VALIDATION GATE (orchestrator) ── re-check every confirmed
   │                                         finding's PoC once more before report
Phase 7  Report ──────────────────── only findings_confirmed go in
   │
Handoff  Pipe into office_report → vajra_report; PoCs → office_recheck
```

The orchestrator (main agent) never runs raw exploits itself once fan-out begins —
it plans, dispatches, merges, and gates. Subagents do the grinding.

---

## Subagent dispatch template

Spawn with the `Agent` tool, `subagent_type: general-purpose`, 3–4 at a time.
Each subagent is a self-contained Brahmastra worker for ONE target.

```
You are a Brahmastra exploitation worker. Authorized engagement — authorization
already confirmed by the operator. Scope is STRICT: only touch {HOST}. If a
redirect or link sends you off {HOST}, stop and report it; do not follow it.

Target: {HOST}  (IP {IP}, rank score {SCORE}, rationale: {WHY})
Execute the pt_brahmastra kill-chain Phases 4–6 against this target only:
  - Phase 4: active scanning (ffuf, feroxbuster, nuclei, nikto, nmap as in SKILL.md)
  - Phase 5: exploitation across the attack-class index — focus first on the
    classes implied by the target's rank rationale
  - Phase 6: dynamic verification — for EVERY candidate finding, run the
    known-negative baseline test. A finding is only TRUE_POSITIVE with a live,
    reproducible PoC and captured evidence.

Run exploit code on the Kali box ({KALI_HOST}), not the local host.

Return ONLY a structured list. For each finding:
  STATUS: TRUE_POSITIVE | FALSE_POSITIVE | CONDITIONAL
  CLASS: <attack class>
  SEVERITY: critical|high|medium|low|info
  POC: <exact reproducible command / request>
  EVIDENCE: <what proves it — response snippet, timing, saved file path>
  NOTE: <one line>
Do not include unverified or theoretical findings. No baseline test = not a finding.
```

Because subagent final reports are not shown to the user, the orchestrator must
**relay** what each worker found when it summarizes progress.

---

## Validation gate (Phase 6b) — the "prove every bug" rule

Before writing the report, the orchestrator independently re-runs each
`findings_confirmed` PoC one final time:

- PoC reproduces live → keep, promote to a real finding ID (F-01, F-02, …).
- PoC no longer reproduces → move to `findings_rejected` with reason.
- Requires an external precondition → mark CONDITIONAL, document the precondition.

This double-validation (worker + orchestrator) is what keeps the false-positive rate
near zero and makes every reported finding safe to hand a client.

---

## Handoff to the deliverable pipeline

Autonomous Mode does not replace the report/retest tooling — it feeds it:

1. `findings_confirmed` → format via **office_report** into the tracker template
   (severity-sorted, humanized Description/Remediation, IDs renumbered per severity).
2. Render the client-facing deliverable via **vajra_report**.
3. Each finding's `poc` is the replayable exploit step **office_recheck** needs — the
   retest workflow can later prove patched/unpatched with no re-derivation.

---

## Cost / usage note

Moderate fan-out means 3–4 subagents live at once; each consumes subscription tokens
independently. On very wide scopes (dozens of hosts) the queue keeps concurrency
capped at 4, but total usage still scales with target count. For a large range,
prioritize hard in Phase 3 and cap the number of targets that enter fan-out.
```
