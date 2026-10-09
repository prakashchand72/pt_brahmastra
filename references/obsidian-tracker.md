# Obsidian Tracker Integration

The tracker vault (`~/shared_kali/tracker/`) is an Obsidian vault with
**Dataview** installed. It renders two live notes from per-finding frontmatter:

| Note | Purpose |
|---|---|
| `_dashboard.md` | KPIs (total/open/critical/high/targets), severity bars, open-by-workspace, recent findings |
| `_findings-tracker.md` | Full per-vuln table (severity/status/CWE/CVE/endpoint), open-actions view, per-severity lists |

Both query only `_findings/*.md` notes (`type: finding`). If the dashboard
shows zeros, no finding notes exist yet.

## How data flows

1. `office_template <domain>` → report scaffold with frontmatter
   (`type`, `target`, `workspace`, `status: open`, `date`).
2. `office_report` → fills report + upserts one note per finding under
   `_findings/<target>__<FID>.md` with `severity`, `status`, `cwe`, `cve`,
   `endpoint`, `target`, `workspace`, `report` wiki-link. Sets `status: confirmed`
   once the finding is validated into the report.
3. `office_recheck <file>` → replays PoCs live, writes `rechecks/..._recheck.md`,
   AND flips the matching finding-note statuses (`patched` / `mitigated` /
   `false-positive` / `open`).
4. `memory_reindex` (tracker-memory MCP) → RAG re-ingests so `memory_search`
   sees the new report.

## Finding-note schema

```yaml
---
type: finding
fid: F-01                 # canonical finding ID is F-XX; any C/H/M/L prefix in
                          # tracker notes is a severity slug, NOT the finding ID
title: ...
severity: critical      # critical | high | medium | low | info
status: open            # open | confirmed | patched | mitigated | false-positive
cwe: CWE-209
cve: ""
endpoint: https://...
target: www.example.com
workspace: ASM_NAM
client: Ferrero
report: "[[www.example.com]]"
date: 2026-08-06
tags: [finding]
---
```

Canonical: `~/shared_kali/tracker/Template/Finding_Note_Schema.md`.

## Rules for the model

- **Upsert, never duplicate** — same `(target, fid)` updates the existing
  note.
- Never invent `severity`/`status`/`cwe`/`cve`. `status` starts `open`;
  `office_report` sets `confirmed`; only `office_recheck` moves it to
  `patched` / `mitigated` / `false-positive` / back to `open`.
- The `report` link must match the actual report filename so the wiki-link
  resolves.
- Reports without findings → no finding notes → dashboard shows zero.
