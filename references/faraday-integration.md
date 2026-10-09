# Faraday Integration — Findings Hub

## What it is

Faraday (free, GPL-3.0 Community) is the evidence warehouse between scanning and
reporting. It normalizes output from 80+ pentest tools, dedups findings, tracks
severity/CVE/assets per workspace, and keeps history for recheck diffing. It is a
**dashboard + PostgreSQL database + CLI/API** — the "glass cockpit" view of an
engagement. All flying still happens in the terminal.

## Installed stack (Mac, native — no Docker)

| Component | Location / command |
|---|---|
| Faraday server | `~/faraday-venv/bin/faraday-server` |
| Dashboard | `http://localhost:5985` |
| CLI | `~/faraday-venv/bin/faraday-cli` (alias `faraday-cli` in `~/.zshrc`) |
| Database | PostgreSQL 16 — `brew services` (auto-start) |
| Task queue | Redis 8 — `brew services` (auto-start) |
| Config | `~/.faraday/config/server.ini` |
| Server log | `/tmp/faraday-server.log` |
| Admin login | `faraday` / password set during `faraday-manage initdb` (rotate in dashboard) |

Note: `brew`/`pg`/`redis` binaries are at `/opt/homebrew/bin` — already on PATH via
`~/.zprofile`. Non-interactive shells (scripts, cron) may need `export PATH="/opt/homebrew/bin:$PATH"` first.

## When it turns on

- **Phases 1–3:** nothing to ingest yet — skip Faraday.
- **Phase 4 start:** create workspace, push every scan result as it runs.
- **Phase 5:** import exploit artifacts (sqlmap/burp/metasploit) into same workspace.
- **Phase 6:** re-scan → Faraday diffs old vs new = Patched/Unpatched matrix (feeds `office_recheck`).
- **Phase 7:** export normalized data → feed `office_report`/`vajra_report`. Never use Faraday's own report writer.

## Per-engagement workflow

```bash
# 1. One workspace per client
faraday-cli workspace create "<client>-<YYYYMM>"

# 2. Scope CLI to that workspace (persistent selection)
faraday-cli workspace select "<client>-<YYYYMM>"

# 3. Push live tool output — console plugins need STRUCTURED output to parse
#    reliably, so always export (-oX / -json) and prefer `tool report` on the file
faraday-cli tool run "nmap -sV -sC -oX pentest/HOST/nmap.xml <target>"
faraday-cli tool report -w "<client>-<YYYYMM>" pentest/HOST/nmap.xml
faraday-cli tool run "nuclei -u <target> -severity critical,high,medium,low,info -json-export pentest/HOST/nuclei_results.json"

# 4. Import artifacts already on disk (report plugin parses XML/JSON)
faraday-cli tool report pentest/HOST/nuclei_results.json
faraday-cli tool report pentest/HOST/ferox.json

# 5. Verify ingestion
faraday-cli workspace list
faraday-cli vuln list -w "<client>-<YYYYMM>"
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `faraday-cli` auth error | `printf "http://localhost:5985\nfaraday\n<PASSWORD>\n" \| faraday-cli auth` |
| Dashboard unreachable | `brew services list` → postgresql@16 + redis must be `started`; restart both, then `faraday` (alias) |
| Redis "Module ./modules/redisbloom" abort | Config must NOT reference redisbloom — clean config at `/opt/homebrew/etc/redis.conf` binds only `127.0.0.1` |
| psycopg2 build fail | Set `PG_CONFIG=/opt/homebrew/opt/postgresql@16/bin/pg_config` before pip install |
| `pkg_resources` ModuleNotFoundError | `pip install "setuptools<81"` in the venv |

## Rules

- Scope-first: never create a workspace for an out-of-scope target.
- Dashboard is read-reference; keep executing scans in terminal (MCP/Bash).
- Faraday = aggregation + tracking only. It does NOT scan, exploit, or report for you.
