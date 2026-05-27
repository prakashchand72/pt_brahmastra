# pt_brahmastra

Full-stack authorized web penetration testing skill for Claude Code. Runs a structured kill-chain from passive recon through active exploitation, dynamic verification, and final report generation.

## Installation

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/YOUR_USERNAME/pt_brahmastra ~/.claude/skills/pt_brahmastra
```

That's it. Claude Code auto-discovers skills placed in `~/.claude/skills/`.

## Invocation

Open Claude Code in your pentest working directory, then type any of:

```
/pt_brahmastra
pentest https://target.com
hack this target
find vulns on target.com
security assessment for target.com
```

Claude will load the skill and begin with the **authorization gate** — you must confirm written authorization before any active testing starts.

## What It Does

7-phase kill-chain:

| Phase | Name | Description |
|---|---|---|
| 1 | Authorization gate | Confirms written auth before any active test |
| 2 | Passive recon | Subdomain enum, historical URLs, cert transparency, OSINT |
| 3 | Target prioritization | Scores each host, assigns tiers, picks attack order |
| 4 | Active scanning | Directory brute-force, CVE scan (nuclei), nikto, nmap |
| 5 | Exploitation | 40+ attack classes — SQLi, XSS, auth, IDOR, SSTI, JWT, race conditions, etc. |
| 6 | Dynamic verification | Live proof for every finding; false-positive triage |
| 7 | Report generation | Structured report with severity ratings and evidence |

## Attack Classes Covered

```
Authentication    brute-force · lockout · session fixation · 2FA bypass · password reset · username enum
Injection         SQLi · XSS · command injection · SSTI · XXE · NoSQL · LDAP · prototype pollution
File attacks      path traversal · LFI · RFI · file upload bypass
API / Protocol    CORS · HTTP verb tampering · HPP · CRLF · smuggling · cache poisoning · GraphQL · WebSocket
Client-side       JS analysis · open redirect · clickjacking · CSRF
Access control    IDOR · mass assignment · OAuth/SSO · JWT · forced browsing
Logic             race condition · business logic · negative values · workflow skip
Infra             WebDAV · subdomain takeover · deserialization · info disclosure
```

## Included Files

```
SKILL.md                          ← skill entry point (loaded by Claude Code)
references/
  passive-recon.md                ← full OSINT + recon tool options
  target-scoring.md               ← host scoring matrix and prioritization
  level2-exploitation.md          ← all attack classes with commands
  verification-checklist.md       ← per-finding true/false positive tests
  dynamic-testing.md              ← D1–D8 parallel automated tool phases
  report-templates.md             ← report structure and severity table
playbooks/
  injection-fuzzer.py             ← 13-payload × N-field fuzzer with anomaly detection
  no-lockout-check.py             ← lockout verification (N attempts, keyword detection)
  race-condition.py               ← threading.Barrier synchronized parallel requests
  build-wordlist.sh               ← brand/target-specific credential wordlist generator
```

## Requirements

Tools used by the skill (install on your system):

```bash
# Core
httpx subfinder amass nuclei nikto nmap
ffuf feroxbuster sqlmap dalfox

# From SecLists
apt install seclists   # or: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# Optional (used in specific attack classes)
gau waybackurls openssl curl python3
```

## Usage Notes

- **Always run from your pentest working directory** — tools write output relative to `pentest/`
- **Authorization is mandatory** — the skill will not proceed to active phases without explicit confirmation
- **IP bypass** — if a hostname is CDN/WAF rate-limited, the skill sends requests directly to the raw IP with a `Host:` header
- All playbooks have a `# Configure these` block at the top — edit before running

## Authorization

This skill is for **authorized penetration testing only**. Accepted authorization statements:

- "written authorization"
- "bug bounty"
- "CTF"
- "authorized engagement"

Do not use against targets you do not have explicit written permission to test.
