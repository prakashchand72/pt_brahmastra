# Dynamic Testing — Automated & Parallel Tool Execution

Dynamic testing is the systematic, tool-driven phase that runs in parallel with
and after manual exploitation. The goal: exhaust the attack surface automatically
so nothing is missed. Run tools in background, collect all output, then triage.

---

## Mindset

- Run multiple tools simultaneously — don't wait for one to finish before starting the next
- Every tool writes to a file; review files after all tools complete
- Always record baseline responses before fuzzing — use them to filter noise
- Tools confirm or expand manual findings; they don't replace judgment
- **This host is macOS (BSD userland):** no `grep -P` (use `grep -E`), no `md5sum`
  (use `md5 -q`), SecLists at `~/tools/SecLists`, curl needs `-g` for `[]` in URLs.

---

## Phase D0 — Crawl & Param Discovery (do this FIRST)

Injection phases are only as good as the URL/param list feeding them. Hand-guessed
params (`id`, `q`, `search`) miss everything custom. Run these before D2–D3:

```bash
IP="TARGET_IP"; HOST="target.com"
mkdir -p pentest/dynamic

# Katana — real crawl: JS-rendered routes, forms, robots/sitemap seeds
katana -u "http://$IP" -H "Host: $HOST" -jc -kf robotstxt,sitemapxml \
  -d 3 -o pentest/dynamic/katana_urls.txt &

# Arjun — parameter discovery on every interesting endpoint found so far
# (consumes Phase 2 archive URLs + katana output, not feroxbuster paths)
cat pentest/all_urls.txt pentest/dynamic/katana_urls.txt 2>/dev/null \
  | grep -E '^https?://' | sort -u > pentest/dynamic/probe_urls.txt
arjun --urls pentest/dynamic/probe_urls.txt -oJ pentest/dynamic/arjun_params.json &

# gowitness — screenshot gallery for visual triage while scanners run
gowitness scan file -f pentest/dynamic/probe_urls.txt \
  --screenshot-path pentest/dynamic/screenshots 2>/dev/null &
```

**Fuzzer calibration:** on targets with soft-404s (everything returns 200), always
add `-ac` to ffuf and `--auto-bail --auto-tune` to feroxbuster — fixed `-fs` values
rot as soon as the baseline page changes.

---

## Phase D1 — Launch All Scanners (Parallel)

Start these immediately after Phase 4 active scanning. All run in background.

```bash
IP="TARGET_IP"; HOST="target.com"
mkdir -p pentest/dynamic

# D1-A: Nuclei — CVE + misconfig templates
nuclei -u "http://$IP" -H "Host: $HOST" \
  -tags cve,rce,sqli,xss,ssrf,exposure,misconfig,takeover,default-login \
  -severity medium,high,critical \
  -timeout 10 -c 25 -silent \
  -o pentest/dynamic/nuclei.txt &

# D1-B: Nikto — server/header audit
nikto -h "http://$IP" -vhost "$HOST" \
  -output pentest/dynamic/nikto.txt \
  -Format txt -nointeractive &

# D1-C: Feroxbuster — deep directory enumeration
feroxbuster \
  --url "http://$IP" \
  --headers "Host: $HOST" \
  --wordlist ~/tools/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  --depth 3 --threads 25 --timeout 10 \
  --status-codes 200,201,204,301,302,401,403 \
  --auto-bail --auto-tune \
  --silent \
  --output pentest/dynamic/ferox_dirs.txt &

# D1-D: Feroxbuster — file extensions
feroxbuster \
  --url "http://$IP" \
  --headers "Host: $HOST" \
  --wordlist ~/tools/SecLists/Discovery/Web-Content/raft-medium-files.txt \
  --extensions php,asp,aspx,jsp,bak,old,sql,env,config,txt,log,zip,tar,gz \
  --depth 2 --threads 20 --timeout 10 \
  --status-codes 200,201 \
  --auto-bail --auto-tune \
  --silent \
  --output pentest/dynamic/ferox_files.txt &

# D1-E: Subdomain brute-force (if not already done)
ffuf -u "http://$IP/" -H "Host: FUZZ.$HOST" \
  -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac -mc 200,301,302,401,403 -t 40 -silent \
  -o pentest/dynamic/subdomains.json -of json &

echo "[*] All scanners launched. PIDs: $(jobs -p)"
wait
echo "[*] All scanners complete."
```

---

## Phase D2 — Authentication Dynamic Tests

```bash
IP="TARGET_IP"; HOST="target.com"
LOGIN_URL="http://$IP/login"  # adapt to target

# D2-A: No-lockout verification (50 attempts, structured)
python3 playbooks/no-lockout-check.py \
  2>&1 | tee pentest/dynamic/lockout_check.txt

# D2-B: Targeted brute-force (brand wordlist)
# NOTE: ffuf -mr is a Go RE2 regex — plain | for alternation, never \|
ffuf -u "$LOGIN_URL" -X POST \
  -H "Host: $HOST" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=FUZZ" \
  -w pentest/wordlists/target_creds.txt \
  -mr "success.*true|dashboard|welcome|logout" \
  -t 5 -timeout 15 -s \
  -o pentest/dynamic/bruteforce_targeted.json -of json

# D2-C: Top-10k brute-force (background)
ffuf -u "$LOGIN_URL" -X POST \
  -H "Host: $HOST" \
  -d "username=admin&password=FUZZ" \
  -w ~/tools/SecLists/Passwords/Common-Credentials/10k-most-common.txt \
  -mr "success.*true|dashboard|welcome" \
  -t 8 -timeout 15 -s \
  -o pentest/dynamic/bruteforce_top10k.json -of json &

# D2-D: Multiple usernames (clusterbomb — targeted list × common passwords)
ffuf -u "$LOGIN_URL" -X POST \
  -H "Host: $HOST" \
  -d "username=USER&password=PASS" \
  -mode clusterbomb \
  -w pentest/wordlists/users.txt:USER \
  -w pentest/wordlists/target_creds.txt:PASS \
  -mr "success.*true|dashboard" \
  -t 5 -timeout 15 -s \
  -o pentest/dynamic/bruteforce_clusterbomb.json -of json &

echo "[*] Auth tests launched."
```

---

## Phase D3 — Injection Dynamic Tests

```bash
IP="TARGET_IP"; HOST="target.com"

# D3-A: SQLmap — GET parameter
sqlmap -u "http://$IP/page?id=1" \
  -H "Host: $HOST" \
  --dbms=mysql --level=3 --risk=2 \
  --technique=BEUSTQ --batch \
  --output-dir=pentest/dynamic/sqlmap_get \
  2>&1 | tee pentest/dynamic/sqlmap_get.txt &

# D3-B: SQLmap — POST login form
sqlmap -u "http://$IP/login" \
  --data "username=*&password=test" \
  -H "Host: $HOST" --method POST \
  --dbms=mysql --level=3 --risk=2 \
  --technique=BEUSTQ --ignore-code=500 --batch \
  --output-dir=pentest/dynamic/sqlmap_post \
  2>&1 | tee pentest/dynamic/sqlmap_post.txt &

# D3-C: SQLmap — Cookie
sqlmap -u "http://$IP/dashboard" \
  -H "Host: $HOST" \
  --cookie "session=*" \
  --level=2 --risk=1 --batch \
  --output-dir=pentest/dynamic/sqlmap_cookie \
  2>&1 | tee pentest/dynamic/sqlmap_cookie.txt &

# D3-D: dalfox XSS — GET param
dalfox url "http://$IP/search?q=FUZZ" \
  -H "Host: $HOST" \
  --timeout 15 --silence --no-color \
  2>&1 | tee pentest/dynamic/dalfox_get.txt &

# D3-E: dalfox XSS — POST form
dalfox url "http://$IP/search" \
  -H "Host: $HOST" \
  --data "q=FUZZ&category=all" --method POST \
  --timeout 15 --silence --no-color \
  2>&1 | tee pentest/dynamic/dalfox_post.txt &

# D3-F: Custom injection fuzzer (all fields × payload set)
python3 playbooks/injection-fuzzer.py \
  2>&1 | tee pentest/dynamic/injection_fuzzer.txt &

echo "[*] Injection tests launched."
wait
echo "[*] Injection tests complete."
```

---

## Phase D4 — Header & Protocol Dynamic Tests

```bash
IP="TARGET_IP"; HOST="target.com"

# D4-A: Security headers audit on all discovered paths
echo "=== Security headers audit ===" > pentest/dynamic/headers_audit.txt
while IFS= read -r URL; do
  HEADERS=$(curl -sI "$URL" -H "Host: $HOST" 2>/dev/null)
  MISSING=""
  for H in "x-frame-options" "content-security-policy" "x-content-type-options" \
            "strict-transport-security" "referrer-policy"; do
    echo "$HEADERS" | grep -qi "$H" || MISSING="$MISSING $H"
  done
  [ -n "$MISSING" ] && echo "$URL → MISSING:$MISSING" >> pentest/dynamic/headers_audit.txt
done < <(grep -oE 'http[^[:space:]"]+' pentest/dynamic/ferox_dirs.txt 2>/dev/null | sort -u | head -50)

# D4-B: Cookie flag audit on all login/auth pages
echo "=== Cookie flag audit ===" > pentest/dynamic/cookie_audit.txt
for P in /login /signin /auth /admin /dashboard /account; do
  COOKIE=$(curl -sI "http://$IP$P" -H "Host: $HOST" 2>/dev/null | grep -i 'set-cookie')
  [ -n "$COOKIE" ] && {
    echo "$P: $COOKIE" >> pentest/dynamic/cookie_audit.txt
    echo "$COOKIE" | grep -qiv 'secure' && echo "  !! Missing Secure flag" >> pentest/dynamic/cookie_audit.txt
    echo "$COOKIE" | grep -qiv 'httponly' && echo "  !! Missing HttpOnly flag" >> pentest/dynamic/cookie_audit.txt
    echo "$COOKIE" | grep -qiv 'samesite' && echo "  !! Missing SameSite flag" >> pentest/dynamic/cookie_audit.txt
  }
done

# D4-C: CORS test across all API endpoints
echo "=== CORS audit ===" > pentest/dynamic/cors_audit.txt
for EP in /api/ /api/v1/ /api/v2/ /rest/ /graphql /v1/ /v2/; do
  ACAO=$(curl -sk "http://$IP$EP" -H "Host: $HOST" \
    -H "Origin: https://evil.com" \
    -w "%header{access-control-allow-origin}" -o /dev/null 2>/dev/null)
  ACAC=$(curl -sk "http://$IP$EP" -H "Host: $HOST" \
    -H "Origin: https://evil.com" \
    -w "%header{access-control-allow-credentials}" -o /dev/null 2>/dev/null)
  [ -n "$ACAO" ] && echo "$EP → ACAO=$ACAO ACAC=$ACAC" >> pentest/dynamic/cors_audit.txt
done
# Verdict rule: ACAO reflecting the attacker origin (NOT *) + ACAC=true = exploitable.
# ACAO=* with ACAC=true is browser-blocked — note it, don't report it as exploitable.

# D4-D: Host header injection across key paths
echo "=== Host header injection ===" > pentest/dynamic/hostheader_audit.txt
for P in / /login /reset-password /admin /api/; do
  LOC=$(curl -sk "http://$IP$P" \
    -H "Host: $HOST" \
    -H "X-Forwarded-Host: evil-$(date +%s).com" \
    -w "%header{location}" -o /tmp/hostheader_body.txt 2>/dev/null)
  BODY=$(grep -i 'evil' /tmp/hostheader_body.txt 2>/dev/null | head -1)
  { [ -n "$LOC" ] && echo "$LOC" | grep -qi 'evil'; } && \
    echo "VULNERABLE: $P → Location: $LOC" >> pentest/dynamic/hostheader_audit.txt
  [ -n "$BODY" ] && echo "REFLECTED: $P → body contains injected host" >> pentest/dynamic/hostheader_audit.txt
done

# D4-E: Open redirect scan — source is ARCHIVE URLS (they carry real query strings),
# NOT feroxbuster output (directory results have no params and this finds nothing).
echo "=== Open redirect scan ===" > pentest/dynamic/redirect_audit.txt
cat pentest/all_urls.txt pentest/dynamic/probe_urls.txt 2>/dev/null \
  | grep -E '^https?://' | sort -u \
  | grep -iE '[?&](url|redirect|next|return|goto|dest)=' \
  | while read -r URL; do
    BASE=$(echo "$URL" | sed -E 's/([?&](url|redirect|next|return|goto|dest)=)[^&]*/\1/')
    LOC=$(curl -ski "${BASE}https://evil-test.com" \
      -H "Host: $HOST" -w "%header{location}" -o /dev/null 2>/dev/null)
    echo "$LOC" | grep -qi 'evil-test' && \
      echo "VULNERABLE: $URL" >> pentest/dynamic/redirect_audit.txt
  done

echo "[*] Header/protocol tests complete."
```

---

## Phase D5 — Timing & Side-Channel Tests

```bash
IP="TARGET_IP"; HOST="target.com"

# D5-A: Username timing attack
# NOTE: 5 samples per user is a SCREEN, not proof. The classic oracle: password
# hashing (bcrypt) runs ONLY for valid usernames → valid users respond slower.
# To claim a finding, collect hundreds of samples and compare statistically.
echo "=== Username timing attack ===" > pentest/dynamic/timing_attack.txt
for USER in admin administrator root user guest manager test; do
  TIMES=""
  for i in $(seq 1 20); do
    T=$(curl -sk -X POST "http://$IP/login" -H "Host: $HOST" \
      -d "username=$USER&password=wrongpassword$RANDOM" \
      -w "%{time_total}" -o /dev/null 2>/dev/null)
    TIMES="$TIMES $T"
  done
  AVG=$(python3 -c "ts=[float(x) for x in '$TIMES'.split()]; print(f'{sum(ts)/len(ts):.3f}')" 2>/dev/null)
  echo "$USER: avg=${AVG}s samples=$TIMES" >> pentest/dynamic/timing_attack.txt
done
cat pentest/dynamic/timing_attack.txt

# D5-B: Password reset token entropy check
echo "=== Password reset tokens ===" > pentest/dynamic/reset_tokens.txt
for EMAIL in test1@test.com test2@test.com test3@test.com; do
  TOKEN=$(curl -sk -X POST "http://$IP/reset" -H "Host: $HOST" \
    -d "email=$EMAIL" | sed -n 's/.*token=\([^"& ]*\).*/\1/p' | head -1)
  [ -n "$TOKEN" ] && echo "$EMAIL → $TOKEN" >> pentest/dynamic/reset_tokens.txt
done
# Compare tokens — if sequential or share a common prefix = predictable

# D5-C: IDOR enumeration on numeric IDs
echo "=== IDOR ID scan ===" > pentest/dynamic/idor_scan.txt
for ID in $(seq 1 200); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "http://$IP/api/resource/$ID" \
    -H "Host: $HOST" -b "session=VALID_SESSION" 2>/dev/null)
  SIZE=$(curl -sk -w "%{size_download}" -o /dev/null \
    "http://$IP/api/resource/$ID" \
    -H "Host: $HOST" -b "session=VALID_SESSION" 2>/dev/null)
  [ "$CODE" = "200" ] && echo "id=$ID → HTTP $CODE (${SIZE}B)" >> pentest/dynamic/idor_scan.txt
done
cat pentest/dynamic/idor_scan.txt
```

---

## Phase D6 — Infrastructure Dynamic Tests

```bash
IP="TARGET_IP"; HOST="target.com"

# D6-A: WebDAV probe on all known subdomains
# NOTE: the -w format string literally contains "DAV:" — match a NON-EMPTY value,
# or every result false-fires.
echo "=== WebDAV probe ===" > pentest/dynamic/webdav.txt
for SUB in webdisk files dav ftp storage media; do
  RESULT=$(curl -sk -X OPTIONS "https://$SUB.$HOST/" \
    --max-time 10 \
    -w "HTTP %{http_code} | Allow: %header{allow} | DAV: %header{dav}" \
    -o /dev/null 2>/dev/null)
  echo "$SUB.$HOST → $RESULT" >> pentest/dynamic/webdav.txt
  echo "$RESULT" | grep -qE 'DAV: [0-9a-zA-Z]' && \
    echo "  !! WebDAV ACTIVE on $SUB.$HOST" >> pentest/dynamic/webdav.txt
done

# D6-B: Common admin panel discovery (raft-small-words covers the panel names;
# there is no AdminPanels.fuzz.txt in SecLists)
echo "=== Admin panel scan ===" > pentest/dynamic/admin_panels.txt
ffuf -u "http://$IP/FUZZ" -H "Host: $HOST" \
  -w ~/tools/SecLists/Discovery/Web-Content/raft-small-words.txt \
  -ac -mc 200,301,302,401,403 -t 30 -silent \
  -o pentest/dynamic/admin_panels.json -of json
jq -r '.results[]|"\(.status) \(.url)"' pentest/dynamic/admin_panels.json 2>/dev/null \
  | tee -a pentest/dynamic/admin_panels.txt

# D6-C: API endpoint fuzz (REST + GraphQL + common API paths)
ffuf -u "http://$IP/FUZZ" -H "Host: $HOST" \
  -w ~/tools/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -ac -mc 200,201,204,301,302,401,403 -t 30 -silent \
  -o pentest/dynamic/api_endpoints.json -of json

# D6-D: HTTP methods on all discovered paths
echo "=== HTTP method audit ===" > pentest/dynamic/methods_audit.txt
grep -oE 'https?://[^[:space:]"]+' pentest/dynamic/ferox_dirs.txt 2>/dev/null \
  | sort -u | head -30 \
  | while read -r URL; do
    for METHOD in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
      CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X "$METHOD" "$URL" -H "Host: $HOST" 2>/dev/null)
      [ "$CODE" != "404" ] && [ "$CODE" != "405" ] && \
        echo "$METHOD $URL → $CODE" >> pentest/dynamic/methods_audit.txt
    done
  done

# D6-E: SSL/TLS audit
echo "=== SSL/TLS audit ===" > pentest/dynamic/ssl_audit.txt
# Check protocols + ciphers
nmap --script ssl-enum-ciphers -p 443 "$IP" >> pentest/dynamic/ssl_audit.txt 2>/dev/null
# Check cert validity + expiry
echo | openssl s_client -connect "$IP:443" -servername "$HOST" 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer >> pentest/dynamic/ssl_audit.txt

echo "[*] Infrastructure tests complete."
```

---

## Phase D7 — JavaScript Dynamic Analysis

```bash
IP="TARGET_IP"; HOST="target.com"
mkdir -p pentest/js

# D7-A: Extract and download all JS files
# (D0 katana crawl already feeds urls_js.txt via Phase 4b — this is the quick
# homepage fallback. Handles absolute, protocol-relative //, and root-relative src.)
echo "=== JS file discovery ==="
curl -sk "http://$IP/" -H "Host: $HOST" \
  | grep -oE '(src|href)="[^"]*\.js[^"]*"' \
  | sed 's/.*"\(.*\)".*/\1/' \
  | while read -r JS; do
    case "$JS" in
      http*) : ;;                          # absolute — use as-is
      //*)  JS="https:$JS" ;;              # protocol-relative — keep real host
      /*)   JS="http://$IP$JS" ;;          # root-relative
      *)    JS="http://$IP/$JS" ;;         # relative
    esac
    FNAME=$(printf '%s' "$JS" | md5 -q 2>/dev/null || printf '%s' "$JS" | md5sum | cut -c1-8).js
    curl -sk "$JS" -H "Host: $HOST" -o "pentest/js/$FNAME" 2>/dev/null
    echo "$JS → pentest/js/$FNAME"
  done

# D7-B: Grep all JS for secrets and interesting patterns
echo "=== JS secret scan ===" > pentest/dynamic/js_secrets.txt
grep -rn --color=never \
  -E 'api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|aws_|s3_bucket|firebase|stripe|twilio|sendgrid|password[[:space:]]*[:=]|passwd[[:space:]]*[:=]|db_pass|database_url' \
  pentest/js/ >> pentest/dynamic/js_secrets.txt

# D7-C: Grep for endpoints / API routes
echo "=== JS endpoint extraction ===" > pentest/dynamic/js_endpoints.txt
grep -rhoE '"/(api|v[0-9]+|rest|graphql)[^"]*"' \
  pentest/js/ | tr -d '"' | sort -u >> pentest/dynamic/js_endpoints.txt

# D7-D: Grep for redirect / location manipulation
echo "=== JS redirect sinks ===" > pentest/dynamic/js_redirects.txt
grep -rn --color=never \
  -E 'window\.location|location\.href|location\.replace|location\.assign|document\.location' \
  pentest/js/ >> pentest/dynamic/js_redirects.txt

# D7-E: Source maps (full original source disclosure)
find pentest/js/ -name "*.js" | while read -r F; do
  MAP_URL=$(tail -1 "$F" | sed -n 's/.*sourceMappingURL=//p')
  [ -n "$MAP_URL" ] && echo "SOURCE MAP FOUND: $F → $MAP_URL" >> pentest/dynamic/js_secrets.txt
done

echo "[*] JS analysis complete."
```

---

## Phase D8 — Collect & Triage Results

Run after all background jobs complete.

```bash
echo "===== DYNAMIC TESTING RESULTS SUMMARY =====" > pentest/dynamic/SUMMARY.txt
echo "Date: $(date)" >> pentest/dynamic/SUMMARY.txt
echo "" >> pentest/dynamic/SUMMARY.txt

# Nuclei findings
echo "--- Nuclei ---" >> pentest/dynamic/SUMMARY.txt
wc -l pentest/dynamic/nuclei.txt 2>/dev/null | awk '{print $1 " findings"}' >> pentest/dynamic/SUMMARY.txt
cat pentest/dynamic/nuclei.txt 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# Brute-force hits
echo "--- Brute-force ---" >> pentest/dynamic/SUMMARY.txt
jq -r '.results[]|"\(.input.FUZZ) → \(.status)"' \
  pentest/dynamic/bruteforce_targeted.json 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# Directory findings
echo "--- Directories ---" >> pentest/dynamic/SUMMARY.txt
grep -v '^[A-Z{]' pentest/dynamic/ferox_dirs.txt 2>/dev/null \
  | grep -v '^$' | sort -u >> pentest/dynamic/SUMMARY.txt

# SQLmap — match the canonical confirmation block, not the word "vulnerable"
echo "--- SQLi ---" >> pentest/dynamic/SUMMARY.txt
grep -hE 'identified the following injection point|is vulnerable' \
  pentest/dynamic/sqlmap_*.txt 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# XSS
echo "--- XSS ---" >> pentest/dynamic/SUMMARY.txt
grep -iE 'POC|verified|WEAK' pentest/dynamic/dalfox_*.txt 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# CORS
echo "--- CORS ---" >> pentest/dynamic/SUMMARY.txt
grep -v '^$' pentest/dynamic/cors_audit.txt 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# Host header
echo "--- Host header injection ---" >> pentest/dynamic/SUMMARY.txt
grep -E 'VULNERABLE|REFLECTED' pentest/dynamic/hostheader_audit.txt 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# Missing headers
echo "--- Missing security headers ---" >> pentest/dynamic/SUMMARY.txt
grep 'MISSING' pentest/dynamic/headers_audit.txt 2>/dev/null | sort | uniq -c | sort -rn >> pentest/dynamic/SUMMARY.txt

# Insecure cookies
echo "--- Insecure cookies ---" >> pentest/dynamic/SUMMARY.txt
grep '!!' pentest/dynamic/cookie_audit.txt 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# WebDAV
echo "--- WebDAV ---" >> pentest/dynamic/SUMMARY.txt
grep -E 'ACTIVE|DAV: [0-9a-zA-Z]' pentest/dynamic/webdav.txt 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# IDOR
echo "--- IDOR ---" >> pentest/dynamic/SUMMARY.txt
grep 'id=' pentest/dynamic/idor_scan.txt 2>/dev/null >> pentest/dynamic/SUMMARY.txt

# JS secrets
echo "--- JS secrets ---" >> pentest/dynamic/SUMMARY.txt
grep -v '^$' pentest/dynamic/js_secrets.txt 2>/dev/null | head -20 >> pentest/dynamic/SUMMARY.txt

echo ""
echo "[*] Summary saved to pentest/dynamic/SUMMARY.txt"
cat pentest/dynamic/SUMMARY.txt
```

---

## False Positive Triage After Dynamic Tests

Before promoting a dynamic finding to a report finding:

| Tool | Common FP | How to triage |
|---|---|---|
| Nuclei | Info templates, old CVE on wrong version | Check the template ID + confirm version match |
| SQLmap | "might be injectable" without confirmation | Require `--dbs` or dump to confirm |
| dalfox | Reflected but sanitised by browser | Confirm `alert()` actually fires in real browser |
| Nikto | Old header advisories, version-only flags | Cross-check with actual exploitability |
| ffuf (brute) | Wildcard 200 responses | Use `-ac` auto-calibration, or `-fs` with the baseline size |
| Feroxbuster | Soft-404 (200 with "not found" body) | `--auto-bail --auto-tune`, or `--filter-words`/`--filter-size` |
| Timing attack | Natural variance | Hundreds of samples + statistical comparison, not 5-sample averages |
| IDOR | 200 but returns your own data | Compare body content: does it belong to other user? |

---

## Dynamic Testing Output Files

```
pentest/dynamic/
├── SUMMARY.txt               ← aggregated results — read this first
├── nuclei.txt                ← CVE / misconfig findings
├── nikto.txt                 ← server / header audit
├── katana_urls.txt           ← D0 crawl: JS-rendered routes + forms
├── probe_urls.txt            ← merged URL list (archive + crawl)
├── arjun_params.json         ← discovered parameters per endpoint
├── screenshots/              ← gowitness gallery
├── ferox_dirs.txt            ← directory enumeration
├── ferox_files.txt           ← sensitive file extension scan
├── subdomains.json           ← subdomain brute-force
├── bruteforce_targeted.json  ← brand wordlist hits
├── bruteforce_top10k.json    ← common password hits
├── bruteforce_clusterbomb.json
├── sqlmap_get.txt / sqlmap_post.txt / sqlmap_cookie.txt
├── dalfox_get.txt / dalfox_post.txt
├── injection_fuzzer.txt      ← custom fuzzer anomalies
├── lockout_check.txt         ← lockout verification
├── timing_attack.txt         ← username timing
├── idor_scan.txt             ← IDOR ID enumeration
├── cors_audit.txt            ← CORS per endpoint
├── headers_audit.txt         ← missing headers per URL
├── cookie_audit.txt          ← insecure cookie flags
├── hostheader_audit.txt      ← host header injection
├── redirect_audit.txt        ← open redirect scan
├── methods_audit.txt         ← HTTP method matrix
├── webdav.txt                ← WebDAV per subdomain
├── admin_panels.json         ← admin panel discovery
├── api_endpoints.json        ← API path discovery
├── ssl_audit.txt             ← TLS config
├── reset_tokens.txt          ← password reset entropy
└── js_secrets.txt / js_endpoints.txt / js_redirects.txt
pentest/js/
└── *.js                      ← downloaded JS files
```
