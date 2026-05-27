# Target Scoring & Prioritization

## Scoring Matrix

Apply to each live host from httpx output. Higher total = test first.

| Signal | Points | How to detect |
|---|---|---|
| Admin / login / manager panel accessible | +3 | `/admin/`, `/login`, `/manager/`, `/dashboard/` in scope |
| CMS with version disclosed | +3 | Generator meta tag, changelog file, headers |
| Control panel accessible (cPanel, Plesk, WHM, DirectAdmin) | +3 | `/cpanel`, `/whm`, panel subdomains |
| WebDAV or FTP exposed | +3 | OPTIONS returns `DAV:` header; port 21 open |
| Custom application (no identifiable framework) | +2 | No generator tag, no known CMS fingerprint |
| Outdated server / framework version (CVEs exist) | +2 | Server header, response headers, version files |
| Parameter-rich pages (potential injection surface) | +2 | URLs with `?id=`, `?q=`, `?page=` from gau/wayback |
| API endpoints exposed | +2 | `/api/`, `/rest/`, `/graphql`, `/v1/` |
| File upload functionality present | +2 | Upload form in scope |
| Missing security headers | +1 | No X-Frame-Options, no CSP, no HSTS |
| Shared hosting (co-tenants reachable) | +1 | Multiple SANs on same cert, co-hosted IPs |
| HTTP only (no HTTPS redirect) | +1 | No redirect, no HSTS header |
| CDN-protected (Cloudflare, Akamai, Fastly) | -2 | `CF-Ray:`, `X-Served-By: Akamai`, `x-cache` headers |
| Pure static site | -3 | No forms, no auth, no parameters |

## Tier Assignment

| Score | Tier | Action |
|---|---|---|
| ≥ 8 | 🔴 Tier 1 — Primary | Full kill-chain immediately |
| 5–7 | 🟠 Tier 2 — Secondary | Full Level 1+2 after Tier 1 |
| 2–4 | 🟡 Tier 3 — Quick look | Directory scan + header check only |
| ≤ 1 | ⚪ Tier 4 — Skip | CDN-protected static, no attack surface |

## Technology Fingerprinting

```bash
# Response headers (fastest)
curl -sI "http://TARGET/" | grep -iE 'server:|x-powered-by:|x-generator:|x-cms:|x-runtime:'

# HTML meta tag
curl -sk "http://TARGET/" | grep -i 'generator\|powered by'

# Common version disclosure files (adapt to CMS)
curl -sk "http://TARGET/CHANGELOG.txt" | head -3
curl -sk "http://TARGET/CHANGES" | head -3
curl -sk "http://TARGET/version.txt" | head -3
curl -sk "http://TARGET/package.json" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('version',''))" 2>/dev/null

# JavaScript build artifacts (often expose framework + version)
curl -sk "http://TARGET/" | grep -oP '(src|href)="[^"]*\.(js|css)[^"]*"' \
  | sed 's/.*"\(.*\)".*/\1/' | head -10
```

## High-Value Paths to Check on Any Target

```bash
# Universal
/robots.txt              # reveals hidden paths
/sitemap.xml             # full URL inventory
/.well-known/security.txt  # VDP/bug bounty scope
/humans.txt
/crossdomain.xml
/clientaccesspolicy.xml

# Config / secrets
/.env
/.env.local
/.env.production
/config.yml
/config.json
/web.config
/database.yml
/secrets.yml
/wp-config.php.bak

# Admin / auth
/admin/
/admin/login
/login
/signin
/dashboard/
/manage/
/console/
/control/
/backend/
/staff/
/internal/

# Version disclosure
/CHANGELOG.txt
/CHANGELOG.md
/CHANGES
/VERSION
/version.txt
/package.json
/composer.json
/Gemfile

# Dev artifacts
/phpinfo.php
/info.php
/test.php
/debug/
/trace/
/status
/health
/metrics
/actuator/         # Spring Boot
/actuator/env
/actuator/mappings
```

## API Discovery

```bash
# Common API base paths
for EP in "/api/" "/api/v1/" "/api/v2/" "/rest/" "/graphql" "/gql" \
          "/v1/" "/v2/" "/__api/" "/wp-json/" "/odata/"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "http://TARGET$EP")
  [ "$CODE" != "404" ] && echo "$EP → HTTP $CODE"
done

# GraphQL introspection
curl -sk -X POST "http://TARGET/graphql" \
  -H "Content-Type: application/json" \
  --data '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool 2>/dev/null | head -30
```

## Quick Priority Check List (run on every new target)

```bash
HOST="target.com"; IP=$(dig +short A $HOST | head -1)

# One-liner surface map
for path in /admin/ /login /manager/ /cpanel /phpmyadmin/ /api/ /.env /robots.txt /CHANGELOG.txt; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "http://$IP$path" -H "Host: $HOST")
  [ "$CODE" != "404" ] && echo "$path → HTTP $CODE"
done

# Security headers
curl -sI "http://$IP/" -H "Host: $HOST" \
  | grep -iE 'x-frame|csp|hsts|x-content-type'

# Cookie flags on login
curl -sI "http://$IP/login" -H "Host: $HOST" | grep -i 'set-cookie'

# Version disclosure
curl -sI "http://$IP/" -H "Host: $HOST" | grep -i 'server:\|x-powered-by:'
```

---

## Attack Surface Signals — What to Note on Every Host

Run this block on each live host and note the outputs for prioritization.

```bash
HOST="target.com"; IP=$(dig +short A $HOST | head -1)

echo "=== $HOST ($IP) ==="

# 1. Technology stack
curl -sI "http://$IP/" -H "Host: $HOST" 2>/dev/null \
  | grep -iE 'server:|x-powered-by:|x-generator:|x-runtime:|x-aspnet'

# 2. Login surface
for P in /login /admin /signin /dashboard /manager /portal /staff /internal /auth; do
  C=$(curl -sk -o /dev/null -w "%{http_code}" "http://$IP$P" -H "Host: $HOST")
  [ "$C" != "404" ] && echo "  $P → $C"
done

# 3. Interesting files
for F in /robots.txt /.env /package.json /crossdomain.xml /.well-known/security.txt; do
  C=$(curl -sk -o /dev/null -w "%{http_code}" "http://$IP$F" -H "Host: $HOST")
  S=$(curl -sk -w "%{size_download}" -o /dev/null "http://$IP$F" -H "Host: $HOST")
  [ "$C" = "200" ] && [ "$S" -gt 10 ] && echo "  $F → $C (${S}B)"
done

# 4. Security headers
HEADERS=$(curl -sI "http://$IP/" -H "Host: $HOST" 2>/dev/null)
for H in "x-frame-options" "content-security-policy" "strict-transport-security" \
         "x-content-type-options" "referrer-policy" "permissions-policy"; do
  echo "$HEADERS" | grep -qi "$H" || echo "  MISSING: $H"
done

# 5. Cookie flags on any login
curl -sI "http://$IP/login" -H "Host: $HOST" 2>/dev/null \
  | grep -i 'set-cookie' | grep -iEv 'secure|samesite' | sed 's/^/  INSECURE COOKIE: /'

# 6. WebDAV
curl -sk -X OPTIONS "https://$HOST/" \
  -w "  WebDAV Allow: %header{allow} | DAV: %header{dav}\n" -o /dev/null 2>/dev/null

# 7. API surface
for EP in /api/ /api/v1/ /graphql /rest/ /odata/; do
  C=$(curl -sk -o /dev/null -w "%{http_code}" "http://$IP$EP" -H "Host: $HOST")
  [ "$C" != "404" ] && echo "  API: $EP → $C"
done
```

---

## CVE Quick-Check by Technology

Once a technology + version is confirmed, immediately check for known exploits:

```bash
# Search NVD
curl -sk "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=TECHNOLOGY+VERSION&resultsPerPage=5" \
  | python3 -m json.tool | grep -E '"id"|"descriptions"' | head -20

# Search Exploit-DB
searchsploit "Technology Version"
searchsploit -x EXPLOIT_ID   # view exploit details

# Search Nuclei templates for the technology
nuclei -tl | grep -i 'technology-name'
nuclei -u "http://$IP" -H "Host: $HOST" -tags technology-name -severity high,critical

# Snyk vulnerability DB
curl -sk "https://security.snyk.io/vuln/npm:package-name" | grep -i 'severity\|cve'
```

---

## Scope Verification — Before ANY Active Test

```bash
# Confirm the IP belongs to the target org (not a CDN or shared provider)
whois TARGET_IP | grep -i 'org\|orgname\|netname\|owner'

# Confirm SSL cert matches scope
openssl s_client -connect TARGET_IP:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName

# Check if IP is behind CDN (do not test CDN edge IPs as "the target")
curl -sI "http://TARGET_IP/" -H "Host: TARGET_HOSTNAME" | grep -i 'cf-ray\|x-cache\|via:\|x-served-by'
# If CDN headers present: target the origin IP (if in scope), not the CDN edge

# Verify target is live and responding to your probes
curl -sk "http://TARGET_IP/" -H "Host: TARGET_HOSTNAME" -w "HTTP: %{http_code} | Size: %{size_download}B\n" -o /dev/null
```
