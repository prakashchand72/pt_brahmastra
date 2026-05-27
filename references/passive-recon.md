# Passive Recon Reference

## httpx Full Options

```bash
httpx -l scope.txt \
  -title -tech-detect -ip -status-code \
  -cdn -probe -follow-redirects \
  -threads 50 -timeout 10 \
  -o httpx.txt

# Interesting filters
grep 'SUCCESS' httpx.txt                        # live hosts
grep -i 'MODX\|WordPress\|Drupal\|Shopify' httpx.txt  # CMS targets
grep -i 'SAP\|Hybris\|Commerce' httpx.txt        # SAP targets
grep -v 'Cloudflare\|Akamai' httpx.txt           # non-CDN (testable)
grep -oP '\[\d+\.\d+\.\d+\.\d+\]' httpx.txt | tr -d '[]' | sort -u  # IPs
```

## Subdomain Enumeration

```bash
subfinder -d target.com -o subs_passive.txt
amass enum -passive -d target.com -o subs_amass.txt
cat subs_passive.txt subs_amass.txt | sort -u > subs_all.txt

# CT logs
curl -s "https://crt.sh/?q=%.target.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# DNS brute
dnsx -l subs_all.txt -a -o resolved.txt
```

## Historical URL Discovery

```bash
gau --subs target.com 2>/dev/null | tee urls_gau.txt
waybackurls target.com 2>/dev/null | tee urls_wayback.txt
cat urls_gau.txt urls_wayback.txt | sort -u | grep -v '\.(png|jpg|css|gif|woff)' > urls_interesting.txt

# Find JS files, API endpoints, params
grep '\.js$\|\.json$' urls_interesting.txt
grep '?\|&' urls_interesting.txt  # parameterized URLs
grep -i 'api\|admin\|login\|auth\|token' urls_interesting.txt
```

## Email / SPF / DMARC

```bash
dig +short TXT target.com | grep -i 'spf\|v=spf'
dig +short TXT _dmarc.target.com
# DMARC p=reject = strong protection; p=none = phishing risk
```

## SSL Certificate Analysis

```bash
openssl s_client -connect target.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -E 'Subject:|Issuer:|Not After|DNS:'

# Get all SANs
openssl s_client -connect target.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

## WHOIS / ASN / Hosting

```bash
whois target.com | grep -i 'registrar\|creation\|expiry\|name server'
whois $(dig +short A target.com | head -1) | grep -i 'org\|netname\|country\|cidr'

# Shodan (if API key available)
shodan host $(dig +short A target.com | head -1)
```

## Technology Stack Fingerprinting (passive)

- **Wappalyzer** browser extension on target
- **builtwith.com** for full stack
- **whatcms.org** for CMS detection
- Check response headers: `X-Powered-By`, `Server`, `X-Generator`
- Check HTML `<meta name="generator">`
- Check `robots.txt`, `sitemap.xml` for path hints

## Key Paths to Check (no auth needed)

```
/robots.txt
/sitemap.xml
/.well-known/security.txt
/humans.txt
/crossdomain.xml
/clientaccesspolicy.xml
/CHANGELOG.txt
/VERSION
/package.json
/composer.json
/admin/
/phpmyadmin/
```

---

## Google Dorks

Run these in a browser — no tools required, zero packets sent to target.

```
# Admin panels
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:dashboard
site:target.com inurl:portal

# Exposed files / config
site:target.com filetype:env
site:target.com filetype:sql
site:target.com filetype:log
site:target.com filetype:bak
site:target.com filetype:conf
site:target.com filetype:config
site:target.com ext:php inurl:config

# Sensitive parameters
site:target.com inurl:?id=
site:target.com inurl:?file=
site:target.com inurl:?redirect=
site:target.com inurl:?url=
site:target.com inurl:?page=
site:target.com inurl:?token=

# Exposed credentials / secrets
site:target.com "password" filetype:txt
site:target.com "api_key" OR "api key" OR "apikey"
site:target.com "DB_PASSWORD" OR "database_password"

# Error pages (version / stack disclosure)
site:target.com "Fatal error" "PHP"
site:target.com "Warning: mysqli"
site:target.com "at sun.reflect" OR "java.lang"

# Directory listings
site:target.com intitle:"index of"

# Login pages across subdomains
site:*.target.com inurl:login
site:*.target.com inurl:admin

# Cached / old versions
cache:target.com
```

---

## GitHub / GitLab Recon

```bash
# Search GitHub for target domain leaks (browser)
# https://github.com/search?q=target.com&type=code
# https://github.com/search?q="target.com"+password&type=code
# https://github.com/search?q="target.com"+api_key&type=code
# https://github.com/search?q="@target.com"+password&type=code

# Automated with gh CLI
gh search code "target.com password" --limit 50
gh search code "target.com api_key" --limit 50
gh search code "target.com secret" --limit 50

# GitLeaks on a cloned repo
gitleaks detect --source /path/to/cloned/repo --report-format json --report-path leaks.json

# Trufflehog — search git history for secrets
trufflehog git https://github.com/ORG/REPO --only-verified

# Common things to find:
# - Hardcoded credentials in config files
# - AWS keys, API tokens
# - Database connection strings
# - Internal domain names / IP addresses
# - SSH private keys
# - JWT signing secrets
```

---

## Shodan / Censys

```bash
# Shodan CLI (requires API key)
shodan host TARGET_IP                           # full host report
shodan search "hostname:target.com"             # all known services
shodan search "ssl.cert.subject.CN:target.com"  # by cert CN

# Useful Shodan filters
# org:"Target Company Name"
# ssl:"target.com" port:443
# http.title:"Admin" net:TARGET_IP_RANGE/24
# "Set-Cookie: PHPSESSID" hostname:target.com

# Censys (browser) — censys.io/search
# services.tls.certificates.leaf_data.subject.common_name: target.com
# services.http.response.html_title: "Admin"

# FOFA (Chinese Shodan alternative — covers Asian infra better)
# domain="target.com"
# cert="target.com"
# body="target branding string"

# Extract IP ranges from Shodan to find additional hosts
shodan search --fields ip_str,port,hostnames "org:\"Target Org\"" | sort -u
```

---

## Leaked Credentials & Data Breach Search

```bash
# Dehashed API (requires subscription)
curl -sk "https://api.dehashed.com/search?query=domain:target.com" \
  -H "Accept: application/json" \
  -u "EMAIL:API_KEY" | python3 -m json.tool | grep -i 'password\|hash\|email'

# HaveIBeenPwned API
curl -sk "https://haveibeenpwned.com/api/v3/breachedaccount/TARGET@target.com" \
  -H "hibp-api-key: API_KEY"

# Browser alternatives:
# https://dehashed.com        — email/password combos
# https://intelx.io           — pastebins, darkweb, breaches
# https://leakcheck.io        — email/domain breach lookup
# https://pwndb2am4tzkvold.onion — Tor-accessible breach DB

# Credential stuffing prep — filter leaked creds for target domain
grep "@target.com" leaked_combo.txt | cut -d: -f2 | sort -u > leaked_passwords.txt
```

---

## DNS / Infrastructure Deep Dive

```bash
# Zone transfer attempt (rarely works, always try)
dig AXFR target.com @$(dig +short NS target.com | head -1)

# All record types
for TYPE in A AAAA MX TXT NS SOA CAA CNAME SRV; do
  echo "=== $TYPE ===" && dig +short $TYPE target.com
done

# Reverse DNS on IP range (find other vhosts on shared IP)
for i in $(seq 1 254); do
  HOST=$(dig +short -x "TARGET_IP_PREFIX.$i" 2>/dev/null)
  [ -n "$HOST" ] && echo "TARGET_IP_PREFIX.$i → $HOST"
done

# ASN enumeration — find all IPs owned by the org
whois -h whois.radb.net -- "-i origin AS12345" | grep -oP '\d+\.\d+\.\d+\.\d+/\d+'

# Virtual host discovery on shared IP
ffuf -u "http://TARGET_IP/" -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs BASELINE_SIZE -t 40

# SPF/DMARC misconfig → email spoofing
dig +short TXT target.com | grep spf
dig +short TXT _dmarc.target.com
# No SPF = can spoof from any address
# DMARC p=none = no enforcement even with DMARC
# DMARC p=reject + SPF strict = strong, move on
```

---

## Wayback / Archive Deep Dive

```bash
# Find old endpoints no longer in robots.txt or sitemap
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey&limit=10000" \
  | grep -v '\.(png|jpg|gif|css|ico)$' \
  | sort -u > wayback_urls.txt

# Find old JS files (may contain deprecated endpoints/keys)
grep '\.js$' wayback_urls.txt | sort -u > old_js.txt

# Find old login/admin paths
grep -iE 'admin|login|manage|portal|api' wayback_urls.txt | sort -u

# Find old file types
grep -iE '\.(php|asp|aspx|jsp|bak|sql|zip|tar|gz|env|config)$' wayback_urls.txt

# Download and diff old JS vs current JS (find removed endpoints)
for JS_URL in $(head -5 old_js.txt); do
  wget -q "$JS_URL" -O /tmp/old_$(basename $JS_URL) 2>/dev/null
done
```
