#!/usr/bin/env python3
"""
No-lockout verification — sends N login attempts and reports
whether the server starts returning lockout/block responses.

Usage: python3 no-lockout-check.py
Configure TARGET, HOST, POST_DATA, ATTEMPTS below.
"""

import urllib.request
import urllib.error
import urllib.parse
import re
import time

# ── Configure these for each engagement ──────────────────────────────────────
TARGET    = "http://TARGET_IP/login"      # login endpoint URL
HOST      = "target.com"                  # Host header value
USERNAME  = "admin"                       # username to test
ATTEMPTS  = 50
CHECK_EVERY = 10

# POST body — adapt field names to the target application
def make_post(i):
    return urllib.parse.urlencode({
        "username": USERNAME,
        "password": f"wrongpassword{i}",
    }).encode()

HEADERS = {
    "Host": HOST,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0",
}

# Word-boundary matching — plain substrings false-positive ("ban" in "banner")
LOCKOUT_RE = re.compile(
    r"\b(" + "|".join(re.escape(w) for w in [
        "lock", "locked", "block", "blocked", "ban", "banned", "captcha",
        "too many", "rate limit", "temporarily", "suspended", "try again later",
    ]) + r")\b",
    re.I,
)
# ─────────────────────────────────────────────────────────────────────────────

print(f"[*] Testing lockout: {ATTEMPTS} attempts → {TARGET}")
print(f"[*] Username: {USERNAME}")
print()

locked = False
successes = 0          # consecutive successful requests (baseline connectivity)

for i in range(1, ATTEMPTS + 1):
    try:
        req = urllib.request.Request(TARGET, data=make_post(i), headers=HEADERS)
        start = time.time()
        r = urllib.request.urlopen(req, timeout=15)
        body = r.read().decode(errors="replace")
        elapsed = time.time() - start
        successes += 1

        # Check EVERY response for lockout keywords; print throttled
        hit = LOCKOUT_RE.search(body)
        if hit:
            locked = True
        if hit or i % CHECK_EVERY == 0:
            print(f"Attempt {i:3d}: locked={bool(hit)} ({hit.group(0) if hit else '-'}) | {elapsed:.3f}s | {body[:80]}")

    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        hit = LOCKOUT_RE.search(body)
        if e.code in (403, 429) or hit:
            locked = True
            print(f"Attempt {i:3d}: LOCKOUT SIGNAL — HTTP {e.code} | {body[:80]}")
            break
        if i % CHECK_EVERY == 0:
            print(f"Attempt {i:3d}: HTTP {e.code} | {body[:60]}")
    except Exception as e:
        # Connection failures after successful attempts = likely IP-level block
        if successes > 0:
            locked = True
            print(f"Attempt {i:3d}: LOCKOUT SIGNAL — connection failed after {successes} successes ({e})")
            break
        print(f"Attempt {i:3d}: ERROR — {e}")

print()
if locked:
    print("[+] Lockout/throttling observed — lockout IS enforced.")
else:
    print("[!] No lockout signal in", ATTEMPTS, "attempts → account lockout is NOT enforced.")
