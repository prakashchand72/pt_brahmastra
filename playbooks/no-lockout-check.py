#!/usr/bin/env python3
"""
No-lockout verification — sends N login attempts and reports
whether the server starts returning lockout/block responses.

Usage: python3 no-lockout-check.py
Configure TARGET, HOST, POST_DATA, ATTEMPTS below.
"""

import urllib.request
import urllib.parse
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

LOCKOUT_KEYWORDS = [
    "lock", "block", "ban", "captcha", "too many",
    "rate limit", "temporarily", "suspended", "try again later"
]
# ─────────────────────────────────────────────────────────────────────────────

print(f"[*] Testing lockout: {ATTEMPTS} attempts → {TARGET}")
print(f"[*] Username: {USERNAME}")
print()

for i in range(1, ATTEMPTS + 1):
    try:
        req = urllib.request.Request(TARGET, data=make_post(i), headers=HEADERS)
        start = time.time()
        r = urllib.request.urlopen(req, timeout=15)
        body = r.read().decode(errors="replace")
        elapsed = time.time() - start

        if i % CHECK_EVERY == 0:
            locked = any(w in body.lower() for w in LOCKOUT_KEYWORDS)
            print(f"Attempt {i:3d}: locked={locked} | {elapsed:.3f}s | {body[:80]}")

    except urllib.error.HTTPError as e:
        print(f"Attempt {i:3d}: HTTP {e.code}")
    except Exception as e:
        print(f"Attempt {i:3d}: ERROR — {e}")

print()
print("[*] Done.")
print("[*] If no 'locked=True' appeared → account lockout is NOT enforced.")
