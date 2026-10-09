# Flow-Based Testing — User Journeys, Not Endpoints

The single biggest gap between scanner-style testing and what actually wins
bounties. Scanners test endpoints in isolation; real bugs live in **sequences of
actions with state**. This phase drives the app like a user (playwright MCP),
attacking each *transition*, not just each URL.

**When:** Phase 5, after endpoint-level testing. One journey map per major role.

---

## 1. Map the journeys first

For each role (anon / user / premium / admin), write the 5–10 flows that move
money or data:

```
AUTH:     register → verify email → login → MFA → reset password → change email → logout
PROFILE:  create → edit → upload avatar → delete account
COMMERCE: browse → cart → apply coupon → checkout → pay → refund → invoice download
CONTENT:  create → save draft → publish → share → revoke share
ADMIN:    invite user → change role → export data → audit log
```

Store in `pentest/flows.md`. Every flow = a chain of requests with state carried
forward (IDs, tokens, totals). That state is the attack surface.

## 2. Attack every transition, not every endpoint

For each step N → N+1 in every flow, test:

| # | Transition attack | How |
|---|---|---|
| 1 | **Skip the step** | Jump straight to N+1's request without N (replay the captured N+1 request on a fresh session) |
| 2 | **Reorder** | N+1 before N; repeat step N twice; go back after completion and re-execute |
| 3 | **Tamper the carried state** | Modify IDs/totals/prices in the request that N+1 inherits from N |
| 4 | **Race the transition** | `playbooks/race-condition.py` on checkout/transfer/redeem/vote steps — 20 parallel at the exact commit step |
| 5 | **Cross-role replay** | Capture admin flow requests, replay each with a user token — per-step, not per-page |
| 6 | **Abandon mid-flow** | Start flow, never finish → check half-created objects are invisible/unusable (draft invoices, unpaid orders marked paid) |
| 7 | **Parameter pollution in flow** | Add duplicate/extra params at each step (`role=admin`, `discount=100`, `user_id=<other>`) — flows often trust earlier validation |
| 8 | **Negative/absurd values** | quantity=-1, price=0.001, discount=150%, currency switches mid-checkout |

## 3. The high-yield flow patterns (check ALL of these)

These are the specific chains that pay:

1. **Checkout math:** capture the final payment request → tamper `amount`,
   `currency`, `quantity`, `item_id` (swap to cheaper item, keep expensive
   total), or apply coupon twice (race). Verify: order confirms at wrong price.
2. **Refund abuse:** refund more than paid, refund twice (race), refund an
   already-refunded order, refund then cancel → both succeed?
3. **Invite/role escalation:** invite self as user → tamper role in the accept
   request → admin. Or: accept invite after it was revoked.
4. **Email change / account recovery:** change email → old email still works?
   reset link for old email still valid after change? = pre-hijack persistence.
5. **2FA enrollment gap:** enable 2FA → is the step between "password OK" and
   "2FA pending" replayable/skippable → session granted before OTP.
6. **Password reset chain:** request reset for victim → does the link leak via
   `Host` header / `Referer` to third-party resources on the reset page /
   BCC-style API? Token entropy + single-use + expiry (see D5-B).
7. **OAuth linking:** link attacker's OAuth to victim via missing state/PKCE
   binding (see modern-checklist §3) → login as victim.
8. **Object lifecycle IDOR:** create as A → share to B → revoke → B still has
   access? Delete as A → B's copy still reachable? (stale authorization cache)
9. **Approval workflows:** submit → reject → resubmit identical → status flips?
   Withdraw → funds double-counted?
10. **Export/report flows:** export "my data" → tamper scope param → exports
    everyone's data. Async export → poll the job ID of another user's export.

## 4. Execution method (playwright MCP)

```text
1. Drive the flow once cleanly as each role, capturing every request
   (playwright network log → pentest/flows/<flow>-<role>.har).
2. Diff the HARs across roles: requests present in admin flow but absent in
   user flow = privileged transitions to replay cross-role (row 5 above).
3. For each transition table row: replay the raw request with curl so the PoC
   is a single paste-able command (per the SKILL.md PoC rule).
4. Every "interesting" behavior → Phase 6 verification → Phase 6b gate.
```

## 5. Rules

- **State is the bug.** If a request only makes sense in sequence, testing it
  alone proves nothing. Always test: without the sequence, in the wrong order,
  with the wrong role, twice at once.
- **Money flows first.** Anything touching payment, credits, votes, invites,
  or roles outranks everything else in this file.
- **Screenshot every step** of a successful chain — flow bugs die in triage
  without a visible story. The PoC is the *sequence*, not one request.
- **Idempotency keys:** if requests carry one, replay with the same key (should
  dedupe — does it?) and with it removed (should reject — does it?).
