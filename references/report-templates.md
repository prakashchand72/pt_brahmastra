# Report Templates

## Full Report Header

```markdown
# Penetration Test Report — Verified
## Target: [hostname] — [Brand] ([Organization])

| Field | Value |
|---|---|
| **Target** | `hostname` |
| **IP** | `x.x.x.x` (ISP, City, ASN ASXXXX) |
| **Hosting** | Shared/Dedicated — Apache/Nginx, PHP/Node |
| **CMS** | Name + Version (release date) |
| **Test date** | YYYY-MM-DD |
| **Method** | Black-box, authorized, active + dynamic verification |
| **IP bypass** | All tests run via direct IP + `Host: hostname` header |

---

## Verification Status Summary

Every finding below was actively tested. Status reflects live results.

| ID | Title | Severity | Status |
|---|---|---|---|
| F-01 | [title] | Critical/High/Medium/Low/Info | ✅/❌/⚠️ |

> **FALSE POSITIVES removed:** [list with reason]
> **CONDITIONAL:** [list with condition]
```

---

## Per-Finding Template

```markdown
## F-XX — [Finding Title]

| | |
|---|---|
| **Severity** | Critical / High / Medium / Low / Info |
| **Affected** | `http://target/path` |
| **Status** | ✅ TRUE POSITIVE — actively verified |

### Description

[2-3 sentences explaining what the vulnerability is and why it exists.]

### Proof of Concept

```bash
# Step 1: [action]
curl -sk "http://IP/path" -H "Host: HOSTNAME" \
  [flags] \
  -w "\nHTTP: %{http_code}"
# → [expected response]

# Step 2 (if needed): [action]
[command]
# → [expected response]
```

### Impact

1. [Primary impact — who is affected and how]
2. [Secondary impact — chaining opportunities]
3. [Regulatory / compliance implication if relevant]

### Remediation

- [Specific actionable fix, not "improve security"]
- [Configuration change with exact setting]
- [Framework/library version to upgrade to]
```

---

## Attack Chain Template

```markdown
### Chain [Letter] — [Chain Name]

```
F-XX  [finding title]          [action verb]
      ↓
F-YY  [finding title]          [action verb]
      ↓
Result: [outcome — RCE / credential theft / data exposure / bypass]
```
```

---

## Severity Guidelines

| Severity | Score (CVSS) | Criteria | Example |
|---|---|---|---|
| Critical | 9.0–10.0 | Unauthenticated RCE, full DB dump, all user PII | SQLi returning all passwords |
| High | 7.0–8.9 | Auth bypass, authenticated RCE, significant data exposure | No lockout → brute-force → admin |
| Medium | 4.0–6.9 | User interaction required, partial data exposure, chaining required | Open redirect (JS), XSS stored |
| Low | 1.0–3.9 | Defense-in-depth, info only, hard to exploit | Missing security headers, version disclosure |
| Info | 0.1–0.9 | Best practice, no direct risk | Server banner, outdated minor version |

---

## Negative Results Table

```markdown
## Level 3 Dynamic Testing — Summary of Negative Results

| Attack | Method | Result |
|---|---|---|
| SQL Injection | SQLmap all techniques + manual SLEEP() × N fields | ❌ Not vulnerable |
| Stored/Reflected XSS | dalfox automated + manual | ❌ Not vulnerable |
| Credential brute-force | top-5000 rockyou + N-entry target wordlist | ❌ No valid credentials |
| Timing attack | 5 samples/username, bcrypt constant-time | ❌ Not viable |
| CORS misconfiguration | Origin: evil.com injection | ❌ Not misconfigured |
| HTTP Request Smuggling | CL-TE probe | ❌ Not confirmed |
| SSRF | X-Forwarded-Host injection | ❌ Rejected |
| Username enumeration | Valid vs invalid — same response | ❌ FALSE POSITIVE |
| Account lockout | 50 rapid attempts | ❌ NO LOCKOUT (confirms F-XX) |
| Nuclei CVE scan | tags: cve,rce,sqli,xss,ssrf,exposure,misconfig | 0 findings |
```
