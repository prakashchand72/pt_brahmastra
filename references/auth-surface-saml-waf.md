# Auth-Surface Discovery, SAML Decode & Airlock Fingerprint (v2 additions)

Techniques added after the BCF (Banque Cantonale de Fribourg) engagement. These fill
gaps in the base kill-chain: a dedicated auth-surface sweep, SAML AuthnRequest decoding,
Ergon Airlock WAF fingerprinting, and SPA auth-flow endpoint enumeration.

## A. Auth-Surface Discovery (login / registration / admin)

Not covered as a distinct step before. Run after Phase 2 tech fingerprinting, before
Phase 4. Goal: enumerate every login, registration, onboarding and admin endpoint
across all live hosts — these are the highest-value attack surface for auth bugs.

Wordlist (`auth-paths.txt`):
```
/login /signin /sign-in /logon /auth /auth/login /authenticate /sso /sso/login
/account/login /user/login /users/login /users/sign_in /session /session/new
/oauth /oauth/authorize /oauth2/authorize /oidc /oidc/authorize
/realms/master /realms/master/protocol/openid-connect/auth /authorize
/login.html /login.aspx /login.php /portal /portal/login /secure/login /identity
/saml /saml/login /samlsso /adfs/ls /cas/login /shibboleth
/register /signup /sign-up /create-account /account/register /user/register
/users/new /enrollment /enrol /enroll /onboarding /activate /join
/admin /admin/login /admin/register /administrator /wp-admin /wp-login.php
/manager /manager/html /console /backoffice /controlpanel /dashboard /staff
```

Generate host×path and probe fast with httpx:
```bash
while read h; do while read p; do echo "https://$h$p"; done < auth-paths.txt; done \
  < live_hosts.txt > auth_surface_urls.txt
httpx -l auth_surface_urls.txt -status-code -title -location -t 80 -o auth_surface_results.txt
```

Triage rules:
- **SPA/marketing catch-all** (every path → 200 with the same title) = NOT real
  endpoints. Don't chase.
- **Genuine hits** = distinct status/body: `403` admin, `302/303` to a login URL,
  `200` with a login form/SPA title.
- Record real login/register/admin endpoints (host, path, status, redirect target).

## B. SAML AuthnRequest/Response Decode (HTTP-Redirect binding)

When an SP 302-redirects to an IdP (`.../adfs/ls/?SAMLRequest=...&RelayState=...`),
decode the `SAMLRequest` to read SP metadata (ACS URL, Issuer, Destination, library).

Encoding = **URL-encode( base64url( raw-DEFLATE(xml) ) )** (zlib `wbits=-15`).

```bash
# automated (script in pt_brahmastra/playbooks/saml_decode.py):
curl -sk "https://SP/login" -D - -o /dev/null | python3 saml_decode.py --from-location-header
# manual:
echo '<SAMLRequest>' | base64 -d | python3 -c "import sys,zlib;print(zlib.decompress(sys.stdin.buffer.read(),-15).decode())"
```

What to extract and report: `AssertionConsumerServiceURL` (often leaks an INTERNAL
hostname for reverse-proxied SPs), `Issuer` (SP entity ID), `Destination` (IdP),
`ID` prefix (`ONELOGIN_` = OneLogin php-saml), `ProviderName`. Then check whether the
disclosed hostnames are NXDOMAIN publicly (= split-horizon DNS → internal-only leak).

## C. Ergon Airlock WAF — fingerprint & block-vs-maintenance

Fingerprints:
- Cookies: `AL_SESS-S`, `AL_SESS` (session), `CSRFT<tenant>-S` (CSRF, e.g. `CSRFT759-S`).
- CSRF header injected by `/CSRFT<tenant>.js`: `X-CSRFT<tenant>`.
- Error pages: `/error_path/{400,404,503}.html?al_req_id=<id>` (Airlock request ID).
- Static assets under `/authen/images/airlock/`, `/authen/js/airlock/`.

Distinguish response classes (critical for not wasting time):
| Response | Meaning |
|---|---|
| `200` / `301` / `302` / `303` | normal / backend redirect |
| `303` → `/error_path/400.html?al_req_id=` | Airlock 400 (no backend route / blocked request) |
| `303` → `/error_path/503.html?al_req_id=` | Airlock 503 (backend down OR WAF block) |
| Branded `503` "Maintenance" HTML page | REAL app maintenance (backend returns it even via origin IP) |
| `403` on a host that was `200` earlier | **You got IP-banned by that app/WAF** — cool down |

IP-burn pattern: after a large sweep (~4–5k req), Airlock/fidentity start serving
maintenance/403 to your IP while still serving `200` to clean IPs. Confirm by hitting
an unrelated always-up host (e.g. `www.bcf.ch`) — if it's still `200`, the app-specific
block is real. Slow down (<1 rps), use a browser UA, honor 429/503, spread over time.

## D. SPA Auth-Flow Enumeration (React/Vue signin)

Modern SSO is often a SPA (React/Vue) over NetIQ/Keycloak/etc. Extract the auth API
from the JS bundle to map the login state machine:

1. `curl -sk <signin-page> | grep -oE 'src="[^"]+\.js"'` → download each bundle.
2. Grep for endpoint strings: `grep -oE '"/[a-z-]+"' app.js | sort -u` and the
   `.concat(base, "/endpoint")` maps.
3. Poll the unauthenticated state endpoint (`/state`, `/start`, `/authn/signin/state`)
   to dump the flow config (`view`, `progressPercent`, `expressAuthEnabled`, self-service flags).
4. Look for step-skip endpoints: `promote`/`demote` (NetIQ AM migration), `express-auth`,
   `resend-*` (MFA), `*-self-unblock-init` (self-service reset = account-takeover surface).

## Reference files to update

Add these to the base SKILL.md table:
| File | Load when |
|---|---|
| `references/auth-surface-saml-waf.md` (this file) | Phases 2–4 auth targets, SAML SPs, Airlock-protected targets |
