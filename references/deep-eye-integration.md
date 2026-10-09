# Deep Eye — AI-Orchestrated Scan & Exploitation Engine

Deep Eye (github.com/zakirkun/deep-eye) is an AI-driven penetration-testing engine
that orchestrates multiple LLM providers for **context-aware payload generation**,
runs **50+ vulnerability checks**, and emits **compliance-mapped, deduped, diffable
reports**. It slots into Brahmastra as a **parallel scan/exploit engine** alongside
nuclei/nmap/sqlmap — it is not a replacement for them, and its report writer is **not**
the final deliverable (`office_report`/`vajra_report` own that).

> **Status:** not yet installed on this host. Install it the first time you use it.

## Install (Mac native — no Docker)

```bash
git clone https://github.com/zakirkun/deep-eye.git ~/tools/deep-eye
cd ~/tools/deep-eye
python3 -m venv .deep-venv && source .deep-venv/bin/activate
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
# edit config.yaml: enable at least one AI provider (or OLLAMA), set scope defaults
pip install playwright && playwright install chromium   # optional: browser tests / challenge solve
pip install curl_cffi                                     # optional: TLS evasion
# alias in ~/.zshrc:
#   alias deep-eye="$HOME/tools/deep-eye/.deep-venv/bin/python $HOME/tools/deep-eye/deep_eye.py"
```

First launch without a config runs the interactive wizard. `--setup` forces the wizard,
`--setup-force` overwrites an existing config without prompting.

**Where to run:** same policy as the rest of the skill — recon/scanning on the Mac,
exploit payloads on Kali (`shared_kali`) when possible. Deep Eye is a single CLI that
does both, so point `scanner.proxy` at the engagement's mitmproxy and keep the OAST
callback (`scanner.oast_callback_url`) set to a server you control (Burp Collaborator /
interact.sh) so blind XSS/XXE get out-of-band detection.

## AI Providers (multi-provider failover)

`ai_providers:` in config — any enabled provider can serve `generate()`; providers
fail over automatically. Supported: `openai`, `claude`, `grok`, `gemini`, `ollama`,
`openrouter`, `orcarouter`, `requesty`, `mistral`, `groq`, `lmstudio`, `litellm`,
`nvidia_nim`.

- Offline/no-key option: `ollama` with `base_url: http://localhost:11434`.
- Set the active provider via `scanner.ai_provider` (also the default for `-u` scans).
- Without any AI key the scanner still runs — payload generation falls back to
  static/custom wordlists (`payload_generation.use_ai: false`).

## CLI Reference

```bash
deep-eye -u https://target.com                          # basic scan
deep-eye -c config/config.yaml                          # config-driven
deep-eye -u https://target.com -v                       # verbose
deep-eye -u https://target.com --formats junit,csv,xlsx  # multi-format export
deep-eye -u https://target.com --scope-nl "only /api/* no /logout host target.com"
deep-eye --diff baseline.json current.json --diff-format html --diff-output diff.html
deep-eye -u https://target.com --retest-new baseline.json   # only findings new vs baseline
deep-eye --setup --setup-force                          # config wizard
```

| Flag | Purpose |
|---|---|
| `-u, --url` | Target URL (overrides config) |
| `-c, --config` | Config path (default `config/config.yaml`) |
| `-v` | Verbose |
| `--version`, `--no-banner` | Meta |
| `--formats` | `html,pdf,json,sarif,junit,csv,xlsx` |
| `--diff` / `--diff-output` / `--diff-format` | Diff two scan JSONs (`html/json/csv`) |
| `--retest-new` | Keep only findings absent from a baseline JSON |
| `--scope-nl` | Natural-language scope (allow/deny) |
| `--setup` / `--setup-force` | Config wizard |

## Phase Mapping (Brahmastra kill-chain ↔ Deep Eye)

| Brahmastra phase | Deep Eye surface |
|---|---|
| 1 — Authz gate | `--scope-nl` + `scope.*` config enforce scope before any request |
| 2 — Passive recon | `scanner.enable_recon`, `reconnaissance.enabled_modules` (subdomain, DNS, WHOIS, tech, SSL, port, dir-brute, email, OSINT dorking/metadata/breach/CT/github/pastebin), `experimental.enable_subdomain_scanning`, `openapi.enabled` (Swagger → URL seed) |
| 2b — Tech fingerprint | `waf_fingerprint` (WAF ID + payload profile), `reconnaissance.technology_detection`, tech stack feeds context-aware payload gen |
| 3 — Prioritization | `ai_planner` (post-recon check order + budget: `budget_seconds`, `max_urls`, `threads`) |
| 4 — Active scan | `vulnerability_scanner.enabled_checks` (50+ checks), `secrets_scanner`, `port_scanner`, `directory_bruteforce`, `subdomain_takeover`, `cache_poisoning`, `templates` (Nuclei-style YAML), browser automation |
| 4b — JS pipeline | `supply_chain_js` (SRI / outdated libs / 3rd-party JS), `secrets_scanner.scan_javascript_files` |
| 5 — Exploitation | Deep module set — see "Exploit-class modules" below |
| 6 — Verification | `ai_triage` + `fp_replay` (FP reduction/re-probe), `evidence_summary`, `ml_detection` anomaly baseline, OAST callbacks |
| 6b — Validation gate | `--diff` / `--retest-new` produce Patched/Unpatched matrices for `office_recheck` |
| 7 — Report | `bug_bounty` (HackerOne-style MD per finding), `compliance` (PCI-DSS v4 / SOC2 CC / ISO 27001:2022), exports (HTML/PDF/JSON/SARIF/JUnit/CSV/XLSX) → hand to `office_report`/`vajra_report` |

## Full Vulnerability Check Catalog (`enabled_checks`)

Enable the ones in scope; the config lists all keys. The "deep" modules are the ones
Brahmastra did not previously cover and should be turned on for bug-bounty depth.

**Classic web / injection:** `sql_injection`, `xss`, `stored_xss`, `command_injection`,
`ssrf`, `ssrf_cloud`, `xxe`, `path_traversal`, `lfi`, `rfi`, `csrf`, `open_redirect`,
`open_redirect_deep`, `ssti`, `ssti_engines`, `ldap_injection`, `xml_injection`,
`nosql_injection`, `insecure_deserialization`, `crlf_injection`,
`crlf_header_inject_deep`, `host_header_injection`, `host_header_deep`,
`http_smuggling`, `h2_smuggle`, `cache_poisoning`, `cache_deception`, `hpp_pollution`,
`http_method_override`, `log4shell`, `prototype_pollution`, `mass_assignment`,
`email_injection`, `php_webshell`.

**Auth & session:** `authentication`, `authentication_bypass`, `broken_authentication`,
`jwt_vulnerabilities`, `jwt_deep`, `oauth_testing`, `saml_attacks`, `idor`,
`api_bola_deep`.

**API & protocols:** `api_vulnerabilities`, `api_security` (OWASP API Top 10),
`graphql_vulnerabilities`, `graphql_deep`, `websocket`, `websocket_deep`,
`sse_injection`, `cors_misconfiguration`, `cors_csp`.

**Business logic & misc:** `business_logic` (price/workflow/quantity/coupon abuse),
`file_upload`, `race_condition`, `information_disclosure`,
`security_misconfiguration`, `sensitive_data_exposure`, `secret_scanning`,
`anomaly_detector`, `subdomain_takeover`, `directory_bruteforce`, `port_scanner`,
`waf_fingerprint`, `cloud_misconfig`, `supply_chain_js`.

**Mobile / Frida** (`mobile.enabled` + these keys): `frida_mobile`, `android_static`,
`ios_plist`, `mobile_ssl_pinning`, `mobile_ai_chain`.

## Exploit-class modules worth folding into Phase 5

These are the Deep Eye-native deep checks Brahmastra should adopt:

| Check | What it does |
|---|---|
| `jwt_deep` | alg=none, weak-secret brute, kid injection (`weak_secrets` list configurable) |
| `ssti_engines` | Multi-engine SSTI: Jinja2 / Twig / SpEL / FreeMarker / Velocity / ERB |
| `ssrf_cloud` | Cloud metadata endpoints + SSRF bypass corpus (also core SSRF) |
| `host_header_deep` | Host / X-Forwarded-Host poisoning, reset-path severity boost |
| `h2_smuggle` | h2c upgrade + CL/TE ambiguity |
| `cache_deception` | Path-normalization cache tricks (`.css`, `..;`, encoded delimiters) |
| `http_method_override` | Verb tampering via `X-HTTP-Method-Override` / `_method` |
| `hpp_pollution` | HTTP parameter pollution differential (server-specific parsing) |
| `api_bola_deep` | API BOLA/IDOR + mass-assignment probes |
| `websocket_deep` | CSWSH / origin / handshake injection |
| `sse_injection` | Server-Sent Events endpoint discovery + event reflection |
| `prototype_pollution` | JS `__proto__` / `constructor.prototype` pollution |
| `mass_assignment` | Extra-field privilege/role injection on JSON bodies |
| `php_webshell` | PHP LFI wrappers + webshell path probes |
| `cloud_misconfig` | Bucket listing + metadata SSRF hints |
| `supply_chain_js` | Third-party JS, SRI checks, outdated libs |

## AI pipeline (enable for bug-bounty depth)

```yaml
vulnerability_scanner:
  payload_generation: { use_ai: true, context_aware: true, cve_database: true, custom_wordlists: true }
ai_planner:       { enabled: true, budget_seconds: 600, max_urls: 50, threads: 5 }
ai_triage:        { enabled: true, drop_false_positives: true, drop_threshold: 0.8, min_severity: high }
evidence_summary: { enabled: true, min_severity: high, max_findings: 15 }
fp_replay:        { enabled: true }
bug_bounty:       { enabled: true, format: hackerone, min_severity: high, one_file_per_vuln: true }
rag:              { enabled: true, top_k: 5, min_score: 0.15 }      # CVE RAG (needs scripts/build_cve_rag_index.py)
compliance:       { enabled: true, frameworks: [pci_dss, soc2, iso_27001] }
```

- **Context-aware payloads:** WAF fingerprint + detected tech stack + CVE DB feed
  `AIPayloadGenerator.generate_payloads()` per parameter.
- **AI triage:** scores confidence, flags/drops false positives (threshold 0.8).
- **Evidence summary:** LLM-written one-liner per high/critical finding.
- **FP replay:** re-probes triaged FPs before dropping.
- **Bug bounty writer:** per-vuln HackerOne-style Markdown under `reports/bounty/`.
- **CVE intelligence:** local SQLite (`data/cve_intelligence.db`) + optional live NVD /
  GitHub POC lookup; `scripts/update_cve_database.py` + `scripts/build_cve_rag_index.py`.

## Auth, automation & anti-detection

- **`login_replay`** — authenticate via a JSON login macro before the scan
  (`config/login_macro.json`); re-auth interval, `abort_on_fail`.
- **`auth_session`** — multi-role cookie/header store (`data/auth_sessions.json`).
- **`captcha`** — detect reCAPTCHA / hCaptcha / Turnstile / Arkose; `skip_protected`
  skips vuln scan on captcha pages.
- **`challenge_solver`** — Cloudflare / Akamai challenge solve via Playwright.
- **`intercepting_proxy`** — route traffic through a local mitmweb instance.
- **`tls_evasion`** — curl_cffi impersonation (`chrome120`).
- **`payload_obfuscation`** — WAF-bypass encodings (base64, url, unicode, hex, case,
  comments, concat, null-byte, double-encoding, char-substitution).
- **`rate_limiting`** — requests-per-second / burst / error-delay throttling.

## Secrets scanner (`secrets_scanner`)

Scans response bodies, headers, JS files, and `.git` exposure; entropy detection for
unknown secrets. Pattern pack: AWS/GCP/Azure keys, GitHub/GitLab/Bitbucket tokens,
Slack/Discord/Telegram webhooks, Stripe/PayPal/Square, Twilio/SendGrid/Mailgun,
DB connection strings (MongoDB/Redis/Postgres/MySQL), JWT/OAuth/API keys, PEM/RSA
private keys, npm/Docker/Heroku/Cloudflare/DataDog tokens. Severity-mapped and
whitelist-suppressed (email + domain lists).

## Reporting — export, dedupe, diff, retest

- **Formats:** `html`, `pdf`, `json`, `sarif`, `junit`, `csv`, `xlsx`.
- **Dedupe:** `reporting.dedupe` fingerprint-collapses duplicate findings.
- **Diff:** `--diff baseline.json current.json` → HTML/JSON/CSV diff report.
- **Retest-new:** `--retest-new baseline.json` keeps only findings whose
  `(type, url, parameter)` identity is absent from the baseline — feeds `office_recheck`.
- **Compliance:** tags findings with PCI-DSS v4 / SOC2 CC / ISO 27001:2022 controls.

## Rules

- **Authorization first** — scope via `--scope-nl` + `scope.*` config; never scan
  out-of-scope hosts/ports/paths.
- **Deep Eye's report writer is raw output, not the deliverable.** Its JSON/HTML is a
  source for `office_report` → `vajra_report`. Use `bug_bounty` MD as finding drafts.
- **Result shape** is standard (`type, severity, url, parameter, payload, evidence,
  remediation, fingerprint, cve_references, ai_evidence_summary, false_positive`) —
  map to the Brahmastra finding schema, don't invent keys.
- **Never set `scanner.oast_callback_url` to a third party you don't control.**
- **Run heavy exploit payloads from Kali** (`shared_kali`) where possible; Mac for
  recon/scan.
