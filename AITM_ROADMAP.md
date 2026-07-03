# PhishLab AiTM / Reverse-Proxy Detection Roadmap

Derived from two ultracode reviews (2026-07-03): a dissection of the **PhishGuard** FYP (Amanveer Singh
Madas — AiTM detection pipeline) and a walker/kit audit of PhishLab, plus a head-to-head of every
overlapping capability. Ordered **best-first** (impact/defensibility), not fastest.

## The threat we're adding coverage for
AiTM toolkits (Evilginx2/3, Modlishka, Muraena, EvilProxy) **proxy the real login page** — the victim
sees genuine Microsoft/Okta content, real password + real MFA succeed, and the toolkit copies the
post-auth **session cookie** in transit. Content/visual/URL-blocklist checks are blind (the page *is*
legit). You must fingerprint **the proxy's behaviour**, not the page. PhishLab has zero of this today.

## PhishLab's edge over PhishGuard
PhishGuard only observes from outside (passive HTTP). **PhishLab detonates** — it drives a real
Camoufox/Playwright browser, so it can watch the **session-cookie relay live** (the AiTM mechanism
itself, not a fingerprint). That's the differentiator we build toward.

---

## Best-first build order

### ① AiTM evidence module — `backend/phishlab/aitm.py` (+ scored-Signal seam)   ← STARTED
The marquee capability. Self-contained, keyless, high-precision, no new browser machinery. Plugs into
`enrich.enrich()` (populates `enrichment.aitm`) and `enrich.score_signals()` (folds into `_verdict`).
- **Evilginx wildcard-DNS probe** — random subdomain resolves to the apex IP ⇒ Evilginx catch-all DNS
  (~0% FP; CDN-gated). Highest precision-per-line.
- **Toolkit response headers** — `X-Evilginx` leak (score 70, direct attribution); Muraena set.
- **Toolkit cookies** — `__el`/`_evilginx`/`__token` (Evilginx); `id`=UUID (Modlishka default);
  **`HttpOnly`-without-`Secure` on HTTPS** = definitive proxy Secure-flag strip (Modlishka).
- **Proxy-header leak** — `Via`/`X-Forwarded-*` in the *response* (CDN-allowlisted so Cloudflare ≠ AiTM).
- **Go-proxy tells** — missing `Server` header + `Cache-Control: no-cache,no-store` (Go net/http default;
  corroboration-weight only).
- **URL-structure heuristics** *(PhishLab has ZERO today — comparison flagged this)* — auth-FQDN-embed
  (`login.microsoftonline.com` stuffed inside the hostname), dev-tunnel hosts (ngrok/trycloudflare),
  raw-IP host, IDN/`xn--` homoglyph, Evilginx 8-char lure path + `__el` token.
- **`_infer_toolkit()`** — name Evilginx/Modlishka/Muraena from the signal pattern; add a `threat_type`
  axis (AiTM vs Phishing vs both).

### ② Live session-cookie relay detection  *(where PhishLab beats PhishGuard)*
Instrument the Playwright/Camoufox network layer (`page.on(request/response)`) for the whole detonation;
detect when a submitted credential triggers an outbound relay and a `Set-Cookie` session token flows
back through a lookalike domain in real time. This same runtime-capture is *also* the #1 walker fix
(authoritative exfil evidence — diff filled-vs-transmitted fields). **One spine, two payoffs.**

### ③ Behavioural transport probes
- **Phoca TLS-timing** — `median(TLS handshake)/min(TCP connect)`; a proxy scores 12–40× (two TLS
  sessions per request) vs 1–8× direct. Detects the extra hop itself. **CDN-suppression gate mandatory.**
- **Live served-cert intel** — `ssl.getpeercert()`: self-signed / CN-mismatch / free-CA (Let's Encrypt on
  a "Microsoft" page) / cert-age. *(Comparison: PhishLab's crt.sh is CT-history only — this is net-new.)*
- **Brand coherence** — claimed-brand (regex over captured HTML) vs ASN (`ip_info` already returns it) and
  vs cert issuer. A Microsoft-branded page on DigitalOcean's ASN scores high. Survives a pixel-perfect clone.

### ④ Reach (get past anti-bot to analyze) — from the walker audit + FYP notes #2/#3
- Camoufox `geoip=True` + `humanize=True` + `os='windows'` + `block_webrtc=True`; **persist one context
  per case**; **don't rotate IP/UA after `cf_clearance` mints** (invalidates it → re-challenge loop).
- Headful / `headless="virtual"` for a real-desktop identity; optional `curl_cffi` TLS pre-flight.
- Scanner-vs-victim decloak differential as the pre-walk oracle (honest "couldn't reach victim" verdict).

### ⑤ Depth — walker + kit + source
- Fetch + decode linked external JS (biggest static-coverage gain — kits hide exfil in bundled `.js`).
- Kit path-walk + open-dir parse + magic-byte archive validation (fixes the `_candidates[:30]` truncation
  bug that means the `.zip` is never probed).
- Unify `detonate()` and `session.run()` into one `_walk_step` (batch currently abandons gates at step 0).
- **Bug fixes found:** takeover viewport = `None` → drag/click offset; exfil misattribution to `forms[0]`.

---

## Head-to-head: borrow vs keep (verified by reading both codebases)

**Borrow from PhishGuard (we assumed "don't port" — wrong):**
- 🔥 **Reputation feeds (biggest miss, keyless, low-FP)** — Spamhaus **DBL** (domain) + **ZEN** (IP) via
  plain DNS; **phishunt.io + openphish** feeds (`_fetch_feed` pattern, TTL-cached); **Cloudflare Radar
  top-1M** as a dynamic allowlist augmenting the static ~70-entry `LEGIT_DOMAINS`. → `enrich.py`.
- **Live cert** — `_check_tls_cert` (self-signed/CN-mismatch/free-CA/cert-age). crt.sh ≠ served cert.

**Keep PhishLab's (assumption was right):**
- **RDAP** — ours scores age + has the longer timeout; only alias `eventAction=='created'`.
- **Tech/WhatWeb fingerprint** — PhishGuard has none.
- **Challenge/gate detection** (`detect_challenge`) — PhishGuard has none (its `_html_antibot` is the
  opposite direction: attacker-side cloaking). MERGE only: tighten `bot_cloak` with PhishGuard's
  `RE_WD_FORM` (webdriver-as-form-value) precision.
- **eval/atob obfuscation** — our 4 rules beat their 1; just ADD the `_0x`-hex-variable rule (obfuscator.io).

**Add (PhishGuard-only, PhishLab has nothing):** Google Safe Browsing v4, VirusTotal domain rep, AbuseIPDB
(keyed); **URL-structure heuristics** (→ folded into ①); Spamhaus DBL/ZEN (keyless — highest ROI).

**Skip (different threat model / already have):** PhishGuard's Flask/DB web layer; its Claude verdict layer
(defer — if added later, keep the deterministic score authoritative + load the `claude-api` skill for
current model IDs, don't hardcode the FYP's `claude-haiku-4-5`).

---

## Single highest-leverage first step
`aitm.py` with `wildcard_dns_probe` + the response-header/cookie toolkit analyzer, wired into `enrich.py`
and emitting scored signals. No new browser, no keys, no CDN gate for the DNS/header/cookie tells — the
most precise Evilginx/Modlishka fingerprints and the Signal seam every later probe plugs into.
