# Phishing Detonation Sandbox — Build Plan

**Working name:** PhishLab (rename freely)
**One-liner:** A standalone **desktop application** for a SOC analyst to safely detonate a suspected phishing URL — auto-decloak it, robotically step through the kit (fill *fake* credentials), screenshot every step (any.run-style), document what the kit captures and *where it exfiltrates* (form actions, Telegram bots), enrich it (WHOIS / hosting / URL reputation), and **auto-report it** to Google Safe Browsing, Microsoft, and Fortinet.

> **Use context:** Defensive SOC work on an **isolated external PC**. Everything uses *fake* data against phishing infrastructure the analyst is authorized to investigate. This is analysis + takedown, not attack.

---

## 1. Deployment model

- **Standalone desktop app** (Windows first) — one installer, no external services required.
- **Everything self-contained:** the UI, a local backend, the detonation browser, the database, and the anonymizing proxy all ship inside the app.
- **Runs on the SOC "external"/isolated PC** — segregated from the corporate network so live phishing pages are detonated safely.
- **Egress = the dedicated SOC detonation line (primary).** The external PC sits on its own **separate, purpose-built router** — a segregated, burnable internet connection that is *not* the corporate network. That IS the isolation + anonymity: detonation traffic leaves on a dedicated IP. If that line is consumer/residential-grade it also *helps* decloaking (it naturally looks like a real victim, so it passes IP gates — see §8).
- **No Tor / proxy pool needed for normal use.** The dedicated line does the job. The *only* place a second vantage point (Tor exit, or one cheap proxy) earns its keep: **an "is it actually down?" check** — hit the URL from a different IP/geo to tell "the site is dead for everyone" apart from "it's just cloaking/geo-blocking *us*." Purely optional, off by default.

---

## 2. Architecture (all in one app)

```
┌───────────────────────── Desktop app (one installer) ─────────────────────────┐
│  UI  (Tauri or Electron)  ── talks to →  Local backend (FastAPI, 127.0.0.1)     │
│   • URL input + live timeline           • Orchestrates a detonation "case"      │
│   • screenshots per step                • Detonation engine (Playwright Firefox)│
│   • verdict / IOCs / exfil              • Enrichment (WHOIS, CT, IP, reputation) │
│   • report + one-click report-out       • Reporting/takedown submitters         │
│                                         • SQLite (cases, steps, IOCs, artifacts)│
│                                                                                 │
│  Detonation browser (Firefox, headless) ── egress →  Tor (bundled) → internet   │
│                                                       └ optional proxy/VPN pool  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

- **Detonation engine** = Playwright/`invisible_playwright` **Firefox** (real browser fingerprint), driven step-by-step. This is the heart.
- **Isolation:** every detonation gets a fresh, disposable browser profile/context; no analyst data; downloads blocked; DNS resolved through Tor (no leaks).

---

## 3. Feature breakdown

**A. Detonation (the core)**
- Decloak: follow redirects/JS hops, record the chain, land on the real page.
- Robotic step-through (capped, e.g. ≤6 steps): detect login/credential forms → auto-fill **fake** email + password (+ fake card fields if a payment form) → submit → follow to the next page → repeat.
- Screenshot **every** step (load, form-detected, filled, submitted, next page) → an **any.run-style timeline**.
- **Live analyst narration:** a running log ("Loaded X", "Login form detected", "Filled fake creds", "Submitted → POSTs to Y", "2FA page detected"…).

**B. What's captured + where it goes (exfil intelligence)**
- Detect **what data the kit harvests** (which fields: username, password, OTP, card number/CVV).
- Detect **where it goes:** form `action` host, POST/fetch/XHR destinations, webhook/API endpoints.
- **Telegram bot extraction:** pull bot tokens (`123456789:AA…`) + `chat_id` from page source/JS — a very common exfil channel.
- Email-exfil / PHP-mailer endpoints, other C2 hints.

**C. Enrichment**
- **WHOIS / RDAP** — domain age (newly-registered = strong signal), registrar.
- **Certificate transparency** (crt.sh) — cert age, SANs, issuer.
- **Hosting/IP** — resolve → IP → ASN, geo, hosting provider, IP reputation (GreyNoise).
- **URL reputation ratings** — Fortinet URL rating, Google Safe Browsing lookup, VirusTotal (if key), URLhaus / OpenPhish / PhishTank blocklists.
- **Brand impersonation** — favicon hash vs a brand set, title/keyword/logo match.

**D. Verdict**
- Weighted risk score → *clean / suspicious / likely-phishing / confirmed-phishing* with the reasons that drove it.

**E. Reporting + takedown (auto)**
- One SOC case report (HTML/PDF): timeline + screenshots + IOCs + exfil channels + enrichment + verdict.
- **Auto-submit** the confirmed URL to takedown/blocklist channels: Google Safe Browsing, Microsoft (SmartScreen), Fortinet; optionally Netcraft, APWG, PhishTank.

**G. Takedown tracker (continuous) — its own tab**
- Every URL reported as fake/phishing is added to a **Tracker tab** — one row per site.
- A background scheduler **pings each tracked site continuously (~every 30 min)** and records up/down + latency + status code + a lightweight content check (so a "parked/suspended" replacement page also counts as down).
- Status shown live: **UP** (still live — keep chasing takedown) vs **DOWN** (unreachable / suspended-page → likely taken down) with *first-reported*, *last-seen-up*, *went-down-at*, and total uptime-since-report.
- Alerts/notification when a tracked site flips UP→DOWN (takedown success) — and optionally DOWN→UP (it came back / new host).
- Feeds the SOC report ("reported 2026-07-01, taken down 2026-07-03, alive 2 days").

**H. Phishing-kit extraction**
- After detonation, try to retrieve the KIT ITSELF: the deployed archive left in the web root (kits
  are often just an unzipped `.zip` still sitting there), open-directory listings, and exposed
  source/backup copies (`.bak`, `~`, `.txt`, `.save`, `.old` of the PHP).
- Statically analyze the recovered kit: exfil channels (Telegram tokens, hardcoded e-mail / PHP-mailer
  config, C2 URLs), targeted brands, the kit's own anti-bot/cloaking **blocklist** (which scanner
  IP/UA ranges it refuses), and actor/kit-family **fingerprints** (author strings, comments, kit name).
- Yields deep IOCs + attribution + kit-family tracking; feeds the report and the takedown case.

**I. Live interactive handover (analyst takeover, in-app)**
- A detonation runs as a **live session**: the browser streams to the GUI over a WebSocket (a live
  pane next to the step screenshots) — the analyst watches it happen.
- When an anti-bot gate is detected (Cloudflare/Turnstile/CAPTCHA the sandbox can't clear), automation
  **pauses** and the live pane goes **interactive**: clicks/keystrokes are forwarded to the browser so
  the analyst solves the gate **inside the app** — no stepping out, no separate window.
- **Resume** → the robotic step-through continues from the now-unlocked page. This is what makes
  Cloudflare/CAPTCHA handleable end-to-end (solve-by-human instead of a solver service).

**F. Security / anonymity (cross-cutting)**
- Egress on the dedicated detonation line (see §1); optional proxy/Tor as a second vantage point.
- Disposable profiles, no real data, DNS-leak prevention, network kill-switch, air-gap-friendly.

---

## 4. Phases + timeline

*Estimates assume one focused developer. Ship each phase as a working increment.*

| Phase | Scope | Deliverable | Est. |
|------|-------|-------------|------|
| **0 — Shell** | Desktop scaffold (Tauri/Electron) + bundled local FastAPI + SQLite + bundled Playwright Firefox. URL-in → result-out plumbing. | Installable empty app that can open a page + screenshot it. | 3–5 days |
| **1 — Detonation core (MVP)** | Decloak + robotic step-through (detect form → fake creds → submit → follow) + screenshot-every-step timeline + live narration + capture form fields/actions. | Paste a URL → watch it detonate step-by-step with screenshots. | 1–1.5 wks |
| **2 — Exfil + IOC** | Telegram token/chat-id extraction, exfil-destination detection, IOC aggregation, brand/favicon impersonation. | "Creds captured by this Telegram bot / this host" + IOC list. | 4–6 days |
| **2b — Phishing-kit extraction** | Retrieve the kit (left-behind archive / open directory / exposed source-backups) and statically analyze it for exfil channels, targeted brands, the anti-bot blocklist, and actor/kit-family fingerprints. | The actual kit source + deep IOCs + attribution. | ~1 wk |
| **3 — Enrichment** | WHOIS/RDAP, cert transparency, IP/ASN/GreyNoise, Fortinet/Safe-Browsing/VT/blocklist lookups, risk-score + verdict model. | A scored verdict with full context. | ~1 wk |
| **4 — Anonymity + hardening** | Egress on the dedicated line; optional proxy/vantage; disposable profiles, DNS-leak/kill-switch. | Leak-proof, dedicated-line egress. | 4–6 days |
| **4b — Live interactive handover** | Turn detonation into a live session: stream the browser to the GUI (WebSocket) + forward clicks/keys + pause/resume, so the analyst solves a Cloudflare/Turnstile gate **in-app** and automation resumes. No stepping out. | Watch + take over a detonation live. | 1–1.5 wks |
| **5 — Reporting + takedown** | SOC report (HTML/PDF) + auto-submit to Safe Browsing / Microsoft / Fortinet (+ optional Netcraft/APWG/PhishTank). | One-click "report + takedown". | ~1 wk |
| **5b — Takedown tracker** | Tracker tab: every reported site tracked; background pinger (~30 min) records up/down + latency + suspended-page check; UP→DOWN alerts; uptime-since-report. (Reuses the Shadow-style monitoring scheduler.) | Live board of every reported site + "taken down" status. | 4–6 days |
| **6 — Polish + packaging** | Case history/search, config (keys, proxy/vantage toggle, report toggles), signed Windows installer. | Distributable v1. | 3–5 days |

**Total: ~8–10 weeks to a solid v1** (with kit-extraction + live handover). A demoable MVP (Phases 0–2) ≈ 3 weeks; **Phase 1 detonation core is already built + working.**

---

## 5. Recommended tech stack

- **Shell:** Tauri (lighter, Rust, secure) *or* Electron (familiar, JS ecosystem). Electron is simpler if bundling a Python sidecar.
- **Backend:** Python **FastAPI** (reuses existing engine code) packaged with PyInstaller, run as a localhost sidecar.
- **Detonation browser:** Playwright **Firefox** / `invisible_playwright` (real fingerprint), headless.
- **Anonymity:** bundled **Tor** (SOCKS5), circuit rotation via the control port; optional proxy pool.
- **DB:** SQLite (cases, steps, IOCs) + a files dir for screenshots/artifacts.
- **Reporting:** headless-browser form automation for portals without APIs; APIs where they exist.

---

## 6. Feasibility notes (honest)

- **Detonation, screenshots, form-fill, Telegram/IOC extraction, WHOIS/CT/IP enrichment, Tor egress** — all straightforwardly doable with mature libraries.
- **Auto-reporting is the fiddly part:** Google Safe Browsing has a lookup *API* (key) but *reporting* is largely a web form; Microsoft SmartScreen and Fortinet URL submissions are web forms too. So "auto-report" = **headless-browser form automation** (+ any real APIs), and some portals may throw CAPTCHAs → build per-portal submitters with graceful fallback to "prepared, one-click manual submit."
- **URL reputation (Fortinet/others):** public checkers exist but are rate-limited; cache + throttle.
- **Tor:** some kits block Tor exit nodes → that's when the proxy/VPN fallback kicks in.
- **Installer size:** bundling Firefox + Python + Tor ≈ 250–450 MB. Acceptable for a dedicated SOC tool.

---

## 7. Head start (reusable from the existing Shadow codebase)

Already built + proven — port these into the new app instead of writing from scratch:
- **Firefox detonation browser** — `invisible_playwright` launch + navigate + screenshot + redirect-chain/decloak (from the URL-unmask module).
- **WHOIS, crt.sh cert transparency, GreyNoise IP reputation, DNS** — existing collectors.
- **IOC handling / defang / masking** — existing `masking` util.
- **SSRF-safe fetch + validate-and-pin patterns** — for the *enrichment* calls (the detonation itself intentionally visits the untrusted host, sandboxed).
- **Favicon/image hashing** — existing `image_hash`.

---

---

## 8. How decloaking + cloaking detection actually work

**Cloaking** = the kit serves *different content depending on who asks*: a benign **decoy** (blank/404/redirect-to-the-real-brand) to anything that looks like a scanner, and the real credential page only to a convincing **victim**. So neither decloaking nor detection can work from a single visit.

**Detection = differential across identities.** Fetch the *same* URL as ≥2 identities and diff the responses:

| Axis | "Scanner" identity | "Victim" identity |
|---|---|---|
| User-Agent | bot / curl / Googlebot | real Firefox |
| JavaScript | off | on (full render) |
| IP / ASN | datacenter | residential |
| Referrer | none / direct | the expected one (email provider) |
| Fingerprint | bare | real viewport / locale / timezone + dwell |

Diff these features → **cloaked** if they diverge:
- **final URL** (bot → google.com, victim → off-brand login),
- **HTTP status** (404/403/blank vs 200),
- **title + text similarity**, **DOM** (does one view have `<input type=password>` and the other not?),
- **screenshot perceptual hash** (visually different pages).

**Malicious cloaking specifically** (vs harmless A/B): scanner gets a benign/legit-brand page while the victim gets a **credential form on a domain that ≠ the brand it imitates**, reached only after a gate the scanner failed.

**Decloaking = *be* the convincing victim** so the kit reveals the real page, then follow it in:
1. **Real browser fingerprint** — `invisible_playwright` (real Firefox) so TLS/JA3 + HTTP/2 are genuinely Firefox's, `navigator.webdriver` clean, real viewport/locale/timezone + human dwell.
2. **Run JS + follow every hop** — 30x, `<meta refresh>`, `window.location`, timed redirects — cloaking gates usually decide in JS.
3. **Victim-like network** — residential IP + right geo + expected referrer (this is the residential-proxy-first point from §1).

**Pre-trigger heuristics** (spot cloaking without fully passing the gate): read the page JS for bot-detection logic (`navigator.webdriver`, `isBot()`, screen/timezone/WebGL checks, `if(bot) location=…`); IP-gate probing (datacenter bounced, residential in); known cloaking-service gate fingerprints; header/cookie deltas.

**Honest limit:** if even the victim probe is blocked (residential-only/geo-locked gate, CAPTCHA/Turnstile, single-use link), both views look the same and you'd get a **false "not cloaked."** The sandbox must flag *"couldn't reach victim content — likely an unpassed gate"* rather than call it clean.

> Shadow's URL-unmask module is already the working core of §8 (scanner-view vs victim-view capture, redirect-chain tracking, `verdict=cloaked`). PhishLab reuses it, then *detonates* the victim-view page.

---

*Next concrete step if you want to start now: Phase 0 (desktop shell + bundled backend + browser), then Phase 1 detonation MVP.*
