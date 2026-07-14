# PhishLab

**A self-hosted phishing-detonation sandbox and email-analysis workbench for SOC / blue-team use.**

Paste a suspected phishing URL — or upload the email/attachment that carried it — and PhishLab drives a
**real browser** through the kit in isolation: decloaking it, solving anti-bot walls, robotically walking
the multi-step flow with **fake** credentials, screenshotting every step (any.run-style), and documenting
what the kit captures and **where it exfiltrates**. It statically de-obfuscates packed HTML, decodes QR
"quishing" from PDFs and images, enriches the case (WHOIS / hosting / blocklists / TLS), maps the redirect
chain, recovers the phishing kit where exposed, and helps you report it for takedown — all on one box, where
**the sample itself is never uploaded to a third-party cloud**.

<p>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Windows" src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white">
  <img alt="Defensive security" src="https://img.shields.io/badge/scope-defensive%20security-2ea44f">
  <img alt="Self-hosted" src="https://img.shields.io/badge/data-stays%20on%20your%20box-8957e5">
</p>

> **Defensive use only**, on an **isolated machine**, with **fake data only**. It deliberately visits
> hostile URLs — never point it at anything you aren't authorised to analyse, and never on a box with
> access to production systems.

---

## Why it exists

Cloud sandboxes (any.run, VirusTotal, Hybrid Analysis) are excellent — but every one of them requires you
to **upload the sample**. For a bank SOC, a healthcare provider, or anyone under data-handling constraints,
shipping a live phish (which may carry recipient PII, internal references, or the victim's own address) to a
third party is often a **compliance non-starter**, and it costs per-analysis at scale. Analysts still need
to *see what the kit does*, extract IOCs, and file a takedown — safely, and quickly.

PhishLab is that capability, **self-hosted**: a single-box tool that detonates phishing, parses malicious
email, and automates the tedious parts (de-obfuscation, exfil extraction, evidence capture, takedown
reporting) without a cloud dependency. Samples never leave the machine.

---

## What it does

### Live-URL detonation
- **Real-browser detonation** with an in-app **live streamed view** — a screenshot of every step, exactly
  as the victim's browser renders it.
- **Beats Cloudflare** — the default engine (Chrome / SeleniumBase UC) solves the "Suspected Phishing"
  warning and the "Just a moment" / "Verify you are human" **Turnstile** with a *real OS-mouse click*, and
  powers through bad-TLS-cert and "dangerous site" interstitials to reach the real phish behind them.
- **Robotic multi-step walk** — distinguishes login vs. lead-capture forms, fills **fake** credentials,
  submits, and follows the flow. Handles Microsoft-style **email → password** two-step logins, "please wait
  N seconds" timer gates, and re-prompting harvesters. Records every form action.
- **Exfil extraction** — surfaces the **Telegram Bot-API** channel (bot id + chat id) a kit exfiltrates to,
  and off-site credential POSTs.
- **Decloaking** — compares scanner-view vs. victim-view and **multi-vantage** (direct / Tor / VPN) to spot
  IP/geo and referer cloaking.
- **AiTM / reverse-proxy detection** — Evilginx / Modlishka-style header, cookie, cert and timing tells.
- **Phishing-kit recovery** — open-directory recursion, archive/source pull, exposed credential logs.

### Email & attachment analysis
- Parses **`.eml` / Outlook `.msg` / PDF / HTML** and nested forwarded emails, pulling every candidate link
  from the body, attachments, and **QR codes** — decoded from both **PDF pages** and **inline/attached
  images** ("quishing").
- **Static de-obfuscation** — decodes `\xNN` / `\uNNNN` / `String.fromCharCode` / percent-encoding / `atob`
  (iterated for *nested* layers) so packed-JS harvesters reveal their hidden URLs and exfil tokens.
  **Never executes the JavaScript** — it only rewrites literal escape sequences.
- **File hashes** (MD5 / SHA1 / SHA256) on every attachment.
- **Email intake** — forward a suspect email to a dedicated mailbox (with a **trusted-sender allowlist**)
  and PhishLab auto-analyses the *attachment* and detonates the extracted links.

### Evidence, reporting & scam signals
- **Evidence gallery** — the clean **login-page screenshot (captured before creds are entered)** alongside
  **VirusTotal / FortiGuard / Hybrid Analysis** result screenshots, real **file hashes**, and clickable
  report **permalinks**.
- **Human-assisted scanner reporting** — opens the real VT / FortiGuard / Hybrid Analysis page, fills the
  URL (or looks a file up by SHA-256), and screenshots the verdict; the analyst solves any CAPTCHA.
- **Scam-signals panel** — broad IOCs that are actionable even with no clickable link: callback **phone
  numbers**, **crypto wallet** addresses, **IBAN/bank**, **Telegram/WhatsApp** handles, and **reply-to ≠
  sender** — shown with a low/medium/high **confidence band**, kept deliberately distinct from the hard
  detonation verdict.
- **Redirect-chain + detonation graphs** — link → link → landing page with per-hop status codes, and a
  force-directed node-link graph of the flow (specimen → redirects → landing → creds/IOC).
- **Enrichment** — domain age (RDAP), hosting/ASN/geo, cert-transparency, malware/phishing blocklists, and a
  full **TLS-certificate** breakdown (subject / issuer / validity / SANs / self-signed / free-CA).
- **Takedown tracker + PhishTank watch** — pings reported sites on a schedule (UP/DOWN) from multiple
  vantages, and polls PhishTank until the URL is indexed, then surfaces the `phish_detail` link.

### The verdict
A transparent **weighted verdict** — `inconclusive` → `suspicious` → `likely_phishing` → `confirmed_phishing`
— every reason shown. Hard behavioural signals (Telegram exfil, off-site POST, recovered kit, cloaking,
brand-impersonating credential form) drive it; a false-positive **down-weight** protects established domains
with no hard evidence, while **shared-hosting / free-subdomain** evasion is explicitly defeated.

---

## How it works

```
        ┌──────────────────────────── PhishLab (one box, no cloud) ─────────────────────────────┐
URL  ──▶ │  decloak (multi-vantage)  ──▶  detonation engine  ──▶  robotic walk  ──▶  verdict     │
email ─▶ │  parse .eml/.msg/PDF/HTML/QR ──▶ de-obfuscate ──▶ extract links + exfil + IOCs        │
         │  enrich (RDAP/ASN/blocklists/TLS) · kit recovery · redirect+detonation graphs          │
         │  evidence gallery · scam signals · scanner reporting · takedown tracker                 │
         └──────────────────────────────────────────────────────────────────────────────────────┘
```

- **Detonation engine.** The default is **Chrome via SeleniumBase UC (undetected-chromedriver) + CDP**,
  because it's the only approach that reliably solves Cloudflare's hardened managed **Turnstile** — the
  widget won't even render for a Playwright/Camoufox fingerprint, and clearing it needs a *real OS-mouse
  click* (PyAutoGUI), not a synthetic CDP click. A **Camoufox** (real-fingerprint Firefox) engine is kept as
  a proxy/decloak fallback (`PHISH_ENGINE=camoufox`).
- **Async server, sync browser.** FastAPI/uvicorn runs the API; each detonation runs the synchronous
  SeleniumBase driver in a **worker thread** and streams the latest frame back to the live view. On Windows
  the app forces the **Proactor event-loop policy** at import time so the browser subprocess can spawn
  (the default Selector loop raises `NotImplementedError`), and it never uses `uvicorn --reload` (which
  breaks that subprocess).
- **Static, never dynamic.** Email/attachment parsing only ever *parses, renders, and statically decodes* —
  no macros run, no scripts run; PDFs/images are rendered to bitmaps for QR decode, and the de-obfuscator
  rewrites literal escapes without evaluating a single line of JavaScript.

---

## Notable engineering decisions

These are the tradeoffs that shaped the tool — the "why", not just the "what":

- **Self-hosted by design.** The sample itself never leaves the box — detonation and parsing happen
  locally, and there is no telemetry. (Threat-intel *enrichment* and takedown *reporting* are opt-in and, by
  design, submit **indicators** — a URL, a domain, a hash — to the services you choose, degrading gracefully
  when no keys are set.) That local-first default is the whole point for a regulated SOC.
- **SSRF-hardened.** Every fetched/detonated target is resolved and refused if it's loopback / RFC1918 /
  link-local (cloud-metadata `169.254.169.254`) / CGNAT — with **validate-and-pin** to close the DNS-rebind
  TOCTOU (resolve once, pin the browser/scanner to the validated IP). One allowlisted exception: the tool's
  own `127.0.0.1:<port>` demo fixtures.
- **False-positive discipline in the verdict.** A login form + "collects a password" describes *every* login
  page, so those soft tells are **down-weighted on an established domain with no hard evidence** — but that
  down-weight is defeated for **free-subdomain / shared-hosting** kits (an old parent domain says nothing
  about an attacker's free subdomain), and a **HIGH source-code indicator** (credential form posts off-site,
  packed `atob` kit) is treated as hard. This is why a title-less bank clone still scores as phishing.
- **Soft signals stay soft.** The "scam signals" panel is labelled *leads, not a verdict* and rendered
  separately from the detonation result — an analyst must never mistake a callback-number lead for a
  confirmed detection. In a security tool, breadth you can't stand behind is worse than no breadth.
- **We never ping the attacker.** A recovered Telegram exfil channel is surfaced as an IOC, never as a
  detonation candidate.
- **ToS-respectful reporting.** The VT/FortiGuard/HA reporter *fills* the form and screenshots the result;
  the analyst solves the CAPTCHA and submits. It automates the tedium, not the abuse.
- **Resource-safe on a modest box.** Live-browser detonations are capped by a bounded semaphore
  (`PHISH_MAX_CONCURRENT`, default 3) so an intake burst can't spawn a dozen Chrome instances and exhaust
  RAM; extra detonations queue.
- **Turnkey + self-updating.** One installer, one launcher. `Install.bat` upgrades the box's Python to 3.11+
  if needed; `start.bat` fast-forwards to the latest code and rebuilds the venv when deps change; the console
  can pull an update and cleanly self-restart (exit-42 relaunch loop — not `--reload`).

---

## Install & run (Windows)

```
1.  Install.bat      one-time setup: Python 3.11+ (auto-upgrades via winget if older),
                     dependencies, browsers (Playwright Firefox + Camoufox), Tor, Chrome check
2.  start.bat        the single launcher  ->  http://127.0.0.1:8090
```

`start.bat` fast-forwards to the latest code, kills any stale server, prints the running version, then
starts Tor + the server and opens the console. The default engine uses **Google Chrome** (the installer
checks for it). For a headless logon-autostart, point a `shell:startup` shortcut at `start.bat` with
`PHISH_NO_BROWSER=1`.

> **Isolated host + Defender.** Windows Defender will quarantine live phishing samples mid-analysis — run on
> an isolated VM with real-time protection off, or add a folder exclusion for your sample directory.

## Configuration (optional)

All config is via environment variables, or a **`.env`** in the PhishLab folder or `backend/` (auto-loaded,
**gitignored — never commit it**). Everything works out of the box without any of these. See
[`.env.example`](.env.example) for the full list; the essentials:

- `PHISH_ENGINE` — `seleniumbase` (default) or `camoufox`
- `PHISH_MAX_CONCURRENT` — max simultaneous detonations (default 3)
- `GMAIL_USER` / `GMAIL_APP_PASSWORD` / `MAIL_INTAKE_SENDERS` — email intake (trusted-sender allowlist)
- Optional threat-intel keys, each degrading gracefully if absent:
  `VIRUSTOTAL_KEY`, `GOOGLE_SAFEBROWSING_KEY`, `ABUSEIPDB_KEY`, `PHISHTANK_APP_KEY`

## Try it without a live URL

```bash
cd backend && python demo.py          # end-to-end self-test on a benign, self-hosted fixture
```

`demo.py` serves a multi-step fake-phish (branded login → OTP, with a Telegram exfil bot embedded) and
detonates it, printing the narration, verdict, and exfil channels. The console also ships offline fixtures:
`/demo-phish/`, `/demo-lead/`, `/demo-cfphish/`, `/demo-opendir/`, `/demo-aitm/`, `/demo-jsexfil/`.

## Scope & limitations (honest)

- It targets **phishing / fake websites and phishing email** — not a universal scam classifier. Link-less
  social-engineering (BEC text, romance/investment scams with no page) is surfaced only as *scam-signal
  IOCs*, not detonated.
- It does **browser detonation, not malware sandboxing** — it won't detonate a binary payload.
- **Password-protected archives** can't be opened without the password (often stated in the delivering
  email body).
- Browser automation against third-party sites is inherently **maintenance-sensitive** as those sites change.

## Project layout

```
Install.bat · start.bat           # Windows installer + the single launcher (native, no Docker)
run_server.py                     # server entrypoint (forces the Windows Proactor event-loop policy)
backend/
  api.py                          # local API + serves the single-page console
  web/index.html                  # the console UI (single page, no build step)
  phishlab/
    sb_session.py                 # DEFAULT engine: Chrome/SeleniumBase detonation + Cloudflare solving
    session.py                    # Camoufox engine (live, pausable) + report/takedown flows
    browser.py                    # browser launch + robotic form primitives
    sandbox.py                    # detonate(): decloak -> walk -> weighted verdict
    mailparse.py                  # .eml/.msg/PDF/HTML parsing, QR decode, static de-obfuscation
    extract.py                    # IOC / exfil / brand / scam-signal extraction
    reporter.py                   # human-assisted VT / FortiGuard / Hybrid Analysis capture
    enrich.py · aitm.py           # enrichment + AiTM/reverse-proxy + TLS-certificate detection
    kit.py · tracker.py           # phishing-kit recovery + takedown tracker
    phishtank.py · updater.py     # PhishTank watch + in-app self-update
  requirements.txt
```

## Tech stack

Python · FastAPI / uvicorn · SeleniumBase (UC/CDP) + Chrome · Camoufox / Playwright-Firefox · PyMuPDF +
pyzbar + Pillow (PDF/QR) · httpx (+ SOCKS/Tor) · a single-page vanilla-JS console (no build step).

---

*Built as a defensive-security tool for a bank SOC that needed cloud-grade phishing analysis without sending
samples to the cloud. Runs on an isolated host; fake data only.*
