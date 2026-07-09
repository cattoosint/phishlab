# PhishLab

A **phishing-URL detonation sandbox** for SOC / blue-team use. Paste a suspected phishing link and
PhishLab drives a **real browser** through it in isolation — decloaking it, solving anti-bot walls,
robotically stepping through the kit (filling **fake** credentials on login forms), screenshotting
every step (any.run-style), and documenting what the kit captures and *where it exfiltrates*. It then
enriches the case (WHOIS / hosting / blocklists / TLS certificate), maps the redirect chain, recovers
the phishing kit where exposed, and helps you report it for takedown.

> **Defensive use only**, on an **isolated machine**, with **fake data only**. It deliberately visits
> hostile URLs — never point it at anything you aren't authorised to analyse, and never on a box with
> access to production systems.

## Highlights

- **Real-browser detonation** with a live, in-app streamed view (screenshots every step).
- **Beats Cloudflare** — the default engine (Chrome / SeleniumBase UC) solves the "Suspected Phishing"
  warning and the "Just a moment" / "Verify you are human" Turnstile challenge, and powers through bad
  TLS-cert and "dangerous site" interstitials to reach the real phish behind them.
- **Robotic walk** — detects login vs. lead-capture forms, fills **fake** credentials, submits, and
  follows the flow; records the form actions and any **Telegram** exfil bot/chat it finds.
- **Decloaking** — compares scanner-view vs. victim-view and multi-vantage (direct / Tor / VPN) to spot
  IP/geo and referer cloaking.
- **Enrichment** — domain age (RDAP), hosting/ASN/geo, cert-transparency, malware/phishing blocklists,
  and a full **TLS-certificate** breakdown (subject / issuer / validity / SANs / self-signed / free-CA).
- **Redirect-chain graph** — link → link → final landing page, with per-hop status codes.
- **AiTM / reverse-proxy detection** — Evilginx / Modlishka-style header, cookie, cert and timing tells.
- **Phishing-kit recovery** — open-directory recursion, archive/source pull, exposed credential logs.
- **PhishTank watch** — after a URL is reported, PhishLab polls PhishTank until it's indexed, then
  surfaces the `phish_detail` link with one-click copy / share for your takedown thread.
- **Takedown tracker** — pings reported sites on a schedule (UP / DOWN) from multiple vantages.
- **Email intake** — email the box with the URL as the subject line (empty body) to auto-detonate.
- **Weighted verdict** — `inconclusive` → `suspicious` → `likely_phishing` → `confirmed_phishing`.

## Install & run (Windows)

```
1.  Install.bat      (one-time setup: environment, dependencies, browsers)
2.  PhishLab.bat     (starts the console)   ->   http://127.0.0.1:8090
```

`Install.bat` needs **Python 3.11+** on PATH and installs everything into a local `.venv`. The default
detonation engine uses **Google Chrome**, so install Chrome as well (the installer will tell you if it's
missing). `PhishLab.bat` also self-installs on first run if you skip the installer.

Engines: the default is **Chrome / SeleniumBase** (best for Cloudflare). Set `PHISH_ENGINE=camoufox` to
use the **Camoufox** (real-fingerprint Firefox) engine instead — kept as a proxy / decloak fallback.

## Configuration (optional)

All configuration is via environment variables (or a local `backend/.env`, which is **gitignored and
must never be committed**). Everything works out of the box without any of these:

- `PHISH_ENGINE` — `seleniumbase` (default) or `camoufox`
- `PHISH_TRACK_VANTAGES` / `PHISH_NORD_SERVERS` — extra decloak vantages (e.g. Tor / VPN exits)
- `PHISH_PHISHTANK_USER` — PhishTank reporter account the watch polls
- Optional threat-intel API keys (each degrades gracefully if absent):
  `GOOGLE_SAFEBROWSING_KEY`, `VIRUSTOTAL_KEY`, `ABUSEIPDB_KEY`, `PHISHTANK_APP_KEY`

> Never commit real credentials. `.env` is in `.gitignore`; keep all secrets there and out of the repo.

## Engine self-test (no live URL)

```bash
# locally:  pip install -r backend/requirements.txt && python -m playwright install firefox
cd backend && python demo.py
```

`demo.py` serves a benign multi-step fake-phish fixture (branded login → OTP, with a Telegram exfil bot
embedded) and detonates it, printing the narration, verdict, exfil channels, and a self-check. The
console also ships built-in offline fixtures: `/demo-phish/`, `/demo-lead/`, `/demo-cfphish/`,
`/demo-opendir/`, `/demo-aitm/`, `/demo-jsexfil/`.

## Layout

```
Install.bat · PhishLab.bat        # Windows installer + launcher (native, no Docker needed)
run_server.py                     # server entrypoint (sets the Windows event-loop policy)
backend/
  api.py                          # local API + serves the single-page console
  web/index.html                  # the console UI
  phishlab/
    sb_session.py                 # DEFAULT engine: Chrome/SeleniumBase detonation + Cloudflare solving
    session.py                    # Camoufox engine (live, pausable) + report/takedown flows
    browser.py                    # browser launch + robotic form primitives
    sandbox.py · extract.py       # detonate(): decloak -> walk -> verdict; IOC/exfil extraction
    enrich.py · aitm.py           # enrichment + AiTM/reverse-proxy + TLS-certificate detection
    kit.py · tracker.py           # phishing-kit recovery + takedown tracker
    phishtank.py                  # PhishTank reporting watch
  requirements.txt
```
