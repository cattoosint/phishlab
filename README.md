# PhishLab

A SOC **phishing-URL detonation sandbox** — paste a suspected phishing link, and it auto-decloaks,
robotically steps through the kit (fills *fake* credentials on login pages), screenshots every step
(any.run-style), documents what the kit captures and *where it exfiltrates* (form actions, Telegram
bots), enriches it (WHOIS / hosting / URL reputation), and auto-reports it for takedown.

> Defensive SOC use, on an isolated external PC, with fake data only. Full vision, phases, and
> timeline: **[`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md)**.

## Status

**Phase 1 — detonation core: WORKING** ✅ (verified end-to-end, 7/7 self-checks)
- Decloak (scanner-view vs victim-view differential → cloaking verdict)
- Robotic step-through: detect credential form → fill fake creds → submit → follow the flow
- Screenshot every step + live analyst narration
- Exfil extraction: form actions + **Telegram bot token/chat-id**
- IOC + brand-impersonation extraction
- Weighted verdict (`inconclusive` → `suspicious` → `likely_phishing` → `confirmed_phishing`)

## Run the engine self-test

```bash
# Docker (baked browser):
docker compose build && docker compose run --rm phishlab      # runs backend/demo.py

# or locally (needs: pip install -r backend/requirements.txt && python -m playwright install firefox):
cd backend && python demo.py
```

`demo.py` serves a benign 2-step fake-phish fixture (Microsoft-branded login → OTP, with a Telegram
exfil bot embedded) and detonates it, printing the narration, verdict, exfil channels, and a 7-point
self-check.

## Layout

```
backend/
  phishlab/
    browser.py    # Firefox launch (vanilla Playwright default; invisible_playwright opt-in) + form primitives
    extract.py    # Telegram / IOC / brand extraction (pure, unit-testable)
    sandbox.py    # detonate(url): decloak → robotic step-through → verdict
  demo.py         # end-to-end self-test against a served fixture
  requirements.txt
docs/BUILD_PLAN.md
Dockerfile · docker-compose.yml
```

## Browser engine note

Default = **vanilla Playwright Firefox** (reliable). For best decloaking, set `PHISH_STEALTH=1` to
use `invisible_playwright` (a real-fingerprint Firefox) — pin compatible playwright/Firefox versions
in the image (some builds reject its injected `screenSize`). The engine falls back to vanilla if the
stealth browser can't launch.

## Roadmap (see the build plan)

Phase 2 exfil/IOC depth · Phase 3 enrichment (WHOIS/CT/IP/URL-rating) + verdict · Phase 4 anonymity/
hardening · Phase 5 SOC report + auto-takedown submits · **Phase 5b takedown tracker** (ping every
reported site ~30 min → UP/DOWN) · Phase 6 desktop packaging (Tauri/Electron installer).
