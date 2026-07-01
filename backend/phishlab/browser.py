"""phishlab/browser.py — the detonation browser.

A REAL Firefox via invisible_playwright (ported from Shadow's URL-unmask): its TLS/JA3 + HTTP/2
fingerprint is genuinely Firefox's, so cloaking gates that fingerprint the client see a victim,
not an automation signature. This module owns launching, the two identities used for decloaking
(scanner vs victim), and the robotic form detect / fake-cred fill / submit primitives.

Launch note (invisible_playwright quirk): use `InvisiblePlaywright(headless=...) as browser`, then
`browser.new_context(java_script_enabled=..., user_agent=..., viewport=...)`. A bare new_context()
throws a setDefaultViewport protocol error — always pass an explicit context config.
"""
from __future__ import annotations

import base64
import logging
import os
from contextlib import asynccontextmanager

logger = logging.getLogger("phishlab.browser")

_HEADLESS = (os.getenv("PHISH_HEADFUL") or "").strip().lower() not in ("1", "true", "yes", "on")
NAV_TIMEOUT = int(os.getenv("PHISH_NAV_TIMEOUT_MS") or "35000")

# A real, current Firefox UA for the VICTIM identity (matches the invisible_playwright engine).
FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
# A crawler UA for the SCANNER identity — meant to look like a bot so the kit serves its decoy.
SCANNER_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@asynccontextmanager
async def launch():
    """Launch Firefox once; reuse across scanner + victim contexts.

    Default = vanilla Playwright Firefox (reliable, standard API). Set PHISH_STEALTH=1 to use
    invisible_playwright's real-fingerprint Firefox instead (better decloaking) — but it force-
    injects a viewport `screenSize` some Firefox builds reject, so we fall back to vanilla if it
    fails to launch. In PhishLab's own image the invisible_playwright + Firefox versions are pinned
    compatible; here (Shadow's image) vanilla is the safe path for verifying the engine."""
    if (os.getenv("PHISH_STEALTH") or "").strip().lower() in ("1", "true", "yes", "on"):
        try:
            from invisible_playwright.async_api import InvisiblePlaywright
            async with InvisiblePlaywright(headless=_HEADLESS) as browser:
                yield browser
                return
        except Exception as exc:
            logger.warning("invisible_playwright unavailable (%s) — falling back to vanilla Firefox", exc)
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        browser = await p.firefox.launch(headless=_HEADLESS)
        try:
            yield browser
        finally:
            await browser.close()


async def new_victim_context(browser, *, locale="en-US", tz="America/New_York"):
    """A convincing victim: real UA, JS on, real locale/timezone. NB: do NOT pass an explicit
    `viewport` — invisible_playwright injects a `screenSize` alongside it that this Firefox build's
    protocol rejects (Browser.setDefaultViewport error). The wrapper applies its own coherent
    viewport/fingerprint anyway."""
    return await browser.new_context(
        java_script_enabled=True, user_agent=FIREFOX_UA, locale=locale, timezone_id=tz)


async def new_scanner_context(browser):
    """A bot-like identity: crawler UA, JS off — meant to trip cloaking so we see the decoy."""
    return await browser.new_context(java_script_enabled=False, user_agent=SCANNER_UA)


# ── robotic form primitives ───────────────────────────────────────────────────
_FORMS_JS = """() => Array.from(document.forms).map(f => ({
  action: f.action || location.href,
  method: (f.method || 'get').toLowerCase(),
  fields: Array.from(f.elements).filter(e => e.name || e.type)
             .map(e => ({name: e.name || '', type: (e.type || '').toLowerCase(), id: e.id || ''})),
  has_password: Array.from(f.elements).some(e => (e.type || '').toLowerCase() === 'password'),
}))"""

_FILL_JS = """(cred) => {
  const filled = {password: false, user: false, extra: 0};
  for (const f of document.forms) {
    let pw = null, user = null;
    for (const e of f.elements) {
      const t = (e.type || '').toLowerCase();
      const n = ((e.name || '') + ' ' + (e.id || '') + ' ' + (e.placeholder || '')).toLowerCase();
      if (t === 'password') pw = e;
      else if (t === 'email' || ((t === 'text' || t === '') && /user|email|login|mail|phone|account|id/.test(n))) user = user || e;
      else if (t === 'tel' || t === 'number') { if (!e.value) { e.value = cred.pad; filled.extra++; } }
    }
    if (pw) { pw.value = cred.pw; filled.password = true; }
    if (user) { user.value = cred.user; filled.user = true; }
  }
  return filled;
}"""


async def detect_forms(page) -> list[dict]:
    try:
        return await page.evaluate(_FORMS_JS)
    except Exception:
        return []


async def fill_credentials(page, user: str, pw: str) -> dict:
    """Fill FAKE creds into every form (password + best-guess username/email field)."""
    try:
        return await page.evaluate(_FILL_JS, {"user": user, "pw": pw, "pad": "0000000000"})
    except Exception:
        return {"password": False, "user": False, "extra": 0}


async def submit_form(page) -> bool:
    """Submit — prefer clicking a submit control (triggers the kit's JS handlers) then Enter."""
    for sel in ("button[type=submit]", "input[type=submit]", "form button", "[role=button]"):
        try:
            el = await page.query_selector(sel)
            if el:
                await el.click(timeout=5000)
                return True
        except Exception:
            continue
    try:
        await page.keyboard.press("Enter")
        return True
    except Exception:
        return False


async def screenshot_b64(page) -> str | None:
    try:
        shot = await page.screenshot(type="jpeg", quality=55)
        return base64.b64encode(shot).decode()
    except Exception:
        return None
