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

# Which live browsers are Camoufox (they own their own coherent UA/fingerprint, so contexts must NOT
# override the UA). Tracked PER BROWSER by id() — a module global would be stomped when a concurrent
# report/detonation launch()s or exits, corrupting an in-flight run's fingerprint.
_CAMOUFOX_IDS: set[int] = set()


def is_camoufox(browser) -> bool:
    """True if this browser instance is Camoufox (don't override its UA in contexts)."""
    return id(browser) in _CAMOUFOX_IDS


@asynccontextmanager
async def launch(headed: bool = False):
    """Launch Firefox once; reuse across scanner + victim contexts.

    Default = vanilla Playwright Firefox (reliable, standard API). Set PHISH_STEALTH=1 to use
    invisible_playwright's real-fingerprint Firefox instead (better decloaking) — but it force-
    injects a viewport `screenSize` some Firefox builds reject, so we fall back to vanilla if it
    fails to launch. In PhishLab's own image the invisible_playwright + Firefox versions are pinned
    compatible; here (Shadow's image) vanilla is the safe path for verifying the engine.

    Set PHISH_BROWSER=camoufox to use Camoufox — a real-fingerprint Firefox (spoofed TLS/JA3, humanized
    cursor) that reliably passes Cloudflare/Turnstile so the analyst can reach the actual phish. Falls
    back to vanilla if Camoufox isn't installed (pip install camoufox && python -m camoufox fetch)."""
    hl = False if headed else _HEADLESS   # report windows launch headed so the analyst can solve the CAPTCHA + submit
    if (os.getenv("PHISH_BROWSER") or "").strip().lower() == "camoufox":
        cm = browser = None
        try:
            from camoufox.async_api import AsyncCamoufox
            # a coherent real-desktop identity: Windows fingerprint, human cursor, no WebRTC IP leak,
            # + geoip (tz/locale/geo derived from the egress IP) when camoufox[geoip] is installed.
            opts = {"headless": hl, "humanize": True, "os": "windows", "block_webrtc": True}
            try:
                import geoip2  # noqa: F401
                opts["geoip"] = True
            except Exception:
                pass
            cm = AsyncCamoufox(**opts)
            browser = await cm.__aenter__()      # LAUNCH only is guarded — fall back to vanilla if it fails
        except Exception as exc:
            cm = None
            logger.warning("Camoufox unavailable (%s) — falling back to vanilla Firefox", exc)
        if cm is not None:
            _CAMOUFOX_IDS.add(id(browser))
            try:
                yield browser                     # caller errors propagate correctly (not swallowed -> no athrow)
            finally:
                _CAMOUFOX_IDS.discard(id(browser))
                try:
                    await cm.__aexit__(None, None, None)
                except Exception:
                    pass
            return
    if (os.getenv("PHISH_STEALTH") or "").strip().lower() in ("1", "true", "yes", "on"):
        try:
            from invisible_playwright.async_api import InvisiblePlaywright
            async with InvisiblePlaywright(headless=hl) as browser:
                yield browser
                return
        except Exception as exc:
            logger.warning("invisible_playwright unavailable (%s) — falling back to vanilla Firefox", exc)
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        browser = await p.firefox.launch(headless=hl)
        try:
            yield browser
        finally:
            await browser.close()


# Basic anti-detection — hides the most obvious automation tells that "managed" Cloudflare/Turnstile
# challenges key on. NOT a full stealth solution (deep TLS/JA3/HTTP-2 fingerprinting still detects
# vanilla Playwright); for reliably passing Cloudflare use a real-fingerprint browser (Camoufox).
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => false});
try { Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']}); } catch (e) {}
try { window.chrome = window.chrome || { runtime: {} }; } catch (e) {}
"""


async def new_victim_context(browser, *, locale="en-US", tz="America/New_York"):
    """A convincing victim: real UA, JS on, real locale/timezone, + a light anti-bot patch
    (navigator.webdriver=false). NB: do NOT pass an explicit `viewport` — invisible_playwright injects
    a `screenSize` alongside it that this Firefox build's protocol rejects."""
    # ignore_https_errors: phishing sites routinely have self-signed / expired / mismatched certs — power
    # through the Firefox cert-warning interstitial and analyse the page anyway. (aitm.cert_probe records
    # the cert problems separately for the report.)
    if is_camoufox(browser):
        # Camoufox supplies its own coherent fingerprint (UA/TLS/JA3/canvas) — don't override the UA
        return await browser.new_context(java_script_enabled=True, locale=locale, timezone_id=tz,
                                         ignore_https_errors=True)
    ctx = await browser.new_context(
        java_script_enabled=True, user_agent=FIREFOX_UA, locale=locale, timezone_id=tz,
        ignore_https_errors=True)
    try:
        await ctx.add_init_script(_STEALTH_JS)
    except Exception:
        pass
    return ctx


async def new_scanner_context(browser):
    """A bot-like identity: crawler UA, JS off — meant to trip cloaking so we see the decoy."""
    return await browser.new_context(java_script_enabled=False, user_agent=SCANNER_UA,
                                     ignore_https_errors=True)


# ── robotic form primitives ───────────────────────────────────────────────────
_FORMS_JS = """() => Array.from(document.forms).map(f => {
  const els = Array.from(f.elements).filter(e => e.name || e.type);
  const blob = e => ((e.name||'')+' '+(e.id||'')+' '+(e.placeholder||'')+' '+(e.getAttribute('aria-label')||'')+' '+(e.autocomplete||'')).toLowerCase();
  const type = e => (e.type||'').toLowerCase();
  const hasPw    = els.some(e => type(e)==='password' || /passw|pwd/.test((e.name||'')+' '+(e.id||'')));  // match fill_fields' password test
  const hasEmail = els.some(e => type(e)==='email' || /email|e-mail/.test(blob(e)));
  const hasPhone = els.some(e => type(e)==='tel'   || /phone|mobile/.test(blob(e)));
  const hasName  = els.some(e => /first ?name|last ?name|full ?name|fname|lname|your name/.test(blob(e)));
  // credential login = has a password; lead-capture = name + contact but NO password (marketing/signup)
  let kind = 'other';
  if (hasPw) kind = 'credential';
  else if (hasName && (hasEmail || hasPhone)) kind = 'lead_capture';
  else if (hasEmail || hasPhone) kind = 'contact';
  return {
    action: f.action || location.href,
    method: (f.method || 'get').toLowerCase(),
    fields: els.map(e => ({name: e.name || '', type: type(e), id: e.id || ''})),
    has_password: hasPw, kind: kind,
  };
})"""

# 'log in / sign in' links on the page — used to hunt for the REAL credential login when the current
# page only shows a lead-capture / marketing form (First/Last name, Phone, Email — no password).
_FIND_LOGIN_JS = r"""() => {
  // Match login LINKS by anchor text/aria (word-bounded, so 'catalog-info' doesn't match 'log-in') or by
  // a login PATH SEGMENT (so '/login' matches but '/mycatalog' doesn't). Avoids the substring false
  // positives that would send the walker off to an unrelated page.
  const TXT  = /\b(log ?in|sign ?in|log-in|sign-in|member login|customer login|account login|my account|client portal|member area|sign on)\b/i;
  const PATH = /(^|[\/._-])(login|signin|log-in|sign-in|logon|logins|account|portal|auth|members?)([\/._-]|$)/i;
  const cur = location.href.replace(/#.*$/, '');
  const seen = new Set(); const out = [];
  for (const a of document.querySelectorAll('a[href]')) {
    const href = (a.href || '').replace(/#.*$/, '');
    if (!href || href === cur || href.indexOf('javascript:') === 0 || href.indexOf('mailto:') === 0) continue;
    const txt = (a.textContent || '').trim();
    const aria = a.getAttribute('aria-label') || '';
    let path = href; try { path = new URL(href).pathname; } catch (e) {}
    if ((TXT.test(txt) || TXT.test(aria) || PATH.test(path)) && !seen.has(href)) {
      seen.add(href); out.push({ text: txt.slice(0, 60), href });
    }
  }
  return out.slice(0, 6);
}"""


async def find_login_link(page) -> list[dict]:
    """Login/sign-in links on the page (matched by anchor text/href/aria-label). Used to reach the REAL
    credential login when the page only shows a lead-capture form. Returns [] on any error."""
    try:
        return await page.evaluate(_FIND_LOGIN_JS)
    except Exception:
        return []

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


_FILL_ANY_JS = """(fake) => {
  const out = [];
  const set = (e, val, kind) => {
    try {
      e.focus(); e.value = val;
      e.dispatchEvent(new Event('input', {bubbles: true}));
      e.dispatchEvent(new Event('change', {bubbles: true}));
      out.push({name: e.name || e.id || '', type: (e.type || '').toLowerCase(), kind, value: val});
    } catch (_) {}
  };
  for (const e of document.querySelectorAll('input, textarea')) {
    const t = (e.type || '').toLowerCase();
    if (e.disabled || e.readOnly || ['hidden','submit','button','checkbox','radio','file','image','reset'].includes(t)) continue;
    if (e.value && t !== 'password') continue;   // don't clobber prefilled fields (except password)
    const n = ((e.name||'')+' '+(e.id||'')+' '+(e.placeholder||'')+' '+(e.getAttribute('aria-label')||'')+' '+(e.autocomplete||'')).toLowerCase();
    if (t === 'password' || /passw|pwd/.test(n)) set(e, fake.pw, 'password');
    else if (t === 'email' || /email|e-mail/.test(n)) set(e, fake.email, 'email');
    else if (t === 'tel' || /phone|mobile|\btel\b/.test(n)) set(e, fake.phone, 'phone');
    else if (/otp|\bcode\b|token|2fa|otc|verif|\bpin\b|security code|one.?time/.test(n)) set(e, fake.otp, 'otp/code');
    else if (/user|login|account|username|\bid\b/.test(n)) set(e, fake.user, 'username');
    else if (t === 'number') set(e, fake.otp, 'number');
    else if (t === 'text' || t === 'search' || t === '' || e.tagName === 'TEXTAREA') set(e, fake.text, 'text');
  }
  return out;
}"""

# a "please wait / verifying / redirecting" interstitial the walker should sit through, not stop at
_WAIT_RE = None


async def fill_fields(page, fake: dict) -> list[dict]:
    """Fill EVERY fillable input with type-appropriate FAKE data (password, email, phone, OTP/code,
    username, free text). Returns a list of what was filled — so the analyst sees each entry."""
    try:
        return await page.evaluate(_FILL_ANY_JS, fake)
    except Exception:
        return []


async def click_advance(page) -> str | None:
    """Advance the flow: click the most likely 'go' control — submit, or a button/link whose text is
    continue/next/verify/sign in/log in/proceed/confirm/submit. Returns the label clicked."""
    # 1) a real submit control
    for sel in ("button[type=submit]", "input[type=submit]"):
        try:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                label = (await el.inner_text() if sel.startswith("button") else await el.get_attribute("value")) or "submit"
                await el.click(timeout=5000)
                return label.strip()[:40]
        except Exception:
            continue
    # 2) a button/link/role=button whose text reads like an advance action (multi-language:
    #    'continu' catches continue/continuar/continuer; + PT/ES/FR/DE variants)
    try:
        cand = await page.evaluate("""() => {
          const rx = /continu|next|verify|proceed|confirm|submit|weiter|siguiente|sign\\s*in|log\\s*in|avan[cç]ar|avanzar|pr[oó]xim|prosseguir|acessar|entrar|seguinte|suivant|valider|acc[eé]der|get\\s*started|comen[çc]ar/i;
          const els = Array.from(document.querySelectorAll('button, a, [role=button], input[type=button], input[type=submit]'));
          for (const e of els) {
            const txt = (e.innerText || e.value || '').trim();
            if (rx.test(txt) && e.offsetParent !== null) return txt.slice(0, 40);
          }
          // interstitial GATE: no real form fields + a single visible button -> click it whatever it says
          const inputs = document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]), textarea, select');
          if (inputs.length === 0) {
            const btns = els.filter(e => e.offsetParent !== null && (e.innerText||e.value||'').trim());
            if (btns.length === 1) return (btns[0].innerText||btns[0].value||'').trim().slice(0, 40);
          }
          return null;
        }""")
    except Exception:
        cand = None
    if cand:
        try:
            await page.get_by_text(cand, exact=False).first.click(timeout=5000)
            return cand
        except Exception:
            pass
    try:
        await page.keyboard.press("Enter")
        return "Enter"
    except Exception:
        return None


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
        shot = await page.screenshot(type="jpeg", quality=82)   # clearer thumbnails + lightbox
        return base64.b64encode(shot).decode()
    except Exception:
        return None
