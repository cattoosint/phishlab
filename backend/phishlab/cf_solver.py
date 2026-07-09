"""phishlab/cf_solver.py — Cloudflare "Suspected Phishing" Turnstile solver (SeleniumBase hand-off).

Camoufox/Playwright cannot render OR solve Cloudflare's managed Turnstile on the phishing-warning
interstitial — verified against a live flagged site: the widget doesn't even inject its iframe for the
Playwright/Camoufox fingerprint, and the "Ignore & Proceed" button stays disabled until a token exists.
SeleniumBase UC mode + uc_gui_click_captcha() DOES solve it (a REAL OS-mouse click via PyAutoGUI), then
reaches the phish behind the wall.

Design: run the solver as an isolated SUBPROCESS so its sync webdriver + PyAutoGUI world stays out of the
async server + Playwright. It returns the captured page (url/title/html/screenshot/forms) + cookies so
the walker can analyse the content behind the wall (and best-effort hand the clearance back to Camoufox).

WARNING: the solve moves the PHYSICAL mouse (PyAutoGUI). The UI must tell the analyst not to touch the
mouse/keyboard while it runs — a no-mouse/CDP-native click does NOT pass this hardened Turnstile (tested).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
import time

_HERE = os.path.abspath(__file__)
SOLVE_TIMEOUT = int(os.getenv("PHISH_CF_SOLVE_TIMEOUT") or "200")


def available() -> bool:
    """True if SeleniumBase is importable (the solver can run)."""
    try:
        import seleniumbase  # noqa: F401
        return True
    except Exception:
        return False


async def solve(url: str, timeout: int | None = None) -> dict:
    """Run the Cloudflare solver in a subprocess. Returns a capture dict:
    {solved, final_url, title, html, screenshot(b64), forms, cookies, error}. Never raises."""
    timeout = timeout or SOLVE_TIMEOUT
    out = os.path.join(tempfile.gettempdir(), f"cf_solve_{int(time.time() * 1000)}_{os.getpid()}.json")
    try:
        rc = await asyncio.to_thread(_run_subprocess, url, out, timeout)
    except subprocess.TimeoutExpired:
        return {"solved": False, "error": f"solver timed out after {timeout}s"}
    except Exception as exc:
        return {"solved": False, "error": f"solver launch failed: {type(exc).__name__}: {exc}"[:200]}
    try:
        with open(out, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"solved": False, "error": f"solver produced no result (exit {rc})"}
    finally:
        try:
            os.remove(out)
        except Exception:
            pass


def _run_subprocess(url: str, out: str, timeout: int) -> int:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    p = subprocess.run([sys.executable, _HERE, url, out],
                       capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode


# ── subprocess entry point — self-contained (seleniumbase + stdlib only) ─────────
_FORMS_JS = """
var out = [];
for (var i=0;i<document.forms.length;i++){
  var f=document.forms[i], els=f.elements, hasPw=false, fields=[];
  for (var j=0;j<els.length;j++){
    var e=els[j], t=(e.type||'').toLowerCase();
    if (t==='password' || /passw|pwd/.test((e.name||'')+' '+(e.id||''))) hasPw=true;
    if (e.name||e.type) fields.push({name:e.name||'', type:t});
  }
  out.push({action: f.action||location.href, method:(f.method||'get').toLowerCase(),
            has_password:hasPw, fields:fields});
}
return JSON.stringify(out);
"""


def _main(url: str, out: str) -> int:
    result = {"solved": False, "final_url": None, "title": None, "html": None,
              "screenshot": None, "forms": [], "cookies": [], "error": None, "attempts": 0}
    try:
        from seleniumbase import SB
    except Exception as exc:
        result["error"] = f"seleniumbase not available: {exc}"[:180]
        _write(out, result)
        return 1

    def body_txt(sb):
        try:
            return (sb.get_text("body") or "").lower()
        except Exception:
            return ""

    def bypass_enabled(sb):
        try:
            return bool(sb.execute_script(
                "var b=document.querySelector('#bypass-button');return b&&!b.disabled;"))
        except Exception:
            return False

    try:
        with SB(uc=True, headless=False, locale="en", incognito=True) as sb:
            for attempt in range(3):
                result["attempts"] = attempt + 1
                sb.uc_open_with_reconnect(url, reconnect_time=5)
                sb.sleep(2.0)
                try:
                    sb.uc_gui_click_captcha()          # REAL OS-mouse click on the Turnstile checkbox
                except Exception:
                    pass
                # wait for the token → #bypass-button to enable (click it), or a natural auto-redirect
                for _ in range(7):
                    sb.sleep(2.0)
                    b = body_txt(sb)
                    if "suspected phishing" not in b and "verification failed" not in b:
                        break
                    if bypass_enabled(sb):
                        try:
                            sb.click("#bypass-button")
                        except Exception:
                            pass
                        sb.sleep(3.0)
                        break
                b = body_txt(sb)
                if "verification failed" in b:
                    continue                            # token rejected server-side → retry with a fresh one
                if "suspected phishing" not in b and b:
                    break                               # through the wall
            # ── capture whatever we ended on ──
            b = body_txt(sb)
            result["solved"] = ("suspected phishing" not in b and "verification failed" not in b and bool(b))
            for getter, key in ((sb.get_current_url, "final_url"), (sb.get_title, "title"),
                                (sb.get_page_source, "html")):
                try:
                    result[key] = getter()
                except Exception:
                    pass
            try:
                png = os.path.join(tempfile.gettempdir(), f"cf_shot_{os.getpid()}.png")
                sb.save_screenshot(png)
                with open(png, "rb") as f:
                    result["screenshot"] = base64.b64encode(f.read()).decode()
                os.remove(png)
            except Exception:
                pass
            try:
                result["forms"] = json.loads(sb.execute_script(_FORMS_JS) or "[]")
            except Exception:
                pass
            try:
                result["cookies"] = sb.get_cookies()
            except Exception:
                pass
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"[:200]
    _write(out, result)
    return 0 if result["solved"] else 2


def _write(out, result):
    try:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(result, f)
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1], sys.argv[2]) if len(sys.argv) >= 3 else 1)
