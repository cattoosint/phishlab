"""phishlab/sb_session.py — SeleniumBase (Chrome/UC) detonation engine — the PRIMARY engine.

Replaces Camoufox as the workhorse: Camoufox can't solve Cloudflare's hardened managed Turnstile (the
widget won't even render for its fingerprint), and its streamed-frame take-over never worked reliably.
SeleniumBase UC mode solves Cloudflare (real-mouse Turnstile click), then robotically walks the phish
(fills FAKE creds, submits, captures every step), streaming screenshots into PhishLab's live frame and
transmitting all findings into the same report the UI already renders.

Runs the sync SeleniumBase driver in a WORKER THREAD; the async API just reads the shared latest_frame +
report. No input forwarding (take-over dropped) — the real Chrome window is on the desktop if the analyst
wants to touch it. Camoufox stays available (PHISH_ENGINE=camoufox) as a proxy/decloak backup.

WARNING: the Cloudflare solve moves the PHYSICAL mouse (PyAutoGUI). The UI shows a "don't touch" banner
while report.cf_solving is set — a no-mouse/CDP click does NOT pass this Turnstile (tested).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import threading
import time
import uuid
from io import BytesIO

import httpx

from . import enrich as E
from . import extract as X
from . import indicators as I
from . import kit as K
from . import net_guard as G
from . import session as _sess
from . import tracker as T
from .sandbox import _host, _merge_ip, _verdict

try:
    from PIL import Image
except Exception:                       # Pillow ships with seleniumbase; fall back to raw PNG if absent
    Image = None

MAX_STEPS = int(os.getenv("PHISH_SB_MAX_STEPS") or "8")
# FAKE decoy identity — plausible-looking (a real-format Gmail, not an obvious @example.com that some kits
# reject) so validation passes, but NOT a real account. Overridable via env for a site's own decoy identity.
_FAKE = {"user": os.getenv("PHISH_FAKE_USER", "abelrtsmith"),
         "email": os.getenv("PHISH_FAKE_EMAIL", "abelrtsmith@gmail.com"),
         "pw": os.getenv("PHISH_FAKE_PW", "Nv3r-R3al!P4ss"),
         "phone": "90000000", "otp": "000000", "text": "test"}

# forms on the page → {action, method, has_password, fields}
_FORMS_JS = r"""
var out=[];
for(var i=0;i<document.forms.length;i++){var f=document.forms[i],els=f.elements,hasPw=false,fields=[];
 for(var j=0;j<els.length;j++){var e=els[j],t=(e.type||'').toLowerCase();
  if(t==='password'||/passw|pwd/.test((e.name||'')+' '+(e.id||'')))hasPw=true;
  if(e.name||e.type)fields.push({name:e.name||'',type:t});}
 out.push({action:f.action||location.href,method:(f.method||'get').toLowerCase(),has_password:hasPw,fields:fields});}
return JSON.stringify(out);
"""

# fill EVERY fillable input with type-appropriate FAKE data; returns what was filled
_FILL_JS = r"""
var fake=arguments[0],out=[];
function setv(e,v,k){try{e.focus();e.value=v;e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));out.push({kind:k,value:v});}catch(_){}}
var els=document.querySelectorAll('input,textarea');
for(var i=0;i<els.length;i++){var e=els[i],t=(e.type||'').toLowerCase();
 if(e.disabled||e.readOnly||['hidden','submit','button','checkbox','radio','file','image','reset'].indexOf(t)>=0)continue;
 if(e.value&&t!=='password')continue;
 var n=((e.name||'')+' '+(e.id||'')+' '+(e.placeholder||'')+' '+(e.getAttribute('aria-label')||'')).toLowerCase();
 if(t==='password'||/passw|pwd/.test(n))setv(e,fake.pw,'password');
 else if(t==='email'||/e-?mail|\bmail\b/.test(n)||/@/.test(e.placeholder||''))setv(e,fake.email,'email');
 else if(t==='tel'||/phone|mobile|\btel\b/.test(n))setv(e,fake.phone,'phone');
 else if(/otp|\bcode\b|token|2fa|otc|verif|\bpin\b|one.?time/.test(n))setv(e,fake.otp,'otp/code');
 else if(/user|login|account|username|\bid\b/.test(n))setv(e,fake.user,'username');
 else if(t==='text'||t==='search'||t===''||e.tagName==='TEXTAREA')setv(e,fake.text,'text');}
return JSON.stringify(out);
"""

_SUBMIT_JS = r"""
var b=document.querySelector('button[type=submit],input[type=submit]');
if(!b){var bs=document.querySelectorAll('button,[role=button],a,input[type=button]');
 for(var i=0;i<bs.length;i++){var t=(bs[i].innerText||bs[i].value||'').trim();
  if(/log ?in|sign ?in|submit|continue|next|verify|confirm|proceed|entrar|acessar|weiter/i.test(t)&&bs[i].offsetParent!==null){b=bs[i];break;}}}
if(b){b.click();return true;} var f=document.forms[0]; if(f){f.submit();return true;} return false;
"""

# Click the most-promising control to move DEEPER into the phish. Priority-ranked so it goes for the lure
# CTA (SEE DETAILS / LOGIN / VIEW DOCUMENT) and dismisses gating overlays (Close / Continue / "wait 5s"),
# while NEVER wandering into footer/legal dead-ends (Privacy, Terms, Unsubscribe, Cookie, About…). Takes an
# array of button texts already clicked on this page (arguments[0]) so it can click Close THEN the button
# underneath, without re-clicking the same control. Returns the (lowercased) text it clicked, or null.
_ADVANCE_JS = r"""
var done=arguments[0]||[];
var skip=/privacy|terms|cookie|unsubscribe|about us|contact|help ?center|imprint|legal|copyright|report abuse|do not sell|manage consent|\bpolicy\b|accessibility|sitemap|careers|feedback|support|troubleshoot|can.?t access|cant access|\bforgot\b|trouble|learn more|create one|sign.?in options|privacy statement|use another/i;
var primary=/see details|view (document|file|invoice|message|now)|read message|open (document|file|in)|\baccess\b|log ?in|sign ?in|get started|continue to|release|verify now|confirm|update your|proceed to|click here|go to document|authenticate|unlock|review/i;
var gate=/close|dismiss|got it|\bok\b|i understand|acknowledge|agree|\baccept\b|continue|proceed|next|enter|yes[, ]|start|begin/i;
var inter=/visit|at your own risk|ignore ?& ?proceed|ignore and proceed|go to site|enter site/i;
function vis(e){try{return e.offsetParent!==null&&e.getBoundingClientRect().width>0;}catch(_){return false;}}
var els=document.querySelectorAll('a,button,[role=button],input[type=button],input[type=submit],[onclick]');
var best=null,bestRank=0,bestText='';
for(var i=0;i<els.length;i++){var e=els[i];
 var t=((e.innerText||e.value||e.textContent||'')+' '+((e.getAttribute&&e.getAttribute('aria-label'))||'')).trim();
 if(!t||t.length>80||!vis(e))continue;
 if(done.indexOf(t.toLowerCase())>=0)continue;      // already clicked this exact control on this page
 if(skip.test(t))continue;                          // never click legal/footer dead-ends
 var rank=0;
 if(primary.test(t))rank=4;                         // the lure CTA — deepest into the phish
 else if(gate.test(t))rank=3;                       // a modal/overlay dismiss (Close/Continue)
 else if(inter.test(t))rank=2;                      // browser-warning-style interstitial
 if(rank>bestRank){bestRank=rank;best=e;bestText=t;}
}
if(best){try{best.click();}catch(_){}return bestText.toLowerCase();}
return null;
"""


_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"


def _urlkey(u: str) -> str:
    return (u or "").split("#")[0].rstrip("/").lower()


async def _http_redirect_chain(url: str, max_hops: int = 10) -> list[dict]:
    """Server-side HTTP redirect chain (the 3xx hops) from the entry URL to the final landing page, with
    each hop's status code. Follows redirects MANUALLY and re-checks net_guard on every hop so a phish
    can't steer this server-side fetch to an internal/metadata host (SSRF)."""
    hops = []
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15,
                                     headers={"User-Agent": _UA}) as c:
            cur = url
            for _ in range(max_hops):
                ok, _why = G.check_target(cur)
                if not ok:
                    hops.append({"url": cur, "status": None, "via": "blocked (non-public host)"})
                    break
                r = await c.get(cur)
                loc = r.headers.get("location")
                if 300 <= r.status_code < 400 and loc:
                    hops.append({"url": cur, "status": r.status_code, "via": "http"})
                    cur = str(httpx.URL(cur).join(loc))
                    continue
                hops.append({"url": cur, "status": r.status_code, "via": "final"})
                break
    except Exception:
        pass
    return hops


def _to_jpeg(png, q=72):
    if not png:
        return None
    if Image is None:
        return png
    try:
        im = Image.open(BytesIO(png)).convert("RGB")
        buf = BytesIO()
        im.save(buf, "JPEG", quality=q)
        return buf.getvalue()
    except Exception:
        return png


class SBSession:
    """A live SeleniumBase detonation. Same public surface as session.Session so the API/UI don't care
    which engine ran it: id, state, report, latest_frame, snapshot_state(), forward(), request_takeover(),
    resume(), cancel()."""

    def __init__(self, url: str):
        self.id = uuid.uuid4().hex[:12]
        self.url = url
        self.state = "starting"        # starting | running | done | error | cancelled
        self.report = {
            "url": url, "started_at": time.time(), "narration": [], "steps": [],
            "exfil": {"form_actions": [], "telegram": []}, "iocs": {}, "decloak": None,
            "cloaking": None, "challenge": [], "handover_needed": False, "verdict": None,
            "engine": "seleniumbase",
        }
        self.latest_frame: bytes | None = None
        self.viewport = {"width": 1280, "height": 720}
        self.paused = False
        self._cancel = threading.Event()
        self._html_parts: list[str] = []
        self._sb = None
        self._main_handle = None
        self._thread: threading.Thread | None = None

    # ── public surface (mirrors session.Session) ──
    def _log(self, m):
        self.report["narration"].append(m)

    def snapshot_state(self) -> dict:
        return {"id": self.id, "state": self.state, "paused": False, "report": self.report,
                "has_frame": self.latest_frame is not None, "viewport": self.viewport, "engine": "seleniumbase"}

    async def forward(self, ev: dict):
        return   # take-over/input-forwarding dropped — interact with the real Chrome window directly

    def request_takeover(self):
        self._log("Take-over: a real Chrome window is open on the desktop — interact with it directly "
                  "(in-app forwarding is disabled for the Chrome engine).")

    def resume(self):
        pass

    def cancel(self):
        if self.state in ("done", "error", "cancelled"):
            return
        self.state = "cancelled"
        self._cancel.set()
        self._log("Scan cancelled by the analyst.")

    # ── screenshot streaming ──
    def _shot(self, sb):
        try:
            png = sb.driver.get_screenshot_as_png()
            jpg = _to_jpeg(png)
            if jpg:
                self.latest_frame = jpg
            return jpg
        except Exception:
            return None

    def _shot_b64(self, sb):
        jpg = self._shot(sb)
        return base64.b64encode(jpg).decode() if jpg else None

    def _wait(self, sb, secs):
        end = time.time() + secs
        while time.time() < end:
            if self._cancel.is_set():
                return
            time.sleep(0.4)
            self._shot(sb)

    def _body(self, sb):
        try:
            return (sb.get_text("body") or "").lower()
        except Exception:
            return ""

    def _bypass_enabled(self, sb):
        try:
            return bool(sb.execute_script(
                "var b=document.querySelector('#bypass-button');return b&&!b.disabled;"))
        except Exception:
            return False

    def _timed_gate_seconds(self, sb, html="") -> int:
        """A fake 'let us know you are human / you have to wait N seconds before you proceed' timer gate →
        the seconds to pause before its Continue button enables (clicking early is a no-op). 0 if none."""
        try:
            blob = (self._body(sb) + " " + (html or "")).lower()
        except Exception:
            blob = (html or "").lower()
        if not any(k in blob for k in ("wait for the timer", "before you can proceed", "before you continue",
                                       "let us know you are human", "you have to wait")):
            return 0
        secs = 0
        for m in re.finditer(r"wait\s+(?:for\s+)?(\d{1,3})\s*second", blob):
            secs = max(secs, int(m.group(1)))
        if not secs:
            secs = 6            # a timer is present but the countdown wasn't parseable → safe default
        return min(secs, 15)    # cap so a bogus 'wait 999 seconds' can't stall the whole walk

    def _await_human_captcha(self, sb, timeout=None) -> bool:
        """Auto-solve couldn't clear it (an IMAGE/WORD Cloudflare challenge). Hand off to the analyst in the
        Chrome window and POLL until the challenge clears, then let the walk continue. True if it cleared."""
        if not self._still_gated(sb):
            return True
        timeout = timeout or int(os.getenv("PHISH_CF_HUMAN_TIMEOUT") or "240")
        self.report["human_needed"] = "captcha"
        self.report["cf_solving"] = False        # they must interact now — drop the 'don't touch' banner
        self._log("Cloudflare image/word challenge — SOLVE IT in the Chrome window on the desktop. "
                  "I'll detect when it's done and continue the steps automatically.")
        end = time.time() + timeout
        while time.time() < end:
            if self._cancel.is_set():
                return False
            self._wait(sb, 2)
            if not self._still_gated(sb):
                self.report["human_needed"] = None
                self._log("[OK] Challenge cleared by the analyst — continuing the walk.")
                return True
        self._log("Challenge still unsolved after waiting — stopping (use 'Open in browser' to finish).")
        return False

    def _wait_for_form(self, sb, secs) -> None:
        """After a gate clears, poll (streaming frames) until the real page renders a fillable field / button
        — so the walk doesn't conclude 'nothing to fill' against a still-loading post-gate page."""
        end = time.time() + secs
        while time.time() < end:
            if self._cancel.is_set():
                return
            self._wait(sb, 1)
            try:
                if sb.execute_script(
                        "return document.querySelectorAll('input:not([type=hidden]),textarea,button,form').length>0"):
                    self._wait(sb, 1)          # a beat more so values/handlers attach
                    return
            except Exception:
                pass

    def _wait_for_password(self, sb, secs) -> None:
        """After submitting an email-first login (MS SSO 'email → Next → password'), wait for the password
        field to render so the next loop fills it, instead of stopping the walk after just the email step."""
        end = time.time() + secs
        while time.time() < end:
            if self._cancel.is_set():
                return
            self._wait(sb, 1)
            try:
                if sb.execute_script("return !!document.querySelector('input[type=password]:not([disabled])');"):
                    self._wait(sb, 1)          # a beat more so the field is interactive
                    return
            except Exception:
                pass

    # ── browser interstitials (bad TLS cert / SafeBrowsing) — phishing sites routinely trip these ──
    def _ignore_certs(self, sb):
        try:
            sb.driver.execute_cdp_cmd("Security.setIgnoreCertificateErrors", {"ignore": True})
        except Exception:
            pass

    def _is_interstitial(self, title, html):
        blob = ((title or "") + " " + (html or "")).lower()
        return any(k in blob for k in (
            "privacy error", "your connection is not private", "your connection isn't private",
            "net::err_cert", "err_cert_", "sec_error_", "deceptive site ahead", "dangerous site ahead",
            "the site ahead contains", "attackers might be trying"))

    def _bypass_interstitial(self, sb):
        """Get past Chrome's cert-error ('Privacy error') / SafeBrowsing ('Dangerous site') pages."""
        self._ignore_certs(sb)
        d = sb.driver
        try:                                    # cert error: Chrome's hard-coded bypass phrase
            from selenium.webdriver.common.action_chains import ActionChains
            ActionChains(d).send_keys("thisisunsafe").perform()
        except Exception:
            pass
        for bid in ("details-button", "proceed-link"):   # cert + SafeBrowsing: Advanced -> Proceed
            try:
                el = d.find_element("id", bid)
                if el:
                    el.click()
            except Exception:
                pass

    # ── Cloudflare "Suspected Phishing" solve (SeleniumBase real-mouse) ──
    # challenge phrases that appear on the OUTER page (the Turnstile's own 'verify you are human' text is in
    # a cross-origin iframe get_page_source can't read, but the wrapper card text is on the outer page)
    _CF_PHRASES = ("suspected phishing", "reported for potential", "verification failed", "verify you are human",
                   "checking your browser", "needs to review the security", "one more step before you proceed",
                   "one more step", "before you proceed", "before you continue")

    def _has_cf_widget(self, sb) -> bool:
        """A VISIBLE Cloudflare Turnstile CHALLENGE is on the page (its 'verify you are human' text lives in
        a cross-origin iframe the page source can't read). Visible + sized ONLY — a solved/residual/hidden
        Turnstile element Cloudflare's bot-management leaves in the DOM must NOT false-positive as a gate
        (that made the walk bail on the real post-challenge page)."""
        try:
            return bool(sb.execute_script("""
              function vis(e){ if(!e) return false; var r=e.getBoundingClientRect();
                return e.offsetParent!==null && r.width>20 && r.height>20; }
              if(vis(document.querySelector('iframe[src*="challenges.cloudflare.com"],iframe[src*="turnstile"]'))) return true;
              return vis(document.querySelector('.cf-turnstile,#cf-turnstile'));
            """))
        except Exception:
            return False

    def _still_gated(self, sb) -> bool:
        """True while a Cloudflare gate (warning or challenge) is still on-screen."""
        try:
            t = (sb.get_title() or "").lower()
        except Exception:
            t = ""
        b = self._body(sb)
        if any(k in b for k in self._CF_PHRASES):
            return True
        return ("just a moment" in t or "attention required" in t or "one more step" in t
                or "before you proceed" in t)

    def _is_cf_gate(self, title, html, sb=None) -> bool:
        """A Cloudflare gate: the 'Suspected Phishing' WARNING or an interactive CHALLENGE ('Just a moment',
        'Attention Required', 'One more step before you proceed…' + a Turnstile widget)."""
        if X.is_cf_phish_warning(title, html):
            return True
        t = (title or "").lower()
        # match RENDERED/VISIBLE text, NOT the raw page source: Cloudflare keeps its hidden challenge-
        # template text in the DOM even AFTER the challenge is solved, so raw-html matching fired on the
        # real post-CF landing page and the walk bailed. get_text() only returns what's actually visible.
        b = self._body(sb) if sb is not None else (html or "").lower()
        if "just a moment" in t or "attention required" in t or "one more step" in t or "before you proceed" in t:
            return True
        if any(k in b for k in self._CF_PHRASES):
            return True
        return bool(sb is not None and self._has_cf_widget(sb))    # DOM backstop: a VISIBLE Turnstile only

    def _cf_gate_reason(self, title, html, sb) -> str:
        """Diagnostic: exactly WHY _is_cf_gate fired (which check matched) + a rendered-text snippet."""
        hits = []
        try:
            if X.is_cf_phish_warning(title, html):
                hits.append("phish-warning(html)")
        except Exception:
            pass
        t = (title or "").lower()
        for k in ("just a moment", "attention required", "one more step", "before you proceed"):
            if k in t:
                hits.append("title:" + k)
        try:
            b = self._body(sb) if sb is not None else ""
        except Exception:
            b = ""
        for k in self._CF_PHRASES:
            if k in b:
                hits.append("text:" + k)
        try:
            if self._has_cf_widget(sb):
                hits.append("visible-widget")
        except Exception:
            pass
        return (", ".join(hits) or "none?") + f" | title={title!r} | rendered={b[:160]!r}"

    def _solve_cf(self, sb) -> bool:
        """Clear a Cloudflare gate (warning OR challenge). Real-mouse Turnstile solve + retry."""
        for attempt in range(3):
            if self._cancel.is_set():
                return False
            # a plain 'Ignore & Proceed'/proceed link first (non-Turnstile variants / demo) — no mouse
            try:
                if sb.execute_script(_ADVANCE_JS):
                    self._wait(sb, 3)
                    if not self._still_gated(sb):
                        return True
            except Exception:
                pass
            try:
                sb.uc_gui_click_captcha()          # REAL OS-mouse click on the Turnstile checkbox
            except Exception:
                pass
            for _ in range(7):
                self._wait(sb, 2)
                if not self._still_gated(sb):
                    return True
                if self._bypass_enabled(sb):       # CF phishing-warning 'Ignore & Proceed' button
                    try:
                        sb.click("#bypass-button")
                    except Exception:
                        pass
                    self._wait(sb, 3)
                    if not self._still_gated(sb):
                        return True
                    break
            if "verification failed" in self._body(sb):   # token rejected server-side → fresh token
                self._log(f"  Cloudflare token rejected (attempt {attempt + 1}) — retrying…")
                try:
                    sb.uc_open_with_reconnect(self.url, reconnect_time=4)
                except Exception:
                    pass
                self._wait(sb, 2)
                continue
            if not self._still_gated(sb):
                return True
        # auto-solve exhausted — if it's an image/word challenge, hand to the human and WAIT for them
        return self._await_human_captcha(sb)

    # ── page primitives ──
    def _capture_step(self, sb, action, i):
        st = {"i": i, "action": action}
        html = ""
        try:
            st["url"] = sb.get_current_url()
        except Exception:
            st["url"] = self.url
        try:
            st["title"] = sb.get_title()
        except Exception:
            st["title"] = ""
        try:
            html = sb.get_page_source() or ""
        except Exception:
            html = ""
        try:
            st["forms"] = json.loads(sb.execute_script(_FORMS_JS) or "[]")
        except Exception:
            st["forms"] = []
        st["telegram"] = X.telegram_channels(html)
        st["challenge"] = X.detect_challenge(st.get("title"), html)
        st["screenshot"] = self._shot_b64(sb)
        return st, html

    def _fill(self, sb):
        try:
            return json.loads(sb.execute_script(_FILL_JS, _FAKE) or "[]")
        except Exception:
            return []

    def _submit(self, sb):
        try:
            return bool(sb.execute_script(_SUBMIT_JS))
        except Exception:
            return False

    def _close_extra_tabs(self, sb):
        """Close any popup/OAuth/new tab the walk spawned (e.g. a 'Sign in with Google' button or a
        target=_blank link) so only the detonation tab remains — stops stray Google/login tabs piling up."""
        try:
            d = sb.driver
            handles = d.window_handles
            if len(handles) <= 1:
                return
            main = self._main_handle if self._main_handle in handles else handles[0]
            for h in handles:
                if h == main:
                    continue
                try:
                    d.switch_to.window(h)
                    d.close()
                except Exception:
                    pass
            try:
                d.switch_to.window(main)
            except Exception:
                pass
        except Exception:
            pass

    # ── the detonation walk ──
    def _walk(self, sb):
        fill_count: dict[str, int] = {}      # url -> times we've filled+submitted (≤2 for re-prompting logins)
        adv_clicks: dict[str, dict] = {}     # url -> {button_text: times_clicked} — a few DISTINCT clicks/page
        timed_waited: set[str] = set()       # urls where we've already honoured a 'wait N seconds' timer
        cert_tried: set[str] = set()
        cf_tried: set[str] = set()
        for i in range(MAX_STEPS):
            if self._cancel.is_set():
                break
            self._close_extra_tabs(sb)          # reap any OAuth/popup tab the previous step spawned
            st, html = self._capture_step(sb, "load", i)

            # Chrome cert-error / SafeBrowsing interstitial → power through it (bad certs are the norm here)
            if self._is_interstitial(st.get("title"), html):
                if st.get("url") in cert_tried:
                    self.report["steps"].append(st)
                    self._log("  couldn't get past the browser interstitial — stopping.")
                    break
                cert_tried.add(st.get("url"))
                self._log(f"Step {i}: browser interstitial ('{st.get('title')}') — bypassing (phishing "
                          f"sites routinely have bad TLS certs)…")
                self._bypass_interstitial(sb)
                self._wait(sb, 3)
                continue

            self.report["steps"].append(st)
            self._html_parts.append(html)
            for t in st["telegram"]:
                if t not in self.report["exfil"]["telegram"]:
                    self.report["exfil"]["telegram"].append(t)
            for c in st["challenge"]:
                if c not in self.report["challenge"]:
                    self.report["challenge"].append(c)
            self._log(f"Step {i}: {st['url']} — \"{st['title']}\" — {len(st.get('forms', []))} form(s)"
                      + (f" — TELEGRAM exfil bot {st['telegram'][0]['bot_id']}" if st["telegram"] else ""))

            # Cloudflare gate (Suspected-Phishing WARNING or Just-a-moment/Attention-Required CHALLENGE)
            if self._is_cf_gate(st.get("title"), html, sb):
                if os.getenv("PHISH_CF_DIAG"):        # opt-in: why the gate fired (set PHISH_CF_DIAG=1 to debug)
                    self._log("  [diag] cf-gate reason: " + self._cf_gate_reason(st.get("title"), html, sb))
                if st.get("url") in cf_tried:
                    self._log("  still Cloudflare-gated after a solve attempt — stopping.")
                    break
                cf_tried.add(st.get("url"))
                if "turnstile" not in self.report["challenge"]:
                    self.report["challenge"].append("turnstile")
                self.report["cf_solving"] = True
                self._log("Cloudflare challenge/warning — solving (real-mouse Turnstile if needed). "
                          "DO NOT touch your mouse/keyboard (~30-60s).")
                try:
                    ok = self._solve_cf(sb)
                finally:
                    self.report["cf_solving"] = False   # never leave the 'don't touch mouse' banner stuck
                if ok:
                    self.report["cf_warning_cleared"] = True
                    self.report["cloudflare_bypass"] = {"solved": True, "via": "seleniumbase"}
                    self._log("[OK] Cloudflare cleared — waiting for the real page to render…")
                    # a bot-check (Cloudflare/SSO 'sso_reload') often reveals the REAL sign-in form on the SAME
                    # URL — forget this URL's prior fill/click memory so the now-visible form actually gets
                    # handled (else the walk thinks it already did this URL and stops), then let it render.
                    cur = st.get("url") or ""
                    fill_count.pop(cur, None)
                    adv_clicks.pop(cur, None)
                    timed_waited.discard(cur)
                    self._wait_for_form(sb, 8)
                    continue
                self.report["cloudflare_bypass"] = {"solved": False, "via": "seleniumbase"}
                self.report["handover_needed"] = True
                self._log("Couldn't solve Cloudflare — interact with the Chrome window directly, or 'Open in browser'.")
                break

            # fill FAKE creds into any form + submit. Once per URL normally, but a credential page that
            # RE-PROMPTS (the classic "password incorrect, enter again" harvester, or a login → login flow
            # on the same URL) gets a 2nd fill so the walk pushes through the whole process, not just once.
            url = st.get("url") or ""
            fc = fill_count.get(url, 0)
            has_pw_form = any(f.get("has_password") for f in st.get("forms", []))
            # keep the CLEAN login-page shot (captured at load, BEFORE any creds) as report evidence
            if has_pw_form and not self.report.get("login_screenshot"):
                self.report["login_screenshot"] = st.get("screenshot")
                self.report["login_url"] = url
            if fc == 0 or (fc < 2 and has_pw_form):
                fill_count[url] = fc + 1
                filled = self._fill(sb)
                if not filled and st.get("forms"):        # a form IS present but nothing filled → the login is
                    self._wait_for_form(sb, 5)            # still rendering (heavy MS/SSO clone). Give it a beat
                    filled = self._fill(sb)               # and retry, so the walk doesn't quit on a race.
                if filled:
                    kinds = {f.get("kind") for f in filled}
                    action = next((f.get("action") for f in st.get("forms", []) if f.get("action")), url)
                    off = bool(_host(action) and _host(action) != _host(url))
                    self._log(f"Step {i}: entered " + ", ".join(f"{f['kind']}={f['value']}" for f in filled)
                              + f"  ->  {action}" + ("  [!] OFF-SITE" if off else ""))
                    self._submit(sb)
                    # email-first login (MS SSO: email → Next → password) — WAIT for the password field to
                    # appear so the next loop fills it, instead of concluding the walk after just the email.
                    if "password" not in kinds:
                        self._wait_for_password(sb, 8)
                    else:
                        self._wait(sb, 3)
                    self.report["steps"].append({
                        "i": i, "action": "fill+submit", "filled_fields": filled, "creds_sent_to": action,
                        "off_site": off, "screenshot": self._shot_b64(sb),
                    })
                    for f in st.get("forms", []):
                        if f.get("action"):
                            self.report["exfil"]["form_actions"].append(f.get("action"))
                    continue

            # a fake 'are you human — please wait N seconds' timer gate: read the countdown, PAUSE for it,
            # THEN the advance click below lands on an enabled Continue (clicking early is a no-op).
            if url not in timed_waited:
                secs = self._timed_gate_seconds(sb, html)
                if secs:
                    timed_waited.add(url)
                    self._log(f"Step {i}: 'please wait {secs}s' human-check timer — pausing for it, then continuing…")
                    self._wait(sb, secs + 1.5)

            # click the best control to go DEEPER (lure CTA / dismiss a modal) — a few DISTINCT clicks per page
            # so it can dismiss a 'Close' overlay THEN click the real button underneath (priority-ranked in JS).
            counter = adv_clicks.setdefault(url, {})
            if sum(counter.values()) < 5:
                exhausted = [t for t, n in counter.items() if n >= 2]   # give up on a control after 2 tries
                try:
                    adv = sb.execute_script(_ADVANCE_JS, exhausted)
                except Exception:
                    adv = None
                if adv:
                    counter[adv] = counter.get(adv, 0) + 1
                    self._log(f"Step {i}: clicked '{adv[:50]}' to advance")
                    self._wait(sb, 3)
                    continue
            self._log("Nothing left to fill or click — stopping the walk.")
            break

    # ── async helpers run from the worker thread ──
    def _decloak(self):
        try:
            probes = asyncio.run(T.vantage_probe(self.url))
            mv = T.multi_vantage_verdict(probes)
            self.report["decloak"] = {"scanner": {}, "victim": {"url": self.url}, "cloaked": "no_diff",
                                      "vantages": probes, "multi_vantage": mv}
            self.report["cloaking"] = {"detected": bool(mv.get("cloaked")),
                                       "kind": "ip_geo_cloak" if mv.get("cloaked") else "none"}
            if mv.get("cloaked"):
                self.report["cloaking"]["ip_geo"] = True
                self._log("Decloak (multi-vantage): IP/geo CLOAKING likely — " + ", ".join(mv.get("diffs", [])))
            else:
                self._log(f"Decloak (multi-vantage): consistent across {mv.get('responded', 0)} vantage(s) "
                          f"— no IP/geo cloaking")
        except Exception:
            pass

    def _enrich(self):
        try:
            self.report["enrichment"] = asyncio.run(E.enrich(self.url))
        except Exception:
            self.report["enrichment"] = {}
        try:
            _merge_ip(self.report)
        except Exception:
            pass

    def _kit(self, victim_url):
        try:
            self.report["kit"] = asyncio.run(K.extract_kit(victim_url))
            for t in self.report["kit"].get("telegram", []):
                if t not in self.report["exfil"]["telegram"]:
                    self.report["exfil"]["telegram"].append(t)
        except Exception:
            self.report["kit"] = {}

    def _redirect_graph(self):
        """Build the redirect chain (link → link → final): server-side HTTP 3xx hops + the distinct
        pages the browser actually walked through (JS/meta redirects + multi-step flow)."""
        try:
            http_hops = asyncio.run(_http_redirect_chain(self.url))
        except Exception:
            http_hops = []
        hops: list[dict] = []

        def _add(url, status=None, via="page"):
            if not url:
                return
            if hops and _urlkey(hops[-1]["url"]) == _urlkey(url):
                if status and not hops[-1].get("status"):
                    hops[-1]["status"] = status
                return
            hops.append({"url": url, "status": status, "via": via})

        for h in http_hops:
            _add(h["url"], h.get("status"), h.get("via"))
        for st in self.report.get("steps", []):
            if st.get("url"):
                _add(st["url"], None, "page")
        if len(hops) > 1:
            hops[-1]["via"] = "final"
        self.report["redirects"] = hops

    def _finalize_iocs(self):
        joined = "\n".join(self._html_parts)
        try:
            self.report["iocs"] = X.iocs(joined, self.url,
                                         extra_urls=[a for a in self.report["exfil"]["form_actions"] if a])
            self.report["iocs"]["brands_impersonated"] = X.brand_hits(*[s.get("title", "") for s in self.report["steps"]])
        except Exception:
            pass
        try:
            self.report["indicators"] = I.analyze_source(joined, self.url)
        except Exception:
            pass
        try:  # broad scam leads on the fake-site source (callback phone, wallet, telegram/whatsapp handle)
            self.report["scam_signals"] = X.scam_signals(joined)
        except Exception:
            pass

    # ── main entry (sync, runs in a worker thread) ──
    def run(self):
        t0 = self.report["started_at"]
        try:
            self.state = "running"
            self._log(f"Detonating {self.url}  (engine: SeleniumBase / Chrome UC)")
            self._decloak()
            self._log("Opening Chrome (undetected)…")
            from seleniumbase import SB
            # NOT incognito: incognito forces Chrome's HTTPS-First mode, which blocks HTTP-only phishing
            # sites with a "This site doesn't support a secure connection" wall. SeleniumBase already gives
            # each run a fresh temp profile, so isolation is preserved without the HTTPS-First warning.
            with SB(uc=True, headless=False, locale="en") as sb:
                self._sb = sb
                self._ignore_certs(sb)            # accept bad TLS certs up front (before first nav)
                self._log("Loading the page…")
                try:
                    sb.uc_open_with_reconnect(self.url, reconnect_time=4)
                except Exception:
                    try:
                        sb.open(self.url)
                    except Exception:
                        self._log("(page slow to load — continuing with whatever rendered)")
                self._wait(sb, 2)
                try:
                    self._main_handle = sb.driver.current_window_handle
                except Exception:
                    self._main_handle = None
                self._walk(sb)
                # point the report's victim view + kit-hunt at the reached (real) phish
                try:
                    victim_url = sb.get_current_url()
                except Exception:
                    victim_url = self.url
                if isinstance(self.report.get("decloak"), dict):
                    self.report["decloak"].setdefault("victim", {})["url"] = victim_url
                # SSRF guard: the walk may have been steered (redirect/click) to an internal host; the kit
                # hunt re-fetches this URL server-side + stores bodies, so only chase a PUBLIC target.
                kit_target = victim_url
                try:
                    ok, _why = G.check_target(victim_url)
                except Exception:
                    ok = False
                if not ok:
                    kit_target = self.url
                    self._log("  (reached host isn't public — kit hunt uses the original URL, not the redirected one)")
                self._finalize_iocs()
            self._sb = None
            self._redirect_graph()
            self._log("Enriching — domain age, hosting, blocklists…")
            self._enrich()
            self._log("Hunting the phishing kit (open dir / archive / source / cred logs)…")
            self._kit(kit_target)
            self.report["verdict"] = _verdict(self.report)
            self.report["elapsed"] = round(time.time() - t0, 1)
            self.state = "done"
            self._log(f"Done — {self.report['verdict']['label']} (score {self.report['verdict']['score']}).")
        except Exception as exc:
            self.report["error"] = f"{type(exc).__name__}: {exc}"[:200]
            self.state = "error"
        finally:
            self._sb = None
            self.report.setdefault("verdict", {"label": "incomplete", "score": 0, "reasons": ["scan did not finish"]})
            try:
                _sess._persist(self)
                _sess._evict()
            except Exception:
                pass


def create(url: str) -> SBSession:
    s = SBSession(url)
    with _sess.SESSIONS_LOCK:                 # register so session.get()/api see it (thread-safe)
        _sess.SESSIONS[s.id] = s
    s._thread = threading.Thread(target=s.run, name=f"sb-{s.id}", daemon=True)
    s._thread.start()
    return s
