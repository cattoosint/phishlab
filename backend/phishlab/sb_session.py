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
import threading
import time
import uuid
from io import BytesIO

from . import enrich as E
from . import extract as X
from . import indicators as I
from . import kit as K
from . import session as _sess
from . import tracker as T
from .sandbox import _host, _merge_ip, _verdict

try:
    from PIL import Image
except Exception:                       # Pillow ships with seleniumbase; fall back to raw PNG if absent
    Image = None

MAX_STEPS = int(os.getenv("PHISH_SB_MAX_STEPS") or "8")
_FAKE = {"user": "soc-rev-8842", "email": "soc.rev8842@example.com", "pw": "Nv3r-R3al!P4ss",
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
 else if(t==='email'||/email|e-mail/.test(n))setv(e,fake.email,'email');
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

# broad "click past a NOTICE/ADVISORY/interstitial" control (SG scam advisory, "proceed anyway", etc.)
_ADVANCE_JS = r"""
var rx=/proceed|continue|visit|i understand|acknowledge|go to site|enter site|dismiss|ignore & proceed|ignore and proceed|at your own risk|agree|accept|confirm|yes[, ]|next|verify/i;
var els=document.querySelectorAll('a,button,[role=button],input[type=button],input[type=submit]');
for(var i=0;i<els.length;i++){var e=els[i],t=(e.innerText||e.value||e.textContent||'').trim();
 if(t&&rx.test(t)&&e.offsetParent!==null){e.click();return t.slice(0,50);}}
return null;
"""


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
    def _still_gated(self, sb) -> bool:
        """True while a Cloudflare gate (warning or challenge) is still on-screen."""
        try:
            t = (sb.get_title() or "").lower()
        except Exception:
            t = ""
        b = self._body(sb)
        return ("suspected phishing" in b or "reported for potential" in b or "verification failed" in b
                or "just a moment" in t or "attention required" in t or "verify you are human" in b
                or "checking your browser" in b or "needs to review the security" in b)

    def _is_cf_gate(self, title, html) -> bool:
        """A Cloudflare gate: the 'Suspected Phishing' WARNING or a 'Just a moment'/'Attention Required'
        interactive CHALLENGE. (Matches visible challenge text/title, not just injected CF scripts.)"""
        if X.is_cf_phish_warning(title, html):
            return True
        t = (title or "").lower()
        b = (html or "").lower()
        if "just a moment" in t or "attention required" in t:
            return True
        return any(k in b for k in ("verify you are human", "checking your browser",
                                    "needs to review the security of your connection"))

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
        return not self._still_gated(sb)

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

    # ── the detonation walk ──
    def _walk(self, sb):
        seen_fill: set[str] = set()
        advanced: set[str] = set()
        cert_tried: set[str] = set()
        cf_tried: set[str] = set()
        for i in range(MAX_STEPS):
            if self._cancel.is_set():
                break
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
            if self._is_cf_gate(st.get("title"), html):
                if st.get("url") in cf_tried:
                    self._log("  still Cloudflare-gated after a solve attempt — stopping.")
                    break
                cf_tried.add(st.get("url"))
                if "turnstile" not in self.report["challenge"]:
                    self.report["challenge"].append("turnstile")
                self.report["cf_solving"] = True
                self._log("Cloudflare challenge/warning — solving (real-mouse Turnstile if needed). "
                          "DO NOT touch your mouse/keyboard (~30-60s).")
                ok = self._solve_cf(sb)
                self.report["cf_solving"] = False
                if ok:
                    self.report["cf_warning_cleared"] = True
                    self.report["cloudflare_bypass"] = {"solved": True, "via": "seleniumbase"}
                    self._log("[OK] Cloudflare cleared — continuing.")
                    self._wait(sb, 1)
                    continue
                self.report["cloudflare_bypass"] = {"solved": False, "via": "seleniumbase"}
                self.report["handover_needed"] = True
                self._log("Couldn't solve Cloudflare — interact with the Chrome window directly, or 'Open in browser'.")
                break

            # fill FAKE creds into any form + submit (once per URL)
            url = st.get("url") or ""
            if url not in seen_fill:
                seen_fill.add(url)
                filled = self._fill(sb)
                if filled:
                    action = next((f.get("action") for f in st.get("forms", []) if f.get("action")), url)
                    off = bool(_host(action) and _host(action) != _host(url))
                    self._log(f"Step {i}: entered " + ", ".join(f"{f['kind']}={f['value']}" for f in filled)
                              + f"  ->  {action}" + ("  [!] OFF-SITE" if off else ""))
                    self._submit(sb)
                    self._wait(sb, 3)
                    self.report["steps"].append({
                        "i": i, "action": "fill+submit", "filled_fields": filled, "creds_sent_to": action,
                        "off_site": off, "screenshot": self._shot_b64(sb),
                    })
                    for f in st.get("forms", []):
                        if f.get("action"):
                            self.report["exfil"]["form_actions"].append(f.get("action"))
                    continue

            # no form — click past a notice/advisory/interstitial ("proceed anyway"), once per URL
            if url not in advanced:
                advanced.add(url)
                try:
                    adv = sb.execute_script(_ADVANCE_JS)
                except Exception:
                    adv = None
                if adv:
                    self._log(f"Step {i}: clicked '{adv}' to continue past the page")
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

    # ── main entry (sync, runs in a worker thread) ──
    def run(self):
        t0 = self.report["started_at"]
        try:
            self.state = "running"
            self._log(f"Detonating {self.url}  (engine: SeleniumBase / Chrome UC)")
            self._decloak()
            self._log("Opening Chrome (undetected)…")
            from seleniumbase import SB
            with SB(uc=True, headless=False, locale="en", incognito=True) as sb:
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
                self._walk(sb)
                # point the report's victim view + kit-hunt at the reached (real) phish
                try:
                    victim_url = sb.get_current_url()
                except Exception:
                    victim_url = self.url
                if isinstance(self.report.get("decloak"), dict):
                    self.report["decloak"].setdefault("victim", {})["url"] = victim_url
                self._finalize_iocs()
            self._sb = None
            self._log("Enriching — domain age, hosting, blocklists…")
            self._enrich()
            self._log("Hunting the phishing kit (open dir / archive / source / cred logs)…")
            self._kit(victim_url)
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
    _sess.SESSIONS[s.id] = s                 # register so session.get()/api see it
    s._thread = threading.Thread(target=s.run, name=f"sb-{s.id}", daemon=True)
    s._thread.start()
    return s
