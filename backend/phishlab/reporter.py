"""phishlab/reporter.py — human-assisted abuse reporting to VirusTotal / Hybrid Analysis / FortiGuard.

Once a URL (or attachment) is confirmed phishing, the analyst wants a PROOF artifact from the public
scanners: the actual VirusTotal detection page (58/70, hash, timestamp, vendor breakdown), the Hybrid
Analysis verdict, the FortiGuard category. Their APIs return JSON, not a picture of the page — so this
drives the REAL site in a SeleniumBase/Chrome window (the same engine the detonation uses) and screenshots
the rendered results.

Model (per the analyst's spec):
  * PhishLab opens the right page and BEST-EFFORT pre-fills the URL / uploads the file.
  * A BASIC checkbox CAPTCHA (Cloudflare Turnstile / reCAPTCHA / hCaptcha checkbox) is auto-solved with a
    real OS-mouse click (uc_gui_click_captcha). An IMAGE/WORD challenge is left to the HUMAN, who also does
    the final submit — the live Chrome window is on the desktop; frames stream into the app meanwhile.
  * When the results render (auto-detected) OR the analyst clicks "Capture", the engine screenshots the
    page, SAVES the PNG for download/copy, and best-effort extracts the on-page score/hash/timestamp/vendors
    via a shadow-DOM-piercing deep-text scan (VT's GUI is a web-component SPA). The screenshot is the
    deliverable; the parsed fields are a bonus and never block it.

Runs the sync SeleniumBase driver in a WORKER THREAD and registers in session.SESSIONS, so the existing
/api/session/{sid} + /frame endpoints serve its state + live frame with no new plumbing.
"""
from __future__ import annotations

import base64
import os
import re
import threading
import time
import uuid
import hashlib
from io import BytesIO

from . import net_guard as G
from . import session as _sess

try:
    from PIL import Image
except Exception:
    Image = None

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reports")
HUMAN_TIMEOUT = int(os.getenv("PHISH_REPORT_TIMEOUT") or "600")     # max wait for the human to finish (s)

# flat log of every scanner capture (newest last) so the detonation report's evidence gallery can show the
# latest VT/HA/FortiGuard screenshot per service. File reports carry the ACTUAL file hashes (not scraped).
REPORTS_LOG: list[dict] = []
_LOG_CAP = 60


def _norm_url(u: str) -> str:
    return (u or "").split("#")[0].rstrip("/").lower()


def recent_reports(max_age_s: int = 3600) -> list[dict]:
    """Latest capture per service within max_age_s — the VirusTotal / FortiGuard / Hybrid Analysis columns."""
    cutoff = 0.0
    try:
        cutoff = REPORTS_LOG[-1]["at"] - max_age_s if REPORTS_LOG else 0.0
    except Exception:
        cutoff = 0.0
    latest: dict[str, dict] = {}
    for e in REPORTS_LOG:
        if e.get("at", 0) >= cutoff:
            latest[e["service"]] = e          # later entries overwrite → newest per service
    order = {"virustotal": 0, "hybrid": 1, "fortiguard": 2}
    return sorted(latest.values(), key=lambda e: order.get(e["service"], 9))

SERVICES: dict[str, dict] = {
    "virustotal": {
        "label": "VirusTotal",
        "url_page": "https://www.virustotal.com/gui/home/url",
        "upload_page": "https://www.virustotal.com/gui/home/upload",
        "supports_file": True,
        # markers that the RESULTS page has rendered (deep-text, lowercased)
        "ready": ("security vendors", "no security vendors", "community score"),
    },
    "hybrid": {
        "label": "Hybrid Analysis",
        "url_page": "https://www.hybrid-analysis.com/",
        "upload_page": "https://www.hybrid-analysis.com/",
        "supports_file": True,
        "ready": ("threat score", "malicious", "no specific threat", "verdict"),
    },
    "fortiguard": {
        "label": "FortiGuard Web Filter",
        "url_page": "https://www.fortiguard.com/webfilter",
        "upload_page": None,
        "supports_file": False,
        "ready": ("category", "url is rated", "rating", "the requested url"),
    },
}


# ── deep (shadow-DOM-piercing) helpers, run in the page ──────────────────────────
# collect every <input>/<textarea> across open shadow roots so we can reach VT's web-component search box
_DEEP_INPUTS_JS = r"""
function walk(root, acc){
  try{ root.querySelectorAll('input,textarea').forEach(function(e){acc.push(e);}); }catch(_){ }
  try{ root.querySelectorAll('*').forEach(function(e){ if(e.shadowRoot) walk(e.shadowRoot, acc); }); }catch(_){ }
  return acc;
}
var els = walk(document, []);
function vis(e){ try{ var r=e.getBoundingClientRect(); return r.width>0&&r.height>0&&e.offsetParent!==null; }catch(_){ return false; } }
function score(e){
  var t=(e.type||'').toLowerCase();
  if(['hidden','password','checkbox','radio','submit','button','file','image','reset'].indexOf(t)>=0) return -1;
  var n=((e.name||'')+' '+(e.id||'')+' '+(e.placeholder||'')+' '+(e.getAttribute('aria-label')||'')).toLowerCase();
  var s=0;
  if(vis(e)) s+=5;
  if(/url|search|scan|address|link|website|domain/.test(n)) s+=4;
  if(t==='url'||t==='search') s+=2;
  if(t==='text'||t===''){ s+=1; }
  return s;
}
var best=null, bestS=-1;
for(var i=0;i<els.length;i++){ var s=score(els[i]); if(s>bestS){ bestS=s; best=els[i]; } }
if(!best||bestS<0) return false;
try{
  best.focus(); best.value=arguments[0];
  best.dispatchEvent(new Event('input',{bubbles:true}));
  best.dispatchEvent(new Event('change',{bubbles:true}));
  ['keydown','keypress','keyup'].forEach(function(k){
    best.dispatchEvent(new KeyboardEvent(k,{bubbles:true,key:'Enter',code:'Enter',keyCode:13,which:13}));
  });
  return true;
}catch(_){ return false; }
"""

# deep-find the FIRST <input type=file> across shadow roots, un-hide it, and RETURN the element so Selenium
# can send_keys() the path. VT's upload input lives inside a web-component shadow root (hidden by default).
_FIND_FILE_INPUT_JS = r"""
function walk(root){
  var f=root.querySelector('input[type=file]'); if(f) return f;
  var els=root.querySelectorAll('*');
  for(var i=0;i<els.length;i++){ if(els[i].shadowRoot){ var r=walk(els[i].shadowRoot); if(r) return r; } }
  return null;
}
var f=walk(document);
if(f){ try{ f.style.display='block'; f.style.visibility='visible'; f.style.opacity=1;
            f.removeAttribute('hidden'); f.style.width='1px'; f.style.height='1px'; }catch(_){} }
return f;
"""

# click a 'Confirm upload' / 'Upload file' control (VT shows one for a known-hash file), across shadow roots
_CONFIRM_UPLOAD_JS = r"""
function walk(root, acc){
  try{ root.querySelectorAll('button,[role=button],vt-ui-button,input[type=submit],a').forEach(function(e){acc.push(e);}); }catch(_){ }
  try{ root.querySelectorAll('*').forEach(function(e){ if(e.shadowRoot) walk(e.shadowRoot, acc); }); }catch(_){ }
  return acc;
}
var rx=/confirm upload|upload file|reanalyz|analyse file|analyze file|proceed|continue/i;
var els=walk(document,[]);
for(var i=0;i<els.length;i++){ var e=els[i], t=(e.innerText||e.textContent||e.value||'').trim();
  try{ if(t&&rx.test(t)&&e.offsetParent!==null){ e.click(); return t.slice(0,40); } }catch(_){} }
return null;
"""

# whole rendered text across shadow roots — for robust field extraction without brittle selectors.
# NB: start from document.body, NOT document — `document.innerText` is undefined, so starting at the
# document node captured NOTHING on a plain-DOM page (FortiGuard) and only shadow-root text elsewhere.
_DEEP_TEXT_JS = r"""
function txt(root){
  var t='';
  try{ t += (root.innerText||root.textContent||''); }catch(_){ }
  try{ root.querySelectorAll('*').forEach(function(e){ if(e.shadowRoot) t += '\n'+txt(e.shadowRoot); }); }catch(_){ }
  return t;
}
return txt(document.body||document.documentElement||document);
"""

# a "click the submit/scan/search button" fallback if pressing Enter didn't fire the search
_DEEP_SUBMIT_JS = r"""
function walk(root, acc){
  try{ root.querySelectorAll('button,[role=button],input[type=submit],a').forEach(function(e){acc.push(e);}); }catch(_){ }
  try{ root.querySelectorAll('*').forEach(function(e){ if(e.shadowRoot) walk(e.shadowRoot, acc); }); }catch(_){ }
  return acc;
}
var rx=/\b(scan|search|submit|lookup|check|rate|analy[sz]e|go)\b/i;  // \b so 'Research' nav isn't matched
var els=walk(document,[]);
for(var i=0;i<els.length;i++){ var e=els[i], t=(e.innerText||e.value||e.getAttribute('aria-label')||'').trim();
  try{ if(t&&rx.test(t)&&e.offsetParent!==null){ e.click(); return t.slice(0,40); } }catch(_){ }
}
return null;
"""

_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.I)
# "58/70 security vendors" or "58 / 70 security vendors flagged"
_VENDOR_RE = re.compile(r"(\d{1,3})\s*/\s*(\d{1,3})\s+security\s+vendors", re.I)


def _extract_fields(service: str, text: str, url: str) -> dict:
    """Best-effort scrape of the on-page proof fields from the deep-text dump. Never raises."""
    out: dict = {}
    t = text or ""
    try:
        m = _VENDOR_RE.search(t)
        if m:
            out["detected"] = int(m.group(1))
            out["total"] = int(m.group(2))
            out["score"] = f"{m.group(1)}/{m.group(2)}"
        for label, rx in (("sha256", _SHA256_RE), ("sha1", _SHA1_RE), ("md5", _MD5_RE)):
            hm = rx.search(t)
            if hm:
                out[label] = hm.group(0).lower()
        # "Last Analysis Date" / "N minutes ago" style timestamps VT/HA show
        tm = re.search(r"(last analysis date|analysis date|analyzed|submitted)\D{0,20}"
                       r"(\d[\d:\- ]{6,}|\d+\s+\w+\s+ago)", t, re.I)
        if tm:
            out["analyzed"] = tm.group(2).strip()
        # FortiGuard category line: "Category: Phishing"
        cm = re.search(r"category\s*[:\-]?\s*([A-Za-z][A-Za-z /&,+-]{2,40})", t, re.I)
        if service == "fortiguard" and cm:
            out["category"] = cm.group(1).strip()
    except Exception:
        pass
    return out


def _to_jpeg(png, q=75):
    if not png or Image is None:
        return png
    try:
        im = Image.open(BytesIO(png)).convert("RGB")
        buf = BytesIO()
        im.save(buf, "JPEG", quality=q)
        return buf.getvalue()
    except Exception:
        return png


class ReportSession:
    """A live human-assisted reporting session. Public surface mirrors session.Session / SBSession so the
    existing /api/session/{sid} + /frame endpoints serve it unchanged."""

    def __init__(self, service: str, url: str | None = None,
                 file_bytes: bytes | None = None, file_name: str | None = None):
        self.id = uuid.uuid4().hex[:12]
        self.service = service
        self.url = url
        self.file_bytes = file_bytes
        self.file_name = file_name
        # the hashes of the ACTUAL file (computed from the bytes — NOT scraped off the scanner page)
        self.file_hashes = {} if not file_bytes else {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
        }
        cfg = SERVICES[service]
        self.state = "starting"     # starting|loading|awaiting_human|ready|capturing|done|error|cancelled
        self.report = {
            "kind": "report", "service": service, "service_label": cfg["label"],
            "target": url or file_name or "", "target_kind": "file" if file_bytes else "url",
            "file_hashes": self.file_hashes, "started_at": time.time(), "narration": [],
            "human_needed": None,   # None|'captcha'|'submit'
            "result": {}, "shot_url": None, "permalink": None, "captured_at": None, "engine": "seleniumbase",
        }
        self.latest_frame: bytes | None = None
        self.viewport = {"width": 1280, "height": 720}
        self.paused = False
        self._cancel = threading.Event()
        self._capture_now = threading.Event()
        self._sb = None
        self._thread: threading.Thread | None = None

    # ── public surface ──
    def _log(self, m):
        self.report["narration"].append(m)

    def snapshot_state(self) -> dict:
        return {"id": self.id, "state": self.state, "paused": False, "report": self.report,
                "has_frame": self.latest_frame is not None, "viewport": self.viewport,
                "engine": "seleniumbase", "kind": "report"}

    async def forward(self, ev: dict):
        return   # interact with the real Chrome window directly

    def request_takeover(self):
        self._log("A real Chrome window is open on the desktop — solve any image CAPTCHA / submit there.")

    def resume(self):
        pass

    def capture(self):
        """Analyst pressed 'Capture results' — screenshot + extract on the next loop tick."""
        self._capture_now.set()

    def cancel(self):
        if self.state in ("done", "error", "cancelled"):
            return
        self.state = "cancelled"
        self._cancel.set()
        self._log("Reporting cancelled by the analyst.")

    # ── screenshot streaming ──
    def _shot_png(self, sb):
        try:
            return sb.driver.get_screenshot_as_png()
        except Exception:
            return None

    def _shot(self, sb):
        jpg = _to_jpeg(self._shot_png(sb))
        if jpg:
            self.latest_frame = jpg
        return jpg

    def _wait(self, sb, secs):
        end = time.time() + secs
        while time.time() < end:
            if self._cancel.is_set():
                return
            time.sleep(0.4)
            self._shot(sb)

    def _deep_text(self, sb) -> str:
        try:
            return (sb.execute_script(_DEEP_TEXT_JS) or "").lower()
        except Exception:
            return ""

    def _still_captcha(self, sb) -> bool:
        b = self._deep_text(sb)
        t = ""
        try:
            t = (sb.get_title() or "").lower()
        except Exception:
            pass
        return ("just a moment" in t or "attention required" in t
                or "verify you are human" in b or "checking your browser" in b
                or "select all images" in b or "i'm not a robot" in b)

    def _try_basic_captcha(self, sb) -> None:
        """Auto-solve a BASIC checkbox CAPTCHA (real OS-mouse). Image/word grids are left to the human."""
        try:
            self.report["cf_solving"] = True
            self._log("Basic CAPTCHA present — attempting a checkbox solve. DON'T touch the mouse (~15s).")
            sb.uc_gui_click_captcha()
            self._wait(sb, 4)
        except Exception:
            pass
        finally:
            self.report["cf_solving"] = False

    # ── submission per service ──
    def _navigate_and_prefill(self, sb) -> None:
        cfg = SERVICES[self.service]
        # VirusTotal FILE report: try the file's HASH report first — if VT already has the file it shows the
        # verdict instantly (no upload, no CAPTCHA). Most phishing attachments are already known.
        if self.file_bytes and self.service == "virustotal" and self.file_hashes.get("sha256"):
            if self._vt_file_by_hash(sb):
                return
        page = cfg["upload_page"] if (self.file_bytes and cfg.get("supports_file")) else cfg["url_page"]
        self.state = "loading"
        self._log(f"Opening {cfg['label']} — {page}")
        try:
            sb.uc_open_with_reconnect(page, reconnect_time=5)
        except Exception:
            try:
                sb.open(page)
            except Exception:
                self._log("(page slow to load — continuing)")
        self._wait(sb, 3)
        if self._still_captcha(sb):
            self._try_basic_captcha(sb)

        if self.file_bytes and cfg.get("supports_file"):
            self._prefill_file(sb)
        elif self.url:
            self._prefill_url(sb)

    def _vt_file_by_hash(self, sb) -> bool:
        """Open VirusTotal's report for the file's SHA256 directly. True if VT KNOWS the file (report showing)
        — no upload needed; False if unknown (caller falls back to the upload form)."""
        h = self.file_hashes["sha256"]
        self.state = "loading"
        self._log(f"VirusTotal: looking up the file by SHA256 (skips upload if it's already known) — {h}")
        try:
            sb.uc_open_with_reconnect(f"https://www.virustotal.com/gui/file/{h}", reconnect_time=5)
        except Exception:
            try:
                sb.open(f"https://www.virustotal.com/gui/file/{h}")
            except Exception:
                return False
        self._wait(sb, 4)
        if self._still_captcha(sb):
            self._try_basic_captcha(sb)
            self._wait(sb, 2)
        b = self._deep_text(sb)
        if bool(_VENDOR_RE.search(b)) or "no security vendors flagged" in b:
            self._log("VirusTotal already has this file — showing its report.")
            return True
        self._log("VirusTotal hasn't seen this file — uploading it instead.")
        return False

    def _prefill_url(self, sb) -> None:
        ok = False
        try:
            ok = bool(sb.execute_script(_DEEP_INPUTS_JS, self.url))
        except Exception:
            ok = False
        if ok:
            self._log(f"Pre-filled the URL and pressed search: {self.url}")
            self._wait(sb, 3)
            # if Enter didn't fire the search, try clicking a scan/search button
            try:
                clicked = sb.execute_script(_DEEP_SUBMIT_JS)
                if clicked:
                    self._log(f"Clicked '{clicked}' to submit.")
                    self._wait(sb, 3)
            except Exception:
                pass
        else:
            self.report["human_needed"] = "submit"
            self._log(f"Couldn't reach the input automatically — PASTE this URL and submit in the window: {self.url}")

    def _prefill_file(self, sb) -> None:
        """Write the attachment to a temp file and hand it to the page's <input type=file>."""
        import tempfile
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", self.file_name or "sample.bin")[:80] or "sample.bin"
        tmp = os.path.join(tempfile.gettempdir(), f"pl_report_{self.id}_{safe}")
        try:
            with open(tmp, "wb") as f:
                f.write(self.file_bytes or b"")
        except Exception:
            self.report["human_needed"] = "submit"
            self._log("Couldn't stage the file — upload it manually in the window.")
            return
        self.report["staged_file"] = tmp
        el = None
        try:
            el = sb.driver.execute_script(_FIND_FILE_INPUT_JS)     # deep-find + un-hide + return the element
        except Exception:
            el = None
        if el is not None:
            try:
                el.send_keys(tmp)                                  # hand the OS path to the file input
                self._log(f"Selected {safe} in the upload form.")
                self._wait(sb, 3)
                try:
                    clicked = sb.execute_script(_CONFIRM_UPLOAD_JS)   # VT shows 'Confirm upload' for a known file
                    if clicked:
                        self._log(f"Clicked '{clicked}' to upload.")
                        self._wait(sb, 3)
                except Exception:
                    pass
                return
            except Exception as exc:
                self._log(f"Auto-select failed ({type(exc).__name__}).")
        # couldn't attach automatically → give the analyst the exact path to pick manually
        self.report["human_needed"] = "submit"
        self._log(f"Couldn't auto-attach — in the window click 'Choose file' and pick:  {tmp}")

    # ── results detection + capture ──
    def _browser_alive(self, sb) -> bool:
        try:
            return len(sb.driver.window_handles) > 0
        except Exception:
            return False

    def _results_ready(self, sb) -> bool:
        b = self._deep_text(sb)
        if not b:
            return False
        # the scanner is still working — DON'T grab the spinner/queue page (VT shows the 'Security vendors'
        # header while 'Analysis in progress' is still up, which used to trigger a premature capture)
        if any(k in b for k in ("analysis in progress", "queued for analysis", "in the queue",
                                "your file is queued", "still being analyzed", "we are analyzing")):
            return False
        if self.service == "virustotal":                       # a REAL verdict: 'N/M security vendors' or none
            return bool(_VENDOR_RE.search(b)) or "no security vendors flagged" in b
        if self.service == "hybrid":
            return any(k in b for k in ("threat score", "no specific threat", "malicious activity", "verdict"))
        return any(k in b for k in SERVICES[self.service]["ready"])

    def _do_capture(self, sb, reason: str) -> None:
        self.state = "capturing"
        self._log(f"Capturing results ({reason})…")
        os.makedirs(REPORTS_DIR, exist_ok=True)
        png = self._shot_png(sb)
        path = os.path.join(REPORTS_DIR, f"{self.service}_{self.id}.png")
        try:
            if png:
                with open(path, "wb") as f:
                    f.write(png)
                self.report["shot_url"] = f"/api/report/{self.id}/shot"
                self.report["shot_path"] = path
        except Exception:
            pass
        # keep the streamed frame in sync with what we saved
        jpg = _to_jpeg(png)
        if jpg:
            self.latest_frame = jpg
        try:
            self.report["result"] = _extract_fields(self.service, sb.execute_script(_DEEP_TEXT_JS) or "", self.url or "")
        except Exception:
            self.report["result"] = {}
        # for a FILE report, the hash is the FILE's OWN (from its bytes), NOT whatever 32/64-hex string
        # happened to be scraped off the scanner page.
        if self.file_hashes:
            self.report["result"].update(self.file_hashes)
        try:
            self.report["permalink"] = sb.get_current_url()      # the VirusTotal/HA/FortiGuard report link
        except Exception:
            pass
        self.report["captured_at"] = time.time()
        r = self.report["result"]
        # append to the flat log so the detonation report's evidence gallery shows the latest per service
        if self.report.get("shot_url"):
            REPORTS_LOG.append({
                "service": self.service, "service_label": self.report["service_label"],
                "shot_url": self.report["shot_url"], "permalink": self.report.get("permalink"),
                "target": self.report["target"], "target_kind": self.report["target_kind"],
                "file_hashes": self.file_hashes, "result": r, "at": self.report["captured_at"], "id": self.id})
            del REPORTS_LOG[:-_LOG_CAP]
        self._log("Captured. " + (f"{r.get('score','')} · {r.get('sha256','') or r.get('md5','')}".strip(" ·")
                                  or "screenshot saved — open it to read the score/hash."))

    def _await_and_capture(self, sb) -> None:
        self.state = "awaiting_human"
        self._log("Solve any image/word CAPTCHA and submit in the Chrome window. I'll capture automatically "
                  "when the results render — or press 'Capture results' any time.")
        deadline = time.time() + HUMAN_TIMEOUT
        ready_hits = 0
        while time.time() < deadline:
            if self._cancel.is_set():
                return
            if not self._browser_alive(sb):                # analyst closed the Chrome window → end cleanly
                self.report["browser_closed"] = True
                self.report["human_needed"] = None
                self._log("The Chrome window was closed — ending the report (nothing captured).")
                return
            if self._capture_now.is_set():
                self._do_capture(sb, "analyst pressed Capture")
                return
            self._shot(sb)
            try:
                if self._results_ready(sb):
                    ready_hits += 1
                    if self.state != "ready":
                        self.state = "ready"
                        self.report["human_needed"] = None
                        self._log("Results detected on the page — capturing shortly (or press Capture now).")
                    if ready_hits >= 3:          # stable for ~3 ticks so we don't grab a half-rendered page
                        self._do_capture(sb, "results auto-detected")
                        return
                else:
                    ready_hits = 0
            except Exception:
                pass
            time.sleep(1.2)
        # timed out waiting — capture whatever's on screen as best-effort proof
        self._do_capture(sb, "timeout — best-effort capture")

    # ── main entry (sync worker thread) ──
    def run(self):
        try:
            self.state = "running"
            self._log(f"Reporting {self.report['target']} to {self.report['service_label']} "
                      f"(engine: SeleniumBase / Chrome).")
            from seleniumbase import SB
            with SB(uc=True, headless=False, locale="en") as sb:
                self._sb = sb
                self._navigate_and_prefill(sb)
                if self._cancel.is_set():
                    return
                self._await_and_capture(sb)
            self._sb = None
            if self.state not in ("cancelled", "error"):
                self.state = "done"
                self.report["elapsed"] = round(time.time() - self.report["started_at"], 1)
                self._log(f"Done — {self.report['service_label']} report captured.")
        except Exception as exc:
            self.report["error"] = f"{type(exc).__name__}: {exc}"[:200]
            self.state = "error"
            self._log(f"Reporting failed — {self.report['error']}")
        finally:
            self._sb = None
            self.report.setdefault("result", {})
            try:
                _sess._persist(self)
                _sess._evict()
            except Exception:
                pass


def _guard_url(url: str) -> str | None:
    """The report target is submitted to a 3rd-party scanner (no fetch here), but keep the same public-only
    discipline so we never hand an internal/SSRF host to an external service."""
    ok, why = G.check_target(url)
    return None if ok else why


def create_url(service: str, url: str) -> ReportSession:
    s = ReportSession(service, url=url)
    with _sess.SESSIONS_LOCK:
        _sess.SESSIONS[s.id] = s
    s._thread = threading.Thread(target=s.run, name=f"report-{s.id}", daemon=True)
    s._thread.start()
    return s


def create_file(service: str, file_bytes: bytes, file_name: str) -> ReportSession:
    s = ReportSession(service, file_bytes=file_bytes, file_name=file_name)
    with _sess.SESSIONS_LOCK:
        _sess.SESSIONS[s.id] = s
    s._thread = threading.Thread(target=s.run, name=f"report-{s.id}", daemon=True)
    s._thread.start()
    return s
