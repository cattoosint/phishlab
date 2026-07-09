"""phishlab/phishtank.py — PhishTank reporting poller (SOC "easier reporting" flow).

Workflow: an analyst reports a suspect URL to PhishTank (under the team account, default username
""). PhishTank takes a while to ingest + assign a public phish_detail.php page. This polls
the reporter's PhishTank user page every ~60s (up to 2h) until the reported URL shows up, then surfaces
its phish_detail.php link so the analyst can one-click copy it into WhatsApp for the takedown thread.

Primary signal = the public user page (phishtank.net/user.php?username=X) — no API key needed. The
checkurl API is used as a best-effort supplement (works for any reporter, needs PHISHTANK_APP_KEY).
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid

import httpx

logger = logging.getLogger("phishlab.phishtank")

BASE = os.getenv("PHISH_PHISHTANK_BASE", "https://phishtank.net")
USER_DEFAULT = os.getenv("PHISH_PHISHTANK_USER", "")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

WATCHES: dict[str, "Watch"] = {}
WATCH_CAP = 40           # retained finished watches
RUN_CAP = 25             # concurrent RUNNING watches (protects the reporter's PhishTank rate limit)
MAX_HOURS = 6.0          # hard ceiling on a watch's lifetime


def _norm(url: str) -> str:
    u = (url or "").strip()
    if u and not u.lower().startswith(("http://", "https://")):
        u = "http://" + u
    return u


def _split(u: str) -> tuple[str, str]:
    """(host_without_www, path) — lowercased, scheme/trailing-slash/'…'-truncation stripped."""
    u = (u or "").strip().rstrip("….").lower()   # strip a truncation ellipsis (ASCII or U+2026) + dots
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    if "/" in u:
        host, path = u.split("/", 1)
        path = "/" + path.rstrip("/")
    else:
        host, path = u, ""
    return host, path


# multi-tenant / free-hosting platforms: a *.SUFFIX subdomain is a DIFFERENT tenant, so two hosts that
# merely share one of these suffixes are NOT the same site — require an EXACT host match (no domain tier).
# (These + raw IPs are the dominant phishing host classes, so domain-tier matching there = false positives.)
_MULTITENANT = {
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "github.io", "gitlab.io", "netlify.app",
    "glitch.me", "herokuapp.com", "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com",
    "wixstudio.com", "000webhostapp.com", "r2.dev", "mystagingwebsite.com", "myclickfunnels.com",
    "godaddysites.com", "repl.co", "replit.app", "vercel.app", "onrender.com", "surge.sh", "translate.goog",
    "azurewebsites.net", "cloudfront.net", "amazonaws.com", "googleapis.com", "sharepoint.com",
    "myshopify.com", "square.site", "duckdns.org", "ngrok.app", "ngrok-free.app", "trycloudflare.com",
}


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or "")) or ":" in (host or "")


def _reg(host: str) -> str:
    """Naive registrable domain (eTLD+1), handling the common multi-part TLDs (co.uk, com.sg…)."""
    p = host.split(".")
    if len(p) >= 3 and p[-2] in ("com", "co", "org", "net", "gov", "edu", "ac"):
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) >= 2 else host


def match_url(target: str, listed: str) -> str | None:
    """How confidently `listed` (a PhishTank entry, possibly truncated) is the SAME thing as `target`:
      'exact'  — same host + the path is a prefix either way (listing truncates long URLs)
      'host'   — same host, different path (same phishing host, likely the same incident)
      'domain' — same registrable domain, different subdomain (weaker; verify) — NEVER for raw IPs or
                 multi-tenant/free-hosting suffixes, where a different subdomain is a different tenant
      None     — different registrable domain (e.g. dbs.com.sg vs dbs.com), or a shared-suffix host mismatch
    Scheme / www / trailing-slash differences are ignored throughout."""
    th, tp = _split(target)
    lh, lp = _split(listed)
    if not th or not lh or len(lh) < 4:
        return None
    if th == lh:
        if not lp or not tp or tp.startswith(lp) or lp.startswith(tp):
            return "exact"
        return "host"
    # domain tier: only for genuine registrable domains — never raw IPs or multi-tenant suffixes
    if _is_ip(th) or _is_ip(lh):
        return None
    tr, lr = _reg(th), _reg(lh)
    if tr and tr == lr and "." in tr and tr not in _MULTITENANT:
        return "domain"
    return None


def _detail(pid: str) -> str:
    return f"{BASE}/phish_detail.php?phish_id={pid}"


def parse_user_page(html: str) -> list[dict]:
    """Parse phishtank.net/user.php?username=X → recent submissions [{phish_id, url, detail_url,
    submitted, online}]. Row shape: a phish_detail link cell, then a value cell with the phish URL."""
    rows = []
    for tr in re.split(r"<tr[^>]*>", html or ""):
        mid = re.search(r"phish_detail\.php\?phish_id=(\d+)", tr)
        if not mid:
            continue
        pid = mid.group(1)
        murl = re.search(r'class="value">\s*(https?://[^\s<]+)', tr)
        url = murl.group(1).rstrip("….") if murl else None     # trailing '…'/'.' truncation stripped
        sub = re.search(r"added on ([^<]+)", tr)
        online = None
        if re.search(r">\s*Online\s*<", tr, re.I) or "online.gif" in tr.lower():
            online = True
        elif re.search(r">\s*Offline\s*<", tr, re.I):
            online = False
        rows.append({"phish_id": pid, "url": url, "detail_url": _detail(pid),
                     "submitted": (sub.group(1).strip()[:40] if sub else None), "online": online})
    return rows


async def user_rows(username: str) -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent": UA}, follow_redirects=True) as c:
            r = await c.get(f"{BASE}/user.php", params={"username": username})
            if r.status_code == 200:
                return parse_user_page(r.text)
    except Exception as exc:
        logger.debug("user_rows failed: %s", exc)
    return []


async def check_url(url: str) -> dict | None:
    """PhishTank checkurl API for an exact URL (best-effort; needs PHISHTANK_APP_KEY to be reliable)."""
    data = {"url": url, "format": "json"}
    key = os.getenv("PHISHTANK_APP_KEY")
    if key:
        data["app_key"] = key
    try:
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent": "phishtank/phishlab"}) as c:  # key stays in the POST body only
            r = await c.post("https://checkurl.phishtank.com/checkurl/", data=data)
            if r.status_code == 200 and "json" in (r.headers.get("content-type") or ""):
                res = (r.json().get("results") or {})
                if res.get("in_database") and res.get("phish_id"):
                    return {"phish_id": str(res.get("phish_id")),
                            "detail_url": res.get("phish_detail_page") or _detail(res.get("phish_id")),
                            "verified": res.get("verified"), "url": url}
    except Exception:
        pass
    return None


async def find_for_url(url: str, username: str) -> tuple[dict | None, list[dict]]:
    """Look for `url` in the reporter's PhishTank submissions (rows are newest-first, so the first match
    is the most recent) + a checkurl supplement. Returns (hit_or_None, recent_rows). The hit carries the
    matched listing + submission time + confidence so the analyst can VERIFY it's the right link."""
    rows = await user_rows(username)
    for r in rows:                       # newest-first → most-recent match wins (handles "within 1h")
        conf = match_url(url, r.get("url") or "")
        if conf:
            return {"detail_url": r["detail_url"], "phish_id": r["phish_id"], "matched_url": r.get("url"),
                    "submitted": r.get("submitted"), "online": r.get("online"),
                    "confidence": conf, "source": "user_page"}, rows
    ck = await check_url(url)
    if ck:
        return {**ck, "matched_url": ck.get("url"), "confidence": "checkurl", "source": "checkurl",
                "submitted": None}, rows
    return None, rows


class Watch:
    def __init__(self, url: str, username: str, interval: int, max_seconds: int):
        self.id = uuid.uuid4().hex[:12]
        self.url = url
        self.username = username
        self.interval = max(20, int(interval))
        self.started = time.time()
        self.deadline = self.started + max_seconds
        self.attempts = 0
        self.state = "watching"          # watching | found | expired | stopped | error
        self.detail_url: str | None = None
        self.phish_id: str | None = None
        self.matched_url: str | None = None      # the (possibly truncated) URL PhishTank listed
        self.submitted: str | None = None        # when PhishTank shows it was submitted
        self.confidence: str | None = None       # exact | host | domain | checkurl
        self.last_checked: float | None = None
        self.next_at = self.started
        self.recent: list[dict] = []
        self.error: str | None = None
        self._task: asyncio.Task | None = None

    def snapshot(self) -> dict:
        return {"id": self.id, "url": self.url, "username": self.username, "state": self.state,
                "attempts": self.attempts, "detail_url": self.detail_url, "phish_id": self.phish_id,
                "matched_url": self.matched_url, "submitted": self.submitted, "confidence": self.confidence,
                "started": self.started, "deadline": self.deadline, "interval": self.interval,
                "last_checked": self.last_checked, "next_at": self.next_at,
                "recent": self.recent[:8], "error": self.error}


async def _run(w: Watch):
    try:
        while w.state == "watching" and time.time() < w.deadline:
            w.attempts += 1
            w.last_checked = time.time()
            try:
                hit, rows = await find_for_url(w.url, w.username)
                if rows:
                    w.recent = rows
                if hit and hit.get("detail_url"):
                    w.detail_url = hit["detail_url"]
                    w.phish_id = str(hit.get("phish_id") or "")
                    w.matched_url = hit.get("matched_url")
                    w.submitted = hit.get("submitted")
                    w.confidence = hit.get("confidence")
                    w.state = "found"
                    break
            except Exception as exc:
                w.error = f"{type(exc).__name__}: {exc}"[:120]
            w.next_at = time.time() + w.interval
            await asyncio.sleep(w.interval)
        if w.state == "watching":
            w.state = "expired"
    except asyncio.CancelledError:
        if w.state == "watching":
            w.state = "stopped"


def _evict():
    if len(WATCHES) <= WATCH_CAP:
        return
    done = sorted((w for w in WATCHES.values() if w.state in ("found", "expired", "stopped")),
                  key=lambda w: w.started)
    for w in done[:len(WATCHES) - WATCH_CAP]:
        WATCHES.pop(w.id, None)


def start_watch(url: str, username: str | None = None, interval: int = 30, max_hours: float = 2) -> Watch:
    interval = min(3600, max(20, int(interval or 30)))
    max_hours = min(MAX_HOURS, max(0.05, float(max_hours or 2)))
    running = [w for w in WATCHES.values() if w.state == "watching"]
    if len(running) >= RUN_CAP:                  # bound concurrent pollers → don't hammer PhishTank
        stop_watch(min(running, key=lambda w: w.started).id)
    w = Watch(_norm(url), (username or USER_DEFAULT).strip(), interval, int(max_hours * 3600))
    WATCHES[w.id] = w
    _evict()
    w._task = asyncio.create_task(_run(w))
    return w


def stop_watch(wid: str) -> Watch | None:
    w = WATCHES.get(wid)
    if w and w.state == "watching":
        w.state = "stopped"
        if w._task and not w._task.done():
            w._task.cancel()
    return w


def list_watches() -> list[Watch]:
    return sorted(WATCHES.values(), key=lambda w: -w.started)
