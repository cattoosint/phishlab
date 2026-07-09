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
WATCH_CAP = 40


def _norm(url: str) -> str:
    u = (url or "").strip()
    if u and not u.lower().startswith(("http://", "https://")):
        u = "http://" + u
    return u


def _key(u: str) -> str:
    """Normalize a URL for prefix-matching (the user page truncates long URLs with '…')."""
    u = (u or "").lower().strip().rstrip(".")
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    return u.rstrip("/")


def _match(target: str, listed: str) -> bool:
    """The listed URL is often truncated, so prefix-match either direction."""
    t, l = _key(target), _key(listed)
    if not t or not l or len(l) < 8:
        return False
    return t.startswith(l) or l.startswith(t)


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
        url = murl.group(1).rstrip(".") if murl else None      # trailing '…' truncation stripped
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
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent": f"phishtank/{key or 'phishlab'}"}) as c:
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
    """Look for `url` in the reporter's PhishTank submissions (+ checkurl supplement).
    Returns (hit_or_None, recent_rows)."""
    rows = await user_rows(username)
    hit = next((r for r in rows if r.get("url") and _match(url, r["url"])), None)
    if not hit:
        hit = await check_url(url)
    return hit, rows


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
        self.last_checked: float | None = None
        self.next_at = self.started
        self.recent: list[dict] = []
        self.error: str | None = None
        self._task: asyncio.Task | None = None

    def snapshot(self) -> dict:
        return {"id": self.id, "url": self.url, "username": self.username, "state": self.state,
                "attempts": self.attempts, "detail_url": self.detail_url, "phish_id": self.phish_id,
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


def start_watch(url: str, username: str | None = None, interval: int = 60, max_hours: float = 2) -> Watch:
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
