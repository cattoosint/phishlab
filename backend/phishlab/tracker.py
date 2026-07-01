"""phishlab/tracker.py — takedown tracker.

Every reported/detonated phishing URL is tracked here; a background loop pings each site every
~30 min and records UP vs DOWN (unreachable OR a parked/suspended replacement page), so the SOC
sees the moment a takedown lands. Persisted to data/tracker.json so it survives restarts.
"""
from __future__ import annotations

import asyncio
import json
import os
import time

import httpx

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tracker.json")
PING_INTERVAL = int(os.getenv("PHISH_TRACK_INTERVAL") or "1800")   # 30 min
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
SUSPENDED = ("account suspended", "suspended page", "site not found", "has been seized",
             "domain has expired", "coming soon", "default web page", "site suspended",
             "this account has been suspended", "410 gone")

_sites: dict[str, dict] = {}
_lock = asyncio.Lock()
_loaded = False
_task: asyncio.Task | None = None


def _load() -> None:
    global _loaded
    if _loaded:
        return
    try:
        with open(DATA, encoding="utf-8") as f:
            for s in json.load(f):
                _sites[s["url"]] = s
    except Exception:
        pass
    _loaded = True


def _save() -> None:
    try:
        os.makedirs(os.path.dirname(DATA), exist_ok=True)
        with open(DATA, "w", encoding="utf-8") as f:
            json.dump(list(_sites.values()), f)
    except Exception:
        pass


async def add(url: str, verdict: str | None = None, score: int | None = None) -> dict:
    async with _lock:
        _load()
        if url not in _sites:
            _sites[url] = {"url": url, "verdict": verdict, "score": score, "first_seen": time.time(),
                           "status": "pending", "last_check": None, "last_up": None,
                           "went_down_at": None, "checks": 0, "latency_ms": None, "status_code": None}
            _save()
        s = _sites[url]
    await check(url)
    return s


async def remove(url: str) -> bool:
    async with _lock:
        _load()
        gone = _sites.pop(url, None) is not None
        if gone:
            _save()
    return gone


async def all_sites() -> list[dict]:
    async with _lock:
        _load()
        return sorted(_sites.values(), key=lambda s: (s["status"] != "up", -(s.get("first_seen") or 0)))


def _vantages() -> list[dict]:
    """Vantage points to ping from. 'direct' (your dedicated line) always; add others (Tor / VPN /
    country proxies) via PHISH_TRACK_VANTAGES="tor=socks5://127.0.0.1:9050;de=http://host:port".
    Pinging from several geos tells a real takedown (down everywhere) apart from geo-cloaking (down
    for some vantages only). SOCKS/Tor needs the httpx[socks] extra."""
    out = [{"label": "direct", "proxy": None}]
    for part in (os.getenv("PHISH_TRACK_VANTAGES") or "").split(";"):
        part = part.strip()
        if "=" in part:
            label, proxy = part.split("=", 1)
            out.append({"label": label.strip(), "proxy": proxy.strip()})
    return out


async def _ping(url: str, proxy: str | None = None) -> dict:
    try:
        kw = {"timeout": 15, "follow_redirects": True, "verify": False, "headers": {"User-Agent": UA}}
        if proxy:
            kw["proxy"] = proxy
        async with httpx.AsyncClient(**kw) as c:
            t = time.perf_counter()
            r = await c.get(url)
            ms = int((time.perf_counter() - t) * 1000)
            body = (r.text[:6000] or "").lower()
            suspended = any(k in body for k in SUSPENDED)
            up = (200 <= r.status_code < 400) and not suspended
            return {"up": up, "status_code": r.status_code, "latency_ms": ms, "suspended": suspended}
    except Exception as exc:
        return {"up": False, "status_code": None, "latency_ms": None, "suspended": False,
                "error": type(exc).__name__}


async def check(url: str) -> dict | None:
    vs = _vantages()
    results = await asyncio.gather(*[_ping(url, v["proxy"]) for v in vs])
    per = [{"label": v["label"], **r} for v, r in zip(vs, results)]
    ups = [p for p in per if p["up"]]
    reachable = [p for p in per if p["up"] or p["status_code"] is not None]   # vantage actually worked
    up = len(ups) > 0                                       # alive from at least one vantage
    # geo-cloaking: some vantages get it, others don't (and it's not just a broken proxy)
    geo_cloaked = 0 < len(ups) < len(reachable) if len(reachable) > 1 else False
    async with _lock:
        _load()
        s = _sites.get(url)
        if not s:
            return None
        now = time.time()
        was = s.get("status")
        s["status"] = "up" if up else "down"
        s["last_check"] = now
        s["checks"] = (s.get("checks") or 0) + 1
        s["vantages"] = per
        s["geo_cloaked"] = geo_cloaked
        direct = next((p for p in per if p["label"] == "direct"), per[0])
        s["latency_ms"] = direct.get("latency_ms")
        s["status_code"] = direct.get("status_code")
        if up:
            s["last_up"] = now
            if was == "down":
                s["went_down_at"] = None          # came back
        else:
            if was == "up" and not s.get("went_down_at"):
                s["went_down_at"] = now           # DOWN everywhere -> taken down
        _save()
        return s


async def _loop() -> None:
    while True:
        try:
            for url in list((await all_sites())):
                await check(url["url"])
        except Exception:
            pass
        await asyncio.sleep(PING_INTERVAL)


def start() -> None:
    global _task
    _load()
    if _task is None:
        _task = asyncio.create_task(_loop())
