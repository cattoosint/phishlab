"""phishlab/tracker.py — takedown tracker.

Every reported/detonated phishing URL is tracked here; a background loop pings each site every
~30 min and records UP vs DOWN (unreachable OR a parked/suspended replacement page), so the SOC
sees the moment a takedown lands. Persisted to data/tracker.json so it survives restarts.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import time
from urllib.parse import urlsplit

import httpx
from playwright.async_api import async_playwright

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tracker.json")
PING_INTERVAL = int(os.getenv("PHISH_TRACK_INTERVAL") or "1800")   # 30 min
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
SUSPENDED = ("account suspended", "suspended page", "site not found", "has been seized",
             "domain has expired", "coming soon", "default web page", "site suspended",
             "this account has been suspended", "410 gone")
# host/CDN error pages = the origin is DOWN even if the CDN answers (e.g. Cloudflare 522)
HOST_ERRORS = ("error code 52", "connection timed out", "web server is down", "origin is unreachable",
               "origin web server", "took too long to respond", "gateway time-out", "bad gateway",
               "this site can't be reached", "this site can’t be reached", "no server is available",
               "web server reported", "service temporarily unavailable", "server is unreachable")


def _down_reason(status_code, body: str) -> str | None:
    """Why a site should count as DOWN (None = it's up). Reads CDN/host error pages, not just codes."""
    b = (body or "").lower()
    if status_code is not None:
        if 520 <= status_code <= 527:
            return f"host error {status_code} (origin down behind CDN)"
        if status_code in (502, 503, 504):
            return f"server error {status_code}"
    if any(k in b for k in SUSPENDED):
        return "suspended / parked"
    if any(k in b for k in HOST_ERRORS):
        return "host unreachable"
    return None

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


async def add(url: str, name: str | None = None, verdict: str | None = None,
              score: int | None = None) -> dict:
    async with _lock:
        _load()
        if url not in _sites:
            _sites[url] = {"url": url, "name": (name or (urlsplit(url).hostname or url)),
                           "verdict": verdict, "score": score, "first_seen": time.time(),
                           "status": "pending", "last_check": None, "last_up": None,
                           "went_down_at": None, "confirmed_down": False,
                           "checks": 0, "latency_ms": None, "status_code": None}
            _save()
        elif name:
            _sites[url]["name"] = name
        s = _sites[url]
    await check(url)
    return s


async def rename(url: str, name: str) -> dict | None:
    async with _lock:
        _load()
        s = _sites.get(url)
        if s:
            s["name"] = name.strip() or s.get("name")
            _save()
        return s


async def confirm_down(url: str) -> dict | None:
    """Analyst confirms a takedown — mark it so the board can grey/archive it (not auto-removed)."""
    async with _lock:
        _load()
        s = _sites.get(url)
        if s:
            s["confirmed_down"] = True
            _save()
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
    # NordVPN SOCKS5 exits — built from service creds in the env so creds never live in a vantage
    # string. PHISH_NORD_SERVERS="nl=amsterdam.nl.socks.nordhold.net,us=atlanta.us.socks.nordhold.net".
    nu, npw = os.getenv("NORDVPN_SERVICE_USER"), os.getenv("NORDVPN_SERVICE_PASS")
    if nu and npw:
        servers = os.getenv("PHISH_NORD_SERVERS") or "nl=amsterdam.nl.socks.nordhold.net"
        for pair in servers.split(","):
            pair = pair.strip()
            if "=" in pair:
                label, host = pair.split("=", 1)
                out.append({"label": f"nord-{label.strip()}",
                            "proxy": f"socks5://{nu}:{npw}@{host.strip()}:1080"})
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
            reason = _down_reason(r.status_code, r.text[:8000] or "")
            up = (200 <= r.status_code < 400) and not reason
            return {"up": up, "status_code": r.status_code, "latency_ms": ms, "reason": reason}
    except Exception as exc:
        return {"up": False, "status_code": None, "latency_ms": None,
                "reason": f"unreachable ({type(exc).__name__})"}


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
        s["reason"] = None if up else next((p.get("reason") for p in per if p.get("reason")), "down")
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


async def _capture_one(p, v: dict, url: str) -> dict:
    """Render the URL through ONE vantage (its proxy) and screenshot what it actually sees."""
    launch_kw = {"headless": True}
    if v["proxy"]:
        launch_kw["proxy"] = {"server": v["proxy"]}
    br = None
    try:
        br = await p.firefox.launch(**launch_kw)
        ctx = await br.new_context(viewport={"width": 1000, "height": 680}, ignore_https_errors=True)
        pg = await ctx.new_page()
        r = None
        try:
            r = await pg.goto(url, wait_until="domcontentloaded", timeout=20000)
        except Exception:
            pass
        await pg.wait_for_timeout(1500)
        try:
            shot = base64.b64encode(await pg.screenshot(type="jpeg", quality=60)).decode()
        except Exception:
            shot = None
        try:
            title = await pg.title()
        except Exception:
            title = ""
        try:
            body = await pg.content()
        except Exception:
            body = ""
        status = r.status if r else None
        reason = _down_reason(status, body) if r else "unreachable (no response)"
        up = bool(r) and 200 <= status < 400 and not reason
        return {"label": v["label"], "up": up, "status": status, "reason": reason,
                "title": title, "final_url": pg.url, "screenshot": shot}
    except Exception as exc:
        return {"label": v["label"], "up": False, "status": None, "screenshot": None,
                "title": "", "final_url": url, "reason": f"unreachable ({type(exc).__name__})"}
    finally:
        if br:
            try:
                await br.close()
            except Exception:
                pass


async def capture_views(url: str) -> list[dict]:
    """Load the URL from EVERY vantage (direct + each proxy) and return per-vantage screenshots — the
    visual proof that a site is really down (or geo-cloaked) across regions."""
    vs = _vantages()
    async with async_playwright() as p:
        return list(await asyncio.gather(*[_capture_one(p, v, url) for v in vs]))


def _content_sig(html: str) -> dict:
    """A comparable fingerprint of the visible content — strips tags/scripts, hashes the text."""
    txt = re.sub(r"\s+", " ", re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>|<[^>]+>", " ", html or "")).strip().lower()
    return {"len": len(txt), "hash": hashlib.md5(txt[:4000].encode("utf-8", "ignore")).hexdigest()[:12]}


async def vantage_probe(url: str) -> list[dict]:
    """Fetch the URL from EVERY vantage (direct + Tor + Nord) and fingerprint the content — the
    phase-1 IP/geo cloaking check: does the site serve different pages to different IPs?"""
    vs = _vantages()

    async def one(v):
        try:
            kw = {"timeout": 15, "follow_redirects": True, "verify": False, "headers": {"User-Agent": UA}}
            if v["proxy"]:
                kw["proxy"] = v["proxy"]
            async with httpx.AsyncClient(**kw) as c:
                r = await c.get(url)
                body = r.text or ""
                tm = _TITLE_RE.search(body)
                title = re.sub(r"\s+", " ", tm.group(1)).strip()[:120] if tm else ""
                return {"label": v["label"], "status": r.status_code, "final_url": str(r.url),
                        "title": title, "sig": _content_sig(body),
                        "reason": _down_reason(r.status_code, body[:8000])}
        except Exception as exc:
            return {"label": v["label"], "status": None, "title": "", "final_url": url,
                    "sig": None, "reason": f"unreachable ({type(exc).__name__})"}

    return list(await asyncio.gather(*[one(v) for v in vs]))


def multi_vantage_verdict(probes: list[dict]) -> dict:
    """Compare what each vantage was served. Different title / final host / much-different size across
    the responding vantages = the site cloaks by IP or geo."""
    ok = [p for p in probes if p.get("status") and p.get("sig")]
    if len(ok) < 2:
        return {"cloaked": False, "responded": len(ok), "note": "need >=2 responding vantages"}
    titles = {(p.get("title") or "").strip().lower() for p in ok}
    hosts = {(urlsplit(p.get("final_url") or "").hostname or "") for p in ok}
    lens = [p["sig"]["len"] for p in ok]
    spread = (max(lens) - min(lens)) / max(1, max(lens))
    diffs = []
    if len(titles) > 1:
        diffs.append("different page titles")
    if len(hosts) > 1:
        diffs.append("different final hosts")
    if spread > 0.45:
        diffs.append(f"content size differs {int(spread * 100)}%")
    return {"cloaked": bool(diffs), "diffs": diffs, "responded": len(ok),
            "titles": list(titles)[:4], "hosts": [h for h in hosts if h][:4]}


async def _run_cmd(cmd: list[str], timeout: float = 15.0) -> str:
    try:
        p = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return (out or b"").decode("utf-8", "ignore").strip()[:4000] or "(no output)"
    except asyncio.TimeoutError:
        return "(timed out)"
    except Exception as exc:
        return f"({type(exc).__name__}: {exc})"[:200]


async def network_trace(url: str) -> dict:
    """Network-level proof for a case — ICMP ping + a raw curl HEAD. Down/blocked hosts show it here
    (ping 'Request timed out' / 'could not find host'; curl connection error) as evidence."""
    host = (urlsplit(url).hostname or url)
    if host.startswith("-"):     # never let a hostname be parsed by ping/curl as a flag
        return {"host": host, "ping": "(refused: hostname starts with '-')", "curl": "(refused)",
                "captured": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
    ping_cmd = (["ping", "-n", "3", "-w", "3000", host] if os.name == "nt"
                else ["ping", "-c", "3", "-W", "3", host])
    ping, curl = await asyncio.gather(
        _run_cmd(ping_cmd, 15),
        _run_cmd(["curl", "-sS", "-I", "-m", "12", "--max-redirs", "3", "-A", UA, url], 15),
    )
    return {"host": host, "ping": ping, "curl": curl,
            "captured": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}


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
