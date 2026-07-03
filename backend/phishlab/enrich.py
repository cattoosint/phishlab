"""phishlab/enrich.py — passive enrichment that turns a detonation into a contextual risk picture.

WHOIS/RDAP domain age (a days-old domain is the single strongest phishing signal), hosting/ASN/geo,
cert transparency, and a malware/phishing blocklist check. All KEYLESS + best-effort — each lookup
degrades to None on failure. These hit reputable OSINT services (rdap.org, ip-api, crt.sh, abuse.ch),
NOT the phishing host itself.
"""
from __future__ import annotations

import asyncio
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from . import aitm as A

TIMEOUT = 8.0
UA = "PhishLab/0.1 (SOC phishing analysis)"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"


def _registrable(host: str) -> str:
    # naive eTLD+1 (last two labels) — fine for the .com/.xyz/.top/etc. that dominate phishing;
    # multi-part TLDs (co.uk) fall back to last three when the 2nd-last is a common SLD.
    parts = (host or "").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def _get_json(url: str, timeout: float = TIMEOUT, **kw):
    try:
        async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": UA}, follow_redirects=True) as c:
            r = await c.get(url, **kw)
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return None


async def rdap_domain(host: str) -> dict | None:
    dom = _registrable(host)
    data = await _get_json(f"https://rdap.org/domain/{dom}", timeout=15)   # RDAP can be slow
    if not data:
        return None
    created = None
    for ev in data.get("events", []) or []:
        if ev.get("eventAction") == "registration":
            created = ev.get("eventDate")
    age = None
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - dt).days
        except Exception:
            pass
    registrar = None
    for e in data.get("entities", []) or []:
        if "registrar" in (e.get("roles") or []):
            try:
                for item in e["vcardArray"][1]:
                    if item[0] == "fn":
                        registrar = item[3]
            except Exception:
                pass
    return {"domain": dom, "created": created, "age_days": age, "registrar": registrar}


async def ip_info(host: str) -> dict | None:
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ip = infos[0][4][0]
    except Exception:
        return None
    d = await _get_json(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query")
    if not d or d.get("status") != "success":
        return {"ip": ip}
    return {"ip": ip, "country": d.get("country"), "city": d.get("city"),
            "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as")}


async def urlhaus_check(host: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": UA}) as c:
            r = await c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host})
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    urls = d.get("urls") or []
                    return {"listed": True, "count": len(urls),
                            "threat": (urls[0].get("threat") if urls else None)}
                return {"listed": False}
    except Exception:
        pass
    return None


async def crtsh_recent(host: str) -> dict | None:
    dom = _registrable(host)
    data = await _get_json(f"https://crt.sh/?q=%25.{dom}&output=json")
    if not isinstance(data, list) or not data:
        return None
    newest = None
    for e in data[:300]:
        nb = e.get("not_before")
        if nb and (newest is None or nb > newest):
            newest = nb
    return {"certs": len(data), "newest": newest}


_FP_TECH = [
    ("WordPress", r"wp-content|wp-includes|/wp-json"),
    ("Squarespace", r"squarespace|static1\.squarespace"),
    ("Shopify", r"cdn\.shopify|x-shopify|Shopify\.theme"),
    ("Wix", r"\bwix\.com|wixstatic|_wixCssStates"),
    ("Webflow", r"webflow"),
    ("Ghost", r'content=["\']Ghost'),
    ("Drupal", r"Drupal|/sites/default/files"),
    ("Joomla", r"Joomla|/media/jui/"),
    ("Weebly", r"weebly"),
    ("Google Sites", r"sites\.google\.com|gstatic.*sites"),
    ("Blogger", r"blogspot|blogger\.com"),
    ("Next.js", r"__NEXT_DATA__|/_next/static"),
    ("React", r"\breact(-dom)?(\.min)?\.js"),
    ("Vue.js", r"vue(\.min)?\.js|__vue__"),
    ("Bootstrap", r"bootstrap(\.min)?\.(css|js)"),
    ("jQuery", r"jquery(\.min)?\.js"),
    ("PHP", r"\.php\b|x-powered-by:\s*php"),
    ("Cloudflare", r"__cf_bm|cf-ray|cdnjs\.cloudflare"),
    ("Google Analytics", r"googletagmanager|google-analytics|gtag\("),
]
_FP_HDRS = ("server", "x-powered-by", "x-generator", "via", "x-aspnet-version",
            "x-shopify-stage", "x-drupal-cache")


async def fingerprint(url: str) -> dict | None:
    """WhatWeb-style tech/hosting fingerprint from the page's headers + HTML — identifies the platform
    (Squarespace/Wix/Shopify/WordPress…) so you know who to report to + spot a phish riding a legit SaaS."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False, follow_redirects=True,
                                     headers={"User-Agent": BROWSER_UA}) as c:
            r = await c.get(url)
    except Exception:
        return None
    body = (r.text or "")[:80000]
    blob = body + " " + " ".join(f"{k}:{v}" for k, v in r.headers.items())
    gen = None
    g = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if g:
        gen = g.group(1)[:80]
    tech = sorted({name for name, pat in _FP_TECH if re.search(pat, blob, re.I)})
    return {"status": r.status_code, "server": r.headers.get("server"),
            "powered_by": r.headers.get("x-powered-by"), "generator": gen, "tech": tech}


async def enrich(url: str) -> dict:
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return {}
    rdap, ipi, uh, crt, fp, aitm_r = await asyncio.gather(
        rdap_domain(host), ip_info(host), urlhaus_check(host), crtsh_recent(host), fingerprint(url),
        A.analyze(url), return_exceptions=True)

    def ok(x):
        return x if not isinstance(x, Exception) else None

    return {"host": host, "rdap": ok(rdap), "ip": ok(ipi), "urlhaus": ok(uh), "cert": ok(crt),
            "fingerprint": ok(fp), "aitm": ok(aitm_r)}


def score_signals(enr: dict) -> list[tuple[int, str]]:
    """Enrichment → (score, reason) pairs folded into the verdict."""
    out = []
    rdap = (enr or {}).get("rdap") or {}
    age = rdap.get("age_days")
    if isinstance(age, int):
        if age < 7:
            out.append((25, f"domain registered {age}d ago (brand-new)"))
        elif age < 30:
            out.append((12, f"domain only {age}d old"))
    if ((enr or {}).get("urlhaus") or {}).get("listed"):
        out.append((30, "host is on the URLhaus malware/phishing blocklist"))
    out += A.score_signals((enr or {}).get("aitm") or {})   # AiTM / reverse-proxy toolkit signals
    return out
