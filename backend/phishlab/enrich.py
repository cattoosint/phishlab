"""phishlab/enrich.py — passive enrichment that turns a detonation into a contextual risk picture.

WHOIS/RDAP domain age (a days-old domain is the single strongest phishing signal), hosting/ASN/geo,
cert transparency, and a malware/phishing blocklist check. All KEYLESS + best-effort — each lookup
degrades to None on failure. These hit reputable OSINT services (rdap.org, ip-api, crt.sh, abuse.ch),
NOT the phishing host itself.
"""
from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

TIMEOUT = 8.0
UA = "PhishLab/0.1 (SOC phishing analysis)"


def _registrable(host: str) -> str:
    # naive eTLD+1 (last two labels) — fine for the .com/.xyz/.top/etc. that dominate phishing;
    # multi-part TLDs (co.uk) fall back to last three when the 2nd-last is a common SLD.
    parts = (host or "").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def _get_json(url: str, **kw):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": UA}, follow_redirects=True) as c:
            r = await c.get(url, **kw)
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return None


async def rdap_domain(host: str) -> dict | None:
    dom = _registrable(host)
    data = await _get_json(f"https://rdap.org/domain/{dom}")
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


async def enrich(url: str) -> dict:
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return {}
    rdap, ipi, uh, crt = await asyncio.gather(
        rdap_domain(host), ip_info(host), urlhaus_check(host), crtsh_recent(host),
        return_exceptions=True)

    def ok(x):
        return x if not isinstance(x, Exception) else None

    return {"host": host, "rdap": ok(rdap), "ip": ok(ipi), "urlhaus": ok(uh), "cert": ok(crt)}


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
    return out
