"""phishlab/aitm.py — AiTM / reverse-proxy (Evilginx / Modlishka / Muraena) behavioural detection.

An Adversary-in-the-Middle toolkit PROXIES the real login page, so the CONTENT is byte-identical to the
genuine site — content, visual, and URL-blocklist checks are blind. You have to fingerprint the PROXY
itself: its DNS (Evilginx wildcard-resolves every subdomain to the phishing IP), its response
headers/cookies (toolkit tells + Go net/http defaults + Modlishka's Secure-flag strip), and its URL
shape. Keyless + best-effort; every probe degrades to nothing on error. Techniques adapted from the
PhishGuard FYP (Amanveer Singh Madas, PSB Academy / Coventry University).

Output: a list of scored Signal dicts {name, toolkit, score, evidence, tier}. `score_signals()` folds
them into the detonation verdict via enrich.py. High-precision toolkit tells (X-Evilginx header, __el /
Modlishka-id cookie) score high; ambiguous tells (Go headers, wildcard DNS) score low / are CDN-gated so
ordinary Cloudflare-fronted legit sites do not flag.
"""
from __future__ import annotations

import asyncio
import re
import secrets
import socket
import ssl
import time
from urllib.parse import urlsplit

import httpx

TIMEOUT = 8.0
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"

# CDNs legitimately terminate + forward — their Via / X-Forwarded / catch-all DNS are NOT AiTM tells.
_CDN_TOKENS = ("cloudflare", "akamai", "fastly", "cloudfront", "amazon", "google", "azure", "incapsula",
               "sucuri", "stackpath", "bunnycdn", "keycdn", "varnish", "vegur", "ats/", "gws")

# Response headers that betray a reverse-proxy toolkit (header present) -> (toolkit, score).
_TK_HEADERS = {"x-evilginx": ("Evilginx", 70)}

# Cookie NAMES set by a toolkit -> (toolkit, score).
_TK_COOKIE_NAMES = {"__el": ("Evilginx", 55), "_evilginx": ("Evilginx", 60), "__token": ("Evilginx", 25)}

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.I)

# Brand auth FQDNs a phish stuffs INSIDE a lookalike hostname (login.microsoftonline.com.evil.xyz).
_AUTH_FQDNS = ("login.microsoftonline.com", "login.microsoft.com", "login.live.com", "accounts.google.com",
               "login.okta.com", "signin.aws.amazon.com", "login.yahoo.com", "auth0.com", "okta.com",
               "adfs", "duosecurity.com", "onelogin.com")
_TUNNELS = ("ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com", "loca.lt", "serveo.net",
            "localhost.run", "pagekite.me", "telebit.io", "cfargotunnel.com")
_RISKY_TLD = (".xyz", ".top", ".click", ".online", ".site", ".shop", ".live", ".buzz", ".cfd", ".sbs",
              ".rest", ".icu", ".cyou", ".monster")
_LURE_PATH = re.compile(r"/[A-Za-z0-9_-]{7,24}(?:/|$)")   # Evilginx default lure path (random-ish token)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def _apex(host: str) -> str:
    parts = (host or "").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or "")) or ":" in (host or "")


async def _resolve(host: str) -> set[str]:
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return {ai[4][0] for ai in infos}
    except Exception:
        return set()


def _is_cdn(headers: dict) -> str | None:
    blob = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
    for t in _CDN_TOKENS:
        if t in blob:
            return t
    return None


async def wildcard_dns_probe(host: str, cdn: str | None) -> dict | None:
    """Evilginx runs its own authoritative DNS that wildcard-resolves EVERY subdomain to the phishing IP
    (its lures live on arbitrary subdomains). If a random never-registered subdomain resolves to the same
    IP as the apex, that's a strong Evilginx fingerprint. CDN-gated (CDNs wildcard legitimately) and
    scored moderate (some legit SaaS also wildcard) — it's a lead, corroborated by header/cookie tells."""
    if cdn or _is_ip(host):
        return None
    apex = _apex(host)
    probe = f"wp{secrets.token_hex(6)}.{apex}"
    apex_ips, probe_ips = await asyncio.gather(_resolve(apex), _resolve(probe))
    shared = apex_ips & probe_ips
    if apex_ips and probe_ips and shared:
        return {"name": "evilginx_wildcard_dns", "toolkit": "Evilginx", "score": 40, "tier": "dns",
                "evidence": f"random {probe} -> {sorted(shared)[0]} (== apex IP): catch-all DNS"}
    return None


def analyze_headers(headers: dict, cdn: str | None, url: str) -> list[dict]:
    sigs: list[dict] = []
    low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    for h, (tk, sc) in _TK_HEADERS.items():
        if h in low:
            sigs.append({"name": "toolkit_header", "toolkit": tk, "score": sc, "tier": "http",
                         "evidence": f"{h}: {low[h][:60]} (toolkit header leaked in response)"})
    # proxy-header leak in the RESPONSE (an origin never sends these back) — CDN-gated
    if not cdn:
        for h in ("via", "x-forwarded-for", "x-forwarded-host", "x-real-ip"):
            if h in low:
                sigs.append({"name": "proxy_header_leak", "toolkit": None, "score": 28, "tier": "http",
                             "evidence": f"response carries {h}: {low[h][:50]} (proxy tell)"})
                break
    # Go net/http default: no Server header + no-cache,no-store (Evilginx/Modlishka) — corroboration only
    cc = low.get("cache-control", "").lower()
    if "server" not in low and "no-cache" in cc and "no-store" in cc:
        sigs.append({"name": "go_proxy_tell", "toolkit": None, "score": 12, "tier": "http",
                     "evidence": "no Server header + Cache-Control no-cache,no-store (Go net/http default)"})
    return sigs


def analyze_cookies(set_cookies: list[str], scheme: str) -> list[dict]:
    sigs: list[dict] = []
    https = scheme == "https"
    for raw in set_cookies or []:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, _, val = parts[0].partition("=")
        name, val = name.strip(), val.strip().strip('"')
        flags = {p.split("=", 1)[0].lower() for p in parts[1:]}
        nl = name.lower()
        if nl in _TK_COOKIE_NAMES:
            tk, sc = _TK_COOKIE_NAMES[nl]
            sigs.append({"name": "toolkit_cookie", "toolkit": tk, "score": sc, "tier": "http",
                         "evidence": f"Set-Cookie {name}=… ({tk} tracking cookie)"})
        elif nl == "id" and (_UUID.match(val) or _HEX32.match(val)):
            sigs.append({"name": "modlishka_id_cookie", "toolkit": "Modlishka", "score": 45, "tier": "http",
                         "evidence": f"Set-Cookie id={val[:16]}… (Modlishka default trackingCookie)"})
        # Modlishka strips Secure so it can rewrite cookies: HttpOnly present, Secure absent, on HTTPS
        if https and "httponly" in flags and "secure" not in flags:
            sigs.append({"name": "secure_flag_strip", "toolkit": "Modlishka", "score": 30, "tier": "http",
                         "evidence": f"{name}: HttpOnly without Secure on HTTPS (proxy cookie rewrite)"})
    return sigs


def analyze_url(url: str) -> list[dict]:
    sigs: list[dict] = []
    host = _host(url)
    path = urlsplit(url).path or "/"
    if not host:
        return sigs
    for fq in _AUTH_FQDNS:
        if fq in host and not (host == fq or host.endswith("." + fq)):
            sigs.append({"name": "auth_fqdn_embed", "toolkit": None, "score": 40, "tier": "url",
                         "evidence": f"'{fq}' embedded in an unrelated host ({host})"})
            break
    if any(host == t or host.endswith("." + t) for t in _TUNNELS):
        sigs.append({"name": "dev_tunnel_host", "toolkit": None, "score": 25, "tier": "url",
                     "evidence": f"served from a dev-tunnel host ({host})"})
    if _is_ip(host):
        sigs.append({"name": "raw_ip_host", "toolkit": None, "score": 20, "tier": "url",
                     "evidence": f"login served from a raw IP ({host})"})
    if "xn--" in host:
        sigs.append({"name": "idn_homoglyph", "toolkit": None, "score": 20, "tier": "url",
                     "evidence": f"punycode/IDN host ({host}) — homoglyph brand spoof risk"})
    return sigs


def _infer_toolkit(sigs: list[dict]) -> str | None:
    tally: dict[str, int] = {}
    for s in sigs:
        tk = s.get("toolkit")
        if tk:
            tally[tk] = tally.get(tk, 0) + int(s.get("score", 0))
    return max(tally, key=tally.get) if tally else None


# ── Transport-layer probes — catch a proxy that leaks NO header/cookie tell ───────
_FREE_CA = ("let's encrypt", "zerossl", "buypass", "google trust services")
# Major brands that use their own / DigiCert-class CAs — never Let's Encrypt for production login.
_MAJOR_BRAND = {
    "Microsoft": r"microsoft|office\s*365|outlook|onedrive|sharepoint",
    "Google": r"\bgoogle\b|gmail|google\s*workspace",
    "Apple": r"apple\s*id|icloud",
    "PayPal": r"\bpaypal\b", "Okta": r"\bokta\b",
    "Amazon": r"amazon\s*web\s*services|aws\s*(console|sign)",
}


def _claimed_brand(html: str, title: str) -> str | None:
    blob = ((title or "") + " " + (html or "")[:20000]).lower()
    for brand, pat in _MAJOR_BRAND.items():
        if re.search(pat, blob, re.I):
            return brand
    return None


def _cert_info(host: str, port: int):
    """(issuer_str, self_signed) for the live served leaf cert. Blocking — run via asyncio.to_thread."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert() or {}
        issuer = ""
        for tup in cert.get("issuer", ()):
            for k, v in tup:
                if k in ("organizationName", "commonName"):
                    issuer += " " + str(v)
        return issuer.strip().lower(), False
    except ssl.SSLCertVerificationError as e:
        return "", "self" in str(e).lower() and "signed" in str(e).lower()
    except Exception:
        return None, False


async def cert_probe(host: str, port: int, brand: str | None) -> list[dict]:
    issuer, self_signed = await asyncio.to_thread(_cert_info, host, port)
    out: list[dict] = []
    if self_signed:
        out.append({"name": "self_signed_cert", "toolkit": "Modlishka", "score": 35, "tier": "tls",
                    "evidence": "served leaf cert is self-signed (proxy default; real logins never are)"})
    if issuer and brand and any(fc in issuer for fc in _FREE_CA):
        out.append({"name": "cert_brand_incoherence", "toolkit": None, "score": 30, "tier": "tls",
                    "evidence": f"page claims {brand} but cert from a free CA ({issuer[:40]}) — {brand} doesn't use one"})
    return out


def _timing(host: str, port: int, n: int = 5):
    tcp, tls = [], []
    for _ in range(n):
        s = None
        try:
            t = time.perf_counter()
            s = socket.create_connection((host, port), timeout=5)
            tcp.append(time.perf_counter() - t)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            t2 = time.perf_counter()
            ss = ctx.wrap_socket(s, server_hostname=host)
            tls.append(time.perf_counter() - t2)
            ss.close()
        except Exception:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
    if len(tcp) < 3 or len(tls) < 3:
        return None
    min_tcp = min(tcp)
    if min_tcp < 0.005:                       # LAN / same-host — ratio unreliable
        return None
    med_tls = sorted(tls)[len(tls) // 2]
    return {"ratio": round(med_tls / min_tcp, 1), "min_tcp_ms": round(min_tcp * 1000, 1),
            "med_tls_ms": round(med_tls * 1000, 1)}


async def timing_probe(host: str, port: int, cdn: str | None) -> dict | None:
    """Phoca method: a reverse proxy completes a SECOND TLS session (to the real origin) during the
    client handshake, so median(TLS handshake)/min(TCP connect) balloons (~12-40x) vs ~1-4x direct.
    CDN- and LAN-gated; conservative weight because internet timing is noisy."""
    if cdn:
        return None
    t = await asyncio.to_thread(_timing, host, port)
    if not t:
        return None
    r = t["ratio"]
    sc = 35 if r >= 25 else 20 if r >= 15 else 0
    if not sc:
        return None
    return {"name": "tls_timing_proxy_hop", "toolkit": None, "score": sc, "tier": "tls",
            "evidence": f"TLS handshake {r}x the TCP RTT ({t['med_tls_ms']}ms vs {t['min_tcp_ms']}ms): extra proxy hop"}


async def analyze(url: str) -> dict:
    """Run the AiTM probes and return {signals, toolkit, brand, aitm_score, cdn}. Best-effort; safe."""
    host = _host(url)
    sp = urlsplit(url)
    scheme = (sp.scheme or "http").lower()
    port = sp.port or (443 if scheme == "https" else 80)
    if not host:
        return {"signals": [], "toolkit": None, "aitm_score": 0, "cdn": None}

    headers: dict = {}
    set_cookies: list[str] = []
    html, title = "", ""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False, follow_redirects=True,
                                     headers={"User-Agent": BROWSER_UA}) as c:
            r = await c.get(url)
            headers = dict(r.headers)
            set_cookies = list(r.headers.get_list("set-cookie"))
            html = (r.text or "")[:60000]
            m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            title = m.group(1) if m else ""
    except Exception:
        pass

    cdn = _is_cdn(headers)
    brand = _claimed_brand(html, title)

    tasks = [wildcard_dns_probe(host, cdn)]
    if scheme == "https" and not _is_ip(host):
        tasks += [cert_probe(host, port, brand), timing_probe(host, port, cdn)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    sigs: list[dict] = []
    sigs += analyze_headers(headers, cdn, url)
    sigs += analyze_cookies(set_cookies, scheme)
    sigs += analyze_url(url)
    for res in results:
        if isinstance(res, Exception) or not res:
            continue
        sigs += res if isinstance(res, list) else [res]

    return {"signals": sigs, "toolkit": _infer_toolkit(sigs), "brand": brand,
            "aitm_score": min(100, sum(int(s.get("score", 0)) for s in sigs)), "cdn": cdn}


def score_signals(aitm: dict) -> list[tuple[int, str]]:
    """AiTM signals -> (score, reason) pairs folded into the detonation verdict."""
    out: list[tuple[int, str]] = []
    for s in (aitm or {}).get("signals", []) or []:
        tk = f"[{s['toolkit']}] " if s.get("toolkit") else ""
        out.append((int(s.get("score", 0)), f"AiTM/reverse-proxy: {tk}{s.get('evidence', s.get('name', ''))}"))
    return out
