"""phishlab/extract.py — pull IOCs + exfil channels out of a detonated page's source.

Pure logic (regex/string) so it is unit-testable with no browser. The browser layer feeds raw
HTML/JS + form actions in; this turns it into structured exfil intelligence.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

# Telegram bot token: 8-10 digit bot-id ':' 35-char secret. Phishing kits very commonly POST
# stolen creds straight to a Telegram bot — a token in the page is a strong exfil IOC.
TG_TOKEN = re.compile(r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b")
TG_API = re.compile(r"api\.telegram\.org/bot(\d{8,10}:[A-Za-z0-9_-]{35})", re.I)
TG_CHATID = re.compile(r"(?:chat[_-]?id)\W{0,4}(-?\d{6,15})", re.I)

URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# brands most abused in credential phishing — a cheap impersonation signal
BRANDS = (
    "paypal", "microsoft", "office365", "outlook", "office", "apple", "icloud", "amazon", "google",
    "gmail", "facebook", "instagram", "netflix", "dhl", "fedex", "ups", "usps", "chase", "wellsfargo",
    "bankofamerica", "hsbc", "barclays", "santander", "coinbase", "binance", "metamask", "docusign",
    "adobe", "linkedin", "whatsapp", "telegram", "steam", "roblox", "oracle", "att", "verizon",
)


# Anti-bot / gate fingerprints. If the VICTIM view hits one of these, the page is gated and we
# likely did NOT reach the real content — report it honestly rather than call the page clean.
# STRONG interactive-challenge signals ONLY. Cloudflare injects '/cdn-cgi/challenge-platform/' JS and
# loads challenges.cloudflare.com on EVERY site it fronts (bot management), and legit forms embed
# recaptcha/api.js — matching those flagged ordinary pages (e.g. a FormSubmit "Thanks!" success page)
# as gates. Match the CHALLENGE UI/text, not the CDN or the embedded script host.
CHALLENGE_MARKERS = {
    "cloudflare": ("just a moment", "checking your browser", "cf-browser-verification",
                   "cf-challenge-running", "needs to review the security of your connection",
                   "enable javascript and cookies to continue"),
    "turnstile": ("cf-turnstile",),
    "recaptcha": ("g-recaptcha",),
    "hcaptcha": ("h-captcha",),
    "datadome": ("geo.captcha-delivery.com", "datadome captcha"),
    "akamai": ("ak_bmsc", "_abck"),
    "imperva": ("incapsula incident", "_incap_ses"),
}


def detect_challenge(title: str, html: str) -> list[str]:
    """Anti-bot gate(s) present in the page — Cloudflare/Turnstile/CAPTCHA/etc. Non-empty means the
    page is gated (detonation likely incomplete)."""
    blob = ((title or "") + " " + (html or "")).lower()
    # a host/CDN ERROR page (Cloudflare 52x etc.) is NOT an interactive challenge — don't gate on it
    if any(k in blob for k in ("error code 52", "connection timed out", "web server is down",
                               "522:", "521:", "520:", "523:", "524:", "origin is unreachable")):
        return []
    return [name for name, keys in CHALLENGE_MARKERS.items() if any(k in blob for k in keys)]


def telegram_channels(html: str) -> list[dict]:
    """Telegram exfil channels found in the page: bot token(s) + any chat_ids."""
    tokens = set(TG_TOKEN.findall(html or "")) | set(TG_API.findall(html or ""))
    chat_ids = sorted(set(TG_CHATID.findall(html or "")))
    return [{"bot_token": t, "bot_id": t.split(":")[0], "chat_ids": chat_ids} for t in sorted(tokens)]


def _safe_host(u: str) -> str:
    """Hostname of a URL, or '' — never raises. Attacker HTML can carry malformed URLs (unbalanced IPv6
    bracket -> urlsplit ValueError); one bad href must not crash the whole detonation."""
    try:
        return (urlsplit(u).hostname or "").lower()
    except Exception:
        return ""


def off_host_urls(html: str, page_url: str) -> list[str]:
    """Absolute URLs pointing OFF the page's own host — candidate exfil/C2 endpoints."""
    host = _safe_host(page_url)
    out = set()
    for u in URL_RE.findall(html or ""):
        h = _safe_host(u)
        if h and h != host:
            out.add(u)
    return sorted(out)


def brand_hits(*texts: str) -> list[str]:
    """Brands named in the given text — WORD-BOUNDARY matched (so 'ups' ≠ 'groups', 'att' ≠
    'attention'). Callers should pass page TITLES, not full HTML: a real site legitimately mentions
    Google/Facebook (OAuth buttons) in its markup, but a phish puts the imitated brand in the title."""
    blob = " ".join(t or "" for t in texts).lower()
    return sorted({b for b in BRANDS if re.search(r"\b" + re.escape(b) + r"\b", blob)})


_WAIT_RE = re.compile(
    r"please wait|verifying your|redirecting|one moment|just a (?:moment|second)|checking your browser|"
    r"do not (?:close|refresh)|processing your|hold on|we(?:'| a)re (?:verifying|checking|processing)|"
    r"please hold|loading\.\.\.|redirect you", re.I)


def is_wait_page(title: str | None, html: str | None) -> bool:
    """A 'please wait / verifying / redirecting' interstitial the walker should sit through."""
    return bool(_WAIT_RE.search(((title or "") + " " + (html or ""))[:6000]))


def iocs(html: str, page_url: str, extra_urls=()) -> dict:
    """Aggregate IOCs from the page source + any extra (e.g. form-action) URLs."""
    hosts, ips, emails = set(), set(), set()
    for u in set(URL_RE.findall(html or "")) | set(extra_urls or ()):
        h = _safe_host(u)
        if h:
            hosts.add(h)
    ips.update(IPV4.findall(html or ""))
    emails.update(e.lower() for e in EMAIL.findall(html or ""))
    return {"domains": sorted(hosts), "ips": sorted(ips), "emails": sorted(emails)}
