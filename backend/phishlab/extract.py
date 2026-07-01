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
CHALLENGE_MARKERS = {
    "cloudflare": ("just a moment", "checking your browser", "cf-browser-verification", "cf_chl",
                   "challenge-platform", "attention required", "__cf_chl", "ray id"),
    "turnstile": ("cf-turnstile", "challenges.cloudflare.com", "turnstile"),
    "recaptcha": ("g-recaptcha", "recaptcha/api.js", "grecaptcha"),
    "hcaptcha": ("h-captcha", "hcaptcha.com"),
    "datadome": ("datadome", "dd_cookie"),
    "akamai": ("ak_bmsc", "_abck", "akamai bot"),
    "imperva": ("_incap_", "incapsula", "imperva"),
}


def detect_challenge(title: str, html: str) -> list[str]:
    """Anti-bot gate(s) present in the page — Cloudflare/Turnstile/CAPTCHA/etc. Non-empty means the
    page is gated (detonation likely incomplete)."""
    blob = ((title or "") + " " + (html or "")).lower()
    return [name for name, keys in CHALLENGE_MARKERS.items() if any(k in blob for k in keys)]


def telegram_channels(html: str) -> list[dict]:
    """Telegram exfil channels found in the page: bot token(s) + any chat_ids."""
    tokens = set(TG_TOKEN.findall(html or "")) | set(TG_API.findall(html or ""))
    chat_ids = sorted(set(TG_CHATID.findall(html or "")))
    return [{"bot_token": t, "bot_id": t.split(":")[0], "chat_ids": chat_ids} for t in sorted(tokens)]


def off_host_urls(html: str, page_url: str) -> list[str]:
    """Absolute URLs pointing OFF the page's own host — candidate exfil/C2 endpoints."""
    host = (urlsplit(page_url).hostname or "").lower()
    out = set()
    for u in URL_RE.findall(html or ""):
        h = (urlsplit(u).hostname or "").lower()
        if h and h != host:
            out.add(u)
    return sorted(out)


def brand_hits(*texts: str) -> list[str]:
    """Brands named in the given text — WORD-BOUNDARY matched (so 'ups' ≠ 'groups', 'att' ≠
    'attention'). Callers should pass page TITLES, not full HTML: a real site legitimately mentions
    Google/Facebook (OAuth buttons) in its markup, but a phish puts the imitated brand in the title."""
    blob = " ".join(t or "" for t in texts).lower()
    return sorted({b for b in BRANDS if re.search(r"\b" + re.escape(b) + r"\b", blob)})


def iocs(html: str, page_url: str, extra_urls=()) -> dict:
    """Aggregate IOCs from the page source + any extra (e.g. form-action) URLs."""
    hosts, ips, emails = set(), set(), set()
    for u in set(URL_RE.findall(html or "")) | set(extra_urls or ()):
        h = urlsplit(u).hostname
        if h:
            hosts.add(h.lower())
    ips.update(IPV4.findall(html or ""))
    emails.update(e.lower() for e in EMAIL.findall(html or ""))
    return {"domains": sorted(hosts), "ips": sorted(ips), "emails": sorted(emails)}
