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
    # SG / APAC banks + gov + common local lures (APAC threat model)
    "dbs", "posb", "ocbc", "uob", "maybank", "citibank", "standardchartered", "standard chartered",
    "cimb", "singpass", "singtel", "starhub", "shopee", "lazada", "revolut", "stripe",
    # cloud / file-share lures phishing routinely impersonates
    "sharepoint", "onedrive", "dropbox", "wetransfer",
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


# Cloudflare's "Suspected Phishing" WARNING interstitial (served when a URL is on Cloudflare's phishing
# blocklist): a "This website has been reported…" notice with an "Ignore & Proceed" link + a Turnstile
# "Verify you are human" checkbox. Unlike the "just a moment" JS bot-gate, this is a *bypassable* warning
# — tick the box + click Ignore & Proceed and you reach the real phish. Detect it so the walker auto-
# clears it instead of parking on handover.
def is_cf_phish_warning(title: str, html: str) -> bool:
    """True if the page is Cloudflare's 'Suspected Phishing' warning interstitial (bypassable via
    'Ignore & Proceed'), as opposed to a hard 'just a moment' bot-gate."""
    blob = ((title or "") + " " + (html or "")).lower()
    strong = ("suspected phishing" in blob or "reported for potential phishing" in blob
              or "this website has been reported" in blob)
    proceed = "ignore & proceed" in blob or "ignore and proceed" in blob or "ignore &amp; proceed" in blob
    return bool(strong and (proceed or "cf-turnstile" in blob or "challenges.cloudflare.com" in blob))


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


# ── broad "scam signals" IOCs — the actionable bits a phish/fake-site carries even with NO clickable link
# (a callback number, a crypto wallet to pay, a Telegram/WhatsApp handle to contact, a reply-to that doesn't
# match the sender). These are SOFT LEADS shown with a confidence band — NOT the hard detonation verdict.
_PHONE_RE = re.compile(r"\+\d[\d\s().-]{6,16}\d|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b")
_BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_TME_RE = re.compile(r"(?:t|telegram)\.me/([A-Za-z0-9_+]{4,40})", re.I)
_WA_RE = re.compile(r"(?:wa\.me/|api\.whatsapp\.com/send\?phone=|chat\.whatsapp\.com/)([A-Za-z0-9_+-]{4,40})", re.I)


def _addr_domain(a: str) -> str:
    m = re.search(r"@([a-z0-9.-]+)", (a or "").lower())
    return m.group(1) if m else ""


def scam_signals(text: str, from_addr: str | None = None, reply_to: str | None = None) -> dict:
    """SOFT scam leads from the raw text/source of an email or fake site: callback phone numbers, crypto
    wallet addresses, IBAN/bank, Telegram/WhatsApp handles, and a from↔reply-to domain mismatch. Returns
    {iocs:{...only non-empty...}, confidence: low|medium|high}. Meant to surface something actionable when
    there is no malicious URL — displayed as leads, kept DISTINCT from the detonation verdict."""
    t = text or ""
    phones = []
    for p in _PHONE_RE.findall(t):
        norm = re.sub(r"[^\d+]", "", p)
        if 7 <= len(norm.lstrip("+")) <= 15 and norm not in phones:
            phones.append(norm)
    out: dict = {
        "phones": phones[:20],
        "crypto_wallets": sorted(set(_BTC_RE.findall(t)) | set(_ETH_RE.findall(t)) | set(_XMR_RE.findall(t)))[:20],
        "ibans": sorted(set(_IBAN_RE.findall(t)))[:20],
        "telegram_handles": sorted({m.rstrip("/") for m in _TME_RE.findall(t)})[:20],
        "whatsapp": sorted(set(_WA_RE.findall(t)))[:20],
    }
    fd, rd = _addr_domain(from_addr), _addr_domain(reply_to)
    mismatch = {"from": fd, "reply_to": rd} if (fd and rd and fd != rd) else None
    iocs_nonempty = {k: v for k, v in out.items() if v}
    if mismatch:
        iocs_nonempty["replyto_mismatch"] = mismatch
    # confidence: a wallet / messaging handle / reply-to mismatch is a strong scam tell on its own
    strong = bool(out["crypto_wallets"] or out["telegram_handles"] or out["whatsapp"] or mismatch)
    n = len(iocs_nonempty)
    conf = "high" if (strong and n >= 2) else "medium" if (strong or n >= 2) else "low" if n else None
    return {"iocs": iocs_nonempty, "confidence": conf}
