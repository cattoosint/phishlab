"""phishlab/indicators.py — static source-code phishing analysis.

Reads the ENTIRE page source (HTML + inline JS + form markup) and flags the tell-tale signs of a
phishing kit: credential harvesting, off-host / Telegram / e-mail / webhook exfil, obfuscation,
anti-analysis, brand impersonation, sensitive-data capture, and cloaking logic. Each hit is an
INDICATOR with a severity + score; the total feeds the verdict. Pure logic, no network.

Every detection lives here in code, keyed by a stable id, so "why is this fake" is fully auditable.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

SEV_SCORE = {"high": 22, "medium": 12, "low": 5}

# id, severity, human title, compiled pattern (searched against the whole source, case-insensitive)
_RULES: list[tuple[str, str, str, re.Pattern]] = [
    # ── exfil ────────────────────────────────────────────────────────────────
    ("telegram_bot", "high", "Telegram bot token embedded (stolen data ships to Telegram)",
     re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("telegram_api", "high", "Calls the Telegram Bot API (api.telegram.org/bot…/sendMessage)",
     re.compile(r"api\.telegram\.org/bot|/sendmessage\?", re.I)),
    ("discord_webhook", "high", "Discord webhook exfil endpoint",
     re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I)),
    ("mail_exfil", "high", "Server-side mail() exfil of captured input",
     re.compile(r"mail\s*\(\s*['\"]?[^'\")\s,]+@", re.I)),
    ("bot_send", "medium", "Bot/webhook send helper (sendMessage / sendDocument / notify)",
     re.compile(r"\bsend(?:message|document|data|log)\b|savedata|save_creds|resultado|resultat", re.I)),
    # ── credential harvesting ────────────────────────────────────────────────
    ("password_field", "medium", "Collects a password",
     re.compile(r"type\s*=\s*['\"]?password", re.I)),
    ("sensitive_fields", "high", "Asks for high-value secrets (card / CVV / SSN / seed phrase / PIN)",
     re.compile(r"cvv|cvc|card\s*number|ccnum|\bcard\s*no\b|social\s*security|\bssn\b|"
                r"seed\s*phrase|mnemonic|recovery\s*phrase|routing\s*number|sort\s*code|\biban\b", re.I)),
    ("grabs_form_values", "medium", "Reads form values in JS and posts them onward",
     re.compile(r"\.value\s*[;,)].{0,40}(fetch|xmlhttprequest|\.ajax|\.send\()", re.I | re.S)),
    # ── obfuscation ──────────────────────────────────────────────────────────
    ("eval_decode", "high", "Obfuscated JS: eval() over decoded data (atob/unescape/fromCharCode)",
     re.compile(r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode|function\s*\()", re.I)),
    ("packer", "high", "Dean-Edwards packed JS (eval(function(p,a,c,k,e,…))",
     re.compile(r"eval\(function\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e", re.I)),
    ("atob_blob", "medium", "Base64-decoded payload (atob / unescape / hex escapes)",
     re.compile(r"atob\s*\(|unescape\s*\(|(?:\\x[0-9a-f]{2}){12,}", re.I)),
    ("big_base64", "low", "Large embedded base64 blob (packed kit / hidden logic)",
     re.compile(r"[A-Za-z0-9+/]{300,}={0,2}")),
    # ── anti-analysis ────────────────────────────────────────────────────────
    ("devtools_guard", "medium", "Anti-analysis: detects/blocks DevTools or the debugger",
     re.compile(r"devtools|debugger;|console\.clear\s*\(|detectdevtool", re.I)),
    ("block_keys", "medium", "Blocks F12 / Ctrl+U / right-click (stop source viewing)",
     re.compile(r"keycode\s*==?\s*123|which\s*==?\s*123|ctrlkey.{0,20}(?:85|117|85\b)|"
                r"oncontextmenu|contextmenu.{0,30}return\s*false|event\.button\s*==?\s*2", re.I)),
    # ── cloaking ─────────────────────────────────────────────────────────────
    ("bot_cloak", "medium", "Cloaking logic: sniffs crawler/bot UAs or navigator.webdriver",
     re.compile(r"googlebot|bingbot|crawler|navigator\.webdriver|phantom|headless|\bspider\b", re.I)),
    ("geoip_cloak", "medium", "Cloaking logic: geo/IP lookup to decide what to serve",
     re.compile(r"ip-?api\.com|ipinfo\.io|ipgeolocation|geoip|freegeoip|cf-ipcountry", re.I)),
    # ── provenance / kit ─────────────────────────────────────────────────────
    ("cloned_site", "low", "Markers of a cloned/mirrored site (HTTrack / 'saved from url')",
     re.compile(r"httrack|saved from url=|mirrored from|<!--\s*saved", re.I)),
    ("kit_author", "medium", "Kit author/handle signature in the source",
     re.compile(r"coded\s*by|created\s*by\s*[:=]|tool\s*by|dev\s*by|scama|panel\s*by", re.I)),
    ("meta_refresh", "low", "Meta-refresh / JS redirect chain (staged delivery)",
     re.compile(r"http-equiv\s*=\s*['\"]?refresh|window\.location(?:\.href)?\s*=", re.I)),
]

_BRANDS = ("microsoft", "office365", "office 365", "outlook", "onedrive", "sharepoint", "paypal",
           "apple", "icloud", "google", "gmail", "facebook", "instagram", "amazon", "netflix",
           "chase", "wellsfargo", "bank of america", "coinbase", "binance", "metamask", "dhl",
           "fedex", "ups", "linkedin", "docusign", "adobe", "wetransfer")


def _host(u: str) -> str:
    try:
        return (urlsplit(u).hostname or "").lower().lstrip("www.")
    except Exception:
        return ""


def analyze_source(html: str, url: str) -> dict:
    """Scan the full page source. Returns {indicators:[{id,severity,title,evidence}], score, brand_flag}."""
    src = html or ""
    low = src.lower()
    inds: list[dict] = []
    seen: set[str] = set()

    for rid, sev, title, pat in _RULES:
        m = pat.search(src)
        if not m or rid in seen:
            continue
        seen.add(rid)
        ev = m.group(0)
        ev = (ev[:60] + "…") if len(ev) > 61 else ev
        inds.append({"id": rid, "severity": sev, "title": title, "evidence": ev.strip()})

    # brand impersonation: a brand named prominently on a domain that ISN'T that brand's
    host = _host(url)
    title_txt = ""
    tm = re.search(r"<title[^>]*>(.*?)</title>", low, re.S)
    if tm:
        title_txt = tm.group(1)
    for b in _BRANDS:
        bkey = b.replace(" ", "")
        if (b in title_txt or (low.count(b) >= 3)) and bkey not in host.replace(" ", "").replace("-", ""):
            inds.append({"id": "brand_impersonation", "severity": "high",
                         "title": f"Impersonates a brand ({b}) on an unrelated domain", "evidence": b})
            break

    # off-host form action / off-host POST target (creds leaving the site)
    for m in re.finditer(r"<form[^>]*\saction\s*=\s*['\"]([^'\"]+)['\"]", src, re.I):
        act = m.group(1)
        ah = _host(act if "//" in act else url)
        if ah and host and ah != host and "type=\"password\"" in low.replace("'", "\""):
            inds.append({"id": "offhost_cred_post", "severity": "high",
                         "title": f"Credential form posts OFF-SITE (to {ah})", "evidence": act[:60]})
            break

    score = sum(SEV_SCORE.get(i["severity"], 5) for i in inds)
    order = {"high": 0, "medium": 1, "low": 2}
    inds.sort(key=lambda i: order.get(i["severity"], 3))
    return {"indicators": inds, "score": min(score, 100),
            "counts": {s: sum(1 for i in inds if i["severity"] == s) for s in ("high", "medium", "low")}}


def score_signals(analysis: dict) -> list[tuple[int, str]]:
    """Fold the code analysis into the verdict — capped so it augments, not dominates, live signals."""
    if not analysis or not analysis.get("indicators"):
        return []
    inds = analysis["indicators"]
    contrib = min(sum(SEV_SCORE.get(i["severity"], 5) for i in inds), 45)
    top = inds[0]["title"]
    n = len(inds)
    return [(contrib, f"source-code analysis: {n} phishing indicator(s) — e.g. {top.lower()}")]
