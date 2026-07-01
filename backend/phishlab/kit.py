"""phishlab/kit.py — phishing-KIT extraction.

After detonation, probe the phishing host for the kit itself: an OPEN DIRECTORY, a LEFT-BEHIND
deployment archive (kits are often just an unzipped .zip that's still sitting in the web root), or
EXPOSED source/backup copies of the PHP (.bak / ~ / .txt …) that serve the code instead of running
it. Statically analyse any recovered source for the real exfil config (Telegram, e-mail, C2) and
actor/kit fingerprints. Bounded + best-effort — a handful of capped requests to the (already
detonated) host; each failure degrades to nothing.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

import httpx

from . import extract as X

TIMEOUT = 6.0
MAX_PROBES = 30
MAX_TEXT = 300_000
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

ARCHIVE_NAMES = ("kit", "login", "panel", "files", "office", "www", "backup", "admin",
                 "next", "result", "auth", "secure", "verify", "mail")
ARCHIVE_EXT = (".zip", ".rar", ".tar.gz", ".7z")
SRC_SUFFIX = (".bak", "~", ".txt", ".save", ".old", ".orig")
# sloppy kits log stolen creds to a file on the server — if exposed, this recovers REAL victim data
CRED_LOGS = ("results.txt", "result.txt", "log.txt", "logs.txt", "data.txt", "victims.txt",
             "accounts.txt", "passwords.txt", "creds.txt", "logins.txt", "out.txt", "mail.txt")
CRED_LINE = re.compile(r"[\w.+-]{2,}@[\w.-]+\.\w{2,}\s*[:|;,\t]\s*\S{2,}")   # email<sep>password

DIRLIST = re.compile(r"Index of /|<title>\s*Index of|Directory listing for|Parent Directory", re.I)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MAILTO = re.compile(r"""mail\s*\(\s*['"]?([^'")\s,]+@[^'")\s,]+)""", re.I)   # PHP mail() recipient
AUTHOR = re.compile(r"(?:author|coded by|created by|dev\s*by|tool\s*by)\s*[:=]?\s*([A-Za-z0-9_\-. ]{3,32})", re.I)


def _candidates(url: str) -> list[str]:
    sp = urlsplit(url)
    base = f"{sp.scheme}://{sp.netloc}"
    path = sp.path or "/"
    dirpath = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"
    labels = [p for p in dirpath.strip("/").split("/") if p]
    dirname = labels[-1] if labels else "kit"
    hostlabel = (sp.hostname or "").split(".")[0]
    out = [base + dirpath, base + "/"]                       # 1) open-dir on the page's dir + web root
    for d in (dirpath, "/"):                                 # 2) credential logs (real victim data)
        for n in CRED_LOGS:
            out.append(base + d + n)
    if not path.endswith("/"):                               # 3) source/backup of the detonated file
        for suf in SRC_SUFFIX:
            out.append(base + path + suf)
    names = list(dict.fromkeys([dirname, hostlabel, *ARCHIVE_NAMES]))
    for d in (dirpath, "/"):                                 # 4) left-behind deployment archives
        for n in names:
            for ext in ARCHIVE_EXT:
                out.append(f"{base}{d}{n}{ext}")
    seen, uniq = set(), []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq[:MAX_PROBES]


async def _probe(client, url: str) -> dict | None:
    try:
        r = await client.get(url, headers={"User-Agent": UA})
        if r.status_code != 200:
            return None
        ctype = (r.headers.get("content-type") or "").lower()
        try:
            size = int(r.headers.get("content-length") or 0) or len(r.content)
        except Exception:
            size = len(r.content or b"")
        text = None
        if any(k in ctype for k in ("text", "html", "php", "xml", "json")) or size < MAX_TEXT:
            try:
                text = r.text[:MAX_TEXT]
            except Exception:
                text = None
        return {"url": url, "ctype": ctype, "size": size, "text": text}
    except Exception:
        return None


async def extract_kit(url: str) -> dict:
    cands = _candidates(url)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, verify=False) as client:
            results = await asyncio.gather(*[_probe(client, u) for u in cands], return_exceptions=True)
    except Exception:
        results = []
    open_dirs, archives, sources, cred_logs, texts = [], [], [], [], []
    for h in results:
        if not isinstance(h, dict) or not h:
            continue
        u, txt = h["url"], (h.get("text") or "")
        fname = u.rsplit("/", 1)[-1].lower()
        cred_lines = CRED_LINE.findall(txt) if txt else []
        if cred_lines and (fname in CRED_LOGS or fname.endswith((".txt", ".log"))):
            victims = sorted(set(EMAIL.findall(" ".join(cred_lines))))
            cred_logs.append({"url": u, "count": len(cred_lines), "victims": victims[:100]})
        elif fname.endswith(ARCHIVE_EXT) or "zip" in h["ctype"] or "octet-stream" in h["ctype"]:
            archives.append({"url": u, "size": h["size"]})
        elif DIRLIST.search(txt):
            open_dirs.append({"url": u})
            texts.append(txt)
        elif txt and u != url:                              # a source/backup that served code
            sources.append({"url": u, "size": h["size"]})
            texts.append(txt)
    blob = "\n".join(texts)
    tg = X.telegram_channels(blob)
    emails = sorted(set(MAILTO.findall(blob)) | (set(EMAIL.findall(blob)) if sources else set()))
    exfil_hosts = sorted({(urlsplit(u).hostname or "") for u in X.off_host_urls(blob, url)} - {""})
    authors = sorted({a.strip() for a in AUTHOR.findall(blob) if len(a.strip()) > 2})
    return {
        "found": bool(archives or open_dirs or sources or cred_logs),
        "open_dirs": open_dirs[:5], "archives": archives[:10], "sources": sources[:10],
        "cred_logs": cred_logs[:5],
        "telegram": tg, "emails": emails[:30], "exfil_hosts": exfil_hosts[:20], "authors": authors[:8],
    }


def score_signals(kit: dict) -> list[tuple[int, str]]:
    out = []
    if not kit:
        return out
    if kit.get("cred_logs"):
        n = sum(c.get("count", 0) for c in kit["cred_logs"])
        out.append((35, f"{n} harvested credential(s) recovered from an exposed log on the host"))
    if kit.get("archives"):
        out.append((25, f"phishing-kit archive left exposed ({kit['archives'][0]['url'].rsplit('/', 1)[-1]})"))
    if kit.get("open_dirs"):
        out.append((12, "open directory on the phishing host"))
    if kit.get("telegram"):
        out.append((20, "Telegram exfil bot recovered from the kit source"))
    if kit.get("emails"):
        out.append((10, "e-mail exfil address in the kit source"))
    return out
