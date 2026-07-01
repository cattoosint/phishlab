"""phishlab/kit.py — phishing-KIT extraction (+ artifact recovery).

After detonation, probe the phishing host for the kit itself: an OPEN DIRECTORY, a LEFT-BEHIND
deployment archive (kits are often just an unzipped .zip still in the web root), EXPOSED source /
backup copies of the PHP, and — the SOC jackpot — a CREDENTIAL-LOG file some kits leave on the
server (recovers the real harvested victim creds). Real hits are DOWNLOADED to data/artifacts/… so
the analyst has the files. Bounded + best-effort.

FALSE-POSITIVE GUARD: many sites (SPAs like twitch) return HTTP 200 + the same app page for ANY
path. We fingerprint that "soft-404 / catch-all" first and reject look-alike hits, and we only count
an archive when the response is ACTUALLY archive bytes (magic / content-type), not just a .zip URL.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import os
import re
import time
import zipfile
from urllib.parse import urlsplit

import httpx

from . import extract as X

TIMEOUT = 6.0
MAX_PROBES = 30
MAX_TEXT = 300_000
MAX_SAVE = 25 * 1024 * 1024
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

ART_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "artifacts")
ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"Rar!", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c")

ARCHIVE_NAMES = ("kit", "login", "panel", "files", "office", "www", "backup", "admin",
                 "next", "result", "auth", "secure", "verify", "mail")
ARCHIVE_EXT = (".zip", ".rar", ".tar.gz", ".7z")
SRC_SUFFIX = (".bak", "~", ".txt", ".save", ".old", ".orig")
CRED_LOGS = ("results.txt", "result.txt", "log.txt", "logs.txt", "data.txt", "victims.txt",
             "accounts.txt", "passwords.txt", "creds.txt", "logins.txt", "out.txt", "mail.txt")

CRED_LINE = re.compile(r"[\w.+-]{2,}@[\w.-]+\.\w{2,}\s*[:|;,\t]\s*\S{2,}")
DIRLIST = re.compile(r"Index of /|<title>\s*Index of|Directory listing for|Parent Directory", re.I)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MAILTO = re.compile(r"""mail\s*\(\s*['"]?([^'")\s,]+@[^'")\s,]+)""", re.I)
AUTHOR = re.compile(r"\b(?:author|coded by|created by|dev by|tool by)\b\s*[:=]?\s*([A-Za-z0-9_.][A-Za-z0-9_\-. ]{2,30})", re.I)
SRC_MARKERS = ("<?php", "$_POST", "$_GET", "$_SERVER", "curl_", "file_get_contents", "sendMessage",
               "fopen(", "fwrite(", "base64_decode")


def _candidates(url: str) -> list[str]:
    sp = urlsplit(url)
    base = f"{sp.scheme}://{sp.netloc}"
    path = sp.path or "/"
    dirpath = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"
    labels = [p for p in dirpath.strip("/").split("/") if p]
    dirname = labels[-1] if labels else "kit"
    hostlabel = (sp.hostname or "").split(".")[0]
    out = [base + dirpath, base + "/"]
    for d in (dirpath, "/"):
        for n in CRED_LOGS:
            out.append(base + d + n)
    if not path.endswith("/"):
        for suf in SRC_SUFFIX:
            out.append(base + path + suf)
    names = list(dict.fromkeys([dirname, hostlabel, *ARCHIVE_NAMES]))
    for d in (dirpath, "/"):
        for n in names:
            for ext in ARCHIVE_EXT:
                out.append(f"{base}{d}{n}{ext}")
    seen, uniq = set(), []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq[:MAX_PROBES]


async def _fetch(client, url):
    try:
        return await client.get(url, headers={"User-Agent": UA})
    except Exception:
        return None


def _is_archive(body: bytes, ctype: str) -> bool:
    return (any(body.startswith(m) for m in ARCHIVE_MAGIC)
            or "zip" in ctype or "x-rar" in ctype or "x-7z" in ctype or "gzip" in ctype
            or "octet-stream" in ctype)


def _save(case_dir: str, url: str, body: bytes) -> str | None:
    try:
        os.makedirs(case_dir, exist_ok=True)
        name = re.sub(r"[^A-Za-z0-9._-]", "_", url.rsplit("/", 1)[-1] or "index")[:80] or "file"
        p = os.path.join(case_dir, name)
        with open(p, "wb") as f:
            f.write(body[:MAX_SAVE])
        return p
    except Exception:
        return None


def _analyze_archive(body: bytes) -> dict:
    """Unzip a recovered kit and CLASSIFY each file — which is the Telegram exfil, which is the
    victim list, which is source — so the analyst doesn't hand-dig through it."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(body))
    except Exception:
        return {}
    files, tg, emails, victims = [], [], set(), set()
    for info in zf.infolist()[:300]:
        name = info.filename
        if name.endswith("/") or info.is_dir():
            continue
        role, note = "file", ""
        if 0 < info.file_size <= 2_000_000:
            try:
                txt = zf.read(info)[:MAX_TEXT].decode("utf-8", "ignore")
            except Exception:
                txt = ""
            t = X.telegram_channels(txt)
            cl = CRED_LINE.findall(txt)
            b = name.rsplit("/", 1)[-1].lower()
            if cl and (b in CRED_LOGS or b.endswith((".txt", ".log", ".csv"))):
                role, note = "victim list", f"{len(cl)} entries"
                victims.update(EMAIL.findall(" ".join(cl)))
            elif t:
                role, note = "telegram exfil", f"bot {t[0]['bot_id']}"
                tg.extend(x for x in t if x not in tg)
            elif MAILTO.search(txt):
                m = MAILTO.findall(txt)
                role, note = "email exfil", (m[0] if m else "")
                emails.update(m)
            elif any(k in txt for k in SRC_MARKERS):
                role = "kit source"
        files.append({"name": name, "size": info.file_size, "role": role, "note": note})
    order = {"victim list": 0, "telegram exfil": 1, "email exfil": 2, "kit source": 3, "file": 4}
    files.sort(key=lambda f: order.get(f["role"], 5))
    return {"files": files[:120], "telegram": tg, "emails": sorted(emails)[:20], "victims": sorted(victims)[:100]}


async def extract_kit(url: str) -> dict:
    sp = urlsplit(url)
    base = f"{sp.scheme}://{sp.netloc}"
    host = sp.hostname or "host"
    cands = _candidates(url)
    case_dir = os.path.join(ART_DIR, f"{re.sub(r'[^A-Za-z0-9.-]', '_', host)}_{int(time.time())}")
    saved_any = False

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, verify=False) as client:
            # soft-404 baseline: a path that CANNOT exist. If the server 200s it (SPA/catch-all),
            # we record its body fingerprint so we can reject every look-alike "hit".
            bl = await _fetch(client, f"{base}/__phishlab_{int(time.time())}_nope__.xyz")
            base_hash = (hashlib.md5(bl.content[:8000]).hexdigest()
                         if (bl is not None and bl.status_code == 200) else None)
            resps = await asyncio.gather(*[_fetch(client, u) for u in cands])
    except Exception:
        return {"found": False}

    open_dirs, archives, sources, cred_logs, texts = [], [], [], [], []
    arch_tg, arch_emails, arch_victims = [], set(), set()
    for u, r in zip(cands, resps):
        if r is None or r.status_code != 200:
            continue
        body = r.content or b""
        ctype = (r.headers.get("content-type") or "").lower()
        # reject the catch-all / soft-404 (same body the server serves for any bogus path)
        if base_hash and hashlib.md5(body[:8000]).hexdigest() == base_hash:
            continue
        fname = u.rsplit("/", 1)[-1].lower()

        if _is_archive(body, ctype):
            path = _save(case_dir, u, body)
            saved_any = saved_any or bool(path)
            ana = _analyze_archive(body) if body[:2] == b"PK" else {}
            archives.append({"url": u, "size": len(body), "saved": path, "contents": ana.get("files", [])})
            for t in ana.get("telegram", []):
                if t not in arch_tg:
                    arch_tg.append(t)
            arch_emails.update(ana.get("emails", []))
            arch_victims.update(ana.get("victims", []))
            continue

        try:
            text = body[:MAX_TEXT].decode("utf-8", "ignore")
        except Exception:
            text = ""
        cred_lines = CRED_LINE.findall(text)
        if cred_lines and (fname in CRED_LOGS or fname.endswith((".txt", ".log"))):
            victims = sorted(set(EMAIL.findall(" ".join(cred_lines))))
            path = _save(case_dir, u, body)
            saved_any = saved_any or bool(path)
            cred_logs.append({"url": u, "count": len(cred_lines), "victims": victims[:100], "saved": path})
        elif DIRLIST.search(text):
            open_dirs.append({"url": u})
            texts.append(text)
        elif u != url and any(m in text for m in SRC_MARKERS):   # actual kit CODE, not the app page
            path = _save(case_dir, u, body)
            saved_any = saved_any or bool(path)
            sources.append({"url": u, "size": len(body), "saved": path})
            texts.append(text)

    blob = "\n".join(texts)
    tg = X.telegram_channels(blob)
    for t in arch_tg:                                       # + telegram found inside the archive
        if t not in tg:
            tg.append(t)
    emails = sorted(set(MAILTO.findall(blob)) | (set(EMAIL.findall(blob)) if sources else set()) | arch_emails)
    if arch_victims:                                        # victims recovered from a log inside the archive
        cred_logs.append({"url": "(inside recovered kit archive)", "count": len(arch_victims),
                          "victims": sorted(arch_victims)[:100], "saved": None})
    exfil_hosts = sorted({(urlsplit(u).hostname or "") for u in X.off_host_urls(blob, url)} - {""})
    authors = sorted({a.strip() for a in AUTHOR.findall(blob) if len(a.strip()) > 2})
    return {
        "found": bool(archives or open_dirs or sources or cred_logs),
        "open_dirs": open_dirs[:5], "archives": archives[:10], "sources": sources[:10],
        "cred_logs": cred_logs[:5], "telegram": tg, "emails": emails[:30],
        "exfil_hosts": exfil_hosts[:20], "authors": authors[:8],
        "saved_to": case_dir if saved_any else None,
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
