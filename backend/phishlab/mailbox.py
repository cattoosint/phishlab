"""phishlab/mailbox.py — Gmail intake (Phase 5c).

Poll a dedicated SOC Gmail over IMAP; for each UNREAD message whose SUBJECT is a single (possibly
defanged) URL, refang it and AUTO-DETONATE. Strict: link-only subject, anything else is ignored — so
it never fires on ordinary mail, only a clean URL someone deliberately forwarded.

Gmail needs IMAP enabled (Settings → Forwarding and POP/IMAP) + an App Password (Google Account →
Security → 2-Step Verification → App passwords). Creds live in the gitignored .env:
    GMAIL_USER=soc-phish@gmail.com
    GMAIL_APP_PASSWORD=xxxxxxxxxxxxxxxx
Dormant until both are set.
"""
from __future__ import annotations

import asyncio
import email
import imaplib
import os
import re
import time
from email.header import decode_header

HOST = "imap.gmail.com"
INTERVAL = int(os.getenv("MAIL_POLL_INTERVAL") or "60")
QUEUE: list[dict] = []      # most-recent-first intake items, for the GUI Inbox
_task: asyncio.Task | None = None

_DEFANG = [("hxxp", "http"), ("hXXp", "http"), ("hxxP", "http"), ("[.]", "."), ("(.)", "."),
           ("{.}", "."), ("[dot]", "."), (" dot ", "."), ("[:]", ":"), ("[/]", "/"),
           ("[at]", "@"), ("(at)", "@"), ("​", "")]
_URL_RE = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?$", re.I)


def _cfg() -> tuple[str, str]:
    return os.getenv("GMAIL_USER") or "", os.getenv("GMAIL_APP_PASSWORD") or ""


def enabled() -> bool:
    u, p = _cfg()
    return bool(u and p)


def _refang(s: str) -> str:
    s = (s or "").strip()
    for a, b in _DEFANG:
        s = s.replace(a, b)
    return s.strip().strip("<>").strip()


def subject_url(subject: str) -> str | None:
    """A URL iff the subject is a SINGLE (defanged) URL and nothing else — otherwise None."""
    s = _refang(subject or "")
    if not s or " " in s or "\t" in s:      # link-only: reject anything with whitespace
        return None
    if not _URL_RE.match(s):
        return None
    return s if s.lower().startswith(("http://", "https://")) else "http://" + s


def _decode(v) -> str:
    if not v:
        return ""
    try:
        return "".join(b.decode(enc or "utf-8", "ignore") if isinstance(b, bytes) else b
                       for b, enc in decode_header(v))
    except Exception:
        return str(v)


def _poll_once() -> list[dict]:
    """Sync IMAP fetch of unread link-only subjects (run in a thread). Marks them read."""
    u, p = _cfg()
    out: list[dict] = []
    M = imaplib.IMAP4_SSL(HOST)
    try:
        M.login(u, p)
        M.select("INBOX")
        typ, data = M.search(None, "UNSEEN")
        for num in (data[0].split() if data and data[0] else []):
            typ, md = M.fetch(num, "(RFC822)")
            if not md or not md[0]:
                continue
            msg = email.message_from_bytes(md[0][1])
            subj = _decode(msg.get("Subject"))
            url = subject_url(subj)
            if url:
                out.append({"url": url, "from": _decode(msg.get("From")), "subject": subj})
            M.store(num, "+FLAGS", "\\Seen")       # processed (link or not) — don't re-scan
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return out


async def _loop(detonate_cb) -> None:
    while True:
        if enabled():
            try:
                for it in await asyncio.to_thread(_poll_once):
                    it["at"] = time.time()
                    it["sid"] = None
                    QUEUE.insert(0, it)
                    del QUEUE[60:]
                    try:
                        it["sid"] = detonate_cb(it["url"])       # auto-detonate
                    except Exception:
                        pass
            except Exception:
                pass
        await asyncio.sleep(INTERVAL)


def start(detonate_cb) -> None:
    global _task
    if _task is None and enabled():
        _task = asyncio.create_task(_loop(detonate_cb))
