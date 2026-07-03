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
import json
import os
import re
import time
from email.header import decode_header

HOST = "imap.gmail.com"
INTERVAL = int(os.getenv("MAIL_POLL_INTERVAL") or "30")
QUEUE: list[dict] = []      # most-recent-first intake items, for the GUI Inbox
_task: asyncio.Task | None = None
_STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "mail_state.json")


def _load_uid():
    """The last handled UID from a prior run, or None if this mailbox was never initialised."""
    try:
        with open(_STATE, encoding="utf-8") as f:
            v = json.load(f).get("last_uid")
            return int(v) if v is not None else None
    except Exception:
        return None


def _save_uid() -> None:
    try:
        os.makedirs(os.path.dirname(_STATE), exist_ok=True)
        with open(_STATE, "w", encoding="utf-8") as f:
            json.dump({"last_uid": _last_uid}, f)
    except Exception:
        pass

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


_last_uid = -1   # -1 = not initialised this process; persisted to mail_state.json across restarts


def _poll_once() -> list[dict]:
    """Fetch only NEW mail (UID > watermark) whose subject is a link-only URL. Runs in a thread.

    SAFETY: never touches the existing inbox — no mass mark-read. On the first poll it simply watermarks
    at the current newest UID and processes nothing, so pre-existing mail is ignored entirely. Only mail
    that arrives AFTER activation is considered; the UID watermark (not the \\Seen flag) prevents re-runs,
    so the account's read/unread state is left alone."""
    global _last_uid
    u, p = _cfg()
    out: list[dict] = []
    M = imaplib.IMAP4_SSL(HOST)
    try:
        M.login(u, p)
        M.select("INBOX")
        if _last_uid == -1:                                    # first poll this process
            saved = _load_uid()
            if saved is not None:
                _last_uid = saved                              # resume — catch mail forwarded during downtime
            else:                                              # genuine first run: baseline, ignore all history
                typ, data = M.uid("search", None, "ALL")
                uids = data[0].split() if data and data[0] else []
                _last_uid = int(uids[-1]) if uids else 0
                _save_uid()
                return []
        typ, data = M.uid("search", None, f"{_last_uid + 1}:*")
        for raw in (data[0].split() if data and data[0] else []):
            uid = int(raw)
            if uid <= _last_uid:                               # IMAP 'n:*' can echo the newest — skip it
                continue
            _last_uid = max(_last_uid, uid)
            # read ONLY the Subject/From headers (BODY.PEEK = don't mark read, HEADER.FIELDS = no body)
            typ, md = M.uid("fetch", raw, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])")
            if not md or not md[0] or not isinstance(md[0], tuple):
                continue
            hdr = email.message_from_bytes(md[0][1])
            url = subject_url(_decode(hdr.get("Subject")))
            if not url:
                continue                              # not the link format → never read/store the email
            out.append({"url": url, "from": _decode(hdr.get("From")), "subject": _decode(hdr.get("Subject"))})
        _save_uid()          # persist the advanced watermark so downtime mail isn't lost on a restart
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
                from . import net_guard as G
                for it in await asyncio.to_thread(_poll_once):
                    it["at"] = time.time()
                    it["sid"] = None
                    QUEUE.insert(0, it)
                    del QUEUE[60:]
                    ok, why = G.check_target(it["url"])          # SSRF guard on forwarded URLs
                    if not ok:
                        it["skipped"] = why
                        continue
                    try:
                        it["sid"] = detonate_cb(it["url"])        # auto-detonate
                    except Exception:
                        pass
            except Exception:
                pass
        await asyncio.sleep(INTERVAL)


def dismiss(url: str) -> bool:
    """Remove an item from the intake list — used when it's marked phishing (moved to a case) or a FP."""
    before = len(QUEUE)
    QUEUE[:] = [it for it in QUEUE if it.get("url") != url]
    return len(QUEUE) < before


def start(detonate_cb) -> None:
    global _task
    if _task is None and enabled():
        _task = asyncio.create_task(_loop(detonate_cb))
