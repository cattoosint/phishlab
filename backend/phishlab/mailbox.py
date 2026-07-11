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


# Only ACT on intake mail from a trusted SOC sender — the box also receives UptimeRobot / Google Alerts /
# LinkedIn / newsletters, which must never be auto-detonated. Default: SOC ALERTS (SOC@example.com).
# Override/extend via MAIL_INTAKE_SENDERS (comma-separated); a bare "@domain" entry trusts a whole domain.
_INTAKE_SENDERS = {s.strip().lower() for s in
                   (os.getenv("MAIL_INTAKE_SENDERS") or "SOC@example.com").split(",") if s.strip()}


def _sender_allowed(frm: str) -> bool:
    from email.utils import parseaddr
    addr = (parseaddr(frm or "")[1] or "").strip().lower()
    if not _INTAKE_SENDERS:
        return True                                  # empty allowlist = accept all (explicit opt-out)
    if addr in _INTAKE_SENDERS:
        return True
    dom = addr.split("@")[-1] if "@" in addr else ""
    return bool(dom) and any(a.startswith("@") and dom == a[1:] for a in _INTAKE_SENDERS)


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
    """Fetch NEW mail (UID > watermark): detonate a link-only subject URL AND any links found in the
    attachments (PDF text + QR codes, HTML, or a phish forwarded as a .eml/.msg). Runs in a thread.

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
            # fetch the FULL message (BODY.PEEK = never sets \Seen) — we need the body + attachments so a
            # phish forwarded/attached as .eml/.msg/.pdf/.html gets parsed the same as a manual upload.
            typ, md = M.uid("fetch", raw, "(BODY.PEEK[])")
            if not md or not md[0] or not isinstance(md[0], tuple):
                continue
            full = md[0][1]
            hdr = email.message_from_bytes(full)
            subj, frm = _decode(hdr.get("Subject")), _decode(hdr.get("From"))
            if not _sender_allowed(frm):                       # only trusted SOC sender (SOC@example.com)
                continue                                       # ignore UptimeRobot / alerts / newsletters
            found: list[tuple[str, str]] = []
            body_links: list[tuple[str, str]] = []
            surl = subject_url(subj)                          # mode 1: a link-only subject
            if surl:
                found.append((surl, "subject"))
            if len(full) <= 30_000_000:                        # parse attachments (PDF text/QR, HTML, nested email)
                try:
                    from . import mailparse as MP
                    for lk in MP.parse(full, "intake.eml").get("links", []):
                        src = lk.get("source", "attachment")
                        if src == "body":                      # the analyst's forwarding note, usually — hold as fallback
                            body_links.append((lk["url"], src))
                        else:                                  # mode 2: link from a PDF/HTML/nested attached phish
                            found.append((lk["url"], src))
                except Exception:
                    pass
            if not found:                                      # nothing attached & no subject URL → treat an inline-
                found = body_links                             # forwarded phish's body links as the candidates
            seen = set()
            for url, source in found:                          # one intake item per distinct link
                if url in seen:
                    continue
                seen.add(url)
                out.append({"url": url, "from": frm, "subject": subj, "source": source})
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
