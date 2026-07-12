"""phishlab/mailparse.py — parse a phishing EMAIL (.eml / Outlook .msg) or a loose attachment and pull
out every candidate URL so it can be fed to the detonation engine.

Sources of links: the email body (text + HTML), PDF attachments (link annotations + text + **QR codes**),
HTML attachments (hrefs / text URLs), and **QR codes in image attachments** ("quishing"). Bodies + HTML
are also run through a static **de-obfuscator** (\\xNN / \\uNNNN / fromCharCode / %NN / atob) so packed-JS
harvesters reveal their hidden URLs, and any **Telegram bot-API exfil** channel (bot id + chat id) is
surfaced as a finding (the Telegram API often IS the exfil — there may be no landing URL).

STRICT SAFETY: files are only PARSED / rendered / statically DECODED — never executed. No macros run, no
scripts run; PDFs/images are rendered to bitmaps for QR decode, the de-obfuscator only transforms literal
text (it does not evaluate any JS). Run on the isolated detonation host.
"""
from __future__ import annotations

import base64
import hashlib
import html
import io
import logging
import re
from email import policy
from email.parser import BytesParser

from . import extract as X          # broad scam-signal IOC extraction (phones/wallets/handles/reply-to)

logger = logging.getLogger("phishlab.mailparse")

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"        # .msg (and other OLE compound) file signature
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]\};]+", re.I)
_HREF_RE = re.compile(r"(?:href|src|action|data-href)\s*=\s*[\"']?(https?://[^\"'>\s]+)", re.I)
# refang common threat-intel defanging in bodies (hxxps://evil[.]com)
_DEFANG = [(r"h[x*]{2}ps", "https"), (r"h[x*]{2}p", "http"), (r"\[\.\]", "."), (r"\(\.\)", "."),
           (r"\{\.\}", "."), (r"\[dot\]", "."), (r"\(dot\)", "."), (r"\[:\]", ":"), (r"\[/\]", "/")]


def _refang(t: str) -> str:
    for pat, rep in _DEFANG:
        t = re.sub(pat, rep, t or "", flags=re.I)
    return t


def _clean(u: str) -> str:
    return (u or "").rstrip(".,);:'\"]}>").strip()


# embedded-asset / tracking-pixel URLs (logos, open-trackers, fonts, stylesheets) — never the phishing
# destination, so drop them from the detonation candidate list to keep the analyst's view clean.
_ASSET_RE = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|ico|bmp|tiff?|css|woff2?|ttf|eot|otf)(?:\?|#|$)", re.I)


def _is_asset(url: str) -> bool:
    return bool(_ASSET_RE.search(url or ""))


# template-placeholder artifacts surfaced by de-obfuscation of a kit's SOURCE (before its server fills them
# in): https://${domain}/… , …/bot${TELEGRAM_BOT_TOKEN}/… , {{url}}, <%= x %>, `${x}` — not real URLs.
_TEMPLATE_RE = re.compile(r"\$\{|\$\(|\{\{|<%|<\?|`")


def _is_templated(url: str) -> bool:
    return bool(_TEMPLATE_RE.search(url or ""))


def _find_urls(text: str) -> set[str]:
    """Raw URL scan of already-decoded text — caller handles HTML-entity/defang decoding."""
    out: set[str] = set()
    for m in _URL_RE.findall(text or ""):
        c = _clean(m)
        if c and not _is_asset(c) and not _is_templated(c):
            out.add(c)
    return out


# ── static de-obfuscation ─────────────────────────────────────────────────────────────────────────
# Phishing HTML/JS hides the real URL (and the Telegram exfil token) behind escapes so a naive scan misses
# it. Decode the common tricks STATICALLY — NO JavaScript is executed, nothing is run; we only transform
# the literal text so hidden URLs/tokens become visible to the regex scanners below.
_FCC_RE = re.compile(r"(?:String\.)?fromCharCode\s*\(([\d,\s xX0-9a-fA-F]+)\)", re.I)
_ATOB_RE = re.compile(r"(?:atob|window\.atob)\(\s*['\"]([A-Za-z0-9+/=\s]{12,})['\"]\s*\)", re.I)
_PCT_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")            # ANY run of %NN (single codes count too)
_XESC_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_UESC_RE = re.compile(r"\\u\{?([0-9a-fA-F]{2,6})\}?")


def _fcc(m):
    try:
        nums = re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))
        return "".join(chr(int(x, 0)) for x in nums if 0 <= int(x, 0) < 0x110000)
    except Exception:
        return m.group(0)


def _pct(m):
    try:
        return bytes(int(h, 16) for h in re.findall(r"%([0-9a-fA-F]{2})", m.group(0))).decode("utf-8", "ignore")
    except Exception:
        return m.group(0)


def _atob(m):
    try:
        return base64.b64decode(re.sub(r"\s+", "", m.group(1)) + "===").decode("utf-8", "ignore")
    except Exception:
        return m.group(0)


def _deobf_once(text: str) -> str:
    out = text
    try:
        out = _XESC_RE.sub(lambda m: chr(int(m.group(1), 16)), out)
        out = _UESC_RE.sub(lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0), out)
    except Exception:
        pass
    out = _FCC_RE.sub(_fcc, out)
    out = _PCT_RUN_RE.sub(_pct, out)
    out = _ATOB_RE.sub(_atob, out)
    return out


def _deobfuscate(text: str) -> str:
    """Statically decode nested/mixed obfuscation so hidden URLs / Telegram tokens surface: \\xNN, \\uNNNN,
    String.fromCharCode(dec|0xNN), any run of %NN (decodeURIComponent/unescape/escape output), and
    atob('base64'). Iterates so LAYERED encodings (\\xNN → %NN → real, or double-base64) fully unfold. This
    is PURELY TEXTUAL — it never evaluates JavaScript; it only rewrites literal escape sequences."""
    if not text:
        return ""
    out = text[:3_000_000]              # cap so a pathological blob can't blow up the pass
    for _ in range(4):                  # unfold up to 4 nested layers, stop early when stable
        prev = out
        out = _deobf_once(out)
        if out == prev or len(out) > 6_000_000:
            break
    return out


# Telegram Bot-API exfil: kits POST stolen creds to api.telegram.org/bot<ID>:<TOKEN>/sendMessage?chat_id=<N>.
# The Telegram API IS the exfil channel — there is often NO landing URL to detonate, so surface it as a
# FINDING (not a detonation candidate — we must never ping the attacker's bot).
_TG_BOT_RE = re.compile(r"(\d{6,12}):([A-Za-z0-9_-]{30,45})")
_TG_CHAT_RE = re.compile(r"chat[_ ]?id['\"\s:=]{1,4}(-?\d{5,15})", re.I)


def _telegram_exfil(text: str) -> list[dict]:
    """Telegram bot exfil channels (bot id + token + chat id) found in de-obfuscated source. Deduped."""
    t = _deobfuscate(text or "")
    chats = _TG_CHAT_RE.findall(t)
    out, seen = [], set()
    for m in _TG_BOT_RE.finditer(t):
        bot_id, token = m.group(1), m.group(2)
        if bot_id in seen:
            continue
        seen.add(bot_id)
        out.append({"bot_id": bot_id, "token_prefix": token[:6] + "…",
                    "chat_id": (chats[0] if chats else None)})
    return out


def _image_qr(img_bytes: bytes) -> set[str]:
    """QR-decoded URLs from a raw image (PNG/JPG/GIF) — 'quishing' where the link hides in an inline/attached
    image, not a PDF. Never executes anything."""
    urls: set[str] = set()
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as _qr
    except Exception:
        return urls
    try:
        im = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        for o in _qr(im):
            v = _clean(o.data.decode("utf-8", "ignore"))
            if v.lower().startswith(("http://", "https://")):
                urls.add(v)
            elif "." in v and " " not in v and "://" not in v:
                urls.add("http://" + v)          # bare-domain QR
    except Exception:
        pass
    return urls


def _urls_from_text(text: str) -> set[str]:
    # decode HTML entities (&amp; → &) FIRST so tracked/wrapped URLs aren't left malformed, then ALSO scan a
    # de-obfuscated copy so \xNN / fromCharCode / %NN / atob-hidden URLs surface.
    text = html.unescape(text or "")
    out = _find_urls(_refang(text))
    out |= _find_urls(_refang(_deobfuscate(text)))
    return out


def _urls_from_html(markup: str) -> set[str]:
    markup = html.unescape(markup or "")
    out = _find_urls(_refang(markup))
    out |= _find_urls(_refang(_deobfuscate(markup)))       # de-obfuscated packed JS / escaped strings
    for m in _HREF_RE.findall(markup):
        c = _clean(m)
        if c and not _is_asset(c) and not _is_templated(c):
            out.add(c)
    return out


def _pdf_links(pdf_bytes: bytes) -> tuple[set[str], set[str]]:
    """(text/annotation URLs, QR-decoded URLs) from a PDF. Renders each page to an image and decodes any
    QR codes on it (phishing increasingly hides the link in a QR). Never executes the PDF."""
    text_urls: set[str] = set()
    qr_urls: set[str] = set()
    try:
        import fitz  # PyMuPDF
    except Exception:
        return text_urls, qr_urls
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        return text_urls, qr_urls
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as _qr_decode
    except Exception:
        _qr_decode = None
    try:
        for page in doc:
            try:
                text_urls |= _urls_from_text(page.get_text())
                for lnk in page.get_links():
                    if lnk.get("uri"):
                        text_urls.add(_clean(lnk["uri"]))
            except Exception:
                pass
            if _qr_decode is not None:
                try:
                    pix = page.get_pixmap(dpi=200)
                    im = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                    for o in _qr_decode(im):
                        v = _clean(o.data.decode("utf-8", "ignore"))
                        if v.lower().startswith(("http://", "https://")):
                            qr_urls.add(v)
                        elif "." in v and " " not in v and "://" not in v:
                            qr_urls.add("http://" + v)          # bare-domain QR
                except Exception:
                    pass
    finally:
        try:
            doc.close()
        except Exception:
            pass
    return text_urls, qr_urls


def _att_kind(name: str, ctype: str) -> str:
    n = (name or "").lower()
    c = (ctype or "").lower()
    if n.endswith(".pdf") or "pdf" in c:
        return "pdf"
    if n.endswith((".html", ".htm", ".shtml")) or "html" in c:
        return "html"
    if n.endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".docm", ".xlsm")):
        return "office"
    if n.endswith((".zip", ".rar", ".7z", ".iso", ".img", ".gz", ".tar", ".cab")):
        return "archive"
    if n.endswith((".js", ".vbs", ".hta", ".wsf", ".lnk", ".ps1", ".bat", ".cmd", ".scr", ".jar")):
        return "script"
    if n.endswith((".eml", ".msg")):
        return "email"
    if n.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff")) or c.startswith("image/"):
        return "image"
    return "other"


def _analyze_attachment(name: str, ctype: str, payload: bytes, _depth: int = 0) -> dict:
    """Hash + classify an attachment and extract candidate URLs from PDFs (text + QR), HTML, and (when
    a phishing email is forwarded AS an attachment) recursively from a nested .eml/.msg."""
    kind = _att_kind(name, ctype)
    blob = payload or b""
    sha256 = hashlib.sha256(blob).hexdigest()
    md5 = hashlib.md5(blob).hexdigest()
    sha1 = hashlib.sha1(blob).hexdigest()
    links: list[dict] = []
    telegram: list[dict] = []
    scan_text = ""                                   # decoded text handed up for broad scam-signal scanning
    if kind == "pdf":
        text_urls, qr_urls = _pdf_links(payload)
        for u in sorted(text_urls):
            links.append({"url": u, "source": "pdf-text", "attachment": name})
        for u in sorted(qr_urls):
            links.append({"url": u, "source": "pdf-qr", "attachment": name})
    elif kind == "html":
        markup = payload.decode("utf-8", "ignore")
        for u in sorted(_urls_from_html(markup)):
            links.append({"url": u, "source": "html", "attachment": name})
        telegram = _telegram_exfil(markup)          # a packed-JS harvester often exfils to Telegram, not a URL
        scan_text = markup + "\n" + _deobfuscate(markup)
    elif kind == "image":                            # QR hidden in an inline/attached image ("quishing")
        for u in sorted(_image_qr(payload)):
            links.append({"url": u, "source": "image-qr", "attachment": name})
    elif kind == "email" and _depth < 2:            # a phish email forwarded/attached as .eml/.msg
        try:
            nested = parse(payload, name, _depth + 1)
            for lk in nested.get("links", []):
                links.append({"url": lk["url"], "source": "nested-" + lk.get("source", "link"),
                              "attachment": name})
            telegram = nested.get("telegram_exfil", [])
        except Exception:
            pass
    meta = {"name": name or "(unnamed)", "ctype": ctype or "", "size": len(blob),
            "sha256": sha256, "md5": md5, "sha1": sha1, "kind": kind, "link_count": len(links)}
    return {"meta": meta, "links": links, "kind": kind, "telegram": telegram, "text": scan_text}


def _iter_parts(part):
    """Walk MIME parts, but treat a message/rfc822 sub-message as a TERMINAL (yield it, don't descend)
    so a phish forwarded as an attached email is recursed into as a unit — not flattened into body text."""
    if part.get_content_type() == "message/rfc822":
        yield part
        return
    if part.is_multipart():
        for sub in part.get_payload():
            yield from _iter_parts(sub)
    else:
        yield part


def _auth_results(raw: str) -> dict:
    """Pull spf / dkim / dmarc results out of Authentication-Results / Received-SPF headers."""
    blob = (raw or "").lower()
    def find(k):
        m = re.search(rf"{k}=(\w+)", blob)
        return m.group(1) if m else None
    out = {"spf": find("spf"), "dkim": find("dkim"), "dmarc": find("dmarc")}
    return {k: v for k, v in out.items() if v}


def _parse_eml(data: bytes, _depth: int = 0) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    hdr = {k.lower(): str(v) for k, v in msg.items()}
    received = msg.get_all("received") or []
    headers = {
        "from": str(msg.get("from", "")), "to": str(msg.get("to", "")),
        "subject": str(msg.get("subject", "")), "date": str(msg.get("date", "")),
        "reply_to": str(msg.get("reply-to", "")), "return_path": str(msg.get("return-path", "")),
        "originating": (received[-1][:200] if received else ""),
        "auth": _auth_results((msg.get("authentication-results", "") or "") + " " + (msg.get("received-spf", "") or "")),
    }
    links: list[dict] = []
    attachments: list[dict] = []
    telegram: list[dict] = []
    scan_parts: list[str] = []
    body_preview = ""
    for part in _iter_parts(msg):
        ctype = part.get_content_type()
        if ctype == "message/rfc822":                       # a phish forwarded AS an attached email
            if _depth < 2:
                try:
                    pl = part.get_payload()
                    inner = pl[0] if isinstance(pl, list) and pl else None
                    inner_bytes = inner.as_bytes() if inner is not None else (part.get_payload(decode=True) or b"")
                    fn = part.get_filename() or "attached-email.eml"
                    nested = parse(inner_bytes, fn, _depth + 1)
                    for lk in nested.get("links", []):
                        links.append({"url": lk["url"], "source": "nested-" + lk.get("source", "link"),
                                      "attachment": fn})
                    telegram.extend(nested.get("telegram_exfil", []))
                    attachments.append({"name": fn, "ctype": ctype, "size": len(inner_bytes),
                                        "sha256": hashlib.sha256(inner_bytes).hexdigest(), "kind": "email",
                                        "link_count": len(nested.get("links", []))})
                except Exception:
                    pass
            continue
        if part.is_multipart():
            continue
        fn = part.get_filename()
        disp = part.get_content_disposition()
        if disp == "attachment" or fn:
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            a = _analyze_attachment(fn or "attachment", ctype, payload, _depth)
            attachments.append(a["meta"])
            links.extend(a["links"])
            telegram.extend(a.get("telegram", []))
            if a.get("text"):
                scan_parts.append(a["text"])
        elif ctype == "text/plain":
            try:
                t = part.get_content()
            except Exception:
                t = ""
            body_preview = body_preview or t[:600]
            links.extend({"url": u, "source": "body", "attachment": None} for u in _urls_from_text(t))
            telegram.extend(_telegram_exfil(t))
            scan_parts.append(t + "\n" + _deobfuscate(t))
        elif ctype == "text/html":
            try:
                h = part.get_content()
            except Exception:
                h = ""
            links.extend({"url": u, "source": "body", "attachment": None} for u in _urls_from_html(h))
            telegram.extend(_telegram_exfil(h))
            scan_parts.append(h + "\n" + _deobfuscate(h))
    scam = X.scam_signals("\n".join(scan_parts), headers.get("from"), headers.get("reply_to"))
    return _finish("email", headers, links, attachments, body_preview, telegram, scam)


def _parse_msg(data: bytes, _depth: int = 0) -> dict:
    try:
        import extract_msg
    except Exception:
        return {"kind": "email", "error": "extract-msg not installed (Outlook .msg support)",
                "headers": {}, "links": [], "attachments": [], "telegram_exfil": [], "scam_signals": {"iocs": {}, "confidence": None}}
    m = extract_msg.openMsg(io.BytesIO(data))
    headers = {"from": str(getattr(m, "sender", "") or ""), "to": str(getattr(m, "to", "") or ""),
               "subject": str(getattr(m, "subject", "") or ""), "date": str(getattr(m, "date", "") or ""),
               "reply_to": "", "return_path": "",
               "auth": _auth_results(str(getattr(m, "header", "") or ""))}
    links: list[dict] = []
    telegram: list[dict] = []
    scan_parts: list[str] = []
    body_preview = ""
    for txt, is_html in ((getattr(m, "body", "") or "", False), (getattr(m, "htmlBody", "") or "", True)):
        if isinstance(txt, bytes):
            txt = txt.decode("utf-8", "ignore")
        if not is_html:
            body_preview = body_preview or txt[:600]
        found = _urls_from_html(txt) if is_html else _urls_from_text(txt)
        links.extend({"url": u, "source": "body", "attachment": None} for u in found)
        telegram.extend(_telegram_exfil(txt))
        scan_parts.append(txt + "\n" + _deobfuscate(txt))
    attachments: list[dict] = []
    for att in (getattr(m, "attachments", []) or []):
        try:
            payload = att.data if isinstance(att.data, bytes) else bytes(att.data or b"")
            name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "attachment"
        except Exception:
            continue
        a = _analyze_attachment(name, "", payload, _depth)
        attachments.append(a["meta"])
        links.extend(a["links"])
        telegram.extend(a.get("telegram", []))
        if a.get("text"):
            scan_parts.append(a["text"])
    try:
        m.close()
    except Exception:
        pass
    scam = X.scam_signals("\n".join(scan_parts), headers.get("from"), headers.get("reply_to"))
    return _finish("email", headers, links, attachments, body_preview, telegram, scam)


def _parse_loose(data: bytes, name: str, _depth: int = 0) -> dict:
    """A loose attachment uploaded on its own (a .pdf / .html / etc., not wrapped in an email)."""
    a = _analyze_attachment(name or "file", "", data, _depth)
    scam = X.scam_signals(a.get("text", ""))
    return _finish("file", {"from": "", "subject": name, "auth": {}}, a["links"], [a["meta"]], "",
                   a.get("telegram", []), scam)


def _finish(kind: str, headers: dict, links: list[dict], attachments: list[dict], body_preview: str,
            telegram: list[dict] | None = None, scam: dict | None = None) -> dict:
    seen, uniq = set(), []
    for lk in links:
        u = lk.get("url")
        if u and u not in seen:
            seen.add(u)
            uniq.append(lk)
    tg_seen, tg = set(), []
    for t in (telegram or []):
        bid = t.get("bot_id")
        if bid and bid not in tg_seen:
            tg_seen.add(bid)
            tg.append(t)
    return {"kind": kind, "headers": headers, "links": uniq, "attachments": attachments,
            "body_preview": body_preview, "link_count": len(uniq), "telegram_exfil": tg,
            "scam_signals": scam or {"iocs": {}, "confidence": None}}


def _collect_eml_payloads(data: bytes, out: list) -> None:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    for part in _iter_parts(msg):
        if part.get_content_type() == "message/rfc822":
            try:
                pl = part.get_payload()
                inner = pl[0] if isinstance(pl, list) and pl else None
                inner_bytes = inner.as_bytes() if inner is not None else (part.get_payload(decode=True) or b"")
                out.append((part.get_filename() or "attached-email.eml", inner_bytes))
            except Exception:
                pass
            continue
        if part.is_multipart():
            continue
        fn = part.get_filename()
        if part.get_content_disposition() == "attachment" or fn:
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            out.append((fn or "attachment", payload))


def _collect_msg_payloads(data: bytes, out: list) -> None:
    try:
        import extract_msg
    except Exception:
        return
    m = extract_msg.openMsg(io.BytesIO(data))
    for att in (getattr(m, "attachments", []) or []):
        try:
            payload = att.data if isinstance(att.data, bytes) else bytes(att.data or b"")
            name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "attachment"
            out.append((name, payload))
        except Exception:
            continue
    try:
        m.close()
    except Exception:
        pass


def attachment_payloads(data: bytes, filename: str = "") -> list[tuple[str, bytes]]:
    """Re-extract each attachment's (name, raw_bytes) in the SAME order parse() lists them in
    `attachments[]` — so an index from the parsed view maps back to bytes for re-uploading to a scanner
    (e.g. a PDF → Hybrid Analysis) without a second upload from the browser. Best-effort; never raises."""
    name = (filename or "").lower().strip()
    out: list[tuple[str, bytes]] = []
    try:
        if name.endswith(".msg") or data[:8] == _OLE_MAGIC:
            _collect_msg_payloads(data, out)
        elif name.endswith((".eml", ".txt")) or b"\nReceived:" in data[:8000] or re.match(rb"[\w-]+:\s", data[:200]):
            _collect_eml_payloads(data, out)
        else:
            out.append((filename or "file", data))
    except Exception:
        pass
    return out


def parse(data: bytes, filename: str = "", _depth: int = 0) -> dict:
    """Parse an uploaded .eml / .msg / loose attachment → {kind, headers, links[], attachments[]}.
    Recurses (bounded) into a phish email forwarded AS a .eml/.msg attachment."""
    name = (filename or "").lower().strip()
    try:
        if name.endswith(".msg") or data[:8] == _OLE_MAGIC:
            return _parse_msg(data, _depth)
        if name.endswith((".eml", ".txt")) or b"\nReceived:" in data[:8000] or re.match(rb"[\w-]+:\s", data[:200]):
            return _parse_eml(data, _depth)
        return _parse_loose(data, name, _depth)
    except Exception as exc:
        logger.warning("mailparse failed: %s", exc)
        return {"kind": "file", "error": f"{type(exc).__name__}: {exc}"[:160],
                "headers": {}, "links": [], "attachments": [], "telegram_exfil": [], "scam_signals": {"iocs": {}, "confidence": None}}
