"""phishlab/mailparse.py — parse a phishing EMAIL (.eml / Outlook .msg) or a loose attachment and pull
out every candidate URL so it can be fed to the detonation engine.

Sources of links: the email body (text + HTML), PDF attachments (embedded link annotations + text URLs
+ **QR codes** decoded from the rendered pages — "quishing"), and HTML attachments (hrefs / text URLs).

STRICT SAFETY: files are only PARSED / rendered — never executed. No macros run, no scripts run; PDFs
are rendered to images for QR decode, Office/other files are hashed + listed only. Run on the isolated
detonation host.
"""
from __future__ import annotations

import hashlib
import html
import io
import logging
import re
from email import policy
from email.parser import BytesParser

logger = logging.getLogger("phishlab.mailparse")

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"        # .msg (and other OLE compound) file signature
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]\}]+", re.I)
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


def _find_urls(text: str) -> set[str]:
    """Raw URL scan of already-decoded text — caller handles HTML-entity/defang decoding."""
    out: set[str] = set()
    for m in _URL_RE.findall(text or ""):
        c = _clean(m)
        if c and not _is_asset(c):
            out.add(c)
    return out


def _urls_from_text(text: str) -> set[str]:
    # decode HTML entities (&amp; → &) FIRST so tracked/wrapped URLs aren't left malformed
    return _find_urls(_refang(html.unescape(text or "")))


def _urls_from_html(markup: str) -> set[str]:
    markup = html.unescape(markup or "")
    out = _find_urls(_refang(markup))
    for m in _HREF_RE.findall(markup):
        c = _clean(m)
        if c and not _is_asset(c):
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
    return "other"


def _analyze_attachment(name: str, ctype: str, payload: bytes, _depth: int = 0) -> dict:
    """Hash + classify an attachment and extract candidate URLs from PDFs (text + QR), HTML, and (when
    a phishing email is forwarded AS an attachment) recursively from a nested .eml/.msg."""
    kind = _att_kind(name, ctype)
    sha256 = hashlib.sha256(payload or b"").hexdigest()
    links: list[dict] = []
    if kind == "pdf":
        text_urls, qr_urls = _pdf_links(payload)
        for u in sorted(text_urls):
            links.append({"url": u, "source": "pdf-text", "attachment": name})
        for u in sorted(qr_urls):
            links.append({"url": u, "source": "pdf-qr", "attachment": name})
    elif kind == "html":
        for u in sorted(_urls_from_html(payload.decode("utf-8", "ignore"))):
            links.append({"url": u, "source": "html", "attachment": name})
    elif kind == "email" and _depth < 2:            # a phish email forwarded/attached as .eml/.msg
        try:
            nested = parse(payload, name, _depth + 1)
            for lk in nested.get("links", []):
                links.append({"url": lk["url"], "source": "nested-" + lk.get("source", "link"),
                              "attachment": name})
        except Exception:
            pass
    meta = {"name": name or "(unnamed)", "ctype": ctype or "", "size": len(payload or b""),
            "sha256": sha256, "kind": kind, "link_count": len(links)}
    return {"meta": meta, "links": links, "kind": kind}


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
        elif ctype == "text/plain":
            try:
                t = part.get_content()
            except Exception:
                t = ""
            body_preview = body_preview or t[:600]
            links.extend({"url": u, "source": "body", "attachment": None} for u in _urls_from_text(t))
        elif ctype == "text/html":
            try:
                h = part.get_content()
            except Exception:
                h = ""
            links.extend({"url": u, "source": "body", "attachment": None} for u in _urls_from_html(h))
    return _finish("email", headers, links, attachments, body_preview)


def _parse_msg(data: bytes, _depth: int = 0) -> dict:
    try:
        import extract_msg
    except Exception:
        return {"kind": "email", "error": "extract-msg not installed (Outlook .msg support)",
                "headers": {}, "links": [], "attachments": []}
    m = extract_msg.openMsg(io.BytesIO(data))
    headers = {"from": str(getattr(m, "sender", "") or ""), "to": str(getattr(m, "to", "") or ""),
               "subject": str(getattr(m, "subject", "") or ""), "date": str(getattr(m, "date", "") or ""),
               "reply_to": "", "return_path": "",
               "auth": _auth_results(str(getattr(m, "header", "") or ""))}
    links: list[dict] = []
    body_preview = ""
    for txt, is_html in ((getattr(m, "body", "") or "", False), (getattr(m, "htmlBody", "") or "", True)):
        if isinstance(txt, bytes):
            txt = txt.decode("utf-8", "ignore")
        if not is_html:
            body_preview = body_preview or txt[:600]
        found = _urls_from_html(txt) if is_html else _urls_from_text(txt)
        links.extend({"url": u, "source": "body", "attachment": None} for u in found)
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
    try:
        m.close()
    except Exception:
        pass
    return _finish("email", headers, links, attachments, body_preview)


def _parse_loose(data: bytes, name: str, _depth: int = 0) -> dict:
    """A loose attachment uploaded on its own (a .pdf / .html / etc., not wrapped in an email)."""
    a = _analyze_attachment(name or "file", "", data, _depth)
    return _finish("file", {"from": "", "subject": name, "auth": {}}, a["links"], [a["meta"]], "")


def _finish(kind: str, headers: dict, links: list[dict], attachments: list[dict], body_preview: str) -> dict:
    seen, uniq = set(), []
    for lk in links:
        u = lk.get("url")
        if u and u not in seen:
            seen.add(u)
            uniq.append(lk)
    return {"kind": kind, "headers": headers, "links": uniq, "attachments": attachments,
            "body_preview": body_preview, "link_count": len(uniq)}


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
                "headers": {}, "links": [], "attachments": []}
