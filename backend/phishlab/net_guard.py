"""phishlab/net_guard.py — SSRF guard for detonation/enrichment targets.

PhishLab visits attacker-controlled URLs (and AUTO-detonates URLs forwarded by e-mail). A hostile page
can point its own hostname at an internal IP, so before we fetch a target we resolve it and refuse
loopback / RFC1918 / link-local (169.254.169.254 cloud-metadata) / CGNAT / reserved addresses. Real
phishing is always on a public IP, so this costs nothing for the intended use. The tool's OWN server
(127.0.0.1:<port>, which serves the built-in /demo-phish/ test kit) is the single allowed exception.
Set PHISH_ALLOW_INTERNAL=1 to disable (e.g. an intentional internal test range).
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlsplit

_OWN_PORT = int(os.getenv("PHISH_PORT") or "8090")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_internal(ipstr: str) -> bool:
    try:
        ip = ipaddress.ip_address(ipstr)
    except Exception:
        return True   # unparseable -> treat as unsafe
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified
            or (ip.version == 4 and ip in _CGNAT))


def check_target(url: str) -> tuple[bool, str]:
    """(ok, reason). ok=False means the URL must NOT be fetched/detonated."""
    if (os.getenv("PHISH_ALLOW_INTERNAL") or "").strip().lower() in ("1", "true", "yes", "on"):
        return True, "internal allowed (PHISH_ALLOW_INTERNAL)"
    try:
        sp = urlsplit(url)
    except Exception:
        return False, "malformed URL"
    if sp.scheme not in ("http", "https"):
        return False, f"scheme not allowed ({sp.scheme or 'none'})"
    host = (sp.hostname or "").lower()
    if not host:
        return False, "no host"
    port = sp.port or (443 if sp.scheme == "https" else 80)
    if host in ("127.0.0.1", "localhost", "::1") and port == _OWN_PORT:
        return True, "own server"     # serves /demo-phish/ + the console — trusted
    try:
        ips = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except Exception:
        return False, "DNS resolution failed"
    for ip in ips:
        if _is_internal(ip):
            return False, f"internal/private/metadata target ({host} -> {ip})"
    return True, "public"
