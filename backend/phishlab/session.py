"""phishlab/session.py — a LIVE, pausable detonation session (backs Phase 4b: interactive handover).

sandbox.detonate() is one-shot. A Session instead keeps the browser + page ALIVE, captures a live
frame continuously (polled ~2-3 fps by the GUI), and PAUSES when an anti-bot gate is detected
(state='handover') — the analyst solves it in the live view (clicks/keys are forwarded to the page)
and hits Resume, then the robotic step-through continues. No stepping out of the app.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from urllib.parse import quote, urlsplit

from . import browser as B
from . import enrich as E
from . import extract as X
from . import indicators as I
from . import kit as K
from . import tracker as T
from .sandbox import (MAX_STEPS, SETTLE_MS, _cloak_verdict, _fake_identity, _host, _merge_ip,
                      _snapshot, _verdict, scanner_view)

FRAME_INTERVAL = 0.4      # ~2.5 fps live view
FRAME_QUALITY = 66

SESSIONS: dict[str, "Session"] = {}
CASES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cases")
SESSION_CAP = int(os.getenv("PHISH_SESSION_CAP") or "50")   # sessions kept in RAM; older done ones evict to disk


def _persist(sess) -> None:
    """Write a finished detonation's evidence to disk so it survives a restart."""
    try:
        os.makedirs(CASES_DIR, exist_ok=True)
        with open(os.path.join(CASES_DIR, sess.id + ".json"), "w", encoding="utf-8") as f:
            json.dump({"id": sess.id, "state": sess.state, "report": sess.report, "saved_at": time.time()}, f)
    except Exception:
        pass


def _jpeg_dims(data: bytes):
    """(w,h) of a JPEG from its SOF marker — to compare the streamed frame size to the page viewport
    (a mismatch breaks take-over click mapping)."""
    try:
        i, n = 2, len(data)
        while i < n - 9:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                return {"w": (data[i + 7] << 8) | data[i + 8], "h": (data[i + 5] << 8) | data[i + 6]}
            i += 2 + ((data[i + 2] << 8) | data[i + 3])
    except Exception:
        pass
    return None


def _evict() -> None:
    """Bound RAM: drop the oldest done/error sessions from memory (their report is on disk)."""
    if len(SESSIONS) <= SESSION_CAP:
        return
    done = sorted((s for s in SESSIONS.values() if s.state in ("done", "error", "cancelled")),
                  key=lambda s: (s.report.get("started_at") or 0))
    for s in done[:len(SESSIONS) - SESSION_CAP]:
        SESSIONS.pop(s.id, None)


class _Done:
    """A completed session loaded from disk — report/evidence only, no live browser."""

    def __init__(self, data):
        self.id = data.get("id")
        self.state = data.get("state", "done")
        self.report = data.get("report") or {}
        self.latest_frame = None
        self.paused = False

    def snapshot_state(self):
        return {"id": self.id, "state": self.state, "paused": False, "report": self.report, "has_frame": False}

    async def forward(self, ev):
        pass

    def request_takeover(self):
        pass

    def resume(self):
        pass


class Session:
    def __init__(self, url: str):
        self.id = uuid.uuid4().hex[:12]
        self.url = url
        self.state = "starting"   # starting | running | handover | done | error
        self.report = {
            "url": url, "started_at": time.time(), "narration": [], "steps": [],
            "exfil": {"form_actions": [], "telegram": []}, "iocs": {}, "decloak": None,
            "cloaking": None, "challenge": [], "handover_needed": False, "verdict": None,
        }
        self.latest_frame: bytes | None = None
        self.viewport = {"width": 1280, "height": 720}
        self._frame_dims = None
        self._page = None
        self.paused = False
        self._gate = asyncio.Event()
        self._gate.set()          # set = automation may proceed; clear = paused for takeover
        self._task: asyncio.Task | None = None

    def _log(self, m): self.report["narration"].append(m)

    def _pause(self):
        self.paused = True
        self._gate.clear()
        self.state = "handover"

    async def _checkpoint(self) -> bool:
        """Block while paused (analyst takeover). Returns True if it actually waited."""
        if self.paused:
            self.state = "handover"
            await self._gate.wait()
            self.state = "running"
            return True
        return False

    async def _wait_for_advance(self, page, cap_ms: int = 65000) -> bool:
        """Sit through a 'please wait' interstitial — wait for the page to navigate onward (handles a
        ~60s countdown/redirect). Returns True if it advanced on its own."""
        start = page.url
        try:
            await page.wait_for_url(lambda u: u != start, timeout=cap_ms)
            return True
        except Exception:
            return False

    def request_takeover(self):
        """Analyst pressed 'Take over' — pause automation so they can drive the live browser."""
        if self.state in ("running", "handover", "starting"):
            self._pause()
            self._log("Analyst TOOK OVER — automation paused. Solve/interact in the frame, then Resume automation.")

    def resume(self):
        self.paused = False
        if self.state == "handover":          # unstick the state even if the walker wasn't blocked at a
            self.state = "running"            # checkpoint when Take-over fired (else it stays 'handover')
        self._gate.set()

    def cancel(self):
        """Abort a running scan — cancel the task; the run() finally closes the browser + persists what
        was captured so far. Idempotent; a no-op on an already-finished session."""
        if self.state in ("done", "error", "cancelled"):
            return
        self.state = "cancelled"
        self._log("Scan cancelled by the analyst.")
        self._gate.set()                        # release any pause / checkpoint wait
        if self._task and not self._task.done():
            self._task.cancel()

    async def _reveal_by_interaction(self, page):
        """Dispatch human-like mouse/scroll/click + wait out timer-gated reveals — some kits render the
        credential form only after real interaction (CrawlPhish user-interaction cloaking). Best-effort."""
        try:
            for x, y in ((180, 200), (420, 320), (640, 260), (300, 500)):
                await page.mouse.move(x, y)
                await page.wait_for_timeout(90)
            await page.mouse.wheel(0, 700)
            await page.wait_for_timeout(250)
            await page.mouse.wheel(0, -350)
            try:
                await page.evaluate("() => { window.dispatchEvent(new Event('scroll'));"
                                    " document.body && document.body.dispatchEvent("
                                    "new MouseEvent('mousemove', {bubbles: true})); }")
            except Exception:
                pass
            await page.wait_for_timeout(2500)   # sit out setTimeout-gated reveals
        except Exception:
            pass

    async def _frame_loop(self):
        while self.state not in ("done", "error", "cancelled"):
            pg = self._page
            if pg is not None:
                try:
                    self.latest_frame = await pg.screenshot(type="jpeg", quality=FRAME_QUALITY)
                    self._frame_dims = _jpeg_dims(self.latest_frame) or self._frame_dims
                except Exception:
                    pass   # screenshots can fail mid-navigation; just skip the frame
            # stream fast while the analyst is driving (handover), slower while automation runs
            await asyncio.sleep(0.12 if self.state == "handover" else FRAME_INTERVAL)

    async def _sync_viewport(self, page):
        """Track the page's REAL inner size so forwarded takeover clicks/drags map correctly. The victim
        context has no fixed viewport (Camoufox sets its own), so page.viewport_size is often None/stale —
        read innerWidth/innerHeight from the page. Called after load + each step so a slider solve lands."""
        try:
            vp = await page.evaluate("() => ({w: window.innerWidth, h: window.innerHeight})")
            if vp and vp.get("w") and vp.get("h"):
                self.viewport = {"width": vp["w"], "height": vp["h"]}
        except Exception:
            pass

    async def run(self):
        t0 = self.report["started_at"]
        frames = None
        try:
            async with B.launch() as brw:
                self.state = "running"
                self._log(f"Detonating {self.url}")
                # Create the victim page + start the LIVE stream BEFORE navigating, so the analyst
                # watches the page load. A heavy/slow site then looks like it's loading (not blank/
                # stuck) and a nav timeout no longer crashes the run.
                vctx = await B.new_victim_context(brw)
                page = await vctx.new_page()
                self._page = page
                try:
                    self.viewport = page.viewport_size or self.viewport
                except Exception:
                    pass
                frames = asyncio.create_task(self._frame_loop())
                chain: list[str] = []
                net: list[dict] = []
                filled_vals: set[str] = set()      # fake values we typed — to diff against what got transmitted

                def _on_req(req):
                    try:
                        if len(net) < 300:
                            e = {"method": req.method, "url": req.url, "type": req.resource_type}
                            if req.method in ("POST", "PUT", "PATCH") or req.resource_type in ("xhr", "fetch"):
                                try:
                                    e["body"] = (req.post_data or "")[:3000]   # what actually left the box
                                except Exception:
                                    e["body"] = ""
                            net.append(e)
                    except Exception:
                        pass

                page.on("request", _on_req)

                def _on_resp(resp):
                    try:
                        if resp.request.is_navigation_request() and (not chain or chain[-1] != resp.url):
                            chain.append(resp.url)
                    except Exception:
                        pass

                page.on("response", _on_resp)
                self._log("Loading the page…")
                r = None
                try:
                    # arrive as a victim would — from their webmail — so referer-gated kits render the phish
                    r = await page.goto(self.url, wait_until="domcontentloaded", timeout=B.NAV_TIMEOUT,
                                        referer="https://mail.google.com/")
                except Exception:
                    self._log("(page slow to load — continuing with whatever rendered)")
                await page.wait_for_timeout(SETTLE_MS)
                await self._sync_viewport(page)      # accurate frame->page coord mapping for takeover
                sc = await scanner_view(brw, self.url)
                try:
                    vtitle = await page.title()
                except Exception:
                    vtitle = ""
                vic = {"reached": True, "url": page.url, "status": (r.status if r else None), "title": vtitle}
                dc = {"scanner": sc, "victim": vic, "cloaked": _cloak_verdict(sc, vic), "redirect_chain": chain[:20]}
                self.report["decloak"] = dc
                self.report["cloaking"] = {"detected": dc["cloaked"].startswith("cloaked"), "kind": dc["cloaked"]}
                self._log(f"Decloak - scanner={dc['scanner'].get('url')} victim={dc['victim'].get('url')} verdict={dc['cloaked']}")
                # host/CDN error page (Cloudflare 52x etc.) = the site is DOWN, not a live phish
                _vs = vic.get("status")
                if (_vs and (520 <= _vs <= 527 or _vs in (502, 503, 504))) or any(
                        k in (vtitle or "").lower() for k in ("connection timed out", "error code 52",
                                                              "522:", "web server is down")):
                    self.report["site_down"] = True
                    self._log(f"Site appears DOWN — host/CDN error ({_vs or 'error page'}). Nothing to detonate.")

                # phase-1 IP/geo cloaking: compare what direct / Tor / NordVPN are each served
                self._log("Decloak (multi-vantage) - comparing direct / Tor / NordVPN views…")
                try:
                    probes = await T.vantage_probe(self.url)
                    mv = T.multi_vantage_verdict(probes)
                    dc["vantages"] = probes
                    dc["multi_vantage"] = mv
                    if mv.get("cloaked"):
                        self.report["cloaking"]["ip_geo"] = True
                        self._log(f"  IP/geo CLOAKING likely - {', '.join(mv.get('diffs', []))}")
                        try:                          # cloaked -> capture what EACH vantage actually saw
                            self._log("  capturing per-vantage screenshots so you can see each view…")
                            dc["vantage_views"] = await T.capture_views(self.url)
                        except Exception:
                            pass
                    else:
                        self._log(f"  consistent across {mv.get('responded', 0)} vantage(s) - no IP/geo cloaking")
                    # referer-gated cloaking axis — some kits only render for a visitor arriving from webmail
                    ref = await T.referer_probe(self.url)
                    if ref:
                        dc["referer"] = ref
                        if ref.get("gated"):
                            self.report["cloaking"]["referer"] = True
                            self._log("  content differs WITH a webmail referer — referer-gated cloaking IOC.")
                except Exception:
                    pass

                all_html = []
                fake = _fake_identity()
                waited: set[str] = set()      # URLs we've already sat through a 'wait' on
                acted: set[str] = set()        # URLs we've already filled/clicked (stall guard)
                interacted: set[str] = set()   # URLs we've already tried an interaction-reveal on
                login_hunted: set[str] = set() # URLs where we've already followed a 'log in' link
                for step in range(MAX_STEPS):
                    if await self._checkpoint():          # analyst took over before this step
                        await page.wait_for_timeout(SETTLE_MS)
                    snap = await _snapshot(page)
                    await self._sync_viewport(page)   # keep coord mapping current as the page navigates
                    all_html.append(snap["html"] or "")
                    forms = await B.detect_forms(page)
                    tg = X.telegram_channels(snap["html"] or "")
                    ch = X.detect_challenge(snap.get("title"), snap.get("html") or "")
                    self.report["steps"].append({
                        "i": step, "action": "load", "url": snap["url"], "title": snap["title"],
                        "screenshot": snap["screenshot"], "forms": forms, "telegram": tg, "challenge": ch,
                    })
                    self.report["exfil"]["telegram"].extend(tg)
                    self.report["exfil"]["form_actions"].extend(f.get("action") for f in forms if f.get("action"))
                    for c in ch:
                        if c not in self.report["challenge"]:
                            self.report["challenge"].append(c)
                    self._log(f"Step {step}: {snap['url']} - \"{snap['title']}\" - {len(forms)} form(s)"
                              + (f" - TELEGRAM exfil bot {tg[0]['bot_id']}" if tg else ""))

                    if snap["url"] in acted and not any(f.get("has_password") for f in forms):
                        self._log("Back on a page already handled - no progress, stopping step-through.")
                        break

                    if ch:
                        # anti-bot gate → auto-pause for takeover; re-evaluate the page after resume.
                        self.report["handover_needed"] = True
                        self._log(f"Step {step}: anti-bot gate ({', '.join(ch)}) - Take over to solve it, then Resume automation.")
                        self._pause()
                        await self._checkpoint()
                        self._log("Resumed - re-checking the page.")
                        await page.wait_for_timeout(SETTLE_MS)
                        continue

                    # 'please wait / verifying' interstitial (no cred form): SIT THROUGH IT once, then re-check
                    if (X.is_wait_page(snap.get("title"), snap.get("html"))
                            and not any(f.get("has_password") for f in forms)
                            and snap["url"] not in waited):
                        waited.add(snap["url"])
                        self._log(f"Step {step}: interstitial ('please wait') - waiting for it to advance…")
                        if not await self._wait_for_advance(page):
                            btn = await B.click_advance(page)
                            if btn:
                                self._log(f"  it didn't auto-advance - clicked '{btn}'")
                        await page.wait_for_timeout(SETTLE_MS)
                        continue

                    if await self._checkpoint():          # analyst took over before we fill
                        await page.wait_for_timeout(SETTLE_MS)
                        continue

                    # LOGIN vs LEAD-CAPTURE: a form with no password but name+email/phone is a marketing
                    # lead-capture, NOT a credential login. Hunt for the REAL login page before filling it.
                    has_cred = any(f.get("has_password") for f in forms)
                    if (not has_cred and any(f.get("kind") == "lead_capture" for f in forms)
                            and snap["url"] not in login_hunted and len(login_hunted) < 2):
                        login_hunted.add(snap["url"])
                        links = await B.find_login_link(page)
                        if links:
                            tgt = links[0]["href"]
                            self._log(f"Step {step}: lead-capture form (name/email/phone, no password) — not a "
                                      f"login. Following the real login page: '{links[0].get('text') or tgt}'")
                            self.report["steps"].append({
                                "i": step, "action": "seek_login", "url": snap["url"], "to": tgt,
                                "note": f"lead-capture form here; followed a login link to {tgt}"})
                            try:
                                await page.goto(tgt, wait_until="domcontentloaded", timeout=B.NAV_TIMEOUT)
                                await page.wait_for_timeout(SETTLE_MS)
                                continue
                            except Exception:
                                self._log("  couldn't open that login link — treating the lead form as the target.")
                        else:
                            self._log(f"Step {step}: lead-capture form only, no login page linked — looks like "
                                      f"a lead/marketing funnel, not a credential phish.")

                    # fill ANY field the page asks for (password, email, phone, OTP/code, text) with FAKE data
                    filled = await B.fill_fields(page, fake)
                    acted.add(snap["url"])
                    if filled:
                        filled_vals.update(str(x.get("value", "")) for x in filled if len(str(x.get("value", ""))) >= 4)
                        dest = next((f.get("action") for f in forms if f.get("action")), None) or snap["url"]
                        off = bool(_host(dest) and _host(dest) != _host(snap["url"]))
                        summary = ", ".join(f"{x['kind']}={x['value']}" for x in filled)
                        self._log(f"Step {step}: entered {summary}  ->  {dest}" + ("  [!] OFF-SITE" if off else ""))
                        self.report["steps"].append({
                            "i": step, "action": "fill+submit", "filled_fields": filled,
                            "creds_sent_to": dest, "off_site": off, "screenshot": await B.screenshot_b64(page),
                        })
                        btn = await B.click_advance(page)
                        self._log(f"  submitted via '{btn or 'Enter'}'")
                        try:
                            await page.wait_for_load_state("domcontentloaded", timeout=8000)
                        except Exception:
                            pass
                        await page.wait_for_timeout(SETTLE_MS)
                        continue

                    # nothing to fill — try to click a button-only step forward, else stop
                    btn = await B.click_advance(page)
                    if btn and btn != "Enter":
                        self._log(f"Step {step}: no form - clicked '{btn}' to continue")
                        try:
                            await page.wait_for_load_state("domcontentloaded", timeout=8000)
                        except Exception:
                            pass
                        await page.wait_for_timeout(SETTLE_MS)
                        continue

                    # some kits reveal the phish only AFTER human interaction — simulate it before giving up
                    if snap["url"] not in interacted:
                        interacted.add(snap["url"])
                        self._log("Nothing to fill — simulating human interaction (some kits reveal on mouse/scroll)…")
                        await self._reveal_by_interaction(page)
                        if any(f.get("has_password") for f in await B.detect_forms(page)):
                            self.report.setdefault("cloaking", {})["interaction"] = True
                            self._log("  content REVEALED after interaction — interaction-cloaking IOC. Continuing…")
                            continue

                    self._log("Nothing left to fill or click - stopping step-through.")
                    break

                joined = "\n".join(all_html)
                try:                                          # kit exfil config often lives in bundled .js
                    ext_js = await I.gather_scripts(self.url, joined)
                    if ext_js:
                        joined += "\n/*--external-js--*/\n" + ext_js
                        for t in X.telegram_channels(ext_js):
                            if t not in self.report["exfil"]["telegram"]:
                                self.report["exfil"]["telegram"].append(t)
                except Exception:
                    pass
                self.report["iocs"] = X.iocs(joined, self.url, extra_urls=[a for a in self.report["exfil"]["form_actions"] if a])
                self.report["iocs"]["brands_impersonated"] = X.brand_hits(*[s.get("title", "") for s in self.report["steps"]])
                self.report["indicators"] = I.analyze_source(joined, self.url)   # read the whole source
                victim_url = ((self.report.get("decloak") or {}).get("victim") or {}).get("url") or self.url
                await vctx.close()

            self._log("Enriching - domain age, hosting, blocklists…")
            try:
                self.report["enrichment"] = await E.enrich(self.url)
            except Exception:
                self.report["enrichment"] = {}
            _merge_ip(self.report)
            self._log("Hunting the phishing kit (open dir / archive / source / cred logs)…")
            try:
                self.report["kit"] = await K.extract_kit(victim_url)
                for t in self.report["kit"].get("telegram", []):
                    if t not in self.report["exfil"]["telegram"]:
                        self.report["exfil"]["telegram"].append(t)
            except Exception:
                self.report["kit"] = {}
            # network routing — off-host requests + AUTHORITATIVE exfil (typed-vs-transmitted diff) + AiTM relay
            try:
                _BACKENDS = ("login.microsoftonline.com", "login.live.com", "login.microsoft.com",
                             "accounts.google.com", "oauth2.googleapis.com", "login.okta.com", "okta.com",
                             "auth0.com", "login.yahoo.com")
                thost = ".".join((urlsplit(self.url).hostname or "").split(".")[-2:])
                offhost = [n for n in net if ".".join((urlsplit(n["url"]).hostname or "").split(".")[-2:]) != thost]
                posts = [n for n in offhost if n["method"] in ("POST", "PUT", "PATCH") or n["type"] in ("xhr", "fetch")]
                # authoritative: which fake values we typed actually appear in an off-host request body, and where
                val_kind = {str(x.get("value", "")): x.get("kind") for st in self.report["steps"]
                            for x in (st.get("filled_fields") or []) if len(str(x.get("value", ""))) >= 4}
                cred_exfil = []
                for n in posts:
                    body = n.get("body") or ""
                    hits = sorted({k for v, k in val_kind.items() if v and v in body})
                    if hits:
                        cred_exfil.append({"host": urlsplit(n["url"]).hostname, "url": n["url"][:160], "fields": hits})
                # reverse-proxy relay: a lookalike page POST/xhr to a REAL auth-provider backend
                relay = sorted({urlsplit(n["url"]).hostname for n in posts
                                if any(b in (urlsplit(n["url"]).hostname or "") for b in _BACKENDS)})
                self.report["network"] = {
                    "count": len(net),
                    "hosts": sorted({urlsplit(n["url"]).hostname for n in offhost if urlsplit(n["url"]).hostname})[:40],
                    "exfil": [{"method": n["method"], "url": n["url"][:200], "type": n["type"]} for n in posts][:30],
                    "credential_exfil": cred_exfil[:10], "relay_to": relay[:10],
                }
                # a live relay to the real backend, CORROBORATED by a toolkit fingerprint, is strong AiTM evidence
                aitm = (self.report.get("enrichment") or {}).get("aitm") or {}
                if relay and any(s.get("toolkit") for s in aitm.get("signals", [])):
                    aitm.setdefault("signals", []).append({
                        "name": "live_backend_relay", "toolkit": None, "score": 45, "tier": "runtime",
                        "evidence": f"page relayed credentials to the real auth backend ({relay[0]}) — reverse-proxy (AiTM)"})
                    aitm["aitm_score"] = min(100, sum(int(s.get("score", 0)) for s in aitm["signals"]))
            except Exception:
                self.report["network"] = {}
            self.report["verdict"] = _verdict(self.report)
            self.report["elapsed"] = round(time.time() - t0, 1)
            self.state = "done"
            self._log(f"Done - {self.report['verdict']['label']} (score {self.report['verdict']['score']}).")
        except asyncio.CancelledError:
            self.state = "cancelled"
            self.report.setdefault("verdict", {"label": "cancelled", "score": 0,
                                               "reasons": ["scan cancelled by the analyst"]})
            self._log("Scan cancelled — stopped and browser closed.")
        except Exception as exc:
            self.report["error"] = f"{type(exc).__name__}: {exc}"[:200]
            self.state = "error"
        finally:
            self._page = None
            if frames:
                frames.cancel()
            _persist(self)     # retain the detonation evidence on disk (survives restart)
            _evict()           # bound RAM: evict oldest finished sessions (report stays on disk)

    async def forward(self, ev: dict):
        """Forward an analyst input event to the live page (during handover). Coords are fractions
        (0..1) of the frame, mapped to the page viewport so display scaling doesn't matter."""
        pg = self._page
        if pg is None:
            return
        try:
            t = ev.get("type")
            if t == "click":
                x = float(ev.get("x", 0)) * self.viewport["width"]
                y = float(ev.get("y", 0)) * self.viewport["height"]
                await pg.mouse.click(x, y)
            elif t == "mousedown":                          # start of a drag (slider CAPTCHAs)
                await pg.mouse.move(float(ev.get("x", 0)) * self.viewport["width"],
                                    float(ev.get("y", 0)) * self.viewport["height"])
                await pg.mouse.down()
            elif t == "mousemove":                          # drag motion — stepped so the site sees real movement
                await pg.mouse.move(float(ev.get("x", 0)) * self.viewport["width"],
                                    float(ev.get("y", 0)) * self.viewport["height"], steps=3)
            elif t == "mouseup":
                await pg.mouse.move(float(ev.get("x", 0)) * self.viewport["width"],
                                    float(ev.get("y", 0)) * self.viewport["height"])
                await pg.mouse.up()
            elif t == "scroll":
                dx, dy = float(ev.get("dx", 0)), float(ev.get("dy", 0))
                try:
                    await pg.evaluate("([x, y]) => window.scrollBy(x, y)", [dx, dy])  # reliable in Firefox
                except Exception:
                    pass
                try:
                    if ev.get("x") is not None and ev.get("y") is not None:
                        await pg.mouse.move(float(ev["x"]) * self.viewport["width"],
                                            float(ev["y"]) * self.viewport["height"])
                    await pg.mouse.wheel(dx, dy)                                        # scroll containers
                except Exception:
                    pass
            elif t == "type":
                await pg.keyboard.type(str(ev.get("text", "")))
            elif t == "key":
                await pg.keyboard.press(str(ev.get("key", "")))
        except Exception:
            pass

    def snapshot_state(self) -> dict:
        return {"id": self.id, "state": self.state, "paused": self.paused,
                "report": self.report, "has_frame": self.latest_frame is not None,
                "viewport": self.viewport,
                "frame_dims": self._frame_dims}


def create(url: str) -> Session:
    s = Session(url)
    SESSIONS[s.id] = s
    s._task = asyncio.create_task(s.run())
    return s


# ── in-app takedown reporting (drive the report form, hand off for CAPTCHA) ──────
REPORT_FORMS = {
    "safebrowsing": {"name": "Google Safe Browsing",
                     "url": "https://safebrowsing.google.com/safebrowsing/report_phish/?url={q}"},
    "microsoft": {"name": "Microsoft SmartScreen",
                  "url": "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest"},
    # native=True: open in the analyst's REAL default browser (Cloudflare Turnstile only verifies in a
    # genuine browser — an automated window, even Camoufox, gets an unsolvable checkbox).
    "telegram": {"name": "Telegram Abuse", "url": "https://telegram.org/support", "native": True},
}

# analyst identity used to pre-fill abuse-report forms (Telegram etc.) — env-overridable
REPORTER = {"name": os.getenv("PHISH_REPORTER_NAME", "SOC Team"),
            "email": os.getenv("PHISH_REPORTER_EMAIL", "SOC@example.com"),
            "phone": os.getenv("PHISH_REPORTER_PHONE", "")}

_PREFILL_JS = """(cfg) => {
  let n = 0;
  const fire = (e, v) => { e.focus(); e.value = v; e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true})); n++; };
  for (const e of document.querySelectorAll('input, textarea')) {
    const t = (e.type || '').toLowerCase();
    if (e.disabled || e.readOnly || ['hidden','submit','button','checkbox','radio','file'].includes(t)) continue;
    const s = ((e.name||'')+' '+(e.id||'')+' '+(e.placeholder||'')+' '+(e.getAttribute('aria-label')||'')).toLowerCase();
    if (cfg.reporter && (t === 'email' || /e-?mail/.test(s)) && !e.value) {
      fire(e, cfg.reporter.email);
    } else if (cfg.reporter && (t === 'tel' || /phone|mobile|\\btel\\b|contact number/.test(s)) && !e.value) {
      fire(e, cfg.reporter.phone);
    } else if (cfg.reporter && /(full |your )?name/.test(s) && !/user|login|company|site/.test(s) && !e.value) {
      fire(e, cfg.reporter.name);
    } else if ((t === 'url' || t === 'text' || t === '') && /url|website|link|address|\\bsite\\b|domain/.test(s)) {
      if (!e.value) fire(e, cfg.url);
    } else if (e.tagName === 'TEXTAREA' || /detail|description|comment|message|additional|\\binfo\\b|issue|problem/.test(s)) {
      if (!e.value) fire(e, cfg.detail);
    }
  }
  for (const sel of document.querySelectorAll('select')) {   // native threat-type/category dropdowns
    const s = ((sel.name||'')+' '+(sel.id||'')+' '+(sel.getAttribute('aria-label')||'')).toLowerCase();
    if (/threat|type|category|reason|report/.test(s)) {
      for (const o of sel.options) {
        if (/phish|social eng|scam|unsafe|malic/i.test(o.text||'')) {
          sel.value = o.value; sel.dispatchEvent(new Event('change',{bubbles:true})); n++; break;
        }
      }
    }
  }
  return n;
}"""


class ReportSession(Session):
    """Drives a takedown report FORM in the live frame: opens it, pre-fills the phishing URL, then
    hands to the analyst to pick 'phishing', solve the CAPTCHA, and submit (reuses takeover)."""

    def __init__(self, url: str, target: str, detail: str | None = None):
        super().__init__(url)
        self.target = target
        self.detail = detail or "Phishing website"
        spec = REPORT_FORMS.get(target) or {}
        self.report = {"url": url, "target": target, "target_name": spec.get("name", target),
                       "narration": [], "kind": "report"}

    async def run(self):
        spec = REPORT_FORMS.get(self.target)
        try:
            if not spec:
                raise ValueError(f"unknown report target {self.target}")
            if spec.get("native"):
                await self._run_native(spec)
                return
            # Headed Camoufox (real fingerprint) so Cloudflare Turnstile on the report form (e.g.
            # telegram.org/support) actually verifies — vanilla Playwright Firefox gets soft-blocked
            # ("Verifying…" forever). Falls back to a vanilla headed window if Camoufox is unavailable.
            async with B.launch(headed=True) as browser:
                browser.on("disconnected", lambda: self.resume())     # analyst closed the window = done
                ua = {} if B.is_camoufox(browser) else {"user_agent": B.FIREFOX_UA}   # Camoufox owns its own UA
                ctx = await browser.new_context(no_viewport=True, ignore_https_errors=True, **ua)
                page = await ctx.new_page()
                self.state = "running"
                form_url = spec["url"].replace("{q}", quote(self.url, safe=""))
                self._log(f"Opened a browser WINDOW on your desktop for the {spec['name']} report form "
                          f"(native — no lag, real scrolling).")
                try:
                    await page.goto(form_url, wait_until="domcontentloaded", timeout=B.NAV_TIMEOUT)
                except Exception:
                    self._log("(form slow to load — continuing)")
                # Wait for the (Angular) form to actually RENDER, then prefill — retrying until a field
                # fills. Camoufox renders slower than vanilla Firefox, so a fixed 2.5s wait fired before
                # the URL field existed (MS/Google reports then auto-filled nothing).
                try:
                    await page.wait_for_selector("input:not([type=hidden]), textarea", timeout=15000)
                except Exception:
                    pass
                n = 0
                for _ in range(4):
                    await page.wait_for_timeout(1500)
                    try:
                        n = await page.evaluate(_PREFILL_JS, {"url": self.url, "detail": self.detail, "reporter": REPORTER})
                    except Exception:
                        n = 0
                    if n:
                        break
                self._log(f"Pre-filled {n} field(s). Review, pick the threat type if needed, solve any CAPTCHA, then Submit.")
                try:
                    await page.bring_to_front()
                except Exception:
                    pass
                self._log("In the WINDOW: solve the CAPTCHA + click Submit, then click 'Done — I submitted' here.")
                self._pause()                    # hand to the analyst (they finish in the real window)
                await self._checkpoint()          # blocks until Done (resume) or the window is closed
                self._log(f"{spec['name']}: marked submitted. Closing the window.")
                try:
                    await browser.close()
                except Exception:
                    pass
            self.state = "done"
        except Exception as exc:
            self.report["error"] = f"{type(exc).__name__}: {exc}"[:200]
            self.state = "error"
        finally:
            self._page = None

    async def _run_native(self, spec):
        """Turnstile-gated forms (Telegram): open in the analyst's REAL default browser — Cloudflare's
        'confirm you are human' check only verifies in a genuine browser, never in an automated window
        (Camoufox included). Put the report message on the clipboard so the big field is one paste."""
        import subprocess
        form_url = spec["url"].replace("{q}", quote(self.url, safe=""))
        r = REPORTER
        self.state = "running"
        # expose the fields so the report card can show copy-ready values
        self.report["native_report"] = {"url": form_url, "message": self.detail,
                                         "name": r["name"], "email": r["email"], "phone": r["phone"]}
        copied = False
        try:
            subprocess.run(["clip"], input=self.detail, text=True, timeout=5)   # -> clipboard (paste the message)
            copied = True
        except Exception:
            pass
        opened = False
        try:
            os.startfile(form_url)                     # Windows: the analyst's DEFAULT browser
            opened = True
        except Exception:
            try:
                import webbrowser
                opened = webbrowser.open(form_url)
            except Exception:
                pass
        if opened:
            self._log(f"Opened {spec['name']} in your DEFAULT browser — the Cloudflare check is solvable "
                      f"there (an automated window's checkbox never verifies).")
        else:
            self._log(f"Open {form_url} in your browser to file the {spec['name']} report.")
        if copied:
            self._log("✓ Report message copied to your clipboard — paste it into the 'describe your problem' box.")
        self._log(f"Fill:  Name = {r['name']}   ·   Email = {r['email']}   ·   Phone = {r['phone']}")
        self._log("Then tick 'Confirm you are human' + Submit. Click '✓ Done — I submitted' here when finished.")
        self._pause()                                  # report card shows the fields + a Done button
        await self._checkpoint()                       # blocks until the analyst clicks Done
        self._log(f"{spec['name']}: marked submitted.")
        self.state = "done"


def create_report(url: str, target: str, detail: str | None = None) -> "ReportSession":
    s = ReportSession(url, target, detail)
    SESSIONS[s.id] = s
    s._task = asyncio.create_task(s.run())
    return s


def get(sid: str):
    s = SESSIONS.get(sid)
    if s:
        return s
    try:                                    # evicted from RAM but evidence is on disk
        with open(os.path.join(CASES_DIR, sid + ".json"), encoding="utf-8") as f:
            return _Done(json.load(f))
    except Exception:
        return None
