"""phishlab/session.py — a LIVE, pausable detonation session (backs Phase 4b: interactive handover).

sandbox.detonate() is one-shot. A Session instead keeps the browser + page ALIVE, captures a live
frame continuously (polled ~2-3 fps by the GUI), and PAUSES when an anti-bot gate is detected
(state='handover') — the analyst solves it in the live view (clicks/keys are forwarded to the page)
and hits Resume, then the robotic step-through continues. No stepping out of the app.
"""
from __future__ import annotations

import asyncio
import time
import uuid

from . import browser as B
from . import enrich as E
from . import extract as X
from .sandbox import MAX_STEPS, SETTLE_MS, _decloak, _fake_creds, _host, _snapshot, _verdict

FRAME_INTERVAL = 0.4      # ~2.5 fps live view
FRAME_QUALITY = 66

SESSIONS: dict[str, "Session"] = {}


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

    def request_takeover(self):
        """Analyst pressed 'Take over' — pause automation so they can drive the live browser."""
        if self.state in ("running", "handover", "starting"):
            self._pause()
            self._log("Analyst TOOK OVER — automation paused. Solve/interact in the frame, then Resume automation.")

    def resume(self):
        self.paused = False
        self._gate.set()

    async def _frame_loop(self):
        while self.state not in ("done", "error"):
            pg = self._page
            if pg is not None:
                try:
                    self.latest_frame = await pg.screenshot(type="jpeg", quality=FRAME_QUALITY)
                except Exception:
                    pass   # screenshots can fail mid-navigation; just skip the frame
            await asyncio.sleep(FRAME_INTERVAL)

    async def run(self):
        t0 = self.report["started_at"]
        frames = None
        try:
            async with B.launch() as brw:
                self.state = "running"
                self._log(f"Detonating {self.url}")
                vctx, page, dc = await _decloak(brw, self.url)
                self._page = page
                try:
                    self.viewport = page.viewport_size or self.viewport
                except Exception:
                    pass
                frames = asyncio.create_task(self._frame_loop())
                self.report["decloak"] = dc
                self.report["cloaking"] = {"detected": dc["cloaked"].startswith("cloaked"), "kind": dc["cloaked"]}
                self._log(f"Decloak - scanner={dc['scanner'].get('url')} victim={dc['victim'].get('url')} verdict={dc['cloaked']}")

                all_html = []
                for step in range(MAX_STEPS):
                    if await self._checkpoint():          # analyst took over before this step
                        await page.wait_for_timeout(SETTLE_MS)
                    snap = await _snapshot(page)
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

                    if ch:
                        # anti-bot gate → auto-pause for takeover; re-evaluate the page after resume.
                        self.report["handover_needed"] = True
                        self._log(f"Step {step}: anti-bot gate ({', '.join(ch)}) - Take over to solve it (click the challenge), then Resume automation.")
                        self._pause()
                        await self._checkpoint()
                        self._log("Resumed - re-checking the page.")
                        await page.wait_for_timeout(SETTLE_MS)
                        continue

                    cred_form = next((f for f in forms if f.get("has_password")), None)
                    if not cred_form:
                        self._log("No credential form here - stopping step-through.")
                        break

                    if await self._checkpoint():          # analyst took over before creds are filled
                        await page.wait_for_timeout(SETTLE_MS)
                        continue                          # re-evaluate rather than blindly fill
                    user, pw = _fake_creds()
                    filled = await B.fill_credentials(page, user, pw)
                    dest = cred_form.get("action")
                    off = _host(dest) and _host(dest) != _host(snap["url"])
                    self._log(f"Step {step}: filled FAKE creds ({user}) - POSTs to {dest}"
                              + ("  [!] OFF-SITE" if off else ""))
                    self.report["steps"].append({
                        "i": step, "action": "fill+submit", "filled": filled,
                        "creds_sent_to": dest, "off_site": bool(off),
                        "screenshot": await B.screenshot_b64(page),
                    })
                    await B.submit_form(page)
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=8000)
                    except Exception:
                        pass
                    await page.wait_for_timeout(SETTLE_MS)

                joined = "\n".join(all_html)
                self.report["iocs"] = X.iocs(joined, self.url, extra_urls=[a for a in self.report["exfil"]["form_actions"] if a])
                self.report["iocs"]["brands_impersonated"] = X.brand_hits(
                    *[s.get("title", "") for s in self.report["steps"]], joined[:20000])
                await vctx.close()

            self._log("Enriching - domain age, hosting, blocklists…")
            try:
                self.report["enrichment"] = await E.enrich(self.url)
            except Exception:
                self.report["enrichment"] = {}
            self.report["verdict"] = _verdict(self.report)
            self.report["elapsed"] = round(time.time() - t0, 1)
            self.state = "done"
            self._log(f"Done - {self.report['verdict']['label']} (score {self.report['verdict']['score']}).")
        except Exception as exc:
            self.report["error"] = f"{type(exc).__name__}: {exc}"[:200]
            self.state = "error"
        finally:
            self._page = None
            if frames:
                frames.cancel()

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
            elif t == "scroll":
                # move the pointer over the target first so the wheel scrolls the right element
                if ev.get("x") is not None and ev.get("y") is not None:
                    await pg.mouse.move(float(ev["x"]) * self.viewport["width"],
                                        float(ev["y"]) * self.viewport["height"])
                await pg.mouse.wheel(float(ev.get("dx", 0)), float(ev.get("dy", 0)))
            elif t == "type":
                await pg.keyboard.type(str(ev.get("text", "")))
            elif t == "key":
                await pg.keyboard.press(str(ev.get("key", "")))
        except Exception:
            pass

    def snapshot_state(self) -> dict:
        return {"id": self.id, "state": self.state, "paused": self.paused,
                "report": self.report, "has_frame": self.latest_frame is not None}


def create(url: str) -> Session:
    s = Session(url)
    SESSIONS[s.id] = s
    s._task = asyncio.create_task(s.run())
    return s


def get(sid: str) -> "Session | None":
    return SESSIONS.get(sid)
