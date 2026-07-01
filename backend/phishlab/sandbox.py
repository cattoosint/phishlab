"""phishlab/sandbox.py — the detonation orchestrator.

detonate(url) →
  1. DECLOAK: fetch the URL as a bot (scanner) and as a real Firefox (victim); diff → cloaking verdict.
     Keep the victim page live (that's the real phishing content).
  2. STEP THROUGH: on the victim page, screenshot, detect forms, and if there's a credential form,
     fill FAKE creds, screenshot, submit, follow to the next page — repeat (capped).
  3. Record every step (url, title, screenshot, forms, telegram) + live narration.
  4. Aggregate exfil channels + IOCs → a weighted verdict.

Fake data only; intended for an isolated SOC analysis host.
"""
from __future__ import annotations

import random
import string
import time
from urllib.parse import urlsplit

from . import browser as B
from . import extract as X

MAX_STEPS = 6
SETTLE_MS = 1800


def _fake_creds() -> tuple[str, str]:
    u = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    p = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
    return f"{u}@examplemail.com", p


def _host(u: str) -> str:
    return (urlsplit(u or "").hostname or "").lower()


async def _snapshot(page) -> dict:
    return {"url": page.url, "title": await page.title(), "html": await page.content(),
            "screenshot": await B.screenshot_b64(page)}


def _cloak_verdict(sc: dict, vic: dict) -> str:
    if not sc.get("reached"):
        return "scanner_blocked"          # bot view refused → suggestive of an IP/UA gate
    if sc.get("url") and vic.get("url") and _host(sc["url"]) != _host(vic["url"]):
        return "cloaked_diff_host"
    if vic.get("title") and (sc.get("title") or "") != vic.get("title"):
        return "cloaked_diff_title"
    if sc.get("status") is not None and sc.get("status") != vic.get("status"):
        return "cloaked_diff_status"
    return "no_diff"


async def _decloak(browser, url: str):
    """Return (victim_ctx, victim_page, decloak_report). The victim page is left open + loaded."""
    # scanner view (bot-like) — best-effort; we tolerate it being blocked
    sc = {"reached": False}
    try:
        sctx = await B.new_scanner_context(browser)
        spg = await sctx.new_page()
        r = await spg.goto(url, wait_until="domcontentloaded", timeout=B.NAV_TIMEOUT)
        await spg.wait_for_timeout(700)
        sc = {"reached": True, "url": spg.url, "status": (r.status if r else None), "title": await spg.title()}
        await sctx.close()
    except Exception as exc:
        sc["error"] = f"{type(exc).__name__}: {exc}"[:160]

    # victim view (real Firefox) — kept live for detonation
    vctx = await B.new_victim_context(browser)
    vpg = await vctx.new_page()
    chain: list[str] = []

    def _on_resp(resp):
        try:
            if resp.request.is_navigation_request() and (not chain or chain[-1] != resp.url):
                chain.append(resp.url)
        except Exception:
            pass

    vpg.on("response", _on_resp)
    r = await vpg.goto(url, wait_until="domcontentloaded", timeout=B.NAV_TIMEOUT)
    await vpg.wait_for_timeout(SETTLE_MS)
    vic = {"reached": True, "url": vpg.url, "status": (r.status if r else None), "title": await vpg.title()}

    verdict = _cloak_verdict(sc, vic)
    return vctx, vpg, {"scanner": sc, "victim": vic, "cloaked": verdict, "redirect_chain": chain[:20]}


async def detonate(url: str, *, max_steps: int = MAX_STEPS) -> dict:
    t0 = time.time()
    report = {
        "url": url, "started_at": t0, "narration": [], "steps": [],
        "exfil": {"form_actions": [], "telegram": []}, "iocs": {}, "decloak": None, "verdict": None,
    }
    log = report["narration"].append

    async with B.launch() as brw:
        log(f"Detonating {url}")
        vctx, page, dc = await _decloak(brw, url)
        report["decloak"] = dc
        log(f"Decloak · scanner→{dc['scanner'].get('url')} · victim→{dc['victim'].get('url')} · verdict={dc['cloaked']}")

        all_html: list[str] = []
        try:
            for step in range(max_steps):
                snap = await _snapshot(page)
                all_html.append(snap["html"] or "")
                forms = await B.detect_forms(page)
                tg = X.telegram_channels(snap["html"] or "")
                report["steps"].append({
                    "i": step, "action": "load", "url": snap["url"], "title": snap["title"],
                    "screenshot": snap["screenshot"], "forms": forms, "telegram": tg,
                })
                report["exfil"]["telegram"].extend(tg)
                report["exfil"]["form_actions"].extend(f.get("action") for f in forms if f.get("action"))
                log(f"Step {step}: {snap['url']} — “{snap['title']}” · {len(forms)} form(s)"
                    + (f" · ⚠ TELEGRAM exfil bot {tg[0]['bot_id']}" if tg else ""))

                cred_form = next((f for f in forms if f.get("has_password")), None)
                if not cred_form:
                    log("No credential form here — stopping step-through.")
                    break

                user, pw = _fake_creds()
                filled = await B.fill_credentials(page, user, pw)
                fshot = await B.screenshot_b64(page)
                dest = cred_form.get("action")
                off = _host(dest) and _host(dest) != _host(snap["url"])
                log(f"Step {step}: filled FAKE creds ({user}) → POSTs to {dest}"
                    + ("  ⚠ OFF-SITE (creds leave to a third party)" if off else ""))
                report["steps"].append({
                    "i": step, "action": "fill+submit", "filled": filled,
                    "creds_sent_to": dest, "off_site": bool(off), "screenshot": fshot,
                })
                await B.submit_form(page)
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=8000)
                except Exception:
                    pass
                await page.wait_for_timeout(SETTLE_MS)
        finally:
            joined = "\n".join(all_html)
            report["iocs"] = X.iocs(joined, url, extra_urls=[a for a in report["exfil"]["form_actions"] if a])
            report["iocs"]["brands_impersonated"] = X.brand_hits(
                *[s.get("title", "") for s in report["steps"]], joined[:20000])
            try:
                await vctx.close()
            except Exception:
                pass

    report["verdict"] = _verdict(report)
    report["elapsed"] = round(time.time() - t0, 1)
    return report


def _verdict(r: dict) -> dict:
    score, reasons = 0, []
    if r["exfil"]["telegram"]:
        score += 60
        reasons.append(f"Telegram exfil bot embedded (id {r['exfil']['telegram'][0]['bot_id']})")
    if any(s.get("action") == "fill+submit" for s in r["steps"]):
        score += 25
        reasons.append("live credential form accepted fake creds")
    dc = (r.get("decloak") or {}).get("cloaked", "")
    if dc.startswith("cloaked"):
        score += 20
        reasons.append(f"content cloaking ({dc})")
    if any(s.get("off_site") for s in r["steps"]):
        score += 20
        reasons.append("credentials POST to an off-site host")
    brands = r["iocs"].get("brands_impersonated") or []
    if brands:
        score += 15
        reasons.append("brand impersonation: " + ", ".join(brands))
    score = min(score, 100)
    label = ("confirmed_phishing" if score >= 80 else
             "likely_phishing" if score >= 45 else
             "suspicious" if score >= 20 else "inconclusive")
    return {"label": label, "score": score, "reasons": reasons}
