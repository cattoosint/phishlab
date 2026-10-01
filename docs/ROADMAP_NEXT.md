# PhishLab — next version plan

Written after a full read of the tree at `21cb54e` (8,844 LOC across 23 files). Every claim below was
verified against the code, not the README. Ordered by **what the release needs to be true**, not by
what is quickest.

---

## 1. The structural flaw worth building the next version around: the engine split

This is the single most important finding, and it is invisible from the README.

PhishLab has two detonation engines. They are **not** interchangeable, and the default is the weaker one.

| Capability | `sb_session.py` — **DEFAULT** (Chrome/SeleniumBase UC) | `session.py` (Camoufox, "fallback") |
|---|---|---|
| Solves hardened Cloudflare managed Turnstile | **yes** (real OS-mouse click) | no — widget won't render |
| Live network capture (`page.on` request/response) | **none** | yes |
| Authoritative exfil proof (typed-value → transmitted-body diff) | **no** — infers from DOM `form.action` + page source | yes (`session.py:581-588`) |
| AiTM **live backend relay** detection | **no** | yes (`session.py:589-604`) |
| External/bundled `.js` fetch + de-obfuscate | **no** | yes (`session.py:543-549`) |
| User-interaction cloaking (CrawlPhish) | **no** | yes (`session.py:172`) |
| In-app takeover / pause / resume | **stubs** — `forward()` returns, `resume()` is `pass`, `paused` hardcoded `False` (`sb_session.py:200-212`); analyst must use the real desktop Chrome window | full, in the live pane |

Consequence, stated plainly: **on a Cloudflare-fronted phish you can either get *in* or *see the
relay* — not both.** The capability the AiTM roadmap calls the thing that "beats PhishGuard" (watching
the session-cookie relay live) only exists on the engine that cannot pass the gate that real kits sit
behind. The README's feature list is the **union** of the two engines and is therefore true of no
single configuration.

AiTM *enrichment* is fine on both paths — `enrich.enrich()` calls `aitm.analyze()` and
`enrich.score_signals()` folds it into the verdict regardless of engine. The gap is specifically the
**runtime** tier: anything that requires watching the network during the walk.

### Track A — one engine (the marquee work)

Chrome's DevTools Protocol can do everything Camoufox's `page.on` does. `sb_session.py` already calls
`execute_cdp_cmd` once (`:330`, for `Security.setIgnoreCertificateErrors`) — the seam exists.

1. `Network.enable` + CDP listeners on the default engine; capture method/url/type/headers/post-body
   for the whole detonation (bounded buffer, bodies truncated).
2. Lift the four Camoufox-only analyses into a shared `netanalysis.py` consuming one normalized event
   list, so both engines produce identical `report["network"]`:
   typed-vs-transmitted credential diff · off-host POST set · `_BACKENDS` relay detection ·
   `Set-Cookie` session-token-in-transit.
3. Port external-JS gathering (`indicators.gather_scripts`) and user-interaction cloaking into the
   shared walk.
4. Then **collapse the walkers.** `detonate()` (sandbox.py) and `Session.run()` (session.py) and
   `SBSession.forward()` are three implementations of one state machine. The AiTM roadmap already
   flagged this ("unify into one `_walk_step` — batch currently abandons gates at step 0") and it is
   still open. One walker, two drivers.
5. Only then decide whether Camoufox stays. If the unified engine does relay detection *and* Turnstile,
   Camoufox's remaining unique value is the proxy/decloak vantage — which `httpx[socks]` already covers
   for the scanner view. Deleting an engine is a feature.

**This is what makes the next version announceable:** *one* engine that passes the gate **and** proves the exfil.

---

## 2. Track B — verdicts you can defend

### B1. Silent failure is the integrity bug

`grep -c "except Exception"` → **261**, of which **118** are followed only by `pass`. Every module's
docstring says "best-effort; degrades to nothing on error". That is the right instinct for a tool that
visits hostile hosts, and the wrong one for a tool that outputs a verdict, because:

> a probe that **crashed** and a probe that **found nothing** are indistinguishable in the report.

A DNS timeout on `spamhaus_dbl` silently removes a 35-point signal. The analyst sees a lower score and
no indication that anything was skipped. `enrich()` is the clearest case: `asyncio.gather(...,
return_exceptions=True)` then `ok(x)` maps every exception to `None` — the error is *deliberately*
discarded (`enrich.py:256-259`).

**Fix:** a signal-provenance envelope. Every probe returns `{status: ok|empty|error|skipped|n/a,
value, detail}`. The verdict gains a `coverage` block: which signals ran, which could not be
evaluated, and a confidence band that *narrows* when coverage is incomplete. Then the UI can say
"confirmed_phishing (96) — 14/16 signals evaluated; Spamhaus and RDAP timed out" instead of quietly
scoring 61. **Unknown must never read as clean.**

This is a cross-cutting refactor, so do it *before* Track A, not after — it is the seam the unified
engine should be written against.

### B2. There are zero tests

8,844 LOC. No `tests/`, no `.github/`, no CI. The only harness is `demo.py`, a manual end-to-end script
needing Chrome and a live run. The verdict thresholds (`sandbox.py:387-389` — 80/45/20) and ~30 weighted
signals have never been regression-tested, and nothing stops a refactor from silently changing a
verdict.

The good news: **the fixtures already exist.** `/demo-phish/`, `/demo-lead/`, `/demo-cfphish/`,
`/demo-opendir/`, `/demo-aitm/evilginx`, `/demo-aitm/modlishka`, `/demo-jsexfil/` are a ready-made
corpus seed, and the parsing/scoring layers are pure Python with no browser dependency:

- **Unit, no browser, CI-able on Linux today:** `mailparse` (.eml/.msg/PDF/QR/de-obfuscation),
  `extract` (IOC/telegram/scam-signals), `indicators` (source analysis + `LEGIT_DOMAINS`),
  `aitm` (header/cookie/URL analyzers + `_infer_toolkit`), `enrich.score_signals`,
  `sandbox._verdict`, `net_guard.check_target`.
- **Golden-verdict tests:** freeze the full report JSON for each fixture; a diff fails CI. This single
  mechanism is what makes Track A safe to attempt.
- **CI:** GitHub Actions, Linux, pure-Python layers only (keep the browser tests as a manual
  `demo.py` gate). The repo currently has *no* `.github/` at all — a PR runs nothing.

### B3. Nobody knows if it works

The README describes the scoring philosophy well but contains **no accuracy number**, because there is
no labelled corpus and no measurement. For a detector, that is the missing credential.

Build a **calibration harness**: a labelled set (confirmed phish from PhishTank/OpenPhish + a benign
set from a top-1M list, URLs + saved HTML so it is replayable offline), run the scorer over it, and
report precision/recall/FP-rate per threshold. Outputs:

- the thresholds stop being three magic numbers and become **chosen** numbers,
- the false-positive down-weight logic (`sandbox.py:313-389`) gets *measured* rather than argued,
- the README can state a real figure. "Weighted verdict with every reason shown" is a design claim;
  "4.1% FP at 0.5% FN on 2,000 labelled URLs" is an engineering claim. That is the difference a
  reviewer notices.

---

## 3. Track C — case memory (nothing is remembered today)

Persistence is four ad-hoc JSON dumps: `mailbox` last-UID, `cf_solver` result, `tracker` sites,
`session` report. There is no case store. `BUILD_PLAN.md` Phase 6 ("case history/search") and the
SQLite layer in its architecture diagram were never built; `docker-compose.yml` still promises a
"persistent volume for cases/screenshots" that nothing writes to. `/api/report/recent` lists reporter
screenshots, not cases.

Everything analytical is blocked on this. SQLite + an artifact dir unlocks:

- **Case history + search** — by domain, brand, Telegram bot id, verdict, date, kit hash.
- **Campaign correlation** — the genuinely new capability. The same `bot_id`, exfil host, or kit
  fingerprint across N cases *is* a campaign. "This is the 7th case this month exfiltrating to bot
  `8123…`, all DBS-branded, all on `.top` domains registered within 4 days" is intelligence no
  single-case tool produces, and it is almost free once cases are rows.
- **Kit-family clustering** — fuzzy-hash (TLSH/ssdeep) recovered kits + author strings/comments from
  `kit.py`, cluster, and track families over time. Attribution, not just detection.
- **Metrics** — cases/week, verdict distribution, takedown MTTR from the tracker's
  first-reported → went-down timestamps. The tracker already records these and then forgets them.
- **Report-once** — the `/api/report` flow currently has no memory of what was already submitted.

Schema sketch: `cases` (url, host, verdict, score, engine, started, elapsed) · `signals`
(case_id, name, score, status, evidence) · `iocs` (case_id, type, value) · `artifacts`
(case_id, kind, path, sha256) · `tracker_pings` · `kits` (sha256, tlsh, family). Keep the JSON report
as a blob column so nothing is lost in migration.

---

## 4. Track D — it stops at the analyst's screen

A SOC tool that can't push IOCs into the stack the SOC already runs gets used once and abandoned.

- **Export**: STIX 2.1 bundle, MISP event (push via API), plain CSV/JSON IOC list.
- **SIEM**: Splunk HEC / Sentinel / generic webhook on verdict ≥ threshold.
- **Blocklist out**: a feed file (domains/URLs) the proxy or DNS sinkhole can consume directly —
  the shortest path from "detonated" to "blocked org-wide".
- **Abuse-desk templating**: the registrar/host abuse contact is already derivable from RDAP + ASN;
  generate the takedown email with evidence attached. `reporter.py` automates the *scanner* portals;
  nothing automates the *host*, which is where takedowns actually happen.
- **API auth + multi-analyst**: the console is unauthenticated by design (loopback-only) and
  `_cross_origin` CSRF checks exist on **3 of the 24 state-changing endpoints** (49 routes total, 8 of them demo fixtures) (`api.py:149, 158, 179` — update/apply,
  update/restart, open-native). `/api/detonate`, `/api/email/analyze`, `/api/report`, `/api/tracker/*`
  and `/api/session/*` have none, so a page the analyst has open in another tab can drive detonations
  on their dedicated line. Extend `_cross_origin` to every state-changing endpoint (cheap, do it in
  Track E), then add a token + per-analyst case ownership if PhishLab is ever to serve more than one
  seat.

---

## 5. Track E — truth and hygiene (do this first; it is cheap)

### E1. README claims the code does not support

The "Notable engineering decisions" section is the part a technical reviewer reads closest, so these
matter disproportionately:

- **"validate-and-pin to close the DNS-rebind TOCTOU (resolve once, pin the browser/scanner to the
  validated IP)"** — **not implemented.** `net_guard.check_target()` resolves, checks, and returns
  `(bool, str)`. It never returns or pins an IP; the subsequent fetch resolves again. No
  `--host-resolver-rules`, no pinned-IP transport anywhere in the tree. `enrich.py:248`'s "resolve
  once" is for parallelism, not pinning. **Either implement it** (return the validated IP; pass
  Chrome `--host-resolver-rules=MAP host ip`, and use a pinned-IP httpx transport with the original
  `Host` header + SNI) **or correct the sentence.** Implementing is ~40 lines and keeps the claim.
- **The feature list is the engine union** (§1). Either unify (Track A) or state which engine does what.
- **"no telemetry / the sample never leaves the box"** is accurate and well-qualified — keep it exactly
  as worded.

### E2. SSRF guard coverage is narrower than it looks

`net_guard` is called in `api.py` (entry URL), `sb_session.py` (per redirect hop — good),
`reporter.py`, `mailbox.py`. It is called **zero** times in `kit.py`, `tracker.py`, `enrich.py`,
`phishtank.py`, `session.py`, `aitm.py`, `sandbox.py` — all of which fetch URLs *derived from
attacker-controlled content*. Highest-risk: `kit.py` recursing an open directory (14 fetch sites —
a link in the attacker's listing can point anywhere) and `tracker.py` (23 — pings persisted URLs on a
30-min loop forever). Route every outbound fetch through one guarded client; make the unguarded path
the one you have to ask for.

### E3. Docker/Linux is broken, not merely untested

Two concrete defects:

1. `Dockerfile` → `CMD ["uvicorn", "api:app", "--host", "127.0.0.1", ...]`. Bound to the *container's*
   loopback, so `docker-proxy` (which forwards to the container's `eth0`) can never reach it. The
   published `127.0.0.1:8090:8090` port is dead. Must bind `0.0.0.0` *inside* the container and rely
   on the host-side `127.0.0.1:` publish for the loopback guarantee.
2. The image installs **Playwright Firefox**, but the default engine is **SeleniumBase/Chrome**, which
   is not installed — so the default engine cannot run in the container at all. The real-OS-mouse
   Turnstile click (PyAutoGUI) also has no display.

Pick one: fix it properly (a container that runs the Camoufox engine honestly, documented as
"no Turnstile solving") or **delete `Dockerfile` + `docker-compose.yml`**. A broken Docker path is worse
than none, because it is the first thing a reviewer tries.

### E4. Dependencies float where it hurts most

Pinned: `playwright==1.51.0`, `camoufox==0.4.11` (with an excellent comment explaining why).
Floating: `seleniumbase>=4.50` — *the Cloudflare-solving core* — plus `fastapi`, `uvicorn`, `httpx`,
`cryptography`, `pymupdf`, `pyzbar`, `pillow`. A SeleniumBase minor bump can silently break Turnstile
solving, and the README already concedes browser automation is "maintenance-sensitive". Add a
lockfile (`pip-compile`/`uv lock`) with hashes, and keep `requirements.txt`'s comments — they are
genuinely good documentation. Also fold the `extract-msg --no-deps` step out of `Install.bat` into the
lock, or the installed environment is not reproducible.

### E5. Static allowlist won't scale

`indicators.LEGIT_DOMAINS` is a hand-maintained 70-domain set. The AiTM roadmap's suggestion stands:
augment with a **Cloudflare Radar / Tranco top-1M** cached list (`radar`/`tranco`/`top-1m`: 0 hits in
the tree today). Keep the static set as the high-confidence core; use the dynamic list only for the
false-positive down-weight, never to zero out a verdict.

### E6. Give it a real version

`__version__` is still `"0.1.0"` (`backend/phishlab/__init__.py:2`), there are no git tags, and
`GET /api/version` returns `md5(index.html)[:12]` — a GUI cache-buster, not a release id. Bump it,
tag the release, and have `/api/version` return both (`{"app": "…", "ui": "<md5>"}`) so the console
and `start.bat` can show which build is actually running.

---

## 6. Track F — new detection surface (the "what else")

Ordered by value-per-effort. All fit the existing "parse and statically decode, never execute" rule.

1. **HTML smuggling** — currently the dominant delivery TTP and a direct fit: a `.html` attachment with
   a blob/`data:` URI built in JS, `atob`-decoded, auto-downloaded. `mailparse.py` already de-obfuscates
   nested `atob`/`\xNN`; detecting `Blob` + `msSaveOrOpenBlob` + `a.download` + a decoded archive magic
   number is a contained addition with a high hit rate.
2. **Static payload triage** (not malware sandboxing — keep that scope line): `oletools` macro
   extraction, LNK target parsing, ISO/IMG/VHD listing, OneNote embedded-file extraction, archive
   inspection. Yields IOCs from the ~40% of phish whose payload is an attachment, without detonating a
   binary. The README's "won't detonate a binary payload" limitation stays honest.
3. **Headless-safe Turnstile path** — PyAutoGUI's real-OS-mouse click is what pins PhishLab to an
   interactive Windows desktop and blocks unattended/server operation. Investigate a virtual-display
   (`headless="virtual"` / Xvfb+xdotool) path. This is the gate on every "run it as a service" ambition,
   including intake-at-scale.
4. **Reputation feeds still missing** — `openphish` / `phishunt` (0 hits). Keyless, TTL-cached, and
   the AiTM roadmap already specified the `_fetch_feed` pattern. Cheapest remaining detection win.
5. **MFA/step-up depth** — push-notification and number-matching kits, and OTP re-prompt loops, are
   where AiTM actually lands. The walker handles `email → password` two-step; extend the state machine
   (once unified in Track A) to the step-up families.
6. **Favicon/visual hashing** — `BUILD_PLAN.md` §3C listed brand detection by favicon hash; today it is
   title/keyword regex only. A perceptual hash survives a text-free, image-only clone, which regex
   cannot.

---

## 7. Recommended sequence

Dependency-ordered, not wish-ordered. E is first because it is cheap and removes the claims most
likely to embarrass; B2 is second because **nothing else is safe to refactor without it**.

| # | Work | Why here |
|---|---|---|
| 1 | **E1–E6** — fix/soften README claims, guard every fetch, extend CSRF to all state-changing endpoints, decide Docker, lock deps, real version + tag | Days. Removes the findings a sharp reader hits first. |
| 2 | **B2** — fixture corpus + golden-verdict tests + Linux CI | The safety net every later track needs. |
| 3 | **B1** — signal-provenance envelope + verdict `coverage` | Cross-cutting; the seam Track A must be written against. |
| 4 | **A** — CDP network capture on the default engine → shared `netanalysis.py` → one walker | The marquee capability. Safe now, because 2–3 exist. |
| 5 | **C** — SQLite case store → history/search → campaign correlation | Unlocks everything analytical. |
| 6 | **B3** — labelled corpus + calibration harness → a real accuracy number | Needs C's storage and B1's provenance to mean anything. |
| 7 | **D / F** — exports + SIEM + abuse-desk + auth; HTML smuggling, payload triage, headless Turnstile | Breadth, once the core is trustworthy. |

### What the next version should mean in one line

> *Not more features — the same features, provable.* One engine that both passes the gate and proves
> the exfil; a verdict that reports what it could not evaluate; a measured false-positive rate; and
> cases that are remembered.

The feature breadth is already there. The thing it lacks is the evidence that it is right — which is
precisely the thing a bank SOC, and a hiring reviewer, will ask for first.

---

## Appendix — numbers behind the above (verified at `21cb54e`)

| Metric | Value |
|---|---|
| Python LOC | 7,421 · plus UI `index.html` 1,423 → 8,844 total |
| Largest modules | `session.py` 863 · `api.py` 849 · `sb_session.py` 841 · `reporter.py` 575 · `mailparse.py` 548 |
| `except Exception` handlers | 261 (118 `pass`-only); bare `except:` 0 |
| Tests | 0 · CI workflows 0 (`.github/` absent; only Dependabot's implicit graph job) |
| API routes | 49 (8 demo fixtures) · state-changing non-demo: 24 · with CSRF guard: 3 · with auth: 0 |
| `net_guard` call sites | 4 modules · absent from 7 that fetch derived URLs (`kit`, `tracker`, `enrich`, `phishtank`, `session`, `aitm`, `sandbox`) |
| Persistence | 4 ad-hoc `json.dump` files · 0 databases |
| Git tags / releases | 0 / 0 |
| AiTM roadmap ① ③ | largely delivered (wildcard DNS, header/cookie/URL analyzers, `_infer_toolkit`, live cert, TLS timing, brand coherence) |
| AiTM roadmap ② | partial — runtime relay exists **only** in `session.py`, the non-default engine |
| Still absent from that roadmap | openphish/phishunt feeds · Cloudflare Radar top-1M · external-JS decode on the default engine · unified walker |
