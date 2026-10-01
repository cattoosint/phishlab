# PhishLab — next version plan (driven by SOC KPIs)

**Goal:** move the SOC's phishing KPIs. That means how fast a reported phish gets a verdict, gets
blocked and gets taken down, and how much analyst time each case costs, **without letting false
positives rise**.

Checked against the code at `21cb54e`. Timings below are **upper bounds taken from the code's
timeouts and fixed waits, not measured wall-clock**. Step K1 exists to replace them with real
measurements.

---

## The KPIs, and whether PhishLab can compute them today

| KPI | Definition (from timestamps) | Computable today? |
|---|---|---|
| Time to verdict | `verdict_at − reported_at` | **No.** The case stores `started_at` + `elapsed` but never learns when the phish was reported |
| Time to first verdict | `provisional_verdict_at − reported_at` | **No.** There is no provisional verdict; the verdict only exists at the very end |
| Queue wait | `running_at − queued_at` | **No.** The queued state isn't timestamped |
| Time to acknowledge | `acked_at − verdict_at` | **No.** No notification and no ack exist |
| Time to contain | `blocked_at − verdict_at` | **No.** Blocking happens entirely outside the tool |
| Time to takedown | `down_at − detected_at` | **Partly.** Tracker has `went_down_at − first_seen`, but `first_seen` is when an analyst *manually added* the site, and pings are 30 min apart |
| Automation rate | cases closed with no analyst touch ÷ all cases | **No.** Analyst touch isn't recorded |
| Precision (FP rate) | analyst-marked FP ÷ verdicts ≥ `likely_phishing` | **No.** `/api/mail/dismiss` drops the item without storing *whether* it was phishing or a false positive (`api.py:414-417`) |
| Reports vs unique threats | distinct threats ÷ reports | **No.** No dedupe; every report is a separate detonation |
| Proactive rate | threats found before the first user report ÷ all threats | **No.** PhishLab only acts on URLs someone hands it |

What *does* exist: every finished detonation is written to `backend/data/cases/<id>.json` with its
URL, `started_at`, `elapsed` and verdict (`session.py:40-46`), and the tracker keeps `first_seen` /
`went_down_at` (`tracker.py:84-86`). So the storage is there. Nothing aggregates it, and the timestamps
that matter most for SOC KPIs are never recorded.

---

## Where the time goes today

`report → intake → queue → detonation → verdict → notify → contain → takedown`

### Intake
- **Gmail only:** `HOST = "imap.gmail.com"` is hardcoded (`mailbox.py:24`).
- **30-second poll** (`MAIL_POLL_INTERVAL`, `:25`), opening a fresh SSL connection and logging in on
  every poll (`:124-126`).
- **Only acts on mail from `MAIL_INTAKE_SENDERS`** (`:63-75`). A user's report therefore reaches
  PhishLab only after an analyst forwards it. That human hop is probably the biggest single part of
  time-to-detect, and the tool can't see it.
- **In-memory queue capped at 60** (`:26`, `:194`), lost on restart.
- **The case doesn't know where it came from.** The callback passes only the URL
  (`api.py:402`: `M.start(lambda url: _detonate(url).id)`), so the case can't tell that it came from
  intake, who reported it, or when the email arrived.

### Queue
- **3 concurrent detonations** (`PHISH_MAX_CONCURRENT`, `sb_session.py:48-49`).
- **The slot is held after Chrome has closed.** It is released in `finally` (`:823`), so it stays held
  through the redirect chain, enrichment and kit hunt (`:809-813`). The cap exists to protect RAM from
  Chrome instances, and that post-Chrome work doesn't need it.
- **Unsolvable Cloudflare gates block a slot for about 5 minutes.** `_solve_cf` makes 3 attempts with
  roughly 22 s of fixed waits each (`:434-475`), then waits up to **240 s for a human**
  (`PHISH_CF_HUMAN_TIMEOUT`, `:279`). Intake runs unattended. If there's no human, three such cases
  stall the whole pipeline.
- **No dedupe.** Every intake link becomes a detonation (`mailbox.py:200`). One campaign reported by
  40 users means 40 detonations, run 3 at a time.

### Detonation → verdict: strictly serial
```
decloak (:767) → open Chrome (:773) → walk ≤8 steps (:789) → close Chrome
  → redirect chain (:809) → enrichment (:811) → kit hunt (:813) → verdict (:814)
```
- **These stages don't need the walk.** Decloak, the redirect chain and enrichment use only the
  original URL. Their bounds:
  - decloak: ≤15 s direct, ≤35 s via Tor/VPN (`tracker.py:278`)
  - redirect chain: ≤10 hops × 15 s (`sb_session.py:131-137`)
  - enrichment's slowest path is the AiTM probe: HTTP 8 s → TLS cert 2 × 6 s → TLS timing 5 × 5 s,
    about 45 s worst case on a host that hangs (`aitm.py:254,263,341-347`)
- **The verdict is computed once, at the end, even though URL-only signals carry most of the
  weight.** In `_verdict` (`sandbox.py:313-390`): Safe Browsing **+40**, Spamhaus DBL **+35**,
  URLhaus **+30**, VirusTotal ≥3 engines **+30**, domain age <7 days **+25**, IP/geo cloaking **+18**,
  plus the AiTM toolkit signals. Two of these already reach `likely_phishing` (≥45). A URL that is
  *already blocklisted* still waits for the full browser walk before PhishLab says so.
- **Page bodies get fetched and then thrown away.** The decloak downloads the page body from every
  vantage (`tracker.py:283-285`), then keeps only the title and a content signature. The Telegram-bot
  regex (**+60** on its own) and the source indicators could run on that body before Chrome opens.

### Notify and contain
- **No notification path exists anywhere in the tree** (no SMTP, webhook, Teams or Slack). The verdict
  is only visible in the console, so time-to-acknowledge depends on someone looking at it.
- **Nothing is pushed to a blocklist.**
- **Tracker additions are manual** (`POST /api/tracker`, `api.py:431`). A detonation never adds
  itself, so time-to-takedown only gets measured for sites an analyst remembered to add.

### Takedown
- **Nothing contacts the hosting provider or registrar, which is where takedowns actually happen.**
  `report.takedown_targets()` (`report.py:19`) produces portal *links* (Safe Browsing, Microsoft,
  Fortinet, Netcraft and so on). `reporter.py` drives VT, FortiGuard and Hybrid Analysis, with the
  analyst solving the CAPTCHAs.
- **Takedown time has 30-minute resolution.** The tracker pings every 30 min (`tracker.py:24`). Also,
  `first_seen` is the time the site was added to the tracker (`:84`), not the time it was detected.

---

## The plan, by KPI

### K1. Measure first (days of work, and everything else depends on it)
1. **Lifecycle timestamps on the case:** `reported_at` (the email's `Date` header or the intake time),
   `queued_at`, `running_at`, `provisional_verdict_at`, `verdict_at`, `notified_at`, `acked_at`,
   `blocked_at`, `takedown_requested_at`, `down_at`. Also `source` (console, intake, feed or watch)
   and `reporter`.
2. **Thread the intake metadata into the case:** change `detonate_cb(url)` to
   `detonate_cb(url, meta)`.
3. **Record the analyst's disposition:** a `TP | FP | benign | duplicate` choice stored on the case,
   both from the intake list and from the case view. That gives the precision KPI. It also builds,
   for free, the labelled set you need to tune the verdict thresholds (currently the magic numbers
   80 / 45 / 20 at `sandbox.py:387-389`).
4. **Per-stage timings in the report:** decloak, browser open, walk, CF solve, enrichment, kit and
   total. That turns the bounds above into real numbers.
5. **KPI panel plus a weekly CSV export,** computed from `data/cases/*.json`. A SQLite index can come
   later; the per-case files are enough to start.

### K2. Faster first verdict
1. **Fast lane.** At t=0, start enrichment, the AiTM probe, the redirect chain and a static scan of
   the decloak bodies, all in parallel with launching Chrome. Publish a **provisional verdict** as soon
   as they return. `_verdict()` already copes with a partial report. Label it *provisional*; the full
   verdict replaces it when the walk finishes.
2. **Overlap the pipeline.** Total time becomes roughly *max(walk, enrichment)* instead of
   *decloak + walk + redirect + enrichment + kit*.
3. **Release the slot when Chrome closes.** Move `_DETONATE_SEM.release()` to just after the
   `with SB(...)` block. It's a one-line change, with the same RAM limit and more throughput.
4. **Statically scan the bodies the decloak already fetched** with the Telegram regex and
   `indicators.analyze_source`.

### K3. Throughput when reports arrive in bursts
1. **Dedupe and cache verdicts.** If the normalized URL (or the final landing URL, or the registrable
   domain within a time window) matches an existing case, link the new report to that case instead of
   detonating again. Forty reports then cost one detonation plus 39 linked reports. The KPI counts both
   reports and unique threats.
2. **Park cases that need a human.** When auto-solve fails: close Chrome, free the slot, mark the case
   `needs_analyst` and notify. Reopen it when an analyst picks it up. This keeps unattended intake
   moving.
3. **Priority queue.** Fast-lane `likely`/`confirmed` cases and reports from VIP recipients go first.
   The current semaphore has no notion of priority.

### K4. Shorter intake
1. **IMAP IDLE instead of the 30-second poll** with a fresh login each time, so new mail is seen
   within seconds.
2. **Make the mail host configurable** (`MAIL_IMAP_HOST`) instead of hardcoding Gmail. If the
   organisation runs on Microsoft 365, use Microsoft Graph.
3. **Read the user-reported-message mailbox directly**, i.e. the mailbox the "Report phishing" button
   delivers to. A report then reaches PhishLab without an analyst forwarding it. The trusted-sender
   allowlist exists to stop ordinary mail getting detonated. A dedicated reporting mailbox contains
   nothing but reports, so the rule simply becomes "everything in this mailbox".
   - This is the biggest time-to-detect win if forwarding is manual today.
   - It is also the step that most depends on K3 (dedupe) and K2 (fast lane), because user reports
     come in high volume and most of them aren't phishing.

### K5. Faster containment
1. **Notify** at `likely` and above, via a Teams or Slack webhook or email. Include the verdict, top
   reasons, screenshot and a case link. This starts the acknowledge clock.
2. **Block feed.** Publish confirmed URLs and domains as a plain-text list that the firewall, proxy or
   DNS filter pulls. FortiGate external threat feeds, Palo Alto EDLs and most web proxies accept that
   format. Guardrails:
   - auto-publish only at `confirmed_phishing`
   - `likely` needs one analyst click
   - never publish allowlisted domains
   - entries expire
3. **Auto-add to the tracker** at `likely` and above, with `detected_at` set to the verdict time.
4. **Retro-hunt helper.** Generate the "who else received this?" search (sender, subject, URL,
   domain) as a ready-to-run mail-trace or Defender query. Actually purging mail stays with the
   analyst.

### K6. Faster takedown
1. **Contact the registrar and host directly.** Get the registrar's abuse email from domain RDAP
   (already fetched by `enrich.rdap_domain`) and the host's abuse contact from IP RDAP. Generate the
   takedown email with screenshot, URL, first-seen time and exfil evidence; send it in one click; record
   `takedown_requested_at`.
2. **Submit by API at `confirmed`** to Netcraft and any other service that accepts URL reports that
   way. Check each service's terms first.
3. **Adaptive tracker cadence:** ping every 5 minutes for the first few hours after reporting, then
   back off to 30. That gives takedown time real resolution.

### K7. Detect before anyone reports it
1. **Certificate Transparency brand watch.** Stream newly issued TLS certificates (certstream, or a
   self-hosted CT log poller), match them against the protected brand names and lookalikes, and
   auto-detonate the matches. Phishing sites usually get a certificate *before* the emails go out. This
   is the only lever that yields "detected before the first report".
2. **Lookalike-domain watch.** Generate permutations of the organisation's own domains (typos,
   homoglyphs, TLD swaps, dnstwist-style). Check them periodically for registration and resolution,
   and detonate new ones.
3. **Feed ingestion.** Pull OpenPhish, URLhaus and PhishTank feeds, filter to protected brands and
   auto-detonate. OpenPhish and phishunt were already on the AiTM roadmap and still aren't implemented.

### K8. Keep the speed honest (detection quality)
Faster verdicts and auto-blocking raise the risk of false positives, so precision has to be tracked
next to speed. These items mostly move accuracy rather than speed, so they rank below K1–K7. They
still matter:

- **Engine split.** On the default Chrome engine, exfil proof, live AiTM relay detection, external-JS
  decoding and in-app takeover all go missing:

  | Capability | `sb_session.py` — **default** (Chrome / SeleniumBase UC) | `session.py` (Camoufox) |
  |---|---|---|
  | Solves hardened Cloudflare Turnstile | **yes** (real OS-mouse click) | no |
  | Live network capture | **none** | yes (`page.on`) |
  | Proof of where typed creds were sent | **no**, infers it from DOM `form.action` | yes (`session.py:581-588`) |
  | Live AiTM backend-relay detection | **no** | yes (`session.py:589-604`) |
  | External `.js` fetch and decode | **no** | yes (`session.py:543-549`) |
  | Interaction-gated reveals (CrawlPhish) | **no** | yes (`session.py:170-188`) |
  | In-app takeover / pause / resume | **stubs:** `forward()` returns, `resume()` is `pass` (`sb_session.py:204-212`) | full |

  The fix is CDP network capture on the Chrome engine (it already calls `execute_cdp_cmd` at
  `sb_session.py:330`), plus one shared analysis module so both engines produce the same report.
- **Silent failures.** There are 261 `except Exception` handlers, 118 of them `pass`-only. A
  timed-out Safe Browsing or Spamhaus lookup silently drops its 35–40 points. With a fast lane this
  gets worse: a provisional verdict has to say which signals it doesn't have yet.
- **No tests and no CI.** The fast lane changes *when* the verdict is computed, so add golden-verdict
  tests on the built-in demo kits (`/demo-phish/`, `/demo-cfphish/`, `/demo-aitm/…`, and so on)
  before it ships.

### Hygiene and security (cheap, can be done any time)
- **The README's "validate-and-pin" claim isn't implemented.** `net_guard.check_target()` checks the
  resolved IP but never pins it, so the fetch resolves again (a DNS-rebind window).
- **The SSRF guard is missing from 7 modules that fetch URLs derived from attacker content**
  (`kit`, `tracker`, `enrich`, `phishtank`, `session`, `aitm`, `sandbox`).
- **Cross-origin (CSRF) protection is on only 3 of the 24 state-changing endpoints.** Any page open in
  another browser tab can trigger detonations.
- **The Docker setup doesn't work.** uvicorn binds the container's loopback, so the published port
  can't reach it, and the image installs Firefox while the default engine needs Chrome.
- **Dependencies float.** `seleniumbase>=4.50` is the Turnstile-solving core.
- **No real version.** `__version__` is still `0.1.0` and there are no git tags.

---

## Recommended order (KPI impact per unit of effort)

| # | Work | KPI it moves | Rough effort |
|---|---|---|---|
| 1 | **K1**: lifecycle timestamps, intake→case linkage, TP/FP disposition, per-stage timings, KPI panel | makes every KPI computable | days |
| 2 | **K2.3** free the slot when Chrome closes, then **K2.2** overlap the pipeline | time to verdict, throughput | ~1–2 days |
| 3 | Golden-verdict tests on the demo kits, then **K2.1 / K2.4** fast-lane provisional verdict | time to first verdict | days |
| 4 | **K5.1** notifications + **K5.3** auto-add to tracker | time to acknowledge; takedown becomes measurable | days |
| 5 | **K3** dedupe + park human-needed cases | throughput, queue wait | ~1 week |
| 6 | **K4** IMAP IDLE + configurable host, then reporting-mailbox intake | intake latency, time to detect | ~1 week (more if via Graph) |
| 7 | **K5.2** block feed with guardrails | time to contain | days |
| 8 | **K6** abuse-contact takedown emails + adaptive tracker cadence | time to takedown | ~1 week |
| 9 | **K7** CT / lookalike / feed watch | proactive rate | 1–2 weeks |
| — | **K8** and hygiene, alongside the above | precision | ongoing |

Steps 1–4 are mostly plumbing around logic that already exists. They don't need new detection
techniques, and they move the most KPIs per day of work.

## In one line

The detection logic is largely there. What's missing is speed through the pipeline and the timestamps
to prove it: measure first, run the serial stages in parallel, stop relying on an analyst to forward
mail, and push verdicts to where blocking happens.
