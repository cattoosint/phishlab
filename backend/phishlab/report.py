"""phishlab/report.py — SOC report + takedown targets.

Turns a detonation report into a self-contained, shareable HTML report (verdict + evidence +
screenshot timeline) to attach to a ticket, a Markdown summary for pasting, and the list of
takedown/abuse destinations to submit the URL to (Safe Browsing, Microsoft, Fortinet, Netcraft,
APWG, + the hosting/registrar abuse contacts derived from enrichment).
"""
from __future__ import annotations

import html
import json
from urllib.parse import quote, urlsplit


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def takedown_targets(report: dict) -> list[dict]:
    url = report.get("url", "")
    host = urlsplit(url).hostname or ""
    enr = report.get("enrichment") or {}
    ipinfo = enr.get("ip") or {}
    asn = ipinfo.get("org") or ipinfo.get("isp") or ""
    q = quote(url, safe="")
    qh = quote(host, safe="")
    targets = [
        {"name": "Google Safe Browsing", "note": "report phishing (URL prefilled)",
         "url": "https://safebrowsing.google.com/safebrowsing/report_phish/?url=" + q},
        {"name": "Microsoft (SmartScreen)", "note": "report an unsafe site",
         "url": "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest"},
        {"name": "Fortinet FortiGuard", "note": "submit URL for rating/reclassification",
         "url": "https://www.fortiguard.com/webfilter?q=" + q},
        {"name": "Netcraft", "note": "report phishing (URL prefilled)",
         "url": "https://report.netcraft.com/report?url=" + q},
        {"name": "APWG", "note": "e-mail the Anti-Phishing Working Group",
         "url": f"mailto:reportphishing@apwg.org?subject=Phishing:%20{qh}&body={q}"},
        {"name": "PhishTank", "note": "community blocklist (login required)",
         "url": "https://www.phishtank.com/add_web_phish.php"},
    ]
    if asn:
        targets.append({"name": f"Hosting abuse ({asn[:40]})",
                        "note": "contact the host to pull the site", "url": "https://www.abuseipdb.com/check/" + quote(ipinfo.get("ip") or host)})
    return targets


def _rows(items: list[str]) -> str:
    return "".join(f"<li>{i}</li>" for i in items)


def build_html(report: dict) -> str:
    v = report.get("verdict") or {}
    label = (v.get("label") or "inconclusive").replace("_", " ").upper()
    score = v.get("score", 0)
    colour = "#d95f57" if score >= 80 else "#d99a3a" if score >= 45 else "#4a9eda" if score >= 20 else "#7a8a99"
    url = report.get("url", "")
    dc = report.get("decloak") or {}
    mv = dc.get("multi_vantage") or {}
    ex = report.get("exfil") or {}
    an = report.get("indicators") or {}
    kit = report.get("kit") or {}
    enr = report.get("enrichment") or {}
    rd, ip = enr.get("rdap") or {}, enr.get("ip") or {}
    io = report.get("iocs") or {}
    nw = report.get("network") or {}

    steps_html = ""
    for s in report.get("steps") or []:
        shot = (f"<img src='data:image/jpeg;base64,{s['screenshot']}'>" if s.get("screenshot")
                else "<div class='noshot'>no screenshot</div>")
        if s.get("action") == "fill+submit":
            ff = s.get("filled_fields") or []
            entered = " · ".join(f"{_e(f.get('kind'))}: <b>{_e(f.get('value'))}</b>" for f in ff) or "credentials"
            body = (f"<div class='si'>step {s.get('i')} · fill + submit</div>"
                    f"<div class='st'>Entered {len(ff)} field(s) → submitted</div>"
                    f"<div class='sm'>{entered}</div><div class='sm'>→ {_e(s.get('creds_sent_to'))}"
                    + ("  <span class='hz'>OFF-SITE</span>" if s.get("off_site") else "") + "</div>")
        else:
            tel = ("  <span class='hz'>Telegram bot " + _e((s.get("telegram") or [{}])[0].get("bot_id")) + "</span>"
                   if s.get("telegram") else "")
            body = (f"<div class='si'>step {s.get('i')} · load</div>"
                    f"<div class='st'>{_e(s.get('title') or '(no title)')}</div>"
                    f"<div class='sm'>{_e(s.get('url'))}{tel}</div>")
        steps_html += f"<div class='step'>{shot}<div>{body}</div></div>"

    tel_html = _rows([f"bot <b>{_e(t.get('bot_id'))}</b> · {_e(t.get('bot_token'))}"
                      + (f" · chat {_e(', '.join(t.get('chat_ids') or []))}" if t.get("chat_ids") else "")
                      for t in ex.get("telegram") or []]) or "<li>none</li>"
    ind_html = _rows([f"[{_e(i.get('severity'))}] {_e(i.get('title'))}"
                      + (f" <code>{_e(i.get('evidence'))}</code>" if i.get("evidence") else "")
                      for i in an.get("indicators") or []]) or "<li>none</li>"
    van_html = _rows([f"<b>{_e(p.get('label'))}</b> · {_e(p.get('status'))} · {_e(p.get('title') or p.get('reason') or '')}"
                      for p in dc.get("vantages") or []]) or "<li>single vantage</li>"
    tgt_html = _rows([f"<a href='{_e(t['url'])}' target='_blank'>{_e(t['name'])}</a> — {_e(t['note'])}"
                      for t in takedown_targets(report)])

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>PhishLab report — {_e(urlsplit(url).hostname)}</title>
<style>
 body{{font-family:'Segoe UI',Arial,sans-serif;max-width:1000px;margin:0 auto;padding:28px;color:#1a2027;background:#fff}}
 h1{{font-size:20px;margin:0}} h2{{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#5a6a78;border-bottom:1px solid #e3e8ee;padding-bottom:6px;margin:26px 0 10px}}
 .verd{{display:inline-block;color:#fff;background:{colour};font-weight:700;padding:4px 12px;border-radius:6px}}
 .url{{font-family:Consolas,monospace;background:#f3f5f8;padding:8px 10px;border-radius:6px;word-break:break-all;margin:10px 0}}
 ul{{margin:6px 0;padding-left:20px}} li{{margin:3px 0;font-size:13.5px}} code{{background:#f3f5f8;padding:1px 5px;border-radius:4px;font-size:12px}}
 .hz{{color:#d95f57;font-weight:600}} .kv{{font-size:13.5px;margin:3px 0}} .kv b{{display:inline-block;min-width:130px;color:#5a6a78;font-weight:600}}
 .step{{display:flex;gap:14px;align-items:flex-start;margin:10px 0;padding:10px;border:1px solid #e3e8ee;border-radius:8px}}
 .step img{{width:240px;border:1px solid #dde3ea;border-radius:4px}} .noshot{{width:240px;height:150px;background:#f3f5f8;display:flex;align-items:center;justify-content:center;color:#9aa7b3;font-size:12px;border-radius:4px}}
 .si{{font-family:monospace;font-size:11px;color:#8a97a3}} .st{{font-weight:600;margin:2px 0}} .sm{{font-size:12.5px;color:#556}} .foot{{color:#9aa7b3;font-size:11px;margin-top:30px}}
</style></head><body>
<h1>PhishLab detonation report</h1>
<div class="url">{_e(url)}</div>
<p><span class="verd">{label} · {score}</span></p>
<ul>{_rows([_e(r) for r in v.get('reasons') or []]) or '<li>no strong signals</li>'}</ul>

<h2>Decloak</h2>
<div class="kv"><b>scanner vs victim</b> {_e(dc.get('cloaked') or '—')}</div>
<div class="kv"><b>IP/geo cloaking</b> {'YES — ' + _e(', '.join(mv.get('diffs') or [])) if mv.get('cloaked') else 'no'}</div>
<ul>{van_html}</ul>

<h2>Exfil</h2>
<div class="kv"><b>Telegram</b></div><ul>{tel_html}</ul>

<h2>Code analysis ({_e((an.get('counts') or {}).get('high',0))} high / {_e((an.get('counts') or {}).get('medium',0))} med)</h2>
<ul>{ind_html}</ul>

<h2>Enrichment</h2>
<div class="kv"><b>domain age</b> {_e(rd.get('age_days'))} days · registered {_e((rd.get('created') or '')[:10])} · {_e(rd.get('registrar'))}</div>
<div class="kv"><b>hosting</b> {_e(ip.get('ip'))} · {_e(ip.get('org') or ip.get('isp'))} · {_e(ip.get('country'))}</div>

<h2>Phishing kit</h2>
<ul>{_rows(['archives: ' + str(len(kit.get('archives') or [])), 'open dirs: ' + str(len(kit.get('open_dirs') or [])), 'cred logs: ' + str(len(kit.get('cred_logs') or [])), 'saved to: ' + _e(kit.get('saved_to') or '—')]) if kit.get('found') else '<li>no kit / logs recovered from the host</li>'}</ul>

<h2>IOCs</h2>
<div class="kv"><b>IPs</b> {_e(', '.join(io.get('ips') or []) or '—')}</div>
<div class="kv"><b>domains</b> {_e(', '.join((io.get('domains') or [])[:15]) or '—')}</div>
<div class="kv"><b>off-host requests</b> {_e(', '.join((nw.get('hosts') or [])[:12]) or '—')}</div>

<h2>Screenshot timeline</h2>
{steps_html or '<p>no steps</p>'}

<h2>Report / takedown</h2>
<ul>{tgt_html}</ul>

<div class="foot">Generated by PhishLab. Fake credentials only — no real data submitted. Detonated on the isolated analysis host.</div>
</body></html>"""


def build_markdown(report: dict) -> str:
    v = report.get("verdict") or {}
    lines = [f"# PhishLab report — {report.get('url','')}",
             f"**Verdict:** {(v.get('label') or '').replace('_',' ').upper()} ({v.get('score',0)}/100)", ""]
    for r in v.get("reasons") or []:
        lines.append(f"- {r}")
    ex = report.get("exfil") or {}
    if ex.get("telegram"):
        t = ex["telegram"][0]
        lines += ["", f"**Telegram exfil:** bot `{t.get('bot_token')}` chat `{', '.join(t.get('chat_ids') or [])}`"]
    an = report.get("indicators") or {}
    if an.get("indicators"):
        lines += ["", "**Source indicators:**"] + [f"- [{i['severity']}] {i['title']}" for i in an["indicators"]]
    lines += ["", "**Report to:**"] + [f"- {t['name']}: {t['url']}" for t in takedown_targets(report)]
    return "\n".join(lines)
