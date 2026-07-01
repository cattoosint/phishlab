"""demo.py — verify the detonation engine end-to-end against a self-served phishing FIXTURE.

Serves a benign 2-step fake-phish (Microsoft-branded login -> OTP step) that embeds a Telegram
exfil bot in its source, then runs phishlab.sandbox.detonate() against it and prints the report.
Run inside an env that has invisible_playwright + Firefox (e.g. the Shadow backend container):

    python demo.py
"""
import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from phishlab.sandbox import detonate

try:  # Windows consoles default to cp1252 and choke on non-ASCII; the report is UTF-8
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

PORT = 8098
# a valid-shaped Telegram bot token (bot-id : 35-char secret) — the key exfil IOC
TG = "123456789:1234567890AbCdEfGhIjKlMnOpQrStUvWxY"

LOGIN = f"""<!doctype html><html><head><title>Sign in to your Microsoft account</title></head>
<body><h1>Microsoft</h1><p>Sign in to continue to Office 365</p>
<form method="POST" action="/steal">
  <input type="email" name="loginfmt" placeholder="Email, phone, or Skype">
  <input type="password" name="passwd" placeholder="Password">
  <button type="submit">Sign in</button>
</form>
<script>/* exfil channel: https://api.telegram.org/bot{TG}/sendMessage?chat_id=987654321 */</script>
</body></html>"""

OTP = """<!doctype html><html><head><title>Verify your identity</title></head>
<body><h1>Microsoft</h1><p>Enter the code we sent to your phone</p>
<form method="POST" action="/steal2">
  <input type="text" name="otp" placeholder="Verification code">
  <button type="submit">Verify</button>
</form></body></html>"""

DONE = """<!doctype html><html><head><title>Redirecting…</title></head>
<body><h1>Thank you</h1><p>Redirecting to Office…</p></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        self._send({"/steal": OTP, "/steal2": DONE}.get(self.path, LOGIN))

    def do_POST(self):
        try:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
        except Exception:
            pass
        self._send({"/steal": OTP, "/steal2": DONE}.get(self.path, LOGIN))

    def log_message(self, *a):
        pass


async def main():
    srv = HTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        report = await detonate(f"http://127.0.0.1:{PORT}/login")
    finally:
        srv.shutdown()

    print("\n===== NARRATION =====")
    for line in report["narration"]:
        print(" ", line)
    print("\n===== VERDICT =====")
    v = report["verdict"]
    print(f"  {v['label'].upper()}  score={v['score']}")
    for r in v["reasons"]:
        print("   -", r)
    print("\n===== EXFIL =====")
    print("  telegram bots:", [t["bot_token"] for t in report["exfil"]["telegram"]])
    print("  form actions :", sorted(set(a for a in report["exfil"]["form_actions"] if a)))
    print("  brands       :", report["iocs"].get("brands_impersonated"))
    print(f"\n  steps={len(report['steps'])}  screenshots={sum(1 for s in report['steps'] if s.get('screenshot'))}"
          f"  elapsed={report.get('elapsed')}s")

    # assertions (self-check)
    ok = []
    def ck(n, c): ok.append(c); print(("PASS" if c else "FAIL"), "-", n)
    print("\n===== SELF-CHECK =====")
    ck("victim page reached", report["decloak"]["victim"].get("reached"))
    ck("credential form detonated (fake creds filled+submitted)",
       any(s.get("action") == "fill+submit" for s in report["steps"]))
    ck("multi-step (login -> OTP)", len([s for s in report["steps"] if s.get("action") == "load"]) >= 2)
    ck("Telegram exfil bot extracted", bool(report["exfil"]["telegram"]))
    ck("brand impersonation flagged (microsoft)", "microsoft" in (report["iocs"].get("brands_impersonated") or []))
    ck("screenshots captured", sum(1 for s in report["steps"] if s.get("screenshot")) >= 2)
    ck("verdict is phishing-ish", report["verdict"]["label"] in ("suspicious", "likely_phishing", "confirmed_phishing"))
    print(f"\n==== {sum(ok)}/{len(ok)} ====", "ALL_PASS" if all(ok) else "SOME_FAILED")


if __name__ == "__main__":
    asyncio.run(main())
