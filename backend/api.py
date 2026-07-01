"""api.py — PhishLab local API + GUI host.

Serves the single-page detonation console and runs detonations. Bind to localhost on the isolated
SOC PC. The detonate endpoint intentionally visits the untrusted URL (that is the tool's job) — run
it only on the dedicated detonation host.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from phishlab.sandbox import detonate

app = FastAPI(title="PhishLab", version="0.1.0")
WEB = Path(__file__).parent / "web"


class DetonateReq(BaseModel):
    url: str = Field(min_length=1, max_length=4000)


@app.get("/")
async def index() -> HTMLResponse:
    # no-store so the browser never serves a stale GUI after an update
    return HTMLResponse((WEB / "index.html").read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store, max-age=0"})


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "service": "phishlab"}


@app.post("/api/detonate")
async def api_detonate(req: DetonateReq):
    url = (req.url or "").strip()
    if not url:
        return JSONResponse({"error": "Enter a URL to detonate."}, status_code=400)
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    try:
        return await detonate(url)
    except Exception as exc:  # detonation of a live/hostile page can fail many ways — report it
        return JSONResponse({"error": f"Detonation failed — {type(exc).__name__}: {exc}"[:300]},
                            status_code=500)
