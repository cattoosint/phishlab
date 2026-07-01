"""api.py — PhishLab local API + GUI host.

Serves the single-page detonation console and runs detonations. Bind to localhost on the isolated
SOC PC. The detonate endpoint intentionally visits the untrusted URL (that is the tool's job) — run
it only on the dedicated detonation host.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from phishlab import session as S
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


# ── live interactive session (Phase 4b) ───────────────────────────────────────
def _norm_url(u: str) -> str:
    u = (u or "").strip()
    return u if u.lower().startswith(("http://", "https://")) else "http://" + u


@app.post("/api/session")
async def session_start(req: DetonateReq):
    """Start a LIVE detonation session; returns its id. Poll /state + /frame; POST /input + /resume."""
    url = _norm_url(req.url)
    if not url or url in ("http://", "https://"):
        return JSONResponse({"error": "Enter a URL to detonate."}, status_code=400)
    s = S.create(url)
    return {"id": s.id, "state": s.state}


@app.get("/api/session/{sid}")
async def session_state(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    return s.snapshot_state()


@app.get("/api/session/{sid}/frame")
async def session_frame(sid: str):
    s = S.get(sid)
    if not s or s.latest_frame is None:
        return Response(status_code=204)
    return Response(content=s.latest_frame, media_type="image/jpeg",
                    headers={"Cache-Control": "no-store"})


class InputEv(BaseModel):
    type: str
    x: float | None = None
    y: float | None = None
    key: str | None = None
    text: str | None = None


@app.post("/api/session/{sid}/input")
async def session_input(sid: str, ev: InputEv):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    await s.forward(ev.model_dump())
    return {"ok": True}


@app.post("/api/session/{sid}/takeover")
async def session_takeover(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    s.request_takeover()
    return {"ok": True, "state": s.state}


@app.post("/api/session/{sid}/resume")
async def session_resume(sid: str):
    s = S.get(sid)
    if not s:
        return JSONResponse({"error": "no such session"}, status_code=404)
    s.resume()
    return {"ok": True, "state": s.state}
