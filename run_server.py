"""PhishLab launcher.

Sets the Windows Proactor event-loop policy BEFORE uvicorn builds its loop, then starts the server.
Playwright/Camoufox launch the browser as a subprocess, which the default SelectorEventLoop cannot spawn
(-> NotImplementedError, every detonation fails with 0 steps). `python -m uvicorn` imports the app inside
asyncio.run(), i.e. after the loop already exists, so setting the policy in api.py is too late to be
guaranteed — doing it here, before uvicorn.run(), makes it deterministic on any Python/uvicorn combo.
"""
import asyncio
import os
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

import uvicorn  # noqa: E402  (import after the loop policy is set)

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=int(os.getenv("PORT", "8090")))
