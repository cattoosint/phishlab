# PhishLab — self-contained detonation sandbox image (browser baked in).
FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
# Vanilla Playwright Firefox is the reliable default engine; --with-deps pulls the system libs.
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install --with-deps firefox

COPY backend/ /app/

# Detonation is browser-driven; keep it headless in the container.
ENV PHISH_HEADFUL=0
EXPOSE 8090

# Serve the GUI + detonation API. (Run the engine self-test instead with: python demo.py)
# bind loopback only — the console is unauthenticated; expose it via an authenticated reverse proxy
# if you must reach it off-box. (compose maps 127.0.0.1:8090 to match.)
CMD ["uvicorn", "api:app", "--host", "127.0.0.1", "--port", "8090"]
