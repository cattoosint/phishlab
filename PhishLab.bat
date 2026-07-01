@echo off
setlocal enabledelayedexpansion
title PhishLab
cd /d "%~dp0"

REM ── PhishLab launcher — native, no Docker. Double-click to run. ──────────────
REM First run: creates a local environment + downloads the browser (a few minutes).
REM After that it starts instantly. Needs Python 3.11+ on PATH the first time only.

set "PORT=8090"

if not exist ".venv\Scripts\python.exe" (
  echo.
  echo   First-time setup — building the environment and downloading the browser.
  echo   This runs once and takes a few minutes. Leave this window open.
  echo.
  where python >nul 2>nul || ( echo   [X] Python 3.11+ is required on PATH. Install it from python.org, then re-run. & pause & exit /b 1 )
  python -m venv .venv || ( echo   [X] Could not create the environment. & pause & exit /b 1 )
  call ".venv\Scripts\activate.bat"
  python -m pip install --disable-pip-version-check --quiet --upgrade pip
  python -m pip install --disable-pip-version-check --quiet -r backend\requirements.txt || ( echo   [X] Dependency install failed. & pause & exit /b 1 )
  python -m playwright install firefox || ( echo   [X] Browser download failed. & pause & exit /b 1 )
) else (
  call ".venv\Scripts\activate.bat"
)

REM ── start Tor for the multi-vantage tracker (a 2nd exit to prove takedowns) ──
if exist "tor\tor\tor.exe" (
  netstat -ano | find ":9050" | find "LISTENING" >nul || (
    echo   Starting Tor ^(2nd vantage for the takedown tracker^)...
    start "" /min "tor\tor\tor.exe" --SocksPort 9050 --GeoIPFile "tor\data\geoip" --GeoIPv6File "tor\data\geoip6" --DataDirectory "tor\tordata"
  )
  set "PHISH_TRACK_VANTAGES=tor=socks5://127.0.0.1:9050"
)

echo.
echo   PhishLab running at http://127.0.0.1:%PORT%   (close this window to stop)
echo.
REM open the browser a moment after the server starts
start "" cmd /c "timeout /t 3 >nul & start "" http://127.0.0.1:%PORT%/"
python -m uvicorn api:app --app-dir backend --host 127.0.0.1 --port %PORT%
