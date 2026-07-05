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
  echo   Fetching the Cloudflare-capable browser ^(Camoufox^)...
  python -m camoufox fetch
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

REM ── find the Wi-Fi LAN IP so homies on the same network can reach it ──
set "LANIP="
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 ^| Where-Object {$_.InterfaceAlias -like '*Wi-Fi*' -and $_.IPAddress -notlike '169.*'} ^| Select-Object -First 1).IPAddress"`) do set "LANIP=%%i"

echo.
echo   PhishLab running   ^(close this window to stop^)
echo     You:    http://127.0.0.1:%PORT%
if defined LANIP echo     Homies: http://%LANIP%:%PORT%   ^(same Wi-Fi^)
echo.
REM open the console locally a moment after the server starts (skip when auto-started on boot)
if not defined PHISH_NO_BROWSER start "" cmd /c "timeout /t 3 >nul & start "" http://127.0.0.1:%PORT%/"
REM bind all interfaces so the LAN can reach it; the Host-guard limits callers to localhost + private IPs
REM Self-restart loop: an in-app GitHub update pulls new code then exits with code 42, and we relaunch
REM with the fresh code. (A clean restart — NOT uvicorn --reload, which on Windows breaks Playwright's
REM browser subprocess with NotImplementedError.)
:runserver
python run_server.py
if errorlevel 42 if not errorlevel 43 (echo. & echo === Applying update - relaunching PhishLab === & echo. & goto runserver)
