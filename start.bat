@echo off
setlocal enabledelayedexpansion
title PhishLab
cd /d "%~dp0"

REM ============================================================
REM  start.bat — the ONE launcher. Double-click to run PhishLab.
REM  It always runs the UPDATED version: pulls the latest code,
REM  kills any stale server on the port, then starts Tor + the
REM  server + opens the console. Close the window to stop.
REM  (First-time full setup: run Install.bat once.)
REM ============================================================

set "PORT=8090"

REM ── environment: first run builds it; after that just activate ──
if not exist ".venv\Scripts\python.exe" (
  echo.
  echo   First-time setup — building the environment + downloading the browser ^(a few minutes^).
  echo   TIP: run Install.bat once instead for the FULL setup ^(Tor, Outlook .msg, Chrome check^).
  echo.
  where python >nul 2>nul || ( echo   [X] Python 3.11+ required on PATH. Install from python.org, then re-run. & pause & exit /b 1 )
  python -m venv .venv || ( echo   [X] Could not create the environment. & pause & exit /b 1 )
  call ".venv\Scripts\activate.bat"
  python -m pip install --disable-pip-version-check --quiet --upgrade pip
  python -m pip install --disable-pip-version-check --quiet -r backend\requirements.txt || ( echo   [X] Dependency install failed. & pause & exit /b 1 )
  python -m playwright install firefox || ( echo   [X] Browser download failed. & pause & exit /b 1 )
  python -m camoufox fetch
) else (
  call ".venv\Scripts\activate.bat"
)

REM ── always run the UPDATED version: fast-forward to origin (best-effort; ff-only never clobbers local
REM     work, and it's non-fatal offline). If the pull changed anything, re-sync dependencies. ──
where git >nul 2>nul
if not errorlevel 1 if exist ".git" (
  echo   Checking GitHub for updates...
  for /f %%h in ('git rev-parse HEAD 2^>nul') do set "BEFORE=%%h"
  git pull --ff-only >nul 2>nul
  for /f %%h in ('git rev-parse HEAD 2^>nul') do set "AFTER=%%h"
  if not "!BEFORE!"=="!AFTER!" (
    echo   [OK] Updated to the latest version - syncing dependencies...
    python -m pip install --disable-pip-version-check --quiet -r backend\requirements.txt
  ) else (
    echo   [OK] Already on the latest version.
  )
)
set "VER="
for /f %%h in ('git rev-parse --short HEAD 2^>nul') do set "VER=%%h"

REM ── Tor (2nd decloak vantage for the takedown tracker) ──
if exist "tor\tor\tor.exe" (
  netstat -ano | find ":9050" | find "LISTENING" >nul || (
    echo   Starting Tor ^(2nd vantage for the takedown tracker^)...
    start "" /min "tor\tor\tor.exe" --SocksPort 9050 --GeoIPFile "tor\data\geoip" --GeoIPv6File "tor\data\geoip6" --DataDirectory "tor\tordata"
  )
  set "PHISH_TRACK_VANTAGES=tor=socks5://127.0.0.1:9050"
)

REM ── kill any STALE PhishLab server already on the port, so ONLY this (updated) one serves ──
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%PORT% " ^| findstr LISTENING') do taskkill /F /PID %%p >nul 2>nul

REM ── LAN IP so homies on the same Wi-Fi can reach it ──
set "LANIP="
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 ^| Where-Object {$_.InterfaceAlias -like '*Wi-Fi*' -and $_.IPAddress -notlike '169.*'} ^| Select-Object -First 1).IPAddress"`) do set "LANIP=%%i"

echo.
echo   PhishLab running   ^(close this window to stop^)
if defined VER echo     Version: %VER%
echo     You:    http://127.0.0.1:%PORT%
if defined LANIP echo     Homies: http://%LANIP%:%PORT%   ^(same Wi-Fi^)
echo.
if not defined PHISH_NO_BROWSER start "" cmd /c "timeout /t 3 >nul & start "" http://127.0.0.1:%PORT%/"

REM ── run loop: an in-app update pulls new code then exits 42, and we relaunch with the fresh code
REM     (a clean restart — NOT uvicorn --reload, which on Windows breaks Playwright's browser subprocess) ──
:runserver
python run_server.py
if errorlevel 42 if not errorlevel 43 (echo. & echo === Update applied - relaunching PhishLab === & echo. & goto runserver)
