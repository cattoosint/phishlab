@echo off
setlocal enabledelayedexpansion
title PhishLab - Installer
cd /d "%~dp0"

echo.
echo   ==================================================================
echo     PhishLab - one-time setup  (run once on the detonation box)
echo   ==================================================================
echo.

REM --- Python 3.11+ on PATH ---
where python >nul 2>nul || (
  echo   [X] Python is not on PATH. Install Python 3.11 or newer from
  echo       https://www.python.org/downloads/  (tick "Add python.exe to PATH"^),
  echo       then run this installer again.
  echo.
  pause
  exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set "PYV=%%v"
echo   [OK] Python %PYV%
echo.

REM --- virtual environment ---
if exist ".venv\Scripts\python.exe" (
  echo   [OK] Environment already exists ^(.venv^)
) else (
  echo   [..] Creating the virtual environment ...
  python -m venv .venv || ( echo   [X] Could not create .venv & pause & exit /b 1 )
  echo   [OK] .venv created
)
call ".venv\Scripts\activate.bat"
echo.

REM --- Python dependencies ---
echo   [..] Upgrading pip ...
python -m pip install --disable-pip-version-check --quiet --upgrade pip
echo   [..] Installing dependencies ^(a few minutes the first time^) ...
python -m pip install --disable-pip-version-check --quiet -r backend\requirements.txt || (
  echo   [X] Dependency install failed. Check your connection and re-run.
  pause
  exit /b 1
)
echo   [OK] Python dependencies installed
echo.

REM --- Outlook .msg support (extract-msg hard-pins an OLD beautifulsoup4 that clashes with SeleniumBase's
REM      ~=4.15, so install it WITHOUT its deps to keep the right bs4. Non-fatal: .eml/.pdf/.html work anyway) ---
echo   [..] Installing Outlook .msg support ...
python -m pip install --disable-pip-version-check --quiet --no-deps "extract-msg>=0.48" && python -m pip install --disable-pip-version-check --quiet compressed-rtf ebcdic olefile red-black-tree-mod RTFDE tzlocal && (echo   [OK] Outlook .msg support installed) || (echo   [!] Outlook .msg support skipped ^(non-fatal - .eml/.pdf/.html still parse^))
echo.

REM --- browsers ---
echo   [..] Downloading the Playwright Firefox browser ...
python -m playwright install firefox || echo   [!] Firefox download hiccup - retry later: python -m playwright install firefox
echo   [..] Downloading the anti-bot browser ^(Camoufox^) ...
python -m camoufox fetch || echo   [!] Camoufox fetch hiccup - retry later: python -m camoufox fetch
echo.

REM --- Tor (optional: a 2nd decloak vantage for the multi-vantage cloaking check) ---
if exist "tor\tor\tor.exe" (
  echo   [OK] Tor already present
) else (
  echo   [..] Downloading Tor ^(2nd decloak vantage; ~20 MB, optional^) ...
  if not exist "tor" mkdir tor
  powershell -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri 'https://archive.torproject.org/tor-package-archive/torbrowser/14.5.1/tor-expert-bundle-windows-x86_64-14.5.1.tar.gz' -OutFile 'tor\teb.tar.gz' } catch { exit 1 }"
  if exist "tor\teb.tar.gz" (
    tar -xzf "tor\teb.tar.gz" -C "tor" && del "tor\teb.tar.gz" >nul 2>nul
    if exist "tor\tor\tor.exe" ( echo   [OK] Tor installed ) else ( echo   [!] Tor extract failed - decloak will run without the Tor vantage ^(non-fatal^) )
  ) else (
    echo   [!] Tor download failed - decloak will run without the Tor vantage ^(non-fatal^)
  )
)
echo.

REM --- Chrome (needed by the default SeleniumBase engine for Cloudflare solving) ---
set "CHROME="
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "CHROME=1"
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "CHROME=1"
if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" set "CHROME=1"
if defined CHROME (
  echo   [OK] Google Chrome found  ^(used by the default detonation engine^)
) else (
  echo   [!] Google Chrome was NOT found. The default engine needs it to solve
  echo       Cloudflare. Install Chrome from https://www.google.com/chrome/ and
  echo       re-run, or run with PHISH_ENGINE=camoufox to use the Firefox engine.
)
echo.

REM --- optional .env (API keys / Gmail intake creds) — auto-loaded from the folder OR backend\ ---
if exist ".env" (
  echo   [OK] .env found in this folder - it will be loaded automatically.
) else if exist "backend\.env" (
  echo   [OK] backend\.env found - it will be loaded automatically.
) else (
  echo   [i] No .env yet ^(optional^). Copy  .env.example  to  .env  and fill in any keys you have
  echo       ^(VirusTotal, Gmail intake, etc.^). PhishLab runs fine without it.
)
echo.
echo   ==================================================================
echo     Setup complete.  One-click launch:   start.bat
echo     ^(starts Tor + the server + opens the console^)
echo     Then open in a browser:   http://127.0.0.1:8090
echo   ==================================================================
echo.
pause
