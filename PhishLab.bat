@echo off
REM PhishLab.bat — kept for backwards-compatibility (old shortcuts, the logon autostart, and the in-app
REM update loop all reference it). The ONE real launcher is now start.bat — this just forwards to it so
REM there is a single source of truth and you never end up running a stale version.
cd /d "%~dp0"
call "%~dp0start.bat" %*
