@echo off
REM PhishLab auto-start wrapper — launched on logon by the Startup shortcut so the takedown monitor
REM and Gmail intake auto-resume after a reboot. Runs in the background (no browser pop). Delete the
REM "PhishLab" shortcut from shell:startup to disable auto-start.
set "PHISH_NO_BROWSER=1"
cd /d "%~dp0"
call "%~dp0PhishLab.bat"
