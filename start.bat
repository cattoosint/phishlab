@echo off
REM ============================================================
REM  start.bat  —  one-click PhishLab launcher
REM
REM  Double-click this file. It starts everything:
REM    * Tor  (2nd vantage for the takedown tracker, on 127.0.0.1:9050)
REM    * the PhishLab server (http://127.0.0.1:8090)
REM    * opens the console in your browser
REM  Close the window to stop it all.
REM
REM  (Thin wrapper around PhishLab.bat, the maintained launcher, so
REM   there is a single obvious "start" file and no duplicated logic.)
REM ============================================================
cd /d "%~dp0"
call "%~dp0PhishLab.bat" %*
