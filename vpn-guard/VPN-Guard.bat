@echo off
title VPN Guard
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 vpn_guard.py
  goto done
)
where python >nul 2>nul
if %errorlevel%==0 (
  python vpn_guard.py
  goto done
)
echo Python 3 not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
:done
pause
