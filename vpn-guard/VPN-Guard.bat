@echo off
chcp 65001 >nul
title VPN Guard
cd /d "%~dp0"
set "PY="
py -3 -c "import sys" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "import sys" >nul 2>nul && set "PY=python"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set PY="%LocalAppData%\Programs\Python\Python312\python.exe"
if not defined PY (
  echo Python not found. Installing it automatically, please wait about a minute...
  winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
  if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set PY="%LocalAppData%\Programs\Python\Python312\python.exe"
)
if not defined PY (
  echo Could not install Python automatically.
  echo Install it from https://www.python.org/downloads/ ^(tick "Add python.exe to PATH"^) and run this file again.
  pause
  exit /b 1
)
echo Starting VPN Guard... Do not close this window while protection is needed.
%PY% vpn_guard.py
echo.
echo VPN Guard stopped ^(code %errorlevel%^). If this is an error, send a screenshot of this window.
pause
