@echo off
cd /d "%~dp0"
set "PYW="
set "ARGS="
where pyw >nul 2>nul && (set "PYW=pyw" & set "ARGS=-3")
if not defined PYW (where pythonw >nul 2>nul && set "PYW=pythonw")
if not defined PYW if exist "%LocalAppData%\Programs\Python\Python312\pythonw.exe" set "PYW=%LocalAppData%\Programs\Python\Python312\pythonw.exe"
if not defined PYW (
  echo Python not found. Installing it automatically, please wait about a minute...
  winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
  if exist "%LocalAppData%\Programs\Python\Python312\pythonw.exe" set "PYW=%LocalAppData%\Programs\Python\Python312\pythonw.exe"
)
if not defined PYW (
  echo Could not install Python automatically.
  echo Install it from https://www.python.org/downloads/ ^(tick "Add python.exe to PATH"^) and run this file again.
  pause
  exit /b 1
)
start "" "%PYW%" %ARGS% vpn_guard.py
