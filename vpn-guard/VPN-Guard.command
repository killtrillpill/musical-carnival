#!/bin/bash
# Двойной клик в Finder запускает VPN Guard и открывает панель в браузере.
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Нужен Python 3: https://www.python.org/downloads/  (или в Терминале: xcode-select --install)"
  read -n 1 -s -r -p "Нажми любую клавишу..."; exit 1
fi
python3 vpn_guard.py
read -n 1 -s -r -p "Остановлено. Нажми любую клавишу..."
