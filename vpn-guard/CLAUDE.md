# VPN Guard — контекст для Claude Code

Язык общения с пользователем: русский.

## Что это
Один файл `vpn_guard.py` (stdlib-only, Python 3.8+), Windows + macOS (+Linux по мелочи).
Закрывает выбранные приложения (по умолчанию Telegram, Claude), когда нет VPN или интернета.
Панель настроек — встроенный HTML (переменная `HTML`) на 127.0.0.1, JSON API с токеном.

## Структура файла
A: DEFAULTS/BOUNDS/sanitize/Store (конфиг: %APPDATA%\vpn-guard или ~/Library/Application Support/vpn-guard; env VPN_GUARD_HOME)
B: процессы (tasklist/ps), match_apps, kill_apps, check_internet, парсеры прокси/туннеля (winreg, scutil, netstat)
C: Monitor (тик, перепроверки retries/retry_delay_ms, блок при запуске), автозапуск, диагностика
D: HTTP-обработчик (/api/state, config, calibrate, autostart, shutdown), main()

## Тесты (в tests/, запускать из папки проекта)
python3 tests/test_core.py; python3 tests/test_monitor.py; python3 tests/test_api.py
(пути в тестах указывают на /mnt/user-data/outputs/vpn-guard/vpn_guard.py — поправь на локальный). Для ui.py нужен playwright и переменная SP для папки скриншотов.
Прошло: core 53/53, monitor 30/30, api 21/22 (одно падение — неверное ожидание в тесте: retries ограничен 20, а не 10).

## НЕ проверено на реальных системах
Windows: winreg-прокси, tasklist/taskkill, PowerShell Get-NetAdapter. macOS: scutil --proxy, netstat -rn, ps, LaunchAgent (plist пишется, но не загружается через launchctl). Реальное поведение Happ/Telegram/Claude. Парсеры основаны на известных форматах вывода — первым делом прогнать `python vpn_guard.py --diagnose` на обеих ОС.

## Задачи дальше
1. Проверить на реальных Windows и Mac, исправить парсеры.
2. UI-тест кликами (добавить приложение, пресеты, переключатель) — скриншот первой загрузки выглядел нормально, ошибок консоли нет.
3. Автозапуск на macOS: добавить launchctl load/unload.
4. Старый рабочий Windows-скрипт vpn-killswitch.ps1 (на рабочем столе пользователя) не менять.

## Правила
Claude в списке блокировки по умолчанию — по просьбе пользователя. Защищённые системные процессы не убивать (PROTECTED). Конфиг-патч атомарный.
