#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Guard - не даёт выбранным приложениям работать без VPN (Windows и macOS).

Запуск:   python vpn_guard.py        (откроется панель настроек в браузере)
Диагностика (если что-то не определяется):   python vpn_guard.py --diagnose

Только стандартная библиотека Python 3.8+. Ничего не отправляет в интернет:
панель слушает только 127.0.0.1 и защищена токеном. Настройки лежат в профиле
пользователя (путь покажет --diagnose).
"""
from __future__ import annotations

import argparse
import collections
import copy
import csv
import io
import ipaddress
import json
import os
import platform
import plistlib
import queue
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

APP_NAME = "vpn-guard"
VERSION = "1.0"
IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
DEFAULT_PORT = 47831

# ============================================================== настройки ==

DEFAULTS = {
    "enabled": False,            # при первом запуске защита выключена, пока не проверишь список
    "vpn": {
        "check": True,           # проверять VPN
        "process": "Happ",       # часть имени программы VPN ("" = не привязываться к программе)
        "mode": "auto",          # auto | proxy | tunnel | process
    },
    "apps": ["Telegram", "Claude"],
    "limits": {
        "interval": 1.0,         # секунд между проверками
        "retries": 3,            # перепроверок перед закрытием
        "retry_delay_ms": 300,   # пауза между перепроверками
        "net_timeout_ms": 800,   # сколько ждать ответа сети
        "check_internet": True,
        "hosts": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    },
}

BOUNDS = {
    "interval": (0.5, 30.0),
    "retries": (0, 20),
    "retry_delay_ms": (50, 5000),
    "net_timeout_ms": (200, 5000),
}

LIMIT_PRESETS = {
    "fast":     {"label": "Быстро",      "interval": 1.0, "retries": 1, "retry_delay_ms": 200, "net_timeout_ms": 600},
    "balanced": {"label": "Баланс",      "interval": 1.0, "retries": 3, "retry_delay_ms": 300, "net_timeout_ms": 800},
    "careful":  {"label": "Осторожно",   "interval": 2.0, "retries": 5, "retry_delay_ms": 500, "net_timeout_ms": 1500},
}

MODES = ("auto", "proxy", "tunnel", "process")

# Системные программы, которые нельзя блокировать (иначе можно сломать систему
# или закрыть саму защиту).
PROTECTED = set("""
explorer finder dock systemuiserver windowserver loginwindow launchd kernel_task
svchost csrss winlogon lsass services system smss wininit dwm fontdrvhost
init systemd sshd cmd powershell pwsh conhost windowsterminal terminal iterm2
bash zsh sh fish login sudo
""".split())


def is_protected(name: str) -> bool:
    low = name.strip().lower()
    return low in PROTECTED or low.startswith("python")


def vpn_conflict(app: str, vpn: str) -> bool:
    """Нельзя блокировать сам VPN-клиент: иначе он не сможет переподключиться."""
    a, v = app.lower(), vpn.lower()
    return bool(v) and (v in a or a in v)


_NAME_BAD = re.compile(r'[\x00-\x1f/\\:*?"<>|]')
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def clean_proc_name(raw, allow_empty=False):
    """-> (имя, ошибка)"""
    if not isinstance(raw, str):
        return "", "имя программы должно быть текстом"
    s = re.sub(r"\.(exe|app)$", "", raw.strip(), flags=re.I).strip()
    if not s:
        return ("", None) if allow_empty else ("", "пустое имя программы")
    if len(s) > 64 or _NAME_BAD.search(s) or s.startswith("-"):
        return "", "недопустимое имя программы: «%s»" % raw[:40]
    return s, None


def parse_target(raw):
    """'1.1.1.1' | 'host:8443' | '::1' -> (host, port). ValueError при ошибке."""
    s, port = str(raw).strip(), 443
    if not s:
        raise ValueError("пустой адрес")
    try:
        ipaddress.ip_address(s)
        return s, port
    except ValueError:
        pass
    if s.count(":") == 1:
        s, p = s.split(":")
        if not p.isdigit() or not 1 <= int(p) <= 65535:
            raise ValueError("неверный порт в «%s»" % raw)
        port = int(p)
    try:
        ipaddress.ip_address(s)
    except ValueError:
        if not _HOST_RE.match(s):
            raise ValueError("неверный адрес «%s»" % raw)
    return s, port


def sanitize(patch, cur):
    """Применяет частичное обновление к конфигу. -> (новый_конфиг, [ошибки]).
    При любой ошибке ничего не применяется."""
    if not isinstance(patch, dict):
        return cur, ["неверный формат настроек"]
    new, errs = copy.deepcopy(cur), []
    if "enabled" in patch:
        new["enabled"] = bool(patch["enabled"])
    if "apps" in patch:
        if not isinstance(patch["apps"], list):
            errs.append("список приложений должен быть списком")
        else:
            apps = {}
            for a in patch["apps"][:50]:
                n, e = clean_proc_name(a)
                if not e and is_protected(n):
                    e = "«%s» - системная программа, блокировать её нельзя" % n
                if e:
                    errs.append(e)
                else:
                    apps.setdefault(n.lower(), n)
            new["apps"] = list(apps.values())
    v = patch.get("vpn", {})
    if not isinstance(v, dict):
        errs.append("неверный формат настроек VPN")
    else:
        if "check" in v:
            new["vpn"]["check"] = bool(v["check"])
        if "process" in v:
            n, e = clean_proc_name(v["process"], allow_empty=True)
            errs.append(e) if e else new["vpn"].update(process=n)
        if "mode" in v:
            errs.append("неизвестный режим определения VPN") if v["mode"] not in MODES else new["vpn"].update(mode=v["mode"])
    l = patch.get("limits", {})
    if not isinstance(l, dict):
        errs.append("неверный формат лимитов")
    else:
        for key, cast in (("interval", float), ("retries", int), ("retry_delay_ms", int), ("net_timeout_ms", int)):
            if key in l:
                try:
                    lo, hi = BOUNDS[key]
                    new["limits"][key] = max(lo, min(hi, cast(l[key])))
                except (TypeError, ValueError):
                    errs.append("лимит «%s» должен быть числом" % key)
        if "check_internet" in l:
            new["limits"]["check_internet"] = bool(l["check_internet"])
        if "hosts" in l:
            if not isinstance(l["hosts"], list) or len(l["hosts"]) > 6:
                errs.append("адресов для проверки интернета должно быть не больше 6")
            else:
                hosts = []
                for h in l["hosts"]:
                    try:
                        parse_target(h)
                        hosts.append(str(h).strip())
                    except ValueError as ex:
                        errs.append(str(ex))
                if not hosts and not errs:
                    errs.append("нужен хотя бы один адрес для проверки интернета")
                new["limits"]["hosts"] = hosts
    if new["vpn"]["mode"] == "process" and not new["vpn"]["process"]:
        errs.append("для режима «только процесс» укажи программу VPN")
    errs += ["«%s» нельзя блокировать: это сам VPN-клиент (иначе он не сможет переподключиться)" % a
             for a in new["apps"] if vpn_conflict(a, new["vpn"]["process"])]
    return (cur, errs) if errs else (new, [])


# ============================================================ хранилище ====

def config_dir():
    override = os.environ.get("VPN_GUARD_HOME")
    if override:
        return override
    if IS_WIN:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif IS_MAC:
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, APP_NAME)


def _private_write(path, data: bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    if not IS_WIN:
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class Store:
    def __init__(self, directory=None):
        self.dir = directory or config_dir()
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "config.json")
        self.lock = threading.Lock()
        self.version = 0
        self.first_run = not os.path.exists(self.path)
        self.cfg = self._load()
        self.token = self._token()

    def _load(self):
        cfg = copy.deepcopy(DEFAULTS)
        if self.first_run:
            return cfg
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            new, errs = sanitize(loaded, cfg)
            if errs:
                print("Предупреждение: в config.json есть ошибки, использую значения по умолчанию:", "; ".join(errs))
                try:
                    os.replace(self.path, self.path + ".bad")
                except OSError:
                    pass
                self.first_run = True
                return cfg
            return new
        except (OSError, ValueError):
            self.first_run = True
            return cfg

    def _token(self):
        p = os.path.join(self.dir, "token")
        try:
            with open(p, "r", encoding="ascii") as f:
                t = f.read().strip()
            if len(t) >= 20:
                return t
        except OSError:
            pass
        t = secrets.token_urlsafe(24)
        _private_write(p, t.encode("ascii"))
        return t

    def get(self):
        with self.lock:
            return copy.deepcopy(self.cfg)

    def update(self, patch):
        with self.lock:
            new, errs = sanitize(patch, self.cfg)
            if errs:
                return False, errs
            if new != self.cfg:
                self.cfg = new
                self.version += 1
                self.first_run = False
                _private_write(self.path, json.dumps(new, ensure_ascii=False, indent=2).encode("utf-8"))
            return True, []


# ====================================================== системный слой =====

def run_cmd(cmd, timeout=6):
    kw = {}
    if IS_WIN:
        kw["creationflags"] = 0x08000000      # без мигающего окна консоли
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout, **kw)
        return r.stdout.decode("oem" if IS_WIN else "utf-8", errors="replace")
    except Exception:
        return ""


def parse_tasklist(text):
    out = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2:
            continue
        try:
            pid = int(row[1])
        except ValueError:
            continue
        out.append({"pid": pid, "name": re.sub(r"\.exe$", "", row[0].strip(), flags=re.I), "bundle": ""})
    return out


def parse_ps(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(.+?)\s*$", line)
        if not m:
            continue
        path = m.group(2)
        b = re.search(r"/([^/]+)\.app(?:/|$)", path)
        out.append({"pid": int(m.group(1)), "name": os.path.basename(path), "bundle": b.group(1) if b else ""})
    return out


def list_processes():
    if IS_WIN:
        return parse_tasklist(run_cmd(["tasklist", "/FO", "CSV", "/NH"]))
    return parse_ps(run_cmd(["ps", "-axo", "pid=,comm="]))


def find_vpn_processes(keyword, procs=None):
    kw = keyword.lower()
    if not kw:
        return []
    return [p for p in (procs if procs is not None else list_processes())
            if kw in p["name"].lower() or kw in (p["bundle"] or "").lower()]


def match_apps(procs, names, vpn_keyword="", skip_pids=()):
    """Какие процессы из списка надо закрыть."""
    want = {n.lower() for n in names}
    vk = vpn_keyword.lower()
    res = []
    for p in procs:
        if p["pid"] in skip_pids or is_protected(p["name"]):
            continue
        n, b = p["name"].lower(), (p["bundle"] or "").lower()
        if n not in want and b not in want:
            continue
        if vk and (vk in n or vk in b):
            continue                      # сам VPN-клиент не трогаем
        res.append(p)
    return res


def _kill_pid(pid):
    try:
        if IS_WIN:
            r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=8, creationflags=0x08000000)
            return r.returncode == 0
        os.kill(pid, signal.SIGKILL)
        return True
    except Exception:
        return False


LAST_FAILED = []      # что не удалось закрыть при последнем вызове kill_apps


def kill_apps(names, vpn_keyword=""):
    """Закрывает приложения. -> список закрытых имён."""
    me = {os.getpid(), os.getppid()}
    global LAST_FAILED
    killed, tried = [], match_apps(list_processes(), names, vpn_keyword, me)
    for p in tried:
        if _kill_pid(p["pid"]):
            killed.append(p["bundle"] or p["name"])
    alive = {p["pid"] for p in list_processes()} if tried else set()
    LAST_FAILED = sorted({p["bundle"] or p["name"] for p in tried if p["pid"] in alive})
    return sorted(set(killed) - set(LAST_FAILED))


# ---- проверка интернета -----------------------------------------------------

def _tcp_ok(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def check_internet(hosts, timeout_ms):
    """True, если хоть один адрес ответил. Проверки идут параллельно, ждём не дольше таймаута."""
    targets = []
    for h in hosts:
        try:
            targets.append(parse_target(h))
        except ValueError:
            pass
    if not targets:
        return True
    t = timeout_ms / 1000.0
    q = queue.Queue()
    for h, p in targets:
        threading.Thread(target=lambda h=h, p=p: q.put(_tcp_ok(h, p, t)), daemon=True).start()
    deadline = time.monotonic() + t + 0.4
    for _ in targets:
        left = deadline - time.monotonic()
        if left <= 0:
            return False
        try:
            if q.get(timeout=left):
                return True
        except queue.Empty:
            return False
    return False


# ---- признаки VPN -------------------------------------------------------------

_cache = {}


def cached(key, ttl, fn):
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = fn()
    _cache[key] = (now, val)
    return val


def win_proxy_enabled():
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        v, _ = winreg.QueryValueEx(k, "ProxyEnable")
        return int(v) == 1
    except Exception:
        return False


WIN_VPN_RE = re.compile(
    r"\btap\b|tap-windows|wintun|wireguard|\btun\b|vpn|openvpn|nordlynx|mullvad|"
    r"windscribe|happ|hiddify|outline|l2tp|pptp|sstp|ikev2|cloudflare warp|amnezia|sing-box|xray", re.I)


def win_tunnel_parse(text):
    return any(WIN_VPN_RE.search(l) for l in text.splitlines())


def win_tunnel():
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
           "Get-NetAdapter | Where-Object Status -eq 'Up' | "
           "ForEach-Object { $_.Name + '|' + $_.InterfaceDescription }"]
    return win_tunnel_parse(cached("wintun", 2.0, lambda: run_cmd(cmd, timeout=8)))


_MAC_PROXY_RE = re.compile(r"^\s*(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable)\s*:\s*1\s*$", re.M)
_TUN_RE = re.compile(r"^(utun|ppp|ipsec|tun|tap)\d+$")


def mac_proxy_parse(text):
    return bool(_MAC_PROXY_RE.search(text))


def mac_tunnel_parse(netstat_text, nc_text=""):
    for line in netstat_text.splitlines():
        parts = line.split()
        if parts and parts[0] in ("default", "0/1", "128.0/1", "0.0.0.0/1", "128.0.0.0/1"):
            if any(_TUN_RE.match(p) for p in parts[1:]):
                return True
    return any("(Connected)" in l for l in nc_text.splitlines())


def linux_tunnel_parse(text):
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] in ("default", "0.0.0.0/1", "128.0.0.0/1") and "dev" in parts:
            dev = parts[parts.index("dev") + 1] if parts.index("dev") + 1 < len(parts) else ""
            if re.match(r"^(tun|tap|wg|ppp|utun)\d*$", dev):
                return True
    return False


def sig_proxy():
    if IS_WIN:
        return win_proxy_enabled()
    if IS_MAC:
        return mac_proxy_parse(run_cmd(["scutil", "--proxy"]))
    return False


def sig_tunnel():
    if IS_WIN:
        return win_tunnel()
    if IS_MAC:
        return mac_tunnel_parse(run_cmd(["netstat", "-rn", "-f", "inet"]), run_cmd(["scutil", "--nc", "list"]))
    return linux_tunnel_parse(run_cmd(["ip", "-4", "route"]))


# =============================================================== журнал =====

EVENTS = collections.deque(maxlen=50)
_ev_lock = threading.Lock()


def log(level, msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    with _ev_lock:
        EVENTS.append({"t": time.strftime("%H:%M:%S"), "lvl": level, "msg": msg})
    try:
        print(line, flush=True)
    except Exception:
        pass


def recent_events(n=40):
    with _ev_lock:
        return list(EVENTS)[-n:]


# =============================================================== монитор ====

class Monitor(threading.Thread):
    def __init__(self, store):
        super().__init__(daemon=True)
        self.store = store
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.was = None                  # было ли «всё в порядке» на прошлом тике
        self.calibrated = None           # "proxy" | "tunnel" - запомненный признак VPN
        self._vpn_sig = None             # (process, mode) - сброс калибровки при смене настроек
        self.state = {"status": "starting", "reason": "", "vpn": None, "net": None,
                      "mode": None, "since": time.time(), "last_kill": ""}

    # ---- чтение состояния ----
    def snapshot(self):
        with self.lock:
            return dict(self.state)

    def _set(self, **kw):
        with self.lock:
            if "status" in kw and kw["status"] != self.state["status"]:
                self.state["since"] = time.time()
            self.state.update(kw)

    # ---- VPN ----
    def vpn_ok(self, cfg):
        v = cfg["vpn"]
        sig = (v["process"], v["mode"])
        if sig != self._vpn_sig:
            self._vpn_sig = sig
            self.calibrated = None
        if not v["check"]:
            return True, ""
        if v["process"]:
            if not find_vpn_processes(v["process"]):
                self.calibrated = None
                return False, "программа VPN (%s) не запущена" % v["process"]
            if v["mode"] == "process":
                return True, ""
        mode = v["mode"]
        if mode == "auto":
            if self.calibrated is None:
                if sig_tunnel():
                    self.calibrated = "tunnel"
                elif sig_proxy():
                    self.calibrated = "proxy"
                else:
                    return False, "VPN не подключён"
                log("info", "VPN обнаружен, признак: %s" % ("туннель" if self.calibrated == "tunnel" else "системный прокси"))
            mode = self.calibrated
        self._set(mode=mode)
        ok = sig_proxy() if mode == "proxy" else sig_tunnel()
        return (True, "") if ok else (False, "VPN отключён")

    def protected(self, cfg):
        ok, why = self.vpn_ok(cfg)
        self._set(vpn=ok)
        if not ok:
            self._set(net=None)
            return False, why
        lim = cfg["limits"]
        if lim["check_internet"]:
            net = check_internet(lim["hosts"], lim["net_timeout_ms"])
            self._set(net=net)
            if not net:
                return False, "пропал интернет"
        else:
            self._set(net=None)
        return True, ""

    # ---- один тик ----
    def tick(self, cfg):
        if not cfg["enabled"]:
            self.was = None
            ok, why = self.protected(cfg)       # только для индикаторов
            self._set(status="paused", reason="")
            return
        lim = cfg["limits"]
        now, why = self.protected(cfg)
        if not now and self.was:
            # связь пропала - не закрываем сразу: быстро перепроверяем
            for _ in range(lim["retries"]):
                if self.stop_event.wait(lim["retry_delay_ms"] / 1000.0):
                    return
                now, why = self.protected(cfg)
                if now:
                    log("warn", "короткий сбой связи, всё восстановилось - приложения не тронуты")
                    break
        if self.was is None:
            log("info" if now else "warn",
                "защита включена: " + ("VPN и интернет активны" if now else "%s - приложения заблокированы" % why))
        elif self.was and not now:
            log("bad", "%s - приложения заблокированы" % why)
        elif (not self.was) and now:
            log("ok", "VPN и интернет в норме - приложения разблокированы")
        if not now:
            killed = kill_apps(cfg["apps"], cfg["vpn"]["process"])
            if killed:
                log("bad", "закрыто: %s" % ", ".join(killed))
                self._set(last_kill=time.strftime("%H:%M:%S") + " " + ", ".join(killed))
            if LAST_FAILED:
                log("warn", "НЕ удалось закрыть: %s (запусти VPN Guard от администратора)" % ", ".join(LAST_FAILED))
        self.was = now
        self._set(status="ok" if now else "blocked", reason="" if now else why)

    def run(self):
        while not self.stop_event.is_set():
            t0 = time.monotonic()
            cfg = self.store.get()
            try:
                self.tick(cfg)
            except Exception as ex:                     # мониторинг не должен падать
                log("warn", "ошибка проверки: %s" % ex)
            rest = cfg["limits"]["interval"] - (time.monotonic() - t0)
            self.stop_event.wait(max(0.05, rest))

    def recalibrate(self):
        self.calibrated = None


# ========================================================== автозапуск ======

def _script_path():
    return os.path.abspath(__file__)


def autostart_target():
    """-> (путь_файла, содержимое_bytes) для текущей ОС."""
    exe, script = sys.executable, _script_path()
    frozen = getattr(sys, "frozen", False)        # собранное приложение (PyInstaller)
    if IS_WIN:
        pw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        runner = pw if os.path.exists(pw) and not frozen else exe
        folder = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                              "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        body = '@echo off\r\nchcp 65001 >nul\r\nstart "" /min "%s" %s--no-browser\r\n' % (runner, "" if frozen else '"%s" ' % script)
        return os.path.join(folder, "vpn-guard.bat"), body.encode("utf-8")
    if IS_MAC:
        logp = os.path.join(config_dir(), "launchd.log")
        plist = {
            "Label": "com.vpnguard.agent",
            "ProgramArguments": [exe] + ([] if frozen else [script]) + ["--no-browser"],
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "StandardOutPath": logp,
            "StandardErrorPath": logp,
        }
        return (os.path.expanduser("~/Library/LaunchAgents/com.vpnguard.agent.plist"),
                plistlib.dumps(plist))
    folder = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "autostart")
    body = "[Desktop Entry]\nType=Application\nName=VPN Guard\nExec=\"%s\" %s--no-browser\n" % (exe, "" if frozen else '"%s" ' % script)
    return os.path.join(folder, "vpn-guard.desktop"), body.encode("utf-8")


def autostart_enabled():
    return os.path.exists(autostart_target()[0])


def autostart_set(on):
    path, body = autostart_target()
    if on:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(body)
    elif os.path.exists(path):
        os.remove(path)
    return autostart_enabled()


# ============================================================ диагностика ===

def diagnose_text(store=None):
    cfg = (store.get() if store else None) or DEFAULTS
    lines = ["VPN Guard %s" % VERSION,
             "Система: %s | Python %s" % (platform.platform(), platform.python_version()),
             "Конфиг: %s" % (store.path if store else config_dir()), ""]
    procs = list_processes()
    lines.append("Процессов найдено: %d" % len(procs))
    vp = cfg["vpn"]["process"]
    if vp:
        found = find_vpn_processes(vp, procs)
        lines.append("Программа VPN «%s»: %s" % (vp, ", ".join(sorted({p["name"] for p in found})) or "НЕ НАЙДЕНА"))
    lines.append("")
    lines.append("Признаки VPN:")
    lines.append("  системный прокси: %s" % ("ДА" if sig_proxy() else "нет"))
    lines.append("  туннель/адаптер:  %s" % ("ДА" if sig_tunnel() else "нет"))
    lines.append("")
    lim = cfg["limits"]
    t0 = time.monotonic()
    net = check_internet(lim["hosts"], lim["net_timeout_ms"])
    lines.append("Интернет (%s): %s, %.0f мс" % (", ".join(lim["hosts"]), "ЕСТЬ" if net else "НЕТ",
                                                 (time.monotonic() - t0) * 1000))
    lines.append("")
    lines.append("Что будет закрыто без VPN: %s" % (
        ", ".join(sorted({p["bundle"] or p["name"] for p in match_apps(procs, cfg["apps"], vp, {os.getpid()})}))
        or "(сейчас ничего из списка не запущено)"))
    lines.append("")
    if IS_MAC:
        lines += ["--- scutil --proxy ---", run_cmd(["scutil", "--proxy"]).strip()[:1500],
                  "--- netstat -rn -f inet (начало) ---", "\n".join(run_cmd(["netstat", "-rn", "-f", "inet"]).splitlines()[:14]),
                  "--- scutil --nc list ---", run_cmd(["scutil", "--nc", "list"]).strip()[:600]]
    elif IS_WIN:
        lines += ["--- адаптеры (Up) ---", cached("wintun", 0, lambda: run_cmd(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { $_.Name + '|' + $_.InterfaceDescription }"], 8)).strip()]
    return "\n".join(lines)


# ================================================ интерфейс (HTML) ===

HTML = r'''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Guard</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--text:#1b2230;--muted:#667085;--line:#e3e7ee;--ok:#117a56;--okbg:#e3f5ed;--bad:#b4232a;--badbg:#fdeaea;--warn:#9a5b00;--warnbg:#fff3dc;--accent:#2457d6;--accbg:#e8efff;--field:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#0e1117;--card:#161b24;--text:#e7eaf0;--muted:#9aa4b5;--line:#272e3b;--ok:#47d9a0;--okbg:#0f2a20;--bad:#ff7b7b;--badbg:#2e1316;--warn:#f5b73b;--warnbg:#2a2110;--accent:#7aa5ff;--accbg:#1a2542;--field:#0f141c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:940px;margin:0 auto;padding:0 16px 40px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 0 12px}
.brand{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:650;letter-spacing:-.01em}
.brand svg{width:26px;height:26px;color:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:14px}
.card h2{font-size:15px;margin:0 0 12px;font-weight:650}
.card h2 small{font-weight:400;color:var(--muted);margin-left:6px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid .card{margin:0}
.wide{grid-column:1/-1}
@media (max-width:760px){.grid{grid-template-columns:1fr}}
.pill{display:flex;align-items:center;gap:14px;padding:22px 20px;border-radius:14px;font-weight:650;font-size:19px}
.pill .dot{width:16px;height:16px;border-radius:50%;flex:none;background:currentColor}
.pill.ok{background:var(--okbg);color:var(--ok)} .pill.bad{background:var(--badbg);color:var(--bad)}
.pill.off{background:var(--line);color:var(--muted)} .pill.wait{background:var(--warnbg);color:var(--warn)}
.sub{color:var(--muted);margin:8px 2px 0;font-size:13.5px}
.note{background:var(--warnbg);color:var(--warn);border-radius:10px;padding:10px 12px;margin-top:10px;font-size:13.5px}
label.f{display:block;font-size:13px;color:var(--muted);margin:10px 0 4px}
input[type=text],input[type=number],select,textarea{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:9px;background:var(--field);color:var(--text);font:inherit}
input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:-1px}
textarea{min-height:64px;resize:vertical;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.row>*{flex:1 1 auto}.row .fix{flex:none}
.btn{border:1px solid var(--line);background:var(--card);color:var(--text);padding:8px 12px;border-radius:9px;font:inherit;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.danger{color:var(--bad)}
.btn.small{padding:4px 9px;font-size:13px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}
.chip{display:inline-flex;align-items:center;gap:6px;background:var(--accbg);color:var(--accent);padding:4px 6px 4px 11px;border-radius:99px;font-size:13.5px}
.chip button{border:0;background:transparent;color:inherit;cursor:pointer;font-size:16px;line-height:1;padding:0 4px;border-radius:50%}
.chip.add{background:transparent;border:1px dashed var(--line);color:var(--muted);padding:4px 11px;cursor:pointer}
.chip.add:hover{color:var(--accent);border-color:var(--accent)}
.chip.add.done{opacity:.45;cursor:default}
.hint{color:var(--muted);font-size:12.5px;margin:4px 0 0}
.nums{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media (max-width:760px){.nums{grid-template-columns:1fr 1fr}}
.est{margin-top:12px;background:var(--accbg);color:var(--accent);padding:9px 12px;border-radius:10px;font-size:13.5px}
.picker{border:1px solid var(--line);border-radius:10px;padding:10px;margin-top:8px;max-height:210px;overflow:auto}
.log{font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace;max-height:190px;overflow:auto}
.log div{padding:1px 0}.log .t{color:var(--muted);margin-right:8px}
.log .bad{color:var(--bad)}.log .ok{color:var(--ok)}.log .warn{color:var(--warn)}
.switch{position:relative;display:inline-flex;align-items:center;gap:10px;cursor:pointer;user-select:none}
.switch input{position:absolute;opacity:0;width:0;height:0}
.slider{width:46px;height:26px;background:var(--line);border-radius:99px;position:relative;transition:.15s;flex:none}
.slider:after{content:"";position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:#fff;transition:.15s;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.switch input:checked+.slider{background:var(--ok)}
.switch input:checked+.slider:after{transform:translateX(20px)}
.switch input:focus-visible+.slider{outline:2px solid var(--accent);outline-offset:2px}
.switch.big{font-weight:600}
.toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);background:#1b2230;color:#fff;padding:9px 16px;border-radius:99px;font-size:14px;opacity:0;pointer-events:none;transition:.2s;max-width:90vw;z-index:9}
.toast.show{opacity:1}.toast.err{background:#b4232a}
pre#diag{white-space:pre-wrap;font-size:12px;background:var(--field);border:1px solid var(--line);border-radius:10px;padding:10px;max-height:300px;overflow:auto}
.mini{display:flex;gap:14px;flex-wrap:wrap;margin-top:8px;font-size:13px}
.mini span b{font-weight:600}
.av{display:inline-grid;place-items:center;width:20px;height:20px;border-radius:50%;background:var(--accent);color:#fff;font-size:11px;font-weight:700}
.chip{padding-left:5px;font-size:14.5px}
details.card>summary{cursor:pointer;font-weight:650;font-size:15px;list-style:none}
details.card>summary::before{content:"▸ ";color:var(--muted)}
details[open].card>summary::before{content:"▾ "}
details.card[open]>summary{margin-bottom:12px}
.stopped{text-align:center;padding:60px 10px}
</style>
</head>
<body>
<div class="wrap" id="app">
<header>
  <div class="brand">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>
    VPN Guard
  </div>
  <label class="switch big"><input type="checkbox" id="enabled"><span class="slider"></span><span id="enabledLabel">Защита выключена</span></label>
</header>

<section class="card">
  <div id="pill" class="pill wait"><span class="dot"></span><span id="pillText">Загрузка…</span></div>
  <div class="sub" id="statusSub"></div>
  <div class="note" id="firstRun" hidden>Первый запуск: защита выключена, чтобы случайно не закрыть нужные программы. Проверь настройки ниже и включи переключатель справа вверху.</div>
</section>

<div class="grid">
<section class="card">
  <h2>1. Какой VPN</h2>
  <label class="f" for="vpnPreset">Программа VPN</label>
  <select id="vpnPreset"></select>
  <label class="f" for="vpnProc">Имя программы (часть имени, регистр не важен)</label>
  <div class="row">
    <input type="text" id="vpnProc" placeholder="например: Happ" autocomplete="off" spellcheck="false">
    <button class="btn fix small" id="vpnPick" type="button">Из запущенных…</button>
  </div>
  <div class="picker" id="vpnPicker" hidden></div>
  <label class="f" for="vpnMode">Как понимать, что VPN подключён</label>
  <select id="vpnMode">
    <option value="auto">Автоматически (запомнить при подключении)</option>
    <option value="proxy">Системный прокси включён</option>
    <option value="tunnel">Есть VPN-туннель / адаптер</option>
    <option value="process">Достаточно, что программа запущена</option>
  </select>
  <div class="row" style="margin-top:10px">
    <button class="btn" id="calib" type="button">Определить по текущему подключению</button>
  </div>
  <div class="hint" id="calibMsg">Подключись к VPN и нажми кнопку, если автоопределение ошиблось.</div>
  <label class="switch" style="margin-top:12px"><input type="checkbox" id="vpnCheck"><span class="slider"></span><span>Проверять VPN</span></label>
</section>

<section class="card">
  <h2>2. Что блокировать <small>пока нет VPN</small></h2>
  <div class="chips" id="appChips"></div>
  <div class="row">
    <input type="text" id="appInput" placeholder="имя программы, Enter" autocomplete="off" spellcheck="false">
    <button class="btn fix primary small" id="appAdd" type="button">Добавить</button>
  </div>
  <div class="row" style="margin-top:8px">
    <button class="btn small" id="appPick" type="button">Выбрать из запущенных…</button>
  </div>
  <div class="picker" id="appPicker" hidden></div>
  <label class="f">Быстро добавить</label>
  <div class="chips" id="appPresets"></div>
  <div class="hint">Программа закрывается сразу, как только её откроют без VPN. Если заблокируешь браузер, в котором открыта эта страница, вкладка тоже закроется.</div>
</section>

<details class="card wide">
  <summary>3. Лимиты и скорость реакции <small style="font-weight:400;color:var(--muted)">- можно не трогать</small></summary>
  <div class="row" id="limitPresets" style="margin-bottom:6px"></div>
  <div class="nums">
    <div><label class="f" for="lInterval">Проверять каждые, сек</label><input type="number" id="lInterval" step="0.5" min="0.5" max="30"></div>
    <div><label class="f" for="lRetries">Перепроверок перед закрытием</label><input type="number" id="lRetries" step="1" min="0" max="20"></div>
    <div><label class="f" for="lDelay">Пауза между перепроверками, мс</label><input type="number" id="lDelay" step="50" min="50" max="5000"></div>
    <div><label class="f" for="lTimeout">Ждать ответ сети, мс</label><input type="number" id="lTimeout" step="100" min="200" max="5000"></div>
  </div>
  <div class="est" id="estimate"></div>
  <div class="row" style="margin-top:12px;align-items:flex-start">
    <div>
      <label class="switch"><input type="checkbox" id="lNet"><span class="slider"></span><span>Блокировать и при пропаже интернета</span></label>
      <label class="f" for="lHosts">Адреса для проверки интернета (по одному в строке, до 6)</label>
      <textarea id="lHosts" spellcheck="false"></textarea>
      <div class="hint">Проверка идёт по TCP-порту 443 (или host:порт). Достаточно ответа от любого адреса.</div>
    </div>
  </div>
</details>

<section class="card">
  <h2>Журнал</h2>
  <div class="log" id="log"></div>
</section>

<section class="card">
  <h2>Система</h2>
  <label class="switch"><input type="checkbox" id="autostart"><span class="slider"></span><span>Запускать при входе в систему</span></label>
  <div class="hint">Без запущенной программы защиты нет. Автозапуск стартует её в фоне.</div>
  <div class="row" style="margin-top:12px">
    <button class="btn small primary" id="testBtn" type="button">Проверить, работает ли защита</button>
    <button class="btn small" id="diagBtn" type="button">Диагностика</button>
    <button class="btn small danger" id="stopBtn" type="button">Остановить программу</button>
  </div>
  <div id="testRes" class="hint"></div>
  <pre id="diag" hidden></pre>
</section>
</div>
</div>
<div class="toast" id="toast"></div>

<script>
const T = "__TOKEN__";
const $ = (s) => document.querySelector(s);
let S = null, lastVer = -1, saveTimer = null, pending = false, apps = [], dead = false;

async function api(path, method, body) {
  const r = await fetch(path, {method: method || "GET", headers: {"X-Token": T, "Content-Type": "application/json"}, body: body ? JSON.stringify(body) : undefined});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((j.errors || [j.error || r.statusText]).join("; "));
  return j;
}
let toastT = null;
function toast(msg, err) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast show" + (err ? " err" : "");
  clearTimeout(toastT); toastT = setTimeout(() => t.className = "toast", err ? 4500 : 1400);
}
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

/* ---------- отрисовка ---------- */
function renderStatus() {
  const s = S.status, c = S.config, pill = $("#pill");
  $("#enabled").checked = c.enabled;
  $("#enabledLabel").textContent = c.enabled ? "Защита включена" : "Защита выключена";
  $("#firstRun").hidden = !(S.first_run && !c.enabled);
  let cls = "wait", text = "Проверяю…", sub = "";
  if (!c.enabled) { cls = "off"; text = "Защита выключена - приложения не блокируются"; }
  else if (s.status === "ok") { cls = "ok"; text = "Всё в порядке - приложения разрешены"; }
  else if (s.status === "blocked") { cls = "bad"; text = "Приложения заблокированы: " + s.reason; }
  pill.className = "pill " + cls; $("#pillText").textContent = text;
  const parts = [];
  if (c.vpn.check) parts.push("VPN: " + (s.vpn === true ? "есть" : s.vpn === false ? "нет" : "-"));
  if (c.limits.check_internet) parts.push("интернет: " + (s.net === true ? "есть" : s.net === false ? "нет" : "-"));
  if (s.mode) parts.push("признак: " + ({proxy: "системный прокси", tunnel: "туннель"}[s.mode] || s.mode));
  if (s.last_kill) parts.push("последнее закрытие: " + s.last_kill);
  $("#statusSub").textContent = parts.join("  ·  ");
  const lg = $("#log"); lg.textContent = "";
  if (!S.events.length) lg.append(el("div", "t", "Событий пока нет"));
  S.events.slice().reverse().forEach(e => { const d = el("div", e.lvl); d.append(el("span", "t", e.t), document.createTextNode(e.msg)); lg.append(d); });
  $("#autostart").checked = !!S.autostart;
}

function renderApps() {
  const box = $("#appChips"); box.textContent = "";
  if (!apps.length) box.append(el("span", "hint", "Список пуст - добавь программы ниже"));
  apps.forEach((a, i) => {
    const c = el("span", "chip"); c.append(el("span", "av", a[0].toUpperCase()), document.createTextNode(a)); const b = el("button", "", "×"); b.title = "Убрать"; b.type = "button";
    b.onclick = () => { apps.splice(i, 1); renderApps(); scheduleSave(); };
    c.append(b); box.append(c);
  });
  const pb = $("#appPresets"); pb.textContent = "";
  S.presets.apps.forEach(p => {
    const has = apps.some(a => a.toLowerCase() === p.process.toLowerCase());
    const c = el("span", "chip add" + (has ? " done" : ""), (has ? "✓ " : "+ ") + p.label);
    if (!has) c.onclick = () => { addApp(p.process); };
    pb.append(c);
  });
}

function fillConfig(c) {
  apps = c.apps.slice(); renderApps();
  $("#vpnProc").value = c.vpn.process; $("#vpnMode").value = c.vpn.mode; $("#vpnCheck").checked = c.vpn.check;
  const sel = $("#vpnPreset"); const m = S.presets.vpn.find(p => p.process.toLowerCase() === c.vpn.process.toLowerCase());
  sel.value = m ? m.process : (c.vpn.process ? "__custom" : "__none");
  const l = c.limits;
  $("#lInterval").value = l.interval; $("#lRetries").value = l.retries; $("#lDelay").value = l.retry_delay_ms; $("#lTimeout").value = l.net_timeout_ms;
  $("#lNet").checked = l.check_internet; $("#lHosts").value = l.hosts.join("\n");
  estimate(); lastVer = S.version;
}

function estimate() {
  const i = +$("#lInterval").value || 1, r = +$("#lRetries").value || 0, d = (+$("#lDelay").value || 0) / 1000, t = (+$("#lTimeout").value || 0) / 1000;
  const fast = r * d, slow = i + r * (d + t) + t;
  $("#estimate").textContent = "Приложения закроются примерно через " + fast.toFixed(1) + "-" + slow.toFixed(1) + " с после пропажи связи. Сбой короче " + fast.toFixed(1) + " с будет прощён.";
}

/* ---------- сохранение ---------- */
function collect() {
  return {
    apps: apps,
    vpn: {process: $("#vpnProc").value.trim(), mode: $("#vpnMode").value, check: $("#vpnCheck").checked},
    limits: {interval: +$("#lInterval").value, retries: +$("#lRetries").value, retry_delay_ms: +$("#lDelay").value,
             net_timeout_ms: +$("#lTimeout").value, check_internet: $("#lNet").checked,
             hosts: $("#lHosts").value.split(/[\s,;]+/).filter(Boolean)}
  };
}
function scheduleSave() { pending = true; estimate(); clearTimeout(saveTimer); saveTimer = setTimeout(save, 450); }
async function save() {
  try { const r = await api("/api/config", "POST", collect()); S.config = r.config; S.version = r.version; pending = false; fillConfig(r.config); renderStatus(); toast("Сохранено"); }
  catch (e) { pending = false; toast(e.message, true); await refresh(true); }
}
function addApp(name) {
  name = (name || "").trim(); if (!name) return;
  if (apps.some(a => a.toLowerCase() === name.toLowerCase())) { toast("Уже в списке"); return; }
  apps.push(name); renderApps(); scheduleSave();
}

/* ---------- выбор из запущенных ---------- */
async function openPicker(box, isVpn) {
  if (!box.hidden) { box.hidden = true; return; }
  box.hidden = false; box.textContent = "Загружаю список…";
  try {
    const names = (await api("/api/processes")).names;
    box.textContent = "";
    const f = el("input"); f.type = "text"; f.placeholder = "поиск"; f.style.marginBottom = "8px"; box.append(f);
    const list = el("div", "chips"); box.append(list);
    const draw = () => {
      list.textContent = ""; const q = f.value.toLowerCase(); let n = 0;
      for (const nm of names) {
        if (q && !nm.toLowerCase().includes(q)) continue; if (++n > 120) break;
        const used = !isVpn && apps.some(a => a.toLowerCase() === nm.toLowerCase());
        const c = el("span", "chip add" + (used ? " done" : ""), (used ? "✓ " : "+ ") + nm);
        if (!used) c.onclick = () => { if (isVpn) { $("#vpnProc").value = nm; box.hidden = true; $("#vpnPreset").value = "__custom"; scheduleSave(); } else addApp(nm); };
        list.append(c);
      }
      if (!n) list.append(el("span", "hint", "Ничего не найдено"));
    };
    f.oninput = draw; draw(); f.focus();
  } catch (e) { box.textContent = e.message; }
}

/* ---------- события ---------- */
function bind() {
  $("#enabled").onchange = async (e) => {
    try { const r = await api("/api/config", "POST", {enabled: e.target.checked}); S.config = r.config; renderStatus(); toast(r.config.enabled ? "Защита включена" : "Защита выключена"); }
    catch (x) { toast(x.message, true); e.target.checked = !e.target.checked; }
  };
  ["#vpnMode", "#vpnCheck", "#lInterval", "#lRetries", "#lDelay", "#lTimeout", "#lNet", "#lHosts", "#vpnProc"].forEach(s => $(s).addEventListener("input", scheduleSave));
  $("#vpnPreset").onchange = (e) => { const v = e.target.value; if (v === "__none") $("#vpnProc").value = ""; else if (v !== "__custom") $("#vpnProc").value = v; scheduleSave(); };
  $("#appAdd").onclick = () => { addApp($("#appInput").value); $("#appInput").value = ""; };
  $("#appInput").addEventListener("keydown", (e) => { if (e.key === "Enter") { addApp(e.target.value); e.target.value = ""; } });
  $("#appPick").onclick = () => openPicker($("#appPicker"), false);
  $("#vpnPick").onclick = () => openPicker($("#vpnPicker"), true);
  $("#calib").onclick = async () => {
    $("#calibMsg").textContent = "Проверяю…";
    try { const r = await api("/api/calibrate", "POST", {}); $("#calibMsg").textContent = r.message; if (r.config) { S.config = r.config; fillConfig(r.config); } }
    catch (e) { $("#calibMsg").textContent = e.message; }
  };
  $("#autostart").onchange = async (e) => {
    try { const r = await api("/api/autostart", "POST", {on: e.target.checked}); e.target.checked = r.on; toast(r.on ? "Автозапуск включён" : "Автозапуск выключен"); }
    catch (x) { toast(x.message, true); e.target.checked = !e.target.checked; }
  };
  $("#testBtn").onclick = async () => {
    const b = $("#testRes"); b.textContent = "Проверяю…";
    try {
      const cs = (await api("/api/selftest", "POST", {})).checks; b.textContent = "";
      cs.forEach(c => { const d = el("div", c.ok ? "ok" : "bad", (c.ok ? "✓ " : "✗ ") + c.title + (c.detail ? " - " + c.detail : "")); d.style.color = c.ok ? "var(--ok)" : "var(--bad)"; b.append(d); });
    } catch (e) { b.textContent = e.message; }
  };
  $("#diagBtn").onclick = async () => {
    const p = $("#diag"); if (!p.hidden) { p.hidden = true; return; }
    p.hidden = false; p.textContent = "Собираю данные…";
    try { p.textContent = (await api("/api/diagnose")).text; } catch (e) { p.textContent = e.message; }
  };
  $("#stopBtn").onclick = async () => {
    if (!confirm("Остановить VPN Guard? Приложения перестанут блокироваться.")) return;
    try { await api("/api/shutdown", "POST", {}); } catch (e) {}
    stopped();
  };
  const lp = $("#limitPresets");
  S.presets.limits.forEach(p => {
    const b = el("button", "btn", p.label); b.type = "button";
    b.onclick = () => { $("#lInterval").value = p.interval; $("#lRetries").value = p.retries; $("#lDelay").value = p.retry_delay_ms; $("#lTimeout").value = p.net_timeout_ms; scheduleSave(); };
    lp.append(b);
  });
  const sel = $("#vpnPreset"); sel.textContent = "";
  const add = (v, t) => { const o = el("option", "", t); o.value = v; sel.append(o); };
  add("__none", "Не привязывать к программе (только по сети)");
  S.presets.vpn.forEach(p => add(p.process, p.label));
  add("__custom", "Другая (впиши имя справа)");
}
function stopped() {
  dead = true; $("#app").textContent = "";
  const d = el("div", "stopped"); d.append(el("h2", "", "Программа остановлена"), el("p", "hint", "Приложения больше не блокируются. Можно закрыть вкладку."));
  $("#app").append(d);
}

/* ---------- опрос ---------- */
async function refresh(force) {
  if (dead) return;
  try {
    const first = S === null;
    S = await api("/api/state");
    if (first) { bind(); }
    if (first || force || (S.version !== lastVer && !pending && !document.activeElement.matches("input[type=text],input[type=number],textarea"))) fillConfig(S.config);
    renderStatus();
  } catch (e) {
    if (S) { $("#pillText").textContent = "Нет связи с программой (она закрыта?)"; $("#pill").className = "pill bad"; }
    else document.body.textContent = "Не удалось подключиться: " + e.message;
  }
}
refresh(); setInterval(refresh, 1000);
</script>
</body>
</html>
'''


# ====================================================== панель и API ========

VPN_PRESETS = [
    ("Happ", "Happ"), ("WireGuard", "WireGuard"), ("OpenVPN", "OpenVPN"), ("NordVPN", "Nord"),
    ("Proton VPN", "Proton"), ("Mullvad", "Mullvad"), ("ExpressVPN", "Express"), ("Surfshark", "Surfshark"),
    ("Windscribe", "Windscribe"), ("Cloudflare WARP", "Warp"), ("Outline", "Outline"), ("Hiddify", "Hiddify"),
    ("v2rayN / v2rayU", "v2ray"), ("Clash / Mihomo", "Clash"), ("Amnezia", "Amnezia"), ("Tunnelblick", "Tunnelblick"),
]

_APPS_WIN = [("Telegram", "Telegram"), ("Discord", "Discord"), ("WhatsApp", "WhatsApp"), ("Signal", "Signal"),
             ("Slack", "slack"), ("Zoom", "Zoom"), ("Claude", "Claude"), ("Steam", "steam"),
             ("qBittorrent", "qbittorrent"), ("Chrome", "chrome"), ("Firefox", "firefox"), ("Edge", "msedge"),
             ("Opera", "opera"), ("Brave", "brave")]
_APPS_MAC = [("Telegram", "Telegram"), ("Discord", "Discord"), ("WhatsApp", "WhatsApp"), ("Signal", "Signal"),
             ("Slack", "Slack"), ("Zoom", "zoom.us"), ("Claude", "Claude"), ("Steam", "Steam"),
             ("qBittorrent", "qBittorrent"), ("Chrome", "Google Chrome"), ("Firefox", "Firefox"),
             ("Safari", "Safari"), ("Edge", "Microsoft Edge"), ("Brave", "Brave Browser")]


def presets():
    return {
        "limits": [dict(v, key=k) for k, v in LIMIT_PRESETS.items()],
        "vpn": [{"label": a, "process": b} for a, b in VPN_PRESETS],
        "apps": [{"label": a, "process": b} for a, b in (_APPS_MAC if IS_MAC else _APPS_WIN)],
    }


def process_names(show_all=False):
    names = {}
    for p in list_processes():
        if is_protected(p["name"]) or p["pid"] == os.getpid():
            continue
        if IS_MAC and not show_all:
            if not p["bundle"]:
                continue
            n = p["bundle"]
        else:
            n = p["name"]
        names[n.lower()] = n
    return sorted(names.values(), key=str.lower)


class Ctx:
    store = None
    monitor = None
    port = DEFAULT_PORT
    server = None
    html = ""


def state_payload(ctx):
    return {
        "version": ctx.store.version,
        "first_run": ctx.store.first_run,
        "config": ctx.store.get(),
        "status": ctx.monitor.snapshot(),
        "events": recent_events(30),
        "autostart": autostart_enabled(),
        "presets": presets(),
        "os": "mac" if IS_MAC else "win" if IS_WIN else "other",
    }


def calibrate(ctx):
    cfg = ctx.store.get()
    proc = cfg["vpn"]["process"]
    found = bool(find_vpn_processes(proc)) if proc else None
    sig = {"process": found, "proxy": sig_proxy(), "tunnel": sig_tunnel()}
    if proc and not found:
        return {"signals": sig, "message": "Программа «%s» не запущена. Запусти VPN, подключись и нажми снова." % proc}
    chosen = "tunnel" if sig["tunnel"] else "proxy" if sig["proxy"] else None
    if not chosen:
        return {"signals": sig, "message": "Признаков подключённого VPN нет (ни прокси, ни туннеля). Подключись к VPN и нажми снова."}
    ok, errs = ctx.store.update({"vpn": {"mode": chosen}})
    ctx.monitor.recalibrate()
    label = "VPN-туннель" if chosen == "tunnel" else "системный прокси"
    return {"signals": sig, "config": ctx.store.get(),
            "message": "Найден признак: %s. Режим установлен." % label}


def selftest(ctx):
    """Проверка «работает ли защита»: [{ok, title, detail}]. Ничего не закрывает."""
    cfg, out = ctx.store.get(), []
    add = lambda ok, t, d="": out.append({"ok": ok, "title": t, "detail": d})
    procs = list_processes()
    add(len(procs) > 5, "Список процессов читается", "найдено: %d" % len(procs))
    vp = cfg["vpn"]["process"]
    if vp:
        f = find_vpn_processes(vp, procs)
        add(bool(f), "Программа VPN «%s» запущена" % vp, ", ".join(sorted({p["name"] for p in f})) or "не найдена - запусти её")
    px, tn = sig_proxy(), sig_tunnel()
    add(px or tn, "VPN подключён (признак найден)", "прокси: %s, туннель: %s" % ("да" if px else "нет", "да" if tn else "нет"))
    lim = cfg["limits"]
    add(check_internet(lim["hosts"], lim["net_timeout_ms"]), "Интернет отвечает", ", ".join(lim["hosts"]))
    hit = match_apps(procs, cfg["apps"], vp, {os.getpid()})
    names = ", ".join(sorted({p["bundle"] or p["name"] for p in hit}))
    add(True, "Без VPN будет закрыто: " + (names or "ничего (сейчас эти программы не запущены)"), "реально ничего не закрывалось")
    add(bool(cfg["enabled"]), "Защита включена", "" if cfg["enabled"] else "включи переключатель сверху")
    add(ctx.monitor.is_alive(), "Монитор работает")
    return out


def make_handler(ctx):
    class Handler(BaseHTTPRequestHandler):
        server_version = "VPNGuard/" + VERSION

        def log_message(self, *a):
            pass

        # ---- вспомогательное ----
        def _origins(self):
            return {"http://127.0.0.1:%d" % ctx.port, "http://localhost:%d" % ctx.port}

        def _host_ok(self):
            h = (self.headers.get("Host") or "").lower()
            return h in ("127.0.0.1:%d" % ctx.port, "localhost:%d" % ctx.port)

        def _token_ok(self, query=None):
            t = self.headers.get("X-Token") or ((query or {}).get("t") or [""])[0]
            return bool(t) and secrets.compare_digest(t, ctx.store.token)

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "connect-src 'self'; img-src data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, ensure_ascii=False))

        # ---- GET ----
        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if not self._host_ok():
                return self._json(403, {"error": "forbidden host"})
            if u.path == "/api/ping":
                return self._json(200, {"app": APP_NAME, "version": VERSION})
            if u.path == "/":
                if not self._token_ok(q):
                    return self._send(403, "Открой ссылку, которую показала программа в окне (в ней есть секретный ключ).",
                                      "text/plain; charset=utf-8")
                return self._send(200, ctx.html.replace("__TOKEN__", ctx.store.token), "text/html; charset=utf-8")
            if not self._token_ok():
                return self._json(403, {"error": "нет доступа"})
            if u.path == "/api/state":
                return self._json(200, state_payload(ctx))
            if u.path == "/api/processes":
                return self._json(200, {"names": process_names("all" in q)})
            if u.path == "/api/diagnose":
                return self._json(200, {"text": diagnose_text(ctx.store)})
            return self._json(404, {"error": "не найдено"})

        # ---- POST ----
        def do_POST(self):
            u = urlparse(self.path)
            if not self._host_ok():
                return self._json(403, {"error": "forbidden host"})
            origin = self.headers.get("Origin")
            if origin and origin not in self._origins():
                return self._json(403, {"error": "forbidden origin"})
            if not self._token_ok():
                return self._json(403, {"error": "нет доступа"})
            if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                return self._json(415, {"error": "нужен application/json"})
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if n > 65536:
                    return self._json(413, {"error": "слишком большой запрос"})
                body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                return self._json(400, {"error": "неверный JSON"})

            if u.path == "/api/config":
                ok, errs = ctx.store.update(body)
                if not ok:
                    return self._json(400, {"errors": errs})
                return self._json(200, {"ok": True, "config": ctx.store.get(), "version": ctx.store.version})
            if u.path == "/api/calibrate":
                return self._json(200, calibrate(ctx))
            if u.path == "/api/selftest":
                return self._json(200, {"checks": selftest(ctx)})
            if u.path == "/api/autostart":
                try:
                    return self._json(200, {"on": autostart_set(bool(body.get("on")))})
                except OSError as ex:
                    return self._json(500, {"error": "не удалось изменить автозапуск: %s" % ex})
            if u.path == "/api/shutdown":
                self._json(200, {"ok": True})
                log("info", "остановлено из панели")
                threading.Thread(target=ctx.server.shutdown, daemon=True).start()
                return
            return self._json(404, {"error": "не найдено"})

    return Handler


# ================================================================ запуск ====

def open_panel(url):
    """Открывает панель как отдельное окно-приложение (Chrome/Edge --app), иначе в браузере."""
    cands = []
    if IS_WIN:
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            b = os.environ.get(env, "")
            cands += [os.path.join(b, r"Microsoft\Edge\Application\msedge.exe"),
                      os.path.join(b, r"Google\Chrome\Application\chrome.exe")]
    elif IS_MAC:
        cands = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                 "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                 "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"]
    for c in cands:
        if os.path.exists(c):
            try:
                prof = os.path.join(config_dir(), "window")
                subprocess.Popen([c, "--app=" + url, "--user-data-dir=" + prof, "--window-size=980,860", "--no-first-run"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except OSError:
                pass
    webbrowser.open(url)


def _ping_existing(port):
    import urllib.request
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:%d/api/ping" % port, timeout=0.6) as r:
            return json.loads(r.read().decode("utf-8")).get("app") == APP_NAME
    except Exception:
        return False


def main(argv=None):
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:                  # приложение без консоли
            setattr(sys, name, open(os.devnull, "w"))
        else:
            try:
                getattr(sys, name).reconfigure(encoding="utf-8", errors="replace")   # русский в консоли Windows
            except (AttributeError, ValueError):
                pass
    ap = argparse.ArgumentParser(description="VPN Guard: блокирует выбранные приложения без VPN")
    ap.add_argument("--no-browser", action="store_true", help="не открывать панель в браузере")
    ap.add_argument("--diagnose", action="store_true", help="напечатать диагностику и выйти")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = ap.parse_args(argv)

    store = Store()
    if args.diagnose:
        print(diagnose_text(store))
        return 0

    for p in range(args.port, args.port + 10):
        if _ping_existing(p):
            url = "http://127.0.0.1:%d/?t=%s" % (p, store.token)
            print("VPN Guard уже запущен. Открываю панель:", url)
            if not args.no_browser:
                open_panel(url)
            return 0

    ctx = Ctx()
    ctx.store = store
    ctx.html = HTML
    handler = make_handler(ctx)
    server = None
    for p in range(args.port, args.port + 10):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), handler)
            ctx.port = p
            break
        except OSError:
            continue
    if server is None:
        print("Не удалось занять порт %d-%d" % (args.port, args.port + 9))
        return 1
    ctx.server = server
    ctx.monitor = Monitor(store)
    ctx.monitor.start()
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, lambda *a: threading.Thread(target=server.shutdown, daemon=True).start())
        except ValueError:
            pass

    url = "http://127.0.0.1:%d/?t=%s" % (ctx.port, store.token)
    print("=" * 60)
    print("  VPN Guard запущен. Панель настроек:")
    print("  " + url)
    print("  Не закрывай это окно: пока оно открыто, защита работает.")
    print("  Остановить: Ctrl+C или кнопка в панели.")
    print("=" * 60)
    if not args.no_browser:
        threading.Timer(0.6, lambda: open_panel(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ctx.monitor.stop_event.set()
        server.server_close()
        print("\nVPN Guard остановлен. Приложения больше не блокируются.")
    return 0


def _crash(ex):
    """Без консоли ошибку не видно: пишем в crash.log и показываем окно."""
    import traceback
    text = traceback.format_exc()
    try:
        os.makedirs(config_dir(), exist_ok=True)
        with open(os.path.join(config_dir(), "crash.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + "\n" + text + "\n")
    except OSError:
        pass
    if IS_WIN:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, "VPN Guard не запустился:\n\n%s\n\nПодробности: %s" % (
                text.strip().splitlines()[-1], os.path.join(config_dir(), "crash.log")), "VPN Guard", 0x10)
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as _ex:
        _crash(_ex)
        sys.exit(1)
