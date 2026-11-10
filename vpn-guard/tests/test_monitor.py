import importlib.util, os, sys, tempfile, shutil, subprocess, time
spec = importlib.util.spec_from_file_location("vg", "/home/user/musical-carnival/vpn-guard/vpn_guard.py")
vg = importlib.util.module_from_spec(spec); spec.loader.exec_module(vg)
vg.print = lambda *a, **k: None   # тише

tmp = tempfile.mkdtemp()
for n in ("tgfake", "vpnfake"):
    shutil.copy("/bin/sleep", os.path.join(tmp, n))
F = {"proxy": False, "tunnel": False, "net": True}
vg.sig_proxy = lambda: F["proxy"]
vg.sig_tunnel = lambda: F["tunnel"]
vg.check_internet = lambda hosts, ms: F["net"]

procs = {}
def start(n):
    p = subprocess.Popen([os.path.join(tmp, n), "300"]); procs[n] = p; time.sleep(0.15); return p
def alive(p): return p.poll() is None
def wait_until(cond, timeout=6, step=0.05):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if cond(): return time.monotonic() - t0
        time.sleep(step)
    return None
def events(): return [e["msg"] for e in vg.recent_events(300)]

store = vg.Store(os.path.join(tmp, "cfg"))
mon = vg.Monitor(store); mon.start()
passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond: passed += 1; print("  PASS  " + name + (("   [" + extra + "]") if extra else ""))
    else: failed += 1; print("  FAIL  " + name + "   -> " + str(extra))

base = {"apps": ["tgfake"], "vpn": {"process": "vpnfake", "mode": "auto", "check": True},
        "limits": {"interval": 0.5, "retries": 3, "retry_delay_ms": 300, "net_timeout_ms": 800, "check_internet": True}}

print("S0. защита ВЫКЛЮЧЕНА: ничего не трогаем")
store.update(dict(base, enabled=False))
tg = start("tgfake"); time.sleep(2)
check("приложение живо, статус paused", alive(tg) and mon.snapshot()["status"] == "paused")

print("S1. включили без VPN: блокировка")
store.update({"enabled": True})
t = wait_until(lambda: not alive(tg), 4)
check("уже открытое приложение закрыто", t is not None, "%.2f с" % (t or 0))
check("причина в статусе", mon.snapshot()["status"] == "blocked" and "не запущена" in mon.snapshot()["reason"], mon.snapshot()["reason"])
tg = start("tgfake"); t = wait_until(lambda: not alive(tg), 3)
check("запуск при выключенном VPN: закрывается снова", t is not None and t < 1.2, "%.2f с" % (t or 0))

print("S2. VPN подключился (авто-калибровка)")
vpn = start("vpnfake"); F["proxy"] = True
t = wait_until(lambda: mon.snapshot()["status"] == "ok", 4)
check("статус ok, калибровка = proxy", t is not None and mon.calibrated == "proxy", "%.2f с" % (t or 0))
tg = start("tgfake"); time.sleep(3)
check("при VPN приложение живёт", alive(tg))

print("S3. сбои на доли секунды прощаются")
for i in range(6):
    time.sleep(0.35 + 0.1 * (i % 3)); F["proxy"] = False; time.sleep(0.4); F["proxy"] = True
time.sleep(1.5)
forg = sum(1 for m in events() if "короткий сбой" in m)
check("6 сбоев VPN по 0.4 с: приложение живо", alive(tg))
check("скрипт перепроверил и простил хотя бы часть", forg >= 1, "прощено %d из 6 (остальные не попали на проверку)" % forg)

print("S4. затяжной обрыв VPN")
F["proxy"] = False; t0 = time.monotonic()
t = wait_until(lambda: not alive(tg), 6)
check("приложение закрыто", t is not None, "%.2f с (окно прощения 0.9 с + интервал 0.5 с)" % (t or 0))
check("в журнале причина", any("VPN отключён" in m and "заблокированы" in m for m in events()))
tg = start("tgfake"); t = wait_until(lambda: not alive(tg), 3)
check("пока VPN нет, повторный запуск закрывается ≤1.2 с", t is not None and t < 1.2, "%.2f с" % (t or 0))
F["proxy"] = True
t = wait_until(lambda: mon.snapshot()["status"] == "ok", 4)
check("VPN вернулся -> разблокировка", t is not None, "%.2f с" % (t or 0))
tg = start("tgfake"); time.sleep(2.5); check("после возврата приложение живёт", alive(tg))

print("S5. пропал интернет")
F["net"] = False; time.sleep(0.35); F["net"] = True; time.sleep(1.6)
check("сбой интернета 0.35 с прощён", alive(tg))
F["net"] = False
t = wait_until(lambda: not alive(tg), 6)
check("затяжная потеря интернета -> закрыто", t is not None, "%.2f с" % (t or 0))
check("причина: пропал интернет", "интернет" in mon.snapshot()["reason"], mon.snapshot()["reason"])
F["net"] = True; wait_until(lambda: mon.snapshot()["status"] == "ok", 4)

print("S6. настройки меняются на лету")
F["proxy"] = False; wait_until(lambda: mon.snapshot()["status"] == "blocked", 4)
store.update({"apps": ["otherfake"]})
tg = start("tgfake"); time.sleep(2)
check("убрали из списка: приложение больше не трогаем", alive(tg))
store.update({"apps": ["tgfake"]})
t = wait_until(lambda: not alive(tg), 3)
check("вернули в список: закрыто", t is not None, "%.2f с" % (t or 0))

print("S7. лимиты: retries=0 (без перепроверок) быстрее")
F["proxy"] = True; wait_until(lambda: mon.snapshot()["status"] == "ok", 4)
store.update({"limits": {"retries": 0}})
tg = start("tgfake"); time.sleep(0.8)
F["proxy"] = False; t = wait_until(lambda: not alive(tg), 4)
check("retries=0: закрыто за ≈1 тик", t is not None and t < 1.3, "%.2f с" % (t or 0))
store.update({"limits": {"retries": 3}})

print("S8. режимы определения")
F["proxy"] = False; F["tunnel"] = True; store.update({"vpn": {"mode": "tunnel"}})
t = wait_until(lambda: mon.snapshot()["status"] == "ok", 4); check("режим tunnel: есть туннель -> ok", t is not None)
F["tunnel"] = False; t = wait_until(lambda: mon.snapshot()["status"] == "blocked", 4); check("режим tunnel: туннеля нет -> блок", t is not None)
store.update({"vpn": {"mode": "process"}}); t = wait_until(lambda: mon.snapshot()["status"] == "ok", 4)
check("режим process: достаточно запущенной программы", t is not None)
store.update({"vpn": {"mode": "auto"}}); F["proxy"] = False; F["tunnel"] = False
t = wait_until(lambda: mon.snapshot()["status"] == "blocked", 4)
check("авто: программа есть, но VPN не подключён -> блок", t is not None and "не подключён" in mon.snapshot()["reason"], mon.snapshot()["reason"])

print("S9. программа VPN закрыта совсем")
F["proxy"] = True; wait_until(lambda: mon.snapshot()["status"] == "ok", 4)
vpn.kill(); vpn.wait(); tg = start("tgfake")
t = wait_until(lambda: not alive(tg), 4); check("Happ закрыт -> приложение закрыто", t is not None, "%.2f с" % (t or 0))
check("калибровка сброшена", mon.calibrated is None)
vpn = start("vpnfake"); t = wait_until(lambda: mon.snapshot()["status"] == "ok", 4)
check("Happ запущен снова -> перекалибровка и разблокировка", t is not None and mon.calibrated == "proxy")

print("S10. проверка VPN отключена: решает только интернет")
store.update({"vpn": {"check": False}}); F["proxy"] = False
tg = start("tgfake"); time.sleep(2.5)
check("VPN не проверяется -> приложение живёт", alive(tg))
F["net"] = False; t = wait_until(lambda: not alive(tg), 5); check("а без интернета закрывается", t is not None, "%.2f с" % (t or 0))
F["net"] = True; store.update({"vpn": {"check": True}, "limits": {"check_internet": False}}); F["proxy"] = True
wait_until(lambda: mon.snapshot()["status"] == "ok", 4); tg = start("tgfake"); F["net"] = False; time.sleep(2.5)
check("проверка интернета выключена -> пропажа сети не блокирует", alive(tg))

print("S11. само-защита")
for p in procs.values():
    try: p.kill()
    except Exception: pass
check("защищённые системные имена не попадают в кандидаты",
      not vg.match_apps([{"pid": 5, "name": "explorer", "bundle": ""}], ["explorer"], ""))
mon.stop_event.set(); mon.join(3)
print("\nИтого: %d прошло, %d провалено" % (passed, failed))
shutil.rmtree(tmp, ignore_errors=True)
sys.exit(1 if failed else 0)
