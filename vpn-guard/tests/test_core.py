import importlib.util, os, sys, tempfile, stat, json
spec = importlib.util.spec_from_file_location("vg", "/home/user/musical-carnival/vpn-guard/vpn_guard.py")
vg = importlib.util.module_from_spec(spec); spec.loader.exec_module(vg)

passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond: passed += 1; print("  PASS  " + name)
    else: failed += 1; print("  FAIL  " + name + ("  -> " + str(extra) if extra else ""))

print("== разборщики вывода Windows ==")
tl = '"System Idle Process","0","Services","0","8 K"\r\n"Telegram.exe","4321","Console","1","120,000 K"\r\n"Happ.exe","1111","Console","1","50 K"\r\n"explorer.exe","9","Console","1","1 K"\r\nINFO: bad line\r\n'
procs = vg.parse_tasklist(tl)
check("tasklist: имена без .exe", [p["name"] for p in procs] == ["System Idle Process", "Telegram", "Happ", "explorer"], procs)
check("tasklist: pid числом", procs[1]["pid"] == 4321)
check("tasklist: мусорные строки пропущены", len(procs) == 4)
check("win-адаптеры: Realtek PCI Express не VPN", not vg.win_tunnel_parse("Ethernet 2|Realtek PCI Express Gigabit Ethernet Controller\nWi-Fi|Intel(R) Wi-Fi 6 AX201 160MHz"))
check("win-адаптеры: PPPoE провайдера не VPN", not vg.win_tunnel_parse("Мой провайдер|WAN Miniport (PPPOE)"))
check("win-адаптеры: VirtualBox/Hyper-V не VPN", not vg.win_tunnel_parse("VirtualBox Host-Only Network|VirtualBox Host-Only Ethernet Adapter\nvEthernet (Default Switch)|Hyper-V Virtual Ethernet Adapter"))
check("win-адаптеры: TAP-Windows = VPN", vg.win_tunnel_parse("Ethernet 3|TAP-Windows Adapter V9"))
check("win-адаптеры: Wintun/WireGuard = VPN", vg.win_tunnel_parse("wg0|WireGuard Tunnel") and vg.win_tunnel_parse("Happ|Wintun Userspace Tunnel"))

print("== разборщики вывода macOS ==")
ps = """    1 /sbin/launchd
  501 /Applications/Telegram.app/Contents/MacOS/Telegram
  777 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  778 /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)
  900 /Applications/Happ.app/Contents/MacOS/Happ
 1200 /usr/sbin/cfprefsd
"""
mp = vg.parse_ps(ps)
check("ps: путь с пробелами разобран", any(p["name"] == "Google Chrome" and p["pid"] == 777 for p in mp), mp[2])
check("ps: bundle определён", [p["bundle"] for p in mp if p["pid"] == 501] == ["Telegram"])
check("ps: у демона bundle пустой", [p["bundle"] for p in mp if p["pid"] == 1200] == [""])
m = vg.match_apps(mp, ["Google Chrome"], "Happ")
check("match: Chrome + хелпер закрываются по имени пакета", sorted(p["pid"] for p in m) == [777, 778], [p["pid"] for p in m])
m2 = vg.match_apps(mp, ["Telegram", "Happ"], "Happ")
check("match: VPN-клиент не закрывается, даже если он в списке", [p["pid"] for p in m2] == [501])
m3 = vg.match_apps(mp, ["launchd", "Telegram"], "")
check("match: системные (launchd) защищены", [p["pid"] for p in m3] == [501])
m4 = vg.match_apps(mp, ["telegram"], "", skip_pids={501})
check("match: регистр не важен, свои pid пропускаются", m4 == [])

scutil_on = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  HTTPEnable : 1\n  HTTPPort : 10809\n  HTTPProxy : 127.0.0.1\n  HTTPSEnable : 1\n  SOCKSEnable : 0\n}\n"
scutil_off = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  FTPPassive : 1\n  HTTPEnable : 0\n  SOCKSEnable : 0\n}\n"
check("scutil --proxy: прокси включён", vg.mac_proxy_parse(scutil_on))
check("scutil --proxy: выключен (FTPPassive : 1 не считается)", not vg.mac_proxy_parse(scutil_off))
ns_plain = "Routing tables\n\nInternet:\nDestination        Gateway            Flags           Netif Expire\ndefault            192.168.1.1        UGScg             en0       \n127                127.0.0.1          UCS               lo0       \n"
ns_split = ns_plain + "0/1                10.8.0.1           UGSc            utun4       \n128.0/1            10.8.0.1           UGSc            utun4       \n"
ns_full = ns_plain.replace("192.168.1.1        UGScg             en0", "10.8.0.1          UGScg           utun3")
check("netstat: обычная сеть = нет туннеля", not vg.mac_tunnel_parse(ns_plain))
check("netstat: split-маршруты 0/1+128.0/1 через utun = туннель", vg.mac_tunnel_parse(ns_split))
check("netstat: default через utun = туннель", vg.mac_tunnel_parse(ns_full))
check("scutil --nc list: (Connected) = туннель", vg.mac_tunnel_parse(ns_plain, '* (Connected)      ABC "Work VPN" [VPN:com.apple.neplugin.IKEv2]'))
check("scutil --nc list: (Disconnected) не считается", not vg.mac_tunnel_parse(ns_plain, '* (Disconnected)   ABC "Work VPN" [VPN:com.apple.neplugin.IKEv2]'))
check("linux ip route: tun/wg = туннель", vg.linux_tunnel_parse("default via 10.0.0.1 dev wg0\n") and not vg.linux_tunnel_parse("default via 192.168.0.1 dev eth0\n"))

print("== проверка ввода ==")
D = vg.DEFAULTS
def S(patch, cur=D): return vg.sanitize(patch, cur)
n, e = S({"apps": ["Telegram.exe", "telegram", " Discord ", "Google Chrome.app"]})
check("apps: .exe/.app убираются, дубли по регистру схлопываются", n["apps"] == ["Telegram", "Discord", "Google Chrome"] and not e, (n["apps"], e))
n, e = S({"apps": ["explorer"]}); check("apps: explorer запрещён", bool(e) and n == D)
n, e = S({"apps": ["Finder"]}); check("apps: Finder запрещён", bool(e))
n, e = S({"apps": ["python3.13"]}); check("apps: python* запрещён", bool(e))
n, e = S({"apps": ["../evil"]}); check("apps: путь с / отвергается", bool(e))
n, e = S({"apps": ["a" * 100]}); check("apps: слишком длинное имя отвергается", bool(e))
n, e = S({"apps": ["Happ"]}); check("apps: нельзя блокировать сам VPN-клиент", bool(e), e)
n, e = S({"apps": ["Telegram"], "vpn": {"process": "Telegram"}}); check("vpn: конфликт ловится и при смене VPN", bool(e))
n, e = S({"vpn": {"mode": "bogus"}}); check("vpn: неизвестный режим отвергается", bool(e))
n, e = S({"vpn": {"mode": "process", "process": ""}}); check("vpn: режим process без программы отвергается", bool(e))
n, e = S({"limits": {"interval": 0, "retries": 999, "retry_delay_ms": 1, "net_timeout_ms": 99999}})
check("лимиты: значения зажимаются в границы", (n["limits"]["interval"], n["limits"]["retries"], n["limits"]["retry_delay_ms"], n["limits"]["net_timeout_ms"]) == (0.5, 20, 50, 5000) and not e, n["limits"])
n, e = S({"limits": {"retries": "abc"}}); check("лимиты: текст вместо числа -> ошибка", bool(e))
n, e = S({"limits": {"hosts": ["1.1.1.1", "example.com:8443", "::1"]}}); check("hosts: ip, host:port и ipv6 принимаются", not e and len(n["limits"]["hosts"]) == 3, e)
n, e = S({"limits": {"hosts": ["bad host!"]}}); check("hosts: мусор отвергается", bool(e))
n, e = S({"limits": {"hosts": ["a:99999"]}}); check("hosts: порт >65535 отвергается", bool(e))
n, e = S({"limits": {"hosts": []}}); check("hosts: пустой список отвергается", bool(e))
n, e = S({"limits": {"hosts": ["1.1.1.1"] * 7}}); check("hosts: больше 6 отвергается", bool(e))
n, e = S({"apps": ["Discord"], "limits": {"retries": "x"}}); check("атомарность: при ошибке не применяется ничего", n == D and e)
n, e = S("мусор"); check("не-словарь отвергается", bool(e))
n, e = S({"enabled": True}); check("enabled включается", n["enabled"] is True)
check("защита по умолчанию ВЫКЛЮЧЕНА (первый запуск безопасен)", D["enabled"] is False)

print("== хранилище ==")
with tempfile.TemporaryDirectory() as d:
    st = vg.Store(d)
    check("первый запуск: first_run=True, конфиг по умолчанию", st.first_run and st.get() == D)
    mode = stat.S_IMODE(os.stat(os.path.join(d, "token")).st_mode)
    check("токен создан, права 600", len(st.token) >= 20 and mode == 0o600, oct(mode))
    ok, errs = st.update({"apps": ["Discord"], "enabled": True})
    check("update сохраняет на диск", ok and json.load(open(os.path.join(d, "config.json")))["apps"] == ["Discord"])
    check("файл конфига с правами 600", stat.S_IMODE(os.stat(os.path.join(d, "config.json")).st_mode) == 0o600)
    v = st.version; st.update({"apps": ["Discord"]})
    check("повторное то же значение не пишет заново (version не растёт)", st.version == v)
    ok, errs = st.update({"apps": ["explorer"]})
    check("невалидное отвергается, конфиг не тронут", not ok and st.get()["apps"] == ["Discord"])
    st2 = vg.Store(d)
    check("перезапуск читает сохранённое, токен тот же", st2.get()["apps"] == ["Discord"] and st2.get()["enabled"] and not st2.first_run and st2.token == st.token)
    open(os.path.join(d, "config.json"), "w").write("{сломано")
    st3 = vg.Store(d)
    check("битый config.json -> значения по умолчанию, без падения", st3.get() == D and st3.first_run)
    open(os.path.join(d, "config.json"), "w").write(json.dumps({"apps": ["explorer"]}))
    st4 = vg.Store(d)
    check("config.json с запрещённым именем -> по умолчанию + .bad", st4.get() == D and os.path.exists(os.path.join(d, "config.json.bad")))

print("\nИтого: %d прошло, %d провалено" % (passed, failed))
sys.exit(1 if failed else 0)
