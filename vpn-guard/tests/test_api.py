import os, sys, json, time, tempfile, subprocess, urllib.request, urllib.error, http.client, plistlib, re
tmp = tempfile.mkdtemp(); home = os.path.join(tmp, "home"); os.makedirs(home)
env = dict(os.environ, VPN_GUARD_HOME=os.path.join(tmp, "cfg"), HOME=home, XDG_CONFIG_HOME=os.path.join(home, ".config"))
port = 47850
p = subprocess.Popen([sys.executable, "/home/user/musical-carnival/vpn-guard/vpn_guard.py", "--no-browser", "--port", str(port)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(2)
tok = open(os.path.join(tmp, "cfg", "token")).read().strip()
ok = bad = 0
def chk(n, c, x=""):
    global ok, bad
    if c: ok += 1; print("  PASS ", n)
    else: bad += 1; print("  FAIL ", n, x)
def req(method, path, body=None, headers=None, tokn=True, raw=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Content-Type": "application/json"}
    if tokn: h["X-Token"] = tok
    if headers: h.update(headers)
    if host: h["Host"] = host
    data = raw if raw is not None else (json.dumps(body) if body is not None else None)
    c.request(method, path, data, h)
    r = c.getresponse(); b = r.read().decode()
    try: j = json.loads(b)
    except Exception: j = b
    return r.status, j, dict(r.getheaders())
s, j, _ = req("GET", "/api/ping", tokn=False); chk("ping без токена", s in (200, 403), s)
s, j, _ = req("GET", "/api/state"); chk("state с токеном 200", s == 200 and "status" in j, (s, j))
chk("первый запуск: защита выключена", j.get("config", {}).get("enabled") is False, j)
s, j, _ = req("GET", "/api/state", tokn=False); chk("без токена 403", s == 403, s)
s, j, _ = req("GET", "/api/state", host="evil.com"); chk("чужой Host 403 (DNS-rebinding)", s == 403, s)
s, j, _ = req("POST", "/api/config", {"enabled": True}, headers={"Origin": "http://evil.com"}); chk("чужой Origin 403", s == 403, s)
s, j, _ = req("POST", "/api/config", raw="enabled=1", headers={"Content-Type": "application/x-www-form-urlencoded"}); chk("form content-type 415", s == 415, s)
s, j, _ = req("POST", "/api/config", raw="x" * 300000); chk("огромный запрос 413", s == 413, s)
s, j, _ = req("POST", "/api/config", {"apps": ["explorer"]}); chk("защищённое приложение 400", s == 400, (s, j))
s, j, _ = req("GET", "/api/state"); chk("конфиг не изменился после отказа", "explorer" not in json.dumps(j["config"]["apps"]).lower(), j["config"]["apps"])
s, j, _ = req("POST", "/api/config", {"apps": ["Telegram", "Claude", "Discord"], "limits": {"retries": 5, "interval": 2}}); chk("валидный патч принят", s == 200, (s, j))
s, j, _ = req("POST", "/api/config", {"limits": {"retries": 9999}}); chk("лимит вне границ отклонён/ограничен", s == 400 or (s == 200 and j["config"]["limits"]["retries"] <= 20), (s, j))
cfgf = os.path.join(tmp, "cfg", "config.json"); c = json.load(open(cfgf))
chk("config.json сохранён на диск", "Discord" in c["apps"] and c["limits"]["interval"] == 2, c)
s, j, _ = req("GET", "/api/processes"); chk("список процессов", s == 200 and isinstance(j, (list, dict)), s)
s, j, _ = req("GET", "/api/diagnose"); chk("диагностика", s == 200, s)
s, j, _ = req("POST", "/api/calibrate", {}); chk("calibrate отвечает", s == 200, (s, j))
s, j, _ = req("POST", "/api/autostart", {"enabled": True}); chk("autostart on", s == 200, (s, j))
for root, _, fs in os.walk(home):
    for f in fs: print("     файл автозапуска:", os.path.join(root, f))
s, j, _ = req("POST", "/api/autostart", {"enabled": False}); chk("autostart off", s == 200, (s, j))
q = subprocess.run([sys.executable, "/home/user/musical-carnival/vpn-guard/vpn_guard.py", "--no-browser", "--port", str(port)], env=env, capture_output=True, text=True, timeout=10)
chk("второй экземпляр не запускается дублем", q.returncode == 0 and p.poll() is None, q.stdout[-200:] + q.stderr[-200:])
s, j, _ = req("GET", "/", headers={}, tokn=True); chk("страница с токеном", s == 200 and "__TOKEN__" not in str(j), s)
s, j, h = req("GET", "/api/state"); chk("заголовки безопасности", h.get("X-Frame-Options") == "DENY")
s, j, _ = req("POST", "/api/shutdown", {}); time.sleep(1.5)
chk("shutdown останавливает процесс", p.poll() is not None)
if p.poll() is None: p.kill()
print("Итого: %d прошло, %d провалено" % (ok, bad)); sys.exit(1 if bad else 0)
