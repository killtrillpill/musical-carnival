import os, sys, time, tempfile, subprocess, json
from playwright.sync_api import sync_playwright
SP = os.environ["SP"]
tmp = tempfile.mkdtemp(); cfg = os.path.join(tmp, "cfg")
env = dict(os.environ, VPN_GUARD_HOME=cfg, HOME=tmp)
port = 47860
p = subprocess.Popen([sys.executable, "/home/user/musical-carnival/vpn-guard/vpn_guard.py", "--no-browser", "--port", str(port)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2); tok = open(os.path.join(cfg, "token")).read().strip()
url = "http://127.0.0.1:%d/?t=%s" % (port, tok)
errs = []
with sync_playwright() as pw:
    b = pw.chromium.launch(); pg = b.new_page(viewport={"width": 1100, "height": 1500}, device_scale_factor=1)
    pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto(url); time.sleep(1.5)
    pg.screenshot(path=SP + "/shots/1_first.png", full_page=True)
    print("title:", pg.title())
    # add app
    inp = pg.locator("input[placeholder*='Discord'], #appInput, #appsInput").first
    print("inputs:", pg.eval_on_selector_all("input", "e=>e.map(x=>x.id+':'+x.type)"))
    print("buttons:", pg.eval_on_selector_all("button", "e=>e.map(x=>x.id+'|'+x.textContent.trim().slice(0,30))"))
    b.close()
p.terminate()
print("errors:", errs)
