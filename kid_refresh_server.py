#!/usr/bin/env python3
"""kid-monitor v4 - 平板上网监控（左右布局 + WebUI设置）"""
import http.server, subprocess, json, os, threading, time as _time, logging, re
from datetime import datetime, timezone, timedelta

import db
from config import get as cfg_get, set as cfg_set, get_all as cfg_get_all

# ============ 配置 ============
MONITOR_CONFIG_FILE = os.environ.get("KID_MONITOR_CONFIG", os.path.expanduser("~/.config/kid-control/monitor_config.json"))

def _load_monitor_config():
    try:
        with open(MONITOR_CONFIG_FILE) as f:
            return json.load(f)
    except:
        return {}

def _save_monitor_config(cfg):
    os.makedirs(os.path.dirname(MONITOR_CONFIG_FILE), exist_ok=True)
    with open(MONITOR_CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

# ============ 节假日判断 ============
def _is_chinese_holiday():
    try:
        import chinese_calendar
        today = datetime.now().date()
        return not chinese_calendar.is_workday(today)
    except ImportError:
        return datetime.now().weekday() >= 5

def _get_day_type():
    cfg = _load_monitor_config()
    if cfg.get("vacation_mode", False):
        return "vacation"
    return "holiday" if _is_chinese_holiday() else "workday"

# ============ 日志 ============
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [kid-monitor] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("kid-monitor")

# ============ 文件路径 ============
STATE_FILE = os.environ.get("STATE_FILE", os.path.expanduser("~/.config/kid-control/state.json"))

# ============ 缓存 ============
_cache = {"data": None, "ts": 0}
_cache_lock = threading.Lock()
CACHE_TTL = 60

# ============ 手动刷新状态 ============
_refresh_state = {"running": False, "ts": 0, "failures": 0}
_refresh_lock = threading.Lock()

# ============ ROS 实时查询 ============
CST = timezone(timedelta(hours=8))

def _try_ros_realtime():
    import paramiko
    realtime = {}
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(cfg_get("ROS_HOST"), port=int(cfg_get("ROS_PORT")),
                    username=cfg_get("ROS_USER"), password=cfg_get("ROS_PASS"),
                    timeout=3, banner_timeout=3, auth_timeout=3,
                    allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command('/ip arp print terse', timeout=5)
        mac_ip = {}
        for line in stdout.read().decode().split('\n'):
            ip = mac = ""
            for part in line.split():
                if part.startswith("address="): ip = part.split("=", 1)[1]
                elif part.startswith("mac-address="): mac = part.split("=", 1)[1].upper()
            if ip and mac: mac_ip[mac] = ip
        
        tablets = json.loads(cfg_get("TABLETS", "{}"))
        for mac in tablets:
            ip = mac_ip.get(mac)
            if not ip:
                realtime[mac] = {"ip": None, "tcp_bytes": 0, "udp_bytes": 0, "tcp_conns": 0, "udp_conns": 0, "long_udp": 0, "total_bytes": 0}
                continue
            stdin, stdout, stderr = ssh.exec_command(
                f'/ip firewall connection print detail where src-address="{ip}"', timeout=5)
            s = {"ip": ip, "tcp_bytes": 0, "udp_bytes": 0, "tcp_conns": 0, "udp_conns": 0, "long_udp": 0}
            for line in stdout.read().decode().split('\n'):
                m = re.search(r'protocol=(\w+)', line)
                if not m: continue
                proto = m.group(1).lower()
                def _val(tag):
                    m2 = re.search(rf'{tag}=(\d[\d\s]*)', line)
                    return int(m2.group(1).replace(' ', '')) if m2 else 0
                b = _val('orig-bytes') + _val('repl-bytes')
                t = _val('timeout')
                if proto == 'tcp':
                    s['tcp_bytes'] += b; s['tcp_conns'] += 1
                elif proto == 'udp':
                    s['udp_bytes'] += b; s['udp_conns'] += 1
                    if t > 300: s['long_udp'] += 1
            s['total_bytes'] = s['tcp_bytes'] + s['udp_bytes']
            realtime[mac] = s
        ssh.close()
    except Exception:
        pass
    return realtime

def _collect_data():
    now = datetime.now(CST)
    today_str = now.strftime("%Y-%m-%d")
    dates = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]

    state = {}
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except: pass

    records = []
    try:
        records = db.query_week_snapshots(days=7)
        for r in records:
            if isinstance(r.get("dns_video_domains"), str):
                try: r["dns_video_domains"] = json.loads(r["dns_video_domains"])
                except: r["dns_video_domains"] = []
            if isinstance(r.get("dns_game_domains"), str):
                try: r["dns_game_domains"] = json.loads(r["dns_game_domains"])
                except: r["dns_game_domains"] = []
    except Exception as e:
        log.warning(f"读取数据库失败: {e}")

    tablets = json.loads(cfg_get("TABLETS", "{}"))
    device_daily = {}
    for mac in tablets:
        try:
            device_daily[mac] = db.query_daily_stats(mac, days=7)
        except Exception:
            device_daily[mac] = {}

    if state.get("date") == today_str:
        for mac in tablets:
            su = state.get("usage", {}).get(mac, 0)
            if today_str not in device_daily.get(mac, {}):
                device_daily.setdefault(mac, {})[today_str] = {
                    "samples": 0, "usage_sec": 0, "tcp_kb": 0, "udp_kb": 0,
                    "activities": {}, "blocked_count": 0
                }
            device_daily[mac][today_str]["usage_sec"] = su

    realtime = _try_ros_realtime()
    db_realtime = db.query_all_realtime()
    for mac in tablets:
        if mac not in realtime or (realtime.get(mac, {}).get("ip") is None and mac in db_realtime):
            rt = db_realtime.get(mac, {})
            realtime[mac] = {
                "ip": rt.get("ip"),
                "tcp_bytes": rt.get("tcp_bytes", 0),
                "udp_bytes": rt.get("udp_bytes", 0),
                "tcp_conns": rt.get("tcp_conns", 0),
                "udp_conns": rt.get("udp_conns", 0),
                "long_udp": rt.get("long_udp", 0),
                "total_bytes": rt.get("total_bytes", 0),
            }
        if mac not in realtime:
            realtime[mac] = {"ip": None, "tcp_bytes": 0, "udp_bytes": 0, "tcp_conns": 0, "udp_conns": 0, "long_udp": 0, "total_bytes": 0}

    dd_out = {}
    for mac in tablets:
        dd_out[mac] = {}
        for date in dates:
            d = device_daily.get(mac, {}).get(date, {})
            dd_out[mac][date] = {
                "samples": d.get("samples", 0),
                "usage_sec": d.get("usage_sec", 0),
                "tcp_kb": d.get("tcp_kb", 0),
                "udp_kb": d.get("udp_kb", 0),
                "activities": d.get("activities", {}),
                "blocked_count": d.get("blocked_count", 0),
            }

    config = {}
    config_file = os.path.expanduser("~/.config/kid-control/config.json")
    try:
        with open(config_file) as f:
            config = json.load(f)
    except: pass

    device_limits = {}
    for mac in tablets:
        device_limits[mac] = {}
        mac_limits = config.get("limits", {}).get(mac, {})
        for date in dates:
            device_limits[mac][date] = mac_limits.get(date, 0)

    # 获取默认限额（秒）
    try:
        default_limit = int(cfg_get("DEFAULT_LIMIT", "60")) * 60
    except:
        default_limit = 3600
    
    return {
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "dates": dates,
        "realtime": realtime,
        "device_daily": dd_out,
        "device_limits": device_limits,
        "default_limit": default_limit,
        "history": records[-200:] if records else [],
        "state": state,
        "day_type": _get_day_type(),
        "tablets": tablets,
        "bypass": config.get("bypass", {}),
    }

# ============ 定时采集线程 ============
def _scheduled_collect_loop():
    import subprocess
    while True:
        try:
            cfg = _load_monitor_config()
            vacation = cfg.get("vacation_mode", False)
            now = datetime.now(CST)
            if not vacation and not _is_chinese_holiday():
                log.info(f"工作日({now.strftime('%A')})跳过采集，下轮重试")
                _time.sleep(300)
                continue
            log.info("定时采集开始...")
            result = subprocess.run(
                ["python3", "/app/kid_control.py"],
                capture_output=True, timeout=120
            )
            if result.stdout:
                for line in result.stdout.decode(errors="ignore").strip().split("\n"):
                    if line.strip(): log.info(f"  {line.strip()}")
            if result.returncode != 0 and result.stderr:
                log.warning(f"kid_control.py 返回码={result.returncode}: {result.stderr.decode(errors='ignore')[:200]}")
            with _cache_lock:
                _cache["ts"] = 0
        except Exception as e:
            log.error(f"定时采集异常: {e}")
        _time.sleep(300)

# ============ 后台缓存刷新 ============
def _refresh_cache_loop():
    failures = 0
    while True:
        try:
            data = _collect_data()
            with _cache_lock:
                _cache["data"] = data
                _cache["ts"] = _time.time()
            failures = 0
        except Exception as e:
            failures += 1
            log.warning(f"缓存刷新失败 ({failures}): {e}")
            if failures >= 3:
                log.error("连续失败3次，暂停5分钟")
                _time.sleep(300)
                failures = 0
                continue
        _time.sleep(CACHE_TTL)

def _get_cached_data():
    with _cache_lock:
        if _cache["data"] and (_time.time() - _cache["ts"]) < CACHE_TTL:
            return _cache["data"]
        if _cache["data"]:
            return _cache["data"]
    try:
        data = _collect_data()
        with _cache_lock:
            _cache["data"] = data
            _cache["ts"] = _time.time()
        return data
    except Exception as e:
        log.error(f"数据获取失败: {e}")
        return {"generated_at": "", "dates": [], "realtime": {}, "device_daily": {}, "history": [], "state": {}, "day_type": "workday"}

def _run_refresh():
    with _refresh_lock:
        if _refresh_state["running"]:
            return
        _refresh_state["running"] = True
    try:
        subprocess.run(["python3", "/app/kid_control.py"], capture_output=True, timeout=120)
    except Exception as e:
        log.error(f"手动刷新失败: {e}")
    finally:
        with _cache_lock:
            _cache["ts"] = 0
        with _refresh_lock:
            _refresh_state["running"] = False
            _refresh_state["ts"] = _time.time()

TABLETS_JSON = json.dumps(json.loads(cfg_get("TABLETS", "{}")))

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>家庭平板控制系统</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>📱</text></svg>">
<script>document.body.setAttribute("data-theme",localStorage.getItem("kid-monitor-theme")||"light")</script>
<style>
:root,[data-theme="light"]{
--bg:#f5f5f7;--text:#1d1d1f;--text2:#86868b;--card:#fff;--card-border:transparent;--card-shadow:0 1px 3px rgba(0,0,0,0.06);--section-shadow:0 1px 3px rgba(0,0,0,0.06);
--bar-bg:#f0f0f0;--tr-hover:#fafafa;--th-border:#e5e5e5;--td-border:#f0f0f0;
--tag-game-bg:#fff3e0;--tag-game-c:#e65100;--tag-video-bg:#e3f2fd;--tag-video-c:#1565c0;--tag-active-bg:#e8f5e9;--tag-active-c:#2e7d32;--tag-idle-bg:#f5f5f5;--tag-idle-c:#9e9e9e;--tag-blocked-bg:#fce4ec;--tag-blocked-c:#c62828;
--btn-bg:#fff;--btn-border:#cbd5e1;--btn-hover:#f8fafc;--btn-hover-b:#94a3b8;--btn-color:inherit;
--rt-row-b:transparent;--rt-row-p:6px 0;--rt-card-radius:12px;
--h1-color:#1d1d1f;--progress-shadow:none;--device-glow:none;
--sum-color:var(--text);--title-gradient:none;--accent-bg:transparent;
--right-bg:#fff;--right-border:#e5e5e5;
}
[data-theme="glass"]{
--bg:linear-gradient(135deg,#667eea 0%,#764ba2 50%,#f093fb 100%);--text:#fff;--text2:rgba(255,255,255,0.7);--card:rgba(255,255,255,0.15);--card-border:rgba(255,255,255,0.3);--card-shadow:0 8px 32px rgba(0,0,0,0.1);--section-shadow:0 8px 32px rgba(0,0,0,0.1);
--bar-bg:rgba(255,255,255,0.1);--tr-hover:rgba(255,255,255,0.08);--th-border:rgba(255,255,255,0.15);--td-border:rgba(255,255,255,0.08);
--tag-game-bg:rgba(255,159,10,0.25);--tag-game-c:#ffd599;--tag-video-bg:rgba(64,156,255,0.25);--tag-video-c:#99ccff;--tag-active-bg:rgba(48,209,88,0.25);--tag-active-c:#99ffbb;--tag-idle-bg:rgba(255,255,255,0.15);--tag-idle-c:rgba(255,255,255,0.6);--tag-blocked-bg:rgba(255,71,58,0.25);--tag-blocked-c:#ff9999;
--btn-bg:rgba(255,255,255,0.15);--btn-border:rgba(255,255,255,0.3);--btn-hover:rgba(255,255,255,0.25);--btn-hover-b:rgba(255,255,255,0.5);--btn-color:#fff;
--rt-row-b:1px solid rgba(255,255,255,0.1);--rt-row-p:7px 0;--rt-card-radius:14px;
--h1-color:#fff;--progress-shadow:0 1px 3px rgba(0,0,0,0.4);--device-glow:none;
--sum-color:#fff;--title-gradient:none;--accent-bg:transparent;
--right-bg:rgba(255,255,255,0.1);--right-border:rgba(255,255,255,0.2);
}
[data-theme="dark"]{
--bg:#0a0a0f;--text:#e0e0e0;--text2:#666;--card:#12121a;--card-border:#1e1e2e;--card-shadow:0 4px 24px rgba(0,0,0,0.3);--section-shadow:0 4px 24px rgba(0,0,0,0.3);
--bar-bg:#1a1a28;--tr-hover:rgba(99,102,241,0.05);--th-border:#1e1e2e;--td-border:#14141f;
--tag-game-bg:rgba(251,146,60,0.15);--tag-game-c:#fb923c;--tag-video-bg:rgba(56,189,248,0.15);--tag-video-c:#38bdf8;--tag-active-bg:rgba(34,197,94,0.15);--tag-active-c:#22c55e;--tag-idle-bg:rgba(100,100,100,0.15);--tag-idle-c:#666;--tag-blocked-bg:rgba(239,68,68,0.15);--tag-blocked-c:#ef4444;
--btn-bg:#1a1a28;--btn-border:#2a2a3a;--btn-hover:#222233;--btn-hover-b:#6366f1;--btn-color:#ccc;
--rt-row-b:1px solid #1a1a28;--rt-row-p:7px 0;--rt-card-radius:14px;
--h1-color:transparent;--progress-shadow:none;--device-glow:none;
--sum-color:#e0e0e0;--title-gradient:linear-gradient(135deg,#818cf8,#c084fc,#f472b6);--accent-bg:radial-gradient(ellipse at 20% 20%,rgba(99,102,241,0.15) 0%,transparent 50%),radial-gradient(ellipse at 80% 80%,rgba(236,72,153,0.1) 0%,transparent 50%);
--right-bg:#12121a;--right-border:#1e1e2e;
}
[data-theme="dashboard"]{
--bg:#f8fafc;--text:#1e293b;--text2:#94a3b8;--card:#fff;--card-border:#e2e8f0;--card-shadow:0 1px 3px rgba(0,0,0,0.04),0 4px 12px rgba(0,0,0,0.02);--section-shadow:0 1px 3px rgba(0,0,0,0.04),0 4px 12px rgba(0,0,0,0.02);
--bar-bg:#e2e8f0;--tr-hover:#f8fafc;--th-border:#e2e8f0;--td-border:#f1f5f9;
--tag-game-bg:#fff7ed;--tag-game-c:#ea580c;--tag-video-bg:#f0f9ff;--tag-video-c:#0284c7;--tag-active-bg:#f0fdf4;--tag-active-c:#16a34a;--tag-idle-bg:#f1f5f9;--tag-idle-c:#64748b;--tag-blocked-bg:#fef2f2;--tag-blocked-c:#dc2626;
--btn-bg:linear-gradient(135deg,#6366f1,#8b5cf6);--btn-border:transparent;--btn-hover:linear-gradient(135deg,#5558e6,#7c4fdb);--btn-hover-b:transparent;--btn-color:#fff;
--rt-row-b:1px solid #f1f5f9;--rt-row-p:10px 12px;--rt-card-radius:16px;
--h1-color:#1e293b;--progress-shadow:none;--device-glow:none;
--sum-color:#1e293b;--title-gradient:none;--accent-bg:transparent;
--right-bg:#fff;--right-border:#e2e8f0;
}
[data-theme="hacker"]{
--bg:#050505;--text:#00ff41;--text2:#00cc33;--card:#0a0a0a;--card-border:#00ff4155;
--card-shadow:0 0 15px rgba(0,255,65,0.15),inset 0 0 30px rgba(0,255,65,0.03);
--section-shadow:0 0 20px rgba(0,255,65,0.1),0 0 40px rgba(0,255,65,0.05);
--bar-bg:#111;--tr-hover:rgba(0,255,65,0.08);--th-border:#00ff4144;--td-border:#00ff4122;
--tag-game-bg:rgba(255,100,0,0.2);--tag-game-c:#ff6400;
--tag-video-bg:rgba(0,255,65,0.15);--tag-video-c:#00ff41;
--tag-active-bg:rgba(0,255,65,0.15);--tag-active-c:#00ff41;
--tag-idle-bg:rgba(0,255,65,0.08);--tag-idle-c:#007722;
--tag-blocked-bg:rgba(255,0,0,0.2);--tag-blocked-c:#ff3333;
--btn-bg:transparent;--btn-border:#00ff4166;--btn-hover:rgba(0,255,65,0.1);
--btn-hover-b:#00ff41;--btn-color:#00ff41;
--rt-row-b:1px solid #00ff4122;--rt-row-p:8px 0;--rt-card-radius:0;
--h1-color:#00ff41;--progress-shadow:0 0 10px rgba(0,255,65,0.6);
--device-glow:0 0 20px rgba(0,255,65,0.2);
--sum-color:#00ff41;--title-gradient:linear-gradient(90deg,#00ff41,#00cc33,#00ff41);
--accent-bg:repeating-linear-gradient(0deg,rgba(0,255,65,0.02) 0px,rgba(0,255,65,0.02) 1px,transparent 1px,transparent 2px);
--right-bg:#0a0a0a;--right-border:#00ff4144;
}
[data-theme="hacker"] body::after{
content:'';position:fixed;inset:0;
background:repeating-linear-gradient(0deg,rgba(0,255,65,0.03) 0px,rgba(0,255,65,0.03) 1px,transparent 1px,transparent 3px);
pointer-events:none;z-index:9999;
animation:scanline 8s linear infinite;
}
@keyframes scanline{
0%{background-position:0 0}100%{background-position:0 100vh}
}
[data-theme="hacker"] .container{
text-shadow:0 0 5px rgba(0,255,65,0.3);
}
[data-theme="hacker"] h1{
text-shadow:0 0 20px rgba(0,255,65,0.8),0 0 40px rgba(0,255,65,0.4);
animation:pulse 2s ease-in-out infinite;
}
@keyframes pulse{
0%,100%{opacity:1}50%{opacity:0.85}
}
[data-theme="hacker"] .rt-card{
border:1px solid #00ff4166;
box-shadow:0 0 15px rgba(0,255,65,0.1),inset 0 0 20px rgba(0,255,65,0.02);
transition:all 0.3s;
}
[data-theme="hacker"] .rt-card:hover{
border-color:#00ff41;
box-shadow:0 0 25px rgba(0,255,65,0.25),inset 0 0 30px rgba(0,255,65,0.05);
}
[data-theme="hacker"] .rt-card h3{
border-bottom:1px solid #00ff4133;
padding-bottom:8px;
}
[data-theme="hacker"] .status.on{
box-shadow:0 0 8px #00ff41,0 0 16px #00ff41;
}
[data-theme="hacker"] .btn{
border:1px solid #00ff4166;
background:transparent;
color:#00ff41;
transition:all 0.2s;
text-transform:uppercase;
letter-spacing:1px;
font-size:11px;
}
[data-theme="hacker"] .btn:hover{
background:rgba(0,255,65,0.1);
border-color:#00ff41;
box-shadow:0 0 15px rgba(0,255,65,0.3);
text-shadow:0 0 5px #00ff41;
}
[data-theme="hacker"] .theme-icon{
border-color:#00ff4166;
}
[data-theme="hacker"] .theme-icon:hover{
border-color:#00ff41;
box-shadow:0 0 15px rgba(0,255,65,0.4);
}
[data-theme="hacker"] .bar{
background:linear-gradient(90deg,#00ff41,#00cc33)!important;
box-shadow:0 0 8px rgba(0,255,65,0.4);
}
[data-theme="hacker"] .bar-ok{
background:linear-gradient(90deg,#00ff41,#00cc33)!important;
}
[data-theme="hacker"] .bar-warn{
background:linear-gradient(90deg,#ff9f0a,#ffcc00)!important;
}
[data-theme="hacker"] .bar-over{
background:linear-gradient(90deg,#ff3333,#ff0000)!important;
box-shadow:0 0 10px rgba(255,0,0,0.5);
}
[data-theme="hacker"] .tag{
border:1px solid currentColor;
border-radius:0;
text-transform:uppercase;
font-size:10px;
letter-spacing:0.5px;
}
[data-theme="hacker"] table{
border-collapse:collapse;
}
[data-theme="hacker"] th{
border-bottom:2px solid #00ff4166!important;
text-transform:uppercase;
font-size:11px;
letter-spacing:1px;
}
[data-theme="hacker"] td{
border-bottom:1px solid #00ff4122!important;
}
[data-theme="hacker"] tr:hover td{
background:rgba(0,255,65,0.05)!important;
}
[data-theme="hacker"] .sum-card{
border:1px solid #00ff4144;
background:rgba(0,255,65,0.02);
}
[data-theme="hacker"] .sum-card:hover{
border-color:#00ff41;
box-shadow:0 0 15px rgba(0,255,65,0.2);
}
[data-theme="hacker"] .toggle.on{
background:#00ff41;
box-shadow:0 0 10px rgba(0,255,65,0.5);
}
[data-theme="hacker"] .toggle::after{
background:#050505;
border:1px solid #00ff41;
}
[data-theme="hacker"] .day-badge{
border:1px solid currentColor;
text-transform:uppercase;
letter-spacing:1px;
}
[data-theme="hacker"] .section{
border:1px solid #00ff4144;
}
[data-theme="hacker"] .section h2{
border-left:3px solid #00ff41;
padding-left:10px;
text-transform:uppercase;
letter-spacing:1px;
}
[data-theme="hacker"] input,[data-theme="hacker"] textarea{
border:1px solid #00ff4144!important;
background:#0a0a0a!important;
color:#00ff41!important;
}
[data-theme="hacker"] input:focus,[data-theme="hacker"] textarea:focus{
border-color:#00ff41!important;
box-shadow:0 0 10px rgba(0,255,65,0.3);
outline:none;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"PingFang SC","Helvetica Neue",system-ui,sans-serif;background:var(--bg);color:var(--text);padding:16px;transition:background .3s,color .3s}
body[data-theme="dark"]::before,body[data-theme="hacker"]::before{content:'';position:fixed;inset:0;background:var(--accent-bg);pointer-events:none;z-index:0}
.container{max-width:95%;margin:0 auto;position:relative;z-index:1}
h1{font-size:22px;font-weight:600;margin-bottom:16px;color:var(--h1-color);background:var(--title-gradient);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.updated{font-size:13px;color:var(--text2)}
.refresh-bar{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.btn{padding:5px 14px;border:1px solid var(--btn-border);border-radius:6px;background:var(--btn-bg);cursor:pointer;font-size:13px;color:var(--btn-color);transition:all .15s}
.btn:hover{background:var(--btn-hover);border-color:var(--btn-hover-b)}
.btn:disabled{opacity:0.6;cursor:not-allowed}
.toggle-wrap{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text2)}
.toggle{position:relative;width:36px;height:20px;background:#ccc;border-radius:10px;cursor:pointer;transition:background .2s}
.toggle.on{background:#6366f1}
.toggle::after{content:'';position:absolute;top:2px;left:2px;width:16px;height:16px;background:#fff;border-radius:50%;transition:transform .2s}
.toggle.on::after{transform:translateX(16px)}
.day-badge{display:inline-block;padding:3px 10px;border-radius:6px;font-size:12px;font-weight:600;margin-left:8px}
.day-badge.holiday{background:rgba(255,159,10,0.15);color:#ff9f0a}
.day-badge.workday{background:rgba(48,209,88,0.15);color:#30d158}
.day-badge.vacation{background:rgba(191,90,242,0.15);color:#bf5af2}
.theme-switcher{position:relative;margin-left:auto}
.theme-icon{width:32px;height:32px;border-radius:8px;border:1px solid var(--btn-border);cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:all .2s;background:var(--card)}
.theme-icon:hover{transform:scale(1.1);border-color:#6366f1}
.theme-popover{display:none;position:absolute;right:0;top:40px;background:var(--card);border:1px solid var(--card-border);border-radius:12px;padding:8px;box-shadow:0 8px 32px rgba(0,0,0,0.15);z-index:100;min-width:140px}
.theme-popover.open{display:flex;flex-direction:column;gap:4px}
.theme-opt{display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;cursor:pointer;font-size:13px;color:var(--text);transition:background .15s;border:none;background:transparent;width:100%;text-align:left}
.theme-opt:hover{background:var(--tr-hover)}
.theme-opt.active{background:rgba(99,102,241,0.1);color:#6366f1;font-weight:600}
/* 左右布局 */
.layout{display:grid;grid-template-columns:3fr 1fr;gap:20px}
.left{min-width:0}
.right{background:var(--right-bg);border:1px solid var(--right-border);border-radius:12px;padding:16px;max-height:calc(100vh - 120px);overflow-y:auto;position:sticky;top:16px;min-width:240px}
.right h2{font-size:16px;font-weight:600;margin-bottom:12px;color:var(--text)}
/* 实时卡片 */
.realtime{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:20px}
.rt-card{background:var(--card);border:1px solid var(--card-border);border-radius:var(--rt-card-radius);padding:16px;box-shadow:var(--card-shadow);transition:background .3s,border .3s}
.rt-card h3{font-size:15px;font-weight:600;margin-bottom:10px;display:flex;align-items:center;gap:8px;color:var(--text)}
.rt-card .status{display:inline-block;width:8px;height:8px;border-radius:50%}
.rt-card .status.on{background:#30d158}
.rt-card .status.off{background:var(--text2)}
.rt-row{display:flex;justify-content:space-between;padding:var(--rt-row-p);font-size:13px;border-bottom:var(--rt-row-b)}
.rt-row:last-child{border:none}
.rt-row .label{color:var(--text2)}
.rt-row .value{font-weight:500;font-variant-numeric:tabular-nums;color:var(--text)}
/* 摘要卡片 */
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:20px}
.sum-card{background:var(--card);border:1px solid var(--card-border);border-radius:10px;padding:14px;text-align:center;box-shadow:var(--card-shadow)}
.sum-card .num{font-size:24px;font-weight:700;color:var(--sum-color);font-variant-numeric:tabular-nums}
.sum-card .lbl{font-size:11px;color:var(--text2);margin-top:4px}
/* 表格 */
.section{background:var(--card);border:1px solid var(--card-border);border-radius:12px;padding:16px;box-shadow:var(--section-shadow);margin-bottom:16px}
.section h2{font-size:16px;font-weight:600;margin-bottom:12px;color:var(--text)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}
th{text-align:left;padding:8px 10px;font-weight:500;color:var(--text2);border-bottom:2px solid var(--th-border);white-space:nowrap}
td{padding:8px 10px;border-bottom:1px solid var(--td-border);font-variant-numeric:tabular-nums;color:var(--text)}
tr:hover td{background:var(--tr-hover)}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:500}
.tag-game{background:var(--tag-game-bg);color:var(--tag-game-c)}
.tag-video{background:var(--tag-video-bg);color:var(--tag-video-c)}
.tag-active{background:var(--tag-active-bg);color:var(--tag-active-c)}
.tag-idle{background:var(--tag-idle-bg);color:var(--tag-idle-c)}
.tag-blocked{background:var(--tag-blocked-bg);color:var(--tag-blocked-c)}
.bar-wrap{background:var(--bar-bg);border-radius:4px;height:18px;position:relative;min-width:100px;overflow:hidden}
.bar{height:100%;border-radius:4px;transition:width 0.3s}
.bar-ok{background:linear-gradient(90deg,#30d158,#34c759)}
.bar-warn{background:linear-gradient(90deg,#ff9f0a,#ff6723)}
.bar-over{background:linear-gradient(90deg,#ff453a,#d62d20)}
.bar-text{position:absolute;right:6px;top:50%;transform:translateY(-50%);font-size:10px;font-weight:600;color:#fff;text-shadow:var(--progress-shadow)}
/* 右侧采样表 */
.right table{font-size:12px}
.right th{padding:6px 8px;font-size:11px}
.right td{padding:6px 8px;font-size:11px}
@media(max-width:900px){.layout{grid-template-columns:1fr !important}.right{position:static;max-height:none;overflow-y:visible;min-width:auto}}
@media(max-width:600px){body{padding:10px}.realtime{grid-template-columns:1fr}table{font-size:12px}th,td{padding:6px 4px}.theme-switcher{margin-left:0}.toggle-wrap{margin-left:0}}
</style>
</head>
<body>
<div class="container">
<h1>📱 家庭平板控制系统</h1>
<div class="refresh-bar">
  <button class="btn" id="refreshBtn" onclick="doRefresh()">🔄 刷新</button>
  <span class="updated" id="updateTime">加载中...</span>
  <div class="toggle-wrap">
    <span id="toggleLabel">寒暑假</span>
    <div class="toggle" id="vacationToggle" onclick="toggleVacation()"></div>
  </div>
  <span class="day-badge" id="dayBadge"></span>
  <button class="btn" onclick="toggleSettings()">⚙️ 设置</button>
  <div class="theme-switcher">
    <button class="theme-icon" onclick="toggleThemePopover()" id="themeIcon">🎨</button>
    <div class="theme-popover" id="themePopover">
      <button class="theme-opt" data-theme="light" onclick="setTheme('light')">☀️ 经典浅色</button>
      <button class="theme-opt" data-theme="glass" onclick="setTheme('glass')">💎 毛玻璃</button>
      <button class="theme-opt" data-theme="dark" onclick="setTheme('dark')">🌙 暗色科技</button>
      <button class="theme-opt" data-theme="dashboard" onclick="setTheme('dashboard')">📊 仪表盘</button>
      <button class="theme-opt" data-theme="hacker" onclick="setTheme('hacker')">☠️ 黑客</button>
    </div>
  </div>
</div>
<!-- 设置面板（默认隐藏） -->
<div class="section" id="settingsPanel" style="display:none">
  <h2>⚙️ 系统设置</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px">
    <div>
      <h3 style="font-size:14px;margin-bottom:8px;color:var(--text2)">ROS 连接</h3>
      <div style="display:flex;flex-direction:column;gap:8px">
        <label style="font-size:13px"><span style="color:var(--text2)">主机</span> <input id="cfg_ros_host" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text)"></label>
        <label style="font-size:13px"><span style="color:var(--text2)">端口</span> <input id="cfg_ros_port" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text)"></label>
        <label style="font-size:13px"><span style="color:var(--text2)">用户名</span> <input id="cfg_ros_user" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text)"></label>
        <label style="font-size:13px"><span style="color:var(--text2)">密码</span> <input id="cfg_ros_pass" type="password" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text)"></label>
      </div>
    </div>
    <div>
      <h3 style="font-size:14px;margin-bottom:8px;color:var(--text2)">mosdns</h3>
      <label style="font-size:13px"><span style="color:var(--text2)">审计API</span> <input id="cfg_mosdns_api" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text)"></label>
      <h3 style="font-size:14px;margin:12px 0 8px;color:var(--text2)">时间规则</h3>
      <div style="display:flex;flex-direction:column;gap:8px">
        <label style="font-size:13px"><span style="color:var(--text2)">工作日禁止上网(学习)</span> <input id="cfg_workday_free" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text)"></label>
        <label style="font-size:13px"><span style="color:var(--text2)">寒暑假允许上网(自由)</span> <input id="cfg_vacation_free" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text)"></label>
        <label style="font-size:13px"><span style="color:var(--text2)">默认每日限额(分钟)</span> <input id="cfg_default_limit" type="number" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text)"></label>
      </div>
    </div>
    <div>
      <h3 style="font-size:14px;margin-bottom:8px;color:var(--text2)">平板设备 (JSON)</h3>
      <textarea id="cfg_tablets" rows="4" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text);font-family:monospace;font-size:12px;resize:vertical"></textarea>
      <h3 style="font-size:14px;margin:12px 0 8px;color:var(--text2)">Kid Control 映射 (JSON)</h3>
      <textarea id="cfg_kid_profiles" rows="3" style="width:100%;padding:6px;border:1px solid var(--card-border);border-radius:6px;background:var(--card);color:var(--text);font-family:monospace;font-size:12px;resize:vertical"></textarea>
    </div>
  </div>
  <div style="margin-top:16px;display:flex;gap:8px">
    <button class="btn" onclick="saveSettings()" style="background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none">💾 保存设置</button>
    <button class="btn" onclick="toggleSettings()">取消</button>
    <span id="settingsStatus" style="font-size:13px;color:var(--text2);align-self:center"></span>
  </div>
</div>
<!-- 主布局 -->
<div class="layout">
<div class="left">
  <div class="realtime" id="realtime"></div>
  <div class="summary" id="summary"></div>
  <div id="tables"></div>
  <div class="section" id="videoSection" style="display:none">
    <h2>📺 视频活动时间线</h2>
    <div id="videoContent"></div>
  </div>
</div>
<div class="right">
  <h2>📋 最近采样</h2>
  <div id="recentTable"></div>
</div>
</div>
</div>
<script>
const TABLETS=__TABLETS_PLACEHOLDER__;
const WEEKDAYS=["周一","周二","周三","周四","周五","周六","周日"];
const EMOJI={game:"🎮",video:"📺",active:"✅",idle:"💤",free:"⭐"};
function setTheme(t){
  document.body.setAttribute("data-theme",t);
  localStorage.setItem("kid-monitor-theme",t);
  document.querySelectorAll(".theme-opt").forEach(b=>b.classList.toggle("active",b.dataset.theme===t));
  document.getElementById("themePopover").classList.remove("open");
}
function toggleThemePopover(){document.getElementById("themePopover").classList.toggle("open")}
document.addEventListener("click",function(e){if(!e.target.closest(".theme-switcher"))document.getElementById("themePopover").classList.remove("open")});
let vacationMode=false;
function toggleVacation(){
  vacationMode=!vacationMode;
  updateToggleUI();
  fetch("/api/config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({vacation_mode:vacationMode})}).then(r=>r.json()).then(j=>{if(!j.ok)alert("❌ "+(j.error||"失败"));else updateDayBadge(j.day_type)});
}
function updateToggleUI(){
  const el=document.getElementById("vacationToggle"),lbl=document.getElementById("toggleLabel");
  if(vacationMode){el.classList.add("on");lbl.textContent="寒暑假(开)"}else{el.classList.remove("on");lbl.textContent="寒暑假"}
}
function updateDayBadge(t){
  const b=document.getElementById("dayBadge");
  if(t==="vacation"){b.className="day-badge vacation";b.textContent="🏖️ 寒暑假模式"}
  else if(t==="holiday"){b.className="day-badge holiday";b.textContent="🎉 假日/周末"}
  else{b.className="day-badge workday";b.textContent="💼 工作日"}
}
async function loadConfig(){
  try{const r=await fetch("/api/config");const j=await r.json();if(j.ok){vacationMode=j.vacation_mode;updateToggleUI();updateDayBadge(j.day_type)}}catch(e){}
}
// 设置面板
async function toggleSettings(){
  const p=document.getElementById("settingsPanel");
  if(p.style.display==="none"){
    p.style.display="";
    const r=await fetch("/api/settings");const j=await r.json();
    if(j.ok){
      document.getElementById("cfg_ros_host").value=j.ROS_HOST||"";
      document.getElementById("cfg_ros_port").value=j.ROS_PORT||"";
      document.getElementById("cfg_ros_user").value=j.ROS_USER||"";
      document.getElementById("cfg_ros_pass").value=j.ROS_PASS||"";
      document.getElementById("cfg_mosdns_api").value=j.MOSDNS_API||"";
      document.getElementById("cfg_workday_free").value=j.WORKDAY_FREE_START+"-"+j.WORKDAY_FREE_END||"";
      document.getElementById("cfg_vacation_free").value=j.VACATION_FREE_START+"-"+j.VACATION_FREE_END||"";
      document.getElementById("cfg_default_limit").value=j.DEFAULT_LIMIT||"60";
      document.getElementById("cfg_tablets").value=JSON.stringify(JSON.parse(j.TABLETS||"{}"),null,2);
      document.getElementById("cfg_kid_profiles").value=JSON.stringify(JSON.parse(j.KID_PROFILES||"{}"),null,2);
    }
  }else p.style.display="none";
}
async function saveSettings(){
  const wf=document.getElementById("cfg_workday_free").value.split("-");
  const vf=document.getElementById("cfg_vacation_free").value.split("-");
  const payload={
    ROS_HOST:document.getElementById("cfg_ros_host").value,
    ROS_PORT:document.getElementById("cfg_ros_port").value,
    ROS_USER:document.getElementById("cfg_ros_user").value,
    ROS_PASS:document.getElementById("cfg_ros_pass").value,
    MOSDNS_API:document.getElementById("cfg_mosdns_api").value,
    WORKDAY_FREE_START:wf[0]||"",WORKDAY_FREE_END:wf[1]||"",
    VACATION_FREE_START:vf[0]||"",VACATION_FREE_END:vf[1]||"",
    DEFAULT_LIMIT:document.getElementById("cfg_default_limit").value||"60",
    TABLETS:document.getElementById("cfg_tablets").value,
    KID_PROFILES:document.getElementById("cfg_kid_profiles").value,
  };
  try{
    const r=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const j=await r.json();
    if(j.ok){document.getElementById("settingsStatus").textContent="✅ 已保存";setTimeout(()=>document.getElementById("settingsStatus").textContent="",2000)}
    else document.getElementById("settingsStatus").textContent="❌ "+j.error;
  }catch(e){document.getElementById("settingsStatus").textContent="❌ 网络错误"}
}
(function(){const saved=localStorage.getItem("kid-monitor-theme")||"light";setTheme(saved)})();
function fmt(s){const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h?h+"h"+m+"m":m+"m"}
async function load(){
  try{const r=await fetch("/api/data");const d=await r.json();render(d)}catch(e){document.getElementById("updateTime").textContent="❌ "+e}
}
function render(d){
  document.getElementById("updateTime").textContent="更新: "+d.generated_at;
  if(d.tablets)Object.assign(TABLETS,d.tablets);
  updateDayBadge(d.day_type);
  let rh="";
  for(const[mac,info]of Object.entries(TABLETS)){
    const rt=d.realtime[mac]||{};
    const online=rt.ip!=null;
    const totalKb=Math.floor((rt.total_bytes||0)/1024);
    const tcpKb=Math.floor((rt.tcp_bytes||0)/1024);
    const udpKb=Math.floor((rt.udp_bytes||0)/1024);
    const usage=(d.device_daily[mac]||{})[d.dates[d.dates.length-1]]?.usage_sec||0;
    const limit=(d.device_limits||{})[mac]?.[d.dates[d.dates.length-1]]||d.default_limit||3600;
    rh+=`<div class="rt-card">
      <h3><span class="status ${online?'on':'off'}"></span>${info.label}</h3>
      <div class="rt-row"><span class="label">IP</span><span class="value">${rt.ip||'离线'}</span></div>
      <div class="rt-row"><span class="label">流量</span><span class="value">${totalKb.toLocaleString()} KB</span></div>
      <div class="rt-row"><span class="label">TCP/UDP</span><span class="value">${tcpKb.toLocaleString()}/${udpKb.toLocaleString()}</span></div>
      <div class="rt-row"><span class="label">连接数</span><span class="value">T${rt.tcp_conns||0}/U${rt.udp_conns||0}</span></div>
      <div class="rt-row"><span class="label">今日</span><span class="value" style="font-weight:600">${fmt(usage)}</span></div>
      <div class="rt-row"><span class="label">剩余</span><span class="value remain-val" data-mac="${mac}" style="color:#30d158;font-weight:600">${fmt(Math.max(0,limit-usage))}</span> ${(d.bypass||{})[mac]?.enabled ? '<span class="bypass-badge on">🟢 放行中</span>' : '<span class="bypass-badge off">正常管控</span>'}</div>
      <div style="margin-top:8px;display:flex;gap:6px">
        <button class="btn" onclick="doAdjust('${mac}',-1800)">➖30m</button>
        <button class="btn" onclick="doAdjust('${mac}',1800)">➕30m</button>
        <button class="btn-bypass ${(d.bypass||{})[mac]?.enabled?'on':'off'}" onclick="doToggleBypass('${mac}',${!((d.bypass||{})[mac]?.enabled)})">${(d.bypass||{})[mac]?.enabled?'🔒 恢复限制':'🔓 临时放行'}</button>
      </div>
    </div>`;
  }
  document.getElementById("realtime").innerHTML=rh;
  const records=d.history||[];
  document.getElementById("summary").innerHTML=`
    <div class="sum-card"><div class="num">${records.length}</div><div class="lbl">采样数</div></div>
    <div class="sum-card"><div class="num" style="color:#e65100">🎮${records.filter(r=>r.activity==="game").length}</div><div class="lbl">游戏</div></div>
    <div class="sum-card"><div class="num" style="color:#1565c0">📺${records.filter(r=>r.activity==="video").length}</div><div class="lbl">视频</div></div>
    <div class="sum-card"><div class="num" style="color:#c62828">🚫${records.filter(r=>r.blocked).length}</div><div class="lbl">封禁</div></div>`;
  let th="";
  for(const[mac,info]of Object.entries(TABLETS)){
    const daily=d.device_daily[mac]||{};
    th+=`<div class="section"><h2>${info.label} · 每日</h2>
      <div style="overflow-x:auto"><table><thead><tr>
        <th>日期</th><th>星期</th><th>采样</th><th>使用</th><th>TCP</th><th>UDP</th><th>活动</th><th>封禁</th>
      </tr></thead><tbody>`;
    for(const date of d.dates){
      const dd=daily[date];
      const dt=new Date(date+"T00:00:00+08:00");
      const wd=WEEKDAYS[dt.getDay()===0?6:dt.getDay()-1];
      if(!dd){th+=`<tr><td>${date}</td><td>${wd}</td><td colspan="6" style="color:#86868b">-</td></tr>`;continue}
      const usage=dd.usage_sec||0;
      const limit=(d.device_limits||{})[mac]?.[date]||d.default_limit||3600;
      const pct=Math.min(100,Math.floor(usage/limit*100));
      const barCls=pct<60?"bar-ok":pct<90?"bar-warn":"bar-over";
      let acts="";
      for(const act of["game","video","active","idle","free"]){const cnt=(dd.activities||{})[act]||0;if(cnt)acts+=`<span class="tag tag-${act}">${EMOJI[act]}${cnt}</span> `}
      th+=`<tr><td>${date}</td><td>${wd}</td><td>${dd.samples||0}</td>
        <td><div class="bar-wrap"><div class="bar ${barCls}" style="width:${pct}%"></div><span class="bar-text">${fmt(usage)}/${fmt(limit)}</span></div></td>
        <td>${(dd.tcp_kb||0).toLocaleString()}</td><td>${(dd.udp_kb||0).toLocaleString()}</td>
        <td>${acts||'-'}</td><td>${dd.blocked_count||'0'}</td></tr>`;
    }
    th+="</tbody></table></div></div>";
  }
  document.getElementById("tables").innerHTML=th;
  // 右侧最近采样
  const recent=(d.history||[]).slice(-50).reverse();
  if(recent.length){
    let rth="<table><thead><tr><th>时间</th><th>设备</th><th>活动</th><th>时长</th><th>状态</th></tr></thead><tbody>";
    for(const r of recent){
      const act=r.activity||"idle";
      rth+=`<tr><td>${(r.time||"").slice(0,5)}</td>
        <td>${(TABLETS[r.mac]||{}).label||r.name||""}</td>
        <td><span class="tag tag-${act}">${EMOJI[act]||""}</span></td>
        <td>${fmt(r.usage_sec||0)}</td>
        <td>${r.blocked?'<span class="tag tag-blocked">封禁</span>':'✓'}</td></tr>`;
    }
    rth+="</tbody></table>";
    document.getElementById("recentTable").innerHTML=rth;
  }
}
async function doRefresh(){
  const btn=document.getElementById("refreshBtn");
  btn.disabled=true;btn.textContent="⏳ 采集中...";
  try{const r=await fetch("/kid-refresh");const j=await r.json();
    if(j.ok){let a=0;const poll=async()=>{a++;const d=await(await fetch("/api/data")).json();if(a>30){btn.textContent="⏱️超时";return}if(d.history&&d.history.length>0){btn.textContent="✅ 完成";load();return}setTimeout(poll,2000)};poll()}
    else btn.textContent="❌ "+(j.error||"失败");
  }catch(e){btn.textContent="❌ 网络错误"}
  finally{setTimeout(()=>{btn.disabled=false;btn.textContent="🔄 刷新"},3000)}
}
async function doAdjust(mac,delta){
  try{const r=await fetch("/kid-adjust",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({mac,delta})});
    const j=await r.json();if(j.ok){const el=document.querySelector(`[data-mac="${mac}"] .remain-val`);if(el)el.textContent=fmt(j.remaining_sec);fetch("/kid-refresh").catch(()=>{});setTimeout(load,3000)}else alert("❌ "+j.error);
  }catch(e){alert("❌ 网络错误")}
}
async function doToggleBypass(mac,enabled){
  try{const r=await fetch("/api/bypass",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({mac,bypass:enabled})});
    const j=await r.json();if(j.ok){fetch("/kid-refresh").catch(()=>{});setTimeout(load,1000)}else alert("❌ "+j.error);
  }catch(e){alert("❌ 网络错误")}
}
const PLATFORM_NAMES=bilibili:"B站",douyin:"抖音",iqiyi:"爱奇艺",youku:"优酷",tencent_video:"腾讯视频",mango:"芒果",kuaishou:"快手",xiaohongshu:"小红书",acfun:"AcFun",unknown:"未知"};
function fmtShort(s,e){const a=new Date(s),b=new Date(e);return `${a.getHours().toString().padStart(2,'0')}:${a.getMinutes().toString().padStart(2,'0')}~${b.getHours().toString().padStart(2,'0')}:${b.getMinutes().toString().padStart(2,'0')}`}
function platformDisplay(p){if(!p||p=="unknown")return "未知";return p.split(",").map(x=>PLATFORM_NAMES[x]||x).join("+")}
async function loadVideoSessions(){
  try{const vc=document.getElementById("videoContent");let html="",totalMin=0;
    for(const[mac,info]of Object.entries(TABLETS)){const r=await fetch(`/api/video-sessions?mac=${mac}`);const j=await r.json();if(!j.ok||!j.sessions||j.sessions.length===0)continue;
      html+=`<h3 style="margin:12px 0 6px;font-size:14px">${info.label}</h3><table><thead><tr><th>时段</th><th>平台</th><th>时长</th><th>分</th></tr></thead><tbody>`;
      for(const s of j.sessions){const durMin=Math.round((new Date(s.session_end)-new Date(s.session_start))/60000);totalMin+=durMin;
        html+=`<tr><td>${fmtShort(s.session_start,s.session_end)}</td><td>${platformDisplay(s.platform)}</td><td>约${durMin}分</td><td>${s.avg_score||0}</td></tr>`}
      html+=`</tbody></table>`}
    if(html){const h=Math.floor(totalMin/60),m=totalMin%60;html+=`<div style="margin-top:10px;font-weight:600">总计: ${h>0?h+"时":""}${m}分</div>`;document.getElementById("videoSection").style.display="";document.getElementById("videoContent").innerHTML=html}
    else document.getElementById("videoSection").style.display="none";
  }catch(e){console.error(e)}
}
loadConfig();load();loadVideoSessions();setInterval(load,60000);setInterval(loadVideoSessions,300000);
</script>
</body>
</html>
"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == "/" or self.path == "/index.html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(HTML.replace("__TABLETS_PLACEHOLDER__", TABLETS_JSON).encode())
                return
            if self.path == "/favicon.ico":
                self.send_response(200)
                self.send_header("Content-Type", "image/x-icon")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                with open("/app/favicon.ico", "rb") as f:
                    self.wfile.write(f.read())
                return
            if self.path == "/api/data":
                self._json(200, _get_cached_data())
                return
            if self.path == "/kid-refresh":
                with _refresh_lock:
                    if _refresh_state["running"]:
                        self._json(200, {"ok": True, "msg": "already running"})
                        return
                threading.Thread(target=_run_refresh, daemon=True).start()
                self._json(200, {"ok": True})
                return
            if self.path == "/health":
                self._json(200, {"ok": True, "last_collect": db.get_last_collect_time(),
                    "cache_age": round(_time.time() - _cache.get("ts", 0), 1), "day_type": _get_day_type()})
                return
            if self.path == "/api/bypass":
                mac = body.get("mac")
                bypass = body.get("bypass")
                if not mac or bypass is None:
                    self._json(400, {"ok": False, "error": "mac and bypass required"}); return
                config_file = os.path.expanduser("~/.config/kid-control/config.json")
                config = {}
                try:
                    with open(config_file) as f: config = json.load(f)
                except: pass
                if bypass:
                    config.setdefault("bypass", {})[mac.upper()] = {"enabled": True, "set_at": datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S")}
                    config.setdefault("limits", {}).setdefault(mac.upper(), {})
                    config["limits"][mac.upper()][datetime.now(CST).strftime("%Y-%m-%d")] = 86400
                else:
                    config.get("bypass", {}).pop(mac.upper(), None)
                    default_limit = 3600
                    try:
                        default_limit = int(cfg_get("DEFAULT_LIMIT", "60")) * 60
                    except: pass
                    config.setdefault("limits", {}).setdefault(mac.upper(), {})
                    config["limits"][mac.upper()][datetime.now(CST).strftime("%Y-%m-%d")] = default_limit
                os.makedirs(os.path.dirname(config_file), exist_ok=True)
                with open(config_file, "w") as f: json.dump(config, f, indent=2)
                with _cache_lock: _cache["ts"] = 0; _cache["data"] = None
                self._json(200, {"ok": True, "mac": mac, "bypass": bypass})
                return
            if self.path == "/api/config":
                cfg = _load_monitor_config()
                self._json(200, {"ok": True, "vacation_mode": cfg.get("vacation_mode", False), "day_type": _get_day_type()})
                return
            if self.path == "/api/settings":
                all_cfg = cfg_get_all()
                # 确保返回所有需要的字段
                for key in ["ROS_HOST","ROS_PORT","ROS_USER","ROS_PASS","MOSDNS_API",
                           "WORKDAY_FREE_START","WORKDAY_FREE_END",
                           "VACATION_FREE_START","VACATION_FREE_END",
                           "DEFAULT_LIMIT","TABLETS","KID_PROFILES"]:
                    if key not in all_cfg:
                        from config import DEFAULTS
                        all_cfg[key] = DEFAULTS.get(key, "")
                self._json(200, {"ok": True, **all_cfg})
                return
            if self.path.startswith("/api/video-sessions"):
                from urllib.parse import urlparse, parse_qs
                params = parse_qs(urlparse(self.path).query)
                mac = params.get("mac", [None])[0]
                date = params.get("date", [None])[0] or datetime.now(CST).strftime("%Y-%m-%d")
                if not mac: self._json(400, {"ok": False, "error": "mac required"}); return
                sessions = db.query_video_sessions(mac, date)
                for s in sessions:
                    if isinstance(s.get("domains"), str):
                        try: s["domains"] = json.loads(s["domains"])
                        except: s["domains"] = []
                self._json(200, {"ok": True, "sessions": sessions, "date": date, "mac": mac})
                return
            self._json(404, {"ok": False, "error": "not found"})
        except Exception as e:
            log.error(f"GET {self.path}: {e}")
            try: self._json(500, {"ok": False, "error": str(e)})
            except: pass

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            if self.path == "/kid-adjust":
                mac = body.get("mac"); delta = int(body.get("delta", 0))
                if not mac: self._json(400, {"ok": False, "error": "mac required"}); return
                today_str = datetime.now(CST).strftime("%Y-%m-%d")
                config_file = os.path.expanduser("~/.config/kid-control/config.json")
                config = {}
                try:
                    with open(config_file) as f: config = json.load(f)
                except: pass
                config.setdefault("limits", {}).setdefault(mac, {})
                current_limit = config["limits"][mac].get(today_str, 3600)
                new_limit = max(0, current_limit + delta)
                config["limits"][mac][today_str] = new_limit
                os.makedirs(os.path.dirname(config_file), exist_ok=True)
                with open(config_file, "w") as f: json.dump(config, f, indent=2)
                usage = 0
                try:
                    with open(STATE_FILE) as f: usage = json.load(f).get("usage", {}).get(mac, 0)
                except: pass
                with _cache_lock: _cache["ts"] = 0; _cache["data"] = None
                self._json(200, {"ok": True, "mac": mac, "limit_sec": new_limit, "usage_sec": usage, "remaining_sec": max(0, new_limit - usage)})
                return
            if self.path == "/api/config":
                vacation = body.get("vacation_mode")
                if vacation is None: self._json(400, {"ok": False, "error": "vacation_mode required"}); return
                cfg = _load_monitor_config()
                cfg["vacation_mode"] = bool(vacation)
                _save_monitor_config(cfg)
                self._json(200, {"ok": True, "vacation_mode": cfg["vacation_mode"], "day_type": _get_day_type()})
                return
            if self.path == "/api/settings":
                # 保存所有配置到数据库
                for key in ["ROS_HOST","ROS_PORT","ROS_USER","ROS_PASS","MOSDNS_API","WORKDAY_FREE_START","WORKDAY_FREE_END","VACATION_FREE_START","VACATION_FREE_END"]:
                    if key in body: cfg_set(key, body[key])
                # JSON 字段单独处理
                for key in ["TABLETS","KID_PROFILES"]:
                    if key in body:
                        try:
                            json.loads(body[key])  # 验证JSON合法
                            cfg_set(key, body[key])
                        except json.JSONDecodeError as e:
                            self._json(400, {"ok": False, "error": f"{key} JSON无效: {e}"})
                            return
                # 清缓存让新配置生效
                with _cache_lock: _cache["ts"] = 0; _cache["data"] = None
                self._json(200, {"ok": True})
                return
            self._json(404, {"ok": False, "error": "not found"})
        except Exception as e:
            log.error(f"POST {self.path}: {e}")
            try: self._json(500, {"ok": False, "error": str(e)})
            except: pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, default=str).encode())

    def log_message(self, *a): pass

if __name__ == "__main__":
    log.info("kid-monitor v4 启动于 :18089 (左右布局 + WebUI设置)")
    db.init_db()
    threading.Thread(target=_scheduled_collect_loop, daemon=True).start()
    threading.Thread(target=_refresh_cache_loop, daemon=True).start()
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer(("0.0.0.0", 18089), Handler).serve_forever()
