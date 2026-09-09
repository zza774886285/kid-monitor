"""kid-monitor 配置 - 从数据库读取"""
import json, os
import db

# 默认值
DEFAULTS = {
    "ROS_HOST": "10.1.1.250",
    "ROS_PORT": "8022",
    "ROS_USER": "kirin",
    "ROS_PASS": "890405",
    "MOSDNS_API": "http://10.1.1.140:1053/api/v1/query/audit",
    "TABLETS": "{}",
    "KID_PROFILES": "{}",
    "SERVER_URL": "http://localhost:18089",
    "STATE_FILE": os.path.expanduser("~/.config/kid-control/state.json"),
    "HISTORY_FILE": os.path.expanduser("~/.config/kid-control/history.jsonl"),
    "WORKDAY_FREE_START": "19:10",
    "WORKDAY_FREE_END": "21:00",
    "VACATION_FREE_START": "21:30",
    "VACATION_FREE_END": "08:00",
    "DEFAULT_LIMIT": "60",  # 默认每日限额(分钟)
}

def get(key, default=""):
    """获取配置项，优先从数据库读取"""
    db.init_db()
    val = db.get_config(key)
    if val is not None:
        return val
    env_val = os.environ.get(key)
    if env_val is not None:
        return env_val
    return DEFAULTS.get(key, default)

def get_int(key, default=0):
    val = get(key, str(default))
    try:
        return int(val)
    except:
        return default

def get_json(key):
    val = get(key, "{}")
    try:
        return json.loads(val) if val else {}
    except:
        return {}

def set(key, value):
    """设置配置项到数据库"""
    db.init_db()
    db.set_config(key, value)

def get_all():
    """获取所有配置"""
    db.init_db()
    result = {}
    for key in list(DEFAULTS.keys()):
        val = get(key)
        result[key] = val if val is not None else DEFAULTS.get(key, "")
    return result

# 兼容旧代码
def _init_legacy():
    globals()["ROS_HOST"] = get("ROS_HOST")
    globals()["ROS_PORT"] = get_int("ROS_PORT", 8022)
    globals()["ROS_USER"] = get("ROS_USER")
    globals()["ROS_PASS"] = get("ROS_PASS")
    globals()["MOSDNS_API"] = get("MOSDNS_API")
    globals()["SERVER_URL"] = get("SERVER_URL")
    globals()["STATE_FILE"] = get("STATE_FILE")
    globals()["HISTORY_FILE"] = get("HISTORY_FILE")
    globals()["TABLETS"] = get_json("TABLETS")
    globals()["KID_PROFILES"] = get_json("KID_PROFILES")

_init_legacy()
