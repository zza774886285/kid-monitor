#!/usr/bin/env python3
"""
kid_control.py - 平板上网控制（Kid Control disabled 模式 + 开关联动）
通过 ROS Kid Control disabled 标志控制设备上网
开关模式：开=可以上网，关=不可上网，与时间管控规则联动
"""
import json, os, sys
from datetime import datetime, timezone, timedelta
import paramiko

# ============ 配置 ============
CST = timezone(timedelta(hours=8))

# 平板配置（从环境变量读取，JSON 格式）
# 格式: {"MAC": {"ip": "IP", "name": "名称", "profile_id": ID, "profile_name": "名称"}}
DEFAULT_TABLETS = '{"80:5F:C5:31:4D:5E":{"ip":"","name":"平板1","profile_id":0,"profile_name":"kid-apple"},"A0:DE:0F:45:2D:39":{"ip":"","name":"平板2","profile_id":1,"profile_name":"kid-huawei"}}'
TABLETS_RAW = os.environ.get("TABLETS", DEFAULT_TABLETS)
TABLETS = json.loads(TABLETS_RAW)

# 防火墙地址列表名称（备用）
BLOCK_LIST = "block-tablet"

# ROS 连接配置（从环境变量读取）
ROS_HOST = os.environ.get("ROS_HOST", "")
ROS_PORT = int(os.environ.get("ROS_PORT", "8022"))
ROS_USER = os.environ.get("ROS_USER", "")
ROS_PASS = os.environ.get("ROS_PASS", "")

# 时间配置
WORKDAY_FREE_START = os.environ.get("WORKDAY_FREE_START", "19:10")
WORKDAY_FREE_END = os.environ.get("WORKDAY_FREE_END", "21:00")
VACATION_FREE_START = os.environ.get("VACATION_FREE_START", "21:30")
VACATION_FREE_END = os.environ.get("VACATION_FREE_END", "08:00")

# 配置文件路径
CONFIG_FILE = os.path.expanduser("~/.config/kid-control/config.json")
STATE_FILE = os.path.expanduser("~/.config/kid-control/state.json")

# ============ 工具函数 ============
def log(msg):
    print(f"[{datetime.now(CST).strftime('%H:%M:%S')}] {msg}")

def load_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def is_chinese_holiday():
    try:
        import chinese_calendar
        today = datetime.now(CST).date()
        return not chinese_calendar.is_workday(today)
    except ImportError:
        return datetime.now(CST).weekday() >= 5

def get_day_type():
    cfg = load_config()
    if cfg.get("vacation_mode", False):
        return "vacation"
    return "holiday" if is_chinese_holiday() else "workday"

def parse_time(time_str):
    h, m = map(int, time_str.split(":"))
    return h * 60 + m

def is_workday_block_time():
    now = datetime.now(CST)
    start = parse_time(WORKDAY_FREE_START)
    end = parse_time(WORKDAY_FREE_END)
    now_min = now.hour * 60 + now.minute
    return start <= now_min < end

def is_vacation_free_time():
    now = datetime.now(CST)
    start = parse_time(VACATION_FREE_START)
    end = parse_time(VACATION_FREE_END)
    now_min = now.hour * 60 + now.minute
    if start > end:
        return now_min >= start or now_min < end
    else:
        return start <= now_min < end

def should_block_by_time(day_type):
    """根据时间规则判断是否应该封禁"""
    if day_type == "workday":
        if is_workday_block_time():
            return True, f"工作日学习时段 ({WORKDAY_FREE_START}-{WORKDAY_FREE_END})"
        else:
            return False, "工作日非学习时段"
    else:
        if is_vacation_free_time():
            return False, f"免费时段 ({VACATION_FREE_START}-{VACATION_FREE_END})"
        else:
            return True, f"管控时段 (8:00-{VACATION_FREE_END})"

def get_switch_state(mac):
    """获取平板的开关状态：True=开（可以上网），False=关（不可上网），None=未设置"""
    config = load_config()
    switch_cfg = config.get("switch", {})
    mac_upper = mac.upper()
    if mac_upper in switch_cfg:
        return switch_cfg[mac_upper].get("enabled", False)
    return None

# ============ ROS 操作 ============
def ros_connect():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ROS_HOST, port=ROS_PORT, username=ROS_USER, password=ROS_PASS,
                timeout=10, banner_timeout=3, auth_timeout=3,
                allow_agent=False, look_for_keys=False)
    return ssh

def ros_cmd(ssh, cmd):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
    out = stdout.read().decode(errors='ignore')
    err = stderr.read().decode(errors='ignore')
    return out, err

def set_kid_control_disabled(ssh, profile_id, disabled):
    """设置 Kid Control profile 的 disabled 状态
    disabled=True → Kid Control 不管理设备 → 能上网
    disabled=False → Kid Control 管理设备 → 禁止上网
    """
    cmd = f'/ip kid-control set {profile_id} disabled={"yes" if disabled else "no"}'
    out, err = ros_cmd(ssh, cmd)
    if err and 'no such command' not in err:
        log(f"  设置 Kid Control profile {profile_id} disabled={disabled}: {err.strip()}")
    else:
        log(f"  Kid Control profile {profile_id} → disabled={'yes' if disabled else 'no'}")

def is_kid_control_disabled(ssh, profile_id):
    """检查 Kid Control profile 是否 disabled"""
    out, _ = ros_cmd(ssh, '/ip kid-control print')
    for line in out.split('\n'):
        if f' {profile_id} ' in line or line.startswith(f'{profile_id} '):
            return ' X ' in line  # X 表示 DISABLED
    return False

def block_ip(ssh, ip, name):
    """备用：将 IP 加入地址列表（封禁）"""
    out, _ = ros_cmd(ssh, f'/ip firewall address-list print where list="{BLOCK_LIST}" and address="{ip}"')
    if ip not in out:
        cmd = f'/ip firewall address-list add list="{BLOCK_LIST}" address="{ip}" comment="{name}"'
        ros_cmd(ssh, cmd)
        log(f"  封禁 {name} ({ip})")
    else:
        log(f"  {name} ({ip}) 已在封禁列表中")
    import time
    for i in range(3):
        ros_cmd(ssh, f'/ip firewall connection remove [find src-address={ip} or dst-address={ip}]')
        time.sleep(0.5)
    return True

def unblock_ip(ssh, ip, name):
    """备用：将 IP 从地址列表移除（解封）"""
    out, _ = ros_cmd(ssh, f'/ip firewall address-list print where list="{BLOCK_LIST}" and address="{ip}"')
    if ip in out:
        for line in out.split('\n'):
            if ip in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    item_id = parts[0]
                    ros_cmd(ssh, f'/ip firewall address-list remove {item_id}')
                    log(f"  解封 {name} ({ip})")
                    return True
    log(f"  {name} ({ip}) 不在封禁列表中")
    return False

# ============ 主逻辑 ============
def main():
    now = datetime.now(CST)
    day_type = get_day_type()
    log(f"开始执行 | 日期类型: {day_type} | 时间: {now.strftime('%H:%M:%S')}")
    
    try:
        ssh = ros_connect()
        log("ROS 连接成功")
        
        for mac, info in TABLETS.items():
            ip = info["ip"]
            name = info["name"]
            profile_id = info["profile_id"]
            switch = get_switch_state(mac)
            time_block, time_reason = should_block_by_time(day_type)
            
            if switch is True:
                # 开关=开：跟随时间规则
                should_block = time_block
                log(f"  {name}: 开关=开 | {time_reason} → {'禁止' if should_block else '允许'}上网")
            elif switch is False:
                # 开关=关：强制封禁，不看时间规则
                should_block = True
                log(f"  {name}: 开关=关 → 强制禁止上网")
            else:
                # 未设置开关：跟随时间规则
                should_block = time_block
                log(f"  {name}: 未设开关 | {time_reason} → {'禁止' if should_block else '允许'}上网")
            
            # 设置 Kid Control disabled 状态
            # disabled=yes → Kid Control 不管理 → 能上网
            # disabled=no → Kid Control 管理 → 禁止上网
            set_kid_control_disabled(ssh, profile_id, disabled=not should_block)
            
            # 备用：同时设置 address-list
            if should_block:
                block_ip(ssh, ip, name)
            else:
                unblock_ip(ssh, ip, name)
        
        ssh.close()
        log("完成")
        
    except Exception as e:
        log(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
