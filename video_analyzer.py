"""
video_analyzer.py - 视频活动识别层
读取域名分类规则 + 流量阈值配置，对 DNS + 流量进行联合评分，管理 Video Session。
"""
import json, os, re
from datetime import datetime, timezone, timedelta
import db

CONFIG_DIR = os.environ.get("CONFIG_DIR", os.path.dirname(os.path.abspath(__file__)))
CST = timezone(timedelta(hours=8))

def load_json(path):
    with open(path) as f:
        return json.load(f)

# ============ 域名分类 ============
def classify_domains(dns_domains):
    """
    对 DNS 域名列表进行分类。
    返回: {category: [matched_domains]}
    """
    rules = load_json(os.path.join(CONFIG_DIR, "domain_rules.json"))
    result = {cat: [] for cat in ["VIDEO", "VIDEO_CDN", "GAME", "GAME_CDN", "AD", "SOCIAL", "UPDATE", "OTHER"]}
    for domain in dns_domains:
        domain_lower = domain.lower().strip()
        matched = False
        for cat in ["VIDEO", "VIDEO_CDN", "GAME", "GAME_CDN", "AD", "SOCIAL", "UPDATE"]:
            for pattern in rules.get(cat, []):
                pattern_lower = pattern.lower()
                if _domain_match(domain_lower, pattern_lower):
                    result[cat].append(domain_lower)
                    matched = True
                    break
            if matched:
                break
        if not matched:
            result["OTHER"].append(domain_lower)
    return result

def _domain_match(domain, pattern):
    """域名匹配，支持通配符"""
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .bilivideo.com
        return domain.endswith(suffix) or domain == pattern[2:]
    if "/" in pattern:
        parts = pattern.split("/", 1)
        return domain == parts[0] or domain.endswith("." + parts[0])
    return domain == pattern or domain.endswith("." + pattern)

# ============ 评分 ============
def calc_score(classified, download_bytes, prev_status=None, next_status=None):
    """
    计算 video_score (0-100)
    classified: classify_domains 的返回值
    download_bytes: 5分钟下载字节数
    prev_status / next_status: 前/后窗口的 status (用于连续性加分)
    """
    thresholds = load_json(os.path.join(CONFIG_DIR, "video_thresholds.json"))
    score_dns = thresholds.get("score_dns", {})
    score_traffic = thresholds.get("score_traffic", {})
    cont_bonus = thresholds.get("score_continuity", 10)
    traffic_mb = download_bytes / (1024 * 1024)

    # DNS 证据
    dns_score = 0
    has_video_dns = False
    if classified.get("VIDEO"):
        dns_score += score_dns.get("video_hit", 30)
        has_video_dns = True
    if classified.get("VIDEO_CDN"):
        dns_score += score_dns.get("video_cdn_hit", 40)
        has_video_dns = True
    if classified.get("VIDEO") and classified.get("VIDEO_CDN"):
        dns_score += score_dns.get("multi_domain_bonus", 10)

    # 游戏 DNS 也记（用于 mixed 检测）
    has_game_dns = bool(classified.get("GAME")) or bool(classified.get("GAME_CDN"))

    # 流量证据（取最高档，不累加）
    traffic_score = 0
    traffic_t = thresholds.get("traffic_thresholds_mb", {})
    if traffic_mb >= traffic_t.get("strong", 150):
        traffic_score = score_traffic.get("strong", 40)
    elif traffic_mb >= traffic_t.get("medium", 60):
        traffic_score = score_traffic.get("medium", 30)
    elif traffic_mb >= traffic_t.get("suspect", 30):
        traffic_score = score_traffic.get("suspect", 20)
    elif traffic_mb >= traffic_t.get("weak", 10):
        traffic_score = score_traffic.get("weak", 10)

    # 连续性
    cont_score = 0
    if prev_status in ("ACTIVE", "PROBABLE", "SUSPECT"):
        cont_score += cont_bonus
    if next_status in ("ACTIVE", "PROBABLE", "SUSPECT"):
        cont_score += cont_bonus

    total = min(100, dns_score + traffic_score + cont_score)

    # 判定状态
    if total >= 70:
        status = "ACTIVE"
    elif total >= 50:
        status = "PROBABLE"
    elif total >= 30:
        status = "SUSPECT"
    else:
        status = "NONE"

    # 活动类型判定
    activity_type = "none"
    if has_video_dns and has_game_dns:
        activity_type = "mixed"
    elif has_video_dns:
        activity_type = "video"
    elif has_game_dns:
        activity_type = "game"
    elif status != "NONE":
        activity_type = "unknown"

    # 识别平台
    platforms = _detect_platforms(classified)

    return {
        "score": total,
        "status": status,
        "activity_type": activity_type,
        "platforms": platforms,
        "dns_video_hits": len(classified.get("VIDEO", [])) + len(classified.get("VIDEO_CDN", [])),
        "dns_game_hits": len(classified.get("GAME", [])) + len(classified.get("GAME_CDN", [])),
        "dns_score": dns_score,
        "traffic_score": traffic_score,
        "continuity_score": cont_score,
    }

def _detect_platforms(classified):
    """从分类结果识别平台"""
    PLATFORM_MAP = {
        "bilibili": ["bilibili.com", "bilivideo.com", "bstatic.com", "bilibili.cc", "bilibili.tv"],
        "douyin": ["douyin.com", "douyincdn.com", "douyinpic.com", "douyinliving.com", "snssdk.com", "amemv.com"],
        "iqiyi": ["iqiyi.com", "iqiyi.cn"],
        "youku": ["youku.com", "youku.tv"],
        "tencent_video": ["v.qq.com", "qq.com/video", "gtimg.com", "qpic.cn"],
        "mango": ["mgtv.com"],
        "kuaishou": ["kuaishouzt.com"],
        "xiaohongshu": ["xiaohongshu.com", "xhscdn.com"],
        "acfun": ["acfun.cn"],
    }
    platforms = set()
    all_domains = []
    for cat in ("VIDEO", "VIDEO_CDN"):
        all_domains.extend(classified.get(cat, []))
    for platform, keywords in PLATFORM_MAP.items():
        for domain in all_domains:
            for kw in keywords:
                if kw in domain:
                    platforms.add(platform)
                    break
    return sorted(platforms) if platforms else ["unknown"]

# ============ Session 管理 ============
def update_sessions(mac, today_str, window_ts, score, activity_type, platforms, download_bytes):
    """
    更新 video_sessions。
    - 如果当前窗口 score >= 30 且有活跃 session → 合并
    - 如果当前窗口 score >= 30 且没有活跃 session → 新建
    - 如果当前窗口 score < 30 → 检查 gap 容忍，否则关闭 session
    """
    conn = db.get_conn()
    thresholds = load_json(os.path.join(CONFIG_DIR, "video_thresholds.json"))
    gap_tolerance = thresholds.get("session_gap_tolerance", 2)

    # 获取当前设备今天的最新 session
    current = conn.execute("""
        SELECT id, session_start, session_end, total_download, avg_score, domains, platform
        FROM video_sessions
        WHERE mac = ? AND date = ? AND status = 'active'
        ORDER BY session_end DESC LIMIT 1
    """, (mac, today_str)).fetchone()

    if score >= 30:
        if current:
            # 合并到现有 session
            sid = current[0]
            session_start = current[1]
            old_download = current[3] or 0
            old_avg = current[4] or 0
            existing_domains = json.loads(current[5]) if current[5] else []
            existing_platform = current[6] or "unknown"

            # 更新
            new_download = old_download + download_bytes
            # 滑动平均
            count = conn.execute("SELECT COUNT(*) FROM video_windows WHERE mac=? AND date=? AND ts>=?",
                                 (mac, today_str, session_start)).fetchone()[0]
            new_avg = int((old_avg * (count - 1) + score) / count) if count > 0 else score
            # 合并平台
            all_platforms = set(existing_platform.split(",")) if existing_platform != "unknown" else set()
            all_platforms.update(platforms)
            all_platforms.discard("unknown")
            platform_str = ",".join(sorted(all_platforms)) if all_platforms else "unknown"

            # 合并域名
            for d in platforms:
                if d not in existing_domains and d != "unknown":
                    existing_domains.append(d)

            conn.execute("""
                UPDATE video_sessions SET session_end=?, total_download=?, avg_score=?,
                platform=?, domains=?, updated_at=? WHERE id=?
            """, (window_ts, new_download, new_avg, platform_str,
                  json.dumps(existing_domains), datetime.now(CST).isoformat(), sid))
            conn.commit()
            return sid
        else:
            # 新建 session
            platform_str = ",".join(platforms) if platforms and platforms != ["unknown"] else "unknown"
            cursor = conn.execute("""
                INSERT INTO video_sessions (mac, date, session_start, session_end,
                    platform, total_download, avg_score, domains, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
            """, (mac, today_str, window_ts, window_ts, platform_str, download_bytes, score,
                  json.dumps(platforms), datetime.now(CST).isoformat()))
            conn.commit()
            return cursor.lastrowid
    else:
        # 当前窗口不是视频活动
        if current:
            # 检查是否在 gap 容忍内
            last_end = current[2]  # session_end
            try:
                last_dt = datetime.fromisoformat(last_end).replace(tzinfo=CST)
                now_dt = datetime.fromisoformat(window_ts).replace(tzinfo=CST)
                gap_minutes = (now_dt - last_dt).total_seconds() / 60
                # 每个窗口是5分钟，gap_tolerance 个窗口 = gap_tolerance * 5 分钟
                if gap_minutes <= gap_tolerance * 5:
                    return current[0]  # 还在容忍范围内，不关闭
            except Exception:
                pass

            # 超过容忍范围，关闭 session
            conn.execute("""
                UPDATE video_sessions SET status='closed', updated_at=? WHERE id=?
            """, (datetime.now(CST).isoformat(), current[0]))
            conn.commit()
        return None

# ============ 主分析入口 ============
def analyze(ts, devices):
    """
    主入口：对一批设备在当前5分钟窗口的数据进行分析。

    ts: ISO格式时间戳
    devices: dict[mac] = {
        "ip": "10.1.1.x",
        "name": "设备名",
        "download_bytes": int,
        "upload_bytes": int,
        "dns_domains": ["bilibili.com", ...],
        "dns_video_hits": int,  # 原始统计
        "dns_game_hits": int,   # 原始统计
        "dns_video_domains": [...],  # 原始字段
        "dns_game_domains": [...],   # 原始字段
    }
    """
    now = datetime.now(CST)
    today_str = now.strftime("%Y-%m-%d")
    results = {}

    for mac, data in devices.items():
        dns_domains = data.get("dns_domains", [])
        # 补充原始 DNS 域名到分析列表
        for d in data.get("dns_video_domains", []):
            if d not in dns_domains:
                dns_domains.append(d)
        for d in data.get("dns_game_domains", []):
            if d not in dns_domains:
                dns_domains.append(d)

        # 域名分类
        classified = classify_domains(dns_domains)

        # 评分
        result = calc_score(classified, data.get("download_bytes", 0))

        # 写入 video_windows
        conn = db.get_conn()
        conn.execute("""
            INSERT INTO video_windows
                (ts, date, mac, ip, download_bytes, upload_bytes,
                 dns_total_queries, video_domain_hits, game_domain_hits,
                 video_domains, video_platforms, video_score, video_status, activity_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, today_str, mac, data.get("ip"),
              data.get("download_bytes", 0), data.get("upload_bytes", 0),
              len(dns_domains),
              result.get("dns_video_hits", 0), result.get("dns_game_hits", 0),
              json.dumps(classified.get("VIDEO", []) + classified.get("VIDEO_CDN", [])),
              json.dumps(result.get("platforms", [])),
              result["score"], result["status"], result.get("activity_type", "none")))
        conn.commit()

        # 更新 session
        session_id = update_sessions(
            mac, today_str, ts,
            result["score"], result.get("activity_type", "none"),
            result.get("platforms", []), data.get("download_bytes", 0))

        result["session_id"] = session_id
        results[mac] = result

    return results
