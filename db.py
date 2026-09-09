"""kid-monitor SQLite 数据库模块"""
import sqlite3, json, os, threading

DB_PATH = os.environ.get("DB_PATH", "/app/data/kid_monitor.db")

_local = threading.local()

def get_conn():
    """每线程独立连接"""
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        _local.conn = conn
    return _local.conn

def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            mac TEXT NOT NULL,
            name TEXT,
            ip TEXT,
            date TEXT, time TEXT,
            activity TEXT,
            usage_sec INTEGER DEFAULT 0,
            limit_sec INTEGER DEFAULT 0,
            blocked INTEGER DEFAULT 0,
            delta_total_kb INTEGER DEFAULT 0,
            delta_tcp_kb INTEGER DEFAULT 0,
            delta_udp_kb INTEGER DEFAULT 0,
            tcp_conns INTEGER DEFAULT 0,
            udp_conns INTEGER DEFAULT 0,
            long_udp INTEGER DEFAULT 0,
            dns_video_hits INTEGER DEFAULT 0,
            dns_game_hits INTEGER DEFAULT 0,
            dns_video_domains TEXT DEFAULT '[]',
            dns_game_domains TEXT DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_snap_mac_date ON snapshots(mac, date);
        CREATE INDEX IF NOT EXISTS idx_snap_ts ON snapshots(ts);
        CREATE TABLE IF NOT EXISTS realtime (
            mac TEXT PRIMARY KEY,
            ts TEXT,
            ip TEXT,
            tcp_bytes INTEGER DEFAULT 0,
            udp_bytes INTEGER DEFAULT 0,
            tcp_conns INTEGER DEFAULT 0,
            udp_conns INTEGER DEFAULT 0,
            long_udp INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS video_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            date TEXT NOT NULL,
            mac TEXT NOT NULL,
            ip TEXT,
            download_bytes INTEGER DEFAULT 0,
            upload_bytes INTEGER DEFAULT 0,
            dns_total_queries INTEGER DEFAULT 0,
            video_domain_hits INTEGER DEFAULT 0,
            game_domain_hits INTEGER DEFAULT 0,
            video_domains TEXT DEFAULT '[]',
            video_platforms TEXT DEFAULT '[]',
            video_score INTEGER DEFAULT 0,
            video_status TEXT DEFAULT 'NONE',
            activity_type TEXT DEFAULT 'none'
        );
        CREATE INDEX IF NOT EXISTS idx_vw_mac_date ON video_windows(mac, date);
        CREATE INDEX IF NOT EXISTS idx_vw_ts ON video_windows(ts);
        CREATE TABLE IF NOT EXISTS video_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            date TEXT NOT NULL,
            session_start TEXT NOT NULL,
            session_end TEXT NOT NULL,
            platform TEXT DEFAULT 'unknown',
            total_download INTEGER DEFAULT 0,
            avg_score INTEGER DEFAULT 0,
            domains TEXT DEFAULT '[]',
            status TEXT DEFAULT 'active',
            updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS vs_mac_date ON video_sessions(mac, date);
    """)
    conn.commit()

# ============ 配置管理 ============
def get_config(key, default=None):
    """获取配置项"""
    conn = get_conn()
    row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    if row is None:
        return default
    return row[0]

def set_config(key, value):
    """设置配置项"""
    conn = get_conn()
    conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()

def get_config_json(key, default=None):
    """获取JSON配置项"""
    val = get_config(key)
    if val is None:
        return default if default is not None else {}
    try:
        return json.loads(val)
    except:
        return default if default is not None else {}

def set_config_json(key, value):
    """设置JSON配置项"""
    set_config(key, json.dumps(value, ensure_ascii=False))

def get_all_config():
    """获取所有配置"""
    conn = get_conn()
    rows = conn.execute("SELECT key, value FROM config").fetchall()
    result = {}
    for key, value in rows:
        try:
            result[key] = json.loads(value)
        except:
            result[key] = value
    return result

def store_snapshots(entries):
    """批量写入采样数据"""
    if not entries:
        return
    conn = get_conn()
    conn.executemany("""
        INSERT INTO snapshots (ts, mac, name, ip, date, time, activity,
            usage_sec, limit_sec, blocked, delta_total_kb, delta_tcp_kb, delta_udp_kb,
            tcp_conns, udp_conns, long_udp, dns_video_hits, dns_game_hits,
            dns_video_domains, dns_game_domains)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, [(
        e.get("ts"), e["mac"], e.get("name"), e.get("ip"),
        e.get("date"), e.get("time"), e.get("activity", "idle"),
        e.get("usage_sec", 0), e.get("limit_sec", 0),
        1 if e.get("blocked") else 0,
        e.get("delta_total_kb", 0), e.get("delta_tcp_kb", 0), e.get("delta_udp_kb", 0),
        e.get("tcp_conns", 0), e.get("udp_conns", 0), e.get("long_udp", 0),
        e.get("dns_video_hits", 0), e.get("dns_game_hits", 0),
        json.dumps(e.get("dns_video_domains", []), ensure_ascii=False),
        json.dumps(e.get("dns_game_domains", []), ensure_ascii=False),
    ) for e in entries])
    conn.commit()

def store_realtime(mac, info):
    """更新实时状态"""
    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO realtime (mac, ts, ip, tcp_bytes, udp_bytes,
            tcp_conns, udp_conns, long_udp, total_bytes)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (mac, info.get("ts"), info.get("ip"),
          info.get("tcp_bytes", 0), info.get("udp_bytes", 0),
          info.get("tcp_conns", 0), info.get("udp_conns", 0),
          info.get("long_udp", 0), info.get("total_bytes", 0)))
    conn.commit()

def get_last_collect_time():
    conn = get_conn()
    row = conn.execute("SELECT value FROM meta WHERE key='last_collect'").fetchone()
    return row[0] if row else None

def set_last_collect_time(ts):
    conn = get_conn()
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_collect', ?)", (ts,))
    conn.commit()

def query_week_snapshots(days=7):
    """查询最近 N 天的全部采样记录"""
    conn = get_conn()
    rows = conn.execute("""
        SELECT ts, mac, name, ip, date, time, activity, usage_sec, limit_sec,
               blocked, delta_total_kb, delta_tcp_kb, delta_udp_kb,
               tcp_conns, udp_conns, long_udp,
               dns_video_hits, dns_game_hits, dns_video_domains, dns_game_domains
        FROM snapshots WHERE date >= date('now', ?) ORDER BY ts
    """, (f"-{days} days",)).fetchall()
    return [dict(zip([
        "ts","mac","name","ip","date","time","activity","usage_sec","limit_sec",
        "blocked","delta_total_kb","delta_tcp_kb","delta_udp_kb",
        "tcp_conns","udp_conns","long_udp",
        "dns_video_hits","dns_game_hits","dns_video_domains","dns_game_domains"
    ], r)) for r in rows]

def query_daily_stats(mac, days=7):
    """按设备+日期聚合统计"""
    conn = get_conn()
    rows = conn.execute("""
        SELECT date,
               COUNT(*) as samples,
               MAX(usage_sec) as usage_sec,
               SUM(delta_tcp_kb) as tcp_kb,
               SUM(delta_udp_kb) as udp_kb,
               SUM(blocked) as blocked_count
        FROM snapshots WHERE mac = ? AND date >= date('now', ?)
        GROUP BY date ORDER BY date
    """, (mac, f"-{days} days")).fetchall()

    result = {}
    for r in rows:
        date = r[0]
        acts = dict(conn.execute("""
            SELECT activity, COUNT(*) FROM snapshots
            WHERE mac=? AND date=? GROUP BY activity
        """, (mac, date)).fetchall())
        result[date] = {
            "samples": r[1], "usage_sec": r[2],
            "tcp_kb": r[3] or 0, "udp_kb": r[4] or 0,
            "activities": acts, "blocked_count": r[5] or 0
        }
    return result

def query_recent_history(limit=200):
    """最近 N 条采样明细"""
    conn = get_conn()
    rows = conn.execute("""
        SELECT ts, mac, name, date, time, activity, usage_sec,
               delta_tcp_kb, delta_udp_kb, blocked,
               dns_video_hits, dns_game_hits, dns_video_domains, dns_game_domains
        FROM snapshots ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    return [dict(zip([
        "ts","mac","name","date","time","activity","usage_sec",
        "delta_tcp_kb","delta_udp_kb","blocked",
        "dns_video_hits","dns_game_hits","dns_video_domains","dns_game_domains"
    ], r)) for r in reversed(rows)]

def query_all_realtime():
    conn = get_conn()
    rows = conn.execute("SELECT mac, ts, ip, tcp_bytes, udp_bytes, tcp_conns, udp_conns, long_udp, total_bytes FROM realtime").fetchall()
    return {r[0]: dict(zip(["ts","ip","tcp_bytes","udp_bytes","tcp_conns","udp_conns","long_udp","total_bytes"], r[1:])) for r in rows}

def cleanup_old_data(keep_days=90):
    """清理旧数据"""
    conn = get_conn()
    conn.execute("DELETE FROM snapshots WHERE date < date('now', ?)", (f"-{keep_days} days",))
    conn.execute("DELETE FROM video_windows WHERE date < date('now', ?)", (f"-{keep_days} days",))
    conn.execute("DELETE FROM video_sessions WHERE date < date('now', ?)", (f"-{keep_days} days",))
    conn.commit()

def query_video_sessions(mac, date):
    """查询某设备某天的视频活动 Session"""
    conn = get_conn()
    rows = conn.execute("""
        SELECT session_start, session_end, platform, total_download,
               avg_score, domains, status
        FROM video_sessions
        WHERE mac = ? AND date = ? ORDER BY session_start
    """, (mac, date)).fetchall()
    return [dict(zip([
        "session_start", "session_end", "platform", "total_download",
        "avg_score", "domains", "status"
    ], r)) for r in rows]

def query_video_daily_summary(mac, days=7):
    """查询最近 N 天每天的视频活动时长"""
    conn = get_conn()
    rows = conn.execute("""
        SELECT date,
               COUNT(*) as session_count,
               SUM(avg_score) as total_score,
               SUM(total_download) as total_download,
               MIN(session_start) as first_start,
               MAX(session_end) as last_end
        FROM video_sessions
        WHERE mac = ? AND date >= date('now', ?) AND status = 'active'
        GROUP BY date ORDER BY date
    """, (mac, f"-{days} days")).fetchall()
    return [dict(zip([
        "date", "session_count", "total_score", "total_download",
        "first_start", "last_end"
    ], r)) for r in rows]

def close_video_sessions():
    """关闭所有活跃 session（用于新一天重置）"""
    conn = get_conn()
    conn.execute("UPDATE video_sessions SET status='closed' WHERE status='active'")
    conn.commit()
