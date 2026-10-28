import os
import sqlite3
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

# Resolution of SQLite database path.
# NOTE: Do NOT use "/data/edgeproxy.db" based on existence of "/data":
# "/data" is reserved for shared Caddy logs and certificates (caddy_data volume).
# The SQLite database resides stably in "/app/manager/edgeproxy.db"
# (persisted on host at "/opt/edgeproxy/server/manager/edgeproxy.db").
DB_PATH = os.environ.get("EDGEPROXY_DB_PATH")
if not DB_PATH:
    if os.path.exists("/data") and os.path.isdir("/data"):
        DB_PATH = "/data/edgeproxy.db"
    else:
        DB_PATH = os.path.join(os.path.dirname(__file__), "edgeproxy.db")


def get_db_connection() -> sqlite3.Connection:
    """Establish connection to SQLite database with WAL mode and busy timeout."""
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    """Initialize database schema, tables, indexes, and run migrations."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        upstream TEXT NOT NULL,
        tls_insecure_skip_verify INTEGER DEFAULT 0,
        rathole_port INTEGER UNIQUE NOT NULL,
        rathole_token TEXT NOT NULL,
        policy TEXT DEFAULT 'google_oauth',
        security_headers INTEGER DEFAULT 1,
        enabled INTEGER DEFAULT 1,
        service_token TEXT DEFAULT '',
        link_state TEXT DEFAULT 'down',
        link_last_seen TEXT DEFAULT '',
        link_remote_addr TEXT DEFAULT '',
        link_up_since TEXT DEFAULT '',
        allowed_emails TEXT DEFAULT '',
        ws_read_timeout INTEGER DEFAULT 30,
        ws_write_timeout INTEGER DEFAULT 30,
        ws_idle_timeout INTEGER DEFAULT 60,
        ws_flush_interval INTEGER DEFAULT -1,
        ws_dial_timeout INTEGER DEFAULT 10,
        ws_response_header_timeout INTEGER DEFAULT 30
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sync_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        label TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS client_heartbeats (
        client_name TEXT PRIMARY KEY,
        last_seen TEXT NOT NULL,
        remote_ip TEXT,
        uptime_seconds INTEGER DEFAULT 0,
        version TEXT,
        hostname TEXT,
        latency_ms REAL DEFAULT 0.0
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS client_status (
        client_name TEXT PRIMARY KEY,
        last_seen TEXT NOT NULL,
        remote_ip TEXT,
        uptime_seconds INTEGER DEFAULT 0,
        version TEXT,
        hostname TEXT,
        latency_ms REAL DEFAULT 0.0
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS client_latency_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_name TEXT NOT NULL,
        latency_ms REAL NOT NULL,
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_client_latency_client ON client_latency_stats(client_name);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_client_latency_recorded ON client_latency_stats(recorded_at);")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS client_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_name TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_client_logs_client ON client_logs(client_name);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_client_logs_created ON client_logs(created_at);")

    # Access logs table (ingested from Caddy JSON logs)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT '',
        created_at TEXT DEFAULT '',
        host TEXT NOT NULL,
        method TEXT DEFAULT 'GET',
        uri TEXT NOT NULL,
        status INTEGER NOT NULL,
        email TEXT DEFAULT '',
        remote_ip TEXT NOT NULL,
        bytes INTEGER DEFAULT 0,
        bytes_out INTEGER DEFAULT 0,
        duration_ms REAL DEFAULT 0.0,
        user_agent TEXT DEFAULT '',
        referer TEXT DEFAULT ''
    );
    """)

    # Hourly aggregated bandwidth and request metrics
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS bandwidth_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        bucket_ts TEXT NOT NULL,
        bytes_out INTEGER DEFAULT 0,
        requests INTEGER DEFAULT 0,
        UNIQUE(host, bucket_ts)
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_bw_bucket ON bandwidth_stats(bucket_ts);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_bw_host ON bandwidth_stats(host);")

    # Column migrations
    cursor.execute("PRAGMA table_info(hosts);")
    existing_host_cols = {col["name"] for col in cursor.fetchall()}
    if "service_token" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN service_token TEXT DEFAULT '';")
    if "link_state" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN link_state TEXT DEFAULT 'down';")
    if "link_last_seen" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN link_last_seen TEXT DEFAULT '';")
    if "link_remote_addr" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN link_remote_addr TEXT DEFAULT '';")
    if "link_up_since" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN link_up_since TEXT DEFAULT '';")
    if "allowed_emails" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN allowed_emails TEXT DEFAULT '';")

    if "ws_read_timeout" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN ws_read_timeout INTEGER DEFAULT 30;")
    if "ws_write_timeout" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN ws_write_timeout INTEGER DEFAULT 30;")
    if "ws_idle_timeout" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN ws_idle_timeout INTEGER DEFAULT 60;")
    if "ws_flush_interval" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN ws_flush_interval INTEGER DEFAULT -1;")
    if "ws_dial_timeout" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN ws_dial_timeout INTEGER DEFAULT 10;")
    if "ws_response_header_timeout" not in existing_host_cols:
        cursor.execute("ALTER TABLE hosts ADD COLUMN ws_response_header_timeout INTEGER DEFAULT 30;")

    # Migrations for client_status and client_heartbeats
    for tbl in ("client_status", "client_heartbeats"):
        try:
            cursor.execute(f"PRAGMA table_info({tbl});")
            tbl_cols = {col["name"] for col in cursor.fetchall()}
            if tbl_cols and "latency_ms" not in tbl_cols:
                cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN latency_ms REAL DEFAULT 0.0;")
        except Exception:
            pass

    cursor.execute("PRAGMA table_info(access_logs);")
    existing_acc_cols = {col["name"] for col in cursor.fetchall()}
    if "ts" not in existing_acc_cols:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN ts TEXT DEFAULT '';")
        cursor.execute("UPDATE access_logs SET ts = COALESCE(created_at, datetime('now')) WHERE ts IS NULL OR ts = '';")
    if "created_at" not in existing_acc_cols:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN created_at TEXT DEFAULT '';")
        cursor.execute("UPDATE access_logs SET created_at = COALESCE(ts, datetime('now')) WHERE created_at IS NULL OR created_at = '';")
    if "bytes_out" not in existing_acc_cols:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN bytes_out INTEGER DEFAULT 0;")
        cursor.execute("UPDATE access_logs SET bytes_out = COALESCE(bytes, 0) WHERE bytes_out IS NULL OR bytes_out = 0;")
    if "bytes" not in existing_acc_cols:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN bytes INTEGER DEFAULT 0;")
        cursor.execute("UPDATE access_logs SET bytes = COALESCE(bytes_out, 0) WHERE bytes IS NULL OR bytes = 0;")
    if "method" not in existing_acc_cols:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN method TEXT DEFAULT 'GET';")
    if "email" not in existing_acc_cols:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN email TEXT DEFAULT '';")
    if "user_agent" not in existing_acc_cols:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN user_agent TEXT DEFAULT '';")
    if "referer" not in existing_acc_cols:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN referer TEXT DEFAULT '';")

    conn.commit()

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_ts ON access_logs(ts);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_host ON access_logs(host);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_status ON access_logs(status);")
    conn.commit()

    # One-time migration to standardize WebSocket / session timeouts
    cursor.execute("SELECT value FROM settings WHERE key = 'ws_timeouts_standardized';")
    ws_std_row = cursor.fetchone()
    if not ws_std_row or ws_std_row["value"] != "1":
        cursor.execute("""
            UPDATE hosts SET
                ws_read_timeout = 30,
                ws_write_timeout = 30,
                ws_idle_timeout = 60,
                ws_flush_interval = -1,
                ws_dial_timeout = 10,
                ws_response_header_timeout = 30;
        """)
        cursor.execute("""
            UPDATE hosts SET
                ws_read_timeout = 0,
                ws_write_timeout = 0,
                ws_idle_timeout = 3600,
                ws_flush_interval = 1
            WHERE domain LIKE 'ide.%';
        """)
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ws_timeouts_standardized', '1');")
        conn.commit()

    # Initial seeding if database is empty
    seed_database(cursor, conn)

    # Ensure oauth2_cookie_secret is generated if absent or empty
    cursor.execute("SELECT value FROM settings WHERE key = 'oauth2_cookie_secret';")
    row = cursor.fetchone()
    if not row or not row["value"] or str(row["value"]).strip() == "":
        generated_cookie_secret = secrets.token_urlsafe(32)
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('oauth2_cookie_secret', ?);", (generated_cookie_secret,))
        try:
            cursor.execute("UPDATE settings SET oauth2_cookie_secret = ? WHERE oauth2_cookie_secret IS NULL OR oauth2_cookie_secret = '';", (generated_cookie_secret,))
        except sqlite3.OperationalError:
            pass
        conn.commit()

    # Ensure default sync token exists if sync_tokens table is empty
    cursor.execute("SELECT COUNT(*) FROM sync_tokens;")
    if cursor.fetchone()[0] == 0:
        token = secrets.token_hex(24)
        cursor.execute("""
            INSERT INTO sync_tokens (token, label, created_at)
            VALUES (?, ?, ?)
        """, (token, "Default Backend Agent", datetime.now(timezone.utc).isoformat()))
        conn.commit()

    # Clean legacy keys from settings if present
    cursor.execute("DELETE FROM settings WHERE key IN ('totp_issuer', 'smtp_host', 'smtp_port', 'smtp_username', 'smtp_password', 'smtp_sender');")

    # Ensure default log retention setting exists
    cursor.execute("SELECT value FROM settings WHERE key = 'log_retention_days';")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO settings (key, value) VALUES ('log_retention_days', '30');")

    conn.commit()
    conn.close()


def seed_database(cursor: sqlite3.Cursor, conn: sqlite3.Connection):
    """Seed initial defaults for settings and sync tokens if database is newly created."""
    cursor.execute("SELECT COUNT(*) FROM settings WHERE key = 'root_domain';")
    count_root = cursor.fetchone()[0]

    if count_root == 0:
        root_domain = os.environ.get("DOMAIN", "edge.mpv.cx")
        acme_email = os.environ.get("ACME_EMAIL", "matteo.piva@gmail.com")
        rathole_public_host = os.environ.get("RATHOLE_PUBLIC_HOST", "edge.mpv.cx")
        default_settings = {
            "root_domain": root_domain,
            "acme_email": acme_email,
            "rathole_public_host": rathole_public_host,
            "rathole_public_port": "2333",
            "rathole_transport": "noise",
            "google_oauth_enabled": "0",
            "google_client_id": "",
            "google_client_secret": "",
            "google_allowed_emails": "matteo.piva@gmail.com",
            "oauth2_cookie_secret": secrets.token_urlsafe(32),
        }
        for k, v in default_settings.items():
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?);", (k, v))
        conn.commit()


def get_all_hosts() -> List[Dict[str, Any]]:
    """Retrieve all configured hosts ordered by domain."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM hosts ORDER BY domain ASC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_host_by_id(host_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single host by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM hosts WHERE id = ?;", (host_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def add_host(
    domain: str,
    upstream: str,
    tls_insecure_skip_verify: int,
    policy: str = "google_oauth",
    security_headers: int = 1,
    allowed_emails: str = "",
    service_token: str = "",
    ws_read_timeout: int = 30,
    ws_write_timeout: int = 30,
    ws_idle_timeout: int = 60,
    ws_flush_interval: int = -1,
    ws_dial_timeout: int = 10,
    ws_response_header_timeout: int = 30
) -> Dict[str, Any]:
    """Add a new host reverse tunnel record with assigned Rathole port."""
    if policy not in ("bypass", "service_token"):
        policy = "google_oauth"
    if policy == "service_token" and not service_token:
        service_token = secrets.token_hex(16)
    conn = get_db_connection()
    cursor = conn.cursor()

    # Determine next free Rathole binding port starting from 8001
    cursor.execute("SELECT rathole_port FROM hosts ORDER BY rathole_port ASC;")
    used_ports = {row["rathole_port"] for row in cursor.fetchall()}
    next_port = 8001
    while next_port in used_ports:
        next_port += 1

    token = secrets.token_hex(20)
    now_iso = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO hosts (
            domain, upstream, tls_insecure_skip_verify, rathole_port, rathole_token, policy,
            security_headers, allowed_emails, enabled, service_token, link_state,
            link_last_seen, link_remote_addr, link_up_since,
            ws_read_timeout, ws_write_timeout, ws_idle_timeout,
            ws_flush_interval, ws_dial_timeout, ws_response_header_timeout
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'down', '', '', '', ?, ?, ?, ?, ?, ?);
    """, (
        domain, upstream, tls_insecure_skip_verify, next_port, token, policy,
        security_headers, allowed_emails, service_token,
        ws_read_timeout, ws_write_timeout, ws_idle_timeout,
        ws_flush_interval, ws_dial_timeout, ws_response_header_timeout
    ))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return get_host_by_id(new_id)


def update_host(
    host_id: int,
    domain: str,
    upstream: str,
    tls_insecure_skip_verify: int,
    policy: str = "google_oauth",
    security_headers: int = 1,
    allowed_emails: str = "",
    service_token: str = "",
    ws_read_timeout: Optional[int] = None,
    ws_write_timeout: Optional[int] = None,
    ws_idle_timeout: Optional[int] = None,
    ws_flush_interval: Optional[int] = None,
    ws_dial_timeout: Optional[int] = None,
    ws_response_header_timeout: Optional[int] = None
):
    """Update existing host settings and timeouts."""
    if policy not in ("bypass", "service_token"):
        policy = "google_oauth"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE hosts
        SET domain = ?,
            upstream = ?,
            tls_insecure_skip_verify = ?,
            policy = ?,
            security_headers = ?,
            allowed_emails = ?,
            service_token = ?,
            ws_read_timeout = COALESCE(?, ws_read_timeout),
            ws_write_timeout = COALESCE(?, ws_write_timeout),
            ws_idle_timeout = COALESCE(?, ws_idle_timeout),
            ws_flush_interval = COALESCE(?, ws_flush_interval),
            ws_dial_timeout = COALESCE(?, ws_dial_timeout),
            ws_response_header_timeout = COALESCE(?, ws_response_header_timeout)
        WHERE id = ?;
    """, (
        domain, upstream, tls_insecure_skip_verify, policy, security_headers,
        allowed_emails, service_token,
        ws_read_timeout, ws_write_timeout, ws_idle_timeout,
        ws_flush_interval, ws_dial_timeout, ws_response_header_timeout,
        host_id
    ))
    conn.commit()
    conn.close()


def update_host_link_status(host_id: int, link_state: str, remote_addr: str = "", up_since: str = ""):
    """Update live link state and telemetry for a specific host tunnel."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    if link_state in ("up", "connected"):
        cursor.execute("""
            UPDATE hosts
            SET link_state = ?,
                link_last_seen = ?,
                link_remote_addr = CASE WHEN ? != '' THEN ? ELSE link_remote_addr END,
                link_up_since = CASE WHEN link_up_since IS NULL OR link_up_since = '' OR ? != '' THEN COALESCE(NULLIF(?, ''), ?) ELSE link_up_since END
            WHERE id = ?;
        """, (link_state, now_iso, remote_addr, remote_addr, up_since, up_since, now_iso, host_id))
    else:
        cursor.execute("""
            UPDATE hosts
            SET link_state = ?,
                link_last_seen = ?,
                link_up_since = ''
            WHERE id = ?;
        """, (link_state, now_iso, host_id))
    conn.commit()
    conn.close()


def upsert_client_status(client_name: str, remote_ip: str, uptime_seconds: int = 0, version: str = "", hostname: str = "", latency_ms: float = 0.0):
    """Upsert client status and heartbeat telemetry with latency measurement."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        lat = round(float(latency_ms), 1)
    except (ValueError, TypeError):
        lat = 0.0

    cursor.execute("""
        INSERT INTO client_status (client_name, last_seen, remote_ip, uptime_seconds, version, hostname, latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(client_name) DO UPDATE SET
            last_seen = excluded.last_seen,
            remote_ip = excluded.remote_ip,
            uptime_seconds = excluded.uptime_seconds,
            version = excluded.version,
            hostname = excluded.hostname,
            latency_ms = excluded.latency_ms;
    """, (client_name, now_iso, remote_ip, uptime_seconds, version, hostname, lat))

    cursor.execute("""
        INSERT INTO client_heartbeats (client_name, last_seen, remote_ip, uptime_seconds, version, hostname, latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(client_name) DO UPDATE SET
            last_seen = excluded.last_seen,
            remote_ip = excluded.remote_ip,
            uptime_seconds = excluded.uptime_seconds,
            version = excluded.version,
            hostname = excluded.hostname,
            latency_ms = excluded.latency_ms;
    """, (client_name, now_iso, remote_ip, uptime_seconds, version, hostname, lat))
    conn.commit()
    conn.close()


def record_client_heartbeat(client_name: str, remote_ip: str, uptime_seconds: int = 0, version: str = "", hostname: str = "", latency_ms: float = 0.0):
    """Record heartbeat telemetry received from a remote client agent (alias for upsert_client_status)."""
    upsert_client_status(client_name, remote_ip, uptime_seconds, version, hostname, latency_ms)


def record_client_latency(client_name: str, latency_ms: float):
    """Record client latency observation into client_latency_stats for time-series charts."""
    try:
        lat = round(float(latency_ms), 1)
    except (ValueError, TypeError):
        lat = 0.0
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO client_latency_stats (client_name, latency_ms, recorded_at)
        VALUES (?, ?, datetime('now'));
    """, (client_name, lat))
    conn.commit()
    conn.close()


def get_client_latency_chart_data(client_name: Optional[str] = None, hours: int = 24) -> Dict[str, Any]:
    """Retrieve time-series latency stats aggregated for Chart.js line charts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    h = abs(int(hours)) if hours else 24
    param = f"-{h}"
    query = """
        SELECT recorded_at, latency_ms, client_name
        FROM client_latency_stats
        WHERE recorded_at >= datetime('now', ? || ' hours')
    """
    params: List[Any] = [param]
    if client_name:
        query += " AND client_name = ?"
        params.append(client_name)
    query += " ORDER BY recorded_at ASC;"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    labels = []
    values = []
    points = []
    for r in rows:
        ts = r["recorded_at"]
        val = round(float(r["latency_ms"]), 1)
        labels.append(ts)
        values.append(val)
        points.append({
            "timestamp": ts,
            "latency_ms": val,
            "client_name": r["client_name"]
        })

    return {
        "labels": labels,
        "values": values,
        "points": points,
        "hours": h,
        "client_name": client_name
    }


def get_active_clients() -> List[Dict[str, Any]]:
    """Return all recorded client statuses ordered by last seen timestamp."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT client_name, last_seen, remote_ip, uptime_seconds, version, hostname, latency_ms
        FROM client_status
        ORDER BY last_seen DESC;
    """)
    rows = cursor.fetchall()
    if not rows:
        cursor.execute("""
            SELECT client_name, last_seen, remote_ip, uptime_seconds, version, hostname, latency_ms
            FROM client_heartbeats
            ORDER BY last_seen DESC;
        """)
        rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_client_logs(client_name: str, logs: List[Any]):
    """Insert log entries received from client sync agents."""
    if not logs:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rows_to_insert = []
    for item in logs:
        if isinstance(item, dict):
            lvl = str(item.get("level", "info"))
            msg = str(item.get("message", ""))
            ts = item.get("created_at") or now_ts
        elif isinstance(item, str):
            lvl = "info"
            msg = item
            ts = now_ts
        else:
            lvl = "info"
            msg = str(item)
            ts = now_ts
        if msg.strip():
            rows_to_insert.append((client_name.strip(), lvl[:20], msg.strip(), ts))

    if rows_to_insert:
        cursor.executemany("""
            INSERT INTO client_logs (client_name, level, message, created_at)
            VALUES (?, ?, ?, ?);
        """, rows_to_insert)
    conn.commit()
    conn.close()


def get_recent_client_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve recent client logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, client_name, level, message, created_at
        FROM client_logs
        ORDER BY created_at DESC, id DESC
        LIMIT ?;
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def delete_host(host_id: int):
    """Delete a host tunnel record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM hosts WHERE id = ?;", (host_id,))
    conn.commit()
    conn.close()


def toggle_host_status(host_id: int) -> int:
    """Toggle enabled status of a host tunnel."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT enabled FROM hosts WHERE id = ?;", (host_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return 0
    new_status = 0 if row["enabled"] else 1
    cursor.execute("UPDATE hosts SET enabled = ? WHERE id = ?;", (new_status, host_id))
    conn.commit()
    conn.close()
    return new_status


def get_settings() -> Dict[str, str]:
    """Retrieve all system settings as a key-value dictionary."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings;")
    rows = cursor.fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}


def set_setting(key: str, value: str):
    """Insert or update a setting value."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?);", (key, value))
    conn.commit()
    conn.close()


def update_settings(new_settings: Dict[str, str]):
    """Update multiple system settings atomically."""
    conn = get_db_connection()
    cursor = conn.cursor()
    for k, v in new_settings.items():
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?);", (k, v))
    conn.commit()
    conn.close()


def get_sync_tokens() -> List[Dict[str, Any]]:
    """Retrieve all authorized client sync tokens."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sync_tokens ORDER BY created_at ASC, rowid ASC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_or_create_default_sync_token() -> str:
    """Retrieve default sync token or create one if absent."""
    tokens = get_sync_tokens()
    if tokens:
        return tokens[0]["token"]
    conn = get_db_connection()
    cursor = conn.cursor()
    token = secrets.token_hex(24)
    cursor.execute("""
        INSERT INTO sync_tokens (token, label, created_at)
        VALUES (?, ?, ?);
    """, (token, "Default Backend Agent", datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    return token


def validate_sync_token(token: str) -> bool:
    """Validate whether a client bearer sync token exists."""
    if not token or not token.strip():
        return False
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT token FROM sync_tokens WHERE token = ?;", (token.strip(),))
    row = cursor.fetchone()
    conn.close()
    return row is not None


def get_recent_access_logs(limit: int = 50, filter_host: Optional[str] = None, host: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve recent HTTP access logs recorded from Caddy."""
    target_host = host if host is not None else filter_host
    conn = get_db_connection()
    cursor = conn.cursor()
    if target_host:
        cursor.execute("""
            SELECT id, COALESCE(NULLIF(ts, ''), created_at) as ts, COALESCE(NULLIF(created_at, ''), ts) as created_at,
                   host, method, uri, status, email, remote_ip,
                   COALESCE(bytes, bytes_out) as bytes, COALESCE(bytes_out, bytes) as bytes_out,
                   duration_ms, user_agent, referer
            FROM access_logs
            WHERE host = ?
            ORDER BY id DESC
            LIMIT ?;
        """, (target_host, limit))
    else:
        cursor.execute("""
            SELECT id, COALESCE(NULLIF(ts, ''), created_at) as ts, COALESCE(NULLIF(created_at, ''), ts) as created_at,
                   host, method, uri, status, email, remote_ip,
                   COALESCE(bytes, bytes_out) as bytes, COALESCE(bytes_out, bytes) as bytes_out,
                   duration_ms, user_agent, referer
            FROM access_logs
            ORDER BY id DESC
            LIMIT ?;
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_access_logs_batch(logs: List[Dict[str, Any]]):
    """Insert a batch of parsed Caddy access logs into database."""
    if not logs:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    rows = []
    for l in logs:
        ts_val = l.get("ts") or l.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        b_val = int(l.get("bytes", l.get("bytes_out", 0)))
        rows.append((
            ts_val,
            ts_val,
            l.get("host", ""),
            l.get("method", "GET"),
            l.get("uri", ""),
            int(l.get("status", 200)),
            l.get("email", ""),
            l.get("remote_ip", ""),
            b_val,
            b_val,
            float(l.get("duration_ms", 0.0)),
            l.get("user_agent", ""),
            l.get("referer", "")
        ))
    cursor.executemany("""
        INSERT INTO access_logs (ts, created_at, host, method, uri, status, email, remote_ip, bytes, bytes_out, duration_ms, user_agent, referer)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, rows)
    conn.commit()
    conn.close()


def upsert_bandwidth_batch(bandwidth_entries: List[Dict[str, Any]]):
    """Aggregate bandwidth and request counters per host bucket."""
    if not bandwidth_entries:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    for entry in bandwidth_entries:
        cursor.execute("""
            INSERT INTO bandwidth_stats (host, bucket_ts, bytes_out, requests)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(host, bucket_ts) DO UPDATE SET
                bytes_out = bytes_out + excluded.bytes_out,
                requests = requests + excluded.requests;
        """, (
            entry["host"],
            entry["bucket_ts"],
            int(entry.get("bytes_out", 0)),
            int(entry.get("requests", 0))
        ))
    conn.commit()
    conn.close()


def get_bandwidth_timeline(hours: int = 24, filter_host: Optional[str] = None) -> Dict[str, Any]:
    """Return aggregated bandwidth timeline data formatted for UI charts."""
    conn = get_db_connection()
    cursor = conn.cursor()

    group_expr = "strftime('%Y-%m-%d %H:00', bucket_ts)"

    if filter_host:
        query = f"""
        SELECT {group_expr} as bucket, host, SUM(bytes_out) as total_bytes, SUM(requests) as total_requests
        FROM bandwidth_stats
        WHERE host = ? AND bucket_ts >= datetime('now', '-' || ? || ' hours')
        GROUP BY bucket, host
        ORDER BY bucket ASC
        """
        cursor.execute(query, (filter_host, hours))
    else:
        query = f"""
        SELECT {group_expr} as bucket, host, SUM(bytes_out) as total_bytes, SUM(requests) as total_requests
        FROM bandwidth_stats
        WHERE bucket_ts >= datetime('now', '-' || ? || ' hours')
        GROUP BY bucket, host
        ORDER BY bucket ASC
        """
        cursor.execute(query, (hours,))

    rows = cursor.fetchall()
    conn.close()

    buckets_set = set()
    hosts_data: Dict[str, Dict[str, int]] = {}

    for row in rows:
        b = row["bucket"]
        h = row["host"]
        val = int(row["total_bytes"] or 0)
        buckets_set.add(b)
        if h not in hosts_data:
            hosts_data[h] = {}
        hosts_data[h][b] = val

    sorted_buckets = sorted(list(buckets_set))

    datasets = []
    if filter_host:
        data_points = [hosts_data.get(filter_host, {}).get(b, 0) for b in sorted_buckets]
        datasets.append({
            "label": filter_host,
            "data": data_points
        })
    else:
        if not hosts_data and sorted_buckets:
            datasets.append({"label": "All hosts", "data": [0] * len(sorted_buckets)})
        else:
            for h in sorted(hosts_data.keys()):
                datasets.append({
                    "label": h,
                    "data": [hosts_data[h].get(b, 0) for b in sorted_buckets]
                })

    return {
        "labels": sorted_buckets,
        "datasets": datasets
    }


def purge_old_access_logs(days: Optional[int] = None) -> int:
    """Purge access logs and bandwidth stats older than retention threshold (days)."""
    if days is None:
        settings = get_settings()
        try:
            days = int(settings.get("log_retention_days", 30))
        except (ValueError, TypeError):
            days = 30
    elif days <= 0:
        return 0

    param = f"-{abs(days)}"
    conn = get_db_connection()
    cursor = conn.cursor()
    deleted_total = 0
    try:
        cursor.execute("DELETE FROM access_logs WHERE created_at < datetime('now', ? || ' days');", (param,))
        del_logs = cursor.rowcount if cursor.rowcount > 0 else 0
        cursor.execute("DELETE FROM bandwidth_stats WHERE bucket_ts < datetime('now', ? || ' days');", (param,))
        del_bw = cursor.rowcount if cursor.rowcount > 0 else 0
        cursor.execute("DELETE FROM client_latency_stats WHERE recorded_at < datetime('now', ? || ' days');", (param,))
        del_latency = cursor.rowcount if cursor.rowcount > 0 else 0
        deleted_total = del_logs + del_bw + del_latency
        conn.commit()
    finally:
        conn.close()
    return deleted_total


def export_backup_data() -> Dict[str, Any]:
    """Export complete database configuration snapshot as a JSON dictionary."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM hosts ORDER BY id ASC;")
    hosts = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT key, value FROM settings ORDER BY key ASC;")
    settings = {r["key"]: r["value"] for r in cursor.fetchall()}

    cursor.execute("SELECT token, label, created_at FROM sync_tokens ORDER BY created_at ASC, rowid ASC;")
    sync_tokens = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return {
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
        "settings": settings,
        "sync_tokens": sync_tokens,
    }


def import_backup_data(backup: Dict[str, Any]):
    """Restore database configuration from a backup dictionary atomically."""
    if not isinstance(backup, dict):
        raise ValueError("Invalid JSON structure: expected root object.")

    hosts = backup.get("hosts")
    settings = backup.get("settings")
    sync_tokens = backup.get("sync_tokens")

    if hosts is None or settings is None or sync_tokens is None:
        raise ValueError("Malformed JSON structure: invalid hosts, settings, or sync_tokens.")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Atomic transaction
        cursor.execute("BEGIN TRANSACTION;")

        # 1. Restore settings
        cursor.execute("DELETE FROM settings;")
        for k, v in settings.items():
            cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?);", (k, str(v)))

        # 2. Restore sync tokens
        cursor.execute("DELETE FROM sync_tokens;")
        for st in sync_tokens:
            token = st.get("token")
            label = st.get("label", "Restored Agent")
            created_at = st.get("created_at") or datetime.now(timezone.utc).isoformat()
            if token:
                cursor.execute("""
                    INSERT INTO sync_tokens (token, label, created_at)
                    VALUES (?, ?, ?);
                """, (token, label, created_at))

        # 3. Restore hosts
        cursor.execute("DELETE FROM hosts;")
        for h in hosts:
            domain = h.get("domain")
            upstream = h.get("upstream")
            if not domain or not upstream:
                continue

            rathole_port = h.get("rathole_port")
            rathole_token = h.get("rathole_token") or secrets.token_hex(20)
            policy = h.get("policy", "google_oauth")
            sec_headers = int(h.get("security_headers", 1))
            skip_verify = int(h.get("tls_insecure_skip_verify", 0))
            enabled = int(h.get("enabled", 1))
            service_token = h.get("service_token", "")
            allowed_emails = h.get("allowed_emails", "")
            ws_read_timeout = h.get("ws_read_timeout", 30)
            ws_write_timeout = h.get("ws_write_timeout", 30)
            ws_idle_timeout = h.get("ws_idle_timeout", 60)
            ws_flush_interval = h.get("ws_flush_interval", -1)
            ws_dial_timeout = h.get("ws_dial_timeout", 10)
            ws_response_header_timeout = h.get("ws_response_header_timeout", 30)

            cursor.execute("""
                INSERT INTO hosts (
                    domain, upstream, tls_insecure_skip_verify, rathole_port, rathole_token,
                    policy, security_headers, enabled, service_token, allowed_emails,
                    link_state, link_last_seen, link_remote_addr, link_up_since,
                    ws_read_timeout, ws_write_timeout, ws_idle_timeout,
                    ws_flush_interval, ws_dial_timeout, ws_response_header_timeout
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'down', '', '', '', ?, ?, ?, ?, ?, ?);
            """, (
                domain, upstream, skip_verify, rathole_port, rathole_token,
                policy, sec_headers, enabled, service_token, allowed_emails,
                ws_read_timeout, ws_write_timeout, ws_idle_timeout,
                ws_flush_interval, ws_dial_timeout, ws_response_header_timeout
            ))

        cursor.execute("COMMIT;")
    except Exception:
        cursor.execute("ROLLBACK;")
        conn.close()
        raise
    finally:
        conn.close()
