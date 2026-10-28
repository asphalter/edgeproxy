import os
import time
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import db

logger = logging.getLogger("edgeproxy.stats")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# Candidate paths for Caddy access log file
DEFAULT_LOG_PATHS = [
    os.environ.get("EDGEPROXY_ACCESS_LOG_PATH", ""),
    "/data/caddy/logs/access.jsonl",
    "/data/access.jsonl",
    "/etc/edgeproxy/logs/access.jsonl",
    "/opt/edgeproxy/server/logs/access.jsonl",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "access.jsonl"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "access.jsonl"),
]


def resolve_log_path() -> Optional[str]:
    """Find the first existing path for access log file or return default."""
    for path in DEFAULT_LOG_PATHS:
        if path and os.path.exists(path):
            return path
    env_path = os.environ.get("EDGEPROXY_ACCESS_LOG_PATH")
    if env_path:
        return env_path
    return "/data/caddy/logs/access.jsonl"


def parse_caddy_log_line(line: str) -> Optional[Tuple[Dict[str, Any], str, int]]:
    """
    Parse a JSON log line from Caddy and extract fields for access_logs and bandwidth_stats.
    Returns: (log_dict, bucket_ts, bytes_out) or None if line is invalid.
    """
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)
        # Caddy access logs format
        req = data.get("request", {})
        ts_val = data.get("ts")
        if isinstance(ts_val, (int, float)):
            dt = datetime.fromtimestamp(ts_val, tz=timezone.utc)
            ts_iso = dt.strftime("%Y-%m-%d %H:%M:%S")
            bucket_ts = dt.strftime("%Y-%m-%d %H:00:00")
        elif isinstance(ts_val, str):
            ts_iso = ts_val.replace("T", " ")[:19]
            bucket_ts = ts_iso[:14] + "00:00"
        else:
            now_dt = datetime.now(timezone.utc)
            ts_iso = now_dt.strftime("%Y-%m-%d %H:%M:%S")
            bucket_ts = now_dt.strftime("%Y-%m-%d %H:00:00")

        host = req.get("host", "").lower().split(":")[0]
        uri = req.get("uri", "/")

        # Discard Rathole client polling, telemetry and sync requests to prevent access log flooding
        if uri.startswith("/api/v1/client"):
            return None

        status = int(data.get("status", 200))

        # Client IP extraction (considering headers if present)
        client_ip = req.get("client_ip", "")
        if not client_ip:
            headers = req.get("headers", {})
            xff = headers.get("X-Forwarded-For", [])
            if xff and isinstance(xff, list) and len(xff) > 0:
                client_ip = xff[0].split(",")[0].strip()
            elif not client_ip:
                remote_ip = req.get("remote_ip", "")
                client_ip = remote_ip.split(":")[0] if remote_ip else "127.0.0.1"

        bytes_out = int(data.get("size", 0))
        duration_s = float(data.get("duration", 0.0))
        duration_ms = round(duration_s * 1000.0, 2)

        method = req.get("method", "GET")
        headers = req.get("headers", {})
        email = ""
        x_auth_email = headers.get("X-Auth-Request-Email", [])
        if x_auth_email and isinstance(x_auth_email, list) and len(x_auth_email) > 0:
            email = x_auth_email[0].strip()
        elif "user_id" in data:
            email = str(data.get("user_id") or "").strip()

        user_agent = ""
        ua_list = headers.get("User-Agent", [])
        if ua_list and isinstance(ua_list, list) and len(ua_list) > 0:
            user_agent = ua_list[0][:255]

        referer = ""
        ref_list = headers.get("Referer", [])
        if ref_list and isinstance(ref_list, list) and len(ref_list) > 0:
            referer = ref_list[0][:255]

        # Filter out internal/empty hosts if not relevant
        if not host:
            return None

        log_dict = {
            "ts": ts_iso,
            "host": host,
            "method": method,
            "uri": uri[:255],
            "status": status,
            "email": email[:255],
            "remote_ip": client_ip[:45],
            "bytes": bytes_out,
            "bytes_out": bytes_out,
            "duration_ms": duration_ms,
            "user_agent": user_agent,
            "referer": referer
        }

        return log_dict, bucket_ts, bytes_out

    except Exception:
        return None


def get_stored_offset() -> Tuple[int, int]:
    """Retrieve last ingested file offset and inode from settings."""
    settings = db.get_settings()
    try:
        offset = int(settings.get("stats_last_offset", "0"))
    except ValueError:
        offset = 0

    try:
        inode = int(settings.get("stats_last_inode", "0"))
    except ValueError:
        inode = 0

    return offset, inode


def process_access_log_file(log_path: Optional[str] = None) -> int:
    """
    Read new lines from access log file incrementally, parse them,
    and persist records to SQLite database.
    """
    path = log_path or resolve_log_path()
    if not path or not os.path.exists(path):
        return 0

    try:
        stat_info = os.stat(path)
        current_inode = stat_info.st_ino
        file_size = stat_info.st_size
    except Exception as e:
        logger.debug(f"Unable to read file stat for {path}: {e}")
        return 0

    last_offset, last_inode = get_stored_offset()

    # Log rotation handling: if inode changed or size is smaller than offset, reset to start
    if current_inode != last_inode or file_size < last_offset:
        last_offset = 0

    if file_size == last_offset:
        return 0  # No new data to process

    parsed_logs: List[Dict[str, Any]] = []
    bandwidth_buckets: Dict[Tuple[str, str], Dict[str, int]] = {}

    new_offset = last_offset

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_offset)
            while True:
                line = f.readline()
                if not line:
                    break
                new_offset = f.tell()
                res = parse_caddy_log_line(line)
                if res:
                    log_entry, bucket_ts, b_out = res
                    parsed_logs.append(log_entry)

                    key = (log_entry["host"], bucket_ts)
                    if key not in bandwidth_buckets:
                        bandwidth_buckets[key] = {"bytes_out": 0, "requests": 0}
                    bandwidth_buckets[key]["bytes_out"] += b_out
                    bandwidth_buckets[key]["requests"] += 1

                # Cap batch size to avoid spikes in memory consumption
                if len(parsed_logs) >= 5000:
                    break

    except Exception as e:
        logger.error(f"Error reading log file {path}: {e}")
        return 0

    # Save to database
    if parsed_logs:
        try:
            db.insert_access_logs_batch(parsed_logs)

            bw_list = []
            for (h, b_ts), vals in bandwidth_buckets.items():
                bw_list.append({
                    "host": h,
                    "bucket_ts": b_ts,
                    "bytes_out": vals["bytes_out"],
                    "requests": vals["requests"],
                })
            db.upsert_bandwidth_batch(bw_list)

            # Accumulate and increment per-host outbound traffic (30-day auto-reset counter)
            host_traffic_acc: Dict[str, Dict[str, int]] = {}
            for entry in parsed_logs:
                h = entry["host"]
                b = entry.get("bytes_out", 0)
                if h not in host_traffic_acc:
                    host_traffic_acc[h] = {"bytes_out": 0, "requests": 0}
                host_traffic_acc[h]["bytes_out"] += b
                host_traffic_acc[h]["requests"] += 1

            for h, hdata in host_traffic_acc.items():
                db.increment_host_traffic(h, hdata["bytes_out"], hdata["requests"])
        except Exception as e:
            logger.error(f"Error persisting access logs and bandwidth stats to DB: {e}")
            return 0

    # Update offset and inode in DB
    db.set_setting("stats_last_offset", str(new_offset))
    db.set_setting("stats_last_inode", str(current_inode))

    return len(parsed_logs)


class LogIngester:
    def __init__(self, interval_seconds: float = 5.0, purge_interval_seconds: float = 3600.0):
        self.interval = interval_seconds
        self.purge_interval = purge_interval_seconds
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_purge_time = 0.0

    async def _loop(self):
        logger.info("[stats] Log ingestion background worker started.")
        while self._running:
            try:
                await asyncio.to_thread(process_access_log_file)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[stats] Exception in log ingester worker: {e}")

            # Automated retention purging (once every hour or configured purge_interval)
            now = time.time()
            if now - self._last_purge_time >= self.purge_interval:
                try:
                    deleted = await asyncio.to_thread(db.purge_old_access_logs)
                    logger.info(f"[stats] Automated log purging completed: {deleted} old records removed.")
                    self._last_purge_time = now
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"[stats] Exception during automated log purge: {e}")

            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break
        logger.info("[stats] Log ingestion background worker stopped.")

    def start(self):
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop())

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()


ingester_instance = LogIngester(interval_seconds=5.0)
