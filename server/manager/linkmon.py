import os
import re
import socket
import http.client
import subprocess
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import db
from config_engine import clean_service_name, _UnixSocketHTTPConnection

logger = logging.getLogger("edgeproxy.linkmon")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

_RE_ESTABLISHED = re.compile(r"Control channel established.*service=[\"']?([a-zA-Z0-9_\-]+)[\"']?", re.IGNORECASE)
_RE_CLOSED = re.compile(r"(?:Connection closed|connection reset|Failed to read control channel|Service not exist).*service=[\"']?([a-zA-Z0-9_\-]+)[\"']?", re.IGNORECASE)
_RE_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)")

PODMAN_SOCKETS = [
    "/run/podman/podman.sock",
    f"/run/user/{os.getuid()}/podman/podman.sock" if hasattr(os, "getuid") else "",
    "/var/run/docker.sock"
]


def has_available_podman_socket() -> bool:
    """Check if any podman/docker control socket is accessible."""
    return any(sock and os.path.exists(sock) for sock in PODMAN_SOCKETS)


def is_local_tcp_port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """Verify if local service port is responding in the shared pod network namespace."""
    if not port:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def fetch_rathole_logs(tail: int = 200) -> str:
    """Attempt to read recent Rathole container logs via Podman socket if present."""
    if not has_available_podman_socket():
        return ""

    container_names = ["edgeproxy-rathole", "rathole"]

    # Attempt 1: Direct local log file (All-in-One supervisor container)
    local_log_candidates = [
        "/var/log/rathole.log",
        "/data/rathole/rathole.log",
        "/tmp/rathole.log"
    ]
    for log_file in local_log_candidates:
        if os.path.exists(log_file) and os.path.getsize(log_file) > 0:
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    return "".join(lines[-tail:])
            except Exception:
                pass

    # Attempt 2: Podman API socket (for pod-based legacy setups)
    for sock in PODMAN_SOCKETS:
        if sock and os.path.exists(sock):
            for cname in container_names:
                for path in [
                    f"/v4.0.0/libpod/containers/{cname}/logs?stdout=true&stderr=true&tail={tail}",
                    f"/containers/{cname}/logs?stdout=1&stderr=1&tail={tail}"
                ]:
                    try:
                        conn = _UnixSocketHTTPConnection(sock, timeout=3)
                        conn.request("GET", path)
                        resp = conn.getresponse()
                        if resp.status == 200:
                            data = resp.read()
                            conn.close()
                            # Podman multiplexed stream header stripping (8 bytes header per frame)
                            cleaned = []
                            offset = 0
                            while offset < len(data):
                                if offset + 8 <= len(data) and data[offset] in (1, 2):
                                    frame_len = int.from_bytes(data[offset+4:offset+8], byteorder="big")
                                    frame_data = data[offset+8:offset+8+frame_len]
                                    cleaned.append(frame_data.decode("utf-8", errors="ignore"))
                                    offset += 8 + frame_len
                                else:
                                    cleaned.append(data[offset:].decode("utf-8", errors="ignore"))
                                    break
                            return "".join(cleaned)
                        conn.close()
                    except Exception:
                        pass

    return ""


def parse_service_states(logs_content: str) -> Dict[str, Dict[str, Any]]:
    """Parse log entries to determine service tunnel status (up/down)."""
    states: Dict[str, Dict[str, Any]] = {}

    lines = logs_content.splitlines()
    for line in lines:
        match_est = _RE_ESTABLISHED.search(line)
        if match_est:
            svc = match_est.group(1).strip()
            ts_match = _RE_TIMESTAMP.search(line)
            ts = ts_match.group(1) if ts_match else datetime.now(timezone.utc).isoformat()
            states[svc] = {
                "state": "up",
                "up_since": ts,
                "last_seen": ts,
                "remote_addr": ""
            }
            continue

        match_closed = _RE_CLOSED.search(line)
        if match_closed:
            svc = match_closed.group(1).strip()
            ts_match = _RE_TIMESTAMP.search(line)
            ts = ts_match.group(1) if ts_match else datetime.now(timezone.utc).isoformat()
            states[svc] = {
                "state": "down",
                "up_since": "",
                "last_seen": ts,
                "remote_addr": ""
            }

    return states


def check_and_update_links():
    """Inspect Rathole link telemetry using socket logs if available, or client heartbeat + local TCP checks."""
    hosts = db.get_all_hosts()
    if not hosts:
        return

    # Strategy 1: Podman Socket Log Polling (if socket exists)
    if has_available_podman_socket():
        logs = fetch_rathole_logs(tail=250)
        if logs:
            parsed = parse_service_states(logs)
            if parsed:
                svc_to_host = {clean_service_name(h["domain"]): h for h in hosts}
                for svc_name, info in parsed.items():
                    if svc_name in svc_to_host:
                        host_row = svc_to_host[svc_name]
                        current_state = host_row.get("link_state") or "down"
                        target_state = info["state"]
                        if current_state != target_state or target_state == "up":
                            db.update_host_link_status(
                                host_id=host_row["id"],
                                link_state=target_state,
                                remote_addr=info.get("remote_addr", ""),
                                up_since=info.get("up_since", "")
                            )
                return

    # Strategy 2: Socketless Monitoring via Client Heartbeat & In-Pod TCP Loopback Check
    active_clients = db.get_active_clients()
    client_online = False
    latest_client_ip = ""
    now = datetime.now(timezone.utc)

    for client in active_clients:
        last_seen_str = client.get("last_seen", "")
        if last_seen_str:
            try:
                ls_dt = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                if (now - ls_dt).total_seconds() < 45:
                    client_online = True
                    latest_client_ip = client.get("remote_ip", "")
                    break
            except Exception:
                pass

    for host in hosts:
        if not host.get("enabled", 1):
            continue

        port = host.get("rathole_port")
        port_open = is_local_tcp_port_listening(port) if port else False
        current_state = host.get("link_state") or "down"

        # Link is considered 'up' if client heartbeat is alive and service port responds (or client is online)
        is_up = client_online and port_open
        target_state = "up" if is_up else "down"

        if current_state != target_state or target_state == "up":
            db.update_host_link_status(
                host_id=host["id"],
                link_state=target_state,
                remote_addr=latest_client_ip if target_state == "up" else "",
                up_since=now.isoformat() if target_state == "up" else ""
            )


async def link_monitor_task(interval_seconds: int = 5):
    """Background asyncio worker periodically checking Rathole service link health."""
    mode_desc = "Podman Socket API" if has_available_podman_socket() else "In-Pod Client Heartbeat + TCP Health Check"
    logger.info(f"[LinkMon] Rathole link monitor started (mode: {mode_desc}, interval: {interval_seconds}s)")

    while True:
        try:
            await asyncio.to_thread(check_and_update_links)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"[LinkMon] Error during telemetry update: {e}")
        await asyncio.sleep(interval_seconds)
