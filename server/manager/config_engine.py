import os
import re
import socket
import http.client
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from typing import Dict, Any, List, Tuple, Optional
from db import get_all_hosts, get_settings

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

DEFAULT_PLACEHOLDER_TOKEN = "0000000000000000000000000000000000000000"

def clean_service_name(domain: str) -> str:
    """Generate an identifier for Rathole service (e.g. 'service1' from 'service1.example.com')."""
    part = domain.split(".")[0] if "." in domain else domain
    name = re.sub(r"[^a-zA-Z0-9_]", "_", part)
    return name.strip("_")

def get_cookie_domain(domain: str) -> str:
    """Return base domain for session cookie (e.g. 'example.com' from 'edge.example.com')."""
    clean = domain.strip().lower()
    parts = clean.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean


def parse_upstream_addr(upstream: str) -> Tuple[str, bool]:
    """Parse upstream string and return (host:port, is_tls)."""
    clean = upstream.strip()
    is_tls = False
    if clean.startswith("https://"):
        is_tls = True
        clean = clean[len("https://"):]
    elif clean.startswith("http://"):
        clean = clean[len("http://"):]

    # Remove trailing path if present
    if "/" in clean:
        clean = clean.split("/", 1)[0]

    # Deduce port if missing based on protocol
    if ":" not in clean:
        clean = f"{clean}:443" if is_tls else f"{clean}:80"

    return clean, is_tls


def get_target_paths():
    """Return target paths across server mounts, persistent data directories, and root directories."""
    return {
        "caddy": [
            "/data/caddy/Caddyfile",
            "/etc/edgeproxy/caddy/Caddyfile",
            "/opt/edgeproxy/server/caddy/Caddyfile",
            os.path.join(BASE_DIR, "server/caddy/Caddyfile")
        ],
        "rathole_server": [
            "/data/rathole/server.toml",
            "/etc/edgeproxy/rathole/server.toml",
            "/opt/edgeproxy/server/rathole/server.toml",
            os.path.join(BASE_DIR, "server/rathole/server.toml")
        ],
        "rathole_client": [
            "/data/rathole/client.toml",
            "/etc/edgeproxy/client/rathole/client.toml",
            "/opt/edgeproxy/client/rathole/client.toml",
            os.path.join(BASE_DIR, "client/rathole/client.toml")
        ],
        "oauth2_proxy_cfg": [
            "/data/oauth2-proxy/oauth2-proxy.cfg",
            "/etc/edgeproxy/oauth2-proxy/oauth2-proxy.cfg",
            "/opt/edgeproxy/server/oauth2-proxy/oauth2-proxy.cfg",
            os.path.join(BASE_DIR, "server/oauth2-proxy/oauth2-proxy.cfg")
        ],
        "oauth2_proxy_emails": [
            "/data/oauth2-proxy/authenticated_emails.txt",
            "/etc/edgeproxy/oauth2-proxy/authenticated_emails.txt",
            "/opt/edgeproxy/server/oauth2-proxy/authenticated_emails.txt",
            os.path.join(BASE_DIR, "server/oauth2-proxy/authenticated_emails.txt")
        ]
    }


def write_file_to_targets(paths: List[str], content: str) -> List[str]:
    """Safely and atomically write content to target file paths."""
    written = []
    for path in paths:
        try:
            parent = os.path.dirname(os.path.abspath(path))
            if not (os.path.exists(parent) or "/etc/edgeproxy" in parent or "/opt/edgeproxy" in parent or BASE_DIR in parent):
                continue

            # Idempotency check: if destination file already exists and content is identical, do not touch the file.
            # This preserves the file's mtime and avoids triggering unnecessary inotify reloads (e.g. Caddy --watch).
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as existing_f:
                        if existing_f.read() == content:
                            written.append(path)
                            continue
                except Exception:
                    pass

            os.makedirs(parent, exist_ok=True)
            tmp_path = f"{path}.tmp.{os.getpid()}"
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            written.append(path)
        except Exception as e:
            print(f"[EdgeProxy] Warning: unable to write to {path}: {e}", flush=True)
            try:
                if "tmp_path" in locals() and os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
    return written


def generate_caddyfile(hosts: List[Dict[str, Any]], settings: Dict[str, str]) -> str:
    """Generate dynamic Caddyfile with TLS, reverse proxy, forward_auth and security headers."""
    acme_email = settings.get("acme_email", "matteo.piva@gmail.com")
    lines = [
        "# ==============================================================================",
        "# EdgeProxy — Caddyfile (Dynamically generated by EdgeProxy Manager)",
        "# ==============================================================================",
        "{",
        f"\temail {{$ACME_EMAIL:{acme_email}}}",
        "\tlog access {",
        "\t\toutput file {$ACCESS_LOG_PATH:/data/caddy/logs/access.jsonl} {",
        "\t\t\troll_size 20mb",
        "\t\t\troll_keep 5",
        "\t\t\troll_keep_for 14d",
        "\t\t}",
        "\t\tformat json",
        "\t\tinclude http.log.access",
        "\t\tlevel INFO",
        "\t}",
        "}",
        "",
        "# Reusable snippet for JSON structured access logging",
        "(access_log) {",
        "\tlog {",
        "\t\toutput file {$ACCESS_LOG_PATH:/data/caddy/logs/access.jsonl} {",
        "\t\t\troll_size 20mb",
        "\t\t\troll_keep 5",
        "\t\t\troll_keep_for 14d",
        "\t\t}",
        "\t\tformat json",
        "\t}",
        "}",
        "",
        "# Default fallback for direct IP and unmatched HTTP requests",
        ":80 {",
        "\theader {",
        '\t\tServer "EdgeProxy"',
        "\t}",
        '\trespond "Unauthorized" 401 {',
        "\t\tclose",
        "\t}",
        "}",
        "",
        "# Default fallback for direct IP and unmatched HTTPS requests",
        ":443 {",
        "\ttls internal",
        "\theader {",
        '\t\tServer "EdgeProxy"',
        "\t}",
        '\trespond "Unauthorized" 401 {',
        "\t\tclose",
        "\t}",
        "}",
        "",
        "# Apex / base domain: default public gateway",
        "{$DOMAIN:edge.mpv.cx} {",
        "\timport access_log",
        "\theader {",
        '\t\tServer "EdgeProxy"',
        "\t}",
        "\trequest_body {",
        "\t\tmax_size 100MB",
        "\t}",
        "\t@hidden_files path */.*",
        "\thandle @hidden_files {",
        "\t\trespond \"404 Not Found\" 404 {",
        "\t\t\tclose",
        "\t\t}",
        "\t}",
        '\trespond "Unauthorized" 401 {',
        "\t\tclose",
        "\t}",
        "}",
        "",
        "# Reusable snippet for forward_auth with Google OAuth2 (oauth2-proxy)",
        "(google_auth) {",
        "\tforward_auth {$OAUTH2_PROXY_ADDR:127.0.0.1:4180} {",
        "\t\turi /oauth2/auth",
        "\t\tcopy_headers X-Auth-Request-User X-Auth-Request-Email",
        "\t\theader_up -X-Auth-Request-User",
        "\t\theader_up -X-Auth-Request-Email",
        "\t\t@unauth status 401",
        "\t\thandle_response @unauth {",
        "\t\t\tredir https://auth.{$DOMAIN:edge.mpv.cx}/oauth2/start?rd={scheme}://{host}{uri}",
        "\t\t}",
        "\t}",
        "\thandle_errors 401 {",
        "\t\tredir https://auth.{$DOMAIN:edge.mpv.cx}/oauth2/start?rd={scheme}://{host}{uri}",
        "\t}",
        "}",
        "",
        "# Dedicated Manager UI domain (automatic Google OAuth2 protection if configured)",
        "manager.{$DOMAIN:edge.mpv.cx} {",
        "\timport access_log",
        "\theader {",
        '\t\tServer "EdgeProxy"',
        '\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        '\t\tX-Content-Type-Options "nosniff"',
        '\t\tX-Frame-Options "SAMEORIGIN"',
        '\t\tReferrer-Policy "strict-origin-when-cross-origin"',
        '\t\tPermissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"',
        "\t}",
        "\trequest_body {",
        "\t\tmax_size 100MB",
        "\t}",
        "\t@hidden_files path */.*",
        "\thandle @hidden_files {",
        "\t\trespond \"404 Not Found\" 404 {",
        "\t\t\tclose",
        "\t\t}",
        "\t}",
    ]
    if is_google_oauth_configured(settings):
        lines.append("\t# Se OAuth2 globale è attivo, protegge il Manager con login Google")
        lines.append("\timport google_auth")
    lines.extend([
        "\treverse_proxy {$MANAGER_ADDR:127.0.0.1:8000} {",
        "\t\theader_up Host {host}",
        "\t\theader_up X-Real-IP {remote_host}",
        "\t\theader_up -X-Auth-Request-User",
        "\t\theader_up -X-Auth-Request-Email",
        "\t}",
        "}",
        "",
        "# Auth portal domain (OAuth2-Proxy endpoints and client config API sync)",
        "auth.{$DOMAIN:edge.mpv.cx} {",
        "\timport access_log",
        "\theader {",
        '\t\tServer "EdgeProxy"',
        '\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        '\t\tX-Content-Type-Options "nosniff"',
        '\t\tX-Frame-Options "SAMEORIGIN"',
        '\t\tReferrer-Policy "strict-origin-when-cross-origin"',
        '\t\tPermissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"',
        "\t}",
        "\trequest_body {",
        "\t\tmax_size 100MB",
        "\t}",
        "\t@hidden_files path */.*",
        "\thandle @hidden_files {",
        "\t\trespond \"404 Not Found\" 404 {",
        "\t\t\tclose",
        "\t\t}",
        "\t}",
        "\thandle /api/v1/client/* {",
        "\t\treverse_proxy {$MANAGER_ADDR:127.0.0.1:8000} {",
        "\t\t\theader_up Host {host}",
        "\t\t\theader_up X-Real-IP {remote_host}",
        "\t\t\theader_up -X-Auth-Request-User",
        "\t\t\theader_up -X-Auth-Request-Email",
        "\t\t}",
        "\t}",
        "\thandle {",
        "\t\treverse_proxy {$OAUTH2_PROXY_ADDR:127.0.0.1:4180} {",
        "\t\t\theader_up Host {host}",
        "\t\t\theader_up X-Real-IP {remote_host}",
        "\t\t\theader_up -X-Auth-Request-User",
        "\t\t\theader_up -X-Auth-Request-Email",
        "\t\t}",
        "\t}",
        "}",
        ""
    ])

    active_hosts = [h for h in hosts if h.get("enabled", 1)]
    lines.append("# Managed backend services (Dynamically generated from SQLite database)")

    for host in active_hosts:
        domain = host["domain"]
        rathole_port = host["rathole_port"]
        policy = host.get("policy", "google_oauth")
        sec_headers = host.get("security_headers", 1)
        allowed_emails_raw = host.get("allowed_emails", "").strip()

        lines.append(f"{domain} {{")
        lines.append("\timport access_log")

        lines.append("\theader {")
        lines.append('\t\tServer "EdgeProxy"')
        if sec_headers:
            lines.append('\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"')
            lines.append('\t\tX-Content-Type-Options "nosniff"')
            lines.append('\t\tX-Frame-Options "SAMEORIGIN"')
            lines.append('\t\tReferrer-Policy "strict-origin-when-cross-origin"')
            lines.append('\t\tPermissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"')
        lines.append("\t}")

        lines.append("\trequest_body {")
        lines.append("\t\tmax_size 100MB")
        lines.append("\t}")

        lines.append("\t@hidden_files path */.*")
        lines.append("\thandle @hidden_files {")
        lines.append('\t\trespond "404 Not Found" 404 {')
        lines.append("\t\t\tclose")
        lines.append("\t\t}")
        lines.append("\t}")

        if policy == "google_oauth":
            lines.append("\timport google_auth")
            # If specific allowed emails are configured for this host, enforce on X-Auth-Request-Email header
            if allowed_emails_raw:
                emails_list = [e.strip().lower() for e in allowed_emails_raw.replace(";", ",").split(",") if e.strip()]
                if emails_list:
                    lines.append(f"\t@denied_user not header_regexp X-Auth-Request-Email (?i)^({'|'.join(re.escape(e) for e in emails_list)})$")
                    lines.append('\thandle @denied_user {')
                    lines.append('\t\trespond "403 Access Denied: your Google account is not authorized for this service." 403')
                    lines.append('\t}')
        elif policy == "service_token":
            service_token = host.get("service_token", "").strip()
            lines.append(f"\t@no_token not header X-EdgeProxy-Token {service_token}")
            lines.append("\thandle @no_token {")
            lines.append('\t\trespond 401 "Unauthorized: invalid or missing X-EdgeProxy-Token header"')
            lines.append("\t}")

        # Check if upstream target configured by user uses HTTPS
        raw_upstream = host.get("upstream", "").strip()
        _, is_upstream_tls = parse_upstream_addr(raw_upstream)
        insecure_skip_verify = host.get("tls_insecure_skip_verify", 0)

        # Retrieve WebSocket / HTTP reverse proxy timeout parameters
        ws_read_timeout = host.get("ws_read_timeout")
        ws_write_timeout = host.get("ws_write_timeout")
        ws_idle_timeout = host.get("ws_idle_timeout")
        ws_flush_interval = host.get("ws_flush_interval")
        ws_dial_timeout = host.get("ws_dial_timeout")
        ws_resp_hdr_timeout = host.get("ws_response_header_timeout")

        # Caddy v2 reverse_proxy options & transport http block
        transport_lines = []
        if is_upstream_tls:
            transport_lines.append("\t\t\ttls")
            if insecure_skip_verify:
                transport_lines.append("\t\t\ttls_insecure_skip_verify")
        if ws_dial_timeout is not None and ws_dial_timeout > 0:
            transport_lines.append(f"\t\t\tdial_timeout {ws_dial_timeout}s")
        if ws_resp_hdr_timeout is not None and ws_resp_hdr_timeout > 0:
            transport_lines.append(f"\t\t\tresponse_header_timeout {ws_resp_hdr_timeout}s")
        if ws_idle_timeout is not None and ws_idle_timeout > 0:
            transport_lines.append(f"\t\t\tkeepalive {ws_idle_timeout}s")

        if not transport_lines and ws_flush_interval is None:
            lines.append(f"\treverse_proxy 127.0.0.1:{rathole_port} {{")
            lines.append("\t\theader_up Host {host}")
            lines.append("\t\theader_up X-Real-IP {remote_host}")
            if policy != "google_oauth":
                lines.append("\t\theader_up -X-Auth-Request-User")
                lines.append("\t\theader_up -X-Auth-Request-Email")
            lines.append("\t}")
        else:
            lines.append(f"\treverse_proxy 127.0.0.1:{rathole_port} {{")
            lines.append("\t\theader_up Host {host}")
            lines.append("\t\theader_up X-Real-IP {remote_host}")
            if policy != "google_oauth":
                lines.append("\t\theader_up -X-Auth-Request-User")
                lines.append("\t\theader_up -X-Auth-Request-Email")

            # Informational comments for WebSocket read/write stream settings
            if ws_read_timeout is not None:
                lines.append(f"\t\t# read_timeout {ws_read_timeout}s" if ws_read_timeout > 0 else "\t\t# read_timeout 0")
            if ws_write_timeout is not None:
                lines.append(f"\t\t# write_timeout {ws_write_timeout}s" if ws_write_timeout > 0 else "\t\t# write_timeout 0")

            if ws_flush_interval is not None:
                lines.append(f"\t\tflush_interval {ws_flush_interval}")

            if transport_lines:
                lines.append("\t\ttransport http {")
                lines.extend(transport_lines)
                lines.append("\t\t}")

            lines.append("\t}")

        lines.append("}")
        lines.append("")

    return "\n".join(lines)


def generate_rathole_server_toml(hosts: List[Dict[str, Any]], settings: Dict[str, str]) -> str:
    """Generate rathole server configuration with dynamic port allocation and token authorization."""
    lines = [
        "# ==============================================================================",
        "# Rathole Server Configuration (Dynamically generated by EdgeProxy Manager)",
        "# ==============================================================================",
        "",
        "[server]",
        'bind_addr = "0.0.0.0:2333"',
        "",
    ]

    transport_type = settings.get("rathole_transport", "noise")
    lines.extend([
        "[server.transport]",
        f'type = "{transport_type}"',
    ])
    if transport_type == "noise":
        lines.extend([
            "",
            "[server.transport.noise]",
            'pattern = "Noise_NN_25519_ChaChaPoly_BLAKE2s"',
        ])
    lines.append("")

    active_hosts = [h for h in hosts if h.get("enabled", 1)]
    if not active_hosts:
        lines.append("[server.services.default]")
        lines.append(f'token = "{DEFAULT_PLACEHOLDER_TOKEN}"')
        lines.append('bind_addr = "127.0.0.1:8001"')
        lines.append("")

    for host in active_hosts:
        svc_name = clean_service_name(host["domain"])
        port = host["rathole_port"]
        token = host["rathole_token"]

        lines.append(f"# Service: {host['domain']}")
        lines.append(f"[server.services.{svc_name}]")
        lines.append(f'token = "{token}"')
        lines.append(f'bind_addr = "127.0.0.1:{port}"')
        lines.append("")

    return "\n".join(lines) + "\n"


def generate_rathole_client_toml(hosts: List[Dict[str, Any]], settings: Dict[str, str]) -> str:
    """Generate rathole client configuration for private backend servers."""
    public_host = settings.get("rathole_public_host") or os.environ.get("DOMAIN") or "edge.mpv.cx"
    public_port = settings.get("rathole_public_port", "2333")

    lines = [
        "# ==============================================================================",
        "# Rathole Client Configuration (Private Local Network / Workstation)",
        "# Dynamically generated by EdgeProxy Manager",
        "# Deploy this file to /etc/rathole/client.toml on your local server",
        "# ==============================================================================",
        "",
        "[client]",
        f'remote_addr = "{public_host}:{public_port}"',
        "",
    ]

    transport_type = settings.get("rathole_transport", "noise")
    lines.extend([
        "[client.transport]",
        f'type = "{transport_type}"',
    ])
    if transport_type == "noise":
        lines.extend([
            "",
            "[client.transport.noise]",
            'pattern = "Noise_NN_25519_ChaChaPoly_BLAKE2s"',
        ])
    lines.append("")

    active_hosts = [h for h in hosts if h.get("enabled", 1) and h.get("link_state") != "disconnected"]
    if not active_hosts:
        lines.append("# Default placeholder service to satisfy Rathole client parser when no services are active")
        lines.append("[client.services.default]")
        lines.append(f'token = "{DEFAULT_PLACEHOLDER_TOKEN}"')
        lines.append('local_addr = "127.0.0.1:65535"')
        lines.append("")
    else:
        for host in active_hosts:
            svc_name = clean_service_name(host["domain"])
            token = host["rathole_token"]
            raw_upstream = host.get("upstream", "").strip()
            parsed_addr, _ = parse_upstream_addr(raw_upstream)

            lines.append(f"# Map {host['domain']} to local backend")
            lines.append(f"[client.services.{svc_name}]")
            lines.append(f'token = "{token}"')
            lines.append(f'local_addr = "{parsed_addr}"')
            lines.append("")

    return "\n".join(lines) + "\n"


class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: int = 5):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def is_google_oauth_configured(settings: Dict[str, Any]) -> bool:
    """Check whether Google OAuth2 is enabled and client credentials are fully populated."""
    if not settings:
        return False
    enabled = str(settings.get("google_oauth_enabled", "")).strip().lower() in ("1", "true")
    client_id = str(settings.get("google_client_id", "")).strip()
    client_secret = str(settings.get("google_client_secret", "")).strip()

    if not enabled:
        return False
    if not client_id or not client_secret:
        return False
    if "unconfigured-client-id" in client_id or "unconfigured-client-secret" in client_secret:
        return False
    return True


def generate_oauth2_proxy_cfg(settings: Dict[str, Any]) -> Optional[str]:
    """Generate oauth2-proxy configuration only if Google OAuth2 is validly configured."""
    if not is_google_oauth_configured(settings):
        return None

    root_domain = settings.get("root_domain") or os.environ.get("DOMAIN") or "edge.mpv.cx"
    cookie_domain = get_cookie_domain(root_domain)
    client_id = str(settings.get("google_client_id", "")).strip()
    client_secret = str(settings.get("google_client_secret", "")).strip()
    cookie_secret = str(settings.get("oauth2_cookie_secret", "")).strip() or "rV7kX9Jq2WysVlugaX-o0hBXWhdvCuapam4OT8Moaoa"

    lines = [
        "# ==============================================================================",
        "# EdgeProxy OAuth2-Proxy Configuration (Google OAuth2 Sign-In)",
        "# Dynamically generated by EdgeProxy Manager",
        "# ==============================================================================",
        'http_address = "0.0.0.0:4180"',
        'provider = "google"',
        f'client_id = "{client_id}"',
        f'client_secret = "{client_secret}"',
        f'cookie_secret = "{cookie_secret}"',
        f'cookie_domains = [".{cookie_domain}", "{cookie_domain}"]',
        'cookie_secure = true',
        f'redirect_url = "https://auth.{root_domain}/oauth2/callback"',
        'authenticated_emails_file = "/etc/oauth2-proxy/authenticated_emails.txt"',
        f'whitelist_domains = [".{cookie_domain}"]',
        'set_xauthrequest = true',
        'reverse_proxy = true',
        'upstreams = ["static://202"]',
        'email_domains = ["*"]',
        'pass_user_headers = true',
        '',
    ]
    return "\n".join(lines)


def generate_oauth2_authenticated_emails(settings: Dict[str, str]) -> str:
    """Gather global emails and host-specific allowed emails into whitelist file."""
    all_emails = set()
    allowed = settings.get("google_allowed_emails", "").strip()
    if allowed:
        for email in allowed.replace(";", ",").split(","):
            clean = email.strip().lower()
            if clean:
                all_emails.add(clean)

    hosts = get_all_hosts()
    for host in hosts:
        host_emails = host.get("allowed_emails", "").strip()
        if host_emails:
            for email in host_emails.replace(";", ",").split(","):
                clean = email.strip().lower()
                if clean:
                    all_emails.add(clean)

    lines = [
        "# ==============================================================================",
        "# EdgeProxy — Google OAuth2 Authenticated Emails Whitelist (Global & Per-Host)",
        "# Dynamically generated by EdgeProxy Manager",
        "# ==============================================================================",
    ]
    if all_emails:
        for email in sorted(all_emails):
            lines.append(email)
    else:
        lines.append("matteo.piva@gmail.com")
    return "\n".join(lines) + "\n"


def restart_container_via_podman_socket(container_name: str, podman_socket: str = "/run/podman/podman.sock") -> Tuple[bool, str]:
    """Trigger container restart via Podman socket if available, otherwise return success with in-pod native reload status."""
    if not os.path.exists(podman_socket):
        return True, "File written to disk (in-pod watcher/native reload active)"

    try:
        conn = _UnixSocketHTTPConnection(podman_socket, timeout=10)
        url = f"/v4.0.0/libpod/containers/{container_name}/restart?t=2"
        conn.request("POST", url)
        response = conn.getresponse()
        data = response.read().decode("utf-8")
        conn.close()

        if response.status in (200, 204):
            return True, f"Container {container_name} restarted successfully."

        # Fallback without edgeproxy- prefix if prefixed
        short_name = container_name.replace("edgeproxy-", "")
        if short_name != container_name:
            conn = _UnixSocketHTTPConnection(podman_socket, timeout=10)
            conn.request("POST", f"/v4.0.0/libpod/containers/{short_name}/restart?t=2")
            response = conn.getresponse()
            data = response.read().decode("utf-8")
            conn.close()
            if response.status in (200, 204):
                return True, f"Container {short_name} restarted successfully."

        return False, f"Error restarting {container_name} HTTP {response.status}: {data}"
    except Exception as e:
        return False, f"Exception restarting {container_name} via socket: {e}"


def restart_service_via_supervisor(service_name: str) -> Tuple[bool, str]:
    """Restart a service managed by supervisord in an all-in-one container."""
    try:
        res = subprocess.run(["supervisorctl", "restart", service_name], capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            return True, f"Service {service_name} restarted successfully via supervisorctl: {res.stdout.strip()}"
    except Exception:
        pass
    return False, ""


def restart_oauth2_proxy() -> Tuple[bool, str]:
    """Trigger service restart for oauth2-proxy via supervisorctl or Podman socket."""
    ok, msg = restart_service_via_supervisor("oauth2-proxy")
    if ok:
        return ok, msg
    return restart_container_via_podman_socket("edgeproxy-oauth2-proxy")


def restart_rathole() -> Tuple[bool, str]:
    """Trigger service restart for Rathole via supervisorctl or Podman socket."""
    ok, msg = restart_service_via_supervisor("rathole")
    if ok:
        return ok, msg
    return restart_container_via_podman_socket("edgeproxy-rathole")


def restart_caddy() -> Tuple[bool, str]:
    """Trigger service restart for Caddy via supervisorctl or Podman socket."""
    ok, msg = restart_service_via_supervisor("caddy")
    if ok:
        return ok, msg
    return restart_container_via_podman_socket("edgeproxy-caddy")


def write_all_configurations() -> Dict[str, Any]:
    """Write Caddyfile, rathole server/client toml and oauth2-proxy configurations."""
    hosts = get_all_hosts()
    settings = get_settings()
    targets = get_target_paths()

    caddy_content = generate_caddyfile(hosts, settings)
    caddy_written = write_file_to_targets(targets["caddy"], caddy_content)

    rathole_srv_content = generate_rathole_server_toml(hosts, settings)
    rathole_srv_written = write_file_to_targets(targets["rathole_server"], rathole_srv_content)

    rathole_cli_content = generate_rathole_client_toml(hosts, settings)
    rathole_cli_written = write_file_to_targets(targets["rathole_client"], rathole_cli_content)

    oauth_cfg_content = generate_oauth2_proxy_cfg(settings)
    oauth_cfg_written = []
    if oauth_cfg_content is not None:
        oauth_cfg_written = write_file_to_targets(targets["oauth2_proxy_cfg"], oauth_cfg_content)
    else:
        print("[EdgeProxy] Google OAuth2 not fully configured: preserving existing oauth2-proxy configuration", flush=True)
        for path in targets["oauth2_proxy_cfg"]:
            try:
                parent = os.path.dirname(os.path.abspath(path))
                if not (os.path.exists(parent) or "/etc/edgeproxy" in parent or "/opt/edgeproxy" in parent or BASE_DIR in parent):
                    continue
                if os.path.exists(path) and os.path.getsize(path) > 0:
                    continue
                os.makedirs(parent, exist_ok=True)
                stub_content = (
                    "# ==============================================================================\n"
                    "# EdgeProxy OAuth2-Proxy Configuration\n"
                    "# OAuth2-Proxy: configuration pending — Google credentials required\n"
                    "# ==============================================================================\n"
                )
                with open(path, "w", encoding="utf-8") as f:
                    f.write(stub_content)
                oauth_cfg_written.append(path)
            except Exception as e:
                print(f"[EdgeProxy] Error checking/writing stub oauth2-proxy.cfg on {path}: {e}", flush=True)

    oauth_emails_content = generate_oauth2_authenticated_emails(settings)
    oauth_emails_written = write_file_to_targets(targets["oauth2_proxy_emails"], oauth_emails_content)

    return {
        "caddy_written": caddy_written,
        "rathole_server_written": rathole_srv_written,
        "rathole_client_written": rathole_cli_written,
        "oauth2_proxy_cfg_written": oauth_cfg_written,
        "oauth2_proxy_emails_written": oauth_emails_written,
        "hosts_count": len(hosts),
        "active_hosts": [h.get("domain") for h in hosts if h.get("enabled", 1)],
    }


def reload_caddy() -> Tuple[bool, str]:
    """Reload Caddy reverse proxy via atomic disk write (--watch), Admin API, or Podman socket restart fallback."""
    # Step 1: Ensure Caddyfile is written to disk atomically (triggers Caddy native --watch inotify)
    targets = get_target_paths()
    caddy_content = ""
    caddyfile_path = None
    try:
        hosts = get_all_hosts()
        settings = get_settings()
        caddy_content = generate_caddyfile(hosts, settings)
        write_file_to_targets(targets["caddy"], caddy_content)
    except Exception as e:
        print(f"[EdgeProxy] Warning: failed generating/writing Caddyfile before reload: {e}", flush=True)

    for p in targets["caddy"]:
        if os.path.exists(p):
            caddyfile_path = p
            break

    if not caddy_content and caddyfile_path and os.path.exists(caddyfile_path):
        try:
            with open(caddyfile_path, "r", encoding="utf-8") as f:
                caddy_content = f.read()
        except Exception:
            pass

    admin_errors = []

    # Step 2a: Try Caddy admin Unix socket if available
    socket_candidates = [
        "/run/caddy/caddy.sock",
        "/data/caddy.sock",
        "/run/caddy.sock",
        "/var/run/caddy/caddy.sock"
    ]
    for sock in socket_candidates:
        if os.path.exists(sock):
            try:
                conn = _UnixSocketHTTPConnection(sock, timeout=4)
                headers = {"Content-Type": "text/caddyfile"}
                conn.request("POST", "/load", body=caddy_content.encode("utf-8"), headers=headers)
                response = conn.getresponse()
                data = response.read().decode("utf-8")
                conn.close()
                if response.status in (200, 204):
                    return True, f"Caddy configuration reload successful via Unix socket: {data.strip()}"
                admin_errors.append(f"Unix socket {sock} HTTP {response.status}: {data}")
            except Exception as e:
                admin_errors.append(f"Unix socket {sock} exception: {e}")

    # Step 2b: Try Caddy HTTP Admin API on 127.0.0.1:2019/load and localhost:2019/load
    admin_endpoints = [
        "http://127.0.0.1:2019/load",
        "http://localhost:2019/load"
    ]
    for endpoint in admin_endpoints:
        try:
            req = urllib.request.Request(
                endpoint,
                data=caddy_content.encode("utf-8"),
                headers={"Content-Type": "text/caddyfile"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                res_code = resp.getcode()
                res_body = resp.read().decode("utf-8")
                if res_code in (200, 204):
                    return True, f"Caddy configuration reload successful via Admin API: {endpoint}"
                admin_errors.append(f"{endpoint} returned HTTP {res_code}: {res_body}")
        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8", errors="ignore") if hasattr(he, "read") else ""
            admin_errors.append(f"{endpoint} HTTP error {he.code}: {err_body}")
        except Exception as e:
            admin_errors.append(f"{endpoint} connection error: {e}")

    # Step 3: Admin API fallback -> Podman Socket container restart if socket exists, or native watcher
    if os.path.exists("/run/podman/podman.sock"):
        print(f"[EdgeProxy] Caddy Admin API unreachable ({'; '.join(admin_errors)}). Falling back to Podman socket restart...", flush=True)
        restarted, restart_msg = restart_caddy()
        if restarted:
            return True, f"Caddy reloaded via Podman container restart fallback: {restart_msg}"
    else:
        return True, "Caddy configuration written to disk (in-pod watcher/native reload active)"

    # Step 4: CLI fallback as last resort if caddy CLI is present
    if caddyfile_path:
        try:
            res = subprocess.run(["caddy", "reload", "--config", caddyfile_path], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                return True, f"Caddy reload successful via CLI: {res.stdout.strip()}"
            admin_errors.append(f"CLI failed: {res.stderr.strip()}")
        except Exception:
            pass

    return False, f"All Caddy reload methods failed. Admin API errors: [{'; '.join(admin_errors)}]. Podman restart error: {restart_msg}"


def apply_all_configurations() -> Dict[str, Any]:
    """Write all configuration files and trigger service reloads."""
    write_result = write_all_configurations()

    caddy_reloaded, caddy_msg = reload_caddy()
    rathole_restarted, rathole_msg = restart_rathole()
    oauth2_restarted, oauth2_msg = restart_oauth2_proxy()

    overall_success = caddy_reloaded and rathole_restarted

    return {
        "success": overall_success,
        "files_written": write_result,
        "caddy_reload": {"status": caddy_reloaded, "message": caddy_msg},
        "rathole_restart": {"status": rathole_restarted, "message": rathole_msg},
        "oauth2_restart": {"status": oauth2_restarted, "message": oauth2_msg},
        "hosts_count": write_result["hosts_count"],
        "active_hosts": write_result["active_hosts"],
    }
