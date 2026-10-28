import os
import io
import re
import json
import asyncio
import logging
import secrets
import urllib.parse
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote as urllib_quote
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form, Depends, HTTPException, Header, Response, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import db
import config_engine
import stats
import linkmon

logger = logging.getLogger("edgeproxy.manager")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


async def reconcile_configs_on_startup():
    """Ensure config files on disk match the SQLite database on manager startup."""
    # Step 1: Pre-write Caddyfile and configuration files from DB to disk immediately
    logger.info("[Startup Reconciliation] Step 1: Pre-writing Caddyfile and all configuration files from DB to disk...")
    try:
        prewrite_res = await asyncio.to_thread(config_engine.write_all_configurations)
        logger.info(f"[Startup Reconciliation] Pre-write to disk completed: {prewrite_res.get('active_hosts', [])}")
    except Exception as e:
        logger.error(f"[Startup Reconciliation] Error during immediate pre-write: {e}", exc_info=True)

    delay = float(os.getenv("EDGEPROXY_STARTUP_RECONCILE_DELAY", "2.5"))
    if delay > 0:
        logger.info(f"[Startup Reconciliation] Waiting {delay}s for container initialization in pod...")
        await asyncio.sleep(delay)

    # Step 2: Apply full configuration and reload/restart services
    logger.info("[Startup Reconciliation] Step 2: Applying full configurations and reloading services...")
    try:
        res = await asyncio.to_thread(config_engine.apply_all_configurations)
        logger.info(f"[Startup Reconciliation] Configuration reconciliation completed: {res}")
    except Exception as e:
        logger.error(f"[Startup Reconciliation] Critical error during startup reconciliation: {e}", exc_info=True)

    # Step 3: Verify in-memory Caddy configuration
    try:
        req = urllib.request.Request("http://127.0.0.1:2019/config/")
        with urllib.request.urlopen(req, timeout=4) as resp:
            in_memory_config = resp.read().decode("utf-8")
            hosts = await asyncio.to_thread(db.get_hosts)
            active_domains = [h["domain"] for h in hosts if h.get("enabled", 1)]
            verified = [d for d in active_domains if d in in_memory_config]
            logger.info(f"[Startup Reconciliation] Step 3: In-memory Caddy check verified {len(verified)}/{len(active_domains)} active domains: {verified}")
    except Exception as check_err:
        logger.warning(f"[Startup Reconciliation] Step 3: Caddy Admin API verification query note: {check_err}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database
    db.init_db()

    # Pre-write configuration files immediately so files exist synchronously
    try:
        config_engine.write_all_configurations()
    except Exception as e:
        logger.error(f"[Startup] Error in initial synchronous pre-write: {e}")

    # Reconcile configuration files with active hosts in DB
    reconcile_task = asyncio.create_task(reconcile_configs_on_startup())

    # Start Caddy access log ingestion worker
    stats.ingester_instance.start()

    # Start Rathole link status telemetry monitor
    linkmon_task = asyncio.create_task(linkmon.link_monitor_task(interval_seconds=5))

    yield

    # Clean shutdown of background tasks
    if linkmon_task and not linkmon_task.done():
        linkmon_task.cancel()
    if reconcile_task and not reconcile_task.done():
        reconcile_task.cancel()
    stats.ingester_instance.stop()


app = FastAPI(title="EdgeProxy Manager", version="1.0.0", lifespan=lifespan)

DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")
UPSTREAM_REGEX = re.compile(r"^(https?://)?[a-zA-Z0-9_.-]+(:[0-9]{1,5})?(/.*)?$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def is_allowed_csrf(source: str) -> bool:
    """Validate Origin or Referer against allowed local and dynamic root domains."""
    if not source:
        return False
    try:
        parsed = urllib.parse.urlparse(source)
        hostname = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""
        host_with_port = f"{hostname}{port}"

        base_allowed = {"localhost", "127.0.0.1", "testserver"}
        if hostname in base_allowed or host_with_port in {"localhost:8000", "127.0.0.1:8000"}:
            return True

        settings = db.get_settings()
        root_domain = (settings.get("root_domain") or os.environ.get("DOMAIN") or "").strip().lower()
        if root_domain:
            if hostname == root_domain or hostname.endswith("." + root_domain):
                return True
        return False
    except Exception:
        return False


@app.middleware("http")
async def csrf_origin_middleware(request: Request, call_next):
    """Enforce CSRF origin/referer protection on state-modifying requests."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not request.url.path.startswith("/api/v1/client/"):
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            source = origin or referer
            if source:
                if not is_allowed_csrf(source):
                    logger.warning(f"[CSRF] Blocked untrusted request from origin/referer: {source}")
                    return JSONResponse(status_code=403, content={"detail": "Forbidden: CSRF source domain not permitted"})

    return await call_next(request)


def validate_domain(domain: str):
    """Validate domain syntax."""
    if not domain or not DOMAIN_REGEX.match(domain.strip()):
        raise ValueError("Invalid domain name syntax (e.g. app.example.com).")
    if any(c in domain for c in [";", "{", "}", "\n", "\r"]):
        raise ValueError("Domain contains illegal control characters.")


def validate_upstream(upstream: str):
    """Validate upstream target syntax."""
    if not upstream or not UPSTREAM_REGEX.match(upstream.strip()):
        raise ValueError("Invalid upstream target syntax (e.g. 10.88.0.29:8080 or http://backend:80).")
    if any(c in upstream for c in [";", "{", "}", "\n", "\r"]):
        raise ValueError("Upstream contains illegal control characters.")


def validate_service_token(token: str):
    """Validate service token syntax."""
    if token and any(c in token for c in [" ", ";", "{", "}", "\n", "\r"]):
        raise ValueError("Service token cannot contain spaces or semicolon characters.")


def validate_emails(emails_str: str):
    """Validate comma-separated list of email addresses."""
    if not emails_str:
        return
    emails = [e.strip() for e in emails_str.split(",") if e.strip()]
    for email in emails:
        if not EMAIL_REGEX.match(email):
            raise ValueError(f"Invalid email address: {email}")


def validate_host_inputs(domain: str, upstream: str, allowed_emails: Optional[str] = None):
    validate_domain(domain)
    validate_upstream(upstream)
    if allowed_emails:
        validate_emails(allowed_emails)


TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)
templates = Jinja2Templates(directory=TEMPLATES_DIR)


def format_uptime(seconds: int) -> str:
    """Format seconds into readable uptime string."""
    if seconds <= 0:
        return "0s"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def compute_uptime_seconds(link_up_since: str) -> int:
    """Compute elapsed seconds since link established timestamp."""
    if not link_up_since:
        return 0
    try:
        dt = datetime.fromisoformat(link_up_since.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = int((now - dt).total_seconds())
        return max(0, diff)
    except Exception:
        return 0


templates.env.filters["format_uptime"] = format_uptime


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def dashboard_view(request: Request):
    """Render main overview dashboard with system metrics and operational telemetry."""
    hosts = db.get_all_hosts()
    settings = db.get_settings()
    sync_tokens = db.get_sync_tokens()

    active_hosts = [h for h in hosts if h.get("enabled", 1)]
    live_links = [h for h in hosts if h.get("link_state") == "up"]
    oauth_configured = config_engine.is_google_oauth_configured(settings)

    active_clients = db.get_active_clients()
    client_status = "offline"
    client_last_seen = "Never"
    client_name = "None"
    client_uptime = 0
    client_version = "unknown"
    client_latency_ms = 0.0

    if active_clients:
        latest = active_clients[0]
        client_name = latest["client_name"]
        client_last_seen = latest["last_seen"]
        client_uptime = latest.get("uptime_seconds", 0)
        client_version = latest.get("version", "unknown")
        client_latency_ms = float(latest.get("latency_ms", 0.0) or 0.0)
        try:
            ls_dt = datetime.fromisoformat(latest["last_seen"].replace("Z", "+00:00"))
            if (datetime.now(timezone.utc) - ls_dt).total_seconds() < 45:
                client_status = "online"
        except Exception:
            client_status = "offline"

    for h in hosts:
        h["uptime_seconds"] = compute_uptime_seconds(h.get("link_up_since", ""))

    msg = request.query_params.get("msg")
    error = request.query_params.get("error")

    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "page_title": "Overview",
        "hosts": hosts,
        "active_hosts_count": len(active_hosts),
        "total_hosts_count": len(hosts),
        "live_links_count": len(live_links),
        "oauth_configured": oauth_configured,
        "client_status": client_status,
        "client_last_seen": client_last_seen,
        "client_name": client_name,
        "client_uptime": client_uptime,
        "client_version": client_version,
        "client_latency_ms": client_latency_ms,
        "sync_tokens": sync_tokens,
        "settings": settings,
        "msg": msg,
        "error": error,
    })


@app.get("/hosts", response_class=HTMLResponse)
async def hosts_view(request: Request):
    """Render host reverse tunnels management page."""
    hosts = db.get_all_hosts()
    settings = db.get_settings()
    msg = request.query_params.get("msg")
    error = request.query_params.get("error")

    return templates.TemplateResponse(request=request, name="hosts.html", context={
        "page_title": "Hosts & Tunnels",
        "hosts": hosts,
        "settings": settings,
        "msg": msg,
        "error": error,
    })


@app.post("/hosts/add")
async def add_host_action(
    request: Request,
    domain: str = Form(...),
    upstream: str = Form(...),
    policy: str = Form("google_oauth"),
    security_headers: Optional[str] = Form(None),
    allowed_emails: Optional[str] = Form(None),
    tls_insecure_skip_verify: Optional[str] = Form(None),
    service_token: Optional[str] = Form(None),
    ws_read_timeout: Optional[str] = Form(None),
    ws_write_timeout: Optional[str] = Form(None),
    ws_idle_timeout: Optional[str] = Form(None),
    ws_flush_interval: Optional[str] = Form(None),
    ws_dial_timeout: Optional[str] = Form(None),
    ws_response_header_timeout: Optional[str] = Form(None)
):
    try:
        validate_host_inputs(domain, upstream, allowed_emails)
        validate_service_token(service_token or "")

        def _parse_opt_int(val: Optional[str], default: int) -> int:
            if val is None or str(val).strip() == "":
                return default
            try:
                return int(val)
            except (ValueError, TypeError):
                return default

        skip_verify = 1 if tls_insecure_skip_verify in ("on", "1", "true") else 0
        cleaned_policy = policy if policy in ("bypass", "service_token") else "google_oauth"
        sec_headers = 1 if security_headers in ("on", "1", "true") else 0

        db.add_host(
            domain=domain.strip(),
            upstream=upstream.strip(),
            tls_insecure_skip_verify=skip_verify,
            policy=cleaned_policy,
            security_headers=sec_headers,
            allowed_emails=(allowed_emails or "").strip(),
            service_token=(service_token or "").strip(),
            ws_read_timeout=_parse_opt_int(ws_read_timeout, 30),
            ws_write_timeout=_parse_opt_int(ws_write_timeout, 30),
            ws_idle_timeout=_parse_opt_int(ws_idle_timeout, 60),
            ws_flush_interval=_parse_opt_int(ws_flush_interval, -1),
            ws_dial_timeout=_parse_opt_int(ws_dial_timeout, 10),
            ws_response_header_timeout=_parse_opt_int(ws_response_header_timeout, 30)
        )
        config_engine.apply_all_configurations()
        return RedirectResponse(url="/hosts?msg=Host+added+successfully", status_code=303)
    except Exception as e:
        if "application/json" in request.headers.get("accept", ""):
            raise HTTPException(status_code=400, detail=str(e))
        return RedirectResponse(url=f"/hosts?error={urllib_quote(str(e))}", status_code=303)


@app.post("/hosts/{host_id}/edit")
async def edit_host_action(
    host_id: int,
    request: Request,
    domain: str = Form(...),
    upstream: str = Form(...),
    policy: str = Form("google_oauth"),
    security_headers: Optional[str] = Form(None),
    allowed_emails: Optional[str] = Form(None),
    tls_insecure_skip_verify: Optional[str] = Form(None),
    service_token: Optional[str] = Form(None),
    ws_read_timeout: Optional[str] = Form(None),
    ws_write_timeout: Optional[str] = Form(None),
    ws_idle_timeout: Optional[str] = Form(None),
    ws_flush_interval: Optional[str] = Form(None),
    ws_dial_timeout: Optional[str] = Form(None),
    ws_response_header_timeout: Optional[str] = Form(None)
):
    try:
        validate_host_inputs(domain, upstream, allowed_emails)

        def _parse_opt_int(val: Optional[str]) -> Optional[int]:
            if val is None or str(val).strip() == "":
                return None
            try:
                return int(val)
            except (ValueError, TypeError):
                return None

        skip_verify = 1 if tls_insecure_skip_verify in ("on", "1", "true") else 0
        cleaned_policy = policy if policy in ("bypass", "service_token") else "google_oauth"
        sec_headers = 1 if security_headers in ("on", "1", "true") else 0
        db.update_host(
            host_id=host_id,
            domain=domain.strip(),
            upstream=upstream.strip(),
            tls_insecure_skip_verify=skip_verify,
            policy=cleaned_policy,
            security_headers=sec_headers,
            allowed_emails=(allowed_emails or "").strip(),
            service_token=(service_token or "").strip(),
            ws_read_timeout=_parse_opt_int(ws_read_timeout),
            ws_write_timeout=_parse_opt_int(ws_write_timeout),
            ws_idle_timeout=_parse_opt_int(ws_idle_timeout),
            ws_flush_interval=_parse_opt_int(ws_flush_interval),
            ws_dial_timeout=_parse_opt_int(ws_dial_timeout),
            ws_response_header_timeout=_parse_opt_int(ws_response_header_timeout)
        )
        config_engine.apply_all_configurations()
        return RedirectResponse(url="/hosts?msg=Host+updated+successfully", status_code=303)
    except Exception as e:
        if "application/json" in request.headers.get("accept", ""):
            raise HTTPException(status_code=400, detail=str(e))
        return RedirectResponse(url=f"/hosts?error={urllib_quote(str(e))}", status_code=303)


@app.post("/hosts/{host_id}/delete")
async def delete_host_action(host_id: int):
    db.delete_host(host_id)
    config_engine.apply_all_configurations()
    return RedirectResponse(url="/hosts?msg=Host+deleted+successfully", status_code=303)


@app.post("/hosts/{host_id}/toggle")
async def toggle_host_action(host_id: int):
    db.toggle_host_status(host_id)
    config_engine.apply_all_configurations()
    return RedirectResponse(url="/hosts?msg=Host+status+updated", status_code=303)


@app.post("/hosts/{host_id}/disconnect")
async def disconnect_host_action(host_id: int, request: Request):
    db.update_host_link_status(host_id=host_id, link_state="disconnected", up_since="")
    config_engine.apply_all_configurations()
    if "application/json" in request.headers.get("accept", ""):
        return {"status": "ok", "link_state": "disconnected"}
    return RedirectResponse(url="/links?msg=Link+disconnected", status_code=303)


@app.post("/hosts/{host_id}/connect")
async def connect_host_action(host_id: int, request: Request):
    now_iso = datetime.now(timezone.utc).isoformat()
    db.update_host_link_status(host_id=host_id, link_state="connected", up_since=now_iso)
    config_engine.apply_all_configurations()
    if "application/json" in request.headers.get("accept", ""):
        return {"status": "ok", "link_state": "connected"}
    return RedirectResponse(url="/links?msg=Link+connected", status_code=303)


@app.get("/client-config", response_class=HTMLResponse)
async def client_config_view(request: Request):
    """Render Rathole client.toml view with automatic configuration copy/download."""
    hosts = db.get_all_hosts()
    settings = db.get_settings()
    sync_tokens = db.get_sync_tokens()
    active_clients = db.get_active_clients()

    toml_content = config_engine.generate_rathole_client_toml(hosts, settings)
    token = sync_tokens[0]["token"] if sync_tokens else "UNCONFIGURED"

    return templates.TemplateResponse(request=request, name="client_config.html", context={
        "page_title": "Client Config",
        "toml_content": toml_content,
        "token": token,
        "sync_token": token,
        "sync_tokens": sync_tokens,
        "active_clients": active_clients,
        "settings": settings,
    })


@app.get("/client-config/download")
async def client_config_download():
    """Download dynamically generated client.toml as file attachment."""
    hosts = db.get_all_hosts()
    settings = db.get_settings()
    toml_content = config_engine.generate_rathole_client_toml(hosts, settings)
    return PlainTextResponse(
        toml_content,
        headers={"Content-Disposition": 'attachment; filename="client.toml"'}
    )


@app.get("/api/v1/client/config")
async def api_client_config(authorization: Optional[str] = Header(None)):
    """API endpoint delivering client.toml to Zero-Touch client agent authenticated via bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: missing or invalid Bearer token")

    token = authorization.split("Bearer ", 1)[1].strip()
    if not db.validate_sync_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized: invalid sync token")

    hosts = db.get_all_hosts()
    settings = db.get_settings()
    toml_content = config_engine.generate_rathole_client_toml(hosts, settings)
    return PlainTextResponse(toml_content, media_type="text/plain")


@app.get("/api/v1/client/ping", response_class=PlainTextResponse)
async def api_client_ping():
    """Lightweight ping endpoint for client latency probes."""
    return PlainTextResponse("pong")


@app.post("/api/v1/client/telemetry")
@app.post("/api/v1/client/report")
async def api_client_telemetry(request: Request, authorization: Optional[str] = Header(None)):
    """API endpoint receiving telemetry and logs from Zero-Touch client agent."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: missing or invalid Bearer token")

    token = authorization.split("Bearer ", 1)[1].strip()
    if not db.validate_sync_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized: invalid sync token")

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    client_name = data.get("client_name") or "unknown-client"
    uptime_sec = int(data.get("uptime_seconds") or 0)
    version = data.get("version") or "unknown"
    hostname = data.get("hostname") or ""
    remote_ip = request.client.host if request.client else "unknown"

    raw_latency = data.get("latency_ms")
    try:
        latency_ms = round(float(raw_latency), 1) if raw_latency is not None else 0.0
    except (ValueError, TypeError):
        latency_ms = 0.0

    db.upsert_client_status(
        client_name=client_name,
        remote_ip=remote_ip,
        uptime_seconds=uptime_sec,
        version=version,
        hostname=hostname,
        latency_ms=latency_ms
    )

    if raw_latency is not None:
        db.record_client_latency(client_name=client_name, latency_ms=latency_ms)

    logs = data.get("logs") or []
    if isinstance(logs, list) and len(logs) > 0:
        db.insert_client_logs(client_name, logs)

    return {"status": "ok", "message": "Telemetry received successfully"}


@app.get("/links", response_class=HTMLResponse)
async def links_view(request: Request):
    """Render links telemetry, client status, and logs page."""
    hosts = db.get_all_hosts()
    clients = db.get_active_clients()
    recent_logs = db.get_recent_client_logs(limit=50)
    settings = db.get_settings()

    for h in hosts:
        h["uptime_seconds"] = compute_uptime_seconds(h.get("link_up_since", ""))

    return templates.TemplateResponse(request=request, name="links.html", context={
        "page_title": "Links & Clients",
        "hosts": hosts,
        "clients": clients,
        "recent_logs": recent_logs,
        "settings": settings,
    })


@app.get("/api/v1/links/status")
async def api_links_status():
    """JSON API endpoint returning real-time status of all hosts and active clients."""
    hosts = db.get_all_hosts()
    clients = db.get_active_clients()
    for h in hosts:
        h["uptime_seconds"] = compute_uptime_seconds(h.get("link_up_since", ""))
    return {
        "hosts": hosts,
        "links": hosts,
        "clients": clients,
        "client": clients[0] if clients else {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/v1/links/client-logs")
async def api_links_client_logs(limit: int = 100):
    """Retrieve recent client agent logs."""
    logs = db.get_recent_client_logs(limit=min(max(1, limit), 200))
    return {"status": "ok", "logs": logs}


@app.get("/settings", response_class=HTMLResponse)
async def settings_view(request: Request):
    """Render system settings and Google OAuth2 credentials page."""
    settings = db.get_settings()
    sync_tokens = db.get_sync_tokens()
    oauth_configured = config_engine.is_google_oauth_configured(settings)
    msg = request.query_params.get("msg")
    error = request.query_params.get("error")

    return templates.TemplateResponse(request=request, name="settings.html", context={
        "page_title": "Settings",
        "settings": settings,
        "sync_tokens": sync_tokens,
        "msg": msg,
        "error": error,
        "oauth_configured": oauth_configured,
    })


@app.post("/settings/save")
async def settings_save_action(
    request: Request,
    root_domain: str = Form(...),
    acme_email: str = Form(...),
    rathole_public_host: str = Form(...),
    rathole_public_port: str = Form("2333"),
    google_oauth_enabled: Optional[str] = Form(None),
    google_client_id: Optional[str] = Form(None),
    google_client_secret: Optional[str] = Form(None),
    google_allowed_emails: Optional[str] = Form(None)
):
    try:
        validate_domain(root_domain)
        validate_emails(acme_email)
        if google_allowed_emails:
            validate_emails(google_allowed_emails)

        is_oauth_enabled = "1" if google_oauth_enabled in ("on", "1", "true") else "0"

        new_settings = {
            "root_domain": root_domain.strip(),
            "acme_email": acme_email.strip(),
            "rathole_public_host": rathole_public_host.strip(),
            "rathole_public_port": rathole_public_port.strip(),
            "google_oauth_enabled": is_oauth_enabled,
            "google_client_id": (google_client_id or "").strip(),
            "google_client_secret": (google_client_secret or "").strip(),
            "google_allowed_emails": (google_allowed_emails or "").strip(),
        }
        db.update_settings(new_settings)
        config_engine.apply_all_configurations()
        return RedirectResponse(url="/settings?msg=Settings+updated+successfully", status_code=303)
    except Exception as e:
        logger.error(f"[Settings] Error saving settings: {e}", exc_info=True)
        if "application/json" in request.headers.get("accept", ""):
            raise HTTPException(status_code=400, detail=str(e))
        return RedirectResponse(url=f"/settings?error={urllib_quote(str(e))}", status_code=303)


# --- Backup Manager Endpoints ---

@app.get("/backup/export")
async def backup_export():
    """Export complete database configuration snapshot as JSON."""
    data = db.export_backup_data()
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"edgeproxy-backup-{now_str}.json"
    content = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.post("/backup/import")
async def backup_import(request: Request, file: UploadFile = File(...)):
    """Import and apply database configuration snapshot from uploaded JSON backup file."""
    try:
        content = await file.read()
        if not content:
            raise ValueError("The uploaded backup file is empty.")
        try:
            backup_data = json.loads(content.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid backup JSON format: {e}")

        db.import_backup_data(backup_data)
        logger.info("[Backup Import] Backup imported successfully. Reapplying configurations...")
        config_engine.apply_all_configurations()

        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"status": "ok", "message": "Backup imported and configurations applied successfully."})
        return RedirectResponse(url="/settings?msg=Backup+imported+and+configurations+applied+successfully", status_code=303)
    except Exception as e:
        logger.error(f"[Backup Import] Error importing backup: {e}", exc_info=True)
        if "application/json" in request.headers.get("accept", ""):
            raise HTTPException(status_code=400, detail=str(e))
        return RedirectResponse(url=f"/settings?error={urllib_quote(str(e))}", status_code=303)


# --- Traffic Stats and Access Logs Endpoints ---

@app.get("/stats", response_class=HTMLResponse)
async def stats_view(request: Request):
    """Render traffic statistics and Caddy access logs view."""
    hosts = db.get_all_hosts()
    settings = db.get_settings()
    recent_logs = db.get_recent_access_logs(limit=25)

    return templates.TemplateResponse(request=request, name="stats.html", context={
        "page_title": "Statistics",
        "hosts": hosts,
        "settings": settings,
        "recent_logs": recent_logs,
    })


@app.get("/api/v1/stats/access-logs")
async def api_stats_access_logs(limit: int = 50, host: Optional[str] = None):
    """Retrieve recent access logs with optional host filter."""
    safe_limit = min(max(1, limit), 200)
    filter_host = host.strip() if host else None
    logs = db.get_recent_access_logs(limit=safe_limit, filter_host=filter_host)
    return {"status": "ok", "logs": logs, "count": len(logs)}


@app.get("/api/v1/stats/bandwidth-timeline")
@app.get("/api/v1/stats/bandwidth")
async def api_stats_bandwidth_timeline(hours: int = 24, host: Optional[str] = None):
    """Retrieve aggregated bandwidth and request timelines for charts."""
    safe_hours = min(max(1, hours), 720)
    filter_host = host.strip() if host else None
    data = db.get_bandwidth_timeline(hours=safe_hours, filter_host=filter_host)
    return {
        "status": "ok",
        "labels": data.get("labels", []),
        "datasets": data.get("datasets", []),
        "data": data
    }


@app.get("/api/v1/stats/access")
async def api_stats_access_alias(limit: int = 50, host: Optional[str] = None):
    """Alias for access logs endpoint."""
    return await api_stats_access_logs(limit=limit, host=host)


@app.get("/api/v1/stats/latency")
async def api_stats_latency(hours: int = 24, client: Optional[str] = None):
    """Retrieve time-series latency telemetry for Chart.js rendering."""
    safe_hours = min(max(1, hours), 720)
    filter_client = client.strip() if client else None
    data = db.get_client_latency_chart_data(client_name=filter_client, hours=safe_hours)
    return {
        "status": "ok",
        "labels": data.get("labels", []),
        "values": data.get("values", []),
        "points": data.get("points", []),
        "hours": safe_hours,
        "client_name": filter_client
    }


@app.post("/api/v1/stats/trigger-ingest")
async def api_stats_trigger_ingest():
    """Manually trigger log file ingestion."""
    processed = await asyncio.to_thread(stats.process_access_log_file)
    return {"status": "ok", "processed_lines": processed}


@app.post("/reload-all")
@app.post("/apply")
async def reload_all_action(request: Request):
    """Regenerate all configurations and reload Caddy and Rathole."""
    res = config_engine.apply_all_configurations()
    msg = f"Reloaded+successfully.+Hosts:+{res['hosts_count']}"
    return RedirectResponse(url=f"/?msg={msg}", status_code=303)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}
