import os
import sys
import json
import unittest
import tempfile

# Configure temporary DB path BEFORE importing the manager
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db_path = temp_db.name
temp_db.close()
os.environ["EDGEPROXY_DB_PATH"] = temp_db_path

# Add server/manager directory to sys.path
MANAGER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../server/manager"))
if MANAGER_DIR not in sys.path:
    sys.path.insert(0, MANAGER_DIR)

import db
import config_engine
from app import app
from fastapi.testclient import TestClient


class TestEdgeProxyManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Save backup copies of target files before tests
        cls.saved_files = {}
        for target_list in config_engine.get_target_paths().values():
            for p in target_list:
                if os.path.exists(p):
                    try:
                        with open(p, "r", encoding="utf-8") as f:
                            cls.saved_files[p] = f.read()
                    except Exception:
                        pass

        # Initialize clean SQLite database with default seeds
        db.init_db()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        # Restore original target files
        for p, content in getattr(cls, "saved_files", {}).items():
            try:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception:
                pass
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass

    def test_01_dashboard_view(self):
        """Verify GET /: returns status 200 and HTML dashboard elements."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        content = response.text
        self.assertIn("EdgeProxy Manager", content)
        self.assertIn("Infrastructure Overview", content)
        self.assertIn("Active Host Tunnels", content)

    def test_02_add_host_and_port_assignment(self):
        """Verify POST /hosts/add: adds host demo.mycompany.org, assigns port 8001 and secure token."""
        form_data = {
            "domain": "demo.mycompany.org",
            "upstream": "https://10.88.0.100:9443",
            "tls_insecure_skip_verify": "1",
            "policy": "google_oauth",
            "security_headers": "1"
        }
        response = self.client.post("/hosts/add", data=form_data, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("/hosts", response.headers.get("location", ""))

        # Verify in database
        hosts = db.get_all_hosts()
        demo = next((h for h in hosts if h["domain"] == "demo.mycompany.org"), None)
        self.assertIsNotNone(demo, "Host demo.mycompany.org not found in database")
        self.assertEqual(demo["rathole_port"], 8001, f"Expected port 8001, found {demo['rathole_port']}")
        self.assertEqual(demo["upstream"], "https://10.88.0.100:9443")
        self.assertEqual(demo["tls_insecure_skip_verify"], 1)
        self.assertEqual(demo["policy"], "google_oauth")
        self.assertEqual(demo["security_headers"], 1)
        self.assertTrue(len(demo["rathole_token"]) >= 32, "Generated Rathole token is not valid or secure")

    def test_03_client_config_view(self):
        """Verify GET /client-config: generates client.toml with [client.services.demo] and target."""
        response = self.client.get("/client-config")
        self.assertEqual(response.status_code, 200)
        content = response.text

        # Verify rendered TOML file sections
        self.assertIn("[client.services.demo]", content)
        self.assertIn('local_addr = "10.88.0.100:9443"', content)
        self.assertIn("[client]", content)

        # Verify direct download
        dl_response = self.client.get("/client-config/download")
        self.assertEqual(dl_response.status_code, 200)
        self.assertIn("[client.services.demo]", dl_response.text)
        self.assertIn('local_addr = "10.88.0.100:9443"', dl_response.text)

    def test_04_apply_configurations(self):
        """Verify POST /apply: generation and syntax validity of Caddyfile, Rathole and OAuth2-Proxy configs."""
        response = self.client.post("/apply", follow_redirects=False)
        self.assertEqual(response.status_code, 303)

        hosts = db.get_all_hosts()
        settings = db.get_settings()

        # Genera i testi di configurazione in memoria
        caddy_content = config_engine.generate_caddyfile(hosts, settings)
        server_toml = config_engine.generate_rathole_server_toml(hosts, settings)
        client_toml = config_engine.generate_rathole_client_toml(hosts, settings)
        oauth2_cfg = config_engine.generate_oauth2_proxy_cfg(settings)

        # Assertions on Caddyfile
        self.assertIn("{$DOMAIN:example.com} {", caddy_content)
        self.assertIn('respond "Unauthorized" 401', caddy_content)
        self.assertNotIn("reverse_proxy 127.0.0.1:8000", caddy_content)
        self.assertIn(":80 {", caddy_content)
        self.assertIn(":443 {", caddy_content)
        self.assertNotIn("authelia", caddy_content)
        self.assertIn("demo.mycompany.org {", caddy_content)
        self.assertIn("Strict-Transport-Security", caddy_content)
        self.assertIn("127.0.0.1:8001", caddy_content)
        self.assertIn("import google_auth", caddy_content)
        self.assertIn("import access_log", caddy_content)

        # Asserzioni su server.toml (trasporto valido configurato)
        self.assertTrue('type = "noise"' in server_toml or 'type = "tcp"' in server_toml)
        self.assertIn("[server.services.demo]", server_toml)
        self.assertIn('bind_addr = "127.0.0.1:8001"', server_toml)

        # Asserzioni su client.toml (trasporto valido configurato)
        self.assertTrue('type = "noise"' in client_toml or 'type = "tcp"' in client_toml)
        self.assertIn("[client.services.demo]", client_toml)
        self.assertIn('local_addr = "10.88.0.100:9443"', client_toml)

        # Asserzioni su OAuth2-Proxy: con credenziali non configurate non genera file con placeholder
        self.assertFalse(config_engine.is_google_oauth_configured(settings))
        self.assertIsNone(oauth2_cfg)

        # Con credenziali valide fornite, genera configurazione completa
        configured_settings = dict(settings)
        configured_settings["google_oauth_enabled"] = "1"
        configured_settings["google_client_id"] = "123456789-test.apps.googleusercontent.com"
        configured_settings["google_client_secret"] = "GOCSPX-secret123"
        self.assertTrue(config_engine.is_google_oauth_configured(configured_settings))
        oauth2_cfg_valid = config_engine.generate_oauth2_proxy_cfg(configured_settings)
        self.assertIsNotNone(oauth2_cfg_valid)
        self.assertIn('provider = "google"', oauth2_cfg_valid)
        self.assertIn('http_address = "0.0.0.0:4180"', oauth2_cfg_valid)
        self.assertIn('client_id = "123456789-test.apps.googleusercontent.com"', oauth2_cfg_valid)

    def test_05_stats_routes(self):
        """Verify that /stats page and /api/v1/stats endpoints respond correctly."""
        # Test pagina HTML /stats
        stats_page = self.client.get("/stats")
        self.assertEqual(stats_page.status_code, 200)
        self.assertIn("Traffic Statistics & Telemetry", stats_page.text)
        self.assertIn("bandwidthChart", stats_page.text)
        self.assertIn("accessLogsTableBody", stats_page.text)
        self.assertIn("Tunnel Latency", stats_page.text)
        self.assertNotIn("Recorded Requests", stats_page.text)

        # Test API bandwidth con DB vuoto inizialmente
        bw_res = self.client.get("/api/v1/stats/bandwidth?hours=24")
        self.assertEqual(bw_res.status_code, 200)
        bw_json = bw_res.json()
        self.assertIn("labels", bw_json)
        self.assertIn("datasets", bw_json)

        # Test API access con DB vuoto
        acc_res = self.client.get("/api/v1/stats/access?limit=10")
        self.assertEqual(acc_res.status_code, 200)
        acc_json = acc_res.json()
        self.assertIn("logs", acc_json)
        self.assertIsInstance(acc_json["logs"], list)

    def test_06_stats_ingester_and_jsonl_parsing(self):
        """Verify Caddy JSON access log background ingestion and correct metrics aggregation."""
        import json
        import stats

        # Crea un file temporaneo con righe di log Caddy strutturate
        log_temp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        log_lines = [
            json.dumps({
                "level": "info",
                "ts": 1729700000.0,
                "logger": "http.log.access.log0",
                "msg": "handled request",
                "request": {
                    "remote_ip": "192.168.1.50:45678",
                    "client_ip": "192.168.1.50",
                    "proto": "HTTP/2.0",
                    "method": "GET",
                    "host": "demo.mycompany.org",
                    "uri": "/api/test",
                    "headers": {
                        "X-Auth-Request-Email": ["test.user@example.com"]
                    }
                },
                "user_id": "test.user@example.com",
                "duration": 0.045,
                "size": 4096,
                "status": 200
            }),
            json.dumps({
                "level": "info",
                "ts": 1729700030.0,
                "logger": "http.log.access.log0",
                "msg": "handled request",
                "request": {
                    "remote_ip": "10.0.0.12",
                    "client_ip": "10.0.0.12",
                    "proto": "HTTP/1.1",
                    "method": "POST",
                    "host": "demo.mycompany.org",
                    "uri": "/upload",
                    "headers": {}
                },
                "user_id": "",
                "duration": 0.12,
                "size": 8192,
                "status": 201
            })
        ]
        log_temp.write("\n".join(log_lines) + "\n")
        log_temp.close()

        try:
            # Resetta offset per il file temporaneo
            db.set_setting("stats_last_offset", "0")
            db.set_setting("stats_last_inode", "0")

            # Esegui l'ingestione
            processed = stats.process_access_log_file(log_temp.name)
            self.assertEqual(processed, 2)

            # Seconda esecuzione senza nuovi log: deve processare 0 righe
            processed_again = stats.process_access_log_file(log_temp.name)
            self.assertEqual(processed_again, 0)

            # Verifica record in access_logs
            logs = db.get_recent_access_logs(host="demo.mycompany.org", limit=10)
            self.assertGreaterEqual(len(logs), 2)
            first = next(l for l in logs if l["method"] == "GET")
            self.assertEqual(first["host"], "demo.mycompany.org")
            self.assertEqual(first["email"], "test.user@example.com")
            self.assertEqual(first["status"], 200)
            self.assertEqual(first["bytes"], 4096)
            self.assertAlmostEqual(first["duration_ms"], 45.0, delta=1.0)

            # Verifica API access
            api_acc = self.client.get("/api/v1/stats/access?host=demo.mycompany.org&limit=5")
            self.assertEqual(api_acc.status_code, 200)
            self.assertGreaterEqual(len(api_acc.json()["logs"]), 2)

        finally:
            if os.path.exists(log_temp.name):
                os.remove(log_temp.name)

    def test_07_service_token_policy(self):
        """Verify creating host with service_token policy and associated Caddyfile rules."""
        form_data = {
            "domain": "api-service.mycompany.org",
            "upstream": "http://10.88.0.101:8080",
            "tls_insecure_skip_verify": "0",
            "policy": "service_token",
            "security_headers": "1"
        }
        res = self.client.post("/hosts/add", data=form_data, follow_redirects=False)
        self.assertEqual(res.status_code, 303)

        hosts = db.get_all_hosts()
        svc_host = next((h for h in hosts if h["domain"] == "api-service.mycompany.org"), None)
        self.assertIsNotNone(svc_host)
        self.assertEqual(svc_host["policy"], "service_token")
        self.assertTrue(len(svc_host["service_token"]) >= 16)

        # Verifica Caddyfile
        caddy = config_engine.generate_caddyfile(hosts, db.get_settings())
        self.assertIn("api-service.mycompany.org {", caddy)
        self.assertIn(f"@no_token not header X-EdgeProxy-Token {svc_host['service_token']}", caddy)
        self.assertIn('respond 401 "Unauthorized: invalid or missing X-EdgeProxy-Token header"', caddy)
        self.assertNotIn("import google_auth", caddy.split("api-service.mycompany.org {")[1].split("}")[0])

    def test_08_disconnect_and_connect_link(self):
        """Verify /disconnect and /connect routes and dynamic service removal in client.toml."""
        hosts = db.get_all_hosts()
        svc_host = next((h for h in hosts if h["domain"] == "api-service.mycompany.org"), None)
        self.assertIsNotNone(svc_host)

        # Disconnetti link
        res_disc = self.client.post(f"/hosts/{svc_host['id']}/disconnect", headers={"Accept": "application/json"})
        self.assertEqual(res_disc.status_code, 200)
        self.assertEqual(res_disc.json()["link_state"], "disconnected")

        updated_host = db.get_host_by_id(svc_host["id"])
        self.assertEqual(updated_host["link_state"], "disconnected")
        self.assertEqual(updated_host["link_up_since"], "")

        # Verifica che client.toml NON contenga il servizio disconnesso
        client_toml = config_engine.generate_rathole_client_toml(db.get_all_hosts(), db.get_settings())
        self.assertNotIn("[client.services.api_service]", client_toml)

        # Riconnetti link
        res_conn = self.client.post(f"/hosts/{svc_host['id']}/connect", headers={"Accept": "application/json"})
        self.assertEqual(res_conn.status_code, 200)
        self.assertEqual(res_conn.json()["link_state"], "connected")

        rec_host = db.get_host_by_id(svc_host["id"])
        self.assertEqual(rec_host["link_state"], "connected")
        self.assertTrue(len(rec_host["link_up_since"]) > 0)

        # Verifica che client.toml contenga nuovamente il servizio
        client_toml_after = config_engine.generate_rathole_client_toml(db.get_all_hosts(), db.get_settings())
        self.assertIn("[client.services.api_service]", client_toml_after)

    def test_09_client_report_and_links_view(self):
        """Verify POST /api/v1/client/report, GET /api/v1/links/status and GET /links."""
        sync_token = db.get_or_create_default_sync_token()

        report_payload = {
            "client_name": "toaster",
            "uptime_seconds": 7200,
            "version": "rathole 0.5.0",
            "hostname": "toaster-workstation",
            "logs": [
                {"level": "info", "message": "Control channel established service=ide"},
                {"level": "info", "message": "Zero-Touch Sync OK"}
            ]
        }
        res = self.client.post(
            "/api/v1/client/report",
            headers={"Authorization": f"Bearer {sync_token}"},
            json=report_payload
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")

        # Verifica API status
        st_res = self.client.get("/api/v1/links/status")
        self.assertEqual(st_res.status_code, 200)
        st_data = st_res.json()
        self.assertIn("links", st_data)
        self.assertIn("client", st_data)
        self.assertEqual(st_data["client"]["client_name"], "toaster")
        self.assertEqual(st_data["client"]["uptime_seconds"], 7200)

        # Verifica API client logs
        logs_res = self.client.get("/api/v1/links/client-logs?limit=50")
        self.assertEqual(logs_res.status_code, 200)
        logs = logs_res.json()["logs"]
        self.assertGreaterEqual(len(logs), 2)
        self.assertTrue(any("Control channel established" in l["message"] for l in logs))

        # Verifica pagina HTML /links
        links_page = self.client.get("/links")
        self.assertEqual(links_page.status_code, 200)
        self.assertIn("Link Telemetry & Status", links_page.text)
        self.assertIn("toaster", links_page.text)
        self.assertIn("Control channel established", links_page.text)

    def test_10_websocket_timeouts(self):
        """Verify WebSocket timeout configuration in add_host, update_host and Caddyfile generation."""
        # Register host with custom websocket timeouts
        res = self.client.post("/hosts/add", data={
            "domain": "test-ws.example.com",
            "upstream": "http://10.88.0.28:8000",
            "policy": "bypass",
            "security_headers": "1",
            "ws_read_timeout": "0",
            "ws_write_timeout": "0",
            "ws_idle_timeout": "7200",
            "ws_flush_interval": "1",
            "ws_dial_timeout": "15",
            "ws_response_header_timeout": "45"
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 303)

        matched = [h for h in db.get_all_hosts() if h["domain"] == "test-ws.example.com"]
        self.assertTrue(len(matched) > 0)
        host = matched[0]
        self.assertEqual(host["ws_read_timeout"], 0)
        self.assertEqual(host["ws_write_timeout"], 0)
        self.assertEqual(host["ws_idle_timeout"], 7200)
        self.assertEqual(host["ws_flush_interval"], 1)
        self.assertEqual(host["ws_dial_timeout"], 15)
        self.assertEqual(host["ws_response_header_timeout"], 45)

        # Modify timeouts via update_host
        edit_res = self.client.post(f"/hosts/{host['id']}/edit", data={
            "domain": "test-ws.example.com",
            "upstream": "http://10.88.0.28:8000",
            "policy": "bypass",
            "security_headers": "1",
            "ws_read_timeout": "0",
            "ws_write_timeout": "0",
            "ws_idle_timeout": "3600",
            "ws_flush_interval": "-1",
            "ws_dial_timeout": "10",
            "ws_response_header_timeout": "30"
        }, follow_redirects=False)
        self.assertEqual(edit_res.status_code, 303)

        updated_host = db.get_host_by_id(host["id"])
        self.assertEqual(updated_host["ws_flush_interval"], -1)

        # Verifica rendering Caddyfile
        caddyfile = config_engine.generate_caddyfile([updated_host], {"acme_email": "admin@example.com"})
        self.assertIn("read_timeout 0", caddyfile)
        self.assertIn("write_timeout 0", caddyfile)
        self.assertIn("flush_interval -1", caddyfile)
        self.assertIn("dial_timeout 10s", caddyfile)
        self.assertIn("response_header_timeout 30s", caddyfile)

    def test_09_google_oauth_protection_and_ui_alert(self):
        """Verify oauth2 cfg generation safeguards and warning banners displayed in Web UI."""
        # 1. Helper is_google_oauth_configured
        self.assertFalse(config_engine.is_google_oauth_configured({}))
        self.assertFalse(config_engine.is_google_oauth_configured({"google_oauth_enabled": "0"}))
        self.assertFalse(config_engine.is_google_oauth_configured({
            "google_oauth_enabled": "1",
            "google_client_id": "",
            "google_client_secret": ""
        }))
        self.assertFalse(config_engine.is_google_oauth_configured({
            "google_oauth_enabled": "1",
            "google_client_id": "unconfigured-client-id.apps.googleusercontent.com",
            "google_client_secret": "unconfigured-client-secret"
        }))
        self.assertTrue(config_engine.is_google_oauth_configured({
            "google_oauth_enabled": "1",
            "google_client_id": "687684757289-test.apps.googleusercontent.com",
            "google_client_secret": "GOCSPX-valid_secret"
        }))

        # 2. generate_oauth2_proxy_cfg con credenziali mancanti restituisce None (nessun placeholder)
        self.assertIsNone(config_engine.generate_oauth2_proxy_cfg({
            "google_oauth_enabled": "1",
            "google_client_id": "",
            "google_client_secret": ""
        }))

        # 3. Avviso Web UI su / e /settings quando non configurato
        db.update_settings({"google_oauth_enabled": "0", "google_client_id": "", "google_client_secret": ""})
        dash_res = self.client.get("/")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn("Google OAuth2 is not configured", dash_res.text)

        settings_res = self.client.get("/settings")
        self.assertEqual(settings_res.status_code, 200)
        self.assertIn("Google OAuth2 is not configured", settings_res.text)

    def test_12_input_validation_and_sanitization(self):
        """Verify strict validation and sanitization for domain, upstream and allowed_emails fields."""
        # 1. Tentativo di Caddyfile / TOML Injection su domain con graffe o newline
        bad_domain_form = {
            "domain": "evil.org {\n\treverse_proxy 1.2.3.4\n}",
            "upstream": "10.88.0.1:8080",
            "policy": "bypass",
        }
        res = self.client.post("/hosts/add", data=bad_domain_form, follow_redirects=False)
        self.assertEqual(res.status_code, 303)
        self.assertIn("error=", res.headers.get("location", ""))

        # Con header Accept application/json viene sollevato 400
        res_json = self.client.post("/hosts/add", data=bad_domain_form, headers={"Accept": "application/json"})
        self.assertEqual(res_json.status_code, 400)
        self.assertIn("Invalid domain", res_json.json()["detail"])

        # 2. Upstream con caratteri di comando o spazi
        bad_upstream_form = {
            "domain": "valid-app.example.com",
            "upstream": "10.88.0.1:8080; rm -rf /",
            "policy": "bypass",
        }
        res_up = self.client.post("/hosts/add", data=bad_upstream_form, headers={"Accept": "application/json"})
        self.assertEqual(res_up.status_code, 400)
        self.assertIn("Invalid upstream", res_up.json()["detail"])

        # 3. Email malformata
        bad_email_form = {
            "domain": "email-test.example.com",
            "upstream": "10.88.0.1:8080",
            "policy": "google_oauth",
            "allowed_emails": "valid@example.com, not-an-email, admin@example.com"
        }
        res_em = self.client.post("/hosts/add", data=bad_email_form, headers={"Accept": "application/json"})
        self.assertEqual(res_em.status_code, 400)
        self.assertIn("Invalid email", res_em.json()["detail"])

    def test_13_csrf_origin_middleware(self):
        """Verify that state-changing POST requests from unauthorized origins/referers receive HTTP 403 Forbidden."""
        form_data = {
            "domain": "csrf-test.example.com",
            "upstream": "10.88.0.1:8080",
            "policy": "bypass"
        }
        # Chiamata con Origin maligno esterno
        res_evil = self.client.post(
            "/hosts/add",
            data=form_data,
            headers={"Origin": "https://attacker-evil-site.com"}
        )
        self.assertEqual(res_evil.status_code, 403)
        self.assertIn("Forbidden", res_evil.text)

        # Chiamata con Referer maligno esterno
        res_evil_ref = self.client.post(
            "/hosts/add",
            data=form_data,
            headers={"Referer": "https://hacker.com/exploit.html"}
        )
        self.assertEqual(res_evil_ref.status_code, 403)

        # Chiamata con Origin valido whitelist (http://localhost:8000)
        res_valid = self.client.post(
            "/hosts/add",
            data=form_data,
            headers={"Origin": "http://localhost:8000"},
            follow_redirects=False
        )
        self.assertIn(res_valid.status_code, (200, 303))

    def test_14_backup_export_and_import(self):
        """Verify atomic configuration export and restore via JSON."""
        # 1. Export backup
        res_export = self.client.get("/backup/export")
        self.assertEqual(res_export.status_code, 200)
        self.assertEqual(res_export.headers.get("content-type"), "application/json")
        self.assertIn("attachment; filename=\"edgeproxy-backup-", res_export.headers.get("content-disposition", ""))

        backup_data = res_export.json()
        self.assertIn("hosts", backup_data)
        self.assertIn("settings", backup_data)
        self.assertIn("sync_tokens", backup_data)

        # 2. Modifica un dato nel payload esportato per testare l'import
        test_domain = "restored-service.example.com"
        backup_data["hosts"].append({
            "domain": test_domain,
            "upstream": "10.88.0.50:9000",
            "policy": "bypass",
            "rathole_port": 8099,
            "rathole_token": "token_restored_123"
        })
        backup_json_bytes = json.dumps(backup_data).encode("utf-8")

        # 3. Import backup
        import io
        files = {
            "file": ("backup.json", io.BytesIO(backup_json_bytes), "application/json")
        }
        res_import = self.client.post("/backup/import", files=files, follow_redirects=False)
        self.assertEqual(res_import.status_code, 303)
        self.assertIn("/settings", res_import.headers.get("location", ""))

        # 4. Verifica che l'host importato sia presente nel database
        hosts = db.get_all_hosts()
        restored_host = next((h for h in hosts if h["domain"] == test_domain), None)
        self.assertIsNotNone(restored_host)
        self.assertEqual(restored_host["upstream"], "10.88.0.50:9000")

    def test_15_noise_transport_and_caddy_log_rotation(self):
        """Verify Rathole Noise_NN_25519_ChaChaPoly_BLAKE2s transport generation and Caddy log rotation rules."""
        hosts = db.get_all_hosts()
        settings = db.get_settings()

        # Rathole Server
        server_toml = config_engine.generate_rathole_server_toml(hosts, settings)
        self.assertIn('type = "noise"', server_toml)
        self.assertIn('[server.transport.noise]', server_toml)
        self.assertIn('pattern = "Noise_NN_25519_ChaChaPoly_BLAKE2s"', server_toml)

        # Rathole Client
        client_toml = config_engine.generate_rathole_client_toml(hosts, settings)
        self.assertIn('type = "noise"', client_toml)
        self.assertIn('[client.transport.noise]', client_toml)
        self.assertIn('pattern = "Noise_NN_25519_ChaChaPoly_BLAKE2s"', client_toml)

        # Caddy Log Rotation
        caddyfile = config_engine.generate_caddyfile(hosts, settings)
        self.assertIn("roll_size 20mb", caddyfile)
        self.assertIn("roll_keep 5", caddyfile)
        self.assertIn("roll_keep_for 14d", caddyfile)

    def test_16_rate_limiting_and_log_purging(self):
        """Verify Caddyfile compatibility with official caddy:alpine image and SQLite access log retention purging."""
        hosts = db.get_all_hosts()
        settings = db.get_settings()

        # Verifica Caddyfile (compatibilità con caddy:alpine upstream senza plugin aggiuntivi)
        caddyfile = config_engine.generate_caddyfile(hosts, settings)
        self.assertNotIn("order rate_limit before basicauth", caddyfile)
        self.assertNotIn("(rate_limits)", caddyfile)
        self.assertNotIn("import rate_limits", caddyfile)

        # Inserisci record vecchi (> 30 giorni) e record recenti
        conn = db.get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO access_logs (created_at, host, method, uri, status, remote_ip, bytes_out)
            VALUES (datetime('now', '-45 days'), 'old.example.com', 'GET', '/old', 200, '1.2.3.4', 100);
        """)
        cur.execute("""
            INSERT INTO access_logs (created_at, host, method, uri, status, remote_ip, bytes_out)
            VALUES (datetime('now', '-2 days'), 'recent.example.com', 'GET', '/new', 200, '1.2.3.4', 200);
        """)
        cur.execute("""
            INSERT INTO bandwidth_stats (host, bucket_ts, bytes_out, requests)
            VALUES ('old.example.com', datetime('now', '-45 days'), 100, 1);
        """)
        cur.execute("""
            INSERT INTO bandwidth_stats (host, bucket_ts, bytes_out, requests)
            VALUES ('recent.example.com', datetime('now', '-2 days'), 200, 1);
        """)
        conn.commit()
        conn.close()

        # Esegui purging con retention 30 giorni
        deleted = db.purge_old_access_logs(days=30)
        self.assertGreaterEqual(deleted, 2)

        # Verifica che il record recente esista ancora
        conn = db.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM access_logs WHERE host = 'recent.example.com';")
        self.assertEqual(cur.fetchone()[0], 1)
        cur.execute("SELECT COUNT(*) FROM access_logs WHERE host = 'old.example.com';")
        self.assertEqual(cur.fetchone()[0], 0)
        conn.close()

    def test_17_rathole_client_placeholder_when_no_active_services(self):
        """Verify security placeholder service in client.toml when no active services are configured."""
        settings = db.get_settings()

        # 1. Lista vuota
        toml_empty = config_engine.generate_rathole_client_toml([], settings)
        self.assertIn("[client.services.default]", toml_empty)
        self.assertIn(f'token = "{config_engine.DEFAULT_PLACEHOLDER_TOKEN}"', toml_empty)
        self.assertIn('local_addr = "127.0.0.1:65535"', toml_empty)

        # Verifica che anche la configurazione server placeholder usi lo stesso token
        server_toml_empty = config_engine.generate_rathole_server_toml([], settings)
        self.assertIn("[server.services.default]", server_toml_empty)
        self.assertIn(f'token = "{config_engine.DEFAULT_PLACEHOLDER_TOKEN}"', server_toml_empty)

        # 2. Host disabilitato o disconnected
        hosts = [
            {"domain": "off.example.com", "enabled": 0, "link_state": "connected", "upstream": "http://127.0.0.1:8080", "rathole_token": "tok1"},
            {"domain": "disc.example.com", "enabled": 1, "link_state": "disconnected", "upstream": "http://127.0.0.1:8081", "rathole_token": "tok2"},
        ]
        toml_inactive = config_engine.generate_rathole_client_toml(hosts, settings)
        self.assertIn("[client.services.default]", toml_inactive)
        self.assertNotIn("[client.services.off_example_com]", toml_inactive)
        self.assertNotIn("[client.services.disc_example_com]", toml_inactive)

        # 3. Almeno un host attivo: il placeholder NON deve comparire
        hosts.append(
            {"domain": "active.example.com", "enabled": 1, "link_state": "connected", "upstream": "http://127.0.0.1:3000", "rathole_token": "tok3"}
        )
        toml_active = config_engine.generate_rathole_client_toml(hosts, settings)
        self.assertNotIn("[client.services.default]", toml_active)
        self.assertIn("[client.services.active]", toml_active)
        self.assertIn('local_addr = "127.0.0.1:3000"', toml_active)

    def test_18_manager_domain_oauth_protection(self):
        """Verify that manager.{$DOMAIN} includes 'import google_auth' only when Google OAuth2 is enabled."""
        hosts = db.get_all_hosts()

        # 1. OAuth non configurato (o disattivato)
        settings_no_oauth = {
            "acme_email": "admin@example.com",
            "google_oauth_enabled": "0",
            "google_client_id": "",
            "google_client_secret": ""
        }
        caddy_no_oauth = config_engine.generate_caddyfile(hosts, settings_no_oauth)
        # The manager.{$DOMAIN:example.com} block must not contain import google_auth
        manager_section_no_oauth = caddy_no_oauth.split("manager.{$DOMAIN:example.com} {")[1].split("auth.{$DOMAIN:example.com} {")[0]
        self.assertNotIn("import google_auth", manager_section_no_oauth)

        # 2. OAuth configured with valid credentials
        settings_oauth = {
            "acme_email": "admin@example.com",
            "google_oauth_enabled": "1",
            "google_client_id": "valid-client-id.apps.googleusercontent.com",
            "google_client_secret": "valid-secret-key"
        }
        caddy_oauth = config_engine.generate_caddyfile(hosts, settings_oauth)
        manager_section_oauth = caddy_oauth.split("manager.{$DOMAIN:example.com} {")[1].split("auth.{$DOMAIN:example.com} {")[0]
        self.assertIn("import google_auth", manager_section_oauth)

    def test_19_security_hardening_perimeter(self):
        """Verify perimeter security hardening: anti-fingerprinting (-Server), dotfile blocking, auth anti-spoofing, and DoS limits."""
        hosts = [
            {
                "id": 1,
                "domain": "secure.mycompany.org",
                "upstream": "10.88.0.50:8080",
                "rathole_port": 8001,
                "policy": "google_oauth",
                "security_headers": 1,
                "enabled": 1
            },
            {
                "id": 2,
                "domain": "api-token.mycompany.org",
                "upstream": "10.88.0.51:8080",
                "rathole_port": 8002,
                "policy": "service_token",
                "service_token": "secret-token-xyz",
                "security_headers": 1,
                "enabled": 1
            },
            {
                "id": 3,
                "domain": "public.mycompany.org",
                "upstream": "10.88.0.52:8080",
                "rathole_port": 8003,
                "policy": "public",
                "security_headers": 1,
                "enabled": 1
            }
        ]
        settings = {
            "acme_email": "admin@example.com",
            "google_oauth_enabled": "1",
            "google_client_id": "client-id",
            "google_client_secret": "client-secret"
        }
        caddyfile = config_engine.generate_caddyfile(hosts, settings)

        # 1. Anti-Fingerprinting and Stealth Hardening (Server: EdgeProxy everywhere)
        self.assertIn('Server "EdgeProxy"', caddyfile)
        self.assertNotIn("-Server", caddyfile)
        self.assertIn(':80 {', caddyfile)
        self.assertIn(':443 {', caddyfile)
        self.assertIn('respond "Unauthorized" 401', caddyfile)

        # 2. Block Dotfiles and Hidden Files (@hidden_files path */.* with status 404 and close)
        self.assertIn("@hidden_files path */.*", caddyfile)
        self.assertIn('respond "404 Not Found" 404 {', caddyfile)
        self.assertIn("close", caddyfile)

        # 3. DoS Protection on Payload and Buffers
        self.assertIn("request_body {", caddyfile)
        self.assertIn("max_size 100MB", caddyfile)

        # 4. Advanced Security Headers (HSTS, nosniff, SAMEORIGIN, Referrer-Policy, Permissions-Policy)
        self.assertIn("Strict-Transport-Security", caddyfile)
        self.assertIn("X-Content-Type-Options \"nosniff\"", caddyfile)
        self.assertIn("X-Frame-Options \"SAMEORIGIN\"", caddyfile)
        self.assertIn("Referrer-Policy \"strict-origin-when-cross-origin\"", caddyfile)
        self.assertIn("Permissions-Policy \"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()\"", caddyfile)

        # 5. Authentication Header Anti-Spoofing
        # In google_auth snippet
        google_auth_snippet = caddyfile.split("(google_auth) {")[1].split("manager.{$DOMAIN:example.com} {")[0]
        self.assertIn("header_up -X-Auth-Request-User", google_auth_snippet)
        self.assertIn("header_up -X-Auth-Request-Email", google_auth_snippet)

        # Nel reverse_proxy di host pubblici e service_token
        public_section = caddyfile.split("public.mycompany.org {")[1]
        self.assertIn("header_up -X-Auth-Request-User", public_section)
        self.assertIn("header_up -X-Auth-Request-Email", public_section)

        token_section = caddyfile.split("api-token.mycompany.org {")[1].split("public.mycompany.org {")[0]
        self.assertIn("header_up -X-Auth-Request-User", token_section)
        self.assertIn("header_up -X-Auth-Request-Email", token_section)


    def test_20_client_ping_and_latency_telemetry(self):
        """Verify client ping endpoint, RTT latency telemetry reporting, and telemetry data retention."""
        # 1. Test endpoint GET /api/v1/client/ping
        ping_res = self.client.get("/api/v1/client/ping")
        self.assertEqual(ping_res.status_code, 200)
        self.assertEqual(ping_res.text, "pong")

        # 2. Test invio report con latency_ms
        tokens = db.get_sync_tokens()
        self.assertTrue(len(tokens) > 0)
        token = tokens[0]["token"]

        report_payload = {
            "client_name": "test-telemetry-node",
            "uptime_seconds": 120,
            "version": "rathole 0.5.0",
            "hostname": "worker-node-test",
            "latency_ms": 42.5,
            "logs": [{"level": "info", "message": "Link healthy"}]
        }
        report_res = self.client.post(
            "/api/v1/client/report",
            headers={"Authorization": f"Bearer {token}"},
            json=report_payload
        )
        self.assertEqual(report_res.status_code, 200)
        self.assertEqual(report_res.json().get("status"), "ok")

        # Verifica persistenza stato client e latenza
        active_clients = db.get_active_clients()
        matching = [c for c in active_clients if c["client_name"] == "test-telemetry-node"]
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0]["latency_ms"], 42.5)

        # 3. Test endpoint GET /api/v1/stats/latency
        stats_res = self.client.get("/api/v1/stats/latency?hours=24")
        self.assertEqual(stats_res.status_code, 200)
        stats_data = stats_res.json()
        self.assertEqual(stats_data.get("status"), "ok")
        self.assertIn(42.5, stats_data.get("values", []))

        # 4. Test Data Aging (svecchiamento automatico dei record di latenza)
        # Inserisce un record vecchio (35 giorni fa)
        conn = db.get_db_connection()
        conn.execute("INSERT INTO client_latency_stats (client_name, latency_ms, recorded_at) VALUES ('old-node', 99.9, datetime('now', '-35 days'));")
        conn.commit()
        conn.close()

        deleted = db.purge_old_access_logs(days=30)
        self.assertGreaterEqual(deleted, 1)

        # Verifica che il record di oltre 30 giorni sia stato eliminato
        conn = db.get_db_connection()
        row = conn.execute("SELECT COUNT(*) FROM client_latency_stats WHERE client_name = 'old-node';").fetchone()
        conn.close()
        self.assertEqual(row[0], 0)


    def test_client_log_exclusion_and_outbound_traffic_stats(self):
        """Test anti-flood filter for /api/v1/client and per-host outbound traffic tracking with auto/manual reset."""
        import stats

        # 1. Test anti-flood exclusion in stats.parse_caddy_log_line
        client_sync_line = json.dumps({
            "ts": 1700000000.0,
            "request": {"host": "auth.example.com", "uri": "/api/v1/client/config", "method": "GET"},
            "status": 200,
            "size": 1500
        })
        self.assertIsNone(stats.parse_caddy_log_line(client_sync_line))

        client_telemetry_line = json.dumps({
            "ts": 1700000000.0,
            "request": {"host": "auth.example.com", "uri": "/api/v1/client/telemetry", "method": "POST"},
            "status": 200,
            "size": 250
        })
        self.assertIsNone(stats.parse_caddy_log_line(client_telemetry_line))

        normal_line = json.dumps({
            "ts": 1700000000.0,
            "request": {"host": "demo.mycompany.org", "uri": "/dashboard", "method": "GET"},
            "status": 200,
            "size": 4096
        })
        parsed = stats.parse_caddy_log_line(normal_line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0]["host"], "demo.mycompany.org")
        self.assertEqual(parsed[2], 4096)

        # 2. Test incrementing traffic stats
        test_host = "traffic-test.example.com"
        db.increment_host_traffic(test_host, 1024 * 1024, 1)  # 1 MB, 1 req
        traffic_list = db.get_all_host_traffic_stats()
        found = next((t for t in traffic_list if t["host"] == test_host), None)
        self.assertIsNotNone(found)
        self.assertEqual(found["bytes_out"], 1024 * 1024)
        self.assertEqual(found["requests_count"], 1)
        self.assertIn("1.00 MB", found["formatted_bytes"])
        self.assertIn("bytes_today", found)
        self.assertIn("bytes_today_formatted", found)

        # Second increment
        db.increment_host_traffic(test_host, 2 * 1024 * 1024, 4)
        traffic_list = db.get_all_host_traffic_stats()
        found = next((t for t in traffic_list if t["host"] == test_host), None)
        self.assertEqual(found["bytes_out"], 3 * 1024 * 1024)
        self.assertEqual(found["requests_count"], 5)

        # 3. Test 30-day auto-reset
        conn = db.get_db_connection()
        conn.execute("UPDATE host_traffic_stats SET last_reset = datetime('now', '-31 days') WHERE host = ?;", (test_host,))
        conn.commit()
        conn.close()

        # Calling increment after 30 days should reset old counters and set to new values
        db.increment_host_traffic(test_host, 500, 1)
        traffic_list = db.get_all_host_traffic_stats()
        found = next((t for t in traffic_list if t["host"] == test_host), None)
        self.assertEqual(found["bytes_out"], 500)
        self.assertEqual(found["requests_count"], 1)

        # 4. Test API GET /api/v1/stats/traffic
        api_res = self.client.get("/api/v1/stats/traffic")
        self.assertEqual(api_res.status_code, 200)
        api_data = api_res.json()
        self.assertEqual(api_data.get("status"), "ok")
        self.assertTrue(any(t["host"] == test_host for t in api_data.get("traffic", [])))

        # 5. Test manual reset via POST /stats/traffic/reset for single host
        reset_res = self.client.post("/stats/traffic/reset", data={"host": test_host}, follow_redirects=False)
        self.assertEqual(reset_res.status_code, 303)

        traffic_list = db.get_all_host_traffic_stats()
        found = next((t for t in traffic_list if t["host"] == test_host), None)
        self.assertEqual(found["bytes_out"], 0)
        self.assertEqual(found["requests_count"], 0)

        # 6. Test manual reset for all hosts
        db.increment_host_traffic("host-a.example.com", 2000, 2)
        db.increment_host_traffic("host-b.example.com", 3000, 3)
        reset_all_res = self.client.post("/stats/traffic/reset", follow_redirects=False)
        self.assertEqual(reset_all_res.status_code, 303)

        traffic_list = db.get_all_host_traffic_stats()
        for t in traffic_list:
            if t["host"] in ("host-a.example.com", "host-b.example.com"):
                self.assertEqual(t["bytes_out"], 0)
                self.assertEqual(t["requests_count"], 0)

        # 7. Test /stats HTML view contains new table section
        stats_html_res = self.client.get("/stats")
        self.assertEqual(stats_html_res.status_code, 200)
        self.assertIn("Per-Host Outbound Traffic (30-Day Auto-Reset)", stats_html_res.text)
        self.assertIn("/stats/traffic/reset", stats_html_res.text)

    def test_daily_outbound_traffic_stats(self):
        """Test calculation of daily outbound traffic (bytes_today, bytes_today_formatted) in get_all_host_traffic_stats()."""
        host1 = "daily-test.example.com"
        host2 = "older-test.example.com"

        # Inserisci dati recenti (< 24h) in bandwidth_stats
        conn = db.get_db_connection()
        conn.execute("""
            INSERT INTO bandwidth_stats (host, bucket_ts, bytes_out, requests)
            VALUES (?, datetime('now', '-2 hours'), 5242880, 10);
        """, (host1,))
        # Inserisci dati vecchi (> 24h) in bandwidth_stats
        conn.execute("""
            INSERT INTO bandwidth_stats (host, bucket_ts, bytes_out, requests)
            VALUES (?, datetime('now', '-48 hours'), 10485760, 20);
        """, (host2,))
        conn.commit()
        conn.close()

        # Inserisci anche traffico cumulativo
        db.increment_host_traffic(host1, 5242880, 10)
        db.increment_host_traffic(host2, 10485760, 20)

        traffic = db.get_all_host_traffic_stats()
        h1_stat = next((t for t in traffic if t["host"] == host1), None)
        h2_stat = next((t for t in traffic if t["host"] == host2), None)

        self.assertIsNotNone(h1_stat)
        self.assertIn("bytes_today", h1_stat)
        self.assertIn("bytes_today_formatted", h1_stat)
        self.assertEqual(h1_stat["bytes_today"], 5242880)
        self.assertIn("5.00 MB", h1_stat["bytes_today_formatted"])

        self.assertIsNotNone(h2_stat)
        self.assertIn("bytes_today", h2_stat)
        self.assertIn("bytes_today_formatted", h2_stat)
        self.assertEqual(h2_stat["bytes_today"], 0)
        self.assertEqual(h2_stat["bytes_today_formatted"], "0 B")

        # Verifica API /api/v1/stats/traffic
        api_res = self.client.get("/api/v1/stats/traffic")
        self.assertEqual(api_res.status_code, 200)
        api_data = api_res.json()
        item = next((t for t in api_data["traffic"] if t["host"] == host1), None)
        self.assertIsNotNone(item)
        self.assertEqual(item["bytes_today"], 5242880)
        self.assertIn("5.00 MB", item["bytes_today_formatted"])

        # Verifica stats.html contiene colonna Daily Outbound (24h) e badge-neutral per reset sobrio
        html_res = self.client.get("/stats")
        self.assertEqual(html_res.status_code, 200)
        self.assertIn("Daily Outbound (24h)", html_res.text)
        self.assertIn("badge-neutral", html_res.text)

    def test_32_access_logs_filtering(self):
        """Verify advanced access logs filtering by HTTP status, client IP, and host."""
        # Prepara log di test diversificati
        test_host1 = "filter-a.test.internal"
        test_host2 = "filter-b.test.internal"
        sample_logs = [
            {"ts": "2026-10-28 10:00:00", "created_at": "2026-10-28 10:00:00", "host": test_host1, "method": "GET", "uri": "/api/test200", "status": 200, "remote_ip": "192.168.1.50", "bytes": 100, "duration_ms": 1.2},
            {"ts": "2026-10-28 10:01:00", "created_at": "2026-10-28 10:01:00", "host": test_host1, "method": "GET", "uri": "/api/test302", "status": 302, "remote_ip": "192.168.1.51", "bytes": 120, "duration_ms": 2.1},
            {"ts": "2026-10-28 10:02:00", "created_at": "2026-10-28 10:02:00", "host": test_host1, "method": "GET", "uri": "/api/test401", "status": 401, "remote_ip": "192.168.1.52", "bytes": 150, "duration_ms": 3.0},
            {"ts": "2026-10-28 10:03:00", "created_at": "2026-10-28 10:03:00", "host": test_host1, "method": "GET", "uri": "/api/test403", "status": 403, "remote_ip": "93.38.118.10", "bytes": 200, "duration_ms": 1.5},
            {"ts": "2026-10-28 10:04:00", "created_at": "2026-10-28 10:04:00", "host": test_host1, "method": "GET", "uri": "/api/test404", "status": 404, "remote_ip": "93.38.118.20", "bytes": 220, "duration_ms": 2.2},
            {"ts": "2026-10-28 10:05:00", "created_at": "2026-10-28 10:05:00", "host": test_host1, "method": "POST", "uri": "/api/test502", "status": 502, "remote_ip": "10.0.0.99", "bytes": 300, "duration_ms": 45.0},
            {"ts": "2026-10-28 10:06:00", "created_at": "2026-10-28 10:06:00", "host": test_host2, "method": "GET", "uri": "/b/test401", "status": 401, "remote_ip": "192.168.1.99", "bytes": 140, "duration_ms": 1.1},
            {"ts": "2026-10-28 10:07:00", "created_at": "2026-10-28 10:07:00", "host": test_host2, "method": "GET", "uri": "/b/test200", "status": 200, "remote_ip": "10.0.0.50", "bytes": 110, "duration_ms": 0.9},
        ]
        db.insert_access_logs_batch(sample_logs)

        # 1. Test livello DB: filtro codice numerico esatto (401)
        res_401 = db.get_recent_access_logs(status="401", limit=20)
        self.assertTrue(all(r["status"] == 401 for r in res_401))
        self.assertGreaterEqual(len(res_401), 2)

        # 2. Test livello DB: filtro classe 4xx
        res_4xx = db.get_recent_access_logs(status="4xx", limit=20)
        self.assertTrue(all(400 <= r["status"] < 500 for r in res_4xx))
        statuses_found = {r["status"] for r in res_4xx if r["host"] in (test_host1, test_host2)}
        self.assertIn(401, statuses_found)
        self.assertIn(403, statuses_found)
        self.assertIn(404, statuses_found)
        self.assertNotIn(200, statuses_found)
        self.assertNotIn(502, statuses_found)

        # 3. Test livello DB: filtro IP LIKE (subnet '93.38.')
        res_ip = db.get_recent_access_logs(ip="93.38.", limit=20)
        self.assertTrue(all("93.38." in r["remote_ip"] for r in res_ip))
        self.assertGreaterEqual(len(res_ip), 2)

        # 4. Test livello DB: filtro Host specifico
        res_host1 = db.get_recent_access_logs(host=test_host1, limit=50)
        self.assertTrue(all(r["host"] == test_host1 for r in res_host1))
        self.assertEqual(len(res_host1), 6)

        # 5. Test livello DB: filtri combinati (host1 + 4xx + subnet 192.168.)
        res_combined = db.get_recent_access_logs(host=test_host1, status="4xx", ip="192.168.", limit=20)
        self.assertEqual(len(res_combined), 1)
        self.assertEqual(res_combined[0]["status"], 401)
        self.assertEqual(res_combined[0]["remote_ip"], "192.168.1.52")

        # 6. Test livello API: GET /api/v1/stats/access con status=4xx
        api_4xx = self.client.get("/api/v1/stats/access?status=4xx&limit=50")
        self.assertEqual(api_4xx.status_code, 200)
        data_4xx = api_4xx.json()
        self.assertEqual(data_4xx["status"], "ok")
        self.assertTrue(all(400 <= l["status"] < 500 for l in data_4xx["logs"]))

        # 7. Test livello API: GET /api/v1/stats/access con status=401 e host
        api_401 = self.client.get(f"/api/v1/stats/access?host={test_host2}&status=401")
        self.assertEqual(api_401.status_code, 200)
        data_401 = api_401.json()
        self.assertEqual(len(data_401["logs"]), 1)
        self.assertEqual(data_401["logs"][0]["host"], test_host2)
        self.assertEqual(data_401["logs"][0]["status"], 401)

        # 8. Test livello API: GET /api/v1/stats/access con filtro IP
        api_ip = self.client.get("/api/v1/stats/access?ip=93.38.118.&limit=50")
        self.assertEqual(api_ip.status_code, 200)
        data_ip = api_ip.json()
        self.assertGreaterEqual(len(data_ip["logs"]), 2)
        self.assertTrue(all("93.38.118." in l["remote_ip"] for l in data_ip["logs"]))

        # 9. Test endpoint view /stats con filtri preimpostati e componenti UI
        view_res = self.client.get(f"/stats?host={test_host1}&status=4xx&ip=192.168.")
        self.assertEqual(view_res.status_code, 200)
        self.assertIn("Select Host", view_res.text)
        self.assertIn("Select Status / Outcome", view_res.text)
        self.assertIn("Filter by Client IP", view_res.text)
        self.assertIn("loadAccessLogs", view_res.text)
        self.assertIn("resetAccessFilters", view_res.text)
        # Verifica che il log prefiltrato sia renderizzato
        self.assertIn(test_host1, view_res.text)
        self.assertIn("192.168.1.52", view_res.text)


if __name__ == "__main__":
    unittest.main()
