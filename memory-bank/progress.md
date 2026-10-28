# Progress — EdgeProxy

## Completato

- [x] **Riprogettazione Radicale Rilascio e Deployment All-in-One su GHCR (Ottobre 2026)**:
  - [x] Creato [`server/Containerfile`](server/Containerfile) multi-stage compatto basato su `python:3.12-alpine`, che estrae i binari di `caddy`, `oauth2-proxy` e `rathole` con dipendenze shared libraries e include `supervisor`.
  - [x] Creati [`server/entrypoint.sh`](server/entrypoint.sh) e [`server/supervisord.conf`](server/supervisord.conf) per l'orchestrazione locale a loopback dei 4 processi e il seeding automatico di `/data`.
  - [x] Creati i file Quadlet server definitivi: [`server/quadlet/edgeproxy-server.container`](server/quadlet/edgeproxy-server.container) e il volume [`server/quadlet/edgeproxy_data.volume`](server/quadlet/edgeproxy_data.volume).
  - [x] Aggiornato [`server/manager/config_engine.py`](server/manager/config_engine.py) per la scrittura in `/data/` e il supporto di riavvio nativo via `supervisorctl`.
  - [x] Aggiornato [`server/manager/linkmon.py`](server/manager/linkmon.py) per la lettura del file log rathole `/var/log/rathole.log` nel container unico.
  - [x] Aggiornato [`server/manager/db.py`](server/manager/db.py) per l'utilizzo automatico di `/data/edgeproxy.db`.
  - [x] Configurato [`client/quadlet/edgeproxy-client.container`](client/quadlet/edgeproxy-client.container) e [`client/quadlet/edgeproxy_client_data.volume`](client/quadlet/edgeproxy_client_data.volume).
  - [x] Aggiornato [`server/manager/templates/client_config.html`](server/manager/templates/client_config.html) con il box evidenziato del Quadlet Client precompilato e pulsante di copia rapida.
  - [x] Creato e perfezionato il workflow GitHub Actions [`.github/workflows/build-and-push.yml`](.github/workflows/build-and-push.yml) per la compilazione e il push automatico su `ghcr.io` con lowercasing automatico di `repository_owner`, permessi espliciti `packages: write` e supporto a `workflow_dispatch`.
- [x] **Pulizia e Consolidamento Repository**:
  - [x] Rimossi i vecchi Quadlet del pod (`edgeproxy.pod`, `caddy.container`, `manager.container`, `oauth2-proxy.container`, `rathole.container`, `caddy_config.volume`, `caddy_data.volume`).
  - [x] Rimossi vecchi script e tarball (`deploy-vps.sh`, `scripts/remote-deploy.sh`, `scripts/build-server-release.sh`, `scripts/build-client-release.sh`, `client/install.sh`, `client/sync-agent.sh`, `*.tar.gz`).
  - [x] Rimossi `.env.example`, `server/caddy/Containerfile` e `server/manager/edgeproxy.db`.
  - [x] Creato script unificato di compilazione locale [`scripts/build-images.sh`](scripts/build-images.sh).
  - [x] Riscritte integralmente le guide di installazione e documentazione ([`INSTALL.md`](INSTALL.md) e [`README.md`](README.md)).
  - [x] Aggiornata integralmente la Memory Bank.
  - [x] **Allineamento Token Rathole Placeholder**:
    - [x] Uniformato il token per il servizio placeholder `default` su server e client a `DEFAULT_PLACEHOLDER_TOKEN = "0000000000000000000000000000000000000000"` in [`server/manager/config_engine.py`](server/manager/config_engine.py:14) e [`server/rathole/server.toml`](server/rathole/server.toml:15).
    - [x] Estesi i test unitari in [`tests/test_manager.py`](tests/test_manager.py:643) per verificare la coerenza del placeholder server/client.
  - [x] **Hardening Perimetrale Completo Porte 80 e 443**:
    - [x] **Blocco Dotfiles e File Nascosti**: intercettazione di pattern `*/.*` con `@hidden_files` e risposta `404 Not Found` con chiusura immediata forzata del socket TCP (`close`).
    - [x] **Anti-Spoofing Header di Autenticazione**: rimozione preventiva di `X-Auth-Request-User` e `X-Auth-Request-Email` in `(google_auth)` e nei reverse proxy pubblici o con token, garantendo l'inoltro esclusivamente se autenticati da OAuth2-Proxy.
    - [x] **Protezione DoS Payload/Buffer**: enforcement di `request_body { max_size 100MB }` su ogni blocco e host.
    - [x] **Security Headers Avanzati**: enforcement HSTS preload, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin` e `Permissions-Policy`.
  - [x] **Stealth Hardening / Black-boxing Caddy & Telemetria Latenza (Ottobre 2026)**:
    - [x] **Stealth Black-boxing**: rimozione della risposta 200 "EdgeProxy Gateway" dall'apex domain (`edge.mpv.cx`) sostituita con `401 Unauthorized` e chiusura connessione TCP (`close`).
    - [x] **Catch-all 401 per IP e SNI sconosciuti**: risposte di default forzate a `401 Unauthorized` per connessioni dirette a `:80` e `:443` con hostname o IP non configurati.
    - [x] **Server Header Uniforme**: impostazione tassativa dell'header `Server: EdgeProxy` su tutte le risposte Caddyfile, Manager UI, Auth e vhost proxati.
    - [x] **Client Probing RTT Latenza**: misurazione rapida con curl e invio di `latency_ms` nel payload a `/api/v1/client/report` in [`client/entrypoint.sh`](client/entrypoint.sh).
    - [x] **Backend & Data Aging**: endpoint leggero `GET /api/v1/client/ping`, tabella SQLite `client_latency_stats`, colonna `latency_ms` con migrazione automatica, svecchiamento automatico dei dati in [`db.purge_old_access_logs()`](server/manager/db.py:790), e API `GET /api/v1/stats/latency?hours=24`.
    - [x] **Web UI Dashboard, Links & Stats**: stat card "Tunnel Latency" con badge colorato per soglia ms in [`dashboard.html`](server/manager/templates/dashboard.html), telemetria latenza in tempo reale in [`links.html`](server/manager/templates/links.html), e grafico Chart.js dedicato all'andamento RTT in [`stats.html`](server/manager/templates/stats.html).
    - [x] **Validazione e Test Suite Completa**: validazione Caddyfile con `caddy validate` ed esecuzione completa della test suite unitaria [`tests/test_manager.py`](tests/test_manager.py) in container Podman effimero (20/20 test superati con successo).

  ## Da Fare / Prossimi Passi

- [ ] Monitoraggio e audit periodico del perimetro di esposizione.
