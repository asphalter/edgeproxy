# Active Context — EdgeProxy

> **CRITICAL DIRECTIVE — REMOTE SSH ACCESS REVOKED**:
> L'accesso SSH alla VPS remota (`edge.mpv.cx` / `130.110.9.121`) è stato definitivamente revocato dall'utente ed è **STRETTAMENTE PROIBITO**.
> Nessun tentativo di connessione SSH remota deve essere mai eseguito.
> Tutte le attività di sviluppo, compilazione, testing e verifica sono eseguite esclusivamente in locale all'interno di container Podman effimeri (`--rm`).

## Stato Corrente

- **Architettura Unificata a Container Singoli (Completata - Ottobre 2026)**:
  - **1. Server All-in-One (`edgeproxy-server`)**:
    - Containerfile multi-stage [`server/Containerfile`](server/Containerfile) basato su `python:3.12-alpine`, estraendo i binari ufficiali di `caddy` da `docker.io/caddy:alpine`, `oauth2-proxy` da `quay.io/oauth2-proxy/oauth2-proxy:latest`, e `rathole` da `docker.io/rapiz1/rathole:latest` con relative librerie condivise GNU.
    - Script [`server/entrypoint.sh`](server/entrypoint.sh) e supervisore [`server/supervisord.conf`](server/supervisord.conf) per il coordinamento interno dei processi (Caddy su `:80/:443/:2019`, OAuth2-Proxy su `:4180`, Rathole Server su `:2333 WAN` e loopback `:8001+`, Manager su `127.0.0.1:8000`).
    - Volume persistente unificato `/data` per SQLite (`edgeproxy.db`), certificati TLS ACME Caddy e configurazioni live.
    - Gestione nativa via Quadlet: [`server/quadlet/edgeproxy-server.container`](server/quadlet/edgeproxy-server.container) e [`server/quadlet/edgeproxy_data.volume`](server/quadlet/edgeproxy_data.volume).
  - **2. Client All-in-One (`edgeproxy-client`) e Quadlet Web UI**:
    - Containerfile [`client/Containerfile`](client/Containerfile) con binario Rathole e runtime Alpine.
    - Script [`client/entrypoint.sh`](client/entrypoint.sh) che esegue polling zero-touch a 15s dall'API `/api/v1/client/config` ed avvia e riavvia Rathole a caldo senza interruzioni.
    - Quadlet client: [`client/quadlet/edgeproxy-client.container`](client/quadlet/edgeproxy-client.container) e [`client/quadlet/edgeproxy_client_data.volume`](client/quadlet/edgeproxy_client_data.volume).
    - Web UI Manager: visualizzazione e copia rapida del file Quadlet precompilato con URL e token nella scheda Client Config.
  - **3. Scripting e CI/CD**:
    - Script locale unificato [`scripts/build-images.sh`](scripts/build-images.sh) per compilare entrambe le immagini in locale (`localhost/edgeproxy-server:latest` e `localhost/edgeproxy-client:latest`).
    - GitHub Actions Workflow [`.github/workflows/build-and-push.yml`](.github/workflows/build-and-push.yml) per la compilazione e pubblicazione automatizzata su `ghcr.io`.
  - **4. Pulizia Repository e Documentazione**:
    - Eliminati tutti i vecchi Quadlet del pod multi-container, vecchi tarball, file `.env.example`, vecchi script di deploy/installazione e Containerfile ridondanti.
    - Rimosso [`INSTALL.md`](INSTALL.md) e consolidata tutta la documentazione di installazione e architettura in [`README.md`](README.md).
  - **5. Stealth Hardening & Black-boxing Caddy (Ottobre 2026)**:
    - Rimosso qualsiasi banner default Caddy e impostato tassativamente l'header uniforme `Server: EdgeProxy` su tutte le risposte HTTP/HTTPS (apex, vhost UI manager/auth, host proxati e blocchi di fallback).
    - Risposta `401 Unauthorized` con chiusura immediata della connessione TCP (`close`) su apex domain e per qualsiasi richiesta ad IP diretto o hostname non gestito su `:80` e `:443`.
  - **6. Telemetria Latenza RTT e Visualizzazione UI (Ottobre 2026)**:
    - Misurazione automatica pura del 3-way handshake RTT TCP (sottraendo il tempo DNS `time_namelookup` da `time_connect`) in millisecondi in [`client/entrypoint.sh`](client/entrypoint.sh) verso `/api/v1/client/ping`.
    - Tabella persistente `client_latency_stats` e colonna `latency_ms` in `client_status` con migrazione dinamica in [`server/manager/db.py`](server/manager/db.py).
    - Data aging automatico dei record di latenza in [`db.purge_old_access_logs()`](server/manager/db.py:790).
    - Endpoint API `GET /api/v1/stats/latency?hours=24` per Chart.js.
    - Card con badge cromatico per "Tunnel Latency" in [`dashboard.html`](server/manager/templates/dashboard.html), campo telemetria in tempo reale in [`links.html`](server/manager/templates/links.html) e grafico Chart.js dedicato in [`stats.html`](server/manager/templates/stats.html).
  - **7. Open-Source Scrubbing, Traduzione Integrale in Inglese e Riscrizione README (Ottobre 2026)**:
    - Rimosso qualsiasi riferimento residuo ad email o domini specifici (`matteo.piva@gmail.com`, `mpv.cx`, `edge.mpv.cx`) dai default, configurazioni di Caddy, OAuth2-Proxy, Quadlet, templates e database seed, sostituendoli con `example.com` e `admin@example.com`.
    - Traduzione integrale in lingua inglese di commenti, docstring, messaggi di log, printout a terminale, form hints, script shell [`scripts/build-images.sh`](scripts/build-images.sh) e test unitari [`tests/test_manager.py`](tests/test_manager.py).
    - Rimozione definitiva di `INSTALL.md` e riscrittura di [`README.md`](README.md) come presentazione ufficiale open-source GitHub con guida passo-passo completa, diagrammi e troubleshooting.
  - **8. Brand Asset Rendering (Ottobre 2026)**:
    - Generato asset ad alta risoluzione [`docs/assets/logo.png`](docs/assets/logo.png) (2400x1020 RGBA) tramite container Podman effimero.
    - Rimosso il file SVG intermedio mantenendo esclusivamente [`docs/assets/logo.png`](docs/assets/logo.png).
    - Aggiornato [`README.md`](README.md) per includere [`docs/assets/logo.png`](docs/assets/logo.png).
