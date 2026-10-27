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
    - Guide [`INSTALL.md`](INSTALL.md) e [`README.md`](README.md) interamente riscritte per illustrare esclusivamente la distribuzione con container GHCR precompilati e Quadlet.
