# System Patterns — EdgeProxy

## Architettura Logica Generale

Il sistema è suddiviso in due ambienti operativi isolati:

- **VPS Edge Gateway (Server-Side All-in-One)**: un singolo container OCI (`edgeproxy-server`) che incapsula Caddy v2, OAuth2-Proxy, Rathole Server e Manager Web UI orchestrati su loopback (`127.0.0.1`) con `supervisord` e un volume persistente unificato `edgeproxy_data` montato in `/data`.
- **Backend Locale / LAN (Client-Side All-in-One)**: un singolo container OCI (`edgeproxy-client`) che avvia il processo Rathole Client verso la porta `2333` WAN della VPS via Noise Protocol ed esegue il polling zero-touch a 15s tramite [`client/entrypoint.sh`](client/entrypoint.sh).

```mermaid
flowchart LR
    subgraph WAN_Public["Internet Pubblico"]
        Browser[Browser / Utente]
    end

    subgraph VPS["VPS Edge Server (Singolo Container All-in-One: edgeproxy-server)"]
        direction TB
        Caddy[Caddy Reverse Proxy :80, :443]
        OAuth2[OAuth2-Proxy :4180]
        RatholeServer[Rathole Server :2333 WAN, :8001+ Loopback]
        Manager[Manager Web UI :8000]
        Supervisord[Supervisor Init Loopback]
    end

    subgraph LAN["Rete Locale Protetta (HomeLab / Ufficio: edgeproxy-client)"]
        Client[All-in-One Client Container]
        LocalApps[Servizi Interni :8123, :8080, :3000]
    end

    Browser -->|HTTPS 443 TCP/UDP| Caddy
    Caddy -->|forward_auth| OAuth2
    Caddy -->|reverse_proxy 127.0.0.1:8001+| RatholeServer
    Caddy -->|Manager Route| Manager
    RatholeServer <==|Tunnel TCP Noise :2333 Outbound| Client
    Client -->|Sync 15s HTTPS| Manager
    Client --> LocalApps
```

## Pattern Architetturali

### 1. Singolo Container All-in-One con Supervisord (Server)
- Multi-stage build in [`server/Containerfile`](server/Containerfile) che estrae da immagini upstream ufficiali (`caddy:alpine`, `oauth2-proxy`, `rathole`) e crea un runtime Python 3.12 Alpine snello.
- Entrypoint [`server/entrypoint.sh`](server/entrypoint.sh) che verifica e inizializza `/data` (`/data/edgeproxy.db`, `/data/caddy/Caddyfile`, `/data/rathole/server.toml`, `/data/oauth2-proxy/oauth2-proxy.cfg`) e avvia `supervisord`.
- Processi gestiti da [`server/supervisord.conf`](server/supervisord.conf):
  - `rathole`: bind porta WAN `2333` e local service ports `127.0.0.1:8001+`.
  - `oauth2-proxy`: bind `127.0.0.1:4180` per validazione sessioni Google OAuth2.
  - `caddy`: bind porte pubbliche `80` e `443` (TCP e UDP/QUIC) e admin API `127.0.0.1:2019`.
  - `manager`: bind `127.0.0.1:8000` (FastAPI Web UI + API sync client).

### 2. Singolo Container All-in-One Zero-Touch (Client)
- Containerfile [`client/Containerfile`](client/Containerfile) basato su Alpine con binario `rathole`, `curl`, `jq` e `ca-certificates`.
- Entrypoint [`client/entrypoint.sh`](client/entrypoint.sh):
  - Contatta l'API del Manager `GET /api/v1/client/config` con header `X-Client-Token`.
  - Se la configurazione cambia (o al primo avvio), scrive `/etc/rathole/client.toml` e avvia/riavvia `rathole`.
  - Esegue un loop di polling ogni 15 secondi per garantire la convergenza dinamica dei tunnel.

### 3. Integrazione Podman Quadlet Nativamente Integrata in systemd
- Sul server: file unit [`server/quadlet/edgeproxy-server.container`](server/quadlet/edgeproxy-server.container) e [`server/quadlet/edgeproxy_data.volume`](server/quadlet/edgeproxy_data.volume).
- Sul client: file unit [`client/quadlet/edgeproxy-client.container`](client/quadlet/edgeproxy-client.container) e [`client/quadlet/edgeproxy_client_data.volume`](client/quadlet/edgeproxy_client_data.volume).
- Nessuna dipendenza da compose, script bash di avvio o tarball.
