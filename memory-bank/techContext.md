# Tech Context — EdgeProxy

## Componenti Tecnologici

### Rathole
- Reverse tunnel ad alte prestazioni scritto in Rust.
- Crittografia end-to-end con Noise Protocol sul trasporto WAN (porta `2333/tcp`).
- **Multiplexing**: singolo canale cifrato che trasporta molteplici servizi interni (`[server.services.<name>]` e `[client.services.<name>]`), ciascuno con token dedicato.
- Nel container server: binding dei servizi su `127.0.0.1` (`8001`, `8002`, ...), raggiunti localmente da Caddy come upstream.

### Caddy v2
- Web server e reverse proxy scritto in Go con gestione automatica certificati SSL/TLS via ACME (Let's Encrypt / ZeroSSL).
- Ricaricamento a caldo a zero downtime tramite Admin API (`POST http://127.0.0.1:2019/load`).
- Supporto per HTTP/1.1, HTTP/2 e HTTP/3 (QUIC) su porte `80` e `443` (TCP/UDP).
- Protezione degli endpoint con snippet `forward_auth` collegato a OAuth2-Proxy (`http://127.0.0.1:4180`).

### OAuth2-Proxy
- Reverse proxy di autenticazione per OpenID Connect / OAuth2 (Google Workspace e account Google).
- Verifica sessione tramite cookie cifrato e validazione su `authenticated_emails.txt`.
- Fornisce gli endpoint `/oauth2/auth` e `/oauth2/sign_in` richiamati da Caddy.

### EdgeProxy Manager
- Web UI e motore di orchestrazione basato su FastAPI (Python 3.12).
- Database SQLite memorizzato nel volume unificato `/data/edgeproxy.db`.
- Motore di configurazione [`server/manager/config_engine.py`](server/manager/config_engine.py) per la generazione atomica delle configurazioni e il riavvio via `supervisorctl`.
- Monitoraggio link [`server/manager/linkmon.py`](server/manager/linkmon.py) tramite parsing del log rathole `/var/log/rathole.log`.

### Podman & Quadlet (Container Singoli)
- Rootless/root container nativi OCI gestiti direttamente come servizi systemd tramite Podman Quadlet (`/etc/containers/systemd/`).
- **Server**: [`server/quadlet/edgeproxy-server.container`](server/quadlet/edgeproxy-server.container) monta il volume [`server/quadlet/edgeproxy_data.volume`](server/quadlet/edgeproxy_data.volume).
- **Client**: [`client/quadlet/edgeproxy-client.container`](client/quadlet/edgeproxy-client.container) con `Network=host` per accedere agevolmente a tutti i servizi interni LAN.
- Immagini distribuite via GitHub Container Registry (`ghcr.io`).

## Vincoli di Ambiente
- **Divieto di Connessione SSH**: nessuna connessione verso server remoti o VPS.
- **Isolamento Safe Execution**: operazioni di test, compilazione o verifica eseguite all'interno di container Podman effimeri (`podman run --rm ...`).
