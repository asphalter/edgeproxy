# Project Brief — EdgeProxy

## Obiettivo (Goal)
Esporre in sicurezza i servizi self-hosted in esecuzione su backend locale (dietro NAT/firewall) attraverso un'infrastruttura Edge proprietaria (Rathole + Caddy + Google OAuth2 su Podman Quadlet), sostituendo integralmente le dipendenze da Cloudflare Tunnel e Cloudflare Access.

## Requisiti Chiave
- Reverse tunnel multiplexato crittografato tramite Rathole (Noise Protocol).
- Terminazione TLS automatica multi-SNI e reverse proxy HTTP/HTTPS tramite Caddy v2.
- Autenticazione e protezione perimetrale degli endpoint esposti tramite Google OAuth2 (`oauth2-proxy`).
- Web UI di gestione (FastAPI EdgeProxy Manager) per la configurazione dinamica di host e proxy con sincronizzazione automatica client zero-touch.
- Architettura a container singoli precompilati su GHCR ([`server/quadlet/edgeproxy-server.container`](server/quadlet/edgeproxy-server.container) e [`client/quadlet/edgeproxy-client.container`](client/quadlet/edgeproxy-client.container)) gestiti nativamente con Podman Quadlet / systemd.

## Vincoli Architetturali e Direttive di Sicurezza
- **Accesso SSH Remoto Revocato**: l'accesso SSH alla VPS remota (`edge.mpv.cx` / `130.110.9.121`) è revocato e vietato. Nessun comando SSH verso la VPS remota deve essere eseguito.
- **Safe Execution (Podman)**: qualsiasi operazione di compilazione, test e validazione avviene localmente in container Podman effimeri isolati (`--rm`).
