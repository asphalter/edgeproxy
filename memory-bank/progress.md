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
  - [x] Creato il workflow GitHub Actions [`.github/workflows/build-and-push.yml`](.github/workflows/build-and-push.yml) per la compilazione e il push automatico su `ghcr.io`.
- [x] **Pulizia e Consolidamento Repository**:
  - [x] Rimossi i vecchi Quadlet del pod (`edgeproxy.pod`, `caddy.container`, `manager.container`, `oauth2-proxy.container`, `rathole.container`, `caddy_config.volume`, `caddy_data.volume`).
  - [x] Rimossi vecchi script e tarball (`deploy-vps.sh`, `scripts/remote-deploy.sh`, `scripts/build-server-release.sh`, `scripts/build-client-release.sh`, `client/install.sh`, `client/sync-agent.sh`, `*.tar.gz`).
  - [x] Rimossi `.env.example`, `server/caddy/Containerfile` e `server/manager/edgeproxy.db`.
  - [x] Creato script unificato di compilazione locale [`scripts/build-images.sh`](scripts/build-images.sh).
  - [x] Riscritte integralmente le guide di installazione e documentazione ([`INSTALL.md`](INSTALL.md) e [`README.md`](README.md)).
  - [x] Aggiornata integralmente la Memory Bank.

## Da Fare / Prossimi Passi

- [ ] Verifica periodica di integrità e test suite tramite container Podman effimeri.
