# EdgeProxy

**Alternativa Self-Hosted a Cloudflare Tunnel + Cloudflare Access**

EdgeProxy sostituisce l'esposizione dei servizi interni precedentemente gestita con **Cloudflare Tunnel** (autenticazione Cloudflare Access 2FA e gestione SSL automatica) con uno stack autonomo su **VPS proprietaria con IPv4 pubblico**, preservando la medesima sicurezza ed esperienza d'uso:

- Autenticazione a due fattori con Google OAuth2 SSO.
- Rinnovo automatico certificati SSL/TLS via Let's Encrypt / ZeroSSL (Caddy v2).
- Reverse tunnel multiplexato e crittografato tramite Noise Protocol (Rathole).
- Zero porte in ingresso aperte sul backend locale (attraversamento NAT sicuro).
- **Architettura Unificata a Singolo Container**: Nessun pod multi-container complesso, nessun tarball da estrarre, nessun file `.env` manuale. Solo **due immagini ufficiali precompilate** gestite nativamente da Podman Quadlet / `systemd`:
  - [`server/quadlet/edgeproxy-server.container`](server/quadlet/edgeproxy-server.container)
  - [`client/quadlet/edgeproxy-client.container`](client/quadlet/edgeproxy-client.container)

---

## 1. Architettura e Flusso di Traffico

```mermaid
flowchart LR
    subgraph WAN["Internet Pubblico"]
        Browser[Browser Utente]
    end

    subgraph VPS["VPS Edge Gateway (Singolo Container: edgeproxy-server)"]
        direction TB
        Caddy[Caddy Reverse Proxy :80, :443]
        OAuth2[OAuth2-Proxy Google SSO :4180]
        RatholeServer[Rathole Server :2333 WAN]
        Manager[Manager Web UI :8000]
        Supervisord[Supervisor Init Loopback]
    end

    subgraph Backend["Rete Locale Protetta / LAN (Singolo Container: edgeproxy-client)"]
        Client[EdgeProxy Client Container]
        S1[Servizio Interno :8123]
        S2[Servizio Interno :3000]
    end

    Browser -->|HTTPS 443 TCP/UDP| Caddy
    Caddy -->|forward_auth| OAuth2
    Caddy -->|reverse_proxy 127.0.0.1:8001+| RatholeServer
    Caddy -->|Manager Route| Manager
    RatholeServer <==|Tunnel Noise :2333 Outbound| Client
    Client -->|Sync Automatico 15s| Manager
    Client --> S1
    Client --> S2
```

---

## 2. Componenti Chiave

| Componente | Ruolo | Dettagli Tecnici |
|---|---|---|
| **Caddy v2** | Reverse Proxy & ACME TLS | HTTPS automatico zero-config, supporto HTTP/3 (QUIC), reload a caldo via Admin API `:2019/load`. |
| **OAuth2-Proxy** | Google SSO 2FA | Autenticazione tramite Google Workspace / Gmail con verifica delle email autorizzate. |
| **Rathole** | Reverse Tunnel Multiplexato | Scritto in Rust, trasporto sicuro su Noise Protocol (porta WAN `2333`), binding su loopback interno. |
| **EdgeProxy Manager** | Web UI & Config Engine | Applicazione FastAPI / SQLite per la gestione visuale di host, proxy, statistiche e stato dei tunnel in tempo reale. |
| **Podman Quadlet** | Orchestrazione Nativa | Gestione nativa del ciclo di vita dei container via systemd (`edgeproxy-server.service` e `edgeproxy-client.service`). |

---

## 3. Guida Rapida di Deploy

### Server (VPS Edge Gateway)
1. Aprire le porte firewall necessarie: `80`, `443` (TCP/UDP), `2333` e `8000`.
2. Configurare `/etc/containers/systemd/edgeproxy_data.volume` e `/etc/containers/systemd/edgeproxy-server.container`:
   ```ini
   [Unit]
   Description=EdgeProxy Server (All-in-One)
   After=network-online.target
   Wants=network-online.target

   [Container]
   ContainerName=edgeproxy-server
   Image=ghcr.io/vvelectron/edgeproxy-server:latest
   PublishPort=80:80/tcp
   PublishPort=443:443/tcp
   PublishPort=443:443/udp
   PublishPort=2333:2333/tcp
   PublishPort=8000:8000/tcp
   Volume=edgeproxy_data.volume:/data:z
   Environment=DOMAIN=edge.mpv.cx
   Environment=ACME_EMAIL=matteo.piva@gmail.com

   [Service]
   Restart=always
   TimeoutStartSec=300

   [Install]
   WantedBy=multi-user.target
   ```
3. Avviare con:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now edgeproxy-server.service
   ```

### Client (Backend LAN)
1. Aprire la Web UI del Manager all'indirizzo `https://manager.<dominio>/` e andare nella scheda **Client Config**.
2. Copiare il blocco Quadlet precompilato.
3. Incollare in `/etc/containers/systemd/edgeproxy-client.container` sulla macchina locale e avviare:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now edgeproxy-client.service
   ```

Consultare [`INSTALL.md`](INSTALL.md) per la guida dettagliata passo per passo.

---

## 4. Compilazione Immagini in Locale

Per test e sviluppo locale, utilizzare lo script unificato [`scripts/build-images.sh`](scripts/build-images.sh):

```bash
# Compilazione di entrambe le immagini
./scripts/build-images.sh all

# Compilazione selettiva
./scripts/build-images.sh server
./scripts/build-images.sh client
```

---

## 5. Licenza

Progetto rilasciato sotto licenza MIT.
