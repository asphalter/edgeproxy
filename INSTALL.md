# EdgeProxy — Guida di Installazione e Produzione (All-in-One Quadlet)

> **Architettura All-in-One**: Nessun archivio tarball, nessun file `.env` manuale, nessuno script da compilare.
> Solo due immagini container ufficiali precompilate pubblicate su GitHub Container Registry (`ghcr.io`), gestite nativamente da Podman Quadlet e `systemd`:
> 1. **Server (VPS Edge)**: [`server/quadlet/edgeproxy-server.container`](server/quadlet/edgeproxy-server.container)
> 2. **Client (LAN Backend)**: [`client/quadlet/edgeproxy-client.container`](client/quadlet/edgeproxy-client.container)

---

## Indice dei Contenuti
1. [Panoramica Architetturale](#1-panoramica-architetturale)
2. [Prerequisiti e Configurazione DNS](#2-prerequisiti-e-configurazione-dns)
3. [Installazione Server (VPS Edge)](#3-installazione-server-vps-edge)
4. [Installazione Client (Backend / Workstation LAN)](#4-installazione-client-backend--workstation-lan)
5. [Configurazione Google OAuth2 (Opzionale)](#5-configurazione-google-oauth2-opzionale)
6. [Gestione e Manutenzione](#6-gestione-e-manutenzione)

---

## 1. Panoramica Architetturale

EdgeProxy offre un'alternativa self-hosted a Cloudflare Tunnel + Cloudflare Access. L'architettura è formata da due soli container unificati:

```mermaid
flowchart LR
    subgraph WAN_Public["Internet Pubblico"]
        Browser[Browser / Utente]
    end

    subgraph VPS["VPS Edge Server (Singolo Container: edgeproxy-server)"]
        direction TB
        Caddy[Caddy Reverse Proxy :80, :443]
        OAuth2[OAuth2-Proxy :4180]
        RatholeServer[Rathole Server :2333 WAN, :8001+ Loopback]
        Manager[Manager Web UI :8000]
        Supervisord[Supervisor Init Loopback]
    end

    subgraph LAN["Rete Locale Backend / Workstation (Singolo Container: edgeproxy-client)"]
        Client[All-in-One Client Container]
        LocalApps[Servizi Interni :8123, :8080, :3000]
    end

    Browser -->|HTTPS :443 TCP/UDP| Caddy
    Caddy -->|forward_auth| OAuth2
    Caddy -->|reverse_proxy| RatholeServer
    Caddy -->|Manager Route| Manager
    RatholeServer <==|Tunnel TCP Noise :2333 Outbound| Client
    Client -->|Sync 15s HTTPS| Manager
    Client --> LocalApps
```

- **VPS Edge Server**: Incapsula Caddy v2 (TLS automatico Let's Encrypt / ZeroSSL), OAuth2-Proxy (Google SSO), Rathole Server (terminazione tunnel crittografato) e Manager UI su loopback interno controllati da `supervisord`. I dati persistenti (database SQLite, certificati ACME, configurazioni attive) sono memorizzati nel volume dedicato `edgeproxy_data`.
- **Client LAN**: Unico processo client che scarica a caldo la configurazione dal Manager (zero-touch ogni 15 secondi) e apre il tunnel cifrato Noise verso la VPS. Nessuna porta aperta in ingresso nella rete locale.

---

## 2. Prerequisiti e Configurazione DNS

### Requisiti Server (VPS)
- Sistema operativo Linux moderno con Podman >= 4.4 (supporto Quadlet `/etc/containers/systemd/`).
- Indirizzo IPv4 pubblico statico.

### Configurazione DNS
Configurare presso il proprio registrar DNS (es. Cloudflare, Hetzner, Route53) i seguenti record puntanti all'IP pubblico della VPS:

| Tipo | Nome Record | Destinazione / Valore | Note |
|---|---|---|---|
| `A` | `edge.mpv.cx` | `<IP_PUBBLICO_VPS>` | Dominio base gateway |
| `A` | `manager.edge.mpv.cx` | `<IP_PUBBLICO_VPS>` | Web UI del Pannello di Controllo |
| `A` | `auth.edge.mpv.cx` | `<IP_PUBBLICO_VPS>` | Endpoint autenticazione e API Sync |
| `CNAME` | `*.edge.mpv.cx` | `edge.mpv.cx` | Record Wildcard per tutti i servizi proxy esposti |

*(Sostituire `edge.mpv.cx` con il proprio dominio).*

---

## 3. Installazione Server (VPS Edge)

L'installazione sulla VPS si riduce a 3 passaggi lineari:

### Passo 1: Configurazione Firewall (`firewalld`)
Consentire il traffico sulle porte pubbliche (80 e 443 per Caddy, 2333 per Rathole, 8000 per il bootstrap iniziale della Web UI):

```bash
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=443/udp
sudo firewall-cmd --permanent --add-port=2333/tcp
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --reload
```

### Passo 2: Creazione dei file Quadlet
Creare la directory dei Quadlet di sistema se non esiste:
```bash
sudo mkdir -p /etc/containers/systemd
```

1. **Volume Persistente** (`/etc/containers/systemd/edgeproxy_data.volume`):
```ini
[Volume]
VolumeName=edgeproxy_data
```

2. **Container Server** (`/etc/containers/systemd/edgeproxy-server.container`):
*(Personalizzare `DOMAIN` e `ACME_EMAIL`)*
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

### Passo 3: Avvio del Servizio
Ricaricare il demone `systemd` e avviare il servizio:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now edgeproxy-server.service
```

Podman scaricherà automaticamente l'immagine precompilata da GitHub Container Registry ed eseguirà Caddy, OAuth2-Proxy, Rathole e il Manager Web UI in un unico container isolato.

Accedere alla Web UI aprendo nel browser:
- **`https://manager.edge.mpv.cx/`** (o `http://<IP_PUBBLICO_VPS>:8000/` durante l'emissione del certificato TLS iniziale).

---

## 4. Installazione Client (Backend / Workstation LAN)

Grazie alla Web UI di EdgeProxy non è necessario creare file TOML o configurare token manualmente.

### Passo 1: Ottenere la Configurazione Quadlet
1. Accedere al pannello Manager: **`https://manager.edge.mpv.cx/`**
2. Selezionare la scheda **Client Config** nel menu superiore.
3. Fare clic sul pulsante **📋 Copy Client Quadlet**.
   Il blocco generato conterrà già l'URL esatto del vostro server e il token di sincronizzazione del client:

```ini
[Unit]
Description=EdgeProxy Client (All-in-One)
After=network-online.target
Wants=network-online.target

[Container]
ContainerName=edgeproxy-client
Image=ghcr.io/vvelectron/edgeproxy-client:latest
Network=host
Volume=edgeproxy_client_data.volume:/etc/rathole:z
Environment=SERVER_URL=https://auth.edge.mpv.cx
Environment=SYNC_TOKEN=SECRETSYNC_TOKEN_AUTO_GENERATED
Environment=INTERVAL=15

[Service]
Restart=always
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
```

### Passo 2: Attivazione del Client LAN
Sulla macchina locale (server HomeLab, Workstation, NAS o Raspberry Pi):

```bash
sudo mkdir -p /etc/containers/systemd
sudo nano /etc/containers/systemd/edgeproxy-client.container
# Incollare la configurazione e salvare

sudo systemctl daemon-reload
sudo systemctl enable --now edgeproxy-client.service
```

Il container client eseguirà il pull dell'immagine, scaricherà la configurazione dei servizi dal Manager via HTTPS, avvierà il tunnel Noise crittografato e manterrà aggiornati i tunnel con sincronizzazione automatica a intervalli regolari (15 secondi).

Verifica dello stato:
```bash
sudo podman logs -f edgeproxy-client
```

---

## 5. Configurazione Google OAuth2 (Opzionale)

Per proteggere i servizi esposti e il pannello di controllo tramite Google Workspace o account Gmail:

1. Aprire la [Google Cloud Console](https://console.cloud.google.com/) e selezionare il proprio progetto.
2. In **API e servizi** > **Credenziali**, creare una credenziale di tipo **ID client OAuth**:
   - Tipo applicazione: **Applicazione Web**
   - Nome: `EdgeProxy Gateway`
   - URI di reindirizzamento autorizzati:
     ```text
     https://auth.edge.mpv.cx/oauth2/callback
     ```
3. Nel Manager EdgeProxy, aprire la pagina **Settings**:
   - Selezionare **Enable Google OAuth2 Authentication**.
   - Inserire **Google Client ID** e **Google Client Secret**.
   - Specificare le email consentite in **Allowed User Emails** (es. `utente@gmail.com`).
   - Salvare le impostazioni.

Il Manager riavvierà a caldo `oauth2-proxy` e aggiornerà la configurazione di Caddy in tempo reale senza interruzioni di servizio.

---

## 6. Gestione e Manutenzione

### Aggiunta di un Servizio Proxy
1. Nel Manager, andare su **Hosts** -> fare clic su **Add New Host**.
2. Compilare:
   - **Domain**: es. `grafana.edge.mpv.cx`
   - **Upstream**: es. `127.0.0.1:3000` (indirizzo locale del servizio sulla macchina client)
   - **Access Policy**: `google_oauth` (protetto con login Google) oppure `bypass` (accesso diretto)
3. Salvare: entro 15 secondi il client LAN riceverà il nuovo proxy e Caddy emetterà il certificato TLS automatico per il dominio.

### Backup dei Dati
Tutti i dati persistenti (database SQLite, certificati ACME e configurazioni) risiedono nel volume Quadlet `edgeproxy_data`:

```bash
sudo podman volume export edgeproxy_data > edgeproxy_backup_$(date +%Y%m%d).tar
```
