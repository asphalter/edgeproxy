# EdgeProxy — Deep Review Architetturale, Analisi di Sicurezza e Piano di Miglioramento

> **Data Review**: Ottobre 2026  
> **Oggetto**: Architettura completa EdgeProxy (VPS Edge Server, Podman Quadlet Pod, Reverse Proxy Caddy, Reverse Tunnel Rathole, OAuth2-Proxy, Web Manager FastAPI/SQLite, Client All-in-One)  
> **Autore**: Zoo — Technical Leader & Architect  
> **Stato**: Approvato / Piano Operativo di Riferimento  

---

## 1. Executive Summary & Obiettivi

EdgeProxy nasce per offrire una piattaforma sovrana, autosufficiente e ad alte prestazioni che rimpiazza completamente i servizi commerciali proprietari come Cloudflare Tunnel (cloudflared) e Cloudflare Zero Trust Access.

L'architettura permette di esporre su Internet servizi ospitati su reti locali private, domestiche o enterprise (protette da NAT rigido e firewall senza porte in ingresso aperte) attraverso un singolo VPS pubblico con IP statico, terminazione TLS automatica multi-SNI (Caddy), autenticazione centralizzata con Google OAuth2 e tunnel TCP multiplexato cifrato con Noise Protocol Framework (Rathole).

Il sistema integra un Control Plane unificato in [`server/manager/app.py`](server/manager/app.py) con database locale SQLite in modalità WAL ([`server/manager/db.py:22`](server/manager/db.py:22)), API REST per Zero-Touch sync e un Client All-in-One in container Podman ([`client/Containerfile`](client/Containerfile)) capace di autoconfigurarsi a intervalli regolari (15s) e trasmettere telemetria e log operativi.

```mermaid
flowchart TD
    subgraph WAN_Public["Rete Pubblica Internet"]
        Client[Utente Web / Browser]
    end

    subgraph VPS_Edge["VPS Edge - Podman Pod (edgeproxy)"]
        Caddy["Caddy v2 Reverse Proxy & TLS (Porte 80, 443 TCP/UDP)"]
        OAuth2["OAuth2-Proxy (Porta 4180 / Google OAuth2)"]
        Manager["EdgeProxy Manager FastAPI (Porta interna 8000 + SQLite WAL)"]
        RatholeServer["Rathole Server (Porta 2333 WAN Noise Protocol)"]
    end

    subgraph LAN_Private["Rete Privata Backend / HomeLab"]
        AllInOne["Container All-in-One Client (Rathole Client + Zero-Touch Poller)"]
        Srv1["Servizio 1 (es. Home Assistant :8123)"]
        Srv2["Servizio 2 (es. Jellyfin :8096)"]
        Srv3["Servizio 3 (es. IDE Web :8080)"]
    end

    Client -->|HTTPS 443 / HTTP3| Caddy
    Caddy -->|forward_auth 4180| OAuth2
    Caddy -->|reverse_proxy 127.0.0.1:8000| Manager
    Caddy -->|reverse_proxy 127.0.0.1:8001...| RatholeServer
    RatholeServer <==|Connessione TCP Outbound Cifrata Noise :2333| AllInOne
    AllInOne -->|Zero-Touch Sync 15s HTTPS Bearer Token| Manager
    AllInOne --> Srv1
    AllInOne --> Srv2
    AllInOne --> Srv3
```

---

## 2. Analisi Esaustiva dei Livelli Architetturali

### 2.1 Edge Routing & TLS (Caddy v2)
- **Implementazione**: Container [`server/quadlet/caddy.container`](server/quadlet/caddy.container) eseguito all'interno del Pod `edgeproxy` (`docker.io/caddy:alpine`), con flag `--watch` per reload automatico da modifiche sul file [`server/caddy/Caddyfile`](server/caddy/Caddyfile).
- **Certificati TLS**: Gestione automatica con Let's Encrypt e ZeroSSL; supporto sia a HTTP/2 su TCP che HTTP/3 su UDP sulla porta 443. I certificati e i metadati ACME sono conservati nel volume persistente dedicato [`server/quadlet/caddy_data.volume`](server/quadlet/caddy_data.volume) montato in `/data`.
- **Snippet Modulari**:
  - `(access_log)`: Ingestione e rotazione nativa dei log di accesso in formato JSONL strutturato (`/data/caddy/logs/access.jsonl`) con dimensione massima 20 MB, rotazione a 5 copie e retention a 14 giorni.
  - `(google_auth)`: Integrazione [`forward_auth`](server/caddy/Caddyfile:38) verso `127.0.0.1:4180` (`/oauth2/auth`). In caso di codice HTTP 401, reindirizza automaticamente il client a `https://auth.{$DOMAIN}/oauth2/start?rd={scheme}://{host}{uri}`.
- **Supporto Protocolli Avanzati**: Configurazione dinamica per singolo host di impostazioni WebSocket e streaming ad alto throughput (`keepalive`, `dial_timeout`, `response_header_timeout`, `flush_interval`), oltre alla gestione di upstreams TLS interni con skip della verifica certificato (`tls_insecure_skip_verify`).
- **Meccanismo di Defense-in-Depth anti-disallineamento**:
  - Scrittura atomica del Caddyfile tramite [`server/manager/config_engine.py:write_file_to_targets()`](server/manager/config_engine.py:81).
  - Reload dinamico via Caddy Admin API HTTP (`http://127.0.0.1:2019/load`) senza downtime.
  - Fallback automatico via Podman Socket (`/run/podman/podman.sock`) per riavvio pulito del container qualora l'Admin API non risponda.
  - Riconciliazione sincrona e asincrona al boot orchestrata in [`server/manager/app.py:reconcile_configs_on_startup()`](server/manager/app.py:28).

### 2.2 Identity Federation (OAuth2-Proxy + Google OAuth2)
- **Implementazione**: Container [`server/quadlet/oauth2-proxy.container`](server/quadlet/oauth2-proxy.container) basato sull'immagine ufficiale [`quay.io/oauth2-proxy/oauth2-proxy:latest`](server/quadlet/oauth2-proxy.container:10).
- **Endpoint Dedicato**: Dominio pubblico `https://auth.{$DOMAIN}` riservato alla gestione dell'autenticazione, callback OAuth2 (`/oauth2/callback`), login (`/oauth2/start`) e healthcheck.
- **Sicurezza delle Sessioni**:
  - Cookie cifrato con chiave crittografica AES-256 (`cookie_secret`) a 32 byte urlsafe generata automaticamente all'inizializzazione del database.
  - Scoping del cookie sull'intero root domain (`cookie_domains = [".<dominio>"]`), consentendo Single Sign-On (SSO) trasparente su tutti i sottodomini protetti.
- **Controllo Accessi Granulare**:
  - Whitelist globale delle email autorizzate memorizzata nella tabella `settings` di SQLite.
  - Whitelist specifica per singolo host nella colonna `allowed_emails` della tabella `hosts`.
  - Generazione atomica del file delle email autorizzate in [`server/oauth2-proxy/authenticated_emails.txt`](server/oauth2-proxy/authenticated_emails.txt) richiamato dalla direttiva `authenticated_emails_file`.
- **Policy Supportate**:
  - `google_oauth`: Richiede autenticazione preventiva con redirect su Google.
  - `open` / `bypass`: Accesso pubblico non autenticato (es. gateway pubblici, webhook o API aperte).
  - `service_token`: Validazione di token HTTP `Authorization: Bearer <token>` o header dedicato per chiamate machine-to-machine.

### 2.3 Reverse Tunneling WAN (Rathole + Noise Protocol)
- **Implementazione**: Container [`server/quadlet/rathole.container`](server/quadlet/rathole.container) basato su [`docker.io/rapiz1/rathole:latest`](server/quadlet/rathole.container:10).
- **Architettura di Connessione**:
  - Una sola porta WAN in ascolto sulla VPS: porta TCP `2333`.
  - Il client locale apre una sola connessione in uscita verso la VPS. Nessun pacchetto in ingresso è consentito o necessario sulla rete locale.
- **Protocollo Crittografico**:
  - Implementazione nativa del **Noise Protocol Framework** con schema crittografico `Noise_NN_25519_ChaChaPoly_BLAKE2s`.
  - Garantisce crittografia end-to-end priva dei colli di bottiglia e dell'overhead di handshake TLS convenzionale.
- **Multiplexing e Token Isolati**:
  - Multiplexing ad alte prestazioni di tutti i servizi instradati sulla singola connessione di trasporto.
  - Sul server, ogni servizio viene mappato su una porta interna di loopback dedicata nel pod (`8001`, `8002`, `8003`, ...).
  - Ogni servizio possiede un proprio token crittografico univoco (`rathole_token`) generato casualmente tramite [`secrets.token_hex(16)`](server/manager/db.py:344). Un client non autorizzato su un servizio non può accedere ad altri servizi.

### 2.4 Control Plane & Web UI (FastAPI + SQLite WAL)
- **Implementazione**: Applicazione asincrona Python 3.12 ASGI (Uvicorn + FastAPI) nel container [`server/quadlet/manager.container`](server/quadlet/manager.container).
- **Persistenza**:
  - Database SQLite posizionato stabilmente in `/opt/edgeproxy/server/manager/edgeproxy.db` (mappato in `/app/manager/edgeproxy.db`).
  - Ottimizzazione di concorrenza con `PRAGMA journal_mode=WAL;`, `PRAGMA busy_timeout=5000;` e `PRAGMA synchronous=NORMAL;` per garantire scritture concorrenti senza lock contention.
- **Funzionalità Amministrative**:
  - Gestione CRUD completa dei virtual host con calcolo automatico della porta Rathole libera successiva.
  - Switch immediato delle policy di sicurezza con re-render atomico del Caddyfile.
  - Test live della raggiungibilità del backend tramite socket TCP con timeout configurabile.
  - Link Monitor in tempo reale con polling asincrono dei log del container Rathole e stato del control channel (`up` / `down`).
  - Analisi delle statistiche di traffico: parser asincrono streaming del log Caddy JSONL con aggregazione oraria dei byte trasferiti e visualizzazione grafica con Chart.js.
  - Configurazione dinamica dei parametri di sistema e credenziali Google OAuth.
  - Backup e Restore completo in formato JSON con validazione dello schema e re-applicazione istantanea.

### 2.5 Client All-in-One con Zero-Touch Sync
- **Implementazione**: Container multi-stage basato su [`client/Containerfile`](client/Containerfile) ed eseguito dal Quadlet [`client/quadlet/edgeproxy-client.container`](client/quadlet/edgeproxy-client.container).
- **Struttura Multi-Stage**:
  - Stage 1: Estrazione del binario ufficiale [`rathole`](client/Containerfile:7) e delle relative librerie dinamiche GNU/Linux da `docker.io/rapiz1/rathole:latest`.
  - Stage 2: Runtime leggero basato su Alpine con utility di rete e scripting (`curl`, `bash`, `jq`, `ca-certificates`, `procps`).
- **Loop di Zero-Touch Sync ([`client/entrypoint.sh`](client/entrypoint.sh))**:
  - All'avvio, il container avvia il processo Rathole Client indirizzando l'output su `/tmp/rathole.log` con streaming in tempo reale verso stdout per l'ingestione da parte di systemd/journald.
  - Ogni 15 secondi (intervallo predefinito configurabile con `INTERVAL`), esegue una chiamata HTTPS a `https://auth.<dominio>/api/v1/client/config` autenticata con Bearer Token (`SYNC_TOKEN`).
  - Se il file TOML scaricato è valido e differisce da quello corrente (`/etc/rathole/client.toml`), applica la modifica in modo atomico e riavvia il processo Rathole senza richiedere l'intervento dell'amministratore.
  - Invia periodicamente la telemetria (uptime del sistema, versione del client, stato del processo, ultimi log operativi) all'endpoint `POST /api/v1/client/telemetry`.
  - Gestisce in modo pulito i segnali di terminazione `SIGTERM` e `SIGINT` terminando i processi figlio in ordine controllato.

---

## 3. Identificazione di Debolezze, SPOF e Rischi di Sicurezza Residui

### 3.1 Esposizione Diretta della Porta 8000 nel Pod Quadlet
- **Criticità**: In [`server/quadlet/edgeproxy.pod:13`](server/quadlet/edgeproxy.pod:13) è presente la direttiva:
  ```ini
  PublishPort=8000:8000/tcp
  ```
- **Rischio**: La porta 8000 è la porta di ascolto interna del Manager Web FastAPI. Se l'host VPS non dispone di un firewall di rete perimetrale o se le regole `iptables`/`ufw` non bloccano esplicitamente il traffico in ingresso su 8000 da interfacce esterne, un attaccante potrebbe connettersi direttamente al Manager eludendo Caddy e bypassando TLS e l'autenticazione.
- **Risoluzione Raccomandata**: Rimuovere `PublishPort=8000:8000/tcp` da [`server/quadlet/edgeproxy.pod`](server/quadlet/edgeproxy.pod). All'interno del Podman Pod tutti i container condividono lo stesso namespace di rete di loopback; Caddy può raggiungere il Manager su `127.0.0.1:8000` senza che la porta sia esposta sull'interfaccia pubblica della VPS.

### 3.2 Montaggio del Socket Podman con Privilegi Elevati
- **Criticità**: In [`server/quadlet/manager.container:15`](server/quadlet/manager.container:15), il container del Manager monta il socket del demone container:
  ```ini
  Volume=/run/podman/podman.sock:/run/podman/podman.sock:rw
  SecurityLabelDisable=true
  ```
- **Rischio**: L'accesso in lettura e scrittura a `/run/podman/podman.sock` con etichette SELinux disabilitate garantisce privilegi equivalenti a root sull'host. Se l'applicazione Python/FastAPI dovesse subire una vulnerabilità di tipo Remote Code Execution (RCE) o Server-Side Template Injection, l'attaccante potrebbe assumere il controllo completo di tutti i container e dell'host VPS.
- **Risoluzione Raccomandata**:
  - Implementare un proxy di autorizzazione per il socket Podman (es. socket filtrato che consenta esclusivamente chiamate a `/restart` su container specifici come `edgeproxy-caddy` e `edgeproxy-rathole`).
  - Potenziare l'utilizzo esclusivo dell'Admin API HTTP di Caddy (`:2019/load`) eliminando la necessità di riavviare il container Caddy per le normali modifiche ai virtual host.

### 3.3 Bootstrap Gap e Protezione del Dominio Manager
- **Criticità**: Nel file [`server/caddy/Caddyfile:52`](server/caddy/Caddyfile:52), il virtual host `manager.{$DOMAIN}` non include lo snippet `import google_auth`:
  ```caddy
  manager.{$DOMAIN:localhost} {
      import access_log
      reverse_proxy {$MANAGER_ADDR:127.0.0.1:8000}
  }
  ```
- **Analisi**: Questa scelta è stata progettata per evitare un deadlock "uovo e la gallina" durante il primo avvio, permettendo all'amministratore di accedere alla Web UI per inserire le credenziali di Google OAuth2 (`Client ID` e `Client Secret`). Tuttavia, una volta configurato Google OAuth2, il Manager rimane aperto a chiunque raggiunga il sottodominio, a meno che non si abiliti la protezione.
- **Risoluzione Raccomandata**:
  - Introdurre un'opzione nel Manager per proteggere `manager.<dominio>` con Google OAuth2 una volta configurate le credenziali.
  - In alternativa, implementare un token di amministrazione iniziale monouso generato al boot e stampato nei log, oppure un sistema di autenticazione con credenziali locali di emergenza per la console amministrativa.

### 3.4 Punti Singoli di Fallimento (SPOF)
1. **VPS Singola (Single Node Edge)**: L'intera architettura dipende dalla disponibilità del singolo server VPS. Un guasto hardware, un blocco del sistema operativo o un attacco DDoS sull'IP pubblico della VPS interrompe tutti i collegamenti ai servizi interni.
2. **Singolo Processo Rathole Server**: Se il processo Rathole crasha o incontra un deadlock sul socket di trasporto, tutti i canali multiplexati cadono contemporaneamente. Sebbene Quadlet gestisca il riavvio con `Restart=always`, i flussi TCP attivi subiscono una disconnessione forzata.
3. **Database SQLite Locale**: SQLite risiede su filesystem locale. Se il disco VPS viene corrotto e non è configurata una replica offsite dei backup JSON, la configurazione completa degli host e dei token va perduta.

### 3.5 Colli di Bottiglia Operativi (Bottlenecks)
1. **Throughput WAN della VPS**: Il traffico aggregato per servizi ad alta intensità di banda (es. streaming multimediale 4K su Jellyfin o feed video continui da Frigate NVR) satura rapidamente la banda di rete e il limite di CPU della VPS per la crittografia/decrittografia Noise e TLS.
2. **Crescita della Tabella `access_logs`**: L'ingestione continua dei log JSONL di Caddy nella tabella SQLite `access_logs` ad alto volume di traffico web può generare saturazione del disco e rallentamenti nelle query. È necessario un processo periodico di purging (retention policy a 7 o 14 giorni).
3. **Pattern Crittografico Noise `NN`**: Lo schema `Noise_NN_25519_ChaChaPoly_BLAKE2s` esegue uno scambio di chiavi non autenticato su canale cifrato. La sicurezza dell'accesso è delegata interamente al token di servizio (`rathole_token`). Un pattern Noise autenticato con chiavi statiche pre-condivise (es. `Noise_NK` o `Noise_KK`) aggiungerebbe autenticazione mutua a livello di handshake crittografico.

---

## 4. Matrice dei Miglioramenti Proposti

| ID | Ambito | Descrizione Miglioramento | Priorità | Impatto | Complessità |
|---|---|---|---|---|---|
| **IMP-01** | Sicurezza Rete | Rimozione di `PublishPort=8000:8000/tcp` da [`server/quadlet/edgeproxy.pod`](server/quadlet/edgeproxy.pod) per isolare il Manager all'interno del Pod | Immediata (Breve) | Alto | Bassa |
| **IMP-02** | Autenticazione | Aggiunta di protezione opzionale `import google_auth` o master password per `manager.<dominio>` post-bootstrap | Breve termine | Alto | Media |
| **IMP-03** | Storage & DB | Implementazione di routine automatica di retention log per `access_logs` in SQLite (rotazione a 7 o 14 giorni) | Breve termine | Medio | Bassa |
| **IMP-04** | Sicurezza Daemon | Riduzione dei privilegi del Manager eliminando il socket Podman in favore di Caddy Admin API HTTP ed endpoint dedicati | Medio termine | Alto | Media |
| **IMP-05** | Crittografia WAN | Transizione del profilo Rathole Noise da `Noise_NN` a un pattern autenticato con chiavi statiche pre-condivise | Medio termine | Medio | Media |
| **IMP-06** | Alta Disponibilità | Supporto per failover multi-VPS con sincronizzazione asincrona dello stato SQLite (Litestream / Raft) | Lungo termine | Molto Alto | Alta |
| **IMP-07** | Client Multi-Node | Supporto a cluster di client locali multipli con token e assegnazione di pool di porte distinte | Lungo termine | Alto | Media |

---

## 5. Piano Operativo di Intervento Dettagliato

### Fase 1: Hardening Immediato (Quick Wins)
1. **Isolamento della Porta 8000**: Modificare [`server/quadlet/edgeproxy.pod`](server/quadlet/edgeproxy.pod) eliminando la riga 13. Verificare che Caddy continui a comunicare regolarmente con `127.0.0.1:8000`.
2. **Retention Policy SQLite**: Introdurre un task asincrono in [`server/manager/stats.py`](server/manager/stats.py) che esegua periodicamente `DELETE FROM access_logs WHERE ts < datetime('now', '-14 days')` seguito da `PRAGMA incremental_vacuum;`.
3. **Template Caddyfile Manager Protetto**: Integrare in [`server/manager/config_engine.py`](server/manager/config_engine.py) la generazione condizionale di `import google_auth` anche sul blocco `manager.{$DOMAIN}` quando `google_oauth_enabled == "1"`.

### Fase 2: Consolidamento e Affidabilità (Medio Termine)
1. **Backup Automatico Offsite**: Aggiungere un endpoint per esportazione schedulata o hook verso storage S3-compatibile / WebDAV per il file di backup JSON.
2. **Healthcheck Attivo dei Backend**: Implementare una routine che invii probe HTTP periodici verso i backend registrati e notifichi l'amministratore in caso di degrado o latenza elevata.
3. **Hardening del Runtime Client**: Ottimizzare il containerfile client per consentire l'esecuzione come utente non-root con capacità Linux ridotte (`cap_drop=ALL`).

### Fase 3: Architettura Distribuita (Lungo Termine)
1. **Replica SQLite Continua**: Integrare [Litestream](https://litestream.io/) per lo streaming continuo dei frame WAL di SQLite su object storage, consentendo il ripristino istantaneo Point-in-Time in caso di crash catastrofico della VPS.
2. **Architettura Multi-Edge Anycast**: Distribuzione di Caddy e Rathole su due o più VPS geograficamente distribuite con routing DNS basato su GeoIP o BGP Anycast.

---

## 6. Conclusioni

L'architettura di EdgeProxy si distingue per pulizia concettuale, modernità dello stack tecnologico (Quadlet, Caddy v2, Noise Protocol, FastAPI asincrono) e facilità operativa grazie al client All-in-One con Zero-Touch Sync a 15 secondi. 

L'applicazione delle misure di hardening individuate (chiusura della porta 8000 esterna, protezione del dominio manager e retention dei log SQLite) porta la piattaforma a un livello di maturità e affidabilità idoneo a carichi di produzione continui, garantendo totale sovranità sul flusso dei dati.
