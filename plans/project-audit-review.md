# EdgeProxy — Rapporto di Audit Tecnico, Architetturale e di Sicurezza (Full Review)

> **Data Audit**: 23 Ottobre 2026  
> **Oggetto**: Intero stack EdgeProxy (VPS Server, Client Rathole, Manager FastAPI, Caddy, OAuth2-Proxy, Quadlet)  
> **Autore**: Zoo — Technical Leader & Architect  
> **Stato**: Revisione Completa & Piano di Remediation

---

## 1. Executive Summary & Quadro Generale

EdgeProxy è stato concepito per sostituire l'infrastruttura Cloudflare Tunnel + Cloudflare Access tramite uno stack interamente self-hosted orchestrato con Podman e Quadlet su VPS con IP pubblico. La recente rimozione di Authelia a favore di **Google OAuth2** tramite [`quay.io/oauth2-proxy/oauth2-proxy`](server/quadlet/oauth2-proxy.container:10) ha snellito notevolmente l'architettura.

Tuttavia, l'audit tecnico approfondito ha rilevato **vulnerabilità critiche di sicurezza**, **fragilità operative nell'avvio dei container** e **debito tecnico residuo**. Questo documento fornisce una radiografia completa dello stato del codice, delle configurazioni e dell'architettura, classificando ogni anomalia per livello di severità e definendo un piano di remediation puntuale.

---

## 2. Tabella Sinottica delle Vulnerabilità e Anomalie

| ID | Severità | Area | Oggetto / File Coinvolti | Sintesi Diagnosi | Impatto |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **CRITICO** | Sicurezza | [`server/caddy/Caddyfile`](server/caddy/Caddyfile:10), [`server/manager/app.py`](server/manager/app.py:23) | **Web UI di Gestione esposta senza alcuna autenticazione** su `https://edge.mpv.cx/` e `manager.edge.mpv.cx`. | Qualsiasi utente Internet anonimo ha pieno controllo amministrativo: può creare/eliminare host, alterare segreti OAuth2, visualizzare token Rathole e innescare reload. |
| **SEC-02** | **CRITICO** | Sicurezza | [`server/rathole/server.toml`](server/rathole/server.toml:5), [`client/rathole/client.toml`](client/rathole/client.toml:9), [`server/manager/config_engine.py`](server/manager/config_engine.py:151) | **Tunnel WAN Rathole non cifrato** (`type = "tcp"` in chiaro sulla porta 2333). Mancanza di Noise Protocol. | Per tutti gli upstream HTTP in chiaro (`http://10.88.0.x:8000`), pacchetti, password, cookie e payload transitano su Internet pubblica in chiaro, esponendoli a sniffing e MITM. |
| **SEC-03** | **ALTO** | Sicurezza | [`server/caddy/Caddyfile`](server/caddy/Caddyfile:10), [`server/manager/config_engine.py`](server/manager/config_engine.py:108) | **Assenza totale di HTTP Security Headers** in Caddy (HSTS, CSP, X-Frame-Options, X-Content-Type-Options). | Vulnerabilità a Clickjacking, attacchi di MIME-sniffing, downgrade HTTPS e mancata enforcement delle policy di navigazione sicura. |
| **SEC-04** | **ALTO** | Sicurezza | [`server/manager/app.py`](server/manager/app.py:58), [`server/manager/config_engine.py`](server/manager/config_engine.py:128) | **Mancanza di validazione FQDN / Sanitizzazione input** nel Manager e rischio Caddyfile/TOML Injection. | Invio di caratteri speciali (`\n`, `}`, `{`) può corrompere il Caddyfile o iniettare direttive arbitrarie, provocando denial-of-service o bypass del routing. |
| **SEC-05** | **ALTO** | Sicurezza | [`server/manager/templates/`](server/manager/templates), [`server/manager/app.py`](server/manager/app.py:58) | **Assenza di protezione CSRF** sui form di mutazione stato (`/hosts/add`, `/hosts/{id}/delete`, `/settings/save`, `/apply`). | Un sito terzo malevolo visitato dall'amministratore può sottomettere richieste trans-sito non autorizzate per alterare le configurazioni. |
| **OPS-01** | **ALTO** | Affidabilità | [`server/quadlet/manager.container`](server/quadlet/manager.container:16) | **`pip install` eseguito ad ogni avvio del container** (`Exec=sh -c "pip install ..."`). | Forte ritardo al boot; SPOF e crashloop se la rete o PyPI non rispondono prontamente; usura I/O e rischio di disallineamento dipendenze. |
| **OPS-02** | **ALTO** | Sicurezza / Ops | [`server/quadlet/manager.container`](server/quadlet/manager.container:14), [`server/manager/config_engine.py`](server/manager/config_engine.py:291) | **Mount del socket Podman root** (`/run/podman/podman.sock`) nel container Manager per riavviare i container. | Possibilità teorica di Container Breakout verso l'host con privilegi di root in caso di compromissione del processo FastAPI. |
| **OPS-03** | **MEDIO** | Affidabilità | [`server/manager/config_engine.py`](server/manager/config_engine.py:330) | **Mancanza di validazione preventiva e rollback atomico** in `apply_all_configurations()`; flag `success: True` ritornato anche su errore. | Un Caddyfile errato viene scritto su disco prima del reload: se Caddy non lo applica, al successivo riavvio del demone l'intero reverse proxy fallisce il boot. |
| **PERF-01** | **MEDIO** | Performance | [`server/quadlet/edgeproxy.pod`](server/quadlet/edgeproxy.pod:11), [`deploy-vps.sh`](deploy-vps.sh:1) | **Kernel Linux UDP Buffer per HTTP/3 QUIC non ottimizzati** (`sysctl` mancanti per `rmem_max`/`wmem_max`). | Limitazione del throughput QUIC (Caddy logga warning di buffer insufficiente), caduta di pacchetti sotto carico e fallback forzato su TCP. |
| **PERF-02** | **MEDIO** | Performance | [`client/rathole/client.toml`](client/rathole/client.toml:9), [`server/rathole/server.toml`](server/rathole/server.toml:5) | **Assenza di TCP/Noise Heartbeat esplicito in Rathole** per WebSockets e sessioni IDE a lunga durata. | Connessioni WebSocket persistenti (es. terminale VS Code Server su `ide.mpv.cx`) possono essere terminate silenziosamente dai router NAT dopo timeout di inattività. |
| **DEBT-01** | **MEDIO** | Debito Tecnico | [`README.md`](README.md:22), [`server/Containerfile`](server/Containerfile:18), [`server/supervisord.conf`](server/supervisord.conf:24), [`server/.env.example`](server/.env.example:21), [`deploy-vps.sh`](deploy-vps.sh:70) | **Presenza di residui obsoleti di Authelia** nella documentazione, nel Containerfile unificato, in supervisord e negli script di deploy. | Confusione operativa per manutentori, codice morto non più mantenuto e generazione di variabili d'ambiente inutili. |
| **SEC-06** | **BASSO** | Sicurezza | [`server/manager/db.py`](server/manager/db.py:27) | **Storage dei token Rathole e Google Client Secret in chiaro** nel database SQLite `/data/edgeproxy.db`. | Esposizione dei token se il file DB viene estratto da un backup non cifrato. |

---

## 3. Punti di Forza dell'Attuale Architettura (Cosa Funziona Eccellentemente)

1. **Architettura Podman Pod Nativo ([`server/quadlet/edgeproxy.pod`](server/quadlet/edgeproxy.pod:8))**:
   - L'unione di Caddy, Rathole, OAuth2-Proxy e Manager all'interno di un unico namespace di rete condiviso (`localhost` / `127.0.0.1`) è una scelta architetturale eccellente. 
   - Nessun container applicativo interno (tranne Caddy e Rathole WAN) necessita di esporre porte sull'interfaccia pubblica della VPS, eliminando alla radice rischi di esposizione accidentale delle porte di loopback.

2. **Adozione di Google OAuth2 tramite OAuth2-Proxy ([`server/oauth2-proxy/oauth2-proxy.cfg`](server/oauth2-proxy/oauth2-proxy.cfg:6))**:
   - Sostituire Authelia con `oauth2-proxy` nativo ha eliminato database utenti complessi, gestione password, reset credenziali e configurazioni 2FA fragili. 
   - La delega dell'autenticazione all'infrastruttura Google garantisce standard enterprise con cookie cifrati (`cookie_secure = true`, AES-256-GCM via `cookie_secret`).

3. **Integrazione Caddy + Let's Encrypt ([`server/caddy/Caddyfile`](server/caddy/Caddyfile:10))**:
   - TLS automatico multi-SNI con zero configurazioni manuali di certificati e chiavi private. Rinnovo ACME automatico e supporto HTTP/3 QUIC nativo.

4. **Reverse Tunneling con Rathole ([`server/rathole/server.toml`](server/rathole/server.toml:5))**:
   - Prestazioni di picco in Rust con multiplexing su singola connessione di trasporto e memoria footprint irrisoria (~5MB RAM).
   - Totale assenza di porte aperte sul backend locale (massima sicurezza di rete perimetrale).

5. **Deployment Dinamico Automatizzato ([`scripts/remote-deploy.sh`](scripts/remote-deploy.sh:8))**:
   - Lo script di deploy supporta l'esecuzione in container Podman effimero (`--use-podman`), assicurando l'assenza di contaminazione dell'host locale e l'atomic packaging via `tar over ssh`.

---

## 4. Analisi Dettagliata per Area di Indagine

### Area 1: Sicurezza e Controllo degli Accessi (Security Audit)

#### SEC-01: Protezione della Web UI di Gestione (CRITICO)
- **Diagnosi**:  
  Nel file [`server/caddy/Caddyfile`](server/caddy/Caddyfile:10-12), il blocco principale apex e il sottodominio manager sono configurati come:
  ```caddy
  {$DOMAIN:localhost} {
      reverse_proxy 127.0.0.1:8000
  }
  manager.{$DOMAIN:localhost} {
      reverse_proxy 127.0.0.1:8000
  }
  ```
  Nessuno dei due blocchi invoca lo snippet `import google_auth`. Inoltre, in [`server/manager/app.py`](server/manager/app.py:23-40), non è presente alcun middleware di autenticazione o session check per le route web.
- **Impatto**:  
  La dashboard `https://edge.mpv.cx/` è completamente aperta a chiunque su Internet. Un visitatore casuale o un attaccante può accedere a `/hosts`, cancellare rotte di produzione, creare nuovi tunnel arbitrari, accedere alla scheda `/settings` leggendo le email autorizzate, estrarre token di autenticazione rathole da `/client-config` e forzare il reload dei servizi tramite `/apply`.
- **Remediation**:  
  1. Includere la protezione Google OAuth2 nel blocco dell'interfaccia di gestione in [`server/caddy/Caddyfile`](server/caddy/Caddyfile:10) e nella generazione in [`server/manager/config_engine.py`](server/manager/config_engine.py:114):
     ```caddy
     {$DOMAIN:localhost} {
         import google_auth
         reverse_proxy 127.0.0.1:8000
     }
     ```
  2. Implementare un meccanismo di autenticazione di fallback interno al Manager (HTTP Basic Auth o validazione delle intestazioni `X-Auth-Request-Email` passate da `oauth2-proxy`).

---

#### SEC-02: Crittografia del Tunnel Rathole WAN (CRITICO)
- **Diagnosi**:  
  Nei file [`client/rathole/client.toml`](client/rathole/client.toml:9-13), [`server/rathole/server.toml`](server/rathole/server.toml:5-6) e nella generazione in [`server/manager/config_engine.py`](server/manager/config_engine.py:151), il blocco di trasporto è impostato su:
  ```toml
  [client.transport]
  type = "tcp"
  ```
- **Impatto**:  
  Rathole inoltra i pacchetti a livello TCP grezzo. Se un backend locale associato a un host è in HTTP non cifrato (es. `http://10.88.0.28:8000`), tutti i dati applicativi (comprese richieste HTTP con cookie di sessione, credenziali, token bearer e payload) viaggiano in chiaro sulla rete Internet pubblica tra la macchina locale e la porta `2333` della VPS.
- **Remediation**:  
  Abilitare il supporto nativo di **Noise Protocol** (`type = "noise"`) in Rathole:
  - Generare una coppia di chiavi asimmetriche (X25519) per il server Rathole.
  - Configurare in [`server/rathole/server.toml`](server/rathole/server.toml):
    ```toml
    [server.transport]
    type = "noise"
    [server.transport.noise]
    local_private_key = "${RATHOLE_SERVER_NOISE_KEY}"
    ```
  - Configurare in [`client/rathole/client.toml`](client/rathole/client.toml):
    ```toml
    [client.transport]
    type = "noise"
    [client.transport.noise]
    remote_public_key = "${RATHOLE_SERVER_PUBLIC_KEY}"
    ```
  - In questo modo, l'intero canale di trasporto WAN è crittografato end-to-end con curve crittografiche Noise (ChaCha20-Poly1305 / SHA-256), anche in presenza di servizi backend HTTP in chiaro.

---

#### SEC-03: Assenza di Security Headers HTTP in Caddy (ALTO)
- **Diagnosi**:  
  Nessuna direttiva `header` è definita in [`server/caddy/Caddyfile`](server/caddy/Caddyfile) o generata da [`server/manager/config_engine.py`](server/manager/config_engine.py).
- **Impatto**:  
  Assenza di protezione da attacchi Clickjacking (`X-Frame-Options`), MIME sniffing (`X-Content-Type-Options`), downgrade HTTP (`HSTS`) e isolamento dei contesti di navigazione (`Referrer-Policy`, `Permissions-Policy`).
- **Remediation**:  
  Definire uno snippet riutilizzabile `(security_headers)` in Caddy:
  ```caddy
  (security_headers) {
      header {
          Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
          X-Content-Type-Options "nosniff"
          X-Frame-Options "SAMEORIGIN"
          Referrer-Policy "strict-origin-when-cross-origin"
          Permissions-Policy "camera=(), microphone=(), geolocation=()"
          -Server
      }
  }
  ```
  e importarlo in tutti i virtual host e nello snippet di generazione dinamica.

---

#### SEC-04: Validazione Input e Caddyfile/TOML Injection (ALTO)
- **Diagnosi**:  
  In [`server/manager/app.py`](server/manager/app.py:58) e [`server/manager/config_engine.py`](server/manager/config_engine.py:128), il campo `domain` e i parametri in `settings` vengono concatenati direttamente nelle stringhe di configurazione:
  ```python
  lines.append(f"{domain} {{")
  ```
  Non vi è alcuna validazione tramite espressioni regolari né controllo su caratteri di controllo come `\n`, `\r`, `{`, `}`.
- **Impatto**:  
  Un attaccante (o un errore umano) potrebbe inserire un dominio contenente interruzioni di riga e direttive arbitrarie, provocando alterazione del routing o crash sintattico del Caddyfile.
- **Remediation**:  
  Applicare una regex rigorosa per FQDN conforme a RFC 1123 (`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`) e sanificare rigorosamente gli upstream e i valori di settings.

---

#### SEC-05: Assenza di Protezione CSRF (ALTO)
- **Diagnosi**:  
  Tutte le richieste POST in [`server/manager/app.py`](server/manager/app.py:58) (`/hosts/add`, `/hosts/{id}/delete`, `/settings/save`, `/apply`) sono form standard senza token CSRF né middleware di verifica (es. `starlette-csrf` o double-submit cookie).
- **Impatto**:  
  Un utente autenticato su Google che naviga su un sito esterno malevolo potrebbe essere bersaglio di richieste CSRF che cancellano o alterano le configurazioni dei proxy.
- **Remediation**:  
  Implementare un token CSRF crittografico generato a livello di sessione e convalidato su ogni richiesta di mutazione POST.

---

### Area 2: Lifecycle e Affidabilità dei Container (Operational Resilience)

#### OPS-01: `pip install` all'Avvio del Manager Container (ALTO)
- **Diagnosi**:  
  Nel Quadlet [`server/quadlet/manager.container`](server/quadlet/manager.container:16):
  ```ini
  Image=docker.io/library/python:3.12-alpine
  Exec=sh -c "pip install --no-cache-dir -r /app/manager/requirements.txt && python3 -m uvicorn app:app --host 127.0.0.1 --port 8000 --app-dir /app/manager"
  ```
- **Impatto**:  
  1. **Tempo di avvio e overhead**: Ad ogni avvio o riavvio del container, il sistema scarica e compila da zero i pacchetti Python (`fastapi`, `uvicorn`, `jinja2`, ecc.).
  2. **Affidabilità e crashloop**: Se al boot del server la connettività di rete della VPS tarda ad attivarsi rispetto a systemd, o se PyPI è irraggiungibile/lento, il container termina con codice di errore mandando il servizio in restart loop continuo.
  3. **Incoerenza delle versioni**: Se i requisiti non sono tassativamente pinnati, un aggiornamento a monte può rompere il container senza modifiche al codice locale.
- **Remediation**:  
  Creare un `server/manager/Containerfile` dedicato che pre-installi le dipendenze durante il build:
  ```dockerfile
  FROM docker.io/library/python:3.12-alpine
  WORKDIR /app/manager
  COPY requirements.txt .
  RUN pip install --no-cache-dir -r requirements.txt
  COPY . .
  CMD ["python3", "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000"]
  ```
  Aggiornare [`deploy-vps.sh`](deploy-vps.sh) per eseguire il build dell'immagine locale `localhost/edgeproxy-manager:latest` e puntare il Quadlet ad essa.

---

#### OPS-02: Esposizione del Socket Podman Root (ALTO)
- **Diagnosi**:  
  Il container del manager monta `/run/podman/podman.sock` ([`server/quadlet/manager.container`](server/quadlet/manager.container:14)) per poter inviare richieste REST all'endpoint `/containers/{name}/restart` in [`server/manager/config_engine.py`](server/manager/config_engine.py:291-325).
- **Impatto**:  
  Il socket di Podman (in esecuzione come root) equivale al pieno controllo root sull'host. Qualsiasi vulnerabilità nel codice Python o nelle sue dipendenze permetterebbe un Container Escape immediato.
- **Remediation**:  
  1. Per Caddy: viene già utilizzata la Admin API HTTP locale su `http://127.0.0.1:2019/load`, che non richiede il socket Podman.
  2. Per Rathole e OAuth2-Proxy: invece di montare l'intero socket Podman nel container web, utilizzare un watcher di file leggero (systemd path unit o script triggered via inotify sull'host) oppure limitare l'interfaccia di reload senza esporre il socket di gestione globale dei container.

---

#### OPS-03: Mancanza di Validazione Preventiva e Rollback Atomico (MEDIO)
- **Diagnosi**:  
  In [`server/manager/config_engine.py`](server/manager/config_engine.py:330-365):
  1. I file di configurazione (`Caddyfile`, `server.toml`, `oauth2-proxy.cfg`) vengono sovrascritti sul disco **prima** di tentare il reload di Caddy.
  2. Se la Admin API di Caddy fallisce (es. per un errore sintattico nel file generato), il file errato rimane salvato sul filesystem.
  3. Al successivo riavvio del container Caddy (es. dopo reboot dell'host), Caddy leggerà il file non valido e fallirà l'avvio, bloccando l'intero traffico web.
  4. La funzione [`apply_all_configurations()`](server/manager/config_engine.py:330) restituisce sempre `{"success": True}` indipendentemente dal risultato di [`reload_caddy()`](server/manager/config_engine.py:210).
- **Remediation**:  
  1. Eseguire validazione preventiva in memoria o su file temporaneo (`caddy validate --config /tmp/temp_caddyfile`).
  2. Mantenere un backup atomico della configurazione precedente (`Caddyfile.bak`).
  3. In caso di errore di reload, eseguire il ripristino istantaneo del file precedente (Rollback).
  4. Propagare lo stato di errore reale nell'interfaccia utente.

---

### Area 3: Protocolli e Performance (Performance Audit)

#### PERF-01: Buffer UDP del Kernel per HTTP/3 QUIC (MEDIO)
- **Diagnosi**:  
  Il pod espone la porta `443/udp` ([`server/quadlet/edgeproxy.pod`](server/quadlet/edgeproxy.pod:11)) e Caddy abilita HTTP/3 di default. Tuttavia, le distribuzioni Linux standard impostano `net.core.rmem_max` e `net.core.wmem_max` a circa 212 KB. La libreria QUIC utilizzata da Caddy (`quic-go`) richiede buffer socket di almeno 2.5 MB (ideale 7 MB).
- **Impatto**:  
  Caddy genera avvisi ad ogni avvio e, sotto traffico o latenza variabile, perde pacchetti UDP, con conseguente crollo del throughput HTTP/3 e frequenti fallback forzati su TCP HTTP/2.
- **Remediation**:  
  Aggiungere in [`deploy-vps.sh`](deploy-vps.sh) l'impostazione dei parametri `sysctl`:
  ```bash
  sysctl -w net.core.rmem_max=7340032
  sysctl -w net.core.wmem_max=7340032
  # Persistenza in /etc/sysctl.d/99-edgeproxy-quic.conf
  ```

---

#### PERF-02: Supporto WebSockets e Heartbeat Rathole (MEDIO)
- **Diagnosi**:  
  Per servizi come VS Code Server / code-server (`ide.mpv.cx`), le sessioni terminale e gli stream di debug utilizzano connessioni WebSocket persistenti. In [`client/rathole/client.toml`](client/rathole/client.toml:9) non sono definiti parametri di `heartbeat_interval` o `heartbeat_timeout`.
- **Impatto**:  
  In presenza di router NAT domestici o firewall aziendali che chiudono le connessioni TCP inattive dopo 60-120 secondi, le sessioni idle del terminale Web IDE si disconnettono silenziosamente.
- **Remediation**:  
  Configurare in Rathole:
  ```toml
  [client.transport]
  type = "noise"
  heartbeat_interval = 20
  heartbeat_timeout = 40
  ```
  In Caddy, verificare la direttiva `flush_interval -1` per i flussi interattivi ove necessario.

---

### Area 4: Allineamento Documentale e Debito Tecnico (Tech Debt)

#### DEBT-01: Residui Obsoleti di Authelia (MEDIO)
- **Diagnosi**:  
  Sebbene Authelia sia stata rimossa dal pod di produzione, permangono numerosi residui storici:
  1. [`README.md`](README.md:22): Diagramma Mermaid con Authelia, sezioni dedicate a `users_database.yml` e variabili d'ambiente Authelia.
  2. [`server/Containerfile`](server/Containerfile:18): Vecchia build unificata che include lo stage `authelia/authelia:latest`.
  3. [`server/supervisord.conf`](server/supervisord.conf:24): Configurazione per eseguire `[program:authelia]`.
  4. [`server/.env.example`](server/.env.example:21): Variabili `AUTHELIA_JWT_SECRET`, `AUTHELIA_SESSION_SECRET`, `AUTHELIA_STORAGE_ENCRYPTION_KEY`.
  5. [`deploy-vps.sh`](deploy-vps.sh:70): Generazione di secret Authelia e comandi di log obsoleti.
  6. [`server/manager/db.py`](server/manager/db.py:41): Tabella `users` con colonne `totp_secret`, `totp_enabled`, `password_hash` non più utilizzate.
  7. [`plans/master-architecture-and-guide.md`](plans/master-architecture-and-guide.md:5): Tratta ampiamente Authelia come componente primario.
- **Impatto**:  
  Disorientamento per nuovi sviluppatori o sysadmin, presenza di configurazioni inutili e disallineamento rispetto allo stato reale del runtime.
- **Remediation**:  
  Eseguire una pulizia strutturata di tutti i file menzionati, aggiornando la documentazione per riflettere l'architettura pura con **Google OAuth2 / OAuth2-Proxy**.

---

## 5. Piano di Remediation Raccomandato (Fasi Sequenziali)

### Fase 1: Hardening Critico della Sicurezza (Immediato)
1. **Protezione Web UI di Gestione**:
   - Modificare [`server/caddy/Caddyfile`](server/caddy/Caddyfile:10) e [`server/manager/config_engine.py`](server/manager/config_engine.py:114) per aggiungere `import google_auth` ai blocchi apex (`{$DOMAIN}`) e manager (`manager.{$DOMAIN}`).
2. **Abilitazione Noise Protocol in Rathole**:
   - Generare chiavi Noise e aggiornare [`server/rathole/server.toml`](server/rathole/server.toml:5), [`client/rathole/client.toml`](client/rathole/client.toml:9) e il motore [`server/manager/config_engine.py`](server/manager/config_engine.py:151).
3. **Iniezione Security Headers in Caddy**:
   - Aggiungere snippet `(security_headers)` in [`server/caddy/Caddyfile`](server/caddy/Caddyfile) e integrarlo nella generazione dinamica.

### Fase 2: Resilienza Operativa e Lifecycle dei Container
1. **Containerfile Dedicato per il Manager**:
   - Creare [`server/manager/Containerfile`](server/manager/Containerfile) con `pip install` durante il build dell'immagine.
   - Aggiornare [`server/quadlet/manager.container`](server/quadlet/manager.container:10) per utilizzare l'immagine precompilata ed eliminare `pip install` al comando `Exec=`.
2. **Atomic Write e Rollback del Config Engine**:
   - Riscrivere [`server/manager/config_engine.py`](server/manager/config_engine.py:330) per creare backup preventivi, convalidare il Caddyfile prima della scrittura e gestire rollback in caso di errore.

### Fase 3: Hardening Applicativo Manager
1. **Validazione FQDN e Sanitizzazione**:
   - Introdurre validazione con Pydantic o regex per i campi `domain`, `upstream`, `root_domain` in [`server/manager/app.py`](server/manager/app.py:58).
2. **Protezione CSRF**:
   - Aggiungere middleware CSRF su tutti i form POST.

### Fase 4: Ottimizzazione Network & Performance
1. **Configurazione Kernel per QUIC HTTP/3**:
   - Integrare in [`deploy-vps.sh`](deploy-vps.sh) la configurazione sysctl per i buffer socket UDP `rmem_max` e `wmem_max` a 7.5 MB.
2. **Heartbeat KeepAlive in Rathole**:
   - Aggiungere `heartbeat_interval = 20` e `heartbeat_timeout = 40` per prevenire drop di connessioni WebSocket inattive.

### Fase 5: Pulizia Debito Tecnico e Allineamento
1. Aggiornare [`README.md`](README.md), [`server/.env.example`](server/.env.example), [`deploy-vps.sh`](deploy-vps.sh) e [`plans/master-architecture-and-guide.md`](plans/master-architecture-and-guide.md) eliminando ogni riferimento ad Authelia.
2. Rimuovere [`server/Containerfile`](server/Containerfile) e [`server/supervisord.conf`](server/supervisord.conf) obsoleti o aggiornarli alla nuova architettura.
3. Rimuovere la tabella `users` orfana in [`server/manager/db.py`](server/manager/db.py:41).

---

## 6. Conclusioni dell'Audit

L'architettura attuale di EdgeProxy possiede fondamenta solide e moderne (Podman Pod, Caddy reverse proxy, Rathole tunneling ad alte prestazioni e Google OAuth2 senza credenziali locali). Tuttavia, l'attuale esposizione non protetta della Web UI di gestione e l'assenza di crittografia Noise sul canale Rathole WAN costituiscono vulnerabilità severe che richiedono intervento prioritario secondo le fasi del piano sopra descritto prima di considerare l'infrastruttura pronta per l'ambiente di produzione ad alta affidabilità.
