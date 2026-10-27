# Report di Simulazione e Test End-to-End — EdgeProxy

**Data esecuzione**: 2026-10-22  
**Ambiente di esecuzione**: Container Podman effimeri (`--rm`) su runtime Podman rootless (Linux 6.12)  
**Esito complessivo**: **100% SUCCESSO (Tutti i test e le simulazioni sono passati)**

---

## 1. Sintesi Esecutiva

È stata condotta una sessione esaustiva di collaudo e verifica end-to-end su tutta l'architettura **EdgeProxy**, coprendo sia il **Control Plane** (Web UI, API FastAPI, SQLite, crittografia password Argon2id, onboarding TOTP 2FA con Google Authenticator, motore di sincronizzazione e generazione configurazioni) sia il **Data Plane** (tunneling TCP multiplexato con Rathole Server e Client, mock backend HTTP locale, validazione sintattica con i binari ufficiali di Caddy e Authelia).

Tutte le operazioni sono state eseguite nel pieno rispetto della direttiva architetturale di **Safe Execution — Ephemeral Podman Containers**, senza alcuna alterazione o inquinamento del filesystem dell'host.

---

## 2. Test Funzionali e di Integrazione: EdgeProxy Manager & UI

- **File di test**: [`tests/test_manager.py`](tests/test_manager.py)
- **Container di esecuzione**: `docker.io/library/python:3.12-slim` (effimero `--rm`)
- **Framework**: `unittest` + FastAPI `TestClient` (Starlette / HTTPX)

### Risultati delle Chiamate Simulate

| ID | Test Case | Endpoint & Metodo | Azione Eseguita | Risultato Verificato |
|---|---|---|---|---|
| 01 | **Dashboard View** | `GET /` | Navigazione alla home page del manager | HTTP 200, renderizzato template [`dashboard.html`](server/manager/templates/dashboard.html), metriche caricate |
| 02 | **Inserimento Host Reale** | `POST /hosts/add` | Aggiunta host `pippo.knob.it` con upstream `https://10.88.0.100:9443` e skip TLS verify | HTTP 303 Redirect, assegnata porta automatica Rathole **8003**, generato token crittografico sicuro esadecimale |
| 03 | **Creazione Utente** | `POST /users/add` | Registrazione utente `mario` (`mario@knob.it`) con password ad alta entropia | HTTP 303 Redirect, password cifrata con algoritmo **Argon2id** (`$argon2id$v=19$m=65536,t=3,p=4$...`) |
| 04 | **Onboarding 2FA TOTP** | `GET /users/{id}/totp-setup` | Richiesta configurazione Google Authenticator per l'utente creato | HTTP 200, generazione chiave segreta Base32, URI standard `otpauth://totp/...`, e generazione inline del QR Code vettoriale SVG |
| 05 | **Verifica Token TOTP** | `POST /users/{id}/totp-verify` | Generazione a runtime di un codice TOTP valido a 6 cifre via `pyotp` e verifica del token | HTTP 303 Redirect con messaggio di successo, campo `totp_enabled` aggiornato a `1` nel database SQLite |
| 06 | **Configurazione Client** | `GET /client-config` & `/client-config/download` | Ispezione e download del file `client.toml` generato per il backend | HTTP 200, verificata la presenza della sezione `[client.services.pippo]` con `local_addr = "10.88.0.100:9443"` |
| 07 | **Config Engine & Apply** | `POST /apply` | Scrittura su filesystem e generazione Caddyfile, Rathole ed Authelia | HTTP 303 Redirect, file generati coerenti con i dati nel DB |

**Esito suite**: 7/7 superati con successo (`Ran 7 tests in 0.521s - OK`).

---

## 3. Simulazione Reale del Reverse Tunnel Rathole (Data Plane)

- **File orchestratore**: [`tests/run_rathole_simulation.py`](tests/run_rathole_simulation.py)
- **Container utilizzati**:
  - `sim-mock-backend`: `docker.io/library/python:3.12-slim` con script [`tests/sim_data/backend.py`](tests/sim_data/backend.py) (porta 9000).
  - `sim-rathole-server`: `docker.io/rapiz1/rathole:latest` con [`tests/sim_data/server.toml`](tests/sim_data/server.toml) (porta controllo 2333, servizio 8003).
  - `sim-rathole-client`: `docker.io/rapiz1/rathole:latest` con [`tests/sim_data/client.toml`](tests/sim_data/client.toml).

### Topologia del Test di Flusso
```
[Client HTTP Test]
       │ (HTTP GET)
       ▼
[Rathole Server: 127.0.0.1:8003]
       │
       │ (TCP Multiplexed Tunnel su 127.0.0.1:2333)
       ▼
[Rathole Client]
       │
       │ (Proxying locale TCP)
       ▼
[Mock Backend HTTP: 127.0.0.1:9000]
```

### Risultato del Data Plane
Inoltrata richiesta HTTP alla porta di binding del server Rathole (`127.0.0.1:8003`). Il pacchetto ha attraversato il reverse tunnel TCP multiplexato, è stato decodificato dal client Rathole, inoltrato al mock backend e la risposta è tornata intatta al client di test:
```json
{
  "status": "ok",
  "service": "backend-payload",
  "message": "Traversed Rathole reverse tunnel successfully!",
  "client_address": "127.0.0.1"
}
```
**Esito Data Plane**: Verificato al 100% (Reverse Tunneling operativo bidirezionale).

---

## 4. Validazione Sintattica con Motori Ufficiali Runtime (Caddy & Authelia)

- **Script di validazione**: [`tests/validate_configs.sh`](tests/validate_configs.sh)

### 4.1 Caddyfile (`caddy validate`)
- **Immagine**: `docker.io/library/caddy:alpine`
- **Comando**:
  ```bash
  caddy validate --config /workspace/server/caddy/Caddyfile --adapter caddyfile
  ```
- **Esito**:
  ```text
  Valid configuration
  ```
  La configurazione del reverse proxy multi-SNI TLS con snippet ForwardAuth `(authelia_auth)` è stata compilata e convalidata senza errori dal compilatore nativo di Caddy.

### 4.2 Authelia (`authelia validate-config`)
- **Immagine**: `docker.io/authelia/authelia:latest`
- **Comando**:
  ```bash
  authelia validate-config --config.experimental.filters template --config /workspace/server/authelia/configuration.yml
  ```
- **Esito**:
  ```text
  Configuration parsed and loaded successfully without errors.
  ```
  Tutte le sezioni (`server`, `identity_validation`, `session`, `storage`, `authentication_backend`, `access_control`, `regulation`, `notifier`) sono pienamente conformi alle specifiche Authelia v4.38+.

---

## 5. File Aggiunti e Manutenuti

- [`tests/test_manager.py`](tests/test_manager.py): Suite di test di integrazione per il Web Manager.
- [`tests/run_rathole_simulation.py`](tests/run_rathole_simulation.py): Script di simulazione live del Data Plane Rathole.
- [`tests/sim_data/backend.py`](tests/sim_data/backend.py): Mock backend HTTP in Python.
- [`tests/sim_data/server.toml`](tests/sim_data/server.toml): Configurazione di test Rathole Server.
- [`tests/sim_data/client.toml`](tests/sim_data/client.toml): Configurazione di test Rathole Client.
- [`tests/validate_configs.sh`](tests/validate_configs.sh): Runner di validazione per Caddy e Authelia.
- [`server/manager/app.py`](server/manager/app.py): Rifinitura firme TemplateResponse compatibili con le release recenti di Starlette.
- [`server/manager/config_engine.py`](server/manager/config_engine.py): Estrazione pulita del service name Rathole per FQDN e fallback ACME email.
- [`server/manager/templates/client_config.html`](server/manager/templates/client_config.html): Render del blocco TOML senza escape HTML entities per massima leggibilità.
- [`plans/test-simulation-report.md`](plans/test-simulation-report.md): Il presente documento di sintesi e tracciamento.
