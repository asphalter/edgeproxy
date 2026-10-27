# Product Context — EdgeProxy

## Scopo del Progetto

EdgeProxy è una soluzione infrastrutturale che sostituisce l'esposizione dei servizi interni precedentemente gestita con **Cloudflare Tunnel** (autenticazione Cloudflare Access 2FA via Google Authenticator e gestione SSL automatica) con uno stack self-hosted su **VPS proprietaria con IPv4 pubblico**.

L'obiettivo è mantenere la stessa esperienza di accesso sicuro (Google SSO 2FA, certificati SSL/TLS automatici, zero porte in ingresso nella LAN) eliminando la dipendenza da Cloudflare e ottenendo piena sovranità su dati, credenziali e certificati.

## Problema che Risolve

- Il backend locale si trova dietro NAT/firewall e non può o non deve esporre porte aperte in ingresso.
- Occorre un gateway pubblico fidato con terminazione TLS e autenticazione perimetrale a due fattori.
- Sostituisce Cloudflare Tunnel offrendo:
  - Reverse tunnel multiplexato ad alta efficienza.
  - Certificati TLS Let's Encrypt / ZeroSSL automatici gestiti da Caddy.
  - Autenticazione 2FA Google Workspace / Gmail tramite OAuth2-Proxy.
  - Sincronizzazione automatica della configurazione tra gateway pubblico e client locale.

## Stack Tecnologico

1. **Rathole** — reverse tunnel multiplexato con Noise Protocol (server su VPS, client su backend LAN).
2. **Caddy v2** — reverse proxy e terminazione TLS automatica con supporto HTTP/3.
3. **OAuth2-Proxy** — autenticazione SSO Google con cookie sicuri e forward_auth.
4. **EdgeProxy Manager** — interfaccia web FastAPI e motore di configurazione a caldo.
5. **Podman Quadlet** — deployment all-in-one a container singolo precompilato (immagini pubblicate su GHCR).

## Modello Operativo

- Il traffico in ingresso dall'esterno arriva unicamente sulla VPS pubblica sulle porte `80`, `443` e `2333`.
- Il backend locale apre esclusivamente una connessione TCP in uscita (outbound) verso la porta `2333` della VPS.
- Configurazione zero-touch: il client effettua il polling delle impostazioni dal Manager e si aggiorna automaticamente a caldo.
