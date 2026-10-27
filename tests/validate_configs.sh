#!/usr/bin/env bash
set -e

echo "======================================================================"
echo "Validazione Sintattica Ufficiale: Caddy"
echo "======================================================================"

# Validazione Caddyfile con container effimero caddy:alpine
echo -n "Validazione Caddyfile con 'caddy validate'... "
podman run --rm \
    -e ACME_EMAIL=matteo.piva@gmail.com \
    -e DOMAIN=edge.mpv.cx \
    -e OAUTH2_PROXY_ADDR=127.0.0.1:4180 \
    -v "$(pwd):/workspace:z" -w /workspace \
    caddy:alpine \
    caddy validate --config /workspace/server/caddy/Caddyfile --adapter caddyfile

echo ">>> Caddyfile: 100% VALIDO!"
echo "======================================================================"
