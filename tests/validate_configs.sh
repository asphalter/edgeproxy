#!/usr/bin/env bash
set -e

echo "======================================================================"
echo "Official Syntax Validation: Caddy"
echo "======================================================================"

# Validate Caddyfile with ephemeral container caddy:alpine
echo -n "Validating Caddyfile with 'caddy validate'... "
podman run --rm \
    -e ACME_EMAIL=admin@example.com \
    -e DOMAIN=example.com \
    -e OAUTH2_PROXY_ADDR=127.0.0.1:4180 \
    -v "$(pwd):/workspace:z" -w /workspace \
    caddy:alpine \
    caddy validate --config /workspace/server/caddy/Caddyfile --adapter caddyfile

echo ">>> Caddyfile: 100% VALID!"
echo "======================================================================"
