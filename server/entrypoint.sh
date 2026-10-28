#!/bin/bash
# ==============================================================================
# EdgeProxy Server — All-in-One Entrypoint Script
# Initializes persistent storage in /data, links configuration targets,
# and starts supervisord managing Caddy, Rathole, OAuth2-Proxy, and Manager.
# ==============================================================================
set -e

# If custom CLI arguments are provided, execute them directly
if [[ $# -gt 0 ]]; then
  exec "$@"
fi

DOMAIN="${DOMAIN:-example.com}"
ACME_EMAIL="${ACME_EMAIL:-admin@example.com}"
export DOMAIN
export ACME_EMAIL
export EDGEPROXY_DB_PATH="${EDGEPROXY_DB_PATH:-/data/edgeproxy.db}"
export ACCESS_LOG_PATH="${ACCESS_LOG_PATH:-/data/caddy/logs/access.jsonl}"

echo "[edgeproxy-server] Initializing All-in-One EdgeProxy Server for domain: ${DOMAIN} (${ACME_EMAIL})"

# Ensure persistent directories exist
mkdir -p /data/caddy /data/caddy/logs /data/rathole /data/oauth2-proxy /var/log

# Seed default configurations into /data if they do not exist
if [ ! -f /data/caddy/Caddyfile ]; then
    echo "[edgeproxy-server] Seeding default Caddyfile into /data/caddy/Caddyfile..."
    cp /defaults/caddy/Caddyfile /data/caddy/Caddyfile
fi

if [ ! -f /data/rathole/server.toml ]; then
    echo "[edgeproxy-server] Seeding default server.toml into /data/rathole/server.toml..."
    cp /defaults/rathole/server.toml /data/rathole/server.toml
fi

if [ ! -f /data/oauth2-proxy/oauth2-proxy.cfg ]; then
    echo "[edgeproxy-server] Seeding default oauth2-proxy.cfg into /data/oauth2-proxy/oauth2-proxy.cfg..."
    cp /defaults/oauth2-proxy/oauth2-proxy.cfg /data/oauth2-proxy/oauth2-proxy.cfg
    # Update cookie_domains and redirect_url if DOMAIN is custom
    if [ "$DOMAIN" != "example.com" ]; then
        sed -i "s/example\.com/${DOMAIN}/g" /data/oauth2-proxy/oauth2-proxy.cfg
    fi
fi

if [ ! -f /data/oauth2-proxy/authenticated_emails.txt ]; then
    echo "[edgeproxy-server] Seeding default authenticated_emails.txt into /data/oauth2-proxy/..."
    cp /defaults/oauth2-proxy/authenticated_emails.txt /data/oauth2-proxy/authenticated_emails.txt
    if [ "$ACME_EMAIL" != "admin@example.com" ]; then
        echo "$ACME_EMAIL" >> /data/oauth2-proxy/authenticated_emails.txt
    fi
fi

# Ensure Rathole log file exists
touch /var/log/rathole.log

# Stream rathole logs to stdout in background so container logs capture tunnel events
tail -f /var/log/rathole.log 2>/dev/null &

# Backward-compatibility symlinks so legacy scripts or tools find configs in /etc/edgeproxy
mkdir -p /etc/edgeproxy/caddy /etc/edgeproxy/rathole /etc/edgeproxy/oauth2-proxy /etc/oauth2-proxy
ln -sf /data/caddy/Caddyfile /etc/edgeproxy/caddy/Caddyfile
ln -sf /data/rathole/server.toml /etc/edgeproxy/rathole/server.toml
ln -sf /data/oauth2-proxy/oauth2-proxy.cfg /etc/edgeproxy/oauth2-proxy/oauth2-proxy.cfg
ln -sf /data/oauth2-proxy/authenticated_emails.txt /etc/edgeproxy/oauth2-proxy/authenticated_emails.txt
ln -sf /data/oauth2-proxy/authenticated_emails.txt /etc/oauth2-proxy/authenticated_emails.txt

echo "[edgeproxy-server] Launching supervisord orchestrating Caddy, Rathole, OAuth2-Proxy and Manager..."
exec /usr/bin/supervisord -n -c /etc/supervisord.conf
