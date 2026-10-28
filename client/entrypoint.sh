#!/bin/bash
# ==============================================================================
# EdgeProxy Client — All-in-One Entrypoint Script
# Manages the lifecycle of Rathole Client, zero-touch polling at 15s intervals,
# and heartbeat telemetry/log reporting to EdgeProxy Manager Web UI.
# ==============================================================================
set -e

# If arbitrary CLI arguments are provided, execute directly (command/debug mode)
if [[ $# -gt 0 ]]; then
  exec "$@"
fi

# Environment variable configurations with defaults
SERVER_URL="${SERVER_URL:-https://auth.edge.mpv.cx}"
SYNC_TOKEN="${SYNC_TOKEN:-}"
INTERVAL="${INTERVAL:-15}"
CONFIG_PATH="${CONFIG_PATH:-/etc/rathole/client.toml}"
CLIENT_NAME="${CLIENT_NAME:-$(hostname 2>/dev/null || echo "edgeproxy-client")}"

START_TIME=$(date +%s)
RATHOLE_PID=""
TAIL_PID=""

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [edgeproxy-client] $*"
}

cleanup() {
  log "Termination signal caught, shutting down running processes..."
  if [[ -n "$RATHOLE_PID" ]] && kill -0 "$RATHOLE_PID" 2>/dev/null; then
    log "Terminating Rathole process (PID: ${RATHOLE_PID})..."
    kill -TERM "$RATHOLE_PID" 2>/dev/null || true
    wait "$RATHOLE_PID" 2>/dev/null || true
  fi
  if [[ -n "$TAIL_PID" ]] && kill -0 "$TAIL_PID" 2>/dev/null; then
    kill -TERM "$TAIL_PID" 2>/dev/null || true
  fi
  log "Shutdown complete."
  exit 0
}

trap cleanup SIGTERM SIGINT

# Ensure configuration directory and logs exist
mkdir -p "$(dirname "$CONFIG_PATH")"
mkdir -p /tmp
touch /tmp/rathole.log

# Stream rathole logs to stdout in background
tail -f /tmp/rathole.log 2>/dev/null &
TAIL_PID=$!

sync_config() {
  if [[ -z "$SYNC_TOKEN" ]]; then
    return 1
  fi

  local tmp_file="${CONFIG_PATH}.tmp"
  local http_code
  http_code=$(curl -sS -k -w "%{http_code}" \
    -H "Authorization: Bearer ${SYNC_TOKEN}" \
    "${SERVER_URL}/api/v1/client/config" \
    -o "$tmp_file" 2>/dev/null || echo "000")

  if [[ "$http_code" == "200" ]]; then
    if grep -q "\[client\]" "$tmp_file" 2>/dev/null; then
      if ! cmp -s "$tmp_file" "$CONFIG_PATH" 2>/dev/null; then
        mv "$tmp_file" "$CONFIG_PATH"
        log "Configuration client.toml successfully synchronized and updated."
        return 0
      else
        rm -f "$tmp_file"
        return 1
      fi
    else
      log "Warning: downloaded configuration does not contain [client] section. Ignored."
      rm -f "$tmp_file"
      return 2
    fi
  else
    log "Synchronization from ${SERVER_URL} failed (HTTP ${http_code})."
    rm -f "$tmp_file"
    return 2
  fi
}

send_heartbeat_and_logs() {
  if [[ -z "$SYNC_TOKEN" ]]; then
    return 0
  fi

  local uptime_sec=0
  if [[ -f /proc/uptime ]]; then
    uptime_sec=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
  else
    uptime_sec=$(($(date +%s) - START_TIME))
  fi

  local hname
  hname=$(hostname 2>/dev/null || echo "$CLIENT_NAME")
  local rathole_ver="unknown"
  if command -v rathole >/dev/null 2>&1; then
    rathole_ver=$(rathole --version 2>&1 | head -n1 || echo "unknown")
  fi

  # Measure round-trip connection latency (ms) to server ping endpoint
  local LATENCY_MS
  LATENCY_MS=$(curl -s -k -o /dev/null -w "%{time_connect}" --max-time 3 "${SERVER_URL}/api/v1/client/ping" 2>/dev/null | awk '{printf "%.1f", $1 * 1000}' || echo "0.0")
  if [[ -z "$LATENCY_MS" || ! "$LATENCY_MS" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    LATENCY_MS="0.0"
  fi

  local json_payload=""
  if command -v jq >/dev/null 2>&1; then
    local logs_json="[]"
    if [[ -f /tmp/rathole.log ]]; then
      logs_json=$(tail -n 30 /tmp/rathole.log 2>/dev/null | jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map({
            level: (if test("(?i)error") then "error" elif test("(?i)warn") then "warn" else "info" end),
            message: .
          })
      ' 2>/dev/null || echo "[]")
    fi

    json_payload=$(jq -n \
      --arg cname "$CLIENT_NAME" \
      --argjson uptime "$uptime_sec" \
      --arg ver "$rathole_ver" \
      --arg host "$hname" \
      --argjson latency "$LATENCY_MS" \
      --argjson logs "$logs_json" \
      '{
        client_name: $cname,
        uptime_seconds: $uptime,
        version: $ver,
        hostname: $host,
        latency_ms: $latency,
        logs: $logs
      }' 2>/dev/null || true)
  fi

  if [[ -z "$json_payload" ]]; then
    json_payload="{\"client_name\": \"$CLIENT_NAME\", \"uptime_seconds\": $uptime_sec, \"version\": \"$rathole_ver\", \"hostname\": \"$hname\", \"latency_ms\": $LATENCY_MS, \"logs\": []}"
  fi

  curl -sS -k -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${SYNC_TOKEN}" \
    -d "$json_payload" \
    "${SERVER_URL}/api/v1/client/report" >/dev/null 2>&1 || true
}

start_rathole() {
  if [[ -f "$CONFIG_PATH" ]]; then
    log "Starting Rathole Client (config: ${CONFIG_PATH})..."
    rathole --client "$CONFIG_PATH" >> /tmp/rathole.log 2>&1 &
    RATHOLE_PID=$!
    log "Rathole Client active with PID: ${RATHOLE_PID}"
  else
    log "Warning: ${CONFIG_PATH} not found. Waiting for initial sync..."
  fi
}

restart_rathole() {
  log "Restarting Rathole Client..."
  if [[ -n "$RATHOLE_PID" ]] && kill -0 "$RATHOLE_PID" 2>/dev/null; then
    kill -TERM "$RATHOLE_PID" 2>/dev/null || true
    wait "$RATHOLE_PID" 2>/dev/null || true
  fi
  start_rathole
}

log "=================================================================="
log "Starting EdgeProxy All-in-One Client runtime"
log "Target Server: ${SERVER_URL}"
log "Config Path  : ${CONFIG_PATH}"
log "Poll Interval: ${INTERVAL}s"
log "Client Name  : ${CLIENT_NAME}"
log "=================================================================="

initial_sync_with_retry() {
  if [[ -z "$SYNC_TOKEN" ]]; then
    log "Notice: No SYNC_TOKEN specified, skipping zero-touch configuration download."
    return 0
  fi

  local max_retries=8
  local delay=2
  local max_delay=30
  local attempt=1

  log "Executing initial zero-touch configuration synchronization (up to ${max_retries} attempts with exponential backoff)..."

  while [[ $attempt -le $max_retries ]]; do
    log "Initial sync attempt ${attempt}/${max_retries}..."
    local sync_res=0
    sync_config && sync_res=$? || sync_res=$?

    if [[ $sync_res -eq 0 ]]; then
      log "Initial configuration successfully downloaded on attempt ${attempt}."
      return 0
    elif [[ $sync_res -eq 1 ]] && [[ -f "$CONFIG_PATH" ]]; then
      log "Initial configuration is already up to date on disk (attempt ${attempt})."
      return 0
    fi

    if [[ $attempt -lt $max_retries ]]; then
      log "Initial sync attempt ${attempt} failed (code ${sync_res}). Retrying in ${delay}s..."
      sleep "$delay"
      delay=$((delay * 2))
      if [[ $delay -gt $max_delay ]]; then
        delay=$max_delay
      fi
    fi
    attempt=$((attempt + 1))
  done

  if [[ -f "$CONFIG_PATH" ]]; then
    log "Warning: Initial sync attempts failed, but existing cached configuration found at ${CONFIG_PATH}. Proceeding with cached file."
  else
    log "Warning: Initial sync failed and no local ${CONFIG_PATH} cache exists. Non-fatal: continuing to background polling loop until server becomes available."
  fi
  return 1
}

# Initial sync attempt before launching Rathole
if [[ -n "$SYNC_TOKEN" ]]; then
  initial_sync_with_retry || true
fi

# Launch Rathole
start_rathole

# Polling and telemetry reporting loop
log "Entering background zero-touch synchronization and telemetry loop..."
while true; do
  sleep "$INTERVAL"

  # Sync check
  if [[ -n "$SYNC_TOKEN" ]]; then
    if sync_config; then
      log "New configuration detected. Reloading Rathole Client..."
      restart_rathole
    fi
    send_heartbeat_and_logs
  fi

  # Check if Rathole process unexpectedly died
  if [[ -n "$RATHOLE_PID" ]] && ! kill -0 "$RATHOLE_PID" 2>/dev/null; then
    log "Warning: Rathole Client process (PID: ${RATHOLE_PID}) terminated. Restarting..."
    start_rathole
  elif [[ -z "$RATHOLE_PID" ]] && [[ -f "$CONFIG_PATH" ]]; then
    start_rathole
  fi
done
