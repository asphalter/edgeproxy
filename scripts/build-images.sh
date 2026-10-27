#!/usr/bin/env bash
# ==============================================================================
# EdgeProxy — Local Image Build Script
# Compiles both edgeproxy-server and edgeproxy-client containers locally.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TAG_SERVER="${TAG_SERVER:-localhost/edgeproxy-server:latest}"
TAG_CLIENT="${TAG_CLIENT:-localhost/edgeproxy-client:latest}"

TARGET="${1:-all}"

build_server() {
    echo "=================================================="
    echo "Compilazione Immagine Server: ${TAG_SERVER}"
    echo "=================================================="
    podman build \
        -t "${TAG_SERVER}" \
        -f "${ROOT_DIR}/server/Containerfile" \
        "${ROOT_DIR}/server"
    echo "Compilazione completata con successo: ${TAG_SERVER}"
}

build_client() {
    echo "=================================================="
    echo "Compilazione Immagine Client: ${TAG_CLIENT}"
    echo "=================================================="
    podman build \
        -t "${TAG_CLIENT}" \
        -f "${ROOT_DIR}/client/Containerfile" \
        "${ROOT_DIR}/client"
    echo "Compilazione completata con successo: ${TAG_CLIENT}"
}

case "${TARGET}" in
    server)
        build_server
        ;;
    client)
        build_client
        ;;
    all)
        build_server
        build_client
        ;;
    *)
        echo "Uso: $0 [server|client|all]"
        exit 1
        ;;
esac

echo ""
echo "Tutte le immagini richieste sono state compilate con successo."
