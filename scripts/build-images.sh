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
    echo "Building Server Image: ${TAG_SERVER}"
    echo "=================================================="
    podman build \
        -t "${TAG_SERVER}" \
        -f "${ROOT_DIR}/server/Containerfile" \
        "${ROOT_DIR}/server"
    echo "Build completed successfully: ${TAG_SERVER}"
}

build_client() {
    echo "=================================================="
    echo "Building Client Image: ${TAG_CLIENT}"
    echo "=================================================="
    podman build \
        -t "${TAG_CLIENT}" \
        -f "${ROOT_DIR}/client/Containerfile" \
        "${ROOT_DIR}/client"
    echo "Build completed successfully: ${TAG_CLIENT}"
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
        echo "Usage: $0 [server|client|all]"
        exit 1
        ;;
esac

echo ""
echo "All requested images were successfully built."
