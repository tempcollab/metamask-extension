#!/usr/bin/env bash
set -euo pipefail

# MetaMask Security Audit - Teardown

CONTAINER_NAME="metamask-audit"

echo "[TEARDOWN] Stopping and removing container '${CONTAINER_NAME}'..."

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  docker rm -f "${CONTAINER_NAME}" >/dev/null
  echo "[TEARDOWN] Container '${CONTAINER_NAME}' removed."
else
  echo "[TEARDOWN] Container '${CONTAINER_NAME}' not found - nothing to remove."
fi

echo "[TEARDOWN] Cleanup complete."
