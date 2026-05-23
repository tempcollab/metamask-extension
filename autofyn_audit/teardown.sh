#!/usr/bin/env bash
set -euo pipefail

# MetaMask Security Audit - Teardown
#
# Browser dependencies (Chromium, puppeteer-core) and the pre-downloaded MetaMask CRX
# all live inside the 'metamask-audit' container. Removing that container cleans them up —
# there are no separate browser containers to tear down.

CONTAINER_NAME="metamask-audit"

echo "[TEARDOWN] Stopping and removing container '${CONTAINER_NAME}'..."

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  docker rm -f "${CONTAINER_NAME}" >/dev/null
  echo "[TEARDOWN] Container '${CONTAINER_NAME}' removed."
else
  echo "[TEARDOWN] Container '${CONTAINER_NAME}' not found - nothing to remove."
fi

# Clean up any stale browser test containers from live tests
for c in $(docker ps -a --format '{{.Names}}' | grep -E '^metamask-audit-chain' || true); do
  echo "[TEARDOWN] Removing stale browser test container: $c"
  docker rm -f "$c" >/dev/null 2>&1 || true
done

echo "[TEARDOWN] Cleanup complete."
