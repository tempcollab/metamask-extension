#!/usr/bin/env bash
set -euo pipefail

# MetaMask Security Audit - Docker Environment Setup
# Uses node:22-bookworm pinned by SHA256 for reproducibility.

DOCKER_IMAGE="node@sha256:1031993481795705055273f2eef0c24597abdcb277d6e058c82f78cbbdef92a6"
CONTAINER_NAME="metamask-audit"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[SETUP] MetaMask Security Audit Environment Bootstrap"
echo "[SETUP] Image:     node:22-bookworm@sha256:1031993481795705055273f2eef0c24597abdcb277d6e058c82f78cbbdef92a6"
echo "[SETUP] Container: ${CONTAINER_NAME}"
echo "[SETUP] Repo:      ${REPO_ROOT}"

# Remove any existing container with the same name (idempotent).
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "[SETUP] Removing existing container '${CONTAINER_NAME}'..."
  docker rm -f "${CONTAINER_NAME}" >/dev/null
fi

echo "[SETUP] Pulling image (pinned by SHA256)..."
docker pull "${DOCKER_IMAGE}"

echo "[SETUP] Starting container..."
docker run -d \
  --name "${CONTAINER_NAME}" \
  "${DOCKER_IMAGE}" \
  sleep infinity

echo "[SETUP] Installing system dependencies (git, python3)..."
docker exec "${CONTAINER_NAME}" bash -c "
  apt-get update -qq &&
  apt-get install -y --no-install-recommends git python3 2>&1 | tail -5
"

echo "[SETUP] Verifying Node.js and npm are available..."
docker exec "${CONTAINER_NAME}" node --version
docker exec "${CONTAINER_NAME}" npm --version

echo "[SETUP] Installing tsx globally (needed by VULN-1 exploit)..."
docker exec "${CONTAINER_NAME}" npm install -g tsx 2>&1 | tail -3

echo "[SETUP] Copying repository into container at /repo (read-only reference) and /app (writable workspace)..."
docker cp "${REPO_ROOT}/." "${CONTAINER_NAME}:/repo"
docker exec "${CONTAINER_NAME}" bash -c "cp -r /repo /app"

echo "[SETUP] Setting up /exploits symlink for exploit HTML pages..."
docker exec "${CONTAINER_NAME}" bash -c "ln -sf /repo/autofyn_audit/exploits /exploits"

echo "[SETUP] Setup complete. Container '${CONTAINER_NAME}' is running."
echo "[SETUP] Run './run_all_exploits.sh' to execute all exploit PoCs."
