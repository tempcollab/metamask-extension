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

echo "[SETUP] Installing browser dependencies (Chromium, puppeteer-core)..."
docker exec "${CONTAINER_NAME}" bash -c "
  apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation \
    libnss3 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libgbm1 \
    libasound2 \
    2>&1 | tail -5
"
docker exec "${CONTAINER_NAME}" npm install -g puppeteer-core@24.9.0 2>&1 | tail -3

echo "[SETUP] Verifying browser dependencies..."
docker exec "${CONTAINER_NAME}" chromium --version
docker exec "${CONTAINER_NAME}" node -e "require('puppeteer-core')"

echo "[SETUP] Pre-downloading MetaMask CRX for reproducible live tests..."
METAMASK_EXT_ID="nkbihfbeogaeaoehlefnkodbefgpgknn"
CRX_URL="https://clients2.google.com/service/update2/crx?response=redirect&prodversion=130.0&acceptformat=crx2,crx3&x=id%3D${METAMASK_EXT_ID}%26uc"

docker exec "${CONTAINER_NAME}" bash -c "
  if [ -f '/tmp/metamask-crx/manifest.json' ]; then
    echo '[SETUP] MetaMask CRX already present at /tmp/metamask-crx — skipping download'
    CRX_VER=\$(python3 -c \"import json; d=json.load(open('/tmp/metamask-crx/manifest.json')); print(d.get('version','unknown'))\" 2>/dev/null || echo 'unknown')
    echo '[SETUP] CRX version: ' \${CRX_VER}
    exit 0
  fi
  echo '[SETUP] Downloading MetaMask CRX from Chrome Web Store...'
  echo '[SETUP]   Extension ID: ${METAMASK_EXT_ID}'
  curl -sS -L -o /tmp/metamask.crx '${CRX_URL}' || exit 1
  echo '[SETUP] CRX downloaded, size: ' \$(wc -c < /tmp/metamask.crx) 'bytes'
  python3 -c \"
import zipfile, sys, os
with open('/tmp/metamask.crx', 'rb') as f:
    data = f.read()
idx = data.find(b'PK\x03\x04')
if idx == -1:
    print('[SETUP] ERROR: ZIP magic not found in CRX file')
    sys.exit(1)
with open('/tmp/metamask.zip', 'wb') as out:
    out.write(data[idx:])
os.makedirs('/tmp/metamask-crx', exist_ok=True)
with zipfile.ZipFile('/tmp/metamask.zip') as z:
    z.extractall('/tmp/metamask-crx')
print('[SETUP] CRX extracted to /tmp/metamask-crx')
\" || exit 1
  if [ -f '/tmp/metamask-crx/manifest.json' ]; then
    echo '[SETUP] CRX manifest found, extraction successful'
    CRX_VER=\$(python3 -c \"import json; d=json.load(open('/tmp/metamask-crx/manifest.json')); print(d.get('version','unknown'))\" 2>/dev/null || echo 'unknown')
    echo '[SETUP] CRX version: ' \${CRX_VER}
  else
    echo '[SETUP] ERROR: manifest.json not found after CRX extraction'
    exit 1
  fi
"

echo "[SETUP] Verifying MetaMask CRX extraction..."
docker exec "${CONTAINER_NAME}" bash -c "
  if [ -f '/tmp/metamask-crx/manifest.json' ]; then
    echo '[SETUP] /tmp/metamask-crx/manifest.json exists — CRX ready'
  else
    echo '[SETUP] ERROR: /tmp/metamask-crx/manifest.json not found'
    exit 1
  fi
"

echo "[SETUP] Setup complete. Container '${CONTAINER_NAME}' is running."
echo "[SETUP] Browser deps: Chromium + puppeteer-core installed. MetaMask CRX pre-downloaded."
echo "[SETUP] Run './run_all_exploits.sh' to execute all exploit PoCs."
