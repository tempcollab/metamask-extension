#!/usr/bin/env bash
set -euo pipefail

# MetaMask Extension Security Audit - Setup Script
# Builds the Docker container with MetaMask extension and exploit runner.
#
# Commit: 4e88c336d0a99c322429ec1cf4e6911263cdd0e9
# Docker base: node:24-bookworm@sha256:8530f76a96d88820d288761f022e318970dda93d01536919fbc16076b7983e63

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$AUDIT_DIR")"

IMAGE_NAME="metamask-audit-exploit"
CONTAINER_NAME="metamask-audit-runner"
EXPECTED_COMMIT="4e88c336d0a99c322429ec1cf4e6911263cdd0e9"

echo "=== MetaMask Extension Security Audit - Setup ==="
echo "Repo:   $REPO_DIR"
echo "Audit:  $AUDIT_DIR"
echo "Image:  $IMAGE_NAME"
echo ""

# Verify commit
CURRENT_COMMIT=$(git -C "$REPO_DIR" rev-parse HEAD)
if [ "$CURRENT_COMMIT" != "$EXPECTED_COMMIT" ]; then
    echo "WARNING: Current commit ($CURRENT_COMMIT) != expected ($EXPECTED_COMMIT)"
    echo "Results may differ from the audit."
fi

# Prerequisites
echo "[1/3] Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required"; exit 1; }
echo "  Docker: $(docker --version)"
echo "  Commit: $CURRENT_COMMIT"

# Build Docker image
echo ""
echo "[2/3] Building Docker image (this will take 10-30 minutes on first run)..."
echo "  Building MetaMask from source inside Docker..."
echo "  Image: node:24-bookworm@sha256:8530f76a96d88820d288761f022e318970dda93d01536919fbc16076b7983e63"
echo ""

docker build \
    -t "$IMAGE_NAME" \
    -f "$AUDIT_DIR/docker/Dockerfile" \
    "$REPO_DIR" 2>&1 | tee "$AUDIT_DIR/docker-build.log"

echo ""
echo "[3/3] Verifying build..."
# Quick verification that the image has the extension
docker run --rm "$IMAGE_NAME" \
    node -e "
const fs = require('fs');
const m = JSON.parse(fs.readFileSync('/extension/manifest.json','utf8'));
console.log('Extension: ' + m.name + ' v' + m.version);
console.log('MV' + m.manifest_version);
console.log('externally_connectable:', JSON.stringify(m.externally_connectable));
"

echo ""
echo "=== Setup Complete ==="
echo "Run exploits with:  bash $AUDIT_DIR/scripts/run-live-exploits.sh"
echo "Teardown with:      bash $AUDIT_DIR/scripts/teardown.sh"
