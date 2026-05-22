#!/usr/bin/env bash
set -euo pipefail

# MetaMask Extension Security Audit - Teardown Script
# Removes Docker containers, images, and temporary files.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_DIR="$(dirname "$SCRIPT_DIR")"

IMAGE_NAME="metamask-audit-exploit"
CONTAINER_NAME="metamask-audit-runner"

echo "=== MetaMask Extension Security Audit Teardown ==="

# Stop and remove container
if docker ps -aq --filter "name=$CONTAINER_NAME" 2>/dev/null | grep -q .; then
    echo "Removing container: $CONTAINER_NAME..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
fi

# Remove Docker image
if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Removing Docker image: $IMAGE_NAME..."
    docker rmi "$IMAGE_NAME" 2>/dev/null || true
fi

# Clean up exploit server PID if running locally
if [ -f "$AUDIT_DIR/.exploit-server.pid" ]; then
    PID=$(cat "$AUDIT_DIR/.exploit-server.pid")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping local exploit server (PID: $PID)..."
        kill "$PID" 2>/dev/null || true
    fi
    rm -f "$AUDIT_DIR/.exploit-server.pid"
fi

# Clean up exploit node_modules
if [ -d "$AUDIT_DIR/exploits/node_modules" ]; then
    echo "Cleaning up exploit dependencies..."
    rm -rf "$AUDIT_DIR/exploits/node_modules"
    rm -f "$AUDIT_DIR/exploits/package-lock.json"
fi

# Clean up Docker build log
rm -f "$AUDIT_DIR/docker-build.log"

echo ""
echo "=== Teardown Complete ==="
echo "Note: Results in $AUDIT_DIR/results/ are preserved."
echo "      Run 'rm -rf $AUDIT_DIR/results/' to remove them."
