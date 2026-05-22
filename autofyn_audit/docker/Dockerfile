# MetaMask Extension Security Audit - Live Exploit Pipeline
# Commit: 4e88c336d0a99c322429ec1cf4e6911263cdd0e9
# Base: node:24-bookworm@sha256:8530f76a96d88820d288761f022e318970dda93d01536919fbc16076b7983e63

# ── Stage 1: Build MetaMask Extension ──────────────────────────
FROM node:24-bookworm@sha256:8530f76a96d88820d288761f022e318970dda93d01536919fbc16076b7983e63 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

ENV CI=1
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn .yarn

RUN corepack enable && corepack prepare yarn@4.14.1 --activate

COPY . .

RUN cp .metamaskrc.dist .metamaskrc

# Mock git so `git rev-parse HEAD` returns a fixed hash (build system needs it)
RUN printf '#!/bin/sh\necho 4e88c336d0a99c322429ec1cf4e6911263cdd0e9\n' > /usr/local/bin/git && \
    chmod +x /usr/local/bin/git

# Install dependencies (capture output for VULN-05 evidence)
RUN yarn install 2>&1 | tee /install-log.txt; exit 0

# Build the extension in test/dev mode (faster, no LavaMoat)
RUN SEGMENT_HOST='https://api.segment.io' \
    SEGMENT_WRITE_KEY='FAKE' \
    yarn build:dev testDev --apply-lavamoat=false 2>&1 | tee /build-log.txt

# Create stub lockdown files (build with --apply-lavamoat=false skips them)
RUN for f in lockdown-install.js lockdown-run.js lockdown-more.js; do \
      test -f /build/dist/chrome/scripts/$f || echo "// stub" > /build/dist/chrome/scripts/$f; \
    done

# Verify the build produced output
RUN ls -la /build/dist/chrome/manifest.json

# ── Stage 2: Exploit Runner ───────────────────────────────────
FROM node:24-bookworm@sha256:8530f76a96d88820d288761f022e318970dda93d01536919fbc16076b7983e63 AS runner

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      chromium \
      fonts-liberation \
      libatk-bridge2.0-0 \
      libdrm2 \
      libgbm1 \
      libgtk-3-0 \
      libx11-xcb1 \
      libxcomposite1 \
      libxdamage1 \
      libxrandr2 \
      xdg-utils \
      xvfb \
    && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV CHROME_BIN=/usr/bin/chromium

WORKDIR /exploit

COPY autofyn_audit/exploits/package.json .
RUN npm install --no-audit --no-fund

COPY autofyn_audit/exploits/ .
COPY --from=builder /build/dist/chrome /extension
COPY --from=builder /build-log.txt /build-log.txt
COPY --from=builder /install-log.txt /install-log.txt

RUN mkdir -p /results/screenshots /results/console-logs

CMD ["xvfb-run", "--auto-servernum", "--server-args=-screen 0 1280x1024x24", "node", "harness.js"]
