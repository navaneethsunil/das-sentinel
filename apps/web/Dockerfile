# DAS Sentinel web image (M0-F1) — multi-stage standalone build.
# Digest-pinned base per CLAUDE.md §3 (never a mutable tag) — TR-25. Bump: re-pin
# via `docker buildx imagetools inspect --format '{{.Manifest.Digest}}' node:24-slim`.
FROM node:24-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

FROM node:24-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:24-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS run
WORKDIR /app
# Runtime is `node server.js` (Next standalone) + a `node -e` healthcheck — npm and
# corepack are never invoked. Removing the base image's bundled global npm drops its
# CVEs (tar/undici/brace-expansion, no fixed node base yet) and shrinks attack
# surface: a production image should carry no package manager.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
# Non-root (ASVS/least-privilege); standalone output needs no node_modules copy.
USER node
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public

# Internal-network bind only; the Caddy proxy is the single ingress (TR-4).
CMD ["node", "server.js"]
