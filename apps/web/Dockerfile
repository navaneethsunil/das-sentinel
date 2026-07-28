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

# Distroless runtime (debian12 to match the bookworm build base's node ABI):
# no shell, no package manager, minimal OS = smallest attack surface and far
# fewer base-OS CVEs than node:*-slim. Runtime is only `node server.js` (Next
# standalone), so nothing else is needed. Digest-pinned per §3 (TR-25); the
# ENTRYPOINT is node so CMD passes args, and USER is 65532 (nonroot) built in.
# Bump: `docker buildx imagetools inspect --format '{{.Manifest.Digest}}' \
# gcr.io/distroless/nodejs24-debian12:nonroot`.
# NOTE: the app uses no next/image, so sharp (native, not traced into the
# standalone) is never loaded. If image optimization is added, sharp will need
# its native libs present here (distroless is minimal) — revisit then.
FROM gcr.io/distroless/nodejs24-debian12:nonroot@sha256:14d42e2511532589a7c7e01a753667a74fcc96266e137e8125006b87b0c32d0a AS run
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
COPY --from=build --chown=65532:65532 /app/.next/standalone ./
COPY --from=build --chown=65532:65532 /app/.next/static ./.next/static
COPY --from=build --chown=65532:65532 /app/public ./public

# Internal-network bind only; the Caddy proxy is the single ingress (TR-4).
CMD ["server.js"]
