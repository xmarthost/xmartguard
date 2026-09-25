# XMart Guard portal: API + web UI + agent downloads in one image.

FROM golang:1.24-bookworm AS agent
WORKDIR /src
COPY agent/go.mod agent/go.sum agent/
RUN cd agent && go mod download
COPY agent agent
COPY scripts/build-agent.sh scripts/
COPY VERSION ./
RUN OUT=/out/downloads bash scripts/build-agent.sh

FROM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM node:22-bookworm-slim AS server
WORKDIR /src/server
COPY server/package.json server/package-lock.json ./
RUN npm ci
COPY server ./
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    PORT=8080 \
    WEB_DIR=/app/web \
    DOWNLOADS_DIR=/app/downloads \
    INSTALLER_DIR=/app/installer \
    DATA_DIR=/app/data
WORKDIR /app/server
COPY --from=server /src/server/dist ./dist
COPY --from=server /src/server/node_modules ./node_modules
COPY --from=server /src/server/package.json ./
COPY --from=web /src/web/dist /app/web
COPY --from=agent /out/downloads /app/downloads
COPY installer /app/installer
# Writable data (GeoIP database); mounted as a volume by docker-compose.
RUN mkdir -p /app/data && chown node:node /app/data
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://127.0.0.1:8080/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
