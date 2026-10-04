# syntax=docker/dockerfile:1.7
# Base images are build args so they can point at an internal mirror.
ARG NODE_IMAGE=node:22-alpine
ARG CADDY_IMAGE=caddy:2-alpine

FROM ${NODE_IMAGE} AS build
ARG NPM_REGISTRY=https://registry.npmjs.org/
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm config set registry ${NPM_REGISTRY} && npm ci --ignore-scripts --no-audit --no-fund
COPY . .
RUN npm run build

# Caddy serves the static client, terminates TLS (automatic HTTPS) and
# reverse-proxies the API/WebSocket to the relay.
FROM ${CADDY_IMAGE}
COPY --from=build /app/dist /srv
COPY Caddyfile /etc/caddy/Caddyfile
