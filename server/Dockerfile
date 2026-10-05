# syntax=docker/dockerfile:1.7
# Base images are build args so they can point at an internal mirror.
ARG GO_IMAGE=golang:1.26-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${GO_IMAGE} AS build
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid=" \
    -o /out/doommsg-server ./cmd/doommsg-server \
 && mkdir -p /out/data

# Distroless static: no shell, no package manager, runs as non-root.
FROM ${RUNTIME_IMAGE}
COPY --from=build /out/doommsg-server /usr/local/bin/doommsg-server
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV DOOMMSG_DB=/data/doommsg.db \
    DOOMMSG_LISTEN=:8080 \
    DOOMMSG_METRICS_LISTEN=:9090
USER nonroot:nonroot
EXPOSE 8080 9090
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/doommsg-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/doommsg-server"]
