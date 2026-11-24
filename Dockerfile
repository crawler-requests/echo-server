# syntax=docker/dockerfile:1
#
# Build the console first, then embed it into a static Go binary (CGO disabled),
# so the runtime image carries only the executable, CA roots and tzdata.

FROM node:22-alpine AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/frontend/dist ./frontend/dist

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w \
      -X main.serverVersion=${VERSION} \
      -X main.buildCommit=${COMMIT} \
      -X main.buildDate=${BUILD_DATE}" \
    -o /out/echo-server .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 echo \
 && adduser -D -u 10001 -G echo echo \
 && mkdir -p /data \
 && chown echo:echo /data
COPY --from=build /out/echo-server /usr/local/bin/echo-server
USER echo
ENV ECHO_SERVER_DB=/data/echo.db
VOLUME ["/data"]
EXPOSE 23231 23232
# The binary probes itself instead of hard-coding the plain-HTTP port: with
# HTTP_PORT=0 (HTTPS-only) or a moved plain port, `wget ...:23231` dials a
# closed socket and the container is reported unhealthy forever. The CMD form
# runs through the container shell and resolves the binary on PATH; the string
# spelling is what Docker records as ["CMD-SHELL","echo-server healthcheck"].
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD echo-server healthcheck || exit 1
ENTRYPOINT ["echo-server"]
