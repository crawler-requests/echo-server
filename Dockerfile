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

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 echo \
 && adduser -D -u 10001 -G echo echo \
 && mkdir -p /data \
 && chown echo:echo /data
COPY --from=build /out/echo-server /usr/local/bin/echo-server
USER echo
ENV ECHO_SERVER_DB=/data/echo.db
VOLUME ["/data"]
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["echo-server"]
