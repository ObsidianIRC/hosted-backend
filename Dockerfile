# syntax=docker/dockerfile:1.6
#
# obby-api / hosted-backend image -- REST + JWT + WebRTC SFU + TURN.
# CGO_ENABLED=1 is required because mattn/go-sqlite3 ships as cgo.
#
# Build:   docker build -t obbyworld/obby-api .
# Compose: docker compose up -d

FROM golang:1.25-alpine AS builder
RUN apk add --no-cache build-base sqlite-dev opus-dev opusfile-dev pkgconfig
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/backend .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates sqlite-libs tzdata netcat-openbsd opus opusfile \
    && adduser -D -u 1000 backend \
    && mkdir -p /app/data /app/images /run/obbyirc \
    && chown -R backend:backend /app /run/obbyirc
WORKDIR /app
COPY --from=builder /out/backend /usr/local/bin/backend
USER backend
EXPOSE 8080 3478/udp
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD nc -z 127.0.0.1 8080 || exit 1
CMD ["backend"]
