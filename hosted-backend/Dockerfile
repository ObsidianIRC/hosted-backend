# syntax=docker/dockerfile:1.6
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache build-base sqlite-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/backend .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates sqlite-libs tzdata wget \
    && adduser -D -u 1000 backend \
    && mkdir -p /app/images /app/data /run/obbyirc \
    && chown -R backend:backend /app /run/obbyirc
WORKDIR /app
COPY --from=builder /out/backend /usr/local/bin/backend
USER backend
EXPOSE 8080 3478/udp
CMD ["backend"]
