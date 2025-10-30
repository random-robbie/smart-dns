FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with musl compatibility
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE"
RUN CGO_ENABLED=1 go build -o smartdns-proxy

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates sqlite-libs openssl

WORKDIR /app

# Copy binary and web files
COPY --from=builder /app/smartdns-proxy .
COPY --from=builder /app/web ./web
COPY generate-certs.sh .

# Expose DNS (UDP/TCP), DNS-over-TLS, and API ports
EXPOSE 53/udp 53/tcp 853/tcp 8080/tcp

# Run as root (required for port 53)
CMD ["./smartdns-proxy"]
