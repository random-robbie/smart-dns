#!/bin/bash
# Generate self-signed TLS certificates for DNS-over-TLS

CERT_DIR="/data/certs"
DAYS=3650  # 10 years

echo "Generating self-signed TLS certificates for DNS-over-TLS..."

# Create certificate directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Get hostname and IP address
HOSTNAME=$(hostname)
LOCAL_IP=$(hostname -i 2>/dev/null | awk '{print $1}')

# If we can't get IP from hostname, try to detect it
if [ -z "$LOCAL_IP" ] || [ "$LOCAL_IP" = "127.0.0.1" ]; then
    LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
fi

# Fallback to common private IP if detection fails
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="192.168.1.82"
fi

echo "Using hostname: ${HOSTNAME}.lan"
echo "Using IP: $LOCAL_IP"

# Generate private key and certificate with multiple SANs for compatibility
openssl req -x509 -newkey rsa:4096 -sha256 -days $DAYS -nodes \
  -keyout "$CERT_DIR/dns.key" \
  -out "$CERT_DIR/dns.crt" \
  -subj "/CN=${HOSTNAME}.lan/O=SmartDNS Proxy" \
  -addext "subjectAltName=DNS:${HOSTNAME}.lan,DNS:*.${HOSTNAME}.lan,DNS:${HOSTNAME}.local,DNS:*.${HOSTNAME}.local,DNS:${HOSTNAME},IP:${LOCAL_IP},IP:127.0.0.1"

# Set permissions
chmod 600 "$CERT_DIR/dns.key"
chmod 644 "$CERT_DIR/dns.crt"

echo ""
echo "Certificates generated successfully:"
echo "  Certificate: $CERT_DIR/dns.crt"
echo "  Private Key: $CERT_DIR/dns.key"
echo ""
echo "To use Private DNS on Android:"
echo "  1. Download certificate from web interface (http://${LOCAL_IP}:8080)"
echo "  2. Install it as a CA certificate (Settings > Security > Install from storage)"
echo "  3. Set Private DNS hostname to: ${HOSTNAME}.lan"
echo ""
echo "Certificate includes these hostnames:"
echo "  - ${HOSTNAME}.lan (recommended for Private DNS)"
echo "  - ${HOSTNAME}.local"
echo "  - ${HOSTNAME}"
echo "  - IP: ${LOCAL_IP}"
