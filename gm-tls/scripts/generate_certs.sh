#!/bin/bash
# Generate SM2 test certificates for gm-tls examples
# Requires OpenSSL 1.1.1+ with SM2/SM3/SM4 support

set -e

CERT_DIR="${CERT_DIR:-.}"

echo "Generating SM2 test certificates in $CERT_DIR..."

# CA key and certificate
openssl ecparam -name sm2 -genkey -noout -out "$CERT_DIR/ca-key.pem" 2>/dev/null || {
    echo "Error: OpenSSL does not support SM2. Please install OpenSSL 1.1.1+ with SM2 support."
    exit 1
}

openssl req -new -key "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca.csr" \
    -subj "/CN=GM TLS Test CA/O=Test/C=CN" \
    -sm3

openssl x509 -req -in "$CERT_DIR/ca.csr" \
    -signkey "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca.pem" \
    -sm3 -sm2 \
    -days 3650

# Server key and certificate
openssl ecparam -name sm2 -genkey -noout -out "$CERT_DIR/server-key.pem"
openssl req -new -key "$CERT_DIR/server-key.pem" \
    -out "$CERT_DIR/server.csr" \
    -subj "/CN=localhost/O=Server/C=CN" \
    -sm3

openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/server.pem" \
    -sm3 -sm2 \
    -days 365 \
    -extfile <(echo "subjectAltName=DNS:localhost,DNS:127.0.0.1")

# Client key and certificate
openssl ecparam -name sm2 -genkey -noout -out "$CERT_DIR/client-key.pem"
openssl req -new -key "$CERT_DIR/client-key.pem" \
    -out "$CERT_DIR/client.csr" \
    -subj "/CN=Client/O=Test/C=CN" \
    -sm3

openssl x509 -req -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/client.pem" \
    -sm3 -sm2 \
    -days 365

# Cleanup CSR files
rm -f "$CERT_DIR/ca.csr" "$CERT_DIR/server.csr" "$CERT_DIR/client.csr"

echo "Generated certificates:"
ls -la "$CERT_DIR"/*.pem
echo ""
echo "Done! Certificates are ready in $CERT_DIR"
