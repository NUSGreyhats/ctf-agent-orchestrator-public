#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CREDS_FILE="/root/.ctf-solver-password"

# Generate credentials (only on first run)
if [ ! -f "$CREDS_FILE" ]; then
  python3 -c "import secrets; print(secrets.token_urlsafe(32))" > "$CREDS_FILE"
  chmod 600 "$CREDS_FILE"
fi

export APP_PASSWORD
APP_PASSWORD="$(cat "$CREDS_FILE")"
export SESSION_SECRET
SESSION_SECRET="$(python3 -c "import secrets; print(secrets.token_hex(32))")"

mkdir -p /root/all-things-ai/challenges

# Generate self-signed TLS certificate (only on first run)
CERT_DIR="/root/.ctf-solver-tls"
if [ ! -f "$CERT_DIR/cert.pem" ]; then
  mkdir -p "$CERT_DIR"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days 365 \
    -subj "/CN=ctf-solver"
  chmod 600 "$CERT_DIR/key.pem"
fi
export TLS_CERTFILE="$CERT_DIR/cert.pem"
export TLS_KEYFILE="$CERT_DIR/key.pem"

echo ""
echo "============================================"
echo "  CTF Solver Web App"
echo "============================================"
echo "  Password: $APP_PASSWORD"
echo "============================================"
echo ""

exec python3 "$SCRIPT_DIR/app.py"
