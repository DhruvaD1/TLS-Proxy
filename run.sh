#!/bin/bash 

set -e

echo "=== TLS Termination Proxy Setup & Run Script ==="

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

cleanup() {
    echo "Cleaning up background processes..."
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
}

trap cleanup EXIT

echo "1. Creating certificates directory..."
mkdir -p certs

echo "2. Generating SSL certificates..."
if [ ! -f "certs/server.crt" ] || [ ! -f "certs/server.key" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/C=US/ST=CA/L=San Francisco/O=Test/CN=localhost" 2>/dev/null
    echo "   ✓ SSL certificates generated"
else
    echo "   ✓ SSL certificates already exist"
fi

echo "3. Building Rust project..."
cargo build --release

echo "4. Starting test backend servers..."
python3 -m http.server 8080 --directory /tmp &
BACKEND1_PID=$!
echo "   ✓ Backend server 1 started on port 8080 (PID: $BACKEND1_PID)"

python3 -m http.server 8081 --directory /tmp &
BACKEND2_PID=$!
echo "   ✓ Backend server 2 started on port 8081 (PID: $BACKEND2_PID)"

sleep 2

echo "5. Starting TLS termination proxy..."
echo "   Listening on: https://0.0.0.0:8443"
echo "   Metrics on: http://0.0.0.0:9090/metrics"
echo "   Press Ctrl+C to stop all services"
echo ""

RUST_LOG=info cargo run --release --bin tls-proxy -- --config config.yaml
