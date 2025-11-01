# TLS Termination Proxy

A high-performance TLS termination proxy written in Rust for handling thousands of concurrent connections with minimal latency.

## Features

- High performance async I/O with Tokio
- TLS 1.2/1.3 support using rustls
- Load balancing (round-robin, least-connections)
- Prometheus metrics
- Hot configuration reload
- Certificate management and health checks

## Quick Start

1. Install dependencies:
```bash
cargo build --release
```

2. Generate test certificates:
```bash
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/C=US/ST=CA/L=San Francisco/O=Test/CN=localhost"
```

3. Create `config.yaml`:
```yaml
listen_addr: "0.0.0.0:8443"
backends:
  - "127.0.0.1:8080"
  - "127.0.0.1:8081"
cert_path: "./certs/server.crt"
key_path: "./certs/server.key"
strategy: "round_robin"
metrics_addr: "0.0.0.0:9090"
```

4. Run the proxy:
```bash
cargo run --bin tls-proxy -- --config config.yaml
```

## Configuration

Basic configuration options:
- `listen_addr`: TLS listener address
- `backends`: Backend server addresses
- `cert_path` / `key_path`: TLS certificate files
- `strategy`: Load balancing strategy
- `metrics_addr`: Prometheus metrics endpoint

## Usage

```bash
# Run proxy
tls-proxy --config config.yaml

# View metrics
curl http://localhost:9090/metrics

# Enable debug logging
RUST_LOG=debug tls-proxy --config config.yaml
```

## Testing

```bash
# Run tests
cargo test

# Load test
wrk -t12 -c400 -d30s --latency https://localhost:8443/
```

## License

MIT License
