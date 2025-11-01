use anyhow::Result;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use bytes::Bytes;
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Registry, TextEncoder,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tracing::{error, info};

pub struct ProxyMetrics {
    registry: Registry,
    
    server_start_time: Instant,
    
    connections_total: IntCounterVec,
    connections_active: IntGauge,
    connections_rejected: IntCounter,
    connection_duration: HistogramVec,
    
    tls_handshakes_total: IntCounterVec,
    tls_handshake_duration: Histogram,
    tls_handshake_errors: IntCounterVec,
    
    backend_connections_total: IntCounterVec,
    backend_connection_duration: HistogramVec,
    backend_connection_errors: IntCounterVec,
    backend_health_status: IntGaugeVec,
    
    bytes_transferred_total: IntCounterVec,
    request_duration: HistogramVec,
    requests_total: IntCounterVec,
    
    proxy_errors_total: IntCounterVec,
    rate_limit_exceeded: IntCounter,
    
    system_cpu_usage: Gauge,
    system_memory_usage: Gauge,
    process_resident_memory: Gauge,
    process_virtual_memory: Gauge,
    
    backend_response_time: HistogramVec,
    backend_active_connections: IntGaugeVec,
    
    total_connections: AtomicU64,
    total_bytes_transferred: AtomicU64,
}

impl ProxyMetrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let connections_total = IntCounterVec::new(
            prometheus::Opts::new("proxy_connections_total", "Total number of connections"),
            &["status"],
        )?;

        let connections_active = IntGauge::new(
            "proxy_connections_active",
            "Current number of active connections",
        )?;

        let connections_rejected = IntCounter::new(
            "proxy_connections_rejected_total",
            "Total number of rejected connections",
        )?;

        let connection_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "proxy_connection_duration_seconds",
                "Duration of connections in seconds",
            )
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 60.0]),
            &["backend"],
        )?;

        let tls_handshakes_total = IntCounterVec::new(
            prometheus::Opts::new("proxy_tls_handshakes_total", "Total number of TLS handshakes"),
            &["status"],
        )?;

        let tls_handshake_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "proxy_tls_handshake_duration_seconds",
                "Duration of TLS handshakes in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        )?;

        let tls_handshake_errors = IntCounterVec::new(
            prometheus::Opts::new("proxy_tls_handshake_errors_total", "Total TLS handshake errors"),
            &["error_type"],
        )?;

        let backend_connections_total = IntCounterVec::new(
            prometheus::Opts::new("proxy_backend_connections_total", "Total backend connections"),
            &["backend", "status"],
        )?;

        let backend_connection_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "proxy_backend_connection_duration_seconds",
                "Duration of backend connections",
            )
            .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
            &["backend"],
        )?;

        let backend_connection_errors = IntCounterVec::new(
            prometheus::Opts::new("proxy_backend_connection_errors_total", "Backend connection errors"),
            &["backend", "error_type"],
        )?;

        let backend_health_status = IntGaugeVec::new(
            prometheus::Opts::new("proxy_backend_health_status", "Backend health status (1=healthy, 0=unhealthy)"),
            &["backend"],
        )?;

        let bytes_transferred_total = IntCounterVec::new(
            prometheus::Opts::new("proxy_bytes_transferred_total", "Total bytes transferred"),
            &["direction", "backend"],
        )?;

        let request_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "proxy_request_duration_seconds",
                "Request duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
            &["backend"],
        )?;

        let requests_total = IntCounterVec::new(
            prometheus::Opts::new("proxy_requests_total", "Total number of requests"),
            &["backend", "status"],
        )?;

        let proxy_errors_total = IntCounterVec::new(
            prometheus::Opts::new("proxy_errors_total", "Total proxy errors"),
            &["error_type"],
        )?;

        let rate_limit_exceeded = IntCounter::new(
            "proxy_rate_limit_exceeded_total",
            "Total rate limit exceeded events",
        )?;

        let system_cpu_usage = Gauge::new(
            "system_cpu_usage_percent",
            "System CPU usage percentage",
        )?;

        let system_memory_usage = Gauge::new(
            "system_memory_usage_bytes",
            "System memory usage in bytes",
        )?;

        let process_resident_memory = Gauge::new(
            "process_resident_memory_bytes",
            "Process resident memory in bytes",
        )?;

        let process_virtual_memory = Gauge::new(
            "process_virtual_memory_bytes",
            "Process virtual memory in bytes",
        )?;

        let backend_response_time = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "proxy_backend_response_time_seconds",
                "Backend response time in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["backend"],
        )?;

        let backend_active_connections = IntGaugeVec::new(
            prometheus::Opts::new("proxy_backend_active_connections", "Active connections per backend"),
            &["backend"],
        )?;

        registry.register(Box::new(connections_total.clone()))?;
        registry.register(Box::new(connections_active.clone()))?;
        registry.register(Box::new(connections_rejected.clone()))?;
        registry.register(Box::new(connection_duration.clone()))?;
        registry.register(Box::new(tls_handshakes_total.clone()))?;
        registry.register(Box::new(tls_handshake_duration.clone()))?;
        registry.register(Box::new(tls_handshake_errors.clone()))?;
        registry.register(Box::new(backend_connections_total.clone()))?;
        registry.register(Box::new(backend_connection_duration.clone()))?;
        registry.register(Box::new(backend_connection_errors.clone()))?;
        registry.register(Box::new(backend_health_status.clone()))?;
        registry.register(Box::new(bytes_transferred_total.clone()))?;
        registry.register(Box::new(request_duration.clone()))?;
        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(proxy_errors_total.clone()))?;
        registry.register(Box::new(rate_limit_exceeded.clone()))?;
        registry.register(Box::new(system_cpu_usage.clone()))?;
        registry.register(Box::new(system_memory_usage.clone()))?;
        registry.register(Box::new(process_resident_memory.clone()))?;
        registry.register(Box::new(process_virtual_memory.clone()))?;
        registry.register(Box::new(backend_response_time.clone()))?;
        registry.register(Box::new(backend_active_connections.clone()))?;

        Ok(Self {
            registry,
            server_start_time: Instant::now(),
            connections_total,
            connections_active,
            connections_rejected,
            connection_duration,
            tls_handshakes_total,
            tls_handshake_duration,
            tls_handshake_errors,
            backend_connections_total,
            backend_connection_duration,
            backend_connection_errors,
            backend_health_status,
            bytes_transferred_total,
            request_duration,
            requests_total,
            proxy_errors_total,
            rate_limit_exceeded,
            system_cpu_usage,
            system_memory_usage,
            process_resident_memory,
            process_virtual_memory,
            backend_response_time,
            backend_active_connections,
            total_connections: AtomicU64::new(0),
            total_bytes_transferred: AtomicU64::new(0),
        })
    }

    pub fn record_server_start(&self) {
        info!("Metrics server initialized");
    }

    pub fn record_connection_accepted(&self) {
        self.connections_total.with_label_values(&["accepted"]).inc();
        self.connections_active.inc();
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_completed(&self) {
        self.connections_total.with_label_values(&["completed"]).inc();
        self.connections_active.dec();
    }

    pub fn record_connection_rejected(&self) {
        self.connections_rejected.inc();
    }

    pub fn record_connection_error(&self) {
        self.connections_total.with_label_values(&["error"]).inc();
        self.connections_active.dec();
    }

    pub fn record_connection_timeout(&self) {
        self.connections_total.with_label_values(&["timeout"]).inc();
        self.connections_active.dec();
    }

    pub fn record_connection_duration(&self, duration: Duration, backend: &str) {
        self.connection_duration
            .with_label_values(&[backend])
            .observe(duration.as_secs_f64());
    }

    pub fn record_tls_handshake_success(&self, duration: Duration) {
        self.tls_handshakes_total.with_label_values(&["success"]).inc();
        self.tls_handshake_duration.observe(duration.as_secs_f64());
    }

    pub fn record_tls_handshake_failure(&self) {
        self.tls_handshakes_total.with_label_values(&["failure"]).inc();
        self.tls_handshake_errors.with_label_values(&["handshake_failed"]).inc();
    }

    pub fn record_tls_handshake_timeout(&self) {
        self.tls_handshakes_total.with_label_values(&["timeout"]).inc();
        self.tls_handshake_errors.with_label_values(&["timeout"]).inc();
    }

    pub fn record_backend_connection_success(&self, backend: &str, duration: Duration) {
        self.backend_connections_total.with_label_values(&[backend, "success"]).inc();
        self.backend_connection_duration.with_label_values(&[backend]).observe(duration.as_secs_f64());
    }

    pub fn record_backend_connection_error(&self) {
        self.backend_connection_errors.with_label_values(&["unknown", "connection_failed"]).inc();
    }

    pub fn record_backend_connection_timeout(&self) {
        self.backend_connection_errors.with_label_values(&["unknown", "timeout"]).inc();
    }

    pub fn record_backend_health_status(&self, backend: &str, is_healthy: bool) {
        self.backend_health_status
            .with_label_values(&[backend])
            .set(if is_healthy { 1 } else { 0 });
    }

    pub fn record_bytes_transferred(&self, bytes: u64) {
        self.total_bytes_transferred.fetch_add(bytes, Ordering::Relaxed);
        self.bytes_transferred_total.with_label_values(&["total", "all"]).inc_by(bytes);
    }

    pub fn record_bytes_sent(&self, bytes: u64, backend: &str) {
        self.bytes_transferred_total.with_label_values(&["sent", backend]).inc_by(bytes);
    }

    pub fn record_bytes_received(&self, bytes: u64, backend: &str) {
        self.bytes_transferred_total.with_label_values(&["received", backend]).inc_by(bytes);
    }

    pub fn record_request_duration(&self, duration: Duration, backend: &str) {
        self.request_duration.with_label_values(&[backend]).observe(duration.as_secs_f64());
    }

    pub fn record_request_completed(&self, backend: &str, status: &str) {
        self.requests_total.with_label_values(&[backend, status]).inc();
    }

    pub fn record_proxy_error(&self) {
        self.proxy_errors_total.with_label_values(&["proxy_error"]).inc();
    }

    pub fn record_no_backend_available(&self) {
        self.proxy_errors_total.with_label_values(&["no_backend_available"]).inc();
    }

    pub fn record_rate_limited(&self) {
        self.rate_limit_exceeded.inc();
    }

    pub fn record_accept_error(&self) {
        self.proxy_errors_total.with_label_values(&["accept_error"]).inc();
    }

    pub fn record_backend_response_time(&self, duration: Duration, backend: &str) {
        self.backend_response_time.with_label_values(&[backend]).observe(duration.as_secs_f64());
    }

    pub fn update_backend_active_connections(&self, backend: &str, count: i64) {
        self.backend_active_connections.with_label_values(&[backend]).set(count);
    }

    pub fn update_system_metrics(&self) {
        if let Ok(cpu_usage) = self.get_cpu_usage() {
            self.system_cpu_usage.set(cpu_usage);
        }

        if let Ok(memory_usage) = self.get_memory_usage() {
            self.system_memory_usage.set(memory_usage as f64);
            if let Ok(process_memory) = self.get_process_memory() {
                self.process_resident_memory.set(process_memory.0 as f64);
                self.process_virtual_memory.set(process_memory.1 as f64);
            }
        }
    }

    pub fn get_total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    pub fn get_total_bytes_transferred(&self) -> u64 {
        self.total_bytes_transferred.load(Ordering::Relaxed)
    }

    pub fn get_uptime(&self) -> Duration {
        self.server_start_time.elapsed()
    }

    pub fn export_metrics(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }

    fn get_cpu_usage(&self) -> Result<f64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            let stat = fs::read_to_string("/proc/stat")?;
            let cpu_line = stat.lines().next().ok_or_else(|| anyhow::anyhow!("No CPU line in /proc/stat"))?;
            let values: Vec<u64> = cpu_line
                .split_whitespace()
                .skip(1)
                .take(7)
                .map(|s| s.parse().unwrap_or(0))
                .collect();
            
            if values.len() >= 4 {
                let idle = values[3];
                let total: u64 = values.iter().sum();
                let usage = 100.0 * (total - idle) as f64 / total as f64;
                Ok(usage)
            } else {
                Ok(0.0)
            }
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            Ok(0.0)
        }
    }

    fn get_memory_usage(&self) -> Result<u64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            let meminfo = fs::read_to_string("/proc/meminfo")?;
            let mut total_memory = 0u64;
            let mut available_memory = 0u64;
            
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    total_memory = line.split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0) * 1024;
                } else if line.starts_with("MemAvailable:") {
                    available_memory = line.split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0) * 1024;
                }
            }
            
            Ok(total_memory - available_memory)
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            Ok(0)
        }
    }

    fn get_process_memory(&self) -> Result<(u64, u64)> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            let status = fs::read_to_string("/proc/self/status")?;
            let mut rss = 0u64;
            let mut vsize = 0u64;
            
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    rss = line.split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0) * 1024;
                } else if line.starts_with("VmSize:") {
                    vsize = line.split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0) * 1024;
                }
            }
            
            Ok((rss, vsize))
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            Ok((0, 0))
        }
    }
}

pub struct MetricsServer {
    metrics: Arc<ProxyMetrics>,
    addr: SocketAddr,
}

impl MetricsServer {
    pub fn new(metrics: Arc<ProxyMetrics>, addr: SocketAddr) -> Self {
        Self { metrics, addr }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("Metrics server listening on {}", self.addr);

        let metrics_clone = Arc::clone(&self.metrics);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                metrics_clone.update_system_metrics();
            }
        });

        loop {
            let (stream, _) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let metrics = Arc::clone(&self.metrics);

            tokio::spawn(async move {
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| {
                        let metrics = Arc::clone(&metrics);
                        async move { Self::handle_request(req, metrics).await }
                    }))
                    .await
                {
                    error!("Error serving connection: {}", err);
                }
            });
        }
    }

    async fn handle_request(
        req: Request<Incoming>,
        metrics: Arc<ProxyMetrics>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/metrics") => {
                match metrics.export_metrics() {
                    Ok(metrics_data) => {
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "text/plain; version=0.0.4")
                            .body(Full::new(Bytes::from(metrics_data)))
                            .unwrap())
                    }
                    Err(e) => {
                        error!("Failed to export metrics: {}", e);
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::new(Bytes::from("Internal Server Error")))
                            .unwrap())
                    }
                }
            }
            (&Method::GET, "/health") => {
                let health_data = serde_json::json!({
                    "status": "healthy",
                    "uptime_seconds": metrics.get_uptime().as_secs(),
                    "total_connections": metrics.get_total_connections(),
                    "total_bytes_transferred": metrics.get_total_bytes_transferred()
                });
                
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(health_data.to_string())))
                    .unwrap())
            }
            (&Method::GET, "/") => {
                let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>TLS Termination Proxy</title>
</head>
<body>
    <h1>TLS Termination Proxy</h1>
    <p>Endpoints:</p>
    <ul>
        <li><a href="/metrics">/metrics</a> - Prometheus metrics</li>
        <li><a href="/health">/health</a> - Health check</li>
    </ul>
</body>
</html>"#;
                
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/html")
                    .body(Full::new(Bytes::from(html)))
                    .unwrap())
            }
            _ => {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("Not Found")))
                    .unwrap())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_creation() {
        let metrics = ProxyMetrics::new().unwrap();
        assert!(metrics.export_metrics().is_ok());
    }

    #[test]
    fn test_metrics_recording() {
        let metrics = ProxyMetrics::new().unwrap();
        
        metrics.record_connection_accepted();
        assert_eq!(metrics.get_total_connections(), 1);
        
        metrics.record_bytes_transferred(1024);
        assert_eq!(metrics.get_total_bytes_transferred(), 1024);
        
        metrics.record_tls_handshake_success(Duration::from_millis(10));
        metrics.record_backend_connection_success("backend1", Duration::from_millis(5));
    }

    #[test]
    fn test_uptime_tracking() {
        let metrics = ProxyMetrics::new().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(metrics.get_uptime() >= Duration::from_millis(10));
    }
}
