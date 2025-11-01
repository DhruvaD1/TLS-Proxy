use crate::balancer::{BackendNode, LoadBalancer};
use crate::config::{LimitsConfig, ProxyConfig, TcpConfig};
use crate::metrics::ProxyMetrics;
use crate::tls::TlsManager;
use anyhow::{Context, Result};
use bytes::Bytes;
use parking_lot::RwLock;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock as TokioRwLock, Semaphore};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tracing::{error, info, warn};

pub struct ProxyServer {
    config: Arc<ProxyConfig>,
    tls_manager: Arc<TlsManager>,
    load_balancer: Arc<dyn LoadBalancer>,
    metrics: Arc<ProxyMetrics>,
    active_connections: Arc<AtomicUsize>,
    connection_semaphore: Arc<Semaphore>,
    handshake_semaphore: Arc<Semaphore>,
    rate_limiter: Option<Arc<RateLimiter>>,
}

impl ProxyServer {
    pub fn new(
        config: Arc<ProxyConfig>,
        tls_manager: Arc<TlsManager>,
        load_balancer: Arc<dyn LoadBalancer>,
        metrics: Arc<ProxyMetrics>,
    ) -> Self {
        let connection_semaphore = Arc::new(Semaphore::new(config.limits.max_connections));
        let handshake_semaphore = Arc::new(Semaphore::new(config.limits.max_concurrent_handshakes));
        
        let rate_limiter = config.limits.rate_limit_requests_per_second.map(|rps| {
            Arc::new(RateLimiter::new(rps, config.limits.rate_limit_window))
        });

        Self {
            config,
            tls_manager,
            load_balancer,
            metrics,
            active_connections: Arc::new(AtomicUsize::new(0)),
            connection_semaphore,
            handshake_semaphore,
            rate_limiter,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = self.create_tcp_listener().await?;
        let local_addr = listener.local_addr()?;
        
        info!("TLS Proxy server listening on {}", local_addr);
        self.metrics.record_server_start();

        loop {
            match listener.accept().await {
                Ok((tcp_stream, client_addr)) => {
                    let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!("Connection limit reached, dropping connection from {}", client_addr);
                            self.metrics.record_connection_rejected();
                            continue;
                        }
                    };

                    if let Some(rate_limiter) = &self.rate_limiter {
                        if !rate_limiter.allow_request(client_addr.ip()).await {
                            warn!("Rate limit exceeded for {}", client_addr.ip());
                            self.metrics.record_rate_limited();
                            continue;
                        }
                    }

                    let proxy = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = proxy.handle_connection(tcp_stream, client_addr).await {
                            error!("Error handling connection from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    self.metrics.record_accept_error();
                }
            }
        }
    }

    async fn create_tcp_listener(&self) -> Result<TcpListener> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        
        socket.set_reuse_address(true)?;
        if self.config.tcp.reuse_port {
            socket.set_reuse_port(true)?;
        }
        
        if let Some(size) = self.config.tcp.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = self.config.tcp.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }
        
        socket.set_nonblocking(true)?;
        socket.bind(&self.config.listen_addr.into())?;
        socket.listen(self.config.tcp.max_backlog as i32)?;
        
        let std_listener: std::net::TcpListener = socket.into();
        let tokio_listener = TcpListener::from_std(std_listener)?;
        
        Ok(tokio_listener)
    }

    async fn handle_connection(&self, tcp_stream: TcpStream, client_addr: SocketAddr) -> Result<()> {
        self.configure_tcp_stream(&tcp_stream)?;
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.metrics.record_connection_accepted();
        
        let connection_start = Instant::now();

        let result = timeout(
            self.config.limits.connection_timeout,
            self.handle_tls_handshake(tcp_stream, client_addr)
        ).await;

        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        
        match result {
            Ok(Ok(_)) => {
                self.metrics.record_connection_completed();
                info!("Connection from {} completed in {:?}", client_addr, connection_start.elapsed());
            }
            Ok(Err(e)) => {
                self.metrics.record_connection_error();
                error!("Connection error for {}: {}", client_addr, e);
            }
            Err(_) => {
                self.metrics.record_connection_timeout();
                warn!("Connection from {} timed out", client_addr);
            }
        }

        Ok(())
    }

    async fn handle_tls_handshake(&self, tcp_stream: TcpStream, client_addr: SocketAddr) -> Result<()> {
        let handshake_permit = self.handshake_semaphore.clone().acquire_owned().await?;
        let handshake_start = Instant::now();

        let tls_stream = match timeout(
            Duration::from_secs(30),
            self.tls_manager.accept_tls_connection(tcp_stream)
        ).await {
            Ok(Ok(stream)) => {
                drop(handshake_permit);
                let handshake_duration = handshake_start.elapsed();
                self.metrics.record_tls_handshake_success(handshake_duration);
                info!("TLS handshake completed for {} in {:?}", client_addr, handshake_duration);
                stream
            }
            Ok(Err(e)) => {
                drop(handshake_permit);
                self.metrics.record_tls_handshake_failure();
                return Err(e).context("TLS handshake failed");
            }
            Err(_) => {
                drop(handshake_permit);
                self.metrics.record_tls_handshake_timeout();
                anyhow::bail!("TLS handshake timed out");
            }
        };

        self.handle_proxy_connection(tls_stream, client_addr).await
    }

    async fn handle_proxy_connection(&self, tls_stream: TlsStream<TcpStream>, client_addr: SocketAddr) -> Result<()> {
        let backend = match self.load_balancer.select_backend(Some(client_addr)).await {
            Some(backend) => backend,
            None => {
                self.metrics.record_no_backend_available();
                anyhow::bail!("No healthy backend available");
            }
        };

        info!("Proxying connection from {} to {}", client_addr, backend.config.addr);
        backend.increment_connections();

        let result = self.proxy_streams(tls_stream, &backend, client_addr).await;
        
        backend.decrement_connections();

        if let Err(ref e) = result {
            self.load_balancer.mark_backend_unhealthy(&backend).await;
            error!("Backend {} marked unhealthy due to error: {}", backend.config.addr, e);
        }

        result
    }

    async fn proxy_streams(
        &self,
        mut tls_stream: TlsStream<TcpStream>,
        backend: &Arc<BackendNode>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let backend_stream = match timeout(
            backend.config.timeout,
            TcpStream::connect(backend.config.addr)
        ).await {
            Ok(Ok(stream)) => {
                self.configure_tcp_stream(&stream)?;
                stream
            }
            Ok(Err(e)) => {
                self.metrics.record_backend_connection_error();
                return Err(e).context("Failed to connect to backend");
            }
            Err(_) => {
                self.metrics.record_backend_connection_timeout();
                anyhow::bail!("Backend connection timed out");
            }
        };

        let (tls_read, tls_write) = tokio::io::split(tls_stream);
        let (backend_read, backend_write) = tokio::io::split(backend_stream);

        let client_to_backend = self.copy_stream(
            tls_read,
            backend_write,
            format!("{}->backend", client_addr),
            backend.clone(),
            true,
        );

        let backend_to_client = self.copy_stream(
            backend_read,
            tls_write,
            format!("backend->{}", client_addr),
            backend.clone(),
            false,
        );

        let result = tokio::select! {
            result = client_to_backend => result,
            result = backend_to_client => result,
        };

        match result {
            Ok((bytes_copied, direction)) => {
                info!("Stream {} copied {} bytes", direction, bytes_copied);
                self.metrics.record_bytes_transferred(bytes_copied);
            }
            Err(e) => {
                error!("Stream copy error: {}", e);
                self.metrics.record_proxy_error();
            }
        }

        Ok(())
    }

    async fn copy_stream<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        direction: String,
        backend: Arc<BackendNode>,
        is_client_to_backend: bool,
    ) -> Result<(u64, String)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buffer = vec![0u8; 8192];
        let mut total_bytes = 0u64;
        let mut last_activity = Instant::now();

        loop {
            let bytes_read = timeout(
                self.config.limits.idle_timeout,
                reader.read(&mut buffer)
            ).await
            .context("Read timeout")?
            .context("Read error")?;

            if bytes_read == 0 {
                break;
            }

            timeout(
                Duration::from_secs(30),
                writer.write_all(&buffer[..bytes_read])
            ).await
            .context("Write timeout")?
            .context("Write error")?;

            timeout(
                Duration::from_secs(10),
                writer.flush()
            ).await
            .context("Flush timeout")?
            .context("Flush error")?;

            total_bytes += bytes_read as u64;
            last_activity = Instant::now();

            if is_client_to_backend {
                backend.add_bytes_received(bytes_read as u64);
            } else {
                backend.add_bytes_sent(bytes_read as u64);
            }

            if total_bytes > self.config.limits.max_request_size as u64 {
                anyhow::bail!("Request size limit exceeded");
            }
        }

        Ok((total_bytes, direction))
    }

    fn configure_tcp_stream(&self, stream: &TcpStream) -> Result<()> {
        if self.config.tcp.nodelay {
            stream.set_nodelay(true)?;
        }

        if let Some(keepalive_duration) = self.config.tcp.keepalive {
            let socket = socket2::Socket::from(stream);
            socket.set_keepalive(true)?;
            
            #[cfg(target_os = "linux")]
            {
                socket.set_keepalive_time(keepalive_duration)?;
            }
        }

        Ok(())
    }

    pub fn get_stats(&self) -> ProxyStats {
        ProxyStats {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections_accepted: self.metrics.get_total_connections(),
            total_bytes_transferred: self.metrics.get_total_bytes_transferred(),
            uptime: self.metrics.get_uptime(),
        }
    }
}

impl Clone for ProxyServer {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            tls_manager: Arc::clone(&self.tls_manager),
            load_balancer: Arc::clone(&self.load_balancer),
            metrics: Arc::clone(&self.metrics),
            active_connections: Arc::clone(&self.active_connections),
            connection_semaphore: Arc::clone(&self.connection_semaphore),
            handshake_semaphore: Arc::clone(&self.handshake_semaphore),
            rate_limiter: self.rate_limiter.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyStats {
    pub active_connections: usize,
    pub total_connections_accepted: u64,
    pub total_bytes_transferred: u64,
    pub uptime: Duration,
}

pub struct RateLimiter {
    requests_per_second: u32,
    window_duration: Duration,
    client_buckets: Arc<TokioRwLock<dashmap::DashMap<std::net::IpAddr, TokenBucket>>>,
}

impl RateLimiter {
    pub fn new(requests_per_second: u32, window_duration: Duration) -> Self {
        let client_buckets = Arc::new(TokioRwLock::new(dashmap::DashMap::new()));
        
        let buckets_cleanup = Arc::clone(&client_buckets);
        tokio::spawn(async move {
            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                cleanup_interval.tick().await;
                let buckets = buckets_cleanup.read().await;
                buckets.retain(|_ip, bucket| {
                    bucket.last_refill.elapsed() < Duration::from_secs(300)
                });
            }
        });

        Self {
            requests_per_second,
            window_duration,
            client_buckets,
        }
    }

    pub async fn allow_request(&self, client_ip: std::net::IpAddr) -> bool {
        let buckets = self.client_buckets.read().await;
        let mut bucket = buckets.entry(client_ip).or_insert_with(|| {
            TokenBucket::new(self.requests_per_second, self.window_duration)
        });
        
        bucket.consume()
    }
}

struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_rate: u32,
    last_refill: Instant,
    window_duration: Duration,
}

impl TokenBucket {
    fn new(capacity: u32, window_duration: Duration) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate: capacity,
            last_refill: Instant::now(),
            window_duration,
        }
    }

    fn consume(&mut self) -> bool {
        self.refill();
        
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        
        if elapsed >= self.window_duration {
            self.tokens = self.capacity;
            self.last_refill = now;
        } else {
            let tokens_to_add = (elapsed.as_secs_f64() / self.window_duration.as_secs_f64() * self.refill_rate as f64) as u32;
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            if tokens_to_add > 0 {
                self.last_refill = now;
            }
        }
    }
}

pub struct ConnectionTracker {
    connections: Arc<TokioRwLock<dashmap::DashMap<SocketAddr, ConnectionInfo>>>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(TokioRwLock::new(dashmap::DashMap::new())),
        }
    }

    pub async fn track_connection(&self, client_addr: SocketAddr, backend_addr: SocketAddr) {
        let connections = self.connections.read().await;
        connections.insert(client_addr, ConnectionInfo {
            backend_addr,
            start_time: Instant::now(),
            bytes_sent: Arc::new(AtomicUsize::new(0)),
            bytes_received: Arc::new(AtomicUsize::new(0)),
        });
    }

    pub async fn untrack_connection(&self, client_addr: SocketAddr) {
        let connections = self.connections.read().await;
        connections.remove(&client_addr);
    }

    pub async fn get_active_connections(&self) -> Vec<(SocketAddr, ConnectionInfo)> {
        let connections = self.connections.read().await;
        connections.iter().map(|entry| (*entry.key(), entry.value().clone())).collect()
    }

    pub async fn get_connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub backend_addr: SocketAddr,
    pub start_time: Instant,
    pub bytes_sent: Arc<AtomicUsize>,
    pub bytes_received: Arc<AtomicUsize>,
}

impl ConnectionInfo {
    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn total_bytes(&self) -> usize {
        self.bytes_sent.load(Ordering::Relaxed) + self.bytes_received.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, Duration::from_secs(1));
        
        for _ in 0..10 {
            assert!(bucket.consume());
        }
        
        assert!(!bucket.consume());
    }

    #[test]
    fn test_rate_limiter_creation() {
        let rate_limiter = RateLimiter::new(100, Duration::from_secs(60));
        assert_eq!(rate_limiter.requests_per_second, 100);
        assert_eq!(rate_limiter.window_duration, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_connection_tracker() {
        let tracker = ConnectionTracker::new();
        let client_addr = "127.0.0.1:12345".parse().unwrap();
        let backend_addr = "127.0.0.1:8080".parse().unwrap();

        tracker.track_connection(client_addr, backend_addr).await;
        assert_eq!(tracker.get_connection_count().await, 1);

        tracker.untrack_connection(client_addr).await;
        assert_eq!(tracker.get_connection_count().await, 0);
    }

    #[test]
    fn test_proxy_stats() {
        let stats = ProxyStats {
            active_connections: 42,
            total_connections_accepted: 1000,
            total_bytes_transferred: 1024 * 1024,
            uptime: Duration::from_secs(3600),
        };

        assert_eq!(stats.active_connections, 42);
        assert_eq!(stats.total_connections_accepted, 1000);
        assert_eq!(stats.total_bytes_transferred, 1024 * 1024);
        assert_eq!(stats.uptime, Duration::from_secs(3600));
    }
}
