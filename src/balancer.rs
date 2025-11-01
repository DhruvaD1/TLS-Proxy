use crate::config::{Backend, LoadBalancingStrategy};
use anyhow::{Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[async_trait]
pub trait LoadBalancer: Send + Sync {
    async fn select_backend(&self, client_addr: Option<SocketAddr>) -> Option<Arc<BackendNode>>;
    async fn mark_backend_unhealthy(&self, backend: &BackendNode);
    async fn mark_backend_healthy(&self, backend: &BackendNode);
    fn get_backend_stats(&self) -> Vec<BackendStats>;
    async fn update_backends(&self, backends: Vec<Backend>);
}

#[derive(Debug, Clone)]
pub struct BackendNode {
    pub config: Backend,
    pub stats: BackendStats,
    pub last_health_check: Arc<RwLock<Instant>>,
    pub consecutive_failures: AtomicUsize,
    pub is_healthy: Arc<RwLock<bool>>,
    pub active_connections: AtomicUsize,
    pub total_connections: AtomicU64,
    pub total_bytes_sent: AtomicU64,
    pub total_bytes_received: AtomicU64,
    pub avg_response_time: Arc<RwLock<Duration>>,
}

#[derive(Debug, Clone, Default)]
pub struct BackendStats {
    pub addr: SocketAddr,
    pub is_healthy: bool,
    pub active_connections: usize,
    pub total_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub avg_response_time_ms: u64,
    pub consecutive_failures: usize,
    pub last_health_check: Option<Instant>,
    pub weight: u32,
}

impl BackendNode {
    pub fn new(backend: Backend) -> Self {
        Self {
            stats: BackendStats {
                addr: backend.addr,
                weight: backend.weight,
                ..Default::default()
            },
            config: backend,
            last_health_check: Arc::new(RwLock::new(Instant::now())),
            consecutive_failures: AtomicUsize::new(0),
            is_healthy: Arc::new(RwLock::new(true)),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_received: AtomicU64::new(0),
            avg_response_time: Arc::new(RwLock::new(Duration::from_millis(0))),
        }
    }

    pub fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.total_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        self.total_bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn update_response_time(&self, duration: Duration) {
        let mut avg = self.avg_response_time.write();
        *avg = Duration::from_millis((avg.as_millis() + duration.as_millis()) as u64 / 2);
    }

    pub fn is_available(&self) -> bool {
        self.config.enabled && *self.is_healthy.read()
    }

    pub fn get_stats(&self) -> BackendStats {
        BackendStats {
            addr: self.config.addr,
            is_healthy: *self.is_healthy.read(),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            total_bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
            total_bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
            avg_response_time_ms: self.avg_response_time.read().as_millis() as u64,
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            last_health_check: Some(*self.last_health_check.read()),
            weight: self.config.weight,
        }
    }
}

pub struct BalancerManager {
    strategy: LoadBalancingStrategy,
    backends: Arc<RwLock<Vec<Arc<BackendNode>>>>,
    round_robin_index: AtomicUsize,
    health_checker: HealthChecker,
}

impl BalancerManager {
    pub fn new(strategy: LoadBalancingStrategy, backends: Vec<Backend>) -> Self {
        let backend_nodes: Vec<Arc<BackendNode>> = backends
            .into_iter()
            .map(|b| Arc::new(BackendNode::new(b)))
            .collect();
        
        let backends_arc = Arc::new(RwLock::new(backend_nodes.clone()));
        let health_checker = HealthChecker::new(backends_arc.clone());
        
        Self {
            strategy,
            backends: backends_arc,
            round_robin_index: AtomicUsize::new(0),
            health_checker,
        }
    }

    pub async fn start_health_checks(&self, interval: Duration, timeout_duration: Duration) -> Result<()> {
        self.health_checker.start_health_checks(interval, timeout_duration).await
    }

    fn get_available_backends(&self) -> Vec<Arc<BackendNode>> {
        self.backends
            .read()
            .iter()
            .filter(|b| b.is_available())
            .cloned()
            .collect()
    }
}

#[async_trait]
impl LoadBalancer for BalancerManager {
    async fn select_backend(&self, client_addr: Option<SocketAddr>) -> Option<Arc<BackendNode>> {
        let available_backends = self.get_available_backends();
        
        if available_backends.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % available_backends.len();
                available_backends.get(index).cloned()
            }
            LoadBalancingStrategy::LeastConnections => {
                available_backends
                    .iter()
                    .min_by_key(|b| b.active_connections.load(Ordering::Relaxed))
                    .cloned()
            }
            LoadBalancingStrategy::WeightedRoundRobin => {
                let total_weight: u32 = available_backends.iter().map(|b| b.config.weight).sum();
                if total_weight == 0 {
                    return None;
                }
                
                let mut rng = rand::thread_rng();
                let mut random_weight = rng.gen_range(0..total_weight);
                
                for backend in &available_backends {
                    if random_weight < backend.config.weight {
                        return Some(backend.clone());
                    }
                    random_weight -= backend.config.weight;
                }
                
                available_backends.first().cloned()
            }
            LoadBalancingStrategy::IpHash => {
                if let Some(addr) = client_addr {
                    let mut hasher = DefaultHasher::new();
                    addr.ip().hash(&mut hasher);
                    let hash = hasher.finish() as usize;
                    let index = hash % available_backends.len();
                    available_backends.get(index).cloned()
                } else {
                    available_backends.first().cloned()
                }
            }
            LoadBalancingStrategy::Random => {
                let mut rng = rand::thread_rng();
                let index = rng.gen_range(0..available_backends.len());
                available_backends.get(index).cloned()
            }
        }
    }

    async fn mark_backend_unhealthy(&self, backend: &BackendNode) {
        *backend.is_healthy.write() = false;
        backend.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        tracing::warn!("Marked backend {} as unhealthy", backend.config.addr);
    }

    async fn mark_backend_healthy(&self, backend: &BackendNode) {
        *backend.is_healthy.write() = true;
        backend.consecutive_failures.store(0, Ordering::Relaxed);
        tracing::info!("Marked backend {} as healthy", backend.config.addr);
    }

    fn get_backend_stats(&self) -> Vec<BackendStats> {
        self.backends.read().iter().map(|b| b.get_stats()).collect()
    }

    async fn update_backends(&self, backends: Vec<Backend>) {
        let new_backend_nodes: Vec<Arc<BackendNode>> = backends
            .into_iter()
            .map(|b| Arc::new(BackendNode::new(b)))
            .collect();
        
        let mut current_backends = self.backends.write();
        *current_backends = new_backend_nodes;
        
        tracing::info!("Updated backend configuration with {} backends", current_backends.len());
    }
}

pub struct HealthChecker {
    backends: Arc<RwLock<Vec<Arc<BackendNode>>>>,
}

impl HealthChecker {
    pub fn new(backends: Arc<RwLock<Vec<Arc<BackendNode>>>>) -> Self {
        Self { backends }
    }

    pub async fn start_health_checks(&self, interval: Duration, timeout_duration: Duration) -> Result<()> {
        let backends = self.backends.clone();
        
        tokio::spawn(async move {
            let mut check_interval = tokio::time::interval(interval);
            
            loop {
                check_interval.tick().await;
                
                let current_backends = backends.read().clone();
                
                for backend in current_backends {
                    let backend_clone = backend.clone();
                    let timeout_duration = timeout_duration;
                    
                    tokio::spawn(async move {
                        match Self::check_backend_health(&backend_clone, timeout_duration).await {
                            Ok(is_healthy) => {
                                *backend_clone.last_health_check.write() = Instant::now();
                                if is_healthy {
                                    *backend_clone.is_healthy.write() = true;
                                    backend_clone.consecutive_failures.store(0, Ordering::Relaxed);
                                } else {
                                    backend_clone.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                                    if backend_clone.consecutive_failures.load(Ordering::Relaxed) >= 3 {
                                        *backend_clone.is_healthy.write() = false;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Health check failed for {}: {}", backend_clone.config.addr, e);
                                backend_clone.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                                if backend_clone.consecutive_failures.load(Ordering::Relaxed) >= 3 {
                                    *backend_clone.is_healthy.write() = false;
                                }
                            }
                        }
                    });
                }
            }
        });
        
        Ok(())
    }

    async fn check_backend_health(backend: &BackendNode, timeout_duration: Duration) -> Result<bool> {
        let start_time = Instant::now();
        
        let result = timeout(timeout_duration, TcpStream::connect(backend.config.addr)).await;
        
        let elapsed = start_time.elapsed();
        backend.update_response_time(elapsed);
        
        match result {
            Ok(Ok(_stream)) => {
                tracing::debug!("Health check passed for {} in {}ms", backend.config.addr, elapsed.as_millis());
                Ok(true)
            }
            Ok(Err(e)) => {
                tracing::debug!("Health check failed for {}: {}", backend.config.addr, e);
                Ok(false)
            }
            Err(_) => {
                tracing::debug!("Health check timed out for {}", backend.config.addr);
                Ok(false)
            }
        }
    }
}

pub struct ConnectionPool {
    pools: DashMap<SocketAddr, Arc<BackendPool>>,
    max_idle_connections: usize,
    idle_timeout: Duration,
}

impl ConnectionPool {
    pub fn new(max_idle_connections: usize, idle_timeout: Duration) -> Self {
        Self {
            pools: DashMap::new(),
            max_idle_connections,
            idle_timeout,
        }
    }

    pub async fn get_connection(&self, backend_addr: SocketAddr) -> Result<TcpStream> {
        if let Some(pool) = self.pools.get(&backend_addr) {
            if let Some(conn) = pool.get_connection().await {
                return Ok(conn);
            }
        }
        
        let stream = TcpStream::connect(backend_addr).await
            .with_context(|| format!("Failed to connect to backend {}", backend_addr))?;
        
        Ok(stream)
    }

    pub async fn return_connection(&self, backend_addr: SocketAddr, stream: TcpStream) {
        let pool = self.pools.entry(backend_addr).or_insert_with(|| {
            Arc::new(BackendPool::new(self.max_idle_connections, self.idle_timeout))
        });
        
        pool.return_connection(stream).await;
    }

    pub async fn cleanup_idle_connections(&self) {
        for pool in self.pools.iter() {
            pool.value().cleanup_idle().await;
        }
    }
}

struct BackendPool {
    idle_connections: Arc<RwLock<Vec<(TcpStream, Instant)>>>,
    max_idle: usize,
    idle_timeout: Duration,
}

impl BackendPool {
    fn new(max_idle: usize, idle_timeout: Duration) -> Self {
        Self {
            idle_connections: Arc::new(RwLock::new(Vec::new())),
            max_idle,
            idle_timeout,
        }
    }

    async fn get_connection(&self) -> Option<TcpStream> {
        let mut connections = self.idle_connections.write();
        
        while let Some((stream, timestamp)) = connections.pop() {
            if timestamp.elapsed() < self.idle_timeout {
                return Some(stream);
            }
        }
        
        None
    }

    async fn return_connection(&self, stream: TcpStream) {
        let mut connections = self.idle_connections.write();
        
        if connections.len() < self.max_idle {
            connections.push((stream, Instant::now()));
        }
    }

    async fn cleanup_idle(&self) {
        let mut connections = self.idle_connections.write();
        connections.retain(|(_, timestamp)| timestamp.elapsed() < self.idle_timeout);
    }
}

pub struct CircuitBreaker {
    failure_threshold: usize,
    recovery_timeout: Duration,
    state: Arc<RwLock<CircuitBreakerState>>,
}

#[derive(Debug, Clone)]
enum CircuitBreakerState {
    Closed,
    Open { opened_at: Instant },
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: usize, recovery_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
        }
    }

    pub async fn call<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        {
            let state = self.state.read();
            match &*state {
                CircuitBreakerState::Open { opened_at } => {
                    if opened_at.elapsed() > self.recovery_timeout {
                        drop(state);
                        *self.state.write() = CircuitBreakerState::HalfOpen;
                    } else {
                        return Err(anyhow::anyhow!("Circuit breaker is open").into());
                    }
                }
                CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen => {}
            }
        }

        let result = f();
        
        match result {
            Ok(value) => {
                *self.state.write() = CircuitBreakerState::Closed;
                Ok(value)
            }
            Err(e) => {
                let mut state = self.state.write();
                match &*state {
                    CircuitBreakerState::HalfOpen => {
                        *state = CircuitBreakerState::Open {
                            opened_at: Instant::now(),
                        };
                    }
                    _ => {}
                }
                Err(e)
            }
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(*self.state.read(), CircuitBreakerState::Open { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_backend_node_creation() {
        let backend = Backend {
            addr: "127.0.0.1:8080".parse().unwrap(),
            weight: 100,
            enabled: true,
            timeout: Duration::from_secs(30),
            retry_attempts: 3,
            max_connections: Some(1000),
            health_check_path: Some("/health".to_string()),
        };

        let node = BackendNode::new(backend);
        assert_eq!(node.config.addr.to_string(), "127.0.0.1:8080");
        assert_eq!(node.config.weight, 100);
        assert!(node.is_available());
    }

    #[tokio::test]
    async fn test_round_robin_balancer() {
        let backends = vec![
            Backend {
                addr: "127.0.0.1:8080".parse().unwrap(),
                weight: 1,
                enabled: true,
                timeout: Duration::from_secs(30),
                retry_attempts: 3,
                max_connections: Some(1000),
                health_check_path: Some("/health".to_string()),
            },
            Backend {
                addr: "127.0.0.1:8081".parse().unwrap(),
                weight: 1,
                enabled: true,
                timeout: Duration::from_secs(30),
                retry_attempts: 3,
                max_connections: Some(1000),
                health_check_path: Some("/health".to_string()),
            },
        ];

        let balancer = BalancerManager::new(LoadBalancingStrategy::RoundRobin, backends);
        
        let backend1 = balancer.select_backend(None).await.unwrap();
        let backend2 = balancer.select_backend(None).await.unwrap();
        let backend3 = balancer.select_backend(None).await.unwrap();
        
        assert_ne!(backend1.config.addr, backend2.config.addr);
        assert_eq!(backend1.config.addr, backend3.config.addr);
    }

    #[tokio::test]
    async fn test_least_connections_balancer() {
        let backends = vec![
            Backend {
                addr: "127.0.0.1:8080".parse().unwrap(),
                weight: 1,
                enabled: true,
                timeout: Duration::from_secs(30),
                retry_attempts: 3,
                max_connections: Some(1000),
                health_check_path: Some("/health".to_string()),
            },
            Backend {
                addr: "127.0.0.1:8081".parse().unwrap(),
                weight: 1,
                enabled: true,
                timeout: Duration::from_secs(30),
                retry_attempts: 3,
                max_connections: Some(1000),
                health_check_path: Some("/health".to_string()),
            },
        ];

        let balancer = BalancerManager::new(LoadBalancingStrategy::LeastConnections, backends);
        
        let backend1 = balancer.select_backend(None).await.unwrap();
        backend1.increment_connections();
        
        let backend2 = balancer.select_backend(None).await.unwrap();
        
        assert_ne!(backend1.config.addr, backend2.config.addr);
    }

    #[test]
    fn test_circuit_breaker() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        
        let result = cb.call(|| -> Result<(), anyhow::Error> { Ok(()) });
        assert!(result.is_ok());
        
        assert!(!cb.is_open());
    }

    #[test]
    fn test_backend_stats() {
        let backend = Backend {
            addr: "127.0.0.1:8080".parse().unwrap(),
            weight: 100,
            enabled: true,
            timeout: Duration::from_secs(30),
            retry_attempts: 3,
            max_connections: Some(1000),
            health_check_path: Some("/health".to_string()),
        };

        let node = BackendNode::new(backend);
        node.increment_connections();
        node.add_bytes_sent(1024);
        node.add_bytes_received(2048);

        let stats = node.get_stats();
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.total_bytes_sent, 1024);
        assert_eq!(stats.total_bytes_received, 2048);
    }
}
