use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::{interval, timeout, sleep};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    pub max_connections_per_backend: usize,
    pub min_idle_connections: usize,
    pub max_idle_time: Duration,
    pub connection_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub health_check_interval: Duration,
    pub max_connection_lifetime: Duration,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_backend: 100,
            min_idle_connections: 5,
            max_idle_time: Duration::from_secs(60),
            connection_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(60),
            health_check_interval: Duration::from_secs(30),
            max_connection_lifetime: Duration::from_secs(300),
        }
    }
}

#[derive(Debug)]
pub struct PooledConnection {
    pub stream: TcpStream,
    pub created_at: Instant,
    pub last_used: Instant,
    pub use_count: u64,
    pub backend_addr: SocketAddr,
}

impl PooledConnection {
    pub fn new(stream: TcpStream, backend_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            stream,
            created_at: now,
            last_used: now,
            use_count: 0,
            backend_addr,
        }
    }

    pub fn update_last_used(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
    }

    pub fn is_expired(&self, max_lifetime: Duration) -> bool {
        self.created_at.elapsed() > max_lifetime
    }

    pub fn is_idle(&self, max_idle_time: Duration) -> bool {
        self.last_used.elapsed() > max_idle_time
    }
}

pub struct BackendPool {
    connections: Arc<Mutex<Vec<PooledConnection>>>,
    active_connections: Arc<AtomicUsize>,
    total_connections: Arc<AtomicU64>,
    semaphore: Arc<Semaphore>,
    backend_addr: SocketAddr,
    config: ConnectionPoolConfig,
}

impl BackendPool {
    pub fn new(backend_addr: SocketAddr, config: ConnectionPoolConfig) -> Self {
        let pool = Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            active_connections: Arc::new(AtomicUsize::new(0)),
            total_connections: Arc::new(AtomicU64::new(0)),
            semaphore: Arc::new(Semaphore::new(config.max_connections_per_backend)),
            backend_addr,
            config,
        };
        pool.start_maintenance_tasks();
        pool
    }

    pub async fn get_connection(&self) -> Result<PooledConnection, Box<dyn std::error::Error + Send + Sync>> {
        let _permit = self.semaphore.acquire().await?;

        {
            let mut connections = self.connections.lock().await;
            if let Some(mut conn) = connections.pop() {
                if !conn.is_expired(self.config.max_connection_lifetime) {
                    conn.update_last_used();
                    self.active_connections.fetch_add(1, Ordering::Relaxed);
                    debug!("Reusing pooled connection to {}", self.backend_addr);
                    return Ok(conn);
                }
            }
        }

        debug!("Creating new connection to {}", self.backend_addr);
        let stream = timeout(
            self.config.connection_timeout,
            TcpStream::connect(self.backend_addr)
        ).await??;

        let mut conn = PooledConnection::new(stream, self.backend_addr);
        conn.update_last_used();
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);

        Ok(conn)
    }

    pub async fn return_connection(&self, mut connection: PooledConnection) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);

        if connection.is_expired(self.config.max_connection_lifetime) {
            debug!("Connection to {} expired, not returning to pool", self.backend_addr);
            return;
        }

        let mut connections = self.connections.lock().await;
        if connections.len() < self.config.max_connections_per_backend {
            connections.push(connection);
            debug!("Returned connection to pool for {}", self.backend_addr);
        } else {
            debug!("Pool full for {}, dropping connection", self.backend_addr);
        }
    }

    pub async fn ensure_min_connections(&self) {
        let connections_len = self.connections.lock().await.len();
        let active = self.active_connections.load(Ordering::Relaxed);
        let total_available = connections_len + active;

        if total_available < self.config.min_idle_connections {
            let needed = self.config.min_idle_connections - total_available;
            for _ in 0..needed {
                match self.create_idle_connection().await {
                    Ok(_) => {
                        debug!("Created idle connection for {}", self.backend_addr);
                    }
                    Err(e) => {
                        warn!("Failed to create idle connection for {}: {}", self.backend_addr, e);
                        break;
                    }
                }
            }
        }
    }

    async fn create_idle_connection(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let stream = timeout(
            self.config.connection_timeout,
            TcpStream::connect(self.backend_addr)
        ).await??;

        let connection = PooledConnection::new(stream, self.backend_addr);
        let mut connections = self.connections.lock().await;
        connections.push(connection);
        self.total_connections.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    fn start_maintenance_tasks(&self) {
        let connections = Arc::clone(&self.connections);
        let config = self.config.clone();
        let backend_addr = self.backend_addr;

        tokio::spawn(async move {
            let mut interval = interval(config.health_check_interval);
            loop {
                interval.tick().await;
                Self::cleanup_expired_connections(&connections, &config, backend_addr).await;
            }
        });

        let connections = Arc::clone(&self.connections);
        let config = self.config.clone();
        let backend_addr = self.backend_addr;

        tokio::spawn(async move {
            let mut interval = interval(config.keep_alive_interval);
            loop {
                interval.tick().await;
                Self::send_keep_alive(&connections, backend_addr).await;
            }
        });
    }

    async fn cleanup_expired_connections(
        connections: &Arc<Mutex<Vec<PooledConnection>>>,
        config: &ConnectionPoolConfig,
        backend_addr: SocketAddr,
    ) {
        let mut connections = connections.lock().await;
        let initial_len = connections.len();
        
        connections.retain(|conn| {
            !conn.is_expired(config.max_connection_lifetime) && !conn.is_idle(config.max_idle_time)
        });

        let removed = initial_len - connections.len();
        if removed > 0 {
            debug!("Cleaned up {} expired connections for {}", removed, backend_addr);
        }
    }

    async fn send_keep_alive(
        connections: &Arc<Mutex<Vec<PooledConnection>>>,
        backend_addr: SocketAddr,
    ) {
        let connections = connections.lock().await;
        debug!("Keep-alive check for {} connections to {}", connections.len(), backend_addr);
    }

    pub async fn get_stats(&self) -> (usize, usize, u64) {
        let idle_connections = self.connections.lock().await.len();
        let active_connections = self.active_connections.load(Ordering::Relaxed);
        let total_connections = self.total_connections.load(Ordering::Relaxed);
        (idle_connections, active_connections, total_connections)
    }
}

pub struct ConnectionPoolManager {
    pools: Arc<RwLock<HashMap<SocketAddr, Arc<BackendPool>>>>,
    config: ConnectionPoolConfig,
}

impl ConnectionPoolManager {
    pub fn new(config: ConnectionPoolConfig) -> Self {
        let manager = Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            config,
        };
        manager.start_maintenance_tasks();
        manager
    }

    pub async fn get_connection(&self, backend: SocketAddr) -> Result<PooledConnection, Box<dyn std::error::Error + Send + Sync>> {
        let pool = {
            let pools = self.pools.read().await;
            if let Some(pool) = pools.get(&backend) {
                Arc::clone(pool)
            } else {
                drop(pools);
                let mut pools = self.pools.write().await;
                let pool = Arc::new(BackendPool::new(backend, self.config.clone()));
                pools.insert(backend, Arc::clone(&pool));
                pool
            }
        };

        pool.get_connection().await
    }

    pub async fn return_connection(&self, connection: PooledConnection) {
        let backend = connection.backend_addr;
        if let Some(pool) = self.pools.read().await.get(&backend) {
            pool.return_connection(connection).await;
        }
    }

    pub async fn remove_backend(&self, backend: SocketAddr) {
        let mut pools = self.pools.write().await;
        if pools.remove(&backend).is_some() {
            info!("Removed connection pool for backend {}", backend);
        }
    }

    pub async fn add_backend(&self, backend: SocketAddr) {
        let mut pools = self.pools.write().await;
        if !pools.contains_key(&backend) {
            let pool = Arc::new(BackendPool::new(backend, self.config.clone()));
            pools.insert(backend, pool);
            info!("Added connection pool for backend {}", backend);
        }
    }

    pub async fn get_all_stats(&self) -> HashMap<SocketAddr, (usize, usize, u64)> {
        let pools = self.pools.read().await;
        let mut stats = HashMap::new();
        
        for (backend, pool) in pools.iter() {
            stats.insert(*backend, pool.get_stats().await);
        }
        
        stats
    }

    pub async fn get_pool_count(&self) -> usize {
        self.pools.read().await.len()
    }

    fn start_maintenance_tasks(&self) {
        let pools = Arc::clone(&self.pools);
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                
                let pools = pools.read().await;
                for (backend, pool) in pools.iter() {
                    if let Err(e) = pool.ensure_min_connections().await {
                        warn!("Failed to ensure min connections for {}: {}", backend, e);
                    }
                }
            }
        });
    }

    pub async fn warm_up_pools(&self, backends: &[SocketAddr]) {
        for &backend in backends {
            if let Ok(pool) = self.get_connection(backend).await {
                self.return_connection(pool).await;
            }
        }
        info!("Warmed up connection pools for {} backends", backends.len());
    }

    pub async fn drain_backend(&self, backend: SocketAddr) {
        if let Some(pool) = self.pools.read().await.get(&backend) {
            let mut connections = pool.connections.lock().await;
            let drained = connections.len();
            connections.clear();
            info!("Drained {} connections from backend {}", drained, backend);
        }
    }

    pub async fn health_check_pools(&self) -> Vec<SocketAddr> {
        let pools = self.pools.read().await;
        let mut healthy_backends = Vec::new();

        for (backend, pool) in pools.iter() {
            match timeout(Duration::from_secs(5), TcpStream::connect(*backend)).await {
                Ok(Ok(_)) => {
                    healthy_backends.push(*backend);
                }
                Ok(Err(e)) => {
                    warn!("Backend {} health check failed: {}", backend, e);
                }
                Err(_) => {
                    warn!("Backend {} health check timed out", backend);
                }
            }
        }

        healthy_backends
    }
}

pub struct ConnectionMetrics {
    pub total_connections: u64,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub connection_errors: u64,
    pub average_connection_time: Duration,
    pub peak_connections: usize,
}

impl ConnectionMetrics {
    pub fn new() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            idle_connections: 0,
            connection_errors: 0,
            average_connection_time: Duration::from_millis(0),
            peak_connections: 0,
        }
    }

    pub fn update_peak(&mut self, current: usize) {
        if current > self.peak_connections {
            self.peak_connections = current;
        }
    }
}
