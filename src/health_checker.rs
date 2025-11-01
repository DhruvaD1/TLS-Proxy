use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub path: String,
    pub expected_status: u16,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            path: "/health".to_string(),
            expected_status: 200,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct BackendHealth {
    pub status: HealthStatus,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
    pub last_check: Instant,
    pub response_time: Duration,
    pub error_message: Option<String>,
}

impl Default for BackendHealth {
    fn default() -> Self {
        Self {
            status: HealthStatus::Unknown,
            consecutive_successes: 0,
            consecutive_failures: 0,
            last_check: Instant::now(),
            response_time: Duration::from_millis(0),
            error_message: None,
        }
    }
}

pub struct HealthChecker {
    config: HealthCheckConfig,
    backends: Vec<SocketAddr>,
    health_status: Arc<RwLock<HashMap<SocketAddr, BackendHealth>>>,
}

impl HealthChecker {
    pub fn new(config: HealthCheckConfig, backends: Vec<SocketAddr>) -> Self {
        let health_status = Arc::new(RwLock::new(
            backends.iter().map(|addr| (*addr, BackendHealth::default())).collect()
        ));
        
        Self {
            config,
            backends,
            health_status,
        }
    }

    pub fn start(&self) {
        let config = self.config.clone();
        let backends = self.backends.clone();
        let health_status = Arc::clone(&self.health_status);

        tokio::spawn(async move {
            let mut interval = interval(config.interval);
            
            loop {
                interval.tick().await;
                
                let mut handles = Vec::new();
                
                for backend in &backends {
                    let backend_addr = *backend;
                    let config = config.clone();
                    let health_status = Arc::clone(&health_status);
                    
                    let handle = tokio::spawn(async move {
                        let start_time = Instant::now();
                        let result = Self::check_backend_health(backend_addr, &config).await;
                        let response_time = start_time.elapsed();
                        
                        let mut status_map = health_status.write().unwrap();
                        let backend_health = status_map.entry(backend_addr).or_default();
                        
                        backend_health.last_check = Instant::now();
                        backend_health.response_time = response_time;
                        
                        match result {
                            Ok(_) => {
                                backend_health.consecutive_successes += 1;
                                backend_health.consecutive_failures = 0;
                                backend_health.error_message = None;
                                
                                if backend_health.consecutive_successes >= config.healthy_threshold {
                                    if backend_health.status != HealthStatus::Healthy {
                                        info!("Backend {} is now healthy", backend_addr);
                                    }
                                    backend_health.status = HealthStatus::Healthy;
                                }
                            }
                            Err(e) => {
                                backend_health.consecutive_failures += 1;
                                backend_health.consecutive_successes = 0;
                                backend_health.error_message = Some(e.to_string());
                                
                                if backend_health.consecutive_failures >= config.unhealthy_threshold {
                                    if backend_health.status != HealthStatus::Unhealthy {
                                        warn!("Backend {} is now unhealthy: {}", backend_addr, e);
                                    }
                                    backend_health.status = HealthStatus::Unhealthy;
                                }
                            }
                        }
                    });
                    
                    handles.push(handle);
                }
                
                for handle in handles {
                    let _ = handle.await;
                }
            }
        });
    }

    async fn check_backend_health(backend: SocketAddr, config: &HealthCheckConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let connect_future = TcpStream::connect(backend);
        let mut stream = timeout(config.timeout, connect_future).await??;

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: TLS-Proxy-Health-Check/1.0\r\n\r\n",
            config.path, backend
        );

        timeout(config.timeout, stream.write_all(request.as_bytes())).await??;

        let mut response = Vec::new();
        timeout(config.timeout, stream.read_to_end(&mut response)).await??;

        let response_str = String::from_utf8_lossy(&response);
        if let Some(status_line) = response_str.lines().next() {
            if let Some(status_code_str) = status_line.split_whitespace().nth(1) {
                if let Ok(status_code) = status_code_str.parse::<u16>() {
                    if status_code == config.expected_status {
                        debug!("Health check passed for backend {}", backend);
                        return Ok(());
                    } else {
                        return Err(format!("Unexpected status code: {} (expected {})", status_code, config.expected_status).into());
                    }
                }
            }
        }

        Err("Invalid HTTP response".into())
    }

    pub fn get_healthy_backends(&self) -> Vec<SocketAddr> {
        let status_map = self.health_status.read().unwrap();
        status_map.iter()
            .filter_map(|(addr, health)| {
                if health.status == HealthStatus::Healthy {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn is_backend_healthy(&self, backend: &SocketAddr) -> bool {
        let status_map = self.health_status.read().unwrap();
        status_map.get(backend)
            .map(|health| health.status == HealthStatus::Healthy)
            .unwrap_or(false)
    }

    pub fn get_backend_health(&self, backend: &SocketAddr) -> Option<BackendHealth> {
        let status_map = self.health_status.read().unwrap();
        status_map.get(backend).cloned()
    }

    pub fn get_all_health_status(&self) -> HashMap<SocketAddr, BackendHealth> {
        self.health_status.read().unwrap().clone()
    }

    pub fn force_check(&self, backend: SocketAddr) {
        let config = self.config.clone();
        let health_status = Arc::clone(&self.health_status);
        
        tokio::spawn(async move {
            let start_time = Instant::now();
            let result = Self::check_backend_health(backend, &config).await;
            let response_time = start_time.elapsed();
            
            let mut status_map = health_status.write().unwrap();
            let backend_health = status_map.entry(backend).or_default();
            
            backend_health.last_check = Instant::now();
            backend_health.response_time = response_time;
            
            match result {
                Ok(_) => {
                    backend_health.consecutive_successes += 1;
                    backend_health.consecutive_failures = 0;
                    backend_health.error_message = None;
                    info!("Forced health check passed for backend {}", backend);
                }
                Err(e) => {
                    backend_health.consecutive_failures += 1;
                    backend_health.consecutive_successes = 0;
                    backend_health.error_message = Some(e.to_string());
                    warn!("Forced health check failed for backend {}: {}", backend, e);
                }
            }
        });
    }
}

pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_timeout: Duration,
    failures: Arc<RwLock<HashMap<SocketAddr, (u32, Instant)>>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            failures: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn record_failure(&self, backend: SocketAddr) {
        let mut failures = self.failures.write().unwrap();
        let (count, _) = failures.entry(backend).or_insert((0, Instant::now()));
        *count += 1;
        failures.insert(backend, (*count, Instant::now()));
    }

    pub fn record_success(&self, backend: SocketAddr) {
        let mut failures = self.failures.write().unwrap();
        failures.remove(&backend);
    }

    pub fn is_open(&self, backend: SocketAddr) -> bool {
        let failures = self.failures.read().unwrap();
        if let Some((count, last_failure)) = failures.get(&backend) {
            if *count >= self.failure_threshold {
                return Instant::now().duration_since(*last_failure) < self.recovery_timeout;
            }
        }
        false
    }

    pub fn should_attempt_recovery(&self, backend: SocketAddr) -> bool {
        let failures = self.failures.read().unwrap();
        if let Some((count, last_failure)) = failures.get(&backend) {
            if *count >= self.failure_threshold {
                return Instant::now().duration_since(*last_failure) >= self.recovery_timeout;
            }
        }
        true
    }
}
