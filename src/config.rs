use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub backends: Vec<SocketAddr>,
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: Option<String>,
    pub strategy: String,
    pub metrics_addr: SocketAddr,
    pub rate_limit: RateLimitConfig,
    pub health_check: HealthCheckConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub websocket: WebSocketConfig,
    pub session: SessionConfig,
    pub connection_pool: ConnectionPoolConfig,
    pub certificate: CertificateConfig,
    pub admin: AdminConfig,
    pub performance: PerformanceConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: Option<u32>,
    pub burst_size: Option<u32>,
    pub global_requests_per_second: Option<u32>,
    pub cleanup_interval_seconds: Option<u64>,
    pub whitelist_ips: Option<Vec<String>>,
    pub blacklist_ips: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub interval_seconds: Option<u64>,
    pub timeout_seconds: Option<u64>,
    pub healthy_threshold: Option<u32>,
    pub unhealthy_threshold: Option<u32>,
    pub path: Option<String>,
    pub expected_status: Option<u16>,
    pub enabled: Option<bool>,
    pub user_agent: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: Option<u32>,
    pub recovery_timeout_seconds: Option<u64>,
    pub half_open_max_calls: Option<u32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    pub max_connections: Option<usize>,
    pub connection_timeout_seconds: Option<u64>,
    pub ping_interval_seconds: Option<u64>,
    pub pong_timeout_seconds: Option<u64>,
    pub max_message_size: Option<usize>,
    pub max_frame_size: Option<usize>,
    pub enabled: Option<bool>,
    pub compression: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub timeout_seconds: Option<u64>,
    pub sticky_sessions: Option<bool>,
    pub session_header: Option<String>,
    pub cookie_name: Option<String>,
    pub secure_cookies: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    pub max_connections_per_backend: Option<usize>,
    pub min_idle_connections: Option<usize>,
    pub max_idle_time_seconds: Option<u64>,
    pub connection_timeout_seconds: Option<u64>,
    pub keep_alive_interval_seconds: Option<u64>,
    pub health_check_interval_seconds: Option<u64>,
    pub max_connection_lifetime_seconds: Option<u64>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub auto_reload: Option<bool>,
    pub check_interval_seconds: Option<u64>,
    pub expiry_warning_days: Option<u64>,
    pub domains: Option<Vec<String>>,
    pub ocsp_stapling: Option<bool>,
    pub must_staple: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub bind_address: Option<SocketAddr>,
    pub api_key: Option<String>,
    pub cors_origins: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub basic_auth: Option<BasicAuthConfig>,
    pub tls_enabled: Option<bool>,
    pub read_timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password_hash: String,
    pub realm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub worker_threads: Option<usize>,
    pub max_blocking_threads: Option<usize>,
    pub tcp_nodelay: Option<bool>,
    pub tcp_keepalive_seconds: Option<u64>,
    pub socket_reuse_port: Option<bool>,
    pub max_concurrent_connections: Option<usize>,
    pub connection_timeout_seconds: Option<u64>,
    pub idle_timeout_seconds: Option<u64>,
    pub graceful_shutdown_timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub tls_min_version: Option<String>,
    pub tls_max_version: Option<String>,
    pub cipher_suites: Option<Vec<String>>,
    pub require_sni: Option<bool>,
    pub client_cert_auth: Option<ClientCertAuthConfig>,
    pub hsts_max_age_seconds: Option<u64>,
    pub deny_invalid_hosts: Option<bool>,
    pub proxy_protocol: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCertAuthConfig {
    pub enabled: bool,
    pub ca_cert_path: String,
    pub verify_mode: String,
    pub crl_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: Option<String>,
    pub format: Option<String>,
    pub access_log: Option<AccessLogConfig>,
    pub structured_logging: Option<bool>,
    pub log_requests: Option<bool>,
    pub log_responses: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogConfig {
    pub enabled: bool,
    pub path: String,
    pub rotation: Option<String>,
    pub max_files: Option<u32>,
    pub max_size_mb: Option<u64>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            backends: vec!["127.0.0.1:8080".parse().unwrap()],
            cert_path: "./certs/server.crt".to_string(),
            key_path: "./certs/server.key".to_string(),
            ca_path: None,
            strategy: "round_robin".to_string(),
            metrics_addr: "0.0.0.0:9090".parse().unwrap(),
            rate_limit: RateLimitConfig::default(),
            health_check: HealthCheckConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            websocket: WebSocketConfig::default(),
            session: SessionConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
            certificate: CertificateConfig::default(),
            admin: AdminConfig::default(),
            performance: PerformanceConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: Some(300),
            burst_size: Some(50),
            global_requests_per_second: Some(1000),
            cleanup_interval_seconds: Some(60),
            whitelist_ips: None,
            blacklist_ips: None,
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval_seconds: Some(10),
            timeout_seconds: Some(5),
            healthy_threshold: Some(2),
            unhealthy_threshold: Some(3),
            path: Some("/health".to_string()),
            expected_status: Some(200),
            enabled: Some(true),
            user_agent: Some("TLS-Proxy-Health-Check/1.0".to_string()),
            headers: None,
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: Some(5),
            recovery_timeout_seconds: Some(60),
            half_open_max_calls: Some(3),
            enabled: Some(true),
        }
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_connections: Some(1000),
            connection_timeout_seconds: Some(30),
            ping_interval_seconds: Some(30),
            pong_timeout_seconds: Some(10),
            max_message_size: Some(1024 * 1024),
            max_frame_size: Some(16 * 1024),
            enabled: Some(true),
            compression: Some(true),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: Some(3600),
            sticky_sessions: Some(true),
            session_header: Some("X-Session-ID".to_string()),
            cookie_name: Some("SESSIONID".to_string()),
            secure_cookies: Some(true),
        }
    }
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_backend: Some(100),
            min_idle_connections: Some(5),
            max_idle_time_seconds: Some(300),
            connection_timeout_seconds: Some(30),
            keep_alive_interval_seconds: Some(60),
            health_check_interval_seconds: Some(30),
            max_connection_lifetime_seconds: Some(1800),
            enabled: Some(true),
        }
    }
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            auto_reload: Some(true),
            check_interval_seconds: Some(3600),
            expiry_warning_days: Some(30),
            domains: Some(vec!["localhost".to_string()]),
            ocsp_stapling: Some(false),
            must_staple: Some(false),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bind_address: Some("127.0.0.1:8443".parse().unwrap()),
            api_key: None,
            cors_origins: Some(vec!["*".to_string()]),
            enabled: Some(true),
            basic_auth: None,
            tls_enabled: Some(false),
            read_timeout_seconds: Some(30),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: None,
            max_blocking_threads: None,
            tcp_nodelay: Some(true),
            tcp_keepalive_seconds: Some(600),
            socket_reuse_port: Some(true),
            max_concurrent_connections: Some(100000),
            connection_timeout_seconds: Some(60),
            idle_timeout_seconds: Some(300),
            graceful_shutdown_timeout_seconds: Some(30),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            tls_min_version: Some("1.2".to_string()),
            tls_max_version: Some("1.3".to_string()),
            cipher_suites: None,
            require_sni: Some(false),
            client_cert_auth: None,
            hsts_max_age_seconds: Some(31536000),
            deny_invalid_hosts: Some(false),
            proxy_protocol: Some(false),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: Some("info".to_string()),
            format: Some("json".to_string()),
            access_log: None,
            structured_logging: Some(true),
            log_requests: Some(true),
            log_responses: Some(false),
        }
    }
}

impl ProxyConfig {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .await
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        
        let config: Self = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse YAML config")?;
        
        config.validate().await?;
        Ok(config)
    }
    
    pub async fn validate(&self) -> Result<()> {
        if self.backends.is_empty() {
            anyhow::bail!("At least one backend must be configured");
        }
        
        if !Path::new(&self.cert_path).exists() {
            anyhow::bail!("Certificate file does not exist: {}", self.cert_path);
        }
        
        if !Path::new(&self.key_path).exists() {
            anyhow::bail!("Private key file does not exist: {}", self.key_path);
        }
        
        if let Some(ca_path) = &self.ca_path {
            if !Path::new(ca_path).exists() {
                anyhow::bail!("CA certificate file does not exist: {}", ca_path);
            }
        }
        
        if self.performance.max_concurrent_connections.unwrap_or(1) == 0 {
            anyhow::bail!("max_concurrent_connections must be greater than 0");
        }
        
        match self.strategy.as_str() {
            "round_robin" | "least_connections" | "ip_hash" | "weighted_round_robin" | "random" => {}
            _ => anyhow::bail!("Invalid load balancing strategy: {}", self.strategy),
        }
        
        Ok(())
    }
    
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).context("Failed to serialize config to YAML")
    }
    
    pub async fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let yaml = self.to_yaml()?;
        fs::write(&path, yaml)
            .await
            .with_context(|| format!("Failed to write config to file: {:?}", path.as_ref()))?;
        Ok(())
    }
    
    pub fn get_worker_threads(&self) -> usize {
        self.performance.worker_threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4)
        })
    }
    
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        match feature {
            "health_check" => self.health_check.enabled.unwrap_or(true),
            "circuit_breaker" => self.circuit_breaker.enabled.unwrap_or(true),
            "websocket" => self.websocket.enabled.unwrap_or(true),
            "connection_pool" => self.connection_pool.enabled.unwrap_or(true),
            "admin" => self.admin.enabled.unwrap_or(true),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_default_config() {
        let config = ProxyConfig::default();
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.strategy, "round_robin");
        assert!(config.is_feature_enabled("health_check"));
    }
    
    #[tokio::test]
    async fn test_config_serialization() {
        let config = ProxyConfig::default();
        let yaml = config.to_yaml().unwrap();
        assert!(!yaml.is_empty());
        
        let deserialized: ProxyConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config.listen_addr, deserialized.listen_addr);
        assert_eq!(config.backends, deserialized.backends);
    }
    
    #[test]
    fn test_worker_threads() {
        let mut config = ProxyConfig::default();
        assert!(config.get_worker_threads() > 0);
        
        config.performance.worker_threads = Some(8);
        assert_eq!(config.get_worker_threads(), 8);
    }
}
