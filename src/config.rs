use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub backends: Vec<Backend>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub strategy: LoadBalancingStrategy,
    pub metrics_addr: SocketAddr,
    pub tcp: TcpConfig,
    pub tls: TlsConfig,
    pub health_check: HealthCheckConfig,
    pub limits: LimitsConfig,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub addr: SocketAddr,
    pub weight: u32,
    pub max_connections: Option<usize>,
    pub health_check_path: Option<String>,
    pub timeout: Duration,
    pub retry_attempts: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    IpHash,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConfig {
    pub nodelay: bool,
    pub keepalive: Option<Duration>,
    pub recv_buffer_size: Option<usize>,
    pub send_buffer_size: Option<usize>,
    pub max_backlog: u32,
    pub reuse_port: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub session_timeout: Duration,
    pub session_cache_size: usize,
    pub require_sni: bool,
    pub prefer_server_cipher_order: bool,
    pub min_protocol_version: TlsVersion,
    pub max_protocol_version: TlsVersion,
    pub cipher_suites: Vec<String>,
    pub enable_ocsp_stapling: bool,
    pub client_auth: ClientAuthMode,
    pub ca_cert_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    None,
    Optional,
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
    pub check_path: String,
    pub expected_status: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_request_size: usize,
    pub rate_limit_requests_per_second: Option<u32>,
    pub rate_limit_window: Duration,
    pub max_concurrent_handshakes: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            backends: vec![Backend::default()],
            cert_path: PathBuf::from("./certs/server.crt"),
            key_path: PathBuf::from("./certs/server.key"),
            strategy: LoadBalancingStrategy::RoundRobin,
            metrics_addr: "0.0.0.0:9090".parse().unwrap(),
            tcp: TcpConfig::default(),
            tls: TlsConfig::default(),
            health_check: HealthCheckConfig::default(),
            limits: LimitsConfig::default(),
            log_level: "info".to_string(),
        }
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:8080".parse().unwrap(),
            weight: 1,
            max_connections: Some(1000),
            health_check_path: Some("/health".to_string()),
            timeout: Duration::from_secs(30),
            retry_attempts: 3,
            enabled: true,
        }
    }
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            nodelay: true,
            keepalive: Some(Duration::from_secs(600)),
            recv_buffer_size: Some(8192),
            send_buffer_size: Some(8192),
            max_backlog: 1024,
            reuse_port: true,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(300),
            session_cache_size: 20480,
            require_sni: false,
            prefer_server_cipher_order: true,
            min_protocol_version: TlsVersion::Tls12,
            max_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            enable_ocsp_stapling: false,
            client_auth: ClientAuthMode::None,
            ca_cert_path: None,
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            unhealthy_threshold: 3,
            healthy_threshold: 2,
            check_path: "/health".to_string(),
            expected_status: 200,
            enabled: true,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 100000,
            connection_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            max_request_size: 1024 * 1024,
            rate_limit_requests_per_second: None,
            rate_limit_window: Duration::from_secs(60),
            max_concurrent_handshakes: 1000,
        }
    }
}

impl ProxyConfig {
    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
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
        
        for (i, backend) in self.backends.iter().enumerate() {
            if backend.weight == 0 {
                anyhow::bail!("Backend {} has zero weight", i);
            }
            if backend.timeout.is_zero() {
                anyhow::bail!("Backend {} has zero timeout", i);
            }
        }
        
        if !self.cert_path.exists() {
            anyhow::bail!("Certificate file does not exist: {:?}", self.cert_path);
        }
        
        if !self.key_path.exists() {
            anyhow::bail!("Private key file does not exist: {:?}", self.key_path);
        }
        
        if let Some(ca_path) = &self.tls.ca_cert_path {
            if !ca_path.exists() {
                anyhow::bail!("CA certificate file does not exist: {:?}", ca_path);
            }
        }
        
        if self.limits.max_connections == 0 {
            anyhow::bail!("max_connections must be greater than 0");
        }
        
        if self.limits.max_concurrent_handshakes == 0 {
            anyhow::bail!("max_concurrent_handshakes must be greater than 0");
        }
        
        if self.tls.session_cache_size == 0 {
            anyhow::bail!("session_cache_size must be greater than 0");
        }
        
        Ok(())
    }
    
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).context("Failed to serialize config to YAML")
    }
    
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let yaml = self.to_yaml()?;
        std::fs::write(&path, yaml)
            .with_context(|| format!("Failed to write config to file: {:?}", path.as_ref()))?;
        Ok(())
    }
    
    pub fn get_enabled_backends(&self) -> Vec<&Backend> {
        self.backends.iter().filter(|b| b.enabled).collect()
    }
    
    pub fn total_weight(&self) -> u32 {
        self.get_enabled_backends().iter().map(|b| b.weight).sum()
    }
}

pub struct ConfigWatcher {
    config_path: PathBuf,
    current_config: arc_swap::ArcSwap<ProxyConfig>,
}

impl ConfigWatcher {
    pub fn new(config_path: PathBuf, initial_config: ProxyConfig) -> Self {
        Self {
            config_path,
            current_config: arc_swap::ArcSwap::new(std::sync::Arc::new(initial_config)),
        }
    }
    
    pub async fn start_watching(&self) -> Result<()> {
        use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
        use tokio::sync::mpsc;
        
        let (tx, mut rx) = mpsc::channel(1);
        let config_path = self.config_path.clone();
        let current_config = self.current_config.clone();
        
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(_event) = res {
                    let _ = tx.try_send(());
                }
            },
            Config::default(),
        )?;
        
        if let Some(parent) = self.config_path.parent() {
            watcher.watch(parent, RecursiveMode::NonRecursive)?;
        }
        
        tokio::spawn(async move {
            while let Some(_) = rx.recv().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                
                match ProxyConfig::load_from_file(&config_path).await {
                    Ok(new_config) => {
                        tracing::info!("Configuration reloaded successfully");
                        current_config.store(std::sync::Arc::new(new_config));
                    }
                    Err(e) => {
                        tracing::error!("Failed to reload configuration: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    pub fn get_config(&self) -> std::sync::Arc<ProxyConfig> {
        self.current_config.load_full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_config_loading() {
        let config_content = r#"
listen_addr: "127.0.0.1:8443"
backends:
  - addr: "127.0.0.1:8080"
    weight: 1
    enabled: true
    timeout: 30s
    retry_attempts: 3
cert_path: "./test.crt"
key_path: "./test.key"
strategy: "round_robin"
metrics_addr: "127.0.0.1:9090"
log_level: "debug"
"#;
        
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();
        std::fs::write("./test.crt", "dummy cert").unwrap();
        std::fs::write("./test.key", "dummy key").unwrap();
        
        let config = ProxyConfig::load_from_file(temp_file.path()).await;
        assert!(config.is_ok());
        
        let config = config.unwrap();
        assert_eq!(config.listen_addr.to_string(), "127.0.0.1:8443");
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.strategy, LoadBalancingStrategy::RoundRobin);
        
        std::fs::remove_file("./test.crt").ok();
        std::fs::remove_file("./test.key").ok();
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = ProxyConfig::default();
        config.backends.clear();
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(config.validate());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("At least one backend"));
    }
    
    #[test]
    fn test_config_serialization() {
        let config = ProxyConfig::default();
        let yaml = config.to_yaml().unwrap();
        assert!(!yaml.is_empty());
        
        let deserialized: ProxyConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config.listen_addr, deserialized.listen_addr);
    }
}
