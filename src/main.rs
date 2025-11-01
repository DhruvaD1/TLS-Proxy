use std::sync::Arc;
use std::time::Duration;
use clap::{Arg, Command};
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod config;
mod tls;
mod proxy;
mod balancer;
mod metrics;
mod rate_limiter;
mod health_checker;
mod websocket;
mod admin_api;
mod connection_pool;
mod cert_rotation;

use config::ProxyConfig;
use metrics::ProxyMetrics;
use rate_limiter::{RateLimiter, RateLimitConfig, GlobalRateLimiter};
use health_checker::{HealthChecker, HealthCheckConfig, CircuitBreaker};
use websocket::{WebSocketProxy, WebSocketConfig, StickySession};
use admin_api::{AdminServer, AdminConfig};
use connection_pool::{ConnectionPoolManager, ConnectionPoolConfig};
use cert_rotation::{CertificateManager, CertificateConfig};
use balancer::{LoadBalancer, LoadBalancingStrategy};
use proxy::TlsTerminationProxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let matches = Command::new("TLS Termination Proxy")
        .version("1.0.0")
        .author("Advanced Proxy Team")
        .about("High-performance TLS termination proxy with advanced features")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("config.yaml")
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("info")
        )
        .arg(
            Arg::new("validate-config")
                .long("validate-config")
                .help("Validate configuration and exit")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("generate-certs")
                .long("generate-certs")
                .help("Generate self-signed certificates for testing")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    let log_level = matches.get_one::<String>("log-level").unwrap();
    setup_logging(log_level)?;

    let config_path = matches.get_one::<String>("config").unwrap();
    info!("Loading configuration from: {}", config_path);

    if matches.get_flag("generate-certs") {
        generate_self_signed_certs().await?;
        info!("Self-signed certificates generated successfully");
        return Ok(());
    }

    let config = ProxyConfig::from_file(config_path).await?;
    
    if matches.get_flag("validate-config") {
        info!("Configuration validation successful");
        return Ok(());
    }

    info!("Starting TLS Termination Proxy with advanced features");
    info!("Listen address: {}", config.listen_addr);
    info!("Backends: {:?}", config.backends);
    info!("Load balancing strategy: {:?}", config.strategy);

    let server = AdvancedTlsProxy::new(config).await?;
    server.run().await
}

fn setup_logging(level: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .with(env_filter)
        .init();

    Ok(())
}

async fn generate_self_signed_certs() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;
    
    tokio::fs::create_dir_all("./certs").await?;
    
    let output = Command::new("openssl")
        .args(&[
            "req", "-x509", "-newkey", "rsa:4096", "-keyout", "./certs/server.key",
            "-out", "./certs/server.crt", "-days", "365", "-nodes",
            "-subj", "/C=US/ST=State/L=City/O=Organization/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"
        ])
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                info!("Generated self-signed certificate and key");
            } else {
                error!("Failed to generate certificates: {}", 
                    String::from_utf8_lossy(&result.stderr));
            }
        }
        Err(e) => {
            error!("OpenSSL not found or failed to execute: {}", e);
            info!("You can manually generate certificates with:");
            info!("openssl req -x509 -newkey rsa:4096 -keyout ./certs/server.key -out ./certs/server.crt -days 365 -nodes -subj '/C=US/ST=State/L=City/O=Organization/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'");
        }
    }
    
    Ok(())
}

pub struct AdvancedTlsProxy {
    config: ProxyConfig,
    metrics: Arc<ProxyMetrics>,
    rate_limiter: Arc<RateLimiter>,
    global_rate_limiter: Arc<GlobalRateLimiter>,
    health_checker: Arc<HealthChecker>,
    circuit_breaker: Arc<CircuitBreaker>,
    websocket_proxy: Arc<WebSocketProxy>,
    sticky_sessions: Arc<StickySession>,
    admin_server: Arc<AdminServer>,
    connection_pool: Arc<ConnectionPoolManager>,
    cert_manager: Arc<CertificateManager>,
    load_balancer: Arc<tokio::sync::RwLock<LoadBalancer>>,
    proxy: Arc<TlsTerminationProxy>,
}

impl AdvancedTlsProxy {
    pub async fn new(config: ProxyConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let metrics = Arc::new(ProxyMetrics::new());
        
        let rate_limit_config = RateLimitConfig {
            requests_per_minute: config.rate_limit.requests_per_minute.unwrap_or(300),
            burst_size: config.rate_limit.burst_size.unwrap_or(50),
            cleanup_interval: Duration::from_secs(60),
        };
        let rate_limiter = Arc::new(RateLimiter::new(rate_limit_config));
        
        let global_rate_limiter = Arc::new(GlobalRateLimiter::new(
            config.rate_limit.global_requests_per_second.unwrap_or(1000)
        ));
        
        let health_check_config = HealthCheckConfig {
            interval: Duration::from_secs(config.health_check.interval_seconds.unwrap_or(10)),
            timeout: Duration::from_secs(config.health_check.timeout_seconds.unwrap_or(5)),
            healthy_threshold: config.health_check.healthy_threshold.unwrap_or(2),
            unhealthy_threshold: config.health_check.unhealthy_threshold.unwrap_or(3),
            path: config.health_check.path.clone().unwrap_or("/health".to_string()),
            expected_status: config.health_check.expected_status.unwrap_or(200),
        };
        let health_checker = Arc::new(HealthChecker::new(health_check_config, config.backends.clone()));
        
        let circuit_breaker = Arc::new(CircuitBreaker::new(
            config.circuit_breaker.failure_threshold.unwrap_or(5),
            Duration::from_secs(config.circuit_breaker.recovery_timeout_seconds.unwrap_or(60))
        ));
        
        let websocket_config = WebSocketConfig {
            max_connections: config.websocket.max_connections.unwrap_or(1000),
            connection_timeout: Duration::from_secs(config.websocket.connection_timeout_seconds.unwrap_or(30)),
            ping_interval: Duration::from_secs(config.websocket.ping_interval_seconds.unwrap_or(30)),
            pong_timeout: Duration::from_secs(config.websocket.pong_timeout_seconds.unwrap_or(10)),
            max_message_size: config.websocket.max_message_size.unwrap_or(1024 * 1024),
            max_frame_size: config.websocket.max_frame_size.unwrap_or(16 * 1024),
        };
        let websocket_proxy = Arc::new(WebSocketProxy::new(websocket_config));
        
        let sticky_sessions = Arc::new(StickySession::new(
            Duration::from_secs(config.session.timeout_seconds.unwrap_or(3600))
        ));
        
        let connection_pool_config = ConnectionPoolConfig {
            max_connections_per_backend: config.connection_pool.max_connections_per_backend.unwrap_or(100),
            min_idle_connections: config.connection_pool.min_idle_connections.unwrap_or(5),
            max_idle_time: Duration::from_secs(config.connection_pool.max_idle_time_seconds.unwrap_or(300)),
            connection_timeout: Duration::from_secs(config.connection_pool.connection_timeout_seconds.unwrap_or(30)),
            keep_alive_interval: Duration::from_secs(config.connection_pool.keep_alive_interval_seconds.unwrap_or(60)),
            health_check_interval: Duration::from_secs(config.connection_pool.health_check_interval_seconds.unwrap_or(30)),
            max_connection_lifetime: Duration::from_secs(config.connection_pool.max_connection_lifetime_seconds.unwrap_or(1800)),
        };
        let connection_pool = Arc::new(ConnectionPoolManager::new(connection_pool_config));
        
        let cert_config = CertificateConfig {
            cert_path: config.cert_path.clone().into(),
            key_path: config.key_path.clone().into(),
            ca_path: config.ca_path.as_ref().map(|p| p.clone().into()),
            auto_reload: config.certificate.auto_reload.unwrap_or(true),
            check_interval: Duration::from_secs(config.certificate.check_interval_seconds.unwrap_or(3600)),
            expiry_warning_days: config.certificate.expiry_warning_days.unwrap_or(30),
            domains: config.certificate.domains.clone().unwrap_or_else(|| vec!["localhost".to_string()]),
        };
        let cert_manager = Arc::new(CertificateManager::new(cert_config));
        
        let load_balancer = Arc::new(tokio::sync::RwLock::new(LoadBalancer::new(
            config.backends.clone(),
            LoadBalancingStrategy::from_str(&config.strategy)?,
        )));
        
        let admin_config = AdminConfig {
            bind_address: config.admin.bind_address.unwrap_or_else(|| "127.0.0.1:8443".parse().unwrap()),
            api_key: config.admin.api_key.clone(),
            cors_origins: config.admin.cors_origins.clone().unwrap_or_else(|| vec!["*".to_string()]),
        };
        
        let admin_server = Arc::new(AdminServer::new(
            admin_config,
            Arc::clone(&health_checker),
            Arc::clone(&rate_limiter),
            Arc::clone(&websocket_proxy),
            Arc::clone(&metrics),
            Arc::clone(&load_balancer),
        ));
        
        cert_manager.initialize().await?;
        
        let tls_config = cert_manager.get_current_config().await
            .ok_or("Failed to get TLS configuration")?;
        
        let proxy = Arc::new(TlsTerminationProxy::new(
            config.clone(),
            tls_config,
            Arc::clone(&load_balancer),
            Arc::clone(&metrics),
        ));
        
        health_checker.start();
        
        connection_pool.warm_up_pools(&config.backends).await;
        
        Ok(Self {
            config,
            metrics,
            rate_limiter,
            global_rate_limiter,
            health_checker,
            circuit_breaker,
            websocket_proxy,
            sticky_sessions,
            admin_server,
            connection_pool,
            cert_manager,
            load_balancer,
            proxy,
        })
    }
    
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting all services...");
        
        let metrics_server = Arc::clone(&self.proxy);
        tokio::spawn(async move {
            if let Err(e) = metrics_server.start_metrics_server().await {
                error!("Metrics server error: {}", e);
            }
        });
        
        let admin_server = Arc::clone(&self.admin_server);
        tokio::spawn(async move {
            if let Err(e) = admin_server.start().await {
                error!("Admin server error: {}", e);
            }
        });
        
        let proxy_server = Arc::clone(&self.proxy);
        let main_handle = tokio::spawn(async move {
            if let Err(e) = proxy_server.run().await {
                error!("Proxy server error: {}", e);
            }
        });
        
        info!("All services started successfully");
        info!("Proxy listening on: {}", self.config.listen_addr);
        info!("Metrics available at: {}", self.config.metrics_addr);
        info!("Admin API available at: {}", self.config.admin.bind_address.unwrap_or_else(|| "127.0.0.1:8443".parse().unwrap()));
        info!("Press Ctrl+C to shutdown");
        
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received");
            }
            _ = main_handle => {
                warn!("Main proxy task completed unexpectedly");
            }
        }
        
        info!("Graceful shutdown completed");
        Ok(())
    }
}

impl LoadBalancingStrategy {
    fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match s.to_lowercase().as_str() {
            "round_robin" => Ok(LoadBalancingStrategy::RoundRobin),
            "least_connections" => Ok(LoadBalancingStrategy::LeastConnections),
            "ip_hash" => Ok(LoadBalancingStrategy::IpHash),
            "weighted_round_robin" => Ok(LoadBalancingStrategy::WeightedRoundRobin),
            "random" => Ok(LoadBalancingStrategy::Random),
            _ => Err(format!("Unknown load balancing strategy: {}", s).into()),
        }
    }
}
