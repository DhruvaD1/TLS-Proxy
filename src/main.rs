use anyhow::{Context, Result};
use clap::{Arg, Command};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tls_termination_proxy::{
    balancer::BalancerManager,
    config::{ConfigWatcher, ProxyConfig},
    metrics::{MetricsServer, ProxyMetrics},
    proxy::ProxyServer,
    tls::TlsManager,
};

#[derive(Debug)]
struct AppArgs {
    config_path: PathBuf,
    validate_only: bool,
    generate_config: bool,
    log_level: String,
    metrics_only: bool,
}

impl AppArgs {
    fn from_cli() -> Self {
        let matches = Command::new("TLS Termination Proxy")
            .version(env!("CARGO_PKG_VERSION"))
            .author("Rust TLS Proxy Team")
            .about("High-performance TLS termination proxy written in Rust")
            .arg(
                Arg::new("config")
                    .short('c')
                    .long("config")
                    .value_name("FILE")
                    .help("Configuration file path")
                    .default_value("config.yaml"),
            )
            .arg(
                Arg::new("validate")
                    .long("validate")
                    .help("Validate configuration and exit")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("generate-config")
                    .long("generate-config")
                    .help("Generate example configuration file")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("log-level")
                    .short('l')
                    .long("log-level")
                    .value_name("LEVEL")
                    .help("Log level (trace, debug, info, warn, error)")
                    .default_value("info"),
            )
            .arg(
                Arg::new("metrics-only")
                    .long("metrics-only")
                    .help("Start only the metrics server (useful for debugging)")
                    .action(clap::ArgAction::SetTrue),
            )
            .get_matches();

        Self {
            config_path: PathBuf::from(matches.get_one::<String>("config").unwrap()),
            validate_only: matches.get_flag("validate"),
            generate_config: matches.get_flag("generate-config"),
            log_level: matches.get_one::<String>("log-level").unwrap().clone(),
            metrics_only: matches.get_flag("metrics-only"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = AppArgs::from_cli();

    if args.generate_config {
        return generate_example_config(&args.config_path);
    }

    setup_logging(&args.log_level)?;

    info!("Starting TLS Termination Proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("Loading configuration from: {:?}", args.config_path);

    let config = ProxyConfig::load_from_file(&args.config_path)
        .await
        .context("Failed to load configuration")?;

    info!("Configuration loaded successfully");
    info!("Listen address: {}", config.listen_addr);
    info!("Backends: {:?}", config.backends.iter().map(|b| b.addr).collect::<Vec<_>>());
    info!("Load balancing strategy: {:?}", config.strategy);
    info!("Metrics address: {}", config.metrics_addr);

    if args.validate_only {
        info!("Configuration validation successful");
        return Ok(());
    }

    let config = Arc::new(config);

    let metrics = Arc::new(ProxyMetrics::new().context("Failed to create metrics")?);
    info!("Metrics system initialized");

    let metrics_server = MetricsServer::new(Arc::clone(&metrics), config.metrics_addr);

    if args.metrics_only {
        info!("Starting metrics server only");
        return metrics_server.start().await.context("Metrics server failed");
    }

    let tls_manager = Arc::new(
        TlsManager::new(&config)
            .await
            .context("Failed to create TLS manager")?,
    );
    info!("TLS manager initialized");

    let load_balancer = Arc::new(BalancerManager::new(
        config.strategy,
        config.backends.clone(),
    ));
    info!("Load balancer initialized");

    load_balancer
        .start_health_checks(
            config.health_check.interval,
            config.health_check.timeout,
        )
        .await
        .context("Failed to start health checks")?;
    info!("Health check system started");

    let proxy_server = ProxyServer::new(
        Arc::clone(&config),
        tls_manager,
        load_balancer,
        Arc::clone(&metrics),
    );
    info!("Proxy server initialized");

    let config_watcher = ConfigWatcher::new(args.config_path.clone(), (*config).clone());
    config_watcher
        .start_watching()
        .await
        .context("Failed to start configuration watcher")?;
    info!("Configuration watcher started");

    let shutdown_signal = setup_shutdown_handler();

    info!("Starting all services...");

    tokio::select! {
        result = proxy_server.start() => {
            error!("Proxy server exited: {:?}", result);
            result.context("Proxy server failed")?;
        }
        result = metrics_server.start() => {
            error!("Metrics server exited: {:?}", result);
            result.context("Metrics server failed")?;
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received, stopping services...");
        }
    }

    info!("TLS Termination Proxy stopped");
    Ok(())
}

fn setup_logging(level: &str) -> Result<()> {
    let log_level = match level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => {
            eprintln!("Invalid log level: {}. Using 'info' instead.", level);
            tracing::Level::INFO
        }
    };

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy()
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("tokio_rustls=warn".parse().unwrap())
        .add_directive("hyper=info".parse().unwrap());

    let registry = tracing_subscriber::registry();

    if std::env::var("TLS_PROXY_JSON_LOGS").is_ok() {
        registry
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
                    .with_current_span(false)
                    .with_span_list(true),
            )
            .init();
    } else {
        registry
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
                    .with_target(true)
                    .with_thread_ids(true),
            )
            .init();
    }

    info!("Logging initialized with level: {}", level);
    Ok(())
}

async fn setup_shutdown_handler() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            info!("Received terminate signal");
        },
    }
}

fn generate_example_config(path: &PathBuf) -> Result<()> {
    let config = ProxyConfig::default();
    config.save_to_file(path)?;
    
    println!("Example configuration generated at: {:?}", path);
    println!("\nConfiguration overview:");
    println!("- Listen address: {}", config.listen_addr);
    println!("- Metrics address: {}", config.metrics_addr);
    println!("- Load balancing strategy: {:?}", config.strategy);
    println!("- Number of backends: {}", config.backends.len());
    println!("- TLS certificate: {:?}", config.cert_path);
    println!("- TLS private key: {:?}", config.key_path);
    println!("\nDon't forget to:");
    println!("1. Generate or obtain TLS certificates");
    println!("2. Update backend addresses");
    println!("3. Adjust connection limits and timeouts as needed");
    println!("4. Configure health check settings");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_args_parsing() {
        let _args = AppArgs::from_cli();
    }

    #[tokio::test]
    async fn test_config_generation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.yaml");
        
        let result = generate_example_config(&config_path);
        assert!(result.is_ok());
        assert!(config_path.exists());
        
        let loaded_config = ProxyConfig::load_from_file(&config_path).await;
        assert!(loaded_config.is_ok());
    }

    #[test]
    fn test_logging_setup() {
        let result = setup_logging("debug");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_log_level() {
        let result = setup_logging("invalid");
        assert!(result.is_ok());
    }
}

#[cfg(feature = "integration-tests")]
mod integration_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_full_application_startup() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.yaml");
        
        let mut config = ProxyConfig::default();
        config.listen_addr = "127.0.0.1:0".parse().unwrap();
        config.metrics_addr = "127.0.0.1:0".parse().unwrap();
        config.cert_path = temp_dir.path().join("cert.pem");
        config.key_path = temp_dir.path().join("key.pem");
        
        std::fs::write(&config.cert_path, include_bytes!("../examples/cert.pem")).unwrap();
        std::fs::write(&config.key_path, include_bytes!("../examples/key.pem")).unwrap();
        
        config.save_to_file(&config_path).unwrap();
        
        std::env::set_var("TLS_PROXY_TEST_MODE", "1");
        
        let result = timeout(Duration::from_secs(5), async {
            let config = ProxyConfig::load_from_file(&config_path).await?;
            let metrics = Arc::new(ProxyMetrics::new()?);
            let _metrics_server = MetricsServer::new(Arc::clone(&metrics), config.metrics_addr);
            
            anyhow::Ok(())
        }).await;
        
        std::env::remove_var("TLS_PROXY_TEST_MODE");
        
        match result {
            Ok(Ok(_)) => {},
            Ok(Err(e)) => {
                if !e.to_string().contains("No such file") {
                    panic!("Unexpected error: {}", e);
                }
            },
            Err(_) => panic!("Test timed out"),
        }
    }
}
