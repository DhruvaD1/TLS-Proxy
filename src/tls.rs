use crate::config::{ProxyConfig, TlsConfig, TlsVersion, ClientAuthMode};
use anyhow::{Context, Result};
use rustls::{ServerConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

pub struct TlsManager {
    acceptor: TlsAcceptor,
    config: Arc<TlsConfig>,
}

impl TlsManager {
    pub async fn new(proxy_config: &ProxyConfig) -> Result<Self> {
        let server_config = Self::build_server_config(proxy_config).await?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        
        Ok(Self {
            acceptor,
            config: Arc::new(proxy_config.tls.clone()),
        })
    }
    
    async fn build_server_config(proxy_config: &ProxyConfig) -> Result<ServerConfig> {
        let certs = Self::load_certificates(&proxy_config.cert_path)
            .context("Failed to load certificate")?;
        
        let private_key = Self::load_private_key(&proxy_config.key_path)
            .context("Failed to load private key")?;
        
        let config_builder = ServerConfig::builder();
        
        let config_builder = match proxy_config.tls.client_auth {
            ClientAuthMode::None => config_builder.with_no_client_auth(),
            ClientAuthMode::Optional => {
                let ca_certs = Self::load_ca_certificates(proxy_config)?;
                let client_cert_verifier = Self::build_client_cert_verifier(ca_certs, false)?;
                config_builder.with_client_cert_verifier(client_cert_verifier)
            }
            ClientAuthMode::Required => {
                let ca_certs = Self::load_ca_certificates(proxy_config)?;
                let client_cert_verifier = Self::build_client_cert_verifier(ca_certs, true)?;
                config_builder.with_client_cert_verifier(client_cert_verifier)
            }
        };
        
        let mut server_config = config_builder
            .with_single_cert(certs, private_key)
            .context("Failed to build TLS server configuration")?;
        
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        server_config.session_storage = Arc::new(rustls::server::ServerSessionMemoryCache::new(
            proxy_config.tls.session_cache_size
        ));
        
        if proxy_config.tls.require_sni {
            server_config.ignore_client_order = !proxy_config.tls.prefer_server_cipher_order;
        }
        
        Ok(server_config)
    }
    
    fn load_certificates(cert_path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
        let cert_file = File::open(cert_path)
            .with_context(|| format!("Failed to open certificate file: {:?}", cert_path))?;
        
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain = certs(&mut cert_reader)
            .context("Failed to parse certificates")?
            .into_iter()
            .collect();
        
        Ok(cert_chain)
    }
    
    fn load_private_key(key_path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
        let key_file = File::open(key_path)
            .with_context(|| format!("Failed to open private key file: {:?}", key_path))?;
        
        let mut key_reader = BufReader::new(key_file);
        
        if let Ok(mut pkcs8_keys) = pkcs8_private_keys(&mut key_reader) {
            if !pkcs8_keys.is_empty() {
                return Ok(pkcs8_keys.remove(0).into());
            }
        }
        
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        
        let mut rsa_keys = rsa_private_keys(&mut key_reader)
            .context("Failed to parse RSA private keys")?;
        
        if rsa_keys.is_empty() {
            anyhow::bail!("No valid private key found in key file");
        }
        
        Ok(rsa_keys.remove(0).into())
    }
    
    fn load_ca_certificates(proxy_config: &ProxyConfig) -> Result<Vec<CertificateDer<'static>>> {
        match &proxy_config.tls.ca_cert_path {
            Some(ca_path) => Self::load_certificates(ca_path),
            None => anyhow::bail!("CA certificate path required for client authentication"),
        }
    }
    
    fn build_client_cert_verifier(
        ca_certs: Vec<CertificateDer<'static>>,
        require_auth: bool,
    ) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
        let mut root_cert_store = RootCertStore::empty();
        
        for ca_cert in ca_certs {
            root_cert_store.add(ca_cert)
                .context("Failed to add CA certificate to root store")?;
        }
        
        if require_auth {
            Ok(rustls::server::WebPkiClientVerifier::builder(Arc::new(root_cert_store))
                .build()
                .context("Failed to build client cert verifier")?)
        } else {
            Ok(rustls::server::WebPkiClientVerifier::builder(Arc::new(root_cert_store))
                .allow_unauthenticated()
                .build()
                .context("Failed to build client cert verifier")?)
        }
    }
    
    fn get_cipher_suites(cipher_suite_names: &[String]) -> Result<Vec<rustls::SupportedCipherSuite>> {
        let mut cipher_suites = Vec::new();
        
        for name in cipher_suite_names {
            match name.as_str() {
                "TLS_AES_256_GCM_SHA384" => {
                    cipher_suites.push(rustls::cipher_suite::TLS13_AES_256_GCM_SHA384);
                }
                "TLS_AES_128_GCM_SHA256" => {
                    cipher_suites.push(rustls::cipher_suite::TLS13_AES_128_GCM_SHA256);
                }
                "TLS_CHACHA20_POLY1305_SHA256" => {
                    cipher_suites.push(rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256);
                }
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                    cipher_suites.push(rustls::cipher_suite::TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
                }
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                    cipher_suites.push(rustls::cipher_suite::TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
                }
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                    cipher_suites.push(rustls::cipher_suite::TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
                }
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                    cipher_suites.push(rustls::cipher_suite::TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
                }
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                    cipher_suites.push(rustls::cipher_suite::TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
                }
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                    cipher_suites.push(rustls::cipher_suite::TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
                }
                _ => {
                    tracing::warn!("Unknown cipher suite: {}, skipping", name);
                }
            }
        }
        
        if cipher_suites.is_empty() {
            cipher_suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();
        }
        
        Ok(cipher_suites)
    }
    
    fn get_protocol_versions(tls_config: &TlsConfig) -> Result<Vec<&'static rustls::SupportedProtocolVersion>> {
        let mut versions = Vec::new();
        
        match (tls_config.min_protocol_version, tls_config.max_protocol_version) {
            (TlsVersion::Tls12, TlsVersion::Tls12) => {
                versions.push(&rustls::version::TLS12);
            }
            (TlsVersion::Tls12, TlsVersion::Tls13) => {
                versions.push(&rustls::version::TLS12);
                versions.push(&rustls::version::TLS13);
            }
            (TlsVersion::Tls13, TlsVersion::Tls13) => {
                versions.push(&rustls::version::TLS13);
            }
            _ => {
                anyhow::bail!("Invalid TLS version configuration: min version cannot be higher than max version");
            }
        }
        
        Ok(versions)
    }
    
    pub async fn accept_tls_connection(&self, tcp_stream: TcpStream) -> Result<TlsStream<TcpStream>> {
        let tls_stream = self.acceptor.accept(tcp_stream).await
            .context("TLS handshake failed")?;
        
        Ok(tls_stream)
    }
    
    pub fn get_session_stats(&self) -> TlsSessionStats {
        TlsSessionStats {
            active_sessions: 0,
            total_handshakes: 0,
            failed_handshakes: 0,
            session_resumptions: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsSessionStats {
    pub active_sessions: u64,
    pub total_handshakes: u64,
    pub failed_handshakes: u64,
    pub session_resumptions: u64,
}

pub struct CertificateReloader {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    config: Arc<TlsConfig>,
    current_acceptor: arc_swap::ArcSwap<TlsAcceptor>,
}

impl CertificateReloader {
    pub fn new(
        cert_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
        config: Arc<TlsConfig>,
        initial_acceptor: TlsAcceptor,
    ) -> Self {
        Self {
            cert_path,
            key_path,
            config,
            current_acceptor: arc_swap::ArcSwap::new(Arc::new(initial_acceptor)),
        }
    }
    
    pub async fn start_watching(&self) -> Result<()> {
        use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
        use tokio::sync::mpsc;
        
        let (tx, mut rx) = mpsc::channel(1);
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let config = self.config.clone();
        let current_acceptor = self.current_acceptor.clone();
        
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(_event) = res {
                    let _ = tx.try_send(());
                }
            },
            Config::default(),
        )?;
        
        if let Some(parent) = self.cert_path.parent() {
            watcher.watch(parent, RecursiveMode::NonRecursive)?;
        }
        
        tokio::spawn(async move {
            while let Some(_) = rx.recv().await {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                
                match Self::reload_certificates(&cert_path, &key_path, &config).await {
                    Ok(new_acceptor) => {
                        tracing::info!("TLS certificates reloaded successfully");
                        current_acceptor.store(Arc::new(new_acceptor));
                    }
                    Err(e) => {
                        tracing::error!("Failed to reload TLS certificates: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    async fn reload_certificates(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
        tls_config: &TlsConfig,
    ) -> Result<TlsAcceptor> {
        let certs = TlsManager::load_certificates(cert_path)?;
        let private_key = TlsManager::load_private_key(key_path)?;
        
        let cipher_suites = TlsManager::get_cipher_suites(&tls_config.cipher_suites)?;
        let protocol_versions = TlsManager::get_protocol_versions(tls_config)?;
        
        let config_builder = ServerConfig::builder()
            .with_cipher_suites(&cipher_suites)
            .with_kx_groups(&rustls::ALL_KX_GROUPS)
            .with_protocol_versions(&protocol_versions)?
            .with_no_client_auth();
        
        let mut server_config = config_builder
            .with_single_cert(certs, private_key)?;
        
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        server_config.session_storage = Arc::new(rustls::server::ServerSessionMemoryCache::new(
            tls_config.session_cache_size
        ));
        
        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }
    
    pub fn get_acceptor(&self) -> Arc<TlsAcceptor> {
        self.current_acceptor.load_full()
    }
}

pub struct TlsHealthChecker;

impl TlsHealthChecker {
    pub async fn check_certificate_expiry(cert_path: &std::path::Path) -> Result<std::time::Duration> {
        let certs = TlsManager::load_certificates(cert_path)?;
        
        if let Some(cert) = certs.first() {
            let parsed_cert = x509_parser::parse_x509_certificate(&cert.0)
                .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?
                .1;
            
            let not_after = parsed_cert.validity().not_after;
            let current_time = x509_parser::time::ASN1Time::now();
            
            if not_after > current_time {
                let duration = not_after.timestamp() - current_time.timestamp();
                Ok(std::time::Duration::from_secs(duration as u64))
            } else {
                anyhow::bail!("Certificate has expired");
            }
        } else {
            anyhow::bail!("No certificate found");
        }
    }
    
    pub async fn validate_certificate_chain(cert_path: &std::path::Path) -> Result<()> {
        let certs = TlsManager::load_certificates(cert_path)?;
        
        if certs.is_empty() {
            anyhow::bail!("No certificates found in certificate file");
        }
        
        tracing::info!("Certificate chain contains {} certificates", certs.len());
        
        for (i, cert) in certs.iter().enumerate() {
            match x509_parser::parse_x509_certificate(&cert.0) {
                Ok((_, parsed_cert)) => {
                    tracing::debug!(
                        "Certificate {}: Subject: {:?}, Issuer: {:?}",
                        i,
                        parsed_cert.subject(),
                        parsed_cert.issuer()
                    );
                }
                Err(e) => {
                    anyhow::bail!("Failed to parse certificate {}: {}", i, e);
                }
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;
    
    const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMzEwMDEwMDAwMDBaFw0yNDEwMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDTgvwjlRHZ9IFt
WP4RcZVTgYuiI+fj2K1E8mC0v3qE8n2dCdNUNqf6K8G0W7XnE0+Y9IFtWP4RcZVT
gYuiI+fjAgMBAAEwDQYJKoZIhvcNAQELBQADQQCm5gF0RdFnvFLXdLvQXEqSkNzl
A9PJgOqM1K8FBGBCQw6lF6zJWa3E3BhQKfjA1L3E3BhQKfjA1L3E3BhQKfj
-----END CERTIFICATE-----"#;

    const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA04L8I5UR2fSBbVj+
EXGVUYGLo2P3o1FsE8mC0v3qE8n2dCdNUNqf6K8G0W7XnE0+Y9IFtWP4RcZVTgY
uiI+fjwIDAQABAkEAwQdvpQ9MKjY+5YfuQF+Lb2gHGxKzp9LjZ8gZzJ6BHzDvnC
E7y2I6BQ2w1pCf5gB8FkJHZ3w1dPZx2gn+3p/8qwIhAN+2s6Q1qBQRJGLQf7FJ
3n+B4f+K6hV8EcQdqrKc7SFBrBOgFZ6AiEA5Z4FjQ1qBwR5sJ6G+Lb2gK+rKx6
J3Z8gZzJ6BHzDvnC7qgIgZNmJb+K1E8mC0v3qE8n2dCdNUNqf6K8G0W7XnE0+
-----END PRIVATE KEY-----"#;
    
    #[tokio::test]
    async fn test_certificate_loading() {
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(TEST_CERT.as_bytes()).unwrap();
        cert_file.flush().unwrap();
        
        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(TEST_KEY.as_bytes()).unwrap();
        key_file.flush().unwrap();
        
        let certs = TlsManager::load_certificates(cert_file.path());
        assert!(certs.is_ok());
        
        let key = TlsManager::load_private_key(key_file.path());
        assert!(key.is_ok());
    }
    
    #[test]
    fn test_cipher_suite_parsing() {
        let cipher_names = vec![
            "TLS_AES_256_GCM_SHA384".to_string(),
            "TLS_AES_128_GCM_SHA256".to_string(),
        ];
        
        let cipher_suites = TlsManager::get_cipher_suites(&cipher_names);
        assert!(cipher_suites.is_ok());
        assert_eq!(cipher_suites.unwrap().len(), 2);
    }
    
    #[test]
    fn test_protocol_version_parsing() {
        let tls_config = TlsConfig {
            min_protocol_version: TlsVersion::Tls12,
            max_protocol_version: TlsVersion::Tls13,
            ..Default::default()
        };
        
        let versions = TlsManager::get_protocol_versions(&tls_config);
        assert!(versions.is_ok());
        assert_eq!(versions.unwrap().len(), 2);
    }
}
