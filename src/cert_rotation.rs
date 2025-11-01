use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::{RwLock, watch};
use tokio::time::{interval, timeout};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use x509_parser::prelude::*;
use notify::{Watcher, RecursiveMode, recommended_watcher, Event, EventKind};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct CertificateConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: Option<PathBuf>,
    pub auto_reload: bool,
    pub check_interval: Duration,
    pub expiry_warning_days: u64,
    pub domains: Vec<String>,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("./certs/server.crt"),
            key_path: PathBuf::from("./certs/server.key"),
            ca_path: None,
            auto_reload: true,
            check_interval: Duration::from_secs(3600),
            expiry_warning_days: 30,
            domains: vec!["localhost".to_string()],
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub san_domains: Vec<String>,
    pub fingerprint: String,
    pub key_usage: Vec<String>,
    pub is_self_signed: bool,
    pub is_ca: bool,
}

pub struct CertificateManager {
    config: CertificateConfig,
    current_config: Arc<RwLock<Option<Arc<ServerConfig>>>>,
    cert_info: Arc<RwLock<Option<CertificateInfo>>>,
    config_sender: watch::Sender<Option<Arc<ServerConfig>>>,
    config_receiver: watch::Receiver<Option<Arc<ServerConfig>>>,
}

impl CertificateManager {
    pub fn new(config: CertificateConfig) -> Self {
        let (config_sender, config_receiver) = watch::channel(None);
        
        Self {
            config,
            current_config: Arc::new(RwLock::new(None)),
            cert_info: Arc::new(RwLock::new(None)),
            config_sender,
            config_receiver,
        }
    }

    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let server_config = self.load_certificate().await?;
        
        *self.current_config.write().await = Some(Arc::new(server_config.clone()));
        self.config_sender.send(Some(Arc::new(server_config)))?;
        
        if self.config.auto_reload {
            self.start_file_watcher().await?;
            self.start_periodic_check();
        }

        info!("Certificate manager initialized successfully");
        Ok(())
    }

    async fn load_certificate(&self) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
        let cert_pem = fs::read(&self.config.cert_path).await?;
        let key_pem = fs::read(&self.config.key_path).await?;

        let cert_chain = self.parse_certificates(&cert_pem)?;
        let private_key = self.parse_private_key(&key_pem)?;

        if let Some(cert) = cert_chain.first() {
            let cert_info = self.extract_certificate_info(&cert.0)?;
            *self.cert_info.write().await = Some(cert_info.clone());

            self.validate_certificate(&cert_info)?;
            info!("Loaded certificate for domains: {:?}", cert_info.san_domains);
        }

        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(server_config)
    }

    fn parse_certificates(&self, pem_data: &[u8]) -> Result<Vec<Certificate>, Box<dyn std::error::Error + Send + Sync>> {
        let mut cursor = std::io::Cursor::new(pem_data);
        let cert_ders = certs(&mut cursor)?;
        
        if cert_ders.is_empty() {
            return Err("No certificates found in PEM file".into());
        }

        Ok(cert_ders.into_iter().map(Certificate).collect())
    }

    fn parse_private_key(&self, pem_data: &[u8]) -> Result<PrivateKey, Box<dyn std::error::Error + Send + Sync>> {
        let mut cursor = std::io::Cursor::new(pem_data);
        
        let pkcs8_keys = pkcs8_private_keys(&mut cursor)?;
        if !pkcs8_keys.is_empty() {
            return Ok(PrivateKey(pkcs8_keys[0].clone()));
        }

        let mut cursor = std::io::Cursor::new(pem_data);
        let rsa_keys = rsa_private_keys(&mut cursor)?;
        if !rsa_keys.is_empty() {
            return Ok(PrivateKey(rsa_keys[0].clone()));
        }

        Err("No valid private key found in PEM file".into())
    }

    fn extract_certificate_info(&self, cert_der: &[u8]) -> Result<CertificateInfo, Box<dyn std::error::Error + Send + Sync>> {
        let (_, cert) = X509Certificate::from_der(cert_der)?;

        let serial_number = cert.serial.to_str_radix(16);
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        
        let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());

        let mut san_domains = Vec::new();
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns_name) = name {
                    san_domains.push(dns_name.to_string());
                }
            }
        }

        if san_domains.is_empty() {
            if let Ok(common_name) = cert.subject().iter_common_name().next() {
                san_domains.push(common_name.as_str()?.to_string());
            }
        }

        let fingerprint = format!("{:x}", sha2::Sha256::digest(cert_der));
        
        let mut key_usage = Vec::new();
        if let Ok(Some(ku_ext)) = cert.key_usage() {
            let ku = ku_ext.value;
            if ku.digital_signature() { key_usage.push("Digital Signature".to_string()); }
            if ku.key_encipherment() { key_usage.push("Key Encipherment".to_string()); }
            if ku.key_agreement() { key_usage.push("Key Agreement".to_string()); }
            if ku.key_cert_sign() { key_usage.push("Certificate Sign".to_string()); }
        }

        let is_self_signed = subject == issuer;
        let is_ca = cert.basic_constraints()
            .map(|bc| bc.map(|bc| bc.value.ca).unwrap_or(false))
            .unwrap_or(false);

        Ok(CertificateInfo {
            serial_number,
            subject,
            issuer,
            not_before,
            not_after,
            san_domains,
            fingerprint,
            key_usage,
            is_self_signed,
            is_ca,
        })
    }

    fn validate_certificate(&self, cert_info: &CertificateInfo) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = Utc::now();
        
        if cert_info.not_after < now {
            return Err(format!("Certificate expired on {}", cert_info.not_after).into());
        }

        if cert_info.not_before > now {
            return Err(format!("Certificate not valid until {}", cert_info.not_before).into());
        }

        let days_until_expiry = (cert_info.not_after - now).num_days();
        if days_until_expiry <= self.config.expiry_warning_days as i64 {
            warn!("Certificate expires in {} days ({})", days_until_expiry, cert_info.not_after);
        }

        let configured_domains: std::collections::HashSet<_> = self.config.domains.iter().collect();
        let cert_domains: std::collections::HashSet<_> = cert_info.san_domains.iter().collect();
        
        for domain in &configured_domains {
            if !cert_domains.contains(domain) && !cert_info.san_domains.iter().any(|d| d == "*" || Self::matches_wildcard(d, domain)) {
                warn!("Configured domain '{}' not covered by certificate", domain);
            }
        }

        Ok(())
    }

    fn matches_wildcard(wildcard: &str, domain: &str) -> bool {
        if let Some(wildcard_domain) = wildcard.strip_prefix("*.") {
            if let Some(domain_suffix) = domain.find('.') {
                return &domain[domain_suffix + 1..] == wildcard_domain;
            }
        }
        false
    }

    async fn start_file_watcher(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (tx, mut rx) = mpsc::channel(100);
        let cert_path = self.config.cert_path.clone();
        let key_path = self.config.key_path.clone();

        let mut watcher = recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if let EventKind::Modify(_) = event.kind {
                    let _ = tx.try_send(event);
                }
            }
        })?;

        if let Some(cert_dir) = cert_path.parent() {
            watcher.watch(cert_dir, RecursiveMode::NonRecursive)?;
        }
        if let Some(key_dir) = key_path.parent() {
            if key_dir != cert_path.parent().unwrap_or(Path::new("")) {
                watcher.watch(key_dir, RecursiveMode::NonRecursive)?;
            }
        }

        let current_config = Arc::clone(&self.current_config);
        let cert_info = Arc::clone(&self.cert_info);
        let config_sender = self.config_sender.clone();
        let cert_path_clone = cert_path.clone();
        let key_path_clone = key_path.clone();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let paths: Vec<_> = event.paths.iter().collect();
                if paths.iter().any(|p| p == &&cert_path_clone || p == &&key_path_clone) {
                    info!("Certificate files changed, reloading...");
                    
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    
                    match Self::load_certificate_static(&cert_path_clone, &key_path_clone).await {
                        Ok((server_config, cert_info_new)) => {
                            *current_config.write().await = Some(Arc::new(server_config.clone()));
                            *cert_info.write().await = Some(cert_info_new);
                            
                            if let Err(e) = config_sender.send(Some(Arc::new(server_config))) {
                                error!("Failed to send updated certificate config: {}", e);
                            } else {
                                info!("Certificate reloaded successfully");
                            }
                        }
                        Err(e) => {
                            error!("Failed to reload certificate: {}", e);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn load_certificate_static(
        cert_path: &Path, 
        key_path: &Path
    ) -> Result<(ServerConfig, CertificateInfo), Box<dyn std::error::Error + Send + Sync>> {
        let cert_pem = fs::read(cert_path).await?;
        let key_pem = fs::read(key_path).await?;

        let mut cursor = std::io::Cursor::new(&cert_pem);
        let cert_ders = certs(&mut cursor)?;
        if cert_ders.is_empty() {
            return Err("No certificates found".into());
        }

        let cert_chain: Vec<Certificate> = cert_ders.into_iter().map(Certificate).collect();
        
        let mut cursor = std::io::Cursor::new(&key_pem);
        let private_key = if let Ok(keys) = pkcs8_private_keys(&mut cursor) {
            if !keys.is_empty() {
                PrivateKey(keys[0].clone())
            } else {
                let mut cursor = std::io::Cursor::new(&key_pem);
                let rsa_keys = rsa_private_keys(&mut cursor)?;
                if rsa_keys.is_empty() {
                    return Err("No valid private key found".into());
                }
                PrivateKey(rsa_keys[0].clone())
            }
        } else {
            return Err("Failed to parse private key".into());
        };

        let cert_info = if let Some(cert) = cert_chain.first() {
            let (_, x509_cert) = X509Certificate::from_der(&cert.0)?;
            let serial_number = x509_cert.serial.to_str_radix(16);
            let subject = x509_cert.subject().to_string();
            let issuer = x509_cert.issuer().to_string();
            
            let not_before = DateTime::from_timestamp(x509_cert.validity().not_before.timestamp(), 0)
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());
            let not_after = DateTime::from_timestamp(x509_cert.validity().not_after.timestamp(), 0)
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());

            let mut san_domains = Vec::new();
            if let Ok(Some(san_ext)) = x509_cert.subject_alternative_name() {
                for name in &san_ext.value.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns_name) = name {
                        san_domains.push(dns_name.to_string());
                    }
                }
            }

            let fingerprint = format!("{:x}", sha2::Sha256::digest(&cert.0));

            CertificateInfo {
                serial_number,
                subject,
                issuer,
                not_before,
                not_after,
                san_domains,
                fingerprint,
                key_usage: Vec::new(),
                is_self_signed: subject == issuer,
                is_ca: false,
            }
        } else {
            return Err("No certificate found".into());
        };

        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok((server_config, cert_info))
    }

    fn start_periodic_check(&self) {
        let cert_info = Arc::clone(&self.cert_info);
        let check_interval = self.config.check_interval;
        let expiry_warning_days = self.config.expiry_warning_days;

        tokio::spawn(async move {
            let mut interval = interval(check_interval);
            loop {
                interval.tick().await;
                
                if let Some(info) = cert_info.read().await.as_ref() {
                    let now = Utc::now();
                    let days_until_expiry = (info.not_after - now).num_days();
                    
                    if days_until_expiry <= expiry_warning_days as i64 {
                        if days_until_expiry <= 0 {
                            error!("Certificate has expired!");
                        } else {
                            warn!("Certificate expires in {} days", days_until_expiry);
                        }
                    } else {
                        debug!("Certificate check passed, expires in {} days", days_until_expiry);
                    }
                }
            }
        });
    }

    pub fn get_config_receiver(&self) -> watch::Receiver<Option<Arc<ServerConfig>>> {
        self.config_receiver.clone()
    }

    pub async fn get_current_config(&self) -> Option<Arc<ServerConfig>> {
        self.current_config.read().await.clone()
    }

    pub async fn get_certificate_info(&self) -> Option<CertificateInfo> {
        self.cert_info.read().await.clone()
    }

    pub async fn force_reload(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Force reloading certificate");
        let server_config = self.load_certificate().await?;
        
        *self.current_config.write().await = Some(Arc::new(server_config.clone()));
        self.config_sender.send(Some(Arc::new(server_config)))?;
        
        info!("Certificate force reload completed");
        Ok(())
    }

    pub async fn validate_certificate_file(cert_path: &Path) -> Result<CertificateInfo, Box<dyn std::error::Error + Send + Sync>> {
        let cert_pem = fs::read(cert_path).await?;
        let mut cursor = std::io::Cursor::new(&cert_pem);
        let cert_ders = certs(&mut cursor)?;
        
        if cert_ders.is_empty() {
            return Err("No certificates found in file".into());
        }

        let (_, x509_cert) = X509Certificate::from_der(&cert_ders[0])?;
        
        let serial_number = x509_cert.serial.to_str_radix(16);
        let subject = x509_cert.subject().to_string();
        let issuer = x509_cert.issuer().to_string();
        
        let not_before = DateTime::from_timestamp(x509_cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());
        let not_after = DateTime::from_timestamp(x509_cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());

        let mut san_domains = Vec::new();
        if let Ok(Some(san_ext)) = x509_cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns_name) = name {
                    san_domains.push(dns_name.to_string());
                }
            }
        }

        let fingerprint = format!("{:x}", sha2::Sha256::digest(&cert_ders[0]));

        Ok(CertificateInfo {
            serial_number,
            subject,
            issuer,
            not_before,
            not_after,
            san_domains,
            fingerprint,
            key_usage: Vec::new(),
            is_self_signed: subject == issuer,
            is_ca: false,
        })
    }
}
