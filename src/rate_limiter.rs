use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::time::interval;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst_size: 10,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
struct ClientInfo {
    tokens: u32,
    last_refill: Instant,
    last_request: Instant,
}

pub struct RateLimiter {
    config: RateLimitConfig,
    clients: Arc<RwLock<HashMap<IpAddr, ClientInfo>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let limiter = Self {
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
        };
        limiter.start_cleanup_task();
        limiter
    }

    pub fn check_rate_limit(&self, client_ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut clients = self.clients.write().unwrap();
        
        let client_info = clients.entry(client_ip).or_insert(ClientInfo {
            tokens: self.config.burst_size,
            last_refill: now,
            last_request: now,
        });

        let time_passed = now.duration_since(client_info.last_refill);
        let tokens_to_add = (time_passed.as_secs_f64() * self.config.requests_per_minute as f64 / 60.0) as u32;
        
        if tokens_to_add > 0 {
            client_info.tokens = (client_info.tokens + tokens_to_add).min(self.config.burst_size);
            client_info.last_refill = now;
        }

        client_info.last_request = now;

        if client_info.tokens > 0 {
            client_info.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn start_cleanup_task(&self) {
        let clients = Arc::clone(&self.clients);
        let cleanup_interval = self.config.cleanup_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut clients = clients.write().unwrap();
                clients.retain(|_, info| {
                    now.duration_since(info.last_request) < cleanup_interval * 2
                });
            }
        });
    }

    pub fn get_stats(&self) -> HashMap<IpAddr, (u32, Instant)> {
        let clients = self.clients.read().unwrap();
        clients.iter()
            .map(|(ip, info)| (*ip, (info.tokens, info.last_request)))
            .collect()
    }
}

pub struct GlobalRateLimiter {
    requests_per_second: u32,
    tokens: Arc<RwLock<u32>>,
    last_refill: Arc<RwLock<Instant>>,
}

impl GlobalRateLimiter {
    pub fn new(requests_per_second: u32) -> Self {
        Self {
            requests_per_second,
            tokens: Arc::new(RwLock::new(requests_per_second)),
            last_refill: Arc::new(RwLock::new(Instant::now())),
        }
    }

    pub fn check_global_limit(&self) -> bool {
        let now = Instant::now();
        let mut tokens = self.tokens.write().unwrap();
        let mut last_refill = self.last_refill.write().unwrap();

        let time_passed = now.duration_since(*last_refill);
        let tokens_to_add = (time_passed.as_secs_f64() * self.requests_per_second as f64) as u32;

        if tokens_to_add > 0 {
            *tokens = (*tokens + tokens_to_add).min(self.requests_per_second);
            *last_refill = now;
        }

        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }
}
