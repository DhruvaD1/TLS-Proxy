use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use tracing::{error, info};
use crate::health_checker::HealthChecker;
use crate::rate_limiter::RateLimiter;
use crate::websocket::WebSocketProxy;
use crate::metrics::ProxyMetrics;
use crate::balancer::LoadBalancer;

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminConfig {
    pub bind_address: SocketAddr,
    pub api_key: Option<String>,
    pub cors_origins: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8443".parse().unwrap(),
            api_key: None,
            cors_origins: vec!["*".to_string()],
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SystemStatus {
    pub uptime_seconds: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
    pub active_connections: usize,
    pub total_requests: u64,
    pub healthy_backends: usize,
    pub total_backends: usize,
    pub websocket_connections: usize,
    pub rate_limited_requests: u64,
}

#[derive(Debug, Serialize)]
pub struct BackendStatus {
    pub address: String,
    pub healthy: bool,
    pub response_time_ms: u64,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBackendRequest {
    pub action: String, 
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct RateLimitRequest {
    pub ip: String,
    pub action: String, 
}

pub struct AdminServer {
    config: AdminConfig,
    health_checker: Arc<HealthChecker>,
    rate_limiter: Arc<RateLimiter>,
    websocket_proxy: Arc<WebSocketProxy>,
    metrics: Arc<ProxyMetrics>,
    load_balancer: Arc<RwLock<LoadBalancer>>,
    start_time: std::time::Instant,
}

impl AdminServer {
    pub fn new(
        config: AdminConfig,
        health_checker: Arc<HealthChecker>,
        rate_limiter: Arc<RateLimiter>,
        websocket_proxy: Arc<WebSocketProxy>,
        metrics: Arc<ProxyMetrics>,
        load_balancer: Arc<RwLock<LoadBalancer>>,
    ) -> Self {
        Self {
            config,
            health_checker,
            rate_limiter,
            websocket_proxy,
            metrics,
            load_balancer,
            start_time: std::time::Instant::now(),
        }
    }

    pub async fn start(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let make_svc = make_service_fn(move |_conn| {
            let server = Arc::clone(&self);
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let server = Arc::clone(&server);
                    async move { server.handle_request(req).await }
                }))
            }
        });

        let server = Server::bind(&self.config.bind_address).serve(make_svc);
        info!("Admin API server starting on {}", self.config.bind_address);

        if let Err(e) = server.await {
            error!("Admin server error: {}", e);
        }

        Ok(())
    }

    async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let response = match self.route_request(req).await {
            Ok(resp) => resp,
            Err(e) => {
                error!("Request handling error: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"error": "Internal server error"}).to_string()))
                    .unwrap()
            }
        };

        Ok(response)
    }

    async fn route_request(&self, req: Request<Body>) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref api_key) = self.config.api_key {
            if let Some(auth_header) = req.headers().get("authorization") {
                let auth_str = auth_header.to_str().unwrap_or("");
                if !auth_str.starts_with("Bearer ") || &auth_str[7..] != api_key {
                    return Ok(self.unauthorized_response());
                }
            } else {
                return Ok(self.unauthorized_response());
            }
        }

        let method = req.method();
        let path = req.uri().path();

        let mut response = match (method, path) {
            (&Method::GET, "/health") => self.health_endpoint().await,
            (&Method::GET, "/status") => self.status_endpoint().await,
            (&Method::GET, "/backends") => self.backends_endpoint().await,
            (&Method::POST, "/backends") => self.update_backend_endpoint(req).await?,
            (&Method::GET, "/metrics") => self.metrics_endpoint().await,
            (&Method::GET, "/websockets") => self.websockets_endpoint().await,
            (&Method::POST, "/websockets/close") => self.close_websocket_endpoint(req).await?,
            (&Method::GET, "/rate-limits") => self.rate_limits_endpoint().await,
            (&Method::POST, "/rate-limits") => self.rate_limit_action_endpoint(req).await?,
            (&Method::GET, "/config") => self.config_endpoint().await,
            (&Method::OPTIONS, _) => self.options_response(),
            _ => self.not_found_response(),
        }?;

        self.add_cors_headers(&mut response);
        Ok(response)
    }

    async fn health_endpoint(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let healthy_backends = self.health_checker.get_healthy_backends().await;
        let is_healthy = !healthy_backends.is_empty();

        let status = if is_healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };

        let response = json!({
            "status": if is_healthy { "healthy" } else { "unhealthy" },
            "healthy_backends": healthy_backends.len(),
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        Ok(Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(response.to_string()))?)
    }

    async fn status_endpoint(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let healthy_backends = self.health_checker.get_healthy_backends().await;
        let all_backends = self.health_checker.get_all_health_status().await;
        let ws_connections = self.websocket_proxy.get_connection_count().await;
        let uptime = self.start_time.elapsed().as_secs();

        let status = SystemStatus {
            uptime_seconds: uptime,
            memory_usage_mb: self.get_memory_usage(),
            cpu_usage_percent: 0.0, 
            active_connections: 0, 
            total_requests: self.metrics.get_total_requests().await,
            healthy_backends: healthy_backends.len(),
            total_backends: all_backends.len(),
            websocket_connections: ws_connections,
            rate_limited_requests: 0, 
        };

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&status)?))?)
    }

    async fn backends_endpoint(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let all_backends = self.health_checker.get_all_health_status().await;
        let mut backend_statuses = Vec::new();

        for (addr, health) in all_backends {
            backend_statuses.push(BackendStatus {
                address: addr.to_string(),
                healthy: health.status == crate::health_checker::HealthStatus::Healthy,
                response_time_ms: health.response_time.as_millis() as u64,
                consecutive_failures: health.consecutive_failures,
                consecutive_successes: health.consecutive_successes,
                last_check: chrono::DateTime::<chrono::Utc>::from(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(
                        health.last_check.elapsed().as_secs()
                    )
                ).to_rfc3339(),
                error_message: health.error_message,
            });
        }

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&backend_statuses)?))?)
    }

    async fn update_backend_endpoint(&self, req: Request<Body>) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
        let update_req: UpdateBackendRequest = serde_json::from_slice(&body_bytes)?;

        let addr: SocketAddr = update_req.address.parse()?;

        match update_req.action.as_str() {
            "force_check" => {
                self.health_checker.force_check(addr);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"message": "Health check initiated"}).to_string()))?)
            }
            "drain" => {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"message": "Backend marked for draining"}).to_string()))?)
            }
            _ => Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Body::from(json!({"error": "Invalid action"}).to_string()))?),
        }
    }

    async fn metrics_endpoint(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let metrics_data = self.metrics.export().await;
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from(metrics_data))?)
    }

    async fn websockets_endpoint(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let connections = self.websocket_proxy.get_connections().await;
        let ws_data: Vec<_> = connections
            .into_iter()
            .map(|(id, client, backend, duration, sent, received)| {
                json!({
                    "id": id,
                    "client_address": client.to_string(),
                    "backend_address": backend.to_string(),
                    "duration_seconds": duration.as_secs(),
                    "bytes_sent": sent,
                    "bytes_received": received
                })
            })
            .collect();

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&ws_data)?))?)
    }

    async fn close_websocket_endpoint(&self, req: Request<Body>) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
        let close_req: serde_json::Value = serde_json::from_slice(&body_bytes)?;

        if let Some(connection_id) = close_req.get("connection_id").and_then(|v| v.as_str()) {
            let closed = self.websocket_proxy.close_connection(connection_id).await;
            let message = if closed {
                "Connection closed"
            } else {
                "Connection not found"
            };

            Ok(Response::builder()
                .status(if closed { StatusCode::OK } else { StatusCode::NOT_FOUND })
                .header("content-type", "application/json")
                .body(Body::from(json!({"message": message}).to_string()))?)
        } else {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Body::from(json!({"error": "Missing connection_id"}).to_string()))?)
        }
    }

    async fn rate_limits_endpoint(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let stats = self.rate_limiter.get_stats();
        let rate_limit_data: Vec<_> = stats
            .into_iter()
            .map(|(ip, (tokens, last_request))| {
                json!({
                    "ip": ip.to_string(),
                    "remaining_tokens": tokens,
                    "last_request": chrono::DateTime::<chrono::Utc>::from(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(
                            last_request.elapsed().as_secs()
                        )
                    ).to_rfc3339()
                })
            })
            .collect();

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&rate_limit_data)?))?)
    }

    async fn rate_limit_action_endpoint(&self, req: Request<Body>) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
        let rate_req: RateLimitRequest = serde_json::from_slice(&body_bytes)?;

        match rate_req.action.as_str() {
            "reset" => {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"message": "Rate limit reset (not implemented)"}).to_string()))?)
            }
            _ => Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Body::from(json!({"error": "Invalid action"}).to_string()))?),
        }
    }

    async fn config_endpoint(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let config_data = json!({
            "admin_bind_address": self.config.bind_address.to_string(),
            "api_key_configured": self.config.api_key.is_some(),
            "cors_origins": self.config.cors_origins
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(config_data.to_string()))?)
    }

    fn unauthorized_response(&self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Body::from(json!({"error": "Unauthorized"}).to_string()))
            .unwrap()
    }

    fn not_found_response(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "application/json")
            .body(Body::from(json!({"error": "Not found"}).to_string()))?)
    }

    fn options_response(&self) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("access-control-allow-methods", "GET, POST, OPTIONS")
            .header("access-control-allow-headers", "authorization, content-type")
            .body(Body::empty())?)
    }

    fn add_cors_headers(&self, response: &mut Response<Body>) {
        let headers = response.headers_mut();
        for origin in &self.config.cors_origins {
            headers.insert("access-control-allow-origin", origin.parse().unwrap());
        }
        headers.insert("access-control-allow-credentials", "true".parse().unwrap());
    }

    fn get_memory_usage(&self) -> u64 {
        0
    }
}
