use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};
use tokio_rustls::TlsStream;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{
    accept_async, client_async, tungstenite::Message, WebSocketStream, MaybeTlsStream,
};

#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub ping_interval: Duration,
    pub pong_timeout: Duration,
    pub max_message_size: usize,
    pub max_frame_size: usize,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            connection_timeout: Duration::from_secs(30),
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            max_message_size: 1024 * 1024, 
            max_frame_size: 16 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct WebSocketConnection {
    id: String,
    client_addr: SocketAddr,
    backend_addr: SocketAddr,
    created_at: Instant,
    last_activity: Arc<RwLock<Instant>>,
    bytes_sent: Arc<RwLock<u64>>,
    bytes_received: Arc<RwLock<u64>>,
}

impl WebSocketConnection {
    pub fn new(id: String, client_addr: SocketAddr, backend_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            id,
            client_addr,
            backend_addr,
            created_at: now,
            last_activity: Arc::new(RwLock::new(now)),
            bytes_sent: Arc::new(RwLock::new(0)),
            bytes_received: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn update_activity(&self) {
        *self.last_activity.write().await = Instant::now();
    }

    pub async fn add_bytes_sent(&self, bytes: u64) {
        *self.bytes_sent.write().await += bytes;
    }

    pub async fn add_bytes_received(&self, bytes: u64) {
        *self.bytes_received.write().await += bytes;
    }

    pub async fn get_stats(&self) -> (Duration, u64, u64) {
        let last_activity = *self.last_activity.read().await;
        let bytes_sent = *self.bytes_sent.read().await;
        let bytes_received = *self.bytes_received.read().await;
        (last_activity.duration_since(self.created_at), bytes_sent, bytes_received)
    }
}

pub struct WebSocketProxy {
    config: WebSocketConfig,
    connections: Arc<RwLock<HashMap<String, Arc<WebSocketConnection>>>>,
    connection_counter: Arc<RwLock<u64>>,
}

impl WebSocketProxy {
    pub fn new(config: WebSocketConfig) -> Self {
        let proxy = Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            connection_counter: Arc::new(RwLock::new(0)),
        };
        proxy.start_cleanup_task();
        proxy
    }

    pub async fn handle_websocket<S>(
        &self,
        client_stream: S,
        client_addr: SocketAddr,
        backend_addr: SocketAddr,
        path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.connections.read().await.len() >= self.config.max_connections {
            return Err("Maximum WebSocket connections reached".into());
        }

        let connection_id = {
            let mut counter = self.connection_counter.write().await;
            *counter += 1;
            format!("ws-{}", *counter)
        };

        info!("Establishing WebSocket connection {} from {} to {}", connection_id, client_addr, backend_addr);

        let client_ws = accept_async(client_stream).await?;

        let backend_stream = timeout(
            self.config.connection_timeout,
            TcpStream::connect(backend_addr)
        ).await??;

        let url = format!("ws://{}{}", backend_addr, path);
        let (backend_ws, _) = client_async(&url, backend_stream).await?;

        let connection = Arc::new(WebSocketConnection::new(
            connection_id.clone(),
            client_addr,
            backend_addr,
        ));

        self.connections.write().await.insert(connection_id.clone(), Arc::clone(&connection));

        let result = self.proxy_websocket_streams(client_ws, backend_ws, Arc::clone(&connection)).await;

        self.connections.write().await.remove(&connection_id);
        info!("WebSocket connection {} closed", connection_id);

        result
    }

    async fn proxy_websocket_streams<C, B>(
        &self,
        mut client_ws: WebSocketStream<C>,
        mut backend_ws: WebSocketStream<MaybeTlsStream<B>>,
        connection: Arc<WebSocketConnection>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut client_tx, mut client_rx) = client_ws.split();
        let (mut backend_tx, mut backend_rx) = backend_ws.split();

        let connection_weak = Arc::downgrade(&connection);
        let ping_interval = self.config.ping_interval;
        let pong_timeout = self.config.pong_timeout;

        let ping_task = tokio::spawn(async move {
            let mut interval = interval(ping_interval);
            loop {
                interval.tick().await;
                if let Some(conn) = connection_weak.upgrade() {
                    conn.update_activity().await;
                } else {
                    break;
                }
            }
        });

        let client_to_backend = async {
            while let Some(msg) = client_rx.next().await {
                match msg {
                    Ok(message) => {
                        if message.is_text() || message.is_binary() {
                            connection.add_bytes_received(message.len() as u64).await;
                            connection.update_activity().await;
                        }

                        if message.len() > self.config.max_message_size {
                            warn!("Message size {} exceeds limit {}", message.len(), self.config.max_message_size);
                            break;
                        }

                        if let Err(e) = backend_tx.send(message).await {
                            error!("Failed to forward message to backend: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Client WebSocket error: {}", e);
                        break;
                    }
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };

        let backend_to_client = async {
            while let Some(msg) = backend_rx.next().await {
                match msg {
                    Ok(message) => {
                        if message.is_text() || message.is_binary() {
                            connection.add_bytes_sent(message.len() as u64).await;
                            connection.update_activity().await;
                        }

                        if let Err(e) = client_tx.send(message).await {
                            error!("Failed to forward message to client: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Backend WebSocket error: {}", e);
                        break;
                    }
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };

        tokio::select! {
            result = client_to_backend => {
                if let Err(e) = result {
                    error!("Client to backend proxy error: {}", e);
                }
            }
            result = backend_to_client => {
                if let Err(e) = result {
                    error!("Backend to client proxy error: {}", e);
                }
            }
        }

        ping_task.abort();
        Ok(())
    }

    fn start_cleanup_task(&self) {
        let connections = Arc::clone(&self.connections);
        let connection_timeout = self.config.connection_timeout;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut connections = connections.write().await;
                
                connections.retain(|id, conn| {
                    let should_retain = now.duration_since(conn.created_at) < connection_timeout * 2;
                    if !should_retain {
                        debug!("Cleaning up stale WebSocket connection {}", id);
                    }
                    should_retain
                });
            }
        });
    }

    pub async fn get_connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    pub async fn get_connections(&self) -> Vec<(String, SocketAddr, SocketAddr, Duration, u64, u64)> {
        let connections = self.connections.read().await;
        let mut result = Vec::new();
        
        for (id, conn) in connections.iter() {
            let (duration, bytes_sent, bytes_received) = conn.get_stats().await;
            result.push((
                id.clone(),
                conn.client_addr,
                conn.backend_addr,
                duration,
                bytes_sent,
                bytes_received,
            ));
        }
        
        result
    }

    pub async fn close_connection(&self, connection_id: &str) -> bool {
        self.connections.write().await.remove(connection_id).is_some()
    }

    pub fn is_websocket_request(headers: &HashMap<String, String>) -> bool {
        headers.get("upgrade")
            .map(|v| v.to_lowercase() == "websocket")
            .unwrap_or(false) &&
        headers.get("connection")
            .map(|v| v.to_lowercase().contains("upgrade"))
            .unwrap_or(false)
    }

    pub fn get_websocket_key(headers: &HashMap<String, String>) -> Option<&String> {
        headers.get("sec-websocket-key")
    }
}

pub struct StickySession {
    sessions: Arc<RwLock<HashMap<String, (SocketAddr, Instant)>>>,
    session_timeout: Duration,
}

impl StickySession {
    pub fn new(session_timeout: Duration) -> Self {
        let sticky = Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_timeout,
        };
        sticky.start_cleanup_task();
        sticky
    }

    pub async fn get_backend_for_session(&self, session_id: &str) -> Option<SocketAddr> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id)
            .filter(|(_, last_seen)| last_seen.elapsed() < self.session_timeout)
            .map(|(addr, _)| *addr)
    }

    pub async fn set_backend_for_session(&self, session_id: String, backend: SocketAddr) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, (backend, Instant::now()));
    }

    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }

    fn start_cleanup_task(&self) {
        let sessions = Arc::clone(&self.sessions);
        let session_timeout = self.session_timeout;

        tokio::spawn(async move {
            let mut interval = interval(session_timeout / 2);
            loop {
                interval.tick().await;
                let mut sessions = sessions.write().await;
                sessions.retain(|_, (_, last_seen)| last_seen.elapsed() < session_timeout);
            }
        });
    }

    pub async fn get_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    pub fn extract_session_id_from_cookie(cookie_header: Option<&String>) -> Option<String> {
        cookie_header?
            .split(';')
            .find_map(|cookie| {
                let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                if parts.len() == 2 && parts[0] == "SESSIONID" {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            })
    }
}
