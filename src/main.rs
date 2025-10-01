mod auth;
mod buffer_pool;
mod config;
mod connection;
mod domain;
mod session;
mod socks;
mod traffic;

use crate::buffer_pool::{get_buffer, return_buffer};
use crate::config::{Cli, ProxyConfig};
use crate::connection::{
    get_ip_tracker, is_backlog_threshold_exceeded, is_memory_pressure_high, ConnectionGuard,
    ACTIVE_SOCKS5_CONNECTIONS, CONNECTION_BACKLOG_THRESHOLD, MAX_CONCURRENT_CONNECTIONS,
    MEMORY_PRESSURE_THRESHOLD,
};
use crate::domain::is_domain_allowed;
use crate::session::new_session_id;
use crate::socks::SocksConnector;
use crate::traffic::{get_counters_for_port, load_from_file, reset_port,
                     save_port_to_file, snapshot, TrafficCounters};
use clap::Parser;
use color_eyre::eyre::Result;
use hyper::body::{Body, Frame, SizeHint};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::signal;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::client::conn::http1::Builder;
use hyper::header::{HeaderValue, PROXY_AUTHENTICATE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use tokio::net::TcpListener;

/// RAII guard for buffer management
struct BufferGuard {
    buffer: Option<Vec<u8>>,
    large: bool,
}

impl BufferGuard {
    fn new(buffer: Vec<u8>, large: bool) -> Self {
        Self {
            buffer: Some(buffer),
            large,
        }
    }

    fn take(&mut self) -> Option<Vec<u8>> {
        self.buffer.take()
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            return_buffer(buffer, self.large);
        }
    }
}
// Body wrapper that counts data bytes passing through
#[derive(Debug, Clone, Copy)]
enum CountDir {
    Rx,
    Tx,
}

#[pin_project]
#[derive(Debug)]
struct CountingBody<B> {
    #[pin]
    inner: B,
    counters: Arc<TrafficCounters>,
    dir: CountDir,
}

impl<B> Body for CountingBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Count data bytes if present
                if let Some(data) = frame.data_ref() {
                    match this.dir {
                        CountDir::Rx => this.counters.add_rx(data.len() as u64),
                        CountDir::Tx => this.counters.add_tx(data.len() as u64),
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("sthp=warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    color_eyre::install()?;

    let args = Cli::parse();

    // Create proxy configuration from CLI arguments
    let config = Arc::new(ProxyConfig::from_cli(args).await?);

    info!("HTTP Proxy listening on http://{}", config.listen_addr);
    info!("SOCKS5 backend: {}", config.socks_addr);

    if config.soax_settings.enabled {
        info!(
            "SOAX sticky per-connection enabled; sessionlength={}s",
            config.soax_settings.sessionlength
        );
    }

    // Precompute shared auth/domain configuration to avoid per-connection cloning
    let http_basic = Arc::new(config.http_basic_auth.clone());
    let allowed_domains = Arc::new(config.allowed_domains.clone());

    // Traffic counters for this listening port
    let listen_port = config.listen_addr.port();
    let traffic_counters = get_counters_for_port(listen_port);
    // Compute stats file path from config
    let stats_path = get_stats_path(&config);
    // Load persisted traffic counters for this port (if any)
    if let Err(e) = load_from_file(&stats_path) {
        warn!("Failed to load traffic stats from {:?}: {}", stats_path, e);
    }

    // Periodically log and persist traffic stats
    {
        let counters = Arc::clone(&traffic_counters);
        let stats_path = stats_path.clone();
        let interval = config.stats_interval.max(1);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                let (rx, tx) = counters.get();
                info!("Traffic[port={}]: rx={}B, tx={}B", listen_port, rx, tx);
                if let Err(e) = save_port_to_file(listen_port, &stats_path) {
                    warn!("Failed to save traffic stats: {}", e);
                }
            }
        });
    }

    // Create SOCKS5 connector
    let socks_connector = Arc::new(SocksConnector::new(
        config.socks_addr,
        Arc::new(config.socks_auth.clone()),
        Arc::new(config.vendor_password.clone()),
        Arc::new(config.soax_settings.clone()),
        Arc::new(config.connpnt_settings.clone()),
    ));

    let listener = TcpListener::bind(config.listen_addr).await?;

    // Add a simplified connection monitoring task
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
        let mut last_active_count = 0;
        let mut stable_count_intervals = 0;

        loop {
            interval.tick().await;

            let active = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);

            // Periodic cleanup of IP tracker to remove zero-count entries
            let ip_tracker = get_ip_tracker();
            let cleaned = ip_tracker.cleanup_zero_connections();
            if cleaned > 0 {
                info!("Cleaned up {} zero-connection IP entries", cleaned);
            }

            // Only log when there are significant changes or high activity
            if active > 100 || (active > 0 && active != last_active_count) {
                info!("SOCKS5 Status - Active connections: {}", active);
            }

            // Detect potential connection leaks by monitoring stable high counts
            if active == last_active_count && active > 1000 {
                stable_count_intervals += 1;
                if stable_count_intervals >= 3 {
                    warn!(
                        "Potential connection leak detected: {} connections stable for {} intervals",
                        active, stable_count_intervals
                    );
                }
            } else {
                stable_count_intervals = 0;
            }

            // Alert on very high connection counts
            match active {
                0..=5000 => {
                    // Normal operation
                }
                5001..=15000 => {
                    info!("Moderate connection load: {} active", active);
                }
                15001..=25000 => {
                    warn!("High connection load: {} active", active);
                }
                _ => {
                    error!("CRITICAL connection load: {} active", active);
                }
            }

            last_active_count = active;
        }
    });

    // Graceful shutdown signal handling
    let shutdown = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");

        info!("Shutdown signal received");

        let active = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);
        if active > 0 {
            info!("Waiting for {} SOCKS5 connections to close...", active);

            for i in 1..=30 {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                let remaining = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);

                if remaining == 0 {
                    info!("All connections closed gracefully");
                    break;
                }

                if i % 5 == 0 {
                    info!("Still waiting for {} connections... ({}/30s)", remaining, i);
                }
            }

            let final_count = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);
            if final_count > 0 {
                warn!(
                    "Forced shutdown with {} connections still active",
                    final_count
                );
            }
        }
    };

    // Main server loop
    let server = async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    // Check per-IP connection limits atomically
                    let ip_tracker = get_ip_tracker();
                    let client_ip = peer_addr.ip();
                    let conn_limit = config.conn_per_ip;

                    // Atomically check and increment connection count
                    let new_count = match ip_tracker.try_increment(client_ip, conn_limit) {
                        Some(count) => count,
                        None => {
                            let current_count = ip_tracker.get_count(client_ip);
                            warn!(
                                "Connection limit exceeded for IP {}: {} connections (limit: {})",
                                client_ip, current_count, conn_limit
                            );
                            // Close the connection immediately
                            drop(stream);
                            continue;
                        }
                    };

                    if new_count > 20 {
                        info!(
                            "High connection count for IP {}: {} connections",
                            client_ip, new_count
                        );
                    }

                    // Clone Arc references for the spawned task
                    let socks_connector = Arc::clone(&socks_connector);
                    let http_basic = Arc::clone(&http_basic);
                    let allowed_domains = Arc::clone(&allowed_domains);
                    let config = Arc::clone(&config);
                    let traffic_counters2 = Arc::clone(&traffic_counters);
                    let sessionid = if config.soax_settings.enabled {
                        Some(new_session_id())
                    } else {
                        None
                    };
                    tokio::task::spawn(async move {
                        let io = TokioIo::new(stream);
                        let sess = sessionid.clone();
                        let counters = Arc::clone(&traffic_counters2);
                        let service = service_fn(move |req| {
                            proxy(
                                req,
                                Arc::clone(&socks_connector),
                                Arc::clone(&http_basic),
                                Arc::clone(&allowed_domains),
                                Arc::clone(&config),
                                sess.clone(),
                                Arc::clone(&counters),
                            )
                        });

                        if let Err(err) = http1::Builder::new()
                            .preserve_header_case(true)
                            .title_case_headers(true)
                            .serve_connection(io, service)
                            .with_upgrades()
                            .await
                        {
                            // Only log connection errors, not normal endings
                            if !err.to_string().contains("connection closed") {
                                warn!("Connection from {} error: {:?}", peer_addr, err);
                            }
                        }

                        // Decrement IP connection count when connection ends
                        ip_tracker.decrement(client_ip);
                    });
                }
                Err(e) => {
                    warn!("Accept error: {} (continuing)", e);
                    continue;
                }
            }
        }
    };

    // Run server until the shutdown signal is received
    tokio::select! {
        _ = server => {
            // Server loop ended unexpectedly
            warn!("Server loop terminated");
        }
        _ = shutdown => {
            info!("Server shutdown complete");
        }
    }

    Ok(())
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
    socks_connector: Arc<SocksConnector>,
    http_basic: Arc<Option<HeaderValue>>,
    allowed_domains: Arc<Option<HashSet<String>>>,
    config: Arc<ProxyConfig>,
    sessionid: Option<String>,
    traffic_counters: Arc<TrafficCounters>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Early return for disabled authentication
    if config.no_httpauth {
        // Authentication is disabled, proceed
    } else {
        let headers = req.headers();

        // Early return if no authorization header
        let auth_header = match headers.get(hyper::header::PROXY_AUTHORIZATION) {
            Some(header) => header,
            None => {
                // When the request does not contain a Proxy-Authorization header,
                // send a 407 response with Proxy-Authenticate header
                return Ok(proxy_auth_required_response(
                    "Proxy authentication required",
                ));
            }
        };

        // Early return for authentication failure
        match http_basic.as_ref() {
            Some(expected_auth) => {
                if auth_header != expected_auth {
                    warn!("Failed to authenticate: {:?}", headers);
                    return Ok(proxy_auth_required_response(
                        "Proxy authentication required",
                    ));
                }
            }
            None => {
                warn!("HTTP Basic auth not configured but required");
                return Ok(proxy_auth_required_response(
                    "Proxy authentication required",
                ));
            }
        }
    }
    // Management endpoints (require auth if enabled)
    // Reset first
    if req.method() == Method::POST && req.uri().path() == "/stats/reset" {
        let port = config.listen_addr.port();
        reset_port(port);
        let stats_path = get_stats_path(&config);
        if let Err(e) = save_port_to_file(port, &stats_path) {
            warn!("Failed to persist stats after reset: {}", e);
        }
        return Ok(json_response("{\"ok\":true}".to_string()));
    }
    // Then GET stats
    if req.method() == Method::GET && req.uri().path() == "/stats" {
        let port = config.listen_addr.port();
        let (rx, tx) = snapshot(port).unwrap_or((0, 0));
        let body = format!("{{\"port\":{},\"rx\":{},\"tx\":{}}}", port, rx, tx);
        return Ok(json_response(body));
    }

    // Check domain access for non-CONNECT requests
    if let Some(request_domain) = req.uri().host() {
        if let Err(resp) = check_domain_access(allowed_domains.as_ref(), request_domain) {
            return Ok(*resp);
        }
    }

    if Method::CONNECT == req.method() {
        if let Some(addr) = host_addr(req.uri()) {
            let socks_connector = socks_connector.clone();
            // HTTPS (CONNECT) domain filtering based on allowed_domains
            // For CONNECT, the request URI is authority-form (host:port). Use authority().host().
            if let Some(authority) = req.uri().authority() {
                let host = authority.host();
                if let Err(resp) = check_domain_access(allowed_domains.as_ref(), host) {
                    return Ok(*resp);
                }
            }

            let idle_timeout = config.idle_timeout;
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(
                            upgraded,
                            addr,
                            socks_connector,
                            idle_timeout,
                            sessionid.clone(),
                            Arc::clone(&traffic_counters),
                        )
                        .await
                        {
                            warn!("server io error: {}", e);
                        };
                    }
                    Err(e) => warn!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(empty()))
        } else {
            warn!("CONNECT host is not socket addr: {:?}", req.uri());
            Ok(error_response(
                http::StatusCode::BAD_REQUEST,
                "CONNECT must be to a socket address",
            ))
        }
    } else {
        let host = match req.uri().host() {
            Some(h) => h,
            None => {
                warn!("HTTP request missing host: {:?}", req.uri());
                return Ok(error_response(
                    http::StatusCode::BAD_REQUEST,
                    "HTTP request missing host",
                ));
            }
        };
        let port = req.uri().port_u16().unwrap_or(80);
        let addr = format!("{}:{}", host, port);

        let mut connection_guard = match ConnectionGuard::try_new() {
            Some(guard) => guard,
            None => {
                let current_connections = ConnectionGuard::active_count();
                warn!(
                    "Connection limit reached: {} (max: {})",
                    current_connections, MAX_CONCURRENT_CONNECTIONS
                );
                return Ok(error_response(
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    "Server overloaded, please try again later",
                ));
            }
        };
        let conn_id = ConnectionGuard::active_count();

        // Multi-level warning system for high-capacity server
        if is_memory_pressure_high() {
            let current_connections = ConnectionGuard::active_count();
            error!(
                "Critical connection count: {} (memory pressure threshold: {})",
                current_connections, MEMORY_PRESSURE_THRESHOLD
            );
        } else if is_backlog_threshold_exceeded() {
            let current_connections = ConnectionGuard::active_count();
            warn!(
                "High connection count: {} (threshold: {})",
                current_connections, CONNECTION_BACKLOG_THRESHOLD
            );
        } else {
            let current_connections = ConnectionGuard::active_count();
            if current_connections > 20000 {
                info!("Moderate connection load: {}", current_connections);
            }
        }
        // Count HTTP request body bytes (client -> proxy)
        let req = req.map(|b| CountingBody {
            inner: b,
            counters: Arc::clone(&traffic_counters),
            dir: CountDir::Rx,
        });

        let socks_stream = match socks_connector
            .connect(addr.as_str(), sessionid.as_deref())
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                // Ensure connection guard is properly decremented on error
                connection_guard.decrement();
                warn!("Upstream SOCKS5 connection #{} failed: {}", conn_id, e);
                return Ok(error_response(
                    http::StatusCode::BAD_GATEWAY,
                    "SOCKS5 connection failed",
                ));
            }
        };

        // Optionally force Connection: close for stability (prevents CLOSE_WAIT issues)
        // This trades some performance for better connection management
        let mut req = req;
        if config.force_close {
            req.headers_mut()
                .insert("connection", HeaderValue::from_static("close"));
        }

        let io = TokioIo::new(socks_stream);

        let (mut sender, conn) = Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;

        // Drive the connection and ensure cleanup even if the request times out
        let conn_handle = tokio::spawn(async move {
            if let Err(err) = conn.await {
                // Only log significant connection errors
                if !err.to_string().contains("connection closed") {
                    warn!("HTTP #{} connection error: {:?}", conn_id, err);
                }
            }
        });

        // Apply idle timeout with activity monitoring for HTTP requests
        let timeout_duration = tokio::time::Duration::from_secs(config.idle_timeout);
        let idle_timer = tokio::time::sleep(timeout_duration);
        tokio::pin!(idle_timer);

        let mut request_future = Box::pin(sender.send_request(req));

        let resp = tokio::select! {
            result = &mut request_future => {
                match result {
                    Ok(resp) => {
                        resp
                    },
                    Err(e) => {
                        conn_handle.abort();
                        connection_guard.decrement();
                        let remaining = ConnectionGuard::active_count();
                        warn!("HTTP #{} connection error, {} active", conn_id, remaining);
                        return Err(e);
                    }
                }
            }
            _ = &mut idle_timer => {
                // Timeout reached - abort the connection
                conn_handle.abort();
                connection_guard.decrement();
                let remaining = ConnectionGuard::active_count();
                warn!(
                    "HTTP #{} timeout after {:?}, {} active",
                    conn_id, timeout_duration, remaining
                );
                return Ok(error_response(
                    http::StatusCode::GATEWAY_TIMEOUT,
                    "Request timeout"
                ));
            }
        };

        // We are done initiating the request. Keep the connection driver running
        // in the background until it finishes to ensure the response body is fully
        // streamed and resources are cleaned up properly. In hyper's (sender, conn)
        // model, `conn` is the I/O driver; keeping it alive is sufficient—no need
        // to await sender.closed() here.

        // Spawn a task to handle connection cleanup properly
        // Important: We must not drop this task handle to ensure cleanup happens
        tokio::spawn(async move {
            // Wait for connection driver to finish to ensure proper cleanup
            let _ = conn_handle.await; // wait for connection driver to finish
            drop(connection_guard); // RAII drop -> decrement
        });
        // Intentionally do not abort conn_handle; it will finish when the connection shuts down.

        // Count HTTP response body bytes (proxy -> client)
        let resp = resp.map(|b| {
            CountingBody {
                inner: b,
                counters: Arc::clone(&traffic_counters),
                dir: CountDir::Tx,
            }
            .boxed()
        });

        // Return the response body as-is; hyper will forward it to the client
        Ok(resp)
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

/// Helper function to create an empty response body
fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Helper function to create a full response body
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Helper function to create an error response with status code
fn error_response(
    status: http::StatusCode,
    message: &'static str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full(message));
    *resp.status_mut() = status;
    resp
}

/// Helper function to create a JSON response
fn json_response(body: String) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full(body));
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Helper function to create a 407 Proxy Authentication Required response
fn proxy_auth_required_response(msg: &'static str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut response = Response::new(full(msg));
    *response.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    response.headers_mut().insert(
        PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"proxy\""),
    );
    response
}

/// Helper function to compute stats file path
fn get_stats_path(config: &ProxyConfig) -> PathBuf {
    let port = config.listen_addr.port();
    match &config.stats_dir {
        Some(dir) => PathBuf::from(dir).join(format!("traffic_stats_{}.txt", port)),
        None => PathBuf::from(format!("traffic_stats_{}.txt", port)),
    }
}

/// Helper function to check domain access
fn check_domain_access(
    allowed_domains: &Option<HashSet<String>>,
    domain: &str,
) -> Result<(), Box<Response<BoxBody<Bytes, hyper::Error>>>> {
    if let Some(allowed) = allowed_domains {
        if !is_domain_allowed(allowed, domain) {
            warn!(
                "Access to domain {} is not allowed through the proxy.",
                domain
            );
            return Err(Box::new(error_response(
                http::StatusCode::FORBIDDEN,
                "Access to this domain is not allowed through the proxy.",
            )));
        }
    }
    Ok(())
}

async fn tunnel(
    upgraded: Upgraded,
    addr: String,
    socks_connector: Arc<SocksConnector>,
    idle_timeout: u64,
    sessionid: Option<String>,
    traffic_counters: Arc<TrafficCounters>,
) -> Result<()> {
    let _connection_guard = match ConnectionGuard::try_new() {
        Some(guard) => guard,
        None => {
            let current_connections = ConnectionGuard::active_count();
            warn!(
                "Tunnel connection limit reached: {} (max: {})",
                current_connections, MAX_CONCURRENT_CONNECTIONS
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "Server overloaded",
            )
            .into());
        }
    };
    let conn_id = ConnectionGuard::active_count();

    let socks_stream = match socks_connector
        .connect(addr.as_str(), sessionid.as_deref())
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            // Connection guard will be automatically dropped here, decrementing the counter
            return Err(color_eyre::eyre::eyre!(
                "Upstream SOCKS5 connection failed: {}",
                e
            ));
        }
    };

    let mut client = TokioIo::new(upgraded);
    let mut server = socks_stream;

    // Idle-aware bidirectional copy with immediate connection close detection
    let timeout = tokio::time::Duration::from_secs(idle_timeout);
    let mut from_client = 0u64;
    let mut from_server = 0u64;

    // Use buffer pool for memory optimization with RAII guards
    let use_large_buffers = idle_timeout > 300;
    let client_buf = get_buffer(use_large_buffers);
    let server_buf = get_buffer(use_large_buffers);
    let mut client_guard = BufferGuard::new(client_buf, use_large_buffers);
    let mut server_guard = BufferGuard::new(server_buf, use_large_buffers);
    let mut client_buf = client_guard.take().unwrap();
    let mut server_buf = server_guard.take().unwrap();
    let idle = tokio::time::sleep(timeout);
    tokio::pin!(idle);
    let mut error: Option<color_eyre::eyre::Error> = None;

    loop {
        tokio::select! {
            res = client.read(&mut client_buf) => {
                match res {
                    Ok(0) => {
                        // Client connection closed normally
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = server.write_all(&client_buf[..n]).await {
                            warn!("Tunnel #{} server write error: {}", conn_id, e);
                            error = Some(e.into());
                            break;
                        }
                        from_client += n as u64;
                        idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                    }
                    Err(e) => {
                        warn!("Tunnel #{} client read error: {}", conn_id, e);
                        error = Some(e.into());
                        break;
                    }
                }
            }
            res = server.read(&mut server_buf) => {
                match res {
                    Ok(0) => {
                        // Server connection closed normally
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = client.write_all(&server_buf[..n]).await {
                            warn!("Tunnel #{} client write error: {}", conn_id, e);
                            error = Some(e.into());
                            break;
                        }
                        from_server += n as u64;
                        idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                    }
                    Err(e) => {
                        warn!("Tunnel #{} server read error: {}", conn_id, e);
                        error = Some(e.into());
                        break;
                    }
                }
            }
            _ = &mut idle => {
                warn!("Tunnel #{} idle timeout after {:?}, closing", conn_id, timeout);
                break;
            }
        }
    }

    // Accumulate per-port traffic counters for CONNECT tunnel path
    traffic_counters.add_rx(from_client);
    traffic_counters.add_tx(from_server);

    if let Err(e) = server.shutdown().await {
        // Only log unexpected shutdown errors
        if !e.to_string().contains("connection closed") && !e.to_string().contains("broken pipe") {
            warn!("Server shutdown error: {}", e);
        }
    }
    if let Err(e) = client.shutdown().await {
        // Only log unexpected shutdown errors
        if !e.to_string().contains("connection closed") && !e.to_string().contains("broken pipe") {
            warn!("Client shutdown error: {}", e);
        }
    }

    drop(server);
    drop(client);

    // Return buffers to pool for reuse via RAII guards
    let _client_guard = BufferGuard::new(client_buf, use_large_buffers);
    let _server_guard = BufferGuard::new(server_buf, use_large_buffers);
    // Guards will automatically return buffers when dropped

    // connection_guard will be automatically decremented when dropped
    let remaining = ConnectionGuard::active_count();

    // Only log stats for very large transfers to reduce noise
    if from_client + from_server > 10_485_760 {
        // 10MB threshold
        info!(
            "Tunnel #{} completed large transfer: {}↑ {}↓ bytes, {} active",
            conn_id, from_client, from_server, remaining
        );
    }
    if let Some(e) = error {
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use base64::Engine;
    use hyper::header::HeaderValue;

    #[test]
    fn test_http_basic_auth_header_creation() {
        // Test that we can create HeaderValue from HTTP Basic auth string
        let auth_string = "Basic dGVzdDp0ZXN0"; // base64 encoded "test:test"
        let header_value = HeaderValue::from_str(&auth_string).expect("Valid header value");

        assert_eq!(header_value.to_str().unwrap(), auth_string);
    }

    #[test]
    fn test_base64_encoding() {
        // Test base64 encoding for HTTP Basic auth
        let credentials = "user:password";
        let encoded = general_purpose::STANDARD.encode(credentials);
        let auth_string = format!("Basic {}", encoded);

        // Should be able to create HeaderValue from this
        let _header_value = HeaderValue::from_str(&auth_string).expect("Valid header value");
    }

    #[test]
    fn test_hashset_domain_conversion() {
        // Test Vec to HashSet conversion
        let domains_vec = vec![
            "example.com".to_string(),
            "test.org".to_string(),
            "allowed.net".to_string(),
        ];

        let domains_hashset: HashSet<String> = domains_vec.into_iter().collect();

        assert!(domains_hashset.contains("example.com"));
        assert!(domains_hashset.contains("test.org"));
        assert!(domains_hashset.contains("allowed.net"));
        assert!(!domains_hashset.contains("blocked.com"));
        assert_eq!(domains_hashset.len(), 3);
    }

    #[test]
    fn test_domain_lookup_performance() {
        use std::time::Instant;

        // Create test data
        let domains: Vec<String> = (0..1000).map(|i| format!("domain{}.com", i)).collect();

        // Test Vec performance
        let domains_vec = domains.clone();
        let test_domain = "domain500.com";
        let iterations = 10000;

        let start = Instant::now();
        for _ in 0..iterations {
            let _found = domains_vec.contains(&test_domain.to_string());
        }
        let vec_duration = start.elapsed();

        // Test HashSet performance
        let domains_hashset: HashSet<String> = domains.into_iter().collect();

        let start = Instant::now();
        for _ in 0..iterations {
            let _found = domains_hashset.contains(test_domain);
        }
        let hashset_duration = start.elapsed();

        println!("Vec lookup: {:?}", vec_duration);
        println!("HashSet lookup: {:?}", hashset_duration);

        // HashSet should be significantly faster for large datasets
        assert!(hashset_duration < vec_duration);
    }
}
