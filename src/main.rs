mod auth;
mod buffer_pool;
mod config;
mod connection;
mod domain;
mod session;
mod socks;
mod traffic;

use crate::buffer_pool::lease_buffer;
use crate::config::{Cli, ProxyConfig, ListenMode};
use crate::connection::{
    get_ip_tracker, is_backlog_threshold_exceeded, is_memory_pressure_high, ConnectionGuard,
    ACTIVE_SOCKS5_CONNECTIONS, CONNECTION_BACKLOG_THRESHOLD, MAX_CONCURRENT_CONNECTIONS,
    MEMORY_PRESSURE_THRESHOLD,
};
use crate::domain::is_domain_allowed;
use crate::session::new_session_id;
use crate::socks::SocksConnector;

use crate::traffic::{
    get_counters_for_port, load_from_file, reset_port, save_port_to_file, snapshot, TrafficCounters,
};
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
use hyper::header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, CONNECTION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use hyper_util::rt::TokioIo;
use pin_project::{pin_project, pinned_drop};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

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

// Body wrapper that owns both the connection guard and the driver handle
// ensuring the handle is completed or aborted before the guard is released.
#[pin_project(PinnedDrop)]
/// Wraps an HTTP response body together with the bookkeeping required to keep
/// the connection count in sync with the lifecycle of the underlying IO task.
struct GuardedBody<B> {
    #[pin]
    inner: B,
    connection_guard: Option<ConnectionGuard>,
    driver_handle: Option<JoinHandle<()>>,
}

impl<B> GuardedBody<B> {
    fn new(inner: B, guard: ConnectionGuard, handle: JoinHandle<()>) -> Self {
        Self {
            inner,
            connection_guard: Some(guard),
            driver_handle: Some(handle),
        }
    }
}

impl<B> Body for GuardedBody<B>
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
            Poll::Ready(None) => {
                // Response body has finished streaming. Allow the upstream
                // connection driver to complete gracefully before releasing
                // the connection guard to avoid abrupt aborts.
                if let (Some(guard), Some(handle)) = (this.connection_guard.take(), this.driver_handle.take()) {
                    tokio::spawn(async move {
                        let _ = handle.await; // ignore join errors; connection likely closed
                        drop(guard);
                    });
                }
                Poll::Ready(None)
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

#[pinned_drop]
impl<B> PinnedDrop for GuardedBody<B> {
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();
        if let Some(handle) = this.driver_handle.take() {
            if !handle.is_finished() {
                handle.abort();
            }
        }

        // Ensure the connection guard is always released, even if the body is
        // dropped before reaching the end of stream (for example due to a
        // client disconnect or task cancellation).
        drop(this.connection_guard.take());
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

    if config.socks_listen_addr.is_some() {
        info!("HTTP Proxy listening on http://{}", config.listen_addr);
        info!("SOCKS5 Proxy listening on socks5://{}", config.socks_listen_addr.unwrap());
    } else {
        match config.mode {
            ListenMode::Http => info!("HTTP Proxy listening on http://{}", config.listen_addr),
            ListenMode::Socks => info!("SOCKS5 Proxy listening on socks5://{}", config.listen_addr),
        }
    }
    info!("Upstream SOCKS5: {}", config.socks_addr);

    if config.soax_settings.enabled {
        info!(
            "SOAX sticky per-connection enabled; sessionlength={}s",
            config.soax_settings.sessionlength
        );
    }

    // Precompute shared auth/domain configuration to avoid per-connection cloning
    let http_basic = Arc::new(config.http_basic_auth.clone());
    let allowed_domains = Arc::new(config.allowed_domains.clone());

    // Traffic counters and periodic stats for HTTP listener (if running on this process)
    let listen_port = config.listen_addr.port();
    let traffic_counters = get_counters_for_port(listen_port).await;
    let stats_path = get_stats_path(&config, listen_port);
    if let Err(e) = load_from_file(&stats_path).await {
        warn!("Failed to load traffic stats from {:?}: {}", stats_path, e);
    }
    {
        let counters = Arc::clone(&traffic_counters);
        let stats_path = stats_path.clone();
        let interval = config.stats_interval.max(1);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                let (rx, tx) = counters.get();
                info!("Traffic[port={}]: rx={}B, tx={}B", listen_port, rx, tx);
                if let Err(e) = save_port_to_file(listen_port, &stats_path).await {
                    warn!("Failed to save traffic stats: {}", e);
                }
            }
        });
    }

    // If an additional SOCKS listener is configured, initialize its counters and stats tasks
    let (socks_extra_listener, traffic_counters_socks, _stats_path_socks) = if let Some(saddr) = &config.socks_listen_addr {
        let sport = saddr.port();
        let counters = get_counters_for_port(sport).await;
        let path = get_stats_path(&config, sport);
        if let Err(e) = load_from_file(&path).await {
            warn!("Failed to load traffic stats from {:?}: {}", path, e);
        }
        {
            let counters = Arc::clone(&counters);
            let path = path.clone();

            let interval = config.stats_interval.max(1);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    let (rx, tx) = counters.get();
                    info!("Traffic[port={}]: rx={}B, tx={}B", sport, rx, tx);
                    if let Err(e) = save_port_to_file(sport, &path).await {
                        warn!("Failed to save traffic stats: {}", e);
                    }
                }
            });
        }
        (Some(*saddr), Some(counters), Some(path))
    } else {
        (None, None, None)
    };

    // Create SOCKS5 connector
    let socks_connector = build_socks_connector(config.as_ref());

    let listener = TcpListener::bind(config.listen_addr).await?;
    // Optional extra SOCKS listener bound if configured
    let mut extra_socks_listener: Option<TcpListener> = None;
    if let Some(addr) = socks_extra_listener {
        match TcpListener::bind(addr).await {
            Ok(l) => extra_socks_listener = Some(l),
            Err(e) => warn!("Failed to bind extra SOCKS listener on {}: {}", addr, e),
        }
    }

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
            let cleaned = ip_tracker.cleanup_zero_connections().await;
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
    // Clone Arcs specifically for the main server loop so originals remain for the extra listener
    let sc_for_server = Arc::clone(&socks_connector);
    let hb_for_server = Arc::clone(&http_basic);
    let ad_for_server = Arc::clone(&allowed_domains);
    let cfg_for_server = Arc::clone(&config);

    // Main server loop
    let server = async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    // Check per-IP connection limits atomically
                    let client_ip = peer_addr.ip();
                    let conn_limit = cfg_for_server.conn_per_ip;
                    if try_register_connection(client_ip, conn_limit).await.is_none() {
                        // Close the connection immediately
                        drop(stream);
                        continue;
                    }

                    // Clone Arc references for the spawned task
                    let socks_connector = Arc::clone(&sc_for_server);
                    let http_basic = Arc::clone(&hb_for_server);
                    let allowed_domains = Arc::clone(&ad_for_server);
                    let config = Arc::clone(&cfg_for_server);
                    let traffic_counters2 = Arc::clone(&traffic_counters);
                    let sessionid = if config.soax_settings.enabled {
                        Some(new_session_id())
                    } else {
                        None
                    };
                    tokio::task::spawn(async move {
                        let http_on_main = config.socks_listen_addr.is_some() || config.mode == ListenMode::Http;
                        if http_on_main {
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
                        } else {
                            if let Err(err) = handle_socks5_client(
                                stream,
                                peer_addr,
                                Arc::clone(&socks_connector),
                                Arc::clone(&allowed_domains),
                                Arc::clone(&config),
                                sessionid.clone(),
                                Arc::clone(&traffic_counters2),
                            ).await {
                                warn!("SOCKS5 client {} error: {:?}", peer_addr, err);
                            }
                        }

                        // Decrement IP connection count when connection ends
                        get_ip_tracker().decrement(client_ip).await;
                    });
                }
                Err(e) => {
                    warn!("Accept error: {} (continuing)", e);
                    continue;
                }
            }
        }
    };

    // Spawn accept loop for extra SOCKS listener if present
    if let Some(listener2) = extra_socks_listener {
        let socks_connector = Arc::clone(&socks_connector);
        let allowed_domains = Arc::clone(&allowed_domains);
        let config = Arc::clone(&config);
        let traffic_counters2 = Arc::clone(traffic_counters_socks.as_ref().expect("socks counters must be initialized"));
        tokio::spawn(async move {
            loop {
                match listener2.accept().await {
                    Ok((stream, peer_addr)) => {
                        let client_ip = peer_addr.ip();
                        let conn_limit = config.conn_per_ip;
                        if try_register_connection(client_ip, conn_limit).await.is_none() {
                            drop(stream);
                            continue;
                        }

                        let socks_connector = Arc::clone(&socks_connector);
                        let allowed_domains = Arc::clone(&allowed_domains);
                        let config = Arc::clone(&config);
                        let counters = Arc::clone(&traffic_counters2);
                        let sessionid = if config.soax_settings.enabled { Some(new_session_id()) } else { None };
                        tokio::spawn(async move {
                            if let Err(err) = handle_socks5_client(
                                stream,
                                peer_addr,
                                socks_connector,
                                allowed_domains,
                                config,
                                sessionid,
                                counters,
                            ).await {
                                warn!("SOCKS5 client {} error: {:?}", peer_addr, err);
                            }
                            get_ip_tracker().decrement(client_ip).await;
                        });
                    }
                    Err(e) => {
                        warn!("Accept error (extra socks): {} (continuing)", e);
                        continue;
                    }
                }
            }
        });
    }

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
    if let Some(resp) = check_proxy_auth(req.headers(), http_basic.as_ref(), config.no_httpauth) {
        return Ok(resp);
    }
    // Management endpoints (require auth if enabled)
    // Reset first
    if req.method() == Method::POST && req.uri().path() == "/stats/reset" {
        let port = config.listen_addr.port();
        reset_port(port).await;
        let stats_path = get_stats_path(&config, port);
        if let Err(e) = save_port_to_file(port, &stats_path).await {
            warn!("Failed to persist stats after reset: {}", e);
        }
        return Ok(json_response("{\"ok\":true}".to_string()));
    }
    // Then GET stats
    if req.method() == Method::GET && req.uri().path() == "/stats" {
        let port = config.listen_addr.port();
        let (rx, tx) = snapshot(port).await.unwrap_or((0, 0));
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
            Some(guard) => Some(guard),
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
                if let Some(guard) = connection_guard.take() {
                    drop(guard);
                }
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
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }

        {
            // Remove proxy-specific headers so upstream servers never see proxy credentials.
            let headers = req.headers_mut();
            headers.remove(PROXY_AUTHORIZATION);
            headers.remove("proxy-connection");
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
                        if let Some(guard) = connection_guard.take() {
                            drop(guard);
                        }
                        let remaining = ConnectionGuard::active_count();
                        warn!("HTTP #{} connection error, {} active", conn_id, remaining);
                        return Err(e);
                    }
                }
            }
            _ = &mut idle_timer => {
                // Timeout reached - abort the connection
                conn_handle.abort();
                if let Some(guard) = connection_guard.take() {
                    drop(guard);
                }
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

        // Wrap the response body with counting and guard ownership
        // The GuardedBody will own the ConnectionGuard and conn_handle,
        // ensuring proper cleanup when the body is dropped without needing
        // a separate spawned task. This reduces scheduler overhead.
        let guard = connection_guard
            .take()
            .expect("connection_guard should exist when mapping response body");
        let counters = Arc::clone(&traffic_counters);
        let resp = resp.map(move |b| {
            let counting_body = CountingBody {
                inner: b,
                counters: Arc::clone(&counters),
                dir: CountDir::Tx,
            };
            GuardedBody::new(counting_body, guard, conn_handle).boxed()
        });

        // Return the response body as-is; hyper will forward it to the client
        // The ConnectionGuard will be automatically dropped when the body finishes
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

/// Helper function to compute stats file path for a specific port
fn get_stats_path(config: &ProxyConfig, port: u16) -> PathBuf {
    match &config.stats_dir {
        Some(dir) => PathBuf::from(dir).join(format!("traffic_stats_{}.txt", port)),
        None => PathBuf::from(format!("traffic_stats_{}.txt", port)),
    }
}

/// Validate proxy authentication and return an early response if unauthorized
fn check_proxy_auth(
    headers: &http::HeaderMap,
    http_basic: &Option<HeaderValue>,
    no_httpauth: bool,
) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
    if no_httpauth {
        return None;
    }

    // Require Proxy-Authorization header
    let auth_header = match headers.get(PROXY_AUTHORIZATION) {
        Some(h) => h,
        None => {
            return Some(proxy_auth_required_response(
                "Proxy authentication required",
            ));
        }
    };

    match http_basic {
        Some(expected) => {
            if auth_header != expected {
                warn!("Proxy authentication failed (invalid or mismatched credentials)");
                Some(proxy_auth_required_response(
                    "Proxy authentication required",
                ))
            } else {
                None
            }
        }
        None => {
            warn!("HTTP Basic auth not configured but required");
            Some(proxy_auth_required_response(
                "Proxy authentication required",
            ))
        }
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
    let mut client_lease = lease_buffer(use_large_buffers).await;
    let mut server_lease = lease_buffer(use_large_buffers).await;
    let idle = tokio::time::sleep(timeout);
    tokio::pin!(idle);
    let mut error: Option<color_eyre::eyre::Error> = None;

    loop {
        tokio::select! {
            res = client.read(client_lease.as_mut_slice()) => {
                match res {
                    Ok(0) => {
                        // Client connection closed normally
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = server.write_all(&client_lease.as_mut_slice()[..n]).await {
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
            res = server.read(server_lease.as_mut_slice()) => {
                match res {
                    Ok(0) => {
                        // Server connection closed normally
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = client.write_all(&server_lease.as_mut_slice()[..n]).await {
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

// Read exactly buf.len() bytes from stream within the given duration; used for SOCKS5 handshakes
async fn read_exact_timeout(
    stream: &mut tokio::net::TcpStream,
    buf: &mut [u8],
    dur: std::time::Duration,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    match tokio::time::timeout(dur, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake read timeout")),
    }
}

// Helper: build a SocksConnector from config to avoid duplicate field cloning
fn build_socks_connector(cfg: &ProxyConfig) -> Arc<SocksConnector> {
    Arc::new(SocksConnector::new(
        cfg.socks_addr,
        Arc::new(cfg.socks_auth.clone()),
        Arc::new(cfg.vendor_password.clone()),
        Arc::new(cfg.soax_settings.clone()),
        Arc::new(cfg.connpnt_settings.clone()),
    ))
}

// Helper: register per-IP connection; returns Some(count) if allowed, None if rejected
async fn try_register_connection(client_ip: std::net::IpAddr, conn_limit: usize) -> Option<usize> {
    let ip_tracker = get_ip_tracker();
    match ip_tracker.try_increment(client_ip, conn_limit).await {
        Some(count) => {
            if count > 20 {
                info!("High connection count for IP {}: {} connections", client_ip, count);
            }
            Some(count)
        }
        None => {
            let current_count = ip_tracker.get_count(client_ip).await;
            warn!(
                "Connection limit exceeded for IP {}: {} connections (limit: {})",
                client_ip, current_count, conn_limit
            );
            None
        }
    }
}

async fn handle_socks5_client(
    mut client: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    socks_connector: Arc<SocksConnector>,
    allowed_domains: Arc<Option<HashSet<String>>>,
    config: Arc<ProxyConfig>,
    sessionid: Option<String>,
    traffic_counters: Arc<TrafficCounters>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connection guard to cap concurrent tunnels
    let _connection_guard = match ConnectionGuard::try_new() {
        Some(guard) => guard,
        None => {
            let current_connections = ConnectionGuard::active_count();
            warn!(
                "SOCKS5 connection limit reached: {} (max: {})",
                current_connections, MAX_CONCURRENT_CONNECTIONS
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "Server overloaded",
            )
            .into());
        }
    };
    // Per-step read timeout for SOCKS5 handshake/auth/request to mitigate slowloris
    let hs_timeout = std::time::Duration::from_secs(10);

    // 1) Handshake: read methods
    let mut header = [0u8; 2];
    read_exact_timeout(&mut client, &mut header, hs_timeout).await?;

    if header[0] != 0x05 {
        return Err(color_eyre::eyre::eyre!("Unsupported SOCKS version {}", header[0]));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        read_exact_timeout(&mut client, &mut methods, hs_timeout).await?;
    }
    let need_auth = config.socks_in_auth.is_some();
    let chosen = if need_auth { 0x02 } else { 0x00 };
    if !methods.iter().any(|&m| m == chosen) {
        // No acceptable methods
        let _ = client.write_all(&[0x05, 0xFF]).await;
        return Err(color_eyre::eyre::eyre!(
            "Client did not offer required auth method (need {}): {:?}",
            if need_auth { "username/password" } else { "noauth" },
            methods
        ));
    }
    client.write_all(&[0x05, chosen]).await?;

    // 2) Optional username/password auth (RFC 1929)
    if chosen == 0x02 {
        let mut ver = [0u8; 1];
        read_exact_timeout(&mut client, &mut ver, hs_timeout).await?;
        if ver[0] != 0x01 {
            let _ = client.write_all(&[0x01, 0x01]).await; // failure
            return Err(color_eyre::eyre::eyre!("Invalid auth version {}", ver[0]));
        }
        // username
        let mut ulen = [0u8; 1];
        read_exact_timeout(&mut client, &mut ulen, hs_timeout).await?;
        let ulen = ulen[0] as usize;
        let mut ubuf = vec![0u8; ulen];
        if ulen > 0 {
            read_exact_timeout(&mut client, &mut ubuf, hs_timeout).await?;
        }
        // password
        let mut plen = [0u8; 1];
        read_exact_timeout(&mut client, &mut plen, hs_timeout).await?;
        let plen = plen[0] as usize;
        let mut pbuf = vec![0u8; plen];
        if plen > 0 {
            read_exact_timeout(&mut client, &mut pbuf, hs_timeout).await?;
        }
        let user = String::from_utf8_lossy(&ubuf).to_string();
        let pass = String::from_utf8_lossy(&pbuf).to_string();
        match &config.socks_in_auth {
            Some(expected) if expected.username == user && expected.password == pass => {
                client.write_all(&[0x01, 0x00]).await?; // success
            }
            _ => {
                let _ = client.write_all(&[0x01, 0x01]).await; // failure
                return Err(color_eyre::eyre::eyre!("SOCKS5 inbound auth failed for {peer_addr}"));
            }
        }
    }

    // 3) Request: CONNECT only
    let mut req_hdr = [0u8; 4];
    read_exact_timeout(&mut client, &mut req_hdr, hs_timeout).await?;
    if req_hdr[0] != 0x05 {
        return Err(color_eyre::eyre::eyre!("Invalid request version {}", req_hdr[0]));
    }
    if req_hdr[1] != 0x01 {
        // Command not supported
        let _ = client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err(color_eyre::eyre::eyre!("Unsupported SOCKS5 cmd {}", req_hdr[1]));
    }
    // Strictly validate reserved field (RSV) must be 0x00
    if req_hdr[2] != 0x00 {
        let _ = client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await; // general failure
        return Err(color_eyre::eyre::eyre!("Invalid RSV in SOCKS5 request: {}", req_hdr[2]));
    }

    let atyp = req_hdr[3];

    // destination address
    let mut domain_opt: Option<String> = None;
    let dest_host_port = match atyp {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            read_exact_timeout(&mut client, &mut ip, hs_timeout).await?;
            let mut portb = [0u8; 2];
            read_exact_timeout(&mut client, &mut portb, hs_timeout).await?;
            let port = u16::from_be_bytes(portb);
            let host = std::net::Ipv4Addr::from(ip);
            format!("{}:{}", host, port)
        }
        0x03 => {
            // Domain
            let mut len = [0u8; 1];
            read_exact_timeout(&mut client, &mut len, hs_timeout).await?;
            let len = len[0] as usize;
            let mut dom = vec![0u8; len];
            if len > 0 { read_exact_timeout(&mut client, &mut dom, hs_timeout).await?; }
            let mut portb = [0u8; 2];
            read_exact_timeout(&mut client, &mut portb, hs_timeout).await?;
            let port = u16::from_be_bytes(portb);
            let domain = String::from_utf8_lossy(&dom).to_string();
            domain_opt = Some(domain.clone());
            format!("{}:{}", domain, port)
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            read_exact_timeout(&mut client, &mut ip, hs_timeout).await?;
            let mut portb = [0u8; 2];
            read_exact_timeout(&mut client, &mut portb, hs_timeout).await?;
            let port = u16::from_be_bytes(portb);
            let host = std::net::Ipv6Addr::from(ip);
            format!("[{}]:{}", host, port)
        }
        _ => {
            let _ = client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(color_eyre::eyre::eyre!("Address type not supported: {}", atyp));
        }
    };

    // Domain allowlist check (if applicable)
    if let (Some(allowed), Some(domain)) = (allowed_domains.as_ref(), domain_opt.as_ref()) {
        if !is_domain_allowed(allowed, domain) {
            let _ = client
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            warn!("Access to domain {} is not allowed (SOCKS mode)", domain);
            return Ok(());
        }
    }

    // 4) Connect upstream via SOCKS5
    let mut server = match socks_connector.connect(dest_host_port.as_str(), sessionid.as_deref()).await {
        Ok(s) => s,
        Err(e) => {
            let _ = client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) // general failure
                .await;
            return Err(color_eyre::eyre::eyre!("Upstream SOCKS connect failed: {}", e));
        }
    };

    // 5) Reply success to client with local bound address (use inbound local socket info)
    let local = client.local_addr().ok();
    let (atyp, addr_bytes, port_bytes) = match local {
        Some(std::net::SocketAddr::V4(v4)) => (0x01u8, v4.ip().octets().to_vec(), v4.port().to_be_bytes()),
        Some(std::net::SocketAddr::V6(v6)) => (0x04u8, v6.ip().octets().to_vec(), v6.port().to_be_bytes()),
        None => (0x01u8, [0u8;4].to_vec(), 0u16.to_be_bytes()),
    };
    let mut reply = Vec::with_capacity(4 + addr_bytes.len() + 2);
    reply.extend_from_slice(&[0x05, 0x00, 0x00, atyp]);
    reply.extend_from_slice(&addr_bytes);
    reply.extend_from_slice(&port_bytes);
    client.write_all(&reply).await?;

    // 6) Bidirectional copy with idle timeout and traffic counters
    let timeout = tokio::time::Duration::from_secs(config.idle_timeout);
    let mut from_client = 0u64;
    let mut from_server = 0u64;

    let use_large_buffers = config.idle_timeout > 300;
    let mut client_lease = lease_buffer(use_large_buffers).await;
    let mut server_lease = lease_buffer(use_large_buffers).await;
    let idle = tokio::time::sleep(timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            res = client.read(client_lease.as_mut_slice()) => {
                match res {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = server.write_all(&client_lease.as_mut_slice()[..n]).await {
                            warn!("SOCKS tunnel server write error: {}", e); break;
                        }
                        from_client += n as u64;
                        idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                    }
                    Err(e) => { warn!("SOCKS tunnel client read error: {}", e); break; }
                }
            }
            res = server.read(server_lease.as_mut_slice()) => {
                match res {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = client.write_all(&server_lease.as_mut_slice()[..n]).await {
                            warn!("SOCKS tunnel client write error: {}", e); break;
                        }
                        from_server += n as u64;
                        idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                    }
                    Err(e) => { warn!("SOCKS tunnel server read error: {}", e); break; }
                }
            }
            _ = &mut idle => {
                warn!("SOCKS tunnel idle timeout after {:?}, closing", timeout);
                break;
            }
        }
    }

    traffic_counters.add_rx(from_client);
    traffic_counters.add_tx(from_server);

    let _ = server.shutdown().await;
    let _ = client.shutdown().await;
    Ok(())
}

#[cfg(test)]
fn base_proxy_config(port: u16) -> ProxyConfig {
    use crate::config::{SoaxSettings, ConnpntSettings};

    ProxyConfig {
        mode: ListenMode::Http,
        listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        socks_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 1080)),
        socks_listen_addr: None,
        allowed_domains: None,
        http_basic_auth: None,
        no_httpauth: true,
        idle_timeout: 60,
        conn_per_ip: 100,
        force_close: true,
        soax_settings: SoaxSettings { enabled: false, package_id: None, country: None, region: None, city: None, isp: None, sessionlength: 300, bindttl: None, idlettl: None, opts: vec![] },
        vendor_password: None,
        socks_auth: None,
        socks_in_auth: None,
        stats_dir: None,
        stats_interval: 60,
        connpnt_settings: ConnpntSettings { enabled: false, base_user: None, country: None, keeptime_minutes: 0, project: None, entry_hosts: vec![], socks_port: 9135 },
    }
}

#[cfg(test)]
fn basic_auth_header(user: &str, pass: &str) -> HeaderValue {
    use base64::Engine;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass))
    );
    HeaderValue::from_str(&expected).unwrap()
}

#[cfg(test)]
async fn spawn_in_memory_proxy(
    config: Arc<ProxyConfig>,
    counters: Arc<TrafficCounters>,
) -> (
    hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    JoinHandle<()>,
    JoinHandle<()>,
) {
    use hyper::client::conn::http1::Builder;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::sync::Arc;

    let socks = Arc::new(
        socks::SocksConnectorBuilder::new()
            .socks_addr(config.socks_addr)
            .build()
            .expect("builder should succeed"),
    );
    let http_basic = Arc::new(config.http_basic_auth.clone());
    let allowed = Arc::new(config.allowed_domains.clone());
    let counters_arc = counters.clone();

    let (client_io, server_io) = tokio::io::duplex(16 * 1024);

    let server = tokio::spawn(async move {
        let service = service_fn(move |req| {
            proxy(
                req,
                Arc::clone(&socks),
                Arc::clone(&http_basic),
                Arc::clone(&allowed),
                Arc::clone(&config),
                None,
                Arc::clone(&counters_arc),
            )
        });
        if let Err(e) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(server_io), service)
            .await
        {
            panic!("server error: {}", e);
        }
    });

    let (sender, conn) = Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(TokioIo::new(client_io))
        .await
        .expect("client handshake");
    let client_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    (sender, client_task, server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use base64::Engine;
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper::header::HeaderValue;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tokio::time::{timeout, Duration};
    use serial_test::serial;

    // Test helpers to reduce duplicated fragments (available to all tests below)
    // Read from stream until CRLFCRLF or timeout between reads; returns accumulated bytes
    async fn read_until_header_end(
        stream: &mut tokio::net::TcpStream,
        step_timeout: Duration,
    ) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            match tokio::time::timeout(step_timeout, stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                _ => break,
            }
        }
        buf
    }

    // Spawn a SOCKS accept loop that forwards clients to handle_socks5_client
    fn spawn_socks_accept_loop(
        socks_listener: TcpListener,
        sc: Arc<SocksConnector>,
        allowed: Arc<Option<HashSet<String>>>,
        cfg: Arc<ProxyConfig>,
        counters: Arc<TrafficCounters>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match socks_listener.accept().await { Ok(v) => v, Err(_) => break };
                let sc = Arc::clone(&sc);
                let ad = Arc::clone(&allowed);
                let cfg = Arc::clone(&cfg);
                let counters = Arc::clone(&counters);
                tokio::spawn(async move {
                    let _ = handle_socks5_client(stream, peer, sc, ad, cfg, None, counters).await;
                });
            }
        })
    }

    async fn spawn_fake_socks_upstream() -> (std::net::SocketAddr, JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream socks");
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await { Ok(v) => v, Err(_) => break };
                let mut g=[0u8;2]; if stream.read_exact(&mut g).await.is_err() { break; }
                let mut methods = vec![0u8; g[1] as usize]; if g[1]>0 { if stream.read_exact(&mut methods).await.is_err() { break; } }
                let _ = stream.write_all(&[0x05,0x00]).await; // no-auth
                let mut h=[0u8;4]; if stream.read_exact(&mut h).await.is_err() { break; }
                match h[3] {
                    0x01 => { let mut b=[0u8;4]; let _=stream.read_exact(&mut b).await; }
                    0x03 => { let mut l=[0u8;1]; let _=stream.read_exact(&mut l).await; let mut d=vec![0u8;l[0] as usize]; if l[0]>0 { let _=stream.read_exact(&mut d).await; } }
                    0x04 => { let mut b=[0u8;16]; let _=stream.read_exact(&mut b).await; }
                    _ => {}
                }
                let mut port=[0u8;2]; let _=stream.read_exact(&mut port).await;
                let _ = stream.write_all(&[0x05,0x00,0x00,0x01,0,0,0,0,0,0]).await; // success
                let _ = read_until_header_end(&mut stream, Duration::from_millis(500)).await;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
            }
        });
        (addr, task)
    }

    async fn verify_socks_success_and_http_ok(c: &mut tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut head=[0u8;4]; let _=c.read_exact(&mut head).await; assert_eq!(head[0], 0x05); assert_eq!(head[1], 0x00);
        match head[3] {
            0x01 => { let mut b=[0u8;4]; let _=c.read_exact(&mut b).await; }
            0x04 => { let mut b=[0u8;16]; let _=c.read_exact(&mut b).await; }
            0x03 => { let mut l=[0u8;1]; let _=c.read_exact(&mut l).await; let mut d=vec![0u8;l[0] as usize]; if l[0]>0 { let _=c.read_exact(&mut d).await; } }
            _ => {}
        }
        let mut port=[0u8;2]; let _=c.read_exact(&mut port).await;
        let _=c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        let buf = read_until_header_end(c, Duration::from_millis(800)).await;
        let txt=String::from_utf8_lossy(&buf); assert!(txt.contains("200 OK"), "resp: {}", txt);
    }

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

    #[tokio::test]
    #[serial]
    async fn guarded_body_releases_connection_guard() {
        ACTIVE_SOCKS5_CONNECTIONS.store(0, Ordering::Relaxed);

        let guard = ConnectionGuard::try_new().expect("expected guard to be acquired");
        assert_eq!(ConnectionGuard::active_count(), 1);

        let handle = tokio::spawn(async {});

        {
            let body = GuardedBody::new(Empty::<Bytes>::new(), guard, handle);
            drop(body);
        }

        tokio::task::yield_now().await;

        assert_eq!(ConnectionGuard::active_count(), 0);
    }

    #[tokio::test]
    async fn stats_endpoints_without_auth() {
        use hyper::Request;
        use http_body_util::BodyExt;
        use std::sync::Arc;

        // Prepare config with auth disabled
        let port = 18081u16;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(123, 456);

        let mut cfg = base_proxy_config(port);
        cfg.stats_dir = Some(std::env::temp_dir().join("sthp_test").to_string_lossy().to_string());
        let config = Arc::new(cfg);
        let (mut sender, client_task, server) = spawn_in_memory_proxy(Arc::clone(&config), counters.clone()).await;

        // GET /stats should return current counters
        let req = Request::builder().method("GET").uri("/stats").body(Empty::<Bytes>::new()).unwrap();
        let mut resp = sender.send_request(req).await.expect("send stats");
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body_bytes = resp.body_mut().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body_bytes);
        assert!(body.contains("\"rx\":123"));
        assert!(body.contains("\"tx\":456"));

        // POST /stats/reset should zero the counters
        let req = Request::builder().method("POST").uri("/stats/reset").body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.expect("send reset");
        assert_eq!(resp.status(), http::StatusCode::OK);
        let snapshot_after = snapshot(port).await.unwrap_or((0, 0));
        assert_eq!(snapshot_after, (0, 0));

        drop(sender);
        let _ = client_task.await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn stats_endpoints_with_auth() {
        use hyper::Request;
        use http_body_util::BodyExt;
        use std::sync::Arc;

        // Prepare config with auth enabled
        let port = 18082u16;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(42, 24);

        let auth_header = basic_auth_header("user", "pass");

        let mut cfg = base_proxy_config(port);
        cfg.http_basic_auth = Some(auth_header.clone());
        cfg.no_httpauth = false;
        cfg.stats_dir = Some(std::env::temp_dir().join("sthp_test").to_string_lossy().to_string());
        let config = Arc::new(cfg);

        let (mut sender, client_task, server) = spawn_in_memory_proxy(Arc::clone(&config), counters.clone()).await;

        // Missing auth -> 407
        let req = Request::builder().method("GET").uri("/stats").body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.expect("send stats no auth");
        assert_eq!(resp.status(), http::StatusCode::PROXY_AUTHENTICATION_REQUIRED);

        // Wrong auth -> 407
        let req = Request::builder().method("GET").uri("/stats").header(PROXY_AUTHORIZATION, "Basic d3Jvbmc6d3Jvbmc=")
            .body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.expect("send stats wrong auth");
        assert_eq!(resp.status(), http::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(resp.headers().get(PROXY_AUTHENTICATE).is_some());

        // Correct auth -> 200 with JSON containing snapshot
        let req = Request::builder().method("GET").uri("/stats").header(PROXY_AUTHORIZATION, auth_header)
            .body(Empty::<Bytes>::new()).unwrap();
        let mut resp = sender.send_request(req).await.expect("send stats ok");
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body_bytes = resp.body_mut().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body_bytes);
        assert!(body.contains("\"rx\":42"));
        assert!(body.contains("\"tx\":24"));

        drop(sender);
        let _ = client_task.await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn stats_endpoints_dual_listener_http_port() {
        use hyper::Request;
        use http_body_util::BodyExt;

        let http_port = 18089u16;
        let socks_port = 18090u16;
        reset_port(http_port).await;
        reset_port(socks_port).await;

        let http_counters = get_counters_for_port(http_port).await;
        http_counters.set(111, 222);
        let socks_counters = get_counters_for_port(socks_port).await;
        socks_counters.set(333, 444);

        let mut cfg = base_proxy_config(http_port);
        cfg.socks_listen_addr = Some(std::net::SocketAddr::from(([127,0,0,1], socks_port)));
        cfg.stats_dir = Some(std::env::temp_dir().join("sthp_test_dual").to_string_lossy().to_string());
        let config = Arc::new(cfg);

        let (mut sender, client_task, server) = spawn_in_memory_proxy(Arc::clone(&config), http_counters.clone()).await;

        // GET /stats should return HTTP port counters
        let req = Request::builder().method("GET").uri("/stats").body(Empty::<Bytes>::new()).unwrap();
        let mut resp = sender.send_request(req).await.expect("send stats");
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body_bytes = resp.body_mut().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body_bytes);
        assert!(body.contains(&format!("\"port\":{}", http_port)));
        assert!(body.contains("\"rx\":111"));
        assert!(body.contains("\"tx\":222"));

        drop(sender);
        let _ = client_task.await;
        let _ = server.await;
    }

    #[test]
    fn get_stats_path_distinct_files() {
        let port_a = 19001u16;
        let port_b = 19002u16;
        let mut cfg = base_proxy_config(port_a);
        cfg.stats_dir = Some(std::env::temp_dir().join("sthp_test_paths").to_string_lossy().to_string());
        // Even if we set socks_listen_addr, file names must depend on the queried port
        cfg.socks_listen_addr = Some(std::net::SocketAddr::from(([127,0,0,1], port_b)));

        let pa = get_stats_path(&cfg, port_a);
        let pb = get_stats_path(&cfg, port_b);
        assert_ne!(pa, pb, "expected different stats files per port");
        assert!(pa.to_string_lossy().contains(&port_a.to_string()));
        assert!(pb.to_string_lossy().contains(&port_b.to_string()));
    }

    #[tokio::test]
    async fn authenticated_request_strips_proxy_headers() {
        use hyper::Request;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let port = 18087u16;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake socks listener");
        let socks_addr = socks_listener.local_addr().expect("listener addr");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured);

        let socks_task = tokio::spawn(async move {
            let (mut stream, _) = socks_listener.accept().await.expect("accept socks client");

            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting).await.expect("read greeting header");
            let methods_len = greeting[1] as usize;
            let mut methods = vec![0u8; methods_len];
            if methods_len > 0 {
                stream.read_exact(&mut methods).await.expect("read auth methods");
            }
            stream.write_all(&[0x05, 0x00]).await.expect("write method selection");

            let mut request_header = [0u8; 4];
            stream.read_exact(&mut request_header).await.expect("read request header");
            let atyp = request_header[3];
            match atyp {
                0x01 => {
                    let mut addr = [0u8; 4];
                    stream.read_exact(&mut addr).await.expect("read ipv4 address");
                }
                0x03 => {
                    let mut len_buf = [0u8; 1];
                    stream.read_exact(&mut len_buf).await.expect("read domain length");
                    let len = len_buf[0] as usize;
                    let mut domain = vec![0u8; len];
                    if len > 0 {
                        stream.read_exact(&mut domain).await.expect("read domain name");
                    }
                }
                0x04 => {
                    let mut addr = [0u8; 16];
                    stream.read_exact(&mut addr).await.expect("read ipv6 address");
                }
                _ => {}
            }
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await.expect("read port");

            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.expect("write connect reply");

            let mut buffer = Vec::new();
            let mut temp = [0u8; 1024];
            loop {
                match timeout(Duration::from_secs(1), stream.read(&mut temp)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        buffer.extend_from_slice(&temp[..n]);
                        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Ok(Err(e)) => panic!("failed to read http request: {e}"),
                    Err(_) => break,
                }
            }

            let mut captured = captured_clone.lock().await;
            *captured = buffer;

            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.expect("write http response");
            stream.shutdown().await.expect("shutdown socks stream");
        });

        let auth_header = basic_auth_header("user", "pass");
        let mut cfg = base_proxy_config(port);
        cfg.http_basic_auth = Some(auth_header.clone());
        cfg.no_httpauth = false;
        cfg.socks_addr = socks_addr;
        let config = Arc::new(cfg);

        let (mut sender, client_task, server) = spawn_in_memory_proxy(Arc::clone(&config), counters.clone()).await;

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header(PROXY_AUTHORIZATION, auth_header.clone())
            .header(hyper::header::HOST, "example.com")
            .header("Proxy-Connection", "keep-alive")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let resp = sender.send_request(req).await.expect("send authenticated request");
        assert_eq!(resp.status(), http::StatusCode::OK);

        drop(sender);
        let _ = client_task.await;
        let _ = server.await;
        let _ = socks_task.await;

        let captured_bytes = captured.lock().await.clone();
        assert!(!captured_bytes.is_empty(), "expected captured HTTP request");
        let captured_str = String::from_utf8_lossy(&captured_bytes);
        let lower = captured_str.to_lowercase();
        assert!(!lower.contains("proxy-authorization"));
        assert!(!lower.contains("proxy-connection"));
        assert!(lower.contains("host: example.com"));
    }

    #[tokio::test]
    async fn domain_whitelist_blocks_non_connect() {
        use hyper::Request;
        use std::collections::HashSet;

        let port = 18083u16;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;

        // Only allow example.com apex; request to other.com should be blocked (403)
        let mut allowed_set = HashSet::new();
        allowed_set.insert("example.com".to_string());

        let mut cfg = base_proxy_config(port);
        cfg.allowed_domains = Some(allowed_set);
        let config = Arc::new(cfg);
        let (mut sender, client_task, server) = spawn_in_memory_proxy(Arc::clone(&config), counters.clone()).await;

        // Absolute-form request typical of proxies
        let req = Request::builder().method("GET").uri("http://other.com/")
            .body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.expect("send blocked");
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

        drop(sender);
        let _ = client_task.await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn domain_whitelist_allows_non_connect_then_fails_upstream() {
        use hyper::Request;
        use std::collections::HashSet;

        let port = 18084u16;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;

        // Allow apex + subdomains of example.com
        let mut allowed_set = HashSet::new();
        allowed_set.insert(".example.com".to_string());

        let mut cfg = base_proxy_config(port);
        cfg.allowed_domains = Some(allowed_set);
        let config = Arc::new(cfg);
        let (mut sender, client_task, server) = spawn_in_memory_proxy(Arc::clone(&config), counters.clone()).await;

        // Allowed apex
        let req = Request::builder().method("GET").uri("http://example.com/")
            .body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.expect("send allowed apex");
        // Should not be 403 (domain check passed); likely 502 due to missing upstream
        assert_ne!(resp.status(), http::StatusCode::FORBIDDEN);

        // Allowed subdomain
        let req = Request::builder().method("GET").uri("http://a.example.com/")
            .body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.expect("send allowed subdomain");
        assert_ne!(resp.status(), http::StatusCode::FORBIDDEN);

        drop(sender);
        let _ = client_task.await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn domain_whitelist_blocks_connect() {
        use hyper::Request;
        use std::collections::HashSet;

        let port = 18085u16;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;

        let mut allowed_set = HashSet::new();
        allowed_set.insert("example.com".to_string()); // apex only

        let mut cfg = base_proxy_config(port);
        cfg.allowed_domains = Some(allowed_set);
        let config = Arc::new(cfg);
        let (mut sender, client_task, server) = spawn_in_memory_proxy(Arc::clone(&config), counters.clone()).await;

        let req = Request::builder().method("CONNECT").uri("other.com:443")
            .body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.expect("send CONNECT");
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

        drop(sender);
        let _ = client_task.await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn domain_whitelist_allows_connect_then_fails_upstream() {
        use hyper::Request;
        use std::collections::HashSet;

        let port = 18086u16;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;

        let mut allowed_set = HashSet::new();
        allowed_set.insert(".example.com".to_string()); // apex + subdomains

        let mut cfg = base_proxy_config(port);
        cfg.allowed_domains = Some(allowed_set);
        let config = Arc::new(cfg);
        let (mut sender, client_task, server) = spawn_in_memory_proxy(Arc::clone(&config), counters.clone()).await;

        let req = Request::builder().method("CONNECT").uri("example.com:443")
            .body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.expect("send CONNECT allowed");
        // Not a 403; likely 502 because SOCKS upstream missing
        assert_ne!(resp.status(), http::StatusCode::FORBIDDEN);

        drop(sender);
        let _ = client_task.await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn dual_listeners_end_to_end() {
        use hyper::client::conn::http1::Builder as ClientBuilder;
        use hyper_util::rt::TokioIo;
        use hyper::Request;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 1) Fake upstream SOCKS5 server that replies 200 OK for any CONNECT tunnel
        let (upstream_addr, upstream_task) = spawn_fake_socks_upstream().await;

        // 2) Start our proxy with dual listeners on ephemeral ports
        let mut cfg = base_proxy_config(0);
        cfg.socks_addr = upstream_addr;
        cfg.socks_listen_addr = Some(std::net::SocketAddr::from(([127,0,0,1], 0)));
        cfg.no_httpauth = true;
        cfg.force_close = true;

        // Spawn minimal dual listeners (test-only)
        async fn spawn_dual(config: ProxyConfig) -> (std::net::SocketAddr, std::net::SocketAddr, JoinHandle<()>, JoinHandle<()>) {
            use hyper::server::conn::http1;
            use hyper::service::service_fn;
            let http_listener = TcpListener::bind(config.listen_addr).await.expect("bind http");
            let http_addr = http_listener.local_addr().unwrap();
            let socks_listener = TcpListener::bind(config.socks_listen_addr.unwrap()).await.expect("bind socks");
            let socks_addr = socks_listener.local_addr().unwrap();
            let mut resolved = config.clone();
            resolved.listen_addr = http_addr; resolved.socks_listen_addr = Some(socks_addr);
            let cfg = Arc::new(resolved);
            let http_basic = Arc::new(cfg.http_basic_auth.clone());
            let allowed = Arc::new(cfg.allowed_domains.clone());
            let counters_http = get_counters_for_port(http_addr.port()).await;
            let counters_socks = get_counters_for_port(socks_addr.port()).await;
            let socks_connector = build_socks_connector(cfg.as_ref());
            let cfg_h = Arc::clone(&cfg); let sc_h = Arc::clone(&socks_connector); let allowed_h = Arc::clone(&allowed); let http_basic_h = Arc::clone(&http_basic); let counters_h = Arc::clone(&counters_http);
            let h_task = tokio::spawn(async move {
                loop {
                    let (stream, _) = match http_listener.accept().await { Ok(v)=>v, Err(_)=>break };
                    let sc = Arc::clone(&sc_h); let hb = Arc::clone(&http_basic_h); let ad = Arc::clone(&allowed_h); let cfg = Arc::clone(&cfg_h); let counters = Arc::clone(&counters_h);
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| proxy(req, Arc::clone(&sc), Arc::clone(&hb), Arc::clone(&ad), Arc::clone(&cfg), None, Arc::clone(&counters)));
                        let _ = http1::Builder::new().preserve_header_case(true).title_case_headers(true).serve_connection(TokioIo::new(stream), svc).with_upgrades().await;
                    });
                }
            });
            let sc_s = Arc::clone(&socks_connector); let allowed_s = Arc::clone(&allowed); let cfg_s = Arc::clone(&cfg); let counters_s = Arc::clone(&counters_socks);
            let s_task = spawn_socks_accept_loop(socks_listener, sc_s, allowed_s, cfg_s, counters_s);
            (http_addr, socks_addr, h_task, s_task)
        }
        let (http_addr, socks_addr, http_task, socks_task) = spawn_dual(cfg).await;

        // 3) Run HTTP and SOCKS clients concurrently
        let http_fut = async {
            // Connect hyper client to HTTP listener
            let stream = tokio::net::TcpStream::connect(http_addr).await.expect("connect http");
            let (mut sender, conn) = ClientBuilder::new().preserve_header_case(true).title_case_headers(true).handshake(TokioIo::new(stream)).await.expect("handshake");
            let client_task = tokio::spawn(async move { let _ = conn.await; });
            let req = Request::builder().method("GET").uri("http://example.com/").header(hyper::header::HOST, "example.com").body(Empty::<Bytes>::new()).unwrap();
            let resp = sender.send_request(req).await.expect("send http");
            assert_eq!(resp.status(), http::StatusCode::OK);
            drop(sender); let _ = client_task.await;
        };
        let socks_fut = async {
            let mut c = tokio::net::TcpStream::connect(socks_addr).await.expect("connect socks");
            let _ = c.write_all(&[0x05,0x01,0x00]).await; // noauth offer
            let mut sel=[0u8;2]; let _=c.read_exact(&mut sel).await; assert_eq!(sel, [0x05,0x00]);
            let host=b"example.com"; let mut req=Vec::with_capacity(4+1+host.len()+2);
            req.extend_from_slice(&[0x05,0x01,0x00,0x03, host.len() as u8]); req.extend_from_slice(host); req.extend_from_slice(&80u16.to_be_bytes());
            let _=c.write_all(&req).await;
            verify_socks_success_and_http_ok(&mut c).await;
        };
        let _ = tokio::join!(http_fut, socks_fut);

        // Cleanup
        http_task.abort(); socks_task.abort(); upstream_task.abort();
    }

    #[tokio::test]
    async fn socks_inbound_auth_end_to_end() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use crate::auth::Auth;

        // Fake upstream SOCKS5 server (no-auth) that responds 200 OK over tunnel
        let (upstream_addr, upstream_task) = spawn_fake_socks_upstream().await;

        // Start proxy with inbound SOCKS auth required
        let mut cfg = base_proxy_config(0);
        cfg.socks_addr = upstream_addr;
        cfg.socks_listen_addr = Some(std::net::SocketAddr::from(([127,0,0,1], 0)));
        cfg.socks_in_auth = Some(Auth::new("user".to_string(), "pass".to_string()));
        cfg.no_httpauth = true;
        cfg.force_close = true;

        // Minimal dual listeners (reuse helper pattern from previous test)
        async fn spawn_dual(config: ProxyConfig) -> (std::net::SocketAddr, JoinHandle<()>) {
            let socks_listener = TcpListener::bind(config.socks_listen_addr.unwrap()).await.expect("bind socks");
            let socks_addr = socks_listener.local_addr().unwrap();
            let cfg = Arc::new(ProxyConfig { listen_addr: std::net::SocketAddr::from(([127,0,0,1],0)), socks_listen_addr: Some(socks_addr), ..config });
            let counters = get_counters_for_port(socks_addr.port()).await;
            let sc = build_socks_connector(cfg.as_ref());
            let allowed = Arc::new(cfg.allowed_domains.clone());
            let cfg_s = Arc::clone(&cfg);
            let task = spawn_socks_accept_loop(socks_listener, sc, allowed, cfg_s, counters);
            (socks_addr, task)
        }
        let (socks_addr, socks_task) = spawn_dual(cfg).await;

        // SOCKS client that performs RFC1929 auth then CONNECT and HTTP request
        let mut c = tokio::net::TcpStream::connect(socks_addr).await.expect("connect socks");
        // greeting offers username/password only
        let _ = c.write_all(&[0x05,0x01,0x02]).await;
        let mut sel=[0u8;2]; let _=c.read_exact(&mut sel).await; assert_eq!(sel, [0x05,0x02]);
        // subnegotiation (version 1)
        let u=b"user"; let p=b"pass";
        let mut authmsg=Vec::with_capacity(2+u.len()+p.len());
        authmsg.push(0x01); authmsg.push(u.len() as u8); authmsg.extend_from_slice(u); authmsg.push(p.len() as u8); authmsg.extend_from_slice(p);
        let _=c.write_all(&authmsg).await; let mut ar=[0u8;2]; let _=c.read_exact(&mut ar).await; assert_eq!(ar, [0x01,0x00]);
        // CONNECT
        let host=b"example.com"; let mut req=Vec::new();
        req.extend_from_slice(&[0x05,0x01,0x00,0x03, host.len() as u8]); req.extend_from_slice(host); req.extend_from_slice(&80u16.to_be_bytes());
        let _=c.write_all(&req).await;
        verify_socks_success_and_http_ok(&mut c).await;

        // Cleanup
        socks_task.abort(); upstream_task.abort();
    }
}