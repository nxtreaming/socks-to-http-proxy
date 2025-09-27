mod auth;
mod buffer_pool;
mod config;
mod connection;
mod domain;
mod session;
mod socks;

use crate::buffer_pool::{get_buffer, return_buffer};
use crate::config::{Cli, ProxyConfig};
use crate::connection::{
    get_ip_tracker, is_backlog_threshold_exceeded, is_connection_limit_exceeded,
    is_memory_pressure_high, ConnectionGuard, ACTIVE_SOCKS5_CONNECTIONS,
    CONNECTION_BACKLOG_THRESHOLD, MEMORY_PRESSURE_THRESHOLD,
};
use crate::domain::is_domain_allowed;
use crate::session::new_session_id;
use crate::socks::SocksConnector;
use clap::Parser;
use color_eyre::eyre::Result;

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
use tokio::net::TcpListener;

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

    // Create SOCKS5 connector
    let socks_connector = Arc::new(SocksConnector::new(
        config.socks_addr,
        Arc::new(config.socks_auth.clone()),
        Arc::new(config.soax_password.clone()),
        Arc::new(config.soax_settings.clone()),
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
                    // Check per-IP connection limits
                    let ip_tracker = get_ip_tracker();
                    let client_ip = peer_addr.ip();
                    let conn_limit = config.conn_per_ip;
                    let current_ip_connections = ip_tracker.get_count(client_ip);

                    if current_ip_connections >= conn_limit {
                        warn!(
                            "Connection limit exceeded for IP {}: {} connections",
                            client_ip, current_ip_connections
                        );
                        // Close the connection immediately
                        drop(stream);
                        continue;
                    }

                    // Increment connection count for this IP
                    let new_count = ip_tracker.increment(client_ip);
                    if new_count > conn_limit {
                        warn!(
                            "Connection limit exceeded after increment for IP {}: {} connections",
                            client_ip, new_count
                        );
                        ip_tracker.decrement(client_ip);
                        drop(stream);
                        continue;
                    }

                    if new_count > 20 {
                        info!(
                            "High connection count for IP {}: {} connections",
                            client_ip, new_count
                        );
                    }

                    let socks_connector = socks_connector.clone();
                    let http_basic = http_basic.clone();
                    let allowed_domains = allowed_domains.clone();
                    let config = Arc::clone(&config);
                    let sessionid = if config.soax_settings.enabled {
                        Some(new_session_id())
                    } else {
                        None
                    };
                    tokio::task::spawn(async move {
                        let io = TokioIo::new(stream);
                        let sess = sessionid.clone();
                        let service = service_fn(move |req| {
                            proxy(
                                req,
                                socks_connector.clone(),
                                http_basic.clone(),
                                allowed_domains.clone(),
                                Arc::clone(&config),
                                sess.clone(),
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

    if let (Some(allowed_domains), Some(request_domain)) =
        (allowed_domains.as_ref(), req.uri().host())
    {
        if !is_domain_allowed(allowed_domains, request_domain) {
            warn!(
                "Access to domain {} is not allowed through the proxy.",
                request_domain
            );
            let mut resp = Response::new(full(
                "Access to this domain is not allowed through the proxy.",
            ));
            *resp.status_mut() = http::StatusCode::FORBIDDEN;
            return Ok(resp);
        }
    }

    if Method::CONNECT == req.method() {
        if let Some(addr) = host_addr(req.uri()) {
            let socks_connector = socks_connector.clone();
            // HTTPS (CONNECT) domain filtering based on allowed_domains
            // For CONNECT, the request URI is authority-form (host:port). Use authority().host().
            if let (Some(allowed), Some(authority)) =
                (allowed_domains.as_ref().as_ref(), req.uri().authority())
            {
                let host = authority.host();
                if !is_domain_allowed(allowed, host) {
                    warn!(
                        "Access to domain {} is not allowed through the proxy (CONNECT).",
                        host
                    );
                    let mut resp = Response::new(full(
                        "Access to this domain is not allowed through the proxy.",
                    ));
                    *resp.status_mut() = http::StatusCode::FORBIDDEN;
                    return Ok(resp);
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
            let mut resp = Response::new(full("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        let host = match req.uri().host() {
            Some(h) => h,
            None => {
                warn!("HTTP request missing host: {:?}", req.uri());
                let mut resp = Response::new(full("HTTP request missing host"));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;
                return Ok(resp);
            }
        };
        let port = req.uri().port_u16().unwrap_or(80);
        let addr = format!("{}:{}", host, port);

        // Check connection limits for stability
        if is_connection_limit_exceeded() {
            let current_connections = ConnectionGuard::active_count();
            warn!("Connection limit reached: {}", current_connections);
            let mut resp = Response::new(full("Server overloaded, please try again later"));
            *resp.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
            return Ok(resp);
        }

        let mut connection_guard = ConnectionGuard::new();
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

        let socks_stream = match socks_connector
            .connect(addr.as_str(), sessionid.as_deref())
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                warn!("Upstream SOCKS5 connection #{} failed: {}", conn_id, e);
                let mut resp = Response::new(full("SOCKS5 connection failed"));
                *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                return Ok(resp);
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
                let mut resp = Response::new(full("Request timeout"));
                *resp.status_mut() = http::StatusCode::GATEWAY_TIMEOUT;
                return Ok(resp);
            }
        };

        // We are done initiating the request. Keep driving the connection in background
        // Note on `sender`: in hyper's (sender, conn) model, `conn` is the I/O driver
        // that must keep running to stream the response body. Explicitly calling
        // drop(sender) here is not required for a clean shutdown; dropping it only
        // prevents issuing more requests and it will be dropped at scope end anyway.
        // We keep the driver alive until EOF to avoid truncating large/slow responses.

        // and decrement the active counter only after the connection fully closes.
        let _close_task = tokio::spawn(async move {
            let _ = conn_handle.await; // wait for connection driver to finish
            drop(connection_guard); // RAII drop -> decrement
        });
        // Intentionally do not abort conn_handle; it will finish when the connection shuts down.

        // Return the response body as-is; hyper will forward it to the client
        Ok(resp.map(|b| b.boxed()))
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn proxy_auth_required_response(msg: &'static str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut response = Response::new(full(msg));
    *response.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    response.headers_mut().insert(
        PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"proxy\""),
    );
    response
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn tunnel(
    upgraded: Upgraded,
    addr: String,
    socks_connector: Arc<SocksConnector>,
    idle_timeout: u64,
    sessionid: Option<String>,
) -> Result<()> {
    // Check connection limits for stability
    if is_connection_limit_exceeded() {
        let current_connections = ConnectionGuard::active_count();
        warn!("Tunnel connection limit reached: {}", current_connections);
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Server overloaded",
        )
        .into());
    }

    let mut connection_guard = ConnectionGuard::new();
    let conn_id = ConnectionGuard::active_count();

    let socks_stream = match socks_connector
        .connect(addr.as_str(), sessionid.as_deref())
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
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

    // Use buffer pool for memory optimization
    let use_large_buffers = idle_timeout > 300;
    let mut client_buf = get_buffer(use_large_buffers);
    let mut server_buf = get_buffer(use_large_buffers);
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

    // Return buffers to pool for reuse
    return_buffer(client_buf, use_large_buffers);
    return_buffer(server_buf, use_large_buffers);

    connection_guard.decrement();
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
