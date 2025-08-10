mod auth;

use crate::auth::Auth;
use clap::{value_parser, Args, Parser};
use color_eyre::eyre::Result;

use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::signal;

use base64::engine::general_purpose;
use base64::Engine;
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

// Global counter for tracking active SOCKS5 connections
static ACTIVE_SOCKS5_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

// Connection pool limits for multi-instance deployment on 16GB server
const MAX_CONCURRENT_CONNECTIONS: usize = 40000; // 40K concurent connection (~7.4GB per instance)
const CONNECTION_BACKLOG_THRESHOLD: usize = 30000; // 30K warning threshold (~5.5GB)
const MEMORY_PRESSURE_THRESHOLD: usize = 35000; // 35K memory threshold (~6.4GB)

#[derive(Debug, Args)]
#[group()]
struct Auths {
    /// Socks5 username
    #[arg(short = 'u', long, required = false)]
    username: String,

    /// Socks5 password
    #[arg(short = 'P', long, required = false)]
    password: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about,long_about=None)]
struct Cli {
    /// port where Http proxy should listen
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    listen_ip: Ipv4Addr,

    #[command(flatten)]
    auth: Option<Auths>,

    /// Socks5 proxy address
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    socks_address: SocketAddr,

    /// Comma-separated list of allowed domains
    #[arg(long, value_delimiter = ',')]
    allowed_domains: Option<Vec<String>>,

    /// HTTP Basic Auth credentials in the format "user:passwd"
    #[arg(long)]
    http_basic: Option<String>,

    /// Disable HTTP authentication：1 or 0
    #[arg(long, value_parser = value_parser ! (u8).range(0..=1), default_value_t = 1)]
    no_httpauth: u8,

    /// Idle timeout in seconds for tunnel connections
    #[arg(long, default_value_t = 540)]
    idle_timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("sthp=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    color_eyre::install()?;

    let args = Cli::parse();

    let socks_addr = args.socks_address;
    let port = args.port;
    let auth = args
        .auth
        .map(|auth| Auth::new(auth.username, auth.password));
    let auth = Arc::new(auth);
    let addr = SocketAddr::from((args.listen_ip, port));
    let allowed_domains: Option<HashSet<String>> =
        args.allowed_domains.map(|v| v.into_iter().collect());
    let allowed_domains = Arc::new(allowed_domains);
    let http_basic = args
        .http_basic
        .map(|hb| format!("Basic {}", general_purpose::STANDARD.encode(hb)))
        .map(|auth_str| HeaderValue::from_str(&auth_str).expect("Invalid HTTP Basic auth string"));
    let http_basic = Arc::new(http_basic);
    let no_httpauth = args.no_httpauth == 1;
    let idle_timeout = args.idle_timeout;

    let listener = TcpListener::bind(addr).await?;
    info!("HTTP Proxy listening on http://{}", addr);
    info!("SOCKS5 backend: {}", socks_addr);

    // Add a connection monitoring task (only on Unix to avoid shell overhead on Windows)
    #[cfg(unix)]
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
        let mut consecutive_high_count = 0;

        loop {
            interval.tick().await;

            let close_wait_cmd = format!(
                "netstat -an | grep CLOSE_WAIT | grep :{} | wc -l",
                socks_addr.port()
            );
            let close_wait_count = match tokio::process::Command::new("sh")
                .args(&["-c", &close_wait_cmd])
                .output()
                .await
            {
                Ok(output) => String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .parse::<u32>()
                    .unwrap_or(0),
                Err(e) => {
                    debug!("Failed to check CLOSE_WAIT: {}", e);
                    0
                }
            };

            let active = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);

            // Only log when there are issues or significant activity
            if close_wait_count > 0 || active > 100 {
                info!(
                    "SOCKS5 Status - Active: {}, CLOSE_WAIT: {}",
                    active, close_wait_count
                );
            } else if active > 0 {
                debug!("SOCKS5 Status - Active: {}", active);
            }

            // Alert logic
            match close_wait_count {
                0..=100 => {
                    consecutive_high_count = 0;
                }
                101..=300 => {
                    warn!("Moderate CLOSE_WAIT leak: {} connections", close_wait_count);
                    consecutive_high_count = 0;
                }
                301..=600 => {
                    warn!("High CLOSE_WAIT leak: {} connections", close_wait_count);
                    consecutive_high_count += 1;
                }
                _ => {
                    error!("CRITICAL CLOSE_WAIT leak: {} connections", close_wait_count);
                    consecutive_high_count += 1;
                }
            }

            if consecutive_high_count >= 3 {
                error!(
                    "Persistent connection leak detected for {} intervals",
                    consecutive_high_count
                );
            }
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
                    debug!("New connection from {}", peer_addr);

                    let auth = auth.clone();
                    let http_basic = http_basic.clone();
                    let allowed_domains = allowed_domains.clone();
                    tokio::task::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(move |req| {
                            proxy(
                                req,
                                socks_addr,
                                auth.clone(),
                                http_basic.clone(),
                                allowed_domains.clone(),
                                no_httpauth,
                                idle_timeout,
                            )
                        });

                        if let Err(err) = http1::Builder::new()
                            .preserve_header_case(true)
                            .title_case_headers(true)
                            .serve_connection(io, service)
                            .with_upgrades()
                            .await
                        {
                            debug!("Connection from {} ended: {:?}", peer_addr, err);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    // Return an error to break the loop and shutdown gracefully
                    return Err::<(), color_eyre::eyre::Error>(color_eyre::eyre::eyre!(
                        "Accept error: {}",
                        e
                    ));
                }
            }
        }
    };

    // Run server until the shutdown signal is received
    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!("Server error: {}", e);
            }
        }
        _ = shutdown => {
            info!("Server shutdown complete");
        }
    }

    Ok(())
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
    socks_addr: SocketAddr,
    auth: Arc<Option<Auth>>,
    http_basic: Arc<Option<HeaderValue>>,
    allowed_domains: Arc<Option<HashSet<String>>>,
    no_httpauth: bool,
    idle_timeout: u64,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Early return for disabled authentication
    if no_httpauth {
        // Authentication is disabled, proceed
    } else {
        let headers = req.headers();

        // Early return if no authorization header
        let auth_header = match headers.get(hyper::header::PROXY_AUTHORIZATION) {
            Some(header) => header,
            None => {
                // When the request does not contain a Proxy-Authorization header,
                // send a 407 response code and a Proxy-Authenticate header
                let mut response = Response::new(full("Proxy authentication required"));
                *response.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
                response.headers_mut().insert(
                    PROXY_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"proxy\""),
                );
                return Ok(response);
            }
        };

        // Early return for authentication failure
        match http_basic.as_ref() {
            Some(expected_auth) => {
                if auth_header != expected_auth {
                    warn!("Failed to authenticate: {:?}", headers);
                    let mut resp = Response::new(full(
                        "Authorization failed, you are not allowed through the proxy.",
                    ));
                    *resp.status_mut() = http::StatusCode::FORBIDDEN;
                    return Ok(resp);
                }
            }
            None => {
                warn!("HTTP Basic auth not configured but required");
                let mut resp = Response::new(full(
                    "Authorization failed, you are not allowed through the proxy.",
                ));
                *resp.status_mut() = http::StatusCode::FORBIDDEN;
                return Ok(resp);
            }
        }
    }

    let method = req.method();
    debug!("Proxying request: {} {}", method, req.uri());
    if let (Some(allowed_domains), Some(request_domain)) =
        (allowed_domains.as_ref(), req.uri().host())
    {
        let domain = request_domain.to_owned();
        if !allowed_domains.contains(&domain) {
            warn!(
                "Access to domain {} is not allowed through the proxy.",
                domain
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
            let auth = auth.clone();
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let idle_timeout = idle_timeout;
                        if let Err(e) = tunnel(upgraded, addr, socks_addr, auth, idle_timeout).await
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
        let host = req.uri().host().expect("uri has no host");
        let port = req.uri().port_u16().unwrap_or(80);
        let addr = format!("{}:{}", host, port);

        // Check connection limits for stability
        let current_connections = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);
        if current_connections >= MAX_CONCURRENT_CONNECTIONS {
            warn!("Connection limit reached: {}", current_connections);
            let mut resp = Response::new(full("Server overloaded, please try again later"));
            *resp.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
            return Ok(resp);
        }

        let conn_id = ACTIVE_SOCKS5_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        debug!("HTTP SOCKS5 #{} connecting to {}", conn_id, addr);

        // Multi-level warning system for high-capacity server
        if current_connections > MEMORY_PRESSURE_THRESHOLD {
            error!(
                "Critical connection count: {} (memory pressure threshold: {})",
                current_connections, MEMORY_PRESSURE_THRESHOLD
            );
        } else if current_connections > CONNECTION_BACKLOG_THRESHOLD {
            warn!(
                "High connection count: {} (threshold: {})",
                current_connections, CONNECTION_BACKLOG_THRESHOLD
            );
        } else if current_connections > 20000 {
            info!("Moderate connection load: {}", current_connections);
        }

        let socks_stream = match auth.as_ref() {
            Some(auth) => {
                match Socks5Stream::connect_with_password(
                    socks_addr,
                    addr.clone(),
                    &auth.username,
                    &auth.password,
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(e) => {
                        ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                        warn!("SOCKS5 auth connection #{} failed: {}", conn_id, e);
                        let mut resp = Response::new(full("SOCKS5 authentication failed"));
                        *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                        return Ok(resp);
                    }
                }
            }
            None => match Socks5Stream::connect(socks_addr, addr.clone()).await {
                Ok(stream) => stream,
                Err(e) => {
                    ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    warn!("SOCKS5 connection #{} failed: {}", conn_id, e);
                    let mut resp = Response::new(full("SOCKS5 connection failed"));
                    *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                    return Ok(resp);
                }
            },
        };

        // Force Connection: close for stability (prevents CLOSE_WAIT issues)
        // This trades some performance for better connection management
        let mut req = req;
        req.headers_mut()
            .insert("connection", HeaderValue::from_static("close"));

        let io = TokioIo::new(socks_stream);

        let (mut sender, conn) = Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;

        // Simple connection handling for better performance
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                debug!("HTTP #{} connection ended: {:?}", conn_id, err);
            }
            let remaining = ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed) - 1;
            debug!("HTTP #{} connection closed, {} active", conn_id, remaining);
        });

        // Send the request
        let resp = sender.send_request(req).await?;

        // Ensure immediate resource cleanup when client disconnects
        // This prevents "zombie sessions" that waste backend connections
        drop(sender);

        // Critical fix: Ensure response body will be properly handled
        // The response body must be consumed by the client to prevent CLOSE_WAIT
        // We return the response as-is, but the HTTP framework will handle consumption
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

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn tunnel(
    upgraded: Upgraded,
    addr: String,
    socks_addr: SocketAddr,
    auth: Arc<Option<Auth>>,
    idle_timeout: u64,
) -> Result<()> {
    // Check connection limits for stability
    let current_connections = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);
    if current_connections >= MAX_CONCURRENT_CONNECTIONS {
        warn!("Tunnel connection limit reached: {}", current_connections);
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Server overloaded",
        )
        .into());
    }

    let conn_id = ACTIVE_SOCKS5_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    debug!("SOCKS5 tunnel #{} connecting to {}", conn_id, addr);

    let socks_stream = match auth.as_ref() {
        Some(auth) => {
            match Socks5Stream::connect_with_password(
                socks_addr,
                addr.clone(),
                &auth.username,
                &auth.password,
            )
            .await
            {
                Ok(stream) => stream,
                Err(e) => {
                    ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    return Err(color_eyre::eyre::eyre!(
                        "SOCKS5 auth connection failed: {}",
                        e
                    ));
                }
            }
        }
        None => match Socks5Stream::connect(socks_addr, addr.clone()).await {
            Ok(stream) => stream,
            Err(e) => {
                ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                return Err(color_eyre::eyre::eyre!("SOCKS5 connection failed: {}", e));
            }
        },
    };

    let mut client = TokioIo::new(upgraded);
    let mut server = socks_stream;

    // Idle-aware bidirectional copy with immediate connection close detection
    let timeout = tokio::time::Duration::from_secs(idle_timeout);
    let mut from_client = 0u64;
    let mut from_server = 0u64;

    // Use optimized buffer sizes for 1Gbps network performance
    // Larger buffers for better throughput on high-speed networks
    let buffer_size = if idle_timeout > 300 {
        65536 // 64KB for long-lived connections (better for large transfers)
    } else {
        32768 // 32KB for short-lived connections (balance latency/throughput)
    };
    let mut client_buf = vec![0u8; buffer_size];
    let mut server_buf = vec![0u8; buffer_size];

    loop {
        let idle = tokio::time::sleep(timeout);
        tokio::pin!(idle);

        tokio::select! {
            res = client.read(&mut client_buf) => {
                let n = res?;
                if n == 0 {
                    debug!("Tunnel #{} client connection closed", conn_id);
                    break;
                }
                server.write_all(&client_buf[..n]).await?;
                from_client += n as u64;
            }
            res = server.read(&mut server_buf) => {
                let n = res?;
                if n == 0 {
                    debug!("Tunnel #{} server connection closed", conn_id);
                    break;
                }
                client.write_all(&server_buf[..n]).await?;
                from_server += n as u64;
            }
            _ = &mut idle => {
                debug!("Tunnel #{} idle timeout after {:?}, closing", conn_id, timeout);
                break;
            }
        }
    }

    debug!(
        "Tunnel #{} completed: {}↑ {}↓ bytes",
        conn_id, from_client, from_server
    );

    if let Err(e) = server.shutdown().await {
        debug!(
            "Server shutdown error (normal if danted closed first): {}",
            e
        );
    }
    if let Err(e) = client.shutdown().await {
        debug!("Client shutdown error: {}", e);
    }

    drop(server);
    drop(client);

    let remaining = ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed) - 1;

    // Only log detailed stats for significant transfers or when debugging
    if from_client + from_server > 1024 || tracing::enabled!(tracing::Level::DEBUG) {
        debug!(
            "Tunnel #{} completed: {}↑ {}↓ bytes, {} active",
            conn_id, from_client, from_server, remaining
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
