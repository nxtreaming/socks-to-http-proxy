mod auth;

use crate::auth::Auth;
use clap::{value_parser, Args, Parser};
use color_eyre::eyre::Result;

use tokio_socks::tcp::Socks5Stream;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

// RAII guard to ensure connection count is properly decremented
struct ConnectionGuard {
    decremented: bool,
}

impl ConnectionGuard {
    fn new() -> Self {
        ACTIVE_SOCKS5_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        Self { decremented: false }
    }

    fn decrement(&mut self) {
        if !self.decremented {
            ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            self.decremented = true;
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.decrement();
    }
}

// Buffer pool for memory optimization
struct BufferPool {
    small_buffers: Mutex<Vec<Vec<u8>>>, // 8KB buffers
    large_buffers: Mutex<Vec<Vec<u8>>>, // 16KB buffers
}

impl BufferPool {
    fn new() -> Self {
        Self {
            small_buffers: Mutex::new(Vec::new()),
            large_buffers: Mutex::new(Vec::new()),
        }
    }

    fn get_buffer(&self, large: bool) -> Vec<u8> {
        let size = if large { 16384 } else { 8192 };
        let pool = if large {
            &self.large_buffers
        } else {
            &self.small_buffers
        };

        if let Ok(mut buffers) = pool.lock() {
            if let Some(mut buffer) = buffers.pop() {
                buffer.clear();
                buffer.resize(size, 0);
                return buffer;
            }
        }

        // Create new buffer if pool is empty
        vec![0u8; size]
    }

    fn return_buffer(&self, buffer: Vec<u8>, large: bool) {
        // Only return buffers that are the expected size to avoid memory bloat
        let expected_size = if large { 16384 } else { 8192 };
        if buffer.len() != expected_size {
            return;
        }

        let pool = if large {
            &self.large_buffers
        } else {
            &self.small_buffers
        };
        if let Ok(mut buffers) = pool.lock() {
            // Limit pool size to prevent excessive memory usage
            if buffers.len() < 100 {
                buffers.push(buffer);
            }
        }
    }
}

// Global buffer pool
static BUFFER_POOL: std::sync::OnceLock<BufferPool> = std::sync::OnceLock::new();

// Per-IP connection tracking
struct IpConnectionTracker {
    connections: Mutex<HashMap<IpAddr, usize>>,
}

impl IpConnectionTracker {
    fn new() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
        }
    }

    fn increment(&self, ip: IpAddr) -> usize {
        let mut connections = self.connections.lock().unwrap();
        let count = connections.entry(ip).or_insert(0);
        *count += 1;
        *count
    }

    fn decrement(&self, ip: IpAddr) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(count) = connections.get_mut(&ip) {
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                connections.remove(&ip);
            }
        }
    }

    fn get_count(&self, ip: IpAddr) -> usize {
        let connections = self.connections.lock().unwrap();
        connections.get(&ip).copied().unwrap_or(0)
    }
}

// Global IP connection tracker
static IP_TRACKER: std::sync::OnceLock<IpConnectionTracker> = std::sync::OnceLock::new();

// Global counter for tracking active SOCKS5 connections
static ACTIVE_SOCKS5_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

// Connection pool limits for multi-instance deployment on 16GB server
const MAX_CONCURRENT_CONNECTIONS: usize = 40000; // 40K concurent connection (~7.4GB per instance)
const CONNECTION_BACKLOG_THRESHOLD: usize = 30000; // 30K warning threshold (~5.5GB)
const MEMORY_PRESSURE_THRESHOLD: usize = 35000; // 35K memory threshold (~6.4GB)

#[derive(Debug, Clone, Args)]
struct Auths {
    /// Socks5 username (optional; not needed in --soax-sticky mode)
    #[arg(short = 'u', long)]
    username: Option<String>,

    /// Socks5 password (SOAX package_key in --soax-sticky mode)
    #[arg(short = 'P', long)]
    password: Option<String>,
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

    /// Socks5 proxy address or hostname:port
    #[arg(short, long, default_value = "127.0.0.1:1080", value_name = "HOST:PORT")]
    socks_address: String,

    /// Enable SOAX sticky session per client connection: 1 or 0
    #[arg(long = "soax-sticky", value_parser = value_parser!(u8).range(0..=1), default_value_t = 0)]
    soax_sticky: u8,

    /// SOAX package id (required when --soax-sticky=1)
    #[arg(long)]
    soax_package_id: Option<String>,

    /// SOAX GEO parameters (optional)
    #[arg(long)]
    soax_country: Option<String>,
    #[arg(long)]
    soax_region: Option<String>,
    #[arg(long)]
    soax_city: Option<String>,
    #[arg(long)]
    soax_isp: Option<String>,

    /// SOAX sessionlength in seconds (only used when sticky is enabled)
    #[arg(long, default_value_t = 300)]
    soax_sessionlength: u32,

    /// SOAX bindttl in seconds (optional)
    #[arg(long)]
    soax_bindttl: Option<u32>,

    /// SOAX idlettl in seconds (optional)
    #[arg(long)]
    soax_idlettl: Option<u32>,
    /// Comma-separated list of allowed domains
    /// SOAX opt flags (comma-separated, e.g., 'lookalike,uniqip')
    #[arg(long = "soax-opt", value_delimiter = ',')]
    soax_opt: Option<Vec<String>>,

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

    /// Maximum connections per IP address
    #[arg(long = "conn-per-ip", default_value_t = 500)]
    conn_per_ip: usize,
    /// Force 'Connection: close' on forwarded HTTP requests
    #[arg(long, default_value_t = true)]
    force_close: bool,
}

#[derive(Clone, Debug)]
struct SoaxSettings {
    enabled: bool,
    package_id: Option<String>,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    sessionlength: u32,
    bindttl: Option<u32>,
    idlettl: Option<u32>,
    opts: Vec<String>,
}

impl SoaxSettings {
    fn build_username(&self, sessionid: Option<&str>) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(16);
        if let Some(pkg) = &self.package_id {
            parts.push(format!("package-{}", pkg));
        }
        if let Some(c) = &self.country { parts.push(format!("country-{}", c)); }
        if let Some(r) = &self.region { parts.push(format!("region-{}", r)); }
        if let Some(ci) = &self.city { parts.push(format!("city-{}", ci)); }
        if let Some(i) = &self.isp { parts.push(format!("isp-{}", i)); }

        for opt in &self.opts { parts.push(format!("opt-{}", opt)); }

        if let Some(sid) = sessionid {
            parts.push(format!("sessionid-{}", sid));
            // sessionlength only meaningful when sessionid is present
            parts.push(format!("sessionlength-{}", self.sessionlength));
            if let Some(b) = self.bindttl { parts.push(format!("bindttl-{}", b)); }
            if let Some(i) = self.idlettl { parts.push(format!("idlettl-{}", i)); }
        }
        parts.join("-")
    }
}

static SESSION_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn new_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let ctr = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // compact, URL-safe lowercase hex
    format!("{:x}{:x}", now.as_nanos() & 0xffffffffffff, ctr & 0xffffffff)
}

async fn open_socks5_stream(
    socks_addr: SocketAddr,
    target_addr: &str,
    auth: &Arc<Option<Auth>>,
    soax_password: &Arc<Option<String>>,
    soax_settings: &Arc<SoaxSettings>,
    sessionid: Option<&str>,
) -> std::result::Result<Socks5Stream<tokio::net::TcpStream>, String> {
    if soax_settings.enabled {
        let username = soax_settings.build_username(sessionid);
        let password = soax_password.as_ref().clone().unwrap_or_default();
        if password.is_empty() || soax_settings.package_id.is_none() {
            return Err("SOAX mode requires --soax-package-id and --auth -P <package_key>".to_string());
        }
        Socks5Stream::connect_with_password(socks_addr, target_addr, &username, &password)
            .await
            .map_err(|e| e.to_string())
    } else {
        match auth.as_ref() {
            Some(a) => {
                Socks5Stream::connect_with_password(socks_addr, target_addr, &a.username, &a.password)
                    .await
                    .map_err(|e| e.to_string())
            }
            None => Socks5Stream::connect(socks_addr, target_addr).await.map_err(|e| e.to_string()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("sthp=warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    color_eyre::install()?;

    let args = Cli::parse();

    let socks_ep = args.socks_address;
    let socks_addr: SocketAddr = match tokio::net::lookup_host(&socks_ep).await {
        Ok(mut it) => match it.next() {
            Some(addr) => addr,
            None => {
                return Err(color_eyre::eyre::eyre!(format!(
                    "No addresses found for {}",
                    socks_ep
                )));
            }
        },
        Err(e) => {
            return Err(color_eyre::eyre::eyre!(format!(
                "Failed to resolve {}: {}",
                socks_ep, e
            )));
        }
    };
    let port = args.port;
    let soax_password = Arc::new(args.auth.as_ref().and_then(|a| a.password.clone()));
    let auth = args
        .auth
        .as_ref()
        .and_then(|a| match (&a.username, &a.password) {
            (Some(u), Some(p)) => Some(Auth::new(u.clone(), p.clone())),
            _ => None,
        });
    let auth = Arc::new(auth);
    let soax_password = soax_password.clone();
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
    let conn_per_ip = args.conn_per_ip;

    let force_close = args.force_close;

    let listener = TcpListener::bind(addr).await?;
    info!("HTTP Proxy listening on http://{}", addr);
    info!("SOCKS5 backend: {}", socks_addr);

    let soax_settings = Arc::new(SoaxSettings {
        enabled: args.soax_sticky == 1,
        package_id: args.soax_package_id.clone(),
        country: args.soax_country.clone(),
        region: args.soax_region.clone(),
        city: args.soax_city.clone(),
        isp: args.soax_isp.clone(),
        sessionlength: args.soax_sessionlength,
        bindttl: args.soax_bindttl,
        idlettl: args.soax_idlettl,
        opts: args.soax_opt.clone().unwrap_or_default(),
    });

    if soax_settings.enabled {
        info!("SOAX sticky per-connection enabled; sessionlength={}s", soax_settings.sessionlength);
        if soax_settings.package_id.is_none() {
            warn!("--soax-package-id is required when --soax-sticky=1");
        }
        match soax_password.as_ref() {
            Some(p) if !p.is_empty() => { /* ok */ }
            _ => warn!("SOAX mode expects --auth -P <package_key> (SOAX password)"),
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
                    let ip_tracker = IP_TRACKER.get_or_init(|| IpConnectionTracker::new());
                    let client_ip = peer_addr.ip();
                    let current_ip_connections = ip_tracker.get_count(client_ip);

                    if current_ip_connections >= conn_per_ip {
                        warn!("Connection limit exceeded for IP {}: {} connections", client_ip, current_ip_connections);
                        // Close the connection immediately
                        drop(stream);
                        continue;
                    }

                    // Increment connection count for this IP
                    let new_count = ip_tracker.increment(client_ip);
                    if new_count > 20 {
                        info!("High connection count for IP {}: {} connections", client_ip, new_count);
                    }

                    let soax_password = soax_password.clone();
                    let auth = auth.clone();
                    let http_basic = http_basic.clone();
                    let allowed_domains = allowed_domains.clone();
                    let soax_settings = soax_settings.clone();
                    let sessionid = if soax_settings.enabled { Some(new_session_id()) } else { None };
                    tokio::task::spawn(async move {
                        let io = TokioIo::new(stream);
                        let sess = sessionid.clone();
                        let soax_cfg = soax_settings.clone();
                        let service = service_fn(move |req| {
                            proxy(
                                req,
                                socks_addr,
                                auth.clone(),
                                http_basic.clone(),
                                allowed_domains.clone(),
                                no_httpauth,
                                idle_timeout,
                                force_close,
                                soax_password.clone(),
                                soax_cfg.clone(),
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
    socks_addr: SocketAddr,
    auth: Arc<Option<Auth>>,
    http_basic: Arc<Option<HeaderValue>>,
    allowed_domains: Arc<Option<HashSet<String>>>,
    no_httpauth: bool,
    idle_timeout: u64,
    force_close: bool,
    soax_password: Arc<Option<String>>,
    soax_settings: Arc<SoaxSettings>,
    sessionid: Option<String>,
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
                // send a 407 response with Proxy-Authenticate header
                return Ok(proxy_auth_required_response("Proxy authentication required"));
            }
        };

        // Early return for authentication failure
        match http_basic.as_ref() {
            Some(expected_auth) => {
                if auth_header != expected_auth {
                    warn!("Failed to authenticate: {:?}", headers);
                    return Ok(proxy_auth_required_response("Proxy authentication required"));
                }
            }
            None => {
                warn!("HTTP Basic auth not configured but required");
                return Ok(proxy_auth_required_response("Proxy authentication required"));
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
            let auth = auth.clone();
            let soax_password = soax_password.clone();
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let idle_timeout = idle_timeout;
                        if let Err(e) = tunnel(
                                upgraded,
                                addr,
                                socks_addr,
                                auth,
                                idle_timeout,
                                soax_password.clone(),
                                soax_settings.clone(),
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
        let current_connections = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);
        if current_connections >= MAX_CONCURRENT_CONNECTIONS {
            warn!("Connection limit reached: {}", current_connections);
            let mut resp = Response::new(full("Server overloaded, please try again later"));
            *resp.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
            return Ok(resp);
        }

        let mut connection_guard = ConnectionGuard::new();
        let conn_id = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);

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

        let socks_stream = match open_socks5_stream(
            socks_addr,
            addr.as_str(),
            &auth,
            &soax_password,
            &soax_settings,
            sessionid.as_deref(),
        )
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
        if force_close {
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
        let timeout_duration = tokio::time::Duration::from_secs(idle_timeout);
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
                        let remaining = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);
                        warn!("HTTP #{} connection error, {} active", conn_id, remaining);
                        return Err(e);
                    }
                }
            }
            _ = &mut idle_timer => {
                // Timeout reached - abort the connection
                conn_handle.abort();
                connection_guard.decrement();
                let remaining = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);
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

fn is_domain_allowed(allowed: &std::collections::HashSet<String>, host: &str) -> bool {
    if allowed.contains("*") {
        return true;
    }
    if allowed.contains(host) {
        return true;
    }
    for pat in allowed {
        if let Some(suffix) = pat.strip_prefix("*.") {
            // Match any subdomain of suffix (but not the apex)
            if host.ends_with(suffix) {


                // Ensure there is a dot boundary before suffix
                if host.len() > suffix.len() && host.as_bytes()[host.len() - suffix.len() - 1] == b'.' {
                    return true;
                }
            }
        } else if let Some(suffix) = pat.strip_prefix('.') {
            // Match apex or any subdomain of suffix
            if host == suffix {
                return true;
            }
            if host.ends_with(suffix) {
                if host.len() > suffix.len() && host.as_bytes()[host.len() - suffix.len() - 1] == b'.' {
                    return true;
                }
            }
        }
    }
    false
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn proxy_auth_required_response(msg: &'static str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut response = Response::new(full(msg));
    *response.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    response
        .headers_mut()
        .insert(PROXY_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"proxy\""));
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
    socks_addr: SocketAddr,
    auth: Arc<Option<Auth>>,
    idle_timeout: u64,
    soax_password: Arc<Option<String>>,
    soax_settings: Arc<SoaxSettings>,
    sessionid: Option<String>,
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

    let mut connection_guard = ConnectionGuard::new();
    let conn_id = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);

    let socks_stream = match open_socks5_stream(
        socks_addr,
        addr.as_str(),
        &auth,
        &soax_password,
        &soax_settings,
        sessionid.as_deref(),
    )
    .await
    {
        Ok(stream) => stream,
        Err(e) => {
            return Err(color_eyre::eyre::eyre!("Upstream SOCKS5 connection failed: {}", e));
                }
    };

    let mut client = TokioIo::new(upgraded);
    let mut server = socks_stream;

    // Idle-aware bidirectional copy with immediate connection close detection
    let timeout = tokio::time::Duration::from_secs(idle_timeout);
    let mut from_client = 0u64;
    let mut from_server = 0u64;

    // Use buffer pool for memory optimization
    let buffer_pool = BUFFER_POOL.get_or_init(BufferPool::new);
    let use_large_buffers = idle_timeout > 300;
    let mut client_buf = buffer_pool.get_buffer(use_large_buffers);
    let mut server_buf = buffer_pool.get_buffer(use_large_buffers);
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
    buffer_pool.return_buffer(client_buf, use_large_buffers);
    buffer_pool.return_buffer(server_buf, use_large_buffers);

    connection_guard.decrement();
    let remaining = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);

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

    #[test]
    fn test_connection_guard() {
        // Reset counter for test
        ACTIVE_SOCKS5_CONNECTIONS.store(0, Ordering::Relaxed);

        {
            let _guard = ConnectionGuard::new();
            assert_eq!(ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed), 1);
        }

        // Guard should automatically decrement on drop
        assert_eq!(ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_connection_guard_manual_decrement() {
        // Reset counter for test
        ACTIVE_SOCKS5_CONNECTIONS.store(0, Ordering::Relaxed);

        {
            let mut guard = ConnectionGuard::new();
            assert_eq!(ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed), 1);

            guard.decrement();
            assert_eq!(ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed), 0);

            // Second decrement should be no-op
            guard.decrement();
            assert_eq!(ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed), 0);
        }

        // Drop should not decrement again
        assert_eq!(ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new();

        // Test small buffer
        let small_buf = pool.get_buffer(false);
        assert_eq!(small_buf.len(), 8192);

        // Test large buffer
        let large_buf = pool.get_buffer(true);
        assert_eq!(large_buf.len(), 16384);

        // Return buffers
        pool.return_buffer(small_buf, false);
        pool.return_buffer(large_buf, true);

        // Get buffers again - should reuse from pool
        let reused_small = pool.get_buffer(false);
        let reused_large = pool.get_buffer(true);

        assert_eq!(reused_small.len(), 8192);
        assert_eq!(reused_large.len(), 16384);
    }

    #[test]
    fn test_buffer_pool_size_limit() {
        let pool = BufferPool::new();

        // Fill pool beyond limit
        for _ in 0..150 {
            let buf = pool.get_buffer(false);
            pool.return_buffer(buf, false);
        }

        // Pool should limit size to prevent memory bloat
        {
            let buffers = pool.small_buffers.lock().unwrap();
            assert!(buffers.len() <= 100);
        }
    }
    #[test]
    fn test_is_domain_allowed_exact() {
        let mut set = HashSet::new();
        set.insert("example.com".to_string());
        assert!(is_domain_allowed(&set, "example.com"));
        assert!(!is_domain_allowed(&set, "a.example.com"));
    }

    #[test]
    fn test_is_domain_allowed_wildcard_subdomains() {
        let mut set = HashSet::new();
        set.insert("*.example.com".to_string());
        assert!(is_domain_allowed(&set, "a.example.com"));
        assert!(is_domain_allowed(&set, "a.b.example.com"));
        assert!(!is_domain_allowed(&set, "example.com"));
        assert!(!is_domain_allowed(&set, "badexample.com"));
    }

    #[test]
    fn test_is_domain_allowed_leading_dot_suffix() {
        let mut set = HashSet::new();
        set.insert(".example.com".to_string());
        assert!(is_domain_allowed(&set, "example.com"));
        assert!(is_domain_allowed(&set, "a.example.com"));
        assert!(!is_domain_allowed(&set, "badexample.com"));
    }

    #[test]
    fn test_is_domain_allowed_any_wildcard() {
        let mut set = HashSet::new();
        set.insert("*".to_string());
        assert!(is_domain_allowed(&set, "anything.com"));
        assert!(is_domain_allowed(&set, "sub.domain"));
    }

}
