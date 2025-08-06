mod auth;

use crate::auth::Auth;
use clap::{Args, Parser, value_parser};
use color_eyre::eyre::Result;

use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, info, warn, error};
use tracing_subscriber::EnvFilter;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::signal;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};
use hyper::header::{HeaderValue, PROXY_AUTHENTICATE};
use base64::engine::general_purpose;
use base64::Engine;

use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

// Global counter for tracking active SOCKS5 connections
static ACTIVE_SOCKS5_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

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
    let auth = &*Box::leak(Box::new(auth));
    let addr = SocketAddr::from((args.listen_ip, port));
    let allowed_domains = args.allowed_domains;
    let allowed_domains = &*Box::leak(Box::new(allowed_domains));
    let http_basic = args.http_basic.map(|hb| format!("Basic {}", general_purpose::STANDARD.encode(hb)));
    let http_basic = &*Box::leak(Box::new(http_basic));
    let no_httpauth = args.no_httpauth == 1;

    let listener = TcpListener::bind(addr).await?;
    info!("HTTP Proxy listening on http://{}", addr);
    info!("SOCKS5 backend: {}", socks_addr);

    // Add a connection monitoring task
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        let mut consecutive_high_count = 0;

        loop {
            interval.tick().await;

            let close_wait_cmd = format!("netstat -an | grep CLOSE_WAIT | grep :{} | wc -l", socks_addr.port());
            let close_wait_count = match tokio::process::Command::new("sh")
                .args(&["-c", &close_wait_cmd])
                .output()
                .await
            {
                Ok(output) => {
                    String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(0)
                }
                Err(e) => {
                    debug!("Failed to check CLOSE_WAIT: {}", e);
                    0
                }
            };

            let active = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);

            if close_wait_count > 0 || active > 0 {
                info!("SOCKS5 Status - Active: {}, CLOSE_WAIT: {}", active, close_wait_count);
            }

            // Alert logic
            match close_wait_count {
                0..=10 => {
                    consecutive_high_count = 0;
                }
                11..=100 => {
                    warn!("Moderate CLOSE_WAIT leak: {} connections", close_wait_count);
                    consecutive_high_count = 0;
                }
                101..=500 => {
                    warn!("High CLOSE_WAIT leak: {} connections", close_wait_count);
                    consecutive_high_count += 1;
                }
                _ => {
                    error!("CRITICAL CLOSE_WAIT leak: {} connections", close_wait_count);
                    consecutive_high_count += 1;
                }
            }

            if consecutive_high_count >= 3 {
                error!("Persistent connection leak detected for {} intervals", consecutive_high_count);
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
                warn!("Forced shutdown with {} connections still active", final_count);
            }
        }
    };

    // Main server loop
    let server = async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("New connection from {}", peer_addr);

                    tokio::task::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(move |req| {
                            proxy(req, socks_addr, auth, &http_basic, allowed_domains, no_httpauth)
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
                    return Err::<(), color_eyre::eyre::Error>(color_eyre::eyre::eyre!("Accept error: {}", e));
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
    auth: &'static Option<Auth>,
    http_basic: &Option<String>,
    allowed_domains: &Option<Vec<String>>,
    no_httpauth: bool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let mut http_authed = false;
    let hm = req.headers();

    if no_httpauth {
        http_authed = true;
    } else if hm.contains_key("proxy-authorization") {
        let config_auth = match http_basic {
            Some(value) => value.clone(),
            None => String::new(),
        };
        let http_auth = hm.get("proxy-authorization").unwrap();
        if http_auth == &HeaderValue::from_str(&config_auth).unwrap() {
            http_authed = true;
        }
    } else {
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

    if !http_authed {
        warn!("Failed to authenticate: {:?}", hm);
        let mut resp = Response::new(full(
            "Authorization failed, you are not allowed through the proxy.",
        ));
        *resp.status_mut() = http::StatusCode::FORBIDDEN;
        return Ok(resp);
    }

    let method = req.method();
    debug!("Proxying request: {} {}", method, req.uri());
    if let (Some(allowed_domains), Some(request_domain)) = (allowed_domains, req.uri().host()) {
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
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr, socks_addr, auth).await {
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

        let conn_id = ACTIVE_SOCKS5_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        debug!("HTTP SOCKS5 #{} connecting to {}", conn_id, addr);

        let socks_stream = match auth {
            Some(auth) => {
                match Socks5Stream::connect_with_password(socks_addr, addr.clone(), &auth.username, &auth.password).await {
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
            None => {
                match Socks5Stream::connect(socks_addr, addr.clone()).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                        warn!("SOCKS5 connection #{} failed: {}", conn_id, e);
                        let mut resp = Response::new(full("SOCKS5 connection failed"));
                        *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                        return Ok(resp);
                    }
                }
            }
        };

        // Critical fix: Force Connection: close to prevent keep-alive
        let mut req = req;
        req.headers_mut().insert("connection", HeaderValue::from_static("close"));

        let io = TokioIo::new(socks_stream);

        let (mut sender, conn) = Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;

        // Spawn connection handler with proper cleanup
        tokio::task::spawn(async move {
            // Set timeout to prevent hanging connections
            let result = tokio::time::timeout(
                tokio::time::Duration::from_secs(30),
                conn
            ).await;

            let remaining = ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed) - 1;

            match result {
                Ok(Ok(_)) => debug!("HTTP #{} connection completed, {} active", conn_id, remaining),
                Ok(Err(e)) => debug!("HTTP #{} connection ended: {}, {} active", conn_id, e, remaining),
                Err(_) => {
                    debug!("HTTP #{} connection timed out, {} active", conn_id, remaining);
                }
            }
        });

        // Send the request with Connection: close header
        let resp = sender.send_request(req).await?;

        // Explicitly drop sender to release resources
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
    auth: &Option<Auth>,
) -> Result<()> {
    let conn_id = ACTIVE_SOCKS5_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    debug!("SOCKS5 tunnel #{} connecting to {}", conn_id, addr);

    let socks_stream = match auth {
        Some(auth) => {
            match Socks5Stream::connect_with_password(socks_addr, addr.clone(), &auth.username, &auth.password).await {
                Ok(stream) => stream,
                Err(e) => {
                    ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    return Err(color_eyre::eyre::eyre!("SOCKS5 auth connection failed: {}", e));
                }
            }
        }
        None => {
            match Socks5Stream::connect(socks_addr, addr.clone()).await {
                Ok(stream) => stream,
                Err(e) => {
                    ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    return Err(color_eyre::eyre::eyre!("SOCKS5 connection failed: {}", e));
                }
            }
        }
    };

    let mut client = TokioIo::new(upgraded);
    let mut server = socks_stream;

    // Simple bidirectional copy
    let copy_result = tokio::io::copy_bidirectional(&mut client, &mut server).await;

    // Critical fix: Always shutdown both ends regardless of copy result
    let server_shutdown = async {
        if let Err(e) = server.shutdown().await {
            debug!("Server shutdown error (normal if danted closed first): {}", e);
        }
    };

    let client_shutdown = async {
        if let Err(e) = client.shutdown().await {
            debug!("Client shutdown error: {}", e);
        }
    };

    tokio::join!(server_shutdown, client_shutdown);

    // Force resource cleanup
    drop(server);
    drop(client);

    let remaining = ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed) - 1;

    match copy_result {
        Ok((from_client, from_server)) => {
            debug!("Tunnel #{} completed: {}↑ {}↓ bytes, {} active",
                   conn_id, from_client, from_server, remaining);
        }
        Err(e) => {
            debug!("Tunnel #{} ended with error: {}, {} active", conn_id, e, remaining);
        }
    }

    Ok(())
}
