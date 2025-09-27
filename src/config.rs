use clap::{value_parser, Args, Parser};
use std::collections::HashSet;
use std::net::Ipv4Addr;

/// SOCKS5 authentication credentials
#[derive(Debug, Clone, Args)]
pub struct Auths {
    /// Socks5 username (optional; not needed in --soax-sticky mode)
    #[arg(short = 'u', long)]
    pub username: Option<String>,

    /// Socks5 password (SOAX package_key in --soax-sticky mode)
    #[arg(short = 'P', long)]
    pub password: Option<String>,
}

/// Command line interface configuration
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Port where HTTP proxy should listen
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,

    /// IP address to bind the HTTP proxy server
    #[arg(long, default_value = "0.0.0.0")]
    pub listen_ip: Ipv4Addr,

    /// SOCKS5 authentication credentials
    #[command(flatten)]
    pub auth: Option<Auths>,

    /// SOCKS5 proxy address or hostname:port
    #[arg(short, long, default_value = "127.0.0.1:1080", value_name = "HOST:PORT")]
    pub socks_address: String,

    /// Enable SOAX sticky session per client connection: 1 or 0
    #[arg(long = "soax-sticky", value_parser = value_parser!(u8).range(0..=1), default_value_t = 0)]
    pub soax_sticky: u8,

    /// SOAX package id (required when --soax-sticky=1)
    #[arg(long)]
    pub soax_package_id: Option<String>,

    /// SOAX GEO parameters (optional)
    #[arg(long)]
    pub soax_country: Option<String>,
    #[arg(long)]
    pub soax_region: Option<String>,
    #[arg(long)]
    pub soax_city: Option<String>,
    #[arg(long)]
    pub soax_isp: Option<String>,

    /// SOAX session length in seconds (only used when sticky is enabled)
    #[arg(long, default_value_t = 300)]
    pub soax_sessionlength: u32,

    /// SOAX bind TTL in seconds (optional)
    #[arg(long)]
    pub soax_bindttl: Option<u32>,

    /// SOAX idle TTL in seconds (optional)
    #[arg(long)]
    pub soax_idlettl: Option<u32>,

    /// SOAX opt flags (comma-separated, e.g., 'lookalike,uniqip')
    #[arg(long = "soax-opt", value_delimiter = ',')]
    pub soax_opt: Option<Vec<String>>,

    /// Comma-separated list of allowed domains
    #[arg(long, value_delimiter = ',')]
    pub allowed_domains: Option<Vec<String>>,

    /// HTTP Basic Auth credentials in the format "user:passwd"
    #[arg(long)]
    pub http_basic: Option<String>,

    /// Disable HTTP authentication: 1 or 0
    #[arg(long, value_parser = value_parser!(u8).range(0..=1), default_value_t = 1)]
    pub no_httpauth: u8,

    /// Idle timeout in seconds for tunnel connections
    #[arg(long, default_value_t = 540)]
    pub idle_timeout: u64,

    /// Maximum connections per IP address
    #[arg(long = "conn-per-ip", default_value_t = 500)]
    pub conn_per_ip: usize,

    /// Force 'Connection: close' on forwarded HTTP requests
    #[arg(long, default_value_t = true)]
    pub force_close: bool,
}

/// SOAX proxy configuration settings
#[derive(Clone, Debug)]
pub struct SoaxSettings {
    pub enabled: bool,
    pub package_id: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub sessionlength: u32,
    pub bindttl: Option<u32>,
    pub idlettl: Option<u32>,
    pub opts: Vec<String>,
}

impl SoaxSettings {
    /// Build SOAX username string from configuration parameters
    pub fn build_username(&self, sessionid: Option<&str>) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(16);
        
        if let Some(pkg) = &self.package_id {
            parts.push(format!("package-{}", pkg));
        }
        if let Some(c) = &self.country {
            parts.push(format!("country-{}", c));
        }
        if let Some(r) = &self.region {
            parts.push(format!("region-{}", r));
        }
        if let Some(ci) = &self.city {
            parts.push(format!("city-{}", ci));
        }
        if let Some(i) = &self.isp {
            parts.push(format!("isp-{}", i));
        }

        for opt in &self.opts {
            parts.push(format!("opt-{}", opt));
        }

        if let Some(sid) = sessionid {
            parts.push(format!("sessionid-{}", sid));
            // sessionlength only meaningful when sessionid is present
            parts.push(format!("sessionlength-{}", self.sessionlength));
            if let Some(b) = self.bindttl {
                parts.push(format!("bindttl-{}", b));
            }
            if let Some(i) = self.idlettl {
                parts.push(format!("idlettl-{}", i));
            }
        }
        parts.join("-")
    }

    /// Create SoaxSettings from CLI arguments
    pub fn from_cli(args: &Cli) -> Self {
        Self {
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
        }
    }

    /// Validate SOAX configuration
    pub fn validate(&self, soax_password: &Option<String>) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.package_id.is_none() {
            return Err("SOAX mode requires --soax-package-id".to_string());
        }

        match soax_password {
            Some(p) if !p.is_empty() => Ok(()),
            _ => Err("SOAX mode requires --auth -P <package_key> (SOAX password)".to_string()),
        }
    }
}

/// Proxy server configuration derived from CLI arguments
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen_addr: std::net::SocketAddr,
    pub socks_addr: std::net::SocketAddr,
    pub allowed_domains: Option<HashSet<String>>,
    pub http_basic_auth: Option<hyper::header::HeaderValue>,
    pub no_httpauth: bool,
    pub idle_timeout: u64,
    pub conn_per_ip: usize,
    pub force_close: bool,
    pub soax_settings: SoaxSettings,
    pub soax_password: Option<String>,
    pub socks_auth: Option<crate::auth::Auth>,
}

impl ProxyConfig {
    /// Create ProxyConfig from CLI arguments
    pub async fn from_cli(args: Cli) -> color_eyre::Result<Self> {
        use base64::engine::general_purpose;
        use base64::Engine;
        use hyper::header::HeaderValue;

        // Resolve SOCKS5 address
        let socks_addr = match tokio::net::lookup_host(&args.socks_address).await {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => return Err(color_eyre::eyre::eyre!("No addresses found for {}", args.socks_address)),
            },
            Err(e) => return Err(color_eyre::eyre::eyre!("Failed to resolve {}: {}", args.socks_address, e)),
        };

        // Create listen address
        let listen_addr = std::net::SocketAddr::from((args.listen_ip, args.port));

        // Convert allowed domains to HashSet
        let allowed_domains = args.allowed_domains.clone().map(|v| v.into_iter().collect());

        // Extract SOAX password and SOCKS auth first
        let soax_password = args.auth.as_ref().and_then(|a| a.password.clone());
        let socks_auth = args.auth.as_ref()
            .and_then(|a| match (&a.username, &a.password) {
                (Some(u), Some(p)) => Some(crate::auth::Auth::new(u.clone(), p.clone())),
                _ => None,
            });

        // Create HTTP Basic Auth header
        let http_basic_auth = args
            .http_basic
            .clone()
            .map(|hb| format!("Basic {}", general_purpose::STANDARD.encode(hb)))
            .map(|auth_str| HeaderValue::from_str(&auth_str))
            .transpose()
            .map_err(|_| color_eyre::eyre::eyre!("Invalid HTTP Basic auth string"))?;

        // Create SOAX settings
        let soax_settings = SoaxSettings::from_cli(&args);

        // Validate SOAX configuration
        soax_settings.validate(&soax_password)
            .map_err(|e| color_eyre::eyre::eyre!(e))?;

        Ok(Self {
            listen_addr,
            socks_addr,
            allowed_domains,
            http_basic_auth,
            no_httpauth: args.no_httpauth == 1,
            idle_timeout: args.idle_timeout,
            conn_per_ip: args.conn_per_ip,
            force_close: args.force_close,
            soax_settings,
            soax_password,
            socks_auth,
        })
    }
}
