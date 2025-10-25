use clap::{value_parser, Args, Parser};
use std::collections::HashSet;
use std::net::Ipv4Addr;

use clap::ValueEnum;

/// Listen mode for the proxy server
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ListenMode {
    /// HTTP proxy -> upstream SOCKS5
    Http,
    /// SOCKS5 proxy -> upstream SOCKS5
    Socks,
}

/// SOCKS5 authentication credentials
#[derive(Debug, Clone, Args)]
pub struct Auths {
    /// Socks5 username (optional; not needed in --soax-sticky mode)
    #[arg(short = 'u', long)]
    pub username: Option<String>,

    /// Socks5/vendor password (-P)
    /// - SOAX mode: package_key
    /// - Connpnt mode: vendor password
    #[arg(short = 'P', long)]
    pub password: Option<String>,
}

/// Command line interface configuration
#[derive(Parser, Debug)]
#[command(
    author, version,
    about = "SOCKS/HTTP proxy forwarder",
    long_about = "sthp converts between protocols and forwards via an upstream SOCKS5 proxy.\n\nModes:\n- http  : HTTP proxy -> upstream SOCKS5 (existing)\n- socks : SOCKS5 proxy -> upstream SOCKS5 (new)\n\nFeatures:\n- Optional HTTP Basic or inbound SOCKS5 auth\n- Domain allowlist\n- Connection caps and idle timeout\n- Traffic statistics with persistence (--stats-dir, --stats-interval)\n- Management endpoints (HTTP mode only): GET /stats, POST /stats/reset\n"
)]

pub struct Cli {
    /// Listen mode: http or socks
    #[arg(long, value_enum, default_value_t = ListenMode::Http)]
    pub mode: ListenMode,

    /// Port to listen on (HTTP). Use --http-port to override.
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,

    /// HTTP listen port (overrides --port when provided)
    #[arg(long = "http-port")]
    pub http_port: Option<u16>,

    /// Optional extra SOCKS5 listen port to enable concurrent SOCKS server
    #[arg(long = "socks-port")]
    pub socks_port: Option<u16>,

    /// IP address to bind the server (applies to both HTTP and SOCKS listeners)
    #[arg(long, default_value = "0.0.0.0")]
    pub listen_ip: Ipv4Addr,

    /// SOCKS5 authentication credentials for upstream server
    #[command(flatten)]
    pub auth: Option<Auths>,

    /// Upstream SOCKS5 proxy address or hostname:port
    #[arg(short, long, default_value = "127.0.0.1:1080", value_name = "HOST:PORT")]
    pub socks_address: String,

    /// Inbound SOCKS5 auth for socks mode (format: user:pass)
    #[arg(long = "socks-in-auth")]
    pub socks_in_auth: Option<String>,

    /// Enable SOAX sticky session per client connection: 1 or 0
    #[arg(long = "soax-sticky", value_parser = value_parser!(u8).range(0..=1), default_value_t = 0)]
    pub soax_sticky: u8,

    /// SOAX package id (required when --soax-sticky=1)
    #[arg(long)]
    pub soax_package_id: Option<String>,

    /// SOAX target country (ISO 3166-1 alpha-2 code or full name), e.g., "US" or "United States" (optional)
    #[arg(long, value_name = "COUNTRY")]
    pub soax_country: Option<String>,

    /// SOAX target region/state/province within the country, e.g., "California" or "CA" (optional)
    #[arg(long, value_name = "REGION")]
    pub soax_region: Option<String>,

    /// SOAX target city name, e.g., "Los Angeles" (optional)
    #[arg(long, value_name = "CITY")]
    pub soax_city: Option<String>,

    /// SOAX target ISP/carrier name, e.g., "AT&T" (optional)
    #[arg(long, value_name = "ISP")]
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

    /// Connpnt vendor: enable mode (1/0)
    #[arg(long = "connpnt-enable", value_parser = value_parser!(u8).range(0..=1), default_value_t = 0)]
    pub connpnt_enable: u8,

    /// Connpnt base username (e.g., "ku2605kbkxid")
    #[arg(long = "connpnt-user")]
    pub connpnt_user: Option<String>,

    /// Connpnt target country (e.g., "US", "BR")
    #[arg(long = "connpnt-country")]
    pub connpnt_country: Option<String>,

    /// Connpnt keeptime in minutes (0 means unlimited)
    #[arg(long = "connpnt-keeptime")]
    pub connpnt_keeptime: Option<u32>,

    /// Connpnt project name to prefix ipstr (e.g., proj1, proj2)
    #[arg(long = "connpnt-project")]
    pub connpnt_project: Option<String>,

    /// Connpnt entry hosts (comma-separated)
    #[arg(long = "connpnt-entry-hosts", value_delimiter = ',')]
    pub connpnt_entry_hosts: Option<Vec<String>>,

    /// Connpnt SOCKS port (default 9135)
    #[arg(long = "connpnt-socks-port")]
    pub connpnt_socks_port: Option<u16>,

    /// Comma-separated list of allowed domains
    #[arg(long, value_delimiter = ',')]
    pub allowed_domains: Option<Vec<String>>,

    /// HTTP Basic Auth credentials in the format "user:passwd"
    #[arg(long)]
    pub http_basic: Option<String>,

    /// Disable HTTP authentication: 1 or 0 (HTTP mode only)
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

    /// Directory to persist traffic stats files (per-port). Default: current dir.
    #[arg(long = "stats-dir")]
    pub stats_dir: Option<String>,

    /// Interval seconds to log and persist traffic stats
    #[arg(long = "stats-interval", default_value_t = 60)]
    pub stats_interval: u64,
}

/// Connpnt-style vendor settings (dynamic username pattern)
#[derive(Clone, Debug)]
pub struct ConnpntSettings {
    pub enabled: bool,
    pub base_user: Option<String>,
    pub country: Option<String>,
    pub keeptime_minutes: u32,
    pub project: Option<String>,
    pub entry_hosts: Vec<String>,
    pub socks_port: u16,
}

impl ConnpntSettings {
    pub fn from_cli(args: &Cli) -> Self {
        let enabled = args.connpnt_enable == 1;
        let entry_hosts = if let Some(hs) = args.connpnt_entry_hosts.clone() {
            hs
        } else {
            let is_us = args
                .connpnt_country
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case("US"))
                .unwrap_or(false);
            if is_us {
                vec![
                    "pv3.connpnt134.com".to_string(),
                    "pv2.connpnt134.com".to_string(),
                ]
            } else {
                vec![
                    "pv5.connpnt134.com".to_string(),
                    "pv4.connpnt134.com".to_string(),
                ]
            }
        };
        Self {
            enabled,
            base_user: args.connpnt_user.clone(),
            country: args.connpnt_country.clone(),
            keeptime_minutes: args.connpnt_keeptime.unwrap_or(0),
            project: args.connpnt_project.clone(),
            entry_hosts,
            socks_port: args.connpnt_socks_port.unwrap_or(9135),
        }
    }

    pub fn validate(&self, vendor_password: &Option<String>) -> Result<(), String> {
        if !self.enabled { return Ok(()); }
        if self.base_user.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            return Err("Connpnt mode requires --connpnt-user".to_string());
        }
        if self.country.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            return Err("Connpnt mode requires --connpnt-country".to_string());
        }
        match vendor_password {
            Some(p) if !p.is_empty() => {},
            _ => return Err("Connpnt mode requires --password (-P) as vendor password".to_string()),
        }
        if self.entry_hosts.is_empty() {
            return Err("Connpnt mode requires at least one --connpnt-entry-hosts".to_string());
        }
        Ok(())
    }
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
        fn append_key_value(username: &mut String, key: &str, value: impl std::fmt::Display) {
            if !username.is_empty() {
                username.push('-');
            }
            username.push_str(key);
            username.push('-');
            use std::fmt::Write as _;
            let _ = write!(username, "{}", value);
        }

        let estimated_len = 32 + self.opts.iter().map(|opt| opt.len() + 5).sum::<usize>();
        let mut username = String::with_capacity(estimated_len);

        if let Some(pkg) = &self.package_id {
            append_key_value(&mut username, "package", pkg);
        }
        if let Some(country) = &self.country {
            append_key_value(&mut username, "country", country);
        }
        if let Some(region) = &self.region {
            append_key_value(&mut username, "region", region);
        }
        if let Some(city) = &self.city {
            append_key_value(&mut username, "city", city);
        }
        if let Some(isp) = &self.isp {
            append_key_value(&mut username, "isp", isp);
        }

        for opt in &self.opts {
            append_key_value(&mut username, "opt", opt);
        }

        if let Some(sid) = sessionid {
            append_key_value(&mut username, "sessionid", sid);
            // sessionlength only meaningful when sessionid is present
            append_key_value(&mut username, "sessionlength", self.sessionlength);
            if let Some(bindttl) = self.bindttl {
                append_key_value(&mut username, "bindttl", bindttl);
            }
            if let Some(idlettl) = self.idlettl {
                append_key_value(&mut username, "idlettl", idlettl);
            }
        }

        username
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
    pub mode: ListenMode,
    pub listen_addr: std::net::SocketAddr,
    pub socks_addr: std::net::SocketAddr,
    pub socks_listen_addr: Option<std::net::SocketAddr>,

    pub allowed_domains: Option<HashSet<String>>,
    pub http_basic_auth: Option<hyper::header::HeaderValue>,
    pub no_httpauth: bool,
    pub idle_timeout: u64,
    pub conn_per_ip: usize,
    pub force_close: bool,
    pub soax_settings: SoaxSettings,
    pub vendor_password: Option<String>,
    pub socks_auth: Option<crate::auth::Auth>,
    pub socks_in_auth: Option<crate::auth::Auth>,
    pub stats_dir: Option<String>,
    pub stats_interval: u64,
    pub connpnt_settings: ConnpntSettings,
}

impl ProxyConfig {
    /// Create ProxyConfig from CLI arguments
    pub async fn from_cli(args: Cli) -> color_eyre::Result<Self> {
        use base64::engine::general_purpose;
        use base64::Engine;
        use hyper::header::HeaderValue;

        // Resolve default SOCKS5 address (used in Standard/SOAX modes)
        let socks_addr = match tokio::net::lookup_host(&args.socks_address).await {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => return Err(color_eyre::eyre::eyre!("No addresses found for {}", args.socks_address)),
            },
            Err(e) => return Err(color_eyre::eyre::eyre!("Failed to resolve {}: {}", args.socks_address, e)),
        };

        // Create HTTP listen address (supports --http-port override)
        let http_port = args.http_port.unwrap_or(args.port);
        let listen_addr = std::net::SocketAddr::from((args.listen_ip, http_port));

        // Optional extra SOCKS listener address when --socks-port is provided
        let socks_listen_addr = args
            .socks_port
            .map(|p| std::net::SocketAddr::from((args.listen_ip, p)));

        // Convert allowed domains to HashSet
        let allowed_domains = args.allowed_domains.clone().map(|v| {
            v.into_iter()
                .map(|pattern| pattern.to_ascii_lowercase())
                .collect()
        });

        // Extract vendor password (-P) and SOCKS auth separately
        let vendor_password = args.auth.as_ref().and_then(|a| a.password.clone());
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

        // Provider settings
        let soax_settings = SoaxSettings::from_cli(&args);
        let connpnt_settings = ConnpntSettings::from_cli(&args);

        // Validate provider configuration and mutual exclusivity
        if soax_settings.enabled && connpnt_settings.enabled {
            return Err(color_eyre::eyre::eyre!("SOAX and Connpnt modes cannot both be enabled"));
        }
        soax_settings.validate(&vendor_password)
            .map_err(|e| color_eyre::eyre::eyre!(e))?;
        connpnt_settings.validate(&vendor_password)
            .map_err(|e| color_eyre::eyre::eyre!(e))?;

        // Inbound SOCKS5 auth (socks mode)
        let socks_in_auth = match args.socks_in_auth.as_ref() {
            Some(s) => {
                let mut parts = s.splitn(2, ':');
                let u = parts.next().unwrap_or("").to_string();
                let p = parts.next().unwrap_or("").to_string();
                if u.is_empty() || p.is_empty() {
                    return Err(color_eyre::eyre::eyre!("Invalid --socks-in-auth, expected user:pass"));
                }
                Some(crate::auth::Auth::new(u, p))
            }
            None => None,
        };

        Ok(Self {
            mode: args.mode,
            listen_addr,
            socks_listen_addr,
            socks_addr,
            allowed_domains,
            http_basic_auth,
            no_httpauth: args.no_httpauth == 1,
            idle_timeout: args.idle_timeout,
            conn_per_ip: args.conn_per_ip,
            force_close: args.force_close,
            soax_settings,
            vendor_password,
            socks_auth,
            socks_in_auth,
            stats_dir: args.stats_dir.clone(),
            stats_interval: args.stats_interval,
            connpnt_settings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SoaxSettings;

    fn base_settings() -> SoaxSettings {
        SoaxSettings {
            enabled: true,
            package_id: Some("pkg123".to_string()),
            country: Some("US".to_string()),
            region: Some("CA".to_string()),
            city: Some("LosAngeles".to_string()),
            isp: Some("ATT".to_string()),
            sessionlength: 300,
            bindttl: Some(120),
            idlettl: Some(60),
            opts: vec!["uniqip".to_string(), "lookalike".to_string()],
        }
    }

    #[test]
    fn build_username_without_session() {
        let mut settings = base_settings();
        settings.bindttl = None;
        settings.idlettl = None;

        let username = settings.build_username(None);
        assert_eq!(
            username,
            "package-pkg123-country-US-region-CA-city-LosAngeles-isp-ATT-opt-uniqip-opt-lookalike"
        );
    }

    #[test]
    fn build_username_with_session_and_ttls() {
        let settings = base_settings();
        let username = settings.build_username(Some("abcdef"));
        assert_eq!(
            username,
            "package-pkg123-country-US-region-CA-city-LosAngeles-isp-ATT-opt-uniqip-opt-lookalike-\
sessionid-abcdef-sessionlength-300-bindttl-120-idlettl-60"
        );
    }
}
