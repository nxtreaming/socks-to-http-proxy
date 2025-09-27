use crate::auth::Auth;
use crate::config::SoaxSettings;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_socks::tcp::Socks5Stream;

/// Error type for SOCKS5 connection operations
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    #[error("SOCKS5 connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("SOAX configuration error: {0}")]
    SoaxConfigError(String),
    
    #[error("Authentication failed: {0}")]
    #[allow(dead_code)]
    AuthenticationFailed(String),
}

/// Result type for SOCKS5 operations
pub type SocksResult<T> = Result<T, SocksError>;

/// SOCKS5 connection manager
#[derive(Debug)]
pub struct SocksConnector {
    socks_addr: SocketAddr,
    auth: Arc<Option<Auth>>,
    soax_password: Arc<Option<String>>,
    soax_settings: Arc<SoaxSettings>,
}

impl SocksConnector {
    /// Create a new SOCKS5 connector
    pub fn new(
        socks_addr: SocketAddr,
        auth: Arc<Option<Auth>>,
        soax_password: Arc<Option<String>>,
        soax_settings: Arc<SoaxSettings>,
    ) -> Self {
        Self {
            socks_addr,
            auth,
            soax_password,
            soax_settings,
        }
    }

    /// Open a SOCKS5 stream to the target address
    pub async fn connect(
        &self,
        target_addr: &str,
        sessionid: Option<&str>,
    ) -> SocksResult<Socks5Stream<tokio::net::TcpStream>> {
        if self.soax_settings.enabled {
            self.connect_soax(target_addr, sessionid).await
        } else {
            self.connect_standard(target_addr).await
        }
    }

    /// Connect using SOAX configuration
    async fn connect_soax(
        &self,
        target_addr: &str,
        sessionid: Option<&str>,
    ) -> SocksResult<Socks5Stream<tokio::net::TcpStream>> {
        let username = self.soax_settings.build_username(sessionid);
        let password = self.soax_password
            .as_ref()
            .as_ref()
            .ok_or_else(|| SocksError::SoaxConfigError(
                "SOAX mode requires password (package_key)".to_string()
            ))?;

        if password.is_empty() {
            return Err(SocksError::SoaxConfigError(
                "SOAX password cannot be empty".to_string()
            ));
        }

        if self.soax_settings.package_id.is_none() {
            return Err(SocksError::SoaxConfigError(
                "SOAX mode requires package_id".to_string()
            ));
        }

        Socks5Stream::connect_with_password(self.socks_addr, target_addr, &username, password)
            .await
            .map_err(|e| SocksError::ConnectionFailed(e.to_string()))
    }

    /// Connect using standard SOCKS5 authentication
    async fn connect_standard(
        &self,
        target_addr: &str,
    ) -> SocksResult<Socks5Stream<tokio::net::TcpStream>> {
        match self.auth.as_ref() {
            Some(auth) => {
                Socks5Stream::connect_with_password(
                    self.socks_addr,
                    target_addr,
                    &auth.username,
                    &auth.password,
                )
                .await
                .map_err(|e| SocksError::ConnectionFailed(e.to_string()))
            }
            None => {
                Socks5Stream::connect(self.socks_addr, target_addr)
                    .await
                    .map_err(|e| SocksError::ConnectionFailed(e.to_string()))
            }
        }
    }

    /// Get the SOCKS5 server address
    #[allow(dead_code)]
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// Check if SOAX mode is enabled
    #[allow(dead_code)]
    pub fn is_soax_enabled(&self) -> bool {
        self.soax_settings.enabled
    }

    /// Validate the connector configuration
    #[allow(dead_code)]
    pub fn validate(&self) -> SocksResult<()> {
        if self.soax_settings.enabled {
            self.soax_settings
                .validate(&self.soax_password.as_ref().clone())
                .map_err(|e| SocksError::SoaxConfigError(e))?;
        }
        Ok(())
    }
}

/// Builder for creating SOCKS5 connectors
#[allow(dead_code)]
pub struct SocksConnectorBuilder {
    socks_addr: Option<SocketAddr>,
    auth: Option<Auth>,
    soax_password: Option<String>,
    soax_settings: Option<SoaxSettings>,
}

#[allow(dead_code)]
impl SocksConnectorBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            socks_addr: None,
            auth: None,
            soax_password: None,
            soax_settings: None,
        }
    }

    /// Set the SOCKS5 server address
    pub fn socks_addr(mut self, addr: SocketAddr) -> Self {
        self.socks_addr = Some(addr);
        self
    }

    /// Set the authentication credentials
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Set the SOAX password
    pub fn soax_password(mut self, password: String) -> Self {
        self.soax_password = Some(password);
        self
    }

    /// Set the SOAX settings
    pub fn soax_settings(mut self, settings: SoaxSettings) -> Self {
        self.soax_settings = Some(settings);
        self
    }

    /// Build the SOCKS5 connector
    pub fn build(self) -> SocksResult<SocksConnector> {
        let socks_addr = self.socks_addr
            .ok_or_else(|| SocksError::ConnectionFailed("SOCKS5 address is required".to_string()))?;

        let soax_settings = self.soax_settings.unwrap_or_else(|| SoaxSettings {
            enabled: false,
            package_id: None,
            country: None,
            region: None,
            city: None,
            isp: None,
            sessionlength: 300,
            bindttl: None,
            idlettl: None,
            opts: Vec::new(),
        });

        let connector = SocksConnector::new(
            socks_addr,
            Arc::new(self.auth),
            Arc::new(self.soax_password),
            Arc::new(soax_settings),
        );

        // Validate the configuration
        connector.validate()?;

        Ok(connector)
    }
}

impl Default for SocksConnectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection statistics for monitoring
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub total_connections: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub soax_connections: u64,
    pub standard_connections: u64,
}

#[allow(dead_code)]
impl ConnectionStats {
    /// Record a successful connection
    pub fn record_success(&mut self, is_soax: bool) {
        self.total_connections += 1;
        self.successful_connections += 1;
        if is_soax {
            self.soax_connections += 1;
        } else {
            self.standard_connections += 1;
        }
    }

    /// Record a failed connection
    pub fn record_failure(&mut self) {
        self.total_connections += 1;
        self.failed_connections += 1;
    }

    /// Get the success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_connections == 0 {
            0.0
        } else {
            (self.successful_connections as f64 / self.total_connections as f64) * 100.0
        }
    }

    /// Get the failure rate as a percentage
    pub fn failure_rate(&self) -> f64 {
        if self.total_connections == 0 {
            0.0
        } else {
            (self.failed_connections as f64 / self.total_connections as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SoaxSettings;
    use std::net::{Ipv4Addr, SocketAddr};

    fn create_test_soax_settings() -> SoaxSettings {
        SoaxSettings {
            enabled: true,
            package_id: Some("test-package".to_string()),
            country: Some("US".to_string()),
            region: None,
            city: None,
            isp: None,
            sessionlength: 300,
            bindttl: None,
            idlettl: None,
            opts: vec!["opt1".to_string()],
        }
    }

    #[test]
    fn test_socks_connector_builder() {
        let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
        let auth = Auth::new("user".to_string(), "pass".to_string());
        
        let connector = SocksConnectorBuilder::new()
            .socks_addr(addr)
            .auth(auth)
            .build()
            .expect("Should build successfully");

        assert_eq!(connector.socks_addr(), addr);
        assert!(!connector.is_soax_enabled());
    }

    #[test]
    fn test_socks_connector_builder_with_soax() {
        let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
        let soax_settings = create_test_soax_settings();
        
        let connector = SocksConnectorBuilder::new()
            .socks_addr(addr)
            .soax_password("test-password".to_string())
            .soax_settings(soax_settings)
            .build()
            .expect("Should build successfully");

        assert_eq!(connector.socks_addr(), addr);
        assert!(connector.is_soax_enabled());
    }

    #[test]
    fn test_socks_connector_builder_missing_addr() {
        let result = SocksConnectorBuilder::new().build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SocksError::ConnectionFailed(_)));
    }

    #[test]
    fn test_socks_connector_validation_soax_missing_password() {
        let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
        let soax_settings = create_test_soax_settings();
        
        let result = SocksConnectorBuilder::new()
            .socks_addr(addr)
            .soax_settings(soax_settings)
            .build();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SocksError::SoaxConfigError(_)));
    }

    #[test]
    fn test_connection_stats() {
        let mut stats = ConnectionStats::default();
        
        assert_eq!(stats.success_rate(), 0.0);
        assert_eq!(stats.failure_rate(), 0.0);
        
        stats.record_success(true); // SOAX connection
        stats.record_success(false); // Standard connection
        stats.record_failure();
        
        assert_eq!(stats.total_connections, 3);
        assert_eq!(stats.successful_connections, 2);
        assert_eq!(stats.failed_connections, 1);
        assert_eq!(stats.soax_connections, 1);
        assert_eq!(stats.standard_connections, 1);
        
        assert!((stats.success_rate() - 66.67).abs() < 0.01);
        assert!((stats.failure_rate() - 33.33).abs() < 0.01);
    }
}
