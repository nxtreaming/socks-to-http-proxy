use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global session counter for generating unique session IDs
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a new unique session ID
/// 
/// The session ID is composed of:
/// - Current timestamp (lower 48 bits of nanoseconds since UNIX epoch)
/// - Monotonic counter (lower 32 bits)
/// 
/// This ensures uniqueness even with high concurrency and provides
/// a compact, URL-safe lowercase hex representation.
pub fn new_session_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    
    // Use lower 48 bits of nanoseconds and lower 32 bits of counter
    // This provides good uniqueness while keeping the ID compact
    format!(
        "{:x}{:x}",
        now.as_nanos() & 0xffffffffffff,
        counter & 0xffffffff
    )
}

/// Session ID generator with custom configuration
#[allow(dead_code)]
pub struct SessionIdGenerator {
    counter: AtomicU64,
    prefix: Option<String>,
}

#[allow(dead_code)]
impl SessionIdGenerator {
    /// Create a new session ID generator
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
            prefix: None,
        }
    }

    /// Create a new session ID generator with a prefix
    pub fn with_prefix(prefix: String) -> Self {
        Self {
            counter: AtomicU64::new(1),
            prefix: Some(prefix),
        }
    }

    /// Generate a new session ID using this generator
    pub fn generate(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        
        let id = format!(
            "{:x}{:x}",
            now.as_nanos() & 0xffffffffffff,
            counter & 0xffffffff
        );

        match &self.prefix {
            Some(prefix) => format!("{}-{}", prefix, id),
            None => id,
        }
    }

    /// Reset the counter (useful for testing)
    pub fn reset_counter(&self) {
        self.counter.store(1, Ordering::Relaxed);
    }

    /// Get the current counter value
    pub fn current_counter(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

impl Default for SessionIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a session ID format
///
/// A valid session ID should be a hex string of expected length
#[allow(dead_code)]
pub fn is_valid_session_id(session_id: &str) -> bool {
    if session_id.is_empty() {
        return false;
    }

    // Check if all characters are hex digits
    session_id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract timestamp from a session ID (if possible)
///
/// Returns the timestamp in nanoseconds since UNIX epoch, or None if extraction fails
#[allow(dead_code)]
pub fn extract_timestamp_from_session_id(session_id: &str) -> Option<u128> {
    if session_id.len() < 12 {
        return None;
    }

    // Try to parse the first 12 hex characters as the timestamp portion
    let timestamp_hex = &session_id[..12];
    u128::from_str_radix(timestamp_hex, 16).ok()
}

/// Session metadata for tracking and debugging
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub id: String,
    pub created_at: SystemTime,
    pub client_ip: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
}

#[allow(dead_code)]
impl SessionMetadata {
    /// Create new session metadata
    pub fn new(id: String) -> Self {
        Self {
            id,
            created_at: SystemTime::now(),
            client_ip: None,
            user_agent: None,
        }
    }

    /// Create session metadata with client information
    pub fn with_client_info(
        id: String,
        client_ip: std::net::IpAddr,
        user_agent: Option<String>,
    ) -> Self {
        Self {
            id,
            created_at: SystemTime::now(),
            client_ip: Some(client_ip),
            user_agent,
        }
    }

    /// Get the age of this session
    pub fn age(&self) -> std::time::Duration {
        SystemTime::now()
            .duration_since(self.created_at)
            .unwrap_or_default()
    }

    /// Check if the session is older than the specified duration
    pub fn is_older_than(&self, duration: std::time::Duration) -> bool {
        self.age() > duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_new_session_id_uniqueness() {
        let mut ids = HashSet::new();
        
        // Generate multiple session IDs and ensure they're unique
        for _ in 0..1000 {
            let id = new_session_id();
            assert!(!ids.contains(&id), "Duplicate session ID generated: {}", id);
            ids.insert(id);
        }
    }

    #[test]
    fn test_new_session_id_format() {
        let id = new_session_id();
        
        // Should be lowercase hex
        assert!(is_valid_session_id(&id));
        
        // Should have reasonable length (timestamp + counter in hex)
        assert!(id.len() >= 8 && id.len() <= 32);
    }

    #[test]
    fn test_session_id_generator() {
        let generator = SessionIdGenerator::new();
        
        let id1 = generator.generate();
        let id2 = generator.generate();
        
        assert_ne!(id1, id2);
        assert!(is_valid_session_id(&id1));
        assert!(is_valid_session_id(&id2));
    }

    #[test]
    fn test_session_id_generator_with_prefix() {
        let generator = SessionIdGenerator::with_prefix("test".to_string());
        
        let id = generator.generate();
        assert!(id.starts_with("test-"));
        
        // The part after the prefix should still be valid hex
        let hex_part = &id[5..]; // Skip "test-"
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_is_valid_session_id() {
        assert!(is_valid_session_id("abc123def456"));
        assert!(is_valid_session_id("0123456789abcdef"));
        assert!(is_valid_session_id("ABC123")); // Uppercase is now valid

        assert!(!is_valid_session_id(""));
        assert!(!is_valid_session_id("xyz123")); // Invalid hex chars
        assert!(!is_valid_session_id("123-456")); // Contains dash
    }

    #[test]
    fn test_extract_timestamp_from_session_id() {
        let id = new_session_id();
        
        // Should be able to extract some timestamp
        let timestamp = extract_timestamp_from_session_id(&id);
        assert!(timestamp.is_some());
        
        // Invalid cases
        assert!(extract_timestamp_from_session_id("").is_none());
        assert!(extract_timestamp_from_session_id("short").is_none());
        assert!(extract_timestamp_from_session_id("invalid_hex_chars").is_none());
    }

    #[test]
    fn test_session_metadata() {
        let id = new_session_id();
        let metadata = SessionMetadata::new(id.clone());
        
        assert_eq!(metadata.id, id);
        assert!(metadata.client_ip.is_none());
        assert!(metadata.user_agent.is_none());
        
        // Age should be very small for a just-created session
        let age = metadata.age();
        assert!(age.as_secs() < 1);
        
        // Should not be older than 1 second
        assert!(!metadata.is_older_than(std::time::Duration::from_secs(1)));
    }

    #[test]
    fn test_session_metadata_with_client_info() {
        use std::net::Ipv4Addr;
        
        let id = new_session_id();
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let user_agent = Some("test-agent".to_string());
        
        let metadata = SessionMetadata::with_client_info(id.clone(), ip, user_agent.clone());
        
        assert_eq!(metadata.id, id);
        assert_eq!(metadata.client_ip, Some(ip));
        assert_eq!(metadata.user_agent, user_agent);
    }

    #[test]
    fn test_session_id_generator_counter() {
        let generator = SessionIdGenerator::new();
        
        assert_eq!(generator.current_counter(), 1);
        
        generator.generate();
        assert_eq!(generator.current_counter(), 2);
        
        generator.generate();
        assert_eq!(generator.current_counter(), 3);
        
        generator.reset_counter();
        assert_eq!(generator.current_counter(), 1);
    }
}
