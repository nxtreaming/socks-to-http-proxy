use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

/// Global counter for tracking active SOCKS5 connections
pub static ACTIVE_SOCKS5_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Connection pool limits for multi-instance deployment on 16GB server
pub const MAX_CONCURRENT_CONNECTIONS: usize = 40000; // 40K concurrent connections (~7.4GB per instance)
pub const CONNECTION_BACKLOG_THRESHOLD: usize = 30000; // 30K warning threshold (~5.5GB)
pub const MEMORY_PRESSURE_THRESHOLD: usize = 35000; // 35K memory threshold (~6.4GB)

/// RAII guard to ensure connection count is properly decremented
pub struct ConnectionGuard {
    decremented: bool,
}

impl ConnectionGuard {
    /// Attempt to create a new connection guard and increment the global counter.
    ///
    /// Returns `None` if acquiring a new slot would exceed the
    /// [`MAX_CONCURRENT_CONNECTIONS`] limit.
    pub fn try_new() -> Option<Self> {
        let mut current = ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed);

        loop {
            if current >= MAX_CONCURRENT_CONNECTIONS {
                return None;
            }

            match ACTIVE_SOCKS5_CONNECTIONS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self { decremented: false }),
                Err(observed) => current = observed,
            }
        }
    }

    /// Manually decrement the connection counter
    pub fn decrement(&mut self) {
        if !self.decremented {
            ACTIVE_SOCKS5_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            self.decremented = true;
        }
    }

    /// Get the current active connection count
    pub fn active_count() -> usize {
        ACTIVE_SOCKS5_CONNECTIONS.load(Ordering::Relaxed)
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.decrement();
    }
}

/// Per-IP connection tracking for rate limiting
pub struct IpConnectionTracker {
    connections: RwLock<HashMap<IpAddr, usize>>,
}

impl IpConnectionTracker {
    /// Create a new IP connection tracker
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Increment connection count for an IP address
    #[cfg(test)]
    pub async fn increment(&self, ip: IpAddr) -> usize {
        let mut connections = self.connections.write().await;
        let entry = connections.entry(ip).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Try to increment connection count if it doesn't exceed the limit
    /// Returns Some(new_count) if successful, None if limit would be exceeded
    pub async fn try_increment(&self, ip: IpAddr, limit: usize) -> Option<usize> {
        let mut connections = self.connections.write().await;
        let entry = connections.entry(ip).or_insert(0);
        if *entry >= limit {
            return None;
        }
        *entry += 1;
        Some(*entry)
    }

    /// Decrement connection count for an IP address
    pub async fn decrement(&self, ip: IpAddr) {
        let mut connections = self.connections.write().await;
        if let Some(entry) = connections.get_mut(&ip) {
            if *entry > 0 {
                *entry -= 1;
            }
            if *entry == 0 {
                connections.remove(&ip);
            }
        }
    }

    /// Get current connection count for an IP address
    pub async fn get_count(&self, ip: IpAddr) -> usize {
        let connections = self.connections.read().await;
        connections.get(&ip).copied().unwrap_or(0)
    }

    /// Get total number of tracked IPs
    #[allow(dead_code)]
    pub async fn tracked_ips_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    /// Clean up IPs with zero connections (periodic maintenance)
    #[allow(dead_code)]
    pub async fn cleanup_zero_connections(&self) -> usize {
        let mut connections = self.connections.write().await;
        let before = connections.len();
        connections.retain(|_, count| *count > 0);
        before - connections.len()
    }
}

impl Default for IpConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Global IP connection tracker instance
pub static IP_TRACKER: std::sync::OnceLock<IpConnectionTracker> = std::sync::OnceLock::new();

/// Get or initialize the global IP tracker
pub fn get_ip_tracker() -> &'static IpConnectionTracker {
    IP_TRACKER.get_or_init(IpConnectionTracker::new)
}

/// Check if the current connection count exceeds the memory pressure threshold
pub fn is_memory_pressure_high() -> bool {
    ConnectionGuard::active_count() > MEMORY_PRESSURE_THRESHOLD
}

/// Check if the current connection count exceeds the backlog threshold
pub fn is_backlog_threshold_exceeded() -> bool {
    ConnectionGuard::active_count() > CONNECTION_BACKLOG_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_connection_guard() {
        // Reset counter for test
        ACTIVE_SOCKS5_CONNECTIONS.store(0, Ordering::Relaxed);

        {
            let _guard = ConnectionGuard::try_new().expect("guard should be acquired");
            assert_eq!(ConnectionGuard::active_count(), 1);
        }

        // Guard should automatically decrement on drop
        assert_eq!(ConnectionGuard::active_count(), 0);
    }

    #[test]
    fn test_connection_guard_manual_decrement() {
        // Reset counter for test
        ACTIVE_SOCKS5_CONNECTIONS.store(0, Ordering::Relaxed);

        {
            let mut guard = ConnectionGuard::try_new().expect("guard should be acquired");
            assert_eq!(ConnectionGuard::active_count(), 1);

            guard.decrement();
            assert_eq!(ConnectionGuard::active_count(), 0);

            // Second decrement should be no-op
            guard.decrement();
            assert_eq!(ConnectionGuard::active_count(), 0);
        }

        // Drop should not decrement again
        assert_eq!(ConnectionGuard::active_count(), 0);
    }

    #[tokio::test]
    async fn test_ip_connection_tracker() {
        let tracker = IpConnectionTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Test increment
        let count1 = tracker.increment(ip).await;
        assert_eq!(count1, 1);
        assert_eq!(tracker.get_count(ip).await, 1);

        let count2 = tracker.increment(ip).await;
        assert_eq!(count2, 2);
        assert_eq!(tracker.get_count(ip).await, 2);

        // Test decrement
        tracker.decrement(ip).await;
        assert_eq!(tracker.get_count(ip).await, 1);

        tracker.decrement(ip).await;
        assert_eq!(tracker.get_count(ip).await, 0);

        // IP should be removed when count reaches 0
        tracker.decrement(ip).await; // Should not panic
        assert_eq!(tracker.get_count(ip).await, 0);
    }

    #[tokio::test]
    async fn test_try_increment_limit_behavior() {
        let tracker = IpConnectionTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let limit = 2;

        // First two increments should succeed up to the limit
        assert_eq!(tracker.try_increment(ip, limit).await, Some(1));
        assert_eq!(tracker.try_increment(ip, limit).await, Some(2));

        // Next increment should be rejected (would exceed limit)
        assert_eq!(tracker.try_increment(ip, limit).await, None);
        assert_eq!(tracker.get_count(ip).await, 2);

        // After decrement, increment should succeed again
        tracker.decrement(ip).await;
        assert_eq!(tracker.try_increment(ip, limit).await, Some(2));
    }

    #[test]
    fn test_connection_guard_respects_limit() {
        ACTIVE_SOCKS5_CONNECTIONS.store(MAX_CONCURRENT_CONNECTIONS, Ordering::Relaxed);

        assert!(ConnectionGuard::try_new().is_none());

        // Reset counter so subsequent tests are unaffected
        ACTIVE_SOCKS5_CONNECTIONS.store(0, Ordering::Relaxed);
    }
}
