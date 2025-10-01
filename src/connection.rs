use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

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
    connections: Mutex<HashMap<IpAddr, usize>>,
}

impl IpConnectionTracker {
    /// Create a new IP connection tracker
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Helper to lock the connections map with poisoning recovery
    fn lock_connections(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
        self.connections.lock().unwrap_or_else(|poisoned| {
            // Recover from poisoned mutex by clearing potentially corrupted state
            let mut guard = poisoned.into_inner();
            guard.clear();
            guard
        })
    }

    /// Increment connection count for an IP address
    #[cfg(test)]
    pub fn increment(&self, ip: IpAddr) -> usize {
        let mut connections = self.lock_connections();
        let count = connections.entry(ip).or_insert(0);
        *count += 1;
        *count
    }

    /// Try to increment connection count if it doesn't exceed the limit
    /// Returns Some(new_count) if successful, None if limit would be exceeded
    pub fn try_increment(&self, ip: IpAddr, limit: usize) -> Option<usize> {
        let mut connections = self.lock_connections();
        let count = connections.entry(ip).or_insert(0);
        if *count >= limit {
            return None;
        }
        *count += 1;
        Some(*count)
    }

    /// Decrement connection count for an IP address
    pub fn decrement(&self, ip: IpAddr) {
        let mut connections = self.lock_connections();
        if let Some(count) = connections.get_mut(&ip) {
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                connections.remove(&ip);
            }
        }
    }

    /// Get current connection count for an IP address
    pub fn get_count(&self, ip: IpAddr) -> usize {
        let connections = self.lock_connections();
        connections.get(&ip).copied().unwrap_or(0)
    }

    /// Get total number of tracked IPs
    #[allow(dead_code)]
    pub fn tracked_ips_count(&self) -> usize {
        let connections = self.lock_connections();
        connections.len()
    }

    /// Clean up IPs with zero connections (periodic maintenance)
    #[allow(dead_code)]
    pub fn cleanup_zero_connections(&self) -> usize {
        let mut connections = self.lock_connections();
        let before = connections.len();
        connections.retain(|_, &mut count| count > 0);
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

    #[test]
    fn test_ip_connection_tracker() {
        let tracker = IpConnectionTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Test increment
        let count1 = tracker.increment(ip);
        assert_eq!(count1, 1);
        assert_eq!(tracker.get_count(ip), 1);

        let count2 = tracker.increment(ip);
        assert_eq!(count2, 2);
        assert_eq!(tracker.get_count(ip), 2);

        // Test decrement
        tracker.decrement(ip);
        assert_eq!(tracker.get_count(ip), 1);

        tracker.decrement(ip);
        assert_eq!(tracker.get_count(ip), 0);

        // IP should be removed when count reaches 0
        tracker.decrement(ip); // Should not panic
        assert_eq!(tracker.get_count(ip), 0);
    }

    #[test]
    fn test_try_increment_limit_behavior() {
        let tracker = IpConnectionTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let limit = 2;

        // First two increments should succeed up to the limit
        assert_eq!(tracker.try_increment(ip, limit), Some(1));
        assert_eq!(tracker.try_increment(ip, limit), Some(2));

        // Next increment should be rejected (would exceed limit)
        assert_eq!(tracker.try_increment(ip, limit), None);
        assert_eq!(tracker.get_count(ip), 2);

        // After decrement, increment should succeed again
        tracker.decrement(ip);
        assert_eq!(tracker.try_increment(ip, limit), Some(2));
    }

    #[test]
    fn test_connection_guard_respects_limit() {
        ACTIVE_SOCKS5_CONNECTIONS.store(MAX_CONCURRENT_CONNECTIONS, Ordering::Relaxed);

        assert!(ConnectionGuard::try_new().is_none());

        // Reset counter so subsequent tests are unaffected
        ACTIVE_SOCKS5_CONNECTIONS.store(0, Ordering::Relaxed);
    }
}
