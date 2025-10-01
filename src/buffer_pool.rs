use std::sync::Mutex;

/// Buffer pool for memory optimization
pub struct BufferPool {
    small_buffers: Mutex<Vec<Vec<u8>>>, // 8KB buffers
    large_buffers: Mutex<Vec<Vec<u8>>>, // 16KB buffers
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new() -> Self {
        Self {
            small_buffers: Mutex::new(Vec::new()),
            large_buffers: Mutex::new(Vec::new()),
        }
    }

    /// Helper to lock a buffer pool with poisoning recovery
    fn lock_pool(&self, large: bool) -> std::sync::MutexGuard<'_, Vec<Vec<u8>>> {
        let pool = if large { &self.large_buffers } else { &self.small_buffers };
        pool.lock().unwrap_or_else(|poisoned| {
            // Recover from poisoned mutex by clearing the pool
            let mut guard = poisoned.into_inner();
            guard.clear();
            guard
        })
    }

    /// Get a buffer from the pool or create a new one
    ///
    /// # Arguments
    /// * `large` - If true, returns a 16KB buffer; otherwise returns an 8KB buffer
    pub fn get_buffer(&self, large: bool) -> Vec<u8> {
        let size = if large { 16384 } else { 8192 };
        let mut buffers = self.lock_pool(large);

        if let Some(mut buffer) = buffers.pop() {
            buffer.clear();
            buffer.resize(size, 0);
            return buffer;
        }

        // Create new buffer if pool is empty
        vec![0u8; size]
    }

    /// Return a buffer to the pool for reuse
    ///
    /// # Arguments
    /// * `buffer` - The buffer to return to the pool
    /// * `large` - Whether this is a large buffer (16KB) or small buffer (8KB)
    pub fn return_buffer(&self, mut buffer: Vec<u8>, large: bool) {
        // Only return buffers that are the expected size and capacity to avoid memory bloat
        let expected_size = if large { 16384 } else { 8192 };

        // Reject buffers with wrong size or excessive capacity
        if buffer.len() != expected_size || buffer.capacity() > expected_size * 2 {
            return;
        }

        // Clear the buffer to avoid leaking data between connections
        buffer.clear();
        buffer.resize(expected_size, 0);

        let mut buffers = self.lock_pool(large);
        // Limit pool size to prevent excessive memory usage
        // Use a reasonable limit based on expected concurrency
        if buffers.len() < 100 {
            buffers.push(buffer);
        }
    }

    /// Get statistics about the buffer pool
    #[allow(dead_code)]
    pub fn stats(&self) -> BufferPoolStats {
        let small_count = self.lock_pool(false).len();
        let large_count = self.lock_pool(true).len();

        BufferPoolStats {
            small_buffers_available: small_count,
            large_buffers_available: large_count,
            total_memory_pooled: (small_count * 8192) + (large_count * 16384),
        }
    }

    /// Clear all buffers from the pool (useful for testing or memory cleanup)
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.lock_pool(false).clear();
        self.lock_pool(true).clear();
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the buffer pool
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BufferPoolStats {
    pub small_buffers_available: usize,
    pub large_buffers_available: usize,
    pub total_memory_pooled: usize,
}

/// Global buffer pool instance
pub static BUFFER_POOL: std::sync::OnceLock<BufferPool> = std::sync::OnceLock::new();

/// Get or initialize the global buffer pool
pub fn get_buffer_pool() -> &'static BufferPool {
    BUFFER_POOL.get_or_init(BufferPool::new)
}

/// Convenience function to get a buffer from the global pool
pub fn get_buffer(large: bool) -> Vec<u8> {
    get_buffer_pool().get_buffer(large)
}

/// Convenience function to return a buffer to the global pool
pub fn return_buffer(buffer: Vec<u8>, large: bool) {
    get_buffer_pool().return_buffer(buffer, large);
}

/// Get statistics from the global buffer pool
#[allow(dead_code)]
pub fn get_pool_stats() -> BufferPoolStats {
    get_buffer_pool().stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_basic_operations() {
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
        let stats = pool.stats();
        assert!(stats.small_buffers_available <= 100);
    }

    #[test]
    fn test_buffer_pool_wrong_size_rejection() {
        let pool = BufferPool::new();

        // Create a buffer with wrong size
        let wrong_size_buffer = vec![0u8; 4096]; // 4KB instead of 8KB
        
        // Pool should reject it
        pool.return_buffer(wrong_size_buffer, false);
        
        let stats = pool.stats();
        assert_eq!(stats.small_buffers_available, 0);
    }

    #[test]
    fn test_buffer_pool_stats() {
        let pool = BufferPool::new();
        
        let initial_stats = pool.stats();
        assert_eq!(initial_stats.small_buffers_available, 0);
        assert_eq!(initial_stats.large_buffers_available, 0);
        assert_eq!(initial_stats.total_memory_pooled, 0);

        // Add some buffers
        let small_buf = pool.get_buffer(false);
        let large_buf = pool.get_buffer(true);
        
        pool.return_buffer(small_buf, false);
        pool.return_buffer(large_buf, true);

        let stats = pool.stats();
        assert_eq!(stats.small_buffers_available, 1);
        assert_eq!(stats.large_buffers_available, 1);
        assert_eq!(stats.total_memory_pooled, 8192 + 16384);
    }

    #[test]
    fn test_buffer_pool_clear() {
        let pool = BufferPool::new();
        
        // Add some buffers
        let small_buf = pool.get_buffer(false);
        let large_buf = pool.get_buffer(true);
        
        pool.return_buffer(small_buf, false);
        pool.return_buffer(large_buf, true);

        let stats_before = pool.stats();
        assert!(stats_before.small_buffers_available > 0);
        assert!(stats_before.large_buffers_available > 0);

        // Clear the pool
        pool.clear();

        let stats_after = pool.stats();
        assert_eq!(stats_after.small_buffers_available, 0);
        assert_eq!(stats_after.large_buffers_available, 0);
        assert_eq!(stats_after.total_memory_pooled, 0);
    }

    #[test]
    fn test_global_buffer_pool_functions() {
        // Test global convenience functions
        let small_buf = get_buffer(false);
        assert_eq!(small_buf.len(), 8192);

        let large_buf = get_buffer(true);
        assert_eq!(large_buf.len(), 16384);

        return_buffer(small_buf, false);
        return_buffer(large_buf, true);

        let stats = get_pool_stats();
        assert!(stats.small_buffers_available > 0 || stats.large_buffers_available > 0);
    }
}
