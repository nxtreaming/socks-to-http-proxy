use tokio::sync::Mutex;

const MAX_POOL_SIZE: usize = 100;

/// Buffer pool for memory optimization backed by async-aware mutexes
pub struct BufferPool {
    small_buffers: Mutex<Vec<Vec<u8>>>, // 8KB buffers
    large_buffers: Mutex<Vec<Vec<u8>>>, // 16KB buffers
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new() -> Self {
        Self {
            small_buffers: Mutex::new(Vec::with_capacity(MAX_POOL_SIZE)),
            large_buffers: Mutex::new(Vec::with_capacity(MAX_POOL_SIZE)),
        }
    }

    /// Helper to determine buffer size based on `large` flag
    fn buffer_size(large: bool) -> usize {
        if large {
            16_384
        } else {
            8_192
        }
    }

    /// Get a buffer from the pool or create a new one
    pub async fn get_buffer(&self, large: bool) -> Vec<u8> {
        let size = Self::buffer_size(large);
        let mut pool = if large {
            self.large_buffers.lock().await
        } else {
            self.small_buffers.lock().await
        };

        if let Some(mut buffer) = pool.pop() {
            let capacity = buffer.capacity();

            // Returned buffers should already be sized appropriately, but double-check in debug
            debug_assert!(capacity >= size);
            debug_assert!(capacity <= size * 2);

            if capacity < size {
                // Capacity mismatch - fall back to allocating a fresh buffer.
                return vec![0u8; size];
            }

            if buffer.len() > size {
                buffer.truncate(size);
            } else if buffer.len() < size {
                unsafe {
                    buffer.set_len(size);
                }
            }

            buffer
        } else {
            vec![0u8; size]
        }
    }

    /// Return a buffer to the pool for reuse
    pub async fn return_buffer(&self, mut buffer: Vec<u8>, large: bool) {
        let expected_size = Self::buffer_size(large);

        // Reject buffers with wrong capacity to avoid memory bloat
        if buffer.capacity() < expected_size || buffer.capacity() > expected_size * 2 {
            return;
        }

        // Zero the buffer on return to avoid leaking data between connections
        buffer.clear();
        buffer.resize(expected_size, 0);
        debug_assert_eq!(buffer.len(), expected_size);

        let mut pool = if large {
            self.large_buffers.lock().await
        } else {
            self.small_buffers.lock().await
        };

        if pool.len() < MAX_POOL_SIZE {
            pool.push(buffer);
        }
    }

    /// Get statistics about the buffer pool
    pub async fn stats(&self) -> BufferPoolStats {
        let small_count = {
            let pool = self.small_buffers.lock().await;
            pool.len()
        };
        let large_count = {
            let pool = self.large_buffers.lock().await;
            pool.len()
        };

        BufferPoolStats {
            small_buffers_available: small_count,
            large_buffers_available: large_count,
            total_memory_pooled: (small_count * 8_192) + (large_count * 16_384),
        }
    }

    /// Clear all buffers from the pool (useful for testing or memory cleanup)
    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.small_buffers.lock().await.clear();
        self.large_buffers.lock().await.clear();
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
pub async fn get_buffer(large: bool) -> Vec<u8> {
    get_buffer_pool().get_buffer(large).await
}

/// Convenience function to return a buffer to the global pool
pub async fn return_buffer(buffer: Vec<u8>, large: bool) {
    get_buffer_pool().return_buffer(buffer, large).await;
}

/// Get statistics from the global buffer pool
#[allow(dead_code)]
pub async fn get_pool_stats() -> BufferPoolStats {
    get_buffer_pool().stats().await
}

/// RAII lease that returns the buffer to the global pool on drop
#[derive(Debug)]
pub struct BufferLease {
    buffer: Option<Vec<u8>>, // kept as Vec<u8> to reuse capacity and avoid reallocs
    large: bool,
}

impl BufferLease {
    /// Create a new lease by pulling a buffer from the global pool
    pub async fn new(large: bool) -> Self {
        let buf = get_buffer(large).await;
        Self { buffer: Some(buf), large }
    }

    /// Access the underlying buffer as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer
            .as_mut()
            .expect("buffer should be present")
            .as_mut_slice()
    }

    /// Length of the buffer (always the configured size for small/large)
    pub fn len(&self) -> usize {
        self.buffer
            .as_ref()
            .expect("buffer should be present")
            .len()
    }

    /// Capacity of the buffer
    pub fn capacity(&self) -> usize {
        self.buffer
            .as_ref()
            .expect("buffer should be present")
            .capacity()
    }
}

impl Drop for BufferLease {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            let large = self.large;
            // Return the buffer asynchronously without blocking drop
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    return_buffer(buffer, large).await;
                });
            }
        }
    }
}

/// Convenience function to obtain a leased buffer
pub async fn lease_buffer(large: bool) -> BufferLease {
    BufferLease::new(large).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_buffer_pool_basic_operations() {
        let pool = BufferPool::new();

        // Test small buffer
        let small_buf = pool.get_buffer(false).await;
        assert_eq!(small_buf.len(), 8_192);

        // Test large buffer
        let large_buf = pool.get_buffer(true).await;
        assert_eq!(large_buf.len(), 16_384);

        // Return buffers
        pool.return_buffer(small_buf, false).await;
        pool.return_buffer(large_buf, true).await;

        // Get buffers again - should reuse from pool
        let reused_small = pool.get_buffer(false).await;
        let reused_large = pool.get_buffer(true).await;

        assert_eq!(reused_small.len(), 8_192);
        assert_eq!(reused_large.len(), 16_384);
    }

    #[tokio::test]
    async fn test_buffer_pool_size_limit() {
        let pool = BufferPool::new();

        // Fill pool beyond limit
        for _ in 0..150 {
            let buf = pool.get_buffer(false).await;
            pool.return_buffer(buf, false).await;
        }

        // Pool should limit size to prevent memory bloat
        let stats = pool.stats().await;
        assert!(stats.small_buffers_available <= 100);
    }

    #[tokio::test]
    async fn test_buffer_pool_wrong_size_rejection() {
        let pool = BufferPool::new();

        // Create a buffer with wrong size
        let wrong_size_buffer = vec![0u8; 4_096]; // 4KB instead of 8KB

        // Pool should reject it
        pool.return_buffer(wrong_size_buffer, false).await;

        let stats = pool.stats().await;
        assert_eq!(stats.small_buffers_available, 0);
    }

    #[tokio::test]
    async fn test_buffer_pool_stats() {
        let pool = BufferPool::new();

        let initial_stats = pool.stats().await;
        assert_eq!(initial_stats.small_buffers_available, 0);
        assert_eq!(initial_stats.large_buffers_available, 0);
        assert_eq!(initial_stats.total_memory_pooled, 0);

        // Add some buffers
        let small_buf = pool.get_buffer(false).await;
        let large_buf = pool.get_buffer(true).await;

        pool.return_buffer(small_buf, false).await;
        pool.return_buffer(large_buf, true).await;

        let stats = pool.stats().await;
        assert_eq!(stats.small_buffers_available, 1);
        assert_eq!(stats.large_buffers_available, 1);
        assert_eq!(stats.total_memory_pooled, 8_192 + 16_384);
    }

    #[tokio::test]
    async fn test_buffer_pool_clear() {
        let pool = BufferPool::new();

        // Add some buffers
        let small_buf = pool.get_buffer(false).await;
        let large_buf = pool.get_buffer(true).await;

        pool.return_buffer(small_buf, false).await;
        pool.return_buffer(large_buf, true).await;

        let stats_before = pool.stats().await;
        assert!(stats_before.small_buffers_available > 0);
        assert!(stats_before.large_buffers_available > 0);

        // Clear the pool
        pool.clear().await;

        let stats_after = pool.stats().await;
        assert_eq!(stats_after.small_buffers_available, 0);
        assert_eq!(stats_after.large_buffers_available, 0);
        assert_eq!(stats_after.total_memory_pooled, 0);
    }

    #[tokio::test]
    async fn test_global_buffer_pool_functions() {
        // Test global convenience functions
        let small_buf = get_buffer(false).await;
        assert_eq!(small_buf.len(), 8_192);

        let large_buf = get_buffer(true).await;
        assert_eq!(large_buf.len(), 16_384);

        return_buffer(small_buf, false).await;
        return_buffer(large_buf, true).await;

        let stats = get_pool_stats().await;
        assert!(stats.small_buffers_available > 0 || stats.large_buffers_available > 0);
    }

    #[tokio::test]
    async fn test_reused_small_buffer_length_and_zeroing() {
        let pool = BufferPool::new();

        let mut buf = pool.get_buffer(false).await;
        let capacity = buf.capacity();

        // Modify contents and shrink length to simulate consumer behavior
        buf.fill(0xAA);
        buf.truncate(128);

        pool.return_buffer(buf, false).await;

        let reused = pool.get_buffer(false).await;
        assert_eq!(reused.len(), 8_192);
        assert_eq!(reused.capacity(), capacity);
        assert!(reused.iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn test_reused_large_buffer_length_and_zeroing() {
        let pool = BufferPool::new();

        let mut buf = pool.get_buffer(true).await;
        let capacity = buf.capacity();

        buf.fill(0x55);
        buf.truncate(256);

        pool.return_buffer(buf, true).await;

        let reused = pool.get_buffer(true).await;
        assert_eq!(reused.len(), 16_384);
        assert_eq!(reused.capacity(), capacity);
        assert!(reused.iter().all(|&b| b == 0));
    }
}
