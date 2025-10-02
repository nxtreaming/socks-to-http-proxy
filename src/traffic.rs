use std::collections::HashMap;
use std::io;
use tokio::fs as tfs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Per-listener traffic counters (bytes)
#[derive(Debug, Default)]
pub struct TrafficCounters {
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
}

impl TrafficCounters {
    pub fn add_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }
    pub fn rx(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }
    pub fn tx(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }
    pub fn get(&self) -> (u64, u64) {
        (self.rx(), self.tx())
    }
    pub fn set(&self, rx: u64, tx: u64) {
        self.rx_bytes.store(rx, Ordering::Relaxed);
        self.tx_bytes.store(tx, Ordering::Relaxed);
    }
    pub fn reset(&self) {
        self.set(0, 0);
    }
}

/// Global registry of traffic counters keyed by listening port
static TRAFFIC_REGISTRY: std::sync::OnceLock<RwLock<HashMap<u16, Arc<TrafficCounters>>>> =
    std::sync::OnceLock::new();

fn registry() -> &'static RwLock<HashMap<u16, Arc<TrafficCounters>>> {
    TRAFFIC_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Get or create counters for a given listening port
pub async fn get_counters_for_port(port: u16) -> Arc<TrafficCounters> {
    let mut map = registry().write().await;
    map.entry(port)
        .or_insert_with(|| Arc::new(TrafficCounters::default()))
        .clone()
}

/// Reset counters for a given port
pub async fn reset_port(port: u16) {
    let mut map = registry().write().await;
    let entry = map
        .entry(port)
        .or_insert_with(|| Arc::new(TrafficCounters::default()))
        .clone();
    entry.reset();
}

/// Snapshot of current counters for a port
pub async fn snapshot(port: u16) -> Option<(u64, u64)> {
    let map = registry().read().await;
    map.get(&port).map(|c| (c.rx(), c.tx()))
}

/// Snapshot of all counters (port, rx, tx)
#[allow(dead_code)]
pub async fn all_snapshots() -> Vec<(u16, u64, u64)> {
    let map = registry().read().await;
    map.iter()
        .map(|(&port, counters)| (port, counters.rx(), counters.tx()))
        .collect()
}

/// Load counters from a simple text file: lines of "port\trx\ttx"
pub async fn load_from_file(path: &Path) -> io::Result<()> {
    if !tfs::try_exists(path).await? {
        return Ok(());
    }
    let file = tfs::File::open(path).await?;
    let reader = BufReader::new(file);

    let mut updates = Vec::new();
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let line = line;
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        if let (Ok(port), Ok(rx), Ok(tx)) = (
            parts[0].parse::<u16>(),
            parts[1].parse::<u64>(),
            parts[2].parse::<u64>(),
        ) {
            updates.push((port, rx, tx));
        }
    }

    let mut map = registry().write().await;
    for (port, rx, tx) in updates {
        let entry = map
            .entry(port)
            .or_insert_with(|| Arc::new(TrafficCounters::default()))
            .clone();
        entry.set(rx, tx);
    }
    Ok(())
}

/// Save a single port's counters to a file: one line "port\trx\ttx"
pub async fn save_port_to_file(port: u16, path: &Path) -> io::Result<()> {
    let (rx, tx) = snapshot(port).await.unwrap_or((0, 0));
    if let Some(dir) = path.parent() {
        tfs::create_dir_all(dir).await?;
    }
    let mut tmp = PathBuf::from(path);
    tmp.set_extension("tmp");
    let mut f = tfs::File::create(&tmp).await?;
    f.write_all(format!("{}\t{}\t{}\n", port, rx, tx).as_bytes()).await?;
    f.flush().await?;
    drop(f);
    tfs::rename(tmp, path).await?;
    Ok(())
}

/// Save all counters to a file (multi-port): lines of "port\trx\ttx"
#[allow(dead_code)]
pub async fn save_to_file(path: &Path) -> io::Result<()> {
    let snapshot: Vec<(u16, u64, u64)> = all_snapshots().await;
    if let Some(dir) = path.parent() {
        tfs::create_dir_all(dir).await?;
    }
    let mut tmp = PathBuf::from(path);
    tmp.set_extension("tmp");
    let mut f = tfs::File::create(&tmp).await?;
    for (p, rx, tx) in snapshot {
        f.write_all(format!("{}\t{}\t{}\n", p, rx, tx).as_bytes()).await?;
    }
    f.flush().await?;
    drop(f);
    tfs::rename(tmp, path).await?;
    Ok(())
}
