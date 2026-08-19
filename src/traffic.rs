use std::collections::HashMap;
use std::io;
use tokio::fs as tfs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::warn;

/// Per-listener traffic counters (bytes)
#[derive(Debug, Default)]
pub struct TrafficCounters {
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    /// Last source-absolute rx imported via /stats/add or --stats-sync-from
    sync_rx: AtomicU64,
    sync_tx: AtomicU64,
    /// Counter generation for GET /stats `epoch`: new each process, incremented
    /// on `/stats/reset`. Not restored from the stats file.
    boot_epoch: AtomicU64,
    /// Last source GET /stats epoch observed during sync (0 = unknown / legacy source).
    sync_epoch: AtomicU64,
    /// Source generations that were replaced; delayed samples must not revive them.
    /// New generations are refused once this list reaches [`Self::MAX_RETIRED_EPOCHS`];
    /// existing entries are never evicted.
    retired_epochs: std::sync::Mutex<Vec<u64>>,
}

impl TrafficCounters {
    pub fn add_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_rx_saturating(&self, n: u64) {
        if n == 0 {
            return;
        }
        let _ = self
            .rx_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(n))
            });
    }
    pub fn add_tx_saturating(&self, n: u64) {
        if n == 0 {
            return;
        }
        let _ = self
            .tx_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(n))
            });
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
    pub fn sync_mark(&self) -> (u64, u64) {
        (
            self.sync_rx.load(Ordering::Relaxed),
            self.sync_tx.load(Ordering::Relaxed),
        )
    }
    pub fn set_sync_mark(&self, rx: u64, tx: u64) {
        self.sync_rx.store(rx, Ordering::Relaxed);
        self.sync_tx.store(tx, Ordering::Relaxed);
    }
    pub fn boot_epoch(&self) -> u64 {
        self.boot_epoch.load(Ordering::Acquire)
    }
    /// Consistent (rx, tx, epoch) so GET /stats cannot pair pre-reset totals with
    /// a post-reset generation.
    pub fn snapshot_generation(&self) -> (u64, u64, u64) {
        loop {
            let epoch1 = self.boot_epoch.load(Ordering::Acquire);
            let rx = self.rx_bytes.load(Ordering::Relaxed);
            let tx = self.tx_bytes.load(Ordering::Relaxed);
            let epoch2 = self.boot_epoch.load(Ordering::Acquire);
            if epoch1 == epoch2 {
                return (rx, tx, epoch1);
            }
        }
    }
    pub fn sync_epoch(&self) -> u64 {
        self.sync_epoch.load(Ordering::Relaxed)
    }
    pub fn set_sync_epoch(&self, epoch: u64) {
        self.sync_epoch.store(epoch, Ordering::Relaxed);
    }
    fn set_boot_epoch(&self, epoch: u64) {
        self.boot_epoch.store(epoch, Ordering::Relaxed);
    }
    fn ensure_boot_epoch(&self) {
        if self.boot_epoch.load(Ordering::Relaxed) != 0 {
            return;
        }
        let _ = self.boot_epoch.compare_exchange(
            0,
            process_boot_epoch(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    fn rotate_epoch(&self) {
        let cur = self.boot_epoch.load(Ordering::Relaxed);
        let next = cur.wrapping_add(1);
        self.boot_epoch
            .store(if next == 0 { 1 } else { next }, Ordering::Release);
    }
    /// Hard cap on remembered source generations. Unknown epochs beyond this
    /// are ignored rather than adopted, so delayed samples cannot be revived
    /// by eviction and `/stats/add` cannot grow the set without bound.
    pub const MAX_RETIRED_EPOCHS: usize = 32;
    fn retire_epoch(&self, epoch: u64) {
        if epoch == 0 {
            return;
        }
        let mut retired = self.retired_epochs.lock().expect("retired epochs mutex");
        remember_retired(&mut retired, epoch);
    }
    fn is_retired(&self, epoch: u64) -> bool {
        epoch != 0
            && self
                .retired_epochs
                .lock()
                .expect("retired epochs mutex")
                .contains(&epoch)
    }
    fn can_retire_another(&self) -> bool {
        self.retired_epochs
            .lock()
            .expect("retired epochs mutex")
            .len()
            < Self::MAX_RETIRED_EPOCHS
    }
    fn retired_list(&self) -> Vec<u64> {
        self.retired_epochs
            .lock()
            .expect("retired epochs mutex")
            .clone()
    }
    fn set_retired(&self, epochs: Vec<u64>) {
        *self.retired_epochs.lock().expect("retired epochs mutex") = cap_retired_list(epochs);
    }
    fn retired_after_switch(&self, prev_epoch: u64, new_epoch: u64) -> Vec<u64> {
        let mut retired = self.retired_list();
        if new_epoch != prev_epoch {
            remember_retired(&mut retired, prev_epoch);
        }
        retired
    }
    #[cfg(test)]
    pub fn sub_and_rotate_for_test(&self, snap_rx: u64, snap_tx: u64) {
        self.sub_rx_saturating(snap_rx);
        self.sub_tx_saturating(snap_tx);
        self.rotate_epoch();
    }
    #[cfg(test)]
    fn persist_line(&self, port: u16) -> String {
        let (sync_rx, sync_tx) = self.sync_mark();
        PortFileRecord {
            port,
            rx: self.rx(),
            tx: self.tx(),
            sync_rx,
            sync_tx,
            boot_epoch: self.boot_epoch(),
            sync_epoch: self.sync_epoch(),
            retired: self.retired_list(),
        }
        .to_line()
    }
    fn sub_rx_saturating(&self, n: u64) {
        if n == 0 {
            return;
        }
        let _ = self
            .rx_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(n))
            });
    }
    fn sub_tx_saturating(&self, n: u64) {
        if n == 0 {
            return;
        }
        let _ = self
            .tx_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(n))
            });
    }
    #[cfg(test)]
    pub fn reset(&self) {
        self.set(0, 0);
        // Keep sync watermarks. Clearing them would let --stats-sync-from
        // re-import the old instance's full historical totals after a reset.
    }
}

/// Global registry of traffic counters keyed by listening port
static TRAFFIC_REGISTRY: std::sync::OnceLock<RwLock<HashMap<u16, Arc<TrafficCounters>>>> =
    std::sync::OnceLock::new();
static TRAFFIC_SAVE_LOCKS: std::sync::OnceLock<RwLock<HashMap<u16, Arc<Mutex<()>>>>> =
    std::sync::OnceLock::new();

fn registry() -> &'static RwLock<HashMap<u16, Arc<TrafficCounters>>> {
    TRAFFIC_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

fn save_locks() -> &'static RwLock<HashMap<u16, Arc<Mutex<()>>>> {
    TRAFFIC_SAVE_LOCKS.get_or_init(|| RwLock::new(HashMap::new()))
}

async fn save_lock_for_port(port: u16) -> Arc<Mutex<()>> {
    let mut map = save_locks().write().await;
    map.entry(port)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Stable per-process boot id used in GET /stats `epoch` when a port has no persisted value.
fn process_boot_epoch() -> u64 {
    static EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        (nanos ^ (std::process::id() as u64).wrapping_shl(32)).max(1)
    })
}

/// Get or create counters for a given listening port
pub async fn get_counters_for_port(port: u16) -> Arc<TrafficCounters> {
    let mut map = registry().write().await;
    let counters = map
        .entry(port)
        .or_insert_with(|| Arc::new(TrafficCounters::default()))
        .clone();
    counters.ensure_boot_epoch();
    counters
}

/// Reset counters for a given port (keeps sync watermarks).
/// Takes the per-port save lock so reset cannot interleave with sync/persist.
#[cfg(test)]
pub async fn reset_port(port: u16) {
    let save_lock = save_lock_for_port(port).await;
    let _save_guard = save_lock.lock().await;
    let counters = get_counters_for_port(port).await;
    counters.reset();
}

/// Persist a zeroed snapshot, then subtract that snapshot from live counters.
/// Bytes that existed at the snapshot are cleared; bytes that arrive during the
/// zero write are kept in memory and included in one follow-up snapshot write.
/// Traffic during that follow-up is after the linearization point and is left
/// to the next periodic save. Failure of the initial zeroed file leaves memory
/// unchanged and returns Err. Follow-up write errors are logged; this function
/// still returns Ok because the reset has already been committed.
pub async fn reset_port_and_save(port: u16, path: &Path) -> io::Result<()> {
    let save_lock = save_lock_for_port(port).await;
    let _save_guard = save_lock.lock().await;
    let counters = get_counters_for_port(port).await;
    let (rx, tx) = counters.get();
    let (sync_rx, sync_tx) = counters.sync_mark();
    write_port_file(
        PortFileRecord {
            port,
            rx: 0,
            tx: 0,
            sync_rx,
            sync_tx,
            boot_epoch: counters.boot_epoch(),
            sync_epoch: counters.sync_epoch(),
            retired: counters.retired_list(),
        },
        path,
    )
    .await?;
    counters.sub_rx_saturating(rx);
    counters.sub_tx_saturating(tx);
    let epoch_before = counters.boot_epoch();
    counters.rotate_epoch();
    persist_live_snapshot(
        port,
        path,
        &counters,
        (0, 0, sync_rx, sync_tx, epoch_before),
    )
    .await;
    Ok(())
}

/// Snapshot of current counters for a port
#[cfg(test)]
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
            let sync_rx = parts
                .get(3)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let sync_tx = parts
                .get(4)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let sync_epoch = parts
                .get(6)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let retired = parts
                .get(7)
                .map(|s| parse_retired_list(s))
                .unwrap_or_default();
            updates.push((port, rx, tx, sync_rx, sync_tx, sync_epoch, retired));
        }
    }

    let mut map = registry().write().await;
    for (port, rx, tx, sync_rx, sync_tx, sync_epoch, retired) in updates {
        let entry = map
            .entry(port)
            .or_insert_with(|| Arc::new(TrafficCounters::default()))
            .clone();
        entry.set(rx, tx);
        entry.set_sync_mark(sync_rx, sync_tx);
        // File boot_epoch is ignored. Generation is this process's, rotated on reset.
        entry.set_boot_epoch(0);
        entry.ensure_boot_epoch();
        entry.set_sync_epoch(sync_epoch);
        entry.set_retired(retired);
    }
    Ok(())
}

/// Save a single port's counters to a file: one line "port\trx\ttx\tsync_rx\tsync_tx"
pub async fn save_port_to_file(port: u16, path: &Path) -> io::Result<()> {
    let save_lock = save_lock_for_port(port).await;
    let _save_guard = save_lock.lock().await;
    let counters = get_counters_for_port(port).await;
    let (rx, tx) = counters.get();
    let (sync_rx, sync_tx) = counters.sync_mark();
    write_port_file(
        PortFileRecord {
            port,
            rx,
            tx,
            sync_rx,
            sync_tx,
            boot_epoch: counters.boot_epoch(),
            sync_epoch: counters.sync_epoch(),
            retired: counters.retired_list(),
        },
        path,
    )
    .await
}

struct PortFileRecord {
    port: u16,
    rx: u64,
    tx: u64,
    sync_rx: u64,
    sync_tx: u64,
    boot_epoch: u64,
    sync_epoch: u64,
    retired: Vec<u64>,
}

impl PortFileRecord {
    fn to_line(&self) -> String {
        if self.retired.is_empty() {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                self.port,
                self.rx,
                self.tx,
                self.sync_rx,
                self.sync_tx,
                self.boot_epoch,
                self.sync_epoch
            )
        } else {
            let retired = self
                .retired
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                self.port,
                self.rx,
                self.tx,
                self.sync_rx,
                self.sync_tx,
                self.boot_epoch,
                self.sync_epoch,
                retired
            )
        }
    }
}

fn remember_retired(retired: &mut Vec<u64>, epoch: u64) {
    if epoch == 0 || retired.len() >= TrafficCounters::MAX_RETIRED_EPOCHS {
        return;
    }
    if !retired.contains(&epoch) {
        retired.push(epoch);
    }
}

fn cap_retired_list(epochs: Vec<u64>) -> Vec<u64> {
    let mut out = Vec::new();
    for epoch in epochs {
        remember_retired(&mut out, epoch);
        if out.len() >= TrafficCounters::MAX_RETIRED_EPOCHS {
            break;
        }
    }
    out
}

fn parse_retired_list(s: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for part in s.split(',') {
        if out.len() >= TrafficCounters::MAX_RETIRED_EPOCHS {
            break;
        }
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Ok(epoch) = part.parse::<u64>() {
            remember_retired(&mut out, epoch);
        }
    }
    out
}

async fn write_port_file(rec: PortFileRecord, path: &Path) -> io::Result<()> {
    #[cfg(test)]
    maybe_stall_write(rec.port).await;
    #[cfg(test)]
    if maybe_fail_write(rec.port) {
        return Err(io::Error::other("injected write failure"));
    }
    if let Some(dir) = path.parent() {
        tfs::create_dir_all(dir).await?;
    }
    let mut tmp = PathBuf::from(path);
    tmp.set_extension("tmp");
    let mut f = tfs::File::create(&tmp).await?;
    f.write_all(rec.to_line().as_bytes())
    .await?;
    f.flush().await?;
    drop(f);
    tfs::rename(tmp, path).await?;
    Ok(())
}

/// One follow-up snapshot after a persist-first commit. Concurrent bytes that
/// arrived during the first write are included. Bytes that arrive during this
/// write are after the linearization point. Errors are logged, not returned.
async fn persist_live_snapshot(
    port: u16,
    path: &Path,
    counters: &TrafficCounters,
    written: (u64, u64, u64, u64, u64),
) {
    let (rx, tx) = counters.get();
    let (sync_rx, sync_tx) = counters.sync_mark();
    let live = (rx, tx, sync_rx, sync_tx, counters.boot_epoch());
    if live == written {
        return;
    }
    if let Err(e) = write_port_file(
        PortFileRecord {
            port,
            rx,
            tx,
            sync_rx,
            sync_tx,
            boot_epoch: counters.boot_epoch(),
            sync_epoch: counters.sync_epoch(),
            retired: counters.retired_list(),
        },
        path,
    )
    .await
    {
        warn!(
            "Follow-up stats persist for port {} failed after commit: {}",
            port, e
        );
    }
}

#[cfg(test)]
struct WriteStall {
    port: u16,
    entered: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

#[cfg(test)]
static WRITE_STALLS: std::sync::Mutex<std::collections::VecDeque<WriteStall>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());

#[cfg(test)]
static WRITE_FAIL_AFTER: std::sync::Mutex<Option<(u16, u32)>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn install_write_stall(
    port: u16,
) -> (
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    WRITE_STALLS
        .lock()
        .expect("write stall mutex")
        .push_back(WriteStall {
            port,
            entered: entered_tx,
            release: release_rx,
        });
    (entered_rx, release_tx)
}

#[cfg(test)]
fn install_write_fail_after(port: u16, successes: u32) {
    *WRITE_FAIL_AFTER.lock().expect("write fail mutex") = Some((port, successes));
}

#[cfg(test)]
fn clear_write_fail() {
    *WRITE_FAIL_AFTER.lock().expect("write fail mutex") = None;
}

#[cfg(test)]
async fn maybe_stall_write(port: u16) {
    let stall = {
        let mut queue = WRITE_STALLS.lock().expect("write stall mutex");
        let idx = queue.iter().position(|s| s.port == port);
        match idx {
            Some(i) => queue.remove(i),
            None => None,
        }
    };
    if let Some(stall) = stall {
        let _ = stall.entered.send(());
        let _ = stall.release.await;
    }
}

#[cfg(test)]
fn maybe_fail_write(port: u16) -> bool {
    let mut slot = WRITE_FAIL_AFTER.lock().expect("write fail mutex");
    match slot.as_mut() {
        Some((p, remaining)) if *p == port => {
            if *remaining == 0 {
                *slot = None;
                true
            } else {
                *remaining -= 1;
                false
            }
        }
        _ => false,
    }
}

/// Result of applying another instance's absolute GET /stats counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSyncResult {
    pub added_rx: u64,
    pub added_tx: u64,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncPlan {
    added_rx: u64,
    added_tx: u64,
    new_sync_rx: u64,
    new_sync_tx: u64,
    new_sync_epoch: u64,
}

/// Watermark + epoch plan for one source scrape.
/// `epoch` is a counter generation: a new value means the source reset or
/// restarted. Same generation must never roll watermarks back (stale/out-of-order
/// samples). Sources without epoch also keep watermarks on a dip.
/// `epoch=0` is the unknown/legacy sentinel and is treated as no epoch.
fn plan_sync(
    prev_rx: u64,
    prev_tx: u64,
    prev_epoch: u64,
    source_rx: u64,
    source_tx: u64,
    source_epoch: Option<u64>,
) -> SyncPlan {
    let source_epoch = source_epoch.filter(|&e| e != 0);
    if let Some(e) = source_epoch {
        if prev_epoch != 0 && e != prev_epoch {
            return SyncPlan {
                added_rx: 0,
                added_tx: 0,
                new_sync_rx: source_rx,
                new_sync_tx: source_tx,
                new_sync_epoch: e,
            };
        }
    }
    if source_rx < prev_rx || source_tx < prev_tx {
        return SyncPlan {
            added_rx: 0,
            added_tx: 0,
            new_sync_rx: prev_rx,
            new_sync_tx: prev_tx,
            new_sync_epoch: source_epoch.unwrap_or(prev_epoch),
        };
    }
    SyncPlan {
        added_rx: source_rx - prev_rx,
        added_tx: source_tx - prev_tx,
        new_sync_rx: source_rx,
        new_sync_tx: source_tx,
        new_sync_epoch: source_epoch.unwrap_or(prev_epoch),
    }
}

/// Apply source-absolute rx/tx as a watermark sync and persist.
/// Only the positive delta since the last sync is added, so repeating GET /stats
/// from the old server during DNS overlap will not double-count.
///
/// Persist the expected post-sync file first, then commit the delta in memory.
/// A failure of that first write leaves live counters unchanged. One follow-up
/// snapshot captures concurrent proxy bytes; its errors are logged after commit.
#[cfg(test)]
pub async fn sync_source_and_save(
    port: u16,
    source_rx: u64,
    source_tx: u64,
    path: &Path,
) -> io::Result<StatsSyncResult> {
    sync_source_and_save_with_epoch(port, source_rx, source_tx, None, path).await
}

pub async fn sync_source_and_save_with_epoch(
    port: u16,
    source_rx: u64,
    source_tx: u64,
    source_epoch: Option<u64>,
    path: &Path,
) -> io::Result<StatsSyncResult> {
    let save_lock = save_lock_for_port(port).await;
    let _save_guard = save_lock.lock().await;
    let counters = get_counters_for_port(port).await;
    let source_epoch = source_epoch.filter(|&e| e != 0);
    if let Some(epoch) = source_epoch {
        if counters.is_retired(epoch) {
            let (rx, tx) = counters.get();
            return Ok(StatsSyncResult {
                added_rx: 0,
                added_tx: 0,
                rx,
                tx,
            });
        }
        let prev_epoch = counters.sync_epoch();
        if prev_epoch != 0 && epoch != prev_epoch && !counters.can_retire_another() {
            warn!(
                "Ignoring source epoch {} for port {}: retired generation cap ({}) reached",
                epoch,
                port,
                TrafficCounters::MAX_RETIRED_EPOCHS
            );
            let (rx, tx) = counters.get();
            return Ok(StatsSyncResult {
                added_rx: 0,
                added_tx: 0,
                rx,
                tx,
            });
        }
    }
    let (prev_sync_rx, prev_sync_tx) = counters.sync_mark();
    let (rx, tx) = counters.get();
    let prev_epoch = counters.sync_epoch();
    let plan = plan_sync(
        prev_sync_rx,
        prev_sync_tx,
        prev_epoch,
        source_rx,
        source_tx,
        source_epoch,
    );
    let persisted_rx = rx.saturating_add(plan.added_rx);
    let persisted_tx = tx.saturating_add(plan.added_tx);
    let retired = counters.retired_after_switch(prev_epoch, plan.new_sync_epoch);
    write_port_file(
        PortFileRecord {
            port,
            rx: persisted_rx,
            tx: persisted_tx,
            sync_rx: plan.new_sync_rx,
            sync_tx: plan.new_sync_tx,
            boot_epoch: counters.boot_epoch(),
            sync_epoch: plan.new_sync_epoch,
            retired,
        },
        path,
    )
    .await?;
    counters.add_rx_saturating(plan.added_rx);
    counters.add_tx_saturating(plan.added_tx);
    counters.set_sync_mark(plan.new_sync_rx, plan.new_sync_tx);
    if plan.new_sync_epoch != prev_epoch && prev_epoch != 0 {
        counters.retire_epoch(prev_epoch);
    }
    counters.set_sync_epoch(plan.new_sync_epoch);
    persist_live_snapshot(
        port,
        path,
        &counters,
        (
            persisted_rx,
            persisted_tx,
            plan.new_sync_rx,
            plan.new_sync_tx,
            counters.boot_epoch(),
        ),
    )
    .await;
    let (rx, tx) = counters.get();
    Ok(StatsSyncResult {
        added_rx: plan.added_rx,
        added_tx: plan.added_tx,
        rx,
        tx,
    })
}

/// Parsed `--stats-sync-from` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSyncTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
    /// `user:pass` from `http://user:pass@host:port/stats`, if present
    pub basic_credentials: Option<String>,
}

/// Parse `--stats-sync-from` as `http://[user:pass@]host:port/stats` (http only; use the old IP).
pub fn parse_stats_sync_url(url: &str) -> Result<StatsSyncTarget, String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("stats-sync-from URL is empty".to_string());
    }
    if trimmed.starts_with("https://") {
        return Err("stats-sync-from only supports http:// URLs".to_string());
    }
    let rest = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let (authority, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p.trim_start_matches('/'))),
        None => (rest, "/stats".to_string()),
    };
    let path = if path == "/" || path.is_empty() {
        "/stats".to_string()
    } else {
        path
    };
    let (basic_credentials, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => {
            if userinfo.is_empty() || !userinfo.contains(':') {
                return Err("stats-sync-from userinfo must be user:pass".to_string());
            }
            let mut parts = userinfo.splitn(2, ':');
            let username = parts.next().unwrap_or("");
            let password = parts.next().unwrap_or("");
            if username.is_empty() || password.is_empty() {
                return Err("stats-sync-from userinfo must be user:pass".to_string());
            }
            (Some(userinfo.to_string()), hostport)
        }
        None => (None, authority),
    };
    let (host, port_str) = hostport
        .rsplit_once(':')
        .ok_or_else(|| "stats-sync-from requires host:port".to_string())?;
    if host.is_empty() {
        return Err("stats-sync-from host is invalid".to_string());
    }
    // IPv6 http://[addr]:port is intentionally unsupported; sync targets are IPv4.
    if host.starts_with('[') {
        return Err("stats-sync-from does not support IPv6 addresses".to_string());
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| "stats-sync-from port is invalid".to_string())?;
    Ok(StatsSyncTarget {
        host: host.to_string(),
        port,
        path,
        basic_credentials,
    })
}

/// Parsed GET /stats / POST /stats/add body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedStats {
    pub rx: u64,
    pub tx: u64,
    pub epoch: Option<u64>,
}

/// Parse `{"rx":<u64>,"tx":<u64>}` (optional `port` and `epoch` are accepted).
/// Trailing data is rejected.
pub fn parse_stats_add_json(json: &str) -> Option<ParsedStats> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StatsAddPayload {
        rx: u64,
        tx: u64,
        #[serde(default)]
        #[allow(dead_code)]
        port: Option<u16>,
        #[serde(default)]
        epoch: Option<u64>,
    }
    let parsed: StatsAddPayload = serde_json::from_str(json.trim()).ok()?;
    Some(ParsedStats {
        rx: parsed.rx,
        tx: parsed.tx,
        epoch: parsed.epoch.filter(|&e| e != 0),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_stats_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join("sthp_traffic_tests")
            .join(format!("{}_{}_{}.txt", name, std::process::id(), nanos))
    }

    async fn assert_reload_matches(
        path: &Path,
        port: u16,
        rx: u64,
        tx: u64,
        sync_rx: u64,
        sync_tx: u64,
    ) {
        let counters = get_counters_for_port(port).await;
        counters.set(u64::MAX, u64::MAX);
        counters.set_sync_mark(u64::MAX, u64::MAX);
        load_from_file(path).await.expect("reload stats file");
        assert_eq!(counters.get(), (rx, tx));
        assert_eq!(counters.sync_mark(), (sync_rx, sync_tx));
    }

    #[test]
    fn parse_stats_add_json_accepts_get_stats_payload() {
        assert_eq!(
            parse_stats_add_json("{\"port\":12323,\"rx\":100,\"tx\":200}"),
            Some(ParsedStats {
                rx: 100,
                tx: 200,
                epoch: None
            })
        );
        assert_eq!(
            parse_stats_add_json("{ \"rx\" : 1 , \"tx\" : 2 }"),
            Some(ParsedStats {
                rx: 1,
                tx: 2,
                epoch: None
            })
        );
        assert_eq!(
            parse_stats_add_json("{\"rx\":1,\"tx\":2,\"epoch\":99}"),
            Some(ParsedStats {
                rx: 1,
                tx: 2,
                epoch: Some(99)
            })
        );
        assert_eq!(
            parse_stats_add_json("{\"rx\":1,\"tx\":2,\"epoch\":0}"),
            Some(ParsedStats {
                rx: 1,
                tx: 2,
                epoch: None
            })
        );
        assert_eq!(parse_stats_add_json("{\"rx\":1}"), None);
        assert_eq!(parse_stats_add_json("{\"tx\":2}"), None);
        assert_eq!(parse_stats_add_json("{\"rx\":-1,\"tx\":2}"), None);
        assert_eq!(parse_stats_add_json(""), None);
        assert_eq!(parse_stats_add_json("{\"rx\":1,\"tx\":2}garbage"), None);
        assert_eq!(
            parse_stats_add_json("{\"nested\":{\"rx\":1},\"tx\":2}"),
            None
        );
    }

    #[test]
    fn parse_stats_sync_url_accepts_http_host_port() {
        assert_eq!(
            parse_stats_sync_url("http://10.0.0.8:12323/stats").unwrap(),
            StatsSyncTarget {
                host: "10.0.0.8".to_string(),
                port: 12323,
                path: "/stats".to_string(),
                basic_credentials: None,
            }
        );
        assert_eq!(
            parse_stats_sync_url("10.0.0.8:8080").unwrap(),
            StatsSyncTarget {
                host: "10.0.0.8".to_string(),
                port: 8080,
                path: "/stats".to_string(),
                basic_credentials: None,
            }
        );
        assert_eq!(
            parse_stats_sync_url("http://username:passwd@10.0.0.8:12323/stats").unwrap(),
            StatsSyncTarget {
                host: "10.0.0.8".to_string(),
                port: 12323,
                path: "/stats".to_string(),
                basic_credentials: Some("username:passwd".to_string()),
            }
        );
        assert!(parse_stats_sync_url("https://10.0.0.8:12323/stats").is_err());
        assert!(parse_stats_sync_url("10.0.0.8").is_err());
        assert!(parse_stats_sync_url("http://username@10.0.0.8:12323/stats").is_err());
        assert_eq!(
            parse_stats_sync_url("http://[2001:db8::10]:12323/stats").unwrap_err(),
            "stats-sync-from does not support IPv6 addresses"
        );
    }

    #[test]
    fn plan_sync_grows_or_ignores_same_generation_dip() {
        assert_eq!(
            plan_sync(100, 200, 0, 150, 250, None),
            SyncPlan {
                added_rx: 50,
                added_tx: 50,
                new_sync_rx: 150,
                new_sync_tx: 250,
                new_sync_epoch: 0,
            }
        );
        assert_eq!(
            plan_sync(150, 200, 7, 100, 200, Some(7)),
            SyncPlan {
                added_rx: 0,
                added_tx: 0,
                new_sync_rx: 150,
                new_sync_tx: 200,
                new_sync_epoch: 7,
            }
        );
        assert_eq!(
            plan_sync(100, 200, 1, 40, 500, None),
            SyncPlan {
                added_rx: 0,
                added_tx: 0,
                new_sync_rx: 100,
                new_sync_tx: 200,
                new_sync_epoch: 1,
            }
        );
        assert_eq!(
            plan_sync(100, 200, 7, 5000, 6000, Some(8)),
            SyncPlan {
                added_rx: 0,
                added_tx: 0,
                new_sync_rx: 5000,
                new_sync_tx: 6000,
                new_sync_epoch: 8,
            }
        );
        assert_eq!(
            plan_sync(0, 0, 0, 100, 200, Some(9)),
            SyncPlan {
                added_rx: 100,
                added_tx: 200,
                new_sync_rx: 100,
                new_sync_tx: 200,
                new_sync_epoch: 9,
            }
        );
        assert_eq!(
            plan_sync(100, 0, 7, 10, 0, Some(0)),
            SyncPlan {
                added_rx: 0,
                added_tx: 0,
                new_sync_rx: 100,
                new_sync_tx: 0,
                new_sync_epoch: 7,
            }
        );
    }

    #[tokio::test]
    async fn add_port_and_save_accumulates_and_persists() {
        let port = 39124u16;
        let path = unique_stats_path("add_port_and_save");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(10, 20);

        let result = sync_source_and_save(port, 100, 200, &path)
            .await
            .expect("sync and save");
        assert_eq!(result.added_rx, 100);
        assert_eq!(result.added_tx, 200);
        assert_eq!((result.rx, result.tx), (110, 220));
        assert_eq!(counters.get(), (110, 220));

        let again = sync_source_and_save(port, 100, 200, &path)
            .await
            .expect("repeat sync");
        assert_eq!((again.added_rx, again.added_tx), (0, 0));
        assert_eq!(counters.get(), (110, 220));

        let catch_up = sync_source_and_save(port, 130, 250, &path)
            .await
            .expect("delta sync");
        assert_eq!((catch_up.added_rx, catch_up.added_tx), (30, 50));
        assert_eq!(counters.get(), (140, 270));

        let contents = tfs::read_to_string(&path).await.expect("read saved stats");
        assert_eq!(contents, counters.persist_line(port));

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn reset_port_keeps_sync_watermark() {
        let port = 39125u16;
        let path = unique_stats_path("reset_keeps_watermark");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(10, 20);
        counters.set_sync_mark(0, 0);

        sync_source_and_save(port, 100, 200, &path)
            .await
            .expect("initial sync");
        assert_eq!(counters.get(), (110, 220));
        assert_eq!(counters.sync_mark(), (100, 200));

        reset_port(port).await;
        assert_eq!(counters.get(), (0, 0));
        assert_eq!(counters.sync_mark(), (100, 200));

        let after_reset = sync_source_and_save(port, 100, 200, &path)
            .await
            .expect("sync after reset");
        assert_eq!((after_reset.added_rx, after_reset.added_tx), (0, 0));
        assert_eq!(counters.get(), (0, 0));

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn concurrent_save_port_to_file_calls_do_not_conflict() {
        let port = 39123u16;
        let path = unique_stats_path("concurrent_save_port");
        let counters = get_counters_for_port(port).await;
        counters.set(123, 456);

        let mut tasks = Vec::new();
        for _ in 0..200 {
            let path = path.clone();
            tasks.push(tokio::spawn(async move { save_port_to_file(port, &path).await }));
        }

        for task in tasks {
            task.await.expect("save task should not panic").expect("save should not fail");
        }

        let contents = tfs::read_to_string(&path).await.expect("read saved stats");
        assert_eq!(contents, counters.persist_line(port));

        if let Some(dir) = path.parent() {
            let _ = tfs::remove_dir_all(dir).await;
        }
    }

    async fn unwritable_stats_path(name: &str) -> PathBuf {
        let path = unique_stats_path(name);
        if let Some(dir) = path.parent() {
            tfs::create_dir_all(dir).await.expect("create stats parent");
        }
        let tmp = path.with_extension("tmp");
        tfs::create_dir_all(&tmp)
            .await
            .expect("create blocking tmp dir");
        path
    }

    #[tokio::test]
    async fn persist_failure_does_not_apply_sync_or_drop_live_counters() {
        let port = 39126u16;
        let path = unwritable_stats_path("persist_fail_sync").await;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(100, 200);
        counters.set_sync_mark(0, 0);
        counters.add_rx(10);

        assert!(sync_source_and_save(port, 150, 200, &path).await.is_err());
        assert_eq!(counters.get(), (110, 200));
        assert_eq!(counters.sync_mark(), (0, 0));

        let _ = tfs::remove_dir_all(path.with_extension("tmp")).await;
    }

    #[tokio::test]
    #[serial]
    async fn persist_failure_does_not_lose_concurrent_increments() {
        let port = 39127u16;
        let path = unwritable_stats_path("persist_fail_concurrent").await;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(100, 200);
        counters.set_sync_mark(0, 0);

        let (entered, release) = install_write_stall(port);
        let sync_task = tokio::spawn({
            let path = path.clone();
            async move { sync_source_and_save(port, 150, 200, &path).await }
        });
        entered.await.expect("write should start");
        counters.add_rx(50);
        release.send(()).expect("release write");
        let result = sync_task.await.expect("sync task");
        assert!(result.is_err());
        assert_eq!(counters.rx(), 150);
        assert_eq!(counters.tx(), 200);
        assert_eq!(counters.sync_mark(), (0, 0));

        let _ = tfs::remove_dir_all(path.with_extension("tmp")).await;
    }

    #[tokio::test]
    async fn reset_persist_failure_leaves_counters_unchanged() {
        let port = 39128u16;
        let path = unwritable_stats_path("persist_fail_reset").await;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(100, 200);
        counters.set_sync_mark(50, 60);

        reset_port_and_save(port, &path)
            .await
            .expect_err("write should fail");
        assert_eq!(counters.get(), (100, 200));
        assert_eq!(counters.sync_mark(), (50, 60));

        let _ = tfs::remove_dir_all(path.with_extension("tmp")).await;
    }

    #[tokio::test]
    async fn reset_port_and_save_zeros_bytes_and_keeps_watermark() {
        let port = 39129u16;
        let path = unique_stats_path("reset_and_save");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(10, 20);
        counters.set_sync_mark(0, 0);
        sync_source_and_save(port, 100, 200, &path)
            .await
            .expect("initial sync");

        let epoch_before = counters.boot_epoch();
        reset_port_and_save(port, &path)
            .await
            .expect("reset persist");
        assert_eq!(counters.get(), (0, 0));
        assert_eq!(counters.sync_mark(), (100, 200));
        assert_ne!(counters.boot_epoch(), epoch_before);
        let contents = tfs::read_to_string(&path).await.expect("read");
        assert_eq!(contents, counters.persist_line(port));

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    #[serial]
    async fn reset_keeps_bytes_added_during_persist() {
        let port = 39130u16;
        let path = unique_stats_path("reset_during_write");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(100, 200);
        counters.set_sync_mark(50, 60);

        let (entered, release) = install_write_stall(port);
        let reset_task = tokio::spawn({
            let path = path.clone();
            async move { reset_port_and_save(port, &path).await }
        });
        entered.await.expect("write should start");
        counters.add_rx(10);
        counters.add_tx(5);
        release.send(()).expect("release write");
        reset_task
            .await
            .expect("reset task")
            .expect("reset persist");
        assert_eq!(counters.get(), (10, 5));
        assert_eq!(counters.sync_mark(), (50, 60));
        let contents = tfs::read_to_string(&path).await.expect("read");
        assert_eq!(contents, counters.persist_line(port));
        assert_reload_matches(&path, port, 10, 5, 50, 60).await;

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    #[serial]
    async fn reset_persists_bytes_added_during_followup_write() {
        let port = 39133u16;
        let path = unique_stats_path("reset_during_followup");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(100, 200);
        counters.set_sync_mark(50, 60);

        let (entered1, release1) = install_write_stall(port);
        let (entered2, release2) = install_write_stall(port);
        let reset_task = tokio::spawn({
            let path = path.clone();
            async move { reset_port_and_save(port, &path).await }
        });
        entered1.await.expect("first write should start");
        counters.add_rx(10);
        counters.add_tx(5);
        release1.send(()).expect("release first write");
        entered2.await.expect("follow-up write should start");
        counters.add_rx(3);
        counters.add_tx(1);
        release2.send(()).expect("release follow-up write");
        reset_task
            .await
            .expect("reset task")
            .expect("reset persist");
        assert_eq!(counters.get(), (13, 6));
        assert_eq!(counters.sync_mark(), (50, 60));
        let contents = tfs::read_to_string(&path).await.expect("read");
        // Linearization: follow-up writes the snapshot taken at its start (10,5),
        // not bytes that arrived while that write was in flight.
        assert_eq!(
            contents,
            format!(
                "{}\t10\t5\t50\t60\t{}\t{}\n",
                port,
                counters.boot_epoch(),
                counters.sync_epoch()
            )
        );
        assert_reload_matches(&path, port, 10, 5, 50, 60).await;

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    #[serial]
    async fn reset_followup_persist_failure_still_reports_success() {
        let port = 39134u16;
        let path = unique_stats_path("reset_followup_fail");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(100, 200);
        counters.set_sync_mark(50, 60);
        let epoch_before = counters.boot_epoch();

        install_write_fail_after(port, 1);
        let (entered, release) = install_write_stall(port);
        let reset_task = tokio::spawn({
            let path = path.clone();
            async move { reset_port_and_save(port, &path).await }
        });
        entered.await.expect("first write should start");
        counters.add_rx(10);
        counters.add_tx(5);
        release.send(()).expect("release first write");
        reset_task
            .await
            .expect("reset task")
            .expect("reset already committed");
        assert_eq!(counters.get(), (10, 5));
        assert_eq!(counters.sync_mark(), (50, 60));
        assert_ne!(counters.boot_epoch(), epoch_before);
        let contents = tfs::read_to_string(&path).await.expect("read");
        assert_eq!(
            contents,
            format!(
                "{}\t0\t0\t50\t60\t{}\t{}\n",
                port,
                epoch_before,
                counters.sync_epoch()
            )
        );
        clear_write_fail();

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    #[serial]
    async fn sync_keeps_bytes_added_during_persist() {
        let port = 39131u16;
        let path = unique_stats_path("sync_during_write");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(100, 200);
        counters.set_sync_mark(0, 0);

        let (entered, release) = install_write_stall(port);
        let sync_task = tokio::spawn({
            let path = path.clone();
            async move { sync_source_and_save(port, 150, 200, &path).await }
        });
        entered.await.expect("write should start");
        counters.add_rx(50);
        counters.add_tx(7);
        release.send(()).expect("release write");
        let result = sync_task.await.expect("sync task").expect("sync persist");
        assert_eq!((result.added_rx, result.added_tx), (150, 200));
        assert_eq!(counters.get(), (300, 407));
        assert_eq!(counters.sync_mark(), (150, 200));
        let contents = tfs::read_to_string(&path).await.expect("read");
        assert_eq!(contents, counters.persist_line(port));
        assert_reload_matches(&path, port, 300, 407, 150, 200).await;

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn sync_source_restart_adopts_new_watermark_epoch() {
        let port = 39132u16;
        let path = unique_stats_path("sync_source_restart");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(1000, 2000);
        counters.set_sync_mark(5000, 6000);
        counters.set_sync_epoch(1);

        let dropped = sync_source_and_save_with_epoch(port, 10, 20, Some(2), &path)
            .await
            .expect("source restart");
        assert_eq!((dropped.added_rx, dropped.added_tx), (0, 0));
        assert_eq!(counters.get(), (1000, 2000));
        assert_eq!(counters.sync_mark(), (10, 20));
        assert_eq!(counters.sync_epoch(), 2);

        let catch_up = sync_source_and_save_with_epoch(port, 15, 28, Some(2), &path)
            .await
            .expect("growth after restart");
        assert_eq!((catch_up.added_rx, catch_up.added_tx), (5, 8));
        assert_eq!(counters.get(), (1005, 2008));
        assert_eq!(counters.sync_mark(), (15, 28));
        assert_reload_matches(&path, port, 1005, 2008, 15, 28).await;

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn sync_same_epoch_stale_sample_does_not_roll_back_watermark() {
        let port = 39135u16;
        let path = unique_stats_path("sync_stale_same_epoch");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(0, 0);
        counters.set_sync_mark(0, 0);
        let a = sync_source_and_save_with_epoch(port, 100, 0, Some(7), &path)
            .await
            .expect("first");
        let b = sync_source_and_save_with_epoch(port, 150, 0, Some(7), &path)
            .await
            .expect("grow");
        let stale = sync_source_and_save_with_epoch(port, 100, 0, Some(7), &path)
            .await
            .expect("stale");
        let again = sync_source_and_save_with_epoch(port, 150, 0, Some(7), &path)
            .await
            .expect("repeat");
        assert_eq!(
            [a.added_rx, b.added_rx, stale.added_rx, again.added_rx],
            [100, 50, 0, 0]
        );
        assert_eq!(counters.get(), (150, 0));
        assert_eq!(counters.sync_mark(), (150, 0));
        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn sync_source_epoch_change_resets_watermarks_without_dip() {
        let port = 39136u16;
        let path = unique_stats_path("sync_boot_epoch");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(1000, 2000);
        counters.set_sync_mark(100, 200);
        counters.set_sync_epoch(1);
        let restarted = sync_source_and_save_with_epoch(port, 5000, 6000, Some(2), &path)
            .await
            .expect("boot id change");
        assert_eq!((restarted.added_rx, restarted.added_tx), (0, 0));
        assert_eq!(counters.sync_mark(), (5000, 6000));
        assert_eq!(counters.sync_epoch(), 2);
        assert_eq!(counters.get(), (1000, 2000));
        let catch_up = sync_source_and_save_with_epoch(port, 5010, 6010, Some(2), &path)
            .await
            .expect("same boot growth");
        assert_eq!((catch_up.added_rx, catch_up.added_tx), (10, 10));
        assert_eq!(counters.get(), (1010, 2010));
        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn load_from_file_does_not_restore_boot_epoch() {
        let port = 39138u16;
        let path = unique_stats_path("boot_not_restored");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        let process_epoch = counters.boot_epoch();
        if let Some(dir) = path.parent() {
            tfs::create_dir_all(dir).await.expect("create stats parent");
        }
        tfs::write(
            &path,
            format!("{}\t1\t2\t3\t4\t999999\t5\n", port),
        )
        .await
        .expect("write fake epoch file");
        load_from_file(&path).await.expect("load");
        assert_eq!(counters.get(), (1, 2));
        assert_eq!(counters.sync_mark(), (3, 4));
        assert_eq!(counters.sync_epoch(), 5);
        assert_eq!(counters.boot_epoch(), process_epoch);
        assert_ne!(counters.boot_epoch(), 999999);
        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn sync_retired_generation_is_not_reactivated() {
        let port = 39139u16;
        let path = unique_stats_path("sync_retired_generation");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(0, 0);
        counters.set_sync_mark(0, 0);

        let a = sync_source_and_save_with_epoch(port, 100, 0, Some(7), &path)
            .await
            .expect("e7=100");
        let b = sync_source_and_save_with_epoch(port, 150, 0, Some(7), &path)
            .await
            .expect("e7=150");
        let c = sync_source_and_save_with_epoch(port, 10, 0, Some(8), &path)
            .await
            .expect("e8=10");
        let d = sync_source_and_save_with_epoch(port, 100, 0, Some(7), &path)
            .await
            .expect("delayed e7=100");
        let e = sync_source_and_save_with_epoch(port, 150, 0, Some(7), &path)
            .await
            .expect("delayed e7=150");
        assert_eq!(
            [a.added_rx, b.added_rx, c.added_rx, d.added_rx, e.added_rx],
            [100, 50, 0, 0, 0]
        );
        assert_eq!(counters.get(), (150, 0));
        assert_eq!(counters.sync_mark(), (10, 0));
        assert_eq!(counters.sync_epoch(), 8);
        assert!(counters.is_retired(7));

        counters.set(u64::MAX, u64::MAX);
        counters.set_sync_mark(u64::MAX, u64::MAX);
        counters.set_retired(vec![999]);
        load_from_file(&path).await.expect("reload retired");
        assert_eq!(counters.get(), (150, 0));
        assert_eq!(counters.sync_mark(), (10, 0));
        assert_eq!(counters.sync_epoch(), 8);
        assert!(counters.is_retired(7));
        assert!(!counters.is_retired(999));

        let delayed_after_reload = sync_source_and_save_with_epoch(port, 150, 0, Some(7), &path)
            .await
            .expect("delayed e7 after reload");
        assert_eq!(delayed_after_reload.added_rx, 0);
        assert_eq!(counters.get(), (150, 0));

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn sync_retired_generation_survives_more_than_32_switches() {
        let port = 39142u16;
        let path = unique_stats_path("sync_retired_many_switches");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(0, 0);
        counters.set_sync_mark(0, 0);

        let first = sync_source_and_save_with_epoch(port, 100, 0, Some(1), &path)
            .await
            .expect("e1=100");
        let grew = sync_source_and_save_with_epoch(port, 150, 0, Some(1), &path)
            .await
            .expect("e1=150");
        assert_eq!([first.added_rx, grew.added_rx], [100, 50]);

        for epoch in 2..=(1 + TrafficCounters::MAX_RETIRED_EPOCHS as u64) {
            let switched = sync_source_and_save_with_epoch(port, 10, 0, Some(epoch), &path)
                .await
                .expect("generation switch");
            assert_eq!(switched.added_rx, 0);
        }
        assert!(counters.is_retired(1));
        assert_eq!(
            counters.retired_list().len(),
            TrafficCounters::MAX_RETIRED_EPOCHS
        );
        assert_eq!(
            counters.sync_epoch(),
            1 + TrafficCounters::MAX_RETIRED_EPOCHS as u64
        );
        assert_eq!(counters.get(), (150, 0));

        let past_cap = 2 + TrafficCounters::MAX_RETIRED_EPOCHS as u64;
        let refused = sync_source_and_save_with_epoch(port, 10, 0, Some(past_cap), &path)
            .await
            .expect("generation past cap");
        assert_eq!(refused.added_rx, 0);
        assert_eq!(
            counters.sync_epoch(),
            1 + TrafficCounters::MAX_RETIRED_EPOCHS as u64
        );
        assert_eq!(counters.sync_mark(), (10, 0));
        assert_eq!(
            counters.retired_list().len(),
            TrafficCounters::MAX_RETIRED_EPOCHS
        );

        let delayed_100 = sync_source_and_save_with_epoch(port, 100, 0, Some(1), &path)
            .await
            .expect("delayed e1=100");
        let delayed_150 = sync_source_and_save_with_epoch(port, 150, 0, Some(1), &path)
            .await
            .expect("delayed e1=150");
        assert_eq!([delayed_100.added_rx, delayed_150.added_rx], [0, 0]);
        assert_eq!(counters.get(), (150, 0));
        assert_eq!(counters.sync_mark(), (10, 0));
        assert_eq!(
            counters.sync_epoch(),
            1 + TrafficCounters::MAX_RETIRED_EPOCHS as u64
        );

        counters.set(u64::MAX, u64::MAX);
        counters.set_sync_mark(u64::MAX, u64::MAX);
        counters.set_retired(Vec::new());
        load_from_file(&path).await.expect("reload many retired");
        assert!(counters.is_retired(1));
        let delayed_after_reload = sync_source_and_save_with_epoch(port, 150, 0, Some(1), &path)
            .await
            .expect("delayed e1 after reload");
        assert_eq!(delayed_after_reload.added_rx, 0);
        assert_eq!(counters.get(), (150, 0));

        let current = 1 + TrafficCounters::MAX_RETIRED_EPOCHS as u64;
        let grew_current = sync_source_and_save_with_epoch(port, 20, 0, Some(current), &path)
            .await
            .expect("current generation still grows");
        assert_eq!(grew_current.added_rx, 10);
        assert_eq!(counters.get(), (160, 0));
        let still_refused = sync_source_and_save_with_epoch(port, 10, 0, Some(past_cap), &path)
            .await
            .expect("still past cap after reload");
        assert_eq!(still_refused.added_rx, 0);
        assert_eq!(counters.sync_epoch(), current);
        assert_eq!(
            counters.retired_list().len(),
            TrafficCounters::MAX_RETIRED_EPOCHS
        );

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn load_from_file_caps_oversized_retired_list() {
        let port = 39143u16;
        let path = unique_stats_path("load_caps_retired");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        let retired = (1..=40)
            .map(|epoch| epoch.to_string())
            .collect::<Vec<_>>()
            .join(",");
        if let Some(dir) = path.parent() {
            tfs::create_dir_all(dir).await.expect("create stats parent");
        }
        tfs::write(
            &path,
            format!("{}\t150\t0\t10\t0\t1\t41\t{}\n", port, retired),
        )
        .await
        .expect("write oversized retired file");

        load_from_file(&path).await.expect("load oversized retired");
        assert_eq!(
            counters.retired_list().len(),
            TrafficCounters::MAX_RETIRED_EPOCHS
        );
        assert!(counters.is_retired(1));
        assert!(counters.is_retired(TrafficCounters::MAX_RETIRED_EPOCHS as u64));
        assert!(!counters.is_retired(40));
        assert_eq!(counters.sync_epoch(), 41);
        assert_eq!(counters.get(), (150, 0));

        let dropped = sync_source_and_save_with_epoch(port, 100, 0, Some(40), &path)
            .await
            .expect("truncated epoch is unknown while cap is full");
        assert_eq!(dropped.added_rx, 0);
        assert_eq!(counters.sync_epoch(), 41);
        assert_eq!(counters.get(), (150, 0));

        let delayed_kept = sync_source_and_save_with_epoch(port, 150, 0, Some(1), &path)
            .await
            .expect("kept retired epoch");
        assert_eq!(delayed_kept.added_rx, 0);

        let grew = sync_source_and_save_with_epoch(port, 20, 0, Some(41), &path)
            .await
            .expect("current generation grows");
        assert_eq!(grew.added_rx, 10);
        assert_eq!(counters.get(), (160, 0));

        save_port_to_file(port, &path)
            .await
            .expect("rewrite capped list");
        let contents = tfs::read_to_string(&path).await.expect("read capped file");
        let field = contents
            .trim()
            .split('\t')
            .nth(7)
            .expect("retired field");
        assert_eq!(
            field.split(',').count(),
            TrafficCounters::MAX_RETIRED_EPOCHS
        );

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn sync_epoch_zero_is_treated_as_unknown() {
        let port = 39140u16;
        let path = unique_stats_path("sync_epoch_zero");
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        counters.set(0, 0);
        counters.set_sync_mark(0, 0);

        let a = sync_source_and_save_with_epoch(port, 100, 0, Some(7), &path)
            .await
            .expect("e7=100");
        let b = sync_source_and_save_with_epoch(port, 10, 0, Some(0), &path)
            .await
            .expect("e0=10");
        let c = sync_source_and_save_with_epoch(port, 100, 0, Some(7), &path)
            .await
            .expect("e7=100 again");
        assert_eq!([a.added_rx, b.added_rx, c.added_rx], [100, 0, 0]);
        assert_eq!(counters.get(), (100, 0));
        assert_eq!(counters.sync_mark(), (100, 0));
        assert_eq!(counters.sync_epoch(), 7);

        let _ = tfs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn snapshot_generation_never_pairs_high_totals_with_new_epoch() {
        let port = 39141u16;
        reset_port(port).await;
        let counters = get_counters_for_port(port).await;
        let high = 1_000_000u64;
        let live_epoch = Arc::new(AtomicU64::new(counters.boot_epoch()));
        let stop = Arc::new(AtomicBool::new(false));
        let torn = Arc::new(AtomicBool::new(false));

        let reader = {
            let counters = counters.clone();
            let live_epoch = live_epoch.clone();
            let stop = stop.clone();
            let torn = torn.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let epoch_before = live_epoch.load(Ordering::Acquire);
                    let (rx, _tx, epoch) = counters.snapshot_generation();
                    let epoch_after = live_epoch.load(Ordering::Acquire);
                    if epoch_before == epoch_after && rx == high && epoch != epoch_before {
                        torn.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            })
        };

        for _ in 0..20_000 {
            live_epoch.store(counters.boot_epoch(), Ordering::Release);
            counters.set(high, 0);
            counters.sub_and_rotate_for_test(high, 0);
        }

        stop.store(true, Ordering::Release);
        reader.join().expect("reader");
        assert!(
            !torn.load(Ordering::Relaxed),
            "GET snapshot paired pre-reset totals with the post-reset epoch"
        );
        let (rx, _tx, epoch) = counters.snapshot_generation();
        assert_eq!(rx, 0);
        assert_ne!(epoch, 0);
    }
}
