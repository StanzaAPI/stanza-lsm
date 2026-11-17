//! Core `LsmEngine<B>` coordinating the Write-Ahead Log, MVCC Memtable,
//! prefix-compressed SSTables, Kirsch-Mitzenmacher Bloom filters, bounded Block Cache,
//! point-in-time `Snapshot` watermarks, and leveled compaction.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::cache::BlockCache;
use crate::error::Result;
use crate::manifest::ManifestState;
use crate::memtable::{InternalEntry, Memtable, MvccKey, MvccValue, OpKind, WriteBatch};
use crate::sst::{SstBuilder, SstLookup, SstMeta, SstReader, DEFAULT_BLOCK_SIZE};
use crate::vfs::StorageBackend;
use crate::wal::{Wal, WalRecoveryReport};

pub const ACTIVE_WAL_FILE: &str = "active.wal";

/// Configuration parameters for `LsmEngine`.
#[derive(Clone, Debug)]
pub struct LsmConfig {
    /// Flush the in-memory Memtable to an L0 SSTable when its approximate size reaches this threshold.
    pub memtable_max_bytes: usize,
    /// Trigger an L0 -> L1 compaction when the number of L0 SSTables reaches this threshold.
    pub l0_compaction_trigger: usize,
    /// Target byte size of each prefix-compressed SSTable data block (default 4,096 B).
    pub block_size: usize,
    /// Bits per key allocated to each SSTable's Kirsch-Mitzenmacher Bloom filter (default 10).
    pub bloom_bits_per_key: usize,
    /// Capacity of the in-memory decoded block cache in bytes (default 8 MiB).
    pub block_cache_bytes: usize,
    /// Whether every `put` / `delete` / `write_batch` immediately calls `fdatasync` on the WAL.
    pub sync_writes: bool,
}

impl Default for LsmConfig {
    fn default() -> Self {
        Self {
            memtable_max_bytes: 256 * 1024, // 256 KiB default so flushes/compactions exercise readily
            l0_compaction_trigger: 4,
            block_size: DEFAULT_BLOCK_SIZE,
            bloom_bits_per_key: 10,
            block_cache_bytes: 8 * 1024 * 1024,
            sync_writes: true,
        }
    }
}

/// Telemetry and amplification metrics for an `LsmEngine` instance.
#[derive(Clone, Debug, Default)]
pub struct EngineMetrics {
    pub logical_bytes_written: u64,
    pub physical_bytes_written: u64,
    pub wal_bytes_written: u64,
    pub sst_bytes_written: u64,
    pub flushes_completed: u64,
    pub compactions_completed: u64,
    pub tombstones_purged: u64,
    pub obsolete_versions_dropped: u64,
    pub point_lookups: u64,
    pub memtable_hits: u64,
    pub sst_hits: u64,
    pub bloom_work_avoided: u64,
    pub bloom_false_positives: u64,
    pub block_cache_hits: u64,
    pub block_cache_misses: u64,
    pub block_cache_evictions: u64,
    pub l0_sst_count: usize,
    pub l1_sst_count: usize,
    pub total_sst_bytes: u64,
    pub uncompressed_key_bytes: u64,
    pub compressed_key_bytes: u64,
    pub last_recovery: WalRecoveryReport,
}

impl EngineMetrics {
    /// Write Amplification Factor: `physical_bytes_written / logical_bytes_written`.
    pub fn write_amplification(&self) -> f64 {
        if self.logical_bytes_written == 0 {
            1.0
        } else {
            (self.physical_bytes_written as f64) / (self.logical_bytes_written as f64)
        }
    }

    /// Fraction of SSTable key bytes saved by 16-entry prefix delta-compression (`0.0..1.0`).
    pub fn key_prefix_savings_ratio(&self) -> f64 {
        if self.uncompressed_key_bytes == 0 {
            0.0
        } else {
            1.0 - ((self.compressed_key_bytes as f64) / (self.uncompressed_key_bytes as f64))
        }
    }
}

/// Handle to a point-in-time MVCC snapshot at a pinned sequence number.
/// While alive, `LsmEngine::compact` will never garbage-collect versions needed to reconstruct
/// the database state as of `seq`. Automatically unregisters on `Drop`.
#[derive(Debug)]
pub struct Snapshot<B: StorageBackend> {
    engine: LsmEngine<B>,
    seq: u64,
}

impl<B: StorageBackend> Snapshot<B> {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.engine.get_at(key, self.seq)
    }

    pub fn scan_range(
        &self,
        start_key: &[u8],
        end_key: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.engine.scan_range_at(start_key, end_key, self.seq)
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.engine.scan_prefix_at(prefix, self.seq)
    }
}

impl<B: StorageBackend> Drop for Snapshot<B> {
    fn drop(&mut self) {
        self.engine.release_snapshot(self.seq);
    }
}

struct EngineState<B: StorageBackend> {
    config: LsmConfig,
    backend: B,
    wal: Wal<B>,
    memtable: Memtable,
    manifest: ManifestState,
    /// L0 SSTables ordered oldest -> newest (so lookups search in `.iter().rev()`).
    l0_readers: Vec<SstReader<B>>,
    /// L1 SSTables ordered oldest -> newest / merged run.
    l1_readers: Vec<SstReader<B>>,
    cache: BlockCache,
    next_seq: u64,
    /// Reference counts of active snapshots by pinned sequence number.
    active_snapshots: BTreeMap<u64, usize>,
    metrics: EngineMetrics,
}

/// Thread-safe, cloneable handle to the Crash-Safe WAL + LSM-Tree storage engine.
#[derive(Clone)]
pub struct LsmEngine<B: StorageBackend> {
    inner: Arc<Mutex<EngineState<B>>>,
}

impl<B: StorageBackend> std::fmt::Debug for LsmEngine<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LsmEngine").finish()
    }
}

impl<B: StorageBackend> LsmEngine<B> {
    /// Opens or recovers an `LsmEngine` on `backend` with `config`.
    pub fn open(backend: B, config: LsmConfig) -> Result<Self> {
        let cache = BlockCache::new(config.block_cache_bytes);
        let manifest = ManifestState::load_or_init(&backend)?;

        let mut l0_readers = Vec::new();
        let mut l1_readers = Vec::new();
        let mut max_seq = manifest.last_flushed_seq;

        if let Some(l0_ids) = manifest.levels.first() {
            for &id in l0_ids {
                let reader = SstReader::open(backend.clone(), id, 0, cache.clone())?;
                if reader.meta().max_seq > max_seq {
                    max_seq = reader.meta().max_seq;
                }
                l0_readers.push(reader);
            }
        }
        if let Some(l1_ids) = manifest.levels.get(1) {
            for &id in l1_ids {
                let reader = SstReader::open(backend.clone(), id, 1, cache.clone())?;
                if reader.meta().max_seq > max_seq {
                    max_seq = reader.meta().max_seq;
                }
                l1_readers.push(reader);
            }
        }

        // Remove any orphan `.tmp` or unreferenced `.sst` files left by a pre-manifest crash
        Self::cleanup_orphan_files(&backend, &manifest)?;

        let wal = Wal::open(backend.clone(), ACTIVE_WAL_FILE, config.sync_writes)?;
        let (replayed_entries, recovery_report) = wal.recover()?;

        let mut memtable = Memtable::new();
        for entry in replayed_entries {
            if entry.seq > manifest.last_flushed_seq {
                if entry.seq > max_seq {
                    max_seq = entry.seq;
                }
                memtable.apply(entry.seq, entry.op, entry.key, entry.value);
            }
        }

        let mut metrics = EngineMetrics {
            last_recovery: recovery_report,
            ..Default::default()
        };
        Self::refresh_sst_metrics(&l0_readers, &l1_readers, &cache, &mut metrics);

        let state = EngineState {
            config,
            backend,
            wal,
            memtable,
            manifest,
            l0_readers,
            l1_readers,
            cache,
            next_seq: max_seq + 1,
            active_snapshots: BTreeMap::new(),
            metrics,
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(state)),
        })
    }

    /// Inserts or updates `key` with `value`, returning the assigned MVCC sequence number.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<u64> {
        let mut g = self.inner.lock().unwrap();
        let seq = g.next_seq;
        let phys = g.wal.append_single(seq, OpKind::Put, key, value)?;
        g.next_seq += 1;
        g.memtable
            .apply(seq, OpKind::Put, key.to_vec(), value.to_vec());

        let logical = (key.len() + value.len()) as u64;
        g.metrics.logical_bytes_written += logical;
        g.metrics.physical_bytes_written += phys as u64;
        g.metrics.wal_bytes_written += phys as u64;

        if g.memtable.approx_bytes() >= g.config.memtable_max_bytes {
            Self::flush_locked(&mut g)?;
        }
        Ok(seq)
    }

    /// Writes a deletion tombstone for `key`, returning the assigned MVCC sequence number.
    pub fn delete(&self, key: &[u8]) -> Result<u64> {
        let mut g = self.inner.lock().unwrap();
        let seq = g.next_seq;
        let phys = g.wal.append_single(seq, OpKind::Delete, key, &[])?;
        g.next_seq += 1;
        g.memtable
            .apply(seq, OpKind::Delete, key.to_vec(), Vec::new());

        let logical = key.len() as u64;
        g.metrics.logical_bytes_written += logical;
        g.metrics.physical_bytes_written += phys as u64;
        g.metrics.wal_bytes_written += phys as u64;

        if g.memtable.approx_bytes() >= g.config.memtable_max_bytes {
            Self::flush_locked(&mut g)?;
        }
        Ok(seq)
    }

    /// Commits a multi-operation `WriteBatch` as a single atomic WAL frame and applies it
    /// to the Memtable. Returns the inclusive `(first_seq, last_seq)` range assigned.
    pub fn write_batch(&self, batch: &WriteBatch) -> Result<(u64, u64)> {
        if batch.is_empty() {
            let g = self.inner.lock().unwrap();
            let current = g.next_seq.saturating_sub(1);
            return Ok((current, current));
        }

        let mut g = self.inner.lock().unwrap();
        let base_seq = g.next_seq;
        let phys = g.wal.append_batch(base_seq, batch)?;

        let mut logical = 0u64;
        for (i, (op, k, v)) in batch.ops.iter().enumerate() {
            let seq = base_seq + (i as u64);
            logical += (k.len() + v.len()) as u64;
            g.memtable.apply(seq, *op, k.clone(), v.clone());
        }
        let last_seq = base_seq + (batch.ops.len() as u64) - 1;
        g.next_seq = last_seq + 1;

        g.metrics.logical_bytes_written += logical;
        g.metrics.physical_bytes_written += phys as u64;
        g.metrics.wal_bytes_written += phys as u64;

        if g.memtable.approx_bytes() >= g.config.memtable_max_bytes {
            Self::flush_locked(&mut g)?;
        }
        Ok((base_seq, last_seq))
    }

    /// Explicitly flushes the WAL to durable storage (`fdatasync`).
    pub fn sync(&self) -> Result<()> {
        let g = self.inner.lock().unwrap();
        g.wal.sync()
    }

    /// Retrieves the latest value for `key`.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let seq = {
            let g = self.inner.lock().unwrap();
            g.next_seq.saturating_sub(1)
        };
        self.get_at(key, seq)
    }

    /// Retrieves the value of `key` as of `snapshot_seq` (`seq <= snapshot_seq`).
    pub fn get_at(&self, key: &[u8], snapshot_seq: u64) -> Result<Option<Vec<u8>>> {
        let mut g = self.inner.lock().unwrap();
        g.metrics.point_lookups += 1;

        if let Some(res) = g.memtable.get(key, snapshot_seq) {
            g.metrics.memtable_hits += 1;
            return Ok(res);
        }

        // Search L0 from newest SSTable to oldest
        let mut bloom_avoided = 0u64;
        let mut bloom_fp = 0u64;
        let mut found: Option<Option<Vec<u8>>> = None;

        for reader in g.l0_readers.iter().rev() {
            match reader.get(key, snapshot_seq)? {
                SstLookup::RangeFilteredOut => {}
                SstLookup::BloomFilteredOut => {
                    bloom_avoided += 1;
                }
                SstLookup::Miss {
                    bloom_false_positive,
                } => {
                    if bloom_false_positive {
                        bloom_fp += 1;
                    }
                }
                SstLookup::Found { op, value, .. } => {
                    found = Some(match op {
                        OpKind::Put => Some(value),
                        OpKind::Delete => None,
                    });
                    break;
                }
            }
        }

        if found.is_none() {
            for reader in g.l1_readers.iter().rev() {
                match reader.get(key, snapshot_seq)? {
                    SstLookup::RangeFilteredOut => {}
                    SstLookup::BloomFilteredOut => {
                        bloom_avoided += 1;
                    }
                    SstLookup::Miss {
                        bloom_false_positive,
                    } => {
                        if bloom_false_positive {
                            bloom_fp += 1;
                        }
                    }
                    SstLookup::Found { op, value, .. } => {
                        found = Some(match op {
                            OpKind::Put => Some(value),
                            OpKind::Delete => None,
                        });
                        break;
                    }
                }
            }
        }

        g.metrics.bloom_work_avoided += bloom_avoided;
        g.metrics.bloom_false_positives += bloom_fp;
        if found.is_some() {
            g.metrics.sst_hits += 1;
        }
        let (ch, cm, ce) = g.cache.stats();
        g.metrics.block_cache_hits = ch;
        g.metrics.block_cache_misses = cm;
        g.metrics.block_cache_evictions = ce;

        Ok(found.flatten())
    }

    /// Creates a consistent point-in-time `Snapshot` pinned at the current sequence number.
    pub fn snapshot(&self) -> Snapshot<B> {
        let mut g = self.inner.lock().unwrap();
        let seq = g.next_seq.saturating_sub(1);
        *g.active_snapshots.entry(seq).or_insert(0) += 1;
        Snapshot {
            engine: self.clone(),
            seq,
        }
    }

    fn release_snapshot(&self, seq: u64) {
        let mut g = self.inner.lock().unwrap();
        if let Some(count) = g.active_snapshots.get_mut(&seq) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                g.active_snapshots.remove(&seq);
            }
        }
    }

    /// Scans all live key-value pairs in `[start_key, end_key)` in ascending key order.
    pub fn scan_range(
        &self,
        start_key: &[u8],
        end_key: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let seq = {
            let g = self.inner.lock().unwrap();
            g.next_seq.saturating_sub(1)
        };
        self.scan_range_at(start_key, end_key, seq)
    }

    /// Scans all live key-value pairs matching `prefix` in ascending key order.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let seq = {
            let g = self.inner.lock().unwrap();
            g.next_seq.saturating_sub(1)
        };
        self.scan_prefix_at(prefix, seq)
    }

    pub fn scan_prefix_at(
        &self,
        prefix: &[u8],
        snapshot_seq: u64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let upper = prefix_upper_bound(prefix);
        self.scan_range_at(prefix, upper.as_deref(), snapshot_seq)
    }

    /// Performs a K-way MVCC merge across Memtable + L0 SSTables + L1 SSTables for `[start_key, end_key)`
    /// as of `snapshot_seq`, resolving newer versions over older ones and filtering tombstones.
    pub fn scan_range_at(
        &self,
        start_key: &[u8],
        end_key: Option<&[u8]>,
        snapshot_seq: u64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let g = self.inner.lock().unwrap();

        // Map `user_key -> (highest_visible_seq, op, value)`
        let mut merged: BTreeMap<Vec<u8>, (u64, OpKind, Vec<u8>)> = BTreeMap::new();

        for entry in g.memtable.range_visible(start_key, end_key, snapshot_seq) {
            merged.insert(entry.key, (entry.seq, entry.op, entry.value));
        }

        // L0 newest to oldest, then L1 newest to oldest
        for reader in g.l0_readers.iter().rev().chain(g.l1_readers.iter().rev()) {
            for entry in reader.range_visible(start_key, end_key, snapshot_seq)? {
                match merged.get(&entry.key) {
                    Some((existing_seq, _, _)) if *existing_seq >= entry.seq => {}
                    _ => {
                        merged.insert(entry.key, (entry.seq, entry.op, entry.value));
                    }
                }
            }
        }

        let mut out = Vec::with_capacity(merged.len());
        for (k, (_, op, v)) in merged {
            if op == OpKind::Put {
                out.push((k, v));
            }
        }
        Ok(out)
    }

    /// Forces an immediate flush of the active Memtable to an L0 SSTable.
    pub fn flush(&self) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        Self::flush_locked(&mut g)
    }

    /// Forces an immediate compaction of all L0 and L1 SSTables into a consolidated L1 run.
    pub fn compact(&self) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if !g.memtable.is_empty() {
            Self::flush_locked(&mut g)?;
        }
        Self::compact_locked(&mut g, true)
    }

    /// Returns a snapshot of current storage engine metrics and amplification ratios.
    pub fn metrics(&self) -> EngineMetrics {
        let mut g = self.inner.lock().unwrap();
        let EngineState {
            l0_readers,
            l1_readers,
            cache,
            metrics,
            ..
        } = &mut *g;
        Self::refresh_sst_metrics(l0_readers, l1_readers, cache, metrics);
        g.metrics.clone()
    }

    /// Returns the current sequence watermark (highest assigned sequence number).
    pub fn current_seq(&self) -> u64 {
        let g = self.inner.lock().unwrap();
        g.next_seq.saturating_sub(1)
    }

    /// Verifies the CRC32C integrity of every block across all active SSTables on disk.
    pub fn verify_all_sstables(&self) -> Result<usize> {
        let g = self.inner.lock().unwrap();
        let mut total_entries = 0usize;
        for reader in g.l0_readers.iter().chain(g.l1_readers.iter()) {
            let entries = reader.iter_all_internal()?;
            total_entries += entries.len();
        }
        Ok(total_entries)
    }

    fn flush_locked(g: &mut EngineState<B>) -> Result<()> {
        if g.memtable.is_empty() {
            return Ok(());
        }

        let entries: Vec<InternalEntry> = g.memtable.iter_internal().collect();
        let max_seq = g.memtable.max_seq();
        let sst_id = g.manifest.next_sst_id;

        let builder = SstBuilder::new(g.config.block_size, g.config.bloom_bits_per_key);
        let meta = builder.build(&g.backend, sst_id, 0, &entries)?;
        let reader = SstReader::open(g.backend.clone(), sst_id, 0, g.cache.clone())?;

        g.manifest.next_sst_id = sst_id + 1;
        g.manifest.last_flushed_seq = max_seq;
        if g.manifest.levels.is_empty() {
            g.manifest.levels.push(Vec::new());
        }
        g.manifest.levels[0].push(sst_id);
        let manifest_bytes = g.manifest.store_atomic(&g.backend)?;

        // Now that the SSTable and MANIFEST are durably committed on disk, reset the WAL and Memtable.
        g.wal.reset()?;
        g.memtable = Memtable::new();
        g.l0_readers.push(reader);

        g.metrics.flushes_completed += 1;
        g.metrics.sst_bytes_written += meta.file_size;
        g.metrics.physical_bytes_written += meta.file_size + (manifest_bytes as u64);

        if g.l0_readers.len() >= g.config.l0_compaction_trigger {
            Self::compact_locked(g, false)?;
        } else {
            let EngineState {
                l0_readers,
                l1_readers,
                cache,
                metrics,
                ..
            } = g;
            Self::refresh_sst_metrics(l0_readers, l1_readers, cache, metrics);
        }

        Ok(())
    }

    fn compact_locked(g: &mut EngineState<B>, force: bool) -> Result<()> {
        if g.l0_readers.is_empty()
            && (g.l1_readers.is_empty() || (!force && g.l1_readers.len() <= 1))
        {
            return Ok(());
        }

        // Collect all internal entries from L0 and L1, sorted by `(user_key ASC, seq DESC)`.
        let mut all_versions: BTreeMap<MvccKey, MvccValue> = BTreeMap::new();

        let mut old_ids = Vec::new();
        for reader in g.l1_readers.iter().chain(g.l0_readers.iter()) {
            old_ids.push(reader.meta().id);
            for entry in reader.iter_all_internal()? {
                all_versions.insert((entry.key, Reverse(entry.seq)), (entry.op, entry.value));
            }
        }

        // Determine the oldest pinned snapshot sequence number.
        // Any version with `seq <= min_pinned_seq` can be coalesced to its single newest version
        // at or below `min_pinned_seq`, and bottom-level tombstones `<= min_pinned_seq` can be purged.
        let min_pinned_seq = g
            .active_snapshots
            .keys()
            .next()
            .copied()
            .unwrap_or(u64::MAX);

        let mut compacted_entries: Vec<InternalEntry> = Vec::with_capacity(all_versions.len());
        let mut last_user_key: Option<Vec<u8>> = None;
        let mut seen_below_watermark_for_key = false;
        let mut tombstones_purged = 0u64;
        let mut obsolete_dropped = 0u64;

        for ((key, Reverse(seq)), (op, value)) in all_versions {
            let is_new_key = last_user_key.as_deref() != Some(key.as_slice());
            if is_new_key {
                last_user_key = Some(key.clone());
                seen_below_watermark_for_key = false;
            }

            if seq > min_pinned_seq {
                // Newer than at least one active snapshot -> must preserve exact MVCC version!
                compacted_entries.push(InternalEntry {
                    key,
                    seq,
                    op,
                    value,
                });
            } else if !seen_below_watermark_for_key {
                // This is the newest version at or below `min_pinned_seq`.
                seen_below_watermark_for_key = true;
                if op == OpKind::Delete {
                    // Since L0+L1 is the bottom level of our tree, a tombstone at or below the
                    // oldest active snapshot has no older values left to shadow and can be purged!
                    tombstones_purged += 1;
                } else {
                    compacted_entries.push(InternalEntry {
                        key,
                        seq,
                        op,
                        value,
                    });
                }
            } else {
                // Older shadowed version below all active snapshots -> drop!
                obsolete_dropped += 1;
            }
        }

        let mut new_l1_readers = Vec::new();
        let mut new_l1_ids = Vec::new();

        if !compacted_entries.is_empty() {
            let sst_id = g.manifest.next_sst_id;
            g.manifest.next_sst_id = sst_id + 1;

            let builder = SstBuilder::new(g.config.block_size, g.config.bloom_bits_per_key);
            let meta = builder.build(&g.backend, sst_id, 1, &compacted_entries)?;
            let reader = SstReader::open(g.backend.clone(), sst_id, 1, g.cache.clone())?;

            g.metrics.sst_bytes_written += meta.file_size;
            g.metrics.physical_bytes_written += meta.file_size;

            new_l1_ids.push(sst_id);
            new_l1_readers.push(reader);
        }

        while g.manifest.levels.len() < 2 {
            g.manifest.levels.push(Vec::new());
        }
        g.manifest.levels[0].clear();
        g.manifest.levels[1] = new_l1_ids;
        let manifest_bytes = g.manifest.store_atomic(&g.backend)?;
        g.metrics.physical_bytes_written += manifest_bytes as u64;

        // Remove obsolete SSTables from cache and disk
        for old_id in old_ids {
            g.cache.invalidate_sst(old_id);
            let _ = g.backend.remove_file(&SstMeta::filename(old_id));
        }
        g.backend.sync_dir()?;

        g.l0_readers.clear();
        g.l1_readers = new_l1_readers;
        g.metrics.compactions_completed += 1;
        g.metrics.tombstones_purged += tombstones_purged;
        g.metrics.obsolete_versions_dropped += obsolete_dropped;

        let EngineState {
            l0_readers,
            l1_readers,
            cache,
            metrics,
            ..
        } = g;
        Self::refresh_sst_metrics(l0_readers, l1_readers, cache, metrics);
        Ok(())
    }

    fn cleanup_orphan_files(backend: &B, manifest: &ManifestState) -> Result<()> {
        let mut live_sst_names = std::collections::HashSet::new();
        for lvl in &manifest.levels {
            for &id in lvl {
                live_sst_names.insert(SstMeta::filename(id));
            }
        }
        let files = backend.list_files()?;
        let mut removed_any = false;
        for name in files {
            if name.ends_with(".tmp") || (name.ends_with(".sst") && !live_sst_names.contains(&name))
            {
                let _ = backend.remove_file(&name);
                removed_any = true;
            }
        }
        if removed_any {
            backend.sync_dir()?;
        }
        Ok(())
    }

    fn refresh_sst_metrics(
        l0: &[SstReader<B>],
        l1: &[SstReader<B>],
        cache: &BlockCache,
        metrics: &mut EngineMetrics,
    ) {
        metrics.l0_sst_count = l0.len();
        metrics.l1_sst_count = l1.len();
        let mut total_bytes = 0u64;
        let mut uncomp_keys = 0u64;
        let mut comp_keys = 0u64;
        for r in l0.iter().chain(l1.iter()) {
            total_bytes += r.meta().file_size;
            uncomp_keys += r.meta().uncompressed_key_bytes as u64;
            comp_keys += r.meta().compressed_key_bytes as u64;
        }
        metrics.total_sst_bytes = total_bytes;
        metrics.uncompressed_key_bytes = uncomp_keys;
        metrics.compressed_key_bytes = comp_keys;
        let (ch, cm, ce) = cache.stats();
        metrics.block_cache_hits = ch;
        metrics.block_cache_misses = cm;
        metrics.block_cache_evictions = ce;
    }
}

/// Computes the smallest byte slice strictly greater than all keys starting with `prefix`,
/// or `None` if `prefix` is empty or all `0xFF` bytes.
fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut out = prefix.to_vec();
    while let Some(last) = out.pop() {
        if last < 0xFF {
            out.push(last + 1);
            return Some(out);
        }
    }
    None
}
