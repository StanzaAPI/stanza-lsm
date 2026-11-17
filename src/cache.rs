//! Bounded in-memory block cache for verified SSTable data blocks.
//! Keys are `(sst_id, block_offset)` and values are `Arc<Vec<InternalEntry>>`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::memtable::InternalEntry;

type BlockKey = (u64, u64);
type BlockValue = (Arc<Vec<InternalEntry>>, usize);

#[derive(Debug)]
struct CacheState {
    map: HashMap<BlockKey, BlockValue>,
    order: VecDeque<BlockKey>,
    used_bytes: usize,
    capacity_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct BlockCache {
    inner: Arc<Mutex<CacheState>>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    evictions: Arc<AtomicU64>,
}

impl BlockCache {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CacheState {
                map: HashMap::new(),
                order: VecDeque::new(),
                used_bytes: 0,
                capacity_bytes: capacity_bytes.max(4096),
            })),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            evictions: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn get(&self, sst_id: u64, block_offset: u64) -> Option<Arc<Vec<InternalEntry>>> {
        let g = self.inner.lock().unwrap();
        if let Some((entries, _)) = g.map.get(&(sst_id, block_offset)) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(Arc::clone(entries))
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub fn insert(
        &self,
        sst_id: u64,
        block_offset: u64,
        entries: Arc<Vec<InternalEntry>>,
        byte_weight: usize,
    ) {
        let mut g = self.inner.lock().unwrap();
        let key = (sst_id, block_offset);
        if g.map.contains_key(&key) {
            return;
        }
        let weight = byte_weight.max(64);
        while g.used_bytes + weight > g.capacity_bytes && !g.order.is_empty() {
            if let Some(oldest) = g.order.pop_front() {
                if let Some((_, old_w)) = g.map.remove(&oldest) {
                    g.used_bytes = g.used_bytes.saturating_sub(old_w);
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        g.used_bytes += weight;
        g.order.push_back(key);
        g.map.insert(key, (entries, weight));
    }

    pub fn invalidate_sst(&self, sst_id: u64) {
        let mut g = self.inner.lock().unwrap();
        g.order.retain(|(id, _)| *id != sst_id);
        let to_remove: Vec<(u64, u64)> = g
            .map
            .keys()
            .filter(|(id, _)| *id == sst_id)
            .copied()
            .collect();
        for k in to_remove {
            if let Some((_, w)) = g.map.remove(&k) {
                g.used_bytes = g.used_bytes.saturating_sub(w);
            }
        }
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.evictions.load(Ordering::Relaxed),
        )
    }
}
