//! Multi-Version Concurrency Control (MVCC) ordered in-memory table (`Memtable`)
//! and atomic `WriteBatch`.
//!
//! Entries are keyed by `(user_key ASC, seq_no DESC)` so point lookups and prefix/range
//! scans can evaluate visibility at any historical `snapshot_seq` without locking out writers.

use std::cmp::Reverse;
use std::collections::BTreeMap;

/// Operation tag stored in WAL frames, Memtable entries, and SSTable blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpKind {
    Put = 1,
    Delete = 2,
}

impl OpKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(OpKind::Put),
            2 => Some(OpKind::Delete),
            _ => None,
        }
    }
}

/// A single versioned entry in the storage engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalEntry {
    pub key: Vec<u8>,
    pub seq: u64,
    pub op: OpKind,
    pub value: Vec<u8>,
}

/// An atomic batch of `Put` and `Delete` operations written as a single all-or-nothing
/// CRC32C-protected WAL frame and applied atomically to the `Memtable`.
#[derive(Clone, Debug, Default)]
pub struct WriteBatch {
    pub(crate) ops: Vec<(OpKind, Vec<u8>, Vec<u8>)>,
    pub(crate) payload_bytes: usize,
}

impl WriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put<K: Into<Vec<u8>>, V: Into<Vec<u8>>>(&mut self, key: K, value: V) {
        let k = key.into();
        let v = value.into();
        self.payload_bytes += k.len() + v.len() + 9;
        self.ops.push((OpKind::Put, k, v));
    }

    pub fn delete<K: Into<Vec<u8>>>(&mut self, key: K) {
        let k = key.into();
        self.payload_bytes += k.len() + 9;
        self.ops.push((OpKind::Delete, k, Vec::new()));
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn approx_bytes(&self) -> usize {
        self.payload_bytes
    }
}

/// Ordered MVCC Memtable storing `(user_key, Reverse(seq)) -> (OpKind, value)`.
pub type MvccKey = (Vec<u8>, Reverse<u64>);
pub type MvccValue = (OpKind, Vec<u8>);

#[derive(Clone, Debug, Default)]
pub struct Memtable {
    entries: BTreeMap<MvccKey, MvccValue>,
    approx_bytes: usize,
    min_seq: u64,
    max_seq: u64,
}

impl Memtable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            approx_bytes: 0,
            min_seq: u64::MAX,
            max_seq: 0,
        }
    }

    pub fn apply(&mut self, seq: u64, op: OpKind, key: Vec<u8>, value: Vec<u8>) {
        let added = key.len() + value.len() + 24;
        self.approx_bytes = self.approx_bytes.saturating_add(added);
        if seq < self.min_seq {
            self.min_seq = seq;
        }
        if seq > self.max_seq {
            self.max_seq = seq;
        }
        self.entries.insert((key, Reverse(seq)), (op, value));
    }

    /// Resolves the newest version of `key` with `seq <= snapshot_seq`.
    /// Returns `Some(Some(val))` on a visible `Put`, `Some(None)` on a visible `Delete` tombstone,
    /// or `None` if `key` has no version `<= snapshot_seq` in this Memtable.
    pub fn get(&self, key: &[u8], snapshot_seq: u64) -> Option<Option<Vec<u8>>> {
        let start = (key.to_vec(), Reverse(snapshot_seq));
        let end = (key.to_vec(), Reverse(0));
        if let Some(((k, _rev_seq), (op, val))) = self.entries.range(start..=end).next() {
            if k.as_slice() == key {
                return match op {
                    OpKind::Put => Some(Some(val.clone())),
                    OpKind::Delete => Some(None),
                };
            }
        }
        None
    }

    /// Exports all internal MVCC entries in `(user_key ASC, seq DESC)` order for SSTable flushing.
    pub fn iter_internal(&self) -> impl Iterator<Item = InternalEntry> + '_ {
        self.entries
            .iter()
            .map(|((k, Reverse(seq)), (op, val))| InternalEntry {
                key: k.clone(),
                seq: *seq,
                op: *op,
                value: val.clone(),
            })
    }

    /// Returns visible entries in `[start_key, end_key)` as of `snapshot_seq` (including tombstones
    /// so the caller's K-way merge across Memtable + SSTables can shadow older SSTable values).
    pub fn range_visible(
        &self,
        start_key: &[u8],
        end_key: Option<&[u8]>,
        snapshot_seq: u64,
    ) -> Vec<InternalEntry> {
        let mut out = Vec::new();
        let mut last_user_key: Option<&[u8]> = None;

        let lower = (start_key.to_vec(), Reverse(u64::MAX));
        for ((k, Reverse(seq)), (op, val)) in self.entries.range(lower..) {
            if let Some(upper) = end_key {
                if k.as_slice() >= upper {
                    break;
                }
            }
            if *seq > snapshot_seq {
                continue;
            }
            if last_user_key == Some(k.as_slice()) {
                continue;
            }
            last_user_key = Some(k.as_slice());
            out.push(InternalEntry {
                key: k.clone(),
                seq: *seq,
                op: *op,
                value: val.clone(),
            });
        }
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn approx_bytes(&self) -> usize {
        self.approx_bytes
    }

    pub fn min_seq(&self) -> u64 {
        if self.entries.is_empty() {
            0
        } else {
            self.min_seq
        }
    }

    pub fn max_seq(&self) -> u64 {
        self.max_seq
    }
}
