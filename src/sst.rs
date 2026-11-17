//! Prefix-compressed 4 KiB block SSTable writer and reader (`SstBuilder`, `SstReader`).
//!
//! Layout on disk (`{sst_id:06}.sst`):
//! - `[Data Block 0]` ... `[Data Block N-1]`
//!   Each data block targets 4,096 bytes and encodes sorted `(key, seq DESC, op, value)`
//!   records using prefix delta-compression with restart points every `RESTART_INTERVAL` (16)
//!   entries, followed by `[restart_offsets: u32 * R][num_restarts: u32][masked_crc32c: u32]`.
//! - `[Bloom Filter Block]`: `[filter_bytes...][masked_crc32c: u32]`
//! - `[Index Block]`: `[count: u32]([first_key][last_key][offset: u64][len: u32])*[masked_crc32c: u32]`
//! - `[Footer (56 bytes)]`:
//!   - `index_offset: u64` (0..8)
//!   - `index_len: u32` (8..12)
//!   - `bloom_offset: u64` (12..20)
//!   - `bloom_len: u32` (20..24)
//!   - `min_seq: u64` (24..32)
//!   - `max_seq: u64` (32..40)
//!   - `entry_count: u32` (40..44)
//!   - `uncompressed_key_bytes: u32` (44..48)
//!   - `compressed_key_bytes: u32` (48..52)
//!   - `footer_masked_crc32c: u32` (48..52? wait: 52..56, magic 56..64 -> 64 bytes total!)

use std::sync::Arc;

use crate::bloom::BloomFilter;
use crate::cache::BlockCache;
use crate::crc32c::{crc32c, mask_crc32c, unmask_crc32c};
use crate::error::{LsmError, Result};
use crate::memtable::{InternalEntry, OpKind};
use crate::vfs::StorageBackend;

pub const DEFAULT_BLOCK_SIZE: usize = 4096;
pub const RESTART_INTERVAL: usize = 16;
pub const SST_MAGIC: u64 = 0x5354_414E_5A4C_534D; // "STANZLSM"
pub const FOOTER_LEN: usize = 64;

/// Metadata for an immutable SSTable on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SstMeta {
    pub id: u64,
    pub level: usize,
    pub file_size: u64,
    pub min_key: Vec<u8>,
    pub max_key: Vec<u8>,
    pub min_seq: u64,
    pub max_seq: u64,
    pub entry_count: u32,
    pub uncompressed_key_bytes: u32,
    pub compressed_key_bytes: u32,
}

impl SstMeta {
    pub fn filename(id: u64) -> String {
        format!("{id:06}.sst")
    }
}

#[derive(Clone, Debug)]
pub struct BlockIndexEntry {
    pub first_key: Vec<u8>,
    pub last_key: Vec<u8>,
    pub offset: u64,
    pub len: u32,
}

pub struct SstBuilder {
    block_size: usize,
    bits_per_key: usize,
}

impl Default for SstBuilder {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            bits_per_key: 10,
        }
    }
}

impl SstBuilder {
    pub fn new(block_size: usize, bits_per_key: usize) -> Self {
        Self {
            block_size: block_size.max(512),
            bits_per_key: bits_per_key.clamp(2, 32),
        }
    }

    /// Writes a sorted stream of `InternalEntry` records to `{id:06}.sst` atomically
    /// via `{id:06}.sst.tmp` -> `sync_file` -> `rename_atomic` -> `sync_dir`.
    pub fn build<B: StorageBackend>(
        &self,
        backend: &B,
        id: u64,
        level: usize,
        entries: &[InternalEntry],
    ) -> Result<SstMeta> {
        if entries.is_empty() {
            return Err(LsmError::InvalidArgument(
                "cannot build SSTable from empty entry slice",
            ));
        }

        let mut file_buf = Vec::with_capacity(entries.len() * 48 + 512);
        let mut index_entries = Vec::new();
        let mut user_keys_for_bloom: Vec<&[u8]> = Vec::with_capacity(entries.len());

        let mut min_seq = u64::MAX;
        let mut max_seq = 0u64;
        let mut uncompressed_key_bytes = 0u32;
        let mut compressed_key_bytes = 0u32;

        // Current data block state
        let mut block_buf = Vec::with_capacity(self.block_size + 256);
        let mut restarts: Vec<u32> = Vec::new();
        let mut prev_key: Vec<u8> = Vec::new();
        let mut block_first_key: Option<Vec<u8>> = None;
        let mut block_last_key: Vec<u8> = Vec::new();
        let mut in_block_count = 0usize;

        for entry in entries {
            user_keys_for_bloom.push(entry.key.as_slice());
            if entry.seq < min_seq {
                min_seq = entry.seq;
            }
            if entry.seq > max_seq {
                max_seq = entry.seq;
            }

            let is_restart = in_block_count.is_multiple_of(RESTART_INTERVAL);
            let shared = if is_restart {
                restarts.push(block_buf.len() as u32);
                0usize
            } else {
                shared_prefix_len(&prev_key, &entry.key)
            };
            let unshared = entry.key.len() - shared;

            uncompressed_key_bytes = uncompressed_key_bytes.saturating_add(entry.key.len() as u32);
            compressed_key_bytes = compressed_key_bytes.saturating_add(unshared as u32);

            if block_first_key.is_none() {
                block_first_key = Some(entry.key.clone());
            }
            block_last_key.clone_from(&entry.key);

            // Encode entry: [shared: u16][unshared: u16][val_len: u32][seq: u64][op: u8][unshared_key][val]
            block_buf.extend_from_slice(&(shared as u16).to_le_bytes());
            block_buf.extend_from_slice(&(unshared as u16).to_le_bytes());
            block_buf.extend_from_slice(&(entry.value.len() as u32).to_le_bytes());
            block_buf.extend_from_slice(&entry.seq.to_le_bytes());
            block_buf.push(entry.op as u8);
            block_buf.extend_from_slice(&entry.key[shared..]);
            block_buf.extend_from_slice(&entry.value);

            prev_key.clone_from(&entry.key);
            in_block_count += 1;

            let est_block_size = block_buf.len() + (restarts.len() * 4) + 8;
            if est_block_size >= self.block_size {
                let offset = file_buf.len() as u64;
                let len = Self::finish_data_block(&mut file_buf, &mut block_buf, &mut restarts);
                index_entries.push(BlockIndexEntry {
                    first_key: block_first_key.take().unwrap_or_default(),
                    last_key: block_last_key.clone(),
                    offset,
                    len,
                });
                prev_key.clear();
                in_block_count = 0;
            }
        }

        if in_block_count > 0 {
            let offset = file_buf.len() as u64;
            let len = Self::finish_data_block(&mut file_buf, &mut block_buf, &mut restarts);
            index_entries.push(BlockIndexEntry {
                first_key: block_first_key.take().unwrap_or_default(),
                last_key: block_last_key.clone(),
                offset,
                len,
            });
        }

        // Write Bloom filter block
        let bloom_offset = file_buf.len() as u64;
        let bloom = BloomFilter::build(&user_keys_for_bloom, self.bits_per_key);
        let bloom_raw = bloom.to_bytes();
        let bloom_crc = mask_crc32c(crc32c(&bloom_raw));
        file_buf.extend_from_slice(&bloom_raw);
        file_buf.extend_from_slice(&bloom_crc.to_le_bytes());
        let bloom_len = (bloom_raw.len() + 4) as u32;

        // Write sparse Index block
        let index_offset = file_buf.len() as u64;
        let mut index_raw = Vec::with_capacity(index_entries.len() * 48 + 4);
        index_raw.extend_from_slice(&(index_entries.len() as u32).to_le_bytes());
        for idx in &index_entries {
            index_raw.extend_from_slice(&(idx.first_key.len() as u16).to_le_bytes());
            index_raw.extend_from_slice(&idx.first_key);
            index_raw.extend_from_slice(&(idx.last_key.len() as u16).to_le_bytes());
            index_raw.extend_from_slice(&idx.last_key);
            index_raw.extend_from_slice(&idx.offset.to_le_bytes());
            index_raw.extend_from_slice(&idx.len.to_le_bytes());
        }
        let index_crc = mask_crc32c(crc32c(&index_raw));
        file_buf.extend_from_slice(&index_raw);
        file_buf.extend_from_slice(&index_crc.to_le_bytes());
        let index_len = (index_raw.len() + 4) as u32;

        // Write 64-byte Footer
        let entry_count = entries.len() as u32;
        let mut footer_body = [0u8; 52];
        footer_body[0..8].copy_from_slice(&index_offset.to_le_bytes());
        footer_body[8..12].copy_from_slice(&index_len.to_le_bytes());
        footer_body[12..20].copy_from_slice(&bloom_offset.to_le_bytes());
        footer_body[20..24].copy_from_slice(&bloom_len.to_le_bytes());
        footer_body[24..32].copy_from_slice(&min_seq.to_le_bytes());
        footer_body[32..40].copy_from_slice(&max_seq.to_le_bytes());
        footer_body[40..44].copy_from_slice(&entry_count.to_le_bytes());
        footer_body[44..48].copy_from_slice(&uncompressed_key_bytes.to_le_bytes());
        footer_body[48..52].copy_from_slice(&compressed_key_bytes.to_le_bytes());

        let footer_crc = mask_crc32c(crc32c(&footer_body));
        file_buf.extend_from_slice(&footer_body);
        file_buf.extend_from_slice(&footer_crc.to_le_bytes());
        file_buf.extend_from_slice(&SST_MAGIC.to_le_bytes());

        let final_name = SstMeta::filename(id);
        let tmp_name = format!("{final_name}.tmp");
        backend.write_file(&tmp_name, &file_buf)?;
        backend.sync_file(&tmp_name)?;
        backend.rename_atomic(&tmp_name, &final_name)?;
        backend.sync_dir()?;

        Ok(SstMeta {
            id,
            level,
            file_size: file_buf.len() as u64,
            min_key: entries.first().unwrap().key.clone(),
            max_key: entries.last().unwrap().key.clone(),
            min_seq,
            max_seq,
            entry_count,
            uncompressed_key_bytes,
            compressed_key_bytes,
        })
    }

    fn finish_data_block(
        file_buf: &mut Vec<u8>,
        block_buf: &mut Vec<u8>,
        restarts: &mut Vec<u32>,
    ) -> u32 {
        for &r in restarts.iter() {
            block_buf.extend_from_slice(&r.to_le_bytes());
        }
        block_buf.extend_from_slice(&(restarts.len() as u32).to_le_bytes());
        let crc = mask_crc32c(crc32c(block_buf));
        block_buf.extend_from_slice(&crc.to_le_bytes());
        let len = block_buf.len() as u32;
        file_buf.extend_from_slice(block_buf);
        block_buf.clear();
        restarts.clear();
        len
    }
}

/// Reader for an immutable SSTable on disk with Bloom filter pre-check,
/// sparse index binary search, and per-block CRC32C verification.
#[derive(Clone, Debug)]
pub struct SstReader<B: StorageBackend> {
    backend: B,
    meta: SstMeta,
    bloom: BloomFilter,
    index: Vec<BlockIndexEntry>,
    cache: BlockCache,
}

/// Outcome of a point lookup against a single SSTable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SstLookup {
    /// Key fell outside `[min_key, max_key]` of the SSTable.
    RangeFilteredOut,
    /// Key was inside `[min_key, max_key]`, and the Bloom filter proved it is absent without reading any data block.
    BloomFilteredOut,
    /// Data block was checked, but no version `<= snapshot_seq` matched `key` (false positive or newer version only).
    Miss { bloom_false_positive: bool },
    /// Found visible `Put(value)` or `Delete` tombstone.
    Found {
        op: OpKind,
        value: Vec<u8>,
        seq: u64,
    },
}

impl<B: StorageBackend> SstReader<B> {
    pub fn open(backend: B, id: u64, level: usize, cache: BlockCache) -> Result<Self> {
        let filename = SstMeta::filename(id);
        let file_len = backend.file_len(&filename)?;
        if file_len < FOOTER_LEN as u64 {
            return Err(LsmError::CorruptSstFooter {
                sst_id: id,
                reason: "file shorter than 64-byte footer",
            });
        }

        let footer = backend.read_range(&filename, file_len - FOOTER_LEN as u64, FOOTER_LEN)?;
        let magic = u64::from_le_bytes(footer[56..64].try_into().unwrap());
        if magic != SST_MAGIC {
            return Err(LsmError::CorruptSstFooter {
                sst_id: id,
                reason: "invalid SSTable magic number",
            });
        }

        let stored_footer_crc =
            unmask_crc32c(u32::from_le_bytes(footer[52..56].try_into().unwrap()));
        let actual_footer_crc = crc32c(&footer[0..52]);
        if stored_footer_crc != actual_footer_crc {
            return Err(LsmError::CorruptSstFooter {
                sst_id: id,
                reason: "footer CRC32C mismatch",
            });
        }

        let index_offset = u64::from_le_bytes(footer[0..8].try_into().unwrap());
        let index_len = u32::from_le_bytes(footer[8..12].try_into().unwrap()) as usize;
        let bloom_offset = u64::from_le_bytes(footer[12..20].try_into().unwrap());
        let bloom_len = u32::from_le_bytes(footer[20..24].try_into().unwrap()) as usize;
        let min_seq = u64::from_le_bytes(footer[24..32].try_into().unwrap());
        let max_seq = u64::from_le_bytes(footer[32..40].try_into().unwrap());
        let entry_count = u32::from_le_bytes(footer[40..44].try_into().unwrap());
        let uncompressed_key_bytes = u32::from_le_bytes(footer[44..48].try_into().unwrap());
        let compressed_key_bytes = u32::from_le_bytes(footer[48..52].try_into().unwrap());

        // Read and verify Bloom filter block
        if bloom_len < 6 {
            return Err(LsmError::CorruptSstFooter {
                sst_id: id,
                reason: "bloom block shorter than minimum length",
            });
        }
        let bloom_block = backend.read_range(&filename, bloom_offset, bloom_len)?;
        let bloom_payload = &bloom_block[..bloom_len - 4];
        let bloom_expected_crc = unmask_crc32c(u32::from_le_bytes(
            bloom_block[bloom_len - 4..].try_into().unwrap(),
        ));
        let bloom_actual_crc = crc32c(bloom_payload);
        if bloom_expected_crc != bloom_actual_crc {
            return Err(LsmError::CorruptSstBlock {
                sst_id: id,
                block_offset: bloom_offset,
                expected_crc: bloom_expected_crc,
                actual_crc: bloom_actual_crc,
            });
        }
        let bloom = BloomFilter::from_bytes(bloom_payload).ok_or(LsmError::CorruptSstFooter {
            sst_id: id,
            reason: "malformed bloom filter payload",
        })?;

        // Read and verify Index block
        if index_len < 8 {
            return Err(LsmError::CorruptSstFooter {
                sst_id: id,
                reason: "index block shorter than minimum length",
            });
        }
        let index_block = backend.read_range(&filename, index_offset, index_len)?;
        let index_payload = &index_block[..index_len - 4];
        let index_expected_crc = unmask_crc32c(u32::from_le_bytes(
            index_block[index_len - 4..].try_into().unwrap(),
        ));
        let index_actual_crc = crc32c(index_payload);
        if index_expected_crc != index_actual_crc {
            return Err(LsmError::CorruptSstBlock {
                sst_id: id,
                block_offset: index_offset,
                expected_crc: index_expected_crc,
                actual_crc: index_actual_crc,
            });
        }

        let index = Self::decode_index(id, index_payload)?;
        if index.is_empty() {
            return Err(LsmError::CorruptSstFooter {
                sst_id: id,
                reason: "SSTable index contains zero blocks",
            });
        }

        let min_key = index.first().unwrap().first_key.clone();
        let max_key = index.last().unwrap().last_key.clone();

        let meta = SstMeta {
            id,
            level,
            file_size: file_len,
            min_key,
            max_key,
            min_seq,
            max_seq,
            entry_count,
            uncompressed_key_bytes,
            compressed_key_bytes,
        };

        Ok(Self {
            backend,
            meta,
            bloom,
            index,
            cache,
        })
    }

    pub fn meta(&self) -> &SstMeta {
        &self.meta
    }

    /// Looks up the newest version of `key` with `seq <= snapshot_seq`.
    pub fn get(&self, key: &[u8], snapshot_seq: u64) -> Result<SstLookup> {
        if key < self.meta.min_key.as_slice() || key > self.meta.max_key.as_slice() {
            return Ok(SstLookup::RangeFilteredOut);
        }
        if !self.bloom.may_contain(key) {
            return Ok(SstLookup::BloomFilteredOut);
        }

        // Binary-search the first block whose `last_key >= key`.
        let start_blk = self
            .index
            .partition_point(|blk| blk.last_key.as_slice() < key);
        let mut any_key_version_seen = false;
        for blk in &self.index[start_blk..] {
            if key < blk.first_key.as_slice() {
                break;
            }
            let entries = self.read_data_block(blk.offset, blk.len as usize)?;
            let start_idx = entries.partition_point(|e| e.key.as_slice() < key);
            for entry in &entries[start_idx..] {
                if entry.key.as_slice() != key {
                    break;
                }
                any_key_version_seen = true;
                if entry.seq <= snapshot_seq {
                    return Ok(SstLookup::Found {
                        op: entry.op,
                        value: entry.value.clone(),
                        seq: entry.seq,
                    });
                }
            }
        }

        Ok(SstLookup::Miss {
            bloom_false_positive: !any_key_version_seen,
        })
    }

    /// Reads all internal MVCC entries in this SSTable (used during compaction and full verification).
    pub fn iter_all_internal(&self) -> Result<Vec<InternalEntry>> {
        let mut out = Vec::with_capacity(self.meta.entry_count as usize);
        for blk in &self.index {
            let entries = self.read_data_block(blk.offset, blk.len as usize)?;
            out.extend(entries.iter().cloned());
        }
        Ok(out)
    }

    /// Reads visible entries in `[start_key, end_key)` as of `snapshot_seq` (one newest visible
    /// entry per user key within this SSTable).
    pub fn range_visible(
        &self,
        start_key: &[u8],
        end_key: Option<&[u8]>,
        snapshot_seq: u64,
    ) -> Result<Vec<InternalEntry>> {
        if let Some(upper) = end_key {
            if upper <= self.meta.min_key.as_slice() {
                return Ok(Vec::new());
            }
        }
        if start_key > self.meta.max_key.as_slice() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        let mut last_emitted_key: Option<Vec<u8>> = None;

        let start_blk = self
            .index
            .partition_point(|blk| blk.last_key.as_slice() < start_key);
        for blk in &self.index[start_blk..] {
            if let Some(upper) = end_key {
                if blk.first_key.as_slice() >= upper {
                    break;
                }
            }
            let entries = self.read_data_block(blk.offset, blk.len as usize)?;
            let start_idx = entries.partition_point(|e| e.key.as_slice() < start_key);
            for entry in &entries[start_idx..] {
                if let Some(upper) = end_key {
                    if entry.key.as_slice() >= upper {
                        return Ok(out);
                    }
                }
                if entry.seq > snapshot_seq {
                    continue;
                }
                if last_emitted_key.as_deref() == Some(entry.key.as_slice()) {
                    continue;
                }
                last_emitted_key = Some(entry.key.clone());
                out.push(entry.clone());
            }
        }

        Ok(out)
    }

    fn read_data_block(&self, offset: u64, len: usize) -> Result<Arc<Vec<InternalEntry>>> {
        if let Some(cached) = self.cache.get(self.meta.id, offset) {
            return Ok(cached);
        }

        let filename = SstMeta::filename(self.meta.id);
        let raw = self.backend.read_range(&filename, offset, len)?;
        if raw.len() < 8 {
            return Err(LsmError::CorruptSstBlock {
                sst_id: self.meta.id,
                block_offset: offset,
                expected_crc: 0,
                actual_crc: 0,
            });
        }

        let payload = &raw[..len - 4];
        let expected_crc = unmask_crc32c(u32::from_le_bytes(raw[len - 4..len].try_into().unwrap()));
        let actual_crc = crc32c(payload);
        if expected_crc != actual_crc {
            return Err(LsmError::CorruptSstBlock {
                sst_id: self.meta.id,
                block_offset: offset,
                expected_crc,
                actual_crc,
            });
        }

        let num_restarts =
            u32::from_le_bytes(payload[payload.len() - 4..].try_into().unwrap()) as usize;
        let restarts_bytes = num_restarts.saturating_mul(4).saturating_add(4);
        if restarts_bytes > payload.len() {
            return Err(LsmError::CorruptSstBlock {
                sst_id: self.meta.id,
                block_offset: offset,
                expected_crc,
                actual_crc,
            });
        }

        let entries_end = payload.len() - restarts_bytes;
        let mut cursor = 0usize;
        let mut prev_key = Vec::new();
        let mut decoded = Vec::new();

        while cursor < entries_end {
            if cursor + 17 > entries_end {
                return Err(LsmError::CorruptSstBlock {
                    sst_id: self.meta.id,
                    block_offset: offset,
                    expected_crc,
                    actual_crc,
                });
            }
            let shared = u16::from_le_bytes([payload[cursor], payload[cursor + 1]]) as usize;
            let unshared = u16::from_le_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
            let val_len = u32::from_le_bytes([
                payload[cursor + 4],
                payload[cursor + 5],
                payload[cursor + 6],
                payload[cursor + 7],
            ]) as usize;
            let seq = u64::from_le_bytes(payload[cursor + 8..cursor + 16].try_into().unwrap());
            let op = OpKind::from_u8(payload[cursor + 16]).ok_or(LsmError::CorruptSstBlock {
                sst_id: self.meta.id,
                block_offset: offset,
                expected_crc,
                actual_crc,
            })?;
            cursor += 17;

            if shared > prev_key.len() || cursor + unshared + val_len > entries_end {
                return Err(LsmError::CorruptSstBlock {
                    sst_id: self.meta.id,
                    block_offset: offset,
                    expected_crc,
                    actual_crc,
                });
            }

            let mut key = Vec::with_capacity(shared + unshared);
            key.extend_from_slice(&prev_key[..shared]);
            key.extend_from_slice(&payload[cursor..cursor + unshared]);
            cursor += unshared;

            let value = payload[cursor..cursor + val_len].to_vec();
            cursor += val_len;

            prev_key.clone_from(&key);
            decoded.push(InternalEntry {
                key,
                seq,
                op,
                value,
            });
        }

        let arc = Arc::new(decoded);
        self.cache
            .insert(self.meta.id, offset, Arc::clone(&arc), len);
        Ok(arc)
    }

    fn decode_index(sst_id: u64, payload: &[u8]) -> Result<Vec<BlockIndexEntry>> {
        if payload.len() < 4 {
            return Err(LsmError::CorruptSstFooter {
                sst_id,
                reason: "index payload shorter than 4 bytes",
            });
        }
        let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
        let mut cursor = 4usize;
        let mut out = Vec::with_capacity(count);

        for _ in 0..count {
            if cursor + 2 > payload.len() {
                return Err(LsmError::CorruptSstFooter {
                    sst_id,
                    reason: "truncated first_key len in index",
                });
            }
            let fk_len = u16::from_le_bytes([payload[cursor], payload[cursor + 1]]) as usize;
            cursor += 2;
            if cursor + fk_len + 2 > payload.len() {
                return Err(LsmError::CorruptSstFooter {
                    sst_id,
                    reason: "truncated first_key in index",
                });
            }
            let first_key = payload[cursor..cursor + fk_len].to_vec();
            cursor += fk_len;

            let lk_len = u16::from_le_bytes([payload[cursor], payload[cursor + 1]]) as usize;
            cursor += 2;
            if cursor + lk_len + 12 > payload.len() {
                return Err(LsmError::CorruptSstFooter {
                    sst_id,
                    reason: "truncated last_key/offset in index",
                });
            }
            let last_key = payload[cursor..cursor + lk_len].to_vec();
            cursor += lk_len;

            let offset = u64::from_le_bytes(payload[cursor..cursor + 8].try_into().unwrap());
            let len = u32::from_le_bytes(payload[cursor + 8..cursor + 12].try_into().unwrap());
            cursor += 12;

            out.push(BlockIndexEntry {
                first_key,
                last_key,
                offset,
                len,
            });
        }
        Ok(out)
    }
}

#[inline]
fn shared_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let limit = a.len().min(b.len()).min(u16::MAX as usize);
    let mut i = 0usize;
    while i < limit && a[i] == b[i] {
        i += 1;
    }
    i
}
