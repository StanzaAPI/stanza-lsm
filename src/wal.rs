//! Crash-safe Write-Ahead Log (`Wal`) with atomic `WriteBatch` framing,
//! masked Castagnoli CRC32C checksums, and torn-tail truncation vs mid-log
//! corruption detection.
//!
//! Frame binary format (header = 19 bytes):
//! - `magic: u16` (`0x5357` = `"SW"`)
//! - `frame_type: u8` (`1 = SingleOp`, `2 = AtomicBatch`)
//! - `masked_crc32c: u32` (computed over `[frame_type, base_seq, payload_len, payload...]`)
//! - `base_seq: u64` (starting sequence number of this frame)
//! - `payload_len: u32`
//! - `payload: [u8; payload_len]`

use crate::crc32c::{crc32c, crc32c_extend, mask_crc32c, unmask_crc32c};
use crate::error::{LsmError, Result};
use crate::memtable::{InternalEntry, OpKind, WriteBatch};
use crate::vfs::StorageBackend;

const WAL_MAGIC: u16 = 0x5357; // "SW"
const HEADER_LEN: usize = 19;
const FRAME_SINGLE: u8 = 1;
const FRAME_BATCH: u8 = 2;

/// Summary of WAL recovery after opening or recovering from a crash.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalRecoveryReport {
    pub frames_replayed: usize,
    pub ops_replayed: usize,
    pub valid_bytes: u64,
    pub torn_tail_bytes_truncated: u64,
    pub max_seq_recovered: u64,
}

/// Write-Ahead Log writer and crash-recovery reader.
#[derive(Clone, Debug)]
pub struct Wal<B: StorageBackend> {
    backend: B,
    filename: String,
    sync_on_write: bool,
}

impl<B: StorageBackend> Wal<B> {
    pub fn open(backend: B, filename: impl Into<String>, sync_on_write: bool) -> Result<Self> {
        let filename = filename.into();
        if !backend.exists(&filename) {
            backend.write_file(&filename, &[])?;
            backend.sync_file(&filename)?;
            backend.sync_dir()?;
        }
        Ok(Self {
            backend,
            filename,
            sync_on_write,
        })
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Appends a single `Put` or `Delete` record to the WAL and optionally flushes via `fdatasync`.
    /// Returns the number of physical bytes written to the WAL frame.
    pub fn append_single(&self, seq: u64, op: OpKind, key: &[u8], value: &[u8]) -> Result<usize> {
        let mut payload = Vec::with_capacity(1 + 4 + 4 + key.len() + value.len());
        payload.push(op as u8);
        payload.extend_from_slice(&(key.len() as u32).to_le_bytes());
        payload.extend_from_slice(&(value.len() as u32).to_le_bytes());
        payload.extend_from_slice(key);
        payload.extend_from_slice(value);

        self.write_frame(FRAME_SINGLE, seq, &payload)
    }

    /// Appends an atomic `WriteBatch` as a single CRC32C-guarded WAL frame.
    /// If power fails mid-frame, recovery truncates the entire incomplete batch frame
    /// so partial batches are never applied.
    pub fn append_batch(&self, base_seq: u64, batch: &WriteBatch) -> Result<usize> {
        let mut payload = Vec::with_capacity(4 + batch.approx_bytes());
        payload.extend_from_slice(&(batch.ops.len() as u32).to_le_bytes());
        for (op, key, val) in &batch.ops {
            payload.push(*op as u8);
            payload.extend_from_slice(&(key.len() as u32).to_le_bytes());
            payload.extend_from_slice(&(val.len() as u32).to_le_bytes());
            payload.extend_from_slice(key);
            payload.extend_from_slice(val);
        }
        self.write_frame(FRAME_BATCH, base_seq, &payload)
    }

    pub fn sync(&self) -> Result<()> {
        self.backend.sync_file(&self.filename)?;
        Ok(())
    }

    /// Resets the WAL to an empty durable file after a Memtable flush to SSTable.
    pub fn reset(&self) -> Result<()> {
        self.backend.truncate_file(&self.filename, 0)?;
        Ok(())
    }

    /// Replays all valid committed frames from the WAL.
    ///
    /// - If the final frame at the end of the file is incomplete (torn write during power loss)
    ///   or fails CRC32C at the tail without any subsequent valid frame header, `recover`
    ///   truncates the torn tail back to the last valid frame boundary and records
    ///   `torn_tail_bytes_truncated`.
    /// - If a frame in the middle of the WAL fails CRC32C (followed by another valid `WAL_MAGIC`
    ///   frame header), `recover` returns `Err(LsmError::CorruptWalFrame)` rather than silently
    ///   skipping mid-log corruption.
    pub fn recover(&self) -> Result<(Vec<InternalEntry>, WalRecoveryReport)> {
        if !self.backend.exists(&self.filename) {
            return Ok((Vec::new(), WalRecoveryReport::default()));
        }
        let raw = self.backend.read_file(&self.filename)?;
        let total_len = raw.len();
        let mut offset = 0usize;
        let mut entries = Vec::new();
        let mut report = WalRecoveryReport::default();

        while offset < total_len {
            let remaining = total_len - offset;
            if remaining < HEADER_LEN {
                // Incomplete frame header at the tail of the WAL -> torn write on power loss.
                report.torn_tail_bytes_truncated = remaining as u64;
                self.backend.truncate_file(&self.filename, offset as u64)?;
                break;
            }

            let magic = u16::from_le_bytes([raw[offset], raw[offset + 1]]);
            let frame_type = raw[offset + 2];
            let stored_masked_crc = u32::from_le_bytes([
                raw[offset + 3],
                raw[offset + 4],
                raw[offset + 5],
                raw[offset + 6],
            ]);
            let base_seq = u64::from_le_bytes([
                raw[offset + 7],
                raw[offset + 8],
                raw[offset + 9],
                raw[offset + 10],
                raw[offset + 11],
                raw[offset + 12],
                raw[offset + 13],
                raw[offset + 14],
            ]);
            let payload_len = u32::from_le_bytes([
                raw[offset + 15],
                raw[offset + 16],
                raw[offset + 17],
                raw[offset + 18],
            ]) as usize;

            if magic != WAL_MAGIC {
                // Check if there are valid frames later in the buffer (mid-file corruption)
                if Self::has_subsequent_valid_frame(&raw[offset + 1..]) {
                    return Err(LsmError::CorruptWalFrame {
                        offset: offset as u64,
                        expected_crc: WAL_MAGIC as u32,
                        actual_crc: magic as u32,
                        reason: "corrupt magic header in middle of WAL",
                    });
                }
                report.torn_tail_bytes_truncated = remaining as u64;
                self.backend.truncate_file(&self.filename, offset as u64)?;
                break;
            }

            let frame_end = offset
                .saturating_add(HEADER_LEN)
                .saturating_add(payload_len);
            if frame_end > total_len {
                // Truncated frame payload at the tail of the WAL -> torn write during power loss.
                report.torn_tail_bytes_truncated = remaining as u64;
                self.backend.truncate_file(&self.filename, offset as u64)?;
                break;
            }

            let payload = &raw[offset + HEADER_LEN..frame_end];
            let expected_crc = unmask_crc32c(stored_masked_crc);
            let actual_crc = Self::compute_frame_crc(frame_type, base_seq, payload);

            if expected_crc != actual_crc {
                // Distinguish a torn write on the final frame from bitrot in the middle of the WAL:
                if frame_end < total_len && Self::has_subsequent_valid_frame(&raw[frame_end..]) {
                    return Err(LsmError::CorruptWalFrame {
                        offset: offset as u64,
                        expected_crc,
                        actual_crc,
                        reason: "CRC32C mismatch in committed mid-log WAL frame (bitrot detected)",
                    });
                }
                // Final frame had a corrupt tail from an incomplete sector flush before power loss.
                report.torn_tail_bytes_truncated = (total_len - offset) as u64;
                self.backend.truncate_file(&self.filename, offset as u64)?;
                break;
            }

            match frame_type {
                FRAME_SINGLE => {
                    let entry = Self::decode_single_payload(base_seq, payload, offset as u64)?;
                    if entry.seq > report.max_seq_recovered {
                        report.max_seq_recovered = entry.seq;
                    }
                    entries.push(entry);
                    report.ops_replayed += 1;
                }
                FRAME_BATCH => {
                    let batch_entries =
                        Self::decode_batch_payload(base_seq, payload, offset as u64)?;
                    for entry in batch_entries {
                        if entry.seq > report.max_seq_recovered {
                            report.max_seq_recovered = entry.seq;
                        }
                        entries.push(entry);
                        report.ops_replayed += 1;
                    }
                }
                _ => {
                    return Err(LsmError::CorruptWalFrame {
                        offset: offset as u64,
                        expected_crc,
                        actual_crc,
                        reason: "unknown WAL frame type",
                    });
                }
            }

            report.frames_replayed += 1;
            offset = frame_end;
            report.valid_bytes = offset as u64;
        }

        Ok((entries, report))
    }

    fn write_frame(&self, frame_type: u8, base_seq: u64, payload: &[u8]) -> Result<usize> {
        let crc = Self::compute_frame_crc(frame_type, base_seq, payload);
        let masked_crc = mask_crc32c(crc);

        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&WAL_MAGIC.to_le_bytes());
        frame.push(frame_type);
        frame.extend_from_slice(&masked_crc.to_le_bytes());
        frame.extend_from_slice(&base_seq.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);

        self.backend.append_file(&self.filename, &frame)?;
        if self.sync_on_write {
            self.backend.sync_file(&self.filename)?;
        }
        Ok(frame.len())
    }

    fn compute_frame_crc(frame_type: u8, base_seq: u64, payload: &[u8]) -> u32 {
        let mut header_meta = [0u8; 13];
        header_meta[0] = frame_type;
        header_meta[1..9].copy_from_slice(&base_seq.to_le_bytes());
        header_meta[9..13].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let c = crc32c(&header_meta);
        crc32c_extend(c, payload)
    }

    fn has_subsequent_valid_frame(slice: &[u8]) -> bool {
        if slice.len() < HEADER_LEN {
            return false;
        }
        let magic = u16::from_le_bytes([slice[0], slice[1]]);
        let ftype = slice[2];
        magic == WAL_MAGIC && (ftype == FRAME_SINGLE || ftype == FRAME_BATCH)
    }

    fn decode_single_payload(seq: u64, payload: &[u8], offset: u64) -> Result<InternalEntry> {
        if payload.len() < 9 {
            return Err(LsmError::CorruptWalFrame {
                offset,
                expected_crc: 0,
                actual_crc: 0,
                reason: "single payload shorter than 9 bytes",
            });
        }
        let op = OpKind::from_u8(payload[0]).ok_or(LsmError::CorruptWalFrame {
            offset,
            expected_crc: 0,
            actual_crc: 0,
            reason: "invalid op code in WAL single frame",
        })?;
        let key_len = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
        let val_len = u32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]) as usize;
        if 9 + key_len + val_len != payload.len() {
            return Err(LsmError::CorruptWalFrame {
                offset,
                expected_crc: 0,
                actual_crc: 0,
                reason: "single payload length mismatch",
            });
        }
        let key = payload[9..9 + key_len].to_vec();
        let value = payload[9 + key_len..9 + key_len + val_len].to_vec();
        Ok(InternalEntry {
            key,
            seq,
            op,
            value,
        })
    }

    fn decode_batch_payload(
        base_seq: u64,
        payload: &[u8],
        offset: u64,
    ) -> Result<Vec<InternalEntry>> {
        if payload.len() < 4 {
            return Err(LsmError::CorruptWalFrame {
                offset,
                expected_crc: 0,
                actual_crc: 0,
                reason: "batch payload shorter than 4 bytes",
            });
        }
        let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let mut cursor = 4usize;
        let mut out = Vec::with_capacity(count);

        for i in 0..count {
            if cursor + 9 > payload.len() {
                return Err(LsmError::CorruptWalFrame {
                    offset,
                    expected_crc: 0,
                    actual_crc: 0,
                    reason: "truncated op header inside WAL batch",
                });
            }
            let op = OpKind::from_u8(payload[cursor]).ok_or(LsmError::CorruptWalFrame {
                offset,
                expected_crc: 0,
                actual_crc: 0,
                reason: "invalid op code inside WAL batch",
            })?;
            let key_len = u32::from_le_bytes([
                payload[cursor + 1],
                payload[cursor + 2],
                payload[cursor + 3],
                payload[cursor + 4],
            ]) as usize;
            let val_len = u32::from_le_bytes([
                payload[cursor + 5],
                payload[cursor + 6],
                payload[cursor + 7],
                payload[cursor + 8],
            ]) as usize;
            cursor += 9;
            if cursor + key_len + val_len > payload.len() {
                return Err(LsmError::CorruptWalFrame {
                    offset,
                    expected_crc: 0,
                    actual_crc: 0,
                    reason: "truncated key/value inside WAL batch",
                });
            }
            let key = payload[cursor..cursor + key_len].to_vec();
            cursor += key_len;
            let value = payload[cursor..cursor + val_len].to_vec();
            cursor += val_len;
            out.push(InternalEntry {
                key,
                seq: base_seq + (i as u64),
                op,
                value,
            });
        }

        if cursor != payload.len() {
            return Err(LsmError::CorruptWalFrame {
                offset,
                expected_crc: 0,
                actual_crc: 0,
                reason: "trailing garbage inside WAL batch frame",
            });
        }

        Ok(out)
    }
}
