//! Structured error types for the `stanza-lsm` storage engine and compliance layer.

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum LsmError {
    Io(io::Error),
    CorruptWalFrame {
        offset: u64,
        expected_crc: u32,
        actual_crc: u32,
        reason: &'static str,
    },
    CorruptSstBlock {
        sst_id: u64,
        block_offset: u64,
        expected_crc: u32,
        actual_crc: u32,
    },
    CorruptSstFooter {
        sst_id: u64,
        reason: &'static str,
    },
    CorruptManifest {
        line: usize,
        reason: String,
    },
    InvalidArgument(&'static str),
    IdempotencyConflict {
        scope: String,
        key: String,
        expected_sha256: String,
        actual_sha256: String,
    },
    AuditChainBroken {
        seq: u64,
        expected_hash: String,
        actual_hash: String,
        reason: &'static str,
    },
}

impl fmt::Display for LsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LsmError::Io(e) => write!(f, "I/O error: {e}"),
            LsmError::CorruptWalFrame {
                offset,
                expected_crc,
                actual_crc,
                reason,
            } => write!(
                f,
                "corrupt WAL frame at byte offset {offset} ({reason}): expected crc32c={expected_crc:#010x}, actual={actual_crc:#010x}"
            ),
            LsmError::CorruptSstBlock {
                sst_id,
                block_offset,
                expected_crc,
                actual_crc,
            } => write!(
                f,
                "corrupt SSTable {sst_id:06}.sst block at offset {block_offset}: expected crc32c={expected_crc:#010x}, actual={actual_crc:#010x}"
            ),
            LsmError::CorruptSstFooter { sst_id, reason } => {
                write!(f, "corrupt SSTable {sst_id:06}.sst footer: {reason}")
            }
            LsmError::CorruptManifest { line, reason } => {
                write!(f, "corrupt MANIFEST at line {line}: {reason}")
            }
            LsmError::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            LsmError::IdempotencyConflict {
                scope,
                key,
                expected_sha256,
                actual_sha256,
            } => write!(
                f,
                "idempotency payload conflict for {scope}:{key}: original sha256={expected_sha256}, new={actual_sha256}"
            ),
            LsmError::AuditChainBroken {
                seq,
                expected_hash,
                actual_hash,
                reason,
            } => write!(
                f,
                "tamper-evident audit chain broken at seq {seq} ({reason}): expected={expected_hash}, actual={actual_hash}"
            ),
        }
    }
}

impl std::error::Error for LsmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LsmError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for LsmError {
    fn from(value: io::Error) -> Self {
        LsmError::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, LsmError>;
