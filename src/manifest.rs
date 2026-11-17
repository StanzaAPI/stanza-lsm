//! Crash-safe `MANIFEST` persistence tracking the active SSTable set across levels,
//! `next_sst_id`, and `last_flushed_seq`.
//!
//! Written via `MANIFEST.tmp` -> `sync_file` -> `rename_atomic("MANIFEST.tmp", "MANIFEST")` -> `sync_dir`,
//! with a masked CRC32C header over the manifest payload.

use crate::crc32c::{crc32c, mask_crc32c, unmask_crc32c};
use crate::error::{LsmError, Result};
use crate::vfs::StorageBackend;

pub const MANIFEST_FILE: &str = "MANIFEST";
pub const MANIFEST_TMP: &str = "MANIFEST.tmp";
const MANIFEST_MAGIC: u32 = 0x534D_414E; // "SMAN"

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestState {
    pub next_sst_id: u64,
    pub last_flushed_seq: u64,
    /// `levels[0]` is L0 (ordered oldest -> newest SSTable ID), `levels[1]` is L1, etc.
    pub levels: Vec<Vec<u64>>,
}

impl Default for ManifestState {
    fn default() -> Self {
        Self {
            next_sst_id: 1,
            last_flushed_seq: 0,
            levels: vec![Vec::new(), Vec::new()],
        }
    }
}

impl ManifestState {
    pub fn load_or_init<B: StorageBackend>(backend: &B) -> Result<Self> {
        if !backend.exists(MANIFEST_FILE) {
            let init = Self::default();
            init.store_atomic(backend)?;
            return Ok(init);
        }
        let raw = backend.read_file(MANIFEST_FILE)?;
        if raw.len() < 8 {
            return Err(LsmError::CorruptManifest {
                line: 0,
                reason: "MANIFEST shorter than 8-byte header".to_string(),
            });
        }
        let magic = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        if magic != MANIFEST_MAGIC {
            return Err(LsmError::CorruptManifest {
                line: 0,
                reason: "invalid MANIFEST magic".to_string(),
            });
        }
        let expected_crc = unmask_crc32c(u32::from_le_bytes(raw[4..8].try_into().unwrap()));
        let body = &raw[8..];
        let actual_crc = crc32c(body);
        if expected_crc != actual_crc {
            return Err(LsmError::CorruptManifest {
                line: 0,
                reason: format!(
                    "MANIFEST CRC32C mismatch: expected={expected_crc:#010x}, actual={actual_crc:#010x}"
                ),
            });
        }

        let text = std::str::from_utf8(body).map_err(|e| LsmError::CorruptManifest {
            line: 0,
            reason: format!("invalid UTF-8 in MANIFEST: {e}"),
        })?;

        let mut state = Self::default();
        for (idx, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| LsmError::CorruptManifest {
                    line: idx + 1,
                    reason: format!("missing '=' in line: {line}"),
                })?;
            match k {
                "next_sst_id" => {
                    state.next_sst_id =
                        v.parse::<u64>().map_err(|e| LsmError::CorruptManifest {
                            line: idx + 1,
                            reason: e.to_string(),
                        })?;
                }
                "last_flushed_seq" => {
                    state.last_flushed_seq =
                        v.parse::<u64>().map_err(|e| LsmError::CorruptManifest {
                            line: idx + 1,
                            reason: e.to_string(),
                        })?;
                }
                lvl if lvl.starts_with('L') => {
                    let level_num =
                        lvl[1..]
                            .parse::<usize>()
                            .map_err(|e| LsmError::CorruptManifest {
                                line: idx + 1,
                                reason: e.to_string(),
                            })?;
                    while state.levels.len() <= level_num {
                        state.levels.push(Vec::new());
                    }
                    let mut ids = Vec::new();
                    if !v.is_empty() {
                        for tok in v.split(',') {
                            let id = tok.parse::<u64>().map_err(|e| LsmError::CorruptManifest {
                                line: idx + 1,
                                reason: e.to_string(),
                            })?;
                            ids.push(id);
                        }
                    }
                    state.levels[level_num] = ids;
                }
                other => {
                    return Err(LsmError::CorruptManifest {
                        line: idx + 1,
                        reason: format!("unknown MANIFEST key '{other}'"),
                    });
                }
            }
        }
        Ok(state)
    }

    pub fn store_atomic<B: StorageBackend>(&self, backend: &B) -> Result<usize> {
        let mut body = String::new();
        body.push_str(&format!("next_sst_id={}\n", self.next_sst_id));
        body.push_str(&format!("last_flushed_seq={}\n", self.last_flushed_seq));
        for (lvl, ids) in self.levels.iter().enumerate() {
            let csv: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
            body.push_str(&format!("L{}={}\n", lvl, csv.join(",")));
        }

        let body_bytes = body.as_bytes();
        let masked_crc = mask_crc32c(crc32c(body_bytes));
        let mut raw = Vec::with_capacity(8 + body_bytes.len());
        raw.extend_from_slice(&MANIFEST_MAGIC.to_le_bytes());
        raw.extend_from_slice(&masked_crc.to_le_bytes());
        raw.extend_from_slice(body_bytes);

        backend.write_file(MANIFEST_TMP, &raw)?;
        backend.sync_file(MANIFEST_TMP)?;
        backend.rename_atomic(MANIFEST_TMP, MANIFEST_FILE)?;
        backend.sync_dir()?;
        Ok(raw.len())
    }
}
