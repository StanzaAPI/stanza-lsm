//! Pluggable storage backend (`StorageBackend`) with:
//! 1. `PosixFs`: real directory-backed OS filesystem with `fdatasync`, `fsync`, and parent-directory `fsync`.
//! 2. `SimFs`: Deterministic Simulation Testing (DST) virtual file system modeling volatile OS page cache,
//!    durable disk sectors, torn tail writes on power loss, un-fsynced directory renames, and bitrot.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Deterministic 64-bit SplitMix64 pseudo-random number generator.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn gen_range(&mut self, upper_exclusive: usize) -> usize {
        if upper_exclusive <= 1 {
            return 0;
        }
        (self.next_u64() as usize) % upper_exclusive
    }

    pub fn gen_bool(&mut self, numerator: u32, denominator: u32) -> bool {
        if denominator == 0 {
            return false;
        }
        ((self.next_u64() as u32) % denominator) < numerator
    }
}

/// Abstract filesystem interface allowing the LSM engine to run identically against
/// POSIX disk directories (`PosixFs`) and deterministic fault-injecting memory disks (`SimFs`).
pub trait StorageBackend: Send + Sync + Clone + 'static {
    /// Appends bytes to a file in the volatile page cache (requires `sync_file` to persist across power loss).
    fn append_file(&self, name: &str, data: &[u8]) -> io::Result<u64>;

    /// Overwrites or creates a file in the volatile page cache.
    fn write_file(&self, name: &str, data: &[u8]) -> io::Result<()>;

    /// Atomically renames `src` to `dst` in the directory namespace (requires `sync_dir` to persist across power loss).
    fn rename_atomic(&self, src: &str, dst: &str) -> io::Result<()>;

    /// Truncates a file to `len` bytes and flushes the truncation.
    fn truncate_file(&self, name: &str, len: u64) -> io::Result<()>;

    /// Flushes a file's page-cache buffers to durable disk media (`fdatasync` / `fsync`).
    fn sync_file(&self, name: &str) -> io::Result<()>;

    /// Flushes directory metadata changes (file creations, renames, unlinks) to durable disk media.
    fn sync_dir(&self) -> io::Result<()>;

    /// Reads the entire contents of `name`.
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>>;

    /// Reads `len` bytes starting at `offset` from `name`.
    fn read_range(&self, name: &str, offset: u64, len: usize) -> io::Result<Vec<u8>>;

    /// Returns the length of `name` in bytes.
    fn file_len(&self, name: &str) -> io::Result<u64>;

    /// Checks whether `name` exists in the visible namespace.
    fn exists(&self, name: &str) -> bool;

    /// Removes `name` from the directory namespace.
    fn remove_file(&self, name: &str) -> io::Result<()>;

    /// Lists all visible file names in deterministic sorted order.
    fn list_files(&self) -> io::Result<Vec<String>>;
}

/// Real OS directory backend using POSIX `File::sync_data` and parent directory `File::sync_all`.
#[derive(Clone, Debug)]
pub struct PosixFs {
    root: PathBuf,
}

impl PosixFs {
    pub fn open<P: AsRef<Path>>(root: P) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let vfs = Self { root };
        vfs.sync_dir()?;
        Ok(vfs)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl StorageBackend for PosixFs {
    fn append_file(&self, name: &str, data: &[u8]) -> io::Result<u64> {
        let path = self.resolve(name);
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(data)?;
        file.metadata().map(|m| m.len())
    }

    fn write_file(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let path = self.resolve(name);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(data)
    }

    fn rename_atomic(&self, src: &str, dst: &str) -> io::Result<()> {
        fs::rename(self.resolve(src), self.resolve(dst))
    }

    fn truncate_file(&self, name: &str, len: u64) -> io::Result<()> {
        let path = self.resolve(name);
        let file = OpenOptions::new().write(true).open(&path)?;
        file.set_len(len)?;
        file.sync_data()
    }

    fn sync_file(&self, name: &str) -> io::Result<()> {
        let path = self.resolve(name);
        let file = OpenOptions::new().read(true).open(&path)?;
        file.sync_data()
    }

    fn sync_dir(&self) -> io::Result<()> {
        let dir = File::open(&self.root)?;
        dir.sync_all()
    }

    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        fs::read(self.resolve(name))
    }

    fn read_range(&self, name: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut file = File::open(self.resolve(name))?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn file_len(&self, name: &str) -> io::Result<u64> {
        fs::metadata(self.resolve(name)).map(|m| m.len())
    }

    fn exists(&self, name: &str) -> bool {
        self.resolve(name).exists()
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        let path = self.resolve(name);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn list_files(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_string());
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Crash simulation modes for `SimFs::simulate_power_loss`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashMode {
    /// Drops all unsynced page-cache writes and un-fsynced directory renames cleanly.
    DropUnsynced,
    /// Partially writes a random prefix (`1..unflushed_len`) of any unsynced WAL append
    /// to simulate a mid-sector / mid-frame torn write during power loss, and corrupts
    /// the torn tail if the frame was only partially written.
    TornWriteTail,
}

#[derive(Clone, Debug)]
struct SimFileState {
    /// Bytes guaranteed to survive power loss (`sync_file` completed).
    durable_bytes: Vec<u8>,
    /// Bytes currently visible in OS page cache (includes `durable_bytes` plus unsynced appends/writes).
    page_cache_bytes: Vec<u8>,
}

#[derive(Debug)]
struct SimFsInner {
    /// Currently visible files in the OS directory cache.
    visible_files: BTreeMap<String, SimFileState>,
    /// Directory snapshot from the last `sync_dir()` call (maps filename -> durable_bytes at that point
    /// plus any subsequent `sync_file` updates on files that were already registered in the directory).
    durable_dir_names: BTreeMap<String, bool>,
    /// Optional countdown until an injected `io::ErrorKind::Other` ("simulated disk I/O error").
    fail_after_writes: Option<usize>,
    /// Counters for telemetry and test verification.
    pub file_sync_count: u64,
    pub dir_sync_count: u64,
    pub crash_count: u64,
    pub torn_bytes_injected: u64,
    pub bitflips_injected: u64,
}

/// Deterministic Simulation Testing (DST) Virtual File System.
#[derive(Clone, Debug)]
pub struct SimFs {
    inner: Arc<Mutex<SimFsInner>>,
}

impl Default for SimFs {
    fn default() -> Self {
        Self::new()
    }
}

impl SimFs {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SimFsInner {
                visible_files: BTreeMap::new(),
                durable_dir_names: BTreeMap::new(),
                fail_after_writes: None,
                file_sync_count: 0,
                dir_sync_count: 0,
                crash_count: 0,
                torn_bytes_injected: 0,
                bitflips_injected: 0,
            })),
        }
    }

    /// Configures `SimFs` to return an `io::Error` after `n` write/append operations.
    pub fn set_fail_after_writes(&self, n: Option<usize>) {
        let mut g = self.inner.lock().unwrap();
        g.fail_after_writes = n;
    }

    /// Returns `(file_sync_count, dir_sync_count, crash_count, torn_bytes_injected, bitflips_injected)`.
    pub fn stats(&self) -> (u64, u64, u64, u64, u64) {
        let g = self.inner.lock().unwrap();
        (
            g.file_sync_count,
            g.dir_sync_count,
            g.crash_count,
            g.torn_bytes_injected,
            g.bitflips_injected,
        )
    }

    /// Flips a specific bit on durable & cached storage to simulate silent media corruption (bitrot).
    pub fn inject_bitflip(&self, name: &str, byte_offset: usize, bit_mask: u8) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let state = g
            .visible_files
            .get_mut(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no file {name}")))?;
        if byte_offset >= state.page_cache_bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bitflip offset out of range",
            ));
        }
        state.page_cache_bytes[byte_offset] ^= bit_mask;
        if byte_offset < state.durable_bytes.len() {
            state.durable_bytes[byte_offset] ^= bit_mask;
        }
        g.bitflips_injected += 1;
        Ok(())
    }

    /// Appends raw garbage / partial frame bytes directly to `name` on disk to simulate an un-synced
    /// torn tail write before power loss.
    pub fn inject_torn_tail(&self, name: &str, partial_bytes: &[u8]) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let state = g
            .visible_files
            .get_mut(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no file {name}")))?;
        state.durable_bytes.extend_from_slice(partial_bytes);
        state.page_cache_bytes.extend_from_slice(partial_bytes);
        g.torn_bytes_injected += partial_bytes.len() as u64;
        Ok(())
    }

    /// Simulates an immediate power loss (`SIGKILL` / cord pull):
    /// - Any file not committed to `durable_dir_names` via `sync_dir()` (or created via WAL append)
    ///   may vanish if its creation/rename was not directory-synced.
    /// - Any file with `page_cache_bytes.len() > durable_bytes.len()` either loses the unsynced tail
    ///   (`CrashMode::DropUnsynced`) or persists a random partial prefix of the unsynced tail
    ///   (`CrashMode::TornWriteTail`).
    pub fn simulate_power_loss(&self, rng: &mut SplitMix64, mode: CrashMode) {
        let mut g = self.inner.lock().unwrap();
        g.crash_count += 1;
        g.fail_after_writes = None;

        let durable_names = g.durable_dir_names.clone();
        let mut next_files = BTreeMap::new();
        let mut torn_added = 0u64;

        for (name, mut file) in g.visible_files.clone() {
            // Keep files that were directory-synced, or WAL files whose inode exists on first write.
            let is_wal = name.ends_with(".wal");
            if !durable_names.contains_key(&name) && !is_wal {
                continue;
            }
            if file.page_cache_bytes.len() > file.durable_bytes.len() {
                let unsynced_slice = &file.page_cache_bytes[file.durable_bytes.len()..];
                match mode {
                    CrashMode::DropUnsynced => {
                        file.page_cache_bytes.truncate(file.durable_bytes.len());
                    }
                    CrashMode::TornWriteTail => {
                        // Persist a strict prefix (0..unsynced_slice.len()) so the last frame is torn!
                        let keep = if unsynced_slice.len() > 1 {
                            1 + rng.gen_range(unsynced_slice.len() - 1)
                        } else {
                            0
                        };
                        file.durable_bytes
                            .extend_from_slice(&unsynced_slice[..keep]);
                        file.page_cache_bytes = file.durable_bytes.clone();
                        torn_added += keep as u64;
                    }
                }
            } else {
                file.page_cache_bytes = file.durable_bytes.clone();
            }
            next_files.insert(name, file);
        }

        g.torn_bytes_injected += torn_added;
        g.visible_files = next_files;
    }

    fn check_write_fault(g: &mut SimFsInner) -> io::Result<()> {
        if let Some(rem) = g.fail_after_writes.as_mut() {
            if *rem == 0 {
                return Err(io::Error::other(
                    "SimFs injected disk write fault (ENOSPC/EIO)",
                ));
            }
            *rem -= 1;
        }
        Ok(())
    }
}

impl StorageBackend for SimFs {
    fn append_file(&self, name: &str, data: &[u8]) -> io::Result<u64> {
        let mut g = self.inner.lock().unwrap();
        Self::check_write_fault(&mut g)?;
        let entry = g
            .visible_files
            .entry(name.to_string())
            .or_insert_with(|| SimFileState {
                durable_bytes: Vec::new(),
                page_cache_bytes: Vec::new(),
            });
        entry.page_cache_bytes.extend_from_slice(data);
        Ok(entry.page_cache_bytes.len() as u64)
    }

    fn write_file(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        Self::check_write_fault(&mut g)?;
        g.visible_files.insert(
            name.to_string(),
            SimFileState {
                durable_bytes: Vec::new(),
                page_cache_bytes: data.to_vec(),
            },
        );
        Ok(())
    }

    fn rename_atomic(&self, src: &str, dst: &str) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let src_state = g.visible_files.remove(src).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("rename missing {src}"))
        })?;
        g.visible_files.insert(dst.to_string(), src_state);
        Ok(())
    }

    fn truncate_file(&self, name: &str, len: u64) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let state = g.visible_files.get_mut(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("truncate missing {name}"))
        })?;
        let new_len = (len as usize).min(state.page_cache_bytes.len());
        state.page_cache_bytes.truncate(new_len);
        state.durable_bytes = state.page_cache_bytes.clone();
        g.file_sync_count += 1;
        Ok(())
    }

    fn sync_file(&self, name: &str) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let state = g.visible_files.get_mut(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("sync missing {name}"))
        })?;
        state.durable_bytes = state.page_cache_bytes.clone();
        g.file_sync_count += 1;
        Ok(())
    }

    fn sync_dir(&self) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let names: BTreeMap<String, bool> =
            g.visible_files.keys().map(|k| (k.clone(), true)).collect();
        g.durable_dir_names = names;
        g.dir_sync_count += 1;
        Ok(())
    }

    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let state = g.visible_files.get(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("read missing {name}"))
        })?;
        Ok(state.page_cache_bytes.clone())
    }

    fn read_range(&self, name: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let state = g.visible_files.get(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("read_range missing {name}"),
            )
        })?;
        let start = offset as usize;
        let end = start.saturating_add(len);
        if end > state.page_cache_bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "read_range {offset}..{end} exceeds file len {}",
                    state.page_cache_bytes.len()
                ),
            ));
        }
        Ok(state.page_cache_bytes[start..end].to_vec())
    }

    fn file_len(&self, name: &str) -> io::Result<u64> {
        let g = self.inner.lock().unwrap();
        let state = g.visible_files.get(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("file_len missing {name}"))
        })?;
        Ok(state.page_cache_bytes.len() as u64)
    }

    fn exists(&self, name: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.visible_files.contains_key(name)
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.visible_files.remove(name);
        Ok(())
    }

    fn list_files(&self) -> io::Result<Vec<String>> {
        let g = self.inner.lock().unwrap();
        Ok(g.visible_files.keys().cloned().collect())
    }
}
