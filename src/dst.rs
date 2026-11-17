//! Deterministic Simulation Testing (DST) fault-injection harness (`DstRunner`).
//!
//! Runs randomized stateful operations (`Put`, `Delete`, `WriteBatch`, `Snapshot`, `Flush`,
//! `Compact`, `SimulatePowerLoss` with torn WAL tails, and `InjectBitflip` corruption probes)
//! against `LsmEngine<SimFs>` in lockstep with a reference `BTreeMap` oracle.

use std::collections::BTreeMap;

use crate::engine::{LsmConfig, LsmEngine, Snapshot, ACTIVE_WAL_FILE};
use crate::error::{LsmError, Result};
use crate::memtable::WriteBatch;
use crate::sst::SstMeta;
use crate::vfs::{CrashMode, SimFs, SplitMix64, StorageBackend};

/// Summary statistics from a multi-seed Deterministic Simulation Testing campaign.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DstReport {
    pub seeds_run: usize,
    pub total_steps: usize,
    pub puts_committed: usize,
    pub deletes_committed: usize,
    pub batches_committed: usize,
    pub flushes_triggered: usize,
    pub compactions_triggered: usize,
    pub crashes_simulated: usize,
    pub torn_wal_recoveries: usize,
    pub snapshots_verified: usize,
    pub range_scans_verified: usize,
    pub bitflip_corruptions_caught: usize,
}

/// Runs a deterministic simulation campaign across `num_seeds` (starting at `base_seed`),
/// executing `steps_per_seed` operations per seed and asserting all 5 storage invariants.
pub fn run_dst_campaign(
    base_seed: u64,
    num_seeds: usize,
    steps_per_seed: usize,
) -> Result<DstReport> {
    let mut total = DstReport::default();

    for i in 0..num_seeds {
        let seed = base_seed.wrapping_add(i as u64);
        let sub = run_single_seed(seed, steps_per_seed)?;
        total.seeds_run += 1;
        total.total_steps += sub.total_steps;
        total.puts_committed += sub.puts_committed;
        total.deletes_committed += sub.deletes_committed;
        total.batches_committed += sub.batches_committed;
        total.flushes_triggered += sub.flushes_triggered;
        total.compactions_triggered += sub.compactions_triggered;
        total.crashes_simulated += sub.crashes_simulated;
        total.torn_wal_recoveries += sub.torn_wal_recoveries;
        total.snapshots_verified += sub.snapshots_verified;
        total.range_scans_verified += sub.range_scans_verified;
        total.bitflip_corruptions_caught += sub.bitflip_corruptions_caught;
    }

    Ok(total)
}

type OracleMap = BTreeMap<Vec<u8>, Vec<u8>>;

/// Runs a single deterministic simulation seed and verifies all storage invariants.
pub fn run_single_seed(seed: u64, steps: usize) -> Result<DstReport> {
    let mut rng = SplitMix64::new(seed);
    let sim_fs = SimFs::new();

    // Small Memtable & block size so flushes, multi-block SSTables, and compactions happen frequently
    let config = LsmConfig {
        memtable_max_bytes: 2048,
        l0_compaction_trigger: 3,
        block_size: 512,
        bloom_bits_per_key: 10,
        block_cache_bytes: 16 * 1024,
        sync_writes: true,
    };

    let mut engine = LsmEngine::open(sim_fs.clone(), config.clone())?;
    let mut oracle: OracleMap = BTreeMap::new();
    let mut pinned_snapshots: Vec<(Snapshot<SimFs>, OracleMap)> = Vec::new();
    let mut report = DstReport {
        seeds_run: 1,
        ..Default::default()
    };

    let key_space = 64usize;

    for step in 0..steps {
        report.total_steps += 1;
        let action = rng.gen_range(100);

        if action < 35 {
            // 1. Single Put
            let k = make_domain_key(&mut rng, key_space);
            let v = make_domain_value(&mut rng, step);
            engine.put(&k, &v)?;
            oracle.insert(k, v);
            report.puts_committed += 1;
        } else if action < 50 {
            // 2. Single Delete
            let k = make_domain_key(&mut rng, key_space);
            engine.delete(&k)?;
            oracle.remove(&k);
            report.deletes_committed += 1;
        } else if action < 68 {
            // 3. Atomic WriteBatch (2..=6 operations)
            let batch_len = 2 + rng.gen_range(5);
            let mut batch = WriteBatch::new();
            let mut staged = Vec::with_capacity(batch_len);
            for sub in 0..batch_len {
                let k = make_domain_key(&mut rng, key_space);
                if rng.gen_bool(3, 4) {
                    let v = make_domain_value(&mut rng, step * 10 + sub);
                    batch.put(k.clone(), v.clone());
                    staged.push((true, k, v));
                } else {
                    batch.delete(k.clone());
                    staged.push((false, k, Vec::new()));
                }
            }
            engine.write_batch(&batch)?;
            for (is_put, k, v) in staged {
                if is_put {
                    oracle.insert(k, v);
                } else {
                    oracle.remove(&k);
                }
            }
            report.batches_committed += 1;
        } else if action < 76 {
            // 4. Take or verify a point-in-time MVCC Snapshot
            if pinned_snapshots.len() < 4 && rng.gen_bool(2, 3) {
                let snap = engine.snapshot();
                pinned_snapshots.push((snap, oracle.clone()));
            } else if !pinned_snapshots.is_empty() {
                let idx = rng.gen_range(pinned_snapshots.len());
                let (snap, snap_oracle) = &pinned_snapshots[idx];
                verify_snapshot_matches_oracle(snap, snap_oracle)?;
                report.snapshots_verified += 1;
                if rng.gen_bool(1, 2) {
                    pinned_snapshots.swap_remove(idx);
                }
            }
        } else if action < 83 {
            // 5. Explicit Flush or Compaction
            if rng.gen_bool(1, 2) {
                engine.flush()?;
                report.flushes_triggered += 1;
            } else {
                engine.compact()?;
                report.compactions_triggered += 1;
            }
        } else if action < 93 {
            // 6. Simulate sudden power loss (with optional torn tail frame in WAL) and recover!
            pinned_snapshots.clear(); // In-memory snapshots don't survive process restart

            let inject_torn = rng.gen_bool(3, 5);
            if inject_torn {
                // Append an incomplete / corrupted WAL batch frame at the end of active.wal
                // representing a multi-key WriteBatch that lost power mid-sector before fdatasync!
                let mut partial_batch = Vec::from(&b"SW\x02\x12\x34\x56\x78"[..]);
                let garbage_len = 1 + rng.gen_range(24);
                for _ in 0..garbage_len {
                    partial_batch.push(rng.next_u64() as u8);
                }
                let _ = sim_fs.inject_torn_tail(ACTIVE_WAL_FILE, &partial_batch);
            }

            let mode = if rng.gen_bool(1, 2) {
                CrashMode::TornWriteTail
            } else {
                CrashMode::DropUnsynced
            };
            sim_fs.simulate_power_loss(&mut rng, mode);
            report.crashes_simulated += 1;

            engine = LsmEngine::open(sim_fs.clone(), config.clone())?;
            let metrics = engine.metrics();
            if metrics.last_recovery.torn_tail_bytes_truncated > 0 {
                report.torn_wal_recoveries += 1;
            }

            // Invariant 1 & 2: Every committed key/batch is intact; torn batch was 0% applied.
            verify_engine_matches_oracle(&engine, &oracle, key_space)?;
            report.range_scans_verified += 1;
        } else {
            // 7. Verify range scans & inject reversible 1-bit disk corruption on an SSTable block
            verify_engine_matches_oracle(&engine, &oracle, key_space)?;
            report.range_scans_verified += 1;

            if probe_sstable_bitflip_detection(&sim_fs, &engine, &mut rng)? {
                report.bitflip_corruptions_caught += 1;
            }
        }
    }

    // Final verification of all remaining open snapshots + live database state
    for (snap, snap_oracle) in &pinned_snapshots {
        verify_snapshot_matches_oracle(snap, snap_oracle)?;
        report.snapshots_verified += 1;
    }
    pinned_snapshots.clear();

    engine.compact()?;
    report.compactions_triggered += 1;
    verify_engine_matches_oracle(&engine, &oracle, key_space)?;
    report.range_scans_verified += 1;

    Ok(report)
}

fn make_domain_key(rng: &mut SplitMix64, key_space: usize) -> Vec<u8> {
    let id = rng.gen_range(key_space);
    match id % 4 {
        0 => format!("ref:lei:5493001KJTIIGC{:06}", id).into_bytes(),
        1 => format!("idem:x12:ISA13-{:09}:ST02-{:04}", id / 4, id).into_bytes(),
        2 => format!("ref:ndc:0002-8215-{:02}", id).into_bytes(),
        _ => format!("audit:seq:{:016x}", id).into_bytes(),
    }
}

fn make_domain_value(rng: &mut SplitMix64, step: usize) -> Vec<u8> {
    let payload_tag = rng.next_u64();
    format!("{{\"step\":{step},\"digest\":\"{payload_tag:016x}\",\"status\":\"ACTIVE\"}}")
        .into_bytes()
}

fn verify_engine_matches_oracle(
    engine: &LsmEngine<SimFs>,
    oracle: &BTreeMap<Vec<u8>, Vec<u8>>,
    key_space: usize,
) -> Result<()> {
    // 1. Point lookup verification across the entire key space (both present and absent keys)
    let mut probe_rng = SplitMix64::new(0xBEEF);
    for id in 0..key_space {
        let k = match id % 4 {
            0 => format!("ref:lei:5493001KJTIIGC{:06}", id).into_bytes(),
            1 => format!("idem:x12:ISA13-{:09}:ST02-{:04}", id / 4, id).into_bytes(),
            2 => format!("ref:ndc:0002-8215-{:02}", id).into_bytes(),
            _ => format!("audit:seq:{:016x}", id).into_bytes(),
        };
        let actual = engine.get(&k)?;
        let expected = oracle.get(&k).cloned();
        if actual != expected {
            return Err(LsmError::InvalidArgument(
                "DST invariant violation: point lookup disagrees with oracle",
            ));
        }
        let _ = probe_rng.next_u64();
    }

    // 2. Full range scan equivalence check
    let full_scan = engine.scan_range(b"", None)?;
    let expected_vec: Vec<(Vec<u8>, Vec<u8>)> =
        oracle.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if full_scan != expected_vec {
        return Err(LsmError::InvalidArgument(
            "DST invariant violation: full scan_range disagrees with oracle",
        ));
    }

    // 3. Prefix scan equivalence check on "ref:lei:"
    let lei_scan = engine.scan_prefix(b"ref:lei:")?;
    let expected_lei: Vec<(Vec<u8>, Vec<u8>)> = oracle
        .iter()
        .filter(|(k, _)| k.starts_with(b"ref:lei:"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if lei_scan != expected_lei {
        return Err(LsmError::InvalidArgument(
            "DST invariant violation: prefix scan disagrees with oracle",
        ));
    }

    Ok(())
}

fn verify_snapshot_matches_oracle(
    snap: &Snapshot<SimFs>,
    snap_oracle: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    let actual_scan = snap.scan_range(b"", None)?;
    let expected_scan: Vec<(Vec<u8>, Vec<u8>)> = snap_oracle
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if actual_scan != expected_scan {
        return Err(LsmError::InvalidArgument(
            "DST invariant violation: MVCC snapshot scan disagrees with historical oracle",
        ));
    }
    for (k, expected_val) in snap_oracle {
        let actual_val = snap.get(k)?;
        if actual_val.as_ref() != Some(expected_val) {
            return Err(LsmError::InvalidArgument(
                "DST invariant violation: MVCC snapshot point get disagrees with historical oracle",
            ));
        }
    }
    Ok(())
}

/// Flips a single bit inside a data block of an active SSTable on disk, verifies that
/// `LsmEngine` or `SstReader` detects the CRC32C mismatch (`LsmError::CorruptSstBlock`),
/// and restores the flipped bit so the simulation can continue cleanly.
fn probe_sstable_bitflip_detection(
    sim_fs: &SimFs,
    engine: &LsmEngine<SimFs>,
    rng: &mut SplitMix64,
) -> Result<bool> {
    let files = sim_fs.list_files()?;
    let sst_files: Vec<String> = files.into_iter().filter(|f| f.ends_with(".sst")).collect();
    if sst_files.is_empty() {
        return Ok(false);
    }

    let target = &sst_files[rng.gen_range(sst_files.len())];
    let len = sim_fs.file_len(target)? as usize;
    if len <= 64 {
        return Ok(false);
    }

    // Flip a bit at byte offset 8 (inside Data Block 0)
    let flip_offset = 8usize;
    let bit_mask = 1u8 << (rng.gen_range(8) as u8);
    sim_fs.inject_bitflip(target, flip_offset, bit_mask)?;

    // Open a fresh SstReader with an empty BlockCache so it must read from disk and check CRC32C
    let sst_id = target.trim_end_matches(".sst").parse::<u64>().unwrap_or(1);
    let fresh_cache = crate::cache::BlockCache::new(4096);
    let check_res = crate::sst::SstReader::open(sim_fs.clone(), sst_id, 0, fresh_cache)
        .and_then(|r| r.iter_all_internal());

    // Restore the flipped bit immediately
    sim_fs.inject_bitflip(target, flip_offset, bit_mask)?;

    match check_res {
        Err(LsmError::CorruptSstBlock { .. }) | Err(LsmError::CorruptSstFooter { .. }) => {
            // Confirm restored SSTable now verifies cleanly
            let _ = engine.verify_all_sstables()?;
            let _ = SstMeta::filename(sst_id);
            Ok(true)
        }
        Ok(_) => Err(LsmError::InvalidArgument(
            "DST invariant violation: 1-bit SSTable corruption was not detected by CRC32C",
        )),
        Err(other) => Err(other),
    }
}
