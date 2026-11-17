//! # `stanza-lsm`
//!
//! Zero-dependency, `#![forbid(unsafe_code)]` Crash-Safe Write-Ahead Log (WAL) and
//! prefix-compressed Log-Structured Merge-Tree (LSM) storage engine in Rust, built for
//! Stanza API compliance ledgers, idempotency deduplication, and reference-data tables.
//!
//! ## Core Architecture
//! - **Crash-Safe WAL (`wal`)**: Binary frames guarded by masked Castagnoli CRC32C checksums,
//!   atomic `WriteBatch` framing, torn-tail truncation on power-loss recovery, and strict
//!   mid-log bitrot rejection.
//! - **MVCC Memtable & Snapshots (`memtable`, `engine`)**: Versioned `(user_key ASC, seq DESC)`
//!   ordering supporting non-blocking point-in-time `Snapshot` reads whose sequence watermarks
//!   are respected during background/leveled SSTable compaction.
//! - **Prefix-Compressed 4 KiB SSTables (`sst`, `bloom`, `cache`)**: 16-key restart-interval
//!   prefix delta-encoding, per-block CRC32C trailers, Kirsch-Mitzenmacher double-hashing
//!   Bloom filters (10 bits/key), and a bounded block cache.
//! - **Deterministic Simulation Testing (`vfs::SimFs`, `dst`)**: Seeded virtual file system
//!   modeling volatile page cache vs durable sectors, torn WAL writes, un-fsynced directory
//!   renames, and single-bit disk corruption.
//! - **Stanza API Compliance Layer (`compliance`)**: Fail-closed idempotency store with SHA-256
//!   payload conflict detection, tamper-evident SHA-256 hash-chained audit logs, and prefix-indexed
//!   regulatory reference tables (GLEIF LEI, OpenFDA NDC, GS1, X12).

#![forbid(unsafe_code)]

pub mod bloom;
pub mod cache;
pub mod compliance;
pub mod crc32c;
pub mod dst;
pub mod engine;
pub mod error;
pub mod manifest;
pub mod memtable;
pub mod sha256;
pub mod sst;
pub mod vfs;
pub mod wal;

pub use compliance::{
    AuditChainVerification, AuditEvent, IdempotencyOutcome, StanzaComplianceStore,
};
pub use dst::{run_dst_campaign, run_single_seed, DstReport};
pub use engine::{EngineMetrics, LsmConfig, LsmEngine, Snapshot};
pub use error::{LsmError, Result};
pub use memtable::{InternalEntry, OpKind, WriteBatch};
pub use vfs::{CrashMode, PosixFs, SimFs, SplitMix64, StorageBackend};
pub use wal::{Wal, WalRecoveryReport};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wal_torn_tail_truncation_and_mid_log_bitrot() {
        let sim = SimFs::new();
        let wal = Wal::open(sim.clone(), "test.wal", true).unwrap();

        wal.append_single(1, OpKind::Put, b"lei:549300AAA", b"ACTIVE")
            .unwrap();
        let mut batch = WriteBatch::new();
        batch.put(b"x12:claim:1".to_vec(), b"837P".to_vec());
        batch.put(b"x12:claim:2".to_vec(), b"835".to_vec());
        wal.append_batch(2, &batch).unwrap();

        // Inject a 12-byte torn frame at the tail of the WAL
        sim.inject_torn_tail("test.wal", b"SW\x02\xaa\xbb\xcc\xdd\x04\x00\x00\x00\xff")
            .unwrap();

        let (entries, report) = wal.recover().unwrap();
        assert_eq!(report.frames_replayed, 2);
        assert_eq!(report.ops_replayed, 3);
        assert_eq!(report.torn_tail_bytes_truncated, 12);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].key, b"x12:claim:2");

        // Now flip a bit inside the first frame's payload (mid-log bitrot followed by a valid second frame)
        sim.inject_bitflip("test.wal", 24, 0x01).unwrap();
        let err = wal.recover().unwrap_err();
        match err {
            LsmError::CorruptWalFrame { .. } => {}
            other => panic!("expected CorruptWalFrame on mid-log bitrot, got {other:?}"),
        }
    }

    #[test]
    fn test_mvcc_snapshot_isolation_across_flush_and_compaction() {
        let sim = SimFs::new();
        let cfg = LsmConfig {
            memtable_max_bytes: 1024,
            l0_compaction_trigger: 2,
            block_size: 512,
            bloom_bits_per_key: 10,
            block_cache_bytes: 64 * 1024,
            sync_writes: true,
        };
        let engine = LsmEngine::open(sim, cfg).unwrap();

        engine.put(b"lei:5493001", b"v1").unwrap();
        engine.put(b"lei:5493002", b"v1").unwrap();
        let snap1 = engine.snapshot();

        // Overwrite and delete after snap1
        engine.put(b"lei:5493001", b"v2").unwrap();
        engine.delete(b"lei:5493002").unwrap();
        let snap2 = engine.snapshot();

        engine.put(b"lei:5493001", b"v3").unwrap();
        engine.flush().unwrap();
        engine.compact().unwrap();

        // Even after flush and L0->L1 compaction, both pinned snapshots must see their exact historical state!
        assert_eq!(
            snap1.get(b"lei:5493001").unwrap().as_deref(),
            Some(&b"v1"[..])
        );
        assert_eq!(
            snap1.get(b"lei:5493002").unwrap().as_deref(),
            Some(&b"v1"[..])
        );

        assert_eq!(
            snap2.get(b"lei:5493001").unwrap().as_deref(),
            Some(&b"v2"[..])
        );
        assert_eq!(snap2.get(b"lei:5493002").unwrap(), None);

        assert_eq!(
            engine.get(b"lei:5493001").unwrap().as_deref(),
            Some(&b"v3"[..])
        );
        assert_eq!(engine.get(b"lei:5493002").unwrap(), None);

        // Drop snapshots and compact again: historical versions and tombstones are now garbage-collected
        drop(snap1);
        drop(snap2);
        engine.compact().unwrap();
        assert_eq!(
            engine.get(b"lei:5493001").unwrap().as_deref(),
            Some(&b"v3"[..])
        );
        assert_eq!(engine.get(b"lei:5493002").unwrap(), None);
        let m = engine.metrics();
        assert!(m.tombstones_purged >= 1);
        assert!(m.obsolete_versions_dropped >= 2);
    }

    #[test]
    fn test_stanza_compliance_idempotency_audit_and_reference() {
        let sim = SimFs::new();
        let engine = LsmEngine::open(sim.clone(), LsmConfig::default()).unwrap();
        let store = StanzaComplianceStore::new(engine.clone());

        // 1. Idempotency check-or-record + replay + payload mismatch detection
        let first = store
            .check_or_record_idempotency(
                "x12-837p",
                "ISA13-000421:ST02-0001",
                b"ST*837*0001~BHT*0019*00*0123~",
                b"{\"valid\":true,\"claims\":1}",
                1_763_000_000_000,
            )
            .unwrap();
        assert!(matches!(first, IdempotencyOutcome::Recorded { .. }));

        let replay = store
            .check_or_record_idempotency(
                "x12-837p",
                "ISA13-000421:ST02-0001",
                b"ST*837*0001~BHT*0019*00*0123~",
                b"{\"ignored\":true}",
                1_763_000_005_000,
            )
            .unwrap();
        match replay {
            IdempotencyOutcome::Replayed {
                cached_response, ..
            } => assert_eq!(cached_response, b"{\"valid\":true,\"claims\":1}"),
            _ => panic!("expected Replayed outcome"),
        }

        let conflict = store
            .check_or_record_idempotency(
                "x12-837p",
                "ISA13-000421:ST02-0001",
                b"ST*837*0001~TAMPERED_CLAIM_PAYLOAD~",
                b"{}",
                1_763_000_010_000,
            )
            .unwrap_err();
        assert!(matches!(conflict, LsmError::IdempotencyConflict { .. }));

        // 2. Tamper-evident SHA-256 compliance audit chain
        let ev1 = store
            .append_audit_event(
                1_763_000_001_000,
                "tenant_baa_01",
                "pharma-dscsa",
                "gtin:00300028215017:sn:998123",
                "verified",
                b"{\"gtin\":\"00300028215017\",\"lot\":\"L441\"}",
            )
            .unwrap();
        let ev2 = store
            .append_audit_event(
                1_763_000_002_000,
                "tenant_baa_01",
                "x12-parser",
                "isa13:000421",
                "allow",
                b"{\"transactions\":5}",
            )
            .unwrap();
        assert_eq!(ev2.prev_chain_hash, ev1.chain_hash);

        let verified = store.verify_audit_chain().unwrap();
        assert_eq!(verified.events_verified, 2);
        assert_eq!(verified.head_chain_hash, ev2.chain_hash);

        let tenant_logs = store.query_tenant_audit("tenant_baa_01").unwrap();
        assert_eq!(tenant_logs.len(), 2);

        // 3. Reference dataset ingestion & prefix scan
        let _digest = store
            .ingest_reference_batch(
                "lei",
                &[
                    (
                        "5493001KJTIIGC8Y1R12",
                        b"{\"name\":\"ACME CLEARING CORP\",\"status\":\"ISSUED\"}",
                    ),
                    (
                        "5493001KJTIIGC9Z9A88",
                        b"{\"name\":\"STANZA HOLDINGS LLC\",\"status\":\"ISSUED\"}",
                    ),
                    (
                        "213800WAVVOPS85N2205",
                        b"{\"name\":\"EUROSETTLE PLC\",\"status\":\"LAPSED\"}",
                    ),
                ],
            )
            .unwrap();
        engine.flush().unwrap();

        let hit = store
            .lookup_reference("lei", "5493001KJTIIGC8Y1R12")
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&hit).unwrap().contains("ACME CLEARING"));
        assert!(store
            .lookup_reference("lei", "00000000000000000000")
            .unwrap()
            .is_none());

        let prefix_hits = store
            .scan_reference_prefix("lei", "5493001KJTIIGC")
            .unwrap();
        assert_eq!(prefix_hits.len(), 2);
    }

    #[test]
    fn test_deterministic_simulation_campaign_100_seeds() {
        let report = run_dst_campaign(0x5354_414E_5A41, 100, 120).unwrap();
        assert_eq!(report.seeds_run, 100);
        assert_eq!(report.total_steps, 12_000);
        assert!(report.crashes_simulated > 500);
        assert!(report.torn_wal_recoveries > 200);
        assert!(report.snapshots_verified > 100);
        assert!(report.bitflip_corruptions_caught > 100);
    }
}
