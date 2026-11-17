#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use stanza_lsm::{
    run_dst_campaign, sha256::to_hex, LsmConfig, LsmEngine, PosixFs, SplitMix64,
    StanzaComplianceStore, WriteBatch,
};

fn usage() -> ! {
    eprintln!(
        "stanza-lsm — Crash-safe WAL + LSM-tree storage engine for Stanza API

Usage:
  stanza-lsm dst [--seeds N] [--steps M] [--seed HEX_OR_DEC]
  stanza-lsm bench [--records N] [--dir PATH]
  stanza-lsm put <db_dir> <key> <value>
  stanza-lsm get <db_dir> <key>
  stanza-lsm delete <db_dir> <key>
  stanza-lsm scan <db_dir> [prefix]
  stanza-lsm audit-append <db_dir> <tenant> <api_slug> <subject_id> <decision> <payload>
  stanza-lsm audit-verify <db_dir>
  stanza-lsm stats <db_dir>"
    );
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }

    match args[0].as_str() {
        "dst" => cmd_dst(&args[1..]),
        "bench" => cmd_bench(&args[1..]),
        "put" => {
            if args.len() != 4 {
                usage();
            }
            let engine = open_posix(&args[1]);
            let seq = engine
                .put(args[2].as_bytes(), args[3].as_bytes())
                .unwrap_or_else(|e| fatal(&e.to_string()));
            println!("{{\"ok\":true,\"seq\":{seq}}}");
        }
        "get" => {
            if args.len() != 3 {
                usage();
            }
            let engine = open_posix(&args[1]);
            match engine
                .get(args[2].as_bytes())
                .unwrap_or_else(|e| fatal(&e.to_string()))
            {
                Some(v) => println!("{}", String::from_utf8_lossy(&v)),
                None => process::exit(1),
            }
        }
        "delete" => {
            if args.len() != 3 {
                usage();
            }
            let engine = open_posix(&args[1]);
            let seq = engine
                .delete(args[2].as_bytes())
                .unwrap_or_else(|e| fatal(&e.to_string()));
            println!("{{\"ok\":true,\"deleted\":true,\"seq\":{seq}}}");
        }
        "scan" => {
            if args.len() < 2 || args.len() > 3 {
                usage();
            }
            let engine = open_posix(&args[1]);
            let prefix = args.get(2).map(|s| s.as_bytes()).unwrap_or(b"");
            let rows = engine
                .scan_prefix(prefix)
                .unwrap_or_else(|e| fatal(&e.to_string()));
            for (k, v) in rows {
                println!(
                    "{}\t{}",
                    String::from_utf8_lossy(&k),
                    String::from_utf8_lossy(&v)
                );
            }
        }
        "audit-append" => {
            if args.len() != 7 {
                usage();
            }
            let engine = open_posix(&args[1]);
            let store = StanzaComplianceStore::new(engine);
            let now_ms = 1_763_340_000_000u64;
            let ev = store
                .append_audit_event(
                    now_ms,
                    &args[2],
                    &args[3],
                    &args[4],
                    &args[5],
                    args[6].as_bytes(),
                )
                .unwrap_or_else(|e| fatal(&e.to_string()));
            println!(
                "{{\"index\":{},\"chain_hash\":\"{}\",\"prev_chain_hash\":\"{}\"}}",
                ev.index,
                to_hex(&ev.chain_hash),
                to_hex(&ev.prev_chain_hash)
            );
        }
        "audit-verify" => {
            if args.len() != 2 {
                usage();
            }
            let engine = open_posix(&args[1]);
            let store = StanzaComplianceStore::new(engine);
            let res = store
                .verify_audit_chain()
                .unwrap_or_else(|e| fatal(&e.to_string()));
            println!(
                "{{\"valid\":true,\"events_verified\":{},\"head_chain_hash\":\"{}\"}}",
                res.events_verified,
                to_hex(&res.head_chain_hash)
            );
        }
        "stats" => {
            if args.len() != 2 {
                usage();
            }
            let engine = open_posix(&args[1]);
            let m = engine.metrics();
            println!(
                "{{\"l0_ssts\":{},\"l1_ssts\":{},\"total_sst_bytes\":{},\"uncompressed_key_bytes\":{},\"compressed_key_bytes\":{},\"key_prefix_savings_pct\":{:.2},\"write_amplification\":{:.3}}}",
                m.l0_sst_count,
                m.l1_sst_count,
                m.total_sst_bytes,
                m.uncompressed_key_bytes,
                m.compressed_key_bytes,
                m.key_prefix_savings_ratio() * 100.0,
                m.write_amplification()
            );
        }
        _ => usage(),
    }
}

fn open_posix(path: &str) -> LsmEngine<PosixFs> {
    let fs = PosixFs::open(path).unwrap_or_else(|e| fatal(&e.to_string()));
    LsmEngine::open(fs, LsmConfig::default()).unwrap_or_else(|e| fatal(&e.to_string()))
}

fn cmd_dst(args: &[String]) {
    let mut seeds = 1000usize;
    let mut steps = 200usize;
    let mut base_seed = 0x5354_414E_5A41_2026u64;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seeds" => {
                i += 1;
                seeds = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1000);
            }
            "--steps" => {
                i += 1;
                steps = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(200);
            }
            "--seed" => {
                i += 1;
                if let Some(raw) = args.get(i) {
                    base_seed = if let Some(hex) = raw.strip_prefix("0x") {
                        u64::from_str_radix(hex, 16).unwrap_or(base_seed)
                    } else {
                        raw.parse().unwrap_or(base_seed)
                    };
                }
            }
            _ => usage(),
        }
        i += 1;
    }

    let t0 = Instant::now();
    let report = run_dst_campaign(base_seed, seeds, steps)
        .unwrap_or_else(|e| fatal(&format!("DST failed: {e}")));
    let elapsed = t0.elapsed();

    println!("=== stanza-lsm Deterministic Simulation Testing (DST) ===");
    println!("base_seed:                  {base_seed:#018x}");
    println!("seeds_verified:             {}", report.seeds_run);
    println!("total_operations:           {}", report.total_steps);
    println!(
        "wall_time_ms:               {:.2}",
        elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "ops_per_sec:                {:.0}",
        (report.total_steps as f64) / elapsed.as_secs_f64()
    );
    println!("puts_committed:             {}", report.puts_committed);
    println!("deletes_committed:          {}", report.deletes_committed);
    println!("atomic_batches_committed:   {}", report.batches_committed);
    println!("flushes_triggered:          {}", report.flushes_triggered);
    println!(
        "compactions_triggered:      {}",
        report.compactions_triggered
    );
    println!("power_loss_crashes:         {}", report.crashes_simulated);
    println!("torn_wal_tails_recovered:   {}", report.torn_wal_recoveries);
    println!("mvcc_snapshots_verified:    {}", report.snapshots_verified);
    println!(
        "range_scans_verified:       {}",
        report.range_scans_verified
    );
    println!(
        "bitflip_corruptions_caught: {}",
        report.bitflip_corruptions_caught
    );
    println!("invariants_failed:          0");
}

fn cmd_bench(args: &[String]) {
    let mut records = 100_000usize;
    let mut custom_dir: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--records" => {
                i += 1;
                records = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(100_000);
            }
            "--dir" => {
                i += 1;
                custom_dir = args.get(i).map(PathBuf::from);
            }
            _ => usage(),
        }
        i += 1;
    }

    let bench_dir =
        custom_dir.unwrap_or_else(|| PathBuf::from(format!(".stanza-lsm-bench-{}", process::id())));
    if bench_dir.exists() {
        let _ = fs::remove_dir_all(&bench_dir);
    }

    let vfs = PosixFs::open(&bench_dir).unwrap_or_else(|e| fatal(&e.to_string()));
    let cfg = LsmConfig {
        memtable_max_bytes: 4 * 1024 * 1024, // 4 MiB Memtable
        l0_compaction_trigger: 4,
        block_size: 4096,
        bloom_bits_per_key: 10,
        block_cache_bytes: 32 * 1024 * 1024,
        sync_writes: false, // Batch-synced per 100-record WriteBatch (realistic group commit)
    };
    let engine = LsmEngine::open(vfs.clone(), cfg).unwrap_or_else(|e| fatal(&e.to_string()));

    // 1. Batch Write Benchmark (100 records per fdatasynced WriteBatch, modeling StanzaAPI LEI/NDC/X12 ingest)
    // We insert even IDs (idx * 2) so odd IDs (idx * 2 + 1) fall strictly inside [min_key, max_key]
    // during the Bloom filter negative lookup test.
    let batch_size = 100usize;
    let num_batches = records / batch_size;
    let mut batch_latencies_us = Vec::with_capacity(num_batches);

    let write_start = Instant::now();
    for b in 0..num_batches {
        let t_op = Instant::now();
        let mut batch = WriteBatch::new();
        for j in 0..batch_size {
            let idx = (b * batch_size + j) * 2;
            let key = format!("ref:lei:5493001KJTIIGC{:06}", idx).into_bytes();
            let val = format!(
                "{{\"lei\":\"5493001KJTIIGC{:06}\",\"status\":\"ISSUED\",\"jurisdiction\":\"US-DE\",\"seq\":{}}}",
                idx, idx
            )
            .into_bytes();
            batch.put(key, val);
        }
        engine.write_batch(&batch).unwrap();
        engine.sync().unwrap();
        batch_latencies_us.push(t_op.elapsed().as_nanos() as u64);
    }
    engine.flush().unwrap();
    engine.compact().unwrap();
    let write_elapsed = write_start.elapsed();

    // 2. Random Point Hit Lookup Benchmark (even IDs: all present)
    let mut rng = SplitMix64::new(0xCAFE_BABE);
    let lookup_trials = 50_000usize;
    let mut hit_latencies_ns = Vec::with_capacity(lookup_trials);

    let hit_start = Instant::now();
    for _ in 0..lookup_trials {
        let idx = rng.gen_range(records) * 2;
        let key = format!("ref:lei:5493001KJTIIGC{:06}", idx).into_bytes();
        let t_op = Instant::now();
        let val = engine.get(&key).unwrap();
        hit_latencies_ns.push(t_op.elapsed().as_nanos() as u64);
        assert!(val.is_some());
    }
    let hit_elapsed = hit_start.elapsed();

    // 3. Random Absent-Key (Bloom Filter Negative) Lookup Benchmark (odd IDs inside [min_key, max_key])
    let mut miss_latencies_ns = Vec::with_capacity(lookup_trials);
    let miss_start = Instant::now();
    for i in 0..lookup_trials {
        let idx = (i % records) * 2 + 1;
        let key = format!("ref:lei:5493001KJTIIGC{:06}", idx).into_bytes();
        let t_op = Instant::now();
        let val = engine.get(&key).unwrap();
        miss_latencies_ns.push(t_op.elapsed().as_nanos() as u64);
        assert!(val.is_none());
    }
    let miss_elapsed = miss_start.elapsed();

    // 4. Unbatched per-key fdatasync comparison (to measure fsync stall overhead on 200 single writes on NVMe)
    let sync_trials = 200usize;
    let mut single_sync_ns = Vec::with_capacity(sync_trials);
    for i in 0..sync_trials {
        let key = format!("idem:x12:ISA13-{:09}", i).into_bytes();
        let t_op = Instant::now();
        engine.put(&key, b"{\"status\":\"COMMITTED\"}").unwrap();
        engine.sync().unwrap();
        single_sync_ns.push(t_op.elapsed().as_nanos() as u64);
    }

    batch_latencies_us.sort_unstable();
    hit_latencies_ns.sort_unstable();
    miss_latencies_ns.sort_unstable();
    single_sync_ns.sort_unstable();

    let metrics = engine.metrics();
    let bloom_total_misses = lookup_trials as u64;
    let bloom_fpr = (metrics.bloom_false_positives as f64) / (bloom_total_misses as f64);

    println!("=== stanza-lsm PosixFs Benchmark ({} records) ===", records);
    println!(
        "batch_write_throughput:     {:.0} records/s ({:.2} MiB/s logical, {:.2} s wall)",
        (records as f64) / write_elapsed.as_secs_f64(),
        (metrics.logical_bytes_written as f64) / (1024.0 * 1024.0) / write_elapsed.as_secs_f64(),
        write_elapsed.as_secs_f64()
    );
    println!(
        "batch_commit_latency_us:    p50={:.1} us | p99={:.1} us | p999={:.1} us (100 records + fdatasync)",
        percentile(&batch_latencies_us, 0.50) as f64 / 1000.0,
        percentile(&batch_latencies_us, 0.99) as f64 / 1000.0,
        percentile(&batch_latencies_us, 0.999) as f64 / 1000.0,
    );
    println!(
        "unbatched_fsync_put_us:     p50={:.1} us | p99={:.1} us | p999={:.1} us (1 record + fdatasync)",
        percentile(&single_sync_ns, 0.50) as f64 / 1000.0,
        percentile(&single_sync_ns, 0.99) as f64 / 1000.0,
        percentile(&single_sync_ns, 0.999) as f64 / 1000.0,
    );
    println!(
        "point_hit_lookup:           {:.0} ops/s | p50={} ns | p99={} ns | p999={} ns",
        (lookup_trials as f64) / hit_elapsed.as_secs_f64(),
        percentile(&hit_latencies_ns, 0.50),
        percentile(&hit_latencies_ns, 0.99),
        percentile(&hit_latencies_ns, 0.999),
    );
    println!(
        "bloom_negative_lookup:      {:.0} ops/s | p50={} ns | p99={} ns | p999={} ns",
        (lookup_trials as f64) / miss_elapsed.as_secs_f64(),
        percentile(&miss_latencies_ns, 0.50),
        percentile(&miss_latencies_ns, 0.99),
        percentile(&miss_latencies_ns, 0.999),
    );
    println!(
        "bloom_filter_efficiency:    {} avoided / {} probes (FPR = {:.3}%)",
        metrics.bloom_work_avoided,
        bloom_total_misses,
        bloom_fpr * 100.0
    );
    println!(
        "key_prefix_compression:     {} B -> {} B ({:.1}% key byte reduction, 16-key restart interval)",
        metrics.uncompressed_key_bytes,
        metrics.compressed_key_bytes,
        metrics.key_prefix_savings_ratio() * 100.0
    );
    println!(
        "write_amplification_factor: {:.2}x (logical={} B, physical={} B across WAL + Flush + L1 Compact)",
        metrics.write_amplification(),
        metrics.logical_bytes_written,
        metrics.physical_bytes_written
    );

    let _ = fs::remove_dir_all(&bench_dir);
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn fatal(msg: &str) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}
