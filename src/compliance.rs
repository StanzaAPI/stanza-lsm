//! Stanza API Compliance & Reference Storage Layer (`StanzaComplianceStore`).
//!
//! Provides three domain primitives built on `LsmEngine<B>`:
//! 1. **Fail-Closed Idempotency & Replay Dedup**: Prevents duplicate processing of ANSI X12
//!    `837P`/`835` claim control numbers, ISO 20022 payment `EndToEndId`s, and Stripe webhooks,
//!    with SHA-256 payload conflict detection.
//! 2. **Tamper-Evident SHA-256 Compliance Audit Chain**: Commits each audit record and its
//!    tenant secondary index key in an atomic `WriteBatch`, chained by FIPS 180-4 SHA-256 digests
//!    for HIPAA BAA and FDA DSCSA 6-year verification trails.
//! 3. **Prefix-Compressed Reference Table Store**: Batch delta-ingestion and Bloom-accelerated
//!    point/prefix lookups for GLEIF LEI, OpenFDA NDC, GS1 GTIN, and EU VAT reference tables.

use crate::engine::LsmEngine;
use crate::error::{LsmError, Result};
use crate::memtable::WriteBatch;
use crate::sha256::{sha256, to_hex, Sha256};
use crate::vfs::StorageBackend;

const AUDIT_HEAD_KEY: &[u8] = b"audit:meta:head";

/// Result of an idempotency check-or-record operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdempotencyOutcome {
    /// First time seeing `(scope, key)` — payload hash and response were durably recorded.
    Recorded { seq: u64, payload_sha256: [u8; 32] },
    /// `(scope, key)` was already committed with the exact same `payload_sha256`.
    Replayed {
        recorded_at_ms: u64,
        payload_sha256: [u8; 32],
        cached_response: Vec<u8>,
    },
}

/// A single tamper-evident compliance audit event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub index: u64,
    pub timestamp_ms: u64,
    pub tenant_id: String,
    pub api_slug: String,
    pub subject_id: String,
    pub decision: String,
    pub payload_sha256: [u8; 32],
    pub prev_chain_hash: [u8; 32],
    pub chain_hash: [u8; 32],
}

/// Summary returned by `verify_audit_chain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditChainVerification {
    pub events_verified: u64,
    pub head_chain_hash: [u8; 32],
}

/// Stanza API domain store wrapping `LsmEngine<B>`.
#[derive(Clone, Debug)]
pub struct StanzaComplianceStore<B: StorageBackend> {
    engine: LsmEngine<B>,
}

impl<B: StorageBackend> StanzaComplianceStore<B> {
    pub fn new(engine: LsmEngine<B>) -> Self {
        Self { engine }
    }

    pub fn engine(&self) -> &LsmEngine<B> {
        &self.engine
    }

    /// Checks whether `(scope, idempotency_key)` has already been processed:
    /// - If unseen, records `(timestamp_ms, sha256(request_payload), response_bytes)` and returns `Recorded`.
    /// - If seen with identical `sha256(request_payload)`, returns `Replayed` with the original response.
    /// - If seen with a different `request_payload`, fails closed with `LsmError::IdempotencyConflict`.
    pub fn check_or_record_idempotency(
        &self,
        scope: &str,
        idempotency_key: &str,
        request_payload: &[u8],
        response_bytes: &[u8],
        timestamp_ms: u64,
    ) -> Result<IdempotencyOutcome> {
        let storage_key = format!("idem:{scope}:{idempotency_key}").into_bytes();
        let actual_hash = sha256(request_payload);

        if let Some(existing) = self.engine.get(&storage_key)? {
            if existing.len() >= 40 {
                let recorded_at_ms = u64::from_le_bytes(existing[0..8].try_into().unwrap());
                let expected_hash: [u8; 32] = existing[8..40].try_into().unwrap();
                if expected_hash != actual_hash {
                    return Err(LsmError::IdempotencyConflict {
                        scope: scope.to_string(),
                        key: idempotency_key.to_string(),
                        expected_sha256: to_hex(&expected_hash),
                        actual_sha256: to_hex(&actual_hash),
                    });
                }
                return Ok(IdempotencyOutcome::Replayed {
                    recorded_at_ms,
                    payload_sha256: expected_hash,
                    cached_response: existing[40..].to_vec(),
                });
            }
        }

        let mut record = Vec::with_capacity(40 + response_bytes.len());
        record.extend_from_slice(&timestamp_ms.to_le_bytes());
        record.extend_from_slice(&actual_hash);
        record.extend_from_slice(response_bytes);

        let seq = self.engine.put(&storage_key, &record)?;
        Ok(IdempotencyOutcome::Recorded {
            seq,
            payload_sha256: actual_hash,
        })
    }

    /// Appends a tamper-evident compliance audit event and its tenant secondary index
    /// in a single atomic `WriteBatch`.
    pub fn append_audit_event(
        &self,
        timestamp_ms: u64,
        tenant_id: &str,
        api_slug: &str,
        subject_id: &str,
        decision: &str,
        raw_payload: &[u8],
    ) -> Result<AuditEvent> {
        let (prev_index, prev_hash) = match self.engine.get(AUDIT_HEAD_KEY)? {
            Some(buf) if buf.len() == 40 => {
                let idx = u64::from_be_bytes(buf[0..8].try_into().unwrap());
                let h: [u8; 32] = buf[8..40].try_into().unwrap();
                (idx, h)
            }
            _ => (0u64, [0u8; 32]),
        };

        let index = prev_index + 1;
        let payload_sha256 = sha256(raw_payload);
        let chain_hash = Self::compute_chain_hash(
            &prev_hash,
            index,
            timestamp_ms,
            tenant_id,
            api_slug,
            subject_id,
            decision,
            &payload_sha256,
        );

        let event = AuditEvent {
            index,
            timestamp_ms,
            tenant_id: tenant_id.to_string(),
            api_slug: api_slug.to_string(),
            subject_id: subject_id.to_string(),
            decision: decision.to_string(),
            payload_sha256,
            prev_chain_hash: prev_hash,
            chain_hash,
        };

        let encoded = Self::encode_audit_event(&event);
        let entry_key = format!("audit:entry:{index:016x}").into_bytes();
        let tenant_idx_key = format!("audit:tenant:{tenant_id}:{index:016x}").into_bytes();

        let mut head_val = [0u8; 40];
        head_val[0..8].copy_from_slice(&index.to_be_bytes());
        head_val[8..40].copy_from_slice(&chain_hash);

        let mut batch = WriteBatch::new();
        batch.put(entry_key, encoded);
        batch.put(tenant_idx_key, index.to_be_bytes().to_vec());
        batch.put(AUDIT_HEAD_KEY.to_vec(), head_val.to_vec());
        self.engine.write_batch(&batch)?;

        Ok(event)
    }

    /// Walks the entire `audit:entry:*` chain from genesis (`[0u8; 32]`), recomputing every
    /// SHA-256 link and checking sequence contiguity (`1..=N`) and `audit:meta:head` agreement.
    pub fn verify_audit_chain(&self) -> Result<AuditChainVerification> {
        let rows = self.engine.scan_prefix(b"audit:entry:")?;
        let mut expected_index = 1u64;
        let mut prev_hash = [0u8; 32];

        for (_k, val) in &rows {
            let ev = Self::decode_audit_event(val).ok_or_else(|| LsmError::AuditChainBroken {
                seq: expected_index,
                expected_hash: to_hex(&prev_hash),
                actual_hash: "<malformed-entry>".to_string(),
                reason: "corrupt binary audit record",
            })?;

            if ev.index != expected_index {
                return Err(LsmError::AuditChainBroken {
                    seq: expected_index,
                    expected_hash: format!("index={expected_index}"),
                    actual_hash: format!("index={}", ev.index),
                    reason: "missing or out-of-order audit sequence number",
                });
            }

            if ev.prev_chain_hash != prev_hash {
                return Err(LsmError::AuditChainBroken {
                    seq: ev.index,
                    expected_hash: to_hex(&prev_hash),
                    actual_hash: to_hex(&ev.prev_chain_hash),
                    reason: "prev_chain_hash link mismatch",
                });
            }

            let recomputed = Self::compute_chain_hash(
                &ev.prev_chain_hash,
                ev.index,
                ev.timestamp_ms,
                &ev.tenant_id,
                &ev.api_slug,
                &ev.subject_id,
                &ev.decision,
                &ev.payload_sha256,
            );
            if recomputed != ev.chain_hash {
                return Err(LsmError::AuditChainBroken {
                    seq: ev.index,
                    expected_hash: to_hex(&recomputed),
                    actual_hash: to_hex(&ev.chain_hash),
                    reason: "recomputed SHA-256 chain hash mismatch (tampered payload)",
                });
            }

            prev_hash = ev.chain_hash;
            expected_index += 1;
        }

        let count = expected_index - 1;
        if let Some(head_buf) = self.engine.get(AUDIT_HEAD_KEY)? {
            if head_buf.len() != 40 {
                return Err(LsmError::AuditChainBroken {
                    seq: count,
                    expected_hash: to_hex(&prev_hash),
                    actual_hash: "<invalid-head-len>".to_string(),
                    reason: "audit:meta:head length mismatch",
                });
            }
            let head_idx = u64::from_be_bytes(head_buf[0..8].try_into().unwrap());
            let head_hash: [u8; 32] = head_buf[8..40].try_into().unwrap();
            if head_idx != count || head_hash != prev_hash {
                return Err(LsmError::AuditChainBroken {
                    seq: count,
                    expected_hash: to_hex(&prev_hash),
                    actual_hash: to_hex(&head_hash),
                    reason:
                        "audit:meta:head does not match terminal chain entry (truncation detected)",
                });
            }
        } else if count > 0 {
            return Err(LsmError::AuditChainBroken {
                seq: count,
                expected_hash: to_hex(&prev_hash),
                actual_hash: "<missing-head>".to_string(),
                reason: "audit:meta:head missing while audit entries exist",
            });
        }

        Ok(AuditChainVerification {
            events_verified: count,
            head_chain_hash: prev_hash,
        })
    }

    /// Queries all audit events for `tenant_id` in chronological order via the secondary index.
    pub fn query_tenant_audit(&self, tenant_id: &str) -> Result<Vec<AuditEvent>> {
        let prefix = format!("audit:tenant:{tenant_id}:").into_bytes();
        let idx_rows = self.engine.scan_prefix(&prefix)?;
        let mut events = Vec::with_capacity(idx_rows.len());
        for (_k, v) in idx_rows {
            if v.len() == 8 {
                let seq = u64::from_be_bytes(v.try_into().unwrap());
                let entry_key = format!("audit:entry:{seq:016x}").into_bytes();
                if let Some(raw) = self.engine.get(&entry_key)? {
                    if let Some(ev) = Self::decode_audit_event(&raw) {
                        events.push(ev);
                    }
                }
            }
        }
        Ok(events)
    }

    /// Bulk-ingests a batch of compliance reference records (e.g., `dataset = "lei"`, `"ndc"`, `"gs1"`, `"vat"`)
    /// in an atomic `WriteBatch` and updates the dataset's SHA-256 manifest digest.
    pub fn ingest_reference_batch(
        &self,
        dataset: &str,
        records: &[(&str, &[u8])],
    ) -> Result<[u8; 32]> {
        let mut batch = WriteBatch::new();
        let mut digest = Sha256::new();

        for (id, payload) in records {
            let key = format!("ref:{dataset}:{id}").into_bytes();
            digest.update(&key);
            digest.update(b"=");
            digest.update(payload);
            digest.update(b"\n");
            batch.put(key, payload.to_vec());
        }

        let checksum = digest.finalize();
        let meta_key = format!("ref_meta:{dataset}:sha256").into_bytes();
        batch.put(meta_key, checksum.to_vec());
        self.engine.write_batch(&batch)?;
        Ok(checksum)
    }

    /// Point lookup for a compliance reference identifier (e.g., `dataset = "lei"`, `id = "5493001KJTIIGC8Y1R12"`).
    pub fn lookup_reference(&self, dataset: &str, id: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("ref:{dataset}:{id}").into_bytes();
        self.engine.get(&key)
    }

    /// Prefix scan over a compliance reference dataset (e.g., all NDCs under a labeler prefix).
    pub fn scan_reference_prefix(
        &self,
        dataset: &str,
        id_prefix: &str,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let full_prefix = format!("ref:{dataset}:{id_prefix}");
        let strip_len = format!("ref:{dataset}:").len();
        let rows = self.engine.scan_prefix(full_prefix.as_bytes())?;
        let mut out = Vec::with_capacity(rows.len());
        for (k, v) in rows {
            if k.len() > strip_len {
                if let Ok(id_str) = std::str::from_utf8(&k[strip_len..]) {
                    out.push((id_str.to_string(), v));
                }
            }
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_chain_hash(
        prev_hash: &[u8; 32],
        index: u64,
        timestamp_ms: u64,
        tenant_id: &str,
        api_slug: &str,
        subject_id: &str,
        decision: &str,
        payload_sha256: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash);
        hasher.update(&index.to_be_bytes());
        hasher.update(&timestamp_ms.to_be_bytes());
        hasher.update(&(tenant_id.len() as u32).to_be_bytes());
        hasher.update(tenant_id.as_bytes());
        hasher.update(&(api_slug.len() as u32).to_be_bytes());
        hasher.update(api_slug.as_bytes());
        hasher.update(&(subject_id.len() as u32).to_be_bytes());
        hasher.update(subject_id.as_bytes());
        hasher.update(&(decision.len() as u32).to_be_bytes());
        hasher.update(decision.as_bytes());
        hasher.update(payload_sha256);
        hasher.finalize()
    }

    fn encode_audit_event(ev: &AuditEvent) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + ev.tenant_id.len() + ev.subject_id.len());
        buf.extend_from_slice(&ev.index.to_be_bytes());
        buf.extend_from_slice(&ev.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&ev.payload_sha256);
        buf.extend_from_slice(&ev.prev_chain_hash);
        buf.extend_from_slice(&ev.chain_hash);

        for s in [&ev.tenant_id, &ev.api_slug, &ev.subject_id, &ev.decision] {
            let bytes = s.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(bytes);
        }
        buf
    }

    fn decode_audit_event(raw: &[u8]) -> Option<AuditEvent> {
        if raw.len() < 112 + 8 {
            return None;
        }
        let index = u64::from_be_bytes(raw[0..8].try_into().ok()?);
        let timestamp_ms = u64::from_be_bytes(raw[8..16].try_into().ok()?);
        let payload_sha256: [u8; 32] = raw[16..48].try_into().ok()?;
        let prev_chain_hash: [u8; 32] = raw[48..80].try_into().ok()?;
        let chain_hash: [u8; 32] = raw[80..112].try_into().ok()?;

        let mut cursor = 112usize;
        let mut strings = Vec::with_capacity(4);
        for _ in 0..4 {
            if cursor + 2 > raw.len() {
                return None;
            }
            let len = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]) as usize;
            cursor += 2;
            if cursor + len > raw.len() {
                return None;
            }
            let s = std::str::from_utf8(&raw[cursor..cursor + len])
                .ok()?
                .to_string();
            cursor += len;
            strings.push(s);
        }

        Some(AuditEvent {
            index,
            timestamp_ms,
            tenant_id: strings[0].clone(),
            api_slug: strings[1].clone(),
            subject_id: strings[2].clone(),
            decision: strings[3].clone(),
            payload_sha256,
            prev_chain_hash,
            chain_hash,
        })
    }
}
