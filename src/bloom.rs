//! Kirsch-Mitzenmacher double-hashing Bloom filter (`h_i(x) = h_1(x) + i * h_2(x)`).
//! Embedded in every SSTable so point lookups for absent keys (such as unseen X12 claim
//! control numbers or unallocated DSCSA serials) avoid disk block reads.

use crate::crc32c::crc32c;

#[derive(Clone, Debug)]
pub struct BloomFilter {
    num_probes: u8,
    bits: Vec<u8>,
}

impl BloomFilter {
    /// Builds a Bloom filter for `keys` using `bits_per_key` (typically 10 bits/key -> ~0.82% FPR).
    pub fn build(keys: &[&[u8]], bits_per_key: usize) -> Self {
        let bits_per_key = bits_per_key.clamp(2, 32);
        // Optimal k = ln(2) * bits_per_key ~= 0.69 * bits_per_key
        let num_probes = ((bits_per_key as f64 * 0.69) as u8).clamp(1, 20);
        let total_bits = (keys.len() * bits_per_key).max(64);
        let total_bytes = total_bits.div_ceil(8);
        let actual_bits = (total_bytes * 8) as u32;
        let mut bits = vec![0u8; total_bytes];

        for &key in keys {
            let (h1, h2) = Self::hash_pair(key);
            let mut h = h1;
            for _ in 0..num_probes {
                let bit_pos = (h % actual_bits) as usize;
                bits[bit_pos / 8] |= 1u8 << (bit_pos % 8);
                h = h.wrapping_add(h2);
            }
        }

        Self { num_probes, bits }
    }

    /// Queries whether `key` may be in the set. Never returns a false negative.
    #[inline]
    pub fn may_contain(&self, key: &[u8]) -> bool {
        if self.bits.is_empty() {
            return true;
        }
        let actual_bits = (self.bits.len() * 8) as u32;
        let (h1, h2) = Self::hash_pair(key);
        let mut h = h1;
        for _ in 0..self.num_probes {
            let bit_pos = (h % actual_bits) as usize;
            if (self.bits[bit_pos / 8] & (1u8 << (bit_pos % 8))) == 0 {
                return false;
            }
            h = h.wrapping_add(h2);
        }
        true
    }

    /// Serializes the filter into `[num_probes: u8][bits...]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bits.len());
        out.push(self.num_probes);
        out.extend_from_slice(&self.bits);
        out
    }

    /// Deserializes a filter from `[num_probes: u8][bits...]`.
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < 2 {
            return None;
        }
        let num_probes = raw[0].clamp(1, 30);
        let bits = raw[1..].to_vec();
        Some(Self { num_probes, bits })
    }

    pub fn byte_size(&self) -> usize {
        1 + self.bits.len()
    }

    #[inline]
    fn hash_pair(key: &[u8]) -> (u32, u32) {
        let h1 = crc32c(key);
        // Derive a second independent-behaving 32-bit stride via Murmur3 finalizer mix
        let mut h2 = h1 ^ (key.len() as u32).wrapping_mul(0x9E37_79B9);
        h2 ^= h2 >> 16;
        h2 = h2.wrapping_mul(0x85EB_CA6B);
        h2 ^= h2 >> 13;
        h2 = h2.wrapping_mul(0xC2B2_AE35);
        h2 ^= h2 >> 16;
        let delta = h2.rotate_left(15);
        (h1, delta.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_no_false_negatives_and_low_fpr() {
        let present: Vec<Vec<u8>> = (0..2_000u32)
            .map(|i| format!("lei:549300{:014}", i).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = present.iter().map(|v| v.as_slice()).collect();
        let filter = BloomFilter::build(&refs, 10);

        for k in &present {
            assert!(filter.may_contain(k), "false negative on present key");
        }

        let mut false_positives = 0usize;
        let trials = 10_000usize;
        for i in 2_000..(2_000 + trials as u32) {
            let probe = format!("lei:549300{:014}", i).into_bytes();
            if filter.may_contain(&probe) {
                false_positives += 1;
            }
        }
        let fpr = (false_positives as f64) / (trials as f64);
        assert!(
            fpr < 0.02,
            "expected FPR < 2% at 10 bits/key, got {:.4}%",
            fpr * 100.0
        );
    }
}
