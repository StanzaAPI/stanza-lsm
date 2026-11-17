//! Castagnoli CRC32C checksum implementation with a compile-time lookup table
//! and LevelDB/RocksDB frame masking to prevent zero-buffer framing weaknesses.

const CRC32C_POLY: u32 = 0x82F6_3B78;
const MASK_DELTA: u32 = 0xA282_EAD8;

const fn build_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC32C_TABLE: [u32; 256] = build_crc32c_table();

/// Computes the raw Castagnoli CRC32C checksum over `data`.
#[inline]
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_extend(0, data)
}

/// Extends an existing CRC32C checksum with additional `data`.
#[inline]
pub fn crc32c_extend(initial: u32, data: &[u8]) -> u32 {
    let mut crc = !initial;
    for &byte in data {
        let idx = ((crc ^ (byte as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[idx];
    }
    !crc
}

/// Masks a CRC32C value for storage in WAL frames and SSTable block trailers.
/// Taking the CRC of a buffer that already contains its own unmasked CRC produces
/// a constant, so masking rotates and shifts the value before serialization.
#[inline]
pub const fn mask_crc32c(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(MASK_DELTA)
}

/// Unmasks a stored CRC32C value.
#[inline]
pub const fn unmask_crc32c(masked: u32) -> u32 {
    let rot = masked.wrapping_sub(MASK_DELTA);
    rot.rotate_left(15)
}

/// Computes the masked CRC32C directly over `data`.
#[inline]
pub fn masked_crc32c(data: &[u8]) -> u32 {
    mask_crc32c(crc32c(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_standard_vectors() {
        // IETF RFC 3720 / iSCSI standard CRC32C check value for "123456789"
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn test_crc32c_incremental_and_mask() {
        let full = crc32c(b"stanza-lsm-wal-frame");
        let part1 = crc32c(b"stanza-lsm-");
        let combined = crc32c_extend(part1, b"wal-frame");
        assert_eq!(full, combined);

        let masked = mask_crc32c(full);
        assert_ne!(masked, full);
        assert_eq!(unmask_crc32c(masked), full);
    }
}
