//! CRC-32C (Castagnoli polynomial) checksum, as required by the `OP_MSG`
//! `checksum` field (RFC 4960, appendix B).

/// Compute the CRC-32C of `data`.
pub fn checksum(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

/// Check that `data` has CRC-32C `expected`.
pub fn verify(data: &[u8], expected: u32) -> bool {
    crc32c::crc32c(data) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference value from RFC 3720 / crc32c test vectors: CRC-32C of the
    // 32 bytes "123456789" padded standard vector.
    #[test]
    fn known_vector() {
        // Standard check value: CRC-32C("123456789") = 0xE3069283.
        assert_eq!(checksum(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn verify_roundtrip() {
        let data = b"hello, mongodb wire protocol";
        let c = checksum(data);
        assert!(verify(data, c));
        assert!(!verify(data, c ^ 1));
    }
}
