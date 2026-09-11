//! zstd compression (id 3), behind feature `zstd`.

use crate::error::ProtocolError;

pub(crate) fn compress(data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    // Level 3: the zstd default, matching the official driver.
    zstd::bulk::compress(data, 3).map_err(|e| ProtocolError::Compression(e.to_string()))
}

pub(crate) fn decompress(data: &[u8], expected_len: usize) -> Result<Vec<u8>, ProtocolError> {
    // +1 headroom so oversized output is caught here, not by the caller.
    zstd::bulk::decompress(data, expected_len + 1)
        .map_err(|e| ProtocolError::Compression(e.to_string()))
}
