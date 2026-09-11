//! Snappy compression (id 1), behind feature `snappy`.
//!
//! Uses the framing (chunked) stream format, matching the official driver.

use std::io::{Read, Write};

use crate::error::ProtocolError;

pub(crate) fn compress(data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut out = Vec::new();
    snap::write::FrameEncoder::new(&mut out)
        .write_all(data)
        .map_err(|e| ProtocolError::Compression(e.to_string()))?;
    Ok(out)
}

pub(crate) fn decompress(data: &[u8], expected_len: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut out = Vec::with_capacity(expected_len);
    let dec = snap::read::FrameDecoder::new(data);
    dec.take((expected_len + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|e| ProtocolError::Compression(e.to_string()))?;
    Ok(out)
}
