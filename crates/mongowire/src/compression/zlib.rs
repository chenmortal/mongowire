//! zlib compression (id 2), behind feature `zlib`.
//!
//! Wire format matches the official driver: raw zlib (deflate) stream with a
//! zlib header, default compression level.

use crate::error::ProtocolError;

pub(crate) fn compress(data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data)
        .map_err(|e| ProtocolError::Compression(e.to_string()))?;
    enc.finish().map_err(|e| ProtocolError::Compression(e.to_string()))
}

pub(crate) fn decompress(data: &[u8], expected_len: usize) -> Result<Vec<u8>, ProtocolError> {
    use std::io::Read;
    let dec = flate2::read::ZlibDecoder::new(data);
    // One extra byte of headroom so oversized output is caught here rather
    // than by the caller's length check.
    let mut out = Vec::with_capacity(expected_len);
    dec.take((expected_len + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|e| ProtocolError::Compression(e.to_string()))?;
    Ok(out)
}
