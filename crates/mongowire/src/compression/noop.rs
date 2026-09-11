//! The `noop` compressor (id 0): identity transform, used for testing.

pub(crate) fn compress(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}
