//! OP_COMPRESSED compression algorithms.
//!
//! Each compressor lives behind its own feature (`zlib` / `snappy` / `zstd`),
//! following the official Rust driver; `noop` (id 0) is always available.
//! Wire IDs per the official spec.

#[cfg(feature = "snappy")]
mod snappy;
#[cfg(feature = "zlib")]
mod zlib;
#[cfg(feature = "zstd")]
mod zstd;
mod noop;

/// The `compressorId` byte of `OP_COMPRESSED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressorId {
    Noop,
    Snappy,
    Zlib,
    Zstd,
}

impl CompressorId {
    /// Wire byte.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Noop => mongo_common::consts::compressor_ids::NOOP,
            Self::Snappy => mongo_common::consts::compressor_ids::SNAPPY,
            Self::Zlib => mongo_common::consts::compressor_ids::ZLIB,
            Self::Zstd => mongo_common::consts::compressor_ids::ZSTD,
        }
    }

    /// Interpret a wire byte. Ids 4-255 are reserved.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            mongo_common::consts::compressor_ids::NOOP => Self::Noop,
            mongo_common::consts::compressor_ids::SNAPPY => Self::Snappy,
            mongo_common::consts::compressor_ids::ZLIB => Self::Zlib,
            mongo_common::consts::compressor_ids::ZSTD => Self::Zstd,
            _ => return None,
        })
    }

    /// Handshake name (`hello.compression` strings).
    pub fn name(self) -> &'static str {
        match self {
            Self::Noop => "noop",
            Self::Snappy => "snappy",
            Self::Zlib => "zlib",
            Self::Zstd => "zstd",
        }
    }

    /// Parse a handshake name.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "noop" => Self::Noop,
            "snappy" => Self::Snappy,
            "zlib" => Self::Zlib,
            "zstd" => Self::Zstd,
            _ => return None,
        })
    }

    /// Whether this build can actually compress/decompress with this id.
    pub fn is_enabled(self) -> bool {
        match self {
            Self::Noop => true,
            Self::Snappy => cfg!(feature = "snappy"),
            Self::Zlib => cfg!(feature = "zlib"),
            Self::Zstd => cfg!(feature = "zstd"),
        }
    }
}

/// Compress `data` with `id`.
///
/// # Errors
/// [`crate::ProtocolError::UnsupportedCompressor`] when the id is unknown or
/// its feature is disabled; [`crate::ProtocolError::Compression`] on failure.
pub fn compress(
    id: CompressorId,
    data: &[u8],
) -> Result<Vec<u8>, crate::error::ProtocolError> {
    match id {
        CompressorId::Noop => Ok(noop::compress(data)),
        #[cfg(feature = "snappy")]
        CompressorId::Snappy => snappy::compress(data),
        #[cfg(not(feature = "snappy"))]
        CompressorId::Snappy => Err(crate::error::ProtocolError::UnsupportedCompressor(
            id.to_u8(),
        )),
        #[cfg(feature = "zlib")]
        CompressorId::Zlib => zlib::compress(data),
        #[cfg(not(feature = "zlib"))]
        CompressorId::Zlib => Err(crate::error::ProtocolError::UnsupportedCompressor(
            id.to_u8(),
        )),
        #[cfg(feature = "zstd")]
        CompressorId::Zstd => zstd::compress(data),
        #[cfg(not(feature = "zstd"))]
        CompressorId::Zstd => Err(crate::error::ProtocolError::UnsupportedCompressor(
            id.to_u8(),
        )),
    }
}

/// Decompress `data`, expecting `expected_len` bytes afterwards.
///
/// # Errors
/// Same as [`compress`], plus
/// [`crate::ProtocolError::DecompressedSizeMismatch`] when the output length
/// disagrees with `OP_COMPRESSED.uncompressedSize`.
pub fn decompress(
    id: CompressorId,
    data: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>, crate::error::ProtocolError> {
    let out = match id {
        CompressorId::Noop => noop::compress(data),
        #[cfg(feature = "snappy")]
        CompressorId::Snappy => snappy::decompress(data, expected_len)?,
        #[cfg(not(feature = "snappy"))]
        CompressorId::Snappy => {
            return Err(crate::error::ProtocolError::UnsupportedCompressor(
                id.to_u8(),
            ))
        }
        #[cfg(feature = "zlib")]
        CompressorId::Zlib => zlib::decompress(data, expected_len)?,
        #[cfg(not(feature = "zlib"))]
        CompressorId::Zlib => {
            return Err(crate::error::ProtocolError::UnsupportedCompressor(
                id.to_u8(),
            ))
        }
        #[cfg(feature = "zstd")]
        CompressorId::Zstd => zstd::decompress(data, expected_len)?,
        #[cfg(not(feature = "zstd"))]
        CompressorId::Zstd => {
            return Err(crate::error::ProtocolError::UnsupportedCompressor(
                id.to_u8(),
            ))
        }
    };
    if out.len() != expected_len {
        return Err(crate::error::ProtocolError::DecompressedSizeMismatch {
            expected: expected_len,
            actual: out.len(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_roundtrip() {
        let data = b"the quick brown fox".to_vec();
        let compressed = compress(CompressorId::Noop, &data).unwrap();
        assert_eq!(compressed, data);
        let out = decompress(CompressorId::Noop, &compressed, data.len()).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn disabled_compressor_errors() {
        // All features off in the default build.
        if !CompressorId::Zstd.is_enabled() {
            assert!(matches!(
                compress(CompressorId::Zstd, b"x"),
                Err(crate::error::ProtocolError::UnsupportedCompressor(3))
            ));
        }
    }

    #[test]
    fn id_mapping() {
        assert_eq!(CompressorId::from_u8(2), Some(CompressorId::Zlib));
        assert_eq!(CompressorId::from_u8(4), None);
        assert_eq!(CompressorId::from_name("snappy"), Some(CompressorId::Snappy));
        assert_eq!(CompressorId::Zstd.name(), "zstd");
    }
}
