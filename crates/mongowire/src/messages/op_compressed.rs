//! `OP_COMPRESSED` — wraps another opcode's body, compressed.
//!
//! ```text
//! struct OP_COMPRESSED {
//!     MsgHeader header;             // handled by framing
//!     int32  originalOpcode;
//!     int32  uncompressedSize;      // size of deflated compressedMessage
//!     uint8  compressorId;
//!     char*  compressedMessage;     // the wrapped body, excluding MsgHeader
//! }
//! ```

use bytes::{Bytes, BytesMut};

use mongo_common::io::ProtocolRead;
use mongo_common::io::ProtocolWrite;

use crate::compression::CompressorId;
use crate::error::ProtocolError;
use crate::messages::{Message, Opcode};

/// The OP_COMPRESSED body.
#[derive(Debug, Clone, PartialEq)]
pub struct OpCompressed {
    /// Opcode of the wrapped message.
    pub original_opcode: Opcode,
    /// Size of `compressed_message` after decompression.
    pub uncompressed_size: i32,
    pub compressor_id: CompressorId,
    pub compressed_message: Bytes,
}

impl OpCompressed {
    /// Wrap an already-encoded body of `opcode`, compressing it with `id`.
    ///
    /// # Errors
    /// [`ProtocolError::Compression`] if the compressor fails,
    /// [`ProtocolError::UnsupportedCompressor`] if the compressor is
    /// disabled in this build.
    pub fn wrap(opcode: Opcode, body: Bytes, id: CompressorId) -> Result<Self, ProtocolError> {
        let uncompressed_size = i32::try_from(body.len())
            .map_err(|_| ProtocolError::Compression("body larger than i32::MAX".to_owned()))?;
        let compressed_message = Bytes::from(crate::compression::compress(id, &body)?);
        Ok(Self {
            original_opcode: opcode,
            uncompressed_size,
            compressor_id: id,
            compressed_message,
        })
    }

    /// Decompress and parse the wrapped body.
    ///
    /// `max_msg_len` bounds the accepted `uncompressedSize` (real servers
    /// reject a decompressed size above their message limit): a hostile frame
    /// declaring ~2 GiB otherwise forces a 2 GiB allocation from ~30 bytes on
    /// the wire (security review, PoC-confirmed).
    ///
    /// Nested OP_COMPRESSED is rejected: compression is single-level on the
    /// wire, and the nested form once reached an `unreachable!()` in the
    /// server loop.
    ///
    /// # Errors
    /// [`ProtocolError::InvalidOpMsg`] on a negative `uncompressedSize` or
    /// nested compression, [`ProtocolError::MessageTooLarge`] when
    /// `uncompressedSize` exceeds `max_msg_len`,
    /// [`ProtocolError::DecompressedSizeMismatch`] if the decompressed
    /// length disagrees with it, [`ProtocolError::UnsupportedCompressor`] if
    /// the compressor is disabled in this build, or whatever
    /// [`MessageBody::parse_body`] rejects for the wrapped opcode.
    pub fn unwrap_body(
        &self,
        max_msg_len: i32,
    ) -> Result<crate::messages::MessageBody, ProtocolError> {
        if self.uncompressed_size < 0 {
            return Err(ProtocolError::InvalidOpMsg("negative uncompressedSize"));
        }
        if self.original_opcode == Opcode::Compressed {
            return Err(ProtocolError::InvalidOpMsg("nested OP_COMPRESSED"));
        }
        if self.uncompressed_size > max_msg_len {
            return Err(ProtocolError::MessageTooLarge {
                size: self.uncompressed_size,
                max: max_msg_len,
            });
        }
        let decompressed = crate::compression::decompress(
            self.compressor_id,
            &self.compressed_message,
            self.uncompressed_size as usize,
        )?;
        crate::messages::MessageBody::parse_body(self.original_opcode, Bytes::from(decompressed))
    }
}

impl Message for OpCompressed {
    const OPCODE: crate::messages::Opcode = crate::messages::Opcode::Compressed;

    fn body_len(&self) -> usize {
        4 + 4 + 1 + self.compressed_message.len()
    }

    fn encode_body(&self, out: &mut BytesMut) {
        out.reserve(self.body_len());
        out.put_i32_le(self.original_opcode.to_i32());
        out.put_i32_le(self.uncompressed_size);
        out.put_u8(self.compressor_id.to_u8());
        out.put_bytes(&self.compressed_message);
    }

    fn parse_body(body: Bytes) -> Result<Self, ProtocolError> {
        let mut r: &[u8] = &body;
        let raw_opcode = r.read_i32_le()?;
        let original_opcode =
            Opcode::from_i32(raw_opcode).ok_or(ProtocolError::UnsupportedOpcode(raw_opcode))?;
        let uncompressed_size = r.read_i32_le()?;
        if uncompressed_size < 0 {
            return Err(ProtocolError::InvalidOpMsg("negative uncompressedSize"));
        }
        let raw_id = r.read_u8()?;
        let compressor_id = CompressorId::from_u8(raw_id)
            .ok_or(ProtocolError::UnsupportedCompressor(raw_id))?;
        // Everything left is the compressed payload, as a zero-copy view.
        let start = body.len() - r.remaining();
        let compressed_message = body.slice(start..);
        Ok(Self {
            original_opcode,
            uncompressed_size,
            compressor_id,
            compressed_message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongo_common::consts::MAX_MSG_LEN;
    use crate::messages::{MessageBody, OpMsg};
    use wirebson::{Bson, Document};

    /// A plain OP_MSG body (no checksum) as raw bytes.
    fn msg_body() -> Bytes {
        let msg = OpMsg::new(
            crate::messages::MsgFlags::empty(),
            Document::from_iter([("insert", Bson::from("actor")), ("$db", Bson::from("monila"))])
                .encode()
                .unwrap(),
            vec![],
        )
        .unwrap();
        let mut out = BytesMut::new();
        msg.encode_body(&mut out);
        out.freeze()
    }

    #[test]
    fn noop_roundtrip_through_wrap_parse_unwrap() {
        let body = msg_body();
        let compressed = OpCompressed::wrap(Opcode::Msg, body.clone(), CompressorId::Noop).unwrap();
        // The noop compressor stores the payload verbatim.
        assert_eq!(compressed.compressed_message, body);
        assert_eq!(compressed.uncompressed_size, body.len() as i32);

        // Body length: originalOpcode + uncompressedSize + compressorId + payload.
        assert_eq!(compressed.body_len(), 4 + 4 + 1 + body.len());

        let mut out = BytesMut::new();
        compressed.encode_body(&mut out);
        assert_eq!(out.len(), compressed.body_len());
        let parsed = OpCompressed::parse_body(out.freeze()).unwrap();
        assert_eq!(parsed, compressed);

        let MessageBody::Msg(msg) = parsed.unwrap_body(MAX_MSG_LEN).unwrap() else {
            panic!("expected the wrapped OP_MSG")
        };
        assert_eq!(msg.document().command().unwrap(), "insert");
    }

    #[test]
    fn full_frame_roundtrip_through_framing() {
        let compressed = OpCompressed::wrap(Opcode::Msg, msg_body(), CompressorId::Noop).unwrap();
        let body = MessageBody::Compressed(compressed);
        let mut out = BytesMut::new();
        crate::framing::encode_message(&mut crate::messages::Header::new(9, 0, Opcode::Compressed), &body, false, &mut out).unwrap();
        let (header, parsed) =
            crate::framing::parse_message(&mut out, mongo_common::consts::MAX_MSG_LEN)
                .unwrap()
                .unwrap();
        assert_eq!(header.op_code, Opcode::Compressed);
        let MessageBody::Compressed(c) = parsed else {
            panic!("expected a Compressed body")
        };
        assert_eq!(c.original_opcode, Opcode::Msg);
        assert!(matches!(c.unwrap_body(MAX_MSG_LEN).unwrap(), MessageBody::Msg(_)));
    }

    #[test]
    fn nested_compressed_is_rejected() {
        // Compression is single-level on the wire: unwrapping an
        // OP_COMPRESSED that wraps another one must error (it once reached an
        // `unreachable!()` in the server loop — security review, PoC'd).
        let inner = OpCompressed::wrap(Opcode::Msg, msg_body(), CompressorId::Noop).unwrap();
        let mut inner_bytes = BytesMut::new();
        inner.encode_body(&mut inner_bytes);
        let outer =
            OpCompressed::wrap(Opcode::Compressed, inner_bytes.freeze(), CompressorId::Noop)
                .unwrap();

        assert!(matches!(
            outer.unwrap_body(MAX_MSG_LEN),
            Err(ProtocolError::InvalidOpMsg("nested OP_COMPRESSED"))
        ));
    }

    #[test]
    fn oversized_uncompressed_size_is_rejected_before_allocating() {
        // A ~30-byte frame declaring a 2 GiB uncompressed size must be
        // rejected against the message limit, never allocated (security
        // review: PoC produced a 2 GiB VmPeak spike).
        let compressed = OpCompressed {
            original_opcode: Opcode::Msg,
            uncompressed_size: 0x7FFF_FFFF,
            compressor_id: CompressorId::Noop,
            compressed_message: msg_body(),
        };
        assert!(matches!(
            compressed.unwrap_body(MAX_MSG_LEN),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn tampered_uncompressed_size_is_caught() {
        let compressed = OpCompressed::wrap(Opcode::Msg, msg_body(), CompressorId::Noop).unwrap();
        let wrong = OpCompressed {
            uncompressed_size: compressed.uncompressed_size + 1,
            ..compressed.clone()
        };
        assert!(matches!(
            wrong.unwrap_body(MAX_MSG_LEN),
            Err(ProtocolError::DecompressedSizeMismatch { expected, actual })
            if expected == wrong.uncompressed_size as usize && actual == expected - 1
        ));

        // A negative size is rejected before decompression is attempted.
        let negative = OpCompressed {
            uncompressed_size: -1,
            ..compressed
        };
        assert!(matches!(
            negative.unwrap_body(MAX_MSG_LEN),
            Err(ProtocolError::InvalidOpMsg("negative uncompressedSize"))
        ));
    }

    #[test]
    fn parse_rejects_negative_size_and_truncation() {
        // originalOpcode + uncompressedSize + compressorId, size = -1.
        let mut buf = BytesMut::new();
        buf.put_i32_le(Opcode::Msg.to_i32());
        buf.put_i32_le(-1);
        buf.put_u8(CompressorId::Noop.to_u8());
        assert!(matches!(
            OpCompressed::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidOpMsg("negative uncompressedSize"))
        ));

        // The fixed part is 9 bytes (opcode + size + id); everything beyond
        // it is an opaque payload. Prefixes cutting into the fixed part
        // error; longer prefixes parse, with the payload truncated — the
        // size disagreement only surfaces in `unwrap_body`.
        let compressed = OpCompressed::wrap(Opcode::Msg, msg_body(), CompressorId::Noop).unwrap();
        let mut out = BytesMut::new();
        compressed.encode_body(&mut out);
        let body = out.freeze();
        for n in 0..body.len() {
            let result = OpCompressed::parse_body(body.slice(..n));
            assert_eq!(result.is_ok(), n >= 9, "n={n}: {result:?}");
        }
        let cut = OpCompressed::parse_body(body.slice(..9)).unwrap();
        assert!(cut.compressed_message.is_empty());
        assert!(matches!(
            cut.unwrap_body(MAX_MSG_LEN),
            Err(ProtocolError::DecompressedSizeMismatch { .. })
        ));
    }

    #[test]
    fn parse_rejects_unknown_opcode_and_compressor() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(42); // originalOpcode
        buf.put_i32_le(0);
        buf.put_u8(CompressorId::Noop.to_u8());
        assert!(matches!(
            OpCompressed::parse_body(buf.freeze()),
            Err(ProtocolError::UnsupportedOpcode(42))
        ));

        let mut buf = BytesMut::new();
        buf.put_i32_le(Opcode::Msg.to_i32());
        buf.put_i32_le(0);
        buf.put_u8(200); // reserved compressor id
        assert!(matches!(
            OpCompressed::parse_body(buf.freeze()),
            Err(ProtocolError::UnsupportedCompressor(200))
        ));
    }

    #[test]
    fn disabled_compressor_is_rejected() {
        // The default build only ships the noop compressor.
        if !CompressorId::Snappy.is_enabled() {
            assert!(matches!(
                OpCompressed::wrap(Opcode::Msg, msg_body(), CompressorId::Snappy),
                Err(ProtocolError::UnsupportedCompressor(1))
            ));
        }
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn zlib_roundtrip() {
        check_roundtrip(CompressorId::Zlib);
    }

    #[cfg(feature = "snappy")]
    #[test]
    fn snappy_roundtrip() {
        check_roundtrip(CompressorId::Snappy);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_roundtrip() {
        check_roundtrip(CompressorId::Zstd);
    }

    /// Wrap → encode → parse → unwrap with a real compressor: the payload
    /// shrinks (the body is highly repetitive) and survives intact.
    #[cfg(any(feature = "zlib", feature = "snappy", feature = "zstd"))]
    fn check_roundtrip(id: CompressorId) {
        // One OP_MSG carrying a large repetitive payload, which every real
        // compressor must shrink.
        let mut long = String::new();
        for _ in 0..200 {
            long.push_str("actor-");
        }
        let msg = OpMsg::new(
            crate::messages::MsgFlags::empty(),
            Document::from_iter([
                ("insert", Bson::from("actor")),
                ("notes", Bson::from(long.as_str())),
                ("$db", Bson::from("monila")),
            ])
            .encode()
            .unwrap(),
            vec![],
        )
        .unwrap();
        let mut body_mut = BytesMut::new();
        msg.encode_body(&mut body_mut);
        let body = body_mut.freeze();

        let compressed = OpCompressed::wrap(Opcode::Msg, body.clone(), id).unwrap();
        assert!(
            compressed.compressed_message.len() < body.len(),
            "{:?} must shrink the payload",
            id
        );
        assert_eq!(compressed.body_len(), 4 + 4 + 1 + compressed.compressed_message.len());

        let mut out = BytesMut::new();
        compressed.encode_body(&mut out);
        let parsed = OpCompressed::parse_body(out.freeze()).unwrap();
        assert_eq!(parsed.compressor_id, id);
        let MessageBody::Msg(unwrapped) = parsed.unwrap_body(MAX_MSG_LEN).unwrap() else {
            panic!("expected the wrapped OP_MSG")
        };
        assert_eq!(unwrapped, msg);
    }
}
