//! Standard message header and opcode (official spec: "Standard Message
//! Header"), 16 bytes, little-endian.

use bytes::BytesMut;

use mongo_common::consts::{MSG_HEADER_LEN, MAX_MSG_LEN, opcodes};
use mongo_common::io::{ProtocolRead, ReadError};

use crate::error::ProtocolError;

/// Wire opcodes with a known body type in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Reply,
    Update,
    Insert,
    Reserved,
    Query,
    GetMore,
    Delete,
    KillCursors,
    Compressed,
    Msg,
}

impl Opcode {
    /// Wire value.
    pub fn to_i32(self) -> i32 {
        match self {
            Self::Reply => opcodes::OP_REPLY,
            Self::Update => opcodes::OP_UPDATE,
            Self::Insert => opcodes::OP_INSERT,
            Self::Reserved => opcodes::OP_RESERVED,
            Self::Query => opcodes::OP_QUERY,
            Self::GetMore => opcodes::OP_GET_MORE,
            Self::Delete => opcodes::OP_DELETE,
            Self::KillCursors => opcodes::OP_KILL_CURSORS,
            Self::Compressed => opcodes::OP_COMPRESSED,
            Self::Msg => opcodes::OP_MSG,
        }
    }

    /// Interpret a wire value.
    pub fn from_i32(v: i32) -> Option<Self> {
        Some(match v {
            opcodes::OP_REPLY => Self::Reply,
            opcodes::OP_UPDATE => Self::Update,
            opcodes::OP_INSERT => Self::Insert,
            opcodes::OP_RESERVED => Self::Reserved,
            opcodes::OP_QUERY => Self::Query,
            opcodes::OP_GET_MORE => Self::GetMore,
            opcodes::OP_DELETE => Self::Delete,
            opcodes::OP_KILL_CURSORS => Self::KillCursors,
            opcodes::OP_COMPRESSED => Self::Compressed,
            opcodes::OP_MSG => Self::Msg,
            _ => return None,
        })
    }
}

/// The standard message header.
///
/// [`Header::message_length`] is computed during encoding; it includes the 16
/// bytes of the header itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Total message size including this field. Zero on freshly built
    /// headers (see [`Header::new`]); filled in by
    /// [`crate::framing::encode_message`].
    pub message_length: i32,
    pub request_id: i32,
    pub response_to: i32,
    pub op_code: Opcode,
}

impl Header {
    /// Build a header with [`Self::message_length`] left at zero (to be
    /// filled during encoding).
    pub fn new(request_id: i32, response_to: i32, op_code: Opcode) -> Self {
        Self {
            message_length: 0,
            request_id,
            response_to,
            op_code,
        }
    }

    /// Validate and parse the first 16 bytes.
    ///
    /// # Errors
    /// * [`ProtocolError::InvalidHeader`] — length below the header size.
    /// * [`ProtocolError::MessageTooLarge`] — length above `max_len`.
    /// * [`ProtocolError::UnsupportedOpcode`] — unknown opcode.
    pub fn parse(buf: &[u8], max_len: i32) -> Result<Self, ProtocolError> {
        let mut r: &[u8] = buf
            .get(..MSG_HEADER_LEN)
            .ok_or(ProtocolError::InvalidHeader("short header"))?;
        let message_length = r.read_i32_le().unwrap_or(0);
        if message_length < MSG_HEADER_LEN as i32 {
            return Err(ProtocolError::InvalidHeader("length below header size"));
        }
        if message_length > max_len {
            return Err(ProtocolError::MessageTooLarge {
                size: message_length,
                max: max_len,
            });
        }
        if message_length > MAX_MSG_LEN {
            return Err(ProtocolError::MessageTooLarge {
                size: message_length,
                max: MAX_MSG_LEN,
            });
        }
        let request_id = r.read_i32_le().unwrap_or(0);
        let response_to = r.read_i32_le().unwrap_or(0);
        let raw_opcode = r.read_i32_le().unwrap_or(0);
        let op_code = Opcode::from_i32(raw_opcode).ok_or(ProtocolError::UnsupportedOpcode(raw_opcode))?;
        Ok(Self {
            message_length,
            request_id,
            response_to,
            op_code,
        })
    }

    /// Append the 16 header bytes to `out` (with the current
    /// [`Self::message_length`], which may still be zero).
    pub fn encode(&self, out: &mut BytesMut) {
        out.extend_from_slice(&self.message_length.to_le_bytes());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        out.extend_from_slice(&self.response_to.to_le_bytes());
        out.extend_from_slice(&self.op_code.to_i32().to_le_bytes());
    }
}

impl From<ReadError> for ProtocolError {
    fn from(e: ReadError) -> Self {
        Self::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 16 header bytes for the given fields.
    fn bytes(message_length: i32, request_id: i32, response_to: i32, op_code: i32) -> [u8; 16] {
        let mut b = [0u8; MSG_HEADER_LEN];
        b[0..4].copy_from_slice(&message_length.to_le_bytes());
        b[4..8].copy_from_slice(&request_id.to_le_bytes());
        b[8..12].copy_from_slice(&response_to.to_le_bytes());
        b[12..16].copy_from_slice(&op_code.to_le_bytes());
        b
    }

    #[test]
    fn parse_happy_path() {
        // Fields of the recorded handshake1 header (see tests/data).
        let h = Header::parse(&bytes(372, 1, 0, opcodes::OP_QUERY), 1 << 20).unwrap();
        assert_eq!(h.message_length, 372);
        assert_eq!(h.request_id, 1);
        assert_eq!(h.response_to, 0);
        assert_eq!(h.op_code, Opcode::Query);
    }

    #[test]
    fn parse_short_buffer() {
        for n in 0..MSG_HEADER_LEN {
            let buf = bytes(372, 1, 0, opcodes::OP_QUERY);
            assert!(
                matches!(Header::parse(&buf[..n], MAX_MSG_LEN), Err(ProtocolError::InvalidHeader(_))),
                "n={n}"
            );
        }
    }

    #[test]
    fn parse_length_below_header_size() {
        for length in [0, 1, 15] {
            assert!(
                matches!(
                    Header::parse(&bytes(length, 1, 0, opcodes::OP_QUERY), MAX_MSG_LEN),
                    Err(ProtocolError::InvalidHeader("length below header size"))
                ),
                "length={length}"
            );
        }
        // Negative lengths (e.g. the -1 all-ff prefix) are caught the same way.
        assert!(matches!(
            Header::parse(&bytes(-1, 1, 0, opcodes::OP_QUERY), MAX_MSG_LEN),
            Err(ProtocolError::InvalidHeader(_))
        ));
    }

    #[test]
    fn parse_length_above_max() {
        // Both a stricter caller-provided limit ...
        assert!(matches!(
            Header::parse(&bytes(2000, 1, 0, opcodes::OP_QUERY), 1000),
            Err(ProtocolError::MessageTooLarge {
                size: 2000,
                max: 1000
            })
        ));
        // ... and the absolute crate limit.
        assert!(matches!(
            Header::parse(&bytes(MAX_MSG_LEN + 1, 1, 0, opcodes::OP_QUERY), MAX_MSG_LEN),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn parse_unknown_opcode() {
        assert!(matches!(
            Header::parse(&bytes(16, 1, 0, 42), MAX_MSG_LEN),
            Err(ProtocolError::UnsupportedOpcode(42))
        ));
    }

    #[test]
    fn encode_parse_roundtrip() {
        for op in [
            Opcode::Reply,
            Opcode::Update,
            Opcode::Insert,
            Opcode::Reserved,
            Opcode::Query,
            Opcode::GetMore,
            Opcode::Delete,
            Opcode::KillCursors,
            Opcode::Compressed,
            Opcode::Msg,
        ] {
            // A ready-to-send header carries its length (as `encode_message`
            // would fill it in for a bodyless message).
            let header = Header {
                message_length: MSG_HEADER_LEN as i32,
                request_id: 7,
                response_to: 9,
                op_code: op,
            };
            let mut out = BytesMut::new();
            header.encode(&mut out);
            assert_eq!(out.len(), MSG_HEADER_LEN);

            let parsed = Header::parse(&out, MAX_MSG_LEN).unwrap();
            assert_eq!(parsed, Header {
                message_length: MSG_HEADER_LEN as i32,
                request_id: 7,
                response_to: 9,
                op_code: op,
            });
        }
    }

    #[test]
    fn opcode_wire_values() {
        for op in [
            Opcode::Reply,
            Opcode::Update,
            Opcode::Insert,
            Opcode::Reserved,
            Opcode::Query,
            Opcode::GetMore,
            Opcode::Delete,
            Opcode::KillCursors,
            Opcode::Compressed,
            Opcode::Msg,
        ] {
            assert_eq!(Opcode::from_i32(op.to_i32()), Some(op));
        }
        assert_eq!(Opcode::from_i32(42), None);
        assert_eq!(Opcode::from_i32(0), None);
        assert_eq!(Opcode::from_i32(opcodes::OP_RESERVED), Some(Opcode::Reserved));
    }
}
