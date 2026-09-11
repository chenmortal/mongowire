//! Protocol message types.
//!
//! The [`Message`] trait and [`MessageBody`] enum form a sync, pure-bytes
//! core: `parse_body` consumes a `Bytes` slice of the body (everything after
//! the 16-byte header), `encode_body` appends to a `BytesMut`. Framing
//! (headers, length checks, checksums) lives in [`crate::framing`].

pub mod header;
pub mod op_compressed;
pub mod op_msg;
pub mod op_query;
pub mod op_reply;

pub use header::{Header, Opcode};
pub use op_compressed::OpCompressed;
pub use op_msg::{DocumentSequence, MsgFlags, OpMsg, Sections};
pub use op_query::{OpQuery, QueryFlags};
pub use op_reply::{OpReply, ReplyFlags};

use bytes::{Bytes, BytesMut};

use crate::error::ProtocolError;

/// A wire protocol message body.
pub trait Message: Sized {
    /// The opcode this body belongs to.
    const OPCODE: Opcode;

    /// Total encoded body length in bytes (excluding the 16-byte header),
    /// including the checksum trailer when present.
    fn body_len(&self) -> usize;

    /// Append the encoded body to `out`.
    fn encode_body(&self, out: &mut BytesMut);

    /// Parse a body slice (everything after the header; for `checksumPresent`
    /// messages this includes the trailing 4-byte checksum).
    ///
    /// # Errors
    /// [`ProtocolError`] on any structural violation.
    fn parse_body(body: Bytes) -> Result<Self, ProtocolError>;
}

/// Any message body, tagged by opcode.
#[derive(Debug, Clone)]
pub enum MessageBody {
    Msg(OpMsg),
    Query(OpQuery),
    Reply(OpReply),
    Compressed(OpCompressed),
}

impl MessageBody {
    /// The opcode of this body.
    pub fn opcode(&self) -> Opcode {
        match self {
            Self::Msg(_) => Opcode::Msg,
            Self::Query(_) => Opcode::Query,
            Self::Reply(_) => Opcode::Reply,
            Self::Compressed(_) => Opcode::Compressed,
        }
    }

    /// Total encoded body length in bytes.
    pub fn body_len(&self) -> usize {
        match self {
            Self::Msg(m) => m.body_len(),
            Self::Query(q) => q.body_len(),
            Self::Reply(r) => r.body_len(),
            Self::Compressed(c) => c.body_len(),
        }
    }

    /// Append the encoded body to `out`.
    pub fn encode_body(&self, out: &mut BytesMut) {
        match self {
            Self::Msg(m) => m.encode_body(out),
            Self::Query(q) => q.encode_body(out),
            Self::Reply(r) => r.encode_body(out),
            Self::Compressed(c) => c.encode_body(out),
        }
    }

    /// Parse a body of the given opcode.
    ///
    /// # Errors
    /// [`ProtocolError::UnsupportedOpcode`] for opcodes without a body type;
    /// otherwise whatever the concrete parser rejects.
    pub fn parse_body(opcode: Opcode, body: Bytes) -> Result<Self, ProtocolError> {
        match opcode {
            Opcode::Msg => Ok(Self::Msg(OpMsg::parse_body(body)?)),
            Opcode::Query => Ok(Self::Query(OpQuery::parse_body(body)?)),
            Opcode::Reply => Ok(Self::Reply(OpReply::parse_body(body)?)),
            Opcode::Compressed => Ok(Self::Compressed(OpCompressed::parse_body(body)?)),
            Opcode::Update
            | Opcode::Insert
            | Opcode::Reserved
            | Opcode::GetMore
            | Opcode::Delete
            | Opcode::KillCursors => Err(ProtocolError::UnsupportedOpcode(opcode.to_i32())),
        }
    }
}
