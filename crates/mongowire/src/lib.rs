//! MongoDB wire protocol for servers, structured after `pgwire`.
//!
//! Layering (feature-gated like pgwire — with no features you get only the
//! protocol message layer):
//!
//! * `messages` — message types ([`Message`], [`MessageBody`], OP_MSG /
//!   OP_QUERY / OP_REPLY / OP_COMPRESSED) with a sync, pure-bytes
//!   encode/decode core.
//! * [`framing`] — length-prefixed frame parsing/encoding on `BytesMut`.
//! * `compression` — OP_COMPRESSED support; `zlib` / `snappy` / `zstd`
//!   features (noop always available).
//! * `api` + `codec` (behind `server`) — embeddable tokio server: a
//!   `tokio_util::codec` adapter plus handler traits.
//!
//! Protocol details follow the official specification; unknown required
//! `OP_MSG` flag bits error, unknown optional bits are ignored, CRC-32C
//! checksums are validated on read and computed on write, and `moreToCome`
//! requests are never replied to.

#![forbid(unsafe_code)]

pub mod error;
pub mod framing;
pub mod messages;

#[cfg(feature = "server")]
pub mod codec;

#[cfg(feature = "server")]
pub mod api;

pub mod compression;

/// In-crate test client for integration tests (requires `server` for tokio).
#[cfg(feature = "server")]
pub mod test_client;

pub use error::{Error, ProtocolError};
pub use messages::{
    Message, MessageBody, OpCompressed, OpMsg, OpQuery, OpReply, Sections,
    op_msg::{DocumentSequence, MsgFlags},
};
