//! tokio codec adapter (feature `server`): a `tokio_util::codec`
//! `Decoder`/`Encoder` pair over [`crate::framing`], mirroring pgwire's
//! `PgWireMessageServerCodec`.

use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::ProtocolError;
use crate::framing;
use crate::messages::{Header, MessageBody};

/// Server-side codec configuration.
#[derive(Debug, Clone)]
pub struct CodecConfig {
    /// Max accepted message size (defaults to
    /// [`mongo_common::consts::MAX_MSG_LEN`]).
    pub max_msg_len: i32,
}

impl Default for CodecConfig {
    fn default() -> Self {
        Self {
            max_msg_len: mongo_common::consts::MAX_MSG_LEN,
        }
    }
}

/// Decodes client messages; encodes server messages.
///
/// Decoding freezes the whole message region so raw documents inside it are
/// zero-copy views.
#[derive(Debug)]
pub struct MongoCodec {
    config: CodecConfig,
}

impl MongoCodec {
    pub fn new(config: CodecConfig) -> Self {
        Self { config }
    }
}

impl Decoder for MongoCodec {
    type Item = (Header, MessageBody);
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        framing::parse_message(src, self.config.max_msg_len)
    }
}

impl Encoder<(Header, MessageBody)> for MongoCodec {
    type Error = ProtocolError;

    /// Encodes without a CRC-32C trailer: the `Encoder` only sees the message,
    /// not the connection's checksum setting (which lives in
    /// [`crate::api::ConnectionInfo`]). Checksummed replies are written by
    /// [`crate::api`] via [`framing::encode_message`] directly onto the
    /// stream; the `Decoder` verifies incoming trailers either way.
    fn encode(
        &mut self,
        item: (Header, MessageBody),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let (mut header, body) = item;
        framing::encode_message(&mut header, &body, false, dst)
    }
}

/// Encode a message into a fresh buffer (test helper shared by api code).
pub fn to_bytes(
    header: &mut Header,
    body: &MessageBody,
    checksum: bool,
) -> Result<Bytes, ProtocolError> {
    let mut out = BytesMut::new();
    framing::encode_message(header, body, checksum, &mut out)?;
    Ok(out.freeze())
}
