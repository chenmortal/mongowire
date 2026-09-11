//! A minimal tokio test client (the `wireclient` equivalent), compiled only
//! for the crate's own tests.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::ProtocolError;
use crate::messages::{Header, MessageBody, OpQuery, OpReply};

/// A test client speaking raw wire frames over TCP.
pub struct TestClient {
    stream: TcpStream,
    buf: BytesMut,
}

/// Process-wide monotonic request-id source, shared by the send helpers.
fn next_id() -> i32 {
    use std::sync::atomic::{AtomicI32, Ordering};
    static NEXT: AtomicI32 = AtomicI32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Encode one full frame: header (message_length computed) + body, plus a
/// CRC-32C trailer when `checksum` is set.
///
/// # Errors
/// Encoding errors, mapped onto `io::Error` for `write_all`.
fn frame_bytes(
    request_id: i32,
    response_to: i32,
    body: &MessageBody,
    checksum: bool,
) -> std::io::Result<Bytes> {
    let mut header = Header::new(request_id, response_to, body.opcode());
    let mut out = BytesMut::new();
    crate::framing::encode_message(&mut header, body, checksum, &mut out)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(out.freeze())
}

impl TestClient {
    /// Connect to a test server.
    ///
    /// # Errors
    /// Connection failures.
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        Ok(Self {
            stream: TcpStream::connect(addr).await?,
            buf: BytesMut::new(),
        })
    }

    /// Encode and write one frame.
    async fn write_frame(
        &mut self,
        request_id: i32,
        response_to: i32,
        body: &MessageBody,
        checksum: bool,
    ) -> std::io::Result<()> {
        let bytes = frame_bytes(request_id, response_to, body, checksum)?;
        self.stream.write_all(&bytes).await
    }

    /// Send a message with the given header (message_length is computed).
    ///
    /// # Errors
    /// Write failures or encoding errors.
    pub async fn send(
        &mut self,
        request_id: i32,
        response_to: i32,
        body: &MessageBody,
    ) -> std::io::Result<()> {
        self.write_frame(request_id, response_to, body, false).await
    }

    /// Send a message with a CRC-32C trailer; for OP_MSG the encoder also
    /// sets the `checksumPresent` flag bit so a receiver finds the trailer.
    ///
    /// # Errors
    /// See [`Self::send`].
    pub async fn send_with_checksum(
        &mut self,
        request_id: i32,
        response_to: i32,
        body: &MessageBody,
    ) -> std::io::Result<()> {
        self.write_frame(request_id, response_to, body, true).await
    }

    /// Send `request` as a legacy OP_QUERY on `admin.$cmd`, returning the
    /// request id (to match against the reply header's `responseTo`).
    ///
    /// # Errors
    /// See [`Self::send`].
    pub async fn send_op_query_handshake(
        &mut self,
        request: wirebson::RawDocument,
    ) -> std::io::Result<i32> {
        let id = next_id();
        self.send(id, 0, &MessageBody::Query(OpQuery::handshake(request))).await?;
        Ok(id)
    }

    /// Receive one message; `None` on clean EOF.
    ///
    /// # Errors
    /// Read failures or protocol errors.
    pub async fn recv(&mut self) -> Result<Option<(Header, MessageBody)>, ProtocolError> {
        loop {
            if let Some(msg) = crate::framing::parse_message(&mut self.buf, i32::MAX)? {
                return Ok(Some(msg));
            }
            if 0 == self.stream.read_buf(&mut self.buf).await? {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(ProtocolError::InvalidHeader("truncated message before EOF"));
            }
        }
    }

    /// Receive the next message, which must be an OP_REPLY.
    ///
    /// # Errors
    /// See [`Self::recv`].
    ///
    /// # Panics
    /// On EOF or a non-OP_REPLY message — test-helper behavior, mirroring
    /// [`Self::request`].
    pub async fn recv_op_reply(&mut self) -> Result<(Header, OpReply), ProtocolError> {
        let (header, body) =
            self.recv().await?.expect("connection closed before the OP_REPLY");
        match body {
            MessageBody::Reply(reply) => Ok((header, reply)),
            body => panic!("expected an OP_REPLY, got {body:?}"),
        }
    }

    /// Convenience: request/response round trip; asserts `responseTo`.
    ///
    /// # Errors
    /// See [`Self::recv`].
    pub async fn request(
        &mut self,
        body: &MessageBody,
    ) -> Result<(Header, MessageBody), ProtocolError> {
        let id = next_id();
        self.send(id, 0, body).await?;
        let (header, reply) = self.recv().await?.expect("server closed connection");
        assert_eq!(header.response_to, id, "mismatched responseTo");
        Ok((header, reply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{MsgFlags, OpMsg};
    use mongo_common::consts::MAX_MSG_LEN;
    use wirebson::{Bson, Document};

    /// Encode a document and unwrap (test documents are always valid).
    fn raw(pairs: impl IntoIterator<Item = (&'static str, Bson)>) -> wirebson::RawDocument {
        Document::from_iter(pairs).encode().unwrap()
    }

    /// Parse exactly one frame back out of a fresh buffer.
    fn parse(frame: &[u8]) -> (Header, MessageBody) {
        crate::framing::parse_message(&mut BytesMut::from(frame), MAX_MSG_LEN)
            .unwrap()
            .expect("a complete frame")
    }

    /// The OP_MSG body the checksummed helper is exercised with.
    fn ping_body() -> MessageBody {
        MessageBody::Msg(
            OpMsg::new(MsgFlags::empty(), raw([("ping", Bson::Int32(1))]), Vec::new()).unwrap(),
        )
    }

    #[test]
    fn handshake_frame_roundtrips_through_framing() {
        // The frame `send_op_query_handshake` writes: OpQuery::handshake(...)
        // with a fresh request id and responseTo 0.
        let request = raw([("isMaster", Bson::Int32(1))]);
        let body = MessageBody::Query(OpQuery::handshake(request.clone()));
        let frame = frame_bytes(5, 0, &body, false).unwrap();

        let (header, parsed) = parse(&frame);
        assert_eq!(header.request_id, 5);
        assert_eq!(header.response_to, 0);
        let MessageBody::Query(query) = parsed else {
            panic!("expected an OP_QUERY, got {parsed:?}")
        };
        assert_eq!(query.full_collection_name, "admin.$cmd");
        assert_eq!(query.number_to_return, -1);
        assert_eq!(query.query, request);
    }

    #[test]
    fn checksummed_frame_roundtrips_through_framing() {
        // The frame `send_with_checksum` writes: OP_MSG with the flag patched
        // in and a valid CRC-32C trailer.
        let frame = frame_bytes(9, 0, &ping_body(), true).unwrap();

        let (header, parsed) = parse(&frame);
        assert_eq!(header.request_id, 9);
        let MessageBody::Msg(msg) = parsed else {
            panic!("expected an OP_MSG, got {parsed:?}")
        };
        assert!(msg.flags.contains(MsgFlags::CHECKSUM_PRESENT));
        let checksum = msg.checksum.expect("checksummed frame");
        assert_eq!(checksum, mongo_common::crc32c::checksum(&frame[..frame.len() - 4]));
        assert_eq!(msg.document(), &raw([("ping", Bson::Int32(1))]));
    }
}
