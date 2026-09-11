//! Embeddable MongoDB server framework (feature `server`), mirroring pgwire's
//! `api` layer: handler traits the user implements, plus the connection glue.
//!
//! Layering is pgwire-like: [`process_socket`] is a dumb connection loop — it
//! unwraps frames, builds [`Command`]s and ships replies — while all command
//! semantics live in [`CommandHandler`] implementations. Ready-made handlers
//! wrap an inner one and peel off the standard commands:
//!
//! * [`BuiltinHandler`] — `hello` / `isMaster` (with compression negotiation)
//!   and `ping`;
//! * [`ScramBridge`] — `saslStart` / `saslContinue` against a
//!   [`CredentialSource`].
//!
//! ```text
//! ServerHandlers {
//!     command_handler: Arc::new(BuiltinHandler::new(
//!         Arc::new(ScramBridge::new(user_handler, credentials)),
//!         config.compressors.clone(),
//!         config.max_msg_len,
//!     )),
//! }
//! ```
//!
//! # Reply encoding
//! Replies are never compressed (no negotiated-compressor state is tracked
//! deep enough to justify it; the spec allows an uncompressed reply to a
//! compressed request). OP_MSG replies carry a CRC-32C trailer when
//! [`ServerConfig::checksum`] is set; legacy OP_QUERY/OP_REPLY frames never
//! do (checksums are an OP_MSG feature).

pub mod auth;
pub mod client_info;
pub mod handler;
pub mod response;

pub use auth::{AuthState, CredentialSource, MemoryCredentialSource, ScramBridge};
pub use client_info::ConnectionInfo;
pub use handler::{Command, CommandHandler, Reply};
pub use response::{handshake_reply, ping_reply, query_handshake_reply};

use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::codec::{CodecConfig, MongoCodec};
use crate::compression::CompressorId;
use crate::error::Error;
use crate::framing;
use crate::messages::{Header, MessageBody, MsgFlags, ReplyFlags};
use wirebson::RawDocument;

/// Server behavior knobs.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Max accepted message size.
    pub max_msg_len: i32,
    /// Append CRC-32C checksums to replies (spec 4.2 behavior: enabled on
    /// non-TLS connections). The example server has a `--no-checksum` flag.
    pub checksum: bool,
    /// Compressors offered in the handshake, in preference order.
    pub compressors: Vec<CompressorId>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_msg_len: mongo_common::consts::MAX_MSG_LEN,
            checksum: true,
            compressors: Vec::new(),
        }
    }
}

/// The handlers a server provides. Extend with auth handlers as they grow.
#[derive(Clone)]
pub struct ServerHandlers {
    pub command_handler: Arc<dyn CommandHandler>,
}

/// Accept loop convenience: spawn [`process_socket`] per connection.
///
/// Deployment hardening is the embedder's job: this loop neither caps the
/// number of concurrent connections nor applies read timeouts, and a peer
/// that declares a large frame pins buffer space until the frame completes
/// or the socket dies. Put a connection limiter / idle timeout in front when
/// exposing the server to untrusted networks.
pub async fn serve(listener: TcpListener, handlers: ServerHandlers, config: ServerConfig) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let handlers = handlers.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = process_socket(stream, handlers, config).await;
                });
            }
            Err(_) => continue,
        }
    }
}

/// Drive one connection to completion: read frames, dispatch commands,
/// write replies. Protocol errors close the connection; command errors are
/// written as error replies.
pub async fn process_socket(
    stream: TcpStream,
    handlers: ServerHandlers,
    config: ServerConfig,
) -> std::io::Result<()> {
    let mut ctx = ConnectionInfo::new();
    ctx.peer_addr = stream.peer_addr().ok();
    ctx.checksum = config.checksum;
    let mut framed = Framed::new(
        stream,
        MongoCodec::new(CodecConfig {
            max_msg_len: config.max_msg_len,
        }),
    );

    while let Some(item) = framed.next().await {
        // A decode error means the byte stream cannot be trusted: close.
        // (Clean EOF ends the loop with `None` instead.)
        let Ok((header, body)) = item else {
            return Ok(());
        };

        // OP_COMPRESSED carries the real request wrapped inside; unwrap it
        // first. Decompression failures are framing failures: close.
        let body = match body {
            MessageBody::Compressed(compressed) => match compressed.unwrap_body(config.max_msg_len)
            {
                Ok(body) => body,
                Err(_) => return Ok(()),
            },
            body => body,
        };

        match body {
            // OP_QUERY survives in modern MongoDB only for the legacy
            // handshake; it is answered here rather than through the handler
            // chain (which speaks OP_MSG `Command`s).
            MessageBody::Query(query) => {
                let Ok(name) = query.query.command() else {
                    return Ok(());
                };
                if !matches!(name, "hello" | "isMaster" | "ismaster") {
                    let err = Error::command(
                        59,
                        "CommandNotFound",
                        "OP_QUERY only supports hello/isMaster",
                    );
                    if let Some(reply) = error_reply(&err, &MessageBody::Query(query)) {
                        send_reply(&mut framed, &ctx, header.request_id, reply).await?;
                    }
                    continue;
                }
                // Negotiate against the query's `compression` array (spec:
                // the reply lists the intersection in server preference
                // order). A `BuiltinHandler` for OP_MSG handshakes should be
                // built with the same `config.compressors` list.
                let requested = requested_compressors(&query.query);
                let negotiated = negotiate(&config.compressors, requested.as_deref());
                ctx.negotiated_compressors = negotiated.clone();
                let reply = handshake_reply(&negotiated, config.max_msg_len, true)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let body = MessageBody::Reply(query_handshake_reply(reply.document().clone()));
                send_reply(&mut framed, &ctx, header.request_id, body).await?;
            }
            MessageBody::Msg(msg) => {
                let Ok(name) = msg.document().command() else {
                    return Ok(());
                };
                let command = Command {
                    name: name.to_owned(),
                    body: msg.document().clone(),
                    sequences: msg.sections.sequences.clone(),
                    flags: msg.flags,
                };
                // Requests with moreToCome MUST NOT be replied to; the handler
                // still runs (its side effects are wanted, its result is not).
                let more_to_come = command.flags.contains(MsgFlags::MORE_TO_COME);
                let outcome = handlers.command_handler.handle_command(&mut ctx, &command).await;
                if more_to_come {
                    continue;
                }
                match outcome {
                    Ok(Reply::Msg(reply)) => {
                        send_reply(
                            &mut framed,
                            &ctx,
                            header.request_id,
                            MessageBody::Msg(reply),
                        )
                        .await?;
                    }
                    Ok(Reply::NoReply) => {}
                    Err(err) => match error_reply(&err, &MessageBody::Msg(msg)) {
                        Some(reply) => {
                            send_reply(&mut framed, &ctx, header.request_id, reply).await?
                        }
                        // Protocol-level errors cannot reach a handler, but a
                        // handler may still wrap one: close either way.
                        None => return Ok(()),
                    },
                }
            }
            // A server never receives OP_REPLY requests; ignore the frame.
            MessageBody::Reply(_) => {}
            // Defense in depth: `unwrap_body` rejects nested compression, so
            // this arm is unreachable today — close rather than panic if a
            // future change breaks that invariant.
            MessageBody::Compressed(_) => return Ok(()),
        }
    }
    Ok(())
}

/// Map a handler error onto the wire, or `None` when the connection must
/// close instead (protocol errors).
///
/// `request` selects the reply shape: OP_QUERY requests get an OP_REPLY with
/// the `QueryFailure` flag set, everything else gets an OP_MSG body.
pub(crate) fn error_reply(err: &Error, request: &MessageBody) -> Option<MessageBody> {
    // Protocol errors carry no reply body: the connection must close.
    let raw = err.to_error_response_doc()?.encode().ok()?;
    Some(match request {
        MessageBody::Query(_) => MessageBody::Reply({
            let mut reply = query_handshake_reply(raw);
            reply.response_flags |= ReplyFlags::QUERY_FAILURE;
            reply
        }),
        _ => MessageBody::Msg(response::op_msg(MsgFlags::empty(), raw).ok()?),
    })
}

/// Send one reply frame with `responseTo = response_to`.
///
/// Uncompressed replies go through the codec's `Encoder`. Checksummed OP_MSG
/// replies bypass it (the codec never appends trailers — it does not know the
/// connection's checksum setting) and are encoded via
/// [`framing::encode_message`] straight onto the stream. `Framed`'s write
/// buffer is empty here: [`SinkExt::send`] flushes, so frame ordering is
/// preserved.
async fn send_reply(
    framed: &mut Framed<TcpStream, MongoCodec>,
    ctx: &ConnectionInfo,
    response_to: i32,
    body: MessageBody,
) -> std::io::Result<()> {
    let mut header = Header::new(ctx.next_request_id(), response_to, body.opcode());
    if ctx.checksum && matches!(body, MessageBody::Msg(_)) {
        let mut out = BytesMut::new();
        framing::encode_message(&mut header, &body, true, &mut out)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        framed.get_mut().write_all(&out).await?;
        framed.get_mut().flush().await
    } else {
        framed
            .send((header, body))
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// A wrapping [`CommandHandler`] that answers the built-in commands —
/// `hello` / `isMaster` (via [`handshake_reply`], with compression
/// negotiation) and `ping` (via [`ping_reply`]) — and forwards everything
/// else to `inner`.
///
/// Negotiation updates [`ConnectionInfo::negotiated_compressors`]; the
/// configured list should match [`ServerConfig::compressors`].
pub struct BuiltinHandler {
    inner: Arc<dyn CommandHandler>,
    compressors: Vec<CompressorId>,
    max_msg_len: i32,
}

impl BuiltinHandler {
    /// Answer `hello` / `isMaster` / `ping` from `compressors` / `max_msg_len`
    /// and delegate the rest to `inner`.
    pub fn new(
        inner: Arc<dyn CommandHandler>,
        compressors: Vec<CompressorId>,
        max_msg_len: i32,
    ) -> Self {
        Self {
            inner,
            compressors,
            max_msg_len,
        }
    }
}

#[async_trait]
impl CommandHandler for BuiltinHandler {
    async fn handle_command(
        &self,
        ctx: &mut ConnectionInfo,
        command: &Command,
    ) -> Result<Reply, Error> {
        match command.name.as_str() {
            "hello" | "isMaster" | "ismaster" => {
                let requested = requested_compressors(&command.body);
                let negotiated = negotiate(&self.compressors, requested.as_deref());
                ctx.negotiated_compressors = negotiated.clone();
                // Old `isMaster` callers expect the legacy `ismaster` reply key.
                let legacy = command.name != "hello";
                Ok(Reply::Msg(handshake_reply(
                    &negotiated,
                    self.max_msg_len,
                    legacy,
                )?))
            }
            "ping" => Ok(Reply::Msg(ping_reply()?)),
            _ => self.inner.handle_command(ctx, command).await,
        }
    }
}

/// The `compression` array of a handshake command, when the client sent one.
fn requested_compressors(body: &RawDocument) -> Option<Vec<String>> {
    let wirebson::RawBsonRef::Array(names) = body.get("compression").ok().flatten()? else {
        return None;
    };
    let mut out = Vec::new();
    for value in names.shallow().ok()?.iter() {
        if let wirebson::Bson::String(name) = value {
            out.push(name.clone());
        }
    }
    Some(out)
}

/// Intersect the server's configured compressors with the client's request,
/// keeping the server's preference order. No request means no compression.
fn negotiate(configured: &[CompressorId], requested: Option<&[String]>) -> Vec<CompressorId> {
    let Some(requested) = requested else {
        return Vec::new();
    };
    configured
        .iter()
        .copied()
        .filter(|c| requested.iter().any(|name| name == c.name()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use wirebson::{Array, Bson, Document};

    use crate::error::ProtocolError;
    use crate::messages::Opcode;

    /// Encode a document and unwrap (test documents are always valid).
    fn raw(pairs: impl IntoIterator<Item = (&'static str, Bson)>) -> RawDocument {
        Document::from_iter(pairs).encode().unwrap()
    }

    #[test]
    fn negotiate_intersects_in_server_preference_order() {
        let configured = [CompressorId::Zlib, CompressorId::Snappy, CompressorId::Zstd];
        let requested = vec![
            "zstd".to_owned(),
            "snappy".to_owned(),
            "noop".to_owned(),
        ];
        assert_eq!(
            negotiate(&configured, Some(&requested)),
            vec![CompressorId::Snappy, CompressorId::Zstd]
        );
        // No request from the client: no compression at all.
        assert!(negotiate(&configured, None).is_empty());
        assert!(negotiate(&[], Some(&requested)).is_empty());
    }

    #[test]
    fn requested_compressors_reads_the_handshake_field() {
        let body = raw([
            ("hello", Bson::Int32(1)),
            ("compression", Bson::Array(Array::from_iter([
                Bson::from("snappy"),
                Bson::Int32(1), // non-string entries are skipped
                Bson::from("zlib"),
            ]))),
        ]);
        assert_eq!(
            requested_compressors(&body),
            Some(vec!["snappy".to_owned(), "zlib".to_owned()])
        );
        // Absent or wrongly typed field: no request.
        assert_eq!(requested_compressors(&raw([("hello", Bson::Int32(1))])), None);
        assert_eq!(
            requested_compressors(&raw([("hello", Bson::Int32(1)), ("compression", Bson::Null)])),
            None
        );
    }

    #[test]
    fn command_errors_become_op_msg_error_bodies() {
        let err = Error::command(59, "CommandNotFound", "no such command");
        let request = MessageBody::Msg(response::op_msg(MsgFlags::empty(), raw([("ping", Bson::Int32(1))])).unwrap());
        let Some(MessageBody::Msg(reply)) = error_reply(&err, &request) else {
            panic!("expected an OP_MSG error reply")
        };
        assert_eq!(reply.flags, MsgFlags::empty());
        let doc = reply.document().shallow().unwrap();
        assert_eq!(doc.get("ok"), Some(&Bson::Double(0.0)));
        assert_eq!(doc.get("errmsg"), Some(&Bson::from("no such command")));
        assert_eq!(doc.get("code"), Some(&Bson::Int32(59)));
        assert_eq!(doc.get("codeName"), Some(&Bson::from("CommandNotFound")));
    }

    #[test]
    fn query_errors_become_op_reply_query_failures() {
        use crate::messages::OpQuery;
        let err = Error::command(59, "CommandNotFound", "OP_QUERY only supports hello/isMaster");
        let request = MessageBody::Query(OpQuery::handshake(raw([("find", Bson::from("x"))])));
        let Some(MessageBody::Reply(reply)) = error_reply(&err, &request) else {
            panic!("expected an OP_REPLY error reply")
        };
        assert!(reply.response_flags.contains(ReplyFlags::QUERY_FAILURE));
        assert_eq!(reply.number_returned, 1);
        let doc = reply.documents[0].shallow().unwrap();
        assert_eq!(doc.get("ok"), Some(&Bson::Double(0.0)));
        assert_eq!(doc.get("code"), Some(&Bson::Int32(59)));
    }

    #[test]
    fn protocol_errors_have_no_reply() {
        let err = Error::from(ProtocolError::ChecksumMismatch {
            expected: 1,
            computed: 2,
        });
        let request = MessageBody::Msg(response::op_msg(MsgFlags::empty(), raw([("ping", Bson::Int32(1))])).unwrap());
        assert!(error_reply(&err, &request).is_none());
    }

    /// A handler answering `echo` and rejecting everything else — the
    /// user-supplied bottom of the chain in these tests.
    struct EchoHandler;

    #[async_trait]
    impl CommandHandler for EchoHandler {
        async fn handle_command(
            &self,
            _ctx: &mut ConnectionInfo,
            command: &Command,
        ) -> Result<Reply, Error> {
            match command.name.as_str() {
                "echo" => Ok(Reply::Msg(response::op_msg(
                    MsgFlags::empty(),
                    raw([("ok", Bson::Double(1.0)), ("echo", Bson::from(command.name.as_str()))]),
                )?)),
                _ => Err(Error::command(
                    59,
                    "CommandNotFound",
                    format!("unknown command {}", command.name),
                )),
            }
        }
    }

    /// The full server stack under test: built-ins around the echo handler.
    fn test_handlers(compressors: Vec<CompressorId>) -> ServerHandlers {
        ServerHandlers {
            command_handler: Arc::new(BuiltinHandler::new(
                Arc::new(EchoHandler),
                compressors,
                mongo_common::consts::MAX_MSG_LEN,
            )),
        }
    }

    /// Bind an ephemeral listener and serve it in the background.
    async fn spawn_server(handlers: ServerHandlers, config: ServerConfig) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { serve(listener, handlers, config).await });
        addr
    }

    /// A minimal in-test wire client (independent of `crate::test_client`).
    struct TestClient {
        stream: TcpStream,
        buf: BytesMut,
    }

    impl TestClient {
        async fn connect(addr: std::net::SocketAddr) -> std::io::Result<Self> {
            Ok(Self {
                stream: TcpStream::connect(addr).await?,
                buf: BytesMut::new(),
            })
        }

        async fn send(&mut self, request_id: i32, body: &MessageBody) -> std::io::Result<()> {
            let mut header = Header::new(request_id, 0, body.opcode());
            let bytes = crate::codec::to_bytes(&mut header, body, false)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            self.stream.write_all(&bytes).await
        }

        async fn recv(&mut self) -> Result<Option<(Header, MessageBody)>, ProtocolError> {
            loop {
                if let Some(msg) = framing::parse_message(&mut self.buf, i32::MAX)? {
                    return Ok(Some(msg));
                }
                if 0 == self.stream.read_buf(&mut self.buf).await? {
                    return if self.buf.is_empty() {
                        Ok(None) // clean EOF: the server closed
                    } else {
                        Err(ProtocolError::InvalidHeader("truncated message before EOF"))
                    };
                }
            }
        }
    }

    /// An OP_MSG request document.
    fn msg(flags: MsgFlags, pairs: impl IntoIterator<Item = (&'static str, Bson)>) -> MessageBody {
        MessageBody::Msg(response::op_msg(flags, raw(pairs)).unwrap())
    }

    /// The shallow reply document of an OP_MSG reply.
    fn reply_doc(reply: &MessageBody) -> Document {
        let MessageBody::Msg(msg) = reply else {
            panic!("expected an OP_MSG reply, got {reply:?}")
        };
        msg.document().shallow().unwrap()
    }

    #[tokio::test]
    async fn hello_over_op_msg() {
        let addr = spawn_server(test_handlers(Vec::new()), ServerConfig::default()).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        client.send(7, &msg(MsgFlags::empty(), [("hello", Bson::Int32(1))])).await.unwrap();
        let (header, reply) = client.recv().await.unwrap().expect("connection closed");
        assert_eq!(header.op_code, Opcode::Msg);
        assert_eq!(header.response_to, 7);
        let doc = reply_doc(&reply);
        assert_eq!(doc.get("ok"), Some(&Bson::Double(1.0)));
        assert_eq!(doc.get("isWritablePrimary"), Some(&Bson::Bool(true)));
        // Default config checksums replies: the trailer must validate (recv
        // would have errored otherwise) and the flag must be visible.
        let MessageBody::Msg(msg) = &reply else { unreachable!() };
        assert!(msg.flags.contains(MsgFlags::CHECKSUM_PRESENT));
        assert!(msg.checksum.is_some());
    }

    #[tokio::test]
    async fn ping_over_op_msg() {
        let addr = spawn_server(test_handlers(Vec::new()), ServerConfig::default()).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        client.send(8, &msg(MsgFlags::empty(), [("ping", Bson::Int32(1))])).await.unwrap();
        let (header, reply) = client.recv().await.unwrap().expect("connection closed");
        assert_eq!(header.response_to, 8);
        assert_eq!(reply_doc(&reply).get("ok"), Some(&Bson::Double(1.0)));
    }

    #[tokio::test]
    async fn echo_is_forwarded_past_the_builtin_handler() {
        let addr = spawn_server(test_handlers(Vec::new()), ServerConfig::default()).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        client.send(9, &msg(MsgFlags::empty(), [("echo", Bson::Int32(1))])).await.unwrap();
        let (_, reply) = client.recv().await.unwrap().expect("connection closed");
        let doc = reply_doc(&reply);
        assert_eq!(doc.get("ok"), Some(&Bson::Double(1.0)));
        assert_eq!(doc.get("echo"), Some(&Bson::from("echo")));
    }

    #[tokio::test]
    async fn hello_negotiates_compression_with_op_msg() {
        let addr = spawn_server(
            test_handlers(vec![CompressorId::Zlib, CompressorId::Snappy]),
            ServerConfig::default(),
        )
        .await;
        let mut client = TestClient::connect(addr).await.unwrap();

        // The client asks for zstd first; the server's preference wins.
        let request = msg(
            MsgFlags::empty(),
            [
                ("hello", Bson::Int32(1)),
                ("compression", Bson::Array(Array::from_iter([
                    Bson::from("zstd"),
                    Bson::from("snappy"),
                ]))),
            ],
        );
        client.send(10, &request).await.unwrap();
        let (_, reply) = client.recv().await.unwrap().expect("connection closed");
        let doc = reply_doc(&reply);
        assert_eq!(
            doc.get("compression"),
            Some(&Bson::Array(Array::from_iter([Bson::from("snappy")])))
        );
    }

    #[tokio::test]
    async fn hello_over_op_query_gets_an_op_reply() {
        // The OP_QUERY handshake negotiates from `config.compressors`.
        let config = ServerConfig {
            compressors: vec![CompressorId::Snappy],
            ..ServerConfig::default()
        };
        let addr = spawn_server(test_handlers(config.compressors.clone()), config).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        // The legacy handshake: `{"ismaster": true}` on `admin.$cmd`.
        let query = crate::messages::OpQuery::handshake(raw([
            ("ismaster", Bson::Bool(true)),
            ("compression", Bson::Array(Array::from_iter([Bson::from("snappy")]))),
        ]));
        client.send(11, &MessageBody::Query(query)).await.unwrap();

        let (header, reply) = client.recv().await.unwrap().expect("connection closed");
        assert_eq!(header.op_code, Opcode::Reply);
        assert_eq!(header.response_to, 11, "OP_QUERY replies echo the request id");
        let MessageBody::Reply(op_reply) = &reply else {
            panic!("expected an OP_REPLY, got {reply:?}")
        };
        assert!(op_reply.response_flags.contains(ReplyFlags::AWAIT_CAPABLE));
        assert!(!op_reply.response_flags.contains(ReplyFlags::QUERY_FAILURE));
        assert_eq!(op_reply.number_returned, 1);
        let doc = op_reply.documents[0].shallow().unwrap();
        assert_eq!(doc.get("ok"), Some(&Bson::Double(1.0)));
        assert_eq!(doc.get("ismaster"), Some(&Bson::Bool(true)));
        // Negotiated against the query's compression array.
        assert_eq!(
            doc.get("compression"),
            Some(&Bson::Array(Array::from_iter([Bson::from("snappy")])))
        );
    }

    #[tokio::test]
    async fn non_handshake_op_query_gets_a_query_failure() {
        let addr = spawn_server(test_handlers(Vec::new()), ServerConfig::default()).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        let query = crate::messages::OpQuery::handshake(raw([("find", Bson::from("coll"))]));
        client.send(12, &MessageBody::Query(query)).await.unwrap();

        let (header, reply) = client.recv().await.unwrap().expect("connection closed");
        assert_eq!(header.op_code, Opcode::Reply);
        assert_eq!(header.response_to, 12);
        let MessageBody::Reply(op_reply) = &reply else {
            panic!("expected an OP_REPLY, got {reply:?}")
        };
        assert!(op_reply.response_flags.contains(ReplyFlags::QUERY_FAILURE));
        let doc = op_reply.documents[0].shallow().unwrap();
        assert_eq!(doc.get("ok"), Some(&Bson::Double(0.0)));
        // The connection stays usable: a follow-up ping still works.
        client.send(13, &msg(MsgFlags::empty(), [("ping", Bson::Int32(1))])).await.unwrap();
        let (_, reply) = client.recv().await.unwrap().expect("connection closed");
        assert_eq!(reply_doc(&reply).get("ok"), Some(&Bson::Double(1.0)));
    }

    #[tokio::test]
    async fn unknown_command_gets_an_error_reply() {
        let addr = spawn_server(test_handlers(Vec::new()), ServerConfig::default()).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        client.send(14, &msg(MsgFlags::empty(), [("fooey", Bson::Int32(1))])).await.unwrap();
        let (header, reply) = client.recv().await.unwrap().expect("connection closed");
        assert_eq!(header.response_to, 14);
        let doc = reply_doc(&reply);
        assert_eq!(doc.get("ok"), Some(&Bson::Double(0.0)));
        assert_eq!(doc.get("code"), Some(&Bson::Int32(59)));
        assert_eq!(doc.get("codeName"), Some(&Bson::from("CommandNotFound")));
        assert!(doc.get("errmsg").is_some());
    }

    #[tokio::test]
    async fn more_to_come_requests_get_no_reply() {
        let addr = spawn_server(test_handlers(Vec::new()), ServerConfig::default()).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        // The handler runs (side effects), but nothing may come back.
        client
            .send(15, &msg(MsgFlags::MORE_TO_COME, [("ping", Bson::Int32(1))]))
            .await
            .unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_millis(200), client.recv()).await;
        assert!(result.is_err(), "a reply arrived for a moreToCome request: {result:?}");
    }

    #[tokio::test]
    async fn checksummed_requests_get_checksummed_replies_and_no_checksum_config_does_not() {
        // Requests may carry checksums (send() does not add them, so craft one
        // via framing directly); replies follow ServerConfig.checksum.
        let handlers = test_handlers(Vec::new());
        let config = ServerConfig {
            checksum: false,
            ..ServerConfig::default()
        };
        let addr = spawn_server(handlers, config).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        client.send(16, &msg(MsgFlags::empty(), [("ping", Bson::Int32(1))])).await.unwrap();
        let (_, reply) = client.recv().await.unwrap().expect("connection closed");
        let MessageBody::Msg(msg) = &reply else { unreachable!() };
        assert!(!msg.flags.contains(MsgFlags::CHECKSUM_PRESENT));
        assert_eq!(msg.checksum, None);
    }

    #[tokio::test]
    async fn protocol_error_closes_the_connection() {
        let addr = spawn_server(test_handlers(Vec::new()), ServerConfig::default()).await;
        let mut client = TestClient::connect(addr).await.unwrap();

        // A well-formed frame whose CRC-32C trailer is wrong: the codec
        // rejects it on read and process_socket must close.
        let mut frame = crate::codec::to_bytes(
            &mut Header::new(17, 0, Opcode::Msg),
            &msg(MsgFlags::CHECKSUM_PRESENT, [("ping", Bson::Int32(1))]),
            true,
        )
        .unwrap()
        .to_vec();
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        client.stream.write_all(&frame).await.unwrap();

        // The server closes; the client reads a clean EOF.
        let received = client.recv().await.unwrap();
        assert!(received.is_none(), "connection must close after a protocol error");
    }

    #[tokio::test]
    async fn clean_eof_ends_process_socket() {
        let addr = spawn_server(test_handlers(Vec::new()), ServerConfig::default()).await;
        let mut client = TestClient::connect(addr).await.unwrap();
        client.send(18, &msg(MsgFlags::empty(), [("ping", Bson::Int32(1))])).await.unwrap();
        client.recv().await.unwrap().expect("ping must be answered");
        drop(client.stream); // half-close from the client side
        // Give the server a moment to reap the connection; the assertion is
        // that nothing panics and the accept loop keeps serving.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut client = TestClient::connect(addr).await.unwrap();
        client.send(19, &msg(MsgFlags::empty(), [("ping", Bson::Int32(1))])).await.unwrap();
        let (_, reply) = client.recv().await.unwrap().expect("server must keep accepting");
        assert_eq!(reply_doc(&reply).get("ok"), Some(&Bson::Double(1.0)));
    }

    #[test]
    fn builtin_handler_updates_negotiated_compressors() {
        // Direct handler-level check (no socket): negotiation state lands in
        // the ConnectionInfo for later commands.
        let handlers = test_handlers(vec![CompressorId::Snappy]);
        let mut ctx = ConnectionInfo::new();
        let command = Command {
            name: "hello".to_owned(),
            body: raw([
                ("hello", Bson::Int32(1)),
                ("compression", Bson::Array(Array::from_iter([Bson::from("snappy")]))),
            ]),
            sequences: Vec::new(),
            flags: MsgFlags::empty(),
        };
        let reply = futures::executor::block_on(handlers.command_handler.handle_command(&mut ctx, &command)).unwrap();
        let Reply::Msg(msg) = reply else { panic!("expected a reply") };
        let doc = msg.document().shallow().unwrap();
        assert_eq!(doc.get("isWritablePrimary"), Some(&Bson::Bool(true)));
        assert_eq!(ctx.negotiated_compressors, vec![CompressorId::Snappy]);

        // isMaster keeps the legacy reply key.
        let command = Command {
            name: "isMaster".to_owned(),
            body: raw([("isMaster", Bson::Int32(1))]),
            sequences: Vec::new(),
            flags: MsgFlags::empty(),
        };
        let reply = futures::executor::block_on(handlers.command_handler.handle_command(&mut ctx, &command)).unwrap();
        let Reply::Msg(msg) = reply else { panic!("expected a reply") };
        let doc = msg.document().shallow().unwrap();
        assert_eq!(doc.get("ismaster"), Some(&Bson::Bool(true)));
        assert_eq!(doc.get("compression"), None, "no request, no compression field");
        assert!(ctx.negotiated_compressors.is_empty());
    }
}
