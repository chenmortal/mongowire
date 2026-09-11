#![cfg(feature = "server")]
//! End-to-end integration: an in-process server on real sockets, driven by
//! the in-crate [`TestClient`].
//!
//! The inline [`MiniHandler`] keeps the suite self-contained: it depends only
//! on the frozen `api` contract (the [`CommandHandler`] trait plus the
//! `response` reply builders), so these tests exercise exactly what
//! `api::process_socket` does with wire-level requests — OP_MSG dispatch,
//! legacy OP_QUERY handshakes, CRC-32C checksums, OP_COMPRESSED ingress and
//! command-error replies.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use mongo_common::consts::MAX_MSG_LEN;
use tokio::net::TcpListener;
use wirebson::{Bson, Document, RawBsonRef, RawDocument};

use mongowire::api::response::{handshake_reply, op_msg, ping_reply};
use mongowire::api::{
    serve, Command, CommandHandler, ConnectionInfo, Reply, ServerConfig, ServerHandlers,
};
use mongowire::compression::CompressorId;
use mongowire::messages::{MsgFlags, Opcode, OpCompressed, OpMsg};
use mongowire::test_client::TestClient;
use mongowire::{Error, Message, MessageBody};

/// Minimal self-contained handler: `hello` / `isMaster` / `ping` / `echo`,
/// everything else a `CommandNotFound` error.
struct MiniHandler;

#[async_trait]
impl CommandHandler for MiniHandler {
    async fn handle_command(
        &self,
        _ctx: &mut ConnectionInfo,
        command: &Command,
    ) -> Result<Reply, Error> {
        match command.name.as_str() {
            "hello" => Ok(Reply::Msg(handshake_reply(&[], MAX_MSG_LEN, false)?)),
            "isMaster" | "ismaster" => {
                Ok(Reply::Msg(handshake_reply(&[], MAX_MSG_LEN, true)?))
            }
            "ping" => Ok(Reply::Msg(ping_reply()?)),
            // Echo the raw body document straight back.
            "echo" => Ok(Reply::Msg(op_msg(MsgFlags::empty(), command.body.clone())?)),
            other => Err(Error::command(
                59,
                "CommandNotFound",
                format!("no such command: {other}"),
            )),
        }
    }
}

/// Bind an ephemeral port and accept on it in the background.
async fn spawn_server(config: ServerConfig) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        ServerHandlers { command_handler: Arc::new(MiniHandler) },
        config,
    ));
    addr
}

/// Connect to a freshly spawned server.
async fn connect(addr: std::net::SocketAddr) -> TestClient {
    TestClient::connect(addr.to_string().as_str()).await.unwrap()
}

/// Encode a document and unwrap (test documents are always valid).
fn raw(pairs: impl IntoIterator<Item = (&'static str, Bson)>) -> RawDocument {
    Document::from_iter(pairs).encode().unwrap()
}

/// An OP_MSG request `{<name>: 1}` with no flags.
fn request_msg(name: &'static str) -> OpMsg {
    OpMsg::new(MsgFlags::empty(), raw([(name, Bson::Int32(1))]), Vec::new()).unwrap()
}

/// Reduce a reply body to its OP_MSG, unwrapping one OP_COMPRESSED layer if
/// the server chose to compress the response.
fn as_op_msg(body: MessageBody) -> OpMsg {
    match body {
        MessageBody::Msg(msg) => msg,
        MessageBody::Compressed(c) => match c.unwrap_body(MAX_MSG_LEN).expect("reply decompresses") {
            MessageBody::Msg(msg) => msg,
            body => panic!("expected a compressed OP_MSG, got {body:?}"),
        },
        body => panic!("expected an OP_MSG reply, got {body:?}"),
    }
}

/// The `ok` field of a reply document; panics unless it is a double.
fn ok_of(doc: &RawDocument) -> f64 {
    match doc.get("ok") {
        Ok(Some(RawBsonRef::Double(ok))) => ok,
        other => panic!("reply has no double `ok` field: {other:?} in {doc}"),
    }
}

#[tokio::test]
async fn op_msg_ping_roundtrip() {
    let mut client = connect(spawn_server(ServerConfig::default()).await).await;

    const REQUEST_ID: i32 = 7;
    client
        .send(REQUEST_ID, 0, &MessageBody::Msg(request_msg("ping")))
        .await
        .unwrap();
    let (header, body) = client.recv().await.unwrap().expect("server closed the connection");
    assert_eq!(header.response_to, REQUEST_ID, "the reply must echo the request id");

    let reply = as_op_msg(body);
    assert_eq!(ok_of(reply.document()), 1.0);
}

#[tokio::test]
async fn op_query_handshake_gets_op_reply() {
    let mut client = connect(spawn_server(ServerConfig::default()).await).await;

    let request_id = client
        .send_op_query_handshake(raw([("isMaster", Bson::Int32(1))]))
        .await
        .unwrap();
    let (header, reply) = client.recv_op_reply().await.unwrap();
    assert_eq!(header.response_to, request_id, "the reply must echo the request id");
    assert_eq!(reply.number_returned, 1);

    let doc = &reply.documents[0];
    assert_eq!(ok_of(doc), 1.0);
    // The legacy handshake reply carries the legacy boolean `ismaster: true`
    // (real mongod's key style for OP_QUERY handshakes) plus `helloOk`.
    assert_eq!(
        doc.get("ismaster").unwrap(),
        Some(RawBsonRef::Bool(true)),
        "legacy key missing or wrong: {doc}"
    );
    assert!(matches!(doc.get("helloOk"), Ok(Some(_))), "helloOk missing: {doc}");
}

#[tokio::test]
async fn checksummed_ping_roundtrip() {
    let mut client = connect(spawn_server(ServerConfig::default()).await).await;

    // The request carries a valid CRC-32C trailer (`checksumPresent`); the
    // server must validate it and answer normally.
    const REQUEST_ID: i32 = 11;
    client
        .send_with_checksum(REQUEST_ID, 0, &MessageBody::Msg(request_msg("ping")))
        .await
        .unwrap();
    let (header, body) = client.recv().await.unwrap().expect("server closed the connection");
    assert_eq!(header.response_to, REQUEST_ID);

    let reply = as_op_msg(body);
    assert_eq!(ok_of(reply.document()), 1.0);
}

#[tokio::test]
async fn op_compressed_noop_ping_roundtrip() {
    let mut client = connect(spawn_server(ServerConfig::default()).await).await;

    let mut body = BytesMut::new();
    request_msg("ping").encode_body(&mut body);
    let compressed =
        OpCompressed::wrap(Opcode::Msg, body.freeze(), CompressorId::Noop).expect("noop wraps");
    let (_header, reply) = client.request(&MessageBody::Compressed(compressed)).await.unwrap();

    assert_eq!(ok_of(as_op_msg(reply).document()), 1.0);
}

#[tokio::test]
async fn echo_roundtrip() {
    let mut client = connect(spawn_server(ServerConfig::default()).await).await;

    let body = raw([("echo", Bson::from("hi")), ("$db", Bson::from("admin"))]);
    let msg = OpMsg::new(MsgFlags::empty(), body.clone(), Vec::new()).unwrap();
    let (_header, reply) = client.request(&MessageBody::Msg(msg)).await.unwrap();
    assert_eq!(as_op_msg(reply).document(), &body);
}

#[tokio::test]
async fn unknown_command_yields_error_reply_and_lives_on() {
    let mut client = connect(spawn_server(ServerConfig::default()).await).await;

    let (_header, reply) = client
        .request(&MessageBody::Msg(request_msg("definitelyNotACommand")))
        .await
        .unwrap();
    let msg = as_op_msg(reply);
    let doc = msg.document();
    assert_eq!(doc.get("ok").unwrap(), Some(RawBsonRef::Double(0.0)));
    assert!(matches!(doc.get("errmsg"), Ok(Some(RawBsonRef::String(_)))), "no errmsg in {doc}");

    // Command errors are written as error replies; the connection stays
    // usable afterwards (only protocol errors close it).
    let (_header, reply) = client.request(&MessageBody::Msg(request_msg("ping"))).await.unwrap();
    assert_eq!(ok_of(as_op_msg(reply).document()), 1.0);
}
