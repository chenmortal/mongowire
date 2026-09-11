//! Example MongoDB-wire server.
//!
//! Answers `hello` / `isMaster` (both OP_MSG and legacy OP_QUERY), `ping`,
//! `buildInfo`, and a trivial `find` on the `demo` collection; every other
//! command is answered with a `CommandNotFound` error reply. Prints decoded
//! commands via wirebson's log formatting. Usage:
//!
//! ```text
//! mongowire-server [--bind 127.0.0.1:27017] [--no-checksum]
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use mongo_common::bson::ObjectId;
use wirebson::{Array, Bson, Document};

use mongowire::api::response::{handshake_reply, op_msg, ping_reply};
use mongowire::api::{Command, CommandHandler, ConnectionInfo, Reply, ServerConfig, ServerHandlers};
use mongowire::messages::MsgFlags;
use mongowire::Error;

/// The one document the demo `find` serves.
const GREETING: &str = "hello from mongowire";

/// The application-level command handler of the example server.
///
/// Handshake and ping are answered with the built-in
/// [`mongowire::api::response`] builders; everything else is demo logic.
struct DemoHandler {
    /// Copied out of [`ServerConfig`]: the handshake reply reports the limit,
    /// and this handler is the only place that builds one.
    max_msg_len: i32,
}

impl DemoHandler {
    /// Dispatch one decoded command. Sync on purpose: nothing here awaits,
    /// the trait impl below just boxes the call.
    fn handle(&self, command: &Command) -> Result<Reply, Error> {
        // Log formatting via wirebson's `Display` (`log_document` shape).
        eprintln!("[conn] {} {}", command.name, command.body);
        match command.name.as_str() {
            "hello" => Ok(Reply::Msg(handshake_reply(&[], self.max_msg_len, false)?)),
            "isMaster" | "ismaster" => {
                Ok(Reply::Msg(handshake_reply(&[], self.max_msg_len, true)?))
            }
            "ping" => Ok(Reply::Msg(ping_reply()?)),
            "buildInfo" => {
                let mut doc = Document::new();
                doc.add("version", "7.0.0-mongowire");
                doc.add("gitVersion", "demo");
                doc.add("ok", 1.0);
                Ok(Reply::Msg(op_msg(MsgFlags::empty(), doc.encode().map_err(bson_error)?)?))
            }
            "find" => self.find(command),
            other => Err(Error::command(
                59,
                "CommandNotFound",
                format!("no such command: {other}"),
            )),
        }
    }

    /// The `find` handler: one fake document for collection `demo`.
    fn find(&self, command: &Command) -> Result<Reply, Error> {
        let collection = match command.body.get("find").map_err(bson_error)? {
            Some(wirebson::RawBsonRef::String(name)) => name,
            Some(_) => {
                return Err(Error::command(
                    73,
                    "TypeMismatch",
                    "find: the collection name must be a string",
                ));
            }
            None => {
                return Err(Error::command(
                    40414,
                    "Location40414",
                    "find: missing collection name",
                ));
            }
        };
        if collection != "demo" {
            return Err(Error::command(
                26,
                "NamespaceNotFound",
                format!("no such collection: demo.{collection}"),
            ));
        }

        let mut first = Document::new();
        first.add("_id", Bson::ObjectId(ObjectId::new()));
        first.add("greeting", GREETING);
        let cursor = Document::from_iter([
            ("id", Bson::Int64(0)),
            ("ns", Bson::from("demo.demo")),
            ("firstBatch", Bson::Array(Array::from_iter([Bson::Document(first)]))),
        ]);
        let reply = Document::from_iter([
            ("cursor", Bson::Document(cursor)),
            ("ok", Bson::Double(1.0)),
        ]);
        Ok(Reply::Msg(op_msg(MsgFlags::empty(), reply.encode().map_err(bson_error)?)?))
    }
}

/// Lift a BSON encoding failure into the crate error type (protocol tier:
/// the server layer closes the connection instead of replying).
fn bson_error(e: wirebson::Error) -> Error {
    Error::Protocol(e.into())
}

/// The `#[async_trait]` desugaring, written out by hand so the example needs
/// no extra dependency: box the per-command future and dispatch.
impl CommandHandler for DemoHandler {
    fn handle_command<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        _ctx: &'life1 mut ConnectionInfo,
        command: &'life2 Command,
    ) -> Pin<Box<dyn Future<Output = Result<Reply, Error>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.handle(command) })
    }
}

/// Print the usage line and exit.
fn usage() -> ! {
    eprintln!("usage: mongowire-server [--bind <ip:port>] [--no-checksum]");
    std::process::exit(2);
}

/// `--bind <ip:port>` (default `127.0.0.1:27017`) and `--no-checksum`.
fn parse_args() -> (String, bool) {
    let mut bind = String::from("127.0.0.1:27017");
    let mut checksum = true;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => bind = args.next().unwrap_or_else(|| usage()),
            "--no-checksum" => checksum = false,
            _ => usage(),
        }
    }
    (bind, checksum)
}

#[tokio::main]
async fn main() {
    let (bind, checksum) = parse_args();
    let config = ServerConfig { checksum, ..ServerConfig::default() };

    let listener = tokio::net::TcpListener::bind(bind.as_str())
        .await
        .unwrap_or_else(|e| {
            eprintln!("mongowire-server: cannot bind {bind}: {e}");
            std::process::exit(1);
        });
    println!("listening on {bind}");

    let handlers = ServerHandlers {
        command_handler: Arc::new(DemoHandler { max_msg_len: config.max_msg_len }),
    };
    mongowire::api::serve(listener, handlers, config).await;
}
