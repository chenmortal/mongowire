//! Handler traits — the user-facing embedding API (pgwire analog).

use async_trait::async_trait;

use crate::api::client_info::ConnectionInfo;
use crate::error::Error;
use crate::messages::{DocumentSequence, MsgFlags, OpMsg};
use wirebson::RawDocument;

/// One incoming command, decoded from an OP_MSG.
///
/// Document sequences are surfaced separately; merging them into the body as
/// an array is the handler's decision (spec: "Parsers MAY choose to merge").
#[derive(Debug, Clone)]
pub struct Command {
    /// First body field name (the command), e.g. `"hello"`, `"ping"`, `"find"`.
    pub name: String,
    /// The kind-0 body document, raw.
    pub body: RawDocument,
    /// Kind-1 sections in order.
    pub sequences: Vec<DocumentSequence>,
    /// Request flag bits (e.g. `moreToCome`).
    pub flags: MsgFlags,
}

/// What a handler wants done after processing a command.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Send this message back (with `responseTo` set by the server layer).
    Msg(OpMsg),
    /// Send nothing (e.g. the request had `moreToCome` set).
    NoReply,
}

/// The one handler a MongoDB server needs: command in, reply out.
///
/// Handshake commands (`hello`, `isMaster`, `ping`, `saslStart`, …) arrive
/// here like any other command; see [`crate::api::response`] for ready-made
/// handshake replies.
#[async_trait]
pub trait CommandHandler: Send + Sync + 'static {
    /// # Errors
    /// The error is converted to a wire error reply via
    /// [`crate::Error::to_error_response_doc`].
    async fn handle_command(
        &self,
        ctx: &mut ConnectionInfo,
        command: &Command,
    ) -> Result<Reply, Error>;
}
