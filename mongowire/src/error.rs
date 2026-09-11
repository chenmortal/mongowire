//! Error model, in two tiers:
//!
//! 1. [`ProtocolError`] — the byte stream is malformed. The connection cannot
//!    be recovered safely and MUST be closed.
//! 2. [`Error::Command`] — a handler-level failure. It is serialized back to
//!    the client as an OP_MSG body `{ok: 0.0, errmsg, code, codeName, $db}`.

/// Malformed-protocol errors: close the connection.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid message header: {0}")]
    InvalidHeader(&'static str),

    #[error("message too large: {size} > {max}")]
    MessageTooLarge { size: i32, max: i32 },

    #[error("unsupported opcode: {0}")]
    UnsupportedOpcode(i32),

    #[error("invalid OP_MSG: {0}")]
    InvalidOpMsg(&'static str),

    #[error("invalid message body: {0}")]
    InvalidBody(&'static str),

    #[error("checksum mismatch: expected {expected:#010x}, computed {computed:#010x}")]
    ChecksumMismatch { expected: u32, computed: u32 },

    #[error("unsupported compressor id: {0}")]
    UnsupportedCompressor(u8),

    #[error("compression failed: {0}")]
    Compression(String),

    #[error("decompressed size mismatch: expected {expected}, got {actual}")]
    DecompressedSizeMismatch { expected: usize, actual: usize },

    #[error(transparent)]
    Bson(#[from] wirebson::Error),

    #[error(transparent)]
    Scalar(#[from] mongo_common::bson::ScalarError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Crate error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The byte stream is unusable; the caller must close the connection.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// A command-level failure, reported to the client over the wire.
    #[error("command error {code} ({code_name}): {message}")]
    Command {
        code: i32,
        code_name: &'static str,
        message: String,
    },
}

impl Error {
    /// Build a command error with a MongoDB error code.
    pub fn command(code: i32, code_name: &'static str, message: impl Into<String>) -> Self {
        Self::Command {
            code,
            code_name,
            message: message.into(),
        }
    }

    /// Serialize this error as an OP_MSG reply body:
    /// `{ok: 0.0, errmsg, code, codeName, $db: "admin"}`.
    ///
    /// Protocol errors (which cannot reach a handler) never produce a body —
    /// the connection is closed instead.
    pub fn to_error_response_doc(&self) -> Option<wirebson::Document> {
        let Error::Command { code, code_name, message } = self else {
            return None;
        };
        let mut doc = wirebson::Document::new();
        doc.add("ok", 0.0_f64);
        doc.add("errmsg", message.clone());
        doc.add("code", *code);
        doc.add("codeName", *code_name);
        doc.add("$db", "admin");
        Some(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirebson::Bson;

    #[test]
    fn command_error_display() {
        let e = Error::command(96, "OperationFailed", "boom");
        assert!(e.to_string().contains("96"));
        assert!(e.to_string().contains("boom"));
    }

    #[test]
    fn command_error_maps_to_response_doc() {
        let doc = Error::command(18, "AuthenticationFailed", "nope")
            .to_error_response_doc()
            .expect("command errors always produce a body");
        assert_eq!(doc.get("ok"), Some(&Bson::Double(0.0)));
        assert_eq!(doc.get("errmsg"), Some(&Bson::from("nope")));
        assert_eq!(doc.get("code"), Some(&Bson::Int32(18)));
        assert_eq!(doc.get("codeName"), Some(&Bson::from("AuthenticationFailed")));
        assert_eq!(doc.get("$db"), Some(&Bson::from("admin")));
    }

    #[test]
    fn protocol_error_has_no_response_doc() {
        let e = Error::Protocol(ProtocolError::UnsupportedOpcode(42));
        assert!(e.to_error_response_doc().is_none());
    }

    #[test]
    fn response_doc_encodes_and_reparses() {
        let raw = Error::command(59, "CommandNotFound", "unknown command")
            .to_error_response_doc()
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(raw.command().unwrap(), "ok");
        let doc = raw.shallow().unwrap();
        assert_eq!(doc.get("code"), Some(&Bson::Int32(59)));
    }
}
