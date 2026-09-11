//! Ready-made reply bodies for handshake commands.

use crate::compression::CompressorId;
use crate::error::{Error, ProtocolError};
use crate::messages::{MsgFlags, OpMsg, OpReply};
use wirebson::RawDocument;

/// A BSON failure while encoding a reply this crate builds. Such documents
/// are static shapes and always valid, so this is purely defensive — but it
/// must be mapped somewhere, and "protocol error" is the honest bucket.
pub(crate) fn bson_error(e: wirebson::Error) -> Error {
    Error::from(ProtocolError::from(e))
}

/// Build the `hello` / `isMaster` reply body (the OP_MSG shape).
///
/// Reports this crate's defaults: `maxMessageSizeBytes`, `maxBsonObjectSize`,
/// `maxWriteBatchSize`, `ok: 1.0`, plus `compression` when negotiated.
pub fn handshake_reply(
    compressors: &[CompressorId],
    max_msg_len: i32,
    legacy_is_master: bool,
) -> Result<OpMsg, Error> {
    let mut doc = wirebson::Document::new();
    doc.add("ok", 1.0_f64);
    // Old drivers (`isMaster` commands, all OP_QUERY handshakes) expect the
    // legacy response key; `hello` callers get the modern one.
    if legacy_is_master {
        doc.add("ismaster", true);
    } else {
        doc.add("isWritablePrimary", true);
    }
    doc.add("helloOk", true);
    doc.add("maxBsonObjectSize", mongo_common::consts::MAX_BSON_LEN);
    doc.add("maxMessageSizeBytes", max_msg_len);
    doc.add("maxWriteBatchSize", 100_000_i32);
    doc.add("localTime", wirebson::Bson::from(std::time::SystemTime::now()));
    doc.add("logicalSessionTimeoutMinutes", 30_i32);
    doc.add("connectionId", 1_i32);
    doc.add("minWireVersion", 0_i32);
    doc.add("maxWireVersion", 21_i32);
    doc.add("readOnly", false);
    if !compressors.is_empty() {
        let mut compression = wirebson::Array::new();
        for compressor in compressors {
            compression.push(compressor.name());
        }
        doc.add("compression", compression);
    }
    let raw = doc.encode().map_err(bson_error)?;
    op_msg(crate::messages::MsgFlags::empty(), raw)
}

/// Build the legacy OP_REPLY wrapper for an OP_QUERY handshake response.
pub fn query_handshake_reply(body: RawDocument) -> OpReply {
    OpReply {
        response_flags: crate::messages::ReplyFlags::AWAIT_CAPABLE,
        cursor_id: 0,
        starting_from: 0,
        number_returned: 1,
        documents: vec![body],
    }
}

/// The `ping` reply: `{ok: 1.0}`.
pub fn ping_reply() -> Result<OpMsg, Error> {
    let mut doc = wirebson::Document::new();
    doc.add("ok", 1.0_f64);
    let raw = doc.encode().map_err(bson_error)?;
    op_msg(crate::messages::MsgFlags::empty(), raw)
}

/// Wrap a body document into an OP_MSG with the given flags.
pub fn op_msg(flags: MsgFlags, body: RawDocument) -> Result<OpMsg, Error> {
    OpMsg::new(flags, body, Vec::new()).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirebson::Bson;

    /// The reply body, decoded shallowly (test docs never nest deeply).
    fn body(msg: &OpMsg) -> wirebson::Document {
        msg.document().shallow().unwrap()
    }

    #[test]
    fn hello_reply_fields() {
        let msg = handshake_reply(&[], 48_000_000, false).unwrap();
        let doc = body(&msg);
        assert_eq!(doc.get("ok"), Some(&Bson::Double(1.0)));
        assert_eq!(doc.get("isWritablePrimary"), Some(&Bson::Bool(true)));
        assert_eq!(doc.get("ismaster"), None, "legacy key only for isMaster");
        assert_eq!(doc.get("helloOk"), Some(&Bson::Bool(true)));
        assert_eq!(doc.get("maxBsonObjectSize"), Some(&Bson::Int32(16_777_216)));
        assert_eq!(doc.get("maxMessageSizeBytes"), Some(&Bson::Int32(48_000_000)));
        assert_eq!(doc.get("maxWriteBatchSize"), Some(&Bson::Int32(100_000)));
        assert_eq!(doc.get("logicalSessionTimeoutMinutes"), Some(&Bson::Int32(30)));
        assert_eq!(doc.get("connectionId"), Some(&Bson::Int32(1)));
        assert_eq!(doc.get("minWireVersion"), Some(&Bson::Int32(0)));
        assert_eq!(doc.get("maxWireVersion"), Some(&Bson::Int32(21)));
        assert_eq!(doc.get("readOnly"), Some(&Bson::Bool(false)));
        // localTime: a recent timestamp (milliseconds since the epoch).
        let Bson::DateTime(ms) = doc.get("localTime").unwrap() else {
            panic!("localTime must be a DateTime")
        };
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        assert!((*ms - now).abs() < 60_000, "localTime {ms} vs now {now}");
        // No compression negotiated: the field must be absent.
        assert_eq!(doc.get("compression"), None);
        // Fresh replies carry no checksum bits; framing appends the trailer.
        assert_eq!(msg.flags, crate::messages::MsgFlags::empty());
        assert_eq!(msg.checksum, None);
    }

    #[test]
    fn legacy_is_master_reply_uses_legacy_key() {
        let doc = body(&handshake_reply(&[], 48_000_000, true).unwrap());
        assert_eq!(doc.get("ismaster"), Some(&Bson::Bool(true)));
        assert_eq!(doc.get("isWritablePrimary"), None);
    }

    #[test]
    fn compression_array_lists_names_in_preference_order() {
        let compressors = [
            CompressorId::Zlib,
            CompressorId::Snappy,
            CompressorId::Zstd,
            CompressorId::Noop,
        ];
        let doc = body(&handshake_reply(&compressors, 48_000_000, false).unwrap());
        let Some(Bson::Array(names)) = doc.get("compression") else {
            panic!("compression must be an array")
        };
        let names: Vec<&Bson> = names.iter().collect();
        assert_eq!(
            names,
            vec![
                &Bson::from("zlib"),
                &Bson::from("snappy"),
                &Bson::from("zstd"),
                &Bson::from("noop"),
            ]
        );
    }

    #[test]
    fn ping_reply_is_ok_only() {
        let doc = body(&ping_reply().unwrap());
        assert_eq!(doc.len(), 1);
        assert_eq!(doc.get("ok"), Some(&Bson::Double(1.0)));
    }
}
