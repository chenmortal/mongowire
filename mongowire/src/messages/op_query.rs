//! `OP_QUERY` — legacy handshake query (removed in MongoDB 5.1 except for
//! `hello` / `isMaster`).
//!
//! ```text
//! struct OP_QUERY {
//!     MsgHeader header;                 // handled by framing
//!     int32    flags;
//!     cstring  fullCollectionName;      // e.g. "admin.$cmd"
//!     int32    numberToSkip;
//!     int32    numberToReturn;
//!     document query;
//!     [document returnFieldsSelector;]
//! }
//! ```

use bitflags::bitflags;
use bytes::{Bytes, BytesMut};

use mongo_common::bson::scalar::MIN_DOC_LEN;
use mongo_common::io::{ProtocolRead, ProtocolWrite};

use crate::error::ProtocolError;
use crate::messages::Message;

bitflags! {
    /// `OP_QUERY` flags (wire `i32`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct QueryFlags: i32 {
        const TAILABLE_CURSOR = mongo_common::consts::query_flags::TAILABLE_CURSOR;
        const SLAVE_OK = mongo_common::consts::query_flags::SLAVE_OK;
        const OPLOG_REPLAY = mongo_common::consts::query_flags::OPLOG_REPLAY;
        const NO_CURSOR_TIMEOUT = mongo_common::consts::query_flags::NO_CURSOR_TIMEOUT;
        const AWAIT_DATA = mongo_common::consts::query_flags::AWAIT_DATA;
        const EXHAUST = mongo_common::consts::query_flags::EXHAUST;
        const PARTIAL = mongo_common::consts::query_flags::PARTIAL;
    }
}

/// The OP_QUERY body.
#[derive(Debug, Clone, PartialEq)]
pub struct OpQuery {
    pub flags: QueryFlags,
    /// e.g. `"admin.$cmd"` for the handshake.
    pub full_collection_name: String,
    pub number_to_skip: i32,
    pub number_to_return: i32,
    pub query: wirebson::RawDocument,
    /// Optional trailing document.
    pub return_fields_selector: Option<wirebson::RawDocument>,
}

/// Slice one length-prefixed document off `body` as a zero-copy [`Bytes`]
/// view while advancing the cursor `r` (over the same region) past it.
///
/// The document length is validated against the cursor before slicing, so
/// [`Bytes::slice`] never panics; [`wirebson::RawDocument::from_bytes`]
/// re-validates the length prefix and the trailing NUL.
fn take_document(body: &Bytes, r: &mut &[u8]) -> Result<wirebson::RawDocument, ProtocolError> {
    let start = body.len() - r.remaining();
    let len = r
        .peek_i32_le()
        .map_err(|_| ProtocolError::InvalidBody("truncated document"))?;
    if len < MIN_DOC_LEN as i32 || len as usize > r.remaining() {
        return Err(ProtocolError::InvalidBody("invalid document length"));
    }
    let doc = wirebson::RawDocument::from_bytes(body.slice(start..start + len as usize))?;
    r.read_bytes(len as usize)
        .map_err(|_| ProtocolError::InvalidBody("truncated document"))?;
    Ok(doc)
}

impl Message for OpQuery {
    const OPCODE: crate::messages::Opcode = crate::messages::Opcode::Query;

    fn body_len(&self) -> usize {
        // 4 (flags) + cstring + 4 (numberToSkip) + 4 (numberToReturn)
        // + query [+ returnFieldsSelector].
        12
            + self.full_collection_name.len()
            + 1
            + self.query.as_bytes().len()
            + self
                .return_fields_selector
                .as_ref()
                .map_or(0, |d| d.as_bytes().len())
    }

    fn encode_body(&self, out: &mut BytesMut) {
        debug_assert!(
            !self.full_collection_name.as_bytes().contains(&0),
            "fullCollectionName must not contain NUL bytes"
        );
        out.reserve(self.body_len());
        out.put_i32_le(self.flags.bits());
        out.put_bytes(self.full_collection_name.as_bytes());
        out.put_u8(0);
        out.put_i32_le(self.number_to_skip);
        out.put_i32_le(self.number_to_return);
        out.put_bytes(self.query.as_bytes());
        if let Some(selector) = &self.return_fields_selector {
            out.put_bytes(selector.as_bytes());
        }
    }

    fn parse_body(body: Bytes) -> Result<Self, ProtocolError> {
        let mut r: &[u8] = &body;
        let flags = QueryFlags::from_bits_truncate(r.read_i32_le()?);
        let name = r.read_cstring()?;
        if name.is_empty() {
            return Err(ProtocolError::InvalidBody("empty fullCollectionName"));
        }
        // Strict UTF-8: a lossy conversion would change the byte length of
        // the name, making encode(body_len) diverge from the parsed frame.
        let full_collection_name = String::from_utf8(name.to_vec())
            .map_err(|_| ProtocolError::InvalidBody("invalid UTF-8 in fullCollectionName"))?;
        let number_to_skip = r.read_i32_le()?;
        let number_to_return = r.read_i32_le()?;

        let query = take_document(&body, &mut r)?;

        let return_fields_selector = match r.is_empty() {
            true => None,
            false => Some(take_document(&body, &mut r)?),
        };
        // `take_document` validates each document against its own slice, but
        // bytes AFTER the selector are still trailing garbage: reject them
        // (the Go reference errors on `len(b) != selectorLow + l` too). A
        // `debug_assert!` here once let release builds accept such frames
        // while debug builds panicked (found by review).
        if !r.is_empty() {
            return Err(ProtocolError::InvalidBody(
                "trailing bytes after returnFieldsSelector",
            ));
        }

        Ok(Self {
            flags,
            full_collection_name,
            number_to_skip,
            number_to_return,
            query,
            return_fields_selector,
        })
    }
}

impl OpQuery {
    /// Build the canonical pre-4.4 handshake: query `{"isMaster": 1.0, ...}`
    /// on `admin.$cmd`.
    pub fn handshake(request: wirebson::RawDocument) -> Self {
        Self {
            flags: QueryFlags::empty(),
            full_collection_name: "admin.$cmd".to_owned(),
            number_to_skip: 0,
            number_to_return: -1,
            query: request,
            return_fields_selector: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirebson::{Bson, Document};

    /// Encode a document and unwrap (test documents are always valid).
    fn raw(pairs: impl IntoIterator<Item = (&'static str, Bson)>) -> wirebson::RawDocument {
        Document::from_iter(pairs).encode().unwrap()
    }

    /// Encode the body into an owned `Bytes` for parsing back.
    fn encoded(q: &OpQuery) -> Bytes {
        let mut out = BytesMut::new();
        q.encode_body(&mut out);
        out.freeze()
    }

    #[test]
    fn roundtrip_query_only() {
        let q = OpQuery {
            flags: QueryFlags::SLAVE_OK | QueryFlags::EXHAUST,
            full_collection_name: "admin.$cmd".to_owned(),
            number_to_skip: 0,
            number_to_return: -1,
            query: raw([("isMaster", Bson::Bool(true)), ("$db", Bson::from("admin"))]),
            return_fields_selector: None,
        };
        assert_eq!(q.body_len(), encoded(&q).len());
        assert_eq!(OpQuery::parse_body(encoded(&q)).unwrap(), q);
    }

    #[test]
    fn roundtrip_with_selector() {
        let q = OpQuery {
            flags: QueryFlags::empty(),
            full_collection_name: "db.coll".to_owned(),
            number_to_skip: 3,
            number_to_return: 10,
            query: raw([("find", Bson::from("coll")), ("limit", Bson::Int32(10))]),
            return_fields_selector: Some(raw([
                ("_id", Bson::Int32(1)),
                ("name", Bson::Int32(1)),
            ])),
        };
        assert_eq!(q.body_len(), encoded(&q).len());
        assert_eq!(OpQuery::parse_body(encoded(&q)).unwrap(), q);
    }

    #[test]
    fn flags_roundtrip_and_truncation() {
        // All known bits survive the round-trip...
        let q = OpQuery::handshake(raw([("isMaster", Bson::Int32(1))]))
            .with_flags(QueryFlags::all());
        assert_eq!(OpQuery::parse_body(encoded(&q)).unwrap().flags, QueryFlags::all());

        // ...unknown bits are dropped on parse, matching the legacy servers'
        // forward-compatibility behaviour.
        let mut buf = BytesMut::new();
        buf.put_i32_le(QueryFlags::SLAVE_OK.bits() | 0x4000_0000);
        buf.put_cstring("admin.$cmd").unwrap();
        buf.put_i32_le(0);
        buf.put_i32_le(-1);
        let raw_query = raw([("isMaster", Bson::Int32(1))]);
        let raw_bytes = raw_query.as_bytes();
        buf.put_bytes(raw_bytes);
        let parsed = OpQuery::parse_body(buf.freeze()).unwrap();
        assert_eq!(parsed.flags, QueryFlags::SLAVE_OK);
    }

    #[test]
    fn parse_rejects_empty_collection_name() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(0); // flags
        buf.put_u8(0); // empty cstring
        buf.put_i32_le(0); // numberToSkip
        buf.put_i32_le(-1); // numberToReturn
        let raw_query = raw([("isMaster", Bson::Int32(1))]);
        buf.put_bytes(raw_query.as_bytes());
        assert!(matches!(
            OpQuery::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidBody("empty fullCollectionName"))
        ));
    }

    #[test]
    fn parse_rejects_trailing_garbage() {
        let q = OpQuery::handshake(raw([("isMaster", Bson::Int32(1))]));
        let mut body = encoded(&q).to_vec();
        body.push(0); // one stray byte after the query document
        assert!(matches!(
            OpQuery::parse_body(Bytes::from(body)),
            Err(ProtocolError::InvalidBody(_) | ProtocolError::Bson(_))
        ));
    }

    #[test]
    fn parse_never_panics_on_truncation() {
        // Without a selector only the full body parses: every proper prefix
        // cuts the query document short.
        let plain = OpQuery::handshake(raw([("isMaster", Bson::Int32(1))]));
        let body = encoded(&plain);
        for n in 0..body.len() {
            assert!(OpQuery::parse_body(body.slice(..n)).is_err(), "n={n}");
        }
        assert!(OpQuery::parse_body(body).is_ok());

        // With a selector every prefix still parses or errors without
        // panicking; exactly one prefix — the body without the selector — is
        // a valid selector-less query.
        let mut q = OpQuery::handshake(raw([("isMaster", Bson::Int32(1))]));
        q.return_fields_selector = Some(raw([("_id", Bson::Int32(1))]));
        let body = encoded(&q);
        let sel_len = q.return_fields_selector.as_ref().unwrap().len();
        let mut ok_at = Vec::new();
        for n in 0..body.len() {
            if OpQuery::parse_body(body.slice(..n)).is_ok() {
                ok_at.push(n);
            }
        }
        assert_eq!(ok_at, vec![body.len() - sel_len]);
    }

    #[test]
    fn documents_are_zero_copy_views_of_the_body() {
        let q = OpQuery::handshake(raw([("isMaster", Bson::Int32(1))]));
        let body = encoded(&q);
        let parsed = OpQuery::parse_body(body.clone()).unwrap();
        // 4 (flags) + name + NUL + 4 + 4 (numbers) is where the query starts.
        let query_offset = 4 + "admin.$cmd".len() + 1 + 8;
        assert_eq!(
            parsed.query.as_bytes().as_ptr() as usize,
            body.as_ptr() as usize + query_offset
        );
        assert_eq!(parsed.query.as_bytes(), &body[query_offset..]);
    }

    impl OpQuery {
        fn with_flags(mut self, flags: QueryFlags) -> Self {
            self.flags = flags;
            self
        }
    }

    #[test]
    fn trailing_bytes_after_selector_are_rejected() {
        // A valid query + selector followed by one junk byte: a
        // `debug_assert!` here once panicked in debug builds while release
        // builds silently accepted the frame (review finding).
        let q = OpQuery {
            return_fields_selector: Some(raw([("_id", Bson::Int32(1))])),
            ..OpQuery::handshake(raw([("isMaster", Bson::Int32(1))]))
        };
        let mut body = Vec::from(encoded(&q).as_ref());
        // A minimal valid document `{}` after the selector is still garbage.
        body.extend_from_slice(&[0x05, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(
            OpQuery::parse_body(Bytes::from(body)),
            Err(ProtocolError::InvalidBody(
                "trailing bytes after returnFieldsSelector"
            ))
        ));
    }
}
