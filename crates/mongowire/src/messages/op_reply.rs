//! `OP_REPLY` — legacy reply to `OP_QUERY` (removed in MongoDB 5.1).
//!
//! ```text
//! struct OP_REPLY {
//!     MsgHeader header;          // handled by framing
//!     int32    responseFlags;
//!     int64    cursorID;
//!     int32    startingFrom;
//!     int32    numberReturned;
//!     document* documents;       // numberReturned documents, back to back
//! }
//! ```

use bitflags::bitflags;
use bytes::{Bytes, BytesMut};

use mongo_common::bson::scalar::MIN_DOC_LEN;
use mongo_common::io::{ProtocolRead, ProtocolWrite};

use crate::error::ProtocolError;
use crate::messages::Message;

bitflags! {
    /// `OP_REPLY` `responseFlags` (wire `i32`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ReplyFlags: i32 {
        const CURSOR_NOT_FOUND = mongo_common::consts::reply_flags::CURSOR_NOT_FOUND;
        const QUERY_FAILURE = mongo_common::consts::reply_flags::QUERY_FAILURE;
        const SHARD_CONFIG_STALE = mongo_common::consts::reply_flags::SHARD_CONFIG_STALE;
        const AWAIT_CAPABLE = mongo_common::consts::reply_flags::AWAIT_CAPABLE;
    }
}

/// The OP_REPLY body.
#[derive(Debug, Clone, PartialEq)]
pub struct OpReply {
    pub response_flags: ReplyFlags,
    pub cursor_id: i64,
    pub starting_from: i32,
    /// Must equal `documents.len()`; `numberReturned` documents follow
    /// back-to-back with no separators.
    pub number_returned: i32,
    pub documents: Vec<wirebson::RawDocument>,
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

impl Message for OpReply {
    const OPCODE: crate::messages::Opcode = crate::messages::Opcode::Reply;

    fn body_len(&self) -> usize {
        // 4 (responseFlags) + 8 (cursorID) + 4 (startingFrom) + 4
        // (numberReturned) + the documents back to back.
        20 + self
            .documents
            .iter()
            .map(|d| d.as_bytes().len())
            .sum::<usize>()
    }

    fn encode_body(&self, out: &mut BytesMut) {
        debug_assert_eq!(
            self.number_returned, self.documents.len() as i32,
            "numberReturned must equal documents.len()"
        );
        out.reserve(self.body_len());
        out.put_i32_le(self.response_flags.bits());
        out.put_i64_le(self.cursor_id);
        out.put_i32_le(self.starting_from);
        // `documents` is the source of truth on the wire; parsing guarantees
        // the `number_returned` invariant (see the struct docs).
        out.put_i32_le(self.documents.len() as i32);
        for doc in &self.documents {
            out.put_bytes(doc.as_bytes());
        }
    }

    fn parse_body(body: Bytes) -> Result<Self, ProtocolError> {
        let mut r: &[u8] = &body;
        let response_flags = ReplyFlags::from_bits_truncate(r.read_i32_le()?);
        let cursor_id = r.read_i64_le()?;
        let starting_from = r.read_i32_le()?;
        let number_returned = r.read_i32_le()?;
        if number_returned < 0 {
            return Err(ProtocolError::InvalidBody("negative numberReturned"));
        }
        // Every document is at least `MIN_DOC_LEN` bytes, so a larger count
        // cannot fit into the body — reject it before allocating.
        if number_returned as usize > r.remaining() / MIN_DOC_LEN {
            return Err(ProtocolError::InvalidBody(
                "numberReturned exceeds the body size",
            ));
        }

        let mut documents = Vec::with_capacity(number_returned as usize);
        for _ in 0..number_returned {
            documents.push(take_document(&body, &mut r)?);
        }
        // The trailing check makes `documents.len() == number_returned`
        // airtight: fewer documents fail above, extra bytes fail here.
        if !r.is_empty() {
            return Err(ProtocolError::InvalidBody(
                "trailing bytes after the documents",
            ));
        }

        Ok(Self {
            response_flags,
            cursor_id,
            starting_from,
            number_returned,
            documents,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirebson::{Bson, Document};

    fn raw(pairs: impl IntoIterator<Item = (&'static str, Bson)>) -> wirebson::RawDocument {
        Document::from_iter(pairs).encode().unwrap()
    }

    fn encoded(r: &OpReply) -> Bytes {
        let mut out = BytesMut::new();
        r.encode_body(&mut out);
        out.freeze()
    }

    fn reply(documents: Vec<wirebson::RawDocument>) -> OpReply {
        OpReply {
            response_flags: ReplyFlags::AWAIT_CAPABLE,
            cursor_id: 0,
            starting_from: 0,
            number_returned: documents.len() as i32,
            documents,
        }
    }

    #[test]
    fn roundtrip_no_documents() {
        let r = reply(Vec::new());
        assert_eq!(r.number_returned, 0);
        assert_eq!(r.body_len(), 20);
        assert_eq!(OpReply::parse_body(encoded(&r)).unwrap(), r);
    }

    #[test]
    fn roundtrip_multiple_documents() {
        let r = reply(vec![
            raw([("ok", Bson::Double(1.0))]),
            raw([("ok", Bson::Double(0.0)), ("errmsg", Bson::from("boom"))]),
            raw([("value", Bson::Int32(-42))]),
        ]);
        assert_eq!(r.number_returned, 3);
        // 4 + (tag+key+value) + end, summed per document:
        // `{"ok":1.0}` = 4+12+1 = 17, `{"ok":0.0,"errmsg":"boom"}` =
        // 4+12+17+1 = 34, `{"value":-42}` = 4+11+1 = 16.
        assert_eq!(r.body_len(), 20 + 17 + 34 + 16);
        assert_eq!(OpReply::parse_body(encoded(&r)).unwrap(), r);
    }

    #[test]
    fn roundtrip_extreme_scalars_and_flags() {
        let r = OpReply {
            response_flags: ReplyFlags::all(),
            cursor_id: i64::MIN,
            starting_from: i32::MAX,
            number_returned: 1,
            documents: vec![raw([("d", Bson::Double(-0.5))])],
        };
        assert_eq!(OpReply::parse_body(encoded(&r)).unwrap(), r);
    }

    #[test]
    fn parse_rejects_number_returned_mismatch() {
        let doc = raw([("ok", Bson::Double(1.0))]);
        let raw_doc = doc.as_bytes();

        // Claim two documents but provide one: the second cannot be read.
        let mut buf = BytesMut::new();
        buf.put_i32_le(0);
        buf.put_i64_le(0);
        buf.put_i32_le(0);
        buf.put_i32_le(2);
        buf.put_bytes(raw_doc);
        assert!(matches!(
            OpReply::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidBody("truncated document"))
        ));

        // Claim one document but provide none: there is no room for even the
        // minimum 5-byte document.
        let mut buf = BytesMut::new();
        buf.put_i32_le(0);
        buf.put_i64_le(0);
        buf.put_i32_le(0);
        buf.put_i32_le(1);
        assert!(matches!(
            OpReply::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidBody(
                "numberReturned exceeds the body size"
            ))
        ));

        // Claim one document but provide two.
        let mut buf = BytesMut::new();
        buf.put_i32_le(0);
        buf.put_i64_le(0);
        buf.put_i32_le(0);
        buf.put_i32_le(1);
        buf.put_bytes(raw_doc);
        buf.put_bytes(raw_doc);
        assert!(matches!(
            OpReply::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidBody(
                "trailing bytes after the documents"
            ))
        ));
    }

    #[test]
    fn parse_rejects_negative_number_returned() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(0);
        buf.put_i64_le(0);
        buf.put_i32_le(0);
        buf.put_i32_le(-1);
        assert!(matches!(
            OpReply::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidBody("negative numberReturned"))
        ));
    }

    #[test]
    fn parse_rejects_oversized_number_returned() {
        // numberReturned = i32::MAX cannot possibly fit: the guard must reject
        // it before the `Vec` allocation instead of attempting ~34 GiB.
        let mut buf = BytesMut::new();
        buf.put_i32_le(0);
        buf.put_i64_le(0);
        buf.put_i32_le(0);
        buf.put_i32_le(i32::MAX);
        assert!(matches!(
            OpReply::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidBody(
                "numberReturned exceeds the body size"
            ))
        ));
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let r = reply(vec![raw([("ok", Bson::Double(1.0))])]);
        let mut body = encoded(&r).to_vec();
        body.push(0);
        assert!(matches!(
            OpReply::parse_body(Bytes::from(body)),
            Err(ProtocolError::InvalidBody(
                "trailing bytes after the documents"
            ))
        ));
    }

    #[test]
    fn parse_never_panics_on_truncation() {
        let r = reply(vec![
            raw([("ok", Bson::Double(1.0))]),
            raw([("value", Bson::Int32(7))]),
        ]);
        let body = encoded(&r);
        for n in 0..body.len() {
            // Every proper prefix fails: documents are length-delimited, so a
            // cut can only shorten the last one below its declared length.
            assert!(OpReply::parse_body(body.slice(..n)).is_err(), "n={n}");
        }
        assert!(OpReply::parse_body(body).is_ok());
    }

    #[test]
    fn documents_are_zero_copy_views_of_the_body() {
        let r = reply(vec![raw([("ok", Bson::Double(1.0))])]);
        let body = encoded(&r);
        let parsed = OpReply::parse_body(body.clone()).unwrap();
        assert_eq!(
            parsed.documents[0].as_bytes().as_ptr() as usize,
            body.as_ptr() as usize + 20
        );
    }

    #[test]
    fn unknown_flag_bits_are_truncated() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(ReplyFlags::all().bits() | 0x8000_0000u32 as i32);
        buf.put_i64_le(0);
        buf.put_i32_le(0);
        buf.put_i32_le(0);
        let parsed = OpReply::parse_body(buf.freeze()).unwrap();
        assert_eq!(parsed.response_flags, ReplyFlags::all());
        assert_eq!(parsed.number_returned, 0);
        assert!(parsed.documents.is_empty());
    }
}
