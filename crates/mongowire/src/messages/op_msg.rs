//! `OP_MSG` — the extensible message format used for both client requests
//! and server replies (official spec: "`OP_MSG`").
//!
//! ```text
//! OP_MSG {
//!     MsgHeader header;           // handled by framing
//!     uint32 flagBits;
//!     Sections[] sections;
//!     optional<uint32> checksum;  // present iff flagBits bit 0 set
//! }
//! ```

use bitflags::bitflags;
use bytes::{Bytes, BytesMut};

use mongo_common::bson::scalar::MIN_DOC_LEN;
use mongo_common::io::ProtocolWrite;

use wirebson::RawDocument;

use crate::error::ProtocolError;
use crate::messages::Message;

bitflags! {
    /// `OP_MSG` `flagBits`.
    ///
    /// Bits 0-15 are *required*: [`MsgFlags::parse`] errors on unknown set
    /// bits. Bits 16-31 are *optional*: unknown set bits are ignored (and
    /// cleared), as the spec mandates for parsers that are not proxies.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MsgFlags: u32 {
        /// The message ends with a 4-byte CRC-32C checksum.
        const CHECKSUM_PRESENT = mongo_common::consts::msg_flags::CHECKSUM_PRESENT;
        /// Another message follows without further action from the receiver;
        /// such requests MUST NOT be replied to.
        const MORE_TO_COME = mongo_common::consts::msg_flags::MORE_TO_COME;
        /// The client is prepared for multiple `moreToCome` replies.
        const EXHAUST_ALLOWED = mongo_common::consts::msg_flags::EXHAUST_ALLOWED;
    }
}

impl MsgFlags {
    /// Validate raw wire bits.
    ///
    /// # Errors
    /// [`ProtocolError::InvalidOpMsg`] if any unknown bit among bits 0-15 is
    /// set (spec: parsers MUST error). Unknown bits 16-31 are silently
    /// cleared.
    pub fn parse(raw: u32) -> Result<Self, ProtocolError> {
        // Bits 0-15 are required by the spec: any unknown set bit among them
        // must make the parser fail. Bits 16-31 are optional; unknown ones
        // are silently cleared (this parser is not a proxy, so it does not
        // forward them either).
        const REQUIRED_BITS: u32 = 0x0000_ffff;
        let known = Self::CHECKSUM_PRESENT.bits()
            | Self::MORE_TO_COME.bits()
            | Self::EXHAUST_ALLOWED.bits();
        if raw & REQUIRED_BITS & !known != 0 {
            return Err(ProtocolError::InvalidOpMsg("unknown required flag bits"));
        }
        Ok(Self::from_bits_truncate(raw))
    }
}

/// One kind-1 section: an identifier plus document sequence.
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentSequence {
    /// Replaces this (possibly nested) field of the body; MUST NOT also
    /// exist as a top-level body field.
    pub identifier: String,
    /// Documents back-to-back with no separators.
    pub documents: Vec<RawDocument>,
}

/// The sections of an OP_MSG.
///
/// Invariants (spec "Sections" + the Go reference's `checkSections`):
/// * at least one section;
/// * exactly one kind-0 (body) section containing exactly one document, and
///   it is the first section;
/// * every kind-1 section has a non-empty identifier that does not equal any
///   top-level field name of the body;
/// * kind-2 sections are rejected on ingress (internal use only).
///
/// The first three are structural in this representation: [`Sections`] always
/// holds the kind-0 document (so at least one section always exists), it is
/// stored ahead of all sequences (so the kind-0 section is always first), and
/// it is a single document. [`Sections::new`] enforces the identifier rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Sections {
    /// The kind-0 body document.
    pub body: RawDocument,
    /// All kind-1 sections in order.
    pub sequences: Vec<DocumentSequence>,
}

impl Sections {
    /// Assemble and validate sections.
    ///
    /// Zero-document sequences are accepted, mirroring the Go reference
    /// (where the document loop simply does not run).
    ///
    /// # Errors
    /// [`ProtocolError::InvalidOpMsg`] if a sequence identifier is empty (or
    /// contains a NUL byte, which could not be encoded as a cstring) or
    /// duplicates a top-level field name of `body`;
    /// [`ProtocolError::Bson`] if `body` itself is malformed.
    pub fn new(body: RawDocument, sequences: Vec<DocumentSequence>) -> Result<Self, ProtocolError> {
        if sequences.is_empty() {
            return Ok(Self {
                body,
                sequences,
            });
        }
        // Collect the body's top-level field names once: checking each
        // identifier with `body.get` walks the whole document per section,
        // which is quadratic O(fields × sections) on hostile input (a PoC
        // spent 5.6 s of CPU on a 630 KB message — security review).
        let body_fields: std::collections::HashSet<Vec<u8>> = body
            .fields()
            .map(|field| field.map(|(name, _)| name.as_bytes().to_vec()))
            .collect::<Result<_, _>>()?;
        for seq in &sequences {
            if seq.identifier.is_empty() {
                return Err(ProtocolError::InvalidOpMsg("kind 1 section has no identifier"));
            }
            if seq.identifier.as_bytes().contains(&0) {
                return Err(ProtocolError::InvalidOpMsg("kind 1 identifier contains NUL"));
            }
            if body_fields.contains(seq.identifier.as_bytes()) {
                return Err(ProtocolError::InvalidOpMsg(
                    "kind 1 identifier duplicates a body field",
                ));
            }
        }
        Ok(Self { body, sequences })
    }

    /// Encoded length: kind bytes + body doc + per-sequence
    /// (1 + 4 + cstring + docs).
    pub fn size(&self) -> usize {
        let mut n = 1 + self.body.as_bytes().len();
        for seq in &self.sequences {
            n += 1 + 4 + seq.identifier.len() + 1;
            n += seq.documents.iter().map(|d| d.as_bytes().len()).sum::<usize>();
        }
        n
    }
}

/// Slice one length-prefixed document off `body` in `offset..end` as a
/// zero-copy [`Bytes`] view, returning it together with the offset past the
/// document.
///
/// The declared length is validated against the bounds before slicing, so
/// [`Bytes::slice`] never panics; [`RawDocument::from_bytes`] re-validates
/// the length prefix and the trailing NUL.
fn take_document(
    body: &Bytes,
    offset: usize,
    end: usize,
) -> Result<(RawDocument, usize), ProtocolError> {
    let rest = end
        .checked_sub(offset)
        .ok_or(ProtocolError::InvalidOpMsg("section cursor overran its end"))?;
    if rest < 4 {
        return Err(ProtocolError::InvalidOpMsg("truncated document"));
    }
    let len = i32::from_le_bytes(body[offset..offset + 4].try_into().expect("4 bytes checked"));
    if len < MIN_DOC_LEN as i32 || len as usize > rest {
        return Err(ProtocolError::InvalidOpMsg("invalid document length"));
    }
    let doc = RawDocument::from_bytes(body.slice(offset..offset + len as usize))?;
    Ok((doc, offset + len as usize))
}

/// The OP_MSG body.
#[derive(Debug, Clone, PartialEq)]
pub struct OpMsg {
    pub flags: MsgFlags,
    pub sections: Sections,
    /// Present iff [`MsgFlags::CHECKSUM_PRESENT`]; validated by
    /// [`crate::framing`] before this value is parsed.
    pub checksum: Option<u32>,
}

impl OpMsg {
    /// Build a message from a body document and optional sequences,
    /// validating via [`Sections::new`].
    ///
    /// A freshly built message never carries a checksum: the CRC-32C trailer
    /// is computed by [`crate::framing::encode_message`] over header+body,
    /// which it follows with the `CHECKSUM_PRESENT` flag set on the wire.
    /// That flag is therefore cleared here, maintaining the
    /// `checksum.is_some() == flags.contains(CHECKSUM_PRESENT)` invariant.
    ///
    /// # Errors
    /// [`ProtocolError::InvalidOpMsg`] on section invariant violations.
    pub fn new(
        flags: MsgFlags,
        body: RawDocument,
        sequences: Vec<DocumentSequence>,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            flags: flags - MsgFlags::CHECKSUM_PRESENT,
            sections: Sections::new(body, sequences)?,
            checksum: None,
        })
    }

    /// The kind-0 body document.
    pub fn document(&self) -> &RawDocument {
        &self.sections.body
    }
}

impl Message for OpMsg {
    const OPCODE: crate::messages::Opcode = crate::messages::Opcode::Msg;

    fn body_len(&self) -> usize {
        4 + self.sections.size() + if self.checksum.is_some() { 4 } else { 0 }
    }

    fn encode_body(&self, out: &mut BytesMut) {
        debug_assert!(
            self.checksum.is_some() == self.flags.contains(MsgFlags::CHECKSUM_PRESENT),
            "checksum presence must match the CHECKSUM_PRESENT flag"
        );
        out.reserve(self.body_len());
        out.put_u32_le(self.flags.bits());
        out.put_u8(0); // kind 0: the body document
        out.put_bytes(self.sections.body.as_bytes());
        for seq in &self.sections.sequences {
            out.put_u8(1); // kind 1: document sequence
            // The section size includes the size field itself, the
            // identifier cstring and the documents.
            let size = 4 + seq.identifier.len() + 1
                + seq.documents.iter().map(|d| d.as_bytes().len()).sum::<usize>();
            out.put_u32_le(size as u32);
            out.put_bytes(seq.identifier.as_bytes());
            out.put_u8(0);
            for doc in &seq.documents {
                out.put_bytes(doc.as_bytes());
            }
        }
        if let Some(checksum) = self.checksum {
            out.put_u32_le(checksum);
        }
    }

    /// Parse a body slice (flags, sections and — with `checksumPresent` —
    /// the trailing checksum).
    ///
    /// The checksum value is extracted from the trailer but **not**
    /// validated here: validation needs the 16 header bytes, so it is done
    /// by [`crate::framing::parse_message`] before this method runs.
    ///
    /// # Errors
    /// [`ProtocolError::InvalidOpMsg`] on any structural violation
    /// (mirroring `UnmarshalBinaryNocopy` in `reference/wire/op_msg.go`):
    /// unknown flag bits, unknown section kinds, truncated or overlapping
    /// sections, and the [`Sections`] invariants.
    fn parse_body(body: Bytes) -> Result<Self, ProtocolError> {
        // The Go reference demands 4 (flags) + 1 (kind) + at least one
        // payload byte before it touches anything beyond the flags.
        if body.len() < 5 {
            return Err(ProtocolError::InvalidOpMsg("body too short for OP_MSG"));
        }
        let flags = MsgFlags::parse(u32::from_le_bytes(
            body[..4].try_into().expect("len checked above"),
        ))?;
        let checksummed = flags.contains(MsgFlags::CHECKSUM_PRESENT);
        // With a checksum the trailer needs 4 more bytes; without it, a
        // checksummed-looking body of 6..=8 bytes would drive `end` below the
        // section cursor and underflow the arithmetic below (found by review:
        // a 22-byte frame panicked here).
        if body.len() < 6 + usize::from(checksummed) * 4 {
            return Err(ProtocolError::InvalidOpMsg("body too short for OP_MSG"));
        }
        // Everything from `offset` on must stay below `end`: with a checksum
        // the last 4 bytes are the trailer, not sections.
        let end = body.len() - usize::from(checksummed) * 4;

        let mut offset = 4;
        let mut body_doc: Option<RawDocument> = None;
        let mut sequences: Vec<DocumentSequence> = Vec::new();

        loop {
            let Some(&kind) = body.get(offset) else {
                return Err(ProtocolError::InvalidOpMsg("truncated section kind"));
            };
            offset += 1;

            match kind {
                0 => {
                    if body_doc.is_some() {
                        return Err(ProtocolError::InvalidOpMsg("multiple kind 0 sections"));
                    }
                    if !sequences.is_empty() {
                        return Err(ProtocolError::InvalidOpMsg(
                            "kind 0 section must be the first section",
                        ));
                    }
                    let (doc, next) = take_document(&body, offset, end)?;
                    body_doc = Some(doc);
                    offset = next;
                }
                1 => {
                    let section_room = end
                        .checked_sub(offset)
                        .ok_or(ProtocolError::InvalidOpMsg("section cursor overran its end"))?;
                    if section_room < 4 {
                        return Err(ProtocolError::InvalidOpMsg("truncated section size"));
                    }
                    // The size includes the size field itself, the identifier
                    // and the documents. Like the Go reference, require at
                    // least 5 bytes beyond the size field (a non-trivial
                    // identifier); zero-document sequences stay allowed.
                    let raw_size =
                        u32::from_le_bytes(body[offset..offset + 4].try_into().expect("checked"));
                    let sec_size = i64::from(raw_size) - 4;
                    if sec_size < 5 {
                        return Err(ProtocolError::InvalidOpMsg("section size too small"));
                    }
                    // `offset` still points at the size field: the section
                    // payload (identifier + documents) must fit behind it.
                    if sec_size > (end - offset - 4) as i64 {
                        return Err(ProtocolError::InvalidOpMsg("section exceeds the message"));
                    }
                    offset += 4;
                    let sec_end = offset + sec_size as usize;

                    // The identifier cstring must fit inside the section and
                    // must be non-empty (it replaces a body field name).
                    let Some(ident_len) = body[offset..sec_end].iter().position(|&b| b == 0) else {
                        return Err(ProtocolError::InvalidOpMsg("truncated section identifier"));
                    };
                    let identifier =
                        String::from_utf8_lossy(&body[offset..offset + ident_len]).into_owned();
                    offset += ident_len + 1;

                    // Documents back-to-back until exactly the section end.
                    let mut sec_rest = sec_end - offset;
                    let mut documents = Vec::new();
                    while sec_rest != 0 {
                        // `take_document` errors on a document straddling the
                        // section end (the Go reference's `secSize < 0`).
                        let (doc, next) = take_document(&body, offset, sec_end)?;
                        sec_rest -= next - offset;
                        offset = next;
                        documents.push(doc);
                    }
                    sequences.push(DocumentSequence { identifier, documents });
                }
                // Kind 2 is reserved for internal use and rejected on
                // ingress, like any other unknown kind.
                _ => return Err(ProtocolError::InvalidOpMsg("unknown section kind")),
            }

            // A section boundary must land exactly at the end of the
            // (checksum-aware) body.
            if offset == end {
                break;
            }
        }

        let checksum = checksummed.then(|| {
            u32::from_le_bytes(body[end..end + 4].try_into().expect("len checked above"))
        });

        // checkSections: the sections must fill the body exactly, with
        // exactly one kind-0 section (first, single document) and well-formed
        // kind-1 identifiers.
        let Some(body_doc) = body_doc else {
            return Err(ProtocolError::InvalidOpMsg("no kind 0 section"));
        };
        let sections = Sections::new(body_doc, sequences)?;
        debug_assert_eq!(
            sections.size(),
            end - 4,
            "sections must occupy the whole body between flags and checksum"
        );

        Ok(Self {
            flags,
            sections,
            checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wirebson::{Bson, Document};

    /// Encode a document and unwrap (test documents are always valid).
    fn raw(pairs: impl IntoIterator<Item = (&'static str, Bson)>) -> RawDocument {
        Document::from_iter(pairs).encode().unwrap()
    }

    /// Encode the body into an owned `Bytes` for parsing back.
    fn encoded(msg: &OpMsg) -> Bytes {
        let mut out = BytesMut::new();
        msg.encode_body(&mut out);
        out.freeze()
    }

    /// Build a body document with a single kind-0 section plus a kind-1
    /// section for `identifier`, as raw wire bytes (no checksum).
    fn body_bytes(
        flags: u32,
        body: &RawDocument,
        identifier: &str,
        docs: &[RawDocument],
    ) -> Bytes {
        let msg = OpMsg::new(
            MsgFlags::from_bits_truncate(flags),
            body.clone(),
            vec![DocumentSequence {
                identifier: identifier.to_owned(),
                documents: docs.to_vec(),
            }],
        )
        .unwrap();
        encoded(&msg)
    }

    #[test]
    fn roundtrip_single_section() {
        let msg = OpMsg::new(MsgFlags::MORE_TO_COME, raw([("hello", Bson::from("world"))]), vec![])
            .unwrap();
        assert_eq!(msg.body_len(), encoded(&msg).len());
        assert_eq!(OpMsg::parse_body(encoded(&msg)).unwrap(), msg);
        assert_eq!(
            OpMsg::parse_body(encoded(&msg)).unwrap().document(),
            &raw([("hello", Bson::from("world"))])
        );
    }

    #[test]
    fn roundtrip_multi_section() {
        let msg = OpMsg::new(
            MsgFlags::empty(),
            raw([("insert", Bson::from("actor")), ("$db", Bson::from("monila"))]),
            vec![DocumentSequence {
                identifier: "documents".to_owned(),
                documents: vec![raw([("name", Bson::from("n1"))]), raw([("name", Bson::from("n2"))])],
            }],
        )
        .unwrap();

        // 4 flags + (1 + body) + (1 + 4 + "documents" + NUL + 2 docs).
        // Each `{"name": "nX"}` document is 4 (len) + [1 + 4 + 1 (cstring)]
        // + [4 + 3 (string "nX\0")] + 1 (terminator) = 18 bytes.
        let expected_len = 4
            + 1 + msg.sections.body.as_bytes().len()
            + 1 + 4 + "documents".len() + 1
            + 2 * (4 + 1 + "name".len() + 1 + 4 + 3 + 1);
        assert_eq!(msg.body_len(), expected_len);
        assert_eq!(msg.body_len(), encoded(&msg).len());
        assert_eq!(OpMsg::parse_body(encoded(&msg)).unwrap(), msg);
    }

    #[test]
    fn zero_document_sequence_is_allowed() {
        // Like the Go reference: the document loop simply does not run. The
        // identifier must still be long enough for the section size
        // check (>= 5 bytes beyond the size field).
        let msg = OpMsg::new(
            MsgFlags::empty(),
            raw([("insert", Bson::from("c"))]),
            vec![DocumentSequence {
                identifier: "documents".to_owned(),
                documents: Vec::new(),
            }],
        )
        .unwrap();
        let parsed = OpMsg::parse_body(encoded(&msg)).unwrap();
        assert_eq!(parsed, msg);
        assert!(parsed.sections.sequences[0].documents.is_empty());
    }

    #[test]
    fn parse_never_panics_on_truncation() {
        let msg = OpMsg::new(
            MsgFlags::empty(),
            raw([("insert", Bson::from("actor"))]),
            vec![DocumentSequence {
                identifier: "documents".to_owned(),
                documents: vec![raw([("a", Bson::Int32(1))]), raw([("b", Bson::Int32(2))])],
            }],
        )
        .unwrap();
        let body = encoded(&msg);
        // Cutting anywhere inside a section must error, never panic. The one
        // exception is the boundary right after the kind-0 section, which is
        // itself a complete (sequence-less) OP_MSG.
        let kind0_end = 4 + 1 + msg.sections.body.as_bytes().len();
        for n in 0..body.len() {
            let result = OpMsg::parse_body(body.slice(..n));
            assert!(result.is_ok() == (n == kind0_end), "n={n}: {result:?}");
        }
        assert!(OpMsg::parse_body(body).is_ok());
    }

    #[test]
    fn parse_rejects_two_kind0_sections() {
        let doc = raw([("hello", Bson::Int32(1))]);
        let mut buf = BytesMut::new();
        buf.put_u32_le(0); // flags
        buf.put_u8(0);
        buf.put_bytes(doc.as_bytes());
        buf.put_u8(0);
        buf.put_bytes(doc.as_bytes());
        assert!(matches!(
            OpMsg::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidOpMsg("multiple kind 0 sections"))
        ));
    }

    #[test]
    fn parse_rejects_kind0_after_kind1() {
        let doc = raw([("hello", Bson::Int32(1))]);
        let mut buf = BytesMut::new();
        buf.put_u32_le(0); // flags
        // kind 1 section with identifier "documents" and one document.
        buf.put_u8(1);
        buf.put_u32_le((4 + "documents".len() + 1 + doc.len()) as u32);
        buf.put_bytes(b"documents");
        buf.put_u8(0);
        buf.put_bytes(doc.as_bytes());
        // ... followed by the body section.
        buf.put_u8(0);
        buf.put_bytes(doc.as_bytes());
        assert!(matches!(
            OpMsg::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidOpMsg(
                "kind 0 section must be the first section"
            ))
        ));
    }

    #[test]
    fn parse_rejects_unknown_section_kinds() {
        for kind in [2u8, 3, 7, 255] {
            let mut buf = BytesMut::new();
            buf.put_u32_le(0); // flags
            buf.put_u8(kind);
            buf.put_bytes(raw([("hello", Bson::Int32(1))]).as_bytes());
            assert!(
                matches!(
                    OpMsg::parse_body(buf.freeze()),
                    Err(ProtocolError::InvalidOpMsg("unknown section kind"))
                ),
                "kind={kind}"
            );
        }
    }

    #[test]
    fn parse_rejects_empty_identifier() {
        // A kind-1 section whose identifier is just the NUL byte: parses
        // structurally (the empty document fills the section) but violates
        // the identifier invariant in `Sections::new`.
        let mut buf = BytesMut::new();
        buf.put_u32_le(0); // flags
        buf.put_u8(0);
        buf.put_bytes(raw([("hello", Bson::Int32(1))]).as_bytes());
        buf.put_u8(1);
        buf.put_u32_le(4 + 1 + 5);
        buf.put_u8(0); // empty identifier
        buf.put_bytes(&[5, 0, 0, 0, 0]); // the empty document
        assert!(matches!(
            OpMsg::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidOpMsg("kind 1 section has no identifier"))
        ));
    }

    #[test]
    fn sections_new_rejects_empty_and_nul_identifiers() {
        let doc = raw([("hello", Bson::Int32(1))]);
        assert!(matches!(
            Sections::new(
                doc.clone(),
                vec![DocumentSequence { identifier: String::new(), documents: vec![] }]
            ),
            Err(ProtocolError::InvalidOpMsg("kind 1 section has no identifier"))
        ));
        assert!(matches!(
            Sections::new(
                doc,
                vec![DocumentSequence { identifier: "a\0b".to_owned(), documents: vec![] }]
            ),
            Err(ProtocolError::InvalidOpMsg("kind 1 identifier contains NUL"))
        ));
    }

    #[test]
    fn identifier_must_not_duplicate_a_body_field() {
        let body = raw([("insert", Bson::from("actor")), ("documents", Bson::Null)]);
        assert!(matches!(
            Sections::new(
                body,
                vec![DocumentSequence {
                    identifier: "documents".to_owned(),
                    documents: vec![raw([("a", Bson::Int32(1))])],
                }]
            ),
            Err(ProtocolError::InvalidOpMsg(
                "kind 1 identifier duplicates a body field"
            ))
        ));
    }

    #[test]
    fn parse_rejects_truncated_and_overrun_sections() {
        let doc = raw([("hello", Bson::Int32(1))]);
        let good = body_bytes(0, &doc, "documents", std::slice::from_ref(&doc));

        // Every prefix must parse-or-error without panicking; the only valid
        // prefix is the one ending right after the kind-0 section.
        let kind0_end = 4 + 1 + doc.len();
        for n in 0..good.len() {
            let result = OpMsg::parse_body(good.slice(..n));
            assert!(result.is_ok() == (n == kind0_end), "n={n}: {result:?}");
        }

        // A section size larger than the remaining body.
        let mut buf = BytesMut::new();
        buf.put_u32_le(0); // flags
        buf.put_u8(0);
        buf.put_bytes(doc.as_bytes());
        buf.put_u8(1);
        buf.put_u32_le((4 + "documents".len() + 1 + 1024) as u32);
        buf.put_bytes(b"documents");
        buf.put_u8(0);
        buf.put_bytes(doc.as_bytes());
        assert!(matches!(
            OpMsg::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidOpMsg("section exceeds the message"))
        ));

        // A document straddling the section end: its length prefix claims
        // more bytes than the section leaves.
        let mut buf = BytesMut::new();
        buf.put_u32_le(0); // flags
        buf.put_u8(0);
        buf.put_bytes(doc.as_bytes());
        buf.put_u8(1);
        buf.put_u32_le((4 + "documents".len() + 1 + 8) as u32);
        buf.put_bytes(b"documents");
        buf.put_u8(0);
        buf.put_u32_le(19); // a document header claiming 19 of the 8 left
        buf.put_bytes(&[0u8; 8]);
        assert!(matches!(
            OpMsg::parse_body(buf.freeze()),
            Err(ProtocolError::InvalidOpMsg("invalid document length"))
        ));
    }

    #[test]
    fn body_too_short_errors() {
        for n in 0..6 {
            let buf = BytesMut::from(&vec![0u8; n][..]);
            assert!(
                matches!(
                    OpMsg::parse_body(buf.freeze()),
                    Err(ProtocolError::InvalidOpMsg("body too short for OP_MSG"))
                ),
                "n={n}"
            );
        }
    }

    #[test]
    fn flags_parse_rejects_unknown_required_bits() {
        // Bit 15 is the highest required bit; unknown lower bits error.
        assert!(matches!(
            MsgFlags::parse(1 << 15),
            Err(ProtocolError::InvalidOpMsg("unknown required flag bits"))
        ));
        // The flagBits of tests/data/msg_fuzz1.hex.
        assert!(matches!(
            MsgFlags::parse(0x3030_3030),
            Err(ProtocolError::InvalidOpMsg("unknown required flag bits"))
        ));
        // Unknown required bits error even next to known ones.
        assert!(matches!(
            MsgFlags::parse(MsgFlags::MORE_TO_COME.bits() | 1 << 4),
            Err(ProtocolError::InvalidOpMsg("unknown required flag bits"))
        ));
    }

    #[test]
    fn flags_parse_clears_unknown_optional_bits() {
        // Bits 16-31: unknown set bits are silently cleared ...
        assert_eq!(MsgFlags::parse(1 << 17).unwrap(), MsgFlags::empty());
        // ... while known ones (like exhaustAllowed, bit 16) are preserved.
        assert_eq!(
            MsgFlags::parse(MsgFlags::EXHAUST_ALLOWED.bits() | 1 << 17).unwrap(),
            MsgFlags::EXHAUST_ALLOWED
        );
    }

    #[test]
    fn more_to_come_roundtrip() {
        let msg =
            OpMsg::new(MsgFlags::MORE_TO_COME, raw([("ping", Bson::Int32(1))]), vec![]).unwrap();
        let parsed = OpMsg::parse_body(encoded(&msg)).unwrap();
        assert_eq!(parsed.flags, MsgFlags::MORE_TO_COME);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn new_strips_checksum_flag() {
        // Constructed messages carry no checksum value, so the flag must not
        // claim one (invariant: checksum.is_some() == flag set).
        let msg = OpMsg::new(
            MsgFlags::CHECKSUM_PRESENT | MsgFlags::MORE_TO_COME,
            raw([("ping", Bson::Int32(1))]),
            vec![],
        )
        .unwrap();
        assert_eq!(msg.flags, MsgFlags::MORE_TO_COME);
        assert_eq!(msg.checksum, None);
    }

    #[test]
    fn checksum_roundtrip_and_body_len() {
        // Hand-build a checksummed body: flags with the bit set + trailer.
        let doc = raw([("hello", Bson::Int32(1))]);
        let mut buf = BytesMut::new();
        buf.put_u32_le(MsgFlags::CHECKSUM_PRESENT.bits());
        buf.put_u8(0);
        buf.put_bytes(doc.as_bytes());
        buf.put_u32_le(0xdead_beef);
        let body = buf.freeze();

        let parsed = OpMsg::parse_body(body.clone()).unwrap();
        assert_eq!(parsed.flags, MsgFlags::CHECKSUM_PRESENT);
        assert_eq!(parsed.checksum, Some(0xdead_beef));
        // body_len includes the trailer.
        assert_eq!(parsed.body_len(), body.len());
        assert_eq!(parsed.body_len(), encoded(&parsed).len());

        // The value round-trips byte-exactly; validation is framing's job.
        let re_encoded = encoded(&parsed);
        assert_eq!(re_encoded, body);
        assert_eq!(OpMsg::parse_body(re_encoded).unwrap(), parsed);
    }

    #[test]
    fn sections_fill_the_body_exactly() {
        let msg = OpMsg::new(
            MsgFlags::empty(),
            raw([("insert", Bson::from("actor"))]),
            vec![DocumentSequence {
                identifier: "documents".to_owned(),
                documents: vec![raw([("a", Bson::Int32(1))])],
            }],
        )
        .unwrap();
        assert_eq!(msg.body_len(), 4 + msg.sections.size());
        assert_eq!(OpMsg::parse_body(encoded(&msg)).unwrap(), msg);
    }

    #[test]
    fn documents_are_zero_copy_views_of_the_body() {
        let msg = OpMsg::new(MsgFlags::empty(), raw([("hello", Bson::Int32(1))]), vec![]).unwrap();
        let body = encoded(&msg);
        let parsed = OpMsg::parse_body(body.clone()).unwrap();
        // 4 (flags) + 1 (kind) is where the document starts.
        assert_eq!(
            parsed.document().as_bytes().as_ptr() as usize,
            body.as_ptr() as usize + 5
        );
    }

    #[test]
    fn short_checksummed_bodies_error_instead_of_panicking() {
        // A checksummed body needs flags + kind + a document + the 4-byte
        // trailer; bodies of 6..=9 bytes once drove `end - offset` negative
        // (22-byte frames panicked remotely — review finding).
        for body_len in 5usize..=9 {
            let mut body = vec![0x01, 0x00, 0x00, 0x00]; // checksumPresent
            body.resize(body_len, 0xAB);
            let result = OpMsg::parse_body(Bytes::from(body));
            assert!(result.is_err(), "body_len={body_len} must not parse");
        }
    }
}
