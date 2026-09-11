//! Frame parsing/encoding over `BytesMut`: header, length limits, checksum.
//!
//! State functions, so they are directly testable against golden bytes and
//! fuzzable without tokio (the `server` codec is a thin wrapper).

use bytes::{Bytes, BytesMut};

use mongo_common::consts::{msg_flags, MAX_MSG_LEN, MSG_HEADER_LEN};

use crate::error::ProtocolError;
use crate::messages::{Header, MessageBody, Opcode};

/// Parse one complete message from `buf`, consuming its bytes.
///
/// * Returns `Ok(None)` if `buf` does not yet hold a full message (needs more
///   data); nothing is consumed.
/// * Validates the header (length bounds, known opcode) and — for OP_MSG
///   with `checksumPresent` — the CRC-32C over header+body-minus-checksum
///   before returning.
///
/// # Errors
/// [`ProtocolError`] on malformed input; the caller must close the
/// connection.
pub fn parse_message(
    buf: &mut BytesMut,
    max_len: i32,
) -> Result<Option<(Header, MessageBody)>, ProtocolError> {
    if buf.len() < MSG_HEADER_LEN {
        // Not even a length prefix to peek yet.
        return Ok(None);
    }
    // Validate the header as soon as its 16 bytes have arrived, so absurd
    // lengths and unknown opcodes fail fast instead of buffering a huge body.
    let header = Header::parse(&buf[..MSG_HEADER_LEN], max_len)?;
    let message_length = header.message_length as usize; // >= MSG_HEADER_LEN
    if buf.len() < message_length {
        // Incomplete frame: wait for more data, consume nothing.
        return Ok(None);
    }
    // For OP_MSG with `checksumPresent`, verify the CRC-32C against the
    // trailing 4 bytes before the frame is consumed: the checksum covers the
    // 16 header bytes plus the body without its trailer (Go reference
    // `msg_body.go` `validateChecksum`). A frame claiming `checksumPresent`
    // but too short to hold flags + kind + a minimum body document + the
    // trailer (header + 10) can never be valid — reject it here rather than
    // delegating to the body parser (defense in depth; found by review).
    if header.op_code == Opcode::Msg
        && (MSG_HEADER_LEN + 4..MSG_HEADER_LEN + 10).contains(&message_length)
        && u32::from_le_bytes(
            buf[MSG_HEADER_LEN..MSG_HEADER_LEN + 4].try_into().expect("length checked above"),
        ) & mongo_common::consts::msg_flags::CHECKSUM_PRESENT
            != 0
    {
        return Err(ProtocolError::InvalidOpMsg(
            "frame too short for a checksummed OP_MSG",
        ));
    }
    if header.op_code == Opcode::Msg && message_length >= MSG_HEADER_LEN + 8 {
        let frame = &buf[..message_length];
        let flag_bits = u32::from_le_bytes(
            frame[MSG_HEADER_LEN..MSG_HEADER_LEN + 4].try_into().expect("length checked above"),
        );
        if flag_bits & msg_flags::CHECKSUM_PRESENT != 0 {
            let expected = u32::from_le_bytes(
                frame[message_length - 4..].try_into().expect("length checked above"),
            );
            let computed = mongo_common::crc32c::checksum(&frame[..message_length - 4]);
            if computed != expected {
                return Err(ProtocolError::ChecksumMismatch { expected, computed });
            }
        }
    }
    // Consume exactly one frame. The body-parse error below still leaves the
    // frame consumed (the caller closes the connection on any protocol error).
    let mut frame = freeze(buf, message_length);
    let body_bytes = frame.split_off(MSG_HEADER_LEN);
    let body = MessageBody::parse_body(header.op_code, body_bytes)?;
    Ok(Some((header, body)))
}

/// Encode a full message (header + body, plus checksum when `checksum`).
///
/// [`Header::message_length`] is computed here and returned in the result.
///
/// # Errors
/// [`ProtocolError::MessageTooLarge`] if the total exceeds `MAX_MSG_LEN`.
pub fn encode_message(
    header: &mut Header,
    body: &MessageBody,
    checksum: bool,
    out: &mut BytesMut,
) -> Result<(), ProtocolError> {
    let total = MSG_HEADER_LEN + body.body_len() + usize::from(checksum) * 4;
    // Guard the `usize -> i32` narrowing before comparing with `MAX_MSG_LEN`.
    let total = i32::try_from(total).map_err(|_| ProtocolError::MessageTooLarge {
        size: i32::MAX,
        max: MAX_MSG_LEN,
    })?;
    if total > MAX_MSG_LEN {
        return Err(ProtocolError::MessageTooLarge {
            size: total,
            max: MAX_MSG_LEN,
        });
    }
    header.message_length = total;
    out.reserve(total as usize);
    let start = out.len();
    header.encode(out);
    body.encode_body(out);
    if checksum {
        // The length above already accounts for the 4-byte trailer.
        //
        // An OP_MSG receiver locates the trailer via the `checksumPresent`
        // flag bit, so that bit must be set in the encoded `flagBits` for
        // the trailer to be seen. Freshly built `OpMsg` values carry no
        // checksum value (see `OpMsg::new`), so patch the bit into the wire
        // bytes here — before computing the CRC-32C over header+body, which
        // must cover the flags as finally written.
        if let MessageBody::Msg(msg) = body {
            // The trailer is appended here; a body that already carries one
            // (e.g. a re-encoded *parsed* message) would end up with two, so
            // reject it instead of asserting (found by review).
            if msg.checksum.is_some() {
                return Err(ProtocolError::InvalidOpMsg(
                    "body already carries a checksum trailer",
                ));
            }
            let flags_at = start + MSG_HEADER_LEN;
            let flag_bits = u32::from_le_bytes(
                out[flags_at..flags_at + 4].try_into().expect("flags just written"),
            ) | msg_flags::CHECKSUM_PRESENT;
            out[flags_at..flags_at + 4].copy_from_slice(&flag_bits.to_le_bytes());
        }
        let computed = mongo_common::crc32c::checksum(&out[start..]);
        out.extend_from_slice(&computed.to_le_bytes());
    }
    Ok(())
}

/// Freeze a fully received message region as zero-copy `Bytes`.
pub(crate) fn freeze(buf: &mut BytesMut, len: usize) -> Bytes {
    buf.split_to(len).freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{Opcode, OpQuery, OpReply, QueryFlags, ReplyFlags};
    use wirebson::{Bson, Document};

    const HANDSHAKE_QUERY: [&str; 2] = ["handshake1_header.hex", "handshake1_body.hex"];

    /// Parse a standard hexdump (offset, hex bytes, ASCII column) back to
    /// bytes. Lines may omit the ASCII column.
    fn hexdump(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for line in s.lines() {
            // Everything from the first '|' on is the ASCII column.
            let hex = line.split('|').next().unwrap_or_default();
            let mut tokens = hex.split_whitespace();
            match tokens.next() {
                // Skip the 8-hex-digit offset column when present.
                Some(off) if off.len() == 8 && off.bytes().all(|b| b.is_ascii_hexdigit()) => {}
                Some(tok) => out.push(u8::from_str_radix(tok, 16).unwrap()),
                None => continue,
            }
            for tok in tokens {
                out.push(u8::from_str_radix(tok, 16).unwrap());
            }
        }
        out
    }

    /// Read a recorded hexdump from `tests/data`.
    fn recorded(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/").to_owned() + name;
        hexdump(&std::fs::read_to_string(path).unwrap())
    }

    /// A full recorded frame: 16-byte header followed by the body.
    fn recorded_frame(parts: &[&str]) -> Vec<u8> {
        let mut frame = Vec::new();
        for part in parts {
            frame.extend_from_slice(&recorded(part));
        }
        frame
    }

    #[test]
    fn hexdump_parser_handles_both_column_layouts() {
        assert_eq!(
            hexdump("00000000  74 01 00 00  |t...|"),
            vec![0x74, 0x01, 0x00, 0x00]
        );
        // Last line of a dump has no ASCII column.
        assert_eq!(hexdump("00000164  64 00 00 00"), vec![0x64, 0x00, 0x00, 0x00]);
        assert!(hexdump("").is_empty());
    }

    #[test]
    fn incomplete_frames_wait_and_consume_nothing() {
        let frame = recorded_frame(&HANDSHAKE_QUERY);
        for n in [0, 1, 4, 15, 16, 17, 100, frame.len() - 1] {
            let mut buf = BytesMut::from(&frame[..n]);
            let before = buf.clone();
            assert!(matches!(parse_message(&mut buf, MAX_MSG_LEN), Ok(None)), "n={n}");
            assert_eq!(&buf[..], &before[..], "n={n}");
        }
    }

    #[test]
    fn handshake1_op_query_golden() {
        let frame = recorded_frame(&HANDSHAKE_QUERY);
        let mut buf = BytesMut::from(&frame[..]);
        let (header, body) = parse_message(&mut buf, MAX_MSG_LEN).unwrap().unwrap();
        assert!(buf.is_empty(), "the whole frame must be consumed");

        // messageLength=0x174=372, requestID=1, responseTo=0, opCode=OP_QUERY.
        assert_eq!(header.message_length, 0x174);
        assert_eq!(header.request_id, 1);
        assert_eq!(header.response_to, 0);
        assert_eq!(header.op_code, Opcode::Query);

        let MessageBody::Query(q) = &body else {
            panic!("expected a Query body, got {:?}", body)
        };
        assert_eq!(q.flags, QueryFlags::empty());
        assert_eq!(q.full_collection_name, "admin.$cmd");
        assert_eq!(q.number_to_skip, 0);
        assert_eq!(q.number_to_return, -1);
        assert!(q.return_fields_selector.is_none());
        let query = q.query.shallow().unwrap();
        // The nodejs 4.0-beta driver sends the (lowercase) `ismaster` command.
        assert_eq!(query.command(), Some("ismaster"));
        assert_eq!(query.get("ismaster"), Some(&Bson::Bool(true)));

        // Re-encode: byte-exact equality with the recorded traffic.
        let mut out = BytesMut::new();
        let mut header = header;
        encode_message(&mut header, &body, false, &mut out).unwrap();
        assert_eq!(&out[..], &frame[..]);
    }

    #[test]
    fn handshake2_op_reply_golden() {
        let frame = recorded_frame(&["handshake2_header.hex", "handshake2_body.hex"]);
        let mut buf = BytesMut::from(&frame[..]);
        let (header, body) = parse_message(&mut buf, MAX_MSG_LEN).unwrap().unwrap();

        assert_eq!(header.message_length, 0x13f);
        assert_eq!(header.request_id, 0x122);
        assert_eq!(header.response_to, 1);
        assert_eq!(header.op_code, Opcode::Reply);

        let MessageBody::Reply(r) = &body else {
            panic!("expected a Reply body, got {:?}", body)
        };
        assert_eq!(r.response_flags, ReplyFlags::AWAIT_CAPABLE);
        assert_eq!(r.cursor_id, 0);
        assert_eq!(r.starting_from, 0);
        assert_eq!(r.number_returned, 1);
        assert_eq!(r.documents.len(), 1);
        assert_eq!(r.documents[0].command().unwrap(), "ismaster");
        assert_eq!(r.documents[0].shallow().unwrap().get("ok"), Some(&Bson::Double(1.0)));

        let mut out = BytesMut::new();
        let mut header = header;
        encode_message(&mut header, &body, false, &mut out).unwrap();
        assert_eq!(&out[..], &frame[..]);
    }

    #[test]
    fn handshake3_and_4_are_the_retry_exchange() {
        // handshake3 is handshake1 re-sent with requestID=2 ...
        let frame = recorded_frame(&["handshake3_header.hex", "handshake3_body.hex"]);
        let mut buf = BytesMut::from(&frame[..]);
        let (header, body) = parse_message(&mut buf, MAX_MSG_LEN).unwrap().unwrap();
        assert_eq!(
            header,
            Header {
                message_length: 372,
                request_id: 2,
                response_to: 0,
                op_code: Opcode::Query
            }
        );
        let mut out = BytesMut::new();
        let mut header = header;
        encode_message(&mut header, &body, false, &mut out).unwrap();
        assert_eq!(&out[..], &frame[..]);

        // ... and handshake4 is its OP_REPLY (responseTo=2).
        let frame = recorded_frame(&["handshake4_header.hex", "handshake4_body.hex"]);
        let mut buf = BytesMut::from(&frame[..]);
        let (header, body) = parse_message(&mut buf, MAX_MSG_LEN).unwrap().unwrap();
        assert_eq!(
            header,
            Header {
                message_length: 319,
                request_id: 0x123,
                response_to: 2,
                op_code: Opcode::Reply
            }
        );
        assert!(matches!(body, MessageBody::Reply(_)));
        let mut out = BytesMut::new();
        let mut header = header;
        encode_message(&mut header, &body, false, &mut out).unwrap();
        assert_eq!(&out[..], &frame[..]);
    }

    #[test]
    fn handshake5_and_6_headers_are_op_msg() {
        // handshake5/6 are OP_MSG (opcode 2013) exchanges; their bodies are
        // covered by Agent E's golden suite once `OpMsg::parse_body` lands.
        for name in ["handshake5_header.hex", "handshake6_header.hex"] {
            let header_bytes = recorded(name);
            let header = Header::parse(&header_bytes, MAX_MSG_LEN).unwrap();
            assert_eq!(header.op_code, Opcode::Msg, "{name}");
        }
        assert_eq!(
            &recorded("handshake5_header.hex")[..4],
            &92i32.to_le_bytes()[..]
        );
    }

    #[test]
    fn frames_feed_incrementally() {
        let frame = recorded_frame(&HANDSHAKE_QUERY);
        let mut buf = BytesMut::new();
        let mut parsed = None;
        for chunk in frame.chunks(7) {
            buf.extend_from_slice(chunk);
            if let Some(msg) = parse_message(&mut buf, MAX_MSG_LEN).unwrap() {
                parsed = Some(msg);
            }
        }
        let (header, _) = parsed.expect("the frame must eventually parse");
        assert_eq!(header.message_length, 372);
        assert!(buf.is_empty(), "trailing bytes must not be consumed");
    }

    #[test]
    fn body_parse_error_consumes_the_frame() {
        // OP_QUERY header claiming a 21-byte message whose body carries an
        // empty fullCollectionName: the frame is consumed even though parsing
        // fails.
        let mut frame = Vec::from(21i32.to_le_bytes());
        frame.extend_from_slice(&1i32.to_le_bytes());
        frame.extend_from_slice(&0i32.to_le_bytes());
        frame.extend_from_slice(&2004i32.to_le_bytes());
        // OP_QUERY body: flags = 0, then an empty (immediate NUL) cstring.
        frame.extend_from_slice(&[0, 0, 0, 0, 0]);
        let mut buf = BytesMut::from(&frame[..]);
        assert!(matches!(
            parse_message(&mut buf, MAX_MSG_LEN),
            Err(ProtocolError::InvalidBody("empty fullCollectionName"))
        ));
        assert!(buf.is_empty(), "the broken frame must still be consumed");
    }

    #[test]
    fn absurd_length_fails_fast_without_the_body() {
        let mut buf = BytesMut::from(&(MAX_MSG_LEN + 1).to_le_bytes()[..]);
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&2004i32.to_le_bytes());
        assert!(matches!(
            parse_message(&mut buf, MAX_MSG_LEN),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn negative_length_is_a_protocol_error() {
        let mut buf = BytesMut::from(&(-1i32).to_le_bytes()[..]);
        buf.extend_from_slice(&[0; 12]);
        assert!(matches!(
            parse_message(&mut buf, MAX_MSG_LEN),
            Err(ProtocolError::InvalidHeader(_))
        ));
    }

    fn raw(pairs: impl IntoIterator<Item = (&'static str, Bson)>) -> wirebson::RawDocument {
        Document::from_iter(pairs).encode().unwrap()
    }

    #[test]
    fn encode_sets_message_length_and_roundtrips() {
        let q = OpQuery::handshake(raw([("isMaster", Bson::Int32(1))]));
        let body = MessageBody::Query(q.clone());
        let mut header = Header::new(42, 0, Opcode::Query);
        let mut out = BytesMut::new();
        encode_message(&mut header, &body, false, &mut out).unwrap();
        assert_eq!(header.message_length, (16 + body.body_len()) as i32);
        let written_length = i32::from_le_bytes(out[..4].try_into().unwrap());
        assert_eq!(written_length, header.message_length);

        let (header2, body2) = parse_message(&mut out, MAX_MSG_LEN).unwrap().unwrap();
        assert_eq!(header2.request_id, 42);
        assert_eq!(header2.message_length, header.message_length);
        let MessageBody::Query(q2) = &body2 else {
            panic!("expected a Query body, got {:?}", body2)
        };
        assert_eq!(q2, &q);
    }

    #[test]
    fn encode_rejects_oversize_and_leaves_out_untouched() {
        // A structurally valid (all-zero fields) document of exactly
        // MAX_MSG_LEN bytes: header + OP_REPLY fixed part push the total over.
        let max = MAX_MSG_LEN as usize;
        let mut doc = vec![0u8; max];
        doc[..4].copy_from_slice(&(max as u32).to_le_bytes());
        let body = MessageBody::Reply(OpReply {
            response_flags: ReplyFlags::empty(),
            cursor_id: 0,
            starting_from: 0,
            number_returned: 1,
            documents: vec![wirebson::RawDocument::from_vec(doc).unwrap()],
        });
        let mut header = Header::new(1, 0, Opcode::Reply);
        let mut out = BytesMut::new();
        assert!(matches!(
            encode_message(&mut header, &body, false, &mut out),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
        assert!(out.is_empty());
    }

    /// A checksummed OP_MSG ready for `encode_message(checksum = true)`.
    fn checksummed_msg() -> (Header, MessageBody) {
        let doc = raw([("ping", Bson::Int32(1))]);
        let msg = crate::messages::OpMsg::new(
            crate::messages::MsgFlags::MORE_TO_COME,
            doc,
            Vec::new(),
        )
        .unwrap();
        (Header::new(7, 0, Opcode::Msg), MessageBody::Msg(msg))
    }

    #[test]
    fn checksum_encoding_roundtrips() {
        let (mut header, body) = checksummed_msg();
        let mut out = BytesMut::new();
        encode_message(&mut header, &body, true, &mut out).unwrap();

        // message_length includes the header, the body and the trailer; the
        // trailer is exactly the CRC-32C of everything before it.
        assert_eq!(header.message_length as usize, out.len());
        let written_len = i32::from_le_bytes(out[..4].try_into().unwrap());
        assert_eq!(written_len, header.message_length);
        let expected_checksum = mongo_common::crc32c::checksum(&out[..out.len() - 4]);
        assert_eq!(
            u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap()),
            expected_checksum
        );

        // The receiver sees the flag, the checksum value and the message.
        let (header2, body2) = parse_message(&mut out, MAX_MSG_LEN).unwrap().unwrap();
        assert!(out.is_empty(), "the whole frame must be consumed");
        assert_eq!(header2.message_length, header.message_length);
        let MessageBody::Msg(msg) = &body2 else {
            panic!("expected a Msg body, got {body2:?}")
        };
        assert_eq!(msg.flags, crate::messages::MsgFlags::CHECKSUM_PRESENT | crate::messages::MsgFlags::MORE_TO_COME);
        assert_eq!(msg.checksum, Some(expected_checksum));
        assert_eq!(msg.document(), &raw([("ping", Bson::Int32(1))]));
    }

    #[test]
    fn corrupt_trailer_byte_fails_checksum() {
        let (mut header, body) = checksummed_msg();
        let mut out = BytesMut::new();
        encode_message(&mut header, &body, true, &mut out).unwrap();
        let expected = u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap());

        let last = out.len() - 1;
        out[last] ^= 0x01;
        // The computed value is the original checksum; the stored (corrupted)
        // one differs from it.
        assert!(matches!(
            parse_message(&mut out, MAX_MSG_LEN),
            Err(ProtocolError::ChecksumMismatch { expected: e, computed: c })
            if e != expected && c == expected
        ));
    }

    #[test]
    fn corrupt_body_byte_fails_checksum() {
        let (mut header, body) = checksummed_msg();
        let mut out = BytesMut::new();
        encode_message(&mut header, &body, true, &mut out).unwrap();
        let expected = u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap());

        // Flip a bit in the middle of the body document (after the 20 header
        // + flags bytes, before the 4 trailer bytes).
        let mid = out.len() - 5;
        out[mid] ^= 0x80;
        assert!(matches!(
            parse_message(&mut out, MAX_MSG_LEN),
            Err(ProtocolError::ChecksumMismatch { expected: e, computed: c })
            if e == expected && c != expected
        ));
    }

    #[test]
    fn checksummed_frames_feed_incrementally() {
        let (mut header, body) = checksummed_msg();
        let mut frame = BytesMut::new();
        encode_message(&mut header, &body, true, &mut frame).unwrap();

        let mut buf = BytesMut::new();
        let mut parsed = None;
        for chunk in frame.chunks(5) {
            buf.extend_from_slice(chunk);
            if let Some(msg) = parse_message(&mut buf, MAX_MSG_LEN).unwrap() {
                parsed = Some(msg);
            }
        }
        let (header, body) = parsed.expect("the frame must eventually parse");
        assert_eq!(header.op_code, Opcode::Msg);
        assert!(matches!(body, MessageBody::Msg(m) if m.checksum.is_some()));
        assert!(buf.is_empty());
    }

    #[test]
    fn non_msg_bodies_take_the_trailer_without_flag_patch() {
        // Only OP_MSG carries flagBits; for other opcodes the trailer is
        // simply appended (checksums are an OP_MSG feature, but the encoder
        // stays generic).
        let reply = OpReply {
            response_flags: ReplyFlags::empty(),
            cursor_id: 0,
            starting_from: 0,
            number_returned: 0,
            documents: Vec::new(),
        };
        let body = MessageBody::Reply(reply);
        let mut header = Header::new(1, 0, Opcode::Reply);
        let mut out = BytesMut::new();
        encode_message(&mut header, &body, true, &mut out).unwrap();
        assert_eq!(header.message_length as usize, out.len());
        let expected = mongo_common::crc32c::checksum(&out[..out.len() - 4]);
        assert_eq!(
            u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap()),
            expected
        );
    }

    #[test]
    fn short_checksummed_frame_is_rejected_not_panicked() {
        // The exact packet the correctness review used to trigger a panic:
        // messageLength=22, checksumPresent, kind 0 + 1 pad byte. It skips
        // checksum validation (too short to hold a trailer) and must be
        // rejected cleanly by the body parser / framing guard.
        let mut frame = Vec::new();
        frame.extend_from_slice(&22i32.to_le_bytes()); // messageLength
        frame.extend_from_slice(&1i32.to_le_bytes()); // requestID
        frame.extend_from_slice(&0i32.to_le_bytes()); // responseTo
        frame.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
        frame.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // checksumPresent
        frame.extend_from_slice(&[0x00]); // kind 0
        frame.extend_from_slice(&[0xAB]); // pad
        assert_eq!(frame.len(), 22);
        let mut buf = BytesMut::from(&frame[..]);
        assert!(matches!(
            parse_message(&mut buf, MAX_MSG_LEN),
            Err(ProtocolError::InvalidOpMsg(_))
        ));
        // Guard errors fire before the frame is consumed; the caller closes
        // the connection on any protocol error, so that is fine.
        let _ = buf;
    }

    #[test]
    fn trailing_bytes_after_op_query_selector_are_rejected_end_to_end() {
        // query + selector parse cleanly; a further document after the
        // selector is trailing garbage and must error (never panic, never be
        // silently dropped).
        let q = OpQuery {
            full_collection_name: "admin.$cmd".to_owned(),
            query: Document::from_iter([("isMaster", Bson::Bool(true))])
                .encode()
                .unwrap(),
            return_fields_selector: Some(
                Document::from_iter([("_id", Bson::Int32(1))]).encode().unwrap(),
            ),
            ..OpQuery::handshake(Document::new().encode().unwrap())
        };
        let body = MessageBody::Query(q);
        let mut frame = BytesMut::new();
        let mut header = Header::new(1, 0, Opcode::Query);
        encode_message(&mut header, &body, false, &mut frame).unwrap();
        // A minimal valid document `{}` appended after the selector. The
        // attacker controls the header too, so grow the declared
        // messageLength to swallow it — the trailing check must then fire
        // (appending bytes OUTSIDE the declared frame would just be the next
        // frame's prefix).
        frame.extend_from_slice(&[0x05, 0x00, 0x00, 0x00, 0x00]);
        let grown = header.message_length + 5;
        frame[..4].copy_from_slice(&grown.to_le_bytes());

        let mut buf = BytesMut::from(&frame[..]);
        assert!(matches!(
            parse_message(&mut buf, MAX_MSG_LEN),
            Err(ProtocolError::InvalidBody(
                "trailing bytes after returnFieldsSelector"
            ))
        ));
    }

}
