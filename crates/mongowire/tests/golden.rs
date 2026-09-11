//! Golden tests against FerretDB/wire's recorded hex dumps
//! (`tests/data/*.hex`, copied from `reference/wire/testdata`).
//!
//! `handshake{1..6}_{header,body}.hex` are single messages split into their
//! 16-byte header and body (`hexdump -C` layout); `import.hex` and
//! `msg_fuzz1.hex` are full frames — header and body concatenated in one
//! file (`xxd` layout). Every parse here goes through
//! [`mongowire::framing::parse_message`], i.e. exactly the path production
//! traffic takes, and every valid message is re-encoded byte-exactly.

use bytes::{BytesMut};

use mongo_common::consts::{MAX_MSG_LEN, MSG_HEADER_LEN};
use mongowire::framing;
use mongowire::messages::{Header, MessageBody, Opcode};
use mongowire::{DocumentSequence, Message, MsgFlags, OpMsg, ProtocolError};
use wirebson::{Bson, RawDocument};

/// Parse a standard hexdump back to bytes.
///
/// Handles both layouts found in `tests/data`: the `hexdump -C` layout
/// (8-digit offset column, `|ASCII|` column) and the `xxd` layout (4-digit
/// offset column, bare ASCII column). Data tokens are always exactly two hex
/// digits; parsing a line stops at the first token that is not, which skips
/// the offset (4 or 8 digits) and the ASCII column.
fn hexdump(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in s.lines() {
        let mut tokens = line.split_whitespace();
        match tokens.next() {
            // Skip the offset column when present (4 or 8 hex digits).
            Some(off) if matches!(off.len(), 4 | 8) && off.bytes().all(|b| b.is_ascii_hexdigit()) => {}
            Some(tok) => {
                push_byte(&mut out, tok);
            }
            None => continue,
        }
        for tok in tokens {
            if !push_byte(&mut out, tok) {
                break; // reached the ASCII column
            }
        }
    }
    out
}

/// Append `tok` if it is a 2-digit hex byte; report whether to continue.
fn push_byte(out: &mut Vec<u8>, tok: &str) -> bool {
    if tok.len() == 2 && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
        out.push(u8::from_str_radix(tok, 16).unwrap());
        true
    } else {
        false
    }
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

/// Parse exactly one message from `frame`.
fn parse_frame(frame: &[u8]) -> (Header, MessageBody) {
    let mut buf = BytesMut::from(frame);
    let (header, body) = framing::parse_message(&mut buf, MAX_MSG_LEN)
        .unwrap_or_else(|e| panic!("frame of {} bytes must parse: {e}", frame.len()))
        .unwrap_or_else(|| panic!("frame of {} bytes must be complete", frame.len()));
    assert!(buf.is_empty(), "the whole frame must be consumed");
    (header, body)
}

/// Re-encode a parsed message and require byte-exact equality with the
/// recorded traffic (checksums are only re-verified, never recomputed, for
/// already-checksummed messages, so `checksum = false` is the faithful mode).
fn assert_reencodes_byte_exactly(header: Header, body: &MessageBody, frame: &[u8]) {
    let mut out = BytesMut::new();
    let mut header = header;
    framing::encode_message(&mut header, body, false, &mut out).unwrap();
    assert_eq!(out.as_ref(), frame, "re-encoded message must be byte-exact");
}

/// The body of an OP_MSG message, and its sections.
fn expect_msg(body: MessageBody) -> OpMsg {
    let MessageBody::Msg(msg) = body else {
        panic!("expected an OP_MSG body, got {body:?}")
    };
    msg
}

#[test]
fn handshake5_op_msg_golden() {
    let frame = recorded_frame(&["handshake5_header.hex", "handshake5_body.hex"]);
    assert_eq!(frame.len(), 92);
    let (header, body) = parse_frame(&frame);

    // messageLength=0x5c=92, requestID=3, responseTo=0, opCode=OP_MSG.
    assert_eq!(
        header,
        Header {
            message_length: 92,
            request_id: 3,
            response_to: 0,
            op_code: Opcode::Msg
        }
    );

    let msg = expect_msg(body);
    // flagBits = 0: no checksumPresent, no moreToCome, and no checksum value.
    assert_eq!(msg.flags, MsgFlags::empty());
    assert_eq!(msg.checksum, None);
    assert!(msg.sections.sequences.is_empty(), "a single kind-0 section");

    // The command document: `{buildInfo: 1, lsid: {...}, $db: "admin"}` —
    // a 4.4+ `buildInfo` handshake over OP_MSG.
    let doc = msg.document();
    assert_eq!(doc.command().unwrap(), "buildInfo");
    assert_eq!(doc.get("buildInfo").unwrap().unwrap().to_bson().unwrap(), Bson::Int32(1));
    assert_eq!(doc.get("$db").unwrap().unwrap().to_bson().unwrap(), Bson::String("admin".into()));
    assert!(
        matches!(
            doc.get("lsid").unwrap().unwrap().to_bson().unwrap(),
            Bson::Document(_)
        ),
        "lsid carries the session id"
    );

    assert_reencodes_byte_exactly(header, &MessageBody::Msg(msg), &frame);
}

#[test]
fn handshake6_op_msg_golden() {
    let frame = recorded_frame(&["handshake6_header.hex", "handshake6_body.hex"]);
    assert_eq!(frame.len(), 1931);
    let (header, body) = parse_frame(&frame);

    // messageLength=0x78b=1931, requestID=0x124=292, responseTo=3 — the
    // reply to handshake5's requestID=3 — opCode=OP_MSG.
    assert_eq!(
        header,
        Header {
            message_length: 1931,
            request_id: 292,
            response_to: 3,
            op_code: Opcode::Msg
        }
    );

    let msg = expect_msg(body);
    assert_eq!(msg.flags, MsgFlags::empty());
    assert_eq!(msg.checksum, None);

    // The reply document: `{version: "5.0.0", gitVersion: "...", modules:
    // [...], ..., ok: 1.0}` — a MongoDB 5.0.0 `buildInfo` response.
    let doc = msg.document();
    assert_eq!(doc.command().unwrap(), "version");
    assert_eq!(
        doc.get("version").unwrap().unwrap().to_bson().unwrap(),
        Bson::String("5.0.0".into())
    );
    assert_eq!(doc.get("ok").unwrap().unwrap().to_bson().unwrap(), Bson::Double(1.0));
    let git = doc.get("gitVersion").unwrap().unwrap().to_bson().unwrap();
    assert!(
        matches!(&git, Bson::String(s) if s.starts_with("1184f004a99660de6f5e7455734")),
        "gitVersion: {git:?}"
    );

    assert_reencodes_byte_exactly(header, &MessageBody::Msg(msg), &frame);
}

#[test]
fn import_op_msg_golden() {
    // A full frame in one file: header + body, 327 bytes total.
    let frame = recorded("import.hex");
    assert_eq!(frame.len(), 327);
    let (header, body) = parse_frame(&frame);

    // messageLength=0x147=327, requestID=7, responseTo=0, opCode=OP_MSG.
    assert_eq!(
        header,
        Header {
            message_length: 327,
            request_id: 7,
            response_to: 0,
            op_code: Opcode::Msg
        }
    );

    let msg = expect_msg(body);
    assert_eq!(msg.flags, MsgFlags::empty());
    assert_eq!(msg.checksum, None);

    // Body section: `{insert: "actor", ordered: true, writeConcern: {w:
    // "majority"}, $db: "monila"}`; the documents ride in a kind-1 section.
    let doc = msg.document();
    assert_eq!(doc.command().unwrap(), "insert");
    assert_eq!(doc.get("insert").unwrap().unwrap().to_bson().unwrap(), Bson::String("actor".into()));
    assert_eq!(doc.get("ordered").unwrap().unwrap().to_bson().unwrap(), Bson::Bool(true));
    assert_eq!(
        doc.get("$db").unwrap().unwrap().to_bson().unwrap(),
        Bson::String("monila".into())
    );
    let wc = doc.get("writeConcern").unwrap().unwrap().to_bson().unwrap();
    assert!(matches!(wc, Bson::Document(_)), "writeConcern: {wc:?}");

    // The one document sequence: identifier `documents` (which must not
    // collide with a body field — `Sections::new` enforces that) and two
    // actor documents keyed by ObjectId `_id`s.
    assert_eq!(msg.sections.sequences.len(), 1);
    let seq = &msg.sections.sequences[0];
    assert_eq!(seq.identifier, "documents");
    assert_eq!(seq.documents.len(), 2);
    for actor in &seq.documents {
        assert!(matches!(
            actor.get("_id").unwrap().unwrap().to_bson().unwrap(),
            Bson::ObjectId(_)
        ));
    }
    assert_eq!(msg.sections.size(), msg.body_len() - 4);

    assert_reencodes_byte_exactly(header, &MessageBody::Msg(msg), &frame);
}

#[test]
fn import_frame_feeds_incrementally() {
    // The same frame fed byte-chunk by byte-chunk must parse exactly once,
    // at the end, without ever erroring.
    let frame = recorded("import.hex");
    let mut buf = BytesMut::new();
    let mut parsed = None;
    for chunk in frame.chunks(13) {
        buf.extend_from_slice(chunk);
        if let Some(msg) = framing::parse_message(&mut buf, MAX_MSG_LEN).unwrap() {
            assert!(parsed.is_none(), "the frame must parse exactly once");
            parsed = Some(msg);
        }
    }
    assert!(parsed.is_some(), "the frame must eventually parse");
    assert!(buf.is_empty());
}

#[test]
fn msg_fuzz1_is_rejected_cleanly() {
    // A fuzzer-generated "OP_MSG" (48 bytes): the header is well-formed
    // (messageLength=48, opcode=2013) but flagBits is the ASCII text
    // `0000` = 0x30303030, which sets unknown *required* flag bits (4, 5,
    // 12, 13 among others). The spec mandates that parsers reject such
    // messages; we must error, never panic.
    let frame = recorded("msg_fuzz1.hex");
    assert_eq!(frame.len(), 48);
    let mut buf = BytesMut::from(&frame[..]);
    assert!(matches!(
        framing::parse_message(&mut buf, MAX_MSG_LEN),
        Err(ProtocolError::InvalidOpMsg("unknown required flag bits"))
    ));

    // No prefix of the frame errors early — it is simply incomplete — and
    // the complete frame errors cleanly.
    for n in 0..frame.len() {
        let mut buf = BytesMut::from(&frame[..n]);
        assert!(
            matches!(framing::parse_message(&mut buf, MAX_MSG_LEN), Ok(None)),
            "n={n}"
        );
    }
}

#[test]
fn recorded_op_msg_bodies_round_trip_through_op_msg_new() {
    // The recorded body documents survive a build-parse round trip through
    // the public constructor: sections assembled by hand must encode to the
    // same bytes for single-section messages.
    for name in ["handshake5", "handshake6"] {
        let frame = recorded_frame(&[&format!("{name}_header.hex"), &format!("{name}_body.hex")]);
        let (_, body) = parse_frame(&frame);
        let msg = expect_msg(body);
        let rebuilt = OpMsg::new(msg.flags, msg.document().clone(), Vec::new()).unwrap();
        let mut out = BytesMut::new();
        rebuilt.encode_body(&mut out);
        assert_eq!(&out[..], &frame[MSG_HEADER_LEN..], "{name} body must rebuild byte-exactly");
    }

    // import.hex rebuilt through `Sections::new` with its document sequence.
    let frame = recorded("import.hex");
    let (_, body) = parse_frame(&frame);
    let msg = expect_msg(body);
    let seq = msg.sections.sequences[0].clone();
    let rebuilt = OpMsg::new(msg.flags, msg.document().clone(), vec![seq]).unwrap();
    assert_eq!(rebuilt, msg);
    let DocumentSequence { .. } = msg.sections.sequences[0];

    // Sanity: the raw kind-0 document really has no `documents` field, which
    // is what lets the kind-1 identifier pass the collision check.
    let raw: &RawDocument = msg.document();
    assert!(raw.get("documents").unwrap().is_none());
}
