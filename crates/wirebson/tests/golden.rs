//! Golden tests against FerretDB/wire's recorded hex dumps
//! (`tests/data/*.hex`, copied from `reference/wire/wirebson/testdata`).
//!
//! Each file is a `hex.Dump`-style hexdump: offset column, hex byte columns,
//! ASCII column. Files are decoded, re-encoded, and must reproduce the input
//! bytes exactly.

use bytes::Bytes;

use wirebson::{Error, RawDocument, MAX_NESTING_DEPTH};

/// Directory with the copied hexdump files.
const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

/// Parse a hexdump file back into bytes.
fn parse_hexdump(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        // Everything before the first `|` is the offset plus the hex columns;
        // the ASCII column (which could mimic hex tokens) is ignored.
        let hex_part = line.split('|').next().expect("non-empty line");
        let mut tokens = hex_part.split_whitespace();
        let offset = usize::from_str_radix(tokens.next().expect("offset"), 16).expect("offset hex");
        assert_eq!(offset, out.len(), "hexdump offset gap in line {line:?}");
        for token in tokens {
            assert_eq!(token.len(), 2, "bad hex byte {token:?}");
            out.push(u8::from_str_radix(token, 16).expect("byte hex"));
        }
    }
    out
}

fn load(name: &str) -> Vec<u8> {
    let path = format!("{DATA_DIR}/{name}");
    let text = std::fs::read_to_string(&path).expect("testdata file");
    parse_hexdump(&text)
}

/// The reference `all.hex` document: every type the Go reference supports,
/// including duplicates, empty strings, NaNs and infinities.
#[test]
fn all_roundtrips_byte_exactly() {
    let bytes = load("all.hex");

    let raw = RawDocument::from_bytes(Bytes::from(bytes.clone())).expect("valid document");
    assert_eq!(raw.command().unwrap(), "document");

    // 15 top-level fields in a fixed order.
    let fields: Vec<_> = raw.fields().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        fields.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        [
            "document", "array", "float64", "string", "binary", "undefined", "objectID", "bool",
            "datetime", "null", "regex", "int32", "timestamp", "int64", "decimal128",
        ]
    );

    // Both decode depths re-encode to the exact input bytes.
    for decoded in [raw.shallow().unwrap(), raw.deep().unwrap()] {
        assert_eq!(decoded.encode().unwrap().as_bytes(), bytes);
    }

    // Spot checks against the Go test expectations.
    let doc = raw.deep().unwrap();
    let strings = match doc.get("string") {
        Some(wirebson::Bson::Array(arr)) => arr.clone(),
        other => panic!("string field: {other:?}"),
    };
    assert_eq!(
        strings.values,
        vec![
            wirebson::Bson::String("foo".to_owned()),
            wirebson::Bson::String(String::new()),
        ]
    );

    let binary = match doc.get("binary") {
        Some(wirebson::Bson::Array(arr)) => arr.clone(),
        other => panic!("binary field: {other:?}"),
    };
    assert_eq!(
        binary.values,
        vec![
            wirebson::Bson::Binary(mongo_common::bson::Binary {
                subtype: mongo_common::bson::BinarySubtype::UserDefined(0x80),
                bytes: vec![0x42],
            }),
            wirebson::Bson::Binary(mongo_common::bson::Binary {
                subtype: mongo_common::bson::BinarySubtype::Generic,
                bytes: Vec::new(),
            }),
        ]
    );
}

/// The reference `nested.hex` document nests 150 levels deep, alternating
/// documents and arrays (`{"f": [{"0": ...}]}`), ending at a null element.
///
/// The Go reference has no decode depth limit — it decodes all 150 levels and
/// only truncates its *log rendering* at depth 20. This crate enforces
/// [`wirebson::MAX_NESTING_DEPTH`] (20) as a hard decode guard, so a full
/// deep decode of this file is expected to fail; structural checks and raw
/// walking still cover it byte-exactly.
#[test]
fn nested_is_valid_but_too_deep_to_decode() {
    let bytes = load("nested.hex");
    assert_eq!(bytes.len(), 1200);

    let raw = RawDocument::from_bytes(Bytes::from(bytes.clone())).expect("valid document");

    // Walk down all 150 levels raw (no recursion, no depth limit): each level
    // is a single element ("f" in documents, "0" in arrays) whose value is
    // again a document/array, until the innermost 8-byte document holding
    // one null.
    let mut region: &[u8] = raw.as_bytes();
    let mut parent_is_array = false; // the outermost level is a document
    let mut level = 0;
    loop {
        level += 1;
        assert_eq!(region.len(), 1200 - 8 * (level - 1), "level {level}");
        let expected_name: &[u8] = if parent_is_array { b"0\0" } else { b"f\0" };
        assert_eq!(&region[5..7], expected_name, "level {level}");
        let tag = region[4];
        match tag {
            // The element's value is another nested composite: descend. The
            // child's own 4-byte length field begins right after the 3-byte
            // element header (tag + name + NUL), at region[7..11].
            0x03 | 0x04 => {
                parent_is_array = tag == 0x04;
                let l = u32::from_le_bytes(region[7..11].try_into().unwrap()) as usize;
                region = &region[7..7 + l];
            }
            // Innermost level: a single null element.
            0x0a => {
                assert_eq!(level, 150, "innermost level");
                break;
            }
            other => panic!("unexpected tag {other:#04x} at level {level}"),
        }
    }
    assert_eq!(level, 150);
    assert_eq!(region.len(), 8);

    // Full decode is rejected by the depth guard in both modes.
    assert_eq!(
        raw.deep(),
        Err(Error::NestedTooDeep {
            max: MAX_NESTING_DEPTH
        })
    );
    assert_eq!(
        raw.shallow(),
        Err(Error::NestedTooDeep {
            max: MAX_NESTING_DEPTH
        })
    );

    // The validated raw bytes round-trip unchanged.
    assert_eq!(raw.clone().into_bytes().to_vec(), bytes);
    assert_eq!(
        RawDocument::from_bytes(raw.into_bytes()).unwrap().as_bytes(),
        bytes
    );
}

/// The same nesting shape as `nested.hex`, but within the depth limit, must
/// decode and re-encode byte-exactly through both depths.
#[test]
fn nested_within_limit_roundtrips() {
    use wirebson::{Array, Bson, Document};

    // Every nesting region (document or array) counts as one decode depth
    // level. Build exactly 20: the root document, 18 alternating wrappers,
    // and an innermost document holding a single null.
    let mut value: Bson = Bson::Document(Document::from_iter([("f", Bson::Null)]));
    for i in 0..18 {
        value = if i % 2 == 0 {
            Bson::Array(Array::from_iter([value]))
        } else {
            Bson::Document(Document::from_iter([("f", value)]))
        };
    }
    let doc = Document::from_iter([("f", value.clone())]);

    let bytes = doc.encode().unwrap();
    let raw = RawDocument::from_bytes(bytes.clone().into_bytes()).unwrap();

    for decoded in [raw.shallow().unwrap(), raw.deep().unwrap()] {
        assert_eq!(decoded, doc);
        assert_eq!(decoded.encode().unwrap().as_bytes(), bytes.as_bytes());
    }

    // One level beyond the limit must be rejected: wrap the value once more.
    let too_deep = Document::from_iter([("f", Bson::Array(Array::from_iter([value])))]);
    let raw = RawDocument::from_bytes(too_deep.encode().unwrap().into_bytes()).unwrap();
    assert_eq!(
        raw.deep(),
        Err(Error::NestedTooDeep {
            max: MAX_NESTING_DEPTH
        })
    );
}

/// Extra confidence: the recorded MongoDB handshake documents must also
/// round-trip byte-exactly through both decode depths.
#[test]
fn handshakes_roundtrip_byte_exactly() {
    for name in ["handshake1.hex", "handshake2.hex", "handshake3.hex", "handshake4.hex"] {
        let bytes = load(name);
        let raw = RawDocument::from_bytes(Bytes::from(bytes.clone()))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        for decoded in [raw.shallow().unwrap(), raw.deep().unwrap()] {
            assert_eq!(
                decoded.encode().unwrap().as_bytes(),
                bytes,
                "{name}: re-encode mismatch"
            );
        }
    }
}
