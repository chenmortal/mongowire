//! Document/array encoding and log-friendly formatting.

use mongo_common::bson::scalar::BinarySubtype;
use mongo_common::io::ProtocolWrite;

use crate::error::Error;
use crate::value::Bson;
use crate::MAX_NESTING_DEPTH;

/// Encode a document into a fresh byte vector: 4-byte length prefix, fields,
/// trailing NUL.
///
/// # Errors
/// [`Error::invalid`] if a field name contains interior NUL bytes, or a
/// document exceeds the maximum BSON length.
pub(crate) fn encode_document(doc: &crate::Document, out: &mut Vec<u8>) -> Result<(), Error> {
    let len_pos = out.placeholder_i32();

    for field in &doc.fields {
        encode_field(out, &field.name, &field.value)?;
    }

    out.put_u8(0);
    patch_len(out, len_pos)
}

/// Encode an array (keys "0", "1", …).
///
/// # Errors
/// Same as [`encode_document`].
pub(crate) fn encode_array(arr: &crate::Array, out: &mut Vec<u8>) -> Result<(), Error> {
    let len_pos = out.placeholder_i32();

    for (i, value) in arr.values.iter().enumerate() {
        encode_field(out, &i.to_string(), value)?;
    }

    out.put_u8(0);
    patch_len(out, len_pos)
}

/// Overwrite the length placeholder at `len_pos` with the bytes written since.
fn patch_len(out: &mut Vec<u8>, len_pos: usize) -> Result<(), Error> {
    let total = out.len() - len_pos;
    let total = i32::try_from(total)
        .map_err(|_| Error::invalid(len_pos, "document exceeds the maximum BSON length"))?;
    out.put_i32_le_at(len_pos, total);
    Ok(())
}

/// Encode a single `tag byte + cstring name + value` field.
fn encode_field(out: &mut Vec<u8>, name: &str, value: &Bson) -> Result<(), Error> {
    let field_start = out.len();
    out.put_u8(value.tag());
    out.put_cstring(name)
        .map_err(|_| Error::invalid(field_start, "interior NUL in field name"))?;
    encode_value(out, value)
}

/// Encode a field value (the caller wrote the tag byte and name already).
fn encode_value(out: &mut Vec<u8>, value: &Bson) -> Result<(), Error> {
    match value {
        Bson::Document(doc) => encode_document(doc, out),
        Bson::Array(arr) => encode_array(arr, out),
        Bson::JavaScriptScope { code, scope } => {
            // int32 total length, string code, document scope.
            if scope.as_bytes().len() < mongo_common::bson::scalar::MIN_DOC_LEN {
                // Only `RawDocument::default()` can be invalid: every other
                // value passed validation at construction.
                return Err(Error::invalid(out.len(), "empty JavaScript scope document"));
            }
            let len_pos = out.placeholder_i32();
            encode_string(out, code)?;
            out.put_bytes(scope.as_bytes());
            patch_len(out, len_pos)
        }
        other => {
            let scalar = other.as_scalar().ok_or_else(|| {
                Error::invalid(out.len(), "unexpected composite value without as_scalar()")
            })?;

            // Length-prefixed strings may legally contain interior NULs —
            // the decoder accepts them, so encode must too (an asymmetry the
            // fuzzer caught: some decoded documents could not re-encode).
            // NUL is still impossible in cstring positions (field names,
            // regex pattern/options) — those go through `put_cstring`.
            mongo_common::bson::encode_scalar(&scalar, out).map_err(Error::from)?;
            Ok(())
        }
    }
}

/// A length-prefixed string value: int32 (len + 1), bytes, NUL. Embedded
/// NULs are legal here (only cstring positions forbid them).
fn encode_string(out: &mut Vec<u8>, s: &str) -> Result<(), Error> {
    let len = i32::try_from(s.len())
        .ok()
        .and_then(|l| l.checked_add(1))
        .ok_or_else(|| Error::invalid(out.len(), "string too large"))?;
    out.put_i32_le(len);
    out.put_bytes(s.as_bytes());
    out.put_u8(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Log-friendly rendering, following the Go reference's `LogMessage` /
// `LogMessageIndent` shape (exact parity is not guaranteed).
// ---------------------------------------------------------------------------

/// Render a document like the Go reference's `LogMessageIndent` (used by
/// `Display` and test diffing). `indent` enables multi-line output.
pub fn log_document(doc: &crate::Document, indent: bool) -> String {
    let mut s = String::new();
    write_document(&mut s, doc, if indent { 0 } else { -1 }, 1);
    s
}

/// Render an array like [`log_document`].
pub fn log_array(arr: &crate::Array, indent: bool) -> String {
    let mut s = String::new();
    write_array(&mut s, arr, if indent { 0 } else { -1 }, 1);
    s
}

/// Indentation level: `-1` means compact single-line output.
fn write_document(out: &mut String, doc: &crate::Document, indent: isize, depth: usize) {
    if doc.is_empty() {
        out.push_str("{}");
        return;
    }
    if depth > MAX_NESTING_DEPTH {
        out.push_str("{...}");
        return;
    }

    match indent {
        i if i < 0 => {
            out.push('{');
            for (i, field) in doc.fields.iter().enumerate() {
                out.push_str(&quote(&field.name));
                out.push_str(": ");
                write_value(out, &field.value, indent, depth + 1);
                if i + 1 != doc.fields.len() {
                    out.push_str(", ");
                }
            }
            out.push('}');
        }
        i => {
            out.push_str("{\n");
            for field in &doc.fields {
                push_indent(out, i + 1);
                out.push_str(&quote(&field.name));
                out.push_str(": ");
                write_value(out, &field.value, i + 1, depth + 1);
                out.push_str(",\n");
            }
            push_indent(out, i);
            out.push('}');
        }
    }
}

/// See [`write_document`].
fn write_array(out: &mut String, arr: &crate::Array, indent: isize, depth: usize) {
    if arr.is_empty() {
        out.push_str("[]");
        return;
    }
    if depth > MAX_NESTING_DEPTH {
        out.push_str("[...]");
        return;
    }

    match indent {
        i if i < 0 => {
            out.push('[');
            for (i, value) in arr.values.iter().enumerate() {
                write_value(out, value, indent, depth + 1);
                if i + 1 != arr.values.len() {
                    out.push_str(", ");
                }
            }
            out.push(']');
        }
        i => {
            out.push_str("[\n");
            for value in &arr.values {
                push_indent(out, i + 1);
                write_value(out, value, i + 1, depth + 1);
                out.push_str(",\n");
            }
            push_indent(out, i);
            out.push(']');
        }
    }
}

fn push_indent(out: &mut String, level: isize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// A double-quoted string with escapes.
fn quote(s: &str) -> String {
    format!("{s:?}")
}

/// Render one value.
fn write_value(out: &mut String, value: &Bson, indent: isize, depth: usize) {
    match value {
        Bson::Double(v) => {
            if v.is_nan() {
                out.push_str("NaN");
            } else if v.is_infinite() {
                out.push_str(if v.is_sign_negative() { "-Inf" } else { "+Inf" });
            } else {
                out.push_str(&format_f64(*v));
            }
        }
        Bson::String(s) => out.push_str(&quote(s)),
        Bson::Document(doc) => write_document(out, doc, indent, depth),
        Bson::Array(arr) => write_array(out, arr, indent, depth),
        Bson::Binary(b) => {
            out.push_str("Binary(");
            out.push_str(subtype_name(b.subtype));
            out.push(':');
            out.push_str(&base64(&b.bytes));
            out.push(')');
        }
        Bson::Undefined => out.push_str("undefined"),
        Bson::ObjectId(id) => {
            out.push_str("ObjectId('");
            out.push_str(&hex(id.as_bytes()));
            out.push_str("')");
        }
        Bson::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Bson::DateTime(ms) => out.push_str(&format_datetime(*ms)),
        Bson::Null => out.push_str("null"),
        Bson::Regex(r) => {
            out.push('/');
            out.push_str(&r.pattern);
            out.push('/');
            out.push_str(&r.options);
        }
        Bson::DbPointer(p) => {
            out.push_str("DbPointer(");
            out.push_str(&quote(&p.namespace));
            out.push_str(", ObjectId('");
            out.push_str(&hex(p.id.as_bytes()));
            out.push_str("'))");
        }
        Bson::JavaScript(code) => {
            out.push_str("JavaScript(");
            out.push_str(&quote(code));
            out.push(')');
        }
        Bson::Symbol(s) => {
            out.push_str("Symbol(");
            out.push_str(&quote(s));
            out.push(')');
        }
        Bson::JavaScriptScope { code, scope } => {
            out.push_str("JavaScriptScope({code: ");
            out.push_str(&quote(code));
            out.push_str(", scope: RawDocument<");
            out.push_str(&scope.as_bytes().len().to_string());
            out.push_str(">})");
        }
        Bson::Int32(v) => out.push_str(&v.to_string()),
        Bson::Timestamp(t) => {
            out.push_str(&format!(
                "Timestamp({{s: {}, i: {}}})",
                t.seconds, t.increment
            ));
        }
        Bson::Int64(v) => {
            out.push_str("int64(");
            out.push_str(&v.to_string());
            out.push(')');
        }
        Bson::Decimal128(d) => {
            let l = u64::from_le_bytes(d.to_le_bytes()[..8].try_into().expect("8 bytes"));
            let h = u64::from_le_bytes(d.to_le_bytes()[8..].try_into().expect("8 bytes"));
            out.push_str(&format!("Decimal128(H:{h},L:{l})"));
        }
        Bson::MinKey => out.push_str("MinKey"),
        Bson::MaxKey => out.push_str("MaxKey"),
    }
}

/// Like the Go reference: shortest representation, with `.0` appended to
/// integral values.
fn format_f64(v: f64) -> String {
    let mut s = format!("{v}");
    if !s.contains('.') {
        s.push_str(".0");
    }
    s
}

/// Human-readable binary subtype names.
fn subtype_name(subtype: BinarySubtype) -> &'static str {
    match subtype {
        BinarySubtype::Generic => "generic",
        BinarySubtype::Function => "function",
        BinarySubtype::BinaryOld => "binary-old",
        BinarySubtype::UuidOld => "uuid-old",
        BinarySubtype::Uuid => "uuid",
        BinarySubtype::Md5 => "md5",
        BinarySubtype::Encrypted => "encrypted",
        BinarySubtype::UserDefined(_) => "user",
    }
}

/// Lowercase hexadecimal, two characters per byte.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Standard base64 with padding.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        s.push(ALPHABET[(n >> 18) as usize & 63] as char);
        s.push(ALPHABET[(n >> 12) as usize & 63] as char);
        s.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

/// RFC 3339 in UTC with millisecond precision (fraction omitted when zero).
fn format_datetime(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod / 60) % 60, sod % 60);
    if millis == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
    }
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongo_common::bson::scalar::{Binary, ObjectId, Timestamp};

    /// The canonical `{"hello": "world"}` document from bsonspec.org.
    const HELLO: &[u8] = &[
        0x16, 0x00, 0x00, 0x00, 0x02, b'h', b'e', b'l', b'l', b'o', 0x00, 0x06, 0x00, 0x00, 0x00,
        b'w', b'o', b'r', b'l', b'd', 0x00, 0x00,
    ];

    #[test]
    fn encode_hello_world_byte_exact() {
        let mut doc = crate::Document::new();
        doc.add("hello", "world");
        let raw = doc.encode().unwrap();
        assert_eq!(raw.as_bytes(), HELLO);
    }

    #[test]
    fn encode_empty_document() {
        let raw = crate::Document::new().encode().unwrap();
        assert_eq!(raw.as_bytes(), &[5, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_array_keys() {
        let arr = crate::Array::from_iter([Bson::Int32(7), Bson::Null]);
        let bytes = {
            let mut out = Vec::new();
            encode_array(&arr, &mut out).unwrap();
            out
        };
        let expected: Vec<u8> = [
            15u32.to_le_bytes().as_slice(),
            &[0x10, b'0', 0x00],
            7i32.to_le_bytes().as_slice(),
            &[0x0a, b'1', 0x00],
            &[0x00],
        ]
        .concat();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn encode_rejects_interior_nul_in_field_names_only() {
        // NUL is forbidden in cstring positions (field names) but legal in
        // length-prefixed string VALUES — the decoder accepts those, so
        // encode must too (fuzzer-found asymmetry).
        let mut doc = crate::Document::new();
        doc.fields.push(crate::Field {
            name: "a\0b".to_owned(),
            value: Bson::Int32(1),
        });
        assert!(matches!(
            doc.encode(),
            Err(Error::InvalidInput { reason, .. }) if reason.contains("field name")
        ));

        // A string value with an embedded NUL round-trips byte-exactly.
        let mut doc = crate::Document::new();
        doc.add("bad", "va\0lue");
        let raw = doc.encode().unwrap();
        assert_eq!(raw.deep().unwrap(), doc);
        assert_eq!(raw.deep().unwrap().encode().unwrap(), raw);
    }

    /// Every [`Bson`] variant (including nested composites, JS-with-scope,
    /// raw Decimal128 bytes and every binary subtype) must round-trip
    /// byte-exactly through both shallow and deep decoding.
    #[test]
    fn roundtrip_every_variant() {
        let inner = crate::Document::from_iter([("x", Bson::MinKey)]);
        let scope = crate::Document::from_iter([("scope", true)]).encode().unwrap();

        let mut doc = crate::Document::new();
        doc.add("double", 42.13);
        doc.add("double_neg_zero", -0.0);
        doc.add("string", "привет");
        doc.add("document", inner);
        doc.add("array", crate::Array::from_iter([Bson::Null, Bson::Int32(1)]));
        for (name, subtype) in [
            ("binary_generic", BinarySubtype::Generic),
            ("binary_function", BinarySubtype::Function),
            ("binary_old", BinarySubtype::BinaryOld),
            ("binary_uuid_old", BinarySubtype::UuidOld),
            ("binary_uuid", BinarySubtype::Uuid),
            ("binary_md5", BinarySubtype::Md5),
            ("binary_encrypted", BinarySubtype::Encrypted),
            ("binary_user", BinarySubtype::UserDefined(0x80)),
        ] {
            doc.add(
                name,
                Bson::Binary(Binary {
                    subtype,
                    bytes: vec![0x0a, 0x0b, 0x0c],
                }),
            );
        }
        doc.add("undefined", Bson::Undefined);
        doc.add("object_id", Bson::ObjectId(ObjectId::from_bytes([1; 12])));
        doc.add("bool", Bson::Bool(true));
        doc.add("datetime", Bson::DateTime(-42));
        doc.add("null", Bson::Null);
        doc.add(
            "regex",
            Bson::Regex(mongo_common::bson::Regex {
                pattern: "^a".to_owned(),
                options: "im".to_owned(),
            }),
        );
        doc.add(
            "db_pointer",
            Bson::DbPointer(mongo_common::bson::DbPointer {
                namespace: "a.b".to_owned(),
                id: ObjectId::from_bytes([2; 12]),
            }),
        );
        doc.add("javascript", Bson::JavaScript("1 + 1".to_owned()));
        doc.add("symbol", Bson::Symbol("sym".to_owned()));
        doc.add(
            "javascript_scope",
            Bson::JavaScriptScope {
                code: "code()".to_owned(),
                scope,
            },
        );
        doc.add("int32", Bson::Int32(i32::MIN));
        doc.add(
            "timestamp",
            Bson::Timestamp(Timestamp {
                seconds: 0x11223344,
                increment: 0x55667788,
            }),
        );
        doc.add("int64", Bson::Int64(i64::MAX));
        doc.add(
            "decimal128",
            Bson::Decimal128(mongo_common::bson::Decimal128::from_le_bytes([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ])),
        );
        doc.add("min_key", Bson::MinKey);
        doc.add("max_key", Bson::MaxKey);

        let raw = doc.encode().unwrap();
        let bytes = raw.as_bytes();

        // Byte-stable through both decode depths.
        for decoded in [raw.shallow().unwrap(), raw.deep().unwrap()] {
            assert_eq!(decoded, doc);
            assert_eq!(decoded.encode().unwrap().as_bytes(), bytes);
        }
    }

    #[test]
    fn binary_old_layout() {
        let mut doc = crate::Document::new();
        doc.add(
            "b",
            Bson::Binary(Binary {
                subtype: BinarySubtype::BinaryOld,
                bytes: vec![1, 2, 3],
            }),
        );
        let bytes = doc.encode().unwrap();

        // 4 len + [tag, name, NUL] + [i32 len, subtype, i32 inner, 3 bytes] + term
        let expected: Vec<u8> = [
            20u32.to_le_bytes().as_slice(),
            &[0x05, b'b', 0x00],
            7i32.to_le_bytes().as_slice(),
            &[0x02],
            3i32.to_le_bytes().as_slice(),
            &[1, 2, 3],
            &[0x00],
        ]
        .concat();
        assert_eq!(bytes.as_bytes(), expected);

        // And it decodes back.
        let decoded = bytes.deep().unwrap();
        assert_eq!(
            decoded.get("b"),
            Some(&Bson::Binary(Binary {
                subtype: BinarySubtype::BinaryOld,
                bytes: vec![1, 2, 3]
            }))
        );
    }

    #[test]
    fn truncation_never_panics() {
        let mut doc = crate::Document::new();
        doc.add("d", crate::Document::from_iter([("x", Bson::Int32(1))]));
        doc.add("a", crate::Array::from_iter([Bson::Null]));
        let bytes = doc.encode().unwrap().into_bytes().to_vec();

        for n in 0..bytes.len() {
            assert!(
                crate::RawDocument::from_vec(bytes[..n].to_vec()).is_err(),
                "truncation {n} unexpectedly validated"
            );
        }
    }

    #[test]
    fn log_compact() {
        let mut doc = crate::Document::new();
        doc.add("hello", "world");
        doc.add("n", 42);
        doc.add("arr", crate::Array::from_iter([Bson::Int32(1), Bson::Null]));
        doc.add("empty_doc", crate::Document::new());
        doc.add("empty_arr", crate::Array::new());
        assert_eq!(
            log_document(&doc, false),
            r#"{"hello": "world", "n": 42, "arr": [1, null], "empty_doc": {}, "empty_arr": []}"#
        );
    }

    #[test]
    fn log_indent() {
        let mut doc = crate::Document::new();
        doc.add("a", 1);
        doc.add("d", crate::Document::from_iter([("b", true)]));
        assert_eq!(
            log_document(&doc, true),
            "{\n  \"a\": 1,\n  \"d\": {\n    \"b\": true,\n  },\n}"
        );
    }

    #[test]
    fn log_special_values() {
        let arr = crate::Array::from_iter([
            Bson::Double(f64::NAN),
            Bson::Double(f64::INFINITY),
            Bson::Double(f64::NEG_INFINITY),
            Bson::Double(42.0),
            Bson::Double(-0.0),
            Bson::Undefined,
            Bson::ObjectId(ObjectId::from_bytes([0xab; 12])),
            Bson::Bool(false),
            Bson::DateTime(1_627_378_542_123),
            Bson::DateTime(-62_135_596_800_000),
            Bson::Null,
            Bson::Regex(mongo_common::bson::Regex {
                pattern: "p".to_owned(),
                options: "o".to_owned(),
            }),
            Bson::Int32(7),
            Bson::Timestamp(Timestamp {
                seconds: 5,
                increment: 6,
            }),
            Bson::Int64(9),
            Bson::MinKey,
            Bson::MaxKey,
        ]);
        assert_eq!(
            log_array(&arr, false),
            "[NaN, +Inf, -Inf, 42.0, -0.0, undefined, \
             ObjectId('abababababababababababab'), false, \
             2021-07-27T09:35:42.123Z, 0001-01-01T00:00:00Z, null, /p/o, \
             7, Timestamp({s: 5, i: 6}), int64(9), MinKey, MaxKey]"
        );
    }

    #[test]
    fn log_js_scope_and_binary() {
        let mut doc = crate::Document::new();
        doc.add(
            "js",
            Bson::JavaScriptScope {
                code: "1".to_owned(),
                scope: crate::Document::new().encode().unwrap(),
            },
        );
        doc.add(
            "b",
            Bson::Binary(Binary {
                subtype: BinarySubtype::UserDefined(0x80),
                bytes: b"hi".to_vec(),
            }),
        );
        doc.add("sym", Bson::Symbol("s".to_owned()));
        assert_eq!(
            log_document(&doc, false),
            format!(
                "{{\"js\": JavaScriptScope({{code: \"1\", scope: RawDocument<5>}}), \
                 \"b\": Binary(user:aGk=), \"sym\": Symbol(\"s\")}}"
            )
        );
    }

    #[test]
    fn log_depth_cutoff() {
        // Nest documents deeper than MAX_NESTING_DEPTH; rendering must cut off
        // without recursing further.
        let mut doc = crate::Document::from_iter([("v", Bson::Int32(1))]);
        for _ in 0..(MAX_NESTING_DEPTH + 5) {
            doc = crate::Document::from_iter([("f", Bson::Document(doc))]);
        }
        let rendered = log_document(&doc, false);
        // Exactly MAX_NESTING_DEPTH levels are rendered, then a cutoff marker.
        assert_eq!(rendered.matches("\"f\":").count(), MAX_NESTING_DEPTH);
        assert!(rendered.contains("{...}"), "{rendered}");
    }

    /// Randomized byte-stability: whatever document the strategy builds,
    /// encoding it, decoding (in either depth) and re-encoding must reproduce
    /// the exact bytes.
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn value() -> impl Strategy<Value = Bson> {
            prop_oneof![
                any::<f64>().prop_map(Bson::Double),
                "[^\0]{0,8}".prop_map(Bson::String),
                any::<i32>().prop_map(Bson::Int32),
                any::<i64>().prop_map(Bson::Int64),
                any::<bool>().prop_map(Bson::Bool),
                (any::<u32>(), any::<u32>())
                    .prop_map(|(s, i)| Bson::Timestamp(Timestamp {
                        seconds: s,
                        increment: i,
                    })),
                Just(Bson::Null),
                Just(Bson::Undefined),
                Just(Bson::MinKey),
                Just(Bson::MaxKey),
                // one level of nesting
                "[^\0]{0,4}".prop_map(|s| Bson::Document(crate::Document::from_iter([
                    ("s", Bson::String(s))
                ]))),
                "[^\0]{0,4}".prop_map(|s| Bson::Array(crate::Array::from_iter([
                    Bson::Int32(1),
                    Bson::String(s)
                ]))),
            ]
        }

        fn document() -> impl Strategy<Value = crate::Document> {
            proptest::collection::vec(("[^\0]{0,8}", value()), 0..12).prop_map(|fields| {
                fields
                    .into_iter()
                    .map(|(name, value)| crate::Field { name, value })
                    .collect()
            })
        }

        proptest! {
            #[test]
            fn encode_decode_byte_stable(doc in document()) {
                let bytes = doc.encode().unwrap();
                let raw = crate::RawDocument::from_bytes(bytes.clone().into_bytes()).unwrap();

                for decoded in [raw.shallow().unwrap(), raw.deep().unwrap()] {
                    let reencoded = decoded.encode().unwrap();
                    prop_assert_eq!(reencoded.as_bytes(), bytes.as_bytes());
                }
            }
        }
    }
}
