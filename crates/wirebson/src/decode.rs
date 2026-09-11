//! Document/array decoding — walking fields and dispatching on element tags.
//!
//! Scalars are parsed with the same wire layout rules as
//! [`mongo_common::bson::parse_scalar`]; this module borrows strings directly
//! from the input instead of copying them ([`crate::RawBsonRef`] holds
//! `&str`s), so the two are cross-checked by unit tests rather than layered.

use bytes::Bytes;

use mongo_common::bson::scalar::{
    Binary, BinarySubtype, Decimal128, ObjectId, Timestamp, MIN_DOC_LEN, TAG_ARRAY, TAG_BINARY,
    TAG_BOOL, TAG_DATE_TIME, TAG_DB_POINTER, TAG_DECIMAL128, TAG_DOCUMENT, TAG_DOUBLE, TAG_INT32,
    TAG_INT64, TAG_JAVASCRIPT, TAG_JAVASCRIPT_SCOPE, TAG_MAX_KEY, TAG_MIN_KEY, TAG_NULL,
    TAG_OBJECT_ID, TAG_REGEX, TAG_STRING, TAG_SYMBOL, TAG_TIMESTAMP, TAG_UNDEFINED,
};
use mongo_common::bson::{DbPointer, Regex};
use mongo_common::io::{ProtocolRead, ReadError};

use crate::error::Error;
use crate::raw::{RawArray, RawDocument};
use crate::raw_value::RawBsonRef;
use crate::{Array, Document, Field, Bson, MAX_NESTING_DEPTH};

/// Walk mode: shallow keeps composites raw, deep recurses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Shallow,
    Deep,
}

/// Decode a validated raw document into fields.
///
/// `bytes` must be a complete document (4-byte length prefix + fields +
/// trailing NUL), as guaranteed by [`crate::RawDocument::from_bytes`]. `depth`
/// is the nesting level of *this* document; see [`MAX_NESTING_DEPTH`].
///
/// Both modes fully materialize nested composites into eager values: the
/// [`Bson`] type has no raw document/array variants, so a nested composite is
/// decoded the same way either way. The distinction only matters at the
/// [`RawBsonRef`] level ([`crate::RawDocument::fields`]), where composites
/// genuinely stay raw.
pub(crate) fn decode_document(bytes: &Bytes, mode: Mode, depth: usize) -> Result<Document, Error> {
    Ok(Document {
        fields: decode_fields(bytes, mode, depth)?,
    })
}

/// Decode a validated raw array into values, in element order.
///
/// Element names (`"0"`, `"1"`, …) are neither required nor validated,
/// matching the Go reference.
pub(crate) fn decode_array(bytes: &Bytes, mode: Mode, depth: usize) -> Result<Array, Error> {
    if depth > MAX_NESTING_DEPTH {
        return Err(Error::NestedTooDeep { max: MAX_NESTING_DEPTH });
    }

    let mut scanner = Scanner::new(bytes);
    let mut values = Vec::new();

    while let Some((_name, raw)) = scanner.next()? {
        values.push(materialize(raw, mode, depth)?);
    }

    Ok(Array { values })
}

/// Decode a document body (bytes after the 4-byte length prefix, ending at
/// the trailing NUL) into fields.
///
/// Internal helper shared by [`crate::RawDocument::shallow`] /
/// [`crate::RawDocument::deep`].
pub(crate) fn decode_fields(
    bytes: &Bytes,
    mode: Mode,
    depth: usize,
) -> Result<Vec<crate::Field>, Error> {
    if depth > MAX_NESTING_DEPTH {
        return Err(Error::NestedTooDeep { max: MAX_NESTING_DEPTH });
    }

    let mut scanner = Scanner::new(bytes);
    let mut fields = Vec::new();

    while let Some((name, raw)) = scanner.next()? {
        let value = materialize(raw, mode, depth)?;
        fields.push(Field {
            name: name.to_owned(),
            value,
        });
    }

    Ok(fields)
}

/// Turn a raw field value into an eager one, recursing into composites with
/// proper depth tracking.
fn materialize(value: RawBsonRef<'_>, mode: Mode, depth: usize) -> Result<Bson, Error> {
    match value {
        RawBsonRef::Document(d) => {
            Ok(Bson::Document(decode_document(&d.into_bytes(), mode, depth + 1)?))
        }
        RawBsonRef::Array(a) => {
            Ok(Bson::Array(decode_array(&a.into_bytes(), mode, depth + 1)?))
        }
        // The eager type keeps the scope raw (already validated while scanning).
        RawBsonRef::JavaScriptScope { code, scope } => {
            Ok(Bson::JavaScriptScope {
                code: code.to_owned(),
                scope,
            })
        }
        other => match mode {
            // Composites were handled above; scalars decode identically in
            // both modes.
            Mode::Shallow => other.to_bson(),
            Mode::Deep => other.deep(),
        },
    }
}

/// Low-level single-pass cursor over a validated document's fields.
///
/// Yields borrowed names and raw values; nested composites are sliced off the
/// parent `Bytes` zero-copy and validated, but not recursed into.
pub(crate) struct Scanner<'a> {
    /// The whole document, length prefix included; composite children are
    /// sliced from it.
    parent: &'a Bytes,
    /// `parent` after the 4-byte length prefix.
    body: &'a [u8],
    /// Offset within `body` of the next field's tag byte.
    offset: usize,
}

impl<'a> Scanner<'a> {
    /// New cursor over a validated document.
    pub(crate) fn new(doc: &'a Bytes) -> Self {
        Self {
            parent: doc,
            body: doc.get(4..).unwrap_or(&[]),
            offset: 0,
        }
    }

    /// The next `(name, raw value)`, or `None` at the terminating NUL.
    ///
    /// # Errors
    /// [`Error::ShortInput`] / [`Error::invalid`] / [`Error::Utf8`] /
    /// [`Error::Scalar`] for malformed fields.
    pub(crate) fn next(&mut self) -> Result<Option<(&'a str, RawBsonRef<'a>)>, Error> {
        let Some(&tag) = self.body.get(self.offset) else {
            // Unreachable for validated documents: their last byte is the
            // terminating NUL, handled just below.
            return Err(Error::ShortInput {
                needed: self.offset + 1,
                got: self.body.len(),
            });
        };

        if tag == 0 {
            if self.offset + 1 != self.body.len() {
                return Err(Error::invalid(
                    self.offset,
                    "data after end-of-document marker",
                ));
            }
            return Ok(None);
        }
        self.offset += 1;

        let rel = self.body[self.offset..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::ShortInput {
                needed: self.body.len() + 1,
                got: self.body.len(),
            })?;
        let name = std::str::from_utf8(&self.body[self.offset..self.offset + rel])?;
        self.offset += rel + 1;

        let voff = self.offset;
        let rest = &self.body[voff..];
        let (value, consumed) = parse_value(tag, rest, self.parent, 4 + voff)?;
        self.offset += consumed;

        Ok(Some((name, value)))
    }
}

/// Parse one field value (`rest` starts at the value) into a borrowed
/// [`RawBsonRef`], returning the value's byte count.
///
/// `abs` is the absolute offset of the value within `parent`, used for error
/// offsets and zero-copy composite slicing.
fn parse_value<'a>(
    tag: u8,
    rest: &'a [u8],
    parent: &Bytes,
    abs: usize,
) -> Result<(RawBsonRef<'a>, usize), Error> {
    let mut r: &'a [u8] = rest;

    let value = match tag {
        TAG_DOCUMENT | TAG_ARRAY => {
            let l = doc_len(rest, abs)?;
            let child = parent.slice(abs..abs + l);
            r.read_bytes(l).map_err(map_read)?; // always succeeds: `doc_len` checked
            if tag == TAG_DOCUMENT {
                RawBsonRef::Document(RawDocument::from_bytes(child)?)
            } else {
                RawBsonRef::Array(RawArray::from_bytes(child)?)
            }
        }

        TAG_JAVASCRIPT_SCOPE => {
            if rest.len() < 4 {
                return Err(Error::ShortInput {
                    needed: 4,
                    got: rest.len(),
                });
            }
            let total = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes")) as usize;

            let mut cur: &'a [u8] = &rest[4..];
            let code = read_str(&mut cur, abs + 4)?;

            let scope_off = rest.len() - cur.remaining();
            if rest.len() < scope_off + 4 {
                return Err(Error::ShortInput {
                    needed: scope_off + 4,
                    got: rest.len(),
                });
            }
            let l = u32::from_le_bytes(rest[scope_off..scope_off + 4].try_into().expect("4 bytes"))
                as usize;
            if l < MIN_DOC_LEN {
                return Err(Error::invalid(abs + scope_off, "scope length below minimum"));
            }
            if rest.len() < scope_off + l {
                return Err(Error::ShortInput {
                    needed: scope_off + l,
                    got: rest.len(),
                });
            }
            let scope =
                RawDocument::from_bytes(parent.slice(abs + scope_off..abs + scope_off + l))?;

            let actual = scope_off + l;
            if total != actual {
                return Err(Error::LengthMismatch {
                    declared: total,
                    actual,
                });
            }
            r.read_bytes(actual).map_err(map_read)?; // always succeeds: checked above

            RawBsonRef::JavaScriptScope { code, scope }
        }

        TAG_DOUBLE => RawBsonRef::Double(f64::from_le_bytes(
            r.read_bytes(8).map_err(map_read)?.try_into().expect("8 bytes"),
        )),
        TAG_STRING => RawBsonRef::String(read_str(&mut r, abs)?),
        TAG_BINARY => RawBsonRef::Binary(read_binary(&mut r, abs)?),
        TAG_UNDEFINED => RawBsonRef::Undefined,
        TAG_OBJECT_ID => RawBsonRef::ObjectId(ObjectId::from_bytes(
            r.read_bytes(12).map_err(map_read)?.try_into().expect("12 bytes"),
        )),
        TAG_BOOL => RawBsonRef::Bool(match r.read_u8().map_err(map_read)? {
            0 => false,
            1 => true,
            _ => return Err(Error::invalid(abs, "invalid bool byte")),
        }),
        TAG_DATE_TIME => RawBsonRef::DateTime(r.read_i64_le().map_err(map_read)?),
        TAG_NULL => RawBsonRef::Null,
        TAG_REGEX => {
            let pattern = read_cstr(&mut r)?;
            let options = read_cstr(&mut r)?;
            RawBsonRef::Regex(Regex {
                pattern: pattern.to_owned(),
                options: options.to_owned(),
            })
        }
        TAG_DB_POINTER => {
            let namespace = read_str(&mut r, abs)?;
            let id = ObjectId::from_bytes(
                r.read_bytes(12).map_err(map_read)?.try_into().expect("12 bytes"),
            );
            RawBsonRef::DbPointer(DbPointer {
                namespace: namespace.to_owned(),
                id,
            })
        }
        TAG_JAVASCRIPT => RawBsonRef::JavaScript(read_str(&mut r, abs)?),
        TAG_SYMBOL => RawBsonRef::Symbol(read_str(&mut r, abs)?),
        TAG_INT32 => RawBsonRef::Int32(r.read_i32_le().map_err(map_read)?),
        TAG_TIMESTAMP => RawBsonRef::Timestamp(Timestamp {
            increment: r.read_u32_le().map_err(map_read)?, // increment precedes seconds
            seconds: r.read_u32_le().map_err(map_read)?,
        }),
        TAG_INT64 => RawBsonRef::Int64(r.read_i64_le().map_err(map_read)?),
        TAG_DECIMAL128 => RawBsonRef::Decimal128(Decimal128::from_le_bytes(
            r.read_bytes(16).map_err(map_read)?.try_into().expect("16 bytes"),
        )),
        TAG_MIN_KEY => RawBsonRef::MinKey,
        TAG_MAX_KEY => RawBsonRef::MaxKey,
        _ => return Err(Error::invalid(abs, "unknown element type")),
    };

    Ok((value, rest.len() - r.remaining()))
}

/// Read a nested document/array declared length: 4-byte prefix, at least
/// [`MIN_DOC_LEN`], and actually present in `rest`.
fn doc_len(rest: &[u8], abs: usize) -> Result<usize, Error> {
    if rest.len() < 4 {
        return Err(Error::ShortInput {
            needed: 4,
            got: rest.len(),
        });
    }
    let l = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
    if l < MIN_DOC_LEN {
        return Err(Error::invalid(abs, "composite length below minimum"));
    }
    if rest.len() < l {
        return Err(Error::ShortInput {
            needed: l,
            got: rest.len(),
        });
    }
    Ok(l)
}

/// Read a length-prefixed string, borrowing from the input.
fn read_str<'a>(r: &mut &'a [u8], abs: usize) -> Result<&'a str, Error> {
    let len = r.read_u32_le().map_err(map_read)? as usize;
    if len < 1 {
        return Err(Error::invalid(abs, "zero-length string"));
    }
    let bytes = r.read_bytes(len - 1).map_err(map_read)?;
    if r.read_u8().map_err(map_read)? != 0 {
        return Err(Error::invalid(abs, "string not NUL-terminated"));
    }
    Ok(std::str::from_utf8(bytes)?)
}

/// Read a NUL-terminated string, borrowing from the input.
fn read_cstr<'a>(r: &mut &'a [u8]) -> Result<&'a str, Error> {
    let bytes = r.read_cstring().map_err(map_read)?;
    Ok(std::str::from_utf8(bytes)?)
}

/// Read binary data with its subtype.
///
/// The length field is the payload size *without* the subtype byte, matching
/// the Go reference (`wirebson.decodeBinary`), libbson, the official drivers
/// and recorded MongoDB traffic (this is also what
/// `mongo_common::bson::parse_scalar` implements). The obsolete subtype 2
/// additionally carries a 4-byte inner length at the start of its payload.
fn read_binary(r: &mut &[u8], abs: usize) -> Result<Binary, Error> {
    let len = r.read_u32_le().map_err(map_read)? as usize;
    let subtype = BinarySubtype::from_u8(r.read_u8().map_err(map_read)?).map_err(Error::from)?;
    let payload = match subtype {
        BinarySubtype::BinaryOld => {
            let inner = r.read_u32_le().map_err(map_read)? as usize;
            if inner + 4 != len {
                return Err(Error::invalid(abs, "old binary inner length mismatch"));
            }
            inner
        }
        _ => len,
    };
    Ok(Binary {
        subtype,
        bytes: r.read_bytes(payload).map_err(map_read)?.to_vec(),
    })
}

/// Map a `mongo_common` read error into ours (`read_cstring` is the only
/// source of `ReadError::Invalid`, and never on this path).
fn map_read(e: ReadError) -> Error {
    match e {
        ReadError::ShortInput { needed, got } => Error::ShortInput { needed, got },
        ReadError::Invalid(reason) => Error::invalid(0, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongo_common::bson::Scalar;
    use mongo_common::bson::scalar::BinarySubtype;
    use mongo_common::io::ProtocolWrite;

    /// The canonical `{"hello": "world"}` document from bsonspec.org.
    const HELLO: &[u8] = &[
        0x16, 0x00, 0x00, 0x00, // total length
        0x02, // string
        b'h', b'e', b'l', b'l', b'o', 0x00, // name
        0x06, 0x00, 0x00, 0x00, b'w', b'o', b'r', b'l', b'd', 0x00, // value
        0x00, // terminator
    ];

    fn decode(bytes: &[u8]) -> Result<Document, Error> {
        decode_document(&Bytes::copy_from_slice(bytes), Mode::Deep, 1)
    }

    #[test]
    fn hello_world() {
        let doc = decode(HELLO).unwrap();
        assert_eq!(doc.len(), 1);
        assert_eq!(doc.get("hello"), Some(&Bson::String("world".to_owned())));
        assert_eq!(doc, decode_document(&Bytes::copy_from_slice(HELLO), Mode::Shallow, 1).unwrap());
    }

    #[test]
    fn empty_document() {
        let doc = decode(&[0x05, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert!(doc.is_empty());
    }

    #[test]
    fn array_elements_in_order_names_ignored() {
        // {"0": 1, "7": 2} — the "7" name is bogus but must be accepted.
        let bytes: Vec<u8> = [
            14u32.to_le_bytes().as_slice(),
            &[TAG_INT32, b'0', 0x00],
            1i32.to_le_bytes().as_slice(),
            &[TAG_INT32, b'7', 0x00],
            2i32.to_le_bytes().as_slice(),
            &[0x00],
        ]
        .concat();
        let arr = decode_array(&Bytes::copy_from_slice(&bytes), Mode::Deep, 1).unwrap();
        assert_eq!(
            arr.values,
            vec![Bson::Int32(1), Bson::Int32(2)]
        );
    }

    #[test]
    fn duplicates_preserved_get_first() {
        let bytes: Vec<u8> = [
            17u32.to_le_bytes().as_slice(),
            &[TAG_INT32, b'a', 0x00],
            1i32.to_le_bytes().as_slice(),
            &[TAG_INT32, b'a', 0x00],
            2i32.to_le_bytes().as_slice(),
            &[0x00],
        ]
        .concat();
        let doc = decode(&bytes).unwrap();
        assert_eq!(doc.len(), 2);
        assert_eq!(doc.get("a"), Some(&Bson::Int32(1)));
    }

    #[test]
    fn nested_composites() {
        let doc = crate::Document::from_iter([
            ("d", Bson::Document(crate::Document::from_iter([("x", Bson::Int32(1))]))),
            (
                "a",
                Bson::Array(crate::Array::from_iter([Bson::String("s".to_owned())])),
            ),
            (
                "js",
                Bson::JavaScriptScope {
                    code: "1 + 1".to_owned(),
                    scope: crate::RawDocument::from_vec(
                        crate::Document::from_iter([("y", Bson::Null)]).encode().unwrap().into_bytes().to_vec(),
                    )
                    .unwrap(),
                },
            ),
        ]);
        let bytes = doc.encode().unwrap().into_bytes();
        for mode in [Mode::Shallow, Mode::Deep] {
            let decoded = decode_document(&bytes, mode, 1).unwrap();
            assert_eq!(&decoded, &doc, "mode {mode:?}");
        }
    }

    #[test]
    fn js_scope_length_mismatch() {
        let scope = crate::Document::from_iter([("y", Bson::Null)]).encode().unwrap();
        let mut value = Vec::new();
        let pos = value.placeholder_i32();
        mongo_common::bson::encode_scalar(&Scalar::String("code".to_owned()), &mut value).unwrap();
        value.put_bytes(scope.as_bytes());
        // Patch the total length to one byte too many.
        value.put_i32_le_at(pos, (value.len() - pos + 1) as i32);

        let doc_bytes: Vec<u8> = [
            (value.len() as u32 + 8).to_le_bytes().as_slice(),
            &[TAG_JAVASCRIPT_SCOPE, b'c', 0x00],
            value.as_slice(),
            &[0x00],
        ]
        .concat();
        assert!(matches!(
            decode(&doc_bytes),
            Err(Error::LengthMismatch { .. })
        ));
    }

    #[test]
    fn premature_terminator_rejected() {
        // {"a": 1} followed by stray NULs inside the declared length.
        let bytes: Vec<u8> = [
            10u32.to_le_bytes().as_slice(),
            &[0x00],
            &[0x2a, 0x00, 0x00, 0x00],
        ]
        .concat();
        assert!(matches!(decode(&bytes), Err(Error::InvalidInput { .. })));
    }

    #[test]
    fn unknown_tag_rejected() {
        let bytes: Vec<u8> = [
            8u32.to_le_bytes().as_slice(),
            &[0x42, b'a', 0x00],
            &[0x00],
        ]
        .concat();
        assert!(matches!(decode(&bytes), Err(Error::InvalidInput { .. })));
    }

    #[test]
    fn truncated_fields_error_never_panic() {
        // A nested document that declares more bytes than its parent has.
        let inner_len = 64u32.to_le_bytes();
        let bytes: Vec<u8> = [
            16u32.to_le_bytes().as_slice(),
            &[TAG_DOCUMENT, b'd', 0x00],
            inner_len.as_slice(),
            5u32.to_le_bytes().as_slice(),
            &[0x00],
        ]
        .concat();
        for n in 0..bytes.len() {
            let res = decode(&bytes[..n]);
            assert!(res.is_err(), "truncation {n} unexpectedly decoded");
        }
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn depth_guard_boundary() {
        // A document nested k deep is decoded at depth k; 20 is allowed, 21 is not.
        let build = |n: usize| {
            let mut doc = crate::Document::from_iter([("v", Bson::Int32(42))]);
            for _ in 0..n {
                doc = crate::Document::from_iter([("f", Bson::Document(doc))]);
            }
            doc.encode().unwrap()
        };

        // 19 wrappers + the innermost document = 20 levels.
        let ok = build(19).into_bytes();
        assert!(decode_document(&ok, Mode::Deep, 1).is_ok());

        // 20 wrappers + the innermost = 21 levels.
        let too_deep = build(20).into_bytes();
        assert_eq!(
            decode_document(&too_deep, Mode::Deep, 1),
            Err(Error::NestedTooDeep { max: MAX_NESTING_DEPTH })
        );
        assert_eq!(
            decode_document(&too_deep, Mode::Shallow, 1),
            Err(Error::NestedTooDeep { max: MAX_NESTING_DEPTH })
        );
    }

    /// The borrowed value parsing here must agree with
    /// `mongo_common::bson::parse_scalar` on both value bytes and length for
    /// every scalar kind, binary data included (both crates encode the
    /// length field as the payload size, excluding the subtype byte).
    #[test]
    fn scalar_parsing_matches_mongo_common() {
        let scalars: Vec<Scalar> = vec![
            Scalar::Double(42.13),
            Scalar::String("привет".to_owned()),
            Scalar::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes: vec![1, 2, 3],
            }),
            Scalar::Binary(Binary {
                subtype: BinarySubtype::BinaryOld,
                bytes: vec![9; 7],
            }),
            Scalar::Binary(Binary {
                subtype: BinarySubtype::Uuid,
                bytes: Vec::new(),
            }),
            Scalar::Binary(Binary {
                subtype: BinarySubtype::UserDefined(0x80),
                bytes: vec![0x42],
            }),
            Scalar::Undefined,
            Scalar::ObjectId(ObjectId::from_bytes([7; 12])),
            Scalar::Bool(true),
            Scalar::DateTime(-42),
            Scalar::Null,
            Scalar::Regex(Regex {
                pattern: "^a".to_owned(),
                options: "im".to_owned(),
            }),
            Scalar::DbPointer(DbPointer {
                namespace: "a.b".to_owned(),
                id: ObjectId::from_bytes([9; 12]),
            }),
            Scalar::JavaScript("1 + 1".to_owned()),
            Scalar::Symbol("sym".to_owned()),
            Scalar::Int32(-5),
            Scalar::Timestamp(Timestamp {
                seconds: 123,
                increment: 456,
            }),
            Scalar::Int64(i64::MIN),
            Scalar::Decimal128(Decimal128::from_le_bytes([1; 16])),
            Scalar::MinKey,
            Scalar::MaxKey,
        ];

        for case in scalars {
            let mut buf = Vec::new();
            let tag = mongo_common::bson::tag_of(&case);

            mongo_common::bson::encode_scalar(&case, &mut buf).unwrap();
            let (expected, expected_len) = mongo_common::bson::parse_scalar(tag, &buf).unwrap();

            let parent = Bytes::copy_from_slice(&buf);
            let (actual, actual_len) = parse_value(tag, &parent, &parent, 0).unwrap();
            assert_eq!(actual_len, expected_len, "consumed mismatch for {case:?}");
            assert_eq!(actual.to_bson().unwrap(), Bson::from(expected));
        }
    }

    /// Binary values following the official BSON specification (length
    /// including the subtype byte, as produced by real MongoDB servers and
    /// `mongo_common::bson::encode_scalar`) are one byte shorter than this
    /// crate's Go-compatible layout parses them; the length field is what
    /// decides, so such input yields a truncated/garbled payload or a
    /// short-input error rather than a misparse panic.
    #[test]
    fn spec_convention_binary_len_errors_or_roundtrips() {
        // Official-spec encoding of a 3-byte generic binary: len = 4.
        let buf = [4u8, 0, 0, 0, 0x00, 1, 2, 3];
        let parent = Bytes::copy_from_slice(&buf);
        // len = 4 is parsed as a 4-byte payload, but only 3 follow.
        assert!(parse_value(TAG_BINARY, &parent, &parent, 0).is_err());
    }
}
