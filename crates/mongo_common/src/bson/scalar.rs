//! BSON scalar types and tag-level scalar parsing/encoding.
//!
//! Per <https://bsonspec.org/spec.html>. Composite types — document (0x03),
//! array (0x04) and code-with-scope (0x0F) — are handled by `wirebson`, not
//! here; [`parse_scalar`] rejects those tags.

use crate::io::{ProtocolRead, ProtocolWrite, ReadError};
use std::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// BSON element type tags
// ---------------------------------------------------------------------------

pub const TAG_DOUBLE: u8 = 0x01;
pub const TAG_STRING: u8 = 0x02;
pub const TAG_DOCUMENT: u8 = 0x03;
pub const TAG_ARRAY: u8 = 0x04;
pub const TAG_BINARY: u8 = 0x05;
pub const TAG_UNDEFINED: u8 = 0x06;
pub const TAG_OBJECT_ID: u8 = 0x07;
pub const TAG_BOOL: u8 = 0x08;
pub const TAG_DATE_TIME: u8 = 0x09;
pub const TAG_NULL: u8 = 0x0A;
pub const TAG_REGEX: u8 = 0x0B;
pub const TAG_DB_POINTER: u8 = 0x0C;
pub const TAG_JAVASCRIPT: u8 = 0x0D;
pub const TAG_SYMBOL: u8 = 0x0E;
pub const TAG_JAVASCRIPT_SCOPE: u8 = 0x0F;
pub const TAG_INT32: u8 = 0x10;
pub const TAG_TIMESTAMP: u8 = 0x11;
pub const TAG_INT64: u8 = 0x12;
pub const TAG_DECIMAL128: u8 = 0x13;
pub const TAG_MIN_KEY: u8 = 0xFF;
pub const TAG_MAX_KEY: u8 = 0x7F;

/// Minimum length of any BSON document: 4-byte length + trailing NUL.
pub const MIN_DOC_LEN: usize = 5;

// ---------------------------------------------------------------------------
// Scalar types
// ---------------------------------------------------------------------------

/// A BSON ObjectId: 12 bytes (4-byte seconds timestamp, 5-byte random, 3-byte counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 12]);

/// Process-global counter feeding the last 3 bytes of [`ObjectId::new`].
///
/// Per the BSON specification the increment "starts at a random value" in some
/// drivers; starting at zero and incrementing monotonically per process is
/// equally valid and makes generated ids unique within a process.
static OBJECT_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

impl ObjectId {
    /// The raw 12 bytes.
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// The raw 12 bytes.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Generate a new ObjectId: unix seconds + 5 random bytes + 3-byte counter.
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        // 4-byte big-endian unix timestamp; clamp a pre-epoch clock to 0
        // instead of panicking.
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as u32);

        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&seconds.to_be_bytes());
        bytes[4..9].copy_from_slice(&rand::random::<[u8; 5]>());
        // 3-byte big-endian slice of the process-global counter.
        let counter = OBJECT_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        bytes[9..12].copy_from_slice(&counter.to_be_bytes()[1..]);
        Self(bytes)
    }

    /// Lowercase 24-character hexadecimal representation.
    pub fn to_hex(&self) -> String {
        const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(24);
        for byte in self.0 {
            out.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
            out.push(HEX_DIGITS[usize::from(byte & 0x0F)] as char);
        }
        out
    }

    /// Parse the 24-character hexadecimal representation.
    ///
    /// # Errors
    /// [`ScalarError::Invalid`] if the string is not 24 hex characters.
    pub fn from_hex(s: &str) -> Result<Self, ScalarError> {
        let input = s.as_bytes();
        if input.len() != 24 {
            return Err(ScalarError::Invalid {
                tag: TAG_OBJECT_ID,
                reason: "object id hex string must be 24 characters",
            });
        }
        let mut bytes = [0u8; 12];
        for (i, pair) in input.chunks_exact(2).enumerate() {
            let hi = hex_digit(pair[0]).ok_or(ScalarError::Invalid {
                tag: TAG_OBJECT_ID,
                reason: "object id hex string contains a non-hex character",
            })?;
            let lo = hex_digit(pair[1]).ok_or(ScalarError::Invalid {
                tag: TAG_OBJECT_ID,
                reason: "object id hex string contains a non-hex character",
            })?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

/// Decode one ASCII hex digit, upper or lower case.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A BSON internal timestamp: seconds since the unix epoch plus an
/// incrementing ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Timestamp {
    pub seconds: u32,
    pub increment: u32,
}

/// A BSON regular expression: pattern plus options string (e.g. `"imxs"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Regex {
    pub pattern: String,
    pub options: String,
}

/// BSON binary data with its subtype.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Binary {
    pub subtype: BinarySubtype,
    pub bytes: Vec<u8>,
}

/// BSON binary subtypes. Wire byte values per the BSON specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinarySubtype {
    Generic,
    Function,
    /// Obsolete; `bytes` is prefixed with a 4-byte length on the wire.
    BinaryOld,
    /// Obsolete UUID (old driver format).
    UuidOld,
    Uuid,
    Md5,
    Encrypted,
    /// 0x80-0xFF: user-defined subtypes.
    UserDefined(u8),
}

impl BinarySubtype {
    /// Wire byte for this subtype.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Generic => 0x00,
            Self::Function => 0x01,
            Self::BinaryOld => 0x02,
            Self::UuidOld => 0x03,
            Self::Uuid => 0x04,
            Self::Md5 => 0x05,
            Self::Encrypted => 0x06,
            Self::UserDefined(b) => b,
        }
    }

    /// Interpret a wire byte as a subtype.
    ///
    /// # Errors
    /// [`ScalarError::Invalid`] for reserved values 0x07-0x7F.
    pub fn from_u8(b: u8) -> Result<Self, ScalarError> {
        match b {
            0x00 => Ok(Self::Generic),
            0x01 => Ok(Self::Function),
            0x02 => Ok(Self::BinaryOld),
            0x03 => Ok(Self::UuidOld),
            0x04 => Ok(Self::Uuid),
            0x05 => Ok(Self::Md5),
            0x06 => Ok(Self::Encrypted),
            0x07..=0x7F => Err(ScalarError::Invalid {
                reason: "reserved binary subtype",
                tag: b,
            }),
            0x80..=0xFF => Ok(Self::UserDefined(b)),
        }
    }
}

/// A BSON Decimal128, stored exactly as the 16 bytes that appear on the wire
/// (IEEE 764-2008 decimal floating point, little-endian order).
///
/// No arithmetic is provided by default; enable the `decimal128-convert`
/// feature for conversions to `rust_dec::Decimal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Decimal128([u8; 16]);

impl Decimal128 {
    /// From the 16 bytes in wire (little-endian) order.
    pub fn from_le_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes in wire (little-endian) order.
    pub fn to_le_bytes(&self) -> [u8; 16] {
        self.0
    }
}

/// A BSON DBPointer (deprecated, still round-trippable).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DbPointer {
    pub namespace: String,
    pub id: ObjectId,
}

/// Any non-composite BSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Scalar {
    Double(f64),
    String(String),
    Binary(Binary),
    Undefined,
    ObjectId(ObjectId),
    Bool(bool),
    /// Milliseconds since the unix epoch (may be negative).
    DateTime(i64),
    Null,
    Regex(Regex),
    DbPointer(DbPointer),
    JavaScript(String),
    Symbol(String),
    Int32(i32),
    Timestamp(Timestamp),
    Int64(i64),
    Decimal128(Decimal128),
    MinKey,
    MaxKey,
}

/// Errors from scalar parsing/encoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScalarError {
    /// Not enough input to parse the value.
    #[error("unexpected end of input: needed {needed} byte(s), got {got}")]
    ShortInput { needed: usize, got: usize },
    /// Input is invalid for the given tag.
    #[error("invalid input for tag {tag:#04x}: {reason}")]
    Invalid {
        tag: u8,
        reason: &'static str,
    },
    /// A string field was not valid UTF-8.
    #[error("invalid utf-8")]
    Utf8(#[from] std::str::Utf8Error),
    /// The value cannot be represented in the requested type.
    #[error("value out of range for the requested type")]
    OutOfRange,
    /// The scalar kind does not match the requested conversion.
    #[error("cannot convert this scalar kind to the requested type")]
    NotConvertible,
}

impl From<ReadError> for ScalarError {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::ShortInput { needed, got } => Self::ShortInput { needed, got },
            ReadError::Invalid(reason) => Self::Invalid { tag: 0, reason },
        }
    }
}

/// The BSON element tag for this scalar.
pub fn tag_of(s: &Scalar) -> u8 {
    match s {
        Scalar::Double(_) => TAG_DOUBLE,
        Scalar::String(_) => TAG_STRING,
        Scalar::Binary(_) => TAG_BINARY,
        Scalar::Undefined => TAG_UNDEFINED,
        Scalar::ObjectId(_) => TAG_OBJECT_ID,
        Scalar::Bool(_) => TAG_BOOL,
        Scalar::DateTime(_) => TAG_DATE_TIME,
        Scalar::Null => TAG_NULL,
        Scalar::Regex(_) => TAG_REGEX,
        Scalar::DbPointer(_) => TAG_DB_POINTER,
        Scalar::JavaScript(_) => TAG_JAVASCRIPT,
        Scalar::Symbol(_) => TAG_SYMBOL,
        Scalar::Int32(_) => TAG_INT32,
        Scalar::Timestamp(_) => TAG_TIMESTAMP,
        Scalar::Int64(_) => TAG_INT64,
        Scalar::Decimal128(_) => TAG_DECIMAL128,
        Scalar::MinKey => TAG_MIN_KEY,
        Scalar::MaxKey => TAG_MAX_KEY,
    }
}

/// Parse one scalar value (given its element tag) from `input`, returning the
/// scalar and the number of bytes consumed.
///
/// Tags of composite types (0x03, 0x04, 0x0F) are rejected — those belong to
/// `wirebson`.
///
/// # Errors
/// * [`ScalarError::ShortInput`] — truncated input.
/// * [`ScalarError::Invalid`] — bad length, bad subtype, or composite tag.
/// * [`ScalarError::Utf8`] — string field is not UTF-8.
pub fn parse_scalar(tag: u8, input: &[u8]) -> Result<(Scalar, usize), ScalarError> {
    use Scalar as S;
    let mut r: &[u8] = input;
    let scalar = match tag {
        TAG_DOUBLE => S::Double(f64::from_le_bytes(r.read_bytes(8)?.try_into().unwrap())),
        TAG_STRING => S::String(parse_string(&mut r, tag)?),
        TAG_BINARY => {
            // The length field counts the payload bytes only (the subtype byte
            // is NOT included) — the real-world convention shared by libbson,
            // the official drivers and recorded MongoDB traffic. (The BSON
            // spec's prose is ambiguous; wire behavior is not.)
            let len = read_u32_as_usize(&mut r, tag)?;
            let subtype = BinarySubtype::from_u8(r.read_u8()?)?;
            let payload_len = match subtype {
                BinarySubtype::BinaryOld => {
                    // Obsolete subtype 2: the stored bytes begin with a
                    // 4-byte inner length; the outer length covers it.
                    let inner = read_u32_as_usize(&mut r, tag)?;
                    if inner + 4 != len {
                        return Err(ScalarError::Invalid {
                            tag,
                            reason: "old binary inner length mismatch",
                        });
                    }
                    inner
                }
                _ => len,
            };
            S::Binary(Binary {
                subtype,
                bytes: r.read_bytes(payload_len)?.to_vec(),
            })
        }
        TAG_UNDEFINED => S::Undefined,
        TAG_OBJECT_ID => S::ObjectId(ObjectId::from_bytes(r.read_bytes(12)?.try_into().unwrap())),
        TAG_BOOL => match r.read_u8()? {
            0 => S::Bool(false),
            1 => S::Bool(true),
            _ => {
                return Err(ScalarError::Invalid {
                    tag,
                    reason: "invalid bool byte",
                });
            }
        },
        TAG_DATE_TIME => S::DateTime(r.read_i64_le()?),
        TAG_NULL => S::Null,
        TAG_REGEX => {
            let pattern = read_cstring_str(&mut r, tag)?;
            let options = read_cstring_str(&mut r, tag)?;
            S::Regex(Regex { pattern, options })
        }
        TAG_DB_POINTER => {
            let namespace = parse_string(&mut r, tag)?;
            let id = ObjectId::from_bytes(r.read_bytes(12)?.try_into().unwrap());
            S::DbPointer(DbPointer { namespace, id })
        }
        TAG_JAVASCRIPT => S::JavaScript(parse_string(&mut r, tag)?),
        TAG_SYMBOL => S::Symbol(parse_string(&mut r, tag)?),
        TAG_INT32 => S::Int32(r.read_i32_le()?),
        TAG_TIMESTAMP => S::Timestamp(Timestamp {
            increment: r.read_u32_le()?, // increment precedes seconds on the wire
            seconds: r.read_u32_le()?,
        }),
        TAG_INT64 => S::Int64(r.read_i64_le()?),
        TAG_DECIMAL128 => S::Decimal128(Decimal128::from_le_bytes(
            r.read_bytes(16)?.try_into().unwrap(),
        )),
        TAG_MIN_KEY => S::MinKey,
        TAG_MAX_KEY => S::MaxKey,
        TAG_DOCUMENT | TAG_ARRAY | TAG_JAVASCRIPT_SCOPE => {
            return Err(ScalarError::Invalid {
                tag,
                reason: "composite type; handled by wirebson",
            });
        }
        _ => {
            return Err(ScalarError::Invalid {
                tag,
                reason: "unknown element type",
            });
        }
    };
    let consumed = input.len() - r.remaining();
    Ok((scalar, consumed))
}

fn parse_string(r: &mut &[u8], tag: u8) -> Result<String, ScalarError> {
    let len = read_u32_as_usize(r, tag)?;
    // Length includes the trailing NUL.
    if len == 0 {
        return Err(ScalarError::Invalid {
            tag,
            reason: "zero-length string",
        });
    }
    let bytes = r.read_bytes(len - 1)?;
    if r.read_u8()? != 0 {
        return Err(ScalarError::Invalid {
            tag,
            reason: "string not NUL-terminated",
        });
    }
    Ok(std::str::from_utf8(bytes)?.to_owned())
}

fn read_cstring_str(r: &mut &[u8], _tag: u8) -> Result<String, ScalarError> {
    let bytes = r.read_cstring()?;
    let owned = bytes.to_vec();
    Ok(std::str::from_utf8(&owned)?.to_owned())
}

fn read_u32_as_usize(r: &mut &[u8], tag: u8) -> Result<usize, ScalarError> {
    let v = r.read_u32_le()?;
    usize::try_from(v).map_err(|_| ScalarError::Invalid {
        tag,
        reason: "impossible length",
    })
}

/// Encode the scalar's value bytes (without the tag byte or field name) into
/// `out`, returning the number of bytes written.
///
/// # Errors
/// Currently infallible; the `Result` keeps room for future validation.
pub fn encode_scalar(s: &Scalar, out: &mut impl ProtocolWrite) -> Result<usize, ScalarError> {
    use Scalar as S;
    let start = out.len();
    match s {
        S::Double(v) => out.put_bytes(&v.to_le_bytes()),
        S::String(v) => encode_string(v, out)?,
        S::Binary(b) => {
            // Length field = payload bytes (excluding the subtype byte);
            // obsolete subtype 2 additionally carries a 4-byte inner length
            // inside the stored bytes, so the outer length is payload + 4.
            let extra = if b.subtype == BinarySubtype::BinaryOld { 4 } else { 0 };
            let len = b
                .bytes
                .len()
                .checked_add(extra)
                .and_then(|l| i32::try_from(l).ok())
                .ok_or(ScalarError::OutOfRange)?;
            out.put_i32_le(len);
            out.put_u8(b.subtype.to_u8());
            if b.subtype == BinarySubtype::BinaryOld {
                let inner = i32::try_from(b.bytes.len()).map_err(|_| ScalarError::OutOfRange)?;
                out.put_i32_le(inner);
            }
            out.put_bytes(&b.bytes);
        }
        S::Undefined | S::Null | S::MinKey | S::MaxKey => {}
        S::ObjectId(v) => out.put_bytes(v.as_bytes()),
        S::Bool(v) => out.put_u8(u8::from(*v)),
        S::DateTime(v) => out.put_i64_le(*v),
        S::Regex(r) => {
            out.put_cstring(&r.pattern).map_err(|_| ScalarError::Invalid {
                tag: TAG_REGEX,
                reason: "interior NUL in pattern",
            })?;
            out.put_cstring(&r.options).map_err(|_| ScalarError::Invalid {
                tag: TAG_REGEX,
                reason: "interior NUL in options",
            })?;
        }
        S::DbPointer(p) => {
            encode_string(&p.namespace, out)?;
            out.put_bytes(p.id.as_bytes());
        }
        S::JavaScript(v) | S::Symbol(v) => encode_string(v, out)?,
        S::Int32(v) => out.put_i32_le(*v),
        S::Timestamp(v) => {
            out.put_u32_le(v.increment);
            out.put_u32_le(v.seconds);
        }
        S::Int64(v) => out.put_i64_le(*v),
        S::Decimal128(v) => out.put_bytes(&v.to_le_bytes()),
    }
    Ok(out.len() - start)
}

fn encode_string(v: &str, out: &mut impl ProtocolWrite) -> Result<(), ScalarError> {
    let len = v
        .len()
        .checked_add(1)
        .and_then(|l| i32::try_from(l).ok())
        .ok_or(ScalarError::OutOfRange)?;
    out.put_i32_le(len);
    out.put_bytes(v.as_bytes());
    out.put_u8(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_scalars() {
        let cases: Vec<Scalar> = vec![
            Scalar::Double(1.5),
            Scalar::String("привет".to_owned()),
            Scalar::Binary(Binary {
                subtype: BinarySubtype::Uuid,
                bytes: vec![1, 2, 3],
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

        for case in cases {
            let mut buf = Vec::new();
            let n = encode_scalar(&case, &mut buf).unwrap();
            let (decoded, used) = parse_scalar(tag_of(&case), &buf).unwrap();
            assert_eq!(used, n, "consumed != written for {case:?}");
            assert_eq!(decoded, case);
        }
    }

    #[test]
    fn truncated_input_errors() {
        let mut buf = Vec::new();
        encode_scalar(&Scalar::String("hello".to_owned()), &mut buf).unwrap();
        for n in 0..buf.len() {
            assert!(
                parse_scalar(TAG_STRING, &buf[..n]).is_err(),
                "expected error at truncation {n}"
            );
        }
    }

    #[test]
    fn composite_tags_rejected() {
        for tag in [TAG_DOCUMENT, TAG_ARRAY, TAG_JAVASCRIPT_SCOPE] {
            assert!(parse_scalar(tag, &[0; 16]).is_err());
        }
    }

    #[test]
    fn binary_old_subtype() {
        // Length field counts everything after the subtype byte:
        // 4-byte inner length + 3 payload bytes = 7.
        let input: Vec<u8> = [
            7u32.to_le_bytes().as_slice(),
            &[0x02],
            3u32.to_le_bytes().as_slice(),
            &[1, 2, 3],
        ]
        .concat();
        let (s, used) = parse_scalar(TAG_BINARY, &input).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(
            s,
            Scalar::Binary(Binary {
                subtype: BinarySubtype::BinaryOld,
                bytes: vec![1, 2, 3],
            })
        );
    }

    #[test]
    fn wire_order_timestamp() {
        // increment first, then seconds.
        let input: Vec<u8> = 0xAAu32
            .to_le_bytes()
            .into_iter()
            .chain(0xBBu32.to_le_bytes())
            .collect();
        let (s, used) = parse_scalar(TAG_TIMESTAMP, &input).unwrap();
        assert_eq!(used, 8);
        assert_eq!(
            s,
            Scalar::Timestamp(Timestamp {
                seconds: 0xBB,
                increment: 0xAA,
            })
        );
    }

    // -----------------------------------------------------------------------
    // ObjectId
    // -----------------------------------------------------------------------

    /// The 3-byte counter, big-endian, as a u32.
    fn object_id_counter(id: &ObjectId) -> u32 {
        let b = id.as_bytes();
        (u32::from(b[9]) << 16) | (u32::from(b[10]) << 8) | u32::from(b[11])
    }

    #[test]
    fn object_id_new_layout() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let mut ids = Vec::new();
        for _ in 0..8 {
            ids.push(ObjectId::new());
        }

        for id in &ids {
            let b = id.as_bytes();
            // Timestamp: 4-byte big-endian unix seconds, within a second of now
            // (generators run on the same machine; allow a small skew).
            let ts = u32::from_be_bytes(b[0..4].try_into().unwrap());
            assert!(
                now.saturating_sub(ts) <= 2,
                "timestamp {ts} too far from now {now}"
            );
        }

        // The 3-byte counter strictly increases per generation within this
        // thread (other threads may interleave, so only bound the distance).
        for pair in ids.windows(2) {
            let delta = object_id_counter(&pair[1]).wrapping_sub(object_id_counter(&pair[0]));
            assert!((1..=1000).contains(&delta), "counter delta {delta}");
            assert_ne!(pair[0], pair[1]);
        }

        // The 5 random middle bytes vary between invocations: with 16 draws
        // from a 2^40 space, seeing fewer than 4 distinct values is impossible
        // for any practical RNG.
        let distinct: std::collections::HashSet<&[u8]> =
            ids.iter().map(|id| &id.as_bytes()[4..9]).collect();
        assert!(distinct.len() >= 4, "random part never varies");
    }

    #[test]
    fn object_id_hex_roundtrip() {
        // The classic MongoDB documentation ObjectId.
        const HEX: &str = "507f1f77bcf86cd799439011";
        const BYTES: [u8; 12] = [
            0x50, 0x7f, 0x1f, 0x77, 0xbc, 0xf8, 0x6c, 0xd7, 0x99, 0x43, 0x90, 0x11,
        ];

        let id = ObjectId::from_bytes(BYTES);
        assert_eq!(id.to_hex(), HEX);
        assert_eq!(id.to_string(), HEX);
        assert_eq!(ObjectId::from_hex(HEX).unwrap(), id);

        // Case-insensitive input, lowercase output.
        let upper = ObjectId::from_hex(&HEX.to_uppercase()).unwrap();
        assert_eq!(upper, id);
        assert_eq!(upper.to_hex(), HEX);

        // Output only ever contains lowercase hex digits.
        for generated in [ObjectId::new(), ObjectId::new()] {
            let hex = generated.to_hex();
            assert_eq!(hex.len(), 24);
            assert!(
                hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "not lowercase hex: {hex}"
            );
            assert_eq!(ObjectId::from_hex(&hex).unwrap(), generated);

            // Generated ids also survive a wire round-trip.
            let mut buf = Vec::new();
            encode_scalar(&Scalar::ObjectId(generated), &mut buf).unwrap();
            let (decoded, used) = parse_scalar(TAG_OBJECT_ID, &buf).unwrap();
            assert_eq!(used, 12);
            assert_eq!(decoded, Scalar::ObjectId(generated));
        }
    }

    #[test]
    fn object_id_hex_errors() {
        let valid = "507f1f77bcf86cd799439011";

        let too_short = &valid[..23];
        assert_eq!(
            ObjectId::from_hex(too_short),
            Err(ScalarError::Invalid {
                tag: TAG_OBJECT_ID,
                reason: "object id hex string must be 24 characters",
            })
        );
        assert!(ObjectId::from_hex("").is_err());
        assert!(ObjectId::from_hex("507F1F77BCF86CD7994390110").is_err()); // 25 chars

        for bad in [
            "507f1f77bcf86cd79943901g", // trailing non-hex
            "507f1f77bcf86cd79943901 ", // trailing space
            "z07f1f77bcf86cd799439011", // leading non-hex
            "507f1f77bcf86cd79943901\x01",
        ] {
            assert_eq!(
                ObjectId::from_hex(bad),
                Err(ScalarError::Invalid {
                    tag: TAG_OBJECT_ID,
                    reason: "object id hex string contains a non-hex character",
                })
            );
        }

        // Empty/multibyte unicode input is rejected, not panicking.
        assert!(ObjectId::from_hex("разработка").is_err());
        assert!(ObjectId::from_hex("507f1f77bcf86cd79943901😀").is_err());
    }
}
