//! Conversions between BSON scalars and native Rust types — the MongoDB
//! counterpart of `mysql_common`'s value conversions.
//!
//! Falling conversions are lossless (`From`); narrowing conversions are
//! range-checked and return [`ScalarError::OutOfRange`]; kind mismatches
//! return [`ScalarError::NotConvertible`].

use super::scalar::{Binary, ObjectId, Scalar, ScalarError};
#[cfg(feature = "uuid")]
use super::scalar::BinarySubtype;

impl From<i32> for Scalar {
    fn from(v: i32) -> Self {
        Self::Int32(v)
    }
}

impl From<i64> for Scalar {
    fn from(v: i64) -> Self {
        Self::Int64(v)
    }
}

impl From<f64> for Scalar {
    fn from(v: f64) -> Self {
        Self::Double(v)
    }
}

impl From<bool> for Scalar {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<String> for Scalar {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for Scalar {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}

impl From<ObjectId> for Scalar {
    fn from(v: ObjectId) -> Self {
        Self::ObjectId(v)
    }
}

impl From<Binary> for Scalar {
    fn from(v: Binary) -> Self {
        Self::Binary(v)
    }
}

/// Signed integers below `i32` always fit.
macro_rules! scalar_from_small_signed {
    ($($t:ty),*) => {
        $(impl From<$t> for Scalar {
            fn from(v: $t) -> Self { Self::Int32(i32::from(v)) }
        })*
    };
}

scalar_from_small_signed!(i8, i16);

impl From<u8> for Scalar {
    fn from(v: u8) -> Self {
        Self::Int32(i32::from(v))
    }
}

impl From<u16> for Scalar {
    fn from(v: u16) -> Self {
        Self::Int32(i32::from(v))
    }
}

macro_rules! try_from_numeric {
    ($($t:ty),*) => {
        $(impl TryFrom<&Scalar> for $t {
            type Error = ScalarError;

            fn try_from(v: &Scalar) -> Result<$t, ScalarError> {
                let wide: i64 = match v {
                    Scalar::Int32(i) => i64::from(*i),
                    Scalar::Int64(i) => *i,
                    Scalar::Bool(b) => i64::from(*b),
                    Scalar::Double(f) if f.fract() == 0.0 && *f >= i64::MIN as f64 && *f <= i64::MAX as f64 => *f as i64,
                    _ => return Err(ScalarError::NotConvertible),
                };
                <$t>::try_from(wide).map_err(|_| ScalarError::OutOfRange)
            }
        })*
    };
}

try_from_numeric!(i8, i16, i32, i64, i128, u8, u16, u32, u64);

impl TryFrom<&Scalar> for f64 {
    type Error = ScalarError;

    fn try_from(v: &Scalar) -> Result<f64, ScalarError> {
        match v {
            Scalar::Double(f) => Ok(*f),
            Scalar::Int32(i) => Ok(f64::from(*i)),
            Scalar::Int64(i) => Ok(*i as f64),
            _ => Err(ScalarError::NotConvertible),
        }
    }
}

impl TryFrom<&Scalar> for f32 {
    type Error = ScalarError;

    fn try_from(v: &Scalar) -> Result<f32, ScalarError> {
        f64::try_from(v).map(|f| f as f32)
    }
}

impl TryFrom<&Scalar> for bool {
    type Error = ScalarError;

    fn try_from(v: &Scalar) -> Result<bool, ScalarError> {
        match v {
            Scalar::Bool(b) => Ok(*b),
            _ => Err(ScalarError::NotConvertible),
        }
    }
}

impl TryFrom<&Scalar> for String {
    type Error = ScalarError;

    fn try_from(v: &Scalar) -> Result<String, ScalarError> {
        match v {
            Scalar::String(s) | Scalar::JavaScript(s) | Scalar::Symbol(s) => Ok(s.clone()),
            Scalar::ObjectId(id) => Ok(id.to_hex()),
            _ => Err(ScalarError::NotConvertible),
        }
    }
}

impl TryFrom<&Scalar> for std::time::SystemTime {
    type Error = ScalarError;

    fn try_from(v: &Scalar) -> Result<std::time::SystemTime, ScalarError> {
        match v {
            Scalar::DateTime(ms) => {
                let d = std::time::Duration::from_millis(ms.unsigned_abs());
                if *ms >= 0 {
                    Ok(std::time::UNIX_EPOCH + d)
                } else {
                    Ok(std::time::UNIX_EPOCH - d)
                }
            }
            _ => Err(ScalarError::NotConvertible),
        }
    }
}

impl From<std::time::SystemTime> for Scalar {
    fn from(t: std::time::SystemTime) -> Self {
        match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Scalar::DateTime(d.as_millis() as i64),
            Err(e) => Scalar::DateTime(-(e.duration().as_millis() as i64)),
        }
    }
}

impl TryFrom<&Scalar> for std::time::Duration {
    type Error = ScalarError;

    fn try_from(v: &Scalar) -> Result<std::time::Duration, ScalarError> {
        match v {
            Scalar::Int64(ms) if *ms >= 0 => Ok(std::time::Duration::from_millis(*ms as u64)),
            _ => Err(ScalarError::NotConvertible),
        }
    }
}

#[cfg(feature = "uuid")]
impl TryFrom<&Scalar> for uuid::Uuid {
    type Error = ScalarError;

    fn try_from(v: &Scalar) -> Result<uuid::Uuid, ScalarError> {
        match v {
            Scalar::Binary(b) if b.subtype == BinarySubtype::Uuid && b.bytes.len() == 16 => {
                uuid::Uuid::from_slice(&b.bytes).map_err(|_| ScalarError::OutOfRange)
            }
            _ => Err(ScalarError::NotConvertible),
        }
    }
}

#[cfg(feature = "uuid")]
impl From<uuid::Uuid> for Scalar {
    fn from(v: uuid::Uuid) -> Self {
        Scalar::Binary(Binary {
            subtype: BinarySubtype::Uuid,
            bytes: v.as_bytes().to_vec(),
        })
    }
}

#[cfg(feature = "decimal128-convert")]
impl TryFrom<&Scalar> for dec::Decimal128 {
    type Error = ScalarError;

    fn try_from(v: &Scalar) -> Result<dec::Decimal128, ScalarError> {
        match v {
            Scalar::Decimal128(d) => {
                // The 16 wire bytes are exactly the IEEE 764-2008 decimal128
                // interchange representation (1 sign bit, 17-bit combination
                // field, 113-bit DPD coefficient continuation) in little-endian
                // order, and `dec::Decimal128` stores that same representation —
                // its `from_le_bytes`/`to_le_bytes` take and produce it natively
                // (see its NAN/ZERO/ONE constants). So this is a lossless,
                // bit-preserving conversion: NaNs, infinities, signed zero and
                // payload bits all survive, and it cannot fail.
                Ok(dec::Decimal128::from_le_bytes(d.to_le_bytes()))
            }
            _ => Err(ScalarError::NotConvertible),
        }
    }
}

#[cfg(feature = "decimal128-convert")]
impl From<dec::Decimal128> for Scalar {
    fn from(v: dec::Decimal128) -> Self {
        Scalar::Decimal128(super::scalar::Decimal128::from_le_bytes(v.to_le_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrowing_is_range_checked() {
        assert_eq!(i8::try_from(&Scalar::Int32(127)).unwrap(), 127);
        assert_eq!(
            i8::try_from(&Scalar::Int32(128)),
            Err(ScalarError::OutOfRange)
        );
        assert_eq!(
            u8::try_from(&Scalar::Int32(-1)),
            Err(ScalarError::OutOfRange)
        );
        assert_eq!(i128::try_from(&Scalar::Int64(-5)).unwrap(), -5);
        assert_eq!(
            u64::try_from(&Scalar::Int64(-5)),
            Err(ScalarError::OutOfRange)
        );
    }

    #[test]
    fn kind_mismatch_is_not_convertible() {
        assert_eq!(
            i64::try_from(&Scalar::String("x".to_owned())),
            Err(ScalarError::NotConvertible)
        );
        assert_eq!(
            bool::try_from(&Scalar::Int32(1)),
            Err(ScalarError::NotConvertible)
        );
    }

    #[test]
    fn int_from_double_requires_integral() {
        assert_eq!(i64::try_from(&Scalar::Double(2.0)).unwrap(), 2);
        assert_eq!(
            i64::try_from(&Scalar::Double(2.5)),
            Err(ScalarError::NotConvertible)
        );
    }

    #[test]
    fn string_forms() {
        assert_eq!(
            String::try_from(&Scalar::Symbol("s".to_owned())).unwrap(),
            "s"
        );
    }

    #[test]
    fn system_time_roundtrip() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(123_456);
        let s = Scalar::from(t);
        assert_eq!(std::time::SystemTime::try_from(&s).unwrap(), t);
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn uuid_roundtrip() {
        let u = uuid::Uuid::nil();
        let s = Scalar::from(u);
        assert_eq!(uuid::Uuid::try_from(&s).unwrap(), u);
    }

    #[cfg(feature = "decimal128-convert")]
    mod decimal128 {
        use super::*;
        use crate::bson::Decimal128;

        /// Scalar holding exactly these wire bits (IEEE 764-2008 decimal128,
        /// little-endian order).
        fn scalar_from_bits(bits: u128) -> Scalar {
            Scalar::Decimal128(Decimal128::from_le_bytes(bits.to_le_bytes()))
        }

        /// Known decimal128 bit patterns. The u128 values are the interchange
        /// bit patterns produced by decNumber (the IEEE 764-2008 reference
        /// implementation, as wrapped by `dec`) for the given textual value;
        /// each is re-validated against `dec`'s parser at run time below.
        const CASES: &[(&str, u128)] = &[
            ("1", 0x2208_0000_0000_0000_0000_0000_0000_0001),
            ("1.5", 0x2207_c000_0000_0000_0000_0000_0000_0015),
            ("-1.5", 0xa207_c000_0000_0000_0000_0000_0000_0015),
            // Negative zero keeps its sign bit.
            ("-0", 0xa208_0000_0000_0000_0000_0000_0000_0000),
            ("0.000001", 0x2206_8000_0000_0000_0000_0000_0000_0001),
            ("-123.456", 0xa207_4000_0000_0000_0000_0000_0002_8e56),
            // Extreme exponents: smallest subnormal and largest exponent.
            ("1E-6176", 0x0000_0000_0000_0000_0000_0000_0000_0001),
            ("1E+6111", 0x43ff_c000_0000_0000_0000_0000_0000_0001),
            // Full 34-digit coefficient.
            (
                "1234567890123456789012345678901234",
                0x2608_134b_9c1e_28e5_6f3c_1271_7782_3534,
            ),
            ("Infinity", 0x7800_0000_0000_0000_0000_0000_0000_0000),
            ("-Infinity", 0xf800_0000_0000_0000_0000_0000_0000_0000),
            ("NaN", 0x7c00_0000_0000_0000_0000_0000_0000_0000),
        ];

        #[test]
        fn known_bit_patterns_roundtrip() {
            for &(text, bits) in CASES {
                let parsed: dec::Decimal128 = text.parse().unwrap();
                // Sanity-check the vector itself against decNumber.
                assert_eq!(
                    parsed.to_le_bytes(),
                    bits.to_le_bytes(),
                    "vector for {text:?} disagrees with dec"
                );

                let scalar = scalar_from_bits(bits);

                // Scalar -> dec preserves bits (byte equality: dec's `PartialEq`
                // is numeric, so it cannot compare NaNs).
                let d = dec::Decimal128::try_from(&scalar).unwrap();
                assert_eq!(d.to_le_bytes(), bits.to_le_bytes(), "{text}");
                assert_eq!(d.to_le_bytes(), parsed.to_le_bytes(), "{text}");

                // dec -> Scalar preserves bits exactly.
                assert_eq!(Scalar::from(d), scalar, "{text}");
            }
        }

        #[test]
        fn decimal128_value_semantics() {
            let d = dec::Decimal128::try_from(&scalar_from_bits(
                0x2207_c000_0000_0000_0000_0000_0000_0015,
            ))
            .unwrap();
            assert_eq!(d.to_standard_notation_string(), "1.5");
            assert_eq!(d.exponent(), -1);
            assert_eq!(d.coefficient(), 15);

            let d = dec::Decimal128::try_from(&scalar_from_bits(
                0xa207_4000_0000_0000_0000_0000_0002_8e56,
            ))
            .unwrap();
            assert_eq!(d.to_standard_notation_string(), "-123.456");
            assert_eq!(d.exponent(), -3);
            assert_eq!(d.coefficient(), -123_456);

            // Negative zero is zero, but signed.
            let d = dec::Decimal128::try_from(&scalar_from_bits(
                0xa208_0000_0000_0000_0000_0000_0000_0000,
            ))
            .unwrap();
            assert!(d.is_zero() && d.is_signed());

            // Extremes: 1E-6176 is the smallest subnormal, 1E+6111 the largest
            // exponent.
            let d = dec::Decimal128::try_from(&scalar_from_bits(1)).unwrap();
            assert_eq!(d.exponent(), -6176);
            assert!(d.is_subnormal());

            let d = dec::Decimal128::try_from(&Scalar::from("1E+6111".parse::<dec::Decimal128>().unwrap())).unwrap();
            assert_eq!(d.exponent(), 6111);
            assert_eq!(d.coefficient(), 1);
        }

        #[test]
        fn decimal128_nan_and_inf() {
            // Positive infinity.
            let d = dec::Decimal128::try_from(&scalar_from_bits(
                0x7800_0000_0000_0000_0000_0000_0000_0000,
            ))
            .unwrap();
            assert!(d.is_infinite() && !d.is_negative());

            // Negative infinity.
            let d = dec::Decimal128::try_from(&scalar_from_bits(
                0xf800_0000_0000_0000_0000_0000_0000_0000,
            ))
            .unwrap();
            assert!(d.is_infinite() && d.is_negative());

            // NaN: dec never rejects it, and payload bits survive the round trip.
            let bits = 0x7c00_0000_0000_0000_0000_0000_1f3a_b6d1; // payload bits set
            let d = dec::Decimal128::try_from(&scalar_from_bits(bits)).unwrap();
            assert!(d.is_nan() && !d.is_infinite());
            assert_eq!(Scalar::from(d), scalar_from_bits(bits));

            // dec's own specials convert back to their exact bits.
            for special in [
                dec::Decimal128::NAN,
                dec::Decimal128::ZERO,
                dec::Decimal128::ONE,
            ] {
                assert_eq!(
                    dec::Decimal128::try_from(&Scalar::from(special))
                        .unwrap()
                        .to_le_bytes(),
                    special.to_le_bytes()
                );
            }
        }

        #[test]
        fn decimal128_roundtrip_random_bits() {
            // Bit-exact round trip over arbitrary bit patterns, including
            // non-canonical encodings and specials.
            for _ in 0..1000 {
                let bits = rand::random::<u128>();
                let scalar = scalar_from_bits(bits);
                let d = dec::Decimal128::try_from(&scalar)
                    .unwrap_or_else(|e| panic!("{bits:#034x}: {e:?}"));
                assert_eq!(d.to_le_bytes(), bits.to_le_bytes(), "{bits:#034x}");
                assert_eq!(Scalar::from(d), scalar, "{bits:#034x}");
            }
        }

        #[test]
        fn decimal128_kind_mismatch() {
            assert_eq!(
                dec::Decimal128::try_from(&Scalar::Int32(1)),
                Err(ScalarError::NotConvertible)
            );
            assert_eq!(
                dec::Decimal128::try_from(&Scalar::String("1.5".to_owned())),
                Err(ScalarError::NotConvertible)
            );
            assert_eq!(
                dec::Decimal128::try_from(&Scalar::Null),
                Err(ScalarError::NotConvertible)
            );
        }
    }
}
