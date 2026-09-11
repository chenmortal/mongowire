//! Conversions between [`Bson`] and native Rust types.
//!
//! * `From<T> for Bson` — lossless, infallible.
//! * `TryFrom<&Bson> for T` — kind-mismatch → [`Error::Scalar`](crate::error::Error::Scalar)
//!   ([`ScalarError::NotConvertible`](mongo_common::bson::ScalarError::NotConvertible)),
//!   out-of-range → out-of-range.
//!
//! Time, Uuid and Decimal support follows `mongo_common::bson::convert`.

use crate::value::Bson;

macro_rules! bson_from_signed {
    ($($t:ty),*) => {
        $(impl From<$t> for Bson {
            fn from(v: $t) -> Self { Self::Int32(i32::from(v)) }
        })*
    };
}

bson_from_signed!(i8, i16);

impl From<u8> for Bson {
    fn from(v: u8) -> Self {
        Self::Int32(i32::from(v))
    }
}

impl From<u16> for Bson {
    fn from(v: u16) -> Self {
        Self::Int32(i32::from(v))
    }
}

impl From<i32> for Bson {
    fn from(v: i32) -> Self {
        Self::Int32(v)
    }
}

impl From<i64> for Bson {
    fn from(v: i64) -> Self {
        Self::Int64(v)
    }
}

impl From<f64> for Bson {
    fn from(v: f64) -> Self {
        Self::Double(v)
    }
}

impl From<bool> for Bson {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<String> for Bson {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for Bson {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}

impl From<mongo_common::bson::ObjectId> for Bson {
    fn from(v: mongo_common::bson::ObjectId) -> Self {
        Self::ObjectId(v)
    }
}

impl From<mongo_common::bson::scalar::Binary> for Bson {
    fn from(v: mongo_common::bson::scalar::Binary) -> Self {
        Self::Binary(v)
    }
}

impl From<mongo_common::bson::Regex> for Bson {
    fn from(v: mongo_common::bson::Regex) -> Self {
        Self::Regex(v)
    }
}

impl From<mongo_common::bson::scalar::Timestamp> for Bson {
    fn from(v: mongo_common::bson::scalar::Timestamp) -> Self {
        Self::Timestamp(v)
    }
}

/// Narrowing numeric conversions, delegating to the scalar layer.
macro_rules! bson_try_numeric {
    ($($t:ty),*) => {
        $(impl TryFrom<&Bson> for $t {
            type Error = crate::Error;

            fn try_from(v: &Bson) -> Result<$t, crate::Error> {
                match v.as_scalar() {
                    Some(s) => Ok(<$t>::try_from(&s)?),
                    None => Err(mongo_common::bson::ScalarError::NotConvertible.into()),
                }
            }
        })*
    };
}

bson_try_numeric!(i8, i16, i32, i64, i128, u8, u16, u32, u64, f32, f64, bool, String);

impl TryFrom<&Bson> for std::time::SystemTime {
    type Error = crate::Error;

    fn try_from(v: &Bson) -> Result<std::time::SystemTime, crate::Error> {
        match v.as_scalar() {
            Some(s) => Ok(std::time::SystemTime::try_from(&s)?),
            None => Err(mongo_common::bson::ScalarError::NotConvertible.into()),
        }
    }
}

impl From<std::time::SystemTime> for Bson {
    fn from(t: std::time::SystemTime) -> Self {
        Self::DateTime(match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_millis() as i64,
            Err(e) => -(e.duration().as_millis() as i64),
        })
    }
}

#[cfg(feature = "serde_json")]
mod serde_json_conv {
    use super::Bson;
    use crate::{Array, Document};
    use mongo_common::bson::Binary;

    impl TryFrom<&Bson> for serde_json::Value {
        type Error = crate::Error;

        fn try_from(v: &Bson) -> Result<serde_json::Value, crate::Error> {
            Ok(match v {
                Bson::Double(f) => serde_json::Value::from(*f),
                Bson::String(s) | Bson::JavaScript(s) | Bson::Symbol(s) => {
                    serde_json::Value::from(s.as_str())
                }
                Bson::Bool(b) => serde_json::Value::from(*b),
                Bson::Null | Bson::Undefined => serde_json::Value::Null,
                Bson::Int32(i) => serde_json::Value::from(*i),
                Bson::Int64(i) => serde_json::Value::from(*i),
                Bson::DateTime(ms) => serde_json::Value::from(*ms),
                Bson::ObjectId(id) => serde_json::Value::from(id.to_hex()),
                Bson::Decimal128(d) => serde_json::Value::from(format!("{d:?}")),
                Bson::Document(doc) => {
                    let mut map = serde_json::Map::new();
                    for (k, v) in doc.iter() {
                        map.insert(k.to_owned(), serde_json::Value::try_from(v)?);
                    }
                    serde_json::Value::Object(map)
                }
                Bson::Array(arr) => {
                    let mut list = Vec::with_capacity(arr.len());
                    for v in arr.iter() {
                        list.push(serde_json::Value::try_from(v)?);
                    }
                    serde_json::Value::Array(list)
                }
                // Binary-ish types render as extended-json-shaped maps.
                Bson::Binary(b) => json_binary(b),
                Bson::Timestamp(_) | Bson::Regex(_) | Bson::DbPointer(_) => {
                    return Err(crate::Error::invalid(
                        0,
                        "extended-json rendering not implemented for this type",
                    ));
                }
                Bson::JavaScriptScope { .. } | Bson::MinKey | Bson::MaxKey => {
                    return Err(crate::Error::invalid(
                        0,
                        "extended-json rendering not implemented for this type",
                    ));
                }
            })
        }
    }

    fn json_binary(b: &Binary) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "$binary".to_owned(),
            serde_json::Value::from(hex_string(&b.bytes)),
        );
        serde_json::Value::Object(map)
    }

    fn hex_string(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    impl From<&Document> for serde_json::Value {
        fn from(doc: &Document) -> Self {
            serde_json::Value::try_from(&Bson::Document(doc.clone()))
                .unwrap_or(serde_json::Value::Null)
        }
    }

    impl From<&Array> for serde_json::Value {
        fn from(arr: &Array) -> Self {
            serde_json::Value::try_from(&Bson::Array(arr.clone())).unwrap_or(serde_json::Value::Null)
        }
    }
}
