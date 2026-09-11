//! Compile-time syntax sugar for building [`Document`] / [`Array`] values.
//!
//! * [`doc!`] — comma-separated `key: value` pairs → [`Document`].
//! * [`arr!`] — comma-separated values → [`Array`].
//! * [`oid!`] — 24-char hex string → `Bson::ObjectId`.
//! * [`dt!`] — i64 epoch milliseconds → `Bson::DateTime`.
//!
//! These wrap the existing `Into<Bson>` conversions; they do no parsing of
//! their own beyond what Rust's literal/identifier matching already provides.
//! `null`, `MIN_KEY`, and `MAX_KEY` are recognised as identifiers and mapped
//! to the corresponding [`Bson`] variants.
//!
//! Nested documents/arrays must re-enter `doc!` / `arr!`:
//!
//! ```
//! use wirebson::{doc, arr};
//!
//! let user = doc! {
//!     "name": "ada",
//!     "age": 36,
//!     "tags": arr!["math", "cs"],
//!     "meta": doc! { "v": 1 },
//!     "deleted": null,
//! };
//! assert_eq!(user.len(), 5);
//! ```

/// Build a [`Document`] from comma-separated `"key": value` pairs.
///
/// Numeric, string, and boolean literals are mapped to their natural BSON
/// types via the existing `Into<Bson>` conversions (`30` → `Int32`,
/// `30i64` → `Int64`, `3.14` → `Double`, `"s"` → `String`, `true` → `Bool`).
/// The identifiers `null`, `MIN_KEY`, and `MAX_KEY` produce the corresponding
/// `Bson` variants. Other values are inserted via `Into<Bson>`.
#[macro_export]
macro_rules! doc {
    () => {{
        $crate::Document::new()
    }};
    ( $($pairs:tt)* ) => {{
        let mut __doc = $crate::Document::new();
        $crate::__doc_build!(__doc, $($pairs)*);
        __doc
    }};
}

/// Build an [`Array`] from comma-separated values.
///
/// See [`doc!`] for the rules on literal types, `null` / `MIN_KEY` / `MAX_KEY`,
/// and the role of `Into<Bson>`.
#[macro_export]
macro_rules! arr {
    () => {{
        $crate::Array::new()
    }};
    ( $($items:tt)* ) => {{
        let mut __arr = $crate::Array::new();
        $crate::__arr_build!(__arr, $($items)*);
        __arr
    }};
}

/// Build a `Bson::ObjectId` from a 24-character hexadecimal string.
///
/// Panics at runtime if `s` is not exactly 24 hex characters. Use
/// [`mongo_common::bson::ObjectId::from_hex`] directly when you need error
/// handling.
#[macro_export]
macro_rules! oid {
    ($s:expr) => {
        $crate::Bson::ObjectId(
            $crate::macros::__oid_from_hex($s)
                .unwrap_or_else(|__e| panic!("oid!(): invalid hex string {:?}: {:?}", $s, __e))
        )
    };
}

/// Build a `Bson::DateTime` from an `i64` epoch milliseconds value.
#[macro_export]
macro_rules! dt {
    ($ms:expr) => {
        $crate::Bson::DateTime($ms)
    };
}

// ---------------------------------------------------------------------------
// Internal helpers — not part of the public API.
// ---------------------------------------------------------------------------
//
// `doc!` / `arr!` use a tt-muncher because `null` is a reserved keyword
// (cannot appear in `:expr` position) and `MIN_KEY` / `MAX_KEY` are
// identifiers without a binding; the dedicated arms match them as bare
// tokens before the generic `:expr` arm is reached.

#[doc(hidden)]
#[macro_export]
macro_rules! __doc_build {
    // terminator: nothing left to consume
    ($doc:ident,) => {};
    ($doc:ident) => {};

    // null — with trailing comma and rest
    ($doc:ident, $key:literal : null , $($rest:tt)*) => {
        $doc.add($key, $crate::Bson::Null);
        $crate::__doc_build!($doc, $($rest)*);
    };
    // null — last pair
    ($doc:ident, $key:literal : null) => {
        $doc.add($key, $crate::Bson::Null);
    };

    // MIN_KEY
    ($doc:ident, $key:literal : MIN_KEY , $($rest:tt)*) => {
        $doc.add($key, $crate::Bson::MinKey);
        $crate::__doc_build!($doc, $($rest)*);
    };
    ($doc:ident, $key:literal : MIN_KEY) => {
        $doc.add($key, $crate::Bson::MinKey);
    };

    // MAX_KEY
    ($doc:ident, $key:literal : MAX_KEY , $($rest:tt)*) => {
        $doc.add($key, $crate::Bson::MaxKey);
        $crate::__doc_build!($doc, $($rest)*);
    };
    ($doc:ident, $key:literal : MAX_KEY) => {
        $doc.add($key, $crate::Bson::MaxKey);
    };

    // generic — with trailing comma and rest
    ($doc:ident, $key:literal : $value:expr , $($rest:tt)*) => {
        $doc.add($key, $value);
        $crate::__doc_build!($doc, $($rest)*);
    };
    // generic — last pair
    ($doc:ident, $key:literal : $value:expr) => {
        $doc.add($key, $value);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __arr_build {
    // terminator
    ($arr:ident,) => {};
    ($arr:ident) => {};

    // null
    ($arr:ident, null , $($rest:tt)*) => {
        $arr.push($crate::Bson::Null);
        $crate::__arr_build!($arr, $($rest)*);
    };
    ($arr:ident, null) => {
        $arr.push($crate::Bson::Null);
    };

    // MIN_KEY
    ($arr:ident, MIN_KEY , $($rest:tt)*) => {
        $arr.push($crate::Bson::MinKey);
        $crate::__arr_build!($arr, $($rest)*);
    };
    ($arr:ident, MIN_KEY) => {
        $arr.push($crate::Bson::MinKey);
    };

    // MAX_KEY
    ($arr:ident, MAX_KEY , $($rest:tt)*) => {
        $arr.push($crate::Bson::MaxKey);
        $crate::__arr_build!($arr, $($rest)*);
    };
    ($arr:ident, MAX_KEY) => {
        $arr.push($crate::Bson::MaxKey);
    };

    // generic
    ($arr:ident, $value:expr , $($rest:tt)*) => {
        $arr.push($value);
        $crate::__arr_build!($arr, $($rest)*);
    };
    ($arr:ident, $value:expr) => {
        $arr.push($value);
    };
}

// Helper for `oid!`: regular function so the panic message stays stable and
// callers can call it directly when they want a Result.
#[doc(hidden)]
#[inline]
pub fn __oid_from_hex(
    s: &str,
) -> ::core::result::Result<mongo_common::bson::ObjectId, mongo_common::bson::ScalarError> {
    mongo_common::bson::ObjectId::from_hex(s)
}

#[cfg(test)]
mod tests {
    use crate::{Array, Bson, Document};

    #[test]
    fn doc_empty() {
        let d = doc! {};
        assert!(d.is_empty());
        assert_eq!(d, Document::new());
    }

    #[test]
    fn doc_int32_default() {
        let d = doc! { "n": 30 };
        assert_eq!(d.get("n"), Some(&Bson::Int32(30)));
    }

    #[test]
    fn doc_int64_explicit() {
        let d = doc! { "n": 30i64 };
        assert_eq!(d.get("n"), Some(&Bson::Int64(30)));
    }

    #[test]
    fn doc_double() {
        let d = doc! { "r": 1.25 };
        assert_eq!(d.get("r"), Some(&Bson::Double(1.25)));
    }

    #[test]
    fn doc_string() {
        let d = doc! { "s": "hi" };
        assert_eq!(d.get("s"), Some(&Bson::String("hi".to_owned())));
    }

    #[test]
    fn doc_bool() {
        let d = doc! { "on": true, "off": false };
        assert_eq!(d.get("on"), Some(&Bson::Bool(true)));
        assert_eq!(d.get("off"), Some(&Bson::Bool(false)));
    }

    #[test]
    fn doc_null() {
        let d = doc! { "x": null };
        assert_eq!(d.get("x"), Some(&Bson::Null));
    }

    #[test]
    fn doc_min_max_keys() {
        let d = doc! { "lo": MIN_KEY, "hi": MAX_KEY };
        assert_eq!(d.get("lo"), Some(&Bson::MinKey));
        assert_eq!(d.get("hi"), Some(&Bson::MaxKey));
    }

    #[test]
    fn doc_nested() {
        let d = doc! {
            "user": doc! { "name": "x", "v": 1i64 },
            "tags": arr!["a", "b"],
        };
        assert_eq!(d.len(), 2);
        match d.get("user") {
            Some(Bson::Document(inner)) => {
                assert_eq!(inner.get("name"), Some(&Bson::String("x".to_owned())));
                assert_eq!(inner.get("v"), Some(&Bson::Int64(1)));
            }
            other => panic!("expected nested doc, got {other:?}"),
        }
        match d.get("tags") {
            Some(Bson::Array(arr)) => {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr.iter().next(), Some(&Bson::String("a".to_owned())));
            }
            other => panic!("expected nested array, got {other:?}"),
        }
    }

    #[test]
    fn doc_preserves_field_order_and_duplicates() {
        let d = doc! { "a": 1, "b": 2, "a": 3 };
        let names: Vec<&str> = d.field_names().collect();
        assert_eq!(names, vec!["a", "b", "a"]);
        // get returns the FIRST occurrence, matching Document semantics.
        assert_eq!(d.get("a"), Some(&Bson::Int32(1)));
    }

    #[test]
    fn doc_trailing_comma_ok() {
        let d = doc! { "a": 1, "b": 2, };
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn doc_expression_value() {
        let v: i64 = 42;
        let s = String::from("dyn");
        let d = doc! { "v": v, "s": s };
        assert_eq!(d.get("v"), Some(&Bson::Int64(42)));
        assert_eq!(d.get("s"), Some(&Bson::String("dyn".to_owned())));
    }

    #[test]
    fn doc_encode_decode_roundtrip() {
        let d = doc! {
            "s": "x",
            "n": 7,
            "arr": arr![1, 1.25, null, MAX_KEY],
            "inner": doc! { "k": true },
        };
        let raw = d.encode().expect("encode");
        assert_eq!(raw.deep().expect("deep"), d);
    }

    #[test]
    fn arr_empty() {
        let a = arr![];
        assert!(a.is_empty());
        assert_eq!(a, Array::new());
    }

    #[test]
    fn arr_scalars() {
        let a = arr![1, 1.25, "three", true, null, MIN_KEY];
        let v: Vec<&Bson> = a.iter().collect();
        assert_eq!(
            v,
            vec![
                &Bson::Int32(1),
                &Bson::Double(1.25),
                &Bson::String("three".to_owned()),
                &Bson::Bool(true),
                &Bson::Null,
                &Bson::MinKey,
            ]
        );
    }

    #[test]
    fn arr_trailing_comma_ok() {
        let a = arr![1, 2, 3,];
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn arr_nested() {
        let a = arr![1, doc! { "k": 1 }, arr![2, 3]];
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn oid_string_literal() {
        let hex = "507f1f77bcf86cd799439011";
        let v = oid!(hex);
        let expected = mongo_common::bson::ObjectId::from_hex(hex).unwrap();
        assert_eq!(v, Bson::ObjectId(expected));
        // First/last byte of the parsed ObjectId.
        let bytes = expected.as_bytes();
        assert_eq!(bytes[0], 0x50);
        assert_eq!(bytes[11], 0x11);
    }

    #[test]
    fn dt_i64() {
        assert_eq!(dt!(1234567890), Bson::DateTime(1234567890));
    }

    #[test]
    fn dt_expression() {
        let ms: i64 = 999;
        assert_eq!(dt!(ms), Bson::DateTime(999));
    }
}
