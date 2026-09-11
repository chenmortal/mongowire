//! BSON scalar layer.
//!
//! This module owns the pure scalar types ([`scalar`]) shared by every BSON
//! implementation in the workspace, tag-level scalar parsing/encoding, and
//! conversions between scalars and native Rust types ([`convert`]).
//!
//! Composite values (documents, arrays, code-with-scope) belong to the
//! `wirebson` crate, which builds on top of this module.

pub mod convert;
pub mod scalar;

pub use scalar::{
    Binary, BinarySubtype, Decimal128, DbPointer, ObjectId, Regex, Scalar, ScalarError, Timestamp,
    encode_scalar, parse_scalar, tag_of,
};
