//! BSON documents for the MongoDB wire protocol, modeled after FerretDB's
//! `wirebson`.
//!
//! Two shapes of every composite value:
//!
//! * **Raw** ([`RawDocument`] / [`RawArray`]) — the bytes themselves, held in
//!   a [`bytes::Bytes`] so slicing off a decoded message is zero-copy.
//! * **Eager** ([`Document`] / [`Array`]) — parsed fields, mutable.
//!
//! Decoding is available in two depths, mirroring the Go reference:
//! [`RawDocument::shallow`] keeps nested composites raw (cheap), while
//! [`RawDocument::deep`] recurses fully.
//!
//! All 20 BSON element types are supported and round-trippable, including the
//! deprecated ones (DBPointer, Symbol, …) that the Go reference rejects.

#![forbid(unsafe_code)]

pub mod array;
pub mod convert;
pub mod decode;
pub mod document;
pub mod encode;
pub mod error;
pub mod raw;
pub mod raw_value;
pub mod value;

pub use array::Array;
pub use document::{Document, Field};
pub use error::Error;
pub use raw::{FieldsIter, RawArray, RawDocument};
pub use raw_value::RawBsonRef;
pub use value::Bson;

/// Maximum nesting depth accepted when decoding (and used by log formatting),
/// mirroring the Go reference's guard.
pub const MAX_NESTING_DEPTH: usize = 20;
