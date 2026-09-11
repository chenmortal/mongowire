//! BSON values: the eager [`Bson`] enum and its tag mapping.

use mongo_common::bson::scalar::{
    Binary, Timestamp, TAG_ARRAY, TAG_BINARY, TAG_BOOL, TAG_DATE_TIME, TAG_DB_POINTER,
    TAG_DECIMAL128, TAG_DOCUMENT, TAG_DOUBLE, TAG_INT32, TAG_INT64, TAG_JAVASCRIPT,
    TAG_JAVASCRIPT_SCOPE, TAG_MAX_KEY, TAG_MIN_KEY, TAG_NULL, TAG_OBJECT_ID, TAG_REGEX, TAG_STRING,
    TAG_SYMBOL, TAG_TIMESTAMP, TAG_UNDEFINED,
};
use mongo_common::bson::{Decimal128, DbPointer, ObjectId, Regex};

use crate::{Array, Document, RawDocument};

/// Any BSON value, eagerly materialized.
///
/// Scalar types are reused from `mongo_common::bson`; only documents, arrays
/// and code-with-scope gain raw/eager variants.
#[derive(Debug, Clone, PartialEq)]
pub enum Bson {
    Double(f64),
    String(String),
    Document(Document),
    Array(Array),
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
    JavaScriptScope {
        code: String,
        scope: RawDocument,
    },
    Int32(i32),
    Timestamp(Timestamp),
    Int64(i64),
    Decimal128(Decimal128),
    MinKey,
    MaxKey,
}

impl Bson {
    /// The BSON element tag for this value.
    pub fn tag(&self) -> u8 {
        match self {
            Self::Double(_) => TAG_DOUBLE,
            Self::String(_) => TAG_STRING,
            Self::Document(_) => TAG_DOCUMENT,
            Self::Array(_) => TAG_ARRAY,
            Self::Binary(_) => TAG_BINARY,
            Self::Undefined => TAG_UNDEFINED,
            Self::ObjectId(_) => TAG_OBJECT_ID,
            Self::Bool(_) => TAG_BOOL,
            Self::DateTime(_) => TAG_DATE_TIME,
            Self::Null => TAG_NULL,
            Self::Regex(_) => TAG_REGEX,
            Self::DbPointer(_) => TAG_DB_POINTER,
            Self::JavaScript(_) => TAG_JAVASCRIPT,
            Self::Symbol(_) => TAG_SYMBOL,
            Self::JavaScriptScope { .. } => TAG_JAVASCRIPT_SCOPE,
            Self::Int32(_) => TAG_INT32,
            Self::Timestamp(_) => TAG_TIMESTAMP,
            Self::Int64(_) => TAG_INT64,
            Self::Decimal128(_) => TAG_DECIMAL128,
            Self::MinKey => TAG_MIN_KEY,
            Self::MaxKey => TAG_MAX_KEY,
        }
    }

    /// Convert a scalar-backed value into its `mongo_common` scalar form.
    /// Composites return `None`.
    pub fn as_scalar(&self) -> Option<mongo_common::bson::Scalar> {
        use mongo_common::bson::Scalar;
        Some(match self {
            Self::Double(v) => Scalar::Double(*v),
            Self::String(v) => Scalar::String(v.clone()),
            Self::Binary(v) => Scalar::Binary(v.clone()),
            Self::Undefined => Scalar::Undefined,
            Self::ObjectId(v) => Scalar::ObjectId(*v),
            Self::Bool(v) => Scalar::Bool(*v),
            Self::DateTime(v) => Scalar::DateTime(*v),
            Self::Null => Scalar::Null,
            Self::Regex(v) => Scalar::Regex(v.clone()),
            Self::DbPointer(v) => Scalar::DbPointer(v.clone()),
            Self::JavaScript(v) => Scalar::JavaScript(v.clone()),
            Self::Symbol(v) => Scalar::Symbol(v.clone()),
            Self::Int32(v) => Scalar::Int32(*v),
            Self::Timestamp(v) => Scalar::Timestamp(*v),
            Self::Int64(v) => Scalar::Int64(*v),
            Self::Decimal128(v) => Scalar::Decimal128(*v),
            Self::MinKey => Scalar::MinKey,
            Self::MaxKey => Scalar::MaxKey,
            Self::Document(_) | Self::Array(_) | Self::JavaScriptScope { .. } => return None,
        })
    }
}

impl From<mongo_common::bson::Scalar> for Bson {
    fn from(s: mongo_common::bson::Scalar) -> Self {
        use mongo_common::bson::Scalar;
        match s {
            Scalar::Double(v) => Self::Double(v),
            Scalar::String(v) => Self::String(v),
            Scalar::Binary(v) => Self::Binary(v),
            Scalar::Undefined => Self::Undefined,
            Scalar::ObjectId(v) => Self::ObjectId(v),
            Scalar::Bool(v) => Self::Bool(v),
            Scalar::DateTime(v) => Self::DateTime(v),
            Scalar::Null => Self::Null,
            Scalar::Regex(v) => Self::Regex(v),
            Scalar::DbPointer(v) => Self::DbPointer(v),
            Scalar::JavaScript(v) => Self::JavaScript(v),
            Scalar::Symbol(v) => Self::Symbol(v),
            Scalar::Int32(v) => Self::Int32(v),
            Scalar::Timestamp(v) => Self::Timestamp(v),
            Scalar::Int64(v) => Self::Int64(v),
            Scalar::Decimal128(v) => Self::Decimal128(v),
            Scalar::MinKey => Self::MinKey,
            Scalar::MaxKey => Self::MaxKey,
        }
    }
}

impl From<Document> for Bson {
    fn from(v: Document) -> Self {
        Self::Document(v)
    }
}

impl From<crate::Array> for Bson {
    fn from(v: crate::Array) -> Self {
        Self::Array(v)
    }
}
