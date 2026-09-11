//! Borrowing view over a single raw BSON field value.

use mongo_common::bson::scalar::{Binary, Timestamp};
use mongo_common::bson::{Decimal128, DbPointer, ObjectId, Regex};

use crate::{RawArray, RawDocument};

/// A raw field value. Strings borrow from the parent document; composites are
/// cheap `Bytes` slices (zero-copy).
#[derive(Debug, Clone, PartialEq)]
pub enum RawBsonRef<'a> {
    Double(f64),
    String(&'a str),
    Document(RawDocument),
    Array(RawArray),
    Binary(Binary),
    Undefined,
    ObjectId(ObjectId),
    Bool(bool),
    DateTime(i64),
    Null,
    Regex(Regex),
    DbPointer(DbPointer),
    JavaScript(&'a str),
    Symbol(&'a str),
    JavaScriptScope {
        code: &'a str,
        scope: RawDocument,
    },
    Int32(i32),
    Timestamp(Timestamp),
    Int64(i64),
    Decimal128(Decimal128),
    MinKey,
    MaxKey,
}

impl RawBsonRef<'_> {
    /// Materialize into an eager [`Bson`](crate::Bson). Composites stay raw
    /// where [`crate::Bson`] has a raw variant (`JavaScriptScope`), otherwise
    /// they decode shallowly.
    ///
    /// # Errors
    /// Malformed nested composites.
    pub fn to_bson(&self) -> Result<crate::Bson, crate::Error> {
        use crate::Bson;
        Ok(match self {
            Self::Double(v) => Bson::Double(*v),
            Self::String(v) => Bson::String((*v).to_owned()),
            Self::Document(d) => Bson::Document(d.shallow()?),
            Self::Array(a) => Bson::Array(a.shallow()?),
            Self::Binary(v) => Bson::Binary(v.clone()),
            Self::Undefined => Bson::Undefined,
            Self::ObjectId(v) => Bson::ObjectId(*v),
            Self::Bool(v) => Bson::Bool(*v),
            Self::DateTime(v) => Bson::DateTime(*v),
            Self::Null => Bson::Null,
            Self::Regex(v) => Bson::Regex(v.clone()),
            Self::DbPointer(v) => Bson::DbPointer(v.clone()),
            Self::JavaScript(v) => Bson::JavaScript((*v).to_owned()),
            Self::Symbol(v) => Bson::Symbol((*v).to_owned()),
            Self::JavaScriptScope { code, scope } => Bson::JavaScriptScope {
                code: (*code).to_owned(),
                scope: scope.clone(),
            },
            Self::Int32(v) => Bson::Int32(*v),
            Self::Timestamp(v) => Bson::Timestamp(*v),
            Self::Int64(v) => Bson::Int64(*v),
            Self::Decimal128(v) => Bson::Decimal128(*v),
            Self::MinKey => Bson::MinKey,
            Self::MaxKey => Bson::MaxKey,
        })
    }

    /// Decode recursively into an eager value. Note: a code-with-scope value
    /// keeps its scope raw, matching [`crate::Bson::JavaScriptScope`].
    ///
    /// # Errors
    /// Malformed nested composites.
    pub fn deep(&self) -> Result<crate::Bson, crate::Error> {
        use crate::Bson;
        Ok(match self {
            Self::Document(d) => Bson::Document(d.deep()?),
            Self::Array(a) => Bson::Array(a.deep()?),
            Self::JavaScriptScope { code, scope } => Bson::JavaScriptScope {
                code: (*code).to_owned(),
                scope: scope.clone(),
            },
            other => other.to_bson()?,
        })
    }
}
