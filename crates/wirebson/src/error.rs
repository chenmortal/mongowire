//! Errors produced by BSON parsing and encoding.

/// Error type for the `wirebson` crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Not enough input to continue parsing.
    #[error("unexpected end of input: needed {needed} byte(s), got {got}")]
    ShortInput { needed: usize, got: usize },

    /// Input is structurally invalid.
    #[error("invalid input at offset {offset}: {reason}")]
    InvalidInput {
        offset: usize,
        reason: std::borrow::Cow<'static, str>,
    },

    /// The declared document/array length disagrees with the actual bytes.
    #[error("length mismatch: declared {declared}, actual {actual}")]
    LengthMismatch { declared: usize, actual: usize },

    /// A string field was not valid UTF-8.
    #[error("invalid utf-8")]
    Utf8(#[from] std::str::Utf8Error),

    /// Nesting exceeds [`crate::MAX_NESTING_DEPTH`].
    #[error("nesting too deep (max {max})")]
    NestedTooDeep { max: usize },

    /// An error surfaced by `mongo_common`'s scalar layer.
    #[error(transparent)]
    Scalar(#[from] mongo_common::bson::ScalarError),
}

impl Error {
    /// Convenience constructor for [`Error::InvalidInput`].
    pub fn invalid(offset: usize, reason: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self::InvalidInput {
            offset,
            reason: reason.into(),
        }
    }
}
