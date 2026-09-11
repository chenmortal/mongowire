//! Authentication mechanisms: SCRAM-SHA-1 / SCRAM-SHA-256 (client and server
//! sides) and PLAIN.
//!
//! This module implements the SASL byte protocols only. Bridging to BSON
//! command documents (`saslStart` / `saslContinue`) is the caller's job
//! (see `mongowire::api`).

pub mod plain;
pub mod scram;

pub use plain::{PlainMessage, build_client_payload, parse_client_payload};
pub use scram::{
    ScramClient, ScramMechanism, ScramServer, ServerFirst, StoredCredentials, mongo_sha1_password,
};

/// Authentication protocol errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The peer sent something that is not a valid message of the mechanism.
    #[error("invalid authentication message: {0}")]
    InvalidMessage(&'static str),
    /// The server rejected the credentials.
    #[error("authentication failed: {0}")]
    Failure(String),
    /// The server-final nonce did not include the client nonce.
    #[error("nonce mismatch")]
    NonceMismatch,
    /// The server signature sent by the server did not match.
    #[error("server signature mismatch")]
    ServerSignatureMismatch,
    /// The client proof sent by the client did not match.
    #[error("client proof mismatch")]
    ClientProofMismatch,
    /// The mechanism is in the wrong state for this step.
    #[error("authentication step out of order")]
    State,
}
