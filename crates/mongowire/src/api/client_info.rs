//! Per-connection state.

use std::sync::atomic::{AtomicI32, Ordering};

use super::auth::AuthState;
use crate::compression::CompressorId;

/// Mutable per-connection context handed to handlers.
#[derive(Debug)]
pub struct ConnectionInfo {
    request_id_counter: AtomicI32,
    /// Remote address, when the transport has one.
    pub peer_addr: Option<std::net::SocketAddr>,
    /// Compressors negotiated during the handshake, in preference order.
    pub negotiated_compressors: Vec<CompressorId>,
    /// Whether replies should carry CRC-32C checksums (non-TLS connections).
    pub checksum: bool,
    /// SASL/SCRAM progress, maintained by the [`ScramBridge`] handler.
    ///
    /// [`ScramBridge`]: crate::api::auth::ScramBridge
    pub auth: AuthState,
}

impl ConnectionInfo {
    pub fn new() -> Self {
        Self {
            request_id_counter: AtomicI32::new(0),
            peer_addr: None,
            negotiated_compressors: Vec::new(),
            checksum: true,
            auth: AuthState::default(),
        }
    }

    /// Generate the next server-side request id.
    pub fn next_request_id(&self) -> i32 {
        self.request_id_counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        Self::new()
    }
}
