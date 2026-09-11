//! SCRAM (RFC 5802 / RFC 7677) client and server state machines, following
//! the MongoDB SASL profile:
//!
//! * GS2 header is `n,,` (no channel binding); client-final channel-binding
//!   attribute is `biws` (base64 of `n,,`).
//! * `auth_message = client-first-bare + "," + server-first + "," +
//!   client-final-without-proof`.
//! * SCRAM-SHA-1 (MongoDB quirk): the password fed into PBKDF2 is
//!   [`mongo_sha1_password`] — `hex(md5(username + ":mongo:" + password))`.
//! * SCRAM-SHA-256: the literal password (SASLprep) is used.
//! * Default iterations: 10000 (SHA-1) / 15000 (SHA-256).
//!
//! Payloads exchanged in BSON `saslStart`/`saslContinue` documents are the
//! raw SCRAM message strings (no extra base64 layer).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_array;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::auth::AuthError;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// The single-letter attribute keys of SCRAM messages (RFC 5802 section 5.1).
const USERNAME_KEY: char = 'n';
const NONCE_KEY: char = 'r';
const SALT_KEY: char = 's';
const ITERATION_KEY: char = 'i';
const CHANNEL_BINDING_KEY: char = 'c';
const PROOF_KEY: char = 'p';
const VERIFIER_KEY: char = 'v';
const ERROR_KEY: char = 'e';

/// Base64 of the GS2 header `n,,` — the client-final `c` attribute value used
/// when no channel binding is in effect (RFC 5802 section 5.1).
const NO_CHANNEL_BINDING_FLAG: &str = "biws";

/// Upper bound on the PBKDF2 iteration count accepted from a peer. A hostile
/// peer could otherwise force minutes of CPU per authentication attempt
/// (drivers apply the same idea; MongoDB servers use well below this).
const MAX_SCRAM_ITERATIONS: u32 = 1_000_000;

/// The GS2 header accepted by [`ScramServer::handle_client_first`]: `n,` +
/// the separating comma, i.e. "no channel binding, no authorization identity".
const GS2_NO_BINDING_HEADER: &str = "n,,";

/// The SCRAM mechanism and its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScramMechanism {
    Sha1,
    Sha256,
}

impl ScramMechanism {
    /// SASL mechanism name, e.g. `"SCRAM-SHA-256"`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SCRAM-SHA-1",
            Self::Sha256 => "SCRAM-SHA-256",
        }
    }

    /// Parse a SASL mechanism name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SCRAM-SHA-1" => Some(Self::Sha1),
            "SCRAM-SHA-256" => Some(Self::Sha256),
            _ => None,
        }
    }

    /// MongoDB's default iteration count for new credentials.
    pub fn default_iterations(self) -> u32 {
        match self {
            Self::Sha1 => 10_000,
            Self::Sha256 => 15_000,
        }
    }
}

/// MongoDB-specific SCRAM-SHA-1 password digest:
/// `hex(md5(username + ":mongo:" + password))`. This string (not the raw
/// password) is what PBKDF2 consumes for SCRAM-SHA-1.
///
/// For SCRAM-SHA-256 use the raw password instead.
pub fn mongo_sha1_password(username: &str, password: &str) -> String {
    let mut md5 = Md5::new();
    md5.update(username.as_bytes());
    md5.update(b":mongo:");
    md5.update(password.as_bytes());
    to_lower_hex(&md5.finalize())
}

impl ScramMechanism {
    /// `SaltedPassword = PBKDF2(HMAC-<hash>, password, salt, iterations)`.
    ///
    /// `password` must already be in the mechanism-appropriate form (see
    /// [`StoredCredentials::derive`]).
    fn salted_password(self, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                let salted: [u8; 20] = pbkdf2_array::<HmacSha1, 20>(password, salt, iterations)
                    .expect("HMAC accepts keys of any length");
                salted.to_vec()
            }
            Self::Sha256 => {
                let salted: [u8; 32] = pbkdf2_array::<HmacSha256, 32>(password, salt, iterations)
                    .expect("HMAC accepts keys of any length");
                salted.to_vec()
            }
        }
    }
}

/// `HMAC(key, input)` under the mechanism's digest.
fn hmac_bytes(mechanism: ScramMechanism, key: &[u8], input: &[u8]) -> Vec<u8> {
    fn mac<M: Mac + KeyInit>(key: &[u8], input: &[u8]) -> Vec<u8> {
        let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
        mac.update(input);
        mac.finalize().into_bytes().to_vec()
    }
    match mechanism {
        ScramMechanism::Sha1 => mac::<HmacSha1>(key, input),
        ScramMechanism::Sha256 => mac::<HmacSha256>(key, input),
    }
}

/// `H(input)` under the mechanism's digest.
fn hash_bytes(mechanism: ScramMechanism, input: &[u8]) -> Vec<u8> {
    match mechanism {
        ScramMechanism::Sha1 => Sha1::digest(input).to_vec(),
        ScramMechanism::Sha256 => Sha256::digest(input).to_vec(),
    }
}

/// XOR two equal-length byte strings (used to derive/hide the client proof).
fn xor_bytes(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    debug_assert_eq!(lhs.len(), rhs.len());
    lhs.iter().zip(rhs.iter()).map(|(l, r)| l ^ r).collect()
}

/// Lowercase hexadecimal encoding (no `hex` crate in the dependency tree).
fn to_lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// RFC 5803 username escaping for SCRAM: `=` becomes `=3D` and `,` becomes
/// `=2C` (the `=` replacement must happen first).
fn escape_username(username: &str) -> String {
    username.replace('=', "=3D").replace(',', "=2C")
}

/// The password PBKDF2 consumes for `mechanism`: the MongoDB SCRAM-SHA-1
/// digest for SHA-1, the raw (SASLprep'd by the caller) password for SHA-256.
fn effective_password(mechanism: ScramMechanism, username: &str, password: &str) -> String {
    match mechanism {
        ScramMechanism::Sha1 => mongo_sha1_password(username, password),
        ScramMechanism::Sha256 => password.to_owned(),
    }
}

/// A fresh client/server nonce: base64 of 18 random bytes (24 printable
/// characters), well above the 18-byte minimum of RFC 5802 section 5.1.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE64.encode(bytes)
}

/// Split a comma-separated SCRAM attribute list into `(key, value)` pairs.
///
/// Every comma-separated part must have the shape `X=value`; values may be
/// empty.
///
/// # Errors
/// [`AuthError::InvalidMessage`] if any attribute is malformed.
fn parse_attributes(msg: &str) -> Result<Vec<(char, &str)>, AuthError> {
    msg.split(',')
        .map(|attr| {
            let mut chars = attr.char_indices();
            match (chars.next(), chars.next()) {
                (Some((_key_offset, key)), Some((eq_offset, '='))) => {
                    Ok((key, &attr[eq_offset + 1..]))
                }
                _ => Err(AuthError::InvalidMessage("malformed SCRAM attribute")),
            }
        })
        .collect()
}

/// Server-side stored credentials for one user and mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredentials {
    pub salt: Vec<u8>,
    pub iterations: u32,
    /// `H(ClientKey)` — see RFC 5802.
    pub stored_key: Vec<u8>,
    /// `HMAC(SaltedPassword, "Server Key")` — see RFC 5802.
    pub server_key: Vec<u8>,
}

impl StoredCredentials {
    /// Derive stored credentials from a password (the mechanism-appropriate
    /// form: [`mongo_sha1_password`] output for SHA-1, raw password for
    /// SHA-256).
    ///
    /// With `SaltedPassword = PBKDF2(HMAC-<hash>, password, salt, iterations)`:
    ///
    /// * `stored_key` = `H(HMAC(SaltedPassword, "Client Key"))`
    /// * `server_key` = `HMAC(SaltedPassword, "Server Key")`
    ///
    /// `iterations` must be at least 1 (`StoredCredentials` cannot represent a
    /// derivation error); callers should refuse server-chosen counts they
    /// consider too low.
    pub fn derive(
        mechanism: ScramMechanism,
        password: &str,
        salt: &[u8],
        iterations: u32,
    ) -> Self {
        let salted_password = mechanism.salted_password(password.as_bytes(), salt, iterations);
        let client_key = hmac_bytes(mechanism, &salted_password, b"Client Key");
        let stored_key = hash_bytes(mechanism, &client_key);
        let server_key = hmac_bytes(mechanism, &salted_password, b"Server Key");
        Self {
            salt: salt.to_vec(),
            iterations,
            stored_key,
            server_key,
        }
    }
}

impl ServerFirst {
    /// Parse a server-first message. Attributes may appear in any order; the
    /// first occurrence of each of `r` (nonce), `s` (base64 salt) and `i`
    /// (iteration count) is used, unknown attributes are ignored.
    fn parse(msg: &str) -> Result<Self, AuthError> {
        let mut nonce: Option<&str> = None;
        let mut salt: Option<Vec<u8>> = None;
        let mut iterations: Option<u32> = None;
        for (key, value) in parse_attributes(msg)? {
            match key {
                NONCE_KEY if nonce.is_none() => nonce = Some(value),
                SALT_KEY if salt.is_none() => {
                    salt = Some(
                        BASE64.decode(value)
                            .map_err(|_| AuthError::InvalidMessage("invalid base64 salt"))?,
                    );
                }
                ITERATION_KEY if iterations.is_none() => {
                    let parsed: u32 = value.parse().map_err(|_| {
                        AuthError::InvalidMessage("invalid iteration count")
                    })?;
                    // A malicious server can otherwise force minutes of PBKDF2
                    // in the client (CPU-exhaustion vector; drivers cap too).
                    if parsed == 0 || parsed > MAX_SCRAM_ITERATIONS {
                        return Err(AuthError::InvalidMessage("iteration count out of range"));
                    }
                    iterations = Some(parsed);
                }
                _ => {}
            }
        }
        let nonce = nonce
            .filter(|nonce| !nonce.is_empty())
            .ok_or(AuthError::InvalidMessage("missing server nonce"))?;
        let salt = salt.ok_or(AuthError::InvalidMessage("missing salt"))?;
        let iterations = iterations.ok_or(AuthError::InvalidMessage("missing iteration count"))?;
        Ok(Self {
            nonce: nonce.to_owned(),
            salt,
            iterations,
        })
    }
}

/// The parsed server-first message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFirst {
    /// The server nonce — MUST start with the client nonce.
    pub nonce: String,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

/// Client-side SCRAM state machine.
///
/// ```text
/// let mut c = ScramClient::new(ScramMechanism::Sha256, "user", "pwd")?;
/// let first = c.client_first_message();          // "n,,n=user,r=<nonce>"
/// // ... send `first` in saslStart, receive payload ...
/// c.receive_server_first(&payload)?;             // parses + verifies nonce
/// let final_msg = c.client_final_message();      // "c=biws,r=...,p=<proof>"
/// // ... send `final_msg` in saslContinue, receive payload ...
/// c.receive_server_final(&payload)?;             // verifies "v=" signature
/// ```
#[derive(Debug)]
pub struct ScramClient {
    pub mechanism: ScramMechanism,
    pub username: String,
    /// The mechanism-appropriate password PBKDF2 consumes (see
    /// [`effective_password`]): [`mongo_sha1_password`] output for SHA-1, the
    /// raw password for SHA-256.
    password: String,
    client_nonce: String,
    server_first: Option<ServerFirst>,
    salted_password: Option<Vec<u8>>,
    /// Accumulated `client-first-bare + "," + server-first + "," +
    /// client-final-without-proof`.
    auth_message: String,
    state: ClientState,
}

/// Client-side handshake progress. `FirstSent` covers both "client-first sent"
/// and "server-first received" (distinguished by `server_first`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    Init,
    FirstSent,
    FinalSent,
    Done,
}

impl ScramClient {
    /// Start a client exchange. The nonce is generated internally.
    ///
    /// For SCRAM-SHA-1 the MongoDB password quirk is applied internally (the
    /// caller passes the plaintext password); for SCRAM-SHA-256 the raw
    /// password is used as-is.
    pub fn new(
        mechanism: ScramMechanism,
        username: &str,
        password: &str,
    ) -> Result<Self, AuthError> {
        Ok(Self::with_nonce(
            mechanism,
            username,
            effective_password(mechanism, username, password),
            generate_nonce(),
        ))
    }

    /// Like [`ScramClient::new`] with a caller-chosen nonce and an explicit
    /// PBKDF2-ready password. Private; also lets tests pin RFC test vectors.
    fn with_nonce(
        mechanism: ScramMechanism,
        username: &str,
        effective_password: String,
        client_nonce: String,
    ) -> Self {
        Self {
            mechanism,
            username: username.to_owned(),
            password: effective_password,
            client_nonce,
            server_first: None,
            salted_password: None,
            auth_message: String::new(),
            state: ClientState::Init,
        }
    }

    /// Produce the client-first message, including the GS2 header (`n,,`).
    ///
    /// # Errors
    /// [`AuthError::State`] if called twice.
    pub fn client_first_message(&mut self) -> Result<String, AuthError> {
        if self.state != ClientState::Init {
            return Err(AuthError::State);
        }
        let escaped_username = escape_username(&self.username);
        let bare =
            format!("{USERNAME_KEY}={escaped_username},{NONCE_KEY}={}", self.client_nonce);
        self.auth_message = bare.clone();
        self.state = ClientState::FirstSent;
        Ok(format!("n,,{bare}"))
    }

    /// Consume the server-first message (e.g. `r=<n>...`,s=<b64>,i=<n>`).
    /// Verifies that the server nonce extends the client nonce.
    ///
    /// # Errors
    /// [`AuthError::InvalidMessage`], [`AuthError::NonceMismatch`],
    /// [`AuthError::State`].
    pub fn receive_server_first(&mut self, msg: &str) -> Result<(), AuthError> {
        if self.state != ClientState::FirstSent || self.server_first.is_some() {
            return Err(AuthError::State);
        }
        let server_first = ServerFirst::parse(msg)?;
        if !server_first.nonce.starts_with(&self.client_nonce) {
            return Err(AuthError::NonceMismatch);
        }
        let salted_password = self.mechanism.salted_password(
            self.password.as_bytes(),
            &server_first.salt,
            server_first.iterations,
        );
        self.auth_message = format!("{},{},", self.auth_message, msg);
        self.salted_password = Some(salted_password);
        self.server_first = Some(server_first);
        Ok(())
    }

    /// Produce the client-final message (`c=biws,r=<full-nonce>,p=<proof>`).
    ///
    /// # Errors
    /// [`AuthError::State`] if [`Self::receive_server_first`] has not succeeded.
    pub fn client_final_message(&mut self) -> Result<String, AuthError> {
        if self.state != ClientState::FirstSent {
            return Err(AuthError::State);
        }
        let server_first = self.server_first.as_ref().ok_or(AuthError::State)?;
        let full_nonce = server_first.nonce.clone();
        let salted_password = self
            .salted_password
            .as_deref()
            .ok_or(AuthError::State)?
            .to_vec();

        // ClientProof = ClientKey XOR ClientSignature, where ClientSignature
        // = HMAC(StoredKey, auth_message) and auth_message ends with the
        // client-final message without proof.
        let client_key = hmac_bytes(self.mechanism, &salted_password, b"Client Key");
        let stored_key = hash_bytes(self.mechanism, &client_key);
        let without_proof = format!(
            "{CHANNEL_BINDING_KEY}={NO_CHANNEL_BINDING_FLAG},{NONCE_KEY}={full_nonce}"
        );
        self.auth_message.push_str(&without_proof);
        let client_signature =
            hmac_bytes(self.mechanism, &stored_key, self.auth_message.as_bytes());
        let proof = xor_bytes(&client_key, &client_signature);
        self.state = ClientState::FinalSent;
        Ok(format!(
            "{without_proof},{PROOF_KEY}={}",
            BASE64.encode(proof)
        ))
    }

    /// Consume the server-final message (`v=<b64>`), verifying the server
    /// signature in constant time. The client derives `ServerKey` itself, so
    /// it can (and does) authenticate the server too.
    ///
    /// # Errors
    /// [`AuthError::ServerSignatureMismatch`], [`AuthError::InvalidMessage`],
    /// [`AuthError::State`]. A server error (`e=<text>`) becomes
    /// [`AuthError::Failure`].
    pub fn receive_server_final(&mut self, msg: &str) -> Result<(), AuthError> {
        if self.state != ClientState::FinalSent {
            return Err(AuthError::State);
        }
        let attrs = parse_attributes(msg)?;
        let [(key, value)] = attrs.as_slice() else {
            return Err(AuthError::InvalidMessage(
                "malformed server-final message",
            ));
        };
        match *key {
            ERROR_KEY => Err(AuthError::Failure((*value).to_owned())),
            VERIFIER_KEY => {
                let received = BASE64
                    .decode(*value)
                    .map_err(|_| AuthError::InvalidMessage("invalid base64 server signature"))?;
                let salted_password = self
                    .salted_password
                    .as_deref()
                    .ok_or(AuthError::State)?;
                let server_key = hmac_bytes(self.mechanism, salted_password, b"Server Key");
                let expected =
                    hmac_bytes(self.mechanism, &server_key, self.auth_message.as_bytes());
                if expected.len() == received.len()
                    && bool::from(expected.as_slice().ct_eq(received.as_slice()))
                {
                    self.state = ClientState::Done;
                    Ok(())
                } else {
                    Err(AuthError::ServerSignatureMismatch)
                }
            }
            _ => Err(AuthError::InvalidMessage(
                "expected v= or e= in server-final message",
            )),
        }
    }
}

/// Server-side SCRAM state machine for authenticating one client.
///
/// The caller supplies the stored credentials for the claimed username; this
/// type knows nothing about storage.
#[derive(Debug)]
pub struct ScramServer {
    pub mechanism: ScramMechanism,
    server_nonce: String,
    client_first_bare: String,
    server_first_message: String,
    state: ServerState,
    /// The credential identity supplied by the caller of
    /// [`ScramServer::handle_client_first`] (trusted to match the username the
    /// client claimed inside the message).
    username: String,
    /// The client's nonce; the server nonce is appended to it, so this is
    /// always a prefix of the full exchanged nonce.
    client_nonce: String,
    credentials: Option<StoredCredentials>,
}

#[derive(Debug, PartialEq, Eq)]
enum ServerState {
    ExpectClientFirst,
    ExpectClientFinal,
    Done,
}

impl ScramServer {
    /// Start a server exchange. The server nonce is generated internally.
    pub fn new(mechanism: ScramMechanism) -> Self {
        Self::with_nonce(mechanism, generate_nonce())
    }

    /// Like [`ScramServer::new`] with a caller-chosen nonce. Private; also
    /// lets tests pin RFC test vectors.
    fn with_nonce(mechanism: ScramMechanism, server_nonce: String) -> Self {
        Self {
            mechanism,
            server_nonce,
            client_first_bare: String::new(),
            server_first_message: String::new(),
            state: ServerState::ExpectClientFirst,
            username: String::new(),
            client_nonce: String::new(),
            credentials: None,
        }
    }

    /// Consume the client-first message (e.g. `n,,n=user,r=<nonce>`), verify
    /// it, and produce the server-first message using `credentials` (which
    /// the caller looked up for the claimed username).
    ///
    /// The server nonce is appended to the client nonce exactly. Only the
    /// GS2 header `n,,` (no channel binding, no authorization identity) is
    /// accepted.
    ///
    /// # Errors
    /// [`AuthError::InvalidMessage`], [`AuthError::State`].
    pub fn handle_client_first(
        &mut self,
        msg: &str,
        username: &str,
        credentials: &StoredCredentials,
    ) -> Result<String, AuthError> {
        if self.state != ServerState::ExpectClientFirst {
            return Err(AuthError::State);
        }
        let bare = if let Some(bare) = msg.strip_prefix(GS2_NO_BINDING_HEADER) {
            bare
        } else if msg.starts_with("y,,") || msg.starts_with("p=") {
            return Err(AuthError::InvalidMessage(
                "channel binding is not supported",
            ));
        } else {
            return Err(AuthError::InvalidMessage("invalid GS2 header"));
        };

        let mut attrs = parse_attributes(bare)?.into_iter();
        // RFC 5802 section 5.1: an unrecognized *mandatory* extension (`m=`)
        // MUST make authentication fail; unknown ordinary attributes are
        // simply ignored.
        if attrs.clone().any(|(key, _)| key == 'm') {
            return Err(AuthError::InvalidMessage(
                "mandatory extension not supported",
            ));
        }
        // The client's claimed username (`_claimed`) is not re-verified: the
        // caller already looked up `credentials` for the identity they passed.
        let Some((USERNAME_KEY, _claimed)) = attrs.next() else {
            return Err(AuthError::InvalidMessage(
                "expected n=<username> attribute",
            ));
        };
        let Some((NONCE_KEY, client_nonce)) = attrs.next() else {
            return Err(AuthError::InvalidMessage("expected r=<nonce> attribute"));
        };
        if client_nonce.is_empty() {
            return Err(AuthError::InvalidMessage("missing client nonce"));
        }

        self.client_first_bare = bare.to_owned();
        self.client_nonce = client_nonce.to_owned();
        self.username = username.to_owned();
        self.credentials = Some(credentials.clone());
        let full_nonce = format!("{client_nonce}{}", self.server_nonce);
        self.server_first_message = format!(
            "{NONCE_KEY}={full_nonce},{SALT_KEY}={},{}={}",
            BASE64.encode(&credentials.salt),
            ITERATION_KEY,
            credentials.iterations
        );
        self.state = ServerState::ExpectClientFinal;
        Ok(self.server_first_message.clone())
    }

    /// The username claimed by the client, after [`Self::handle_client_first`].
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Consume the client-final message, verify the client proof in constant
    /// time, and produce the server-final message (`v=<b64>`).
    ///
    /// # Errors
    /// [`AuthError::ClientProofMismatch`], [`AuthError::InvalidMessage`],
    /// [`AuthError::NonceMismatch`], [`AuthError::State`].
    pub fn handle_client_final(&mut self, msg: &str) -> Result<String, AuthError> {
        if self.state != ServerState::ExpectClientFinal {
            return Err(AuthError::State);
        }
        let credentials = self.credentials.as_ref().ok_or(AuthError::State)?;

        let mut channel_binding: Option<&str> = None;
        let mut nonce: Option<&str> = None;
        let mut proof: Option<&str> = None;
        for (key, value) in parse_attributes(msg)? {
            match key {
                CHANNEL_BINDING_KEY if channel_binding.is_none() => channel_binding = Some(value),
                NONCE_KEY if nonce.is_none() => nonce = Some(value),
                PROOF_KEY if proof.is_none() => proof = Some(value),
                _ => {
                    return Err(AuthError::InvalidMessage(
                        "unexpected attribute in client-final message",
                    ));
                }
            }
        }
        if channel_binding != Some(NO_CHANNEL_BINDING_FLAG) {
            return Err(AuthError::InvalidMessage("expected c=biws channel binding"));
        }
        let full_nonce = format!("{}{}", self.client_nonce, self.server_nonce);
        if nonce != Some(full_nonce.as_str()) {
            return Err(AuthError::NonceMismatch);
        }
        let proof_b64 = proof
            .ok_or(AuthError::InvalidMessage("missing p=<proof> attribute"))?;
        let proof = BASE64
            .decode(proof_b64)
            .map_err(|_| AuthError::InvalidMessage("invalid base64 client proof"))?;

        // Recover ClientKey = ClientProof XOR ClientSignature, then check that
        // H(ClientKey) equals the stored key (both in constant time).
        let without_proof = format!(
            "{CHANNEL_BINDING_KEY}={NO_CHANNEL_BINDING_FLAG},{NONCE_KEY}={full_nonce}"
        );
        let auth_message =
            format!("{},{},{}", self.client_first_bare, self.server_first_message, without_proof);
        let client_signature =
            hmac_bytes(self.mechanism, &credentials.stored_key, auth_message.as_bytes());
        if proof.len() != client_signature.len() {
            return Err(AuthError::InvalidMessage("client proof has the wrong length"));
        }
        let client_key = xor_bytes(&proof, &client_signature);
        let hashed_client_key = hash_bytes(self.mechanism, &client_key);
        if !bool::from(hashed_client_key.as_slice().ct_eq(credentials.stored_key.as_slice())) {
            return Err(AuthError::ClientProofMismatch);
        }
        let server_signature =
            hmac_bytes(self.mechanism, &credentials.server_key, auth_message.as_bytes());
        self.state = ServerState::Done;
        Ok(format!("{VERIFIER_KEY}={}", BASE64.encode(server_signature)))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    /// A client with a pinned nonce. `password` is the raw password; the
    /// mechanism-appropriate transformation (MongoDB SHA-1 quirk) is applied.
    fn client_with_nonce(
        mechanism: ScramMechanism,
        username: &str,
        password: &str,
        client_nonce: &str,
    ) -> ScramClient {
        ScramClient::with_nonce(
            mechanism,
            username,
            effective_password(mechanism, username, password),
            client_nonce.to_owned(),
        )
    }

    /// A client with a pinned nonce and a raw PBKDF2 password (no MongoDB
    /// SHA-1 quirk), for RFC-derived vectors.
    fn raw_password_client_with_nonce(
        mechanism: ScramMechanism,
        username: &str,
        raw_password: &str,
        client_nonce: &str,
    ) -> ScramClient {
        ScramClient::with_nonce(
            mechanism,
            username,
            raw_password.to_owned(),
            client_nonce.to_owned(),
        )
    }

    fn server_with_nonce(mechanism: ScramMechanism, server_nonce: &str) -> ScramServer {
        ScramServer::with_nonce(mechanism, server_nonce.to_owned())
    }

    /// Drive one full client/server exchange with random nonces.
    fn run_exchange(
        mut client: ScramClient,
        mut server: ScramServer,
        username: &str,
        credentials: &StoredCredentials,
    ) -> Result<(), AuthError> {
        let client_first = client.client_first_message()?;
        let server_first = server.handle_client_first(&client_first, username, credentials)?;
        client.receive_server_first(&server_first)?;
        let client_final = client.client_final_message()?;
        let server_final = server.handle_client_final(&client_final)?;
        assert_eq!(server.username(), username);
        client.receive_server_final(&server_final)?;
        // Both sides must reject any further step.
        assert_eq!(server.handle_client_final(&client_final), Err(AuthError::State));
        assert_eq!(client.receive_server_final(&server_final), Err(AuthError::State));
        Ok(())
    }

    /// RFC 5802 section 5.1 SCRAM-SHA-1 example (user "user", password
    /// "pencil", salt `QSXCR+Q6sek8bf92`, 4096 iterations), with every
    /// exchanged message pinned to the published bytes.
    #[test]
    fn rfc5802_scram_sha1_vector() {
        let salt = BASE64.decode("QSXCR+Q6sek8bf92").unwrap();
        let credentials =
            StoredCredentials::derive(ScramMechanism::Sha1, "pencil", &salt, 4096);
        let mut client = raw_password_client_with_nonce(
            ScramMechanism::Sha1,
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL",
        );
        let mut server =
            server_with_nonce(ScramMechanism::Sha1, "3rfcNHYJY1ZVvWVs7j");

        let client_first = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";
        assert_eq!(client.client_first_message().unwrap(), client_first);

        let server_first = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        assert_eq!(
            server.handle_client_first(client_first, "user", &credentials).unwrap(),
            server_first
        );

        client.receive_server_first(server_first).unwrap();

        let client_final = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,\
                            p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";
        assert_eq!(client.client_final_message().unwrap(), client_final);

        let server_final = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";
        assert_eq!(
            server.handle_client_final(client_final).unwrap(),
            server_final
        );
        client.receive_server_final(server_final).unwrap();
    }

    /// RFC 7677 section 3 SCRAM-SHA-256 example (user "user", password
    /// "pencil", salt `W22ZaJ0SNY7soEsUEjb6gQ==`, 4096 iterations), with
    /// every exchanged message pinned to the published bytes.
    #[test]
    fn rfc7677_scram_sha256_vector() {
        let salt = BASE64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let credentials =
            StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let mut client = raw_password_client_with_nonce(
            ScramMechanism::Sha256,
            "user",
            "pencil",
            "rOprNGfwEbeRWgbNEkqO",
        );
        let mut server =
            server_with_nonce(ScramMechanism::Sha256, "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0");

        let client_first = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
        assert_eq!(client.client_first_message().unwrap(), client_first);

        let server_first =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,\
             i=4096";
        assert_eq!(
            server.handle_client_first(client_first, "user", &credentials).unwrap(),
            server_first
        );

        client.receive_server_first(server_first).unwrap();

        let client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                            p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
        assert_eq!(client.client_final_message().unwrap(), client_final);

        let server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        assert_eq!(
            server.handle_client_final(client_final).unwrap(),
            server_final
        );
        client.receive_server_final(server_final).unwrap();
    }

    #[test]
    fn full_roundtrip_sha1() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(
            ScramMechanism::Sha1,
            &mongo_sha1_password("bob", "s3cret"),
            &salt,
            ScramMechanism::Sha1.default_iterations(),
        );
        let client = ScramClient::new(ScramMechanism::Sha1, "bob", "s3cret").unwrap();
        let server = ScramServer::new(ScramMechanism::Sha1);
        run_exchange(client, server, "bob", &credentials).unwrap();
    }

    #[test]
    fn full_roundtrip_sha256() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials =
            StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let client = ScramClient::new(ScramMechanism::Sha256, "user", "pencil").unwrap();
        let server = ScramServer::new(ScramMechanism::Sha256);
        run_exchange(client, server, "user", &credentials).unwrap();
    }

    /// The SHA-1 quirk must be applied symmetrically: the client hashes the
    /// plaintext password, the stored credentials were derived from
    /// [`mongo_sha1_password`] output, and the exchange succeeds.
    #[test]
    fn mongo_sha1_quirk_roundtrip() {
        assert_eq!(
            mongo_sha1_password("user", "pwd"),
            "58a5ef6a66ff3b073530259153e94ae2" // md5("user:mongo:pwd")
        );
        let digest = mongo_sha1_password("user", "pwd");
        assert_eq!(digest.len(), 32);
        assert!(digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));

        let salt = b"saltsalt".to_vec();
        let credentials =
            StoredCredentials::derive(ScramMechanism::Sha1, &digest, &salt, 4096);
        // A client that fed the raw password would fail; the quirk-applying
        // client succeeds.
        let quirked = client_with_nonce(ScramMechanism::Sha1, "user", "pwd", "clientnonce123456");
        let server = server_with_nonce(ScramMechanism::Sha1, "servernonce1234567");
        run_exchange(quirked, server, "user", &credentials).unwrap();

        let raw = raw_password_client_with_nonce(ScramMechanism::Sha1, "user", "pwd", "clientnonce123456");
        let server = server_with_nonce(ScramMechanism::Sha1, "servernonce1234567");
        assert!(run_exchange(raw, server, "user", &credentials).is_err());
    }

    #[test]
    fn wrong_password_rejected_with_client_proof_mismatch() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials =
            StoredCredentials::derive(ScramMechanism::Sha256, "right-password", &salt, 4096);
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "wrong-password", "clientnonce123456");
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");

        let first = client.client_first_message().unwrap();
        let server_first = server.handle_client_first(&first, "user", &credentials).unwrap();
        client.receive_server_first(&server_first).unwrap();
        let final_msg = client.client_final_message().unwrap();
        assert_eq!(
            server.handle_client_final(&final_msg),
            Err(AuthError::ClientProofMismatch)
        );
    }

    #[test]
    fn tampered_server_nonce_rejected_by_client() {
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        client.client_first_message().unwrap();
        // The server nonce no longer extends the client nonce.
        let forged = "r=tamperednonce,s=MDIzNDU2Nzg=,i=4096";
        assert_eq!(client.receive_server_first(forged), Err(AuthError::NonceMismatch));
    }

    #[test]
    fn tampered_proof_rejected_by_server() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");

        let first = client.client_first_message().unwrap();
        let server_first = server.handle_client_first(&first, "user", &credentials).unwrap();
        client.receive_server_first(&server_first).unwrap();
        let final_msg = client.client_final_message().unwrap();

        // Flip one character inside the base64 proof (keeping it valid base64).
        let proof_pos = final_msg.find(",p=").unwrap() + 3;
        let (head, tail) = final_msg.split_at(proof_pos);
        let flipped = if tail.starts_with('d') { "e" } else { "d" };
        let tampered = format!("{}{}{}", head, flipped, &tail[1..]);
        assert_ne!(tampered, final_msg);

        assert_eq!(
            server.handle_client_final(&tampered),
            Err(AuthError::ClientProofMismatch)
        );
    }

    #[test]
    fn wrong_server_signature_rejected_by_client() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");

        let first = client.client_first_message().unwrap();
        let server_first = server.handle_client_first(&first, "user", &credentials).unwrap();
        client.receive_server_first(&server_first).unwrap();
        let final_msg = client.client_final_message().unwrap();
        let server_final = server.handle_client_final(&final_msg).unwrap();

        // Tamper with the verifier: replace the base64 body with zeros.
        let forged = format!("v={}", BASE64.encode([0u8; 32]));
        assert_ne!(forged, server_final);
        assert_eq!(
            client.receive_server_final(&forged),
            Err(AuthError::ServerSignatureMismatch)
        );
    }

    #[test]
    fn truncated_server_signature_rejected() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");

        let first = client.client_first_message().unwrap();
        let server_first = server.handle_client_first(&first, "user", &credentials).unwrap();
        client.receive_server_first(&server_first).unwrap();
        client.client_final_message().unwrap();
        // A truncated verifier must be a mismatch, not a panic.
        assert_eq!(
            client.receive_server_final("v=AAAA"),
            Err(AuthError::ServerSignatureMismatch)
        );
    }

    #[test]
    fn server_error_message_is_surfaced() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");

        let first = client.client_first_message().unwrap();
        let server_first = server.handle_client_first(&first, "user", &credentials).unwrap();
        client.receive_server_first(&server_first).unwrap();
        client.client_final_message().unwrap();
        assert_eq!(
            client.receive_server_final("e=invalid-credentials"),
            Err(AuthError::Failure("invalid-credentials".to_owned()))
        );
    }

    #[test]
    fn gs2_channel_binding_rejected_by_server() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "user", &salt, 4096);
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");
        assert_eq!(
            server.handle_client_first("y,,n=user,r=nonce123", "user", &credentials),
            Err(AuthError::InvalidMessage("channel binding is not supported"))
        );
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");
        assert_eq!(
            server.handle_client_first("p=tls-server-end-point,,n=user,r=nonce123", "user", &credentials),
            Err(AuthError::InvalidMessage("channel binding is not supported"))
        );
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");
        assert_eq!(
            server.handle_client_first("gibberish", "user", &credentials),
            Err(AuthError::InvalidMessage("invalid GS2 header"))
        );
    }

    #[test]
    fn client_first_username_is_escaped() {
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "co=mma,user", "p", "nonce12345678");
        assert_eq!(
            client.client_first_message().unwrap(),
            "n,,n=co=3Dmma=2Cuser,r=nonce12345678"
        );
    }

    #[test]
    fn server_first_attributes_may_be_reordered() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");

        let first = client.client_first_message().unwrap();
        server.handle_client_first(&first, "user", &credentials).unwrap();

        // The attributes appear in a different order, but both sides must see
        // byte-identical server-first messages (the message is hashed into
        // auth_message verbatim), so rewrite the server's copy too.
        let permuted = format!(
            "s={},i=4096,r=clientnonce123456servernonce1234567",
            BASE64.encode(&credentials.salt)
        );
        assert_ne!(permuted, server.server_first_message);
        server.server_first_message = permuted.clone();

        client.receive_server_first(&permuted).unwrap();
        let final_msg = client.client_final_message().unwrap();
        let server_final = server.handle_client_final(&final_msg).unwrap();
        client.receive_server_final(&server_final).unwrap();
    }

    #[test]
    fn malformed_server_first_messages_rejected() {
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        client.client_first_message().unwrap();
        for bad in [
            "",
            "r=clientnonce123456extra,s=MDIzNDU2Nzg=",      // missing i
            "s=MDIzNDU2Nzg=,i=4096",                        // missing r
            "r=notmyclientnonce,s=MDIzNDU2Nzg=,i=4096",     // wrong nonce prefix
            "r=clientnonce123456,s=!!!,i=4096",             // bad base64 salt
            "r=clientnonce123456,s=MDIzNDU2Nzg=,i=zero",    // bad iteration count
            "r=clientnonce123456,s=MDIzNDU2Nzg=,i=0",       // zero iterations
            "r=clientnonce123456,s=MDIzNDU2Nzg=,i=99999999999999999999", // overflow
            "noncettribute,s=MDIzNDU2Nzg=,i=4096",          // malformed attribute
            "\u{20ac}=x,s=MDIzNDU2Nzg=,i=4096",             // multibyte attribute key
        ] {
            let result = client.receive_server_first(bad);
            assert!(result.is_err(), "expected rejection of {bad:?}");
        }
    }

    #[test]
    fn state_machine_enforced_on_client() {
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        // client-final before client-first.
        assert_eq!(client.client_final_message(), Err(AuthError::State));
        assert_eq!(client.receive_server_final("v=AAAA"), Err(AuthError::State));

        let first = client.client_first_message().unwrap();
        // Calling client-first twice is out of order.
        assert_eq!(client.client_first_message(), Err(AuthError::State));

        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let server_first = server.handle_client_first(&first, "user", &credentials).unwrap();

        // client-final before server-first.
        let mut fresh = client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        fresh.client_first_message().unwrap();
        assert_eq!(fresh.client_final_message(), Err(AuthError::State));

        client.receive_server_first(&server_first).unwrap();
        // Replaying the server-first step is out of order.
        assert_eq!(client.receive_server_first(&server_first), Err(AuthError::State));

        let final_msg = client.client_final_message().unwrap();
        // Producing client-final twice is out of order.
        assert_eq!(client.client_final_message(), Err(AuthError::State));
        let server_final = server.handle_client_final(&final_msg).unwrap();
        // Completing the handshake twice is out of order.
        assert_eq!(client.receive_server_final(&server_final), Ok(()));
    }

    #[test]
    fn state_machine_enforced_on_server() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");
        // client-final before client-first.
        assert_eq!(
            server.handle_client_final("c=biws,r=x,p=AAAA"),
            Err(AuthError::State)
        );

        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        let first = client.client_first_message().unwrap();
        server.handle_client_first(&first, "user", &credentials).unwrap();
        // Replaying the client-first step is out of order.
        assert_eq!(
            server.handle_client_first(&first, "user", &credentials),
            Err(AuthError::State)
        );
    }

    #[test]
    fn malformed_client_final_rejected_by_server() {
        let salt = b"0123456789abcdef".to_vec();
        let credentials = StoredCredentials::derive(ScramMechanism::Sha256, "pencil", &salt, 4096);
        let mut client =
            client_with_nonce(ScramMechanism::Sha256, "user", "pencil", "clientnonce123456");
        let mut server = server_with_nonce(ScramMechanism::Sha256, "servernonce1234567");
        let first = client.client_first_message().unwrap();
        server.handle_client_first(&first, "user", &credentials).unwrap();
        client.receive_server_first(
            "r=clientnonce123456servernonce1234567,s=MDIzNDU2Nzg=,i=4096",
        )
        .unwrap();
        client.client_final_message().unwrap();

        // Wrong channel-binding flag.
        assert_eq!(
            server.handle_client_final(
                "c=eHl6,r=clientnonce123456servernonce1234567,p=dGhlIHBhc3N3b3Jk",
            ),
            Err(AuthError::InvalidMessage("expected c=biws channel binding"))
        );
        // Wrong full nonce.
        assert_eq!(
            server.handle_client_final(
                "c=biws,r=othernonce,p=dGhlIHBhc3N3b3Jk",
            ),
            Err(AuthError::NonceMismatch)
        );
        // Missing proof.
        assert_eq!(
            server.handle_client_final(
                "c=biws,r=clientnonce123456servernonce1234567",
            ),
            Err(AuthError::InvalidMessage("missing p=<proof> attribute"))
        );
        // Invalid base64 proof.
        assert_eq!(
            server.handle_client_final(
                "c=biws,r=clientnonce123456servernonce1234567,p=!!!",
            ),
            Err(AuthError::InvalidMessage("invalid base64 client proof"))
        );
        // Unknown attribute.
        assert_eq!(
            server.handle_client_final(
                "c=biws,r=clientnonce123456servernonce1234567,p=dGhlIHBhc3N3b3Jk,z=extra",
            ),
            Err(AuthError::InvalidMessage(
                "unexpected attribute in client-final message"
            ))
        );
    }

    #[test]
    fn generated_nonces_have_sufficient_entropy() {
        let client = ScramClient::new(ScramMechanism::Sha256, "user", "pwd").unwrap();
        let server = ScramServer::new(ScramMechanism::Sha256);
        // 18 random bytes -> 24 base64 chars, >= 18 bytes of randomness.
        assert!(client.client_nonce.len() >= 18);
        assert!(server.server_nonce.len() >= 18);
    }
}
