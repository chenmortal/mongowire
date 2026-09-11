//! SASL bridge: `saslStart` / `saslContinue` commands mapped onto
//! [`mongo_common::auth::ScramServer`] (SCRAM-SHA-1 / SCRAM-SHA-256).
//!
//! Like [`crate::api::BuiltinHandler`], this is a wrapping [`CommandHandler`]:
//! it answers the two SASL commands itself and forwards everything else to the
//! inner handler. The per-connection SCRAM state machine lives in
//! [`ConnectionInfo::auth`], which the server layer resets per connection.
//!
//! Payload encoding matches the official drivers (Rust driver
//! `client/auth/scram.rs`, Go reference `wireclient/conn.go Login()`): the
//! SCRAM message strings travel as BSON binary subtype 0 in both directions.
//! String payloads are accepted on ingress for tolerance, but replies always
//! use binary so real clients interoperate.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use wirebson::{Bson, Document, RawDocument};

use mongo_common::auth::{ScramMechanism, ScramServer, StoredCredentials};

use crate::api::client_info::ConnectionInfo;
use crate::api::handler::{Command, CommandHandler, Reply};
use crate::api::response::{bson_error, op_msg};
use crate::error::Error;
use crate::messages::{MsgFlags, OpMsg};

/// MongoDB's `AuthenticationFailed` code.
const AUTHENTICATION_FAILED: i32 = 18;

/// Per-connection authentication state, stored inside
/// [`ConnectionInfo::auth`].
#[derive(Debug, Default)]
pub struct AuthState {
    /// The in-flight SCRAM server exchange, if any. `None` between exchanges
    /// (a completed or aborted handshake clears it).
    pub scram: Option<(ScramMechanism, ScramServer)>,
    /// The identity that last authenticated successfully on this connection.
    pub authenticated: Option<String>,
}

/// Where the bridge looks up SCRAM credentials.
///
/// `username` is the identity the client claimed inside the client-first
/// message (RFC 5803-escaped forms already unescaped). Returning `None`
/// fails the exchange with `AuthenticationFailed`.
pub trait CredentialSource: Send + Sync {
    /// The stored credentials for `username` under `mechanism`, or `None`.
    fn lookup(&self, mechanism: ScramMechanism, username: &str) -> Option<StoredCredentials>;
}

/// A `CommandHandler` that answers `saslStart` / `saslContinue` and forwards
/// every other command to `inner`.
///
/// Compose it around the rest of the handler chain, e.g.
/// `ScramBridge::new(builtin_or_user_handler, Arc::new(credential_store))`.
///
/// NOTE: the bridge PERFORMS authentication but does not ENFORCE it —
/// commands reach the inner handler regardless of auth state. Gate access
/// yourself by checking `ctx.auth.authenticated` (or wrap the inner handler
/// accordingly) when unauthenticated access must be refused.
pub struct ScramBridge {
    inner: Arc<dyn CommandHandler>,
    credentials: Arc<dyn CredentialSource>,
}

impl ScramBridge {
    /// Wrap `inner` so that SASL commands are answered from `credentials`.
    pub fn new(inner: Arc<dyn CommandHandler>, credentials: Arc<dyn CredentialSource>) -> Self {
        Self { inner, credentials }
    }

    /// `{saslStart: 1, mechanism, payload, $db}` → server-first reply.
    fn sasl_start(&self, ctx: &mut ConnectionInfo, body: &RawDocument) -> Result<Reply, Error> {
        if ctx.auth.scram.is_some() {
            return Err(auth_failed(
                "saslStart while an authentication exchange is already in progress",
            ));
        }
        let mechanism = parse_mechanism(body)?;
        let client_first = payload_str(body)?;
        let username = parse_client_first_username(&client_first)
            .ok_or_else(|| auth_failed("malformed client-first message"))?;
        let Some(credentials) = self.credentials.lookup(mechanism, &username) else {
            // Like MongoDB, the failure does not distinguish "unknown user"
            // from "wrong password" on the wire.
            return Err(auth_failed("Authentication failed."));
        };
        let mut server = ScramServer::new(mechanism);
        let server_first = server
            .handle_client_first(&client_first, &username, &credentials)
            .map_err(|e| auth_failed(e.to_string()))?;
        ctx.auth.scram = Some((mechanism, server));
        Ok(Reply::Msg(sasl_reply(1, false, &server_first)?))
    }

    /// `{saslContinue: 1, conversationId, payload, $db}` → server-final reply.
    fn sasl_continue(&self, ctx: &mut ConnectionInfo, body: &RawDocument) -> Result<Reply, Error> {
        let client_final = payload_str(body)?;
        // Take the state machine out: any error below aborts the exchange
        // (the next attempt must start with a fresh saslStart).
        let Some((_, mut server)) = ctx.auth.scram.take() else {
            return Err(auth_failed("saslContinue without saslStart"));
        };
        let conversation_id = conversation_id_of(body);
        let server_final = match server.handle_client_final(&client_final) {
            Ok(server_final) => {
                ctx.auth.authenticated = Some(server.username().to_owned());
                server_final
            }
            Err(e) => return Err(auth_failed(e.to_string())),
        };
        Ok(Reply::Msg(sasl_reply(conversation_id, true, &server_final)?))
    }
}

#[async_trait]
impl CommandHandler for ScramBridge {
    async fn handle_command(
        &self,
        ctx: &mut ConnectionInfo,
        command: &Command,
    ) -> Result<Reply, Error> {
        match command.name.as_str() {
            "saslStart" => self.sasl_start(ctx, &command.body),
            "saslContinue" => self.sasl_continue(ctx, &command.body),
            _ => self.inner.handle_command(ctx, command).await,
        }
    }
}

/// An [`Error::Command`] with MongoDB's `AuthenticationFailed` code.
fn auth_failed(message: impl Into<String>) -> Error {
    Error::command(AUTHENTICATION_FAILED, "AuthenticationFailed", message)
}

/// The `mechanism` string of a SASL command, parsed into a SCRAM mechanism.
fn parse_mechanism(body: &RawDocument) -> Result<ScramMechanism, Error> {
    let name = match body.get("mechanism").map_err(bson_error)? {
        Some(wirebson::RawBsonRef::String(name)) => name,
        _ => return Err(auth_failed("saslStart requires a string mechanism")),
    };
    ScramMechanism::from_name(name)
        .ok_or_else(|| auth_failed(format!("unsupported authentication mechanism {name}")))
}

/// The `payload` field of a SASL command. Drivers send BSON binary subtype 0;
/// plain strings are accepted for tolerance.
fn payload_bytes(body: &RawDocument) -> Result<Vec<u8>, Error> {
    match body.get("payload").map_err(bson_error)? {
        Some(wirebson::RawBsonRef::Binary(binary)) => Ok(binary.bytes),
        Some(wirebson::RawBsonRef::String(payload)) => Ok(payload.as_bytes().to_vec()),
        Some(_) => Err(auth_failed("payload must be a string or binary")),
        None => Err(auth_failed("missing payload")),
    }
}

/// [`payload_bytes`] plus a UTF-8 check (SCRAM messages are ASCII).
fn payload_str(body: &RawDocument) -> Result<String, Error> {
    let bytes = payload_bytes(body)?;
    String::from_utf8(bytes).map_err(|_| auth_failed("payload is not valid UTF-8"))
}

/// The `conversationId` of a SASL command, when present (`saslContinue`).
fn conversation_id_of(body: &RawDocument) -> i32 {
    match body.get("conversationId") {
        Ok(Some(wirebson::RawBsonRef::Int32(id))) => id,
        Ok(Some(wirebson::RawBsonRef::Int64(id))) => id as i32,
        _ => 1,
    }
}

/// A SCRAM message as BSON binary subtype 0 — the drivers' choice.
fn payload_bson(message: &str) -> Bson {
    Bson::Binary(mongo_common::bson::Binary {
        subtype: mongo_common::bson::BinarySubtype::Generic,
        bytes: message.as_bytes().to_vec(),
    })
}

/// `{conversationId, done, payload, ok: 1.0}` — the SASL step reply.
fn sasl_reply(conversation_id: i32, done: bool, payload: &str) -> Result<OpMsg, Error> {
    let mut doc = Document::new();
    doc.add("conversationId", conversation_id);
    doc.add("done", done);
    doc.add("payload", payload_bson(payload));
    doc.add("ok", 1.0_f64);
    let raw = doc.encode().map_err(bson_error)?;
    op_msg(MsgFlags::empty(), raw)
}

/// The username claimed by a client-first message (`n,,n=<user>,r=<nonce>`).
///
/// The RFC 5803 escapes are undone (`=2C` → `,` before `=3D` → `=`, reversing
/// the escape order). `None` when the message has no `n=` attribute.
fn parse_client_first_username(client_first: &str) -> Option<String> {
    let bare = client_first.strip_prefix("n,,").unwrap_or(client_first);
    let username = bare.split(',').next()?.strip_prefix("n=")?;
    // The escaped username cannot contain a literal `,`, so the first
    // comma-separated attribute is the whole username.
    Some(username.replace("=2C", ",").replace("=3D", "="))
}

/// An in-memory [`CredentialSource`] for tests and examples.
#[derive(Debug, Default)]
pub struct MemoryCredentialSource {
    users: HashMap<(ScramMechanism, String), StoredCredentials>,
}

impl MemoryCredentialSource {
    /// Store credentials derived from `password` for `username`.
    pub fn insert(
        &mut self,
        mechanism: ScramMechanism,
        username: impl Into<String>,
        password: &str,
    ) {
        let username = username.into();
        // The mechanism-appropriate password PBKDF2 consumes (the public form
        // of `effective_password` in `mongo_common::auth`): the MongoDB md5
        // digest for SHA-1, the raw password for SHA-256.
        let effective = match mechanism {
            ScramMechanism::Sha1 => mongo_common::auth::mongo_sha1_password(&username, password),
            ScramMechanism::Sha256 => password.to_owned(),
        };
        let salt = Vec::from_iter(0..16u8); // a real store would persist a per-user salt
        let credentials =
            StoredCredentials::derive(mechanism, &effective, &salt, mechanism.default_iterations());
        self.users.insert((mechanism, username), credentials);
    }
}

impl CredentialSource for MemoryCredentialSource {
    fn lookup(&self, mechanism: ScramMechanism, username: &str) -> Option<StoredCredentials> {
        self.users
            .get(&(mechanism, username.to_owned()))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handler::Reply;
    use crate::api::response::ping_reply;
    use futures::executor::block_on;
    use mongo_common::auth::ScramClient;
    use wirebson::RawDocument;

    /// A handler recording that it received a command (for forward checks).
    #[derive(Debug, Default)]
    struct ForwardProbe {
        seen: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl CommandHandler for ForwardProbe {
        async fn handle_command(
            &self,
            _ctx: &mut ConnectionInfo,
            _command: &Command,
        ) -> Result<Reply, Error> {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Reply::Msg(ping_reply().unwrap()))
        }
    }

    /// A store with one SCRAM-SHA-256 user and one SCRAM-SHA-1 user.
    fn store() -> MemoryCredentialSource {
        let mut store = MemoryCredentialSource::default();
        store.insert(ScramMechanism::Sha256, "ada", "lovelace");
        store.insert(ScramMechanism::Sha1, "grace", "hopper");
        store
    }

    fn bridge(store: MemoryCredentialSource) -> ScramBridge {
        ScramBridge::new(
            Arc::new(ForwardProbe::default()),
            Arc::new(store),
        )
    }

    /// A SASL command document from the client's point of view (binary
    /// payload, like the drivers send).
    fn sasl_command(name: &str, mechanism: Option<&str>, payload: &str, extra: &[(&str, Bson)]) -> Command {
        let mut doc = Document::new();
        doc.add(name, 1_i32);
        if let Some(mechanism) = mechanism {
            doc.add("mechanism", mechanism);
        }
        doc.add(
            "payload",
            Bson::Binary(mongo_common::bson::Binary {
                subtype: mongo_common::bson::BinarySubtype::Generic,
                bytes: Vec::from(payload.as_bytes()),
            }),
        );
        doc.add("conversationId", 1_i32);
        for (key, value) in extra {
            doc.add(*key, value.clone());
        }
        doc.add("$db", "admin");
        Command {
            name: name.to_owned(),
            body: doc.encode().unwrap(),
            sequences: Vec::new(),
            flags: MsgFlags::empty(),
        }
    }

    /// Run one command through the bridge, unwrapping the reply message.
    fn handle(
        bridge: &ScramBridge,
        ctx: &mut ConnectionInfo,
        command: &Command,
    ) -> Result<Document, Error> {
        match block_on(bridge.handle_command(ctx, command))? {
            Reply::Msg(msg) => Ok(msg.document().shallow().unwrap()),
            Reply::NoReply => panic!("SASL steps always reply"),
        }
    }

    /// The binary payload of a SASL reply, as a string.
    fn reply_payload(reply: &Document) -> String {
        let Some(Bson::Binary(binary)) = reply.get("payload") else {
            panic!("SASL replies carry a binary payload")
        };
        assert_eq!(
            binary.subtype,
            mongo_common::bson::BinarySubtype::Generic,
            "payloads are BSON binary subtype 0"
        );
        String::from_utf8(binary.bytes.clone()).unwrap()
    }

    /// Drive a full SCRAM exchange through the bridge with `password`.
    fn run_exchange(mechanism: ScramMechanism, user: &str, password: &str) -> Result<(), Error> {
        let bridge = bridge(store());
        let mut ctx = ConnectionInfo::new();
        let mut client = ScramClient::new(mechanism, user, password).unwrap();

        let first = client.client_first_message().unwrap();
        let reply = handle(
            &bridge,
            &mut ctx,
            &sasl_command("saslStart", Some(mechanism.name()), &first, &[]),
        )?;
        assert_eq!(reply.get("ok"), Some(&Bson::Double(1.0)));
        assert_eq!(reply.get("conversationId"), Some(&Bson::Int32(1)));
        assert_eq!(reply.get("done"), Some(&Bson::Bool(false)));
        client.receive_server_first(&reply_payload(&reply)).unwrap();

        let final_msg = client.client_final_message().unwrap();
        let reply = handle(
            &bridge,
            &mut ctx,
            &sasl_command("saslContinue", None, &final_msg, &[]),
        )?;
        assert_eq!(reply.get("ok"), Some(&Bson::Double(1.0)));
        assert_eq!(reply.get("conversationId"), Some(&Bson::Int32(1)));
        assert_eq!(reply.get("done"), Some(&Bson::Bool(true)));
        client.receive_server_final(&reply_payload(&reply)).unwrap();

        assert_eq!(ctx.auth.authenticated.as_deref(), Some(user));
        assert!(ctx.auth.scram.is_none(), "the exchange must be cleared");
        Ok(())
    }

    #[test]
    fn scram_sha256_happy_path() {
        run_exchange(ScramMechanism::Sha256, "ada", "lovelace").unwrap();
    }

    #[test]
    fn scram_sha1_happy_path() {
        run_exchange(ScramMechanism::Sha1, "grace", "hopper").unwrap();
    }

    #[test]
    fn wrong_password_fails_with_authentication_failed() {
        let err = run_exchange(ScramMechanism::Sha256, "ada", "wrong").unwrap_err();
        let Error::Command { code, code_name, message } = err else {
            panic!("expected a command error")
        };
        assert_eq!(code, AUTHENTICATION_FAILED);
        assert_eq!(code_name, "AuthenticationFailed");
        assert!(message.contains("client proof mismatch"), "{message}");
    }

    #[test]
    fn unknown_user_fails_without_leaking_why() {
        let err = run_exchange(ScramMechanism::Sha256, "nobody", "whatever").unwrap_err();
        assert!(matches!(
            err,
            Error::Command { code: AUTHENTICATION_FAILED, .. }
        ));
    }

    #[test]
    fn string_payloads_are_accepted() {
        let bridge = bridge(store());
        let mut ctx = ConnectionInfo::new();
        let mut client = ScramClient::new(ScramMechanism::Sha256, "ada", "lovelace").unwrap();
        let first = client.client_first_message().unwrap();

        // Same as `sasl_command`, but with the payload as a BSON string.
        let mut doc = Document::new();
        doc.add("saslStart", 1_i32);
        doc.add("mechanism", "SCRAM-SHA-256");
        doc.add("payload", first.as_str());
        doc.add("$db", "admin");
        let command = Command {
            name: "saslStart".to_owned(),
            body: doc.encode().unwrap(),
            sequences: Vec::new(),
            flags: MsgFlags::empty(),
        };
        let reply = handle(&bridge, &mut ctx, &command).unwrap();
        assert_eq!(reply.get("ok"), Some(&Bson::Double(1.0)));
    }

    #[test]
    fn unsupported_mechanism_is_rejected() {
        let bridge = bridge(store());
        let mut ctx = ConnectionInfo::new();
        let err = handle(
            &bridge,
            &mut ctx,
            &sasl_command("saslStart", Some("SCRAM-SHA-3"), "n,,n=ada,r=nonce", &[]),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Command { code: AUTHENTICATION_FAILED, .. }
        ));
    }

    #[test]
    fn sasl_continue_without_start_is_rejected() {
        let bridge = bridge(store());
        let mut ctx = ConnectionInfo::new();
        let err = handle(
            &bridge,
            &mut ctx,
            &sasl_command("saslContinue", None, "c=biws,r=x,p=AAAA", &[]),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Command { code: AUTHENTICATION_FAILED, .. }
        ));
    }

    #[test]
    fn second_sasl_start_while_in_flight_is_rejected() {
        let bridge = bridge(store());
        let mut ctx = ConnectionInfo::new();
        let mut client = ScramClient::new(ScramMechanism::Sha256, "ada", "lovelace").unwrap();
        let first = client.client_first_message().unwrap();
        handle(
            &bridge,
            &mut ctx,
            &sasl_command("saslStart", Some("SCRAM-SHA-256"), &first, &[]),
        )
        .unwrap();
        let mut second = ScramClient::new(ScramMechanism::Sha256, "ada", "lovelace").unwrap();
        let other_first = second.client_first_message().unwrap();
        let err = handle(
            &bridge,
            &mut ctx,
            &sasl_command("saslStart", Some("SCRAM-SHA-256"), &other_first, &[]),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Command { code: AUTHENTICATION_FAILED, .. }
        ));
    }

    #[test]
    fn missing_or_wrong_typed_fields_are_rejected() {
        let bridge = bridge(store());
        let mut ctx = ConnectionInfo::new();

        // No payload at all.
        let mut doc = Document::new();
        doc.add("saslStart", 1_i32);
        doc.add("mechanism", "SCRAM-SHA-256");
        let command = Command {
            name: "saslStart".to_owned(),
            body: doc.encode().unwrap(),
            sequences: Vec::new(),
            flags: MsgFlags::empty(),
        };
        assert!(matches!(
            handle(&bridge, &mut ctx, &command),
            Err(Error::Command { code: AUTHENTICATION_FAILED, .. })
        ));

        // No mechanism.
        let mut doc = Document::new();
        doc.add("saslStart", 1_i32);
        doc.add("payload", "n,,n=ada,r=nonce");
        let command = Command {
            name: "saslStart".to_owned(),
            body: doc.encode().unwrap(),
            sequences: Vec::new(),
            flags: MsgFlags::empty(),
        };
        assert!(matches!(
            handle(&bridge, &mut ctx, &command),
            Err(Error::Command { code: AUTHENTICATION_FAILED, .. })
        ));
    }

    #[test]
    fn other_commands_are_forwarded_to_the_inner_handler() {
        let bridge = bridge(store());
        let mut ctx = ConnectionInfo::new();
        let command = Command {
            name: "ping".to_owned(),
            body: RawDocument::from_vec(
                Document::from_iter([("ping", Bson::Int32(1)), ("$db", Bson::from("admin"))])
                    .encode()
                    .unwrap()
                    .into_bytes()
                    .to_vec(),
            )
            .unwrap(),
            sequences: Vec::new(),
            flags: MsgFlags::empty(),
        };
        let reply = block_on(bridge.handle_command(&mut ctx, &command)).unwrap();
        assert!(matches!(reply, Reply::Msg(_)));
    }

    #[test]
    fn username_escaping_is_undone() {
        assert_eq!(
            parse_client_first_username("n,,n=co=3Dmma=2Cuser,r=nonce").as_deref(),
            Some("co=mma,user")
        );
        assert_eq!(parse_client_first_username("n,,n=plain,r=x").as_deref(), Some("plain"));
        assert_eq!(parse_client_first_username("n,,r=noname"), None);
        assert_eq!(parse_client_first_username(""), None);
    }

    #[test]
    fn escaped_usernames_authenticate_end_to_end() {
        let mut store = MemoryCredentialSource::default();
        store.insert(ScramMechanism::Sha256, "co=mma,user", "pw");
        let bridge = bridge(store);
        let mut ctx = ConnectionInfo::new();
        let mut client = ScramClient::new(ScramMechanism::Sha256, "co=mma,user", "pw").unwrap();

        let first = client.client_first_message().unwrap();
        let reply = handle(
            &bridge,
            &mut ctx,
            &sasl_command("saslStart", Some("SCRAM-SHA-256"), &first, &[]),
        )
        .unwrap();
        client.receive_server_first(&reply_payload(&reply)).unwrap();

        let final_msg = client.client_final_message().unwrap();
        handle(
            &bridge,
            &mut ctx,
            &sasl_command("saslContinue", None, &final_msg, &[]),
        )
        .unwrap();
        assert_eq!(ctx.auth.authenticated.as_deref(), Some("co=mma,user"));
    }

    #[test]
    fn memory_store_derives_mechanism_appropriate_credentials() {
        // The SHA-1 store entry must accept the plaintext password (the
        // MongoDB md5 quirk is applied symmetrically on both sides).
        let store = store();
        let salted = store.lookup(ScramMechanism::Sha1, "grace").unwrap();
        let reference = StoredCredentials::derive(
            ScramMechanism::Sha1,
            &mongo_common::auth::mongo_sha1_password("grace", "hopper"),
            &Vec::from_iter(0..16u8),
            ScramMechanism::Sha1.default_iterations(),
        );
        assert_eq!(salted, reference);
        assert!(store.lookup(ScramMechanism::Sha256, "grace").is_none());
    }
}
