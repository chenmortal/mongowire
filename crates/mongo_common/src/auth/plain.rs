//! PLAIN mechanism payload helpers (RFC 4616):
//! `authz-id NUL authc-id NUL password`, encoded as UTF-8.

use crate::auth::AuthError;

/// A parsed PLAIN client payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainMessage {
    /// Authorization identity (often empty).
    pub authz_id: String,
    /// Authentication identity — the username.
    pub authc_id: String,
    pub password: String,
}

/// Parse a PLAIN client payload (exactly two NUL separators).
///
/// All three fields (`authz-id`, `authc-id`, `password`) must be valid UTF-8;
/// any of them may be empty.
///
/// # Errors
/// [`AuthError::InvalidMessage`] if the payload does not have exactly two NULs
/// or is not valid UTF-8.
pub fn parse_client_payload(payload: &[u8]) -> Result<PlainMessage, AuthError> {
    let fields: Vec<&[u8]> = payload.split(|&byte| byte == 0).collect();
    if fields.len() != 3 {
        return Err(AuthError::InvalidMessage("expected two NUL separators"));
    }
    let as_utf8 = |bytes: &[u8]| -> Result<String, AuthError> {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| AuthError::InvalidMessage("payload is not valid UTF-8"))
    };
    Ok(PlainMessage {
        authz_id: as_utf8(fields[0])?,
        authc_id: as_utf8(fields[1])?,
        password: as_utf8(fields[2])?,
    })
}

/// Build a PLAIN client payload: `authz_id \0 authc_id \0 password`.
pub fn build_client_payload(authz_id: &str, authc_id: &str, password: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(authz_id.len() + authc_id.len() + password.len() + 2);
    payload.extend_from_slice(authz_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(authc_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(password.as_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes = build_client_payload("", "user", "pwd");
        assert_eq!(bytes, b"\0user\0pwd".to_vec());
        let parsed = parse_client_payload(&bytes).unwrap();
        assert_eq!(
            parsed,
            PlainMessage {
                authz_id: String::new(),
                authc_id: "user".to_owned(),
                password: "pwd".to_owned(),
            }
        );
    }

    #[test]
    fn too_many_nuls_rejected() {
        assert_eq!(
            parse_client_payload(b"a\0b\0c\0d"),
            Err(AuthError::InvalidMessage("expected two NUL separators"))
        );
    }

    #[test]
    fn too_few_nuls_rejected() {
        assert_eq!(
            parse_client_payload(b"abc"),
            Err(AuthError::InvalidMessage("expected two NUL separators"))
        );
        assert_eq!(
            parse_client_payload(b"a\0b"),
            Err(AuthError::InvalidMessage("expected two NUL separators"))
        );
        assert_eq!(
            parse_client_payload(b""),
            Err(AuthError::InvalidMessage("expected two NUL separators"))
        );
    }

    #[test]
    fn roundtrip_with_all_fields() {
        let bytes = build_client_payload("authz", "authc", "p@ss word");
        assert_eq!(bytes, b"authz\0authc\0p@ss word".to_vec());
        let parsed = parse_client_payload(&bytes).unwrap();
        assert_eq!(
            parsed,
            PlainMessage {
                authz_id: "authz".to_owned(),
                authc_id: "authc".to_owned(),
                password: "p@ss word".to_owned(),
            }
        );
    }

    #[test]
    fn empty_fields_are_allowed() {
        let parsed = parse_client_payload(b"\0\0").unwrap();
        assert_eq!(
            parsed,
            PlainMessage {
                authz_id: String::new(),
                authc_id: String::new(),
                password: String::new(),
            }
        );
    }

    #[test]
    fn invalid_utf8_rejected() {
        assert_eq!(
            parse_client_payload(b"a\0b\0\xff"),
            Err(AuthError::InvalidMessage("payload is not valid UTF-8"))
        );
    }
}
