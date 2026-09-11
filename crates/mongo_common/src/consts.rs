//! Protocol constants from the official MongoDB wire protocol specification.
//!
//! All integers on the wire are little-endian.

/// Size of the standard message header in bytes:
/// `messageLength` + `requestID` + `responseTo` + `opCode`, each `i32`.
pub const MSG_HEADER_LEN: usize = 16;

/// Maximum total message size accepted on the wire.
///
/// Matches `MaxMsgLen` in FerretDB/wire and the official Rust driver's default
/// `maxMessageSizeBytes` (48 MB).
pub const MAX_MSG_LEN: i32 = 48_000_000;

/// Maximum size of a single BSON document (`maxBSONObjectSize`, 16 MiB).
pub const MAX_BSON_LEN: i32 = 16_777_216;

/// Wire `opCode` values. See the "Opcodes" table of the official specification.
pub mod opcodes {
    /// Reply to a client request; `responseTo` is set. Removed in MongoDB 5.1
    /// (kept only as what servers may still emit for legacy handshakes).
    pub const OP_REPLY: i32 = 1;
    pub const OP_UPDATE: i32 = 2001;
    pub const OP_INSERT: i32 = 2002;
    /// Formerly used for OP_GET_BY_OID.
    pub const OP_RESERVED: i32 = 2003;
    /// Removed in MongoDB 5.1, except for the `hello` / `isMaster` handshake.
    pub const OP_QUERY: i32 = 2004;
    pub const OP_GET_MORE: i32 = 2005;
    pub const OP_DELETE: i32 = 2006;
    pub const OP_KILL_CURSORS: i32 = 2007;
    /// Wraps other opcodes using compression.
    pub const OP_COMPRESSED: i32 = 2012;
    /// Used for both client requests and database replies.
    pub const OP_MSG: i32 = 2013;
}

/// `OP_MSG` `flagBits` (u32 on the wire).
///
/// Bits 0-15 are *required*: parsers MUST error on unknown set bits.
/// Bits 16-31 are *optional*: parsers MUST ignore unknown set bits, and
/// proxies MUST clear them before forwarding.
pub mod msg_flags {
    /// Bit 0: the message ends with a 4-byte CRC-32C checksum.
    pub const CHECKSUM_PRESENT: u32 = 1 << 0;
    /// Bit 1: another message follows without further action from the receiver.
    /// Requests with this bit set MUST NOT be replied to.
    pub const MORE_TO_COME: u32 = 1 << 1;
    /// Bit 16: the client is prepared for multiple `moreToCome` replies.
    pub const EXHAUST_ALLOWED: u32 = 1 << 16;
}

/// `OP_QUERY` `flags` (i32 on the wire), bit positions per the legacy spec.
pub mod query_flags {
    /// Bit 1: tailable cursor.
    pub const TAILABLE_CURSOR: i32 = 1 << 1;
    /// Bit 2: allow query of a replica secondary.
    pub const SLAVE_OK: i32 = 1 << 2;
    /// Bit 3: internal replication use.
    pub const OPLOG_REPLAY: i32 = 1 << 3;
    /// Bit 4: cursor does not time out.
    pub const NO_CURSOR_TIMEOUT: i32 = 1 << 4;
    /// Bit 5: await data (use with [`TAILABLE_CURSOR`]).
    pub const AWAIT_DATA: i32 = 1 << 5;
    /// Bit 6: exhaust cursor.
    pub const EXHAUST: i32 = 1 << 6;
    /// Bit 7: allow partial results from shards.
    pub const PARTIAL: i32 = 1 << 7;
}

/// `OP_REPLY` `responseFlags` (i32 on the wire), bit positions per the legacy spec.
pub mod reply_flags {
    /// Bit 0: cursor no longer exists on the server.
    pub const CURSOR_NOT_FOUND: i32 = 1 << 0;
    /// Bit 1: query failed.
    pub const QUERY_FAILURE: i32 = 1 << 1;
    /// Bit 2: shard config is stale.
    pub const SHARD_CONFIG_STALE: i32 = 1 << 2;
    /// Bit 3: server supports `AwaitData`.
    pub const AWAIT_CAPABLE: i32 = 1 << 3;
}

/// `compressorId` byte of `OP_COMPRESSED`.
pub mod compressor_ids {
    /// Content is uncompressed; used for testing.
    pub const NOOP: u8 = 0;
    pub const SNAPPY: u8 = 1;
    pub const ZLIB: u8 = 2;
    pub const ZSTD: u8 = 3;
    /// 4-255 are reserved for future use.
    pub const FIRST_RESERVED: u8 = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_len() {
        assert_eq!(MSG_HEADER_LEN, 16);
        // 4 fields of i32 each.
        assert_eq!(MSG_HEADER_LEN, std::mem::size_of::<i32>() * 4);
    }

    #[test]
    fn limits_match_references() {
        assert_eq!(MAX_MSG_LEN, 48_000_000);
        assert_eq!(MAX_BSON_LEN, 16_777_216);
        assert_eq!(MAX_BSON_LEN, 16 * 1024 * 1024);
    }

    #[test]
    fn opcode_values() {
        use super::opcodes::*;
        assert_eq!(OP_REPLY, 1);
        assert_eq!(OP_UPDATE, 2001);
        assert_eq!(OP_INSERT, 2002);
        assert_eq!(OP_RESERVED, 2003);
        assert_eq!(OP_QUERY, 2004);
        assert_eq!(OP_GET_MORE, 2005);
        assert_eq!(OP_DELETE, 2006);
        assert_eq!(OP_KILL_CURSORS, 2007);
        assert_eq!(OP_COMPRESSED, 2012);
        assert_eq!(OP_MSG, 2013);
    }

    #[test]
    fn flag_bits() {
        use super::msg_flags::*;
        assert_eq!(CHECKSUM_PRESENT, 1);
        assert_eq!(MORE_TO_COME, 2);
        assert_eq!(EXHAUST_ALLOWED, 1 << 16);
    }
}
