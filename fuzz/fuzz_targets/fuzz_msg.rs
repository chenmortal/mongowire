//! Fuzz the wire framing path: header validation, length bounds, OP_MSG
//! sections/flags/checksum, OP_QUERY/OP_REPLY/OP_COMPRESSED bodies.
//!
//! Mirrors the Go reference's `FuzzMsg` (seeded with the same recorded
//! traffic). `parse_message` is the exact production entry point; it must
//! never panic and never loop regardless of input.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = bytes::BytesMut::from(data);
    // Errors are fine — a panic, hang, or allocation blow-up is not.
    let _ = mongowire::framing::parse_message(&mut buf, mongo_common::consts::MAX_MSG_LEN);
});
