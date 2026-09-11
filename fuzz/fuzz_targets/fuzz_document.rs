//! Fuzz BSON document validation and decoding (mirrors the Go reference's
//! `FuzzDocument`).
//!
//! Invariants asserted beyond "no panic":
//! * a validated document decodes at both depths or errors cleanly;
//! * our own encoding must decode again, and encoding is **idempotent**:
//!   `encode(deep(encode(deep(raw))))` is byte-stable. (The first encode MAY
//!   canonicalize non-canonical array element names — arrays are lists, and
//!   the Go reference ignores element names the same way — but the
//!   canonical form must be a fixpoint.)

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = wirebson::RawDocument::from_bytes(bytes::Bytes::copy_from_slice(data)) else {
        return;
    };
    let _ = raw.shallow();
    let Ok(doc) = raw.deep() else { return };
    let Ok(re1) = doc.encode() else {
        panic!("a document we decoded must encode");
    };
    let Ok(doc2) = re1.deep() else {
        panic!("our own encoding must decode");
    };
    let Ok(re2) = doc2.encode() else {
        panic!("our own encoding must encode");
    };
    assert_eq!(
        re1.as_bytes(),
        re2.as_bytes(),
        "encode is not idempotent after deep decode"
    );
});
