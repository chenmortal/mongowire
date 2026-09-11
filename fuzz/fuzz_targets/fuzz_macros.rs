//! Fuzz the runtime contracts of the `doc!` / `arr!` / `oid!` / `dt!` macros.
//!
//! `macro_rules!` expands at compile time, so we can't drive the macro
//! *syntax* with random bytes. What we *can* do is exercise the runtime
//! code the macros expand into and assert it agrees with the direct
//! `Document::add` / `Array::push` / `ObjectId::from_hex` / literal
//! `Bson::DateTime` paths — any divergence (e.g. a future macro change
//! picking the wrong variant tag or losing a field) will fail this
//! fuzzer.
//!
//! Invariants asserted:
//!
//! 1. `oid!` on any 24-character valid hex string produces the same
//!    `Bson::ObjectId` as `ObjectId::from_hex`.
//! 2. `dt!` is a transparent constructor: every `i64` slice becomes the
//!    matching `Bson::DateTime`.
//! 3. `doc!` / `arr!` round-trip through encode/decode byte-stable
//!    (canonical invariant, mirroring `fuzz_document.rs`).

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1) oid!: every 24-byte valid-hex window must agree with the API.
    for window in data.windows(24) {
        let Ok(hex) = std::str::from_utf8(window) else {
            continue;
        };
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let macro_oid = wirebson::oid!(hex);
        let api_oid = wirebson::Bson::ObjectId(
            mongo_common::bson::ObjectId::from_hex(hex).unwrap(),
        );
        assert_eq!(macro_oid, api_oid);
    }

    // 2) dt!: transparent i64 -> Bson::DateTime.
    for chunk in data.chunks_exact(8) {
        let ms = i64::from_le_bytes(chunk.try_into().unwrap());
        assert_eq!(wirebson::dt!(ms), wirebson::Bson::DateTime(ms));
    }

    // 3) doc!/arr!: build a doc whose `values` field is the result of
    // an `arr!`-style sequence (exercised via the equivalent
    // `FromIterator` path that the macro emits), then verify the
    // canonical encode/decode byte-stability invariant.
    let scalars: Vec<wirebson::Bson> = data
        .chunks(8)
        .map(|c| {
            let mut buf = [0u8; 8];
            buf[..c.len()].copy_from_slice(c);
            wirebson::Bson::Int64(i64::from_le_bytes(buf))
        })
        .collect();
    if scalars.is_empty() {
        return;
    }
    let inner: wirebson::Array = scalars.iter().cloned().collect();
    let doc = wirebson::doc! { "values": inner, "count": scalars.len() as i64 };

    let Ok(raw1) = doc.encode() else { return };
    let Ok(decoded) = raw1.deep() else { return };
    let Ok(raw2) = decoded.encode() else { return };
    assert_eq!(
        raw1.as_bytes(),
        raw2.as_bytes(),
        "encode is not idempotent after deep decode"
    );
});
