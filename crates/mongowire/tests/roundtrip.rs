//! Property-based round-trip tests: random documents of every BSON type must
//! survive encode → decode → encode with byte-exact stability.

use proptest::prelude::*;

use wirebson::{Array, Bson, Document, RawDocument};

/// A BSON Binary with random content and a valid subtype.
fn arb_binary() -> impl Strategy<Value = mongo_common::bson::Binary> {
    (prop::collection::vec(any::<u8>(), 0..64), 0u8..=6).prop_map(|(bytes, subtype)| {
        mongo_common::bson::Binary {
            subtype: mongo_common::bson::BinarySubtype::from_u8(subtype)
                .unwrap_or(mongo_common::bson::BinarySubtype::Generic),
            bytes,
        }
    })
}

fn arb_leaf() -> impl Strategy<Value = Bson> {
    prop_oneof![
        any::<f64>().prop_map(Bson::Double),
        // Skip NUL in strings: interior NULs are rejected by design.
        "[^\u{0}]{0,32}".prop_map(Bson::String),
        any::<bool>().prop_map(Bson::Bool),
        any::<i64>().prop_map(Bson::DateTime),
        any::<i32>().prop_map(Bson::Int32),
        any::<i64>().prop_map(Bson::Int64),
        Just(Bson::Undefined),
        Just(Bson::Null),
        Just(Bson::MinKey),
        Just(Bson::MaxKey),
        arb_binary().prop_map(Bson::Binary),
        // Regexes without NULs.
        ("[^\u{0}]{0,16}", "[^\u{0}]{0,4}").prop_map(|(pattern, options)| {
            Bson::Regex(mongo_common::bson::Regex {
                pattern,
                options,
            })
        }),
        "[^\u{0}]{0,32}".prop_map(Bson::JavaScript),
        "[^\u{0}]{0,16}".prop_map(Bson::Symbol),
        (any::<u32>(), any::<u32>()).prop_map(|(seconds, increment)| {
            Bson::Timestamp(mongo_common::bson::Timestamp {
                seconds,
                increment,
            })
        }),
        any::<[u8; 16]>().prop_map(|bytes| {
            Bson::Decimal128(mongo_common::bson::Decimal128::from_le_bytes(bytes))
        }),
    ]
}

fn arb_value(depth: u32) -> impl Strategy<Value = Bson> {
    arb_leaf().prop_recursive(depth, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4)
                .prop_map(|values| Bson::Array(Array { values })),
            prop::collection::vec(("[^\u{0}]{0,12}", inner), 0..4)
                .prop_map(|fields| Bson::Document(fields.into_iter().collect::<Document>())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn document_roundtrips_byte_exactly(doc in arb_value(3)) {
        // Only documents are encodable as top-level values.
        let Bson::Document(doc) = doc else { return Ok(()) };
        let raw = doc.encode().expect("generated docs must encode");

        // Decode deep and re-encode: bytes must be identical.
        let decoded = raw.deep().expect("our own bytes must decode");
        let reencoded = decoded.encode().expect("decoded docs must encode");
        prop_assert_eq!(raw.as_bytes(), reencoded.as_bytes());

        // The decoded document must equal the original.
        prop_assert_eq!(&doc, &decoded);

        // The raw form validates standalone.
        prop_assert!(RawDocument::from_bytes(raw.into_bytes()).is_ok());
    }

    #[test]
    fn truncated_documents_never_panic(doc in arb_value(2)) {
        let Bson::Document(doc) = doc else { return Ok(()) };
        let raw = doc.encode().expect("generated docs must encode");
        let bytes = raw.as_bytes();
        for n in 0..bytes.len() {
            // Every truncation must fail validation — never panic and never
            // decode.
            let truncated = bytes::Bytes::copy_from_slice(&bytes[..n]);
            let result = RawDocument::from_bytes(truncated).and_then(|r| r.deep().map(|_| ()));
            prop_assert!(result.is_err(), "truncation at byte {n} must not decode");
        }
    }
}
