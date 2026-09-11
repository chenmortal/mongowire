//! Base primitives for the MongoDB wire protocol — the `mysql_common` of the MongoDB ecosystem.
//!
//! This crate is the lowest layer of the `mongowire` workspace and has no
//! dependencies on other workspace crates. It is usable directly by any
//! client or server driver:
//!
//! * [`consts`] — protocol constants (opcodes, limits, flag bits).
//! * [`io`] — protocol IO helper traits (LE integers, cstrings, length prefixes).
//! * [`crc32c`] — CRC-32C (Castagnoli) checksum.
//! * [`bson`] — BSON scalar types, tag-level scalar parsing and Rust type conversions.
//! * [`auth`] — SCRAM-SHA-1 / SCRAM-SHA-256 (both sides) and PLAIN helpers.
//!
//! Document/array structure and full BSON encode/decode live in the `wirebson`
//! crate; wire protocol messages live in the `mongowire` crate.

#![forbid(unsafe_code)]

pub mod auth;
pub mod bson;
pub mod consts;
pub mod crc32c;
pub mod io;
