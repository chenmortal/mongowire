# mongowire

[English](README.md) | [简体中文](README.zh-CN.md)

Rust implementation of the MongoDB wire protocol: a server-side protocol
parser plus an embeddable tokio server. The structure follows
[pgwire](https://github.com/sunng87/pgwire) (the Rust PostgreSQL wire
protocol library); protocol details follow the
[official specification](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/).

## Crate layout

```
mongo_common   Base primitives (the mysql_common of this stack)
               ├── consts   Protocol constants (opcodes/limits/flag bits/compressor IDs)
               ├── io       Protocol IO helper traits (LE integers/cstrings/length prefixes)
               ├── crc32c   CRC-32C (Castagnoli) checksum
               ├── bson     BSON scalar types + tag-level parsing + Rust type conversions
               │            (i8~i128/f64/bool/String/time/Uuid/Decimal128, per feature)
               └── auth     SCRAM-SHA-1 / SCRAM-SHA-256 state machines (both sides) + PLAIN
wirebson       BSON structure layer (modeled after FerretDB wirebson)
               Zero-copy RawDocument/RawArray over bytes::Bytes + eager Document/Array,
               shallow/deep decoding, all 20 BSON types, log-friendly formatting
mongowire      Protocol layer (no runtime dependency by default)
               ├── messages   OP_MSG / OP_QUERY / OP_REPLY / OP_COMPRESSED
               ├── framing    16-byte header + length prefix + CRC-32C (verify on
               │              read, compute on write)
               ├── compression  noop always built; zlib/snappy/zstd per feature
               ├── codec      (server) tokio_util::codec adapter
               └── api        (server) CommandHandler trait, built-in hello/ping
                              replies, saslStart/saslContinue SCRAM bridge
mongowire-server  Example server (hello/ping/buildInfo/find demo)
```

Dependency chain: `mongo_common` → `wirebson` → `mongowire` → example.

## Feature matrix

| crate | feature | notes |
|---|---|---|
| all | (default) | Pure sync protocol/BSON layers, no tokio |
| mongowire | `server` | tokio + tokio-util codec + api layers (embeddable server) |
| mongowire | `zlib` / `snappy` / `zstd` | OP_COMPRESSED compressors; `compression` umbrella |
| mongo_common | `uuid` / `decimal128-convert` | Uuid / rust-dec Decimal128 value conversions |
| wirebson | `serde_json` / `uuid` / `decimal128-convert` | Bson ↔ corresponding types |

## Spec points (implemented strictly)

- Little-endian throughout; `MsgHeader` is 16 bytes (`messageLength` includes itself).
- `OP_MSG` `flagBits`: **unknown bits 0–15 MUST error, bits 16–31 MUST be
  ignored**; with `checksumPresent`, a CRC-32C (RFC 4960 appendix B) covers the
  header plus the body before the trailing 4 bytes — this crate **verifies on
  read and computes on write** (MongoDB 4.2+ behavior on non-TLS connections;
  both reference implementations only did half each).
- Sections: exactly one kind-0 body (first); kind-1 document-sequence
  identifiers are non-empty and must not duplicate a top-level body field;
  kind-2 (internal use) is rejected.
- `moreToCome` requests are never replied to; replies may only stream when the
  request set `exhaustAllowed`.
- `OP_QUERY` survives only for the legacy handshake (`hello`/`isMaster`,
  issued on `admin.$cmd` by pre-4.4 drivers), answered with `OP_REPLY`.
- Limits: `MAX_MSG_LEN = 48_000_000`, `MAX_BSON_LEN = 16_777_216`.

## Quick start

```bash
cargo run -p mongowire-server -- --bind 127.0.0.1:27017
```

Embedding your own service: implement `CommandHandler` and compose the
built-in replies:

```rust
use std::sync::Arc;
use mongowire::api::{Command, CommandHandler, ConnectionInfo, Reply, ServerConfig, ServerHandlers};
use mongowire::api::response::{handshake_reply, ping_reply};
use mongowire::Error;

struct MyHandler { max_msg_len: i32 }

impl CommandHandler for MyHandler {
    async fn handle_command(&self, _ctx: &mut ConnectionInfo, cmd: &Command) -> Result<Reply, Error> {
        match cmd.name.as_str() {
            "ping" => Ok(Reply::Msg(mongowire::api::ping_reply()?)),
            // ... your command logic; Err(...) is converted to a
            // {ok: 0.0, errmsg, code, codeName} wire reply
            _ => Err(Error::command(59, "CommandNotFound", format!("no such command: {}", cmd.name))),
        }
    }
}
```

## Testing and verification

```bash
cargo test --workspace --all-features   # everything: 239 tests
cargo test -p mongowire --test golden   # golden tests: byte-exact replay of real MongoDB traffic
```

Golden data comes from [FerretDB/wire](https://github.com/FerretDB/wire)
testdata (`crates/mongowire/tests/data/*.hex`, hexdump format): real
`isMaster`/`buildInfo` handshakes (both OP_QUERY and OP_MSG), an `insert`
with a kind-1 document sequence, and a fuzzed malformed sample. Every valid
frame re-encodes **byte-exactly**; the malformed one errors cleanly.

Coverage: per-byte truncation loops (no parse path panics), RFC 5802/7677
official SCRAM vectors, proptest document round-trips, end-to-end socket
integration (OP_MSG/OP_QUERY/checksums/compression/moreToCome), and two
cargo-fuzz targets (`fuzz/` — see below).

## Fuzzing

```bash
cd fuzz && cargo +nightly fuzz run fuzz_msg -- -max_total_time=300
cargo +nightly fuzz run fuzz_document -- -max_total_time=300
```

Both targets are seeded with the committed recorded-traffic corpus and have
each driven real fixes: strict UTF-8 for section identifiers and
`fullCollectionName` (a lossy conversion drifted the byte accounting), and
NUL-in-string-values encode/decode symmetry.

## References

- `reference/pgwire` — structural template (messages/api/tokio layering)
- `reference/wire` (FerretDB, Go) — source of the protocol and wirebson
  design, and of the golden data
- `reference/mongo-rust-driver` — official Rust driver (compression /
  SCRAM / message model cross-checks)
