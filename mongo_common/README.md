# mongo_common

Base primitives for the MongoDB wire protocol — the `mysql_common` of this
stack. The lowest layer of the [mongowire](https://github.com/chenmortal/mongowire)
workspace, with no dependencies on other workspace crates; usable directly by
any MongoDB client or server implementation.

MongoDB wire 协议的基础原语层 —— 本技术栈的 `mysql_common`。
[mongowire](https://github.com/chenmortal/mongowire) workspace 的最底层，
不依赖 workspace 内任何其他 crate，任何 MongoDB 客户端/服务端实现都可直接使用。

[crates.io](https://crates.io/crates/mongo_common) ·
[docs.rs](https://docs.rs/mongo_common) ·
[Repository](https://github.com/chenmortal/mongowire) ·
License: Apache-2.0 · `#![forbid(unsafe_code)]`

## English

### Modules

| module | contents |
|---|---|
| `consts` | protocol constants: opcodes, limits, flag bits, compressor IDs |
| `io` | protocol IO helper traits: LE integers, cstrings, length prefixes |
| `crc32c` | CRC-32C (Castagnoli, RFC 4960 appendix B) checksum |
| `bson` | BSON scalar types, tag-level scalar parsing, Rust type conversions (i8–i128, f64, bool, String, time, Uuid, Decimal128) |
| `auth` | SCRAM-SHA-1 / SCRAM-SHA-256 state machines (both sides) + PLAIN |

### Features

| feature | enables |
|---|---|
| `uuid` | `Uuid` value conversions |
| `decimal128-convert` | `rust-dec` Decimal128 value conversions |

Document/array structure and full BSON encode/decode live in
[`wirebson`](https://crates.io/crates/wirebson); wire protocol m
in [`mongowire`](https://crates.io/crates/mongowire).

## 简体中文

### 模块

| 模块 | 内容 |
|---|---|
| `consts` | 协议常量：操作码、限制值、标志位、压缩器 ID |
| `io` | 协议 IO 辅助 trait：小端整数、cstring、长度前缀 |
| `crc32c` | CRC-32C（Castagnoli，RFC 4960 附录 B）校验和 |
| `bson` | BSON 标量类型、标签级标量解析、Rust 类型转换（i8–i128id、Decimal128） |
| `auth` | SCRAM-SHA-1 / SCRAM-SHA-256 状态机（客户端与服务端两侧）+ PLAIN |

### 特性

| 特性 | 启用内容 |
|---|---|
| `uuid` | `Uuid` 值转换 |
| `decimal128-convert` | `rust-dec` Decimal128 值转换 |

文档/数组结构与完整 BSON 编解码见
[`wirebson`](https://crates.io/crates/wirebson)，wire 协议消息见
[`mongowire`](https://crates.io/crates/mongowire)。
