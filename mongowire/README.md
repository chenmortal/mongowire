# mongowire

MongoDB wire protocol for servers, structured after
[pgwire](https://github.com/sunng87/pgwire) (the Rust PostgreSQL wire protocol
library); protocol details follow the
[official specification](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/).
Part of the [mongowire](https://github.com/chenmortal/mongowire)

面向服务端的 MongoDB wire 协议实现，结构仿照
[pgwire](https://github.com/sunng87/pgwire)（Rust 的 PostgreSQL wire 协议库）；
协议细节严格遵循
[官方规范](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/)。
[mongowire](https://github.com/chenmortal/mongowire) workspace

[crates.io](https://crates.io/crates/mongowire) ·
[docs.rs](https://docs.rs/mongowire) ·
[Repository](https://github.com/chenmortal/mongowire) ·
License: Apache-2.0 · `#![forbid(unsafe_code)]`

## English

### Layering

Feature-gated like pgwire — with no features you get only the pure, sync
protocol message layer (no tokio, no async runtime):

| layer | default | contents |
|---|---|---|
| `messages` | yes | `Message` / `MessageBody`: OP_MSG / OP_QUERwith a sync, pure-bytes encode/decode core |
| `framing` | yes | 16-byte header, length prefix, CRC-32C (verify on read, compute on write) on `BytesMut` |
| `compression` | noop | OP_COMPRESSED; `zlib` / `snappy` / `zst umbrella |
| `codec` | `server` | `tokio_util::codec` adapter |
| `api` | `server` | `CommandHandler` trait, built-in `hello`/`pslContinue` SCRAM bridge |

```rust
use mongowire::{Message, MessageBody, OpMsg, OpQuery, OpReply, OpCompressed,
                Sections, MsgFlags, DocumentSequence, Error, Pro
```

### Spec compliance (strict)

* Little-endian throughout; `MsgHeader` is 16 bytes (`messageLength` includes itself).
* OP_MSG `flagBits`: unknown bits 0–15 **MUST error**, bits 16–3
* With `checksumPresent`, a CRC-32C covers header + body before the trailing
  4 bytes — verified on read, computed on write (MongoDB 4.2+ be
  non-TLS connections).
* Sections: exactly one kind-0 body (first); kind-1 identifiers
  must not duplicate a top-level body field; kind-2 rejected.
* `moreToCome` requests are never replied to; replies may only s
  request set `exhaustAllowed`.
* `OP_QUERY` survives only for the legacy handshake (`hello`/`is

### Features

| feature | enables |
|---|---|
| `server` | tokio + `tokio_util::codec` + `api` layers (embedda
| `zlib` / `snappy` / `zstd` | OP_COMPRESSED compressors |
| `compression` | umbrella for all compressors |

Built on [`wirebson`](https://crates.io/crates/wirebson) and
[`mongo_common`](https://crates.io/crates/mongo_common).

## 简体中文

### 分层

与 pgwire 一样按特性裁剪 —— 不启用任何特性时只有纯同步的协议消息层
（无 tokio、无异步运行时）：

| 层 | 默认 | 内容 |
|---|---|---|
| `messages` | 是 | `Message` / `MessageBody`：OP_MSG / OP_QUERY同步纯字节编解码核心 |
| `framing` | 是 | 16 字节消息头、长度前缀、CRC-32C（读取时校验、写入时计算），基于 `BytesMut` |
| `compression` | noop | OP_COMPRESSED；按特性启用 `zlib` / `sna为总开关 |
| `codec` | `server` | `tokio_util::codec` 适配器 |
| `api` | `server` | `CommandHandler` trait、内建 `hello`/`ping`nue` SCRAM 桥接 |

```rust
use mongowire::{Message, MessageBody, OpMsg, OpQuery, OpReply, OpCompressed,
                Sections, MsgFlags, DocumentSequence, Error, Pro
```

### 规范符合性（严格实现）

* 全程小端；`MsgHeader` 为 16 字节（`messageLength` 包含自身）。
* OP_MSG `flagBits`：未知位 0–15 **必须报错**，位 16–31 必须忽略
* 置位 `checksumPresent` 时，CRC-32C 覆盖消息头 + 尾部 4 字节之前的消息体 ——
  读取时校验、写入时计算（MongoDB 4.2+ 在非 TLS 连接上的行为）。
* Sections：有且仅有一个 kind-0 body（位于首位）；kind-1 标识符非空且不得与
  body 顶层字段重名；kind-2 拒绝。
* `moreToCome` 请求永不应答；仅当请求置位 `exhaustAllowed` 时才可流式应答。
* `OP_QUERY` 仅保留用于旧版握手（`hello`/`isMaster`）。

### 特性

| 特性 | 启用内容 |
|---|---|
| `server` | tokio + `tokio_util::codec` + `api` 层（可嵌入式服
| `zlib` / `snappy` / `zstd` | OP_COMPRESSED 压缩器 |
| `compression` | 全部压缩器的总开关 |

构建于 [`wirebson`](https://crates.io/crates/wirebson) 与
[`mongo_common`](https://crates.io/crates/mongo_common) 之上。
