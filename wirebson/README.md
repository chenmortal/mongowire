# wirebson

BSON documents for the MongoDB wire protocol, modeled after FerretDB's
`wirebson`. Part of the
[mongowire](https://github.com/chenmortal/mongowire) workspace.

面向 MongoDB wire 协议的 BSON 文档层，仿照 FerretDB 的 `wirebson` 设计。
[mongowire](https://github.com/chenmortal/mongowire) workspace 的一员。

[crates.io](https://crates.io/crates/wirebson) ·
[docs.rs](https://docs.rs/wirebson) ·
[Repository](https://github.com/chenmortal/mongowire) ·
License: Apache-2.0 · `#![forbid(unsafe_code)]`

## English

### Two shapes of every composite value

* **Raw** ([`RawDocument`] / [`RawArray`]) — the bytes themselves, held in a
  `bytes::Bytes`, so slicing off a decoded message is zero-copy.
* **Eager** ([`Document`] / [`Array`]) — parsed fields, mutable.

Decoding comes in two depths, mirroring the Go reference:

```rust
use wirebson::{Document, RawDocument};

// let raw: RawDocument = /* zero-copy slice of a decoded wire m

let doc = raw.shallow()?; // nested composites stay raw — cheap
let all = raw.deep()?;    // fully recursive decode
```

### Highlights

* All 20 BSON element types are supported and round-trippable —
  deprecated ones (DBPointer, Symbol, …) that the Go reference rejects.
* `MAX_NESTING_DEPTH` (20) guards decoding and log formatting.
* Log-friendly formatting for documents and values.

### Features

| feature | enables |
|---|---|
| `serde_json` | `Bson` ↔ `serde_json::Value` conversions |
| `uuid` | `Bson` ↔ `Uuid` conversions |
| `decimal128-convert` | `Bson` ↔ `rust-dec` Decimal128 conversions |

BSON scalar types and tag-level parsing live one layer down in
[`mongo_common`](https://crates.io/crates/mongo_common).

[`RawDocument`]: https://docs.rs/wirebson/latest/wirebson/struct
[`RawArray`]: https://docs.rs/wirebson/latest/wirebson/struct.RawArray.html
[`Document`]: https://docs.rs/wirebson/latest/wirebson/struct.Do
[`Array`]: https://docs.rs/wirebson/latest/wirebson/struct.Array.html

## 简体中文

### 每个复合值有两种形态

* **Raw**（[`RawDocument`] / [`RawArray`]）—— 就是字节本身，保存在
  `bytes::Bytes` 中，从解码后的消息上切片是零拷贝的。
* **Eager**（[`Document`] / [`Array`]）—— 已解析字段，可变。

解码提供两种深度，与 Go 参考实现对齐：

```rust
use wirebson::{Document, RawDocument};

// let raw: RawDocument = /* 从解码后的 wire 消息零拷贝切片 */;

let doc = raw.shallow()?; // 嵌套文档/数组保持 raw —— 低成本
let all = raw.deep()?;    // 完整递归解码
```

### 亮点

* 支持全部 20 种 BSON 元素类型且可无损往返 —— 包括 Go 参考实现拒
  已废弃类型（DBPointer、Symbol 等）。
* `MAX_NESTING_DEPTH`（20）守护解码与日志格式化。
* 文档与值提供适合日志输出的格式化。

### 特性

| 特性 | 启用内容 |
|---|---|
| `serde_json` | `Bson` ↔ `serde_json::Value` 转换 |
| `uuid` | `Bson` ↔ `Uuid` 转换 |
| `decimal128-convert` | `Bson` ↔ `rust-dec` Decimal128 转换 |

BSON 标量类型与标签级解析在下一层
[`mongo_common`](https://crates.io/crates/mongo_common) 中。
