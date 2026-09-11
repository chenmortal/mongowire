# mongowire

Rust 实现的 MongoDB Wire Protocol 解析库:服务端协议解析 + 可嵌入 tokio server,结构对标 [pgwire](https://github.com/sunng87/pgwire)(Rust 版 PostgreSQL wire 协议库),协议细节以[官方规范](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/)为准。

## Crate 结构

```
mongo_common   基础原语(定位类似 Rust MySQL 生态的 mysql_common)
               ├── consts   协议常量(opcode/上限/flag 位/compressorId)
               ├── io       协议 IO 辅助 traits(LE 整数/cstring/长度前缀)
               ├── crc32c   CRC-32C(Castagnoli)校验和
               ├── bson     BSON 标量类型 + tag 级解析 + Rust 类型互转
               │            (i8~i128/f64/bool/String/时间/Uuid/Decimal128,按 feature)
               └── auth     SCRAM-SHA-1 / SCRAM-SHA-256 双侧状态机 + PLAIN
wirebson       BSON 结构层(对标 FerretDB wirebson)
               RawDocument/RawArray 零拷贝(Bytes)+ Document/Array 完整形态,
               浅/深解码,全部 20 种 BSON 类型,日志友好格式化
mongowire      协议层(默认无运行时依赖)
               ├── messages   OP_MSG / OP_QUERY / OP_REPLY / OP_COMPRESSED
               ├── framing    16 字节头 + 长度前缀 + CRC-32C(读校验/写计算)
               ├── compression  noop 常驻;zlib/snappy/zstd 按 feature
               ├── codec      (server) tokio_util::codec 适配
               └── api        (server) CommandHandler trait、内置 hello/ping
                              应答、saslStart/saslContinue SCRAM 桥接
mongowire-server  示例 server(hello/ping/buildInfo/find demo)
```

依赖链:`mongo_common` → `wirebson` → `mongowire` → 示例。

## Feature 矩阵

| crate | feature | 说明 |
|---|---|---|
| 全部 | (默认) | 纯同步协议/BSON 层,无 tokio |
| mongowire | `server` | tokio + tokio-util codec + api 层(可嵌入 server) |
| mongowire | `zlib` / `snappy` / `zstd` | OP_COMPRESSED 各压缩算法;`compression` 伞 feature |
| mongo_common | `uuid` / `decimal128-convert` | Uuid / rust-dec Decimal128 值转换 |
| wirebson | `serde_json` / `uuid` / `decimal128-convert` | Bson ↔ 对应类型转换 |

## 规范要点(实现严格遵循)

- 小端字节序;`MsgHeader` 16 字节(messageLength 含自身)。
- `OP_MSG` flagBits:**低 16 位未知位必须报错,高 16 位必须忽略**;`checksumPresent` 时 CRC-32C(RFC 4960 App. B)覆盖 header+body 尾部 4 字节前——本项目**读时校验、写时计算**(MongoDB 4.2+ 非 TLS 行为;两个参考实现各只做了一半)。
- Sections:恰一个 kind-0 body(且在首位);kind-1 文档序列 identifier 非空且不得与 body 顶层字段重名;kind-2(内部用途)拒绝。
- `moreToCome` 请求不回包;回复仅在请求带 `exhaustAllowed` 时可流式。
- `OP_QUERY` 仅保留给旧版握手(`hello`/`isMaster`,pre-4.4 驱动在 `admin.$cmd` 发起),以 `OP_REPLY` 应答。
- 限制:`MAX_MSG_LEN = 48_000_000`,`MAX_BSON_LEN = 16_777_216`。

## 快速开始

```bash
cargo run -p mongowire-server -- --bind 127.0.0.1:27017
```

嵌入自己的服务:实现 `CommandHandler`,组合内置应答:

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
            // ... 你的命令逻辑;Err(...) 会转成 {ok: 0.0, errmsg, code, codeName} 回包
            _ => Err(Error::command(59, "CommandNotFound", format!("no such command: {}", cmd.name))),
        }
    }
}
```

## 测试与验证

```bash
cargo test --workspace --all-features   # 全量:230+ 测试
cargo test -p mongowire --test golden   # 黄金测试:真实 MongoDB 流量 dump 字节级往返
```

黄金数据来自 [FerretDB/wire](https://github.com/FerretDB/wire) 的 testdata(`crates/mongowire/tests/data/*.hex`,hexdump 格式):真实 `isMaster`/`buildInfo` 握手(OP_QUERY 与 OP_MSG 两种)、带 kind-1 文档序列的 `insert`、fuzz 恶意样本。所有合法帧解析后重编码**字节级一致**;模糊样本干净报错。

测试覆盖:逐字节截断(所有解析路径不 panic)、SCRAM RFC 5802/7677 官方向量、proptest 随机文档往返、端到端 socket 集成(OP_MSG/OP_QUERY/校验和/压缩/moreToCome)。

## 参考材料

- `reference/pgwire` — 结构模板(messages/api/tokio 分层)
- `reference/wire`(FerretDB,Go)— 协议与 wirebson 设计来源,黄金数据来源
- `reference/mongo-rust-driver` — 官方 Rust 驱动(压缩/SCRAM/消息模型对照)
