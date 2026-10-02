# Harmonia / 和弦 — server

多设备环境变量同步的 TypeScript 服务端，采用 MIT 许可证。当前是实验性实现，尚不具备生产使用条件。

设计目标与里程碑见 [workspace](https://github.com/harmonia-vault/workspace)。本仓库只保存源码、文档和合成测试数据。

## 当前可测试能力

- Node SQLite 与每账号 SQLite Durable Object 调用相同业务逻辑；D1 只做邮箱到账号的目录。
- 每次请求检查账号代际、登录会话、设备持钥会话、设备状态及环境授权；支持 RO / RW / Admin、期限和管理签名降权/撤销。
- 验证协议 v1 设备写入签名与管理授权签名；服务端保存密文，不解密变量。历史事件附接受时的签名授权快照。
- 事务内按服务器接受顺序分配序号；同设备、同幂等 ID 和同内容重试返回原序号，修改内容则拒绝。SQLite 重启后继续拉取补漏。
- 客户端 SHA256 密码等价凭据在服务端用独立随机盐和 Argon2id（64 MiB、3 次、并行度 1）验证。Node 使用 hash-wasm，Workers 使用成熟的 noble/hashes 实现，相同参数互操作。
- Nodemailer 适配只接受 TLS 465 或强制 STARTTLS 587，禁用 debug/logger；测试不发送真实邮件。

## 本机开发

```sh
mise install
mise exec -- pnpm install --frozen-lockfile
mise run check
```

依赖构建脚本只批准 esbuild 和 workerd，并记录在 pnpm-workspace.yaml。

Node 调试使用隔离数据库目录，不导入真实环境变量或凭据：

```sh
HARMONIA_DATABASE=/tmp/harmonia-local-test/harmonia.sqlite mise exec -- pnpm start
```

默认仅监听 `127.0.0.1:8787`；远程明文监听被拒绝。供其他设备访问时必须由本机或共享网络命名空间内的 TLS 代理提供 HTTPS。本轮没有配置或部署代理。`HARMONIA_PORT` 可更改本地端口；`HARMONIA_DATABASE` 指向单实例持久卷数据库。

注册默认关闭，要求验证邮箱默认开启。两个开关为 `HARMONIA_ALLOW_REGISTRATION` 与 `HARMONIA_REQUIRE_EMAIL_VERIFICATION`。在 Node 上显式允许注册且关闭邮箱验证时可以建立空账号；它没有可信设备，仍无法读写 vault。邮箱验证开启时注册失败关闭；Workers 注册尚未接通，无论如何不能得到可信设备。关闭验证不会把邮箱标记为已验证，后续开启验证会拒绝未验证账号登录。

## API 与设备持钥证明

1. `POST /v1/login`，JSON 为 `{email, credential}`；`credential` 是客户端固定 SHA256 的小写十六进制。返回登录 token、账号 ID 和代际。登录不建立设备信任。
2. 用登录 token 请求 `POST /v1/accounts/{id}/device-challenges`，JSON `{}`。请求头带 `Authorization: Bearer ...`、`X-Harmonia-Device-Id`、`X-Harmonia-Account-Generation`。
3. 设备必须用本地账号、代际、设备 ID、登录 token 的 SHA256、挑战 ID、nonce 和期限重建固定用途数组，精确比对返回 `signingPayload` 后再对其 UTF-8 `JSON.stringify` 签 Ed25519，避免盲签不可信用途，提交 `POST .../device-sessions`，JSON `{challengeId,signature}`。挑战绑定账号、代际、设备、公钥登记状态、登录会话和用途，120 秒内单次使用；成功后发行新的设备绑定 token。
4. 使用设备绑定 token 执行 `GET .../pull?after=0`、`POST .../mutations` 或 `POST .../grants`。所有请求重新检查当前授权。

写入请求为 `{mutation,signature}`，授权请求为 `{grant,signature}`，内部字段与签名编码见 protocol 仓库。返回 `{sequence,replayed}`。成功后必须通过拉取结果更新客户端状态。

拉取返回 `{accountId,accountGeneration,sequence,grants,events}`，每个事件包含 `{sequence,mutation,authorization}`。只下发当前可读环境、当前密钥版本的密文；当前授权快照也包含已过期/撤销授权，便于客户端清除缓存。账号序号不保证对单个设备连续：被过滤的其他环境和授权更新仍占序号。首次获授权、重新获授权或密钥版本变化时，客户端必须 `after=0` 全量重建；不能沿用此前全局 checkpoint。无 WebSocket，当前调用方主动拉取；通知层尚待实现。

## 集成测试入口

```sh
mise exec -- pnpm exec tsx tests/synthetic-server.ts
```

该入口仅监听本机随机端口、建立临时 SQLite，并输出一行 JSON 合成账号和密钥元数据。它不进入生产构建，没有公开 bootstrap 路由；退出时清理数据库。所有密钥为固定合成测试值，只用于跨语言 HTTP / HPKE / AEAD 验收。

## 持久化和容器边界

`Dockerfile` 构建 Node 24 单实例服务，以非 root 用户运行，`/data` 为 SQLite 持久卷，不依赖 Cloudflare。当前服务只监听容器内 loopback，外部端口映射本身不能访问；HTTPS 代理必须共享服务网络命名空间。容器构建/运行通过与否见 [测试记录](docs/TESTING.md)。本轮没有发布镜像或部署服务。

Workers 配置使用每账号 `ACCOUNTS` DO 与 `DIRECTORY` D1。数据库 ID 是占位值；不要直接部署。线上资源和 Argon2id 配额尚未验证；本地 workerd 结果不能代替上线验收，也不能据此降低密码参数。

## 未完成的安全与产品门槛

- SPAKE2 配对、首台可信手机建立、手机系统密钥保护、环境建立/轮换与恢复封套管理未接通，公开入口无法建立可信设备。
- 邮箱验证、邮件证明的破坏性重置、受限恢复会话、恢复码重输/挑战/原子切换尚未实现。不存在绕过邮箱证明或信任建立的公开测试入口。
- 管理签名和写入签名已验证，完整历史授权链的客户端信任证明、历史接受时间证据及生产限流仍需完善。
- 单账号文档限制 1 MB；超过容量拒绝写入并回滚。尚未做面向大历史的分表、分页/压缩或快照检查点。
- 后台设备会话自动续期尚未接通；当前持钥会话最长一小时。Workers 注册和 WebSocket 通知未实现；Docker 仅单实例，不支持多副本并发数据库访问。SMTP 真实服务器握手和邮件投递未验收。

真实检查结果见 [测试记录](docs/TESTING.md)，明确区分通过、失败与未运行。Docker 隔离测试可在本机镜像构建后运行 `python3 tests/docker-smoke.py`；仅创建随机测试容器和卷，结束后清理。
