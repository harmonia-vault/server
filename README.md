# Harmonia / 和弦 — server

多设备环境变量同步的 TypeScript 服务端，采用 MIT 许可证。当前是实验性实现，尚不具备生产使用条件。

设计目标与里程碑见 [workspace](https://github.com/harmonia-vault/workspace)。本仓库只保存源码、文档和合成测试数据。

## 当前可测试能力

- Node SQLite 与每账号 SQLite Durable Object 调用相同业务逻辑；D1 只做邮箱到账号的目录。
- 每次请求检查账号代际、登录会话、设备持钥会话、设备状态及环境授权；支持 RO / RW / Admin、期限和管理签名降权/撤销。
- 验证协议 v1 设备写入签名与管理授权签名；服务端保存密文，不解密变量。历史事件附接受时的签名授权快照。
- 事务内按服务器接受顺序分配序号；同设备、同幂等 ID 和同内容重试返回原序号，修改内容则拒绝。SQLite 重启后继续拉取补漏。
- 客户端 SHA256 密码等价凭据在服务端用独立随机盐和 Argon2id（64 MiB、3 次、并行度 1）验证。Node 使用 hash-wasm，Workers 使用成熟的 noble/hashes 实现，相同参数互操作。
- 已登记设备可用独立开机挑战取得设备绑定会话，无需密码登录；单次 nonce、两公钥、当前授权和账号代际在服务端重新核验。
- 恢复码持钥取得受限会话；完整封套、新两公钥及新码重签的固定可信根一起原子轮换，支持幂等状态查询。协议与限制见 [恢复协议](https://github.com/harmonia-vault/protocol/blob/main/docs/RECOVERY.md) 和 [开机会话](https://github.com/harmonia-vault/protocol/blob/main/docs/BOOT-SESSION.md)。
- 邮箱验证与邮件证明的破坏性重置采用同一账号事务；旧权限/会话和 vault 原子失效，支持结果查询与幂等重试。Node 使用严格 TLS SMTP，Workers 使用官方 EmailService 绑定，测试不发送真实邮件。配置与接口见 [邮箱说明](docs/EMAIL.md)。
- WebSocket 只发送持久序号提示，使用请求头单次票据与逐次当前授权检查；断线仍按原拉取序号补漏。本人写入收据可核验丢失响应后的接受状态。接口见 [通知与结果查询](docs/NOTIFICATIONS.md)。
- 管理签名支持环境创建、密文名称修改、删除、完整密钥轮换和全局设备撤销；写入后经相同持久序号拉取下发。接口与容量边界见 [环境生命周期](docs/ENVIRONMENTS.md)。

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

注册默认关闭，要求验证邮箱默认开启。两个开关为 `HARMONIA_ALLOW_REGISTRATION` 与 `HARMONIA_REQUIRE_EMAIL_VERIFICATION`。在 Node 上显式允许注册且关闭邮箱验证时可以建立空账号；它没有可信设备，仍无法读写 vault。邮箱验证开启但未配置发送器时注册失败关闭；已配置发送器时建立未验证空账号，完成邮件证明后才能登录。Workers 以 D1 仅目录预留、每账号 DO 权威状态实现相同注册机制。关闭验证不会把邮箱标记为已验证，后续开启验证会拒绝未验证账号登录。

## API 与设备持钥证明

1. `POST /v1/login`，JSON 为 `{email, credential}`；`credential` 是客户端固定 SHA256 的小写十六进制。返回登录 token、账号 ID 和代际。登录不建立设备信任。
2. 用登录 token 请求 `POST /v1/accounts/{id}/device-challenges`，JSON `{}`。请求头带 `Authorization: Bearer ...`、`X-Harmonia-Device-Id`、`X-Harmonia-Account-Generation`。
3. 设备必须用本地账号、代际、设备 ID、登录 token 的 SHA256、挑战 ID、nonce 和期限重建固定用途数组，精确比对返回 `signingPayload` 后再对其 UTF-8 `JSON.stringify` 签 Ed25519，避免盲签不可信用途，提交 `POST .../device-sessions`，JSON `{challengeId,signature}`。挑战绑定账号、代际、设备、公钥登记状态、登录会话和用途，120 秒内单次使用；成功后发行新的设备绑定 token。
4. 使用设备绑定 token 执行 `GET .../pull?after=0`、`POST .../mutations` 或 `POST .../grants`。所有请求重新检查当前授权。

写入请求为 `{mutation,signature}`，授权请求为 `{grant,signature}`，内部字段与签名编码见 protocol 仓库。返回 `{sequence,replayed}`。成功后必须通过拉取结果更新客户端状态。

暂停模式可请求 `GET .../pull?after=<authorizationSequence>&scope=authorizations`：返回 `scope:"authorizations"`、当前 `grants`、签名 `environmentEvents`，普通 `events` 为空。授权检查点独立于数据检查点，暂停刷新不应用变量或推进数据序号；恢复时如授权检查点领先，须全量补拉。环境删除墓碑按接受时主体列表下发，即使当前 grant 已清除也能停止旧来源；其他历史环境事件须重新检查当前可读权限。轮换事件保留完整签名 manifest，可能包含密文，仅用于校验和生命周期处理，不能在暂停时应用其中变量。

拉取返回 `{accountId,accountGeneration,sequence,grants,events,environmentEvents}`，每个事件包含 `{sequence,mutation,authorization}`。只下发当前可读环境、当前密钥版本的密文；当前授权快照也包含已过期/撤销授权，便于客户端清除缓存。账号序号不保证对单个设备连续：被过滤的其他环境和授权更新仍占序号。首次获授权、重新获授权或密钥版本变化时，客户端必须 `after=0` 全量重建；不能沿用此前全局 checkpoint。WebSocket 只提示当前持久序号；断线后从本地检查点补拉，定期拉取仍负责漏通知补偿。

## 集成测试入口

```sh
mise exec -- pnpm exec tsx tests/synthetic-server.ts
```

可加 `--capture-email` 捕获仅 `.invalid` 合成邮箱邮件，测试专用 `GET /test/emails` 返回捕获内容；加 `--empty-vault` 保留合成登录账号并清空设备、环境、恢复与可信根，以验收首次初始化。这些开关只存在于测试入口，不进生产构建。

可加 `--recovery-envelopes /tmp/synthetic-envelopes.json` 提供合成 HPKE 封套数组 `[{environmentId,envelope}]`，加 `--with-trust-root` 建立合成恢复码签可信根。输出只含合成测试元数据。

该入口仅监听本机随机端口、建立临时 SQLite，并输出一行 JSON 合成账号和密钥元数据。它不进入生产构建，没有公开 bootstrap 路由；退出时清理数据库。所有密钥为固定合成测试值，只用于跨语言 HTTP / HPKE / AEAD 验收。

## 持久化和容器边界

`Dockerfile` 构建 Node 24 单实例服务，以非 root 用户运行，`/data` 为 SQLite 持久卷，不依赖 Cloudflare。当前服务只监听容器内 loopback，外部端口映射本身不能访问；HTTPS 代理必须共享服务网络命名空间。容器构建/运行通过与否见 [测试记录](docs/TESTING.md)。本轮没有发布镜像或部署服务。

Workers 配置使用每账号 `ACCOUNTS` DO 与 `DIRECTORY` D1。数据库 ID 是占位值；不要直接部署。自动日志/trace 观测默认关闭，启用前必须验证认证头与正文脱敏。线上资源和 Argon2id 配额尚未验证；本地 workerd 结果不能代替上线验收，也不能据此降低密码参数。

## 未完成的安全与产品门槛

- 首台可信根初始化与 SPAKE2 配对审批业务已接通，验证双设备签名、双向确认和当前管理权限。[多管理 v2](docs/ENROLLMENT-V2.md) 支持初始环境内的历史双签来源与当前精确 Admin 重查；新环境/跨 keyVersion 的签名生命周期来源扩展仍安全拒绝。真实手机系统密钥保护、强认证 UI、环境建立/轮换的完整用户流程仍待接通。存储强制恢复封套版本完整性。
- 邮箱验证、破坏性重置、受限恢复与原子轮换内核已实现；真实邮件投递、完整恢复码重输 UI、手机强认证、客户端完整恢复历史授权链验证与用户流程仍待验收。
- 管理签名和写入签名已验证，完整历史授权链的客户端信任证明、历史接受时间证据及生产限流仍需完善。
- 单账号文档限制 1 MB，历史与幂等收据计入；超过容量拒绝写入并回滚。环境变更请求体上限 1 MB，v2 配对批准请求上限 262,144 字节，其他接口上限 100 kB。较大的完整轮换仍可能超过账号总容量，尚未做面向大历史的分表、分页/压缩或快照检查点。
- 暂未定义独立账号级管理授权，因此当前拒绝删除最后一个环境；可先创建新环境再删除旧环境。不会从密码登录或根公钥字段隐式提升管理权限。
- 服务端开机持钥续期入口已实现；三平台无人登录启动及系统密钥保护仍需完整验收。当前持钥会话最长一小时。WebSocket 通知已通过本地回归，线上休眠/容量与 TCP 关闭仍待验收；Docker 仅单实例，不支持多副本并发数据库访问。SMTP 隔离 TLS 回归已通过，真实外部邮件服务器与投递未验收。

真实检查结果见 [测试记录](docs/TESTING.md)，明确区分通过、失败与未运行。Docker 隔离测试可在本机镜像构建后运行 `python3 tests/docker-smoke.py`；仅创建随机测试容器和卷，结束后清理。
