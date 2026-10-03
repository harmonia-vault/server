# 原恢复事务三态合同：有限验证

下方原结果表与初轮失败属于 v1 冻结候选；v2 增量结果另列，原日志和冻结材料保持不变。

全部使用合成账号、恢复种子、Ed/X钥和临时SQLite/DO；未运行线上服务、VM、宿主环境扫描、手机客户端。测试基础server `2f15b94ce5023357320b415e5f3a4aebb29c2856`、protocol `1c0b24180e7fabfcd9109dbabb2afbf6195f22d8`，另加本候选精确diff。尚未公开的候选不能称公开快照已通过。

| 检查 | 真实结果 | wall秒 | stdout SHA256 |
| --- | --- | --- | --- |
| TypeScript noEmit | PASS / exit0 | 1.367 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Node生产构建 | PASS / exit0 | 0.822 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 固定六组：NodeTCP 6 + workerd 6；协议协商2 | PASS / exit0 | 8.962 | `e2db40537ef5114101acd655eb7adee31b27e1cbdc9bb9b6a430c5b466ebbace` |
| 旧DAG HTTP/连续恢复/rotation受影响回归35 | PASS / exit0 | 16.672 | `44d9282c0ceb593cebad52fcb26db5a569318ba4033068e94f69dfc1fff02e35` |
| 新规范字节/Ed签名向量4 | PASS / exit0 | 0.138 | `a726fe270fbaafacb6da730cfcf09d9514f160847ddbdcb2e94f7f1b5a083160` |

合计服务器49测试与protocol4测试PASS，0fail/skip。没有运行完整服务器全矩阵、Go/nativeSDK或移动UI，不拿这些结果代替冷取消产品验收。

## 六组实际范围

1. 原transition接受优先；旧close session拒绝，fresh当前新码受限session查询原hash/sequence，重复/错hash/错旧session验证。
2. 正确双签原包先成熟DAG验证；实际SQLite UPDATE trigger失败整事务回滚；成功回应合成丢弃后同ID查询closed；正确原包迟到拒绝，权限/恢复双钥/全部envelopes/history不变。
3. 无challenge先close与丢challenge回应后精确basis关闭；v1/v2、recovered、rotation同ID晚到拒绝；其他legacy ID兼容；原session/hash不匹配不误关。
4. 两实际HTTP请求并发create/close与submit/close；Node两个TCP server和两个SQLite连接，workerd同account DO；只有一个终态和一次seq；submit赢时鉴权失败后fresh会话查询accepted。固定顺序1/2组另分别证明两种赢家。
5. 原closed跨后续恢复generation及实际SQLite/DO重启仍可查询；accepted保留challenge排除预算，255/256边界；256墓碑+1旧预留只能预算中性转换，不能新分配；接近1MB空间关闭整体回滚。
6. 当前受限proof、密码login、错gen/签名/未来基点、JSON重复字段/非法UTF8/额外字段/query/超过8192/major1；all-Admin精确历史双钥、recovered-v2错X先拒后正确关闭；未知version/坏hash/挑战碰撞/真正accepted碰撞经共同Store读拒绝。每个新请求成功或错误都检查major回显。

Node并发不是跨进程/跨主机压力证明；workerd是实际本地运行时及SQLite DO，不是线上Cloudflare。持久失败注入发生在SQL UPDATE，不是COMMIT/fsync硬件崩溃。丢回应为合成不使用首次返回结果，未冒称TCP真实断线。原envelope使用80字节编码占位，本批新测试没有HPKE/PAKE。

## 复现命令

固定Node24.16.0，依赖按现server pnpm-lock安装。不要在脱离可信源的用户目录以root执行；测试不需root。仅在隔离源码目录运行：

```sh
mise exec node@24.16.0 -- node node_modules/typescript/bin/tsc --noEmit --project tsconfig.json
mise exec node@24.16.0 -- node node_modules/typescript/bin/tsc --project tsconfig.build.json
mise exec node@24.16.0 -- node --import tsx --test --test-concurrency=1 test/recovery-operation-resolution.test.ts test/protocol-info.test.ts
mise exec node@24.16.0 -- node --import tsx --test --test-concurrency=1 test/recovery-dag-http.test.ts test/recovery-authority.test.ts test/lifecycle.test.ts
```

protocol目录：

```sh
mise exec node@24.16.0 -- node --test tests/recovery-operation-resolution.test.ts
```

## 保留的初轮失败

- 首次类型检查工具路径通过pnpm11触发依赖安装且非TTY拒绝purge；退出1，未替换依赖。改用固定Node和现有tsc，无重新安装。
- 次轮类型检查发现收据profile类型扩宽为string；三轮发现测试Uint8Array类型及union未缩窄；保留两次退出2，修类型而非放宽DTO。
- 首个实际14项：3PASS/11FAIL，wall5.478s，stdout SHA `8d6e5ca131e90ddf184e89f0db12137728842608b3217bf2bcc31bfaf6c9676d`。10项新挑战概括误调用拒空Admin授权helper；另1项DO预读Fault跨RPC丢类型使409变500。只修新空集摘要及DO固定错误适配。
- 中间14/14通过后增加每个回应major断言，实际13PASS/1FAIL，wall8.360s，stdout SHA `4c4a7f1400c80dd2e35454eaa4a7e8aee4fcb4abf0d984562311e314fc4dcf5c`。Node外层读取超限body的413漏协议major，窄加固定错误header；最终14/14通过。
- 私有向量生成首次tsx CLI受沙箱IPC EPERM，未产生向量；换Node --import tsx正常生成。无权限/密码机制放宽。

原FAIL日志和最终PASS日志在私有交付evidence完整保留，发布此说明只引用hash/分类，不公开运行时tokens、私有路径或原环境。

## 尚未实现/验证

客户端原target从authenticated whole-state生成、终止intent持久化、严格三态解析、锁外retirement/CAS保存失败恢复、B3 UI冷取消/新ID重开均未接通。服务器accepted/closed收据不能自行清本地journal或设Applied/trusted。

旧writer混跑/回滚不能安全保留终态保障；先统一升级并禁止旧writer，见实现说明。墓碑预算或整体1MB空间满时明确pending，不能删安全墓碑解限。

## v2：原 closed 收据与后续 legacy 断链

父任务独立 Node TCP/workerd 两项在 v1 上实际失败，wall1.574s：原 intent 已 closed 后，不同 ID 的合法 legacy rotation 成功，fresh 当前第二代恢复码可正常取得受限会话，但原 target 查询误返 `403 recovery_chain_invalid`。原墓碑未改变。独立失败 stdout SHA256 `bd311c03bd822345c87a745c0ad2d27f69b22ad0b9a0653907779c391e5864fc` 保留。

v2 仅调整已有 closed 分支顺序：签名、当前受限会话、当前恢复代际、账号代际和原 sessionHash 区分先验证；共同 Store validator 已核原 closed 结构/序号/targetHash。其后精确比较 targetHash 和固定字段数组，返回原收据。该只读分支不再依赖后续 current DAG 无 gap；新 close 和 accepted 仍执行完整 DAG/历史 basis 校验。没有放宽任何晚到 challenge/submit guard，也没有改变签名域、请求/响应字段、字节向量或 quota。

| v2 检查 | 真实结果 | wall秒 | stdout SHA256 |
| --- | --- | --- | --- |
| TypeScript noEmit | PASS / exit0 | 1.310 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Node生产构建 | PASS / exit0 | 0.817 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 新 legacy-gap Node TCP/workerd 2 | PASS / exit0 | 1.476 | `c68c80d03a718bc138eba3c1863b5e183f2c4c2a4e00dd5e37bda206eda48784` |
| 原固定六组12 + 协议协商2 | PASS / exit0 | 7.340 | `53cbc96740733c3ae339ded7d7d616bbcdfd81ec95e7df72e4d44e6f3c6c8a6b` |
| 旧受影响回归35 | PASS / exit0 | 15.321 | `2ab8b7fa8ea501cb18713fb478f1df99e8378986ae27d4ecda08eb1dd6e1af4c` |

v2 新增负例使用有效签名：普通 login 不是受限恢复会话；已删除的旧会话拒绝；错误账号代际拒绝；更改 declaredIntentHash、接收公钥、历史 sequence 均冲突；当前 DAG 有 gap 时新 ID 不得 close。原 closed 重复查询或重复 resolve-or-close 都返回原 sequence，不追加墓碑，不推进账号序号。

新增测试首次实际 2FAIL/0PASS，wall1.384s，stdout SHA256 `09587fe60756afc1e2eda20b33518b01e0245ae235c03b63b69ac7427cafe6a0`：测试错误地期望旧会话 `403 recovery_session_stale`，而合法 legacy rotation 会删除旧 recoverySessions，实际 `401 unauthorized`。按现 lifecycle 语义修正为精确 401，保留原失败，没有修改产品鉴权或放宽为任意失败。

该增量合计51个服务器测试通过，0fail/skip；父任务原独立两例的原样复跑另在私有证据列出，不重复计入51。protocol 签名域与测试/向量字节未变，沿用 v1 4/4 PASS，v2 未重新运行 protocol。完整服务器矩阵、Core/B3b/native/UI仍未运行。

新增复现（server目录）：

```sh
mise exec node@24.16.0 -- node --import tsx --test --test-concurrency=1 test/recovery-operation-legacy-gap.test.ts
```
