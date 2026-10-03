# 重复恢复的平坦来源图内核

本切片完成独立编码、严格 JSON 解析和历史密码学核验；尚未接入新 HTTP、协议 major 协商、持久化接受或手机/CLI 第二次恢复用户流程。旧恢复、Proof2/Proof3 和证书 v1-v4 的入口与解析语义保持原样。当前可用的恢复设备管理见 [第1层说明](RECOVERED-MANAGEMENT.md)。

完整线合同见 [protocol/RECOVERY-DAG.md](https://github.com/harmonia-vault/protocol/blob/main/docs/RECOVERY-DAG.md)。该合同与本切片的密码学通过不代表服务器路由已经开放。

## 类型和固定字节

新能力为 `issuer-recovery-dag-v1`，完整图 profile 为 `harmonia/issuer-proof/v4`。来源明确分为原 Proof2 与独立 `harmonia/issuer-proof/v3-source/v1` 叶；叶不包含完整恢复记录、嵌套来源或其它图。平坦表的每项为 `{kind,record}`，kind 只能是 `transition-v1`、`recovered-v1`、`transition-v2` 或 `recovered-v2`。

- 原初始化锚完整保存 proposal、原 challenge proof 和原设备/恢复双签。原根两公钥、账号代际和精确原 genesis 集合固定；当前 root self-grant 或服务器目录不能替代它。
- 来源、叶和完整图分别按固定 4、12、6 项 UTF-8 JSON 编码。记录与依赖按 kind/referenceHash ASCII 顺序规范化；同引用重复或更换 kind 拒绝。
- 新恢复 transition 使用独立 v2 域和原 25 项顺序；新恢复设备使用独立 v2 域和原 18 项顺序。完整清单、封套、权限、来源与可信根摘要重新计算，不能只信行内 hash。
- 证书 v5 固定 16 项，绑定完整图 hash。验证必须提供受保护原根/初始化 pin，以及已确认的配对 context/transcript；同时检查审批者与候选签名、来源路径终点、逐环境 Admin、候选公钥用途和授权期限。这里没有运行 PAKE 传输，也没有建立新设备会话。

`src/recovery-dag-wire.ts` 提供独立新类型、规范编码和严格解析；`src/recovery-dag.ts` 验证平坦历史与候选闭包；`src/issuer-dag.ts` 验证证书 v5。成熟权限图部分由 `src/issuer-recovery.ts` 抽出的共享函数复用，不通过伪造证书、占位签名或降级 wrapper 调用旧解析器。

## 历史与当前权限边界

核验按已签 expectedSequence+1 的接受序号迭代，每个恢复记录处理一次。完整 head 前缀、恢复设备身份、source 直接依赖和来源 origin 均不能越过本次签名截止序号。每条依赖的 kind/hash 精确匹配；缺失、向前引用、环、重复序号/操作或完整候选中未使用的分支拒绝。来源图复用 memo，不递归嵌入完整证明。

外层来源可以使用原 Proof2，但仍须包含最新已验恢复 head 的完整闭包，TrustRoot 的恢复代际/两公钥须精确匹配该 head。已见 head 的 hash/序号必须保留；原根和初始化锚不能改变。旧单签断链只有完整 ALL Admin 的明确 manager-reanchor 路径可处理，期间恢复公钥先退役，不能被本次新钥复用。

历史 Admin/RO/RW 与双签身份用于验证当时的来源。它们不授予当前设备权限；尚未接入的接受服务必须在同一个账号 Store 事务中再次比对真实已接受归档/历史序号、当前设备、代际、全部环境 KV、GG、角色与期限、恢复 head、单次 nonce 及完整封套集合。不能用历史图或根元数据替代当前权限。

新 DAG 入口先在 2 MiB/64 层限制内快照 JSON 材料，再进行验证。已验 pin、记录、身份、head 与来源 memo 由运行时私有字段持有；公开 Map/Set/getter 与验证结果返回独立快照。调用方修改原输入或返回对象不能改变已验状态，内部循环直接使用 owned 材料，不重复复制 getter。旧入口不使用这项新快照流程。

图按成熟证明格式保留验证必需的已签初始化、恢复包和 HPKE 材料；不新增独立 vault 封套列表、业务标签/变量名/数据密文、token 或私钥。测试附带的公开种子明确属于固定合成向量，生产实现不保存恢复私钥。

## 容量与未接范围

新独立 JSON/规范编码上限 2 MiB，JSON 深度 64；拒绝无效 UTF-8、重复对象键、未知字段、尾随内容与 null/缺省数组。记录最多 256，其中 transition/recovered 各 128；直接依赖边最多 8,192。每叶权源最多 1,024、origin 最多 128、身份分支最多 32、每路径最多 32、归档总数最多 256；每组环境清单/targets 最多 256。现有最后环境删除门槛与非空恢复清单保持一致。

单账号持久化 1 MB 限制没有提高。本切片没有增加安全状态、修改 D1/DO 分工、改变旧幂等记录或开放 major2。后续须独立完成显式新路由/协商、单权威原子接受、跨 profile 原 ID 冲突/旧回执、重复恢复后的普通控制图，以及真实 HTTPS/SQLite、CLI 和手机验收。

## 实测

最终公开合成向量快照 `test/vectors/recovery-dag-v1.json` 的 SHA256 为 `22f82f175fcd940c04e6745150e9399f747bc9954fee3cad0e4af614e0697287`。向量来自 protocol 同名文件，可独立 clone server 执行，不依赖其它仓库本地路径。

新增测试 47/47 通过：Node 独立编码/hash 与 Go 逐字一致，实际 Ed25519 核验 t1→E→t2→G→G全环境Admin t3，最终恢复代际4/序号42；G→H 三环境RO双签及 v5 归档控制图也通过。其中3主项核验原输入/返回快照修改隔离与大小/深度边界；其余必要拒绝覆盖锚/初始化替换、缺依赖、错误 kind、向前引用、旧域、部分清单、未知/null/重复 JSON、已见 head 回退和配对 anchor 不一致。服务端不解密变量；实际 HPKE/AEAD 是 Go 向量生成端的独立测试，不把本切片记成 HTTP 或手机端到端通过。

完整检查、固定基线及未跑范围见 [验证记录](TESTING.md)。
