# 环境来源与多管理设备 v3

这是实验性服务端实现。Node SQLite 与每账号 SQLite Durable Object 调用同一事务业务；没有新增 D1 安全状态、线上部署或设备信任捷径。

## 明确协商与原接口

新配对使用 `/v1/accounts/:id/pairings-v3`，两端传 `certificateVersion: "3"` 与 `capabilities: ["issuer-origin-v1"]`。发起、状态、中继、批准、完成的精确字段与 [v2](ENROLLMENT-V2.md) 相同，但批准证明必须是 `harmonia/issuer-proof/v2`，签名域为 `harmonia/device-enrollment/v3`。固定 16 项签名数组绑定完整证明摘要。SPAKE2 原语 profile 没有改变。

`/pairings` 与 `/pairings-v2` 的字段、固定签域和证明 profile 保持原样，拒绝未知字段或不匹配的 version/capability；不会隐式降级。已完成的 v1/v2 双签归档可以成为 v3 历史节点，v3 归档也能继续委派到另一设备。

新设备仍须本机真实 PAKE 确认管理者两公钥和 transcript，再核验外层证书。服务器目录和仅自洽的根声明不能成为信任锚。既有设备必须保留受保护的精确初始授权摘要集合；服务器候选证明不能扩大该集合。

## 环境提交与两个权限来源

创建或轮换环境使用 `POST /v1/accounts/:id/environment-changes-v2`，精确 JSON 为 `{change, signature, origin: {origin, signature}}`。内层 `EnvironmentChange` 保留原有签名编码；操作者再独立签 `harmonia/environment-origin/v1` 的固定 17 项数组。来源证书绑定完整内层规范字节及原签名的摘要、账号代际、操作者、操作、源环境授权版本、目标环境新旧版本、原检查点和幂等键。

`before` 和 `after` 按主体 ID ASCII 严格升序。每行只包含主体 ID、两公钥、钥匙版本、授权代际、角色、期限、精确签名 grant 摘要。来源证明没有标签、变量名、数据密文或恢复封套。

创建的 `before` 为空，`after` 只能是操作者自己的首个 Admin，期限不超过当前源 Admin。轮换的两清单覆盖相同的全部有效接收设备，原公钥、角色和期限保持不变，钥匙版本与授权代际加一。每个新授权有两条父来源：操作者旧 Admin，以及该接收者自己的旧授权。旧接收者可以是 RO/RW；它不能作为普通委派的管理父节点。临时 B 可以保留 A 原有永久权利，不能伪造 A 的旧永久授权或给其他设备扩权。

同一账号事务中，服务器验证两份真实签名、完整变更摘要、当前操作者 Admin/期限/两公钥/代际、精确旧接收者集合和完整新清单。接受后冻结来源证书及授权历史；原始变更事件序号必须等于 `expectedSequence + 1`。重加密变量各自取得后续序号。事件内层 `change` 精确为 `{change, signature}`，来源证书仅在事件外层 `origin`；不会在内层重复附加字段。本人收据的 `sequence` 是整笔事务的最终序号，环境事件本身仍是 `expectedSequence + 1`。

v2 提交幂等内容固定为 `JSON.stringify(["harmonia/environment-submission/v2", base64url(changeCanonical), changeSignature, base64url(originCanonical), originSignature])`。`GET /environment-changes-v2/:idempotencyKey` 只查询本人收据，返回 `state`、可选 `sequence` 与 `contentHash`，摘要是上述 UTF-8 内容的 SHA256。改任何签名、内容或 profile 不会成为另一笔同键写入。原 `/environment-changes` 拒绝附加 origin；改名和删除继续使用原接口。

## 控制面候选与读取隔离

普通或暂停拉取显式加 `capability=issuer-origin-v1` 时，返回 `issuerEvidence`：按本设备当前可读目标构造完整控制来源闭包，当前授权与生命周期来源独立于 `after`；普通拉取还加入本次实际返回事件的冻结授权与写入者双签身份路径。暂停流不返回普通数据事件，也不因此引入其数据来源。每个遇到的来源证书都必须包含全部 `before`/`after` 行对应的精确签名授权和身份分支，不能只保留当前读者的一行。来源依赖旧版本时不会自动扩展后来不相关的轮换。没有可读目标时为 `null`，当前签名撤销/过期 grant 仍返回。没有 capability 的旧响应不加来源字段，包括环境事件中的 origin。

准备轮换时，管理者使用 `GET /issuer-evidence?environmentId=E&capability=issuer-origin-v1`。只有该环境当前 Admin 的设备绑定会话可以调用，返回 `{sequence, grants, issuerEvidence}`：`grants` 是完整当前有效接收者集合，证明目标仅为操作者自己的当前 Admin。它包括必要的历史 RO/RW 来源与受双签保护的身份分支，不能从目录公钥或历史图猜当前接收集合。

证明的主身份路径从固定根到本次管理者；其他操作者或接收者使用同根双签分支。相同前缀可以复用，同设备不同公钥或不同证书、重复完整路径、循环和授权分叉均拒绝。根没有父节点的 selfAdmin 必须逐字匹配原双签初始化 proposal 中的精确初始 grant 集合，并匹配已接受的 `authorization: null` 历史；单独的历史 null、自洽根声明或当前 selfGrant 均不能成为 genesis。新能力缺唯一有效原记录时返回 `initialization_evidence_required`，不会向旧账号或夹具补造原记录；旧不请求该能力的接口行为保留。批准与首次完成都重新检查当前逐目标 Admin、期限、keyVersion 与精确 grant 摘要；历史证书不能替代当前权限。

仅获 Y 授权的 C 可取得验证 Y 来源所需的 X 权限元数据；不会收到 X 的标签、变量名或数据密文。封套仍为已有接收者公钥加密的 80 字节 HPKE 数据。来源候选须由客户端对受保护根 pin、精确初始授权和既有账本核验，不能直接持久化。暂停刷新不应用变量或推进数据检查点。

## 恢复原初始化锚

`GET /recovery-vault?capability=issuer-origin-v1` 在既有受限恢复或全环境 Admin 授权检查后，额外返回 `originalInitialization`。它只有唯一已接受原初始化的 `proposal, proof, deviceSignature, recoverySignature, sequence`；`proof` 精确字段为 `accountId, accountGeneration, loginTokenHash, challengeId, nonce, expiresAt, proposalHash`。没有原 bearer、邮件地址、密码验证值或待完成挑战。旧无 capability 响应不改变，旧测试夹具缺原记录时明确返回 `null`，不会从当前 selfAdmin 或序号补造根。

客户端用当前恢复码派生公钥验证当前可信根，再以精确相同的根 Ed/X 元组核验原设备签名。该签名绑定完整原 proposal 摘要，其中包含原恢复两公钥、原恢复签根声明和全部初始 grants；之后验证原恢复签名。恢复码轮换保留这份原记录，原恢复公钥可以不同于当前恢复公钥。初始序号只是接受一致性，不代替双签密码学锚。

本快照先完成原初始化来源锚。恢复所有后来新增环境和跨版本历史的通用来源图为下一独立切片；本页不将其列为已完成。 后续独立切片的服务端合同见 [完整恢复历史来源图](RECOVERY-SOURCES.md)，该页单独记录验证范围。

## 边界与证据

新证明最多 512 个授权节点、128 个来源证书、16 条辅助路径；单条路径最多 32 项，总归档引用最多 128 项。规范证明编码、v3 批准正文和环境提交正文各限 1 MB；其他正文仍限 100 kB，v2 批准仍限 262,144 字节。单账号文档的 1 MB 容量边界没有解除，历史、完整证书和幂等收据计入；超过容量受控拒绝并原子回滚。

2026-10-02 新增 25 项定向测试通过，完整服务端检查 134/134 通过：Go/TS 17 项来源、9 项证明与 16 项证书固定编码互操作；真实 Node TCP 与 workerd HTTP 的非根创建、v3 继续归档委派、永久 Admin/RO 权利保留、防降级、两签幂等、精确来源历史、假 genesis 拒绝、当前授权换代/期限/代际拒绝、全响应跨环境数据隔离、完整旧新清单及双签身份、不同路径历史写入者来源、新能力缺原记录拒绝，以及真实 SQLite 失败回滚。原初始化锚另外验证真实 HTTP 两签、恢复码轮换保留原记录和缺记录返回 null。

服务端单元中继采用公开合成声明，不替代真实 PAKE、HPKE/AEAD 和受保护客户端账本的联合验收。线上资源、真实手机系统认证及完整产品流程仍未完成。完整结果见 [测试记录](TESTING.md)。
