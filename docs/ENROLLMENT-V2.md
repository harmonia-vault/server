# 多管理设备 v2 服务端入网

本切片把多管理设备的逐环境签名来源接入同一套 Node / Workers 业务。新设备 C 由可信管理设备 B 批准，仍须本机真实 SPAKE2 双向确认 B 的两把公钥、固定 context 和 transcript。HTTPS 登录和服务器目录不能成为客户端信任锚。批准端使用本地受保护的根 pin 与已有收据验证证明后签名，不能盲签服务端返回的数组。

密码学编码、来源图与客户端信任边界见 [协议说明](https://github.com/harmonia-vault/protocol/blob/main/docs/ISSUER-PROOF.md)。服务端只验证不透明封套、标准 Ed25519 签名和固定 JSON 数组摘要，不持有环境明文或设备私钥。

## HTTP 合同

基路径为 `/v1/accounts/:accountId/pairings-v2`。请求使用 `Authorization: Bearer ...` 与 `X-Harmonia-Account-Generation`。管理者额外使用 `X-Harmonia-Device-Id`，Bearer 必须是该设备完成持钥证明后的设备绑定会话。新设备的发起/完成操作使用其原始登录会话；登录会话本身不能授予环境读写或管理权限。v2 不接受 query 参数。

| 操作 | 方法与路径 | 精确 JSON 字段 |
| --- | --- | --- |
| 发起 | `POST` 基路径 | `idempotencyKey, deviceId, signingPublicKey, receivingPublicKey, approverDeviceId, certificateVersion, capabilities` |
| 状态 | `GET /:idempotencyKey` | 无正文 |
| 公开中继 | `POST /:idempotencyKey/relay` | `side, kind, payload, signature` |
| 管理者批准 | `POST /:idempotencyKey/approve` | `certificateVersion, capabilities, grants, transcriptHash, issuerProof, signature` |
| 新设备完成 | `POST /:idempotencyKey/complete` | `signature` |

发起端和批准端都必须明确传 `certificateVersion: "2"` 与 `capabilities: ["issuer-proof-v1"]`。SPAKE2 原语 profile 仍为 `boringssl-spake2-edwards25519-draft02-v1`。完成时新设备必须对本机已经验证的 v2 证书签名。

状态包含既有 `state, idempotencyKey, pairingProfile, context, messages, confirmations, approval, sequence`，明确增加相同 version/capabilities。`approval` 为完整 v2 对象：`certificateVersion, context, pairingProfile, transcriptHash, grants, issuerProof, approverSignature`，完成后再带 `initiatorSignature`。两端固定 16 字段签名数组使用 `harmonia/device-enrollment/v2`，末尾绑定完整 `issuerProofHash`。

服务器不会生成客户端信任 pin。管理者从受保护既有收据及已经验证的逐环境当前授权构造证明；新设备先用本机已确认 PAKE 管理者公钥验 v2 外层签名，再验历史路径和逐环境授权图。

## 两种验证不能互相替代

历史证明验证有序根到管理者双签路径、每个设备独立 Ed/X 公钥、逐环境 Admin 父摘要、授权期限不扩张、代际和幂等分叉、重复项、循环及缺失来源。旧挑战过期后仍可作为历史来源验证，不能由此恢复当前权限。归档 v2 节点固定当时的 proof hash 和双签，不把完整父证明递归嵌套。

服务端批准和首次完成都在同一账号权威事务内，再检查当前管理者设备未撤销、公钥与账号代际相同、逐目标环境仍有未到期 Admin、keyVersion 相同。每个 target 摘要还必须等于当前已接受 Admin grant 的精确签名字节与签名；即使角色仍是 Admin，grant 内容或 grantGeneration 改变也拒绝旧审批。

历史路径必须精确匹配服务器已完成的入网存档。Admin 图中的每个 grant 必须存在于已接受 `grantHistory`，其父摘要必须匹配接受时冻结的授权。无父的根 selfAdmin 只接受首次初始化中 `authorization: null` 的精确历史记录。根声明中的恢复公钥只是已签元数据，不产生全局管理权。

完成原子保存新设备、全部获授环境的封套、完整双签收据、授权历史与一次持久序号。未知结果可查询原幂等键，成功后相同签名重试返回原序号；不同 profile 共用幂等键会冲突。实际 SQLite 写失败不留下半个设备或半笔授权。

## 兼容与有界失败

原 `/pairings` 继续严格 v1 字段，不接收附加 proof/version/capabilities，也不自动降级。v1 只允许精确既有根设备批准；非根管理者及旧的未完成非根 v1 审批必须重新选择 v2。已经完成的合法 v1 历史证书仍可作为 v2 路径祖先。

路径最多 32 项，Admin 来源与目标分别最多 256 项。v2 批准请求体和规范证明编码各限 262,144 字节；Node 前端、Workers 前端与公共解析器使用同一限制。环境生命周期入口仍限 1 MB，其他入口仍限 100 kB。账号持久文档仍限 1 MB；本切片没有解除历史容量限制，也没有增加 JSON 重复字段专用解析器。

本切片支持首次初始化的同环境、同 keyVersion 根 selfAdmin→A 授 B Admin→B 授 C，以及带已归档 v2 节点继续到 D。新建环境或跨 keyVersion 的来源需要签名 `EnvironmentChange` 扩展证明；目前尚未实现。即使新环境中的 B Admin 已经通过正式业务获得授权，缺少该证明仍返回 `issuer_environment_evidence_required`。这种拒绝不会偷偷将根公钥或恢复元数据提升为账号级管理权。

## 实测证据与限制

2026-10-02，新增 19 项测试通过：固定 Go 编码/摘要/签名、被外层自洽重签的恶意来源图、真实 Node TCP 与 workerd HTTP 明确协商和防降级、A→B→C→D 归档、批准后降权/精确 Admin 改变/全局撤销/到期/旧代际拒绝、新环境扩权拒绝、畸形输入、请求体限制和真实 SQLite UPDATE 失败原子回滚。服务端这些中继消息为公开合成声明，不能代替真实 SPAKE2 原语验收。

工作区另有真实 Go→HTTPS→TS SQLite 联合验收：首根 A、真实 v1 PAKE B Admin、真实 v2 PAKE C RO、已接受响应丢失后的加密收据恢复、C 实际 HPKE/AEAD 验历史 A/B 值，以及降权/撤销后的授权停用。它使用临时账号与合成钥匙，没有真实用户数据。真手机多管理批准 UI、完整恢复/环境生命周期信任扩展和线上资源仍待验收；不得宣称生产可用。
