# 前台待审批提示

这是只读元数据接口，供 App 前台提示与待审批数量使用。它复用账号 Store 内现有配对记录，不增加推送权限、独立安全状态或新的批准方式。密码登录不等于可信设备；最终批准继续使用相同版本的双向 PAKE 确认、设备双签、环境角色与期限校验。

## 请求与固定版本

- `GET /v1/accounts/{accountId}/pairing-requests-v3`：仅证书版本 `3`、能力 `issuer-origin-v1`。
- `GET /v1/accounts/{accountId}/pairing-requests-v4`：仅证书版本 `4`、能力 `issuer-recovery-v1`。

请求头沿用 `Authorization: Bearer ...`、`X-Harmonia-Account-Generation`、`X-Harmonia-Device-Id`。token 必须已经通过设备持钥证明绑定到该管理设备；账号登录会话或另一设备的 token 不能冒充管理者。没有 query、body、版本协商 header 或自动降级。未知 `v2`/`v5` 路径返回 `404 not_found`；已知路径非 GET 返回 `405 method_not_allowed`；任何 query 返回 `400 query_forbidden`。响应为 `Cache-Control: no-store`。

v3 响应的合成例子：

```json
{
  "accountGeneration": "1",
  "certificateVersion": "3",
  "capabilities": ["issuer-origin-v1"],
  "requests": [
    {
      "idempotencyKey": "synthetic-pairing",
      "initiatorDeviceId": "synthetic-cli",
      "state": "pending",
      "expiresAt": "2090000000"
    }
  ]
}
```

v4 的结构相同，证书版本为 `4`、唯一能力为 `issuer-recovery-v1`。客户端应精确检查版本和能力；这不是协议 major 3/4。数组按期限的数值、再按 idempotencyKey 的 ASCII 顺序排列，最多 64 项，与现有账号配对容量一致。期限是规范十进制 Unix 秒字符串。

## 每次查询的授权与过滤

同一个账号 Store 事务先核验账号代际、当前登录会话、设备未撤销、会话绑定设备，并要求该设备当前至少有一个仍有效的环境 Admin 授权。失效会话或代际返回 `401`；未可信/绑定不符/没有有效 Admin 返回 `403`，不返回任何请求列表。

只列出当前设备被精确指定为 approver、登记的 Ed25519/X25519 双公钥仍相同、账号及代际相同、版本相同、未完成、未到期的记录；发起登录会话也必须仍有效。已完成、被清理或失效的请求不列出。已批准记录额外逐环境检查当前 Admin、keyVersion、期限和原冻结来源证明；任何条件失效即排除该行，不能用历史批准替代当前权限。

`pending` 尚未选择环境，因此这里只要求管理者当前仍有可批准的 Admin 环境，不能推断它能批准所有环境。`approved` 表示已有批准材料、等待发起端完成双签，App 不应再次邀请批准。降权后如果仍管理其他环境，合法 pending 可保留，但已经失去批准来源的 approved 必须移除。

每行只有请求 ID、候选设备 ID、状态和期限，没有短码、nonce、公钥、中继、credential、token、授权封套、环境标签、变量名或数据密文。候选设备 ID 是未可信显示元数据，不是公钥来源或权限凭据。查询不递增账号持久序号。现有 WebSocket 只通知配置序号，不能当作 pending 配对推送；App 在前台主动刷新该投影即可，不申请后台推送权限。

## 前台使用顺序

进入前台或审批页面时读取适合当前设备信任来源的固定版本接口；新 pending 可提示一次，同一 ID 避免重复弹窗。approved 只显示等待完成，complete 后列表自然移除。选择一项后请求同版本 `pairings-v3/{id}` 或 `pairings-v4/{id}`，走原 PAKE 与签名批准；metadata 中的任意状态都不能直接批准、登记或解密。

## 本地测试与范围

新增独立 `test/pending-pairings.test.ts` 对真实 Node TCP/SQLite 和本地 workerd HTTP/SQLite DO 各运行 5 项测试，10/10 通过。核验两版本合法中继/批准/完成、最小字段、其他 approver/账号隔离、登录会话冒充、RO/降权/撤销、授权和会话到期、代际及钥匙变化、失效 initiator、完整批准来源变化、64 项容量/确定排序与只读序号。workerd 负例通过独立测试 RPC 的明确 JSON 快照注入合成状态；此 RPC 不进生产构建。

本轮没有真实手机提示验收、推送、Cloudflare 线上部署、DAG major2 HTTP、CI、Release 或 Docker 重跑。固定结果和夹具失败记录见 [测试记录](TESTING.md)。
