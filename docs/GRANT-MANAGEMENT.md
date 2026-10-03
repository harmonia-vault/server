# 既有设备授权管理与精确回执

本切片复用已有签名 Grant 和全局设备撤销域，不增加协议版本或设备信任入口。Node SQLite 与每账号 SQLite Durable Object 调用同一业务；没有新增 D1 安全状态。仍是实验性实现。

## 独立管理投影

`GET /v1/accounts/:id/grant-management?environmentId=E&capability=issuer-origin-v1` 使用当前设备绑定会话。每次检查账号代际、会话期限、设备未全局撤销以及本设备当前 E Admin、环境钥匙版本和授权期限；历史身份或权限图不能替代当前管理权。

响应精确字段：

```text
{accountId, accountGeneration, environmentId, sequence, keyVersion,
 subjects: [{deviceId, signingPublicKey, receivingPublicKey,
             currentGrant: SignedGrant | null, highestGrantGeneration}],
 issuerEvidence: IssuerProofV2}
```

`subjects` 按设备 ID ASCII 排序，包含既有未全局撤销设备，最多 256 项。两公钥须精确匹配已接受双签入网归档；原根身份来自唯一有效原双签初始化。缺少档案、原初始化、精确授权历史或钥匙不一致时整次拒绝，不静默省略或从目录补造可信身份。

`currentGrant` 保留本环境最高已接受授权，包括 `none`、已过期角色和旧 keyVersion。`highestGrantGeneration` 为十进制字符串，必须等于完整接受历史中的最高代际及当前签名包的代际。例如 C 已到期授权为 KV2/GG5，其他设备轮换到 KV3 后它仍为 KV2/GG5；恢复授权须显式产生 KV3/GG6，不能重置为 GG1。

已受信既有设备从未获得 E 授权时，`currentGrant:null`、`highestGrantGeneration:"0"`。这只是该服务器快照中的缺席状态，不是密码学缺席证明。客户端必须保持已保护的历史授权代际下界，不能因候选 null/GG0 清掉已见状态；快照序号也须不低于受保护检查点。服务器写入事务仍检查 `currentGG + 1`，遇冲突不得偷偷重签或换幂等 ID。

普通/暂停 pull 在当前授权 none 或到期时，也提供独立历史签名来源，便于原 A 审批的 C 核验后来的 B 撤销签名并清缓存。历史 target 不替代当前授权，可读集合仍单独决定是否返回数据。

证明目标只有本次管理者自己在 E 的当前 Admin。普通和过期非 none 授权、必要历史管理来源及全部 subject 双签身份进入完整控制闭包；`none` 记录只独立验签并保留冻结的 Admin 来源，不成为可授予权限的图节点。客户端用受保护根 pin、精确原初始化授权集合及已见账本验证候选，再逐一匹配 subject Ed/X、签名、环境、代际和当前检查点；不能直接信任响应中的目录字段。

本投影不含环境标签、变量名、变量数据密文或恢复封套。图可包含验证来源所需的其他环境控制授权及已有接收者 HPKE 封套，这些字段不授予其他环境读写权。

已有准备轮换用的 `/issuer-evidence?environmentId=E&capability=issuer-origin-v1` 保持原活动接收者投影，不因管理界面需要已过期/撤销记录而改变轮换清单。

## 提交与本人精确回执

角色/期限编辑继续 `POST /v1/accounts/:id/grants`，请求 `{grant,signature}`。只管理已受信设备；新设备仍须完整配对。RO/RW/Admin 需要当前环境钥匙的接收封套，none 的封套为空。期限与当前 Admin 上限按已有业务核验，临时 Admin 不能签永久有效的新权利；当前 none 提交同样受已有期限校验。服务端逐次验证当前权限及独立 Ed25519 签名，接受后按原拉取流更新本机。

`GET /v1/accounts/:id/grant-status?idempotencyKey=K` 只查本人作为 issuer 的 `grant/<deviceId>/<K>`：

```text
{idempotencyKey, accepted:false}
{idempotencyKey, accepted:true, sequence, contentHash}
```

`contentHash` 是 `SHA256(UTF8(base64url(grantSigningBytes) + "." + originalSignature))` 的小写十六进制，与原不可变签名包精确匹配。后续同对象改角色、轮换或删除历史不改变已接受收据。只允许单个该查询参数，拒绝重复键或主体选择参数。

回执查询只需当前可信设备绑定会话和账号代际，不要求仍有原环境 Admin；降权后仍可确认本人过去操作，不能据此恢复权限。全局撤销设备、旧代际、未绑定登录和其他设备 token 均拒绝。返回只含 ID、接受结果、序号和摘要，不含名称、签名、封套或凭据；响应 `Cache-Control:no-store`。

客户端在第一次提交前保护持久化原签名包、原 ID 和原会话上下文。丢失响应后先查精确回执，再核验相同包摘要与接受序号；不得用当前同值或 pull 推断接受，不得生成新 ID 重写。`accepted:false` 不能证明已经尝试的请求永远未被接受，也不能解除未知结果门槛或允许取消。只有提交前可退役原 ID；已尝试包继续结果查询或按现有规则重试原包。

## 全局设备撤销回执

已有 `/device-revocations` 挑战和 `/device-revocations/complete` 保持账号/代际、目标两公钥、全环境当前 Admin、原 sessionHash、nonce 和 120 秒单次期限规则。全局撤销清除目标当前授权和绑定会话，保留必要历史验签来源。

新增 `GET /v1/accounts/:id/device-revocation-status?idempotencyKey=K` 采用上述同一安全回执 DTO，范围只有本设备发起的原操作。未知或待完成返回 `accepted:false`；已接受的 `contentHash` 为 `SHA256(UTF8(base64url(deviceRevocationSigningBytes) + "." + originalSignature))`。旧 `/device-revocations/:K` 的 pending/TTL DTO 保持不变。

原 token 失效后，若设备当前仍有合法授权，可按开机持钥流程取得新的设备绑定会话查询原收据。查询不需要重签旧操作。原撤销包继续绑定原 sessionHash，用新 token 重新提交会被拒绝，不能盲改会话或重新发起同目标操作绕过未知结果。

## 测试与限制

独立 `test/grant-management.test.ts` 9/9 定向通过：真实 Node TCP 与本地 workerd SQLite DO 验证角色编辑、none/过期/旧 KV 最高代际、原摘要、降权后查询、身份隔离、当前期限、独立 none 签名、精确原包与新 boot 会话边界、缺失档案/历史/初始化拒绝，以及 SQLite UPDATE 失败原子回滚。封套和数据仍为合成结构；真实 Go 加密原 journal、客户端验证及手机管理流程由独立联合验收记录，不在本页提前宣称通过。

证明沿用最多 512 授权节点、128 来源、16 辅助路径、总归档 128 项及 1 MB 规范编码边界；虽 subject 上限 256，复杂档案可能先碰证明容量。单账号 1 MB 文档含历史、封套和回执，超过容量受控拒绝并回滚。没有分页、历史压缩或跨副本存储。此切片未部署、发布安装包或加入 CI；Docker/线上资源没有重复验收。完整检查的实际结果见 [测试记录](TESTING.md)。
