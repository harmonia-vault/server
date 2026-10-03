# 恢复环境钥匙的签名承诺

HPKE 封装只需要接收公钥。服务器因此也能向用户恢复公钥封装任意环境钥匙；解封成功不能证明钥匙来源。空环境没有变量可供 AEAD 验值，更不能依赖该步骤发现替换。每个恢复环境都须先验证独立签名承诺，包括空环境。

## 显式同事务响应

请求 `GET /v1/accounts/:id/recovery-vault?capability=issuer-origin-v1&envelopeEvidence=recovery-envelope-v1`。它沿用当前代际的受限恢复会话或逐环境全部当前 Admin 设备会话检查；新增字段与 vault 密文、环境集合、当前恢复代际、原初始化及来源图在同一个账号 Store 事务投影。D1 不保存第二份安全状态。

不传新标志的旧 DTO 保持不变。重复、未知标志或缺少原 capability 拒绝。新增字段精确为：

```text
envelopeEvidence: {
  profile: "harmonia/recovery-envelope-evidence/v1",
  environmentChanges: [{sequence, change: {change, signature},
                        origin: SignedEnvironmentOrigin | null,
                        authorization: SignedGrant}],
  recoveryRotations: [{sequence, proposal, proof, signature}]
}
```

`environmentChanges` 只含现存环境当前 keyVersion 的已接受 create/rotate 完整签包，按接受序号排序。原完整 Change 包含恢复代际和恢复封套；客户端用已验证历史身份和 Admin 来源核验操作者 Ed25519 签名，并检查 Origin 摘要精确绑定整个签包。服务端也重查完整用途字段、两签、冻结授权和原 head 序号，不把目录公钥当作客户端信任锚。

`recoveryRotations` 只含当前恢复代际已完成、具有真实十三项签名用途的 v1 原记录，完整保留 proposal 的全部封套及新可信根、原 RecoveryRotationProof 和新恢复钥签名。proof 精确字段为 `accountId,accountGeneration,sessionHash,recoveryGeneration,challengeId,nonce,expiresAt,newRecoveryGeneration,newRecoverySigningPublicKey,newRecoveryReceivingPublicKey,envelopesHash,trustRootHash`。没有原 bearer 或私钥。根 ID/两公钥保持原值，新恢复公钥和代际绑定一致。历史已接受的期限不因现在到期而否定原签名。旧无可信根的十二项夹具不会被补造为十三项记录。

## 每个环境先验承诺

客户端必须先完成原双签初始化与完整历史来源核验，再逐环境验证当前封套，最后才 HPKE 解封：

- 原恢复代际、原初始环境和 KV1：当前封套须逐字等于原双签 proposal 承诺的封套。
- 当前 KV 的 create/rotate：完整环境签包与已核来源图的 Origin 摘要、操作者签名和接受时 Admin 精确相符，恢复代际与封套逐字匹配。
- 后续恢复代际：使用本机用户恢复码派生的当前恢复签名公钥验证原轮换签名，重算完整封套集合摘要与可信根摘要，再逐环境比较当前版本和封套。

缺任一环境承诺、遗漏材料、包或 hash 替换、跨代际/版本不匹配均须整次拒绝，不先保存部分钥匙或信任。服务器返回的裸公钥、裸封套和 HPKE 成功都不能补缺失签名。该 v1 轮换记录只能证明封套承诺；它不是拟议连续恢复授权链的旧钥授权，不自动让新设备取得管理权。

恢复查询者具有全 vault 的恢复权限，因此这里返回完整环境签包及其中已有密文；这些材料不进入普通设备的控制证明。仅 Y 读者仍无法通过此接口获取 X 标签、变量名或数据。新标志不会注册设备、变更角色或绕过显式恢复码轮换。

## 证据与边界

新增服务端 `test/recovery-envelope-evidence.test.ts` 5/5 通过，包含真实 Node TCP 与本地 workerd SQLite DO 的原响应不变、同快照投影、完整环境包、十三项原轮换签名/完整清单、查询隔离、签名篡改拒绝及真实 SQL UPDATE 失败回滚。替换裸封套不会改掉已签承诺；客户端必须比较两者。

独立 Go HTTPS/race 验收已核验全部设备撤销、新 Y、X 轮换、恢复 gen2 和空环境公开 HPKE 替包拒绝；实际结果由父任务汇总，不将结构合成封套测试替代真实加解密。单账号 1 MB 与来源图容量边界保持不变，未做大历史分页或线上部署。此切片尚未接通新的连续恢复过渡和恢复设备入网；这些使用独立新能力，不能从本响应暗中升级。完整记录见 [测试记录](TESTING.md)。
