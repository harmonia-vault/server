# 恢复设备的环境与授权管理

本切片将已明确登记并通过开机持钥的恢复管理设备及其 v4 子设备接入既有环境业务。采用 `issuer-recovery-v1` 的成熟 `harmonia/issuer-proof/v3`，不更改密码学签名域，不加入下一次恢复所需的 source DAG。连续恢复、受限会话及设备登记边界见 [连续恢复授权](RECOVERY-AUTHORITY.md)。

## 显式控制接口

- `GET /v1/accounts/:id/issuer-evidence?environmentId=E&capability=issuer-recovery-v1` 返回独立类型 `{sequence,grants,issuerEvidence}`；issuerEvidence 必须是 Proof3。grants 是该环境当前有效接收者集合，targets 精确指向请求设备当前 Admin 授权。
- `GET .../grant-management?environmentId=E&capability=issuer-recovery-v1` 返回 `{accountId,accountGeneration,environmentId,sequence,keyVersion,subjects,issuerEvidence}`，issuerEvidence 必须是 Proof3。每个 subject 为 `{deviceId,signingPublicKey,receivingPublicKey,currentGrant,highestGrantGeneration}`；从未获该环境授权的已登记设备是 null/GG0，none、过期或旧 keyVersion 的已有授权保留其最高代际。目录公钥不能建立信任，所有主体均须匹配完整双签或恢复双签归档。

旧 `issuer-origin-v1` 控制接口继续返回原 Proof2 类型，不接收、回退或隐式转换新图。未知、重复能力及多余查询字段拒绝。两个接口逐次检查设备绑定会话、账号代际、设备状态和环境当前 Admin、版本、期限。none 只保留独立签名和被接受时冻结的管理来源，不能成为可授予权限的图节点。

控制响应不新增独立 vault 封套列表，不返回环境标签、变量名、业务数据密文、原 token 或私钥。完整 Proof3 的原初始化、连续恢复 transition 与 recovered 归档仍须保留既有 canonical 要求的签名材料，其中可能包含其他环境 ID、历史权限和无法由请求设备解开的 HPKE 封套。不能删除这些嵌套材料后声称仍返回可验证的同一 Proof3。

## 环境提交与原操作确认

`POST .../environment-changes-v3` 禁止查询参数，正文精确 `{change,signature,origin}`，复用现有 `SignedEnvironmentChangeV2`。只用于 create/rotate；两份真实设备签名分别绑定完整环境变更和控制面来源。当前来源通过 Proof3 重建并匹配已接受原初始化、恢复链、设备归档和授权历史；完整 before/after 清单及旧接收者来源均验证。新请求仍在同一个账号事务检查当前 Admin、keyVersion、grantGeneration、期限、expectedSequence、恢复代际、全部设备封套和全部存活值重加密，没有从原根元数据取得额外权限。

响应仍是 `{sequence,replayed}`。环境事件接受序号为 expectedSequence+1，轮换内每个值继续消耗一个持久序号，返回的 sequence 是事务尾。内层事件 change 精确 `{change,signature}`，origin 只在外层。环境请求上限仍为 1 MB，账号持久容量仍为 1 MB；容量或 SQL 提交失败整笔回滚。

`GET .../environment-changes-v3/:id` 禁止查询参数，返回 `{state:"unknown"}` 或 `{state:"complete",sequence,contentHash}`。contentHash 完全复用原 `harmonia/environment-submission/v2` 两签完整包摘要，不创建新签名域。v2/v3 共用原 issuer/id 幂等库，同包跨入口只返回已接受的旧序号，异内容拒绝；逐次当前权限检查在重试之前执行。未知结果仍保存原签包和原 ID，不能据 unknown 自动换 ID 重签。

rename/delete 使用原 `/environment-changes` 的 `{change,signature}`，不硬塞 origin。`/grants`、本人 grant-status 和全设备撤销也保留原签名域及幂等记录；操作成功后通过相同的验证 pull 更新本机。暂未定义账号级管理授权，最后一个环境的删除门槛保持不变。

## 本地产品回归

2026-10-03 新增独立 `test/recovered-management.test.ts` 定向 5/5 通过，测试约 8.72 秒。 01:49 UTC 查验整仓 `mise run check` 183/183、typecheck 与生产 build 通过，任务约 19.52 秒。真实 Node TCP 和本地 workerd SQLite DO 各验证：全部旧设备撤销后恢复 E；E 在 Y 批准 F，新增 Z 后从完整归档确认从未获 Z 授权的 F；授 RW、F 写值与验证拉取、授 Admin、F 新增 W 和轮换 Z；完整两签摘要、事务尾序号、同 ID 查询和重试；原接口 rename/delete。另核验跨环境无当前 Admin 拒绝、none 只作历史来源、旧能力拒新身份、缺 F 归档拒绝及真实 SQLite 写失败原子回滚。

初跑两项权限断言失败：测试只将 Z 降权，却期待仍有 Y Admin 的 E 重试由 Y 授权创建 Z 时被拒绝。改为对实际来源 Y 降权后通过，没有更改当前权限检查或签名校验。结构封套和值包均是公开合成输入，本节不宣称实际 HPKE、PAKE、手机完整管理 UI、下一次恢复或线上资源验收；真实 Go 用户链由独立联合验收记录。未部署、发布或加入 CI。
