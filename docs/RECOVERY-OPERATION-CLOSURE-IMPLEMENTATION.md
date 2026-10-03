# 恢复原事务终止：实现与存储兼容

该切片只实现服务器权威三态合同，仍为实验性软件。请求/数组规范见protocol的 `docs/RECOVERY-OPERATION-CLOSURE.md`；客户端显式终止和原保护记录整体CAS尚未实现。

## 实现职责

`recovery-operation-resolution-wire.ts`负责严格请求、确定编码、目标/挑战摘要与成熟Ed25519验签；`recovery-operation-resolution.ts`负责当前受限权限、历史basis和终态排序；`recovery-operation-guards.ts`负责唯一恢复ID视图、联合预算、读写validator；`http-recovery-operation-resolution.ts`只适配受限HTTP输入。

新路由的当前完整码证明仍由既有recovery-challenges/recovery-sessions执行，服务端独立随机单次nonce，并逐次检查当前恢复代际。请求本身Ed签绑定当前session hash及mode。旧session hash仅历史标识；原session过期不自动推定失败/closed。transition并发先接受导致旧close会话失效时应拒绝鉴权，fresh当前码会话才能读原接受收据。

共同guard在每个原创建/提交事务当前授权之后、原挑战重返/幂等/nonce消费以前。closed使进入业务事务的任何同ID晚到操作409；原权限/major门槛可先拒绝；accepted保持原包hash/sequence，不能写墓碑。原source、nonce、generation、manifest和双签机制不修改。all-Admin挑战的精确Ed/X身份来自其冻结已验历史source；recovered挑战精确比较其目标双钥；原old-recovery挑战没记新device双钥时不声称服务器已验证未知选择。

## 实际五表上限和联合计数

固定基础server `2f15b94ce5023357320b415e5f3a4aebb29c2856` 的写上限证据：

| 表 | 基础源码位置 | 写上限 |
| --- | --- | --- |
| recoveryAuthorityChallenges | src/recovery-authority.ts:143 | Object.keys >=128拒绝 |
| recoveredDeviceChallenges | src/recovery-authority.ts:253 | Object.keys >=128拒绝 |
| recoveryDAGChallenges | src/recovery-dag-service.ts:71 | Object.keys >=128拒绝 |
| recoveredDAGChallenges | src/recovery-dag-service.ts:113 | Object.keys >=128拒绝 |
| recoveryRotations | src/lifecycle.ts:136 | Object.keys >=128拒绝 |

这些是原写路径检查，不是任意外部损坏JSON的历史可信证明。新代码保留五个各自限制，并在新分配之前增加联合预算。算法先对同ID检查完整目录：v1/v2接受历史、完成rotation、各挑战及墓碑；多accepted、多challenge、accepted与异kind挑战、closed与任何既有来源同在都报state_invalid。随后枚举五表keys，将没有真正accepted记录的ID放入Set，预算=Set.size+closed.entries数量。

accepted排除条件不是TTL、已返回HTTP或客户端声称成功：必须实际存在同ID唯一已接受历史（v1 transition、v1 recovered、v2 DAG record）或rotation.state=complete；若保留挑战只能同kind，否则损坏拒绝。该接受记录不再可能由新关闭转换成墓碑，故不占未完成预算。测试直接断言accepted保留挑战被排除及255允许/256拒绝新分配边界。

新分配最多256。已有超预算挑战可以同ID转换：pending移除1、closed增加1，联合数量不变。因为旧五表各128，历史预留最多640，新validator硬读上限640；它不是新分配配额。测试构造256墓碑+1旧预留时拒新ID，但唯一旧预留可转换成第257墓碑；已有收据持续可查。跨kind复用先共同目录拒绝，不能用Set去重突破预算。无墓碑驱逐。

账号document仍最多1,000,000字节。超限关闭在整个SQLite/DO事务内拒绝，原挑战/sequence不半更新；测试用接近上限合成padding验证。永久预算或空间满是明确阻塞，保持pending，不能自动删除安全记录。

## 实际读写与重建审计

固定基础 `src/store.ts:47` 直接 `JSON.parse(String(row.data))`，没有挑字段/strip；`document` JSON.stringify原account，`transaction`在callback后整体UPDATE，故普通旧业务写保留未知JSON字段。新实现在read与document都调用同一个closure validator，损坏状态在任何普通路由业务callback以前被拒绝。

NodeSql使用 `BEGIN IMMEDIATE`、WAL和synchronous=FULL，COMMIT后才观察通知；DO使用同SqlStore和SQLite `transactionSync`，无D1恢复权威。Workers预读故障须在DO内转为固定Fault响应，防RPC序列化丢类型后误变500。Node在路由前body超限的固定错误头也回显规范major；两runtime超限/非法UTF8/重复JSON/错误major均有回归。

基础 `src/account-lifecycle.ts:45` 的未完成注册替换以及153–159的破坏性reset用emptyAccount并删除原对象全部keys，再Object.assign新generation。它们有意清旧generation的所有安全状态；新字段不能跨账号generation保留。其他普通业务通过同Store callback修改原account，没有新挑字段重建路径。本片未更改这些reset机制，也未声称执行新的邮箱reset场景。

读取允许无closure字段，首次终止惰性新增version1容器。未知version/坏摘要/同IDaccepted或挑战碰撞 failclosed。没有新schema数据库表/SQL重排，也不导出D1安全副本。

**旧写进程回滚/混跑不受支持。** 旧SqlStore虽保留未知字段，旧challenge/submit不执行guard；即使另加最低writer数字，未改旧binary也会忽略它。因此产生首个墓碑前必须停止全部旧writer并升级，在此之后不得回滚到本能力以前版本。需要回滚时只能继续修新版或按既有破坏性账号reset丢弃旧vault，不能静默去掉墓碑。本切片没有自动部署或可证明约束旧binary的迁移器。

## 已冻设计与实现差异

原设计SHA `943ec1de3f34ac2e5ec1f24d236b9e4d536b70240cfe31c8b22af926707c9c52` 保留不变。

- 复用当前公开规范 `Harmonia-Protocol-Major`，不使用设计早期所写X前缀。
- 共同ID/预算/validator拆成独立guards文件，避免HTTP/state耦合。
- 历史最大640兼容读只用于既有预留转换；新分配256。五表实际128源码和accepted排除规则如上。
- old-recovery空Admin挑战摘要用现有同域规范空数组hash，未放宽既有拒空授权helper或旧包。
- 测试SQL故障是实际SQLite BEFORE UPDATE trigger拒绝，不是硬件COMMIT/fsync断电；回应未知是合成丢弃已返回结果，不冒称TCP线路真实丢包。
- 并发Node用同进程两个TCP server及两个独立SQLite连接，DO用两个实际HTTP请求/唯一账号对象；固定顺序组分别验证两种赢家，并发组不声称跨进程/分布式故障覆盖。

以上不改旧签包domain，不扩大新本机权限；原B3/S1/S2/native/UI代码不改。实际结果与首FAIL见相邻验证文档。

## v2：合法legacy断链不封锁原closed收据

独立实际Node/workerd反例确认：无挑战intent close成功后，不同ID合法legacy单签rotation完成，fresh当前新码session仍有效，但v1把verifiedAccountDAG放在closed分支之前，导致原query403 recovery_chain_invalid。墓碑未丢失；查询却无法完成。这是具体逻辑缺口，原v1源码/manifest/FAIL保持不变。

v2在唯一事务当前账号/受限session/当前恢复generation和原tuple检查之后，先检查共同目录及已存closed；统一Store已经核version/targetHash/accountgen/seq/碰撞。请求targetHash与规范数组逐字段精确同原记录才只读返回原seq/observedhash。没有closed的所有路径仍完整verifiedAccountDAG/historicalBasis；accepted未放宽，新ID关闭在gap下仍403且零状态。没有移动当前授权到终态后面，不把旧sessionhash当凭据。

新增独立两例同一实际legacy链，同时证明普通login403、被legacy清除的旧session401、错账号gen401、有效本机签名但不同声明/X/基点409，以及当前gap下新ID关闭仍拒绝。此v2是服务器终态查询修复，仍无客户端CAS/UI。
